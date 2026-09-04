use core::marker::PhantomData;

use crate::BorrowedMemoryPool;
use crate::data_structures::interface::{
    Interface, InterfaceConfig, InterfaceHandle, InterfaceTable,
};
use crate::data_structures::neighbour::{
    Neighbour, NeighbourConfig, NeighbourIndex, NeighbourTable,
};
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::route_table::METRIC_DIFFERENCE_THRESHOLD;
use crate::data_structures::route::{Route, RouteTable};
use crate::data_structures::source::{Source, SourceTable};
use crate::data_structures::updates::{Update, UpdateTable};
use crate::data_types::{Address, RouterId};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::router::config::BabelRouterConfig;
use crate::utils::{Instant, InternallyKeyed, ManagedSlice, Timer};

pub mod config;
pub mod handle_input;
pub mod poll_output;

pub struct BabelRouter<'storage, P = NoStateExtension, A = NoExtension>
where
    P: ParserStateExt,
    A: AddressExt,
{
    /// Router ID of this Babel router. This must be globally unique within your routing domain.
    pub(crate) id: RouterId,

    pub(crate) magic_number: u8,

    pub(crate) version_number: u8,

    pub(crate) iface_table: InterfaceTable<'storage, A>,

    pub(crate) neighbor_table: NeighbourTable<'storage, A>,

    pub(crate) pending_seqno: PendingSeqnoRequestTable<'storage, A>,

    pub(crate) route_table: RouteTable<'storage, A>,

    pub(crate) source_table: SourceTable<'storage, A>,

    // Implementation config
    pub(crate) update_table: UpdateTable<'storage, A>,

    pub(crate) update_timer: Timer,

    pub(crate) route_selection_due: bool,

    // Extension markers
    _state_ext_marker: PhantomData<P>,
    _addr_ext_marker: PhantomData<A>,
}

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Create a new Babel Router from config.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new(now: Instant, config: BabelRouterConfig) -> Result<Self, BabelError<A>> {
        use alloc::vec::Vec;
        Self::new_with_storage_inner(
            now,
            config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// Create a new Babel Router with user provided, statically sized storage.
    pub fn new_with_storage(
        now: Instant,
        config: BabelRouterConfig,
        storage: BorrowedMemoryPool<'storage, A>,
    ) -> Result<Self, BabelError<A>> {
        Self::new_with_storage_inner(
            now,
            config,
            storage.interface_table,
            storage.neighbour_table,
            storage.pending_seqno_table,
            storage.route_table,
            storage.source_table,
            storage.update_table,
        )
    }

    fn new_with_storage_inner<IF, N, PS, R, S, U>(
        now: Instant,
        config: BabelRouterConfig,
        interface_table: IF,
        neighbour_table: N,
        pending_seqno_table: PS,
        route_table: R,
        source_table: S,
        update_table: U,
    ) -> Result<Self, BabelError<A>>
    where
        IF: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
        N: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
        PS: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
        R: Into<ManagedSlice<'storage, Option<Route<A>>>>,
        S: Into<ManagedSlice<'storage, Option<Source<A>>>>,
        U: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Ok(Self {
            id: config.id,
            magic_number: config.magic_number,
            version_number: config.version,
            iface_table: InterfaceTable::new_with_storage(interface_table),
            neighbor_table: NeighbourTable::new_with_storage(neighbour_table),
            pending_seqno: PendingSeqnoRequestTable::new_with_storage(pending_seqno_table),
            route_table: RouteTable::new_with_storage(route_table, config.route_expiry_multiplier),
            source_table: SourceTable::new_with_storage(source_table),
            update_table: UpdateTable::new_with_storage(update_table),
            update_timer: Timer::from_interval(now, config.update_interval)?,
            route_selection_due: false,
            _state_ext_marker: PhantomData,
            _addr_ext_marker: PhantomData,
        })
    }

    /// Register a new interface with the router.
    ///
    /// The returned handle will be used to refer to the real interface that packets will be sent
    /// and receieved on.
    pub fn register_interface(
        &mut self,
        now: Instant,
        config: InterfaceConfig<A>,
    ) -> Result<InterfaceHandle, BabelError<A>>
    where
        A: AddressExt,
    {
        Ok(self.iface_table.register_interface(now, config)?)
    }

    /// Add a new neighbour to the router.
    ///
    /// Babel is designed to discover neighbours through multicast hello TLVs. But it allows for
    /// neighbours to be discovered through methods outside of the routing protocol. If there is
    /// some out of band method for neighbour discovery in your application, this is where you will
    /// tell the router about the existance of the neighbour.
    ///
    /// Once the neighbour has been added through this method, it must still conform to the spec to
    /// stay in the neighbour table. If it does not receive any hellos, it will eventually be
    /// removed from the neighbour table.
    pub fn add_neighbour(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
    ) -> Result<(), BabelError<A>> {
        // If the interface doesn't exist then the neighbour can't be created.
        let Some(iface) = self.iface_table.inner.get_by_key(&interface) else {
            return Err(BabelError::InterfaceDoesntExist(interface));
        };

        let config = NeighbourConfig::interface_default(address, iface);

        Ok(self.neighbor_table.add_neighbour(now, config)?)
    }

    pub(crate) fn update_metrics_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour_idx: NeighbourIndex<A>,
    ) -> Result<(), BabelError<A>> {
        let Some(neighbour) = self.neighbor_table.inner.get_by_key(&neighbour_idx) else {
            b_debug!("Cannot update metrics for non-existant neighbour.");
            return Ok(());
        };
        let smoothing_mul = self.route_table.smoothing_multiple;
        for route in self
            .route_table
            .inner
            .iter_mut()
            .filter(|r| r.neigbour() == &neighbour_idx)
        {
            let old_computed = *route.computed_metric();
            route.compute_metric(now, interface, neighbour, &smoothing_mul);

            // Every route over this neighbour has its metric recomputed, but only the selected one
            // can be worth relaying. 3.7.2 scopes the significant-metric trigger to the route that
            // holds its destination: an unselected route was never advertised onwards, so no
            // neighbour is holding a belief about it that the move would correct.
            if route.selected
                && route.computed_metric().abs_diff(old_computed) > METRIC_DIFFERENCE_THRESHOLD
            {
                self.update_table.broadcast_route_update(
                    now,
                    &self.iface_table,
                    &self.neighbor_table,
                    route.key(),
                    None,
                )?;
            }
        }
        Ok(())
    }
}
