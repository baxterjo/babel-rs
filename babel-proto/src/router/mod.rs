use core::marker::PhantomData;

use crate::BorrowedMemoryPool;
use crate::data_structures::interface::{
    Interface, InterfaceConfig, InterfaceHandle, InterfaceTable,
};
use crate::data_structures::neighbour::{
    Neighbour, NeighbourConfig, NeighbourIndex, NeighbourTable,
};
use crate::data_structures::originated_route::originated_route_entry::{
    OriginatedRoute, OriginatedRouteIndex,
};
use crate::data_structures::originated_route::originated_route_table::OriginatedRouteTable;
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::{Route, RouteTable};
use crate::data_structures::source::{Source, SourceTable};
use crate::data_structures::updates::{Update, UpdateQueue};
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, RouterId};
use crate::data_views::{AllRoutes, Selection};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::metric::Metric;
use crate::router::config::BabelRouterConfig;
use crate::utils::{Instant, ManagedSlice, Timer};

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

    pub(crate) route_seqno: SeqNo,

    // Tables
    pub(crate) iface_table: InterfaceTable<'storage, A>,

    pub(crate) neighbor_table: NeighbourTable<'storage, A>,

    pub(crate) pending_seqno: PendingSeqnoRequestTable<'storage, A>,

    pub(crate) route_table: RouteTable<'storage, A>,

    pub(crate) source_table: SourceTable<'storage, A>,

    pub(crate) update_queue: UpdateQueue<'storage, A>,

    pub(crate) originated_routes: OriginatedRouteTable<'storage, A>,

    // Router state
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
    pub fn new(now: Instant, config: BabelRouterConfig) -> Self {
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
            Vec::new(),
        )
    }

    /// Create a new Babel Router with user provided, statically sized storage.
    pub fn new_with_storage(
        now: Instant,
        config: BabelRouterConfig,
        storage: BorrowedMemoryPool<'storage, A>,
    ) -> Self {
        Self::new_with_storage_inner(
            now,
            config,
            storage.interface_table,
            storage.neighbour_table,
            storage.pending_seqno_table,
            storage.route_table,
            storage.source_table,
            storage.update_queue,
            storage.originated_routes,
        )
    }

    fn new_with_storage_inner<IF, N, PS, R, S, U, OR>(
        now: Instant,
        config: BabelRouterConfig,
        interface_table: IF,
        neighbour_table: N,
        pending_seqno_table: PS,
        route_table: R,
        source_table: S,
        update_queue: U,
        originated_routes: OR,
    ) -> Self
    where
        IF: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
        N: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
        PS: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
        R: Into<ManagedSlice<'storage, Option<Route<A>>>>,
        S: Into<ManagedSlice<'storage, Option<Source<A>>>>,
        U: Into<ManagedSlice<'storage, Option<Update<A>>>>,
        OR: Into<ManagedSlice<'storage, Option<OriginatedRoute<A>>>>,
    {
        Self {
            id: config.id,
            magic_number: config.magic_number,
            version_number: config.version,
            route_seqno: SeqNo(config.starting_seqno),
            iface_table: InterfaceTable::new_with_storage(interface_table),
            neighbor_table: NeighbourTable::new_with_storage(neighbour_table),
            pending_seqno: PendingSeqnoRequestTable::new_with_storage(pending_seqno_table),
            route_table: RouteTable::new_with_storage(route_table, config.route_expiry_multiplier),
            source_table: SourceTable::new_with_storage(source_table),
            update_queue: UpdateQueue::new_with_storage(update_queue),
            originated_routes: OriginatedRouteTable::new_with_storage(originated_routes),
            route_selection_due: false,
            _state_ext_marker: PhantomData,
            _addr_ext_marker: PhantomData,
        }
    }

    pub fn route_seqno(&self) -> u16 {
        self.route_seqno.0
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

    /// Inserts a self originated route into the protocol.
    ///
    /// This route has no expiration, the metric must be maintained by the user.
    pub fn originate_route(
        &mut self,
        now: Instant,
        route: OriginatedRouteIndex<A>,
        metric: Metric,
    ) -> Result<(), BabelError<A>> {
        if metric.is_infinite() {
            self.remove_originated_route(now, route);
            return Ok(());
        }

        if let Some(old_route) = self.originated_routes.inner.get_mut_by_key(&route) {
            old_route.metric = metric;
            return Ok(());
        }
        self.originated_routes.insert_route(route, metric)?;

        self.route_selection_due = true;

        Ok(())
    }

    /// Removes a self originated route from the protocol.
    pub fn remove_originated_route(&mut self, now: Instant, route: OriginatedRouteIndex<A>) {
        if self.originated_routes.inner.get_by_key(&route).is_none() {
            b_trace!("Tried to remove non-existant route.");
            return;
        }

        self.originated_routes.inner.free(&route);

        self.route_selection_due = true;

        self.update_queue.queue_triggered_update(
            now,
            &route.destination,
            &self.iface_table,
            &self.neighbor_table,
        );
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

    /// Runs metric updates for all of the routes advertised by this neighbour.
    ///
    /// The work is [`RouteTable::update_metrics_for_neighbour`]. This resolves the index its
    /// callers hold to the entry it names, and hands the route table the two tables a triggered
    /// update needs to reach every neighbour on every interface.
    pub(crate) fn update_metrics_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour_idx: NeighbourIndex<A>,
    ) {
        let Some(neighbour) = self.neighbor_table.inner.get_by_key(&neighbour_idx) else {
            b_debug!("Cannot update metrics for non-existant neighbour.");
            return;
        };

        self.route_table.update_metrics_for_neighbour(
            now,
            interface,
            neighbour,
            &self.iface_table,
            &self.neighbor_table,
            &mut self.update_queue,
        )
    }

    /// The recommended route selection procedure as defined in
    /// [Section 3.6](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    /// and [Appendix A.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    ///
    /// Which route wins a destination is decided by [`DestinationGroup::choose`], over originated
    /// and learned routes alike. This method applies each decision and owns its consequences:
    /// publishing the updates triggered as a result of route selection.
    ///
    /// [`DestinationGroup::choose`]: crate::data_views::all_routes::DestinationGroup::choose
    fn select_routes(&mut self, now: Instant) {
        b_debug!("Route selection...");

        let mut all_routes = AllRoutes::new(&mut self.originated_routes, &mut self.route_table);

        for mut group in all_routes.destination_groups_mut() {
            let dest = group.destination();
            b_trace!("{:?} options for {:?}", group.len(), dest);

            let Selection { previous, winner } = group.choose(&self.source_table);

            b_debug!("{:?} -> {:?}", dest, winner);

            // Deselects everything, then switches the winner back on, so a destination that no
            // longer has an eligible route ends up with nothing selected.
            group.select(winner);

            let changed = match (previous, winner) {
                // A new winner has been selected OR a winner has been selected for the first time.
                (previous, Some(winner)) => previous.is_none_or(|(prev, _)| prev != winner),
                // The route that WAS selected has been retracted, and there are now no eligible
                // routes to replace it.
                (Some((_, prev_metric)), None) => prev_metric == Metric::INFINITY,
                // No winner before and no winner now.
                (None, None) => false,
            };

            if changed {
                self.update_queue.queue_triggered_update(
                    now,
                    &dest,
                    &self.iface_table,
                    &self.neighbor_table,
                );
            }
        }
    }
}
