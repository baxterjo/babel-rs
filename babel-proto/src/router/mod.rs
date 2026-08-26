use core::marker::PhantomData;

use crate::data_structures::interface::{
    Interface, InterfaceConfig, InterfaceHandle, InterfaceTable,
};
use crate::data_structures::neighbour::{Neighbour, NeighbourConfig, NeighbourTable};
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::{Route, RouteTable};
use crate::data_types::{Address, RouterId};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::router::config::BabelRouterConfig;
use crate::utils::{Instant, ManagedSlice, ManagedSliceExt};

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

    // Extension markers
    _state_ext_marker: PhantomData<P>,
    _addr_ext_marker: PhantomData<A>,
}

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Create a new Babel Router with user provided storage.
    ///
    /// Arguments:
    /// `id`: The router ID of this router. This should be globally unique within your routing
    /// domain. `iface_storage`: User provided storage that will be used internally.
    /// `neighbour_storage`: User provided storage that will be used internally.
    /// `pending_seqno_storage`: User provided storage that will be used internally.
    pub fn new_with_storage<IF, N, PS, R>(
        config: BabelRouterConfig,
        iface_storage: IF,
        neighbour_storage: N,
        pending_seqno_storage: PS,
        route_table_storage: R,
    ) -> Self
    where
        IF: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
        N: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
        PS: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
        R: Into<ManagedSlice<'storage, Option<Route<A>>>>,
    {
        Self {
            id: config.id,
            magic_number: config.magic_number,
            version_number: config.version,
            iface_table: InterfaceTable::new_with_storage(iface_storage),
            neighbor_table: NeighbourTable::new_with_storage(neighbour_storage),
            pending_seqno: PendingSeqnoRequestTable::new_with_storage(pending_seqno_storage),
            route_table: RouteTable::new_with_storage(route_table_storage),
            _state_ext_marker: PhantomData,
            _addr_ext_marker: PhantomData,
        }
    }

    /// Create a new Babel Router.
    ///
    /// Arguments:
    /// `id`: The router ID of this router. This should be globally unique within your routing
    /// domain.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new(config: BabelRouterConfig) -> Self {
        Self::new_with_storage(config, Vec::new(), Vec::new(), Vec::new(), Vec::new())
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
}
