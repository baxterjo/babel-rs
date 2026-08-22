use core::marker::PhantomData;

use managed::ManagedSlice;

use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex};
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::{Route, RouteTable};
use crate::data_structures::{interface::InterfaceTable, neighbour::NeighbourTable};
use crate::data_types::{Address, RouterId};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::input::Receive;
use crate::output::{Output, Transmit, TransmitDestination};
use crate::packet::packet_header::BabelPacketHeader;
use crate::packet::packet_slice::PacketSlice;
use crate::packet::parser::Parser;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::tlv::reader::TlvReader;
use crate::packet::tlv::{HelloSlice, IhuSlice, TypedTlv};
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriter, PacketWriterError, PacketWriterStep};
use crate::utils::storage::ManagedSliceExt;
use crate::utils::{Duration, Instant};

pub mod handle_input;
pub mod poll_output;

pub struct BabelRouter<
    'storage,
    P = NoStateExtension,
    A = NoExtension,
    const MN: u8 = { BabelPacketHeader::MAGIC_NUMBER },
    const V: u8 = { BabelPacketHeader::VERSION_NUMBER },
> where
    P: ParserStateExt,
    A: AddressExt,
{
    /// Router ID of this Babel router. This must be globally unique within your routing domain.
    pub(crate) id: RouterId,

    pub(crate) iface_table: InterfaceTable<'storage, A>,

    pub(crate) neighbor_table: NeighbourTable<'storage, A>,

    pub(crate) pending_seqno: PendingSeqnoRequestTable<'storage, A>,

    pub(crate) route_table: RouteTable<'storage, A>,

    // Extension markers
    _state_ext_marker: PhantomData<P>,
    _addr_ext_marker: PhantomData<A>,
}

impl<'storage, A, P, const MN: u8, const V: u8> BabelRouter<'storage, P, A, MN, V>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Create a new Babel Router with user provided storage.
    ///
    /// Arguments:
    /// `id`: The router ID of this router. This should be globally unique within your routing domain.
    /// `iface_storage`: User provided storage that will be used internally.
    /// `neighbour_storage`: User provided storage that will be used internally.
    /// `pending_seqno_storage`: User provided storage that will be used internally.
    pub fn new_with_storage<IF, N, PS, R>(
        id: RouterId,
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
            id,
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
    /// `id`: The router ID of this router. This should be globally unique within your routing domain.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new(id: RouterId) -> Self {
        Self {
            id,
            iface_table: InterfaceTable::new(),
            neighbor_table: NeighbourTable::new(),
            pending_seqno: PendingSeqnoRequestTable::new(),
            route_table: RouteTable::new(),
            _state_ext_marker: PhantomData,
            _addr_ext_marker: PhantomData,
        }
    }

    /// Register a new interface with the router.
    ///
    /// Arguments:
    ///
    /// * `name`: Human readable name for debugging.
    /// * `id`: Interface ID. This should be unique for each instantiation of the router.
    /// * `hello_interval`: Optional multicast hello interval. `None` will use
    /// [`DEFAULT_MULTICAST_HELLO_INTERVAL_SECS`](crate::data_structures::interface::DEFAULT_MULTICAST_HELLO_INTERVAL_SECS)
    /// * `update_interval`: Optional update interval. `None` will use
    /// [`DEFAULT_UPDATE_INTERVAL_SECS`](crate::data_structures::interface::DEFAULT_UPDATE_INTERVAL_SECS)
    pub fn register_interface<I, IA>(
        &mut self,
        now: Instant,
        id: I,
        address: IA,
        hello_interval: Option<Duration>,
        update_interval: Option<Duration>,
    ) -> Result<InterfaceHandle, BabelError<A>>
    where
        I: Into<InterfaceHandle>,
        IA: Into<Address<A>>,
    {
        let handle = id.into();
        let address = address.into();
        Ok(self.iface_table.register_interface(
            now,
            handle,
            address,
            hello_interval,
            update_interval,
        )?)
    }

    /// Add a new neighbour to the router.
    ///
    /// Babel is designed to discover neighbours through multicast hello TLVs. But it allows for
    /// neighbours to be discovered through methods outside of the routing protocol. If there is
    /// some out of band method for neighbour discovery in your application, this is where you will
    /// tell the router about the existance of the neighbour.
    ///
    /// Once the neighbour has been added, it must still conform to the spec to stay in the
    /// neighbour table. If expiry elapses without getting a hello packet from this neighbour, then
    /// it will be removed from the neigbour table.
    pub fn add_neighbour(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        expiry: Duration,
        ucast_hello_interval: Option<Duration>,
    ) -> Result<(), BabelError<A>> {
        Ok(self.neighbor_table.add_neighbour(
            now,
            &NeighbourIndex(interface, address),
            expiry,
            ucast_hello_interval,
        )?)
    }

    //  _    _          _   _ _____  _      ______
    // | |  | |   /\   | \ | |  __ \| |    |  ____|
    // | |__| |  /  \  |  \| | |  | | |    | |__
    // |  __  | / /\ \ | . ` | |  | | |    |  __|
    // | |  | |/ ____ \| |\  | |__| | |____| |____
    // |_|  |_/_/    \_\_| \_|_____/|______|______|
    //
    //
    //  _____ _   _ _____  _    _ _______
    // |_   _| \ | |  __ \| |  | |__   __|
    //   | | |  \| | |__) | |  | |  | |
    //   | | | . ` |  ___/| |  | |  | |
    //  _| |_| |\  | |    | |__| |  | |
    // |_____|_| \_|_|     \____/   |_|
}
