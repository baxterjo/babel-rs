use core::marker::PhantomData;

use managed::ManagedSlice;

use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::{interface::InterfaceTable, neighbour::NeighbourTable};
use crate::data_types::{Address, Interval, RouterId};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::input::{Input, Receive};
use crate::packet::packet_header::BabelPacketHeader;
use crate::packet::packet_slice::PacketSlice;
use crate::packet::parser::Parser;
use crate::InterfaceId;

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
    id: RouterId,

    iface_table: InterfaceTable<'storage>,

    neighbor_table: NeighbourTable<'storage, A>,

    pending_seqno: PendingSeqnoRequestTable<'storage, A>,

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
    pub fn new_with_storage<IF, N, PS>(
        id: RouterId,
        iface_storage: IF,
        neighbour_storage: N,
        pending_seqno_storage: PS,
    ) -> Self
    where
        IF: Into<ManagedSlice<'storage, Option<Interface>>>,
        N: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
        PS: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
    {
        Self {
            id,
            iface_table: InterfaceTable::new_with_storage(iface_storage),
            neighbor_table: NeighbourTable::new_with_storage(neighbour_storage),
            pending_seqno: PendingSeqnoRequestTable::new_with_storage(pending_seqno_storage),
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
    pub fn register_interface<I, HI, UI>(
        &mut self,
        name: &'static str,
        id: I,
        hello_interval: Option<HI>,
        update_interval: Option<UI>,
    ) -> Result<InterfaceHandle, BabelError>
    where
        I: InterfaceId,
        HI: Into<Interval>,
        UI: Into<Interval>,
    {
        Ok(self
            .iface_table
            .register_interface(name, id, hello_interval, update_interval)?)
    }

    pub fn add_neighbour(&mut self, interface: InterfaceHandle, address: Address<A>) {}

    pub fn handle_input<'input>(&mut self, input: Receive<'input, A>) -> Result<(), BabelError> {
        let parser: Parser<P> = Parser::default();
        let packet = PacketSlice::from_slice(input.contents)?;

        Ok(())
    }
}
