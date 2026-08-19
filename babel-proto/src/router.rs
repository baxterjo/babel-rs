use core::marker::PhantomData;

use managed::ManagedSlice;

use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex};
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::{Route, RouteTable};
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
use crate::packet::tlv::reader::TlvReader;
use crate::packet::tlv::{HelloSlice, IhuSlice, TypedTlv};
use crate::utils::{Duration, Instant};
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
    /// Router ID of this Babel router. This must be globally unique within your routing domain.
    id: RouterId,

    iface_table: InterfaceTable<'storage>,

    neighbor_table: NeighbourTable<'storage, A>,

    pending_seqno: PendingSeqnoRequestTable<'storage, A>,

    route_table: RouteTable<'storage, A>,

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
        IF: Into<ManagedSlice<'storage, Option<Interface>>>,
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
    pub fn register_interface<I, HI, UI>(
        &mut self,
        name: &'static str,
        id: I,
        hello_interval: Option<HI>,
        update_interval: Option<UI>,
    ) -> Result<InterfaceHandle, BabelError<A>>
    where
        I: InterfaceId,
        HI: Into<Interval>,
        UI: Into<Interval>,
    {
        Ok(self
            .iface_table
            .register_interface(name, id, hello_interval, update_interval)?)
    }

    /// Add a new neighbour to the router.
    ///
    /// Babel is designed to discover neighbours through multicast hello TLVs. But it allows for
    /// neighbours to be discovered through methods outside of the routing protocol. If there is
    /// some out of band method for neighbour discovery in your application, this is where you will
    /// tell the router about the existance of the neighbour.
    ///
    /// Once the neighbour has been added, it must still conform to the spec to stay in the
    /// neighbour table. If it has not been seen or heard from in a while it will automatically be
    /// removed from the neighbour table.
    pub fn add_neighbour(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ucast_hello_interval: Option<Duration>,
    ) -> Result<(), BabelError<A>> {
        Ok(self.neighbor_table.add_neighbour(
            now,
            &NeighbourIndex(interface, address),
            ucast_hello_interval.map(Interval::from),
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

    pub fn handle_input<'input>(
        &mut self,
        now: Instant,
        input: Receive<'input, A>,
    ) -> Result<(), BabelError<A>> {
        b_trace!("{:?}", input);
        let _parser: Parser<P> = Parser::default();
        let packet = PacketSlice::from_slice(input.contents)?;
        b_trace!("{:?}", packet);

        let magic = packet.magic();
        if magic != MN {
            return Err(BabelError::IncorrectMagicNumber {
                expected: MN,
                received: magic,
            });
        }

        let version = packet.version();
        if version != V {
            return Err(BabelError::IncorrectVersionNumber {
                expected: V,
                received: version,
            });
        }

        for tlv_result in TlvReader::new(packet.body()) {
            let tlv = ok_or_continue!(tlv_result);
            b_trace!("{:?}", tlv);
            match tlv.r#type() {
                HelloSlice::TYPE_ID => {
                    let hello = ok_or_continue!(HelloSlice::from_untyped(tlv));
                    b_debug!("{:?}", hello);
                    self.handle_hello(now, input.iface, input.source_addr, hello)?;
                }
                IhuSlice::TYPE_ID => {
                    let ihu = ok_or_continue!(IhuSlice::from_untyped(tlv));
                    b_debug!("{:?}", ihu);
                    self.handle_ihu(now, input.iface, input.source_addr, ihu)?;
                }
                other => {
                    unimplemented!("Unimplemented TLV found, Type: {}", other);
                }
            }
        }

        Ok(())
    }

    fn handle_hello(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        self.neighbor_table
            .handle_hello(now, interface, address, hello)?;
        Ok(())
    }

    fn handle_ihu(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ihu: IhuSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        self.neighbor_table
            .handle_ihu(now, interface, address, ihu)?;
        Ok(())
    }

    //  _____   ____  _      _         ____  _    _ _______ _____  _    _ _______
    // |  __ \ / __ \| |    | |       / __ \| |  | |__   __|  __ \| |  | |__   __|
    // | |__) | |  | | |    | |      | |  | | |  | |  | |  | |__) | |  | |  | |
    // |  ___/| |  | | |    | |      | |  | | |  | |  | |  |  ___/| |  | |  | |
    // | |    | |__| | |____| |____  | |__| | |__| |  | |  | |    | |__| |  | |
    // |_|     \____/|______|______|  \____/ \____/   |_|  |_|     \____/   |_|
}
