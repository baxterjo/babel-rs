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

    /// Polls output from the router.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output(&mut self, now: Instant) -> Result<Output<'_, A>, BabelError<A>> {
        let buf = Vec::new();
        self.poll_output_with_buf(now, buf)
    }

    /// Polls output for the given interface from the router.
    ///
    /// This is a useful optimization if other interfaces are busy. If the returned [`Output`] is
    /// of the `SetTimer` variant. That duration **is not** specific to the provided interface.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output_for_iface(
        &mut self,
        now: Instant,
        iface: InterfaceHandle,
    ) -> Result<Output<'_, A>, BabelError<A>> {
        let buf = Vec::new();
        self.poll_output_inner(now, Some(iface), buf)
    }

    /// Polls output for the router to transmit with a user allocated buffer.
    ///
    /// Ideally the size of this buffer is equal to the MTU of your platform to ensure network
    /// efficiency with packed packets.
    pub fn poll_output_with_buf<'output, B>(
        &mut self,
        now: Instant,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        self.poll_output_inner(now, None, buf)
    }

    /// Polls output for the router to transmit with a user allocated buffer.
    ///
    /// Ideally the size of this buffer is equal to the MTU of your platform to ensure network
    /// efficiency with packed packets.
    ///
    /// This is a useful optimization if other interfaces are busy. If the returned [`Output`] is
    /// of the `SetTimer` variant. That duration **is not** specific to the provided interface.
    pub fn poll_output_for_iface_with_buf<'output, B>(
        &mut self,
        now: Instant,
        iface: InterfaceHandle,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        self.poll_output_inner(now, Some(iface), buf)
    }

    /// Where polling for output takes place.
    ///
    /// If an active interface is given, the poll will skip all other interfaces for polling.
    fn poll_output_inner<'output, B>(
        &mut self,
        now: Instant,
        active_interface: Option<InterfaceHandle>,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        b_debug!(
            "{} polling for output - active_iface: {:?}",
            self.id,
            active_interface
        );
        // If active address ever becomes Some, then it is a unicast packet.
        let mut active_addr: Option<Address<A>> = None;
        let mut active_iface = active_interface;
        let writer = PacketWriter::new_packet(MN, V, buf.into())?;
        let mut next_poll = Duration::from_micros(u64::MAX);

        let body = match self.build_packet_body(
            now,
            &mut active_iface,
            &mut active_addr,
            &mut next_poll,
            writer,
        ) {
            Ok(writer) => writer,
            Err((err, writer)) => {
                b_debug!("Err building packet body: {}", err);
                writer
            }
        };

        let Some(finished_packet) = body.finish_packet()? else {
            return Ok(Output::SetTimer(next_poll));
        };

        let dest = match active_addr {
            Some(addr) => TransmitDestination::Unicast(addr),
            None => TransmitDestination::Multicast,
        };

        let output = Output::Transmit(Transmit {
            iface: active_iface.expect("Somehow built a packet with no interface?"),
            destination: dest,
            contents: finished_packet.into(),
        });

        b_debug!("{} - {:?}", self.id, output);

        Ok(output)
    }

    fn build_packet_body<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_addr: &mut Option<Address<A>>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        b_trace!("Polling for IHUs");
        writer = self.poll_for_due_ihu(now, active_iface, active_addr, next_poll, writer)?;

        if active_addr.is_none() {
            b_trace!("Polling for MCAST Hellos");
            writer = self.poll_for_mcast_hello(now, active_iface, next_poll, writer)?;
        }
        Ok(writer)
    }

    //  ___  ___  _    _      ___ _  _ _   _
    // | _ \/ _ \| |  | |    |_ _| || | | | |
    // |  _/ (_) | |__| |__   | || __ | |_| |
    // |_|  \___/|____|____| |___|_||_|\___/

    fn poll_for_due_ihu<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_addr: &mut Option<Address<A>>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);

        for neigh_opt in self.neighbor_table.iter_mut() {
            // Skip empty slots.
            let Some(neighbour) = neigh_opt else {
                continue;
            };

            // If this neighbour has not yet set it's IHU timer, skip it.
            //
            // This timer is set when a hello is received, neighbours that have not received hellos
            // will expire.
            let Some(ihu_timer) = &mut neighbour.pending.ihu_timer else {
                continue;
            };

            // If there is some time remaining in the timer, update local min and skip it.
            if let Some(remaining) = ihu_timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }

            // If the active interface has been set and is not the interface for this neighbour,
            // skip it.
            if active_iface.is_some_and(|iface| neighbour.iface != iface) {
                continue;
            } else {
                // Otherwise claim the active address (this won't change the iface if it was
                // already set)
                *active_iface = Some(neighbour.iface)
            }

            // If the active address has been claimed and it is not destined for this neighbour
            // then skip.
            if active_addr.is_some_and(|addr| addr != neighbour.address) {
                continue;
            }

            // Get the interface for this neighbour.
            let iface = self
                .iface_table
                .inner
                .get_by_key(&neighbour.iface)
                .expect("Neighbour exists on unregistered interface?");

            // If the active address is none, we need to check some things.
            if active_addr.is_none() {
                // If the interface wants unicast IHUs in this case, we need to check if this is
                // possible.
                if iface.config.unicast_ihu {
                    // If the writer has TLV's there is no way of knowing which neighbour they are
                    // destined for. Skip this neighbour.
                    if writer.has_tlvs() {
                        continue;
                    } else {
                        // Otherwise this neighbour can claim the address.
                        *active_addr = Some(neighbour.address)
                    }
                }
            }

            // If loop execution has made it to this point then the IHU can be written.

            // TODO: Figure out error handling
            let ae: u8 = iface.config.address.encoding().try_into().unwrap();
            let rx_cost = iface.config.starting_rx_cost;
            writer = writer
                .write_ihu(
                    ae,
                    rx_cost,
                    ihu_timer.interval(),
                    iface.config.address.as_wire(),
                )?
                .finish_tlv()?;

            // Once the packet has been written, reset the IHU timer
            ihu_timer.restart(now);
        }

        // Choose the minimum between next poll and local min.
        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }

    //  ___  ___  _    _      __  __  ___   _   ___ _____   _  _ ___ _    _    ___
    // | _ \/ _ \| |  | |    |  \/  |/ __| /_\ / __|_   _| | || | __| |  | |  / _ \
    // |  _/ (_) | |__| |__  | |\/| | (__ / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  \___/|____|____| |_|  |_|\___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    /// Polls for multicast hellos by interface.
    fn poll_for_mcast_hello<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);
        for iface_opt in self.iface_table.iter_mut() {
            // Skip empty spots in the table.
            let Some(iface) = iface_opt else {
                continue;
            };
            b_trace!("Polling {} for mcast hello", iface.handle);

            // If the timer on the interface hello has not fired, get the minimum between it and
            // min_dur.
            if let Some(remaining) = iface.hello_timer.time_remaining(now) {
                b_trace!("{} centis till next mcast hello", remaining.as_centis());
                local_min = local_min.min(remaining);
                continue;
            }

            if active_iface.is_some_and(|active| active != iface.handle) {
                // If active interface is given, skip others.
                continue;
            }

            // The first interface that requires a hello to be sent gets it.
            if iface.hello_timer.is_finished(now) {
                b_trace!(
                    "[SEND] mcast hello - iface: {} - {:?}",
                    iface.handle,
                    iface.hello_seqno
                );
                // Write the hello
                writer = writer
                    .write_hello(
                        HelloFlags::new(false),
                        iface.hello_seqno,
                        iface.hello_timer.interval(),
                    )?
                    .finish_tlv()?;

                // Restart hello timer
                iface.hello_timer.restart(now);
                // Increment the seqno
                iface.hello_seqno += 1;
                // Update the active interface, this will be the same value if it was given.
                *active_iface = Some(iface.handle)
            }
        }

        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }
}
