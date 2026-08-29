use super::BabelRouter;
use crate::data_structures::interface::{InterfaceError, InterfaceHandle};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::output::{Output, Transmit};
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriter, PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::{Duration, Instant, ManagedSlice};

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Polls output from the router.
    ///
    /// The returned [`Output`] owns its payload, so it does not borrow from the router and can
    /// outlive this call.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output<'output>(
        &mut self,
        now: Instant,
    ) -> Result<Output<'output, A>, BabelError<A>> {
        let buf = alloc::vec::Vec::new();
        self.poll_output_with_buf(now, buf)
    }

    /// Polls output for the given interface from the router.
    ///
    /// This is a useful optimization if other interfaces are busy. If the returned [`Output`] is
    /// of the `SetTimer` variant, it is specific to the polled interface.
    ///
    /// The returned [`Output`] owns its payload, so it does not borrow from the router and can
    /// outlive this call.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output_for_iface<'output>(
        &mut self,
        now: Instant,
        iface: InterfaceHandle,
    ) -> Result<Output<'output, A>, BabelError<A>> {
        let buf = alloc::vec::Vec::new();
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
    /// of the `SetTimer` variant, it is specific to the polled interface.
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
        poll_only: Option<InterfaceHandle>,
        buf: B,
    ) -> Result<Output<'output, A>, BabelError<A>>
    where
        B: Into<ManagedSlice<'output, u8>>,
    {
        b_debug!(
            "{} polling for output - poll_filter: {:?}",
            self.id,
            poll_only
        );

        let writer = PacketWriter::new_packet(self.magic_number, self.version_number, buf.into())?;

        // Poll the body of the packet.
        let (iface, dest, body) = match self.poll_packet_body(now, poll_only, writer)? {
            // This is the only place where meaningful TLV's can be located, so if the PollEvent
            // returns `Wait` then the router has nothing to do and we can return early.
            PollEvent::Wait(dur) => {
                return Ok(Output::SetTimer(dur));
            }
            // Otherwise we continue building the packet.
            PollEvent::Transmit { iface, dest, body } => (iface, dest, body),
        };

        let finished_packet = body.finish_packet()?;

        let output = Output::Transmit(Transmit {
            iface: iface,
            destination: dest
                .try_into()
                .expect("Somehow built a packet with no destination?"),
            contents: finished_packet.into(),
        });

        b_debug!("{} - {:?}", self.id, output);

        Ok(output)
    }

    /// Polls the router for outgoing TLV's in the packet body.
    fn poll_packet_body<'output>(
        &mut self,
        now: Instant,
        poll_only: Option<InterfaceHandle>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<PollEvent<'output, A>, BabelError<A>> {
        // A router with no interfaces can never send anything and has no timer to report, so
        // polling one is a caller mistake rather than an idle state.
        if self.iface_table.is_empty() {
            return Err(InterfaceError::NoInterfacesRegistered.into());
        }

        // A poll scoped to a handle that was never registered matches no interface, so the loop
        // below would find nothing due.
        if let Some(handle) = poll_only
            && !self.iface_table.contains(&handle)
        {
            return Err(BabelError::InterfaceDoesntExist(handle));
        }

        let mut active_dest = DestAddr::default();
        // The identity for the running minimum below. It can only survive as Duration::MAX if no
        // interface was iterated at all, which the guards above have already ruled out: at
        // least one interface is registered, a scoped poll names one that exists, and every
        // interface contributes its multicast Hello timer on every path that reaches the
        // end of the loop. The check after the loop rejects it if that ever stops holding.
        let mut next_poll = Duration::MAX;
        for interface in self.iface_table.iter_mut(poll_only) {
            /// Macro for writer error handling.
            macro_rules! ok_or_try_send {
                ($result:expr) => {
                    match $result {
                        // If result is ok, keep going
                        Ok(writer) => writer,
                        // If result is a BufferTooSmall error and we know where to send the packet,
                        // log it and return an Ok(PollEvent).
                        Err((PacketWriterError::BufferTooSmall { need, remaining }, writer))
                            if writer.has_tlvs() && !active_dest.is_free() =>
                        {
                            b_trace!(
                                "Err - {}",
                                PacketWriterError::BufferTooSmall { need, remaining }
                            );
                            return Ok(PollEvent::Transmit {
                                iface: interface.handle,
                                dest: active_dest,
                                body: writer,
                            });
                        }
                        // Otherwise the writer is useless and we need to surface the error.
                        Err((err, _writer)) => {
                            return Err(err.into());
                        }
                    }
                };
            }
            // First check for hellos. These are most important for keeping the mesh alive.
            b_trace!("Polling for MCAST Hellos");
            writer = ok_or_try_send!(interface.poll_for_mcast_hello(now, &mut next_poll, writer));

            // If the writer has any TLVs in it at this point then the active destination is
            // multicast.
            if writer.has_tlvs() {
                active_dest
                    .claim(DestAddr::Multicast)
                    .expect("Active destination should be free");
            }

            for neighbour in self
                .neighbor_table
                .neighbours_mut_for_iface(interface.handle)
            {
                // If the active destination is free, poll for ucast hellos.
                if active_dest.is_free() {
                    b_trace!("Polling for UCAST Hellos");
                    writer = ok_or_try_send!(neighbour.poll_for_ucast_hello(
                        now,
                        &mut next_poll,
                        writer
                    ));
                    if writer.has_tlvs() {
                        active_dest
                            .claim(DestAddr::Unicast(neighbour.address))
                            .expect("Active destination should be free.");
                    }
                }

                if active_dest.can_send_ihu(&neighbour.address) {
                    b_trace!("Polling for IHUs");
                    writer = ok_or_try_send!(neighbour.poll_for_ihu(
                        now,
                        &mut active_dest,
                        &mut next_poll,
                        interface.cost_calc,
                        writer,
                    ));
                }
            }
            // Only one interface can be written to at a time. If there are TLVs at this point then
            // its time to send.
            if writer.has_tlvs() {
                return Ok(PollEvent::Transmit {
                    iface: interface.handle,
                    dest: active_dest,
                    body: writer,
                });
            }
        }

        // Ideally this is dead code. But this is a backstop if the logic of output polling changes
        // above.
        if next_poll == Duration::MAX {
            return Err(BabelError::NoWakeUpTime);
        }

        Ok(PollEvent::Wait(next_poll))
    }
}

enum PollEvent<'output, A: AddressExt> {
    Transmit {
        iface: InterfaceHandle,
        dest: DestAddr<A>,
        body: PacketWriterStep<'output, Ready>,
    },
    Wait(Duration),
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::InterfaceConfig;
    use crate::data_structures::neighbour::{Neighbour, NeighbourIndex};
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Address, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::{KOutOfJ, RxCost};
    use crate::output::TransmitDestination;
    use crate::packet::packet_slice::PacketSlice;
    use crate::packet::tlv::{HelloSlice, IhuSlice, Tlv, TypedTlv};
    use crate::router::config::BabelRouterConfig;
    use crate::utils::storage::ManagedSliceExt;

    // Long enough that it never fires again during a test unless a test means it to, but small
    // enough that the IHU interval derived from it (3x, below) still fits the 16-bit Interval
    // field without saturating.
    const IFACE_INTERVAL: Duration = Duration::from_secs(200);

    /// The interval a neighbour on a ucast-Hello interface sends its unicast Hellos at.
    ///
    /// Deliberately the shortest interval here, so a ucast-Hello interface is recognisable by
    /// `SetTimer` reporting this.
    const UCAST_INTERVAL: Duration = Duration::from_secs(20);

    /// The interval a fresh neighbour both advertises in and schedules its outgoing IHUs at:
    /// `DEFAULT_LOSSLESS_IHU_RATIO` (3) times its interface's multicast Hello interval, per
    /// RFC 8966 Appendix B.
    ///
    /// Being a multiple of `IFACE_INTERVAL`, an IHU is never the soonest thing due — the Hello it
    /// is derived from always beats it, and the two coincide exactly when the IHU comes due.
    const IHU_INTERVAL: Duration = Duration::from_secs(600);

    const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    /// The address family Babel normally runs on, and the only one the writer compresses.
    const LINK_LOCAL_NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const LINK_LOCAL_NEIGHBOUR_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_1_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_2_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);

    fn router(name: &'static str) -> BabelRouter<'static> {
        BabelRouter::new(BabelRouterConfig::new(
            RouterId::try_from(name).expect("bad router id"),
        ))
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    /// A wired interface config carrying an interval too long to fire again during a test.
    fn iface_config(name: &str, address: Ipv6Addr) -> InterfaceConfig<NoExtension> {
        let mut config = InterfaceConfig::new_wired(iface_handle(name), address.into());
        config.set_mcast_hello_interval(IFACE_INTERVAL.into());
        config
    }

    /// [`iface_config`], for an interface that also hands every neighbour discovered on it a
    /// unicast Hello interval.
    fn ucast_hello_iface_config(name: &str, address: Ipv6Addr) -> InterfaceConfig<NoExtension> {
        let mut config = iface_config(name, address);
        config.set_ucast_hello_interval(UCAST_INTERVAL.into());
        config
    }

    fn expect_transmit<A: AddressExt>(output: Output<'_, A>) -> Transmit<'_, A> {
        match output {
            Output::Transmit(t) => t,
            Output::SetTimer(d) => panic!("expected Transmit, got SetTimer({d:?})"),
        }
    }

    fn expect_set_timer<A: AddressExt>(output: Output<'_, A>) -> Duration {
        match output {
            Output::SetTimer(d) => d,
            Output::Transmit(t) => panic!("expected SetTimer, got Transmit({t:?})"),
        }
    }

    fn tlv_types(contents: &[u8]) -> Vec<u8> {
        PacketSlice::from_slice(contents)
            .expect("packet should parse")
            .body_reader()
            .map(|tlv| tlv.r#type())
            .collect()
    }

    fn nth_tlv(contents: &[u8], n: usize) -> Tlv<'_> {
        PacketSlice::from_slice(contents)
            .expect("packet should parse")
            .body_reader()
            .nth(n)
            .expect("tlv should exist")
    }

    fn nth_hello(contents: &[u8], n: usize) -> HelloSlice<'_> {
        match nth_tlv(contents, n) {
            Tlv::Hello(hello) => hello,
            other => panic!("should be a hello, got {other:?}"),
        }
    }

    fn nth_ihu(contents: &[u8], n: usize) -> IhuSlice<'_> {
        match nth_tlv(contents, n) {
            Tlv::Ihu(ihu) => ihu,
            other => panic!("should be an ihu, got {other:?}"),
        }
    }

    /// Registers an interface with an interval too long to fire again in a test, then drains its
    /// mandatory eager initial multicast hello so it doesn't pollute later assertions.
    fn drained_iface(
        router: &mut BabelRouter<'static>,
        now: Instant,
        name: &str,
        address: Ipv6Addr,
    ) -> InterfaceHandle {
        drained_iface_with_config(router, now, iface_config(name, address))
    }

    /// [`drained_iface`], for an interface that also sends unicast Hellos.
    fn drained_ucast_hello_iface(
        router: &mut BabelRouter<'static>,
        now: Instant,
        name: &str,
        address: Ipv6Addr,
    ) -> InterfaceHandle {
        drained_iface_with_config(router, now, ucast_hello_iface_config(name, address))
    }

    /// [`drained_iface`] for tests that need to tweak the config before registering.
    fn drained_iface_with_config(
        router: &mut BabelRouter<'static>,
        now: Instant,
        config: InterfaceConfig<NoExtension>,
    ) -> InterfaceHandle {
        let handle = router
            .register_interface(now, config)
            .expect("could not register interface");

        let transmit = expect_transmit(router.poll_output(now).expect("poll should succeed"));
        assert_eq!(
            transmit.iface, handle,
            "expected the mandatory initial hello"
        );

        handle
    }

    /// Borrows a neighbour the router already knows about.
    fn neighbour<'r>(
        router: &'r mut BabelRouter<'static>,
        iface: InterfaceHandle,
        address: Ipv6Addr,
    ) -> &'r mut Neighbour<NoExtension> {
        router
            .neighbor_table
            .inner
            .get_mut_by_key(&NeighbourIndex {
                iface,
                addr: address.into(),
            })
            .expect("neighbour should exist")
    }

    /// Adds a neighbour and drains the immediate IHU every new neighbour is born owing, so that
    /// IHU does not pollute assertions about unrelated TLVs.
    ///
    /// A neighbour on an interface that sends unicast Hellos is *also* born owing one of those,
    /// which stays live here.
    fn drained_ihu_neighbour(
        router: &mut BabelRouter<'static>,
        now: Instant,
        iface: InterfaceHandle,
        address: Ipv6Addr,
    ) {
        router
            .add_neighbour(now, iface, address.into())
            .expect("add_neighbour should succeed");
        neighbour(router, iface, address)
            .pending
            .outbound_ihu_timer
            .restart(now);
    }

    //  __  __  ___    _   ___ _____   _  _ ___ _    _    ___
    // |  \/  |/ __|  /_\ / __|_   _| | || | __| |  | |  / _ \
    // | |\/| | (__  / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  |_|\___|/_/ \_\___/ |_|   |_||_|___|____|____\___/

    mod mcast_hello {
        use alloc::vec;

        use super::*;

        #[test]
        fn fires_immediately_on_first_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle = r
                .register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));

            assert_eq!(transmit.iface, handle);
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            let hello = nth_hello(&transmit.contents, 0);
            assert!(hello.flags().is_multicast());
            assert_eq!(hello.seqno(), SeqNo(0));
            assert_eq!(hello.interval(), IFACE_INTERVAL.into());
        }

        #[test]
        fn not_due_after_firing_returns_set_timer_with_remaining() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            drained_iface(&mut r, t0, "iface_1", NODE_ADDR);

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn refires_after_interval_with_incremented_seqno() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);

            let t1 = t0 + IFACE_INTERVAL;
            let transmit = expect_transmit(r.poll_output(t1).expect("poll should succeed"));
            assert_eq!(transmit.iface, handle);

            let hello = nth_hello(&transmit.contents, 0);
            assert_eq!(hello.seqno(), SeqNo(1));
        }

        #[test]
        fn only_one_interface_fires_per_poll_others_drained_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle_a = r
                .register_interface(t0, iface_config("iface_a", NODE_ADDR))
                .expect("register should succeed");
            let handle_b = r
                .register_interface(t0, iface_config("iface_b", NEIGHBOUR_1_ADDR))
                .expect("register should succeed");

            let first = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(first.iface, handle_a);

            let second = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(second.iface, handle_b);

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn for_iface_scoped_poll_ignores_other_due_interfaces() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle_a = r
                .register_interface(t0, iface_config("iface_a", NODE_ADDR))
                .expect("register should succeed");
            let handle_b = r
                .register_interface(t0, iface_config("iface_b", NEIGHBOUR_1_ADDR))
                .expect("register should succeed");

            // iface_a is due too, but scoping to iface_b must still find and fire iface_b's hello.
            let transmit = expect_transmit(
                r.poll_output_for_iface(t0, handle_b)
                    .expect("poll should succeed"),
            );
            assert_eq!(transmit.iface, handle_b);

            // iface_a was left completely untouched by the scoped poll.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.iface, handle_a);
        }
    }

    //  _   _  ___ _   ___ _____   _  _ ___ _    _    ___
    // | | | |/ __/_\ / __|_   _| | || | __| |  | |  / _ \
    // | |_| | (_/ _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    //  \___/ \___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    mod ucast_hello {
        use alloc::vec;

        use super::*;

        /// The interval is carried by the interface, so a neighbour on an interface that never
        /// configured one has no unicast Hello state at all to fire.
        #[test]
        fn not_configured_never_sent() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_ihu_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            assert!(
                neighbour(&mut r, iface, NEIGHBOUR_1_ADDR)
                    .pending
                    .ucast_hello
                    .is_none()
            );

            // Nothing is left to send, and with no unicast Hello in the mix the soonest thing
            // scheduled is the interface's own multicast Hello.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        /// Like an interface's multicast Hello timer, a fresh unicast Hello timer is eager: it
        /// fires on the very first poll rather than making a brand new neighbour wait a full
        /// interval to hear from us.
        #[test]
        fn fires_eagerly_on_the_first_poll_with_correct_fields() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_hello_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_ihu_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));

            assert_eq!(transmit.iface, iface);
            let expected_dest: Address<_> = NEIGHBOUR_1_ADDR.into();
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(expected_dest)
            );
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            let hello = nth_hello(&transmit.contents, 0);
            assert!(hello.flags().is_unicast());
            assert_eq!(hello.seqno(), SeqNo(0));
            assert_eq!(hello.interval(), UCAST_INTERVAL.into());

            // The timer restarted, so an immediate repoll does not refire it — it just reports
            // the full interval it is now waiting out, still the soonest thing scheduled.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn refires_after_its_interval_with_incremented_seqno() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_hello_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_ihu_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            // Drain the eager first Hello with a real poll, so the seqno this test is about
            // actually advances — only a successful write increments it.
            let first = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(nth_hello(&first.contents, 0).seqno(), SeqNo(0));

            // The unicast Hello is the only thing due this early — the interface's Hello and the
            // neighbour's IHU are both far out — so it goes out alone.
            let t1 = t0 + UCAST_INTERVAL;
            let transmit = expect_transmit(r.poll_output(t1).expect("poll should succeed"));

            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            let hello = nth_hello(&transmit.contents, 0);
            assert!(hello.flags().is_unicast());
            assert_eq!(hello.seqno(), SeqNo(1));
        }

        #[test]
        fn conflicting_destination_defers_to_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_hello_iface(&mut r, t0, "iface_1", NODE_ADDR);
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                drained_ihu_neighbour(&mut r, t0, iface, addr);
            }

            // Both neighbours are owed an eager unicast Hello, but a packet only carries one
            // destination, so the second one waits.
            let first = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                first.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );

            let second = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                second.destination,
                TransmitDestination::Unicast(NEIGHBOUR_2_ADDR.into())
            );

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn iface_mismatch_skips_for_scoped_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface_a = drained_ucast_hello_iface(&mut r, t0, "iface_a", NODE_ADDR);
            let iface_b = drained_iface(&mut r, t0, "iface_b", NEIGHBOUR_2_ADDR);
            drained_ihu_neighbour(&mut r, t0, iface_a, NEIGHBOUR_1_ADDR);

            // Scoping to iface_b must not fire iface_a's due ucast hello.
            let remaining = expect_set_timer(
                r.poll_output_for_iface(t0, iface_b)
                    .expect("poll should succeed"),
            );
            assert_eq!(remaining, IFACE_INTERVAL);

            // It's still there, untouched, for an unrestricted poll.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.iface, iface_a);
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
        }
    }

    //  ___ _  _ _   _
    // |_ _| || | | | |
    //  | || __ | |_| |
    // |___|_||_|\___/

    mod ihu {
        use alloc::vec;

        use super::*;

        /// Every new neighbour is born owing an immediate IHU: waiting a full interval before
        /// telling a neighbour we can hear it delays convergence for no reason.
        #[test]
        fn a_new_neighbour_is_sent_an_immediate_ihu() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
        }

        #[test]
        fn fires_multicast_with_correct_fields_and_restarts_the_timer() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu = nth_ihu(&transmit.contents, 0);
            assert_eq!(
                ihu.ae(),
                2,
                "the neighbour's address is a non-link-local IPv6 address"
            );
            // The rx cost is what we tell the neighbour it costs to reach *us*, and this
            // neighbour was added out of band: we have never heard a Hello from it, so its Hello
            // history is empty and `KOutOfJ` rightly calls the link down.
            assert_eq!(
                ihu.rx_cost(),
                RxCost::INFINITY,
                "a neighbour we have never heard from cannot be advertised as reachable"
            );
            assert_eq!(ihu.interval(), IHU_INTERVAL.into());
            // The Address field names the IHU's destination — the neighbour it is for — so that
            // receivers can pick their own out of an aggregated multicast packet.
            assert_eq!(
                ihu.address(16).expect("should have a 16 byte address"),
                Address::<NoExtension>::from(NEIGHBOUR_1_ADDR).as_wire()
            );

            // The timer was restarted by the successful write, so an immediate repoll doesn't
            // refire it and the interface's Hello — a third of the IHU interval — is what's next.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        /// The other half of the rx cost path: once enough Hellos have landed for `KOutOfJ` to
        /// call the link up, that finite cost is what goes out on the wire. A neighbour cannot
        /// compute a route through us until it hears one.
        #[test]
        fn rx_cost_reports_the_link_cost_once_the_hello_history_fills() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            // Left eager, so the IHU goes out on this poll rather than a whole interval later,
            // by which point the interface's Hello would be sharing the packet.
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            // `KOutOfJ::SPEC` wants 2 of the last 3 Hellos; give it 3.
            neighbour(&mut r, iface, NEIGHBOUR_1_ADDR)
                .mcast_hello_info
                .history
                .record_many(true, 3);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu = nth_ihu(&transmit.contents, 0);
            assert_eq!(ihu.rx_cost(), RxCost::from_raw(KOutOfJ::SPEC_CONST));
        }

        /// RFC 8966 3.4.2 has a neighbour let its txcost expire to infinity once it stops hearing
        /// IHUs, which only stays correct while we keep sending them on a cadence.
        #[test]
        fn refires_after_its_interval_elapses() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_ihu_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            // Not yet due, so nothing is sent. The interface's Hello is nearer than the IHU and
            // wins the wake-up — the IHU losing that race is inherent in deriving it as a
            // multiple of the Hello interval.
            let remaining = expect_set_timer(
                r.poll_output(t0 + IFACE_INTERVAL / 2)
                    .expect("poll should succeed"),
            );
            assert_eq!(remaining, IFACE_INTERVAL / 2);

            // At three Hello intervals the IHU is due again, and the Hello it rode in on is due
            // with it, so the two go out together exactly as they did on the first poll.
            let transmit = expect_transmit(
                r.poll_output(t0 + IHU_INTERVAL)
                    .expect("poll should succeed"),
            );
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![HelloSlice::TYPE_ID, IhuSlice::TYPE_ID]
            );
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
        }

        /// AE=3 declares an 8-byte address, so the IHU has to carry exactly the 8-byte suffix.
        /// Writing fewer bytes than the encoding advertises desynchronises the receiver for the
        /// address itself and for every sub-TLV behind it, and link-local is the common
        /// deployment path rather than an edge case.
        #[test]
        fn link_local_neighbour_address_is_sent_as_eight_bytes_with_ae_3() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", LINK_LOCAL_NODE_ADDR);
            r.add_neighbour(t0, iface, LINK_LOCAL_NEIGHBOUR_ADDR.into())
                .expect("add_neighbour should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu = nth_ihu(&transmit.contents, 0);
            assert_eq!(ihu.ae(), 3, "fe80::/64 uses the link-local encoding");
            assert_eq!(
                ihu.address(8).expect("should have an 8 byte address"),
                &[0, 0, 0, 0, 0, 0, 0, 2]
            );

            // The IHU is self-terminating: if the address were written short, the declared TLV
            // length would no longer line up with where the address ends.
            assert!(
                ihu.sub_tlvs(8)
                    .expect("sub-tlv region should resolve")
                    .is_empty(),
                "the address should consume the rest of the TLV body"
            );
        }

        /// Naming the destination in the Address field is what lets one multicast packet carry an
        /// IHU for every neighbour on the interface, each receiver picking out its own.
        #[test]
        fn every_due_neighbour_aggregates_into_one_multicast_packet() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                r.add_neighbour(t0, iface, addr.into())
                    .expect("add_neighbour should succeed");
            }

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![IhuSlice::TYPE_ID, IhuSlice::TYPE_ID]
            );

            for (idx, addr) in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR].into_iter().enumerate() {
                let ihu = nth_ihu(&transmit.contents, idx);
                assert_eq!(
                    ihu.address(16).expect("should have a 16 byte address"),
                    Address::<NoExtension>::from(addr).as_wire(),
                    "each IHU should name the neighbour it is for"
                );
            }

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        /// An IHU only *prefers* multicast: when a unicast Hello has already claimed the packet
        /// for this same neighbour, the IHU rides along rather than being deferred a poll.
        #[test]
        fn rides_along_on_a_packet_a_ucast_hello_already_claimed() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_hello_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![HelloSlice::TYPE_ID, IhuSlice::TYPE_ID]
            );

            // The packet is already addressed to this one neighbour, so the IHU is unambiguous
            // without an Address field and drops it (RFC 8966 4.6.6).
            let ihu = nth_ihu(&transmit.contents, 1);
            assert_eq!(ihu.ae(), 0, "a unicast IHU needs no explicit destination");
            assert!(
                ihu.address(0)
                    .expect("wildcard carries no address")
                    .is_empty(),
                "no address bytes should follow the header"
            );
            // 4 byte packet header, an 8 byte hello, and a 8 byte IHU carrying no address.
            assert_eq!(transmit.contents.len(), 20);
        }

        #[test]
        fn iface_scoped_poll_is_independent_per_interface() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface_a = drained_iface(&mut r, t0, "iface_a", NODE_ADDR);
            let iface_b = drained_iface(&mut r, t0, "iface_b", NEIGHBOUR_2_ADDR);
            r.add_neighbour(t0, iface_a, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            let remaining = expect_set_timer(
                r.poll_output_for_iface(t0, iface_b)
                    .expect("poll should succeed"),
            );
            assert_eq!(remaining, IFACE_INTERVAL);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.iface, iface_a);
        }
    }

    //  ___ _  _ _____ ___ ___ ___    _ _____ ___ ___  _  _
    // |_ _| \| |_   _| __/ __| _ \  /_\_   _|_ _/ _ \| \| |
    //  | || .` | | | | _| (_ |   / / _ \| |  | | (_) | .` |
    // |___|_|\_| |_| |___\___|_|_\/_/ \_\_| |___\___/|_|\_|

    mod integration {
        use alloc::vec;

        use super::*;

        /// A multicast Hello and an IHU have compatible destinations, so a fresh interface with a
        /// fresh neighbour empties both of its eager timers in a single packet.
        #[test]
        fn mcast_hello_and_ihu_bundle_into_one_multicast_packet() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            // Not pre-drained: the interface's mcast hello is eager-due at the same time as the
            // new neighbour's immediate IHU.
            let iface = r
                .register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![HelloSlice::TYPE_ID, IhuSlice::TYPE_ID]
            );
            assert!(nth_hello(&transmit.contents, 0).flags().is_multicast());

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        /// Every other test registers its interface and its neighbours at the same instant, which
        /// leaves the Hello and IHU timers phase-locked: the IHU interval is a whole multiple of
        /// the Hello interval, so the two always come due together and the IHU's remaining time
        /// is never strictly the soonest. A neighbour discovered mid-cycle breaks that lock, and
        /// then the IHU really can be what the router next needs waking for.
        #[test]
        fn a_desynchronised_ihu_can_be_the_soonest_thing_due() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            let at = |secs| t0 + Duration::from_secs(secs);

            // Discovered three quarters of the way through the Hello cycle, so this neighbour's
            // IHU ends up 150s out of phase with the Hello interval it is derived from.
            r.add_neighbour(at(150), iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");
            let transmit = expect_transmit(r.poll_output(at(150)).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
            // The IHU is now due at 750s.

            // Drain the Hellos at 200, 400 and 600 so none of them is sitting overdue.
            for secs in [200, 400, 600] {
                let transmit =
                    expect_transmit(r.poll_output(at(secs)).expect("poll should succeed"));
                assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);
            }
            // The Hello is now due at 800s, a full 50s behind the IHU.

            let remaining = expect_set_timer(r.poll_output(at(740)).expect("poll should succeed"));
            assert_eq!(
                remaining,
                Duration::from_secs(10),
                "the IHU at 750s is nearer than the Hello at 800s"
            );
        }

        /// The multicast Hello is polled before any neighbour, so when both kinds of Hello are
        /// eager-due at once the multicast one claims the packet and the unicast one waits — but
        /// only for a poll, since its timer is never touched by the pass that skipped it.
        #[test]
        fn mcast_hello_claims_the_packet_and_the_ucast_hello_follows_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            // Neither is pre-drained, so the interface's mcast hello, the neighbour's ucast hello
            // and the neighbour's immediate IHU are all due on this first poll.
            let iface = r
                .register_interface(t0, ucast_hello_iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            // Pass 1: the mcast hello claims multicast, which the IHU is happy to share and the
            // ucast hello is not.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![HelloSlice::TYPE_ID, IhuSlice::TYPE_ID]
            );

            // Pass 2, same `now`: the ucast hello's timer was never touched, so it fires on the
            // very next poll with a fresh, unclaimed destination.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);
            assert!(nth_hello(&transmit.contents, 0).flags().is_unicast());
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );

            // Pass 3: everything drained.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn oversized_borrowed_buffer_is_trimmed_to_the_bytes_written() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            r.register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");

            // Far bigger than the eager mcast hello needs, so any untrimmed slack shows up as
            // trailing zeros in the transmitted contents.
            let mut buf = [0u8; 256];
            let transmit = expect_transmit(
                r.poll_output_with_buf(t0, &mut buf[..])
                    .expect("poll should succeed"),
            );

            // 4 byte packet header + 2 byte TLV header + 6 byte hello body.
            assert_eq!(transmit.contents.len(), 12);
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);
        }

        /// With nothing written yet there is no destination to send to and no partial packet worth
        /// salvaging, so the writer is useless and the error is surfaced rather than swallowed
        /// into a `SetTimer` the caller would keep retrying against the same too-small buffer.
        #[test]
        fn buffer_too_small_for_even_one_tlv_is_an_error() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            r.register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");

            // 4 bytes is exactly the packet header, leaving 0 remaining for any TLV.
            let mut buf = [0u8; 4];
            let err = r
                .poll_output_with_buf(t0, &mut buf[..])
                .expect_err("a buffer that cannot hold one TLV should be rejected");

            assert!(matches!(
                err,
                BabelError::PacketWriter(PacketWriterError::BufferTooSmall { .. })
            ));
        }

        /// Once the packet has a destination, a buffer that fills mid-body is not a failure: the
        /// TLVs that fit go out now and the one that didn't stays due, because only a successful
        /// write restarts the timer behind it.
        #[test]
        fn a_buffer_that_fills_mid_packet_sends_what_fits_and_defers_the_rest() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = r
                .register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
                .expect("add_neighbour should succeed");

            // 4 byte packet header + 2 byte TLV header + 6 byte hello body, and not one byte more
            // for the IHU that would otherwise bundle in behind it.
            let mut buf = [0u8; 12];
            let transmit = expect_transmit(
                r.poll_output_with_buf(t0, &mut buf[..])
                    .expect("poll should succeed"),
            );
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            // The IHU was never written, so it is still owed on the next poll.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
        }

        /// Scoping a poll to a handle that was never registered matches no interface. Answering
        /// with a timer would be indistinguishable from a genuinely idle interface, so the bad
        /// handle would go unnoticed while the router's real interfaces went unpolled.
        #[test]
        fn scoped_poll_for_an_unregistered_iface_is_an_error() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let real = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            let ghost = iface_handle("ghost");

            let err = r
                .poll_output_for_iface(t0, ghost)
                .expect_err("an unregistered handle should be rejected");

            assert!(matches!(
                err,
                BabelError::InterfaceDoesntExist(handle) if handle == ghost
            ));

            // The registered interface is untouched and still pollable.
            let remaining = expect_set_timer(
                r.poll_output_for_iface(t0, real)
                    .expect("poll should succeed"),
            );
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        /// A router with no interfaces can never send anything and has no timer to report, so
        /// polling one is a caller mistake rather than an idle state. Rejecting it here is what
        /// lets `poll_output` promise a real `Duration`: every registered interface contributes
        /// its multicast Hello timer, so once one exists there is always something to report.
        #[test]
        fn polling_a_router_with_no_interfaces_is_an_error() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);

            let err = r
                .poll_output(t0)
                .expect_err("a router with no interfaces should be rejected");

            assert!(matches!(
                err,
                BabelError::Interface(InterfaceError::NoInterfacesRegistered)
            ));
        }

        /// The same guard applies to the borrowed-buffer entry point.
        #[test]
        fn polling_with_a_buffer_and_no_interfaces_is_an_error() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);

            let mut buf = [0u8; 64];
            let err = r
                .poll_output_with_buf(t0, &mut buf[..])
                .expect_err("a router with no interfaces should be rejected");

            assert!(matches!(
                err,
                BabelError::Interface(InterfaceError::NoInterfacesRegistered)
            ));
        }
    }
}
