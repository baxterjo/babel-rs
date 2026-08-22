use super::BabelRouter;
use crate::data_structures::interface::InterfaceHandle;
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::output::{Output, Transmit};
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriter, PacketWriterError, PacketWriterStep};
use crate::utils::destination::{Claim, DestAddr};
use crate::utils::storage::ManagedSliceExt;
use crate::utils::{Duration, Instant, ManagedSlice};

impl<'storage, A, P, const MN: u8, const V: u8> BabelRouter<'storage, P, A, MN, V>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Polls output from the router.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn poll_output(&mut self, now: Instant) -> Result<Output<'_, A>, BabelError<A>> {
        let buf = alloc::vec::Vec::new();
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
        let mut active_dest = DestAddr::default();
        let mut active_iface = active_interface;
        let writer = PacketWriter::new_packet(MN, V, buf.into())?;
        let mut next_poll = Duration::from_micros(u64::MAX);

        let body = match self.build_packet_body(
            now,
            &mut active_iface,
            &mut active_dest,
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

        let output = Output::Transmit(Transmit {
            iface: active_iface.expect("Somehow built a packet with no interface?"),
            destination: active_dest
                .try_into()
                .expect("Somehow built a packet with no destination?"),
            contents: finished_packet.into(),
        });

        b_debug!("{} - {:?}", self.id, output);

        Ok(output)
    }

    fn build_packet_body<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        b_trace!("Polling for IHUs");
        writer = self.poll_for_due_ihu(now, active_iface, active_dest, next_poll, writer)?;

        b_trace!("Polling for UCAST Hellos");
        writer = self.poll_for_ucast_hello(now, active_iface, active_dest, next_poll, writer)?;

        // At the very end of polling for potential TLV's check for MCAST hello.
        b_trace!("Polling for MCAST Hellos");
        writer = self.poll_for_mcast_hello(now, active_iface, active_dest, next_poll, writer)?;

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
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);

        for neighbour in self.neighbor_table.iter_mut() {
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
            }

            // If the active address has been claimed and it is not destined for this neighbour
            // then skip.
            if active_dest
                .unicast_addr()
                .is_some_and(|addr| *addr != neighbour.address)
            {
                continue;
            }

            // Get the interface for this neighbour.
            let iface = self
                .iface_table
                .inner
                .get_by_key(&neighbour.iface)
                .expect("Neighbour exists on unregistered interface?");

            // If the active address is multicast and this interface wants unicast IHUs, then skip.
            if active_dest.is_multicast() && iface.config.unicast_ihu {
                continue;
            }

            // At this point
            //
            // The neighbour:
            // - Has an IHU timer that exists and has expired
            // The active interface is either:
            // - Free
            // - Matches this neighbour's interface.
            // The active address is either:
            // - Free
            // - Unicast and matches this address
            // - Multicast and this neighbour's interface does not want unicast ihus

            // TODO: Figure out error handling
            let ae: u8 = iface.config.address.encoding().try_into().unwrap();
            let rx_cost = iface.config.starting_rx_cost;
            let duration = ihu_timer.duration();
            let address = iface.config.address;
            b_debug!(
                "[SEND] IHU - iface: {}, dest_addr: {:?} - ae: {}, rx_cost: {:?}, interval: {}, addr: {:?}",
                iface.handle,
                active_dest,
                ae,
                rx_cost,
                duration.as_centis(),
                address
            );
            writer = writer
                .write_ihu(ae, rx_cost, duration.into(), address.as_wire())?
                .finish_tlv()?;

            // Claim the active address after the write succeeds.
            if iface.config.unicast_ihu {
                // Otherwise this neighbour can claim the address.
                // TODO error handling.
                active_dest
                    .claim(DestAddr::Unicast(neighbour.address))
                    .unwrap();
            } else {
                active_dest.claim(DestAddr::Multicast).unwrap()
            }
            // Claim the active interface after the write succeeds.
            active_iface.claim(iface.handle).unwrap();
            // Once the packet has been written, reset the IHU timer
            ihu_timer.restart(now);
        }

        // Choose the minimum between next poll and local min.
        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }

    //  ___  ___  _    _      _   _  ___   _   ___ _____   _  _ ___ _    _    ___
    // | _ \/ _ \| |  | |    | | | |/ __| /_\ / __|_   _| | || | __| |  | |  / _ \
    // |  _/ (_) | |__| |__  | |_| | (__ / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  \___/|____|____|  \___/ \___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    fn poll_for_ucast_hello<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_addr: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);
        for neighbour in self.neighbor_table.iter_mut() {
            let iface = neighbour.iface;
            let address = neighbour.address;

            // Neighbour wants to send ucast hellos.
            let Some(ucast) = neighbour.pending.ucast_hello.as_mut() else {
                continue;
            };

            // If the timer is not done, update local min and skip.
            if let Some(remaining) = ucast.timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }
            // Skip if active interface is not this neighbour's.
            if active_iface.is_some_and(|active| active != iface) {
                continue;
            }

            if active_addr.is_free()
                || active_addr
                    .unicast_addr()
                    .is_some_and(|addr| *addr == address)
            {
                let flags = HelloFlags::new_unicast();
                let seqno = ucast.seqno;
                let duration = ucast.timer.duration();
                let dest = DestAddr::Unicast(address);

                b_trace!(
                    "[SEND] UCAST HELLO - iface {}, dest: {} - {:?}, {:?}, interval: {}",
                    iface,
                    dest,
                    flags,
                    seqno,
                    duration.as_centis()
                );
                writer = writer
                    .write_hello(flags, seqno, duration.into())?
                    .finish_tlv()?;

                active_iface.claim(iface).unwrap();
                active_addr.claim(DestAddr::Unicast(address)).unwrap();

                ucast.timer.restart(now);
                ucast.seqno += 1;
            }
        }

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
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min = Duration::from_micros(u64::MAX);
        for iface in self.iface_table.iter_mut() {
            // If the timer on the interface hello has not fired, get the minimum between it and
            // min_dur.
            if let Some(remaining) = iface.hello_timer.time_remaining(now) {
                local_min = local_min.min(remaining);
                continue;
            }

            if active_iface.is_some_and(|active| active != iface.handle) {
                // If active interface has been claimed and is not this one, skip
                continue;
            }

            // At this point in execution:
            //
            // The interface:
            // - Hello timer has expired
            // The active interface is either:
            // - Free
            // - Has been claimed and matches this one.

            // If the active destination is free or multicast write a multicast hello.
            if active_dest.is_free() || active_dest.is_multicast() {
                let flags = HelloFlags::new_multicast();
                let seqno = iface.hello_seqno;
                let duration = iface.hello_timer.duration();
                let dest: DestAddr<A> = DestAddr::Multicast;

                b_trace!(
                    "[SEND] MCAST HELLO - iface {}, dest: {} - {:?}, {:?}, interval: {}",
                    iface.handle,
                    dest,
                    flags,
                    seqno,
                    duration.as_centis()
                );

                writer = writer
                    .write_hello(flags, seqno, duration.into())?
                    .finish_tlv()?;

                // Update the active interface, this will be the same value if it was given.
                active_iface.claim(iface.handle).unwrap();
                active_dest.claim(dest).unwrap();

                // Restart hello timer
                iface.hello_timer.restart(now);
                // Increment the seqno
                iface.hello_seqno += 1;
            }
        }

        *next_poll = local_min.min(*next_poll);

        Ok(writer)
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::seqno::SeqNo;
    use crate::data_types::{Address, RouterId};
    use crate::extension::NoExtension;
    use crate::output::TransmitDestination;
    use crate::packet::packet_slice::PacketSlice;
    use crate::packet::tlv::tlv_slice::TlvSlice;
    use crate::packet::tlv::{HelloSlice, IhuSlice, TypedTlv};
    use crate::utils::rx_cost::RxCost;
    use crate::utils::storage::ManagedSliceExt;
    use crate::utils::timer::Timer;

    // Long enough that it never fires again during a test (still under the Timer max of
    // 655.35s), short enough to stay well clear of the small durations used for IHU/ucast hello.
    const IFACE_INTERVAL: Duration = Duration::from_micros(600_000_000);

    const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    /// The address family Babel normally runs on, and the only one the writer compresses.
    const LINK_LOCAL_NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_1_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_2_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);

    fn router(name: &'static str) -> BabelRouter<'static> {
        BabelRouter::new(RouterId::try_from(name).expect("bad router id"))
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
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
            .map(|tlv| tlv.expect("tlv should parse").r#type())
            .collect()
    }

    fn nth_tlv(contents: &[u8], n: usize) -> TlvSlice<'_> {
        PacketSlice::from_slice(contents)
            .expect("packet should parse")
            .body_reader()
            .nth(n)
            .expect("tlv should exist")
            .expect("tlv should parse")
    }

    /// Registers an interface with an interval too long to fire again in a test, then drains its
    /// mandatory eager initial multicast hello so it doesn't pollute later assertions.
    fn drained_iface(
        router: &mut BabelRouter<'static>,
        now: Instant,
        name: &str,
        address: Ipv6Addr,
    ) -> InterfaceHandle {
        let handle = iface_handle(name);
        router
            .register_interface(now, handle, address, Some(IFACE_INTERVAL), None)
            .expect("could not register interface");

        let transmit = expect_transmit(router.poll_output(now).expect("poll should succeed"));
        assert_eq!(
            transmit.iface, handle,
            "expected the mandatory initial hello"
        );

        handle
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
            let handle = iface_handle("iface_1");
            r.register_interface(t0, handle, NODE_ADDR, Some(IFACE_INTERVAL), None)
                .expect("register should succeed");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));

            assert_eq!(transmit.iface, handle);
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            let hello = HelloSlice::from_untyped(nth_tlv(&transmit.contents, 0))
                .expect("should be a hello");
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

            let hello = HelloSlice::from_untyped(nth_tlv(&transmit.contents, 0))
                .expect("should be a hello");
            assert_eq!(hello.seqno(), SeqNo(1));
        }

        #[test]
        fn only_one_interface_fires_per_poll_others_drained_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle_a = iface_handle("iface_a");
            let handle_b = iface_handle("iface_b");
            r.register_interface(t0, handle_a, NODE_ADDR, Some(IFACE_INTERVAL), None)
                .expect("register should succeed");
            r.register_interface(t0, handle_b, NEIGHBOUR_1_ADDR, Some(IFACE_INTERVAL), None)
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
            let handle_a = iface_handle("iface_a");
            let handle_b = iface_handle("iface_b");
            r.register_interface(t0, handle_a, NODE_ADDR, Some(IFACE_INTERVAL), None)
                .expect("register should succeed");
            r.register_interface(t0, handle_b, NEIGHBOUR_1_ADDR, Some(IFACE_INTERVAL), None)
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

        const UCAST_INTERVAL: Duration = Duration::from_secs(20);

        #[test]
        fn not_configured_never_sent() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(
                t0,
                iface_handle("iface_1"),
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                None,
            )
            .expect("add_neighbour should succeed");

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn not_due_immediately_after_registration() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(
                t0,
                iface_handle("iface_1"),
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                Some(UCAST_INTERVAL),
            )
            .expect("add_neighbour should succeed");

            // Unlike interface hellos, a fresh ucast hello timer is NOT eager.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn fires_when_due_with_correct_fields() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.add_neighbour(
                t0,
                iface,
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                Some(UCAST_INTERVAL),
            )
            .expect("add_neighbour should succeed");
            r.neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface, NEIGHBOUR_1_ADDR.into()))
                .expect("neighbour should exist")
                .pending
                .ucast_hello
                .as_mut()
                .expect("ucast hello should be configured")
                .timer = Timer::new_eager(t0, UCAST_INTERVAL).expect("timer should be valid");

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));

            assert_eq!(transmit.iface, iface);
            let expected_dest: Address<_> = NEIGHBOUR_1_ADDR.into();
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(expected_dest)
            );
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);

            let hello = HelloSlice::from_untyped(nth_tlv(&transmit.contents, 0))
                .expect("should be a hello");
            assert!(hello.flags().is_unicast());
            assert_eq!(hello.seqno(), SeqNo(0));
            assert_eq!(hello.interval(), UCAST_INTERVAL.into());

            // The timer restarted, so an immediate repoll does not refire it.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn conflicting_destination_defers_to_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                r.add_neighbour(
                    t0,
                    iface,
                    addr.into(),
                    Duration::from_secs(10),
                    Some(UCAST_INTERVAL),
                )
                .expect("add_neighbour should succeed");
                r.neighbor_table
                    .inner
                    .get_mut_by_key(&NeighbourIndex(iface, addr.into()))
                    .expect("neighbour should exist")
                    .pending
                    .ucast_hello
                    .as_mut()
                    .expect("ucast hello should be configured")
                    .timer = Timer::new_eager(t0, UCAST_INTERVAL).expect("timer should be valid");
            }

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
            let iface_a = drained_iface(&mut r, t0, "iface_a", NODE_ADDR);
            let iface_b = drained_iface(&mut r, t0, "iface_b", NEIGHBOUR_2_ADDR);
            r.add_neighbour(
                t0,
                iface_a,
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                Some(UCAST_INTERVAL),
            )
            .expect("add_neighbour should succeed");
            r.neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface_a, NEIGHBOUR_1_ADDR.into()))
                .expect("neighbour should exist")
                .pending
                .ucast_hello
                .as_mut()
                .expect("ucast hello should be configured")
                .timer = Timer::new_eager(t0, UCAST_INTERVAL).expect("timer should be valid");

            // Scoping to iface_b must not fire iface_a's due ucast hello.
            let remaining = expect_set_timer(
                r.poll_output_for_iface(t0, iface_b)
                    .expect("poll should succeed"),
            );
            assert_eq!(remaining, IFACE_INTERVAL);

            // It's still there, untouched, for an unrestricted poll.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
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

        fn add_neighbour_no_ucast(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            addr: Ipv6Addr,
        ) {
            r.add_neighbour(now, iface, addr.into(), Duration::from_secs(10), None)
                .expect("add_neighbour should succeed");
        }

        fn set_ihu_timer(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            addr: Ipv6Addr,
            duration: Duration,
            eager: bool,
        ) {
            let neighbour = r
                .neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface, addr.into()))
                .expect("neighbour should exist");
            neighbour.pending.ihu_timer = Some(if eager {
                Timer::new_eager(now, duration).expect("timer should be valid")
            } else {
                Timer::new(now, duration).expect("timer should be valid")
            });
        }

        #[test]
        fn never_sent_without_received_hello() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            // A neighbour added out-of-band has no pending IHU timer until a hello is received.
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn not_due_contributes_remaining_to_set_timer() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);
            set_ihu_timer(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                Duration::from_secs(5),
                false,
            );

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, Duration::from_secs(5));
        }

        #[test]
        fn fires_multicast_with_correct_fields_and_restarts_timer() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);
            set_ihu_timer(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                Duration::from_secs(30),
                true,
            );

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu =
                IhuSlice::from_untyped(nth_tlv(&transmit.contents, 0)).expect("should be an ihu");
            assert_eq!(ihu.ae(), 2, "NODE_ADDR is a non-link-local IPv6 address");
            assert_eq!(ihu.rx_cost(), RxCost(10), "default starting_rx_cost");
            assert_eq!(ihu.interval(), Duration::from_secs(30).into());
            assert_eq!(
                ihu.address(16).expect("should have a 16 byte address"),
                &Address::<NoExtension>::from(NODE_ADDR).as_wire()[..]
            );

            // Timer restarted, so an immediate repoll doesn't refire it.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, Duration::from_secs(30));
        }

        /// AE=3 declares an 8-byte address, so the IHU has to carry exactly the 8-byte suffix.
        /// Writing fewer bytes than the encoding advertises desynchronises the receiver for the
        /// address itself and for every sub-TLV behind it, and link-local is the common
        /// deployment path rather than an edge case.
        #[test]
        fn link_local_interface_address_is_sent_as_eight_bytes_with_ae_3() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", LINK_LOCAL_NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);
            set_ihu_timer(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                Duration::from_secs(30),
                true,
            );

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu =
                IhuSlice::from_untyped(nth_tlv(&transmit.contents, 0)).expect("should be an ihu");
            assert_eq!(ihu.ae(), 3, "fe80::/64 uses the link-local encoding");
            assert_eq!(
                ihu.address(8).expect("should have an 8 byte address"),
                &[0, 0, 0, 0, 0, 0, 0, 1]
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

        #[test]
        fn fires_unicast_when_interface_wants_unicast_ihu() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.iface_table
                .inner
                .get_mut_by_key(&iface)
                .expect("interface should exist")
                .config
                .unicast_ihu = true;
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);
            set_ihu_timer(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                Duration::from_secs(30),
                true,
            );

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
        }

        #[test]
        fn conflicting_unicast_destination_defers_second_neighbour_to_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.iface_table
                .inner
                .get_mut_by_key(&iface)
                .expect("interface should exist")
                .config
                .unicast_ihu = true;
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                add_neighbour_no_ucast(&mut r, t0, iface, addr);
                set_ihu_timer(&mut r, t0, iface, addr, Duration::from_secs(30), true);
            }

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
            assert_eq!(remaining, Duration::from_secs(30));
        }

        #[test]
        fn iface_scoped_poll_is_independent_per_interface() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface_a = drained_iface(&mut r, t0, "iface_a", NODE_ADDR);
            let iface_b = drained_iface(&mut r, t0, "iface_b", NEIGHBOUR_2_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface_a, NEIGHBOUR_1_ADDR);
            set_ihu_timer(
                &mut r,
                t0,
                iface_a,
                NEIGHBOUR_1_ADDR,
                Duration::from_secs(30),
                true,
            );

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

        #[test]
        fn ihu_precedes_ucast_and_mcast_hello_when_bundleable() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            r.iface_table
                .inner
                .get_mut_by_key(&iface)
                .expect("interface should exist")
                .config
                .unicast_ihu = true;
            let ucast_interval = Duration::from_secs(20);
            r.add_neighbour(
                t0,
                iface,
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                Some(ucast_interval),
            )
            .expect("add_neighbour should succeed");
            let neighbour = r
                .neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface, NEIGHBOUR_1_ADDR.into()))
                .expect("neighbour should exist");
            neighbour.pending.ihu_timer =
                Some(Timer::new_eager(t0, Duration::from_secs(30)).expect("valid timer"));
            neighbour
                .pending
                .ucast_hello
                .as_mut()
                .expect("configured")
                .timer = Timer::new_eager(t0, ucast_interval).expect("valid timer");

            // IHU and a ucast hello addressed to the same neighbour bundle into one packet,
            // in IHU-then-hello order; the interface's mcast hello (different destination) is
            // blocked this pass since the packet's destination is already unicast.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
            assert_eq!(
                tlv_types(&transmit.contents),
                vec![IhuSlice::TYPE_ID, HelloSlice::TYPE_ID]
            );
            let hello = HelloSlice::from_untyped(nth_tlv(&transmit.contents, 1))
                .expect("should be a hello");
            assert!(hello.flags().is_unicast());

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, ucast_interval);
        }

        #[test]
        fn unicast_ihu_defers_mcast_hello_to_next_immediate_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface_handle = iface_handle("iface_1");
            // Not pre-drained: the interface's mcast hello is eager-due at the same time as the
            // manually-forced IHU below, so both are competing for this poll's destination.
            r.register_interface(t0, iface_handle, NODE_ADDR, Some(IFACE_INTERVAL), None)
                .expect("register should succeed");
            r.iface_table
                .inner
                .get_mut_by_key(&iface_handle)
                .expect("interface should exist")
                .config
                .unicast_ihu = true;
            r.add_neighbour(
                t0,
                iface_handle,
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                None,
            )
            .expect("add_neighbour should succeed");
            r.neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface_handle, NEIGHBOUR_1_ADDR.into()))
                .expect("neighbour should exist")
                .pending
                .ihu_timer = Some(Timer::new_eager(t0, Duration::from_secs(30)).expect("valid"));

            // Pass 1: IHU wins the packet's unicast destination, blocking the mcast hello.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );

            // Pass 2, same `now`: mcast hello's timer was never touched, so it fires on the very
            // next poll with a fresh, unclaimed destination.
            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![HelloSlice::TYPE_ID]);
            assert_eq!(transmit.destination, TransmitDestination::Multicast);

            // Pass 3: everything drained.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, Duration::from_secs(30));
        }

        #[test]
        fn oversized_borrowed_buffer_is_trimmed_to_the_bytes_written() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let handle = iface_handle("iface_1");
            r.register_interface(t0, handle, NODE_ADDR, Some(IFACE_INTERVAL), None)
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

        #[test]
        fn undersized_buffer_write_failure_yields_set_timer_without_panicking() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            r.register_interface(
                t0,
                iface_handle("iface_1"),
                NODE_ADDR,
                Some(IFACE_INTERVAL),
                None,
            )
            .expect("register should succeed");

            // 4 bytes is exactly the packet header, leaving 0 remaining for any TLV.
            let mut buf = [0u8; 4];
            let output = r
                .poll_output_with_buf(t0, &mut buf[..])
                .expect("a write failure should not surface as an Err from poll_output");

            // The mcast hello write fails before contributing to next_poll, so the sentinel
            // "nothing is due" value is returned rather than a short retry.
            assert_eq!(expect_set_timer(output), Duration::from_micros(u64::MAX));
        }
    }
}
