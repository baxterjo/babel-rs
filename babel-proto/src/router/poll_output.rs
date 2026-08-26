use super::BabelRouter;
use crate::data_structures::interface::{InterfaceError, InterfaceHandle};
use crate::data_structures::neighbour::neighbour_entry::DEFAULT_IHU_RATIO;
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::metric::RxCost;
use crate::output::{Output, Transmit};
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriter, PacketWriterError, PacketWriterStep};
use crate::utils::destination::{Claim, DestAddr};
use crate::utils::storage::ManagedSliceExt;
use crate::utils::{Duration, Instant, ManagedSlice};

/// How long to wait before polling again after a TLV write failed.
///
/// A failed write leaves its TLV due — the timer behind it is only restarted once the write
/// succeeds — so the router has to be polled again for that TLV to ever go out. Reporting "nothing
/// is due" would silence it permanently, while a zero duration would spin if the caller keeps
/// handing back a buffer that is too small for the TLV.
const WRITE_FAILURE_RETRY: Duration = Duration::from_millis(100);

/// Folds a candidate wake-up time into a running minimum, where `None` means "nothing due yet".
fn merge_next_poll(slot: &mut Option<Duration>, candidate: Duration) {
    *slot = Some(match *slot {
        Some(current) => current.min(candidate),
        None => candidate,
    });
}

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
    /// of the `SetTimer` variant. That duration **is not** specific to the provided interface.
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

        // A router with no interfaces has nothing it could ever send, and nothing to base a
        // wake-up time on either.
        if self.iface_table.iter_mut().next().is_none() {
            return Err(InterfaceError::NoInterfacesRegistered.into());
        }

        let mut active_dest = DestAddr::default();
        let mut active_iface = active_interface;
        let writer = PacketWriter::new_packet(self.magic_number, self.version_number, buf.into())?;
        let mut next_poll = None;

        let (body, write_failed) = match self.build_packet_body(
            now,
            &mut active_iface,
            &mut active_dest,
            &mut next_poll,
            writer,
        ) {
            Ok(writer) => (writer, false),
            Err((err, writer)) => {
                b_debug!("Err building packet body: {}", err);
                (writer, true)
            }
        };

        let Some(finished_packet) = body.finish_packet()? else {
            // A write failure aborts the rest of the body, so the TLV that failed never got to
            // contribute its timer to `next_poll` and is still due. Ask to be polled again soon,
            // unless something else is already due sooner.
            if write_failed {
                merge_next_poll(&mut next_poll, WRITE_FAILURE_RETRY);
            }

            return Ok(Output::SetTimer(next_poll.unwrap_or(WRITE_FAILURE_RETRY)));
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
        next_poll: &mut Option<Duration>,
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

    // TODO: Periodic IHU scheduling. `pending.ihu_due` is currently the only trigger, so a
    // neighbour gets the one immediate IHU it is born with and nothing after that. The recurring
    // cadence — an interface-level IHU timer, or the ratio from
    // `LinkCostCalculator::hello_ihu_ratio` — still has to drive this flag, and is also what will
    // give this pass a wake-up time to contribute. `now` and `next_poll` are kept in the signature
    // for it.
    #[allow(
        unused_variables,
        reason = "the periodic IHU cadence that uses these is not implemented yet"
    )]
    fn poll_for_due_ihu<'output>(
        &mut self,
        now: Instant,
        active_iface: &mut Option<InterfaceHandle>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Option<Duration>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        for neighbour in self.neighbor_table.iter_mut() {
            if !neighbour.pending.ihu_due {
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
            if active_dest.is_multicast() && iface.unicast_ihu {
                continue;
            }

            // At this point
            //
            // The neighbour:
            // - Has an IHU due
            // The active interface is either:
            // - Free
            // - Matches this neighbour's interface.
            // The active address is either:
            // - Free
            // - Unicast and matches this address
            // - Multicast and this neighbour's interface does not want unicast ihus

            // The Address field names the IHU's destination, so that IHUs for several neighbours
            // can be aggregated into one multicast packet and each receiver can pick out its own.
            // A unicast IHU is already unambiguous, so it uses the wildcard encoding (AE 0) and
            // omits the address entirely, as permitted by RFC 8966 4.6.6.
            let neighbour_addr = neighbour.address;
            let (ae, address): (u8, &[u8]) = if iface.unicast_ihu {
                (0, &[])
            } else {
                // TODO: Figure out error handling
                (
                    neighbour_addr.encoding().try_into().unwrap(),
                    neighbour_addr.as_wire(),
                )
            };

            // The Interval field advertises when the next IHU is due, which RFC 8966 Appendix B
            // puts at three times the multicast Hello interval. Once the periodic cadence lands
            // this should come from whatever timer actually schedules the next IHU.
            let duration = DEFAULT_IHU_RATIO.apply(iface.hello_timer.duration());
            b_debug!(
                "[SEND] IHU - iface: {}, dest_addr: {:?} - ae: {}, rx_cost: hard_coded, interval: {}, addr: {:?}",
                iface.handle,
                active_dest,
                ae,
                duration.as_centis(),
                neighbour_addr
            );

            writer = writer
                .write_ihu(ae, RxCost::from_raw(59), duration.into(), address)?
                .finish_tlv()?;

            // Claim the active address after the write succeeds.
            if iface.unicast_ihu {
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
            // Once the packet has been written, this neighbour's IHU is no longer due. Clearing
            // only after a successful write is what lets a destination conflict defer a neighbour
            // to the next poll instead of dropping its IHU.
            neighbour.pending.ihu_due = false;
        }

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
        next_poll: &mut Option<Duration>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min: Option<Duration> = None;
        for neighbour in self.neighbor_table.iter_mut() {
            let iface = neighbour.iface;
            let address = neighbour.address;

            // Neighbour wants to send ucast hellos.
            let Some(ucast) = neighbour.pending.ucast_hello.as_mut() else {
                continue;
            };

            // If the timer is not done, update local min and skip.
            if let Some(remaining) = ucast.timer.time_remaining(now) {
                merge_next_poll(&mut local_min, remaining);
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

        if let Some(local_min) = local_min {
            merge_next_poll(next_poll, local_min);
        }

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
        next_poll: &mut Option<Duration>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        let mut local_min: Option<Duration> = None;
        for iface in self.iface_table.iter_mut() {
            // If the timer on the interface hello has not fired, get the minimum between it and
            // min_dur.
            if let Some(remaining) = iface.hello_timer.time_remaining(now) {
                merge_next_poll(&mut local_min, remaining);
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

        if let Some(local_min) = local_min {
            merge_next_poll(next_poll, local_min);
        }

        Ok(writer)
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::InterfaceConfig;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::seqno::SeqNo;
    use crate::data_types::{Address, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::RxCost;
    use crate::output::TransmitDestination;
    use crate::packet::packet_slice::PacketSlice;
    use crate::packet::tlv::{HelloSlice, IhuSlice, Tlv, TypedTlv};
    use crate::router::config::BabelRouterConfig;
    use crate::utils::storage::ManagedSliceExt;
    use crate::utils::timer::Timer;

    // Long enough that it never fires again during a test and well clear of the small durations
    // used for IHU/ucast hello, but small enough that the advertised IHU interval derived from it
    // (3x, see `ADVERTISED_IHU_RATIO`) still fits the 16-bit Interval field without saturating.
    const IFACE_INTERVAL: Duration = Duration::from_secs(200);

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
        config.set_mcast_hello_interval(IFACE_INTERVAL);
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

    /// [`drained_iface`], for an interface configured to send its IHUs unicast.
    fn drained_ucast_ihu_iface(
        router: &mut BabelRouter<'static>,
        now: Instant,
        name: &str,
        address: Ipv6Addr,
    ) -> InterfaceHandle {
        let mut config = iface_config(name, address);
        config.set_unicast_ihu(true);
        drained_iface_with_config(router, now, config)
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

    /// Adds a neighbour and drains the immediate IHU every new neighbour is born owing, so that
    /// IHU does not pollute assertions about unrelated TLVs.
    fn drained_neighbour(
        router: &mut BabelRouter<'static>,
        now: Instant,
        iface: InterfaceHandle,
        address: Ipv6Addr,
        ucast_hello_interval: Option<Duration>,
    ) {
        router
            .add_neighbour(now, iface, address.into(), ucast_hello_interval)
            .expect("add_neighbour should succeed");
        router
            .neighbor_table
            .inner
            .get_mut_by_key(&NeighbourIndex(iface, address.into()))
            .expect("neighbour should exist")
            .pending
            .ihu_due = false;
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

        const UCAST_INTERVAL: Duration = Duration::from_secs(20);

        #[test]
        fn not_configured_never_sent() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR, None);

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn not_due_immediately_after_registration() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR, Some(UCAST_INTERVAL));

            // Unlike interface hellos, a fresh ucast hello timer is NOT eager.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, UCAST_INTERVAL);
        }

        #[test]
        fn fires_when_due_with_correct_fields() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            drained_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR, Some(UCAST_INTERVAL));
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

            let hello = nth_hello(&transmit.contents, 0);
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
                drained_neighbour(&mut r, t0, iface, addr, Some(UCAST_INTERVAL));
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
            drained_neighbour(&mut r, t0, iface_a, NEIGHBOUR_1_ADDR, Some(UCAST_INTERVAL));
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

        /// The advertised IHU interval is three times the interface's multicast Hello interval
        /// (RFC 8966 Appendix B).
        const EXPECTED_IHU_INTERVAL: Duration = Duration::from_secs(600);

        fn add_neighbour_no_ucast(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            addr: Ipv6Addr,
        ) {
            r.add_neighbour(now, iface, addr.into(), None)
                .expect("add_neighbour should succeed");
        }

        // TODO: There is no coverage of *periodic* IHUs, because there is no periodic IHU
        // scheduling yet — `pending.ihu_due` is the only trigger, so a neighbour gets its one
        // immediate IHU and nothing after that. Two cases dropped with the old per-neighbour
        // `pending.ihu_timer` need to come back with the cadence:
        //   - an IHU that is not yet due still contributes its remaining time to `SetTimer`
        //   - an IHU refires after its interval elapses
        //
        // The RFC 8966 3.4.2 requirement they defend is that a neighbour that stops hearing IHUs
        // lets its txcost expire to infinity, which only holds if we keep sending them.

        /// Every new neighbour is born owing an immediate IHU: waiting a full interval before
        /// telling a neighbour we can hear it delays convergence for no reason.
        #[test]
        fn a_new_neighbour_is_sent_an_immediate_ihu() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
        }

        #[test]
        fn fires_multicast_with_correct_fields_and_clears_the_flag() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(transmit.destination, TransmitDestination::Multicast);
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);

            let ihu = nth_ihu(&transmit.contents, 0);
            assert_eq!(
                ihu.ae(),
                2,
                "the neighbour's address is a non-link-local IPv6 address"
            );
            assert_eq!(
                ihu.rx_cost(),
                RxCost::from_raw(59),
                "default starting_rx_cost"
            );
            assert_eq!(ihu.interval(), EXPECTED_IHU_INTERVAL.into());
            // The Address field names the IHU's destination — the neighbour it is for — so that
            // receivers can pick their own out of an aggregated multicast packet.
            assert_eq!(
                ihu.address(16).expect("should have a 16 byte address"),
                Address::<NoExtension>::from(NEIGHBOUR_1_ADDR).as_wire()
            );

            // The flag was cleared by the successful write, so an immediate repoll doesn't refire
            // it and only the interface's hello timer is left to report.
            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, IFACE_INTERVAL);
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
            add_neighbour_no_ucast(&mut r, t0, iface, LINK_LOCAL_NEIGHBOUR_ADDR);

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

        #[test]
        fn fires_unicast_when_interface_wants_unicast_ihu() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_ihu_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(
                transmit.destination,
                TransmitDestination::Unicast(NEIGHBOUR_1_ADDR.into())
            );
            assert_eq!(tlv_types(&transmit.contents), vec![IhuSlice::TYPE_ID]);
        }

        /// A unicast IHU is already unambiguous, so RFC 8966 4.6.6 lets it use the wildcard
        /// encoding and omit the address, saving 16 bytes on every IHU.
        #[test]
        fn unicast_ihu_uses_the_wildcard_encoding_and_omits_the_address() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_ihu_iface(&mut r, t0, "iface_1", NODE_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            let transmit = expect_transmit(r.poll_output(t0).expect("poll should succeed"));
            let ihu = nth_ihu(&transmit.contents, 0);

            assert_eq!(ihu.ae(), 0, "a unicast IHU needs no explicit destination");
            assert!(
                ihu.address(0)
                    .expect("wildcard carries no address")
                    .is_empty(),
                "no address bytes should follow the header"
            );
            // 4 byte packet header + 2 byte TLV header + 6 byte IHU body, and nothing more.
            assert_eq!(transmit.contents.len(), 12);
        }

        #[test]
        fn conflicting_unicast_destination_defers_second_neighbour_to_next_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_ucast_ihu_iface(&mut r, t0, "iface_1", NODE_ADDR);
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                add_neighbour_no_ucast(&mut r, t0, iface, addr);
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
            assert_eq!(remaining, IFACE_INTERVAL);
        }

        #[test]
        fn iface_scoped_poll_is_independent_per_interface() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface_a = drained_iface(&mut r, t0, "iface_a", NODE_ADDR);
            let iface_b = drained_iface(&mut r, t0, "iface_b", NEIGHBOUR_2_ADDR);
            add_neighbour_no_ucast(&mut r, t0, iface_a, NEIGHBOUR_1_ADDR);

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
            let iface = drained_ucast_ihu_iface(&mut r, t0, "iface_1", NODE_ADDR);
            let ucast_interval = Duration::from_secs(20);
            // Left un-drained: the IHU every new neighbour owes is what competes with the ucast
            // hello for this poll's packet.
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into(), Some(ucast_interval))
                .expect("add_neighbour should succeed");
            let neighbour = r
                .neighbor_table
                .inner
                .get_mut_by_key(&NeighbourIndex(iface, NEIGHBOUR_1_ADDR.into()))
                .expect("neighbour should exist");
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
            let hello = nth_hello(&transmit.contents, 1);
            assert!(hello.flags().is_unicast());

            let remaining = expect_set_timer(r.poll_output(t0).expect("poll should succeed"));
            assert_eq!(remaining, ucast_interval);
        }

        #[test]
        fn unicast_ihu_defers_mcast_hello_to_next_immediate_poll() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let mut config = iface_config("iface_1", NODE_ADDR);
            config.set_unicast_ihu(true);
            // Not pre-drained: the interface's mcast hello is eager-due at the same time as the
            // new neighbour's immediate IHU, so both are competing for this poll's destination.
            let iface = r
                .register_interface(t0, config)
                .expect("register should succeed");
            r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into(), None)
                .expect("add_neighbour should succeed");

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
            assert_eq!(remaining, IFACE_INTERVAL);
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

        #[test]
        fn undersized_buffer_write_failure_yields_set_timer_without_panicking() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            r.register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");

            // 4 bytes is exactly the packet header, leaving 0 remaining for any TLV.
            let mut buf = [0u8; 4];
            let output = r
                .poll_output_with_buf(t0, &mut buf[..])
                .expect("a write failure should not surface as an Err from poll_output");

            // The write failure aborts the body before the mcast hello contributes its timer to
            // next_poll, but the hello is still due — its timer was never restarted. The router
            // must ask to be polled again rather than reporting that nothing is scheduled, which
            // would silence it for good.
            assert_eq!(expect_set_timer(output), WRITE_FAILURE_RETRY);
        }

        /// The retry is a floor, not an override: a timer that comes due sooner than the retry
        /// window still wins, so a write failure can't delay unrelated work.
        #[test]
        fn write_failure_retry_does_not_delay_a_sooner_timer() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            // Deliberately not drained: the mcast hello is eager-due, so it is the write that
            // fails against the undersized buffer below.
            let iface = r
                .register_interface(t0, iface_config("iface_1", NODE_ADDR))
                .expect("register should succeed");

            // Not yet due, and due sooner than the retry window. Ucast hellos are polled before
            // the mcast hello, so this contributes to next_poll before the failure aborts the
            // body. The neighbour's initial IHU is drained first — it is polled ahead of
            // everything else, and would otherwise be the write that fails.
            let soon = Duration::from_millis(5);
            drained_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR, Some(soon));

            let mut buf = [0u8; 4];
            let output = r
                .poll_output_with_buf(t0, &mut buf[..])
                .expect("a write failure should not surface as an Err from poll_output");

            assert_eq!(expect_set_timer(output), soon);
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
                BabelError::IfaceTable(InterfaceError::NoInterfacesRegistered)
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
                BabelError::IfaceTable(InterfaceError::NoInterfacesRegistered)
            ));
        }
    }
}
