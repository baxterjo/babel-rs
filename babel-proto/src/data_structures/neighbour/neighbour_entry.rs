use thiserror::Error;

use crate::data_structures::interface::{DEFAULT_MULTICAST_HELLO_INTERVAL, InterfaceHandle};
use crate::data_structures::neighbour::NeighbourTableError;
use crate::data_structures::neighbour::neighbour_entry::RxHelloInfoErr::BigSeqnoDiff;
use crate::data_structures::seqno::SeqNo;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::extension::metric_calc::IhuRatio;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::utils::bit_history::BitHistory;
use crate::utils::distance::TxCost;
use crate::utils::timer::{Timer, TimerError};
use crate::utils::{Duration, DurationMultiplier, Instant, InternallyKeyed};

/// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.8) the
/// **advertised** IHU interval is always 3 times the Multicast Hello interval. IHUs are actually
/// sent with each Hello on lossy links (as determined from the Hello history), but only with every
/// third Multicast Hello on lossless links.
pub const DEFAULT_IHU_RATIO: IhuRatio = IhuRatio::new(3, 1);

/// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.12) 3.5 times
/// the advertised IHU interval.
pub const DEFAULT_HOLD_TIME_MULTIPLIER: DurationMultiplier = DurationMultiplier { num: 7, den: 2 };

/// [Appendix A.1](https://datatracker.ietf.org/doc/html/rfc8966#section-a.1-4)
/// If the Interval field of the received Hello is not zero, it resets the neighbour's hello timer
/// to 1.5 times the advertised Interval (the extra margin allows for delay due to jitter).
pub const HELLO_INTERVAL_MULTIPLIER: DurationMultiplier = DurationMultiplier { num: 3, den: 2 };

const DEFAULT_IHU_RATIO_INNER: DurationMultiplier = DurationMultiplier { num: 3, den: 1 };

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourIndex<A>(pub InterfaceHandle, pub Address<A>)
where
    A: AddressExt;

impl<A: AddressExt> core::fmt::Display for NeighbourIndex<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}", self.1, self.0)
    }
}

/// A neighbour table entry as defined in section
/// [3.2.4](https://datatracker.ietf.org/doc/html/rfc8966#name-the-neighbour-table)
///
/// Note: To drive the sans-io state machine for this crate additional state is required for event
/// driven TLVs.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbour<A: AddressExt> {
    // Protocol state as defined by SPEC
    /// the local node's interface over which this neighbour is reachable
    pub(crate) iface: InterfaceHandle,

    /// the address of the neighbouring interface
    pub(crate) address: Address<A>,

    /// a history of recently received Multicast Hello packets from this neighbour; this
    /// can, for example, be a sequence of n bits, for some small value n, indicating which of the
    /// n hellos most recently sent by this neighbour have been received by the local node.
    /// the expected incoming Multicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// the multicast hellotimer, which is set to the interval value carried by scheduled Multicast
    /// Hello TLVs sent by this neighbour
    ///
    /// None if this router has never received a multicast hello from theis neighbour.
    pub(crate) mcast_hello_info: RxHelloInfo,

    /// a history of recently received Unicast Hello packets from this neighbour
    ///
    /// the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// None if this router has never received a unicast hello from this neighbour
    pub(crate) ucast_hello_info: Option<RxHelloInfo>,

    /// the 'transmission cost' value from the last IHU packet received from this
    /// neighbour, or FFFF hexadecimal (infinity) if the IHU hold timer for this neighbour has
    /// expired
    ///
    /// Infinity if this router has never received an IHU from this neighbour.
    pub(crate) tx_cost: TxCost,

    /// and the IHU timer, which is set to a small multiple of the interval carried in IHU TLVs
    /// (see "IHU Hold time" in Appendix B for suggested values).
    ///
    /// None if this router has never received an IHU from this neighbour.
    pub(crate) ihu_timer: Timer,

    // Scheduling state, required to drive Sans-IO state machine.
    /// Pending TLV's that need to go out during `poll_transmit`
    pub(crate) pending: NeighbourPending,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RxHelloInfo {
    history: BitHistory,
    expected_seqno: SeqNo,
    timer: Timer,
}

impl RxHelloInfo {
    pub(crate) const MISSED_HELLO_MAX: u16 = 16;

    /// When a neighbour is new, we have never received a hello from it, so its bit history is all
    /// zeros, its expected seqno is zero, and its multicast hello timer is set to the default
    /// value.
    pub(crate) fn new_default(now: Instant) -> Self {
        Self {
            history: BitHistory::default(),
            expected_seqno: SeqNo::default(),
            timer: Timer::new_unchecked(
                now,
                DEFAULT_MULTICAST_HELLO_INTERVAL * HELLO_INTERVAL_MULTIPLIER,
            ),
        }
    }

    pub(crate) fn new_from_hello(
        now: Instant,
        received_seqno: SeqNo,
        hello_interval: Duration,
    ) -> Result<Self, TimerError> {
        let mut out = Self {
            history: BitHistory::default(),
            expected_seqno: received_seqno,
            timer: Timer::new(now, hello_interval)?,
        };
        // Since this is originated from a hello, the history needs at least one recorded hello.
        out.history.record(true);
        Ok(out)
    }
    /// Records a missed hello (if applicable) and returns the time remaining till the next tick.
    fn poll_tick(&mut self, now: Instant) -> Duration {
        if let Some(remaining) = self.timer.time_remaining(now) {
            return remaining;
        } else {
            self.history.record(false);
            self.timer.restart(now);
            self.timer.duration()
        }
    }

    fn record_hello(
        &mut self,
        now: Instant,
        received_seqno: SeqNo,
        new_interval: Option<Duration>,
    ) -> Result<(), RxHelloInfoErr> {
        let abs_diff = self.expected_seqno.abs_diff(received_seqno);
        if abs_diff > Self::MISSED_HELLO_MAX {
            // In this instance the entire neighbour entry needs to be flushed and re-made.
            return Err(RxHelloInfoErr::BigSeqnoDiff(abs_diff));
        }
        if self.expected_seqno < received_seqno {
            self.history.record_many(false, abs_diff.into());
        } else if self.expected_seqno > received_seqno {
            self.history.undo(abs_diff.into());
        }
        self.history.record(true);

        if let Some(new_interval) = new_interval {
            self.timer
                .set_tick_duration(new_interval * HELLO_INTERVAL_MULTIPLIER)?;
        }

        self.timer.restart(now);

        Ok(())
    }
}

#[derive(Debug, Error)]
enum RxHelloInfoErr {
    #[error("There was a seqno diff greater than {max}: {0}", max = RxHelloInfo::MISSED_HELLO_MAX)]
    BigSeqnoDiff(u16),
    #[error(transparent)]
    Timer(#[from] TimerError),
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct TxHelloInfo {
    pub(crate) seqno: SeqNo,
    pub(crate) timer: Timer,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourPending {
    /// If this node should send unicast hellos to this neighbour, set its timer.
    ///
    /// The spec suggests never sending unicast hellos
    /// [Appendix B. - 4.4](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.4).
    /// But the spec is also written for only IP based transports where multicast can be assumed to
    /// work well.
    pub(crate) ucast_hello: Option<TxHelloInfo>,
    /// Flag for sending ihus to this neighbour. This is most useful when a neighbour is new and
    /// needs an immediate IHU. Periodic IHU polling will ignore this field and send IHU's to all
    /// neighbours based on the interface's IHU interval.
    pub(crate) ihu_due: bool,
}

impl<A: AddressExt> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex(self.iface, self.address)
    }
}

impl<A: AddressExt> Neighbour<A> {
    pub(crate) fn new(
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ucast_hello: Option<Timer>,
    ) -> Self {
        Self {
            iface: interface,
            address,
            // When a neighbour is new, this router has never received a hello from it. This
            // populates the RxHelloInfo with sensible defaults.
            mcast_hello_info: RxHelloInfo::new_default(now),
            ucast_hello_info: None,
            // When a neighbour is new, this router has never received an IHU packet from it, so TX
            // cost is set to infinity
            tx_cost: TxCost::INFINITY,
            // When a neighbour is new, this router has never received an IHU from it, so it's IHU
            // timer is set to the spec default.
            ihu_timer: Timer::new_unchecked(
                now,
                DEFAULT_MULTICAST_HELLO_INTERVAL
                    * DEFAULT_IHU_RATIO_INNER
                    * DEFAULT_HOLD_TIME_MULTIPLIER,
            ),
            pending: NeighbourPending {
                ucast_hello: ucast_hello.map(|t| TxHelloInfo {
                    seqno: SeqNo(0),
                    timer: t,
                }),
                // When a neighbour is new, send an immediate IHU to speed up convergence.
                ihu_due: true,
            },
        }
    }

    fn hello_seqno_flush(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        // Reset everything to default, keeping original settings for outgoing timers.
        self.mcast_hello_info = RxHelloInfo::new_default(now);
        self.ucast_hello_info = self.ucast_hello_info.map(|_| RxHelloInfo::new_default(now));
        self.tx_cost = TxCost::INFINITY;
        self.ihu_timer = Timer::new_unchecked(
            now,
            DEFAULT_MULTICAST_HELLO_INTERVAL
                * DEFAULT_IHU_RATIO_INNER
                * DEFAULT_HOLD_TIME_MULTIPLIER,
        );
        self.pending.ucast_hello = self.pending.ucast_hello.map(|mut utx| {
            utx.timer.restart(now);
            TxHelloInfo {
                seqno: SeqNo(0),
                timer: utx.timer,
            }
        });
        self.pending.ihu_due = true;

        // Now process the incoming hello
        let timer_dur = if interval.is_zero() {
            DEFAULT_MULTICAST_HELLO_INTERVAL * HELLO_INTERVAL_MULTIPLIER
        } else {
            interval.into()
        };
        let new_rx_info = RxHelloInfo::new_from_hello(now, seqno, timer_dur)
            .expect("Timer interval was verified non-zero above");

        if flags.is_unicast() {
            self.ucast_hello_info = Some(new_rx_info)
        } else {
            self.mcast_hello_info = new_rx_info
        }
    }

    pub(crate) fn handle_hello(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        let interval = if interval.is_zero() {
            None
        } else {
            Some(interval.into())
        };

        let mut rx_hello_info = if flags.is_unicast() {
            self.ucast_hello_info
                .unwrap_or_else(|| RxHelloInfo::new_default(now))
        } else {
            self.mcast_hello_info
        };

        match rx_hello_info.record_hello(now, seqno, interval) {
            Ok(_) if flags.is_unicast() => self.ucast_hello_info = Some(rx_hello_info),
            Ok(_) => self.mcast_hello_info = rx_hello_info,
            Err(BigSeqnoDiff(seq)) => {
                b_debug!(
                    "Neighbour flush - iface {}, addr: {} - seqno diff: {}",
                    self.iface,
                    self.address,
                    seq
                );
                self.hello_seqno_flush(now, hello);
            }
            Err(RxHelloInfoErr::Timer(t)) => {
                b_debug!("Err - {} - interval: {:?}", t, interval);
            }
        }
    }

    pub(crate) fn handle_ihu(
        &mut self,
        now: Instant,
        ihu: IhuSlice<'_>,
        hold_time: DurationMultiplier,
    ) -> Result<(), NeighbourTableError<A>> {
        let rx_cost = ihu.rx_cost();
        let interval = ihu.interval();

        let timer_dur: Duration = interval.into();

        self.ihu_timer = Timer::new(now, timer_dur * hold_time)?;

        self.tx_cost = rx_cost.into();

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::extension::NoExtension;
    use crate::packet::tlv::TypedTlv;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    /// The largest interval a Timer will accept. The Interval field on the wire is 16 bits of
    /// centiseconds, so this is also the largest interval a peer can legally advertise.
    const MAX_TIMER: Duration = Duration::from_centis(u16::MAX as u64);

    fn hello_tlv(unicast: bool, seqno: u16, interval_centis: u16) -> [u8; 8] {
        let flags = HelloFlags::new(unicast).to_wire();
        let seqno = seqno.to_be_bytes();
        let interval = interval_centis.to_be_bytes();
        [
            HelloSlice::TYPE_ID,
            HelloSlice::MIN_LEN as u8,
            flags[0],
            flags[1],
            seqno[0],
            seqno[1],
            interval[0],
            interval[1],
        ]
    }

    fn hello(bytes: &[u8]) -> HelloSlice<'_> {
        HelloSlice::from_untyped(TlvSlice::from_slice(bytes).expect("tlv should parse"))
            .expect("hello should parse")
    }

    fn neighbour(now: Instant) -> Neighbour<NoExtension> {
        Neighbour::new(
            now,
            InterfaceHandle::try_from("iface_1").expect("bad interface handle"),
            core::net::Ipv6Addr::LOCALHOST.into(),
            None,
        )
    }

    //  ___ _  _ _____ ___ _____   ___   _      ___  ___  _   _ _  _ ___  ___
    // |_ _| \| |_   _| __| _ \ \ / /_\ | |    | _ )/ _ \| | | | \| |   \/ __|
    //  | || .` | | | | _||   /\ V / _ \| |__  | _ \ (_) | |_| | .` | |) \__ \
    // |___|_|\_| |_| |___|_|_\ \_/_/ \_\____| |___/\___/ \___/|_|\_|___/|___/

    /// The IHU interval is derived by doubling the neighbour's Hello interval, but the Interval
    /// field is 16 bits, so a peer may legally advertise up to `u16::MAX` centiseconds — double
    /// that does not fit in a `Timer`. The doubling has to be clamped before it reaches
    /// `Timer::set_duration`, whose error is unwrapped on the assumption that bounds were
    /// pre-checked. A peer on the link controls this value, so an unclamped doubling is a remote
    /// panic.
    #[test]
    fn hello_interval_that_doubles_past_the_timer_bound_is_clamped() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        // The first hello takes the `None` branch and arms `pending.ihu_timer`, so the second
        // one goes through `set_duration` rather than `new_eager`.
        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        assert!(
            n.pending.ihu_timer.is_some(),
            "the first hello should arm the IHU timer"
        );

        // 32768 centis is the smallest interval whose double overflows the timer's bound.
        n.handle_hello(now, hello(&hello_tlv(false, 1, 32_768)));

        let timer = n
            .pending
            .ihu_timer
            .expect("the IHU timer should still be set");
        assert_eq!(timer.duration(), MAX_TIMER);
    }

    #[test]
    fn maximum_advertised_hello_interval_is_clamped() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        n.handle_hello(now, hello(&hello_tlv(false, 1, u16::MAX)));

        let timer = n
            .pending
            .ihu_timer
            .expect("the IHU timer should still be set");
        assert_eq!(timer.duration(), MAX_TIMER);
    }

    /// Below the doubling boundary the interval must pass through untouched — the clamp should
    /// not be quietly capping ordinary intervals.
    #[test]
    fn hello_interval_below_the_boundary_doubles_without_clamping() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        n.handle_hello(now, hello(&hello_tlv(false, 1, 30_000)));

        let timer = n
            .pending
            .ihu_timer
            .expect("the IHU timer should still be set");
        assert_eq!(timer.duration(), Duration::from_centis(60_000));
    }

    //  _  _ ___ ___ _____ ___  _____   __
    // | || |_ _/ __|_   _/ _ \| _ \ \ / /
    // | __ || |\__ \ | || (_) |   /\ V /
    // |_||_|___|___/ |_| \___/|_|_\ |_|

    #[test]
    fn first_hello_starts_from_a_full_history() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));

        assert_eq!(
            mcast_history(&n).count(),
            16,
            "a new neighbour starts with a clean history for hysteresis"
        );
    }

    #[test]
    fn consecutive_hellos_keep_the_history_clean() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        for seqno in 0..8 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
        }

        assert_eq!(mcast_history(&n).count(), 16, "no hellos were missed");
    }

    #[test]
    fn a_gap_in_seqnos_records_one_miss_per_skipped_hello() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        // Seqnos 1, 2 and 3 never arrived.
        n.handle_hello(now, hello(&hello_tlv(false, 4, 100)));

        assert_eq!(
            mcast_history(&n).count(),
            13,
            "three missed hellos should shift in three zeros"
        );
    }

    /// `record(true)` has to actually be called on a successful hello. If only misses are
    /// recorded, zeros shift in on the first loss and can never shift back out, so link quality
    /// decreases monotonically and permanently.
    #[test]
    fn history_recovers_once_enough_hellos_arrive_in_order() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        n.handle_hello(now, hello(&hello_tlv(false, 4, 100)));
        assert_eq!(mcast_history(&n).count(), 13, "three hellos were missed");

        // Sixteen clean hellos are enough to shift every zero back out of the window.
        for seqno in 5..21 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
        }

        assert_eq!(
            mcast_history(&n).count(),
            16,
            "a link that stops losing hellos should return to a full history"
        );
    }

    /// `seqno - expected_seqno` wraps, so a hello that arrives out of order produces a gap near
    /// 65535 rather than a negative one. Charging that to the history would wipe the whole window
    /// on a single duplicate packet.
    #[test]
    fn a_replayed_hello_does_not_damage_the_history() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        for seqno in 0..3 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
        }
        assert_eq!(mcast_history(&n).count(), 16, "no hellos were missed");

        // Seqno 1 was already accounted for two hellos ago.
        n.handle_hello(now, hello(&hello_tlv(false, 1, 100)));
        assert_eq!(
            mcast_history(&n).count(),
            16,
            "a duplicate hello is not a window of missed hellos"
        );

        // The neighbour is still expecting seqno 3, so its arrival is not a gap either.
        n.handle_hello(now, hello(&hello_tlv(false, 3, 100)));
        assert_eq!(
            mcast_history(&n).count(),
            16,
            "the expected seqno should not have been rewound by the duplicate"
        );
    }

    #[test]
    fn unicast_and_multicast_hellos_keep_separate_histories() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        n.handle_hello(now, hello(&hello_tlv(true, 0, 100)));
        // A gap on the multicast side only.
        n.handle_hello(now, hello(&hello_tlv(false, 4, 100)));

        let NeighbourInitState::HelloReceived(info) = n.state else {
            panic!("expected the neighbour to have heard a hello");
        };
        assert_eq!(
            info.mcast_hello
                .expect("multicast recorded")
                .history
                .count(),
            13
        );
        assert_eq!(
            info.ucast_hello.expect("unicast recorded").history.count(),
            16,
            "a multicast gap must not be charged against the unicast history"
        );
    }
}
