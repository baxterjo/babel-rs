use crate::data_structures::interface::{DEFAULT_MULTICAST_HELLO_INTERVAL_SECS, InterfaceHandle};
use crate::data_structures::neighbour::NeighbourTableError;
use crate::data_structures::seqno::SeqNo;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::utils::bit_history::BitHistory;
use crate::utils::rx_cost::RxCost as TxCost;
use crate::utils::timer::Timer;
use crate::utils::{Duration, HoldTimeMultiplier, Instant, InternallyKeyed};

pub const DEFAULT_NEIGHBOUR_EXPIRY_SECS: u64 = 10;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourIndex<A>(pub InterfaceHandle, pub Address<A>)
where
    A: AddressExt;

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

    /// State data of a neighbour that has either been added manually or has recevied a hello.
    pub(crate) state: NeighbourInitState,

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
    pub(crate) ihu_timer: Option<Timer>,

    // Scheduling state, required to drive Sans-IO state machine.
    /// Pending TLV's that need to go out during `poll_transmit`
    pub(crate) pending: NeighbourPending,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum NeighbourInitState {
    /// If the neighbour was added through an out of band method. Then this router has never
    /// received a hello from it. So we set an expiry timer for it.
    Expiry(Timer),
    /// If the this router has recevied a hello for this neighbour, then the hello info is stored
    /// here.
    HelloReceived(HelloReceived),
}

#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct HelloReceived {
    /// a history of recently received Unicast Hello packets from this neighbour
    ///
    /// the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// None if this router has never received a unicast hello from this neighbour
    ucast_hello: Option<RxHelloInfo>,
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
    mcast_hello: Option<RxHelloInfo>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RxHelloInfo {
    history: BitHistory,
    expected_seqno: SeqNo,
    timer: Timer,
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
    /// Timer for sending periodic IHU's to this neighbour.
    ///
    /// None if router has never received a hello from this neighbour.
    pub(crate) ihu_timer: Option<Timer>,
}

impl<A: AddressExt> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex(self.iface, self.address)
    }
}

impl<A: AddressExt> Neighbour<A> {
    pub(crate) fn new(
        interface: InterfaceHandle,
        address: Address<A>,
        ucast_hello: Option<Timer>,
        init_state: NeighbourInitState,
    ) -> Self {
        Self {
            iface: interface,
            address,
            state: init_state,
            tx_cost: TxCost(u16::MAX),
            ihu_timer: None,
            pending: NeighbourPending {
                ucast_hello: ucast_hello.map(|t| TxHelloInfo {
                    seqno: SeqNo(0),
                    timer: t,
                }),
                ihu_timer: None,
            },
        }
    }

    pub(crate) fn handle_hello(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        // Duration to be used in periodic IHU's if no better duration is given.
        let ihu_dur: Duration;

        let mut hello_info = match self.state {
            // If a hello has been received in the past, grab it.
            NeighbourInitState::HelloReceived(hello_info) => hello_info,
            // Otherwise create a new one.
            _ => HelloReceived::default(),
        };

        if flags.is_unicast() {
            let history = match &mut hello_info.ucast_hello {
                // If the router has received a hello from this neighbour in the past. Calculate
                // any missed hellos that may have occured.
                Some(ucast_info) => {
                    // Record any gaps in history.
                    let hello_gap = seqno - ucast_info.expected_seqno;
                    ucast_info.history.record_many(false, hello_gap.0.into());
                    // Record this hello
                    ucast_info.history.record(true);
                    ucast_info.history
                }
                None => BitHistory::new(),
            };

            let expected_seqno = seqno + 1;

            let timer_dur = match &mut hello_info.ucast_hello {
                // If the hello is scheduled, use the new interval.
                Some(_ucast_info) if hello.is_scheduled() => interval.into(),
                // If not, use the old interval or a default value.
                Some(ucast_info) => ucast_info.timer.duration(),
                None => Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS),
            };

            // Multiply the incoming duration by two and clamp to max timer duration
            ihu_dur = (timer_dur * 2).min(Duration::from_centis(u16::MAX.into()));

            let timer = Timer::new(now, timer_dur).expect("Interval bounds were pre-checked");

            hello_info.ucast_hello = Some(RxHelloInfo {
                history,
                expected_seqno,
                timer,
            });
        } else {
            let history = match &mut hello_info.mcast_hello {
                // If the router has received a hello from this neighbour in the past. Calculate
                // any missed hellos that may have occured.
                Some(mcast_info) => {
                    // Record any gaps in history
                    let hello_gap = seqno - mcast_info.expected_seqno;
                    mcast_info.history.record_many(false, hello_gap.0.into());
                    // Record this hello
                    mcast_info.history.record(true);
                    mcast_info.history
                }
                None => BitHistory::new(),
            };

            let expected_seqno = seqno + 1;

            let timer_dur = match &mut hello_info.mcast_hello {
                // If the hello is scheduled, use the new interval.
                Some(mcast_info) if hello.is_scheduled() => interval.into(),
                // If not, use the old interval or a default value.
                Some(mcast_info) => mcast_info.timer.duration(),
                None => Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS),
            };

            // Multiply the incoming duration by two and clamp to max timer duration
            ihu_dur = (timer_dur * 2).min(Duration::from_centis(u16::MAX.into()));

            let timer = Timer::new(now, timer_dur).expect("Interval bounds were pre-checked");

            hello_info.mcast_hello = Some(RxHelloInfo {
                history,
                expected_seqno,
                timer,
            });
        }

        // Update the state
        self.state = NeighbourInitState::HelloReceived(hello_info);

        let new_ihu_timer = match self.pending.ihu_timer {
            Some(mut timer) => {
                // If there was already an IHU timer, set it under the spec rules (increase creates
                // an eager timer, decrease does not.)
                timer
                    .set_duration(ihu_dur)
                    .expect("Interval bounds were pre-checked");
                Some(timer)
            }
            // If no IHU timer was set, set an eager timer.
            None => Some(Timer::new_eager(now, ihu_dur).expect("Interval bounds were pre-checked")),
        };
        self.pending.ihu_timer = new_ihu_timer;
    }

    pub(crate) fn handle_ihu(
        &mut self,
        now: Instant,
        ihu: IhuSlice<'_>,
        hold_time: HoldTimeMultiplier,
    ) -> Result<(), NeighbourTableError<A>> {
        let rx_cost = ihu.rx_cost();
        let interval = ihu.interval();

        let timer_dur: Duration = interval.into();

        self.ihu_timer = Some(
            Timer::new(now, timer_dur * hold_time)
                .map_err(|_| NeighbourTableError::IntervalCannotBeZero)?,
        );

        // TODO: Need some tx cost calculation here.
        self.tx_cost = rx_cost;

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
            InterfaceHandle::try_from("iface_1").expect("bad interface handle"),
            core::net::Ipv6Addr::LOCALHOST.into(),
            None,
            NeighbourInitState::Expiry(
                Timer::new(now, Duration::from_secs(DEFAULT_NEIGHBOUR_EXPIRY_SECS))
                    .expect("valid timer"),
            ),
        )
    }

    fn mcast_history(n: &Neighbour<NoExtension>) -> BitHistory {
        match n.state {
            NeighbourInitState::HelloReceived(info) => {
                info.mcast_hello
                    .expect("a multicast hello should have been recorded")
                    .history
            }
            NeighbourInitState::Expiry(_) => panic!("expected the neighbour to have heard a hello"),
        }
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
