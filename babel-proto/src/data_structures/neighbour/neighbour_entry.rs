use thiserror::Error;

use crate::data_structures::interface::{DEFAULT_MULTICAST_HELLO_INTERVAL, InterfaceHandle};
use crate::data_structures::neighbour::neighbour_entry::RxHelloInfoErr::BigSeqnoDiff;
use crate::data_structures::neighbour::{
    HELLO_INTERVAL_MULTIPLIER, NeighbourConfig, NeighbourError,
};
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::LinkCostCalculator;
use crate::metric::distance::TxCost;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::bit_history::BitHistory;
use crate::utils::destination::DestAddr;
use crate::utils::{Duration, DurationMultiplier, Instant, InternallyKeyed, Timer, TimerError};

//  _  _ ___ ___ ___ _  _ ___  ___  _   _ ___   ___ _  _ ___  _____  __
// | \| | __|_ _/ __| || | _ )/ _ \| | | | _ \ |_ _| \| |   \| __\ \/ /
// | .` | _| | | (_ | __ | _ \ (_) | |_| |   /  | || .` | |) | _| >  <
// |_|\_|___|___\___|_||_|___/\___/ \___/|_|_\ |___|_|\_|___/|___/_/\_\

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourIndex<A: AddressExt> {
    pub(crate) iface: InterfaceHandle,
    pub(crate) addr: Address<A>,
}

impl<A: AddressExt> core::fmt::Display for NeighbourIndex<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} via {}", self.iface, self.addr)
    }
}

//  _   _ ______ _____ _____ _    _ ____   ____  _    _ _____
// | \ | |  ____|_   _/ ____| |  | |  _ \ / __ \| |  | |  __ \
// |  \| | |__    | || |  __| |__| | |_) | |  | | |  | | |__) |
// | . ` |  __|   | || | |_ |  __  |  _ <| |  | | |  | |  _  /
// | |\  | |____ _| || |__| | |  | | |_) | |__| | |__| | | \ \
// |_| \_|______|_____\_____|_|  |_|____/ \____/ \____/|_|  \_\
//
//
//  ______ _   _ _______ _______     __
// |  ____| \ | |__   __|  __ \ \   / /
// | |__  |  \| |  | |  | |__) \ \_/ /
// |  __| | . ` |  | |  |  _  / \   /
// | |____| |\  |  | |  | | \ \  | |
// |______|_| \_|  |_|  |_|  \_\ |_|

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
    pub(crate) mcast_hello_info: RxHelloInfo,

    /// a history of recently received Unicast Hello packets from this neighbour
    ///
    /// the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    pub(crate) ucast_hello_info: RxHelloInfo,

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
    pub(crate) ihu_hold_timer: Timer,

    // Scheduling state, required to drive Sans-IO state machine.
    /// Pending TLV's that need to go out during `poll_transmit`
    pub(crate) pending: NeighbourPending,
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
    /// Timer for sending ihus to this neighbour.
    pub(crate) outbound_ihu_timer: Timer,
}

impl<A: AddressExt> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex {
            iface: self.iface,
            addr: self.address,
        }
    }
}

impl<A: AddressExt> Neighbour<A> {
    pub(crate) fn new(now: Instant, config: NeighbourConfig<A>) -> Result<Self, NeighbourError<A>> {
        let ucast_hello_timer = match config.ucast_hello_interval {
            Some(interval) => Some(Timer::eager_from_interval(now, interval)?),
            None => None,
        };

        Ok(Self {
            iface: config.iface,
            address: config.address,
            // When a neighbour is new, this router has never received a hello from it. This
            // populates the RxHelloInfo with spec defaults.
            mcast_hello_info: RxHelloInfo::spec_default(now),
            ucast_hello_info: RxHelloInfo::spec_default(now),
            // When a neighbour is new, this router has never received an IHU packet from it, so TX
            // cost is set to infinity
            tx_cost: TxCost::INFINITY,
            // When a neighbour is new, this router has never received an IHU from it, so it's IHU
            // timer is set to the spec default.
            ihu_hold_timer: Timer::from_interval(now, config.inbound_ihu_interval)?,
            pending: NeighbourPending {
                ucast_hello: ucast_hello_timer.map(|t| TxHelloInfo {
                    seqno: SeqNo(0),
                    timer: t,
                }),
                // When a neighbour is new, send an immediate IHU to speed up convergence.
                outbound_ihu_timer: Timer::eager_from_interval(now, config.outbound_ihu_interval)?,
            },
        })
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

    //  _  _   _   _  _ ___  _    ___   _  _ ___ _    _    ___
    // | || | /_\ | \| |   \| |  | __| | || | __| |  | |  / _ \
    // | __ |/ _ \| .` | |) | |__| _|  | __ | _|| |__| |_| (_) |
    // |_||_/_/ \_\_|\_|___/|____|___| |_||_|___|____|____\___/

    pub(crate) fn handle_hello(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        let mut rx_hello_info = if flags.is_unicast() {
            self.ucast_hello_info
        } else {
            self.mcast_hello_info
        };

        match rx_hello_info.record_hello(now, seqno, interval) {
            Ok(_) if flags.is_unicast() => self.ucast_hello_info = rx_hello_info,
            Ok(_) => self.mcast_hello_info = rx_hello_info,
            Err(BigSeqnoDiff(seq)) => {
                b_debug!(
                    "Neighbour flush - iface {}, addr: {} - multicast: {},  seqno diff: {}",
                    self.iface,
                    self.address,
                    flags.is_multicast(),
                    seq
                );
                self.seqno_flush(now, hello);
            }
            Err(RxHelloInfoErr::Timer(t)) => {
                b_debug!("Err - {} - interval: {:?}", t, interval);
            }
        }
    }

    /// Performs the "flush and re-create" function for when the diff between expected seqno and
    /// actual is greater than 16
    fn seqno_flush(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        let default_config = NeighbourConfig::spec_default(self.iface, self.address);

        // Reset everything to default, keeping original settings for outgoing timers.
        //
        // Reset tx cost to infinite, this will be set on the next received IHU from this
        // neighbour.
        self.tx_cost = TxCost::INFINITY;
        // Reset IHU timer.
        self.ihu_hold_timer = Timer::new_unchecked(now, *default_config.inbound_ihu_interval);
        // Reset outgoing ucast hello info if it exists.
        self.pending.ucast_hello = self.pending.ucast_hello.map(|mut utx| {
            utx.timer.restart(now);
            TxHelloInfo {
                seqno: SeqNo(0),
                timer: utx.timer,
            }
        });
        // Send an immediate IHU on the next poll_output that hits this neighbour.
        self.pending.outbound_ihu_timer.restart_eager(now);

        // Now process the incoming hello. An unscheduled Hello (Interval 0) says nothing about
        // when the next one is due, so the interface default stands in.
        let hello_interval = if interval.is_zero() {
            DEFAULT_MULTICAST_HELLO_INTERVAL
        } else {
            interval
        };

        // Reset both rx hello infos. This prevents a flush from one message type from causing a
        // flush for another.
        self.mcast_hello_info = RxHelloInfo::spec_default(now);
        self.ucast_hello_info = RxHelloInfo::spec_default(now);

        if flags.is_unicast() {
            self.ucast_hello_info.expected_seqno = Some(seqno + 1);
            self.ucast_hello_info.timer =
                Timer::from_interval(now, hello_interval).expect("Timer duration checked above");
            self.ucast_hello_info.history.record(true);
        } else {
            self.mcast_hello_info.expected_seqno = Some(seqno + 1);
            self.mcast_hello_info.timer =
                Timer::from_interval(now, hello_interval).expect("Timer duration checked above");
            self.mcast_hello_info.history.record(true);
        }
    }

    //  _  _   _   _  _ ___  _    ___   ___ _  _ _   _
    // | || | /_\ | \| |   \| |  | __| |_ _| || | | | |
    // | __ |/ _ \| .` | |) | |__| _|   | || __ | |_| |
    // |_||_/_/ \_\_|\_|___/|____|___| |___|_||_|\___/

    pub(crate) fn handle_ihu(
        &mut self,
        now: Instant,
        ihu: IhuSlice<'_>,
        hold_time: DurationMultiplier,
    ) -> Result<(), NeighbourError<A>> {
        let rx_cost = ihu.rx_cost();
        let interval = ihu.interval();

        let timer_dur: Duration = interval.into();

        self.ihu_hold_timer = Timer::from_duration(now, timer_dur * hold_time)?;

        self.tx_cost = rx_cost.into();

        Ok(())
    }

    //  _____   ____  _      _         ____  _    _ _______ _____  _    _ _______
    // |  __ \ / __ \| |    | |       / __ \| |  | |__   __|  __ \| |  | |__   __|
    // | |__) | |  | | |    | |      | |  | | |  | |  | |  | |__) | |  | |  | |
    // |  ___/| |  | | |    | |      | |  | | |  | |  | |  |  ___/| |  | |  | |
    // | |    | |__| | |____| |____  | |__| | |__| |  | |  | |    | |__| |  | |
    // |_|     \____/|______|______|  \____/ \____/   |_|  |_|     \____/   |_|

    //  ___  ___  _    _      _   _  ___   _   ___ _____   _  _ ___ _    _    ___
    // | _ \/ _ \| |  | |    | | | |/ __| /_\ / __|_   _| | || | __| |  | |  / _ \
    // |  _/ (_) | |__| |__  | |_| | (__ / _ \\__ \ | |   | __ | _|| |__| |_| (_) |
    // |_|  \___/|____|____|  \___/ \___/_/ \_\___/ |_|   |_||_|___|____|____\___/

    pub(crate) fn poll_for_ucast_hello<'output>(
        &mut self,
        now: Instant,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        // Check if this neighbour wants to send ucast hellos. If not, return the writer unchanged.
        let Some(ucast_hello) = &mut self.pending.ucast_hello else {
            return Ok(writer);
        };

        // If the timer is not done, update next poll and return writer unchanged.
        if let Some(remaining) = ucast_hello.timer.time_remaining(now) {
            *next_poll = remaining.min(*next_poll);
            return Ok(writer);
        }

        let flags = HelloFlags::new_unicast();
        let seqno = ucast_hello.seqno;
        let duration = ucast_hello.timer.duration();

        b_trace!(
            "[SEND] UCAST HELLO - iface {}, addr: {} - {:?}, {:?}, interval: {}",
            self.iface,
            self.address,
            flags,
            seqno,
            duration.as_centis()
        );
        writer = writer
            .write_hello(flags, seqno, duration.into())?
            .finish_tlv()?;

        ucast_hello.timer.restart(now);
        ucast_hello.seqno += 1;

        Ok(writer)
    }

    //  ___  ___  _    _      ___ _  _ _   _
    // | _ \/ _ \| |  | |    |_ _| || | | | |
    // |  _/ (_) | |__| |__   | || __ | |_| |
    // |_|  \___/|____|____| |___|_||_|\___/

    pub(crate) fn poll_for_ihu<'output>(
        &mut self,
        now: Instant,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        cost_calc: &'static dyn LinkCostCalculator,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        // If there is time remaining in the IHU timer for this neighbour, update next_poll and
        // return the writer unchanged.
        if let Some(remaining) = self.pending.outbound_ihu_timer.time_remaining(now) {
            *next_poll = remaining.min(*next_poll);
            return Ok(writer);
        }

        // If the active address has been claimed and it is not destined for this neighbour, return
        // the writer unchanged.
        if active_dest
            .unicast_addr()
            .is_some_and(|addr| *addr != self.address)
        {
            return Ok(writer);
        }

        // At this point
        //
        // The neighbour:
        // - Has an IHU due
        // The active address is either:
        // - Free
        // - Unicast and matches this address
        // - Multicast

        // The Address field names the IHU's destination, so that IHUs for several neighbours
        // can be aggregated into one multicast packet and each receiver can pick out its own.

        // If the active_dest is already targeted at this neighbour on a unicast address, then we
        // can use the wildcard AE with a 0 length address field to save network resources.
        let (ae, addr_wire): (u8, &[u8]) = if active_dest.unicast_addr() == Some(&self.address) {
            (0, &[])
        } else {
            // Otherwise this is a multicast address and the address needs to be included.
            let ae = match self.address.encoding().try_into() {
                Ok(val) => val,
                Err(err) => {
                    // The built in address encoding is well tested, if this error occurs it is due
                    // to the user's AddressExt failing. Return the writer unchanged.
                    b_debug!("AddressEncodingExt Error: {}", err);
                    return Ok(writer);
                }
            };
            (ae, self.address.as_wire())
        };
        let interval = self.pending.outbound_ihu_timer.interval();
        let rx_cost =
            cost_calc.rx_cost(self.mcast_hello_info.history, self.ucast_hello_info.history);

        // The Interval field advertises when the next IHU is due, which RFC 8966 Appendix B
        // puts at three times the multicast Hello interval. Once the periodic cadence lands
        // this should come from whatever timer actually schedules the next IHU.
        b_debug!(
            "[SEND] IHU -  dest_addr: {:?} - ae: {}, rx_cost: {}, interval_csec: {}, addr: {:?}",
            active_dest,
            ae,
            rx_cost,
            interval.as_centis(),
            self.address
        );

        writer = writer
            .write_ihu(ae, rx_cost, interval, addr_wire)?
            .finish_tlv()?;

        // Claim the active address after the write succeeds.
        //
        // Prefer to send to multicast address as an optimization.
        // TODO(#11): Wire up the preference for unicast IHU's here.
        if active_dest.is_free() {
            let _ = active_dest.claim(DestAddr::Multicast);
        }

        // Once the packet has been written, this neighbour's IHU is no longer due. Clearing
        // only after a successful write is what lets a destination conflict defer a neighbour
        // to the next poll instead of dropping its IHU.
        self.pending.outbound_ihu_timer.restart(now);

        Ok(writer)
    }
}

//  ___ __  __  _  _ ___ _    _    ___    ___ _  _ ___ ___
// | _ \\ \/ / | || | __| |  | |  / _ \  |_ _| \| | __/ _ \
// |   / >  <  | __ | _|| |__| |_| (_) |  | || .` | _| (_) |
// |_|_\/_/\_\ |_||_|___|____|____\___/  |___|_|\_|_| \___/

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RxHelloInfo {
    pub(crate) history: BitHistory,
    // TODO: Will likely need to change this to a union enum that contains either the Seqno or a
    // bit history since added. Otherwise there will be no way to expire neighbours that have never
    // received a hello.
    pub(crate) expected_seqno: Option<SeqNo>,
    pub(crate) timer: Timer,
}

impl RxHelloInfo {
    pub(crate) const MISSED_HELLO_MAX: u16 = 16;

    /// When a neighbour is new, we have never received a hello from it, so its bit history is all
    /// zeros, its expected seqno is None, and its multicast hello timer is set to the default
    /// value.
    pub(crate) fn spec_default(now: Instant) -> Self {
        Self {
            history: BitHistory::default(),
            expected_seqno: None,
            timer: Timer::new_unchecked(
                now,
                *DEFAULT_MULTICAST_HELLO_INTERVAL * HELLO_INTERVAL_MULTIPLIER,
            ),
        }
    }

    /// `advertised_interval` is the raw Interval from the Hello; the jitter margin is applied here
    /// so that callers cannot forget it.
    pub(crate) fn new_from_hello(
        now: Instant,
        received_seqno: SeqNo,
        advertised_interval: Interval,
    ) -> Result<Self, TimerError> {
        let mut out = Self {
            history: BitHistory::default(),
            // This hello is about to be recorded below, so the next one this neighbour sends is
            // the one being waited on.
            expected_seqno: Some(received_seqno + 1),
            timer: Timer::from_duration(now, *advertised_interval * HELLO_INTERVAL_MULTIPLIER)?,
        };
        // Since this is originated from a hello, the history needs at least one recorded hello.
        out.history.record(true);
        Ok(out)
    }

    /// Records a missed hello (if applicable) and returns the time remaining until it fires.
    fn poll_tick(&mut self, now: Instant) -> Option<Duration> {
        // If we have never received a seqno for this rx info, there is nothing to do.
        if self.expected_seqno.is_none() {
            return None;
        }
        // If this timer has not fired, return the duration it has remaining.
        if let Some(remaining) = self.timer.time_remaining(now) {
            return Some(remaining);
        }

        // Appendix A.1: "the local node adds a 0 bit to the corresponding Hello history, and
        // increments the expected Hello number". Without the increment the hello this timeout
        // stands in for would be charged twice — once here, and again as a seqno gap when the
        // neighbour's next hello arrives.
        self.history.record(false);
        self.expected_seqno.as_mut().map(|seq| *seq = *seq + 1);

        self.timer.restart(now);
        Some(self.timer.duration())
    }

    fn record_hello(
        &mut self,
        now: Instant,
        received_seqno: SeqNo,
        new_interval: Interval,
    ) -> Result<(), RxHelloInfoErr> {
        // First check incoming seqno against expected if we have received a hello from this
        // neighbour in the past.
        if let Some(expected_seqno) = self.expected_seqno {
            //  Forward distance between received and expected across a seqno wrap
            let forward = (received_seqno - expected_seqno).0;
            //  Backward distance between received and expected across a seqno wrap
            let back = (expected_seqno - received_seqno).0;
            // The minimum of the two is the actual distance between received and expected.
            let diff = forward.min(back);

            if diff > Self::MISSED_HELLO_MAX {
                return Err(RxHelloInfoErr::BigSeqnoDiff(diff));
            }

            if expected_seqno < received_seqno {
                // "the sending node has decreased its Hello interval, and some Hellos were lost;
                // the receiving node adds (nr - ne) 0 bits to the Hello history"
                self.history.record_many(false, forward.into());
            } else if expected_seqno > received_seqno {
                // "the sending node has increased its Hello interval without our noticing; the
                // receiving node removes the last (ne - nr) entries from this neighbour's Hello
                // history"
                self.history.undo(back.into());
            }
        }
        // Now record the new expected seqno.
        // The spec dictates that the expected seqno be set to the receieved seqno + 1 regardless
        // of the relative value of the two seqnos.
        self.expected_seqno = Some(received_seqno + 1);

        // Record the received hello in the bit history.
        self.history.record(true);

        // A hello with a non-zero interval is scheduled.
        if !new_interval.is_zero() {
            self.timer
                .set_tick_duration(*new_interval * HELLO_INTERVAL_MULTIPLIER)
                .expect("Just checked that interval is not zero");
            // Timer only restarts on scheduled hellos.
            self.timer.restart(now);
        }

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

//  _______  __  _  _ ___ _    _    ___    ___ _  _ ___ ___
// |_   _\ \/ / | || | __| |  | |  / _ \  |_ _| \| | __/ _ \
//   | |  >  <  | __ | _|| |__| |_| (_) |  | || .` | _| (_) |
//   |_| /_/\_\ |_||_|___|____|____\___/  |___|_|\_|_| \___/

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct TxHelloInfo {
    pub(crate) seqno: SeqNo,
    pub(crate) timer: Timer,
}

//  _______ ______  _____ _______ _____
// |__   __|  ____|/ ____|__   __/ ____|
//    | |  | |__  | (___    | | | (___
//    | |  |  __|  \___ \   | |  \___ \
//    | |  | |____ ____) |  | |  ____) |
//    |_|  |______|_____/   |_| |_____/

#[cfg(test)]
mod test {
    use super::*;
    use crate::extension::NoExtension;
    use crate::packet::tlv::TypedTlv;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::packet::tlv::tlv_slice::TlvSlice;

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
        let handle = InterfaceHandle::try_from("iface_1").expect("bad interface handle");
        let config = NeighbourConfig::spec_default(handle, core::net::Ipv6Addr::LOCALHOST.into());
        Neighbour::new(now, config).expect("bad neighbour")
    }

    fn mcast_history(n: &Neighbour<NoExtension>) -> BitHistory {
        n.mcast_hello_info.history
    }

    //  _  _ ___ ___ _____ ___  _____   __
    // | || |_ _/ __|_   _/ _ \| _ \ \ / /
    // | __ || |\__ \ | || (_) |   /\ V /
    // |_||_|___|___/ |_| \___/|_|_\ |_|

    /// A neighbour that has never been heard from has an empty history — it has proved nothing
    /// about the link yet — and each hello it does send earns exactly one bit.
    #[test]
    fn a_new_neighbour_earns_its_history_one_hello_at_a_time() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        assert_eq!(
            mcast_history(&n).read(),
            0,
            "nothing has been heard from this neighbour yet"
        );

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));

        assert_eq!(mcast_history(&n).read(), 0b1);
    }

    #[test]
    fn consecutive_hellos_keep_the_history_clean() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        for seqno in 0..8 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
        }

        assert_eq!(
            mcast_history(&n).read(),
            0b1111_1111,
            "eight hellos in order, no misses"
        );
    }

    /// The count alone cannot tell "one miss" from "three": both leave the same number of ones in
    /// the window. The bit pattern is what pins that a gap costs one zero per skipped hello.
    #[test]
    fn a_gap_in_seqnos_records_one_miss_per_skipped_hello() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        // Seqnos 1, 2 and 3 never arrived.
        n.handle_hello(now, hello(&hello_tlv(false, 4, 100)));

        assert_eq!(
            mcast_history(&n).read(),
            0b1_000_1,
            "three missed hellos should shift in exactly three zeros"
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
        assert_eq!(mcast_history(&n).count(), 2, "three hellos were missed");

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

    /// [Appendix A.1](https://datatracker.ietf.org/doc/html/rfc8966#name-maintaining-hello-history):
    /// a hello whose seqno is *smaller* than expected means the sending node increased its Hello
    /// interval without our noticing. The zeros shifted in for the hellos we thought were missed
    /// were never really missed, so the last `ne - nr` entries are removed ("undo history").
    ///
    /// `ne` is then set to `nr + 1` like in every other case, which is what resynchronises us
    /// with the now-slower sender rather than leaving us permanently ahead of it.
    #[test]
    fn a_hello_behind_the_expected_seqno_undoes_history_and_resyncs() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        for seqno in 0..3 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
        }
        assert_eq!(mcast_history(&n).read(), 0b111, "no hellos were missed");
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(3)
        );

        // Two behind: the last two entries are undone, then this hello is appended.
        n.handle_hello(now, hello(&hello_tlv(false, 1, 100)));
        assert_eq!(
            mcast_history(&n).read(),
            0b11,
            "(ne - nr) == 2 entries removed, then a 1 bit appended"
        );
        assert_eq!(
            n.mcast_hello_info.expected_seqno.expect("Sould have seqno"),
            SeqNo(2),
            "ne is set to nr + 1 in every case, resyncing with the slower sender"
        );

        // Resynchronised, so the sender's next hello is in order and costs nothing.
        n.handle_hello(now, hello(&hello_tlv(false, 2, 100)));
        assert_eq!(mcast_history(&n).read(), 0b111);
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(3)
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

        assert_eq!(
            mcast_history(&n).read(),
            0b1_000_1,
            "the multicast side saw three missed hellos"
        );
        assert_eq!(
            n.ucast_hello_info.history.read(),
            0b1,
            "a multicast gap must not be charged against the unicast history"
        );
    }

    /// A unicast hello must not create or disturb the multicast history, and vice versa — they are
    /// separate reachability measurements over the same link.
    #[test]
    fn a_unicast_hello_alone_leaves_the_multicast_history_untouched() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(true, 0, 100)));

        assert_eq!(mcast_history(&n).read(), 0);
        assert_eq!(n.ucast_hello_info.history.read(), 0b1);
    }

    /// The window is 16 wide and seqnos are modulo 2^16, so an ordinary gap that straddles the
    /// wrap is still an ordinary gap. Measuring it with a non-modular distance reads 65534 -> 2 as
    /// a jump of 65532 and flushes a perfectly healthy neighbour on every wrap.
    #[test]
    fn a_gap_across_the_seqno_wrap_is_an_ordinary_gap() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        // Resynchronise onto a seqno just below the wrap.
        n.handle_hello(now, hello(&hello_tlv(false, 65_533, 100)));
        assert_eq!(mcast_history(&n).read(), 0b1);
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(65_534)
        );

        // 65534 and 65535 were lost; 0 arrives on the other side of the wrap.
        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));

        assert_eq!(
            mcast_history(&n).read(),
            0b1_00_1,
            "two missed hellos across the wrap, not a flush"
        );
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(1)
        );
    }

    /// The mirror image: an undo whose distance straddles the wrap.
    #[test]
    fn a_rewind_across_the_seqno_wrap_undoes_history() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        n.handle_hello(now, hello(&hello_tlv(false, 65_534, 100)));
        n.handle_hello(now, hello(&hello_tlv(false, 65_535, 100)));
        n.handle_hello(now, hello(&hello_tlv(false, 0, 100)));
        assert_eq!(mcast_history(&n).read(), 0b111);
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(1)
        );

        // Two behind, back across the wrap.
        n.handle_hello(now, hello(&hello_tlv(false, 65_535, 100)));

        assert_eq!(mcast_history(&n).read(), 0b11, "two entries undone");
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(0)
        );
    }

    //  ___ ___ ___  ___  _  _  ___
    // / __| __/ _ \| _ \| \| |/ _ \
    // \__ \ _| (_) |   /| .` | (_) |
    // |___/___\__\_\_|_\|_|\_|\___/
    //
    //  ___ _    _   _ ___ _  _
    // | __| |  | | | / __| || |
    // | _|| |__| |_| \__ \ __ |
    // |_| |____|\___/|___/_||_|

    /// A seqno further than `MISSED_HELLO_MAX` from the expected one is not a measurable gap — the
    /// history window is only 16 wide, so charging it would say nothing useful. The neighbour is
    /// resynchronised from the hello instead of accumulating nonsense.
    #[test]
    fn a_seqno_jump_past_the_window_flushes_the_correct_hell_history() {
        let now = Instant::from_secs(0);
        let mut n = neighbour(now);

        // Set up hello histories for mcast and ucast
        for seqno in 0..4 {
            n.handle_hello(now, hello(&hello_tlv(false, seqno, 100)));
            n.handle_hello(now, hello(&hello_tlv(true, seqno, 100)));
        }
        assert_eq!(mcast_history(&n).read(), 0b1111);

        // Well past the 16-hello window the history can represent.
        n.handle_hello(now, hello(&hello_tlv(false, 25, 100)));

        assert_eq!(
            mcast_history(&n).read(),
            0b1,
            "the history restarts from the resynchronising hello"
        );
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(26)
        );
        assert!(
            n.ucast_hello_info.expected_seqno.is_none(),
            "When one history is flushed, the other should be reset to default"
        );
        n.handle_hello(now, hello(&hello_tlv(true, 25, 100)));
        assert_eq!(
            n.mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(26),
            "Newly flushed ucast history should not flush again"
        );
    }
}
