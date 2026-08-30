//! Newtype wrappers for the "distance" quantities used by the Babel
//! routing protocol.
//!
//! All four share the same wire representation a 16-bit unsigned
//! integer where `0xFFFF` means "infinite" but they are semantically distinct quantities that are
//! easy to get mixed up.

use core::cmp::Ordering;
use core::convert::TryFrom;
use core::fmt;
use core::ops::Add;

use crate::data_types::seqno::SeqNo;
use crate::utils::Duration;

/// Any distance that is 0xFFFF is considered "infinity"
pub const INFINITY: u16 = 0xFFFF;

macro_rules! distance_newtype {
    (
        $(#[$attr:meta])*
        $name:ident
    ) => {
        $(#[$attr])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "defmt",derive(defmt::Format))]
        pub struct $name(u16);

        impl $name {
            /// The RFC 8966 sentinel value meaning "infinite".
            pub const INFINITY: Self = Self(INFINITY);

            /// Construct directly from a raw wire value, unvalidated.
            #[inline]
            pub const fn from_raw(v: u16) -> Self {
                Self(v)
            }

            /// The raw wire value.
            #[inline]
            pub const fn raw(self) -> u16 {
                self.0
            }

            #[inline]
            pub const fn is_infinite(self) -> bool {
                self.0 == INFINITY
            }

            #[inline]
            pub const fn to_wire(&self)-> [u8;2]{
                self.0.to_be_bytes()
            }
        }

        impl From<u16> for $name {
            #[inline]
            fn from(v: u16) -> Self {
                Self(v)
            }
        }

        impl From<$name> for u16 {
            #[inline]
            fn from(v: $name) -> u16 {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if self.is_infinite() {
                    write!(f, "infinity")
                } else {
                    write!(f, "{}", self.0)
                }
            }
        }
    };
}

distance_newtype! {
    /// A node's estimate of its *reception* cost from a given neighbour
    /// ([Section 3.4.3](https://datatracker.ietf.org/doc/html/rfc8966#name-cost-computation)).
    ///
    /// Derived from Hello history and sent to that neighbour in an
    /// [IHU TLV](crate::packet::tlv::IhuSlice).
    RxCost
}

distance_newtype! {
    /// The cost of *transmitting* to a given neighbour, as reported by that
    /// neighbour's IHU.
    ///
    /// Stored in the neighbour table. Numerically this is just the neighbour's
    /// [`RxCost`], viewed from across the link.
    TxCost
}

distance_newtype! {
    /// A route metric
    /// ([Section 3.5.2](https://datatracker.ietf.org/doc/html/rfc8966#name-metric-computation)).
    ///
    /// The accumulated path cost carried in Update TLVs, used for route selection
    /// ([Section 3.6](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection))
    /// and the feasibility condition
    /// ([Section 3.5.1](https://datatracker.ietf.org/doc/html/rfc8966#name-the-feasibility-condition)).
    Metric
}

impl Metric {
    /// Apply an exponential smoothing algorithm to this metric.
    pub(crate) fn apply_smoothing(
        &mut self,
        other: Metric,
        step_dur: Duration,
        time_constant: Duration,
    ) {
        if step_dur == Duration::ZERO {
            // If the time step was zero, then do nothing.
            return;
        }

        // Get tau as f64 seconds with a div by zero protection.
        let tau =
            core::time::Duration::from(time_constant.max(Duration::from_micros(1))).as_secs_f64();
        // Get delta_t as f64 seconds.
        let delta_f64 = core::time::Duration::from(step_dur).as_secs_f64();

        let alpha = 1.0 - libm::exp(-delta_f64 / tau);

        self.0 = libm::round(self.0 as f64 + (other.0 as f64 - self.0 as f64) * alpha) as u16;
    }
}

// `Cost` is deliberately *not* built with `distance_newtype!`: unlike
// the other three, it is required to be "strictly positive" per the spec. This means it cannot be
// zero.

/// A link cost C(A, B)
/// ([Section 3.4.3](https://datatracker.ietf.org/doc/html/rfc8966#name-cost-computation)).
///
/// The local, policy-defined combination of RxCost and TxCost for a single link.
/// MUST be strictly positive when finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cost(u16);

impl Cost {
    /// All costs of 0xFFFF are considered "infinite"
    pub const INFINITY: Self = Self(INFINITY);

    /// Construct a validated [`Cost`], enforcing the
    /// requirement that a finite cost be strictly positive.
    /// `Cost::INFINITY` is always accepted.
    pub fn new(v: u16) -> Result<Self, NonPositiveCost> {
        if v == 0 {
            Err(NonPositiveCost)
        } else {
            Ok(Self(v))
        }
    }

    /// Construct directly from a raw wire value, without validation.
    /// Prefer [`Cost::new`] or a `From` conversion where possible.
    #[inline]
    pub const fn from_raw(v: u16) -> Self {
        Self(v)
    }

    /// The raw wire value.
    #[inline]
    pub const fn raw(self) -> u16 {
        self.0
    }

    #[inline]
    pub const fn is_infinite(self) -> bool {
        self.0 == INFINITY
    }
}

impl From<Cost> for u16 {
    #[inline]
    fn from(v: Cost) -> u16 {
        v.0
    }
}

impl TryFrom<u16> for Cost {
    type Error = NonPositiveCost;
    fn try_from(v: u16) -> Result<Self, Self::Error> {
        Cost::new(v)
    }
}

impl fmt::Display for Cost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_infinite() {
            write!(f, "infinity")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Error returned by [`Cost::new`] when a value would violate the requirement that a *finite* cost
/// be strictly positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonPositiveCost;

impl fmt::Display for NonPositiveCost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a finite link cost must be strictly positive (greater than zero, less than infinity)"
        )
    }
}

/// The fesibility condition as described in
/// [Section 3.5.1](https://datatracker.ietf.org/doc/html/rfc8966#name-the-feasibility-condition)
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Feasibility {
    pub(crate) seqno: SeqNo,
    pub(crate) metric: Metric,
}

impl Feasibility {
    pub fn new(seqno: SeqNo, metric: Metric) -> Self {
        Self { seqno, metric }
    }
}

impl Ord for Feasibility {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // Early escape hatch for equality
        if self.seqno == other.seqno && self.metric == other.metric {
            return Ordering::Equal;
        }
        // Section 3.5.1 with modifications for readability:
        // (self.seqno, self.metric) < (other.seqno, other.metric)

        // when

        // self.seqno > other.seqno or (self.seqno = other.seqno and self.metric < other.metric)

        // where sequence numbers are compared modulo 216.

        // If our seqno is greater, than our fesibility is less.
        if self.seqno > other.seqno {
            return Ordering::Less;
        }

        // If the seqnos are equal and our metric is less, than our fesibility is less.
        if self.seqno == other.seqno && self.metric < other.metric {
            return Ordering::Less;
        }

        // If none of the above conditions are met, then our feasibility is greater.
        Ordering::Greater
    }
}

impl PartialOrd for Feasibility {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// --- RxCost <-> TxCost
//
// These don't describe the same node's data: an IHU carries A's
// rxcost for the link *to* A, and the receiving neighbour B stores
// that number, unchanged, as its txcost *to* A. The conversion is exact and lossless;
// what changes is *which node* the number describes, not the number
// itself -- which is exactly what "crossing the link" should look
// like in the type system.

impl From<RxCost> for TxCost {
    #[inline]
    fn from(rx: RxCost) -> Self {
        TxCost(rx.0)
    }
}

impl From<TxCost> for RxCost {
    #[inline]
    fn from(tx: TxCost) -> Self {
        RxCost(tx.0)
    }
}

// --- TxCost -> Cost
//
// RFC 8966 leaves cost computation as a matter of local policy (see `LinkCostCalculator`) so this
// impl does not *compute* the link cost, it merely maps infinity to infinity and clamps cost to a
// minimum of 1.

impl From<TxCost> for Cost {
    #[inline]
    fn from(tx: TxCost) -> Self {
        if tx.is_infinite() {
            Cost::INFINITY
        } else {
            // A finite txcost of 0 shouldn't occur on the wire, but
            // nothing in the spec forbids it; clamp to 1 so the
            // strictly-positive invariant always holds regardless of
            // input.
            Cost(tx.0.max(1))
        }
    }
}

// --- Cost + Metric -> Metric
//
// RFC 8966 3.5.2: the RECOMMENDED additive metric is
// M(c, m) = c + m, which must satisfy strict monotonicity
// (M(c, m) > m whenever c is finite) and M(c, m) = infinite whenever
// c is infinite. `Add` is implemented in both orders so a `Cost` and
// a neighbour advertised `Metric` combine naturally either way.

impl Add<Metric> for Cost {
    type Output = Metric;

    fn add(self, neighbour_metric: Metric) -> Metric {
        if self.is_infinite() || neighbour_metric.is_infinite() {
            Metric::INFINITY
        } else {
            // The spec requires strict monotonicity to avoid loops. That is M(m, c) > m. If a link
            // cost saturates, then M(m, c) = INFINITY and INFINITY is always greater than some
            // finite m.
            Metric(self.0.saturating_add(neighbour_metric.0))
        }
    }
}

impl Add<Cost> for Metric {
    type Output = Metric;

    #[inline]
    fn add(self, cost: Cost) -> Metric {
        cost + self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rxcost_crosses_the_link_unchanged() {
        let rx = RxCost::from(96);
        let tx: TxCost = rx.into();
        assert_eq!(tx.raw(), 96);
    }

    #[test]
    fn infinity_propagates_through_every_stage() {
        let tx = TxCost::INFINITY;
        let cost: Cost = tx.into();
        assert!(cost.is_infinite());

        let m = cost + Metric::from(5);
        assert!(m.is_infinite());
    }

    #[test]
    fn additive_metric_is_strictly_monotonic() {
        let c = Cost::new(3).unwrap();
        let m = Metric::from(10);
        assert_eq!((c + m).raw(), 13);
        assert!((c + m).raw() > m.raw());
    }

    #[test]
    fn cost_rejects_zero() {
        assert!(Cost::new(0).is_err());
        assert!(Cost::new(1).is_ok());
        assert_eq!(Cost::new(INFINITY).unwrap(), Cost::INFINITY);
    }

    // ---- Feasibility ------------------------------------------------------------------------

    /// A feasibility distance as it would be read out of an Update: (seqno, advertised metric).
    fn fd(seqno: u16, metric: u16) -> Feasibility {
        Feasibility::new(SeqNo(seqno), Metric::from_raw(metric))
    }

    /// RFC 8966 [3.5.1](https://datatracker.ietf.org/doc/html/rfc8966#name-the-feasibility-condition):
    /// `(s, m) < (s', m')` when `s > s'`, or when `s = s'` and `m < m'`.
    ///
    /// Seqno takes strict precedence, so a newer announcement wins even when its metric is far
    /// worse — that is what lets a node recover from a bad metric without waiting out the old one.
    ///
    /// Note the ordering runs opposite to intuition: a *smaller* `Feasibility` is the better one,
    /// because `update_is_feasible` asks whether the incoming distance is strictly less than the
    /// one already recorded for the source.
    #[test]
    fn a_newer_seqno_wins_regardless_of_metric() {
        assert!(fd(10, 500) < fd(5, 1));
        assert!(fd(5, 1) > fd(10, 500));
    }

    /// The metric only breaks ties within a single seqno.
    #[test]
    fn with_equal_seqnos_the_smaller_metric_wins() {
        assert!(fd(5, 10) < fd(5, 20));
        assert!(fd(5, 20) > fd(5, 10));
    }

    /// The condition is *strictly* less than, so an update that merely repeats the distance
    /// already on record is not feasible.
    #[test]
    fn an_identical_distance_is_neither_better_nor_worse() {
        assert_eq!(fd(5, 10).cmp(&fd(5, 10)), Ordering::Equal);
        assert!(!(fd(5, 10) < fd(5, 10)));
    }

    /// A retraction carries an infinite metric, so at its own seqno it has to be the worst distance
    /// there is — while still losing to any newer seqno, since seqno takes precedence.
    #[test]
    fn an_infinite_metric_is_the_worst_distance_at_its_seqno() {
        assert!(fd(5, INFINITY) > fd(5, INFINITY - 1));
        assert!(fd(6, INFINITY) < fd(5, 0));
    }

    /// Seqnos are compared modulo 2^16, so a distance whose seqno has just wrapped is *newer* than
    /// one sitting just below the wrap — not 65535 steps older.
    #[test]
    fn seqno_comparison_wraps() {
        assert!(fd(0, 100) < fd(65_535, 100));
        assert!(fd(65_535, 100) > fd(0, 100));
    }

    /// [3.2.1](https://datatracker.ietf.org/doc/html/rfc8966#name-sequence-numbers) leaves two
    /// seqnos exactly 32768 apart undefined — there is no answer to which came first. An update at
    /// that distance therefore cannot be shown to be *strictly* better than what is on record, so
    /// it is not feasible, and that has to hold from both sides.
    ///
    /// This asserts the `<` outcome rather than what `cmp` returns: the outcome is what 3.5.1
    /// actually requires, and it stays correct however the incomparability ends up being
    /// represented.
    #[test]
    fn seqnos_half_the_space_apart_are_feasible_in_neither_direction() {
        let a = fd(0, 100);
        let b = fd(32_768, 100);

        assert!(!(a < b));
        assert!(!(b < a));
    }

    // ---- Metric smoothing -------------------------------------------------------------------
    //
    // `apply_smoothing` is the exponential smoothing Appendix A.3 asks for as the input to route
    // selection hysteresis: alpha = 1 - e^(-dt/tau), and the smoothed metric moves `alpha` of the
    // way towards the metric it is chasing.

    /// One full time constant closes 1 - 1/e of the gap. Pinning the arithmetic keeps a refactor
    /// from silently changing how fast hysteresis reacts to a metric change.
    #[test]
    fn one_time_constant_closes_the_expected_fraction_of_the_gap() {
        let tau = Duration::from_secs(10);
        let mut smoothed = Metric::from_raw(0);

        smoothed.apply_smoothing(Metric::from_raw(100), tau, tau);

        // round(0 + (100 - 0) * 0.6321) == 63
        assert_eq!(smoothed, Metric::from_raw(63));
    }

    /// A metric that improves has to be smoothed at exactly the rate one that worsens is, or
    /// hysteresis would bias selection in one direction.
    #[test]
    fn smoothing_runs_downwards_at_the_same_rate() {
        let tau = Duration::from_secs(10);
        let mut smoothed = Metric::from_raw(100);

        smoothed.apply_smoothing(Metric::from_raw(0), tau, tau);

        // round(100 + (0 - 100) * 0.6321) == 37, the mirror of the 63 above.
        assert_eq!(smoothed, Metric::from_raw(37));
    }

    /// Two updates landing on the same `Instant` give a zero-length step. Smoothing over it would
    /// be a no-op anyway once alpha is computed, but the early return is what keeps the second
    /// update from being weighted as though time had passed.
    #[test]
    fn a_zero_time_step_leaves_the_metric_untouched() {
        let mut smoothed = Metric::from_raw(50);

        smoothed.apply_smoothing(
            Metric::from_raw(900),
            Duration::ZERO,
            Duration::from_secs(10),
        );

        assert_eq!(smoothed, Metric::from_raw(50));
    }

    /// After enough time constants alpha is 1.0 to the last bit of an f64, so nothing of the old
    /// value survives: a route that goes quiet and comes back is not held to its history.
    #[test]
    fn a_long_step_lands_on_the_new_metric() {
        let mut smoothed = Metric::from_raw(0);

        smoothed.apply_smoothing(
            Metric::from_raw(1000),
            Duration::from_secs(40),
            Duration::from_secs(1),
        );

        assert_eq!(smoothed, Metric::from_raw(1000));
    }

    #[test]
    fn an_unchanged_metric_is_a_fixed_point() {
        let mut smoothed = Metric::from_raw(250);

        smoothed.apply_smoothing(
            Metric::from_raw(250),
            Duration::from_secs(5),
            Duration::from_secs(10),
        );

        assert_eq!(smoothed, Metric::from_raw(250));
    }

    /// The time constant is derived from hello intervals, so a peer that advertises nothing usable
    /// can drive it to zero. The floor at 1us is what keeps that from dividing by zero; the
    /// consequence is that smoothing degenerates into taking the new metric outright.
    #[test]
    fn a_zero_time_constant_snaps_to_the_new_metric() {
        let mut smoothed = Metric::from_raw(10);

        smoothed.apply_smoothing(
            Metric::from_raw(900),
            Duration::from_secs(1),
            Duration::ZERO,
        );

        assert_eq!(smoothed, Metric::from_raw(900));
    }

    /// Hysteresis is only meaningful if the smoothed metric approaches the real one from one side.
    /// An overshoot would make a route look briefly better than it ever was.
    #[test]
    fn repeated_steps_approach_the_target_without_overshooting() {
        let tau = Duration::from_secs(10);
        let step = Duration::from_secs(2);
        let target = Metric::from_raw(500);

        let mut smoothed = Metric::from_raw(0);
        let mut previous = smoothed;
        for _ in 0..100 {
            smoothed.apply_smoothing(target, step, tau);
            assert!(
                smoothed >= previous,
                "smoothing towards a larger metric never runs backwards"
            );
            assert!(
                smoothed <= target,
                "smoothing never passes the metric it is chasing"
            );
            previous = smoothed;
        }
    }

    /// The smoothed metric is a u16 and every step is rounded, so once `alpha * gap` falls below
    /// half a unit the value stops moving. It settles a unit or two short of the target rather
    /// than creeping onto it. Selection only ever compares smoothed metrics against each other, so
    /// the offset is harmless — but it is worth pinning that this is a fixed point and not a slow
    /// crawl, because a crawl would keep re-triggering comparisons forever.
    #[test]
    fn rounding_settles_just_short_of_the_target() {
        let tau = Duration::from_secs(10);
        let step = Duration::from_secs(2);
        let target = Metric::from_raw(500);

        let mut smoothed = Metric::from_raw(0);
        for _ in 0..1000 {
            smoothed.apply_smoothing(target, step, tau);
        }

        let settled = smoothed;
        smoothed.apply_smoothing(target, step, tau);
        assert_eq!(smoothed, settled, "the value has reached a fixed point");
        assert!(settled < target, "rounding stops it short of the target");
        assert!(
            target.raw() - settled.raw() <= 3,
            "but only just short, was {settled:?}"
        );
    }

    /// Sampling much faster than the time constant moves the metric by less than half a unit per
    /// step, which rounds away entirely. Frequent updates therefore make *no* progress rather than
    /// slow progress, so the smoothed metric only tracks a change once the steps are comparable to
    /// the time constant.
    #[test]
    fn a_step_far_shorter_than_the_time_constant_makes_no_progress() {
        let tau = Duration::from_secs(1000);
        let mut smoothed = Metric::from_raw(100);

        for _ in 0..10 {
            smoothed.apply_smoothing(Metric::from_raw(110), Duration::from_millis(1), tau);
        }

        assert_eq!(smoothed, Metric::from_raw(100));
    }

    /// Chasing infinity walks the smoothed metric through ordinary large-but-finite values, so a
    /// smoothed metric must never be read as "this route is retracted". That is what route
    /// selection's infinity check reads `computed_metric` for.
    #[test]
    fn smoothing_towards_infinity_passes_through_finite_values() {
        let tau = Duration::from_secs(10);
        let mut smoothed = Metric::from_raw(100);

        smoothed.apply_smoothing(Metric::INFINITY, tau, tau);

        assert!(
            !smoothed.is_infinite(),
            "a partially smoothed retraction is not itself a retraction"
        );
        assert!(smoothed.raw() > 100, "but it does move towards infinity");
    }
}
