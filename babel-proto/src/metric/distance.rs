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
            // Saturate at INFINITY - 1 rather than INFINITY. In the spec INFINITY means
            // "unreachable", but adding link costs up to create a metric inherently means that the
            // node we are calculating the metric for **IS** reachable, just very expensive.
            Metric(self.0.saturating_add(neighbour_metric.0).min(INFINITY - 1))
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
}
