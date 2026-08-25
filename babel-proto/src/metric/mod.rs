use core::fmt::Debug;
use core::ops::Div;

#[doc(hidden)]
pub mod distance;
#[doc(hidden)]
pub mod k_of_j;

#[doc(inline)]
pub use distance::{Cost, Metric, RxCost, TxCost};
#[doc(inline)]
pub use k_of_j::KOutOfJ;

use crate::utils::bit_history::BitHistory;
use crate::utils::{Duration, DurationMultiplier};

/// A type that calculates the RxCost from a history of neighbour hellos.
pub trait LinkCostCalculator: Debug {
    /// Calculates the RX cost as a function of the hello histories from hello's received from a
    /// node.
    ///
    /// A result of `0xFFFF` is considered "infinite" and semantically means "this node cannot be
    /// reached"
    ///
    /// Since nodes do not necessarily send periodic Unicast Hellos but do usually send periodic
    /// Multicast Hellos
    /// ([Section 3.4.1](https://datatracker.ietf.org/doc/html/rfc8966#reverse-reachability)), a
    /// node SHOULD use an algorithm that yields a finite rxcost when only Multicast Hellos are
    /// received, unless interoperability with nodes that only send Multicast Hellos is not
    /// required.
    ///
    /// Arguments:
    ///
    /// * `mcast_hello_history`: A [`BitHistory`] of multicast hellos received by this neighbour.
    /// * `ucast_hello_history`: A [`BitHistory`] of unicast hellos received by this neighbour.
    fn rx_cost(&self, mcast_hello_history: BitHistory, ucast_hello_history: BitHistory) -> RxCost;

    /// Calculates the ratio of multicast hellos to IHUs.
    ///
    /// The **advertised** IHU interval is always 3 times the Multicast Hello interval. IHUs are
    /// **actually** sent at the ratio returned here.
    ///
    /// Arguments:
    /// * `mcast_hello_history`: A [`BitHistory`] of multicast hellos received by this neighbour.
    /// * `ucast_hello_history`: A [`BitHistory`] of unicast hellos received by this neighbour.
    fn hello_ihu_ratio(
        &self,
        mcast_hello_history: BitHistory,
        ucast_hello_history: BitHistory,
    ) -> IhuRatio;

    /// Calculates the link cost of for this neighbour.
    ///
    /// Arguments:
    /// * `rx_cost`: This node's own calculated rx_cost as defined by [`Self::rx_cost`]
    /// * `tx_cost`: The tx_cost reported by this neighbour in its IHU TLV.
    fn link_cost(&self, rx_cost: RxCost, tx_cost: TxCost) -> Cost;
}

/// The ratio of IHU's per multicast hello for this interface.
///
/// Lossy links should prefer a lower number (lowest of 1:1)
///
/// Lossless links should prefer a higher ratio (highest of 3:1)
///
/// The bounds of the ratio are enforced.
pub struct IhuRatio(DurationMultiplier);

impl IhuRatio {
    pub const fn new(num: u8, den: u8) -> Self {
        Self(DurationMultiplier::new(num, den))
    }
    pub fn apply(&self, duration: Duration) -> Duration {
        if self.0.num().div(self.0.den()) == 0 {
            return duration;
        }

        if self.0.num().div_ceil(self.0.den()) > 3 {
            return duration * 3;
        }

        duration * self.0
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn out_of_bounds_ratio() {
        let ratio = IhuRatio::new(5, 1);
        let duration = Duration::from_secs(1);
        assert_eq!(3, ratio.apply(duration).as_secs());

        let ratio = IhuRatio::new(1, 5);
        let duration = Duration::from_secs(1);
        assert_eq!(1, ratio.apply(duration).as_secs());
    }
}
