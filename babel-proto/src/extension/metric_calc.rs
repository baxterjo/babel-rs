use core::fmt::Debug;

use crate::utils::bit_history::BitHistory;
use crate::utils::distance::RxCost;
use crate::utils::{Duration, DurationMultiplier};

/// A type that calculates the RxCost from a history of neighbour hellos.
pub trait LinkCostCalculator: Debug {
    /// Calculates the RX cost as a function of the hello histories from hello's received from a
    /// node.
    ///
    /// A result of 0xFFFF is considered "infinite" and semantically means "this node cannot be
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
    /// * `hello_interval`: The hello interval reported by this neighbour. The router will shift a
    /// zero
    fn calculate_rx_cost(
        &self,
        mcast_hello_history: BitHistory,
        mcast_hello_interval: Duration,
        ucast_hello_history: Option<BitHistory>,
        ucast_hello_interval: Option<Duration>,
    ) -> RxCost;

    /// Calculates the ratio of multicast hellos to IHUs.
    ///
    /// the **advertised** IHU interval is always 3 times the Multicast Hello interval. IHUs are
    /// **actually** sent at the given ratio.
    fn hello_ihu_ratio(
        &self,
        mcast_hello_history: BitHistory,
        mcast_hello_interval: Duration,
        ucast_hello_history: Option<BitHistory>,
        ucast_hello_interval: Option<Duration>,
    ) -> IhuRatio;
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
        Self(DurationMultiplier { num, den })
    }
    fn apply(&self, duration: Duration) -> Duration {
        // Clamp the denominator to 1 to avoid div0.
        let denom = self.0.den.max(1);

        if self.0.num / denom > 3 {
            return duration * 3;
        }

        (duration * self.0.num) / denom
    }
}

#[derive(Debug)]
pub struct KOutOfJ;

impl LinkCostCalculator for KOutOfJ {
    fn calculate_rx_cost(
        &self,
        mcast_hello_history: BitHistory,
        mcast_hello_interval: Duration,
        ucast_hello_history: Option<BitHistory>,
        ucast_hello_interval: Option<Duration>,
    ) -> RxCost {
        RxCost::INFINITY
    }

    fn hello_ihu_ratio(
        &self,
        mcast_hello_history: BitHistory,
        mcast_hello_interval: Duration,
        ucast_hello_history: Option<BitHistory>,
        ucast_hello_interval: Option<Duration>,
    ) -> IhuRatio {
        IhuRatio::new(3, 1)
    }
}
