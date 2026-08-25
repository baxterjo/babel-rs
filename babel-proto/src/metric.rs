use core::fmt::Debug;

use crate::utils::bit_history::BitHistory;
use crate::utils::distance::{Cost, RxCost, TxCost};
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
    fn link_cost(rx_cost: RxCost, tx_cost: TxCost) -> Cost;
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
        if self.0.num().div_ceil(self.0.den()) > 3 {
            return duration * 3;
        }

        duration * self.0
    }
}

/// A link cost calculator that is best used for wired interfaces.
///
/// This link is either considered up or down with no in between. This is determined by counting
/// the number of hello's received by a node. If the value is greater than or equal to some k out
/// of 16 hellos, then the link is considered up.
#[derive(Debug)]
pub struct KOutOfJ {
    /// Link cost constant.
    ///
    /// If this link is up then the `rx_cost` of the link will be set to this value.
    cost_const: u16,
    /// Threshold for considering a link to be up.
    k_val: u8,
    /// Window of most recent hellos to compare k_val against.
    j_val: u8,
}

impl KOutOfJ {
    /// Suggested K value from
    /// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.6)
    pub const SPEC_K: u8 = 2;
    /// Suggested J value from
    /// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.6)
    pub const SPEC_J: u8 = 3;
    /// Suggested link cost const value from
    /// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.6)
    pub const SPEC_CONST: u16 = 96;

    /// Create a new KOutOfJ link cost calculator.
    ///
    /// Arguments:
    /// * `link_cost`: The link cost constant, if the link is "up" this will be the cost of the
    ///   link, if it is down, the cost is infinity. Clamped to a minimum of 1.
    /// * `k_val`: The number of received hellos on this link to consider it up. Clamped to minimum
    /// of 1 maximum of `j_val`
    /// * `j_val`: The window of most recently reveived hellos. Clamped to minimum of 1 maximum of
    /// 16.
    pub fn new(link_cost: u16, k_val: u8, j_val: u8) -> Self {
        let j_val = j_val.max(1).min(16);
        let k_val = k_val.max(1).min(j_val);
        Self {
            cost_const: link_cost.max(1),
            k_val: k_val,
            j_val: j_val,
        }
    }
}

impl Default for KOutOfJ {
    fn default() -> Self {
        Self {
            cost_const: Self::SPEC_CONST,
            k_val: Self::SPEC_K,
            j_val: Self::SPEC_J,
        }
    }
}

impl LinkCostCalculator for KOutOfJ {
    fn rx_cost(&self, mcast_hello_history: BitHistory, ucast_hello_history: BitHistory) -> RxCost {
        // If either of the hello histories meet or exceed k_val. Then the cost is finite.
        if mcast_hello_history.get_last(self.j_val.into()).count_ones() >= self.k_val.into()
            || ucast_hello_history.get_last(self.j_val.into()).count_ones() >= self.k_val.into()
        {
            RxCost::from_raw(self.cost_const)
        } else {
            RxCost::INFINITY
        }
    }

    fn link_cost(rx_cost: RxCost, tx_cost: TxCost) -> Cost {
        if rx_cost.is_infinite() {
            Cost::INFINITY
        } else {
            Cost::from(tx_cost)
        }
    }

    fn hello_ihu_ratio(
        &self,
        _mcast_hello_history: BitHistory,
        _ucast_hello_history: BitHistory,
    ) -> IhuRatio {
        IhuRatio::new(3, 1)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn out_of_bounds_ratio() {
        let ratio = IhuRatio::new(5, 1);
        let duration = Duration::from_secs(1);
        assert_eq!(3, ratio.apply(duration).as_secs())
    }

    #[test]
    fn k_of_j_returns_const_when_expected() {
        let _ = env_logger::try_init();
        let mut mcast_history = BitHistory::default();
        let mut ucast_history = BitHistory::default();
        let cost_calc = KOutOfJ::default();

        // record 3
        mcast_history.record_many(true, 3);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            cost_calc.cost_const.into()
        );

        // 2 of 3 still there
        mcast_history.record(false);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            cost_calc.cost_const.into()
        );

        // 1 of 3, link is down.
        mcast_history.record(false);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            RxCost::INFINITY
        );

        // Only zeros in the j window now.
        mcast_history.record(false);

        // record 3 for ucast
        ucast_history.record_many(true, 3);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            cost_calc.cost_const.into()
        );

        // 2 of 3 still there
        ucast_history.record(false);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            cost_calc.cost_const.into()
        );
        // 1 of 3, link is down
        ucast_history.record(false);
        assert_eq!(
            cost_calc.rx_cost(mcast_history, ucast_history),
            RxCost::INFINITY
        );
    }
}
