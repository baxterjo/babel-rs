use core::fmt::Debug;

use crate::utils::Duration;
use crate::utils::bit_history::BitHistory;
use crate::utils::distance::RxCost;

/// A type that calculates the RxCost from a history of neighbour hellos.
pub trait RxCostCalculator: Debug {
    /// Calculates the RX cost as a function of the hello histories from hello's received from a
    /// node.
    ///
    /// A result of 0xFFFF is considered "infinite" and semantically means "this node cannot be
    /// reached"
    fn calculate_rx_cost(
        &self,
        mcast_hello_history: BitHistory,
        ucast_hello_history: Option<BitHistory>,
        history_tick: Duration,
    ) -> RxCost;
}
