//! Utilities that are not defined in the Babel spec but are useful for the implementation.

pub(crate) mod bit_history;
pub(crate) mod cursor;
pub(crate) mod rx_cost;
pub(crate) mod storage;
pub(crate) mod time;
pub(crate) mod timer;

pub use time::Duration;
pub use time::DurationMultiplier as IntervalMultiplier;
pub use time::Instant;
