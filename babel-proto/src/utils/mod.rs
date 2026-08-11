//! Utilities that are not defined in the Babel spec but are useful for the implementation.

pub(crate) mod time;

pub(crate) mod storage;

pub use time::Duration;
pub use time::DurationMultiplier as IntervalMultiplier;
pub use time::Instant;
