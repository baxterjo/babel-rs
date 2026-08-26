//! Utilities that are not defined in the Babel spec but are useful for the implementation.

pub mod bit_history;
pub(crate) mod destination;
pub(crate) mod managed_slice;
pub(crate) mod short_id;
pub(crate) mod storage;
pub(crate) mod time;

pub(crate) use managed_slice::ManagedSlice;
pub(crate) use storage::{InternallyKeyed, ManagedSliceExt};
pub use time::{Duration, DurationMultiplier, Instant, Timer, TimerError};
