/// A monotonic clock source. The only requirement is that `as_millis` returns
/// a consistent millisecond timestamp — the epoch is arbitrary.
pub trait Instant: Copy {
    fn as_millis(&self) -> u64;
}

/// A duration in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration(pub u64);

impl Duration {
    pub const ZERO: Self = Self(0);

    pub fn from_secs(s: u64) -> Self {
        Self(s * 1_000)
    }

    /// Convert from Babel's centisecond wire format.
    pub fn from_centisecs(cs: u16) -> Self {
        Self(cs as u64 * 10)
    }
}
