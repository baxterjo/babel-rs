/// A bitwise history.
///
/// The most recent history is on the right side of the inner value bits, the least recent on the
/// left.
// The spec asks that receiving a seqno that is less than the expected seqno requires that we
// "undo" the history. This means that the inner value must be bigger than the spec required value
// to retain a window of history larger than the value. This implementation uses usize to get the
// largest possible history based on compilation target.
#[derive(Debug, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BitHistory(usize);

impl BitHistory {
    /// Starts with a full history.
    ///
    /// This gives some natural hysteresis for neibour churn.
    pub(crate) fn new() -> Self {
        Self(0xFFFF)
    }

    pub(crate) fn record(&mut self, value: bool) {
        self.0 = (self.0 << 1) | (value as usize);
    }

    pub(crate) fn record_many(&mut self, value: bool, number: usize) {
        // Clamp the possible number of iterations of this to 16
        for _ in 0..number.min(16) {
            self.record(value);
        }
    }

    /// The spec asks that receiving a seqno smaller than the expected seqno that we "undo" the
    /// history.
    pub(crate) fn undo(&mut self, number: u32) {
        self.0 = self.0.unbounded_shr(number);
    }

    /// Reads the inner value from the bit history.
    pub fn read(&self) -> u16 {
        // Truncation saftey: We only want the lower 16 bits of this value, so we *want* to truncate
        self.0 as u16
    }

    pub fn count(&self) -> u32 {
        self.read().count_ones()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn truncate_keeps_lsb() {
        let big_val = BitHistory(0x123456789ABCD);
        assert_eq!(big_val.read(), 0xABCD)
    }
}
