use core::fmt::Debug;
#[cfg(feature = "defmt")]
use core::fmt::Formatter;

/// A bitwise history.
///
/// The most recent history is on the right side of the inner value bits, the least recent on the
/// left.
// The spec asks that receiving a seqno that is less than the expected seqno requires that we
// "undo" the history. This means that the inner value must be bigger than the spec required value
// to retain a window of history larger than the value. This implementation uses usize to get the
// largest possible history based on compilation target.
#[derive(Clone, Copy, Default)]
pub struct BitHistory(usize);

impl Debug for BitHistory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("BitHistory")
            .field(&format_args!("{:#018b}", self.0))
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for BitHistory {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "BitHistory({=usize:b})", self.0)
    }
}

impl BitHistory {
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

    /// Gets the most recent `number` of bits from the bit history.
    pub fn get_last(&self, number: usize) -> u16 {
        let mut mask = 0u16;
        let val = self.read();
        for _ in 0..number {
            mask = mask << 1 | 1;
        }
        val & mask
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

    #[test]
    fn get_last_keeps_expected_bits() {
        let big_val = BitHistory(0x123456789ABCD);
        assert_eq!(big_val.get_last(4), 0xD)
    }
}
