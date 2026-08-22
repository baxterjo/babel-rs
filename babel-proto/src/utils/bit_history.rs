#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct BitHistory(u16);

impl BitHistory {
    /// Starts with a full history.
    ///
    /// This gives some natural hysteresis for neibour churn.
    pub fn new() -> Self {
        Self(0xFFFF)
    }

    /// Shifts new zeros into the bit history until the number of trailing zeros is equal to the
    /// count.
    pub fn set_trailing_zeros(&mut self, zeros: u64) {
        while zeros > self.0.into() {
            self.0 = self.0.unbounded_shl(1);
        }
    }

    pub fn record(&mut self, value: bool) {
        self.0 = (self.0 << 1) | (value as u16);
    }

    pub fn record_many(&mut self, value: bool, number: usize) {
        for _ in 0..number {
            self.record(value);
        }
    }

    pub fn count(&self) -> u32 {
        self.0.count_ones()
    }
}
