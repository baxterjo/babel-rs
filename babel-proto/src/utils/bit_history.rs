#[derive(Debug, Clone, Copy)]
pub struct BitHistory(u16);

impl BitHistory {
    pub fn new() -> Self {
        Self(0)
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
