use thiserror::Error;

use crate::utils::{Duration, Instant};

/// A simple timer.
#[derive(Debug, Clone, Copy)]
pub struct Timer {
    start: Instant,
    duration: Duration,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum TimerError {
    #[error("The duration of a timer cannot be zero.")]
    DurationCannotBeZero,
}

impl Timer {
    pub fn new(now: Instant, duration: Duration) -> Result<Self, TimerError> {
        if duration.as_micros() == 0 {
            return Err(TimerError::DurationCannotBeZero);
        }
        Ok(Self {
            start: now,
            duration,
        })
    }

    /// Start the timer
    pub fn start(&mut self, now: Instant, duration: Duration) -> Result<(), TimerError> {
        if duration.as_micros() == 0 {
            return Err(TimerError::DurationCannotBeZero);
        }
        self.start = now;
        self.duration = duration;
        Ok(())
    }

    /// Restart the timer with the same duration.
    pub fn restart(&mut self, now: Instant) {
        self.start = now;
    }

    pub fn is_finished(&self, now: Instant) -> bool {
        self.times_fired(now) > 0
    }

    pub fn times_fired(&self, now: Instant) -> u64 {
        let since_start = now - self.start;
        // Div 0 safety: Timer cannot exist if duration is zero.
        since_start / self.duration
    }
}
