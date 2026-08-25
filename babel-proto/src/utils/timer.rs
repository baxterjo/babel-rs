use thiserror::Error;

use crate::data_types::Interval;
use crate::utils::{Duration, Instant};

/// A simple timer.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Timer {
    start: Instant,
    duration: Duration,
}

#[derive(Debug, PartialEq, Eq, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TimerError {
    #[error("The duration of a timer cannot be zero.")]
    DurationCannotBeZero,
}

impl Timer {
    pub(crate) fn new_unchecked(now: Instant, duration: Duration) -> Self {
        Self {
            start: now,
            duration,
        }
    }
    /// Create a new timer that will fire after the duration.
    pub fn new(now: Instant, duration: Duration) -> Result<Self, TimerError> {
        if duration.as_micros() == 0 {
            return Err(TimerError::DurationCannotBeZero);
        }

        Ok(Self {
            start: now,
            duration,
        })
    }

    /// Create a new timer that will instantly fire.
    ///
    /// Timers must be restarted manually after firing.
    pub fn new_eager(now: Instant, duration: Duration) -> Result<Self, TimerError> {
        // Set the "start" time in the past. That way the timer fires immediately.
        let pre_start = now - duration;
        Self::new(pre_start, duration)
    }

    pub fn set_tick_duration(&mut self, duration: Duration) -> Result<(), TimerError> {
        *self = Self::new(self.start, duration)?;
        Ok(())
    }

    /// Sets the duration of the timer.
    ///
    /// All babel instances of timers suggest that if a duration increases, the corresponding
    /// message should be sent immediately.
    pub fn set_message_duration(&mut self, duration: Duration) -> Result<(), TimerError> {
        if duration > self.duration {
            *self = Self::new_eager(self.start, duration)?;
        } else {
            *self = Self::new(self.start, duration)?;
        }

        Ok(())
    }

    /// Start the timer
    pub fn start(&mut self, now: Instant, duration: Duration) -> Result<(), TimerError> {
        *self = Self::new(now, duration)?;
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

    pub fn interval(&self) -> Interval {
        self.duration.into()
    }

    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns time remaining if the timer hasn't fired.
    pub fn time_remaining(&self, now: Instant) -> Option<Duration> {
        if self.is_finished(now) {
            return None;
        }

        Some(self.start + self.duration - now)
    }
}

/// Tests that use std
#[cfg(all(test, feature = "std"))]
mod test {
    use super::*;

    #[test]
    fn new_eager_timer() {
        let duration = Duration::from_micros(200);
        let now = Instant::now();
        let future = now + Duration::from_micros(1);
        let mut eager = Timer::new_eager(now, duration).expect("Timer should be created.");
        assert!(eager.is_finished(now));

        // Introduce a small delay to see if there is an overflow issue
        assert!(eager.is_finished(future));

        eager.restart(now);
        assert!(!eager.is_finished(now));
        assert!(eager.is_finished(now + duration));
    }
}
