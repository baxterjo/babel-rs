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
    #[error("Duration too large - given: {given} centiseconds, max: {max} centiseconds", given=0, max = u16::MAX)]
    DurationTooLarge(u64),
}

impl Timer {
    pub(crate) const fn new_unchecked(now: Instant, duration: Duration) -> Self {
        Self {
            start: now,
            duration,
        }
    }

    pub(crate) fn new_eager_unchecked(now: Instant, duration: Duration) -> Self {
        Self {
            start: now - duration,
            duration,
        }
    }

    /// Create a new timer that will fire after the duration.
    pub fn from_duration(now: Instant, duration: Duration) -> Result<Self, TimerError> {
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
    pub fn eager_from_duration(now: Instant, duration: Duration) -> Result<Self, TimerError> {
        // Set the "start" time in the past. That way the timer fires immediately.
        let pre_start = now - duration;
        Self::from_duration(pre_start, duration)
    }

    /// Creates a new timer whos interval will be advertised in a TLV.
    ///
    /// This clamps the bounds of the timer to be able to fit in the interval field on the wire.
    pub fn from_interval(now: Instant, interval: Interval) -> Result<Self, TimerError> {
        Self::from_duration(now, *interval)
    }

    /// Creates a new timer whos interval will be advertised in a TLV.
    ///
    /// This clamps the bounds of the timer to be able to fit in the interval field on the wire.
    pub fn eager_from_interval(now: Instant, interval: Interval) -> Result<Self, TimerError> {
        Self::eager_from_duration(now, *interval)
    }

    pub fn set_tick_duration(&mut self, duration: Duration) -> Result<(), TimerError> {
        *self = Self::from_duration(self.start, duration)?;
        Ok(())
    }

    /// Sets the interval of the timer.
    ///
    /// All timers that are related to sending TLVs and which advertises their duration **in** those
    /// TLVs must immediately fire when their corresponding duration is increased. This will set
    /// an eager timer if the given interval is greater than the existing one.
    pub fn set_tlv_interval(&mut self, interval: Interval) -> Result<(), TimerError> {
        if *interval > self.duration {
            *self = Self::eager_from_interval(self.start, interval)?;
        } else {
            *self = Self::from_interval(self.start, interval)?;
        }

        Ok(())
    }

    /// Restart the timer with the same duration.
    pub fn restart(&mut self, now: Instant) {
        self.start = now;
    }

    /// Restart the timer and it will fire on the first poll.
    pub fn restart_eager(&mut self, now: Instant) {
        self.start = now - self.duration
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
        let mut eager =
            Timer::eager_from_duration(now, duration).expect("Timer should be created.");
        assert!(eager.is_finished(now));

        // Introduce a small delay to see if there is an overflow issue
        assert!(eager.is_finished(future));

        eager.restart(now);
        assert!(!eager.is_finished(now));
        assert!(eager.is_finished(now + duration));
    }

    #[test]
    fn regression_no_timer_can_have_zero_duration() {
        Timer::from_duration(Instant::now(), Duration::from_secs(0)).expect_err(
            "Timer must enforce no zero duration. There is a risk of div by zero otherwise",
        );
    }
}
