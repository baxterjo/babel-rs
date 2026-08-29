/*! Time structures.

The `time` module contains structures used to represent both
absolute and relative time.

 - [Instant] is used to represent absolute time.
 - [Duration] is used to represent relative time.

[Instant]: struct.Instant.html
[Duration]: struct.Duration.html
*/

// Attribution: Copied from smoltcp under BSD Zero Clause License

#[doc(hidden)]
pub mod duration;
#[doc(hidden)]
pub mod instant;
#[doc(hidden)]
pub mod timer;

#[doc(inline)]
pub use duration::Duration;
#[doc(inline)]
pub use instant::Instant;
#[doc(inline)]
pub use timer::Timer;
#[doc(inline)]
pub use timer::TimerError;

use crate::data_types::Interval;

/// Provide a literal or referential duration for certain interval values.
///
/// There are many areas in the spec where the "recommended" value for an interval is a multiple of
/// another interval. This gives users the choice to set a literal value or a multiple value.
///
/// Non Exhaustive list of interval relationships and their defaults:
/// * `ihu_interval = 3 * mcast_hello_interval on lossless links, 1 * mcast_hello_interval` on
/// lossy links. This metric can be tuned through [`LinkCostCalculator::`]
/// * `update_interval = 4 * mcast_hello_interval`
/// * `ihu_hold_time = 3.5 * advertised_ihu_interval`
/// * `route_expiry_time = 3.5 * advertised_update_interval`
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum DurationSpec {
    Literal(Duration),
    Multiple(DurationMultiplier),
}

impl DurationSpec {
    pub const UPDATE_SPEC: DurationSpec =
        DurationSpec::Multiple(DurationMultiplier { num: 4, den: 1 });
    pub const IHU_HOLD_TIME_SPEC: DurationSpec =
        DurationSpec::Multiple(DurationMultiplier { num: 7, den: 2 });

    pub(crate) fn apply_ihu_interval(&self, mcast_hello_interval: Duration) -> Duration {
        // Get the duration from the spec.
        let out = match self {
            Self::Literal(dur) => *dur,
            Self::Multiple(mul) => mcast_hello_interval * *mul,
        };

        // Clamp it to [1:1, 3:1]
        out.min(mcast_hello_interval * 3).max(mcast_hello_interval)
    }

    pub(crate) fn apply(&self, duration: Duration) -> Duration {
        match self {
            Self::Literal(dur) => *dur,
            Self::Multiple(mul) => duration * *mul,
        }
    }

    pub(crate) fn apply_to_interval(&self, interval: Interval) -> Interval {
        match self {
            Self::Literal(dur) => (*dur).into(),
            Self::Multiple(mul) => {
                let new_dur = *interval * *mul;
                new_dur.into()
            }
        }
    }
}

/// A fractional multiplier for [`Duration`] that avoids the use of floating point numbers.
///
/// Note: Arithmetic operations may not be exact, to get as accurate as possible, arithmetic is
/// done in [`Duration`]'s native units (microseconds) so Babel units (centiseconds) have an
/// acceptable level of fidelity.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DurationMultiplier {
    num: u8,
    den: u8,
}

impl DurationMultiplier {
    /// Creates a new multiplier clamping the numerator and denominator to a minimum of 1
    pub const fn new(num: u8, den: u8) -> Self {
        let denom = if den == 0 { 1 } else { den };
        let numer = if num == 0 { 1 } else { num };
        Self {
            num: numer,
            den: denom,
        }
    }

    pub fn num(&self) -> u8 {
        self.num
    }
    pub fn den(&self) -> u8 {
        self.den
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_instant_ops() {
        // std::ops::Add
        assert_eq!(
            Instant::from_millis(4) + Duration::from_millis(6),
            Instant::from_millis(10)
        );
        // std::ops::Sub
        assert_eq!(
            Instant::from_millis(7) - Duration::from_millis(5),
            Instant::from_millis(2)
        );
    }

    #[test]
    fn test_instant_getters() {
        let instant = Instant::from_millis(5674);
        assert_eq!(instant.secs(), 5);
        assert_eq!(instant.millis(), 674);
        assert_eq!(instant.total_millis(), 5674);
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_display() {
        assert_eq!(format!("{}", Instant::from_millis(74)), "0.074s");
        assert_eq!(format!("{}", Instant::from_millis(5674)), "5.674s");
        assert_eq!(format!("{}", Instant::from_millis(5000)), "5.000s");
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_conversions() {
        let mut epoc: ::std::time::SystemTime = Instant::from_millis(0).into();
        assert_eq!(
            Instant::from(::std::time::UNIX_EPOCH),
            Instant::from_millis(0)
        );
        assert_eq!(epoc, ::std::time::UNIX_EPOCH);
        epoc = Instant::from_millis(2085955200i64 * 1000).into();
        assert_eq!(
            epoc,
            ::std::time::UNIX_EPOCH + ::std::time::Duration::from_secs(2085955200)
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn test_instant_conversions_from_std_instant() {
        let std_now = ::std::time::Instant::now();

        let before = Instant::from(std_now);
        ::std::thread::sleep(::std::time::Duration::from_millis(5));
        let after = Instant::from(std_now);

        assert_eq!(
            before, after,
            "converting the same std Instant twice should yield the same result"
        );
    }

    #[test]
    fn test_duration_ops() {
        // std::ops::Add
        assert_eq!(
            Duration::from_millis(40) + Duration::from_millis(2),
            Duration::from_millis(42)
        );
        // std::ops::Sub
        assert_eq!(
            Duration::from_millis(555) - Duration::from_millis(42),
            Duration::from_millis(513)
        );
        // std::ops::Mul
        assert_eq!(Duration::from_millis(13) * 22, Duration::from_millis(286));
        // std::ops::Div
        assert_eq!(Duration::from_millis(53) / 4, Duration::from_micros(13250));
    }

    #[test]
    fn test_duration_assign_ops() {
        let mut duration = Duration::from_millis(4735);
        duration += Duration::from_millis(1733);
        assert_eq!(duration, Duration::from_millis(6468));
        duration -= Duration::from_millis(1234);
        assert_eq!(duration, Duration::from_millis(5234));
        duration *= 4;
        assert_eq!(duration, Duration::from_millis(20936));
        duration /= 5;
        assert_eq!(duration, Duration::from_micros(4187200));
    }

    #[test]
    #[should_panic(expected = "overflow when subtracting durations")]
    fn test_sub_from_zero_overflow() {
        let _ = Duration::from_millis(0) - Duration::from_millis(1);
    }

    #[test]
    #[should_panic(expected = "attempt to divide by zero")]
    fn test_div_by_zero() {
        let _ = Duration::from_millis(4) / 0;
    }

    #[test]
    fn test_duration_getters() {
        let instant = Duration::from_millis(4934);
        assert_eq!(instant.as_secs(), 4);
        assert_eq!(instant.as_millis(), 4934);
    }

    #[test]
    fn test_duration_conversions() {
        let mut std_duration = ::core::time::Duration::from_millis(4934);
        let duration: Duration = std_duration.into();
        assert_eq!(duration, Duration::from_millis(4934));
        assert_eq!(Duration::from(std_duration), Duration::from_millis(4934));

        std_duration = duration.into();
        assert_eq!(std_duration, ::core::time::Duration::from_millis(4934));
    }
}
