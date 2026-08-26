use core::{fmt, ops};

use super::DurationMultiplier;

/// A span of time.
///
/// ### How does [`Duration`] differ from [`Interval`]?
/// An [`Interval`] is a subset of [`Duration`] that is representable in the Babel wire format.
/// * [`Interval`] must be between `0` and [`u16::MAX`] centiseconds.
/// * [`Duration`] can be between `0` and [`u64::MAX`] microseconds.
///
/// So [`Duration`] can be about 28 billion times bigger than the max allowable [`Interval`] value.
///
/// [`Interval`]: crate::data_types::interval::Interval
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Duration {
    micros: u64,
}

impl Duration {
    pub const ZERO: Duration = Duration::from_micros(0);
    /// The longest possible duration we can encode.
    pub const MAX: Duration = Duration::from_micros(u64::MAX);
    /// Create a new `Duration` from a number of microseconds.
    pub const fn from_micros(micros: u64) -> Duration {
        Duration { micros }
    }

    /// Create a new `Duration` from a number of milliseconds.
    pub const fn from_millis(millis: u64) -> Duration {
        Duration {
            micros: millis * 1000,
        }
    }

    /// Create a new `Duration` from a number of centiseconds.
    pub const fn from_centis(centis: u64) -> Duration {
        Duration {
            micros: centis * 10000,
        }
    }

    /// Create a new `Duration` from a number of seconds.
    pub const fn from_secs(secs: u64) -> Duration {
        Duration {
            micros: secs * 1000000,
        }
    }

    /// The number of whole seconds in this `Duration`.
    pub const fn as_secs(&self) -> u64 {
        self.micros / 1000000
    }

    /// The total number of centiseconds in this `Duration`.
    pub const fn as_centis(&self) -> u64 {
        self.micros / 10000
    }

    /// The total number of milliseconds in this `Duration`.
    pub const fn as_millis(&self) -> u64 {
        self.micros / 1000
    }

    /// The total number of microseconds in this `Duration`.
    pub const fn as_micros(&self) -> u64 {
        self.micros
    }

    pub fn clamp_to_wire(&mut self) {
        *self = (*self)
            .min(Duration::from_centis(u16::MAX.into()))
            .max(Duration::from_centis(1));
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{:03}s", self.as_secs(), self.as_millis())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Duration {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{}.{:03}s", self.as_secs(), self.as_millis());
    }
}

impl ops::Add<Duration> for Duration {
    type Output = Duration;

    fn add(self, rhs: Duration) -> Duration {
        Duration::from_micros(self.micros + rhs.as_micros())
    }
}

impl ops::AddAssign<Duration> for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        self.micros += rhs.as_micros();
    }
}

impl ops::Sub<Duration> for Duration {
    type Output = Duration;

    fn sub(self, rhs: Duration) -> Duration {
        Duration::from_micros(
            self.micros
                .checked_sub(rhs.as_micros())
                .expect("overflow when subtracting durations"),
        )
    }
}

impl ops::SubAssign<Duration> for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        self.micros = self
            .micros
            .checked_sub(rhs.as_micros())
            .expect("overflow when subtracting durations");
    }
}

impl ops::Mul<u8> for Duration {
    type Output = Duration;

    fn mul(self, rhs: u8) -> Duration {
        Duration::from_micros(self.micros * rhs as u64)
    }
}

impl ops::MulAssign<u8> for Duration {
    fn mul_assign(&mut self, rhs: u8) {
        self.micros *= rhs as u64;
    }
}

impl ops::Div<u8> for Duration {
    type Output = Duration;

    fn div(self, rhs: u8) -> Duration {
        Duration::from_micros(self.micros / rhs as u64)
    }
}

impl ops::Div<Duration> for Duration {
    type Output = u64;
    fn div(self, rhs: Duration) -> Self::Output {
        let lhs_micros = self.as_micros();
        let rhs_micros = rhs.as_micros();
        lhs_micros / rhs_micros
    }
}

impl ops::DivAssign<u8> for Duration {
    fn div_assign(&mut self, rhs: u8) {
        self.micros /= rhs as u64;
    }
}

impl ops::Shl<u32> for Duration {
    type Output = Duration;

    fn shl(self, rhs: u32) -> Duration {
        Duration::from_micros(self.micros << rhs)
    }
}

impl ops::ShlAssign<u32> for Duration {
    fn shl_assign(&mut self, rhs: u32) {
        self.micros <<= rhs;
    }
}

impl ops::Shr<u32> for Duration {
    type Output = Duration;

    fn shr(self, rhs: u32) -> Duration {
        Duration::from_micros(self.micros >> rhs)
    }
}

impl ops::ShrAssign<u32> for Duration {
    fn shr_assign(&mut self, rhs: u32) {
        self.micros >>= rhs;
    }
}

impl From<::core::time::Duration> for Duration {
    fn from(other: ::core::time::Duration) -> Duration {
        Duration::from_micros(other.as_secs() * 1000000 + other.subsec_micros() as u64)
    }
}

impl From<Duration> for ::core::time::Duration {
    fn from(val: Duration) -> Self {
        ::core::time::Duration::from_micros(val.as_micros())
    }
}

impl ops::Mul<DurationMultiplier> for Duration {
    type Output = Duration;
    fn mul(self, rhs: DurationMultiplier) -> Self::Output {
        Duration::from_micros(
            self.as_micros()
                .saturating_mul(rhs.num.into())
                .saturating_div(rhs.den.into()),
        )
    }
}
