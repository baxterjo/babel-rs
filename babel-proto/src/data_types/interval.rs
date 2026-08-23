use crate::utils::Duration;

/// Interval as defined in section [4.1.2](https://datatracker.ietf.org/doc/html/rfc8966#name-interval)
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Interval(Duration);

impl Interval {
    pub fn from_wire(raw: [u8; 2]) -> Self {
        Self(Duration::from_centis(u16::from_be_bytes(raw).into()))
    }

    pub fn to_wire(&self) -> [u8; 2] {
        (self.0.as_centis() as u16).to_be_bytes()
    }

    pub fn as_centis(&self) -> u16 {
        // This will not truncate because this structure cannot exist with durations over the max
        // allowable here.
        self.0.as_centis() as u16
    }

    pub fn is_zero(&self) -> bool {
        self.as_centis() == 0
    }
}

impl From<Duration> for Interval {
    fn from(value: Duration) -> Self {
        let centis = value.as_centis();

        // If the provided duration is greater than the highest possible wire format, then
        // saturating_trucate it.
        if centis > u16::MAX.into() {
            Self(Duration::from_centis(u16::MAX.into()))
        } else {
            // Otherwise let it through
            Self(Duration::from_centis(centis))
        }
    }
}

impl From<Interval> for Duration {
    fn from(value: Interval) -> Self {
        value.0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_from_duration_cannot_exceed_wire_format() {
        let duration = Duration::from_centis(u64::from(u16::MAX) + 1000);

        let interval = Interval::from(duration);

        assert_eq!(
            interval.as_centis(),
            u16::MAX,
            "The from trait should saturate the possible wire format"
        );
    }
}
