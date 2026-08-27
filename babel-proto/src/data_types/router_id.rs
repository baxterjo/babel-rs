use core::fmt::{Debug as DebugT, Display};

use thiserror::Error;

use crate::MaybeDefmt;
use crate::utils::short_id::fmt_short_id;

/// Router-Id as described in section [4.1.3](https://datatracker.ietf.org/doc/html/rfc8966#name-router-id)
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouterId([u8; 8]);

impl RouterId {
    pub fn new<I>(id: I) -> Result<Self, RouterIdError>
    where
        I: DebugT + Into<[u8; 8]> + MaybeDefmt,
    {
        let raw: [u8; 8] = id.into();
        if raw == [0u8; 8] {
            return Err(RouterIdError::CannotBeAllZeroes);
        }
        if raw == [0xFFu8; 8] {
            return Err(RouterIdError::CannotBeAllOnes);
        }
        Ok(Self(raw))
    }

    pub(crate) fn as_octets(&self) -> &[u8; 8] {
        &self.0
    }
}

impl From<&'_ [u8; 8]> for RouterId {
    fn from(value: &'_ [u8; 8]) -> Self {
        Self(*value)
    }
}

/// Implement from &[u8] as specified in
/// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#section-4.6.9-7.4.1)
impl TryFrom<&[u8]> for RouterId {
    type Error = RouterIdError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut id_bytes = [0; 8];
        if value.len() >= 8 {
            id_bytes[..].copy_from_slice(&value[value.len() - 8..]);
        } else {
            id_bytes[8 - value.len()..].copy_from_slice(value);
        }
        Self::new(id_bytes)
    }
}

impl TryFrom<&str> for RouterId {
    type Error = RouterIdError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > 8 {
            return Err(RouterIdError::IdTooLong { len: value.len() });
        }
        // At this point value is known to be <= 8 bytes.
        let in_bytes = value.as_bytes();
        let mut id_bytes = [0u8; 8];

        id_bytes[8 - in_bytes.len()..].copy_from_slice(in_bytes);
        Self::new(id_bytes)
    }
}

impl Display for RouterId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_short_id(&self.0, f)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RouterIdError {
    #[error("RouterId cannot be all zeros")]
    CannotBeAllZeroes,
    #[error("RouterId cannot be all ones")]
    CannotBeAllOnes,
    #[error("Given node ID is too long, max length is 8 bytes, received {len}")]
    IdTooLong { len: usize },
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::string::ToString;

    use super::*;

    #[test]
    fn from_static_str_right_aligns() {
        let router_id = RouterId::try_from("node_1").expect("Bad router Id");
        assert_eq!(router_id.0, [0, 0, 110, 111, 100, 101, 95, 49]);
    }

    #[test]
    fn display_with_utf8_characters() {
        let router_id = RouterId::try_from("node_1").expect("Bad router id");
        assert_eq!(&router_id.to_string(), "node_1");
    }

    #[test]
    fn display_with_non_utf8_characters() {
        let router_id = RouterId::new([1, 2, 0, 3, 4, 5, 6, 7]).expect("Bad router ID");
        assert_eq!(&router_id.to_string(), "x01 x02 x00 x03 x04 x05 x06 x07");
    }

    #[test]
    fn from_greater_than_8_bytes_takes_right_8_bytes() {
        let id_bytes: &[u8] = &[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let router_id = RouterId::try_from(id_bytes).expect("bad router id");
        assert_eq!(router_id.0, [2u8, 3, 4, 5, 6, 7, 8, 9])
    }

    #[test]
    fn from_less_than_8_bytes_right_aligns() {
        let id_bytes: &[u8] = &[4, 5, 6, 7, 8, 9];
        let router_id = RouterId::try_from(id_bytes).expect("bad router id");
        assert_eq!(router_id.0, [0u8, 0, 4, 5, 6, 7, 8, 9])
    }
}
