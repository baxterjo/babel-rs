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

    pub(crate) fn octets(&self) -> &[u8; 8] {
        &self.0
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

        for (idx, byte) in in_bytes.iter().rev().enumerate() {
            id_bytes[id_bytes.len() - 1 - idx] = *byte;
        }
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
}
