use core::fmt::Debug as DebugT;
use core::fmt::Display;
use thiserror::Error;

/// Router-Id as described in section [4.1.3](https://datatracker.ietf.org/doc/html/rfc8966#name-router-id)
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct RouterId([u8; 8]);

impl RouterId {
    pub fn new<I>(id: I) -> Result<Self, RouterIdError>
    where
        I: RouterIdT,
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

    pub(crate) fn octets<'a>(&'a self) -> &'a [u8; 8] {
        (&self.0).into()
    }
}

impl TryFrom<&'static str> for RouterId {
    type Error = RouterIdError;
    fn try_from(value: &'static str) -> Result<Self, Self::Error> {
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

#[cfg(not(feature = "defmt"))]
pub trait RouterIdT: DebugT + Into<[u8; 8]> {}

#[cfg(not(feature = "defmt"))]
impl<T> RouterIdT for T where T: DebugT + Into<[u8; 8]> {}

#[cfg(feature = "defmt")]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display + defmt::Format {}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouterIdError {
    #[error("RouterId cannot be all zeros")]
    CannotBeAllZeroes,
    #[error("RouterId cannot be all ones")]
    CannotBeAllOnes,
    #[error("Given node ID is too long, max length is 8 bytes, received {len}")]
    IdTooLong { len: usize },
}

#[cfg(test)]
mod test {
    use crate::data_types::RouterId;

    #[test]
    fn from_static_str_right_aligns() {
        let router_id = RouterId::try_from("node_1").expect("Bad router Id");
        println!("{:?}", router_id);
    }
}
