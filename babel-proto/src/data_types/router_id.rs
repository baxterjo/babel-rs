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
        b_debug!("Checking router ID: {}", id);
        let raw: [u8; 8] = id.into();
        if raw == [0, 0, 0, 0, 0, 0, 0, 0] {
            return Err(RouterIdError::CannotBeAllZeroes);
        }
        if raw == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return Err(RouterIdError::CannotBeAllOnes);
        }
        Ok(Self(raw))
    }

    pub(crate) fn octets<'a>(&'a self) -> &'a [u8; 8] {
        (&self.0).into()
    }
}

#[cfg(not(feature = "defmt"))]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display {}

#[cfg(feature = "defmt")]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display + defmt::Format {}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouterIdError {
    #[error("RouterId cannot be all zeros")]
    CannotBeAllZeroes,
    #[error("RouterId cannot be all ones")]
    CannotBeAllOnes,
}
