use core::fmt::Display;

use thiserror::Error;

use crate::interface::InterfaceTable;
use crate::neighbour::NeighbourTable;
use crate::Address;

pub struct BabelRouter<'storage, A>
where
    A: Address,
{
    id: RouterId,

    iface_table: InterfaceTable<'storage>,

    neighbor_table: NeighbourTable<'storage, A>,
}

/// Newtype wrapper around a type that can be converted into 8 Octets.
// This has a generic for good debug display to the user.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct RouterId([u8; 8]);

impl RouterId {
    pub fn new<I>(id: I) -> Result<Self, RouterIdError>
    where
        I: Into<[u8; 8]> + Display,
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

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RouterIdError {
    #[error("RouterId cannot be all zeros")]
    CannotBeAllZeroes,
    #[error("RouterId cannot be all ones")]
    CannotBeAllOnes,
}
