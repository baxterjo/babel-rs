use core::fmt::Debug as DebugT;
use core::fmt::Display;

use managed::ManagedMap;
use managed::ManagedSlice;
use thiserror::Error;

use crate::interface::Interface;
use crate::interface::InterfaceTable;
use crate::neighbour::NeighbourIndex;

pub struct BabelRouter<'storage, I>
where
    I: Display + DebugT,
    for<'a> &'a I: Into<&'a [u8; 8]>,
{
    id: RouterId<I>,

    iface_table: InterfaceTable<'storage>,
}

/// Newtype wrapper around a type that can be converted into 8 Octets.
// This has a generic for good debug display to the user.
#[derive(Debug)]
pub struct RouterId<I>(I)
where
    I: Display + DebugT,
    for<'a> &'a I: Into<&'a [u8; 8]>;

impl<I> RouterId<I>
where
    I: Display + DebugT,
    for<'a> &'a I: Into<&'a [u8; 8]>,
{
    pub fn new(id: I) -> Result<Self, RouterIdError> {
        let raw: &[u8; 8] = (&id).into();
        if *raw == [0, 0, 0, 0, 0, 0, 0, 0] {
            return Err(RouterIdError::CannotBeAllZeroes);
        }
        if *raw == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF] {
            return Err(RouterIdError::CannotBeAllOnes);
        }
        Ok(Self(id))
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
