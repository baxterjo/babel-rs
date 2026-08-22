use core::{convert::Infallible, error::Error as ErrorT, fmt::Debug};

use crate::{
    MaybeDefmt, data_types::address_encoding::AddressEncodingError, extension::NoExtension,
};

/// Extends the acceptable values in the AE field for TLVs.
///
/// Meant to be used in conjunction with [`AddressExt`](crate::extension::address::AddressExt)
pub trait AddressEncodingExt
where
    Self: Debug + Sized + PartialEq + Eq + MaybeDefmt,
{
    type Error: ErrorT + PartialEq + Eq + MaybeDefmt;

    fn from_value(value: u8) -> Result<Self, AddressEncodingError<Self>>;
    fn as_value(&self) -> u8;
    fn address_len(&self) -> usize;
    fn can_compress(&self) -> bool;
}

impl AddressEncodingExt for NoExtension {
    type Error = Infallible;

    fn from_value(_value: u8) -> Result<Self, AddressEncodingError<Self>> {
        Err(AddressEncodingError::UnknownAddressEncoding)
    }

    fn as_value(&self) -> u8 {
        unreachable!("The NoExtension struct should not be constructable.")
    }

    fn address_len(&self) -> usize {
        unreachable!("The NoExtension struct should not be constructable.")
    }

    fn can_compress(&self) -> bool {
        unreachable!("The NoExtension struct should not be constructable.")
    }
}
