use core::convert::Infallible;
use core::error::Error as ErrorT;
use core::fmt::Debug;

use crate::MaybeDefmt;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::extension::NoExtension;

/// Extends the acceptable values in the AE field for TLVs.
///
/// Meant to be used in conjunction with [`AddressExt`](crate::extension::address::AddressExt)
pub trait AddressEncodingExt
where
    Self: Debug + Sized + PartialEq + Eq + Copy + MaybeDefmt,
{
    type Error: ErrorT + PartialEq + Eq + MaybeDefmt;

    /// Try to create this type from the wire representation of this address encoding.
    fn from_value(value: u8) -> Result<Self, AddressEncodingError<Self>>;
    /// Returns the wire representation value of this address encoding.
    fn as_value(&self) -> u8;
    /// Returns the length of the uncompressed address in bytes.
    fn address_len(&self) -> usize;
    /// Returns whether an address with this encoding can be compressed in an update TLV.
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
