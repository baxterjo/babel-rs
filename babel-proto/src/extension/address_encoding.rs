use core::convert::Infallible;
use core::error::Error as ErrorT;
use core::fmt::Debug;

use thiserror::Error;

use crate::MaybeDefmt;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::extension::NoExtension;

#[derive(Debug, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NonReservedEncoding(u8);

#[derive(Debug, Error)]
pub enum ReservedAddressEncodingError {
    #[error("Address encoding is reserved: {0}")]
    EncodingReserved(u8),
    /// If this error occurs, the [`NonReservedEncoding`] will still be provided to the user. But
    /// this result should be treated as unstable and could turn into a different error variant in
    /// future releases.
    #[error("The encoding value provided is unassigned but not designated for experimental use: {}", .0.value())]
    UnstableUnassignedAddress(NonReservedEncoding),
}

impl NonReservedEncoding {
    pub fn new(raw: u8) -> Result<Self, ReservedAddressEncodingError> {
        match raw {
            0..=4 | 255 => Err(ReservedAddressEncodingError::EncodingReserved(raw)),
            5..=223 => Err(ReservedAddressEncodingError::UnstableUnassignedAddress(
                Self(raw),
            )),
            224..=254 => Ok(Self(raw)),
        }
    }
    pub fn value(&self) -> u8 {
        self.0
    }
}

impl Into<u8> for NonReservedEncoding {
    fn into(self) -> u8 {
        self.value()
    }
}

/// Extends the acceptable values in the AE field for TLVs.
///
/// Meant to be used in conjunction with [`AddressExt`](crate::extension::address::AddressExt)
pub trait AddressEncodingExt
where
    Self: Debug + Sized + PartialEq + Eq + Copy + MaybeDefmt,
{
    type Error: ErrorT + PartialEq + Eq + MaybeDefmt;
    type AddressFamily: PartialEq + Eq + MaybeDefmt;

    /// Try to create this type from the wire representation of this address encoding.
    fn from_value(value: u8) -> Result<Self, AddressEncodingError<Self>>;
    /// Returns the wire representation value of this address encoding.
    fn as_value(&self) -> NonReservedEncoding;
    /// Returns the length of the uncompressed address in bytes.
    fn address_len(&self) -> usize;
    /// Returns whether an address with this encoding can be compressed in an update TLV.
    fn can_compress(&self) -> bool;
    /// Returns the number of leading octets this encoding fixes itself, and which therefore never
    /// appear on the wire.
    ///
    /// Example: Link local IPv6 addresses have an implied prefix of `fe80::/64` so those first 8
    /// octets are never emitted on the wire because the encoding implies them for all addresses
    /// with this encoding.
    fn implied_prefix_octets(&self) -> usize {
        0
    }

    fn address_family(&self) -> Self::AddressFamily;
}

impl AddressEncodingExt for NoExtension {
    type Error = Infallible;
    type AddressFamily = Infallible;

    fn from_value(_value: u8) -> Result<Self, AddressEncodingError<Self>> {
        Err(AddressEncodingError::UnknownAddressEncoding)
    }

    fn as_value(&self) -> NonReservedEncoding {
        unreachable!("The NoExtension struct should not be constructable.")
    }

    fn address_len(&self) -> usize {
        unreachable!("The NoExtension struct should not be constructable.")
    }

    fn can_compress(&self) -> bool {
        unreachable!("The NoExtension struct should not be constructable.")
    }

    fn address_family(&self) -> Self::AddressFamily {
        unreachable!("The NoExtension struct should not be constructable.")
    }
}
