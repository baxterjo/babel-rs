use core::{convert::Infallible, error::Error};

use crate::{
    data_types::address::AddressError,
    extension::{address_encoding::AddressEncodingExt, NoExtension},
};

/// Extends the domain of possible address types that can be used in the Babel router.
///
/// This is useful for running Babel over transports that the spec is not written for (e.g.: BLE)
pub trait AddressExt
where
    Self: Sized + Ord + Copy,
{
    type Error: Error;
    type Encoding: AddressEncodingExt;
    /// Return the address encoding and byte representation of the address.
    fn as_bytes(&self, ae: &Self::Encoding) -> &[u8];
    /// Create the address type from un-compressed bytes.
    fn from_bytes(ae: &Self::Encoding, bytes: &[u8]) -> Result<Self, AddressError<Self>>;
}

impl AddressExt for NoExtension {
    type Error = Infallible;
    type Encoding = NoExtension;
    fn as_bytes(&self, ae: &NoExtension) -> &[u8] {
        unreachable!("The NoExtension struct should not be constructable.")
    }
    fn from_bytes(ae: &NoExtension, bytes: &[u8]) -> Result<Self, AddressError<Self>> {
        unreachable!("The NoExtension struct should not be constructable.")
    }
}
