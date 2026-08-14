//!
use core::{
    convert::Infallible,
    fmt::Debug as DebugT,
    hash::Hash as HashT,
    net::{Ipv4Addr, Ipv6Addr},
};

use thiserror::Error as ErrorD;

/// Resolved address as described in section
/// [4.1.4](https://datatracker.ietf.org/doc/html/rfc8966#name-address) and used in data structures
/// described in section [3.2](https://datatracker.ietf.org/doc/html/rfc8966#name-data-structures)
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address<E: AddressExtension> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Extension(E::ExtensionAddress),
}

#[derive(Debug, ErrorD)]
pub enum AddressDecodeError {
    #[error("Wildcard addresses cannot be decoded, they are zero bytes.")]
    CannotDecodeWildcard,
    #[error("Encountered an unknown address encoding.")]
    UnknownAddressEncoding,
    #[error("Attempted to decode a reserved address encoding value")]
    ReservedEncoding,
    #[error("Address byte array was not long enough")]
    AddressTooShort,
    #[error("Address is malformed")]
    MalformedAddress,
}

#[derive(Debug, ErrorD)]
pub enum AddressEncodeError {
    #[error("Cannot encode custom address encoding into reserved value.")]
    NiceTry,
    #[error("Write buffer is too short for address")]
    BufNotLongEnough,
}

// TODO: Using this trait as a generic type bound for other structs that derive Ord and Copy
// requires the trait to also be Ord and Copy, although the type being used in those structs is
// usually AddressExtension::Address which has Ord and copy bounds. If the Ord + Copy bound on
// AddressExtension are to be removed, then Ord and Copy must be implemented manually for types
// that use AddressExtension as a generic arg.
/// Trait for adding an address encoding extension.
///
/// Types that implement this trait must implement Default because instantiations of the type will
/// be dropped and re-instantiated between Babel packets. This resets parser state between Packets.
pub trait AddressExtension: Ord + Copy + DebugT + Default {
    /// User defined address encoding.
    type ExtensionEncoding: DebugT + Eq;
    /// User defined new address type.
    type ExtensionAddress: HashT + DebugT + Copy + Ord + Eq;

    /// Decode the given address from the buffer.
    fn decode(
        &mut self,
        ae: u8,
        input: &[u8],
    ) -> Result<(Self::ExtensionAddress, usize), AddressDecodeError>;

    /// Encode the given address into the buffer.
    ///
    /// This MUST return the number of bytes encoded into the buffer if it succeeds.
    fn encode(
        &mut self,
        addr: &Self::ExtensionAddress,
        buf: &mut [u8],
    ) -> Result<usize, AddressEncodeError>;

    /// Generate this type's ExtensionEncoding from a u8
    ///
    /// The only values this function will ever see are 4-254(inclusive). All other values are
    /// reserved by the Babel spec.
    ///
    /// AE values 4-223 (inclusive) are unassigned but still considered reserved for official use.
    /// This crate will not enforce that restriction.
    ///
    /// Values from 224-254 (inclusive) are for experimental use.
    fn ae_from_u8(raw: u8) -> Option<Self::ExtensionEncoding>;

    /// Encode this type's EncodingExtension as a u8.
    ///
    /// The resulting value **WILL** be checked to ensure the extension is not encoding into a
    /// reserved value.
    fn ae_as_u8(ae: &Self::ExtensionEncoding) -> u8;
}

/// Applies no extension to the base babel spec address encoding scheme.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NoAddressExtension;

impl AddressExtension for NoAddressExtension {
    type ExtensionEncoding = Infallible;
    type ExtensionAddress = Infallible;

    fn decode(
        &mut self,
        _ae: u8,
        _input: &[u8],
    ) -> Result<(Infallible, usize), AddressDecodeError> {
        Err(AddressDecodeError::UnknownAddressEncoding)
    }
    fn encode(&mut self, addr: &Infallible, _buf: &mut [u8]) -> Result<usize, AddressEncodeError> {
        match *addr {} // unreachable: Infallible can't be constructed.
    }

    fn ae_from_u8(_raw: u8) -> Option<Self::ExtensionEncoding> {
        None
    }

    fn ae_as_u8(ae: &Self::ExtensionEncoding) -> u8 {
        match *ae {} // unreachable: Infallible can't be constructed.
    }
}
