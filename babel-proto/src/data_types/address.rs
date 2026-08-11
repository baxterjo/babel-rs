//!
use core::{
    convert::Infallible,
    error::Error,
    fmt::Debug as DebugT,
    hash::Hash as HashT,
    net::{Ipv4Addr, Ipv6Addr},
};

use thiserror::Error as ErrorD;

/// Implements the default address decoding methods as described in section [4.1.4](https://datatracker.ietf.org/doc/html/rfc8966#name-address)
///
/// An address encoding extension can be given to this struct to decode any one of the range of
/// address encodings not specified in section [5 Table 2](https://datatracker.ietf.org/doc/html/rfc8966#table-2)
///
/// This extension must implement [`AddressExtension`]. A default value of [`NoExtension`] is
/// provided.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DefaultAddressCodec<E: AddressExtension = NoExtension> {
    extension: E,
    last_v6: Option<Ipv6Addr>,
}

impl<E: AddressExtension> DefaultAddressCodec<E> {
    pub fn decode(
        &mut self,
        ae: u8,
        plen: u8,
        buf: &[u8],
    ) -> Result<(Address<E>, usize), DecodeError> {
        match ae {
            0 => todo!("Wildcard impl"),
            1 => todo!("IPv4 impl"),
            2 => todo!("Ipv6 impl"),
            3 => todo!("Link local IPv6 impl"),
            4..=223 => {
                b_trace!(
                    "WARNING: An address encoding was received for a reserved address: {} \
                    This crate will pass the encoding to any address extensions, but cannot \
                    guarantee it will do so in future versions.",
                    ae
                );
                self.extension
                    .decode(ae, plen, buf)
                    .map(|(a, n)| (Address::Extension(a), n))
            }
            224..=254 => self
                .extension
                .decode(ae, plen, buf)
                .map(|(a, n)| (Address::Extension(a), n)),
            255 => Err(DecodeError::ReservedEncoding),
        }
    }
}

/// Resolved address as described in section
/// [4.1.4](https://datatracker.ietf.org/doc/html/rfc8966#name-address) and used in data structures
/// described in section [3.2](https://datatracker.ietf.org/doc/html/rfc8966#name-data-structures)
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address<E: AddressExtension = NoExtension> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Extension(E::ExtensionAddress),
}

#[derive(Debug, ErrorD)]
pub enum DecodeError<E: AddressExtension = NoExtension> {
    UnknownAddressEncoding,
    ReservedEncoding,
    Extension(E::ExtensionDecodeError),
}

#[derive(Debug, ErrorD)]
pub enum EncodeError<E: AddressExtension = NoExtension> {
    Extension(E::ExtensionEncodeError),
}

// TODO: Using this trait as a generic type bound for other structs that derive Ord and Copy
// requires the trait to also be Ord and Copy, although the type being used in those structs is
// usually AddressExtension::Address which has Ord and copy bounds. If the Ord + Copy bound on
// AddressExtension are to be removed, then Ord and Copy must be implemented manually for types
// that use AddressExtension as a generic arg.
/// Trait for adding an address encoding extension.
pub trait AddressExtension: Ord + Copy {
    /// User defined new address type.
    type ExtensionAddress: HashT + DebugT + Copy + Ord + Eq;
    /// User defined extension encoding error.
    type ExtensionEncodeError: Error;
    /// User defined extension decoding error.
    type ExtensionDecodeError: Error;

    /// Decode the given address from the buffer.
    ///
    /// If the encoding is not recognized, return `Err(DecodeError::UnknownAddressEncoding)`
    fn decode(
        &mut self,
        ae: u8,
        prefix_len: u8,
        buf: &[u8],
    ) -> Result<(Self::ExtensionAddress, usize), DecodeError>;

    /// Encode the given address into the buffer.
    ///
    /// This MUST return the number of bytes encoded into the buffer.
    fn encode(
        &mut self,
        addr: &Self::ExtensionAddress,
        buf: &mut [u8],
    ) -> Result<usize, EncodeError>;
}

/// Applies no extension to the base babel spec address encoding scheme.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoExtension;

impl AddressExtension for NoExtension {
    type ExtensionAddress = Infallible;
    type ExtensionEncodeError = Infallible;
    type ExtensionDecodeError = Infallible;
    fn decode(
        &mut self,
        _ae: u8,
        _plen: u8,
        _buf: &[u8],
    ) -> Result<(Infallible, usize), DecodeError> {
        Err(DecodeError::UnknownAddressEncoding)
    }
    fn encode(&mut self, addr: &Infallible, _buf: &mut [u8]) -> Result<usize, EncodeError> {
        match *addr {} // unreachable — Infallible can't be constructed
    }
}
