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
    ) -> Result<(RouterAddress<E>, usize), DecodeError> {
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
                    .map(|(a, n)| (RouterAddress::Extension(a), n))
            }
            224..=254 => self
                .extension
                .decode(ae, plen, buf)
                .map(|(a, n)| (RouterAddress::Extension(a), n)),
            255 => Err(DecodeError::ReservedAEUsed),
        }
    }
}

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RouterAddress<E: AddressExtension = NoExtension> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Extension(E::Address),
}

#[derive(Debug, ErrorD)]
pub enum DecodeError<E: AddressExtension = NoExtension> {
    UnknownAddressEncoding,
    ReservedAEUsed,
    Extension(E::DecodeError),
}

#[derive(Debug, ErrorD)]
pub enum EncodeError<E: AddressExtension = NoExtension> {
    Extension(E::EncodeError),
}

/// Implement this trait for any type to provide address encoding extensions.
// TODO: Using this trait as a generic type bound for other structs that derive Ord and Copy
// requires the trait to also be Ord and Copy, although the type being used in those structs is
// usually AddressExtension::Address which has Ord and copy bounds. If the Ord + Copy bound on
// AddressExtension are to be removed, then Ord and Copy must be implemented manually for types
// that use AddressExtension as a generic arg.
pub trait AddressExtension: Ord + Copy {
    type Address: HashT + DebugT + Copy + Ord + Eq;
    type EncodeError: Error;
    type DecodeError: Error;

    fn decode(
        &mut self,
        ae: u8,
        prefix_len: u8,
        buf: &[u8],
    ) -> Result<(Self::Address, usize), DecodeError>;
    fn encode(&mut self, addr: &Self::Address, buf: &mut [u8]) -> Result<usize, EncodeError>;
}

/// Applies no extension to the base babel spec address encoding scheme.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoExtension;

impl AddressExtension for NoExtension {
    type Address = Infallible;
    type EncodeError = Infallible;
    type DecodeError = Infallible;
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
