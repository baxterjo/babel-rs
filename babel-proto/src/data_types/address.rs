//!
use core::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::{data_types::address_encoding::AddressEncoding, extension::address::AddressExt};

/// Resolved address as described in section
/// [4.1.4](https://datatracker.ietf.org/doc/html/rfc8966#name-address) and used in data structures
/// described in section [3.2](https://datatracker.ietf.org/doc/html/rfc8966#name-data-structures)
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Address<E>
where
    E: AddressExt,
{
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Extension(E),
}

#[derive(Debug, Error)]
pub enum AddressError<E>
where
    E: AddressExt,
{
    #[error("Cannot generate single address from wildcard")]
    CannotCreateFromWildCard,
    #[error(
        "Inocorrect number of bytes for address type {address_type} - required: {required_len}, len: {len}"
    )]
    IncorrectByteLength {
        address_type: &'static str,
        required_len: usize,
        len: usize,
    },
    #[error(transparent)]
    Extension(E::Error),
}

impl<E> Address<E>
where
    E: AddressExt,
{
    pub fn from_bytes(
        ae: AddressEncoding<E::Encoding>,
        bytes: &[u8],
    ) -> Result<Self, AddressError<E>> {
        match ae {
            AddressEncoding::WildCard => Err(AddressError::CannotCreateFromWildCard),
            AddressEncoding::Ipv4 => {
                let octets: [u8; 4] =
                    bytes
                        .try_into()
                        .map_err(|_| AddressError::IncorrectByteLength {
                            address_type: "Ipv4",
                            required_len: 4,
                            len: bytes.len(),
                        })?;
                Ok(Self::V4(Ipv4Addr::from_octets(octets)))
            }
            AddressEncoding::Ipv6 => {
                let octets: [u8; 16] =
                    bytes
                        .try_into()
                        .map_err(|_| AddressError::IncorrectByteLength {
                            address_type: "Ipv6",
                            required_len: 16,
                            len: bytes.len(),
                        })?;
                Ok(Self::V6(Ipv6Addr::from_octets(octets)))
            }
            AddressEncoding::LocalIpv6 => {
                let suffix: [u8; 8] =
                    bytes
                        .try_into()
                        .map_err(|_| AddressError::IncorrectByteLength {
                            address_type: "Link Local Ipv6",
                            required_len: 8,
                            len: bytes.len(),
                        })?;
                let prefix: [u8; 8] = [0xFE, 0x80, 0, 0, 0, 0, 0, 0];
                let whole: [u8; 16] = {
                    let mut whole = [0; 16];
                    let (pre, suf) = whole.split_at_mut(prefix.len());
                    pre.copy_from_slice(&prefix);
                    suf.copy_from_slice(&suffix);
                    whole
                };
                Ok(Self::V6(Ipv6Addr::from_octets(whole)))
            }
            AddressEncoding::Extension(e) => {
                let ext_add = E::from_bytes(&e, bytes)?;
                Ok(Self::Extension(ext_add))
            }
        }
    }
}
