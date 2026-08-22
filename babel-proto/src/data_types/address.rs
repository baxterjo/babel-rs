//!

use core::fmt::Display;

use thiserror::Error;

use crate::{data_types::address_encoding::AddressEncoding, extension::address::AddressExt};

/// Have to create my own Ipv4Addr type because core lib doesn't allow borrowing a slice of its
/// octets???
// Crashing out on this FR
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Ipv4Addr {
    octets: [u8; 4],
}

impl Ipv4Addr {
    pub(crate) fn as_octets(&self) -> &[u8] {
        &self.octets
    }

    pub(crate) fn octets(&self) -> [u8; 4] {
        self.octets
    }
}

impl From<core::net::Ipv4Addr> for Ipv4Addr {
    fn from(value: core::net::Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl Into<core::net::Ipv4Addr> for Ipv4Addr {
    fn into(self) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from_octets(self.octets)
    }
}

/// Have to create my own Ipv6Addr type because core lib doesn't allow borrowing a slice of its
/// octets???
///
// Crashing out on this FR
// TODO: Manually implement defmt to skip out on zeros in the middle.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Ipv6Addr {
    octets: [u8; 16],
}

impl Ipv6Addr {
    pub(crate) fn as_octets(&self) -> &[u8] {
        &self.octets
    }

    pub(crate) fn octets(&self) -> [u8; 16] {
        self.octets
    }
}

impl From<core::net::Ipv6Addr> for Ipv6Addr {
    fn from(value: core::net::Ipv6Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl Into<core::net::Ipv6Addr> for Ipv6Addr {
    fn into(self) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from_octets(self.octets)
    }
}

/// Resolved address as described in section
/// [4.1.4](https://datatracker.ietf.org/doc/html/rfc8966#name-address) and used in data structures
/// described in section [3.2](https://datatracker.ietf.org/doc/html/rfc8966#name-data-structures)
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Address<E>
where
    E: AddressExt,
{
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Extension(E),
}

impl<A: AddressExt> Display for Address<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::V4(v4) => write!(f, "{}", Into::<core::net::Ipv4Addr>::into(*v4)),
            Self::V6(v6) => write!(f, "{}", Into::<core::net::Ipv6Addr>::into(*v6)),
            Self::Extension(e) => write!(f, "{:?}", e),
        }
    }
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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

impl<A> Address<A>
where
    A: AddressExt,
{
    pub fn from_bytes(
        ae: AddressEncoding<A::Encoding>,
        bytes: &[u8],
    ) -> Result<Self, AddressError<A>> {
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
                Ok(Self::V4(core::net::Ipv4Addr::from_octets(octets).into()))
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
                Ok(Self::V6(core::net::Ipv6Addr::from_octets(octets).into()))
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
                Ok(Self::V6(core::net::Ipv6Addr::from_octets(whole).into()))
            }
            AddressEncoding::Extension(e) => {
                let ext_add = A::from_bytes(&e, bytes)?;
                Ok(Self::Extension(ext_add))
            }
        }
    }

    pub(crate) fn as_wire(&self) -> &[u8] {
        match self {
            Address::V4(v4) => &v4.as_octets(),
            Address::V6(v6) => {
                if v6.octets()[0..8] == [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
                    &v6.as_octets()[9..]
                } else {
                    v6.as_octets()
                }
            }
            Address::Extension(e) => e.as_bytes(),
        }
    }

    pub(crate) fn encoding(&self) -> AddressEncoding<A::Encoding> {
        match self {
            Address::V4(_) => AddressEncoding::Ipv4,
            Address::V6(v6) => {
                if v6.octets()[0..8] == [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
                    AddressEncoding::LocalIpv6
                } else {
                    AddressEncoding::Ipv6
                }
            }
            Address::Extension(e) => AddressEncoding::Extension(e.encoding()),
        }
    }
}

impl<A: AddressExt> From<core::net::Ipv6Addr> for Address<A> {
    fn from(value: core::net::Ipv6Addr) -> Self {
        Self::V6(value.into())
    }
}

impl<A: AddressExt> From<core::net::Ipv4Addr> for Address<A> {
    fn from(value: core::net::Ipv4Addr) -> Self {
        Self::V4(value.into())
    }
}
