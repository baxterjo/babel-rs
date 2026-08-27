use core::fmt::Debug;

use thiserror::Error;

use crate::extension::address_encoding::AddressEncodingExt;

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressEncodingError<E>
where
    E: AddressEncodingExt,
{
    #[error("Encountered an unknown address encoding.")]
    UnknownAddressEncoding,
    #[error("Attempted to decode a reserved address encoding value")]
    ReservedEncoding,
    #[error("Cannot encode custom address encoding into reserved value.")]
    NiceTry,
    #[error(transparent)]
    Extension(E::Error),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum AddressEncoding<E>
where
    E: AddressEncodingExt,
{
    WildCard,
    Ipv4,
    Ipv6,
    LocalIpv6,
    Extension(E),
}

impl<E> TryFrom<u8> for AddressEncoding<E>
where
    E: AddressEncodingExt,
{
    type Error = AddressEncodingError<E>;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::WildCard),
            1 => Ok(Self::Ipv4),
            2 => Ok(Self::Ipv6),
            3 => Ok(Self::LocalIpv6),
            4..=223 => {
                let aee = E::from_value(value)?;
                b_debug!(
                    "WARNING: Extension resolved a reserved address encoding: {}. This may not work in future versions.",
                    value
                );
                Ok(Self::Extension(aee))
            }
            224..=254 => E::from_value(value).map(|v| Self::Extension(v)),
            255 => Err(AddressEncodingError::ReservedEncoding),
        }
    }
}

impl<E> TryInto<u8> for AddressEncoding<E>
where
    E: AddressEncodingExt,
{
    type Error = AddressEncodingError<E>;

    fn try_into(self) -> Result<u8, Self::Error> {
        let value = match self {
            Self::WildCard => 0,
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
            Self::LocalIpv6 => 3,
            Self::Extension(e) => {
                let ext_value = e.as_value();
                if ext_value <= 3 || ext_value == 255 {
                    return Err(AddressEncodingError::NiceTry);
                }
                ext_value
            }
        };

        Ok(value)
    }
}

impl<E: AddressEncodingExt> AddressEncoding<E> {
    /// Get the length of the uncompressed address.
    pub fn address_len(&self) -> usize {
        match self {
            AddressEncoding::WildCard => 0,
            AddressEncoding::Ipv4 => 4,
            AddressEncoding::Ipv6 => 16,
            AddressEncoding::LocalIpv6 => 8,
            AddressEncoding::Extension(e) => e.address_len(),
        }
    }

    /// Whether an Update TLV in this encoding may omit leading octets of its prefix.
    ///
    /// The wildcard encoding names no address for the omitted octets to come from, and
    /// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update) requires the
    /// Omitted field to be 0 when AE is 3 (link-local IPv6).
    pub fn can_compress(&self) -> bool {
        match self {
            AddressEncoding::WildCard | AddressEncoding::LocalIpv6 => false,
            AddressEncoding::Ipv4 | AddressEncoding::Ipv6 => true,
            AddressEncoding::Extension(e) => e.can_compress(),
        }
    }
}
