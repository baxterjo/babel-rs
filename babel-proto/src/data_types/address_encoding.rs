use core::fmt::Debug;

use thiserror::Error;

use crate::extension::address_encoding::AddressEncodingExt;

#[derive(Debug, Error)]
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

#[derive(Debug, PartialEq, Eq)]
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
            Self::Extension(e) => e.as_value(),
        };
        if value <= 3 || value == 255 {
            return Err(AddressEncodingError::NiceTry);
        }
        Ok(value)
    }
}

impl<E: AddressEncodingExt> AddressEncoding<E> {
    /// Get the length of the address in bytes with the given context.
    // TODO: This will need to take in compression context to make an accurate determination.
    pub fn address_len(&self) -> usize {
        match self {
            AddressEncoding::WildCard => 0,
            AddressEncoding::Ipv4 => 4,
            AddressEncoding::Ipv6 => 16,
            AddressEncoding::LocalIpv6 => 8,
            AddressEncoding::Extension(e) => e.address_len(),
        }
    }
}
