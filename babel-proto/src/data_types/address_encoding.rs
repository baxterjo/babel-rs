use crate::data_types::address::{AddressDecodeError, AddressEncodeError, AddressExtension};

#[derive(Debug, PartialEq, Eq)]
pub enum AddressEncoding<E: AddressExtension> {
    WildCard,
    Ipv4,
    Ipv6,
    LocalIpv6,
    Extension(E::ExtensionEncoding),
    Reserved,
}

impl<E: AddressExtension> AddressEncoding<E> {
    pub fn from_wire(wire: [u8; 1]) -> Result<Self, AddressDecodeError> {
        let ae = u8::from_be_bytes(wire);
        match ae {
            0 => Ok(Self::WildCard),
            1 => Ok(Self::Ipv4),
            2 => Ok(Self::Ipv6),
            3 => Ok(Self::LocalIpv6),
            4..=254 => Ok(Self::Extension(
                E::ae_from_u8(ae).ok_or(AddressDecodeError::UnknownAddressEncoding)?,
            )),
            255 => Ok(Self::Reserved),
        }
    }

    pub fn as_wire(&self) -> Result<[u8; 1], AddressEncodeError> {
        let value: u8 = match self {
            Self::WildCard => 0,
            Self::Ipv4 => 1,
            Self::Ipv6 => 2,
            Self::LocalIpv6 => 3,
            Self::Extension(e) => {
                let out = E::ae_as_u8(e);
                if 4 <= out && out <= 254 {
                    out
                } else {
                    return Err(AddressEncodeError::NiceTry);
                }
            }
            Self::Reserved => 255,
        };
        Ok([value])
    }
}
