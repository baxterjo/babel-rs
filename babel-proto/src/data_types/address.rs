//! Addresses as they appear in Babel data structures and on the wire.
//!
//! [`Address`] is the resolved form used throughout the router. It carries its own address family,
//! which determines both the encoding advertised in a TLV and the number of bytes written for it —
//! see [`Address::encoding`] and [`Address::as_wire`], which must always agree.

use core::fmt::Display;

use thiserror::Error;

use crate::data_types::address_encoding::AddressEncoding;
use crate::extension::address::AddressExt;

/// An IPv4 address that can lend out its octets as a slice.
///
/// `core::net::Ipv4Addr` only yields octets by value, but the TLV writer needs to borrow them to
/// write an address without copying, so the octets are stored directly here.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ipv4Addr {
    octets: [u8; 4],
}

impl Ipv4Addr {
    pub(crate) fn as_octets(&self) -> &[u8] {
        &self.octets
    }
}

impl From<core::net::Ipv4Addr> for Ipv4Addr {
    fn from(value: core::net::Ipv4Addr) -> Self {
        Self {
            octets: value.octets(),
        }
    }
}

impl From<Ipv4Addr> for core::net::Ipv4Addr {
    fn from(val: Ipv4Addr) -> Self {
        core::net::Ipv4Addr::from_octets(val.octets)
    }
}

/// An IPv6 address that can lend out its octets as a slice.
///
/// See [`Ipv4Addr`] for why this exists rather than using `core::net::Ipv6Addr` directly.
// TODO: Manually implement defmt to skip out on zeros in the middle.
#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Ipv6Addr {
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

impl From<Ipv6Addr> for core::net::Ipv6Addr {
    fn from(val: Ipv6Addr) -> Self {
        core::net::Ipv6Addr::from_octets(val.octets)
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
            Address::V4(v4) => v4.as_octets(),
            Address::V6(v6) => {
                if v6.octets()[0..8] == [0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] {
                    &v6.as_octets()[8..]
                } else {
                    v6.as_octets()
                }
            }
            Address::Extension(e) => e.as_octets(),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::extension::NoExtension;

    /// Asserts the three things that have to agree for an address to survive a trip over the wire:
    /// the encoding it declares, the number of bytes it actually writes, and the address that comes
    /// back out the other side.
    ///
    /// The middle one is the load-bearing assertion. `as_wire` and `encoding` are read at different
    /// points of the TLV writer, so a disagreement between them is not a local error: the receiver
    /// consumes `address_len()` bytes regardless, and misparses every sub-TLV behind it.
    fn assert_wire_round_trip(addr: Address<NoExtension>, expected: AddressEncoding<NoExtension>) {
        assert_eq!(addr.encoding(), expected, "unexpected encoding for {addr}");

        let wire = addr.as_wire();
        assert_eq!(
            wire.len(),
            addr.encoding().address_len(),
            "{addr} writes {} byte(s) but declares an AE of {} byte(s)",
            wire.len(),
            addr.encoding().address_len()
        );

        let parsed = Address::from_bytes(addr.encoding(), wire).expect("wire form should parse");
        assert_eq!(parsed, addr, "round trip changed the address");
    }

    #[test]
    fn ipv4_round_trips_as_ae_1() {
        assert_wire_round_trip(
            core::net::Ipv4Addr::new(192, 168, 0, 5).into(),
            AddressEncoding::Ipv4,
        );
    }

    #[test]
    fn global_ipv6_round_trips_as_ae_2() {
        assert_wire_round_trip(
            core::net::Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).into(),
            AddressEncoding::Ipv6,
        );
    }

    #[test]
    fn link_local_ipv6_round_trips_as_ae_3() {
        assert_wire_round_trip(
            core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).into(),
            AddressEncoding::LocalIpv6,
        );
    }

    #[test]
    fn link_local_wire_form_is_the_low_eight_bytes() {
        let addr: Address<NoExtension> =
            core::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x0102, 0x0304, 0x0506, 0x0708).into();

        assert_eq!(
            addr.as_wire(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "a link-local address goes on the wire as the 8-byte suffix after the fe80::/64 prefix"
        );
    }

    /// `fe80::/64` is matched on the full 8-byte prefix, so an address that only shares the leading
    /// two octets is a plain Ipv6 address and must be sent in full.
    #[test]
    fn address_outside_the_link_local_prefix_is_not_compressed() {
        assert_wire_round_trip(
            core::net::Ipv6Addr::new(0xfe80, 0, 0, 1, 0, 0, 0, 1).into(),
            AddressEncoding::Ipv6,
        );
    }

    #[test]
    fn wildcard_cannot_produce_an_address() {
        let err = Address::<NoExtension>::from_bytes(AddressEncoding::WildCard, &[])
            .expect_err("the wildcard encoding names no single address");

        assert!(matches!(err, AddressError::CannotCreateFromWildCard));
    }

    #[test]
    fn from_bytes_rejects_a_length_the_encoding_does_not_expect() {
        // A link-local suffix is 8 bytes; handing it a full 16-byte address must not silently
        // truncate.
        let err = Address::<NoExtension>::from_bytes(AddressEncoding::LocalIpv6, &[0; 16])
            .expect_err("wrong byte count should be rejected");

        assert!(matches!(
            err,
            AddressError::IncorrectByteLength {
                required_len: 8,
                len: 16,
                ..
            }
        ));
    }
}
