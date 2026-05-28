use crate::packet::address_encoding::AddressEncoding;

/// A network prefix — the destination unit for Babel route advertisements.
///
/// `bytes` is always 16 octets. `len` is the prefix length in bits.
/// `encoding` determines how the prefix is serialized on the wire
/// (see RFC 8966 §4.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub encoding: AddressEncoding,
    pub len: u8,
    pub bytes: [u8; 16],
}
