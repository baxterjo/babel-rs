/// Since the bulk of the protocol is taken by addresses, multiple ways of
/// encoding addresses are defined. Additionally, within Update TLVs a common
/// subnet prefix may be omitted when multiple addresses are sent in a single
/// packet -- this is known as address compression
/// ([Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#update)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressEncoding {
    /// Wildcard address. The value is 0 octets long.
    WildCard,
    /// IPv4 address. Compression is allowed. 4 octets or less.
    Ipv4,
    // IPv6 address. Compression is allowed. 16 octets or less.
    Ipv6,
    /// Link-local IPv6 address. Compression is not allowed. The value is 8
    /// octets long, a prefix of fe80::/64 is implied.
    LocalIpv6,
}

impl AddressEncoding {
    pub const fn max_len_bytes(&self) -> usize {
        match self {
            Self::WildCard => 0,
            Self::Ipv4 => 4,
            Self::Ipv6 => 16,
            Self::LocalIpv6 => 8,
        }
    }
}
