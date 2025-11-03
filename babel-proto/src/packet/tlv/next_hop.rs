use crate::packet::address_encoding::AddressEncoding;
use core::net::IpAddr;

/// A Next Hop TLV establishes a next-hop address for a given address family
/// (IPv4 or IPv6) that is implied in subsequent Update TLVs, as described in
/// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#parser-state).
/// This TLV sets up the next hop for subsequent Update TLVs even if it is
/// otherwise ignored due to an unknown mandatory sub-TLV.
///
/// When the address family matches the network-layer protocol over which this
/// packet is transported, a Next Hop TLV is not needed: in the absence of a
/// Next Hop TLV in a given address family, the next-hop address is taken to be
/// the source address of the packet.
pub struct NextHopTlv {
    /// The encoding of the Address field. This SHOULD be 1 (IPv4) or 3
    /// (link-local IPv6), and **MUST NOT** be 0.
    address_encoding: AddressEncoding,
    /// The next-hop address advertised by subsequent Update TLVs for this
    /// address family.
    next_hop: IpAddr,
}

impl NextHopTlv {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 7;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}
