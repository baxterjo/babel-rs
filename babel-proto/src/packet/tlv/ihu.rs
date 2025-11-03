use crate::packet::address_encoding::AddressEncoding;
use core::net::IpAddr;

/// An IHU ("I Heard You") TLV is used for confirming bidirectional reachability and carrying a link's transmission cost.
///
/// Conceptually, an IHU is destined to a single neighbour. However, IHU TLVs
/// contain an explicit destination address, and MAY be sent to a multicast
/// address, as this allows aggregation of IHUs destined to distinct neighbours
/// into a single packet and avoids the need for an ARP or Neighbour Discovery
/// exchange when a neighbour is not being used for data traffic.
pub struct Ihu {
    /// The encoding of the Address field. This should be 1 or 3 in most cases.
    /// As an optimisation, it MAY be 0 if the TLV is sent to a unicast
    /// address, if the association is over a point-to-point link, or when
    /// bidirectional reachability is ascertained by means outside of the Babel
    /// protocol.
    address_encoding: AddressEncoding,
    /// The rxcost according to the sending node of the interface whose address
    /// is specified in the Address field. The value FFFF hexadecimal (infinity)
    /// indicates that this interface is unreachable.
    rx_cost: u16,
    /// An upper bound, expressed in centiseconds, on the time after which the
    /// sending node will send a new IHU; this MUST NOT be 0. The receiving node
    /// will use this value in order to compute a hold time for this symmetric
    /// association.
    interval: u16,
    /// The address of the destination node, in the format specified by the AE
    /// field. Address compression is not allowed.
    address: IpAddr,
}

impl Ihu {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 5;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}
