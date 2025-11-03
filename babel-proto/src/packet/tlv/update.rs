use crate::packet::address_encoding::AddressEncoding;

/// An Update TLV advertises or retracts a route. As an optimisation, it can
/// optionally have the side effect of establishing a new implied router-id and
/// a new default prefix, as described in
/// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#parser-state).
pub struct Update {
    /// The encoding of the Prefix field.
    address_encoding: AddressEncoding,
    /// The individual bits of this field specify special handling of this TLV
    /// (see [`UpdateFlags`]).
    flags: UpdateFlags,
    /// The length in bits of the advertised prefix. If AE is 3 (link-local
    /// IPv6), the Omitted field MUST be 0.
    p_len: u8,
    /// The number of octets that have been omitted at the beginning of the
    /// advertised prefix and that should be taken from a preceding Update TLV
    /// in the same address family with the Prefix flag set.
    omitted: u8,
    /// An upper bound, expressed in centiseconds, on the time after which the
    /// sending node will send a new update for this prefix. This MUST NOT be 0.
    /// The receiving node will use this value to compute a hold time for the
    /// route table entry. The value FFFF hexadecimal (infinity) expresses that
    /// this announcement will not be repeated unless a request is received
    /// ([Section 3.8.2.3](https://datatracker.ietf.org/doc/html/rfc8966#request-expiring)).
    interval: u16,
    /// The originator's sequence number for this update.
    seq_no: u16,
    /// The sender's metric for this route. The value FFFF hexadecimal
    /// (infinity) means that this is a route retraction.
    metric: u16,
    /// The prefix being advertised. This field's size is (Plen/8 - Omitted) rounded upwards.
    // The math here comes out to u32 being the largest possible data type.
    prefix: u32,
}

impl Update {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 8;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}

pub struct UpdateFlags(u8);

impl UpdateFlags {
    /// If set, then this Update TLV establishes a new default prefix for
    /// subsequent Update TLVs with a matching address encoding within the same
    /// packet, even if this TLV is otherwise ignored due to an unknown mandatory sub-TLV;
    pub const PREFIX_FLAG: u8 = 0b1000_0000;
    /// if set, then this TLV establishes a new default router-id for this TLV
    /// and subsequent Update TLVs in the same packet, even if this TLV is
    /// otherwise ignored due to an unknown mandatory sub-TLV. This router-id is
    /// computed from the first address of the advertised prefix as follows:
    /// - If the length of the address is 8 octets or more, then the new
    /// router-id is taken from the 8 last octets of the address;
    /// - If the length of the address is smaller than 8 octets, then the new
    /// router-id consists of the required number of zero octets followed by the
    /// address, i.e., the address is stored on the right of the router-id. For
    /// example, for an IPv4 address, the router-id consists of 4 octets of
    /// zeroes followed by the IPv4 address.
    pub const ROUTER_ID: u8 = 0b0100_0000;
}
