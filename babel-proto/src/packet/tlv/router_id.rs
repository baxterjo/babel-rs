use crate::router_id::RouterId;

/// A Router-Id TLV establishes a router-id that is implied by subsequent Update
/// TLVs, as described in [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#parser-state).
/// This TLV sets the router-id even if it is otherwise ignored due to an
/// unknown mandatory sub-TLV.
pub struct RouterIdTlv {
    /// The router-id for routes advertised in subsequent Update TLVs. This
    /// **MUST NOT** consist of all zeroes or all ones.
    router_id: RouterId,
}

impl RouterIdTlv {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 6;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}
