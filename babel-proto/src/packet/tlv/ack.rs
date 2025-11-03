/// This TLV is sent by a node upon receiving an Acknowledgment Request TLV.
pub struct Ack {
    /// Set to the Opaque value of the Acknowledgment Request that prompted this Acknowledgment.
    opaque: u16,
}

impl Ack {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 3;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}
