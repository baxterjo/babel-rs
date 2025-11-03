/// This TLV requests that the receiver send an Acknowledgment TLV within the number of centiseconds specified by the Interval field.
pub struct AckRequest {
    /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
    opaque: u16,
    /// A time interval in centiseconds after which the sender will assume that this packet has been lost. This MUST NOT be 0. The receiver MUST send an Acknowledgment TLV before this time has elapsed (with a margin allowing for propagation time).
    interval: u16,
    // TODO: Sub TLVs
}

impl AckRequest {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 2;
    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}
