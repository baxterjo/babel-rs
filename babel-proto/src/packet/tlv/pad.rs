/// This TLV is silently ignored on reception. It is allowed in the packet trailer.
pub struct Pad1 {}

impl Pad1 {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 0;
}

/// This TLV is silently ignored on reception. It is allowed in the packet trailer.
pub struct PadN {}

impl PadN {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 1;
}
