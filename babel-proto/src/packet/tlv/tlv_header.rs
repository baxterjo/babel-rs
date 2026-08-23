/// The Babel TVL header as defined in section
/// [4.3](https://datatracker.ietf.org/doc/html/rfc8966#name-tlv-format)
pub struct TlvHeader {
    /// The type of the TLV.
    pub r#type: u8,
    /// The length of the body in octets, exclusive of the Type and Length fields.
    pub length: u8,
}

impl TlvHeader {
    /// Length of the serialized TLV header in bytes
    pub const LEN: usize = 2;
}
