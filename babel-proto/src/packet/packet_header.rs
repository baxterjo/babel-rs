/// Babel packet header as defined in section
/// [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
pub struct PacketHeader {
    /// The arbitrary but carefully chosen value 42 (decimal); packets with a first octet different
    /// from 42 **MUST** be silently ignored.
    pub magic: u8,
    /// This document specifies version 2 of the Babel protocol. Packets with a second octet
    /// different from 2 **MUST** be silently ignored.
    pub version: u8,
    /// The length in octets of the body following the packet header (excluding the Magic, Version,
    /// and Body length fields, and excluding the packet trailer).
    pub body_length: u16,
}

impl PacketHeader {
    /// Length of the serialized Babel packet header in bytes.
    pub const LEN: usize = 4;

    /// Magic number identifying Babel packets as defined in section
    /// [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
    pub const MAGIC_NUMBER: u8 = 42;

    /// Babel protocol version number as defined in section
    /// [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
    pub const VERSION_NUMBER: u8 = 2;
}
