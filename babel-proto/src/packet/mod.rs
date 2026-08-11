//! Packet format as described in section [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
pub mod tlv;

use crate::data_types::address::{AddressCodec, AddressExtension};

/// Magic number identifying Babel packets as defined in section
/// [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
pub const BABEL_PACKET_HEADER_DEFAULT_MAGIC_NUMBER: u8 = 42;

/// Babel protocol version number as defined in section
/// [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
pub const BABEL_PACKET_HEADER_DEFAULT_VERSION_NUMBER: u8 = 2;

pub struct BabelPacketParser<A: AddressExtension> {
    address_codec: AddressCodec<A>,
}

//impl BabelPacketParser<A:AddressExtension>{
//    pub fn parse_packet(&[u8])->Iterator{
//
//    }
//}
