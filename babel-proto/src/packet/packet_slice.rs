use core::fmt::Debug;

use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::len_source::LenSource;
use crate::packet::packet_header::BabelPacketHeader;
use crate::packet::packet_header_slice::PacketHeaderSlice;
use crate::packet::tlv::reader::TlvReader;
use crate::packet::utils::get_unchecked_be_u16;

/// A slice containing the header, body, and trailer of a Babel Packet
pub struct PacketSlice<'a> {
    slice: &'a [u8],
}

impl Debug for PacketSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketSlice")
            .field("magic", &self.magic())
            .field("version", &self.version())
            .field("body_length", &self.body_length())
            .field("trailer_len", &self.trailer().len())
            .field("total_len", &self.slice.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "PacketSlice{{ magic: {}, version: {}, body_length: {}, trailer_len: {}, total_len: {}}}",
            self.magic(),
            self.version(),
            self.body_length(),
            self.trailer().len(),
            self.slice.len()
        )
    }
}

impl<'a> PacketSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, LenError> {
        let header = PacketHeaderSlice::from_slice(slice)?;

        let min_len: usize = header.body_length().into();

        // The slice must, at minimum, be the declared body length plus header length.
        // It can also contain the packet trailer, so the entire slice is still put into the packet.
        if slice.len() < min_len + BabelPacketHeader::LEN {
            return Err(LenError {
                required_len: min_len,
                len: slice.len(),
                len_source: LenSource::Slice,
                layer: Layer::BabelPacketBody,
                layer_start_offset: 0,
            });
        }

        Ok(Self { slice })
    }

    /// Return the slice containing the Babel Packet header, body, and trailer.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reads the `Magic` field from the slice.
    #[inline]
    pub fn magic(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Reads the `Version` field from the slice.
    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Reads the `Body Length` field from the slice.
    #[inline]
    pub fn body_length(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// Returns the slice containing the Babel packet body.
    pub fn body(&self) -> &'a [u8] {
        let body_length: usize = self.body_length().into();

        unsafe {
            // SAFETY:
            // Safe as the constructor checks that the slice has at least the length of the
            // body_len + BabelPacketHeader::LEN
            self.slice
                .get_unchecked(BabelPacketHeader::LEN..body_length + BabelPacketHeader::LEN)
        }
    }

    /// Returns an iterator that iterates over the TLV's in the packet body.
    pub fn body_reader(&self) -> TlvReader<'a> {
        TlvReader::new(self.body())
    }

    /// Returns the slice containing the Babel packet trailer.
    pub fn trailer(&self) -> &'a [u8] {
        let body_length: usize = self.body_length().into();

        unsafe {
            // SAFETY:
            // Safe as the constructor checks that the slice has at least the length of the
            // body_len + BabelPacketHeader::LEN. And if they are equal, then this will be an empty
            // slice.
            self.slice
                .get_unchecked(body_length + BabelPacketHeader::LEN..self.slice.len())
        }
    }

    /// Returns an iterator that iterates over the packet trailer.
    pub fn trailer_reader(&self) -> TlvReader<'a> {
        TlvReader::new(self.trailer())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn normal_babel_packet() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 11, // Body Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Body
            11, 12, 13, // Trailer
        ];

        let packet_slice = PacketSlice::from_slice(packet).expect("Packet should parse");

        assert_eq!(packet_slice.magic(), 42, "Magic incorrect");
        assert_eq!(packet_slice.version(), 2, "Version incorrect");
        assert_eq!(packet_slice.body_length(), 11, "Body length incorrect");
        assert_eq!(
            packet_slice.body(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "Body incorrect"
        );
        assert_eq!(packet_slice.trailer(), &[11, 12, 13], "Trailer incorrect");
    }

    #[test]
    fn babel_packet_with_incorrect_length() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 55, // Body Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Body
            11, 12, 13, // Trailer
        ];

        PacketSlice::from_slice(packet).expect_err("Packet should not parse");
    }

    #[test]
    fn babel_packet_with_no_trailer() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 11, // Body Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Body
        ];

        let packet_slice = PacketSlice::from_slice(packet).expect("Packet should parse");

        assert_eq!(packet_slice.magic(), 42, "Magic incorrect");
        assert_eq!(packet_slice.version(), 2, "Version incorrect");
        assert_eq!(packet_slice.body_length(), 11, "Body length incorrect");
        assert_eq!(
            packet_slice.body(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "Body incorrect"
        );
        assert_eq!(packet_slice.trailer(), &[], "Trailer incorrect");
    }
}
