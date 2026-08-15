use crate::packet::{
    error::{layer::Layer, len_error::LenError},
    len_source::LenSource,
    packet_header::BabelPacketHeader,
    packet_header_slice::BabelPacketHeaderSlice,
    utils::get_unchecked_be_u16,
};

/// A slice containing the header, body, and trailer of a Babel Packet
#[derive(Debug)]
pub struct BabelPacketSlice<'a> {
    slice: &'a [u8],
}

impl<'a> BabelPacketSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, LenError> {
        let header = BabelPacketHeaderSlice::from_slice(slice)?;

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

        let packet_slice = BabelPacketSlice::from_slice(packet).expect("Packet should parse");

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

        BabelPacketSlice::from_slice(packet).expect_err("Packet should not parse");
    }

    #[test]
    fn babel_packet_with_no_trailer() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 11, // Body Length
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Body
        ];

        let packet_slice = BabelPacketSlice::from_slice(packet).expect("Packet should parse");

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
