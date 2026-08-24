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

/// An expanded view of a [`PacketSlice`], returned by [`PacketSlice::debug_tlvs`].
///
/// Formatting this parses the packet's body and trailer and prints each TLV, where the
/// [`PacketSlice`] impls only report their lengths. Nothing is parsed until the value is actually
/// formatted, so building one costs nothing.
pub struct PacketSliceTlvDebug<'a> {
    packet: PacketSlice<'a>,
}

impl Debug for PacketSliceTlvDebug<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketSlice")
            .field("magic", &self.packet.magic())
            .field("version", &self.packet.version())
            .field("body_length", &self.packet.body_length())
            .field("body", &TlvListDebug(self.packet.body()))
            .field("trailer", &TlvListDebug(self.packet.trailer()))
            .field("total_len", &self.packet.slice.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for PacketSliceTlvDebug<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "PacketSlice{{ magic: {}, version: {}, body_length: {}, body: {}, trailer: {}, total_len: {}}}",
            self.packet.magic(),
            self.packet.version(),
            self.packet.body_length(),
            TlvListDebug(self.packet.body()),
            TlvListDebug(self.packet.trailer()),
            self.packet.slice.len()
        )
    }
}

/// The TLVs in one region of a packet, formatted as a list.
struct TlvListDebug<'a>(&'a [u8]);

impl TlvListDebug<'_> {
    /// Bytes the reader gave up on, given an exhausted `reader` over this region.
    ///
    /// [`TlvReader`] stops at the first TLV whose framing it cannot follow, so a short list would
    /// otherwise be indistinguishable from a packet that really did end there. That difference is
    /// the whole point of a debugging aid, so it gets reported rather than swallowed.
    ///
    /// This comes from how far the reader got rather than from the lengths of the TLVs it yielded,
    /// because it consumes malformed and unrecognized TLVs without yielding them. Summing the
    /// yielded lengths would report a region that parsed end to end as having unparsed bytes.
    fn unparsed(&self, reader: &TlvReader<'_>) -> usize {
        self.0.len() - reader.consumed()
    }
}

impl Debug for TlvListDebug<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut list = f.debug_list();
        let mut reader = TlvReader::new(self.0);
        // `by_ref` rather than passing the reader directly: it is `Copy`, so handing it over by
        // value would advance a copy and leave `reader` sitting at zero.
        list.entries(reader.by_ref());

        let unparsed = self.unparsed(&reader);
        if unparsed > 0 {
            list.entry(&format_args!("<{unparsed} unparsed bytes>"));
        }

        list.finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TlvListDebug<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "[");
        let mut reader = TlvReader::new(self.0);
        for (idx, tlv) in reader.by_ref().enumerate() {
            if idx > 0 {
                defmt::write!(f, ", ");
            }
            defmt::write!(f, "{}", tlv);
        }

        let unparsed = self.unparsed(&reader);
        if unparsed > 0 {
            defmt::write!(f, ", <{} unparsed bytes>", unparsed);
        }

        defmt::write!(f, "]")
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
                // The slice has to hold the header as well as the declared body.
                required_len: min_len + BabelPacketHeader::LEN,
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

    /// A view of this packet that expands its TLVs when formatted.
    ///
    /// The [`Debug`] and [`defmt::Format`] impls on [`PacketSlice`] itself only report the body and
    /// trailer lengths, since parsing every TLV is far too expensive to do on every log line. Call
    /// this when the TLVs are what you actually want to see:
    ///
    /// ```
    /// # use babel_proto::packet::packet_slice::PacketSlice;
    /// # let bytes: &[u8] = &[42, 2, 0, 8, 4, 6, 0x80, 0, 0, 15, 0, 200];
    /// let packet = PacketSlice::from_slice(bytes).expect("packet should parse");
    /// # #[cfg(feature = "std")]
    /// println!("{:?}", packet.debug_tlvs());
    /// ```
    ///
    /// Parsing happens during formatting, so an unused value costs nothing.
    pub fn debug_tlvs(&self) -> PacketSliceTlvDebug<'a> {
        PacketSliceTlvDebug {
            packet: PacketSlice { slice: self.slice },
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

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn debug_tlvs_expands_the_body_where_debug_reports_lengths() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 10, // Body Length
            // Hello
            4,  // Hello Type ID
            6,  // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            0, // Pad1
            0, // Pad1
        ];

        let packet_slice = PacketSlice::from_slice(packet).expect("Packet should parse");

        let plain = alloc::format!("{:?}", packet_slice);
        assert!(
            !plain.contains("HelloSlice"),
            "the default Debug impl should not parse TLVs, got: {plain}"
        );

        let expanded = alloc::format!("{:?}", packet_slice.debug_tlvs());
        assert!(
            expanded.contains("HelloSlice"),
            "debug_tlvs should expand the hello, got: {expanded}"
        );
        assert!(
            expanded.contains("seqno: SeqNo(15)"),
            "debug_tlvs should reach the hello's fields, got: {expanded}"
        );
        assert!(
            expanded.contains("Pad1"),
            "debug_tlvs should list padding, got: {expanded}"
        );
        assert!(
            !expanded.contains("unparsed"),
            "a well formed body has no unparsed bytes, got: {expanded}"
        );
    }

    /// The reader stops at the first malformed TLV, so the bytes it gave up on are reported rather
    /// than leaving a short list that looks like a complete one.
    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn debug_tlvs_reports_bytes_the_reader_could_not_parse() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 12, // Body Length
            // Hello
            4,  // Hello Type ID
            6,  // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            // IHU claiming 15 bytes of body that are not here
            5, 15, 1, 0,
        ];

        let packet_slice = PacketSlice::from_slice(packet).expect("Packet should parse");

        let expanded = alloc::format!("{:?}", packet_slice.debug_tlvs());
        assert!(
            expanded.contains("HelloSlice"),
            "the valid hello should still be listed, got: {expanded}"
        );
        assert!(
            expanded.contains("<4 unparsed bytes>"),
            "the truncated ihu should be reported, got: {expanded}"
        );
    }

    /// TLVs the reader skips are still parsed, so they must not be counted as unparsed. Their bytes
    /// are also in the middle of the region rather than trailing it, which is not something the
    /// count can describe.
    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn debug_tlvs_does_not_report_skipped_tlvs_as_unparsed() {
        let packet: &[u8] = &[
            42, // Magic
            2,  // Version
            0, 27, // Body Length
            // Hello
            4,  // Hello Type ID
            6,  // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            // Unrecognized type, framed correctly
            200, // Unassigned Type ID
            4,   // Length
            1, 2, 3, 4, // Body
            // Hello with a Length below its MIN_LEN, also framed correctly
            4, // Hello Type ID
            3, // Length
            0x80, 0x00, // Flags
            0,    // Truncated Seqno
            // IHU
            5,  // IHU Type ID
            6,  // Length
            1,  // AE
            0,  // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
        ];

        let packet_slice = PacketSlice::from_slice(packet).expect("Packet should parse");

        let expanded = alloc::format!("{:?}", packet_slice.debug_tlvs());
        assert!(
            expanded.contains("HelloSlice") && expanded.contains("IhuSlice"),
            "the recognized tlvs should be listed, got: {expanded}"
        );
        assert!(
            !expanded.contains("unparsed"),
            "a body the reader read end to end has no unparsed bytes, got: {expanded}"
        );
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
