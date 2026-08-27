use core::iter::Iterator;

use crate::packet::error::tlv_err::TlvError;
use crate::packet::tlv::Tlv;
use crate::packet::tlv::tlv_slice::TlvSlice;
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlvReader<'a> {
    slice: &'a [u8],
    pos: usize,
}

/// A reader that reads TLV's from a buffer.
///
/// Anytime an Err is yeilded when traversing this iterator, it can be safely ignored and the
/// packet can continue being parsed.
impl<'a> TlvReader<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        Self { slice, pos: 0 }
    }

    /// How far into the slice the reader has read, in octets.
    ///
    /// Once the iterator is exhausted this is the number of octets it was able to make sense of,
    /// which is not the same as the number it yielded: malformed and unrecognized TLVs are
    /// consumed and skipped, so they count here but never appear as items.
    pub fn consumed(&self) -> usize {
        self.pos
    }
}

impl<'a> Iterator for TlvReader<'a> {
    type Item = Tlv<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        // Get next slice.
        //
        // Any error that occurs during parsing
        loop {
            // Normal exit when entire packet has been read.
            if self.pos == self.slice.len() {
                return None;
            }

            match TlvSlice::from_slice(&self.slice[self.pos..self.slice.len()]) {
                Ok(tlv) => {
                    // When the slice parses as expected, position is advanced by the length of the
                    // slice. Any error after this point can be skipped.
                    self.pos += tlv.slice().len();
                    match Tlv::try_from(tlv) {
                        Ok(t) => {
                            // Happy path
                            return Some(t);
                        }
                        Err(other) => {
                            // Some other error occurred
                            b_debug!("Tlv Iter Err: {}", other);
                            continue;
                        }
                    }
                }
                Err(TlvError::Pad1) => {
                    // When the slice is Pad1, the TLV header cannot fully parse, so an error is
                    // returned but this is a normal condition. Advance the position by 1.
                    self.pos += 1;
                    return Some(Tlv::Pad1);
                }
                Err(other) => {
                    // Some other error occurred while parsing the header of the TLV slice. This
                    // cannot be recovered from.
                    b_debug!("Tlv Iter Err: {}", other);
                    return None;
                }
            };
        }
    }
}

#[cfg(test)]
mod test {
    use crate::packet::tlv::Tlv;
    use crate::packet::tlv::reader::TlvReader;

    #[test]
    fn test_normal_packet_body() {
        let body: &[u8] = &[
            // ACK Req
            2,  // Ack req Type ID
            14, // Length
            0, 0, // Reserved
            0x80, 0x80, // Opaque
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, 7, 8, // Sub TLVS
            // ACK
            3, // Ack Type ID
            9, // Length
            0x80, 0x80, // Opaque
            1, 2, 3, 4, 5, 6, 7, // Sub TLVS
            // Hello
            4,  // Hello Type ID
            12, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, // Sub TLVS
            0, // Pad1
            0, // Pad1
            // IHU
            5,  // IHU Type ID
            15, // Length
            1,  // AE
            0,  // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
            192, 168, 0, 5, //
            1, 2, 3, 4, 5, // Sub TLVS
        ];

        let reader = TlvReader::new(body);
        for tlv in reader {
            // Match and check the sub_tlvs. These are the only things that need to be checked here
            // as they are the bounds of the TLV.
            match tlv {
                Tlv::AckReq(slice) => {
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7, 8]);
                }
                Tlv::Ack(slice) => {
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7]);
                }
                Tlv::Hello(slice) => {
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6]);
                }
                Tlv::Ihu(slice) => {
                    assert_eq!(
                        slice.sub_tlvs(4).expect("IHU sub TLVs should parse"),
                        &[1, 2, 3, 4, 5]
                    )
                }
                // Padding between TLVs is a normal part of a packet body and carries nothing to
                // check.
                Tlv::Pad1 => {}
                other => {
                    panic!("Unexpected TLV type ID parsed: {:?}, {:?}", other, reader);
                }
            }
        }
    }

    #[test]
    fn malformed_tlv_does_not_suppress_the_ones_behind_it() {
        // The first Hello is framed correctly but declares a Length (3) below HelloSlice::MIN_LEN
        // (6), so only the typed parse fails. The reader has not lost its place, so the valid TLVs
        // behind it must still be yielded — otherwise any sender on the link could suppress them
        // with a single malformed TLV.
        let body: &[u8] = &[
            // Hello with a Length below its MIN_LEN
            4, // Hello Type ID
            3, // Length
            0x80, 0x00, // Flags
            0,    // Truncated Seqno
            // Hello
            4, // Hello Type ID
            6, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            // Unrecognized type, which is skipped the same way
            200, // Unassigned Type ID
            2,   // Length
            0, 0, // Body
            // IHU
            5,  // IHU Type ID
            10, // Length
            1,  // AE
            0,  // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
            192, 168, 0, 5, // Address
        ];

        let mut types = [0u8; 4];
        let mut count = 0;
        for tlv in TlvReader::new(body) {
            types[count] = tlv.r#type();
            count += 1;
        }

        assert_eq!(
            &types[..count],
            &[4, 5],
            "Malformed and unrecognized TLVs should be skipped, not end iteration"
        );
    }

    #[test]
    fn unparseable_header_ends_iteration() {
        // A declared Length that runs past the end of the body is a framing failure. The reader
        // cannot know where the next TLV starts, so iteration has to stop rather than guess.
        let body: &[u8] = &[
            // Hello
            4, // Hello Type ID
            6, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            // Hello claiming more bytes than remain
            4,   // Hello Type ID
            120, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
        ];

        let mut types = [0u8; 2];
        let mut count = 0;
        for tlv in TlvReader::new(body) {
            types[count] = tlv.r#type();
            count += 1;
        }

        assert_eq!(
            &types[..count],
            &[4],
            "Iteration should stop at the framing error"
        );
    }
}
