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
}

impl<'a> Iterator for TlvReader<'a> {
    type Item = Tlv<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        // Normal exit when entire packet has been read.
        if self.pos == self.slice.len() {
            return None;
        }

        // Get next slice.
        loop {
            match TlvSlice::from_slice(&self.slice[self.pos..self.slice.len()]) {
                Ok(tlv) => {
                    // When the slice parses as expected, position is advanced by the length of the
                    // slice.
                    self.pos += tlv.slice().len();
                    match Tlv::try_from(tlv) {
                        Ok(t) => {
                            // Happy path
                            return Some(t);
                        }
                        Err(TlvError::UnrecognizedTlvType(t)) => {
                            // Unrecognized TLVs are ignored
                            b_debug!("Tlv Iter Err: {}", TlvError::UnrecognizedTlvType(t));
                            continue;
                        }
                        Err(other) => {
                            // Some other error occurred
                            b_debug!("Tlv Iter Err: {}", other);
                            return None;
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
                    // Some other error occurred
                    b_debug!("Tlv Iter Err: {}", other);
                    return None;
                }
            };
        }
    }
}

#[cfg(test)]
mod test {
    use crate::packet::tlv::reader::TlvReader;
    use crate::packet::tlv::Tlv;

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
}
