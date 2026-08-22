use core::iter::Iterator;

use crate::packet::{error::tlv_err::TlvError, tlv::tlv_slice::TlvSlice};
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
    type Item = Result<TlvSlice<'a>, TlvError>;
    fn next(&mut self) -> Option<Self::Item> {
        // Normal exit when entire packet has been read.
        if self.pos == self.slice.len() {
            return None;
        }

        // Get next slice.
        let tlv_result = match TlvSlice::from_slice(&self.slice[self.pos..self.slice.len()]) {
            Ok(tlv) => {
                // When the slice parses as expected, position is advanced by the length of the slice.
                self.pos += tlv.slice().len();
                Ok(tlv)
            }
            Err(TlvError::Pad1) => {
                // When the slice is Pad1, the TLV header cannot fully parse, so an error is
                // returned but this is a normal condition. Advance the position by 1.
                self.pos += 1;
                Err(TlvError::Pad1)
            }
            Err(TlvError::Len(len_error)) => {
                // When a length error occurs, we have lost our place in the packet and must
                // discard the whole thing.
                b_debug!(
                    "Length error when iterating through TLV, discarding packet - Err: {}",
                    len_error
                );
                return None;
            }
            Err(other) => Err(other),
        };

        Some(tlv_result)
    }
}

#[cfg(test)]
mod test {
    use crate::packet::tlv::{
        AckReqSlice, AckSlice, HelloSlice, IhuSlice, TypedTlv, reader::TlvReader,
    };

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
        for tlv_result in reader {
            let tlv = match tlv_result {
                Ok(tlv) => tlv,
                Err(err) => {
                    b_trace!("TLV reader yeilded error: {}", err);
                    continue;
                }
            };
            // Match and check the sub_tlvs. These are the only things that need to be checked here
            // as they are the bounds of the TLV.
            match tlv.r#type() {
                AckReqSlice::TYPE_ID => {
                    let slice = AckReqSlice::from_untyped(tlv).expect("Ack req should have parsed");
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7, 8]);
                }
                AckSlice::TYPE_ID => {
                    let slice = AckSlice::from_untyped(tlv).expect("Ack should have parsed.");
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7]);
                }
                HelloSlice::TYPE_ID => {
                    let slice = HelloSlice::from_untyped(tlv).expect("Hello should have parsed.");
                    assert_eq!(slice.sub_tlvs(), &[1, 2, 3, 4, 5, 6]);
                }
                IhuSlice::TYPE_ID => {
                    let slice = IhuSlice::from_untyped(tlv).expect("IHU slice should have parsed");
                    assert_eq!(
                        slice.sub_tlvs(4).expect("IHU sub TLVs should parse"),
                        &[1, 2, 3, 4, 5]
                    )
                }
                other => {
                    panic!("Unexpected TLV type ID parsed: {}, {:?}", other, reader);
                }
            }
        }
    }
}
