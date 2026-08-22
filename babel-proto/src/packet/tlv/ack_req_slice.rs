use thiserror::Error;

use crate::{
    data_types::Interval,
    packet::{
        tlv::{tlv_header::TlvHeader, TypedTlv},
        utils::get_unchecked_be_u16,
    },
    utils::Duration,
};

/// Acknowledgment request TLV as defined in section
/// [4.6.3](https://datatracker.ietf.org/doc/html/rfc8966#name-acknowledgment-request)
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 2   |    Length     |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Opaque            |          Interval             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This TLV requests that the receiver send an Acknowledgment TLV within the number of centiseconds specified by the Interval field.
///
/// NOTE: `Type`, `Length`, and `Reserved` fields are not represented here as they have no value
/// beyond parsing and encoding.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AckReqSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TypedTlv<'a> for AckReqSlice<'a> {
    const TYPE_ID: u8 = 2;
    const MIN_LEN: usize = 6;
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
}

impl<'a> AckReqSlice<'a> {
    /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
    pub fn opaque(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(TlvHeader::LEN + 2)) }
    }
    /// A time interval in centiseconds after which the sender will assume that this
    /// packet has been lost. This **MUST NOT** be 0. The receiver **MUST** send an Acknowledgment
    /// TLV before this time has elapsed (with a margin allowing for propagation time).
    pub fn interval(&self) -> Interval {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        let centis = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(TlvHeader::LEN + 4)) };
        Duration::from_centis(centis.into()).into()
    }
    /// This TLV is self-terminating and allows sub-TLVs.
    pub fn sub_tlvs(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6). If the lengths are the same this will return an
        // empty slice.
        unsafe {
            self.slice
                .get_unchecked(TlvHeader::LEN + Self::MIN_LEN..self.slice.len())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::packet::tlv::tlv_slice::TlvSlice;

    use super::*;
    #[test]
    fn normal_slice() {
        // With sub_tlvs
        let packet: &[u8] = &[
            2,  // Ack req Type ID
            15, // Length
            0, 0, // Reserved
            0x80, 0x80, // Opaque
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");

        let ack_req = AckReqSlice::from_untyped(tlv_slice).expect("Ack req should parse.");

        assert_eq!(ack_req.opaque(), 0x8080);
        assert_eq!(ack_req.interval(), Duration::from_centis(200).into());
        assert_eq!(ack_req.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        // Without sub_tlvs
        let packet: &[u8] = &[
            2, // Ack req Type ID
            6, // Length
            0, 0, // Reserved
            0x80, 0x80, // Opaque
            0, 200, // Interval
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let ack_req = AckReqSlice::from_untyped(tlv_slice).expect("Ack req should parse.");

        assert_eq!(ack_req.opaque(), 0x8080);
        assert_eq!(ack_req.interval(), Duration::from_centis(200).into());
        assert_eq!(ack_req.sub_tlvs(), &[]);
    }
}
