use crate::{
    packet::{
        tlv::{tlv_header::TlvHeader, TypedTlv},
        utils::get_unchecked_be_u16,
    },
    utils::cursor::ManagedSliceCursor,
};

/// Acknowledgement TLV as defined in section
/// [4.6.4](https://datatracker.ietf.org/doc/html/rfc8966#name-acknowledgment)
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 3   |    Length     |           Opaque              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This TLV is sent by a node upon receiving an Acknowledgment Request TLV.
///
/// Since Opaque values are not globally unique, this TLV **MUST** be sent to a unicast address.
#[derive(Debug)]
pub struct AckSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TypedTlv<'a> for AckSlice<'a> {
    const TYPE_ID: u8 = 3;
    const MIN_LEN: usize = 2;
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
}

impl<'a> AckSlice<'a> {
    /// Set to the Opaque value of the Acknowledgment Request that prompted this Acknowledgment.
    pub fn opaque(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (2).
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }

    /// This TLV is self-terminating and allows sub-TLVs.
    pub fn sub_tlvs(&self) -> &'a [u8] {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (2). If they are the same length this will return an
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
            3,  // Ack Type ID
            11, // Length
            0x80, 0x80, // Opaque
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 3, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 11, "Incorrect length");
        let ack = AckSlice::from_untyped(tlv_slice).expect("Ack should parse.");

        assert_eq!(ack.opaque(), 0x8080);
        assert_eq!(ack.sub_tlvs(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);

        // Without sub_tlvs
        let packet: &[u8] = &[
            3, // Ack Type ID
            2, // Length
            0x80, 0x80, // Opaque
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let ack = AckSlice::from_untyped(tlv_slice).expect("Ack should parse.");

        assert_eq!(ack.opaque(), 0x8080);
        assert_eq!(ack.sub_tlvs(), &[]);
    }

    #[test]
    fn tlv_with_bad_length() {
        // TLV where declared length is less than SELF::MIN_LEN
        let packet: &[u8] = &[
            3, // Ack Type ID
            1, // Length
            0x80, 0x80, // Opaque
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        AckSlice::from_untyped(tlv_slice).expect_err("Ack should not parse.");
    }
}
