use core::fmt::Debug;

use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;
use crate::packet::utils::slice_to_array;

/// Router ID TLV as defined in
/// [Section 4.6.7](https://datatracker.ietf.org/doc/html/rfc8966#name-router-id-2)
///
/// A Router-Id TLV establishes a router-id that is implied by subsequent Update TLVs, as described
/// in [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#parser-state).
/// This TLV sets the router-id even if it is otherwise ignored due to an unknown mandatory sub-TLV.
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 6   |    Length     |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                           Router-Id                           +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct RouterIdSlice<'a> {
    slice: &'a [u8],
}

impl Debug for RouterIdSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RouterIdSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("router_id", &self.router_id())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for RouterIdSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "RouterIdSlice{{ type: {}, length: {}, router_id: {}}}",
            TlvSlice::from_typed(self).r#type(),
            TlvSlice::from_typed(self).length(),
            self.router_id()
        )
    }
}

impl<'a> TypedTlv<'a> for RouterIdSlice<'a> {
    const TYPE_ID: u8 = 6;
    const MIN_LEN: usize = 10;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> RouterIdSlice<'a> {
    /// The router-id for routes advertised in subsequent Update TLVs. This MUST NOT consist of all
    /// zeroes or all ones.
    ///
    /// This accessor method does not check for correct router ID bounds.
    pub(crate) fn router_id(&self) -> &'a [u8; 8] {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10), so the 8 byte range following the Reserved
        // field is always in bounds.
        unsafe {
            slice_to_array::<8>(
                self.slice
                    .get_unchecked(TlvHeader::LEN + 2..TlvHeader::LEN + Self::MIN_LEN),
            )
        }
    }

    /// This TLV is self-terminating and allows sub-TLVs.
    pub(crate) fn sub_tlvs(&self) -> &'a [u8] {
        // PANIC SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10). If they are the same length this will return an
        // empty slice.
        &self.slice[TlvHeader::LEN + Self::MIN_LEN..]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    #[test]
    fn normal_slice() {
        // With sub_tlvs
        let packet: &[u8] = &[
            6,  // Router-Id Type ID
            19, // Length
            0, 0, // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 6, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 19, "Incorrect length");
        let router_id = RouterIdSlice::from_untyped(tlv_slice).expect("Router-Id should parse.");

        assert_eq!(
            router_id.router_id(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            "Incorrect router id"
        );
        assert_eq!(
            router_id.sub_tlvs(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );

        // Without sub_tlvs
        let packet: &[u8] = &[
            6,  // Router-Id Type ID
            10, // Length
            0, 0, // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let router_id = RouterIdSlice::from_untyped(tlv_slice).expect("Router-Id should parse.");

        assert_eq!(
            router_id.router_id(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            "Incorrect router id"
        );
        assert_eq!(router_id.sub_tlvs(), &[], "Should have no sub tlvs");
    }

    #[test]
    fn tlv_with_bad_length() {
        // Declared length runs past the end of the buffer.
        let packet: &[u8] = &[
            6,   // Router-Id Type ID
            120, // Length
            0, 0, // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        // Declared length is less than Self::MIN_LEN, so the Router-Id is truncated.
        let packet: &[u8] = &[
            6, // Router-Id Type ID
            9, // Length
            0, 0, // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        RouterIdSlice::from_untyped(untyped).expect_err("Router-Id should not parse");
    }

    #[test]
    fn tlv_with_wrong_type() {
        let packet: &[u8] = &[
            5,  // IHU Type ID
            10, // Length
            0, 0, // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        RouterIdSlice::from_untyped(untyped).expect_err("Router-Id should not parse");
    }
}
