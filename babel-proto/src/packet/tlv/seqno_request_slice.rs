use core::fmt::Debug;

use crate::data_types::seqno::SeqNo;
use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;
use crate::packet::tlv::{TypedTlv, prefix_field_len};
use crate::packet::utils::{get_unchecked_be_u16, slice_to_array};

/// The seqno request slice as defined in
/// [Section 4.6.11](https://datatracker.ietf.org/doc/html/rfc8966#name-seqno-request)
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 10  |    Length     |      AE       |    Plen       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Seqno             |  Hop Count    |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                          Router-Id                            +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Prefix...
/// +-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// A Seqno Request TLV prompts the receiver to send an Update for a given prefix with a given
/// sequence number, or to forward the request further if it cannot be satisfied locally. Address
/// compression is not allowed.
///
/// A Seqno Request TLV prompts the receiving node to send a finite-metric Update for the prefix
/// specified by the AE, Plen, and Prefix fields, with either a router-id different from what is
/// specified by the Router-Id field, or a Seqno no less (modulo 2^16) than what is specified by the
/// Seqno field. If this request cannot be satisfied locally, then it is forwarded according to the
/// rules set out in
/// [Section 3.8.1.2](https://datatracker.ietf.org/doc/html/rfc8966#handling-seqno-requests).
///
/// While a Seqno Request MAY be sent to a multicast address, it **MUST NOT** be forwarded to a
/// multicast address and **MUST NOT** be forwarded to more than one neighbour. A request **MUST
/// NOT** be forwarded if its Hop Count field is 1.
pub struct SeqnoRequestSlice<'a> {
    slice: &'a [u8],
}

impl Debug for SeqnoRequestSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeqnoRequestSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("ae", &self.ae())
            .field("plen", &self.plen())
            .field("seqno", &self.seqno())
            .field("hop_count", &self.hop_count())
            .field("router_id", &self.router_id())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for SeqnoRequestSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "SeqnoRequestSlice{{ type: {}, length: {}, ae: {}, plen: {}, seqno: {}, hop_count: {}, router_id: {}}}",
            TlvSlice::from_typed(self).r#type(),
            TlvSlice::from_typed(self).length(),
            self.ae(),
            self.plen(),
            self.seqno(),
            self.hop_count(),
            self.router_id()
        )
    }
}

impl<'a> TypedTlv<'a> for SeqnoRequestSlice<'a> {
    const TYPE_ID: u8 = 10;
    const MIN_LEN: usize = 14;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> SeqnoRequestSlice<'a> {
    /// The encoding of the Prefix field. This **MUST NOT** be 0.
    pub fn ae(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (14).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN) }
    }

    /// The length in bits of the requested prefix.
    pub fn plen(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (14).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN + 1) }
    }

    /// The sequence number that is being requested.
    pub fn seqno(&self) -> SeqNo {
        unsafe {
            // SAFETY:
            // Safe as the constructor has checked to ensure the length of the slice is at minimum
            // TlvHeader::LEN (2) + Self::MIN_LEN (14).
            SeqNo(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN + 2),
            ))
        }
    }

    /// The maximum number of times that this TLV may be forwarded, plus 1. This **MUST NOT** be 0.
    pub fn hop_count(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (14).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN + 4) }
    }

    /// The Router-Id that is being requested. This **MUST NOT** consist of all zeroes or all ones.
    ///
    /// This accessor method does not check for correct router ID bounds.
    pub fn router_id(&self) -> &'a [u8; 8] {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (14), so the 8 byte range following the Reserved
        // field is always in bounds.
        unsafe {
            slice_to_array::<8>(
                self.slice
                    .get_unchecked(TlvHeader::LEN + 6..TlvHeader::LEN + Self::MIN_LEN),
            )
        }
    }

    /// The prefix being requested. This field's size is Plen/8 rounded upwards.
    pub fn prefix(&self, implied_octets: usize) -> Result<&'a [u8], TlvError> {
        let idx_end =
            TlvHeader::LEN + Self::MIN_LEN + prefix_field_len(self.plen(), 0, implied_octets)?;
        // This **MUST** be checked as the source of idx_end is supplied through the tlv. So a
        // malicious packet could cause UB.
        Ok(self
            .slice
            .get(TlvHeader::LEN + Self::MIN_LEN..idx_end)
            .ok_or(LenError {
                required_len: idx_end,
                len: self.slice.len(),
                len_source: LenSource::AddressEncoding,
                layer: Layer::BabelTlvBody,
                layer_start_offset: 0,
            })?)
    }

    /// This TLV is self-terminating and allows sub-TLVs.
    ///
    /// The sub-TLVs start where the Prefix field ends, so this needs the same `implied_octets` as
    /// [`Self::prefix`].
    pub fn sub_tlvs(&self, implied_octets: usize) -> Result<&'a [u8], TlvError> {
        let idx_start =
            TlvHeader::LEN + Self::MIN_LEN + prefix_field_len(self.plen(), 0, implied_octets)?;
        // This **MUST** be checked as the source of idx_start is supplied through the tlv. So a
        // malicious packet could cause UB.
        Ok(self.slice.get(idx_start..).ok_or(LenError {
            // The sub-TLV region starts after the prefix, so the TLV has to be at least that long.
            required_len: idx_start,
            len: self.slice.len(),
            len_source: LenSource::AddressEncoding,
            layer: Layer::BabelTlvBody,
            layer_start_offset: 0,
        })?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::data_types::address_encoding::AddressEncoding;
    use crate::extension::NoExtension;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    #[test]
    fn normal_slice() {
        // With sub_tlvs
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            26, // Length
            1,  // AE
            24, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            192, 168, 0, // Prefix
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 10, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 26, "Incorrect length");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(seqno_request.ae(), 1, "Incorrect AE");
        assert_eq!(seqno_request.plen(), 24, "Incorrect plen");
        assert_eq!(seqno_request.seqno(), SeqNo(42), "Incorrect seqno");
        assert_eq!(seqno_request.hop_count(), 16, "Incorrect hop count");
        assert_eq!(
            seqno_request.router_id(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            "Incorrect router id"
        );

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should have sub tlvs"),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );

        // Without sub_tlvs
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            17, // Length
            1,  // AE
            24, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            192, 168, 0, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(
            seqno_request.router_id(),
            &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
            "Incorrect router id"
        );
        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");
        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // A prefix of zero length yields an empty slice.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            14, // Length
            1,  // AE
            0,  // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");
        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn ae_3_prefix_drops_the_implied_octets() {
        // A request for fe80::102:304:506:708/128. AE 3 fixes the first 8 octets, so Plen counts
        // all 128 bits of the prefix but only the 8 octet suffix is carried on the wire.
        let packet: &[u8] = &[
            10,  // Seqno Request Type ID
            22,  // Length
            3,   // AE
            128, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");
        assert_eq!(ae.implied_prefix_octets(), 8, "AE 3 should imply 8 octets");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "Incorrect prefix"
        );

        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // Without the implied octets coming off the length the field reads as the full 16 octets,
        // which runs past the end of the TLV.
        seqno_request
            .prefix(0)
            .expect_err("Prefix should run past the end of the TLV.");
        seqno_request
            .sub_tlvs(0)
            .expect_err("Sub tlvs should start past the end of the TLV.");

        // The same request with sub-TLVs after it. Both accessors have to put the end of the
        // Prefix field in the same place or the sub-TLV region is read from the wrong offset.
        let packet: &[u8] = &[
            10,  // Seqno Request Type ID
            25,  // Length
            3,   // AE
            128, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Prefix
            1, 2, 3, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "Incorrect prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should have sub tlvs"),
            &[1, 2, 3],
            "Incorrect sub tlvs"
        );
    }

    #[test]
    fn ae_3_plen_at_the_implied_floor_has_an_empty_prefix() {
        // fe80::/64 is described entirely by the encoding, so there is nothing left to put in the
        // Prefix field.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            14, // Length
            3,  // AE
            64, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // A prefix that is not a whole number of octets past the floor is rounded upwards, so one
        // bit over the /64 puts a single octet on the wire.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            15, // Length
            3,  // AE
            65, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            0x80, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x80],
            "Incorrect prefix"
        );
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn plen_below_the_implied_prefix_is_rejected() {
        // Plen 8 names bits underneath the /64 that AE 3 fixes, so there is no prefix it could be
        // describing.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            15, // Length
            3,  // AE
            8,  // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            0x01, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect_err("Plen is below the implied prefix"),
            TlvError::PlenBelowImpliedPrefix {
                plen: 8,
                implied_octets: 8
            },
            "Incorrect error"
        );

        // The sub-TLV region is measured from the same Plen, so it is rejected for the same reason
        // rather than reading the remainder from a bogus offset.
        assert_eq!(
            seqno_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect_err("Plen is below the implied prefix"),
            TlvError::PlenBelowImpliedPrefix {
                plen: 8,
                implied_octets: 8
            },
            "Incorrect error"
        );

        // One bit under the floor is still under it, even though it rounds up to the same 8 octets.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            14, // Length
            3,  // AE
            63, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect_err("Plen is below the implied prefix"),
            TlvError::PlenBelowImpliedPrefix {
                plen: 63,
                implied_octets: 8
            },
            "Incorrect error"
        );

        // A Seqno Request never carries AE 0, so a Plen of 0 under AE 3 is a request below the
        // floor rather than a wildcard.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            14, // Length
            3,  // AE
            0,  // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect_err("Plen is below the implied prefix"),
            TlvError::PlenBelowImpliedPrefix {
                plen: 0,
                implied_octets: 8
            },
            "Incorrect error"
        );
    }

    #[test]
    fn encodings_with_no_implied_octets_are_unaffected() {
        // AE 1 and 2 carry their whole address, so the Prefix field is Plen/8 rounded up with
        // nothing taken off and no Plen is too short for the encoding.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            14, // Length
            2,  // AE
            0,  // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let seqno_request =
            SeqnoRequestSlice::from_untyped(tlv_slice).expect("Seqno Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");
        assert_eq!(ae.implied_prefix_octets(), 0, "AE 2 should imply no octets");

        assert_eq!(
            seqno_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[],
            "::/0 should have an empty prefix"
        );
    }

    #[test]
    fn tlv_with_bad_length() {
        // Declared length runs past the end of the buffer.
        let packet: &[u8] = &[
            10,  // Seqno Request Type ID
            120, // Length
            1,   // AE
            24,  // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            192, 168, 0, // Prefix
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        // Declared length is less than Self::MIN_LEN, so the Router-Id is truncated.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            13, // Length
            1,  // AE
            24, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        SeqnoRequestSlice::from_untyped(untyped).expect_err("Seqno Request should not parse");

        // Declared length is at least Self::MIN_LEN but the prefix is too short for the declared
        // plen.
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            15, // Length
            1,  // AE
            24, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        let seqno_request =
            SeqnoRequestSlice::from_untyped(untyped).expect("Seqno Request should parse");
        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(seqno_request.ae()).expect("Bad address encoding");

        seqno_request
            .prefix(ae.implied_prefix_octets())
            .expect_err("Prefix should be too short.");
        seqno_request
            .sub_tlvs(ae.implied_prefix_octets())
            .expect_err("Sub tlvs should start past the end of the TLV.");
    }

    #[test]
    fn tlv_with_wrong_type() {
        let packet: &[u8] = &[
            9,  // Route Request Type ID
            14, // Length
            1,  // AE
            24, // Plen
            0, 42, // Seqno
            16, // Hop Count
            0,  // Reserved
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // Router-Id
        ];

        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        SeqnoRequestSlice::from_untyped(untyped).expect_err("Seqno Request should not parse");
    }
}
