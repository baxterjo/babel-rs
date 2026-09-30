use core::fmt::Debug;

use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;
use crate::packet::tlv::{TypedTlv, prefix_field_len};

/// The route reuquest TLV as defined in
/// [Section 4.6.10](https://datatracker.ietf.org/doc/html/rfc8966#name-route-request)
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 9   |    Length     |      AE       |     Plen      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Prefix...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// A Route Request TLV prompts the receiver to send an update for a given prefix, or a full route
/// table dump. Address compression is not allowed.
///
/// A Request TLV prompts the receiver to send an update message (possibly a retraction) for the
/// prefix specified by the AE, Plen, and Prefix fields, or a full dump of its route table if AE is
/// 0 (in which case Plen must be 0 and Prefix is of length 0). A Request TLV with AE set to 0 and
/// Plen not set to 0 **MUST** be ignored.
pub struct RouteRequestSlice<'a> {
    slice: &'a [u8],
}

impl Debug for RouteRequestSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RouteRequestSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("ae", &self.ae())
            .field("plen", &self.plen())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for RouteRequestSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "RouteRequestSlice{{ type: {}, length: {}, ae: {}, plen: {}}}",
            TlvSlice::from_typed(self).r#type(),
            TlvSlice::from_typed(self).length(),
            self.ae(),
            self.plen()
        )
    }
}

impl<'a> TypedTlv<'a> for RouteRequestSlice<'a> {
    const TYPE_ID: u8 = 9;
    const MIN_LEN: usize = 2;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> RouteRequestSlice<'a> {
    /// The encoding of the Prefix field. The value 0 specifies that this is a request for a full
    /// route table dump (a wildcard request).
    pub fn ae(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (2).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN) }
    }

    /// The length in bits of the requested prefix. This MUST be 0 if AE is 0.
    pub fn plen(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (2).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN + 1) }
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
            9,  // Route Request Type ID
            14, // Length
            1,  // AE
            24, // Plen
            192, 168, 0, // Prefix
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 9, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 14, "Incorrect length");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        assert_eq!(route_request.ae(), 1, "Incorrect AE");
        assert_eq!(route_request.plen(), 24, "Incorrect plen");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should have sub tlvs"),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );

        // Without sub_tlvs
        let packet: &[u8] = &[
            9,  // Route Request Type ID
            5,  // Length
            1,  // AE
            24, // Plen
            192, 168, 0, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");
        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // A prefix that is not a whole number of octets is rounded upwards.
        let packet: &[u8] = &[
            9,  // Route Request Type ID
            5,  // Length
            1,  // AE
            17, // Plen
            192, 168, 128, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");
        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[192, 168, 128],
            "Incorrect prefix"
        );
    }

    #[test]
    fn wildcard_slice() {
        // A wildcard request has an AE of 0, so the Plen and Prefix fields are empty.
        let packet: &[u8] = &[
            9, // Route Request Type ID
            2, // Length
            0, // AE
            0, // Plen
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        assert_eq!(route_request.plen(), 0, "Incorrect plen");
        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            route_request
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
            9,   // Route Request Type ID
            10,  // Length
            3,   // AE
            128, // Plen
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");
        assert_eq!(ae.implied_prefix_octets(), 8, "AE 3 should imply 8 octets");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "Incorrect prefix"
        );

        assert_eq!(
            route_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // Without the implied octets coming off the length the field reads as the full 16 octets,
        // which runs past the end of the TLV. This is what used to drop every conformant AE 3
        // request.
        route_request
            .prefix(0)
            .expect_err("Prefix should run past the end of the TLV.");
        route_request
            .sub_tlvs(0)
            .expect_err("Sub tlvs should start past the end of the TLV.");

        // The same request with sub-TLVs after it. Both accessors have to put the end of the
        // Prefix field in the same place or the sub-TLV region is read from the wrong offset.
        let packet: &[u8] = &[
            9,   // Route Request Type ID
            13,  // Length
            3,   // AE
            128, // Plen
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Prefix
            1, 2, 3, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request
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
            9,  // Route Request Type ID
            2,  // Length
            3,  // AE
            64, // Plen
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // A prefix that is not a whole number of octets past the floor is rounded upwards, so one
        // bit over the /64 puts a single octet on the wire.
        let packet: &[u8] = &[
            9,    // Route Request Type ID
            3,    // Length
            3,    // AE
            65,   // Plen
            0x80, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect("Should be able to get prefix"),
            &[0x80],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs(ae.implied_prefix_octets())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn plen_below_the_implied_prefix_is_rejected() {
        // Plen 8 names bits underneath the /64 that AE 3 fixes, so there is no prefix it could be
        // describing. This used to read as a one octet field and zero-fill into the nonsense
        // destination fe80:0:0:0:0100::/8.
        let packet: &[u8] = &[
            9,    // Route Request Type ID
            3,    // Length
            3,    // AE
            8,    // Plen
            0x01, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        assert_eq!(
            route_request
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
            route_request
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
            9,  // Route Request Type ID
            2,  // Length
            3,  // AE
            63, // Plen
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        assert_eq!(
            route_request
                .prefix(ae.implied_prefix_octets())
                .expect_err("Plen is below the implied prefix"),
            TlvError::PlenBelowImpliedPrefix {
                plen: 63,
                implied_octets: 8
            },
            "Incorrect error"
        );

        // A Plen of 0 under AE 3 is not a wildcard request, it is a request below the floor.
        let packet: &[u8] = &[
            9, // Route Request Type ID
            2, // Length
            3, // AE
            0, // Plen
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        assert_eq!(
            route_request
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
            9, // Route Request Type ID
            2, // Length
            2, // AE
            0, // Plen
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let route_request =
            RouteRequestSlice::from_untyped(tlv_slice).expect("Route Request should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");
        assert_eq!(ae.implied_prefix_octets(), 0, "AE 2 should imply no octets");

        assert_eq!(
            route_request
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
            9,   // Route Request Type ID
            120, // Length
            1,   // AE
            24,  // Plen
            192, 168, 0, // Prefix
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        // Declared length is less than Self::MIN_LEN, so the Plen field is truncated.
        let packet: &[u8] = &[
            9,  // Route Request Type ID
            1,  // Length
            1,  // AE
            24, // Plen
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        RouteRequestSlice::from_untyped(untyped).expect_err("Route Request should not parse");

        // Declared length is at least Self::MIN_LEN but the prefix is too short for the declared
        // plen.
        let packet: &[u8] = &[
            9,  // Route Request Type ID
            3,  // Length
            1,  // AE
            24, // Plen
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        let route_request =
            RouteRequestSlice::from_untyped(untyped).expect("Route Request should parse");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(route_request.ae()).expect("Bad address encoding.");

        route_request
            .prefix(ae.implied_prefix_octets())
            .expect_err("Prefix should be too short.");
        route_request
            .sub_tlvs(ae.implied_prefix_octets())
            .expect_err("Sub tlvs should start past the end of the TLV.");
    }

    #[test]
    fn tlv_with_wrong_type() {
        let packet: &[u8] = &[
            10, // Seqno Request Type ID
            5,  // Length
            1,  // AE
            24, // Plen
            192, 168, 0, // Prefix
        ];

        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        RouteRequestSlice::from_untyped(untyped).expect_err("Route Request should not parse");
    }
}
