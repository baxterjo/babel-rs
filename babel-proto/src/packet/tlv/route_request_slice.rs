use core::fmt::Debug;

use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;

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
    pub fn prefix(&self) -> Result<&'a [u8], TlvError> {
        let prefix_len: usize = self.plen().div_ceil(8).into();
        let idx_end = TlvHeader::LEN + Self::MIN_LEN + prefix_len;
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
    pub fn sub_tlvs(&self) -> Result<&'a [u8], TlvError> {
        let prefix_len: usize = self.plen().div_ceil(8).into();
        let idx_start = TlvHeader::LEN + Self::MIN_LEN + prefix_len;
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

        assert_eq!(
            route_request
                .prefix()
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request.sub_tlvs().expect("Should have sub tlvs"),
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

        assert_eq!(
            route_request
                .prefix()
                .expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs()
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

        assert_eq!(
            route_request
                .prefix()
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

        assert_eq!(route_request.plen(), 0, "Incorrect plen");
        assert_eq!(
            route_request
                .prefix()
                .expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            route_request
                .sub_tlvs()
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
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

        route_request
            .prefix()
            .expect_err("Prefix should be too short.");
        route_request
            .sub_tlvs()
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
