use core::fmt::Debug;

use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;

/// Next Hop TLV as defined in
/// [Section 4.6.8](https://datatracker.ietf.org/doc/html/rfc8966#name-next-hop)
///
/// A Next Hop TLV establishes a next-hop address for a given address family (IPv4 or IPv6) that is
/// implied in subsequent Update TLVs, as described in Section 4.5. This TLV sets up the next hop
/// for subsequent Update TLVs even if it is otherwise ignored due to an unknown mandatory sub-TLV.
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 7   |    Length     |      AE       |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Next hop...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
/// When the address family matches the network-layer protocol over which this packet is
/// transported, a Next Hop TLV is not needed: in the absence of a Next Hop TLV in a given address
/// family, the next-hop address is taken to be the source address of the packet.
///
/// Next Hop TLVs with an unknown value for the AE field MUST be silently ignored.
pub struct NextHopSlice<'a> {
    slice: &'a [u8],
}

impl Debug for NextHopSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NextHopSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("ae", &self.ae())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for NextHopSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "NextHopSlice{{ type: {}, length: {}, ae: {}}}",
            TlvSlice::from_typed(self).r#type(),
            TlvSlice::from_typed(self).length(),
            self.ae()
        )
    }
}

impl<'a> TypedTlv<'a> for NextHopSlice<'a> {
    const TYPE_ID: u8 = 7;
    const MIN_LEN: usize = 2;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> NextHopSlice<'a> {
    /// The encoding of the Address field. This SHOULD be 1 (IPv4) or 3 (link-local IPv6), and MUST
    /// NOT be 0.
    pub fn ae(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN) }
    }

    /// The next-hop address advertised by subsequent Update TLVs for this address family.
    pub fn next_hop(&self, len: usize) -> Result<&'a [u8], TlvError> {
        let idx_end = TlvHeader::LEN + Self::MIN_LEN + len;
        // This **MUST** be checked as the source of len can be user supplied through extensions
        // and cause a footgun.
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
    pub fn sub_tlvs(&self, address_len: usize) -> Result<&'a [u8], TlvError> {
        let idx_start = TlvHeader::LEN + Self::MIN_LEN + address_len;
        let len = self.slice.len();

        // This **MUST** be checked as the source of address_len can be user supplied through
        // extensions and cause a footgun.
        Ok(self.slice.get(idx_start..len).ok_or(LenError {
            // The sub-TLV region starts after the address, so the TLV has to be at least that
            // long. Reporting `len` for both fields renders as "N bytes is too big (maximum N)".
            required_len: idx_start,
            len,
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
            7,  // Next Hop Type ID
            15, // Length
            1,  // AE
            0,  // Reserved
            192, 168, 0, 5, // Next hop
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 7, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 15, "Incorrect length");
        let next_hop = NextHopSlice::from_untyped(tlv_slice).expect("Next Hop should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(next_hop.ae()).expect("Should be known address encoding.");

        assert_eq!(next_hop.ae(), 1, "Incorrect AE");
        assert_eq!(
            next_hop
                .next_hop(ae.address_len())
                .expect("Should be able to get next hop"),
            &[192, 168, 0, 5],
            "Incorrect next hop"
        );
        assert_eq!(
            next_hop
                .sub_tlvs(ae.address_len())
                .expect("Should have sub tlvs"),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );

        // Without sub_tlvs
        let packet: &[u8] = &[
            7, // Next Hop Type ID
            6, // Length
            1, // AE
            0, // Reserved
            192, 168, 0, 5, // Next hop
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let next_hop = NextHopSlice::from_untyped(tlv_slice).expect("Next Hop should parse.");

        assert_eq!(
            next_hop
                .next_hop(ae.address_len())
                .expect("Should be able to get next hop"),
            &[192, 168, 0, 5],
            "Incorrect next hop"
        );
        assert_eq!(
            next_hop
                .sub_tlvs(ae.address_len())
                .expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn tlv_with_bad_length() {
        // Declared length runs past the end of the buffer.
        let packet: &[u8] = &[
            7,   // Next Hop Type ID
            120, // Length
            1,   // AE
            0,   // Reserved
            192, 168, 0, 5, // Next hop
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        // Declared length is less than Self::MIN_LEN, so the Reserved field is truncated.
        let packet: &[u8] = &[
            7, // Next Hop Type ID
            1, // Length
            1, // AE
            0, // Reserved
            192, 168, 0, 5, // Next hop
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        NextHopSlice::from_untyped(untyped).expect_err("Next Hop should not parse");

        // Declared length is at least Self::MIN_LEN but the next hop address is too short for the
        // address encoding.
        let packet: &[u8] = &[
            7, // Next Hop Type ID
            3, // Length
            1, // AE
            0, // Reserved
            192, 168, 0, 5, // Next hop
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        let next_hop = NextHopSlice::from_untyped(untyped).expect("Next Hop should parse");

        next_hop
            .next_hop(4)
            .expect_err("Next hop should be too short.");
        next_hop
            .sub_tlvs(4)
            .expect_err("Sub tlvs should start past the end of the TLV.");
    }

    #[test]
    fn tlv_with_wrong_type() {
        let packet: &[u8] = &[
            5, // IHU Type ID
            6, // Length
            1, // AE
            0, // Reserved
            192, 168, 0, 5, // Next hop
        ];

        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        NextHopSlice::from_untyped(untyped).expect_err("Next Hop should not parse");
    }
}
