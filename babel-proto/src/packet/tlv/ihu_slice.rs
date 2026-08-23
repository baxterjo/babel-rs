use core::fmt::Debug;

use crate::data_types::Interval;
use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::tlv_slice::TlvSlice;
use crate::packet::utils::get_unchecked_be_u16;
use crate::utils::Duration;
use crate::utils::rx_cost::RxCost;

/// IHU TLV as defined in section
/// [4.6.6](https://datatracker.ietf.org/doc/html/rfc8966#name-ihu)
///
/// An IHU ("I Heard You") TLV is used for confirming bidirectional reachability and carrying a
/// link's transmission cost.
///
/// Conceptually, an IHU is destined to a single neighbour. However, IHU TLVs contain an explicit
/// destination address, and MAY be sent to a multicast address, as this allows aggregation of IHUs
/// destined to distinct neighbours into a single packet and avoids the need for an ARP or Neighbour
/// Discovery exchange when a neighbour is not being used for data traffic.
///
/// # Wire Format
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 5   |    Length     |       AE      |    Reserved   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Rxcost             |          Interval             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Address...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
pub struct IhuSlice<'a> {
    slice: &'a [u8],
}

impl Debug for IhuSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IhuSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("ae", &self.ae())
            .field("rx_cost", &self.rx_cost())
            .field("interval", &self.interval())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for IhuSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "IhuSlice{{ type: {}, length: {}, ae: {}, rx_cost: {}, interval: {}}}",
            TlvSlice::from_typed(self).r#type(),
            TlvSlice::from_typed(self).length(),
            self.ae(),
            self.rx_cost(),
            self.interval()
        )
    }
}

impl<'a> TypedTlv<'a> for IhuSlice<'a> {
    const TYPE_ID: u8 = 5;
    const MIN_LEN: usize = 6;
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
}

impl<'a> IhuSlice<'a> {
    /// The encoding of the Address field. This should be 1 or 3 in most cases. As an optimisation,
    /// it MAY be 0 if the TLV is sent to a unicast address, if the association is over a
    /// point-to-point link, or when bidirectional reachability is ascertained by means outside of
    /// the Babel protocol.
    pub fn ae(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN) }
    }

    /// The rxcost according to the sending node of the interface whose address is specified in the
    /// Address field. The value FFFF hexadecimal (infinity) indicates that this interface is
    /// unreachable.
    pub fn rx_cost(&self) -> RxCost {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        unsafe {
            RxCost(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN + 2),
            ))
        }
    }

    /// An upper bound, expressed in centiseconds, on the time after which the sending node will
    /// send a new IHU; this MUST NOT be 0. The receiving node will use this value in order to
    /// compute a hold time for this symmetric association.
    pub fn interval(&self) -> Interval {
        let centis = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(TlvHeader::LEN + 4)) };
        Duration::from_centis(centis.into()).into()
    }

    /// The address of the destination node, in the format specified by the AE field. Address
    /// compression is not allowed.
    pub fn address(&self, len: usize) -> Result<&'a [u8], TlvError> {
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

        b_debug!("Start: {}, Slice Len: {}", idx_start, len);

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

#[cfg(all(test, feature = "std"))]
mod test {
    use super::*;
    use crate::data_types::address_encoding::AddressEncoding;
    use crate::extension::NoExtension;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    #[test]
    fn normal_slice() {
        let packet: &[u8] = &[
            5,  // IHU Type ID
            19, // Length
            1,  // AE
            0,  // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
            192, 168, 0, 5, //
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 5, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 19, "Incorrect length");
        let ihu = IhuSlice::from_untyped(tlv_slice).expect("IHU should parse.");

        let ae: AddressEncoding<NoExtension> =
            AddressEncoding::try_from(ihu.ae()).expect("Should be known address encoding.");

        assert_eq!(ihu.rx_cost(), RxCost(0x8000));
        assert_eq!(ihu.interval(), Duration::from_centis(200).into());
        assert_eq!(
            ihu.address(ae.address_len())
                .expect("Should be able to get address"),
            &[192, 168, 0, 5]
        );
        assert_eq!(
            ihu.sub_tlvs(ae.address_len())
                .expect("Should have sub tlvs"),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9]
        )
    }

    #[test]
    fn tlv_with_bad_length() {
        // Declared length is less than TlvHeader::LEN + Self::MIN_LEN
        let packet: &[u8] = &[
            5, // IHU Type ID
            5, // Length
            1, // AE
            0, // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
            192, 168, 0, 5, //
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        IhuSlice::from_untyped(untyped).expect_err("IHU should not parse");

        // Declared length is greater than TlvHeader::LEN + Self::MIN_LEN but address is too short.
        let packet: &[u8] = &[
            5, // IHU Type ID
            8, // Length
            1, // AE
            0, // Reserved
            0x80, 0x00, // RX Cost
            0, 200, // Interval
            192, 168, 0, 5, //
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        let ihu = IhuSlice::from_untyped(untyped).expect("IHU should parse");

        ihu.address(4).expect_err("Address should be too short.");
    }
}
