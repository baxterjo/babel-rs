use core::fmt::Debug;

use crate::data_types::Interval;
use crate::data_types::seqno::SeqNo;
use crate::metric::Metric;
use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::utils::get_unchecked_be_u16;
use crate::utils::Duration;

/// Update TLV as defined in
/// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update)
///
/// An Update TLV advertises or retracts a route. As an optimisation, it can optionally have the
/// side effect of establishing a new implied router-id and a new default prefix, as described in
/// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#parser-state).
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 8   |    Length     |       AE      |    Flags      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Plen      |    Omitted    |            Interval           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Seqno             |            Metric             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Prefix...
/// +-+-+-+-+-+-+-+-+-+-+-+-
/// ```
/// If the Metric field is finite, the router-id of the originating node for this announcement is
/// taken from the prefix advertised by this Update if the Router-Id flag is set, computed as
/// described in [`UpdateSlice::prefix`]. Otherwise, it is taken either from the preceding
/// Router-Id TLV, or the preceding Update TLV with the Router-Id flag set, whichever comes last,
/// even if that TLV is otherwise ignored due to an unknown mandatory sub-TLV; if there is no
/// suitable TLV, then this update is ignored.
///
/// The next-hop address for this update is taken from the last preceding Next Hop TLV with a
/// matching address family (IPv4 or IPv6) in the same packet even if it was otherwise ignored due
/// to an unknown mandatory sub-TLV; if no such TLV exists, it is taken from the network-layer
/// source address of this packet if it belongs to the same address family as the prefix being
/// announced; otherwise, this Update MUST be ignored.
///
/// If the metric field is FFFF hexadecimal, this TLV specifies a retraction. In that case, the
/// router-id, next hop, and seqno are not used. AE MAY then be 0, in which case this Update
/// retracts all of the routes previously advertised by the sending interface. If the metric is
/// finite, AE MUST NOT be 0; Update TLVs with finite metric and AE equal to 0 MUST be ignored. If
/// the metric is infinite and AE is 0, Plen and Omitted MUST both be 0; Update TLVs that do not
/// satisfy this requirement MUST be ignored.
///
/// Update TLVs with an unknown value in the AE field MUST be silently ignored.
pub struct UpdateSlice<'a> {
    slice: &'a [u8],
}

impl Debug for UpdateSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpdateSlice")
            .field("type", &self.as_untyped().r#type())
            .field("length", &self.as_untyped().length())
            .field("ae", &self.ae())
            .field("flags", &self.flags())
            .field("plen", &self.plen())
            .field("ommitted", &self.ommitted())
            .field("interval", &self.interval())
            .field("seqno", &self.seqno())
            .field("metric", &self.metric())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for UpdateSlice<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "UpdateSlice{{ type: {}, length: {}, ae: {}, flags: {}, plen: {}, ommitted: {}, interval: {}, seqno: {}, metric: {}}}",
            self.as_untyped().r#type(),
            self.as_untyped().length(),
            self.ae(),
            self.flags(),
            self.plen(),
            self.ommitted(),
            self.interval(),
            self.seqno(),
            self.metric()
        )
    }
}

impl<'a> TypedTlv<'a> for UpdateSlice<'a> {
    const TYPE_ID: u8 = 8;
    const MIN_LEN: usize = 10;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> UpdateSlice<'a> {
    /// The encoding of the Prefix field.
    pub fn ae(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN) }
    }

    /// The individual bits of this field specify special handling of this TLV (see
    /// [`UpdateFlags`]).
    pub fn flags(&self) -> UpdateFlags {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10).
        unsafe { UpdateFlags(*self.slice.get_unchecked(TlvHeader::LEN + 1)) }
    }

    /// The length in bits of the advertised prefix. If AE is 3 (link-local IPv6), the Omitted field
    /// MUST be 0.
    pub fn plen(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN + 2) }
    }

    /// The number of octets that have been omitted at the beginning of the advertised prefix and
    /// that should be taken from a preceding Update TLV in the same address family with the Prefix
    /// flag set.
    pub fn ommitted(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10).
        unsafe { *self.slice.get_unchecked(TlvHeader::LEN + 3) }
    }

    /// An upper bound, expressed in centiseconds, on the time after which the sending node will
    /// send a new update for this prefix. This MUST NOT be 0. The receiving node will use this
    /// value to compute a hold time for the route table entry. The value FFFF hexadecimal
    /// (infinity) expresses that this announcement will not be repeated unless a request is
    /// received
    /// ([Section 3.8.2.3](https://datatracker.ietf.org/doc/html/rfc8966#request-expiring)).
    pub fn interval(&self) -> Interval {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (10).
        let centis = unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(TlvHeader::LEN + 4)) };
        Duration::from_centis(centis.into()).into()
    }

    /// The originator's sequence number for this update.
    pub fn seqno(&self) -> SeqNo {
        unsafe {
            // SAFETY:
            // Safe as the constructor has checked to ensure the length of the slice is at minimum
            // TlvHeader::LEN (2) + Self::MIN_LEN (10).
            SeqNo(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN + 6),
            ))
        }
    }

    /// The sender's metric for this route. The value FFFF hexadecimal (infinity) means that this is
    /// a route retraction.
    // TODO: When I wire up cost calculation, this needs to change to Metric
    pub fn metric(&self) -> Metric {
        unsafe {
            // SAFETY:
            // Safe as the constructor has checked to ensure the length of the slice is at minimum
            // TlvHeader::LEN (2) + Self::MIN_LEN (10).
            Metric::from_raw(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN + 8),
            ))
        }
    }

    /// The size in octets of the Prefix field, `(Plen/8).ceil() - implied_octets - Omitted`.
    ///
    /// `implied_octets` is the number of leading octets the address encoding fixes itself and which
    /// therefore never reach the wire - 8 for AE 3, whose `fe80::/64` prefix is implied, and 0 for
    /// every other base-spec encoding. Plen counts the whole advertised prefix including those
    /// octets, so they come off the field length as a second, implicit `Omitted`.
    fn prefix_field_len(&self, implied_octets: usize) -> Result<usize, TlvError> {
        let plen = self.plen();

        // A Plen below the implied prefix names bits underneath the floor the encoding sets, so
        // there is no prefix it could be describing.
        if usize::from(plen) < implied_octets * 8 {
            return Err(TlvError::PlenBelowImpliedPrefix {
                plen,
                implied_octets,
            });
        }

        // The check above makes this subtraction safe.
        let uncompressed_len = usize::from(plen.div_ceil(8)) - implied_octets;

        let omitted = self.ommitted();
        // Can't have a negative length.
        if usize::from(omitted) > uncompressed_len {
            return Err(TlvError::OmittedTooLong { plen, omitted });
        }
        Ok(uncompressed_len - usize::from(omitted))
    }

    /// The prefix being advertised, as it appears on the wire.
    ///
    /// The field holds `(Plen/8).ceil() - implied_octets - Omitted` octets; see
    /// [`Self::prefix_field_len`] for what `implied_octets` means and why it is a parameter.
    pub fn prefix(&self, implied_octets: usize) -> Result<&'a [u8], TlvError> {
        let idx_end = TlvHeader::LEN + Self::MIN_LEN + self.prefix_field_len(implied_octets)?;
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
        let idx_end = TlvHeader::LEN + Self::MIN_LEN + self.prefix_field_len(implied_octets)?;
        // This **MUST** be checked as the source of idx_end is supplied through the tlv. So a
        // malicious packet could cause UB.
        Ok(self.slice.get(idx_end..).ok_or(LenError {
            required_len: idx_end,
            len: self.slice.len(),
            len_source: LenSource::AddressEncoding,
            layer: Layer::BabelTlvBody,
            layer_start_offset: 0,
        })?)
    }

    pub fn is_retraction(&self) -> bool {
        self.metric() == Metric::INFINITY
    }

    pub fn is_blanket_retraction(&self) -> bool {
        self.ae() == 0 && self.is_retraction()
    }
}

/// Update flags as defined in
/// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#section-4.6.9-5)
///
/// The Flags field is interpreted as follows:
///
///```sh
///  0 1 2 3 4 5 6 7
/// +-+-+-+-+-+-+-+-+
/// |P|R|X|X|X|X|X|X|
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// P (Prefix) flag (80 hexadecimal):
///     if set, then this Update TLV establishes a new default prefix for subsequent Update TLVs
/// with a matching address encoding within the same packet, even if this TLV is otherwise ignored
/// due to an unknown mandatory sub-TLV;
///
/// R (Router-Id) flag (40 hexadecimal):
///     if set, then this TLV establishes a new default router-id for this TLV and subsequent Update
/// TLVs in the same packet, even if this TLV is otherwise ignored due to an unknown mandatory
/// sub-TLV. This router-id is computed from the first address of the advertised prefix as follows:
///
///   * if the length of the address is 8 octets or more, then the new router-id is taken from
/// the 8 last octets of the address;
///   * if the length of the address is smaller than 8 octets,
/// then the new router-id consists of the required number of zero octets followed by the address,
/// i.e., the address is stored on the right of the router-id. For example, for an IPv4 address, the
/// router-id consists of 4 octets of zeroes followed by the IPv4 address.
///
/// X:
///     all other bits MUST be sent as 0 and silently ignored on reception.
pub struct UpdateFlags(u8);

impl From<u8> for UpdateFlags {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

impl UpdateFlags {
    pub(crate) fn new(prefix: bool, router_id: bool) -> Self {
        let mut val = 0u8;
        val |= (prefix as u8) << 7;
        val |= (router_id as u8) << 6;
        Self(val)
    }

    pub(crate) fn is_router_id(&self) -> bool {
        self.0 & 1 << 6 > 0
    }
    pub(crate) fn is_prefix(&self) -> bool {
        self.0 & 1 << 7 > 0
    }
}

impl Debug for UpdateFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpdateFlags")
            .field("prefix", &self.is_prefix())
            .field("router_id", &self.is_router_id())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for UpdateFlags {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "UpdateFlags{{ prefix: {}, router_id: {}}}",
            self.is_prefix(),
            self.is_router_id()
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    #[test]
    fn normal_slice() {
        // Full (uncompressed) prefix, with trailing bytes after it.
        let packet: &[u8] = &[
            8,    // Update Type ID
            22,   // Length
            1,    // AE
            0xC0, // Flags (Prefix | Router-Id)
            24,   // Plen
            0,    // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            192, 168, 0, // Prefix
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 8, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 22, "Incorrect length");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert_eq!(update.ae(), 1, "Incorrect AE");
        assert!(update.flags().is_prefix(), "Prefix flag should be set");
        assert!(
            update.flags().is_router_id(),
            "Router-Id flag should be set"
        );
        assert_eq!(update.plen(), 24, "Incorrect plen");
        assert_eq!(update.ommitted(), 0, "Incorrect omitted");
        assert_eq!(
            update.interval(),
            Duration::from_centis(200).into(),
            "Incorrect interval"
        );
        assert_eq!(update.seqno(), SeqNo(42), "Incorrect seqno");
        assert_eq!(
            update.metric(),
            Metric::from_raw(0x0100),
            "Incorrect metric"
        );
        assert_eq!(
            update.prefix(0).expect("Should be able to get prefix"),
            &[192, 168, 0],
            "Incorrect prefix"
        );
        assert_eq!(
            update.sub_tlvs(0).expect("Should have sub tlvs"),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );

        // Compressed prefix (first two octets omitted) and no trailing bytes.
        let packet: &[u8] = &[
            8,  // Update Type ID
            11, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            2,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            5,    // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert!(!update.flags().is_prefix(), "Prefix flag should be clear");
        assert!(
            !update.flags().is_router_id(),
            "Router-Id flag should be clear"
        );
        assert_eq!(update.ommitted(), 2, "Incorrect omitted");
        assert_eq!(
            update.prefix(0).expect("Should be able to get prefix"),
            &[5],
            "Incorrect prefix"
        );
        assert_eq!(
            update.sub_tlvs(0).expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );

        // A fully omitted (default) prefix yields an empty slice.
        let packet: &[u8] = &[
            8,  // Update Type ID
            10, // Length
            1,  // AE
            0,  // Flags
            0,  // Plen
            0,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert_eq!(
            update.prefix(0).expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            update.sub_tlvs(0).expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn retraction_metric() {
        // A metric of FFFF hexadecimal (infinity) means this Update is a route retraction.
        let packet: &[u8] = &[
            8,  // Update Type ID
            13, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            0,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0xFF, 0xFF, // Metric
            192, 168, 0, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert_eq!(
            update.metric(),
            Metric::from_raw(0xFFFF),
            "Incorrect metric"
        );
        assert!(update.metric().is_infinite(), "Metric should be infinite");
    }

    #[test]
    fn omitted_larger_than_prefix() {
        // Omitted (5) claims more octets than Plen (24 bits -> 3 octets) accounts for, which RFC
        // 8966 makes invalid. Both accessors reject it rather than saturating the prefix length to
        // zero and handing the prefix octets back as sub-TLVs.
        let packet: &[u8] = &[
            8,  // Update Type ID
            13, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            5,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            192, 168, 0, // Prefix
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert_eq!(
            update.prefix(0).expect_err("Prefix should be rejected"),
            TlvError::OmittedTooLong {
                plen: 24,
                omitted: 5
            },
            "Incorrect prefix error"
        );
        assert_eq!(
            update.sub_tlvs(0).expect_err("Sub tlvs should be rejected"),
            TlvError::OmittedTooLong {
                plen: 24,
                omitted: 5
            },
            "Incorrect sub tlv error"
        );

        // Omitting exactly as many octets as the prefix holds is still valid and yields an empty
        // prefix, so the rejection starts one octet later.
        let packet: &[u8] = &[
            8,  // Update Type ID
            10, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            3,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        let update = UpdateSlice::from_untyped(tlv_slice).expect("Update should parse.");

        assert_eq!(
            update.prefix(0).expect("Should be able to get prefix"),
            &[],
            "Should have an empty prefix"
        );
        assert_eq!(
            update.sub_tlvs(0).expect("Should be able to get sub tlvs"),
            &[],
            "Should have no sub tlvs"
        );
    }

    #[test]
    fn tlv_with_bad_length() {
        // Declared length runs past the end of the buffer.
        let packet: &[u8] = &[
            8,   // Update Type ID
            120, // Length
            1,   // AE
            0,   // Flags
            24,  // Plen
            0,   // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            192, 168, 0, // Prefix
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        // Declared length is less than Self::MIN_LEN, so the Metric field is truncated.
        let packet: &[u8] = &[
            8,  // Update Type ID
            9,  // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            0,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        UpdateSlice::from_untyped(untyped).expect_err("Update should not parse");

        // Declared length is at least Self::MIN_LEN but the prefix is too short for the declared
        // plen.
        let packet: &[u8] = &[
            8,  // Update Type ID
            11, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            0,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
            192, 168, 0, // Prefix
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        let update = UpdateSlice::from_untyped(untyped).expect("Update should parse");

        update.prefix(0).expect_err("Prefix should be too short.");
        update
            .sub_tlvs(0)
            .expect_err("Sub tlvs should start past the end of the TLV.");
    }

    #[test]
    fn tlv_with_wrong_type() {
        let packet: &[u8] = &[
            5,  // IHU Type ID
            10, // Length
            1,  // AE
            0,  // Flags
            24, // Plen
            0,  // Omitted
            0, 200, // Interval
            0, 42, // Seqno
            0x01, 0x00, // Metric
        ];

        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        UpdateSlice::from_untyped(untyped).expect_err("Update should not parse");
    }

    #[test]
    fn flags_new_wire_layout() {
        // P is 80 hexadecimal and R is 40 hexadecimal, so P is the high bit of the Flags octet.
        assert_eq!(UpdateFlags::new(false, false).0, 0x00, "Incorrect flags");
        assert_eq!(UpdateFlags::new(true, false).0, 0x80, "Incorrect flags");
        assert_eq!(UpdateFlags::new(false, true).0, 0x40, "Incorrect flags");
        assert_eq!(UpdateFlags::new(true, true).0, 0xC0, "Incorrect flags");

        // `new` never sets any of the reserved X bits.
        for prefix in [false, true] {
            for router_id in [false, true] {
                assert_eq!(
                    UpdateFlags::new(prefix, router_id).0 & 0x3F,
                    0,
                    "Reserved bits should be sent as 0"
                );
            }
        }
    }

    #[test]
    fn flags_round_trip() {
        for prefix in [false, true] {
            for router_id in [false, true] {
                let flags = UpdateFlags::new(prefix, router_id);

                assert_eq!(flags.is_prefix(), prefix, "Incorrect prefix flag");
                assert_eq!(flags.is_router_id(), router_id, "Incorrect router-id flag");

                // Every set of flags survives a trip out to the wire and back.
                let parsed = UpdateFlags::from(flags.0);

                assert_eq!(parsed.is_prefix(), prefix, "Incorrect prefix flag");
                assert_eq!(parsed.is_router_id(), router_id, "Incorrect router-id flag");
            }
        }
    }

    #[test]
    fn flags_from_wire() {
        let flags = UpdateFlags::from(0x00);
        assert!(!flags.is_prefix(), "Prefix flag should be clear");
        assert!(!flags.is_router_id(), "Router-Id flag should be clear");

        let flags = UpdateFlags::from(0x80);
        assert!(flags.is_prefix(), "Prefix flag should be set");
        assert!(!flags.is_router_id(), "Router-Id flag should be clear");

        let flags = UpdateFlags::from(0x40);
        assert!(!flags.is_prefix(), "Prefix flag should be clear");
        assert!(flags.is_router_id(), "Router-Id flag should be set");

        let flags = UpdateFlags::from(0xC0);
        assert!(flags.is_prefix(), "Prefix flag should be set");
        assert!(flags.is_router_id(), "Router-Id flag should be set");
    }

    #[test]
    fn flags_ignore_reserved_bits() {
        // All other bits MUST be silently ignored on reception, so the X bits must not leak into
        // either accessor.
        let flags = UpdateFlags::from(0x3F);
        assert!(!flags.is_prefix(), "Prefix flag should be clear");
        assert!(!flags.is_router_id(), "Router-Id flag should be clear");

        let flags = UpdateFlags::from(0xFF);
        assert!(flags.is_prefix(), "Prefix flag should be set");
        assert!(flags.is_router_id(), "Router-Id flag should be set");

        // Each reserved bit on its own leaves both flags clear.
        for bit in 0..6 {
            let flags = UpdateFlags::from(1 << bit);
            assert!(
                !flags.is_prefix(),
                "Prefix flag should be clear for reserved bit {bit}"
            );
            assert!(
                !flags.is_router_id(),
                "Router-Id flag should be clear for reserved bit {bit}"
            );
        }
    }
}
