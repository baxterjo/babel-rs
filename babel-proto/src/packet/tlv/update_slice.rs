use core::fmt::Debug;

use crate::data_structures::seqno::SeqNo;
use crate::data_types::Interval;
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
pub struct UpdateSlice<'a> {
    slice: &'a [u8],
}

impl Debug for UpdateSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UpdateSlice")
            .field("type", &self.as_untyped().r#type())
            .field("length", &self.as_untyped().length())
            .field("ae", &self.ae())
            .finish()
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

    /// The prefix being advertised. This field's size is (Plen/8 - Omitted) rounded upwards.
    pub fn prefix(&self) -> Result<&'a [u8], TlvError> {
        let idx_end: usize = (self.plen().div_ceil(8) - self.ommitted()).into();
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
        val = val | (prefix as u8) << 7;
        val = val | (router_id as u8) << 6;
        Self(val)
    }

    pub(crate) fn is_router_id(&self) -> bool {
        self.0 & 1 << 6 > 0
    }
    pub(crate) fn is_prefix(&self) -> bool {
        self.0 & 1 << 7 > 0
    }
}
