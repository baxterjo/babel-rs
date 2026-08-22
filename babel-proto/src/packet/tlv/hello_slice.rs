use core::fmt::Debug;

use crate::{
    data_structures::seqno::SeqNo,
    data_types::Interval,
    packet::{
        tlv::{tlv_header::TlvHeader, tlv_slice::TlvSlice, TypedTlv},
        utils::get_unchecked_be_u16,
    },
    utils::Duration,
};

/// Hello flags as defined in section
/// [4.6.5](https://datatracker.ietf.org/doc/html/rfc8966#name-hello)
///
/// The Flags field is interpreted as follows:
///
/// ```sh
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |U|X|X|X|X|X|X|X|X|X|X|X|X|X|X|X|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
/// U (Unicast) flag (8000 hexadecimal):
///     if set, then this Hello represents a Unicast Hello, otherwise it represents a Multicast Hello;
///
/// X:
///     all other bits MUST be sent as 0 and silently ignored on reception.
#[derive(PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct HelloFlags(u16);

impl HelloFlags {
    pub const fn new(unicast: bool) -> Self {
        Self(0 | (unicast as u16) << 15)
    }

    pub const fn new_unicast() -> Self {
        Self::new(true)
    }

    pub const fn new_multicast() -> Self {
        Self::new(false)
    }

    pub fn is_unicast(&self) -> bool {
        (self.0 & 0x8000u16) > 0u16
    }

    pub fn is_multicast(&self) -> bool {
        !self.is_unicast()
    }

    pub fn to_wire(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

impl Debug for HelloFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HelloFlags")
            .field("unicast", &self.is_unicast())
            .finish()
    }
}

/// Hello TLV as defined in section
/// [4.6.5](https://datatracker.ietf.org/doc/html/rfc8966#name-hello)
///
/// Every time a Hello is sent, the corresponding seqno counter MUST be incremented. Since there is
/// a single seqno counter for all the Multicast Hellos sent by a given node over a given interface,
/// if the Unicast flag is not set, this TLV MUST be sent to all neighbours on this link, which can
/// be achieved by sending to a multicast destination or by sending multiple packets to the unicast
/// addresses of all reachable neighbours. Conversely, if the Unicast flag is set, this TLV MUST be
/// sent to a single neighbour, which can achieved by sending to a unicast destination. In order to
/// avoid large discontinuities in link quality, multiple Hello TLVs SHOULD NOT be sent in the same
/// packet.
///
/// # Wire format:
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 4   |    Length     |            Flags              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |            Seqno              |          Interval             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub struct HelloSlice<'a> {
    slice: &'a [u8],
}

impl Debug for HelloSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HelloSlice")
            .field("type", &TlvSlice::from_typed(self).r#type())
            .field("length", &TlvSlice::from_typed(self).length())
            .field("flags", &self.flags())
            .field("seqno", &self.seqno())
            .field("interval", &self.interval())
            .finish()
    }
}

impl<'a> TypedTlv<'a> for HelloSlice<'a> {
    const TYPE_ID: u8 = 4;
    const MIN_LEN: usize = 6;
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }

    fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

impl<'a> HelloSlice<'a> {
    /// The individual bits of this field specify special handling of this TLV.
    pub fn flags(&self) -> HelloFlags {
        // SAFETY:
        // Safe as the constructor has checked to ensure the length of the slice is at minimum
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        unsafe {
            HelloFlags(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN),
            ))
        }
    }

    /// If the Unicast flag is set, this is the value of the sending node's outgoing Unicast Hello
    /// seqno for this neighbour. Otherwise, it is the sending node's outgoing Multicast Hello seqno
    /// for this interface.
    pub fn seqno(&self) -> SeqNo {
        unsafe {
            // SAFETY:
            // Safe as the constructor has checked to ensure the length of the slice is at minimum
            // TlvHeader::LEN (2) + Self::MIN_LEN (6).
            SeqNo(get_unchecked_be_u16(
                self.slice.as_ptr().add(TlvHeader::LEN + 2),
            ))
        }
    }

    /// If nonzero, this is an upper bound, expressed in centiseconds, on the time after which the
    /// sending node will send a new scheduled Hello TLV with the same setting of the Unicast flag.
    /// If this is 0, then this Hello represents an unscheduled Hello and doesn't carry any new
    /// information about times at which Hellos are sent.
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
        // TlvHeader::LEN (2) + Self::MIN_LEN (6).
        // If they are the same value then this will return an empty slice.
        unsafe {
            self.slice
                .get_unchecked(TlvHeader::LEN + Self::MIN_LEN..self.slice.len())
        }
    }

    pub fn is_scheduled(&self) -> bool {
        !self.interval().is_zero()
    }

    pub fn is_unscheduled(&self) -> bool {
        self.interval().is_zero()
    }
}

#[cfg(test)]
mod test {
    use crate::packet::tlv::tlv_slice::TlvSlice;

    use super::*;

    #[test]
    fn hello_flags_create_as_expected() {
        assert!(HelloFlags::new(true).is_unicast());
        assert!(HelloFlags::new(false).is_multicast());
    }

    #[test]
    fn normal_slice() {
        let packet: &[u8] = &[
            4,  // Hello Type ID
            15, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        let tlv_slice = TlvSlice::from_slice(packet).expect("Untyped tlv should parse");
        assert_eq!(tlv_slice.r#type(), 4, "Incorrect type ID");
        assert_eq!(tlv_slice.length(), 15, "Incorrect length");
        let hello = HelloSlice::from_untyped(tlv_slice).expect("Hello should parse.");

        let flags = hello.flags();
        assert_eq!(flags, HelloFlags(0x8000), "Incorrect flags");
        assert!(flags.is_unicast(), "Flags should be unicast");
        assert!(!flags.is_multicast(), "Flags should not be multicast");
        assert_eq!(hello.seqno(), SeqNo(15), "Incorrect seqno");
        assert_eq!(
            hello.interval(),
            Duration::from_centis(200).into(),
            "Incorrect interval"
        );
        assert_eq!(
            hello.sub_tlvs(),
            &[1, 2, 3, 4, 5, 6, 7, 8, 9],
            "Incorrect sub tlvs"
        );
    }

    #[test]
    fn tlv_with_bad_length() {
        let packet: &[u8] = &[
            4,   // Hello Type ID
            120, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        TlvSlice::from_slice(packet).expect_err("Should have got length error");

        let packet: &[u8] = &[
            4, // Hello Type ID
            5, // Length
            0x80, 0x00, // Flags
            0, 15, // Seqno
            0, 200, // Interval
            1, 2, 3, 4, 5, 6, 7, 8, 9, // Sub TLVS
        ];

        // Untyped TLV should parse because we don't know the type so we can't know how long it
        // **should** be.
        let untyped = TlvSlice::from_slice(packet).expect("Untyped should parse");

        HelloSlice::from_untyped(untyped).expect_err("Hello should not parse");
    }
}
