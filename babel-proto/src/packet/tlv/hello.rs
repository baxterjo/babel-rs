use crate::{
    data_structures::seqno::SeqNo,
    data_types::Interval,
    packet::tlv::{TlvEncodeError, TlvHeaderT, TlvParseError},
    utils::cursor::ManagedSliceCursor,
};

/// Hello flags as defined in section
/// [4.6.5](https://datatracker.ietf.org/doc/html/rfc8966#name-hello)
///
/// The Flags field is interpreted as follows:
///
///  0                   1
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |U|X|X|X|X|X|X|X|X|X|X|X|X|X|X|X|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// U (Unicast) flag (8000 hexadecimal):
///     if set, then this Hello represents a Unicast Hello, otherwise it represents a Multicast Hello;
/// X:
///     all other bits MUST be sent as 0 and silently ignored on reception.
pub struct HelloFlags(u16);

impl HelloFlags {
    fn is_unicast(&self) -> bool {
        (self.0 & 0x8000u16) > 0u16
    }

    fn is_multicast(&self) -> bool {
        !self.is_unicast()
    }
}

/// Hello TLV as defined in section
/// [4.6.5](https://datatracker.ietf.org/doc/html/rfc8966#name-hello)
///
/// Note: `Type` and `Length` fields are not represented here as they have no value beyond parsing
/// and encoding.
pub struct Hello<'a> {
    /// The individual bits of this field specify special handling of this TLV (see below).
    flags: HelloFlags,
    seqno: SeqNo,
    interval: Interval,
    sub_tlvs: Option<&'a [u8]>,
}

impl TlvHeaderT for Hello<'_> {
    /// Set to 4 to indicate a Hello TLV.
    const TYPE_ID: u8 = 4;
}

impl<'a> Hello<'a> {
    /// Parses the entire tlv INCLUDING the already checked type field.
    ///
    /// Mutates the buffer as it parses bytes.
    // The reason this takes the `Type` field is for unit testing symetric parse / encode.
    fn parse(input: &mut &'a [u8]) -> Result<Self, TlvParseError> {
        let (_headers, mut body, remainder) = Self::parse_header(input)?;

        *input = remainder;

        // Parse flags
        let (flags_bytes, rest) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        body = rest;
        let flags = HelloFlags(u16::from_be_bytes(flags_bytes.try_into()?));

        let (seqno_bytes, rest) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        body = rest;
        let seqno = SeqNo(u16::from_be_bytes(seqno_bytes.try_into()?));

        let (interval_bytes, sub_tlvs) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        let interval = Interval::from_wire(interval_bytes.try_into()?);

        let stlv_opt = if sub_tlvs.len() > 0 {
            Some(sub_tlvs)
        } else {
            None
        };

        Ok(Self {
            flags,
            seqno,
            interval,
            sub_tlvs: stlv_opt,
        })
    }

    /// Encodes the entire tlv into buf.
    ///
    /// Returns the position of the cursor when it succeeds.
    fn encode<'b>(&self, cursor: &mut ManagedSliceCursor<'b>) -> Result<usize, TlvEncodeError> {
        // Write type id
        cursor.write(&Self::TYPE_ID.to_be_bytes())?;

        // Skip and mark length
        let length_idx = cursor.mark_and_skip::<1>()?;
        let mut length = 0;

        // Write flags.
        length += cursor.write(&self.flags.0.to_be_bytes())?;

        // Write seqno
        length += cursor.write(&self.seqno.0.to_be_bytes())?;

        // Write interval
        length += cursor.write(&(self.interval.as_centis() as u16).to_be_bytes())?;

        // Write sub TLVS
        if let Some(stlv) = self.sub_tlvs {
            length += cursor.write(&stlv)?;
        }

        // Backfill length at the marked location
        cursor.backfill_at(length_idx, &[length as u8])?;

        Ok(cursor.position())
    }
}
