use thiserror::Error;

use crate::{
    data_types::Interval,
    packet::tlv::{TlvEncodeError, TlvHeaderT, TlvParseError},
    utils::cursor::ManagedSliceCursor,
};

/// Acknowledgment request TLV as defined in section
/// [4.6.3](https://datatracker.ietf.org/doc/html/rfc8966#name-acknowledgment-request)
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 2   |    Length     |          Reserved             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             Opaque            |          Interval             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// This TLV requests that the receiver send an Acknowledgment TLV within the number of centiseconds specified by the Interval field.
///
/// NOTE: `Type`, `Length`, and `Reserved` fields are not represented here as they have no value
/// beyond parsing and encoding.
#[derive(Debug)]
pub struct AckReq<'a> {
    /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
    pub opaque: u16,
    /// A time interval in centiseconds after which the sender will assume that this
    /// packet has been lost. This **MUST NOT** be 0. The receiver **MUST** send an Acknowledgment
    /// TLV before this time has elapsed (with a margin allowing for propagation time).
    pub interval: Interval,
    /// This TLV is self-terminating and allows sub-TLVs.
    pub sub_tlvs: Option<&'a [u8]>,
}

impl TlvHeaderT for AckReq<'_> {
    /// Set to 2 to indicate an Acknowledgment Request TLV.
    const TYPE_ID: u8 = 2;
}

impl<'a> AckReq<'a> {
    /// Parses the entire tlv INCLUDING the already checked type field.
    ///
    /// Mutates the buffer as it parses bytes.
    // The reason this takes the `Type` field is for unit testing symetric parse / encode.
    fn parse(input: &mut &'a [u8]) -> Result<Self, TlvParseError> {
        // Parse the header.
        let (_header, mut body, in_remainder) = Self::parse_header(input)?;

        // Now if the remainder of the method fails, the input buffer can still be used.
        *input = in_remainder;

        // Trim and ignore reserved bytes
        let (_reserved_bytes, rest) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        body = rest;

        // Parse opaque bytes
        let (opaque_bytes, rest) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        body = rest;
        let opaque = u16::from_be_bytes(opaque_bytes.try_into()?);

        // Parse interval bytes.
        let (interval_bytes, sub_tlvs) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;

        let interval = Interval::from_wire(interval_bytes.try_into()?);

        if interval.is_zero() {
            return Err(AckReqError::IntervalCannotBeZero)?;
        }

        Ok(Self {
            opaque,
            interval,
            sub_tlvs: Some(sub_tlvs),
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

        // Write reserved this must always be zeros.
        length += cursor.write(&0u16.to_be_bytes())?;

        // Write opaque
        length += cursor.write(&self.opaque.to_be_bytes())?;

        // Write interval
        length += cursor.write(&self.interval.as_wire())?;

        // Write sub TLVS
        if let Some(stlv) = self.sub_tlvs {
            length += cursor.write(&stlv)?;
        }

        // Backfill length at the marked location
        cursor.backfill_at(length_idx, &[length as u8])?;

        Ok(cursor.position())
    }
}

/// These are recoverable errors for AckReq parsing and encoding.
///
/// They are usually some form of receiving a packet that is parsable but is out of spec.
#[derive(Debug, Error)]
pub enum AckReqError {
    #[error("The interval value in AckReq cannot be 0.")]
    IntervalCannotBeZero,
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn decode_and_encode_symmetry_when_reserve_is_zero() {
        // The "when reserve is not zero" case will not be tested as it has no value.
        let mut input: &[u8] = &[AckReq::TYPE_ID, 11, 0, 0, 6, 9, 1, 1, 0, 1, 2, 3, 4];
        let expected = input.to_vec();
        let parsed = AckReq::parse(&mut input).expect("Should parse");
        b_debug!("Parsed: {:?}", parsed);
        let mut output = ManagedSliceCursor::new(Vec::new());

        let written = parsed.encode(&mut output).expect("Should encode");
        assert_ne!(written, 0, "Zero bytes written.");
        assert_eq!(output, expected);
    }
}
