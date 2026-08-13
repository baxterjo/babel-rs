use crate::{
    packet::tlv::{AckReq, TlvEncodeError, TlvHeaderT, TlvParseError},
    utils::cursor::ManagedSliceCursor,
};

/// Acknowledgement TLV as defined in section
/// [4.6.4](https://datatracker.ietf.org/doc/html/rfc8966#name-acknowledgment)
///
/// Since Opaque values are not globally unique, this TLV **MUST** be sent to a unicast address.
///
/// NOTE: `Type` and `Length` fields are not represented here as they have no value beyond parsing
/// and encoding.
#[derive(Debug)]
pub struct Ack<'a> {
    /// Set to the Opaque value of the Acknowledgment Request that prompted this Acknowledgment.
    opaque: u16,

    /// This TLV is self-terminating and allows sub-TLVs.
    sub_tlvs: Option<&'a [u8]>,
}

impl TlvHeaderT for Ack<'_> {
    /// Set to 3 to indicate an Acknowledgment TLV.
    const TYPE_ID: u8 = 3;
}

impl<'a> Ack<'a> {
    /// Parses the entire tlv INCLUDING the already checked type field.
    ///
    /// Mutates the buffer as it parses bytes.
    // The reason this takes the `Type` field is for unit testing symetric parse / encode.
    fn parse(input: &mut &'a [u8]) -> Result<Self, TlvParseError> {
        let (_headers, body, remainder) = Self::parse_header(input)?;

        *input = remainder;

        // Parse opaque
        let (opaque_bytes, sub_tlvs) = body
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvParseError::BodyNotLongEnough)?;
        let opaque = u16::from_be_bytes(opaque_bytes.try_into()?);

        let stlv_opt = if sub_tlvs.len() > 0 {
            Some(sub_tlvs)
        } else {
            None
        };

        Ok(Self {
            opaque,
            sub_tlvs: stlv_opt,
        })
    }

    /// Encodes the entire tlv into buf.
    ///
    /// Returns the position of the cursor when it succeeds.
    fn encode<'b>(&self, cursor: &mut ManagedSliceCursor<'b>) -> Result<usize, TlvEncodeError> {
        cursor.write(&Self::TYPE_ID.to_be_bytes())?;

        let len_idx = cursor.mark_and_skip::<1>()?;
        let mut length = 0;

        length += cursor.write(&self.opaque.to_be_bytes())?;

        if let Some(stlv) = self.sub_tlvs {
            length += cursor.write(&stlv)?;
        }

        cursor.backfill_at(len_idx, &[length as u8])?;

        Ok(cursor.position())
    }
}

impl From<AckReq<'_>> for Ack<'_> {
    fn from(value: AckReq<'_>) -> Self {
        Self {
            opaque: value.opaque,
            sub_tlvs: None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn decode_and_encode_symmetry() {
        let mut input: &[u8] = &[Ack::TYPE_ID, 11, 6, 9, 0, 0, 1, 1, 0, 1, 2, 3, 4];
        let expected = input.to_vec();
        let req = Ack::parse(&mut input).expect("Should parse");
        b_debug!("Parsed: {:?}", req);
        let mut output = ManagedSliceCursor::new(Vec::new());

        let written = req.encode(&mut output).expect("Should encode");
        assert_ne!(written, 0, "Zero bytes written.");
        assert_eq!(output, expected);
    }
}
