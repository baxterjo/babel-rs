use core::array::TryFromSliceError;
use thiserror::Error;

use crate::packet::tlv::ack_req::AckReqError::WrongTypeField;

/// Acknowledgment request packet as defined in section
/// [4.6.3](https://datatracker.ietf.org/doc/html/rfc8966#name-acknowledgment-request)
pub struct AckReq<'a> {
    /// The length of the body in octets, exclusive of the Type and Length fields.
    _length: u8,
    /// Sent as 0 and **MUST** be ignored on reception.
    _reserved: u16,
    /// An arbitrary value that will be echoed in the receiver's Acknowledgment TLV.
    pub opaque: u16,
    /// A time interval in centiseconds after which the sender will assume that this
    /// packet has been lost. This **MUST NOT** be 0. The receiver **MUST** send an Acknowledgment
    /// TLV before this time has elapsed (with a margin allowing for propagation time).
    pub interval: u16,
    /// This TLV is self-terminating and allows sub-TLVs.
    pub sub_tlvs: &'a [u8],
}

impl<'a> AckReq<'a> {
    /// 4.6.3-4.2: Set to 2 to indicate an Acknowledgment Request TLV.
    const TYPE_ID: u8 = 2;

    /// Length of the known fields exlusive of type and length fields. Convenience for calculating
    /// length field.
    const LENGTH_OF_KNOWN_FIELDS: u8 =
        (size_of::<u16>() + size_of::<u16>() + size_of::<u16>()) as u8;

    /// Parses the entire tlv INCLUDING the already checked type field.
    ///
    /// Mutates the buffer as it parses bytes.
    // The reason this takes the type field is for unit testing symetric parse / encode.
    fn parse(input: &mut &'a [u8]) -> Result<Self, AckReqError> {
        let (_type_bytes, rest) = input.split_at(size_of::<u8>());
        *input = rest;

        // First get the length
        let (length_bytes, rest) = input.split_at(size_of::<u8>());
        *input = rest;
        let length = u8::from_be_bytes(
            length_bytes
                .try_into()
                .map_err(|_| AckReqError::CouldNotParseLength)?,
        );

        // Now split off the TLV from the buffer.
        let (mut tlv_bytes, rest) = input.split_at(length as usize);

        // Now if the remainder of the method fails, the input buffer can still be used.
        *input = rest;

        // Parse reserved bytes
        let (reserved_bytes, rest) = tlv_bytes.split_at(size_of::<u16>());
        tlv_bytes = rest;
        let reserved = u16::from_be_bytes(reserved_bytes.try_into()?);

        // Parse opaque bytes
        let (opaque_bytes, rest) = tlv_bytes.split_at(size_of::<u16>());
        tlv_bytes = rest;
        let opaque = u16::from_be_bytes(opaque_bytes.try_into()?);

        // Parse interval bytes.
        let (interval_bytes, sub_tlvs) = tlv_bytes.split_at(size_of::<u16>());
        let interval = u16::from_be_bytes(interval_bytes.try_into()?);

        if interval == 0 {
            return Err(AckReqError::IntervalCannotBeZero);
        }

        Ok(Self {
            _length: length,
            _reserved: reserved,
            opaque,
            interval,
            sub_tlvs,
        })
    }

    /// Encodes the entire tlv into buf.
    fn encode(&self, mut buf: &mut [u8]) -> Result<usize, (usize, AckReqError)> {
        let mut encoded = 0usize;
        let length = Self::LENGTH_OF_KNOWN_FIELDS + self.sub_tlvs.len() as u8;

        // Write type id
        encoded += buf
            .write_all(&Self::TYPE_ID.to_be_bytes())
            .map_err(|io| (encoded, AckReqError::from(io)))?;

        // Write length.
        encoded += buf
            .write_all(&length.to_be_bytes())
            .map_err(|io| (encoded, AckReqError::from(io)))?;

        // Write reserved
        encoded += buf
            .write_all(&0u16.to_be_bytes())
            .map_err(|io| (encoded, AckReqError::from(io)))?;

        // Write interval
        encoded += buf
            .write_all(&self.interval.to_be_bytes())
            .map_err(|io| (encoded, AckReqError::from(io)))?;

        // Write sub TLVS
        encoded += buf
            .write_all(self.sub_tlvs)
            .map_err(|io| (encoded, AckReqError::from(io)))?;

        Ok(encoded)
    }
}

#[derive(Debug, Error)]
pub enum AckReqError {
    #[error("The type for AckReq is 2")]
    WrongTypeField,
    #[error("The interval value in AckReq cannot be 0.")]
    IntervalCannotBeZero,
    /// The entire packet (not just this TLV) needs to be thrown away if this happens.
    #[error("Could not parse the packet length from the header.")]
    CouldNotParseLength,
    #[error(transparent)]
    SliceNotLongEnough(#[from] TryFromSliceError),
    #[error(transparent)]
    WritingToBuf(#[from] std::io::Error),
}

mod test {
    use super::*;
    #[test]
    fn decode_and_encode_symmetry() {
        let mut input: &[u8] = &[AckReq::TYPE_ID, 11, 0, 0, 6, 9, 1, 1, 0, 1, 2, 3, 4];
        let expected = input.to_vec();
        let req = AckReq::parse(&mut input).expect("Should parse");
        let mut output = Vec::new();
        let written = req.encode(&mut output).expect("Should encode");
        assert_ne!(written, 0, "Zero bytes written.");
        assert_eq!(output, expected);
    }
}
