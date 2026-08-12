pub mod ack;
pub mod ack_req;

use core::{any::type_name, array::TryFromSliceError};

#[doc(inline)]
pub use ack_req::AckReq;
use thiserror::Error;

use ack_req::AckReqError;

use crate::utils::cursor::ManagedSliceCursorError;

pub enum Tlv<'a> {
    Pad1,
    PadN(&'a u8),
    AckReq(AckReq<'a>),
}

pub struct TlvIter<'a> {
    buf: &'a [u8],
}

#[derive(Debug, Error)]
pub enum TlvParseError {
    #[error(transparent)]
    Header(#[from] TlvHeaderError),
    #[error(transparent)]
    AckReq(#[from] AckReqError),
    #[error("The body of the TLV is not long enough.")]
    BodyNotLongEnough,
    #[error(transparent)]
    SliceNotLongEnough(#[from] TryFromSliceError),
}

#[derive(Debug, Error)]
pub enum TlvHeaderError {
    #[error("Buffer is not long enough to contain a header")]
    BufTooSmallForHeader,
    #[error("Unable to parse type field")]
    TypeFieldParseError,
    #[error("Incorrect Type field for {0} - expected: {1} parsed: {2}")]
    TypeFieldIncorrect(&'static str, u8, u8),
    #[error("Unable to parse length field")]
    LengthFieldParseError,
    #[error("Buffer was too small for given length field - delcared len: {0}, actual: {1}")]
    BufferTooSmallForStatedLength(u8, usize),
}

#[derive(Debug, Error)]
pub enum TlvEncodeError {
    #[error(transparent)]
    BufWriteError(#[from] ManagedSliceCursorError),
}

/// Convenience trait for parsing and validating the header of a TLV struct.
pub trait TlvHeaderT {
    /// The type ID of the TLV
    const TYPE_ID: u8;

    /// Parses and splits the header off of the input buffer.
    ///
    /// Validates the type ID and length of the TLV and returns the split of (header, body,
    /// remainder of buffer)
    fn parse_header<'a>(input: &'a [u8]) -> Result<(&'a [u8], &'a [u8], &'a [u8]), TlvHeaderError> {
        let (header_bytes, rest) = input
            .split_at_checked(size_of::<u16>())
            .ok_or(TlvHeaderError::BufTooSmallForHeader)?;

        // This cannot panic because header_bytes is known to be 2 bytes from above split.
        let (type_byte, length_byte) = header_bytes.split_at(size_of::<u8>());

        let type_id = u8::from_be_bytes(
            type_byte
                .try_into()
                .map_err(|_| TlvHeaderError::TypeFieldParseError)?,
        );
        if type_id != Self::TYPE_ID {
            return Err(TlvHeaderError::TypeFieldIncorrect(
                type_name::<Self>(),
                Self::TYPE_ID,
                type_id,
            ));
        }

        let length = u8::from_be_bytes(
            length_byte
                .try_into()
                .map_err(|_| TlvHeaderError::LengthFieldParseError)?,
        );

        let (body, remainder) = rest.split_at_checked(length.into()).ok_or(
            TlvHeaderError::BufferTooSmallForStatedLength(length, rest.len()),
        )?;

        Ok((header_bytes, body, remainder))
    }
}
