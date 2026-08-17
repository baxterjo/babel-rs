pub mod tlv_header;
pub mod tlv_header_slice;
pub mod tlv_slice;

#[doc(hidden)]
pub mod ack_req_slice;
#[doc(hidden)]
pub mod ack_slice;
#[doc(hidden)]
pub mod hello_slice;
#[doc(hidden)]
pub mod ihu_slice;

use core::any::type_name;

//#[doc(inline)]
//pub use ack_req::AckReq;
//
//#[doc(inline)]
//pub use ack::Ack;

#[doc(inline)]
pub use hello_slice::HelloSlice;

use crate::packet::{
    error::{layer::Layer, len_error::LenError, tlv_err::TlvError},
    len_source::LenSource,
    tlv::tlv_slice::TlvSlice,
};

//#[derive(Debug, Error)]
//pub enum TlvParseError {
//    // Non recoverable errors
//    #[error(transparent)]
//    Header(#[from] TlvHeaderError),
//    #[error("The body of the TLV is not long enough.")]
//    BodyNotLongEnough,
//    #[error(transparent)]
//    SliceNotLongEnough(#[from] TryFromSliceError),
//    // Recoverable errors
//    #[error(transparent)]
//    AckReq(#[from] AckReqError),
//    #[error(transparent)]
//    AeDecodeError(#[from] AddressDecodeError),
//}
//
//#[derive(Debug, Error)]
//pub enum TlvHeaderError {
//    #[error("Buffer is not long enough to contain a header")]
//    BufTooSmallForHeader,
//    #[error("Unable to parse type field")]
//    TypeFieldParseError,
//    #[error("Incorrect Type field for {0} - expected: {1} parsed: {2}")]
//    TypeFieldIncorrect(&'static str, u8, u8),
//    #[error("Unable to parse length field")]
//    LengthFieldParseError,
//    #[error("Buffer was too small for given length field - delcared len: {0}, actual: {1}")]
//    BufferTooSmallForStatedLength(u8, usize),
//}
//
//#[derive(Debug, Error)]
//pub enum TlvEncodeError {
//    #[error(transparent)]
//    BufWriteError(#[from] ManagedSliceCursorError),
//}
//
///// Convenience trait for parsing and validating the header of a TLV struct.
//pub trait TlvHeaderT {
//    /// The type ID of the TLV
//    const TYPE_ID: u8;
//
//    /// Parses and splits the header off of the input buffer.
//    ///
//    /// Validates the type ID and length of the TLV and returns the split of (header, body,
//    /// remainder of buffer)
//    fn parse_header<'a>(input: &'a [u8]) -> Result<(&'a [u8], &'a [u8], &'a [u8]), TlvHeaderError> {
//        let (header_bytes, rest) = input
//            .split_at_checked(size_of::<u16>())
//            .ok_or(TlvHeaderError::BufTooSmallForHeader)?;
//
//        // This cannot panic because header_bytes is known to be 2 bytes from above split.
//        let (type_byte, length_byte) = header_bytes.split_at(size_of::<u8>());
//
//        let type_id = u8::from_be_bytes(
//            type_byte
//                .try_into()
//                .map_err(|_| TlvHeaderError::TypeFieldParseError)?,
//        );
//        if type_id != Self::TYPE_ID {
//            return Err(TlvHeaderError::TypeFieldIncorrect(
//                type_name::<Self>(),
//                Self::TYPE_ID,
//                type_id,
//            ));
//        }
//
//        let length = u8::from_be_bytes(
//            length_byte
//                .try_into()
//                .map_err(|_| TlvHeaderError::LengthFieldParseError)?,
//        );
//
//        let (body, remainder) = rest.split_at_checked(length.into()).ok_or(
//            TlvHeaderError::BufferTooSmallForStatedLength(length, rest.len()),
//        )?;
//
//        Ok((header_bytes, body, remainder))
//    }
//}
//

/// Trait that defines a TLV with a known `Type` value and structure.
///
// IMPORTANT: When accessing fields **BEYOND** TlvHeader::LEN + Self::MIN_LEN, all accessors MUST
// be checked and safe. These constructors DO NOT guarantee safety beyond that point.
pub trait TypedTlv<'a>: Sized
where
    Self: 'a,
{
    /// The type identifier of the TLV.
    const TYPE_ID: u8;
    /// The minimum length that the TLV could be exclusive of type and length fields.
    ///
    /// This is also the minimum value that could appear in the `Length` field.
    ///
    /// This is minimum because some packets use address compression and have variable size.
    const MIN_LEN: usize;

    /// Converts the untyped TlvSlice into a typed slice. After checking the slice has at least the
    /// minimum length to be that Tlv.
    fn from_untyped(raw: TlvSlice<'a>) -> Result<Self, TlvError> {
        let raw_type = raw.r#type();

        if raw_type != Self::TYPE_ID {
            return Err(TlvError::WrongType {
                tlv_name: type_name::<Self>(),
                expected: Self::TYPE_ID,
                actual: raw_type,
            });
        }

        let length: usize = raw.length().into();
        if length < Self::MIN_LEN {
            Err(LenError {
                required_len: Self::MIN_LEN,
                len: length,
                len_source: LenSource::BabelTlvBodyLength,
                layer: Layer::BabelTlvBody,
                layer_start_offset: 0,
            })?;
        }

        Ok(Self::from_slice_unchecked(raw.slice()))
    }

    fn slice(&self) -> &'a [u8];

    /// This method needs to be implemented to store a slice in the TLV.
    ///
    /// The method should never be called directly by users and will only be called by
    /// `<Self as TypedTlv>::from_slice()`. It can be assumed that length checks have been done on
    /// the slice before this function has been called.
    fn from_slice_unchecked(slice: &'a [u8]) -> Self;
}
