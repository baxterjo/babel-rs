use core::fmt::Debug;

use crate::packet::{
    error::{layer::Layer, len_error::LenError, tlv_err::TlvError},
    len_source::LenSource,
    tlv::{tlv_header::TlvHeader, tlv_header_slice::TlvHeaderSlice, TypedTlv},
};

/// A slice containing the header and payload of a TLV.
///
/// The constructor of this struct guarantees:
///  - The TLV is not a Pad1
///  - The slice is at least as long as the TLV header claims it is.
pub struct TlvSlice<'a> {
    slice: &'a [u8],
}

impl Debug for TlvSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlvSlice")
            .field("type", &self.r#type())
            .field("length", &self.length())
            .finish()
    }
}

impl<'a> TlvSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, TlvError> {
        let header = TlvHeaderSlice::from_slice(slice)?;

        let length: usize = header.length().into();

        // Get and check the length of the slice.
        let slice = slice.get(0..length + TlvHeader::LEN).ok_or(LenError {
            required_len: length,
            len: slice.len(),
            len_source: LenSource::BabelTlvBodyLength,
            layer: Layer::BabelTlvBody,
            layer_start_offset: 0,
        })?;

        Ok(Self { slice })
    }

    pub fn from_typed<T: TypedTlv<'a>>(typed: &'a T) -> Self {
        Self {
            slice: typed.slice(),
        }
    }

    pub fn r#type(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks to make sure there is at least TlvHeader::Len (2)
        unsafe { *self.slice.get_unchecked(0) }
    }

    pub fn length(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks to make sure there is at least TlvHeader::Len (2)
        unsafe { *self.slice.get_unchecked(1) }
    }

    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }
}

// Typed TLV's can only ever be constructed from an `TlvSlice`. So it is safe to put the slice
// directly back into `TlvSlice` without doing any length checks.
impl<'a, T: TypedTlv<'a>> From<T> for TlvSlice<'a> {
    fn from(value: T) -> Self {
        Self {
            slice: value.slice(),
        }
    }
}
