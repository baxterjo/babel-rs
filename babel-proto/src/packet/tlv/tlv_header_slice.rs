use crate::packet::{
    error::{layer::Layer, len_error::LenError, tlv_err::TlvError},
    len_source::LenSource,
    tlv::tlv_header::TlvHeader,
};

pub struct TlvHeaderSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TlvHeaderSlice<'a> {
    /// Creates the header slice from the given slice, ensuring the length of the header is long
    /// enough for parsing.
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, TlvError> {
        let type_id = slice.get(0).ok_or(LenError {
            required_len: 0,
            len: slice.len(),
            len_source: LenSource::Slice,
            layer: Layer::BabelTlvHeader,
            layer_start_offset: 0,
        })?;

        if *type_id == 0 {
            return Err(TlvError::Pad1);
        }

        let slice = slice.get(0..TlvHeader::LEN).ok_or(LenError {
            required_len: TlvHeader::LEN,
            len: slice.len(),
            len_source: LenSource::Slice,
            layer: Layer::BabelTlvHeader,
            layer_start_offset: 0,
        })?;

        Ok(Self { slice })
    }

    /// Returns the `Type` field.
    #[inline]
    pub fn r#type(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // TlvHeader::LEN (2)
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Returns the `Length` field.
    #[inline]
    pub fn length(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // TlvHeader::LEN (2)
        unsafe { *self.slice.get_unchecked(1) }
    }
}
