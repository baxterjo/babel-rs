use core::fmt::Debug;

use crate::packet::{
    error::{layer::Layer, len_error::LenError},
    len_source::LenSource,
    packet_header::BabelPacketHeader,
    utils::get_unchecked_be_u16,
};

pub struct PacketHeaderSlice<'a> {
    slice: &'a [u8],
}

impl Debug for PacketHeaderSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketHeaderSlice")
            .field("magic", &self.magic())
            .field("version", &self.version())
            .field("body_length", &self.body_length())
            .field("len", &self.slice.len())
            .finish()
    }
}

impl<'a> PacketHeaderSlice<'a> {
    pub fn from_slice(slice: &'a [u8]) -> Result<Self, LenError> {
        let slice = slice.get(0..BabelPacketHeader::LEN).ok_or(LenError {
            required_len: BabelPacketHeader::LEN,
            len: slice.len(),
            len_source: LenSource::Slice,
            layer: Layer::BabelPacketHeader,
            layer_start_offset: 0,
        })?;

        Ok(Self { slice })
    }

    /// Returns the slice containing the Babel Packet header.
    #[inline]
    pub fn slice(&self) -> &'a [u8] {
        self.slice
    }

    /// Reads the `Magic` field from the slice.
    #[inline]
    pub fn magic(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { *self.slice.get_unchecked(0) }
    }

    /// Reads the `Version` field from the slice.
    #[inline]
    pub fn version(&self) -> u8 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { *self.slice.get_unchecked(1) }
    }

    /// Reads the `Body Length` field from the slice.
    #[inline]
    pub fn body_length(&self) -> u16 {
        // SAFETY:
        // Safe as the constructor checks that the slice has at least the length of the
        // BabelPacketHeader::LEN (4)
        unsafe { get_unchecked_be_u16(self.slice.as_ptr().add(2)) }
    }
}
