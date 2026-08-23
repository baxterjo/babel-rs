/// Helper function for reading big endian u16 values from a ptr unchecked.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure there are at least 2
/// bytes accessable via the ptr. If this is not the case undefined behavior
/// will be triggered.
#[inline]
pub(crate) unsafe fn get_unchecked_be_u16(ptr: *const u8) -> u16 {
    unsafe { u16::from_be_bytes([*ptr, *ptr.add(1)]) }
}

/// Helper function for reinterpreting a slice as a fixed size array without a length check.
///
/// # Safety
///
/// It is in the responsibility of the caller to ensure `slice.len() == N`. If this is not the case
/// undefined behavior will be triggered.
#[inline]
pub(crate) unsafe fn slice_to_array<const N: usize>(slice: &[u8]) -> &[u8; N] {
    unsafe { &*(slice.as_ptr() as *const [u8; N]) }
}
