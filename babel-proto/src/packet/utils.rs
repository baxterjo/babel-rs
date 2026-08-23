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
