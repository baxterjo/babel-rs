use crate::packet::tlv::TypedTlv;

/// PadN TLV as defined in section
/// [4.6.2](https://datatracker.ietf.org/doc/html/rfc8966#name-padn)
///
/// Note: Pad1 is a different type that does not have a length field. So it does not have a
/// struct representation via `Pad1Slice`.
///
/// ```sh
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Type = 1   |    Length     |      MBZ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
/// ```
///
/// This TLV is silently ignored on reception. It is allowed in the packet trailer.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PadNSlice<'a> {
    slice: &'a [u8],
}

impl<'a> TypedTlv<'a> for PadNSlice<'a> {
    const TYPE_ID: u8 = 1;
    const MIN_LEN: usize = 0;
    fn slice(&self) -> &'a [u8] {
        self.slice
    }
    fn from_slice_unchecked(slice: &'a [u8]) -> Self {
        Self { slice }
    }
}
