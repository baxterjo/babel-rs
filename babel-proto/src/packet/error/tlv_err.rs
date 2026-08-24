use thiserror::Error;

use crate::packet::error::len_error::LenError;

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlvError {
    #[error("This TLV is a Pad1 TLV, so a header slice cannot be made.")]
    Pad1,
    #[error(transparent)]
    Len(#[from] LenError),
    #[error("Got the wrong type ID for {tlv_name} - expected {expected}, actual: {actual}")]
    WrongType {
        tlv_name: &'static str,
        expected: u8,
        actual: u8,
    },
    #[error("Unrecognized TLV type ID: {0}")]
    UnrecognizedTlvType(u8),
    #[error("Omitted ({omitted}) is larger than the {plen} bit prefix it omits octets from")]
    OmittedTooLong { plen: u8, omitted: u8 },
}
