use crate::packet::error::len_error::LenError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
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
}
