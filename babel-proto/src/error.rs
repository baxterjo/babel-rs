use thiserror::Error;

use crate::{data_structures::interface::InterfaceTableError, packet::error::len_error::LenError};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BabelError {
    #[error(transparent)]
    Len(#[from] LenError),
    #[error(transparent)]
    IfaceTable(#[from] InterfaceTableError),
}
