#[doc(hidden)]
pub(crate) mod source_entry;
#[doc(hidden)]
pub(crate) mod source_table;
#[doc(inline)]
pub(crate) use source_entry::{Source, SourceIndex};
#[doc(inline)]
pub(crate) use source_table::SourceTable;
use thiserror::Error;

use crate::utils::TimerError;

#[derive(Debug, Error)]
pub enum SourceError {
    #[error(transparent)]
    Timer(#[from] TimerError),
}
