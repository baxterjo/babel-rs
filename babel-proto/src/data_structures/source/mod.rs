#[doc(hidden)]
pub(crate) mod source_entry;
#[doc(hidden)]
pub(crate) mod source_table;
#[doc(inline)]
pub(crate) use source_entry::{Source, SourceIndex};
#[doc(inline)]
pub(crate) use source_table::SourceTable;
use thiserror::Error;

use crate::data_types::address::AddressError;
use crate::extension::address::AddressExt;
use crate::utils::TimerError;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SourceError<A: AddressExt> {
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error("Source table is full")]
    Full,
    #[error(transparent)]
    Address(#[from] AddressError<A>),
}
