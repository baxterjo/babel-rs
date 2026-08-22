use thiserror::Error;

pub(crate) mod neighbour_entry;
pub(crate) mod neighbour_table;

pub use neighbour_entry::{Neighbour, NeighbourIndex};
pub use neighbour_table::NeighbourTable;

use crate::data_types::address::AddressError;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::extension::address::AddressExt;
use crate::packet::error::tlv_err::TlvError;
use crate::utils::timer::TimerError;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighbourTableError<A: AddressExt> {
    /// The storage given for the interface table is full.
    #[error("Neighbour table is full")]
    Full,
    /// In this instance the neighbour is still added to the neighbour table, and the index
    /// inside the error is still valid for referencing the neighbour. The user can decide what
    /// they want to do with this error.
    #[error("A neighbour with the same index was added twice: {0}")]
    DuplicateNeighbour(NeighbourIndex<A>),
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error(transparent)]
    AddressEncoding(#[from] AddressEncodingError<A::Encoding>),
    #[error(transparent)]
    Tlv(#[from] TlvError),
    #[error(transparent)]
    Address(#[from] AddressError<A>),
}
