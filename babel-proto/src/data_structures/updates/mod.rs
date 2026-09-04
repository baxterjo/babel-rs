use thiserror::Error;

#[doc(hidden)]
pub mod update_entry;
#[doc(hidden)]
pub mod update_table;

#[doc(inline)]
pub(crate) use update_entry::Update;
#[doc(inline)]
pub(crate) use update_table::UpdateTable;

use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::utils::TimerError;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum UpdateError {
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error("Triggered update table is full")]
    UpdateTableFull,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct UpdateIndex<A: AddressExt> {
    pub(crate) prefix: Address<A>,
    pub(crate) prefix_len: u8,
    pub(crate) neighbour: NeighbourIndex<A>,
}
