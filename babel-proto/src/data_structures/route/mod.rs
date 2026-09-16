use thiserror::Error;

#[doc(hidden)]
pub mod route_entry;
#[doc(hidden)]
pub mod route_table;

#[doc(inline)]
pub use route_entry::{Route, RouteIndex};
#[doc(inline)]
pub use route_table::RouteTable;

use crate::extension::address::AddressExt;
use crate::utils::TimerError;
use crate::utils::storage::InsertError;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RouteError {
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error("Could not get update queue storage for route.")]
    NoStorageAvaliable,
    #[error("Duplicate route in the table")]
    Duplicate,
    #[error("Route table is full")]
    Full,
}

impl<A: AddressExt> From<InsertError<Route<'_, A>>> for RouteError {
    fn from(value: InsertError<Route<'_, A>>) -> Self {
        match value {
            InsertError::Full(_) => RouteError::Full,
            InsertError::Duplicate(_) => RouteError::Duplicate,
        }
    }
}
