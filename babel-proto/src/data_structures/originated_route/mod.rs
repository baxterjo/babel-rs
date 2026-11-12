use thiserror::Error;

use crate::data_structures::originated_route::originated_route_entry::OriginatedRoute;
use crate::extension::address::AddressExt;
use crate::utils::storage::InsertError;

#[doc(hidden)]
pub mod originated_route_entry;
#[doc(hidden)]
pub mod originated_route_table;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum OriginatedRouteError {
    #[error("Duplicate route in the table")]
    Duplicate,
    #[error("Route table is full")]
    Full,
}

impl<A: AddressExt> From<InsertError<OriginatedRoute<A>>> for OriginatedRouteError {
    fn from(value: InsertError<OriginatedRoute<A>>) -> Self {
        match value {
            InsertError::Full(_) => OriginatedRouteError::Full,
            InsertError::Duplicate(_) => OriginatedRouteError::Duplicate,
        }
    }
}
