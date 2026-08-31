use thiserror::Error;

#[doc(hidden)]
pub mod route_entry;
#[doc(hidden)]
pub mod route_table;

#[doc(inline)]
pub use route_entry::{Route, RouteIndex};
#[doc(inline)]
pub use route_table::RouteTable;

use crate::utils::TimerError;

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum RouteError {
    #[error(transparent)]
    Timer(#[from] TimerError),
}
