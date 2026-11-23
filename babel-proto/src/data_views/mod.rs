//! Views that span more than one of Babel's data structures.
//!
//! The data structures in [`crate::data_structures`] each own one table. Some questions can only
//! be answered by looking at several of them together, and the types here give those questions a
//! single place to live.

#[doc(hidden)]
pub mod all_routes;

#[doc(inline)]
pub(crate) use all_routes::{AllRoutes, AllRoutesMut, AnyRoute, LocalOrigin, Selection};
