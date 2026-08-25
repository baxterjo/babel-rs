#![cfg_attr(not(any(feature = "std")), no_std)]
//#![cfg_attr(not(any(test, feature = "std")), no_std)]

//#[cfg(not(any(test, feature = "alloc")))]
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

#[macro_use]
mod macros;

pub mod data_structures;
pub mod data_types;
pub mod error;
pub mod extension;
pub mod input;
pub mod metric;
pub mod output;
pub mod packet;
pub mod router;
pub mod utils;

#[cfg(test)]
/// Collection of white box tests that need access to `pub(crate)` visibility.
mod tests;

/// Conditional format trait for when defmt is active.
///
/// This is a blanket implemented bound used throughout the public extension traits, so it is
/// exported to keep those traits nameable by downstream users. It is not meant to be implemented
/// manually.
#[cfg(feature = "defmt")]
pub trait MaybeDefmt: defmt::Format {}
#[cfg(feature = "defmt")]
impl<T: defmt::Format> MaybeDefmt for T {}

/// Conditional format trait for when defmt is active.
///
/// This is a blanket implemented bound used throughout the public extension traits, so it is
/// exported to keep those traits nameable by downstream users. It is not meant to be implemented
/// manually.
#[cfg(not(feature = "defmt"))]
pub trait MaybeDefmt {}
#[cfg(not(feature = "defmt"))]
impl<T> MaybeDefmt for T {}
