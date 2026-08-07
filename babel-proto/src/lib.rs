#![cfg_attr(not(any(feature = "std")), no_std)]
//#![cfg_attr(not(any(test, feature = "std")), no_std)]

//#[cfg(not(any(test, feature = "alloc")))]
#[cfg(any(feature = "alloc"))]
extern crate alloc;

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

use core::fmt::{Debug as DebugT, Display};

#[macro_use]
mod macros;

pub mod interface;
pub mod neighbour;
pub mod router;
pub mod source;
pub mod time;

/// Trait wrapper around a generic Address type.
pub trait Address: DebugT + Display + Copy {}
