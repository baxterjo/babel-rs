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

pub mod data_structures;
pub mod data_types;
pub mod output;
pub mod router;
pub mod time;

mod storage;

#[cfg(not(feature = "defmt"))]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display {}

#[cfg(feature = "defmt")]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display + defmt::Format {}

#[cfg(not(feature = "defmt"))]
pub trait InterfaceId: DebugT + Into<[u8; 8]> + Display {}

#[cfg(feature = "defmt")]
pub trait InterfaceId: DebugT + Into<[u8; 8]> + Display + defmt::Format {}
