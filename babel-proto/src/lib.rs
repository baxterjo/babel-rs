#![cfg_attr(not(any(feature = "std")), no_std)]
//#![cfg_attr(not(any(test, feature = "std")), no_std)]

//#[cfg(not(any(test, feature = "alloc")))]
#[cfg(any(feature = "alloc"))]
extern crate alloc;

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

use core::fmt::{Debug as DebugT, Display};
use core::hash::Hash as HashT;
use core::net::Ipv6Addr;

#[macro_use]
mod macros;

pub mod interface;
pub mod neighbour;
pub mod route;
pub mod router;
pub mod source;
mod storage;
pub mod time;

/// Trait wrapper around a generic Address type.
pub trait Address: HashT + DebugT + Display + Copy + Ord + Eq {}

#[cfg(not(feature = "defmt"))]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display {}

#[cfg(feature = "defmt")]
pub trait RouterIdT: DebugT + Into<[u8; 8]> + Display + defmt::Format {}

#[cfg(not(feature = "defmt"))]
pub trait InterfaceId: DebugT + Into<[u8; 8]> + Display {}

#[cfg(feature = "defmt")]
pub trait InterfaceId: DebugT + Into<[u8; 8]> + Display + defmt::Format {}

impl Address for Ipv6Addr {}
