#![cfg_attr(not(any(feature = "std")), no_std)]
//#![cfg_attr(not(any(test, feature = "std")), no_std)]

//#[cfg(not(any(test, feature = "alloc")))]
#[cfg(any(feature = "alloc"))]
extern crate alloc;

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

#[macro_export]
mod macros;

mod router;
