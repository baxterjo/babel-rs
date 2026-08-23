//! Babel data types as described in section [4.1](https://datatracker.ietf.org/doc/html/rfc8966#name-data-types)

pub mod interval;

#[doc(inline)]
pub use interval::Interval;

/// Addresses as described in section [4.1.4 and 4.1.5](https://datatracker.ietf.org/doc/html/rfc8966#name-address)
pub mod address;

#[doc(inline)]
pub use address::Address;

pub mod address_encoding;

pub mod router_id;

#[doc(inline)]
pub use router_id::RouterId;
