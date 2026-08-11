//! Babel data types as described in section [4.1](https://datatracker.ietf.org/doc/html/rfc8966#name-data-types)

/// Interval as defined in section [4.1.2](https://datatracker.ietf.org/doc/html/rfc8966#name-interval)
pub use crate::utils::time::Duration as Interval;

/// Addresses as described in section [4.1.4 and 4.1.5](https://datatracker.ietf.org/doc/html/rfc8966#name-address)
pub mod address;
