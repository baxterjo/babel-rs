//! Wire format as described in section [4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
//!
//! All packet types in the base spec are low-copy sliced or constructed on demand
//! based on a method inspired by
//! [etherparse](https://docs.rs/etherparse/latest/etherparse/index.html). Types that end in
//! "slice" are read only accessors into incoming packets.:
//! - Constructors of packets perform safety checks on slice length. These slices cannot exist
//!   unless they are safe to access using `unsafe`.
//! - Accessors get field values (via copy) on demand.

pub mod error;
pub mod len_source;
pub mod packet_header;
pub mod packet_header_slice;
pub mod packet_slice;
pub mod parser;
pub mod tlv;
pub mod writer;

pub(crate) mod utils;
