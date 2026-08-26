use core::fmt::Display;

use thiserror::Error;

#[doc(hidden)]
pub mod config;
#[doc(hidden)]
pub mod interface_entry;
pub(crate) mod interface_table;

#[doc(inline)]
pub use config::InterfaceConfig;
#[doc(inline)]
pub use interface_entry::Interface;
pub(crate) use interface_table::InterfaceTable;

use crate::data_types::Interval;
use crate::utils::short_id::fmt_short_id;
use crate::utils::{Duration, TimerError};

const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL: Interval =
    Interval::from_duration(Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS));
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(
    DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4,
));

/// An interface handle is used to reference a registered interface f:willor incoming and outgoing
/// operations.
///
/// Users should use this handle to index the interfaces that will speak Babel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceHandle([u8; 8]);

impl TryFrom<&str> for InterfaceHandle {
    type Error = InterfaceError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > 8 {
            return Err(InterfaceError::IdTooLong { len: value.len() });
        }
        // At this point value is known to be <= 8 bytes.
        let in_bytes = value.as_bytes();
        let mut id_bytes = [0u8; 8];

        for (idx, byte) in in_bytes.iter().rev().enumerate() {
            id_bytes[id_bytes.len() - 1 - idx] = *byte;
        }
        Ok(Self(id_bytes))
    }
}

impl Display for InterfaceHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_short_id(&self.0, f)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceError {
    /// The storage given for the interface table is full.
    #[error("Interface table is full")]
    Full,
    /// In this instance the interface is still registered in the interface table, and the handle
    /// inside the error is still valid for referencing the interface. The user can decide what
    /// they want to do with this error.
    #[error("An interface with the same ID was registered twice.")]
    DuplicateInterfaceId(InterfaceHandle),
    #[error("Given interface ID is too long - max: 8, len: {}", len)]
    IdTooLong { len: usize },
    /// The router was polled before any interface was registered, so it has nothing it could
    /// ever send.
    #[error("No interfaces are registered")]
    NoInterfacesRegistered,
    #[error(transparent)]
    Timer(#[from] TimerError),
}
