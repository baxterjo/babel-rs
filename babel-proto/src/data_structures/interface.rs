use core::fmt::Display;
use core::hash::Hash;

use thiserror::Error;

use super::seqno::SeqNo;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::utils::rx_cost::RxCost;
use crate::utils::short_id::fmt_short_id;
use crate::utils::storage::{InternallyKeyed, ManagedSliceExt};
use crate::utils::timer::{Timer, TimerError};
use crate::utils::{Duration, Instant, ManagedSlice};

/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
pub const DEFAULT_MULTICAST_HELLO_INTERVAL: Duration =
    Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS);
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4;

pub struct InterfaceTable<'storage, A: AddressExt> {
    pub(crate) inner: ManagedSlice<'storage, Option<Interface<A>>>,
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl<A: AddressExt> Default for InterfaceTable<'_, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'storage, A: AddressExt> InterfaceTable<'storage, A> {
    /// Create a new interface table with user provided storage.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
    {
        Self {
            inner: table.into(),
        }
    }

    /// Create a new interface table.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
        }
    }

    pub(crate) fn register_interface(
        &mut self,
        now: Instant,
        handle: InterfaceHandle,
        address: Address<A>,
        hello_interval: Option<Duration>,
        update_interval: Option<Duration>,
    ) -> Result<InterfaceHandle, InterfaceTableError> {
        b_debug!("Registering interface: {}", handle);

        // Create hello timer that fires immediately.
        let hello_timer = Timer::new_eager(
            now,
            hello_interval
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS)),
        )?;
        // Update should not fire immediately as the router does not have a route table for this
        // interface.
        let update_timer = Timer::new(
            now,
            update_interval.unwrap_or_else(|| Duration::from_secs(DEFAULT_UPDATE_INTERVAL_SECS)),
        )?;
        // Create the new interface
        let iface: Interface<A> = Interface::new(handle, address, hello_timer, update_timer);
        let handle = iface.handle;

        // Insert into the interface table
        match self.inner.insert(iface) {
            Ok(v) if v.is_some() => {
                b_debug!("Duplicate interface registered");
                Err(InterfaceTableError::DuplicateInterfaceId(handle))
            }
            Ok(_) => Ok(handle),
            Err(_err) => {
                b_debug!("Interface table is full");
                Err(InterfaceTableError::Full)
            }
        }
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Interface<A>> {
        self.inner.iter_mut().filter_map(|v| v.as_mut())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceTableError {
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

/// An interface handle is used to reference a registered interface for incoming and outgoing
/// operations.
///
/// Users should use this handle to index the interfaces that will speak Babel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceHandle([u8; 8]);

impl TryFrom<&str> for InterfaceHandle {
    type Error = InterfaceTableError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > 8 {
            return Err(InterfaceTableError::IdTooLong { len: value.len() });
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

/// Interfaces that speak the Babel Protocol
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Interface<A: AddressExt> {
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    pub(crate) handle: InterfaceHandle,

    pub(crate) hello_seqno: SeqNo,

    /// How often this interface should send hello messages.
    pub(crate) hello_timer: Timer,

    /// How often this interface should send update messages
    pub(crate) update_timer: Timer,

    /// User configuration
    pub(crate) config: InterfaceConfig<A>,
}

impl<A: AddressExt> InternallyKeyed for Interface<A> {
    type Key = InterfaceHandle;
    fn key(&self) -> Self::Key {
        self.handle
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceConfig<A: AddressExt> {
    pub(crate) unicast_ihu: bool,
    pub(crate) address: Address<A>,
    pub(crate) starting_rx_cost: RxCost,
}

impl<A: AddressExt> InterfaceConfig<A> {
    pub fn new(address: Address<A>) -> Self {
        Self {
            unicast_ihu: false,
            address,
            starting_rx_cost: RxCost(10),
        }
    }
}

impl<A: AddressExt> Interface<A> {
    /// Creates a new babel interface with the given interface ID.
    ///
    /// Returns:
    fn new(
        handle: InterfaceHandle,
        address: Address<A>,
        hello_timer: Timer,
        update_timer: Timer,
    ) -> Self {
        Self {
            handle,
            hello_seqno: SeqNo::default(),
            hello_timer,
            update_timer,
            config: InterfaceConfig::new(address),
        }
    }
}
