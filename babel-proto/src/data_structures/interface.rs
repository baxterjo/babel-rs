use core::{fmt::Display, hash::Hash, slice::IterMut};

use managed::ManagedSlice;
use thiserror::Error;

use crate::{
    data_types::Address,
    extension::address::AddressExt,
    utils::{
        rx_cost::RxCost,
        storage::{InternallyKeyed, ManagedSliceExt},
        timer::{Timer, TimerError},
        Duration, Instant,
    },
};

use super::seqno::SeqNo;

/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4;

pub struct InterfaceTable<'storage, A: AddressExt> {
    pub(crate) inner: ManagedSlice<'storage, Option<Interface<A>>>,
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
        // Update should not fire immediately as the router does not have a route table for this interface.
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

    pub(crate) fn iter_mut(&mut self) -> IterMut<'_, Option<Interface<A>>> {
        self.inner.iter_mut()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
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
    #[error(transparent)]
    Timer(#[from] TimerError),
}

/// An interface handle is used to reference a registered interface for incoming and outgoing
/// operations.
///
/// Users should use this handle to index the interfaces that will speak Babel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
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
        let start = self.0.iter().position(|&b| b != 0).unwrap_or(self.0.len());
        let trimmed = &self.0[start..];

        let displayable = trimmed.iter().all(|&b| b.is_ascii_graphic() || b == b' ');

        if displayable {
            // Known to be displayable due to above check.
            f.write_str(core::str::from_utf8(trimmed).unwrap_or(""))
        } else {
            for (idx, b) in self.0.iter().enumerate() {
                if idx != self.0.len() - 1 {
                    write!(f, "x{:02X} ", b)?;
                } else {
                    write!(f, "x{:02X}", b)?;
                }
            }
            Ok(())
        }
    }
}

/// Interfaces that speak the Babel Protocol
#[derive(Debug, Clone, Copy)]
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
