use core::{hash::Hash, slice::IterMut};

use managed::ManagedSlice;
use thiserror::Error;

use crate::{
    utils::{
        storage::{InternallyKeyed, ManagedSliceExt},
        timer::{Timer, TimerError},
        Duration, Instant,
    },
    InterfaceId,
};

use super::seqno::SeqNo;

/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4;

pub struct InterfaceTable<'storage> {
    inner: ManagedSlice<'storage, Option<Interface>>,
}

impl<'storage> InterfaceTable<'storage> {
    /// Create a new interface table with user provided storage.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Interface>>>,
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

    pub(crate) fn register_interface<I>(
        &mut self,
        now: Instant,
        name: &'static str,
        id: I,
        hello_interval: Option<Duration>,
        update_interval: Option<Duration>,
    ) -> Result<InterfaceHandle, InterfaceTableError>
    where
        I: InterfaceId,
    {
        b_debug!("Registering interface: {}", name);

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
        let iface = Interface::new(name, id, hello_timer, update_timer);
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

    pub(crate) fn iter_mut(&mut self) -> IterMut<'_, Option<Interface>> {
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
    #[error(transparent)]
    Timer(#[from] TimerError),
}

/// An interface handle is used to reference a registered interface for incoming and outgoing
/// operations.
///
/// Users should use this handle to index the interfaces that will speak Babel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct InterfaceHandle([u8; 8]);

/// Interfaces that speak the Babel Protocol
#[derive(Debug, Clone, Copy)]
pub struct Interface {
    /// User defined interface name. Used
    pub(crate) name: &'static str,
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    pub(crate) handle: InterfaceHandle,

    pub(crate) hello_seqno: SeqNo,

    /// How often this interface should send hello messages.
    pub(crate) hello_timer: Timer,

    /// How often this interface should send update messages
    pub(crate) update_timer: Timer,
}

impl InternallyKeyed for Interface {
    type Key = InterfaceHandle;
    fn key(&self) -> Self::Key {
        self.handle
    }
}

impl Interface {
    /// Creates a new babel interface with the given interface ID.
    ///
    /// Returns:
    /// -
    /// - An interface struct that will be used by the BabelRouter to keep track of interface state.
    fn new<I>(name: &'static str, id: I, hello_timer: Timer, update_timer: Timer) -> Self
    where
        I: Into<[u8; 8]>,
    {
        let id: [u8; 8] = id.into();
        let handle = InterfaceHandle(id);

        Self {
            name,
            handle,
            hello_seqno: SeqNo::default(),
            hello_timer,
            update_timer,
        }
    }
}
