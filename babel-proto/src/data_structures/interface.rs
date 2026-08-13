use core::hash::Hash;

use managed::ManagedSlice;
use thiserror::Error;

use crate::{
    data_types::Interval,
    utils::{
        storage::{InternallyKeyed, ManagedSliceExt},
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

    pub fn register_interface<I, H, U>(
        &mut self,
        name: &'static str,
        id: I,
        hello_interval: Option<H>,
        update_interval: Option<U>,
    ) -> Result<InterfaceHandle, InterfaceTableError>
    where
        I: InterfaceId,
        H: Into<Interval>,
        U: Into<Interval>,
    {
        b_debug!("Registering interface: {}", name);
        let iface = Interface::new(name, id, hello_interval, update_interval);
        let handle = iface.handle;
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
    name: &'static str,
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    handle: InterfaceHandle,

    hello_seqno: SeqNo,

    /// How often this interface should send hello messages.
    hello_interval: Interval,
    last_hello: Option<Instant>,

    /// How often this interface should send update messages
    update_interval: Interval,
    last_update: Option<Instant>,
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
    fn new<I, H, U>(
        name: &'static str,
        id: I,
        hello_interval: Option<H>,
        update_interval: Option<U>,
    ) -> Self
    where
        I: Into<[u8; 8]>,
        H: Into<Interval>,
        U: Into<Interval>,
    {
        let id: [u8; 8] = id.into();
        let handle = InterfaceHandle(id);

        Self {
            name,
            handle,
            hello_seqno: SeqNo::default(),
            hello_interval: hello_interval.map_or(
                Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS).into(),
                |h| h.into(),
            ),
            last_hello: None,
            update_interval: update_interval.map_or(
                Duration::from_secs(DEFAULT_UPDATE_INTERVAL_SECS).into(),
                |u| u.into(),
            ),
            last_update: None,
        }
    }
}
