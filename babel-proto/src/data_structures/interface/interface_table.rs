use crate::data_structures::interface::{
    Interface, InterfaceConfig, InterfaceError, InterfaceHandle,
};
use crate::extension::address::AddressExt;
use crate::utils::storage::Table;
use crate::utils::{Instant, ManagedSlice};

pub struct InterfaceTable<'storage, A: AddressExt> {
    pub(crate) inner: Table<'storage, InterfaceHandle, Interface<A>>,
}

impl<'storage, A: AddressExt> InterfaceTable<'storage, A> {
    /// Create a new interface table with user provided storage.
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    /// Registers an interface to the interface table.
    ///
    /// Returns an error if the given interface handle has already been registered, or if the
    /// interface table is full.
    pub(crate) fn register_interface(
        &mut self,
        now: Instant,
        config: InterfaceConfig<A>,
    ) -> Result<InterfaceHandle, InterfaceError> {
        b_debug!("Registering interface: {:?}", config);
        if let Some(_iface) = self.inner.get_by_key(&config.id) {
            return Err(InterfaceError::DuplicateInterfaceId(config.id));
        }

        let interface = Interface::new(now, config)?;
        let handle = *interface.handle();

        // Insert into the interface table
        match self.inner.insert(interface) {
            Ok(v) if v.is_some() => {
                // This should be unreachable.
                b_debug!("Duplicate interface registered");
                Err(InterfaceError::DuplicateInterfaceId(handle))
            }
            Ok(_) => Ok(handle),
            Err(_err) => {
                b_debug!("Interface table is full");
                Err(InterfaceError::Full)
            }
        }
    }

    /// Whether the table holds no interfaces at all.
    ///
    /// The backing storage is a slice of `Option`s that may be pre-allocated with empty slots, so
    /// its length says nothing about how many interfaces are registered.
    pub(crate) fn is_empty(&self) -> bool {
        self.inner.iter_slots().all(|slot| slot.is_none())
    }

    /// Whether the given handle refers to a registered interface.
    pub(crate) fn contains(&self, handle: &InterfaceHandle) -> bool {
        self.inner.get_by_key(handle).is_some()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Interface<A>> {
        self.inner.iter()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Interface<A>> {
        self.inner.iter_mut()
    }

    pub(crate) fn iter_mut_filter(
        &mut self,
        poll_only: Option<InterfaceHandle>,
    ) -> impl Iterator<Item = &mut Interface<A>> {
        self.iter_mut()
            .filter(move |iface| poll_only.is_none_or(|p| &p == iface.handle()))
    }

    pub(crate) fn iter_filter(
        &self,
        poll_only: Option<InterfaceHandle>,
    ) -> impl Iterator<Item = &Interface<A>> {
        self.iter()
            .filter(move |iface| poll_only.is_none_or(|p| &p == iface.handle()))
    }
}
