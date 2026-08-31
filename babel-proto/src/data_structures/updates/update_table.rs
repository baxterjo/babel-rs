use crate::data_structures::updates::{Update, UpdateError};
use crate::extension::address::AddressExt;
use crate::utils::ManagedSlice;

/// Table for storing the state of triggered updates.
pub(crate) struct UpdateTable<'storage, A: AddressExt> {
    inner: ManagedSlice<'storage, Option<Update<A>>>,
}

impl<'storage, A: AddressExt> UpdateTable<'storage, A> {
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            inner: storage.into(),
        }
    }

    /// Adds an update destined to a neibour.
    ///
    /// Duplicate updates will silently overwrite old ones. This is by design, a freshly triggered
    /// route udpate **SHOULD** supercede a stale one.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        self.inner
            .insert(update)
            .map_err(|_| UpdateError::UpdateTableFull)?;
        Ok(())
    }
}
