use crate::data_structures::updates::{Update, UpdateError, UpdateIndex};
use crate::extension::address::AddressExt;
use crate::utils::storage::Table;
use crate::utils::{InternallyKeyed, ManagedSlice};

/// Table for storing the state of triggered updates.
pub(crate) struct UpdateTable<'storage, A: AddressExt> {
    inner: Table<'storage, UpdateIndex<A>, Update<A>>,
}

impl<'storage, A: AddressExt> UpdateTable<'storage, A> {
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    /// Adds an update destined to a neibour.
    ///
    /// Duplicate updates will silently overwrite old ones. This is by design, a freshly triggered
    /// route udpate **SHOULD** supercede a stale one.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        if let Some(existing_update) = self.inner.get_by_key(&update.key())
            && existing_update.retry_count > update.retry_count
        {
            // If the exising retry count is higher than the incoming retry count then we can
            // assume a higher priority update is in progress.
            return Ok(());
        } else {
            // Otherwise either the update didn't exist or can be overwritten.
            self.inner
                .insert(update)
                .map_err(|_| UpdateError::UpdateTableFull)?;
        }

        Ok(())
    }
}
