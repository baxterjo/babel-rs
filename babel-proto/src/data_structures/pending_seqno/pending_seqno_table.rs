use crate::data_structures::pending_seqno::pending_seqno_entry::SeqnoRequest;
use crate::extension::address::AddressExt;
use crate::utils::storage::{InsertError, Table};
use crate::utils::{InternallyKeyed, ManagedSlice};

pub struct PendingSeqnoRequestTable<'storage, A: AddressExt> {
    inner: Table<'storage, Option<SeqnoRequest<A>>>,
}

impl<'storage, A> PendingSeqnoRequestTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new [`PendingSeqnoRequestTable`] with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of [`SeqnoRequest`]s
    /// this Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment.
    pub(crate) fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
    {
        Self {
            inner: Table::new(table),
        }
    }

    pub(crate) fn insert(
        &mut self,
        request: SeqnoRequest<A>,
    ) -> Result<(), InsertError<SeqnoRequest<A>>> {
        // A node SHOULD compare every incoming seqno request against its list of recently forwarded
        // seqno requests and avoid forwarding the request if it is redundant (i.e., if the node has
        // recently sent a request with the same prefix, router-id, and a seqno that is not smaller
        // modulo 216).
        if let Some(existing) = self.inner.get_mut_by_key(&request.key()) {
            if existing.seqno < request.seqno {
                // If there is an existing request and its seqno is less than the new request,
                // replace it.
                *existing = request
                // No sorting is necessary here as the sort keys are proven to be the same.
            }
        } else {
            self.inner.insert(request)?;
        }
        Ok(())
    }
}
