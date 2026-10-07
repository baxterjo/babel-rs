use crate::data_structures::pending_seqno::pending_seqno_entry::SeqnoRequest;
use crate::extension::address::AddressExt;
use crate::utils::ManagedSlice;

pub struct PendingSeqnoRequestTable<'storage, A: AddressExt> {
    inner: ManagedSlice<'storage, Option<SeqnoRequest<A>>>,
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
            inner: table.into(),
        }
    }
}
