use managed::ManagedMap;

use crate::{router::RouterId, Address};

pub struct SourceTable<'storage, A>
where
    A: Address,
{
    inner: ManagedMap<'storage, SourceIndex<A>, Source<A>>,
}

impl<'storage, A> SourceTable<'storage, A>
where
    A: Address,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of source this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedMap<'storage, SourceIndex<A>, Source<A>>>,
    {
        Self {
            inner: table.into(),
        }
    }

    /// Create a new interface table.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedMap::Owned(Default::default()),
        }
    }
}

#[derive(Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct SourceIndex<A: Address> {
    prefix: A,
    prefix_len: u8,
    router_id: RouterId,
}

pub struct Source<A: Address> {
    prefix: A,
    prefix_len: u8,
    router_id: RouterId,
    seqno: u16,
    metric: u16,
}
