use managed::ManagedSlice;

use crate::{
    data_types::address::{AddressExtension, RouterAddress},
    router::RouterId,
    utils::storage::InternallyKeyed,
};

use super::seqno::SeqNo;

pub struct SourceTable<'storage, A>
where
    A: AddressExtension,
{
    inner: ManagedSlice<'storage, Option<Source<A>>>,
}

impl<'storage, A> SourceTable<'storage, A>
where
    A: AddressExtension,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of sources this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Source<A>>>>,
    {
        Self {
            inner: table.into(),
        }
    }

    /// Create a new source table.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
        }
    }
}

#[derive(Debug, Hash, PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
pub struct SourceIndex<A: AddressExtension> {
    pub(crate) prefix: RouterAddress<A>,
    pub(crate) prefix_len: u8,
    router_id: RouterId,
}

pub struct Source<A: AddressExtension> {
    prefix: RouterAddress<A>,
    prefix_len: u8,
    router_id: RouterId,
    seqno: SeqNo,
    metric: u16,
}

impl<A: AddressExtension> InternallyKeyed for Source<A> {
    type Key = SourceIndex<A>;
    fn key(&self) -> Self::Key {
        SourceIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            router_id: self.router_id,
        }
    }
}
