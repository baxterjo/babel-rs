use crate::data_types::RouterId;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::utils::ManagedSlice;
use crate::utils::storage::{InternallyKeyed, Table};

pub struct SourceTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: Table<'storage, SourceIndex<A>, Source<A>>,
}

impl<'storage, A> SourceTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of sources this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Source<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }
}

impl<A: AddressExt> SourceTable<'_, A> {
    /// This is a read only check to see if an incoming update is feasible. The source table will
    /// be updated when updates are sent to neighbours.
    pub fn is_feasible(&self, idx: &SourceIndex<A>, metric: Metric, seqno: SeqNo) -> bool {
        // If the update is a retraction then it is automatically feasible.
        if metric == Metric::INFINITY {
            return true;
        }
        // If the table does not contain the source, then the update is automatically feasible.
        let Some(source) = self.inner.get_by_key(idx) else {
            return true;
        };

        // Otherwise, check against the best feasibility ever seen.
        let incoming_feasibility = Feasibility::new(seqno, metric);
        incoming_feasibility < source.feasibility
    }
}

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SourceIndex<A: AddressExt> {
    pub(crate) router_id: RouterId,
    pub(crate) prefix: Address<A>,
    pub(crate) prefix_len: u8,
}

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Source<A: AddressExt> {
    prefix: Address<A>,
    prefix_len: u8,
    router_id: RouterId,
    feasibility: Feasibility,
}

impl<A: AddressExt> InternallyKeyed for Source<A> {
    type Key = SourceIndex<A>;
    fn key(&self) -> Self::Key {
        SourceIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            router_id: self.router_id,
        }
    }
}
