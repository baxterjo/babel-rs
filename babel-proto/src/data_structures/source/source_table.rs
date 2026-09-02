use crate::data_structures::route::Route;
use crate::data_structures::source::source_entry::SPEC_DEFAULT_SOURCE_GC_TIME;
use crate::data_structures::source::{Source, SourceError, SourceIndex};
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::utils::storage::Table;
use crate::utils::{Instant, ManagedSlice};

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

    /// Source table maintenance as described in
    /// [Section 3.7.3](https://datatracker.ietf.org/doc/html/rfc8966#name-maintaining-feasibility-dis)
    pub(crate) fn perform_maintenance(
        &mut self,
        now: Instant,
        route: &Route<A>,
    ) -> Result<(), SourceError> {
        if route.computed_metric == Metric::INFINITY {
            return Ok(());
        }

        let Some(source) = self.inner.get_mut_by_key(route.source()) else {
            // Just checked if there was something in the table.
            let _ = self.inner.insert(Source::new(
                now,
                route.source().prefix,
                route.source().prefix_len,
                route.source().router_id,
                route.seqno,
                route.computed_metric,
                SPEC_DEFAULT_SOURCE_GC_TIME,
            )?);
            return Ok(());
        };

        if route.feasibility() < source.feasibility {
            source.feasibility = route.feasibility()
        }

        Ok(())
    }
}
