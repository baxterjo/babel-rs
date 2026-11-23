use crate::data_structures::originated_route::OriginatedRouteError;
use crate::data_structures::originated_route::originated_route_entry::{
    OriginatedRoute, OriginatedRouteIndex,
};
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::ManagedSlice;
use crate::utils::storage::Table;

/// Table that holds all of this router's self originated routes.
pub(crate) struct OriginatedRouteTable<'storage, A: AddressExt> {
    pub(crate) inner: Table<'storage, Option<OriginatedRoute<A>>>,
}

impl<'storage, A: AddressExt> OriginatedRouteTable<'storage, A> {
    /// Create a new originated route table with user provided storage.
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<OriginatedRoute<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    pub(crate) fn insert_route(
        &mut self,
        route: OriginatedRouteIndex<A>,
        metric: Metric,
    ) -> Result<(), OriginatedRouteError> {
        let route = OriginatedRoute::new(route, metric);
        Ok(self.inner.insert(route)?)
    }
}
