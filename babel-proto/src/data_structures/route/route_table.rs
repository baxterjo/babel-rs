use crate::data_structures::route::route_entry::Route;
use crate::extension::address::AddressExt;
use crate::utils::ManagedSlice;

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    inner: ManagedSlice<'storage, Option<Route<A>>>,
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl<A: AddressExt> Default for RouteTable<'_, A> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'storage, A> RouteTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of routes this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Route<A>>>>,
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
