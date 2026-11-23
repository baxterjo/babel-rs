use crate::data_structures::interface::InterfaceHandle;
use crate::data_types::destination::RouteDestination;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::InternallyKeyed;

/// A self originated route.
///
/// This is a route that this router is advertising. The lifecycle and maintenance of this route is
/// completely up to the user. This protocol will gladly advertise this route forever if it remains
/// unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OriginatedRoute<A: AddressExt> {
    destination: RouteDestination<A>,
    interface: InterfaceHandle,
    pub metric: Metric,
    pub(crate) selected: bool,
}

impl<A: AddressExt> OriginatedRoute<A> {
    pub fn new(index: OriginatedRouteIndex<A>, metric: Metric) -> Self {
        Self {
            destination: index.destination,
            interface: index.interface,
            metric,
            selected: false,
        }
    }
    pub fn destination(&self) -> &RouteDestination<A> {
        &self.destination
    }
    pub fn interface(&self) -> &InterfaceHandle {
        &self.interface
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct OriginatedRouteIndex<A: AddressExt> {
    pub destination: RouteDestination<A>,
    pub interface: InterfaceHandle,
}

impl<A: AddressExt> InternallyKeyed for OriginatedRoute<A> {
    type Key = OriginatedRouteIndex<A>;
    fn key(&self) -> Self::Key {
        OriginatedRouteIndex {
            destination: self.destination,
            interface: self.interface,
        }
    }
}
