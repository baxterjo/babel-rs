use managed::ManagedSlice;

use crate::{
    data_types::address::{AddressExtension, RouterAddress},
    data_types::Interval,
    utils::storage::InternallyKeyed,
    utils::Instant,
};

use super::{neighbour::NeighbourIndex, seqno::SeqNo, source::SourceIndex};

pub struct RouteTable<'storage, A: AddressExtension> {
    inner: ManagedSlice<'storage, Option<Route<A>>>,
}

impl<'storage, A> RouteTable<'storage, A>
where
    A: AddressExtension,
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

/// 3.2.6-1: The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour) (See [`RouteIndex`]), and every route table entry contains the
/// following data:
pub struct Route<A: AddressExtension> {
    /// 3.2.6-2.1: the source (prefix, plen, router-id) for which this route is advertised
    source: SourceIndex<A>,
    /// 3.2.6-2.2: the neighbour (an entry in the neighbour table) that advertised this route
    neigbour: NeighbourIndex<A>,
    /// 3.2.6-2.3: the metric with which this route was advertised by the neighbour, or FFFF
    /// hexadecimal (infinity) for a recently retracted route
    metric: u16,
    /// 3.2.6-2.4: the sequence number with which this route was advertised
    seqno: SeqNo,
    /// 3.2.6-2.5: the next-hop address of this route
    next_hop: A,
    /// 3.2.6-2.6: a boolean flag indicating whether this route is selected, i.e., whether it is
    /// currently being used for forwarding and is being advertised
    selected: bool,

    /// 3.2.6-3: There is one timer associated with each route table entry -- the route expiry
    /// timer. It is initialised and reset as specified in Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#route-acquisition)
    last_update: Instant,
    expiry_interval: Interval,
}
/// 3.2.6-1: The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteIndex<A: AddressExtension> {
    prefix: RouterAddress<A>,
    prefix_len: u8,
    neighbour: NeighbourIndex<A>,
}

impl<A: AddressExtension> InternallyKeyed for Route<A> {
    type Key = RouteIndex<A>;
    fn key(&self) -> Self::Key {
        RouteIndex {
            prefix: self.source.prefix,
            prefix_len: self.source.prefix_len,
            neighbour: self.neigbour,
        }
    }
}
