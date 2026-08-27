use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::source::SourceIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::utils::Timer;
use crate::utils::storage::InternallyKeyed;
/// Route entry as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour) (See [`RouteIndex`]), and every route table entry contains the
/// following data:
pub struct Route<A: AddressExt> {
    /// the source (prefix, plen, router-id) for which this route is advertised
    source: SourceIndex<A>,
    /// the neighbour (an entry in the neighbour table) that advertised this route
    neigbour: NeighbourIndex<A>,
    /// the metric with which this route was advertised by the neighbour, or FFFF
    /// hexadecimal (infinity) for a recently retracted route
    metric: u16,
    /// the sequence number with which this route was advertised
    seqno: SeqNo,
    /// the next-hop address of this route
    next_hop: A,
    /// a boolean flag indicating whether this route is selected, i.e., whether it is
    /// currently being used for forwarding and is being advertised
    selected: bool,

    /// There is one timer associated with each route table entry -- the route expiry
    /// timer. It is initialised and reset as specified in Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#route-acquisition)
    expiry: Timer,
}
/// Route index as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteIndex<A: AddressExt> {
    prefix: Address<A>,
    prefix_len: u8,
    neighbour: NeighbourIndex<A>,
}

impl<A: AddressExt> InternallyKeyed for Route<A> {
    type Key = RouteIndex<A>;
    fn key(&self) -> Self::Key {
        RouteIndex {
            prefix: self.source.prefix,
            prefix_len: self.source.prefix_len,
            neighbour: self.neigbour,
        }
    }
}
