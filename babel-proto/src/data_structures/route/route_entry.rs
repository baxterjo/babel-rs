use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::source::SourceIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::Timer;
use crate::utils::storage::InternallyKeyed;
/// Route entry as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour) (See [`RouteIndex`]), and every route table entry contains the
/// following data:
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route<A: AddressExt> {
    // Spec Info
    /// the source (prefix, plen, router-id) for which this route is advertised
    pub(crate) source: SourceIndex<A>,
    /// the neighbour (an entry in the neighbour table) that advertised this route
    pub(crate) neigbour: NeighbourIndex<A>,
    /// the metric with which this route was advertised by the neighbour, or FFFF
    /// hexadecimal (infinity) for a recently retracted route
    pub(crate) advertised_metric: Metric,
    /// the sequence number with which this route was advertised
    pub(crate) seqno: SeqNo,
    /// The computed metric of this route.
    pub(crate) computed_metric: Metric,
    /// the next-hop address of this route
    pub(crate) next_hop: Address<A>,
    /// a boolean flag indicating whether this route is selected, i.e., whether it is
    /// currently being used for forwarding and is being advertised
    pub(crate) selected: bool,

    /// There is one timer associated with each route table entry -- the route expiry
    /// timer. It is initialised and reset as specified in Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#route-acquisition)
    pub(crate) expiry: Timer,
    // Additional state
    // TODO: Triggered updates defined in section 3.7.2
    //pub(crate) triggered_update: bool,
}
/// Route index as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteIndex<A: AddressExt> {
    pub(crate) prefix: Address<A>,
    pub(crate) prefix_len: u8,
    pub(crate) neighbour: NeighbourIndex<A>,
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
