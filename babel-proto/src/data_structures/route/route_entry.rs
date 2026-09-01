use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex};
use crate::data_structures::route::RouteError;
use crate::data_structures::source::SourceIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::storage::InternallyKeyed;
use crate::utils::{Duration, DurationMultiplier, Instant, Timer};
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
    /// the source (prefix, plen, router-id) that originated this route
    ///
    /// Should not be made public as its prefix & prefix_len cannot change
    source: SourceIndex<A>,

    /// the neighbour (an entry in the neighbour table) that advertised this route
    ///
    /// Should not be made public as it should never change
    neighbour: NeighbourIndex<A>,

    /// the sequence number with which this route was advertised
    pub(crate) seqno: SeqNo,

    /// the metric with which this route was advertised by the neighbour, or FFFF
    /// hexadecimal (infinity) for a recently retracted route
    pub(crate) advertised_metric: Metric,

    /// The computed metric of this route.
    pub(crate) computed_metric: Metric,

    /// The smoothed metric for hysteresis
    pub(crate) smoothed_metric: Metric,

    /// The instant the last smoothed metric was calculated.
    pub(crate) smoothed_metric_time: Instant,

    /// the next-hop address of this route
    pub(crate) next_hop: Address<A>,

    /// a boolean flag indicating whether this route is selected, i.e., whether it is
    /// currently being used for forwarding and is being advertised
    pub(crate) selected: bool,

    /// There is one timer associated with each route table entry -- the route expiry
    /// timer. It is initialised and reset as specified in Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#route-acquisition)
    pub(crate) expiry: Timer,
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
            neighbour: self.neighbour,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Destination<A: AddressExt> {
    pub(crate) prefix: Address<A>,
    pub(crate) prefix_len: u8,
}

impl<A: AddressExt> Route<A> {
    pub(crate) fn new(
        now: Instant,
        source: SourceIndex<A>,
        neighbour: NeighbourIndex<A>,
        seqno: SeqNo,
        advertised_metric: Metric,
        computed_metric: Metric,
        next_hop: Address<A>,
        selected: bool,
        interval: Interval,
        hold_time: DurationMultiplier,
    ) -> Result<Self, RouteError> {
        let expiry = Timer::from_duration(now, Duration::from(interval) * hold_time)?;
        Ok(Self {
            source,
            neighbour,
            seqno,
            advertised_metric,
            computed_metric,
            smoothed_metric: computed_metric,
            smoothed_metric_time: now,
            next_hop,
            selected,
            expiry,
        })
    }
    pub(crate) fn destination(&self) -> Destination<A> {
        Destination {
            prefix: self.source.prefix,
            prefix_len: self.source.prefix_len,
        }
    }

    pub(crate) fn source(&self) -> &SourceIndex<A> {
        &self.source
    }

    pub(crate) fn neigbour(&self) -> &NeighbourIndex<A> {
        &self.neighbour
    }

    pub(crate) fn set_router_id(&mut self, router_id: RouterId) {
        self.source.router_id = router_id;
    }

    /// Recomputes this route's metric from the neighbour's current link cost and updates the
    /// smoothed metric.
    pub(crate) fn update_cost(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        smoothing_multiple: &DurationMultiplier,
    ) {
        // Update computed metric
        let link_cost = interface.cost_calc.link_cost(
            interface.cost_calc.rx_cost(
                neighbour.mcast_hello_info.history,
                neighbour.ucast_hello_info.history,
            ),
            neighbour.tx_cost,
        );
        let computed_metric = interface
            .cost_calc
            .metric(self.advertised_metric, link_cost);
        self.computed_metric = computed_metric;
        // Update smoothed metric
        let step_dur = now - self.smoothed_metric_time;
        let interval = neighbour
            .pending
            .ucast_hello
            .map(|u| u.timer.duration().min(interface.hello_timer.duration()))
            .unwrap_or(interface.hello_timer.duration());
        let time_constant = interval * *smoothing_multiple;
        self.smoothed_metric
            .apply_smoothing(computed_metric, step_dur, time_constant);
        // Update smoothed metric time
        self.smoothed_metric_time = now;
    }
}
