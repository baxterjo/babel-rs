use core::cmp::Ordering;

use crate::data_structures::originated_route::originated_route_entry::{
    OriginatedRoute, OriginatedRouteIndex,
};
use crate::data_structures::originated_route::originated_route_table::OriginatedRouteTable;
use crate::data_structures::route::{Route, RouteIndex, RouteTable};
use crate::data_structures::source::SourceTable;
use crate::data_types::RouterId;
use crate::data_types::destination::RouteDestination;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::storage::{InternallyKeyed, TableSlot};

/// Every route this router holds, whether it originated the route or learned it from a neighbour.
///
/// Babel keeps the two kinds apart: learned routes live in the route table
/// ([Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)) and the
/// routes this node originates live in their own table. They carry the same kind of information
/// under different names and types, so this view presents both through [`AnyRoute`].
pub(crate) struct AllRoutes<'a, 'storage, A: AddressExt> {
    originated: &'a mut OriginatedRouteTable<'storage, A>,
    learned: &'a mut RouteTable<'storage, A>,
}

impl<'a, 'storage, A: AddressExt> AllRoutes<'a, 'storage, A> {
    pub(crate) fn new(
        originated: &'a mut OriginatedRouteTable<'storage, A>,
        learned: &'a mut RouteTable<'storage, A>,
    ) -> Self {
        Self {
            originated,
            learned,
        }
    }

    /// Every route in both tables: all originated routes first, then all learned ones.
    ///
    /// The two halves are each in key order, but the whole is not merged by destination. Use
    /// [`Self::destination_groups_mut`] when the routes need to be seen a destination at a time.
    pub(crate) fn iter(&self) -> impl Iterator<Item = AnyRoute<'_, A>> {
        self.originated
            .inner
            .iter()
            .map(AnyRoute::Originated)
            .chain(self.learned.inner.iter().map(AnyRoute::Learned))
    }

    /// Every route, from either table, towards `destination`.
    pub(crate) fn iter_destination(
        &self,
        destination: &RouteDestination<A>,
    ) -> impl Iterator<Item = AnyRoute<'_, A>> {
        self.iter().filter(move |r| r.destination() == destination)
    }

    /// The selected route for `destination`, from whichever table holds it.
    pub(crate) fn get_selected(
        &self,
        destination: &RouteDestination<A>,
    ) -> Option<AnyRoute<'_, A>> {
        let mut iter = self
            .iter_destination(destination)
            .filter(|route| route.selected());
        let out = iter.next();
        // This is a good spot to assert that only one route is selected for a given destination on
        // non-optimized builds.
        debug_assert!(
            iter.next().is_none(),
            "There should only be one selected route for a destination, across both tables."
        );
        out
    }

    /// Walks both tables a destination at a time, yielding one [`DestinationGroup`] for every
    /// destination that either table holds a route towards.
    ///
    /// This is a merge of the two tables' destination runs: since both are sorted by destination,
    /// the run with the lower destination is yielded on its own, and runs with an equal destination
    /// are yielded together.
    pub(crate) fn destination_groups_mut(
        &mut self,
    ) -> impl Iterator<Item = DestinationGroup<'_, A>> {
        let mut originated = self
            .originated
            .inner
            // Get chunks of the same destination.
            .chunk_by_mut(|a, b| destination_of(a) == destination_of(b))
            // Free slots sort ahead of every occupied one and collapse into one leading run.
            .filter(|run| {
                // First check to see if the run has values. (Filters 0 capacity tables and the last
                // run in chunk_by_mut())
                run.first().is_some_and(|first| {
                    // Then check to make sure the first value in the run is Some (filters empty
                    // slots)
                    first.value().is_some()
                })
            })
            .peekable();

        // Get the same type of iterator from the learned routes table.
        let mut learned = self
            .learned
            .inner
            .chunk_by_mut(|a, b| destination_of(a) == destination_of(b))
            .filter(|run| run.first().is_some_and(|first| first.value().is_some()))
            .peekable();

        // Create an cursor that merges both data sources.
        core::iter::from_fn(move || {
            // Get the next destination from both iterators created above.
            let next_originated = originated.peek().and_then(|run| destination_of(&run[0]));
            let next_learned = learned.peek().and_then(|run| destination_of(&run[0]));

            let ordering = match (next_originated, next_learned) {
                // If neither have a destination, then the iterator is finished.
                (None, None) => return None,
                // This section covers originating and learned tables of differing lengths.
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                // If comparing routes to routes, take the ordering of their destinations.
                (Some(o), Some(l)) => o.cmp(&l),
            };

            // An empty `&mut [T]` stands in for the side that has no routes towards this
            // destination.
            let group = match ordering {
                // If originated has the "Lesser" destination OR has items when learned does not,
                // then the destination group is that of the next originated chunk.
                Ordering::Less => DestinationGroup {
                    originated: originated.next()?,
                    learned: Default::default(),
                },
                // If originated has the "Greater" destination OR the learned table has items when
                // originated does not, then the destination group is that of the learned chunk.
                Ordering::Greater => DestinationGroup {
                    originated: Default::default(),
                    learned: learned.next()?,
                },
                // If both originated and learned have remaining items and they have the same
                // destination, then yeild both.
                Ordering::Equal => DestinationGroup {
                    originated: originated.next()?,
                    learned: learned.next()?,
                },
            };
            Some(group)
        })
    }
}

/// The outcome of choosing a route for one destination, as decided by
/// [`DestinationGroup::choose`].
///
/// This is a decision only. Nothing has been marked selected yet, and nothing has been queued:
/// applying it is [`DestinationGroup::select`], and reacting to it is up to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Selection<A: AddressExt> {
    /// The route the destination pointed at before this decision, with its metric at the time,
    /// whether or not it is still usable.
    pub(crate) previous: Option<(AnyRouteIndex<A>, Metric)>,
    /// The route the destination should point at now. `None` when no route is eligible.
    pub(crate) winner: Option<AnyRouteIndex<A>>,
}

/// A non-empty set of routes, drawn from both tables, that all lead to the same destination.
///
/// Either side may be empty, but never both.
pub(crate) struct DestinationGroup<'a, A: AddressExt> {
    originated: &'a mut [Option<OriginatedRoute<A>>],
    learned: &'a mut [Option<Route<A>>],
}

impl<A: AddressExt> DestinationGroup<'_, A> {
    /// The destination that every route in this group leads to.
    pub(crate) fn destination(&self) -> RouteDestination<A> {
        *self
            .iter()
            .next()
            .expect("a destination group always holds at least one route")
            .destination()
    }

    /// The number of routes towards this destination, across both tables.
    pub(crate) fn len(&self) -> usize {
        self.iter().count()
    }

    /// Every route towards this destination: the originated ones first, then the learned ones.
    pub(crate) fn iter(&self) -> impl Iterator<Item = AnyRoute<'_, A>> {
        self.originated
            .iter()
            .filter_map(|r| r.value())
            .map(AnyRoute::Originated)
            .chain(
                self.learned
                    .iter()
                    .filter_map(|r| r.value())
                    .map(AnyRoute::Learned),
            )
    }

    /// Decides which route this destination should point at, following the recommended route
    /// selection procedure of
    /// [Section 3.6](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    /// and [Appendix A.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection).
    ///
    /// Originated and learned routes compete in one pool. An originated route is eligible whenever
    /// its metric is finite, and it has no smoothed metric of its own, so it defends the
    /// destination with its configured metric on both counts. Ties are broken on
    /// [`AnyRouteIndex`], which puts an originated route ahead of a learned one.
    ///
    /// This only reads the group. Apply the decision with [`Self::select`].
    pub(crate) fn choose(&self, sources: &SourceTable<'_, A>) -> Selection<A> {
        // The route this destination was pointing at before this run, whether or not it is still
        // usable. Only the caller's change detection cares about that distinction.
        let previous = self
            .iter()
            .find(|route| route.selected())
            .map(|route| (route.key(), route.metric()));

        // The previously selected route, but only while it still passes the hard rules. One that
        // has been retracted or has gone unfeasible cannot be used.
        let incumbent = self
            .iter()
            .find(|route| route.selected() && route.is_eligible(sources))
            .map(|route| (route.key(), route.metric(), route.smoothed_metric()));

        let winner = match incumbent {
            // A still-eligible incumbent keeps the destination unless some route beats it on the
            // real metric *and* on the smoothed one.
            Some((incumbent, incumbent_metric, incumbent_smoothed)) => Some(
                self.iter()
                    // A set of potential winners must be eligible
                    .filter(|route| route.is_eligible(sources))
                    // A set of potential winners must have a metric and smoothed metric better than
                    // the incumbent. If there are any items in the iterator after this point, they
                    // are better than the incumbent.
                    .filter(|route| {
                        route.metric() < incumbent_metric
                            && route.smoothed_metric() < incumbent_smoothed
                    })
                    // Take the route that is the minimum of the routes better than the incumbent.
                    // Breaking ties on the route index.
                    .min_by_key(|route| (route.metric(), route.key()))
                    .map(|route| route.key())
                    // If none of these conditions are met, then the incumbent wins.
                    .unwrap_or(incumbent),
            ),
            // Nothing to defend the destination, so the best route takes it outright, with the
            // smoothed metric ignored entirely. This is also the path a destination whose selected
            // route was just retracted takes.
            None => self
                .iter()
                // Potential winners must be eligible
                .filter(|route| route.is_eligible(sources))
                // Take the route with the minimum metric. Breaking ties on the route index.
                .min_by_key(|route| (route.metric(), route.key()))
                .map(|route| route.key()),
        };

        b_trace!(
            "previous: {:?}, incumbent: {:?}, winner: {:?}",
            previous.map(|p| p.0),
            incumbent.map(|i| i.0),
            winner
        );

        Selection { previous, winner }
    }

    /// The route currently selected for this destination, from whichever table holds it.
    pub(crate) fn selected(&self) -> Option<AnyRoute<'_, A>> {
        self.iter().find(|route| route.selected())
    }

    /// Marks `winner` selected and every other route towards this destination, in both tables,
    /// unselected. `None` leaves the destination with nothing selected.
    pub(crate) fn select(&mut self, winner: Option<AnyRouteIndex<A>>) {
        for route in self.originated.iter_mut().filter_map(|r| r.value_mut()) {
            route.selected = winner == Some(AnyRouteIndex::Originated(route.key()));
        }
        for route in self.learned.iter_mut().filter_map(|r| r.value_mut()) {
            route.selected = winner == Some(AnyRouteIndex::Learned(route.key()));
        }
    }
}

/// A shared view of one route from either table.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum AnyRoute<'a, A: AddressExt> {
    /// A route this router originates.
    Originated(&'a OriginatedRoute<A>),
    /// A route learned from a neighbour.
    Learned(&'a Route<A>),
}

// Written by hand so that copying the view does not require `A: Copy`.
impl<A: AddressExt> Clone for AnyRoute<'_, A> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<A: AddressExt> Copy for AnyRoute<'_, A> {}

/// The key of a route in either table.
///
/// `Originated` is declared first, so the derived ordering puts an originated route ahead of a
/// learned one wherever the two are otherwise tied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum AnyRouteIndex<A: AddressExt> {
    Originated(OriginatedRouteIndex<A>),
    Learned(RouteIndex<A>),
}

impl<'a, A: AddressExt> AnyRoute<'a, A> {
    /// The key of this route within its own table.
    pub(crate) fn key(&self) -> AnyRouteIndex<A> {
        match self {
            Self::Originated(route) => AnyRouteIndex::Originated(route.key()),
            Self::Learned(route) => AnyRouteIndex::Learned(route.key()),
        }
    }

    pub(crate) fn destination(&self) -> &'a RouteDestination<A> {
        match self {
            Self::Originated(route) => route.destination(),
            Self::Learned(route) => route.destination(),
        }
    }

    /// The metric this router holds for the route: the configured metric of an originated route,
    /// or the computed metric of a learned one.
    pub(crate) fn metric(&self) -> Metric {
        match self {
            Self::Originated(route) => route.metric,
            Self::Learned(route) => *route.computed_metric(),
        }
    }

    /// The smoothed metric of a learned route. Originated routes are not smoothed, so for them
    /// this is the same as [`Self::metric`].
    pub(crate) fn smoothed_metric(&self) -> Metric {
        match self {
            Self::Originated(route) => route.metric,
            Self::Learned(route) => *route.smoothed_metric(),
        }
    }

    pub(crate) fn selected(&self) -> bool {
        match self {
            Self::Originated(route) => route.selected,
            Self::Learned(route) => route.selected,
        }
    }

    pub(crate) fn is_originated(&self) -> bool {
        matches!(self, Self::Originated(_))
    }

    /// What an Update TLV for this route carries.
    ///
    /// A learned route is announced with the router-id and seqno of the source it was learned
    /// from. An originated route has no source of its own: this router is the source, so it is
    /// announced with this router's router-id and its single, global seqno (Section 3.2.1).
    pub(crate) fn advertisement(&self, origin: LocalOrigin) -> Advertisement {
        match self {
            Self::Originated(route) => Advertisement {
                router_id: origin.router_id,
                seqno: origin.seqno,
                metric: route.metric,
            },
            Self::Learned(route) => Advertisement {
                router_id: route.source().router_id,
                seqno: route.seqno,
                metric: *route.computed_metric(),
            },
        }
    }

    /// Whether this route may be selected at all. See [`is_eligible`] for a learned route. An
    /// originated route only has to have a finite metric: this router is its source, so there is no
    /// feasibility condition to satisfy.
    pub(crate) fn is_eligible(&self, sources: &SourceTable<'_, A>) -> bool {
        match self {
            Self::Originated(route) => route.metric.is_finite(),
            Self::Learned(route) => is_eligible(sources, route),
        }
    }
}

/// The identity this router announces the routes it originates under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct LocalOrigin {
    /// This router's router-id.
    pub(crate) router_id: RouterId,
    /// This router's seqno, which is shared by every route it originates.
    pub(crate) seqno: SeqNo,
}

/// The values an Update TLV carries for a route, as worked out by [`AnyRoute::advertisement`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Advertisement {
    /// The router-id of the route's source, which the Router-Id TLV ahead of the update names.
    pub(crate) router_id: RouterId,
    pub(crate) seqno: SeqNo,
    pub(crate) metric: Metric,
}

/// Section 3.6's hard rules: a route with an infinite metric has been retracted, and an
/// unfeasible one risks a routing loop.
pub(crate) fn is_eligible<A: AddressExt>(
    source_table: &SourceTable<'_, A>,
    route: &Route<A>,
) -> bool {
    route.computed_metric() != &Metric::INFINITY
        && source_table.is_feasible(route.source(), route.advertised_metric(), &route.seqno)
}

/// A route type that knows the destination it leads to.
///
/// Lets [`destination_of`] group the slots of either table by destination.
pub(crate) trait HasDestination<A: AddressExt> {
    fn route_destination(&self) -> &RouteDestination<A>;
}

impl<A: AddressExt> HasDestination<A> for OriginatedRoute<A> {
    fn route_destination(&self) -> &RouteDestination<A> {
        self.destination()
    }
}

impl<A: AddressExt> HasDestination<A> for Route<A> {
    fn route_destination(&self) -> &RouteDestination<A> {
        self.destination()
    }
}

/// The destination of an occupied slot, or `None` for a free one.
///
/// Free slots compare equal to each other and to nothing else, which is what collapses them into
/// the single leading run that [`AllRoutes::destination_groups_mut`] discards.
fn destination_of<A, T>(entry: &Option<T>) -> Option<RouteDestination<A>>
where
    A: AddressExt,
    T: HasDestination<A> + InternallyKeyed,
{
    entry.value().map(|e| *e.route_destination())
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::InterfaceHandle;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::source::SourceIndex;
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::router::config::DEFAULT_ROUTE_EXPIRY_TIME;
    use crate::utils::{Duration, Instant};

    /// Long enough that nothing expires mid-test, still inside the Timer bound.
    const INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));

    const DEST_A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
    const DEST_B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0);
    const DEST_C: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 3, 0, 0, 0, 0);
    const NEIGHBOUR_1: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_2: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    fn destination(prefix: Ipv6Addr) -> RouteDestination<NoExtension> {
        RouteDestination::new(prefix.into(), 64).expect("bad destination")
    }

    fn insert_learned(
        table: &mut RouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        neighbour: Ipv6Addr,
    ) {
        table
            .add_route(
                Instant::from_secs(0),
                SourceIndex {
                    destination: destination(prefix),
                    router_id: RouterId::try_from("rtr-a").expect("bad router id"),
                },
                NeighbourIndex {
                    iface: iface_handle("eth0"),
                    addr: neighbour.into(),
                },
                SeqNo(0),
                Metric::from(10),
                Metric::from(10),
                neighbour.into(),
                INTERVAL,
            )
            .expect("the table has a free slot for the route");
    }

    fn insert_originated(
        table: &mut OriginatedRouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        interface: &str,
    ) {
        insert_originated_with_metric(table, prefix, interface, Metric::from(0));
    }

    /// [`insert_originated`], with the metric the caller wants the route configured with.
    fn insert_originated_with_metric(
        table: &mut OriginatedRouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        interface: &str,
        metric: Metric,
    ) {
        table
            .insert_route(
                OriginatedRouteIndex {
                    destination: destination(prefix),
                    interface: iface_handle(interface),
                },
                metric,
            )
            .expect("the table has a free slot for the route");
    }

    fn originated_key(prefix: Ipv6Addr, interface: &str) -> AnyRouteIndex<NoExtension> {
        AnyRouteIndex::Originated(OriginatedRouteIndex {
            destination: destination(prefix),
            interface: iface_handle(interface),
        })
    }

    /// Runs [`DestinationGroup::choose`] over every destination, without applying anything.
    ///
    /// The source table is empty, so every learned route is feasible and only the metrics and
    /// the originated/learned split decide the outcome.
    fn choices(all: &mut AllRoutes<'_, '_, NoExtension>) -> Vec<Selection<NoExtension>> {
        let sources = SourceTable::new_with_storage(Vec::new());
        all.destination_groups_mut()
            .map(|group| group.choose(&sources))
            .collect()
    }

    /// Destinations held only by the originated table, only by the route table, or by both, each
    /// come out as exactly one group, in destination order.
    #[test]
    fn merges_destinations_across_both_tables() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);

        // DEST_A: originated only. DEST_B: both. DEST_C: learned only.
        insert_originated(&mut originated, DEST_A, "eth0");
        insert_originated(&mut originated, DEST_B, "eth0");
        insert_originated(&mut originated, DEST_B, "wlan0");
        insert_learned(&mut learned, DEST_B, NEIGHBOUR_1);
        insert_learned(&mut learned, DEST_C, NEIGHBOUR_1);
        insert_learned(&mut learned, DEST_C, NEIGHBOUR_2);

        let mut all = AllRoutes::new(&mut originated, &mut learned);
        let groups: Vec<(RouteDestination<NoExtension>, usize, usize)> = all
            .destination_groups_mut()
            .map(|group| {
                let originated = group.iter().filter(|r| r.is_originated()).count();
                (group.destination(), originated, group.len() - originated)
            })
            .collect();

        assert_eq!(
            groups,
            alloc::vec![
                (destination(DEST_A), 1, 0),
                (destination(DEST_B), 2, 1),
                (destination(DEST_C), 0, 2),
            ]
        );
    }

    /// Free slots in either table must not be yielded as a group of their own.
    #[test]
    fn skips_free_slots_in_both_tables() {
        let mut originated_storage: [Option<OriginatedRoute<NoExtension>>; 3] = [const { None }; 3];
        let mut learned_storage: [Option<Route<NoExtension>>; 3] = [const { None }; 3];
        let mut originated = OriginatedRouteTable::new_with_storage(&mut originated_storage[..]);
        let mut learned =
            RouteTable::new_with_storage(&mut learned_storage[..], DEFAULT_ROUTE_EXPIRY_TIME);
        insert_originated(&mut originated, DEST_A, "eth0");
        insert_learned(&mut learned, DEST_B, NEIGHBOUR_1);

        let mut all = AllRoutes::new(&mut originated, &mut learned);
        let lens: Vec<usize> = all.destination_groups_mut().map(|g| g.len()).collect();

        assert_eq!(
            lens,
            alloc::vec![1, 1],
            "two real groups, no free-slot groups"
        );
    }

    /// Selecting a route in one table deselects every other route towards the destination, in both
    /// tables, and the selected route can then be found from either kind.
    #[test]
    fn select_spans_both_tables() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        insert_originated(&mut originated, DEST_A, "eth0");
        insert_learned(&mut learned, DEST_A, NEIGHBOUR_1);

        let mut all = AllRoutes::new(&mut originated, &mut learned);

        // Select the learned route first, then hand the destination to the originated one.
        for mut group in all.destination_groups_mut() {
            let learned_key = group.iter().find(|r| !r.is_originated()).map(|r| r.key());
            group.select(learned_key);
        }
        assert!(
            all.get_selected(&destination(DEST_A))
                .is_some_and(|r| !r.is_originated())
        );

        for mut group in all.destination_groups_mut() {
            let originated_key = group.iter().find(|r| r.is_originated()).map(|r| r.key());
            group.select(originated_key);
        }
        let selected: Vec<AnyRouteIndex<NoExtension>> = all
            .iter()
            .filter(|r| r.selected())
            .map(|r| r.key())
            .collect();
        assert_eq!(
            selected,
            alloc::vec![AnyRouteIndex::Originated(OriginatedRouteIndex {
                destination: destination(DEST_A),
                interface: iface_handle("eth0"),
            })],
            "only the originated route is left selected"
        );

        for mut group in all.destination_groups_mut() {
            group.select(None);
        }
        assert!(all.get_selected(&destination(DEST_A)).is_none());
    }

    /// A destination that only this router originates has no learned route to compete with, and
    /// is still chosen. Selection used to be driven by the route table alone, which never visited
    /// such a destination.
    #[test]
    fn a_destination_only_originated_is_chosen() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        insert_originated(&mut originated, DEST_A, "eth0");

        let mut all = AllRoutes::new(&mut originated, &mut learned);

        assert_eq!(
            choices(&mut all),
            alloc::vec![Selection {
                previous: None,
                winner: Some(originated_key(DEST_A, "eth0")),
            }]
        );
    }

    /// Originated and learned routes compete on metric in one pool, and on an exact tie the
    /// originated route wins, because [`AnyRouteIndex`] orders it first.
    #[test]
    fn originated_and_learned_routes_compete_on_metric() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        // Every learned route here has a metric of 10.
        // DEST_A: originated at 0 beats learned at 10.
        // DEST_B: originated at 10 ties learned at 10, and wins the tie.
        // DEST_C: originated at 20 loses to learned at 10.
        insert_originated_with_metric(&mut originated, DEST_A, "eth0", Metric::from(0));
        insert_originated_with_metric(&mut originated, DEST_B, "eth0", Metric::from(10));
        insert_originated_with_metric(&mut originated, DEST_C, "eth0", Metric::from(20));
        insert_learned(&mut learned, DEST_A, NEIGHBOUR_1);
        insert_learned(&mut learned, DEST_B, NEIGHBOUR_1);
        insert_learned(&mut learned, DEST_C, NEIGHBOUR_1);

        let mut all = AllRoutes::new(&mut originated, &mut learned);
        let winners: Vec<bool> = choices(&mut all)
            .iter()
            .map(|s| matches!(s.winner, Some(AnyRouteIndex::Originated(_))))
            .collect();

        assert_eq!(
            winners,
            alloc::vec![true, true, false],
            "originated wins DEST_A outright and DEST_B on the tie, and loses DEST_C"
        );
    }

    /// An originated route with an infinite metric is not eligible, so a learned route takes the
    /// destination even though the originated one would otherwise win.
    #[test]
    fn an_infinite_originated_route_is_not_chosen() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        insert_originated_with_metric(&mut originated, DEST_A, "eth0", Metric::INFINITY);
        insert_learned(&mut learned, DEST_A, NEIGHBOUR_1);

        let mut all = AllRoutes::new(&mut originated, &mut learned);
        let selection = choices(&mut all);

        assert_eq!(selection.len(), 1);
        assert!(
            matches!(selection[0].winner, Some(AnyRouteIndex::Learned(_))),
            "the learned route wins, got {:?}",
            selection[0].winner
        );
    }

    /// Choosing is a decision only: it reports the route that was selected before, and leaves
    /// the tables exactly as it found them.
    #[test]
    fn choose_reports_the_previous_selection_and_changes_nothing() {
        let mut originated = OriginatedRouteTable::new_with_storage(Vec::new());
        let mut learned = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        insert_originated_with_metric(&mut originated, DEST_A, "eth0", Metric::from(0));
        insert_learned(&mut learned, DEST_A, NEIGHBOUR_1);

        let mut all = AllRoutes::new(&mut originated, &mut learned);

        // Hand the destination to the learned route, so the originated route has to unseat it.
        let learned_key = all
            .iter()
            .find(|r| !r.is_originated())
            .map(|r| r.key())
            .expect("the learned route");
        for mut group in all.destination_groups_mut() {
            group.select(Some(learned_key));
        }

        let selection = choices(&mut all);

        assert_eq!(
            selection,
            alloc::vec![Selection {
                previous: Some((learned_key, Metric::from(10))),
                winner: Some(originated_key(DEST_A, "eth0")),
            }]
        );
        assert_eq!(
            all.get_selected(&destination(DEST_A)).map(|r| r.key()),
            Some(learned_key),
            "choose must not apply its own decision"
        );
    }
}
