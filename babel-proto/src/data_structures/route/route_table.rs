use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::route::route_entry::Route;
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::data_structures::updates::UpdateIndex;
use crate::data_types::destination::RouteDestination;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::packet::parser::ResolvedUpdate;
use crate::utils::storage::{InsertError, Table};
use crate::utils::{Duration, DurationMultiplier, Instant, InternallyKeyed, ManagedSlice, Timer};

pub const DEFAULT_SMOOTHING_MULTIPLE: DurationMultiplier = DurationMultiplier::new(3, 1);
pub const METRIC_DIFFERENCE_THRESHOLD: Metric = Metric::from_raw(100);

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    /// The inner slice for the table.
    pub(crate) inner: Table<'storage, Option<Route<A>>>,

    pub(crate) route_expiry_time: DurationMultiplier,
    /// Multiple of the hello timer of a given route that should be used to generate the time
    /// constant of a route's smoothed metric.
    ///
    /// The time constant will be taken from the max between mcast hello interval and ucast hello
    /// interval (if it exists)
    pub(crate) smoothing_multiple: DurationMultiplier,
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
    pub(crate) fn new_with_storage<T>(storage: T, route_expiry: DurationMultiplier) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Route<A>>>>,
    {
        Self {
            inner: Table::new(storage),
            route_expiry_time: route_expiry,
            smoothing_multiple: DEFAULT_SMOOTHING_MULTIPLE,
        }
    }

    /// Gets the route for the given update.
    ///
    /// This will either return the selected route, or an arbitrary infinite route.
    pub(crate) fn get_for_udpate(&self, update_idx: UpdateIndex<A>) -> Option<&Route<A>> {
        // Track first selected
        let mut first_selected: Option<&Route<A>> = None;
        // Track the last iterated
        let mut last: Option<&Route<A>> = None;
        // Track weather all are infinite.
        let mut all_infinite: Option<bool> = None;

        for route in self
            .inner
            .iter()
            .filter(|r| r.source().destination == update_idx.source.destination)
        {
            if route.selected {
                // When running in non-optimized builds, we want iterate through all of the
                // matching routes to ensure there is only one selected route.
                #[cfg(debug_assertions)]
                if first_selected.is_some() {
                    panic!("There should be only one selected route.")
                }

                first_selected = Some(route);

                // When running optimized builds, return this as soon as it is found.
                #[cfg(not(debug_assertions))]
                return break;
            }
            // Update the last route matching the prefix.
            last = Some(route);

            // Initializes to true && route_is_infinite on the first pass.
            // Updates to existing && route_is_infinite on following passes.
            *all_infinite.get_or_insert(true) &= route.computed_metric().is_infinite();
        }

        // When running non optimized builds, we want to make sure that if we don't find a selected
        // route then we assert all the other routes matching this destination are infinite.
        #[cfg(debug_assertions)]
        if first_selected.is_none() {
            assert!(
                all_infinite.is_none_or(|all_inf| all_inf),
                "There should either be a selected route or all should be unreachable."
            );
        }

        // Returns either the selected route or an arbitrary infinite route.
        // Returns None if there were no routes matching the destination.
        first_selected.or(last)
    }

    pub(crate) fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut Route<A>) -> bool,
    {
        self.inner.retain_mut(f);
    }

    pub(crate) fn flush(&mut self) {
        self.inner.flush();
    }

    /// Route aquisition as defined in section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition)
    ///
    /// Returns `Ok(true)` if the route aquisition requires an update to be sent.
    pub(crate) fn aquire_route(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        feasible: bool,
        update: &ResolvedUpdate<'_, A>,
    ) -> Result<bool, RouteError> {
        match self.inner.get_mut_by_key(&RouteIndex {
            destination: update.destination,
            neighbour: neighbour.key(),
        }) {
            // The following is a direct quote from section 3.5.3 (marked with ~):
            //~ When a Babel node receives an update (prefix, plen, router-id, seqno, metric) from a
            //~ neighbour neigh, it checks whether it already has a route table entry indexed by
            //~ (prefix, plen, neigh).
            //~ If no such entry exists:
            None => {
                //~ if the update is unfeasible, it **MAY** be ignored
                if !feasible {
                    // TODO: Local setting?
                }
                //~ if the metric is infinite (the update is a retraction of a route we do not know
                //~ about), the update is ignored;
                if update.slice.is_retraction() {
                    // This is technically dead code since the logic of the calling function
                    // does not allow a retraction to reach this point. But I'm
                    // keeping it as a regression backstop.
                    return Ok(false);
                }

                //~ otherwise, a new entry is created in the route table, indexed by (prefix, plen,
                //~ neigh), with source equal to (prefix, plen, router-id), seqno equal to seqno,
                //~ and an advertised metric equal to the metric carried by the update.

                // Calculate the link cost to this neighbour
                let link_cost = interface.cost_calc.link_cost(
                    interface.cost_calc.rx_cost(
                        neighbour.mcast_hello_info.history,
                        neighbour.ucast_hello_info.history,
                    ),
                    neighbour.tx_cost,
                );
                let computed_metric = interface.cost_calc.metric(update.slice.metric(), link_cost);

                // NOTE: Ignore the return value if the table is not full as we just checked above
                // if there would be a duplicate.
                let _ = match self.inner.insert(Route::new(
                    now,
                    SourceIndex {
                        destination: update.destination,
                        router_id: update.router_id,
                    },
                    neighbour.key(),
                    update.slice.seqno(),
                    update.slice.metric(),
                    computed_metric,
                    update.next_hop,
                    // Never add new routes as selected as route selection will be run after each
                    // update.
                    false,
                    update.slice.interval(),
                    self.route_expiry_time,
                )?) {
                    // The only error that matters is if the table is full.
                    Err(InsertError::Full(_)) => {
                        return Err(RouteError::Full);
                    }
                    other => other,
                };
                Ok(false)
            }
            //~ If such an entry exists:
            Some(route) => {
                let mut send_update = false;
                //~ if the entry is currently selected, the update is unfeasible, and the router-id
                //~ of the update is equal to the router-id of the entry, then the update **MAY** be
                //~ ignored
                if route.selected && !feasible && route.source().router_id == update.router_id {
                    // TODO: Local setting?
                } else {
                    //~ otherwise, the entry's sequence number, advertised metric, metric, and router-id
                    //~ are updated,

                    // ANALYSIS:
                    // The inverse of the if statement above is worth stating and examining
                    // (condition by condition) what would cause this block to execute in order to
                    // understand the implicit behaviors of this block.

                    // The inverse of the statement is:

                    // If the route is NOT selected
                    //   OR the update is feasible
                    //   OR the route does not match the update router ID.

                    // 1. IF the route is selected THEN the update is either feasible OR the router id
                    // has changed.
                    //   a. In the case that it is only feasible, then you want to update your metric
                    //     because this is the entire premise the Babel algorithm is based on. Only
                    //     update your metric when feasibility is better.
                    //   b. In the case that it is a router ID change, that means the originator of
                    //     the Seqno is no longer the same as the previous Seqno. So this node MUST
                    //     update its metric.
                    //   c. Since both of those cases require an update to the route, they are
                    //     collapsed into one.

                    // 2. IF the update is NOT feasible THEN the route is not selected OR the router
                    // id has changed.
                    //   d. In the case the route is not selected, we want to unconditionally keep
                    //     track of it. This is a method for keeping track of unselected routes to
                    //     allow for fast failover if a route fails.
                    //   e. The router ID change case is covered by b. above.
                    //   f. The union case is covered by c. above.

                    // 3. IF the router ID has NOT changed.
                    //   g. The case of the route not being selected is covered by d. above.
                    //   h. The case of a feasible update is covered by a. above.
                    //   i. The union case is covered by c. above.

                    // TL;DR:
                    // - Only update selected routes when feasible.
                    // - The premise of feasibility relies on the source of Seqno, which is tracked by
                    // router-id, if this changes then Seqno and metric require a hard reset.
                    // - Keep track of all non-selected routes (without regard to feasibility) for
                    // fast failover.

                    // The new hold time is built before the entry is touched. An Interval the timer
                    // rejects has to leave the entry exactly as it was, rather than half-updated with
                    // a new metric under the old expiry and the deselect below never reached.
                    let expiry = Timer::from_duration(
                        now,
                        Duration::from(update.slice.interval()) * self.route_expiry_time,
                    )?;

                    //~ and if the advertised metric is not infinite, the route's expiry
                    //~ timer is reset to a small multiple of the interval value included in the update
                    //~ (see "Route Expiry time" in Appendix B for suggested values).
                    if !update.slice.is_retraction() {
                        // This if statement is is likely always true since the logic of the
                        // calling function does not allow a retraction to reach this point. But I'm
                        // keeping it as a regression backstop.
                        route.expiry = expiry;
                    }

                    //~ If the update is unfeasible, then the (now unfeasible) entry MUST be immediately
                    //~ unselected. (Taken care of in route selection)
                    if !feasible {
                        route.selected = false;
                    }

                    if route.source().router_id != update.router_id {
                        //~ If the update caused the router-id of the entry to change, an update
                        //~ (possibly a retraction) MUST be sent in a timely manner as described in
                        //~ Section 3.7.2.
                        route.set_router_id(update.router_id);

                        // If the router ID for this route was changed and it was selected, and update
                        // MUST be sent.
                        send_update |= route.selected;
                    }

                    route.seqno = update.slice.seqno();

                    route.set_advertised_metric(update.slice.metric());
                }

                Ok(send_update)
            }
        }
    }

    /// Groups the routes in the table by the destination (prefix, plen) they lead to.
    //  `chunk_by` produces "runs" of elements. So this only works because one of the main
    //  predicates of `ManagedSlice<'storage, Option<V>>` is that it is always sorted. The key for
    // the items in this particular `ManagedSlice` is a struct that consists of `(prefix,
    // prefix_len, neighbour)`. Sorting by a key is also sorting by a subset of that key, so
    // this grouping works.
    pub(crate) fn destination_groups_mut(
        &mut self,
    ) -> impl Iterator<Item = DestinationGroup<'_, A>> {
        self.inner
            .chunk_by_mut(|a, b| destination_of(a) == destination_of(b))
            .filter(|group| group.first().is_some_and(Option::is_some))
            .map(DestinationGroup)
    }
}

/// A non-empty run of route table entries that all lead to the same destination.
///
/// Yielded by [`RouteTable::destination_groups_mut`]. The wrapper exists to keep the `Option` that
/// the table's free slots are made of out of the route selection code: every slot in a group is
/// occupied, because free slots sort ahead of every occupied one and so collapse into a single
/// leading run that the grouping discards.
pub(crate) struct DestinationGroup<'storage, A: AddressExt>(&'storage mut [Option<Route<A>>]);

impl<A: AddressExt> DestinationGroup<'_, A> {
    /// The destination that every route in this group leads to.
    pub(crate) fn destination(&self) -> RouteDestination<A> {
        *self
            .iter()
            .next()
            .expect("a destination group always holds at least one route")
            .destination()
    }

    /// The number of routes towards this destination.
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Route<A>> {
        self.0.iter().flatten()
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route<A>> {
        self.0.iter_mut().flatten()
    }
}

/// The destination of an occupied slot, or `None` for a free one.
///
/// Free slots compare equal to each other and to nothing else, which is what collapses them into
/// the single leading group that [`RouteTable::destination_groups_mut`] discards.
fn destination_of<A: AddressExt>(entry: &Option<Route<A>>) -> Option<RouteDestination<A>> {
    entry.as_ref().map(|e| *e.destination())
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::InterfaceHandle;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::router::config::DEFAULT_ROUTE_EXPIRY_TIME;
    use crate::utils::Duration;

    /// Long enough that nothing expires mid-test, still inside the Timer bound.
    const INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));

    const DEST_A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
    const DEST_B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0);
    const NEIGHBOUR_1: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_2: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    const IFACE: &str = "eth0";

    fn iface_handle() -> InterfaceHandle {
        InterfaceHandle::try_from(IFACE).expect("bad interface handle")
    }

    fn route(
        prefix: Ipv6Addr,
        prefix_len: u8,
        router_id: &str,
        neighbour: Ipv6Addr,
    ) -> Route<NoExtension> {
        route_with_metrics(
            prefix,
            prefix_len,
            router_id,
            neighbour,
            Metric::from(10),
            Metric::from(10),
        )
    }

    /// [`route`], with the advertised and computed metrics the caller wants it settled at. The
    /// smoothed metric starts out equal to the computed one, as it does for any freshly created
    /// entry.
    fn route_with_metrics(
        prefix: Ipv6Addr,
        prefix_len: u8,
        router_id: &str,
        neighbour: Ipv6Addr,
        advertised_metric: Metric,
        computed_metric: Metric,
    ) -> Route<NoExtension> {
        Route::new(
            Instant::from_secs(0),
            SourceIndex {
                destination: RouteDestination::new(prefix.into(), prefix_len)
                    .expect("bad destination"),
                router_id: RouterId::try_from(router_id).expect("bad router id"),
            },
            NeighbourIndex {
                iface: iface_handle(),
                addr: neighbour.into(),
            },
            SeqNo(0),
            advertised_metric,
            computed_metric,
            neighbour.into(),
            false,
            INTERVAL,
            DEFAULT_ROUTE_EXPIRY_TIME,
        )
        .expect("bad expiry")
    }

    /// The grouping is by destination, so two routes towards one prefix belong together even when
    /// they were originated by different routers. Section 3.7.2 depends on that: the selected
    /// router-id for a destination can only *change* if routes with differing router-ids compete
    /// against each other.
    #[test]
    fn groups_by_destination_across_router_ids_and_neighbours() {
        let mut table = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);

        // Inserted out of order, and with a same-prefix/different-plen pair, to show the grouping
        // does not lean on insertion order and that plen is part of the destination.
        for r in [
            route(DEST_B, 64, "rtr-b", NEIGHBOUR_1),
            route(DEST_A, 64, "rtr-b", NEIGHBOUR_2),
            route(DEST_A, 32, "rtr-a", NEIGHBOUR_1),
            route(DEST_A, 64, "rtr-a", NEIGHBOUR_1),
        ] {
            table.inner.insert(r).expect("owned storage grows");
        }

        let groups: Vec<(RouteDestination<NoExtension>, Vec<Route<NoExtension>>)> = table
            .destination_groups_mut()
            .map(|group| (group.destination(), group.iter().copied().collect()))
            .collect();

        assert_eq!(
            groups.len(),
            3,
            "(DEST_A, 32), (DEST_A, 64) and (DEST_B, 64)"
        );

        for (destination, routes) in &groups {
            assert!(!routes.is_empty(), "empty slots must not be yielded");
            assert!(
                routes.iter().all(|r| r.destination() == destination),
                "every route in a group shares one destination"
            );
        }

        // The two routes towards (DEST_A, 64) land in one group despite differing in both
        // router-id and neighbour.
        let (_, dest_a_64) = groups
            .iter()
            .find(|(d, _)| d == &RouteDestination::new(DEST_A.into(), 64).unwrap())
            .expect("(DEST_A, 64) group");
        assert_eq!(dest_a_64.len(), 2);
        assert_ne!(
            dest_a_64[0].source().router_id,
            dest_a_64[1].source().router_id,
            "router-id is not part of the destination"
        );
    }

    /// Free slots sort ahead of every occupied one, so they have to be dropped rather than yielded
    /// as a group of their own.
    #[test]
    fn skips_free_slots() {
        let mut storage: [Option<Route<NoExtension>>; 4] = [const { None }; 4];
        let mut table = RouteTable::new_with_storage(&mut storage[..], DEFAULT_ROUTE_EXPIRY_TIME);
        table
            .inner
            .insert(route(DEST_A, 64, "rtr-a", NEIGHBOUR_1))
            .expect("space for one route");

        let groups: Vec<usize> = table.destination_groups_mut().map(|g| g.len()).collect();

        assert_eq!(groups, alloc::vec![1], "three free slots, one real group");
    }
}
