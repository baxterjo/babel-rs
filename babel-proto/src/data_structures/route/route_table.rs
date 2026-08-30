use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::route::route_entry::{Destination, Route};
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::data_types::address::Address;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::packet::parser::ResolvedUpdate;
use crate::utils::{
    Duration, DurationMultiplier, Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt, Timer,
};

pub const DEFAULT_SMOOTHING_MULTIPLE: DurationMultiplier = DurationMultiplier::new(3, 1);

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    /// The inner slice for the table.
    ///
    /// This should never be made public in any way as the insert/remove functions guarantee:
    /// * The table contents are unique by key
    /// * The table is sorted after any addition / removal of the keys.
    inner: ManagedSlice<'storage, Option<Route<A>>>,

    pub(crate) route_expiry_time: DurationMultiplier,
    /// Multiple of the hello timer of a given route that should be used to generate the time
    /// constant of a route's smoothed metric.
    ///
    /// The time constant will be taken from the max between mcast hello interval and ucast hello
    /// interval (if it exists)
    smoothing_multiple: DurationMultiplier,
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
    pub(crate) fn new_with_storage<T>(table: T, route_expiry: DurationMultiplier) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Route<A>>>>,
    {
        Self {
            inner: table.into(),
            route_expiry_time: route_expiry,
            smoothing_multiple: DEFAULT_SMOOTHING_MULTIPLE,
        }
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route<A>> {
        self.inner.iter_mut().filter_map(|e| e.as_mut())
    }

    pub(crate) fn iter_mut_slots(&mut self) -> impl Iterator<Item = &mut Option<Route<A>>> {
        self.inner.iter_mut()
    }

    pub(crate) fn flush(&mut self) {
        self.inner.flush();
    }

    /// Route aquisition as defined in section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition)
    ///
    /// When a Babel node receives an update (prefix, plen, router-id, seqno, metric) from a
    /// neighbour neigh, it checks whether it already has a route table entry indexed by (prefix,
    /// plen, neigh).
    pub(crate) fn aquire_route(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        feasible: bool,
        update: ResolvedUpdate<'_, A>,
    ) -> Result<(), RouteError> {
        match self.inner.get_mut_by_key(&RouteIndex {
            prefix: update.address,
            prefix_len: update.slice.plen(),
            neighbour: neighbour.key(),
        }) {
            // The following is a direct quote from section 3.5.3:
            // If no such entry exists:
            None => {
                // if the update is unfeasible, it **MAY** be ignored
                if !feasible {
                    // TODO: Local setting?
                }
                // if the metric is infinite (the update is a retraction of a route we do not know
                // about), the update is ignored;
                if update.slice.is_retraction() {
                    // NOTE: This is technically dead code since the logic of the calling function
                    // does not allow a retraction to reach this point. But I'm
                    // keeping it as a regression backstop.
                    return Ok(());
                }

                // otherwise, a new entry is created in the route table, indexed by (prefix, plen,
                // neigh), with source equal to (prefix, plen, router-id), seqno equal to seqno,
                // and an advertised metric equal to the metric carried by the update.
                // NOTE: Ignore returned value as we already checked the entry didn't exist above.
                // Calculate the link cost to this neighbour

                let link_cost = interface.cost_calc.link_cost(
                    interface.cost_calc.rx_cost(
                        neighbour.mcast_hello_info.history,
                        neighbour.ucast_hello_info.history,
                    ),
                    neighbour.tx_cost,
                );
                let computed_metric = interface.cost_calc.metric(update.slice.metric(), link_cost);

                let _ = self.inner.insert(Route::new(
                    now,
                    SourceIndex {
                        prefix: update.address,
                        prefix_len: update.slice.plen(),
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
                )?);
            }
            // If such an entry exists:
            Some(route) => {
                // if the entry is currently selected, the update is unfeasible, and the router-id
                // of the update is equal to the router-id of the entry, then the update **MAY** be
                // ignored
                if route.selected && !feasible && route.source().router_id == update.router_id {
                    // TODO: Local setting?
                }
                // The new hold time is built before the entry is touched. An Interval the timer
                // rejects has to leave the entry exactly as it was, rather than half-updated with
                // a new metric under the old expiry and the deselect below never reached.
                let expiry = Timer::from_duration(
                    now,
                    Duration::from(update.slice.interval()) * self.route_expiry_time,
                )?;

                // otherwise, the entry's sequence number, advertised metric, metric, and router-id
                // are updated,
                route.seqno = update.slice.seqno();
                route.advertised_metric = update.slice.metric();
                if route.source().router_id != update.router_id {
                    // If the update caused the router-id of the entry to change, an update
                    // (possibly a retraction) MUST be sent in a timely manner as described in
                    // Section 3.7.2.
                    // TODO: A router ID change should trigger an update
                    route.set_router_id(update.router_id);
                }
                // and if the advertised metric is not infinite, the route's expiry
                // timer is reset to a small multiple of the interval value included in the update
                // (see "Route Expiry time" in Appendix B for suggested values).
                if !update.slice.is_retraction() {
                    // NOTE: This if statement is redundant since the logic of the calling function
                    // does not allow a retraction to reach this point. But I'm
                    // keeping it as a regression backstop.
                    route.expiry = expiry;
                }
                // If the update is unfeasible, then the (now unfeasible) entry MUST be immediately
                // unselected.
                if !feasible {
                    // NOTE: This is likely redundant as route selection always happens after
                    // updates, and unfeasible routes are cleared during selection. Keeping it here
                    // as a backstop.
                    route.selected = false;
                }

                route.update_cost(now, interface, neighbour, &self.smoothing_multiple);

                // TODO: Triggered updates
            }
        }

        Ok(())
    }

    /// Retracts every route this neighbour advertised, which is what an Update with AE 0 and an
    /// infinite metric asks for.
    ///
    /// The expiry timers are deliberately left alone. Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition) resets a
    /// route's expiry timer only when the advertised metric is finite, so a retracted route runs
    /// out the hold time it already had and is flushed when that timer fires.
    pub(crate) fn handle_blanket_retraction(&mut self, neighbour: &Neighbour<A>) {
        for route in self.iter_mut().filter(|r| *r.neigbour() == neighbour.key()) {
            route.advertised_metric = Metric::INFINITY;
            route.computed_metric = Metric::INFINITY;
        }
    }

    /// Retracts the single route indexed by (prefix, prefix_len, neighbour).
    ///
    /// The seqno and router-id of the entry are left as its last real advertisement set them:
    /// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update) says that for a
    /// retraction "the router-id, next hop, and seqno are not used", so there is nothing
    /// meaningful on the wire to replace them with. See [`Self::handle_blanket_retraction`] for
    /// why the expiry timer is untouched.
    pub(crate) fn handle_retraction(
        &mut self,
        neighbour: &Neighbour<A>,
        prefix: Address<A>,
        prefix_len: u8,
    ) {
        let idx = RouteIndex {
            prefix,
            prefix_len,
            neighbour: neighbour.key(),
        };
        // If an unknown route is somehow retracted, silently ignore.
        if let Some(route) = self.inner.get_mut_by_key(&idx) {
            route.advertised_metric = Metric::INFINITY;
            route.computed_metric = Metric::INFINITY;
        }
    }

    pub(crate) fn update_cost_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
    ) {
        let smoothing_mul = self.smoothing_multiple;
        for route in self.iter_mut().filter(|r| r.neigbour() == &neighbour.key()) {
            route.update_cost(now, interface, neighbour, &smoothing_mul);
        }
    }

    /// Groups the routes in the table by the destination (prefix, plen) they lead to.
    //  `chunk_by` produces "runs" of elements. So this only works because one of the main
    //  predicates of `ManagedSliceExt` is that it is always sorted. The key for he items in this
    // particular `ManagedSliceExt` is a struct that consists of `(prefix, prefix_len, neighbour)`.
    // Sorting by a key is also sorting by a subset of that key, so this grouping works.
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
    pub(crate) fn destination(&self) -> Destination<A> {
        self.iter()
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
fn destination_of<A: AddressExt>(entry: &Option<Route<A>>) -> Option<Destination<A>> {
    entry.as_ref().map(Route::destination)
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

    fn route(
        prefix: Ipv6Addr,
        prefix_len: u8,
        router_id: &str,
        neighbour: Ipv6Addr,
    ) -> Route<NoExtension> {
        Route::new(
            Instant::from_secs(0),
            SourceIndex {
                router_id: RouterId::try_from(router_id).expect("bad router id"),
                prefix: prefix.into(),
                prefix_len,
            },
            NeighbourIndex {
                iface: InterfaceHandle::try_from("eth0").expect("bad interface handle"),
                addr: neighbour.into(),
            },
            SeqNo(0),
            Metric::from(10),
            Metric::from(10),
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

        let groups: Vec<(Destination<NoExtension>, Vec<Route<NoExtension>>)> = table
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
                routes.iter().all(|r| r.destination() == *destination),
                "every route in a group shares one destination"
            );
        }

        // The two routes towards (DEST_A, 64) land in one group despite differing in both
        // router-id and neighbour.
        let (_, dest_a_64) = groups
            .iter()
            .find(|(d, _)| d.prefix_len == 64 && d.prefix == DEST_A.into())
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
