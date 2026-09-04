use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::route::route_entry::{Destination, Route};
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::packet::parser::ResolvedUpdate;
use crate::utils::storage::Table;
use crate::utils::{Duration, DurationMultiplier, Instant, InternallyKeyed, ManagedSlice, Timer};

pub const DEFAULT_SMOOTHING_MULTIPLE: DurationMultiplier = DurationMultiplier::new(3, 1);
pub const METRIC_DIFFERENCE_THRESHOLD: Metric = Metric::from_raw(100);

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    /// The inner slice for the table.
    pub(crate) inner: Table<'storage, RouteIndex<A>, Route<A>>,

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

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route<A>> {
        self.inner.iter_mut()
    }

    pub(crate) fn iter_mut_slots(&mut self) -> impl Iterator<Item = &mut Option<Route<A>>> {
        self.inner.iter_mut_slots()
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Route<A>> {
        self.inner.iter()
    }

    /// The route an index names, if it is still in the table.
    pub(crate) fn get_by_key(&self, key: &RouteIndex<A>) -> Option<&Route<A>> {
        self.inner.get_by_key(key)
    }

    /// Test-only door into the table's storage.
    ///
    /// Production code only ever gains a route through [`Self::aquire_route`], which needs an
    /// interface, a neighbour and a parsed update to build one. Tests in other modules need a
    /// table with known contents without staging all of that.
    #[cfg(test)]
    pub(crate) fn insert(&mut self, route: Route<A>) -> Result<Option<Route<A>>, Route<A>> {
        self.inner.insert(route)
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
            prefix: update.address,
            prefix_len: update.slice.plen(),
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

                if let Err(err) = self.inner.insert(Route::new(
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
                )?) {
                    b_debug!("Route table full - Discarded: {:?}", err);
                }
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
                router_id: RouterId::try_from(router_id).expect("bad router id"),
                prefix: prefix.into(),
                prefix_len,
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

    //  ___  ___  _   _ _____ ___     _   ___ ___  _   _ ___ ___ ___ _____ ___ ___  _  _
    // | _ \/ _ \| | | |_   _| __|   /_\ / __/ _ \| | | |_ _/ __|_ _|_   _|_ _/ _ \| \| |
    // |   / (_) | |_| | | | | _|   / _ \ (_| (_) | |_| || |\__ \| |  | |  | | (_) | .` |
    // |_|_\\___/ \___/  |_| |___| /_/ \_\___\__\_\\___/|___|___/___| |_| |___\___/|_|\_|

    /// The `bool` [`RouteTable::aquire_route`] returns is the triggered-update decision of RFC 8966
    /// [3.7.2](https://datatracker.ietf.org/doc/html/rfc8966#name-triggered-updates). Of the
    /// triggers that section lists, acquisition reports exactly one:
    ///
    /// * "if the router-id of the selected route for a given prefix changes, a node MUST send an
    ///   update".
    ///
    /// It is scoped to the *selected* route. Nothing this node puts on the wire is derived from an
    /// unselected route, so its originator changing is not news to anybody.
    ///
    /// The other two triggers are not visible here, because acquisition no longer sees the values
    /// they turn on:
    ///
    /// * the metric "changing significantly" is decided against the *computed* metric, and
    ///   acquisition only records the advertised one — the computed metric is derived once per
    ///   packet, after every Update in it has been applied, so it is `update_metrics_for_neighbour`
    ///   that compares the two and relays the move;
    /// * the selected route for a destination changing is decided by `select_routes`, which runs
    ///   after acquisition.
    ///
    /// Both of those are covered by the `triggered_updates` tests in `router::handle_input`, which
    /// can drive a whole router and so can reach the stage that owns them.
    mod route_acquisition {
        use super::*;
        use crate::data_structures::interface::{Interface, InterfaceConfig};
        use crate::data_structures::neighbour::{Neighbour, NeighbourConfig};
        use crate::metric::{KOutOfJ, TxCost};
        use crate::packet::parser::ResolvedUpdate;
        use crate::packet::tlv::reader::TlvReader;
        use crate::packet::tlv::{Tlv, TypedTlv, UpdateSlice};

        /// This node's own address on [`IFACE`].
        const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0xff);

        /// The txcost the neighbour below was last told about in an IHU. `KOutOfJ` makes the link
        /// cost equal to it once the rxcost is finite, and the spec metric is additive, so every
        /// computed metric here is exactly `advertised + LINK_COST`.
        const LINK_COST: u16 = 20;

        /// The Interval every Update TLV below advertises, in centiseconds.
        const UPDATE_INTERVAL_CENTIS: u16 = 200;

        /// The advertised metric the route in the table below is sitting at, and so the one an
        /// Update has to move away from to be "significant".
        const SETTLED_ADVERTISED: u16 = 480;

        /// The two router-ids a route can be advertised under here.
        const ORIGIN_1: &str = "origin-1";
        const ORIGIN_2: &str = "origin-2";

        fn t0() -> Instant {
            Instant::from_secs(0)
        }

        /// A wired interface, so the cost calculator is the `KOutOfJ` [`LINK_COST`] depends on.
        fn interface() -> Interface<NoExtension> {
            Interface::new(
                t0(),
                InterfaceConfig::new_wired(iface_handle(), NODE_ADDR.into()),
            )
            .expect("bad interface config")
        }

        /// A neighbour in the state a route needs to compute a finite metric: enough hellos heard
        /// for a finite rxcost, and a txcost from an IHU. Missing either one puts the link cost at
        /// infinity and every metric below with it.
        fn established_neighbour(addr: Ipv6Addr) -> Neighbour<NoExtension> {
            let mut neighbour = Neighbour::new(
                t0(),
                NeighbourConfig::spec_default(iface_handle(), addr.into()),
            )
            .expect("bad neighbour config");
            neighbour
                .mcast_hello_info
                .history
                .record_many(true, KOutOfJ::SPEC_J.into());
            neighbour.tx_cost = TxCost::from_raw(LINK_COST);
            neighbour
        }

        /// The wire bytes of one AE 2 Update TLV, so these tests reach acquisition through the same
        /// accessors a real packet does rather than through a second, test-only encoder.
        fn update_bytes(metric: u16, seqno: u16) -> Vec<u8> {
            // The leading 8 octets of DEST_A, which is the whole of an AE 2 /64 on the wire.
            let prefix = &DEST_A.octets()[..8];
            let mut bytes = alloc::vec![
                UpdateSlice::TYPE_ID,
                u8::try_from(UpdateSlice::MIN_LEN + prefix.len()).expect("tlv fits in a length"),
                2,  // AE 2: IPv6
                0,  // no flags
                64, // plen
                0,  // nothing omitted
            ];
            bytes.extend_from_slice(&UPDATE_INTERVAL_CENTIS.to_be_bytes());
            bytes.extend_from_slice(&seqno.to_be_bytes());
            bytes.extend_from_slice(&metric.to_be_bytes());
            bytes.extend_from_slice(prefix);
            bytes
        }

        /// The update as acquisition sees it, i.e. after the parser has resolved the prefix, the
        /// router-id and the next hop out of the packet's state.
        fn resolved<'a>(bytes: &'a [u8], router_id: &str) -> ResolvedUpdate<'a, NoExtension> {
            let Some(Tlv::Update(slice)) = TlvReader::new(bytes).next() else {
                panic!("the bytes should hold exactly one Update TLV");
            };
            ResolvedUpdate {
                router_id: RouterId::try_from(router_id).expect("bad router id"),
                address: DEST_A.into(),
                next_hop: NEIGHBOUR_1.into(),
                slice,
            }
        }

        /// A table holding the one route every test below advertises over: `(DEST_A, 64,
        /// NEIGHBOUR_1)`, settled at [`SETTLED_ADVERTISED`] and originated by [`ORIGIN_1`].
        fn table_with_settled_route(selected: bool) -> RouteTable<'static, NoExtension> {
            let mut table = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let mut route = route_with_metrics(
                DEST_A,
                64,
                ORIGIN_1,
                NEIGHBOUR_1,
                Metric::from(SETTLED_ADVERTISED),
                Metric::from(SETTLED_ADVERTISED + LINK_COST),
            );
            route.selected = selected;
            table.insert(route).expect("owned storage grows");
            table
        }

        /// Runs acquisition of a feasible `update` against `table` from [`NEIGHBOUR_1`], which is
        /// the neighbour the settled route above was learned from.
        fn aquire(
            table: &mut RouteTable<'_, NoExtension>,
            update: &ResolvedUpdate<'_, NoExtension>,
        ) -> bool {
            aquire_with_feasibility(table, true, update)
        }

        /// [`aquire`], with the feasibility the caller's source table would have reported chosen by
        /// the test. Feasibility is decided before acquisition is reached, so it is an input here
        /// rather than something the update's own fields imply.
        fn aquire_with_feasibility(
            table: &mut RouteTable<'_, NoExtension>,
            feasible: bool,
            update: &ResolvedUpdate<'_, NoExtension>,
        ) -> bool {
            table
                .aquire_route(
                    t0(),
                    &interface(),
                    &established_neighbour(NEIGHBOUR_1),
                    feasible,
                    update,
                )
                .expect("acquisition should succeed")
        }

        /// The route the tests below are about, read back out of the table.
        fn settled_route(table: &RouteTable<'_, NoExtension>) -> Route<NoExtension> {
            *table
                .get_by_key(&RouteIndex {
                    prefix: DEST_A.into(),
                    prefix_len: 64,
                    neighbour: NeighbourIndex {
                        iface: iface_handle(),
                        addr: NEIGHBOUR_1.into(),
                    },
                })
                .expect("the settled route should still be in the table")
        }

        /// A prefix this node has never heard of is not a metric that "changes significantly" — it
        /// has no previous value to be compared against, and it is not selected, so there is
        /// nothing 3.7.2 asks to be relayed at this point. The update it eventually deserves is the
        /// one route selection triggers when it hands the destination to this new route.
        #[test]
        fn a_new_route_is_created_without_asking_for_an_update() {
            let mut table = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let bytes = update_bytes(100, 1);

            assert!(!aquire(&mut table, &resolved(&bytes, ORIGIN_1)));

            let route = settled_route(&table);
            assert_eq!(*route.advertised_metric(), Metric::from(100));
            assert_eq!(
                *route.computed_metric(),
                Metric::from(100 + LINK_COST),
                "the spec metric is additive over the link cost"
            );
            assert!(!route.selected, "selection has not run yet");
        }

        /// The retraction of a route this node does not have is ignored outright, so there is
        /// nothing to relay. `handle_update` never lets a retraction reach acquisition, so this
        /// pins the backstop rather than a path the router takes.
        #[test]
        fn a_retraction_for_an_unknown_route_asks_for_no_update() {
            let mut table = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let bytes = update_bytes(0xFFFF, 1);

            assert!(!aquire(&mut table, &resolved(&bytes, ORIGIN_1)));
            assert_eq!(table.iter().count(), 0, "no entry is conjured up");
        }

        /// The ordinary case, and by far the most common one: a neighbour repeating what it has
        /// already said. Neither trigger fires, so a periodic refresh must not turn into a
        /// triggered update — if it did, every node on the link would relay every refresh it heard.
        #[test]
        fn a_refresh_that_moves_nothing_asks_for_no_update() {
            let mut table = table_with_settled_route(true);
            let bytes = update_bytes(SETTLED_ADVERTISED, 2);

            assert!(!aquire(&mut table, &resolved(&bytes, ORIGIN_1)));
            assert_eq!(
                settled_route(&table).seqno,
                SeqNo(2),
                "the entry is still refreshed"
            );
        }

        /// "If the router-id of the selected route for a given prefix changes, a node MUST send an
        /// update" — the one MUST in 3.7.2, because a router-id change is what tells the rest of
        /// the network the prefix has moved to a different originator.
        #[test]
        fn a_router_id_change_on_the_selected_route_asks_for_an_update() {
            let mut table = table_with_settled_route(true);
            let bytes = update_bytes(SETTLED_ADVERTISED, 2);

            assert!(aquire(&mut table, &resolved(&bytes, ORIGIN_2)));
            assert_eq!(
                settled_route(&table).source().router_id,
                RouterId::try_from(ORIGIN_2).expect("bad router id"),
                "the entry is repointed at the new originator either way"
            );
        }

        /// The same change on a route that does not hold its destination. Nothing this node
        /// advertises is derived from an unselected route, so its originator moving is not news to
        /// anybody: 3.7.2's MUST is scoped to "the selected route".
        #[test]
        fn a_router_id_change_on_an_unselected_route_asks_for_no_update() {
            let mut table = table_with_settled_route(false);
            let bytes = update_bytes(SETTLED_ADVERTISED, 2);

            assert!(!aquire(&mut table, &resolved(&bytes, ORIGIN_2)));
            assert_eq!(
                settled_route(&table).source().router_id,
                RouterId::try_from(ORIGIN_2).expect("bad router id"),
            );
        }

        /// However far the advertised metric moves, and in whichever direction, acquisition records
        /// it and asks for nothing. The significant-metric trigger is decided against the
        /// *computed* metric, which is not derived until the whole packet has been applied,
        /// so at this stage there is nothing yet to compare against — see
        /// `update_metrics_for_neighbour` and the `triggered_updates` tests that drive it.
        ///
        /// Moves either side of the threshold are all passed in, so a trigger reappearing here
        /// would fail rather than quietly duplicate the relay one stage later.
        #[test]
        fn a_metric_move_of_any_size_asks_for_no_update() {
            for advertised in [
                SETTLED_ADVERTISED + METRIC_DIFFERENCE_THRESHOLD.raw(),
                SETTLED_ADVERTISED + METRIC_DIFFERENCE_THRESHOLD.raw() + 1,
                SETTLED_ADVERTISED - METRIC_DIFFERENCE_THRESHOLD.raw() - 1,
            ] {
                let mut table = table_with_settled_route(true);
                let bytes = update_bytes(advertised, 2);

                assert!(
                    !aquire(&mut table, &resolved(&bytes, ORIGIN_1)),
                    "a move to {advertised} is recorded, not relayed"
                );
                assert_eq!(
                    *settled_route(&table).advertised_metric(),
                    Metric::from(advertised),
                    "the entry is still brought up to date"
                );
            }
        }

        /// The router-id trigger is scoped to the selected route. An unselected route is not what
        /// this node advertises, so its originator changing is not news to anybody.
        ///
        /// The metric is moved here too, so neither half of the condition can be what keeps this
        /// quiet — it is the route not holding its destination.
        #[test]
        fn a_metric_move_on_an_unselected_route_asks_for_no_update() {
            let mut table = table_with_settled_route(false);
            let bytes = update_bytes(
                SETTLED_ADVERTISED + METRIC_DIFFERENCE_THRESHOLD.raw() + 1,
                2,
            );

            assert!(!aquire(&mut table, &resolved(&bytes, ORIGIN_2)));
            assert_eq!(
                *settled_route(&table).advertised_metric(),
                Metric::from(SETTLED_ADVERTISED + METRIC_DIFFERENCE_THRESHOLD.raw() + 1),
                "the entry is still brought up to date, it is just not relayed"
            );
        }

        //  _   _ _  _ ___ ___   _   ___ ___ ___ _    ___
        // | | | | \| | __| __| /_\ / __|_ _| _ ) |  | __|
        // | |_| | .` | _|| _| / _ \\__ \| || _ \ |__| _|
        //  \___/|_|\_|_| |___/_/ \_\___/___|___/____|___|

        /// The one update 3.5.3 lets a node decline outright: "if the entry is currently selected,
        /// the update is unfeasible, and the router-id of the update is equal to the router-id of
        /// the entry, then the update MAY be ignored".
        ///
        /// Taking that option means the entry is left exactly as it was — not updated and then
        /// unselected. All three conditions have to hold at once, so the three tests after this one
        /// drop each in turn and show the update being applied normally.
        #[test]
        fn an_unfeasible_update_from_the_same_router_for_the_selected_route_is_ignored() {
            let mut table = table_with_settled_route(true);
            let before = settled_route(&table);
            let bytes = update_bytes(300, 2);

            assert!(!aquire_with_feasibility(
                &mut table,
                false,
                &resolved(&bytes, ORIGIN_1)
            ));

            let after = settled_route(&table);
            assert_eq!(
                (
                    after.seqno,
                    *after.advertised_metric(),
                    *after.computed_metric()
                ),
                (
                    before.seqno,
                    *before.advertised_metric(),
                    *before.computed_metric()
                ),
                "an ignored update leaves the entry untouched"
            );
            assert!(
                after.selected,
                "and does not unselect it either — there is nothing new to unselect it over"
            );
        }

        /// Drop the router-id condition. A different originator means the seqno this entry's
        /// feasibility was judged against no longer applies, so the entry needs the hard reset
        /// whether or not the update looked unfeasible against the old source.
        ///
        /// Nothing is asked for, because 3.5.3's "if the update is unfeasible, then the (now
        /// unfeasible) entry MUST be immediately unselected" is applied first: by the time the
        /// router-id trigger is reached there is no longer a *selected* route whose originator
        /// changed, and 3.7.2 scopes that trigger to the selected route. The destination losing the
        /// route it was pointing at is `select_routes`' trigger to report on its next run.
        #[test]
        fn an_unfeasible_update_that_changes_the_router_id_is_applied() {
            let mut table = table_with_settled_route(true);
            let bytes = update_bytes(300, 2);

            assert!(!aquire_with_feasibility(
                &mut table,
                false,
                &resolved(&bytes, ORIGIN_2)
            ));

            let route = settled_route(&table);
            assert!(
                !route.selected,
                "an unfeasible update unselects the entry immediately"
            );
            assert_eq!(
                route.source().router_id,
                RouterId::try_from(ORIGIN_2).expect("bad router id")
            );
            assert_eq!(*route.advertised_metric(), Metric::from(300));
        }

        /// Drop the selected condition. An unselected route is the alternative a destination fails
        /// over to, so it is tracked unconditionally — declining to record what a neighbour is
        /// currently offering would leave nothing to fail over *to*.
        ///
        /// Nothing is relayed, because both triggers are scoped to the selected route.
        #[test]
        fn an_unfeasible_update_for_an_unselected_route_is_applied() {
            let mut table = table_with_settled_route(false);
            let bytes = update_bytes(300, 2);

            assert!(!aquire_with_feasibility(
                &mut table,
                false,
                &resolved(&bytes, ORIGIN_1)
            ));

            let route = settled_route(&table);
            assert_eq!(*route.advertised_metric(), Metric::from(300));
            assert_eq!(route.seqno, SeqNo(2));
        }

        /// Drop the unfeasible condition, which is the ordinary path every other test here takes.
        /// Spelled out once against the same fixture so the four cases can be read together.
        #[test]
        fn a_feasible_update_from_the_same_router_for_the_selected_route_is_applied() {
            let mut table = table_with_settled_route(true);
            let bytes = update_bytes(300, 2);

            assert!(
                !aquire(&mut table, &resolved(&bytes, ORIGIN_1)),
                "the router-id is unchanged, and the metric move is not acquisition's to report"
            );

            let route = settled_route(&table);
            assert_eq!(*route.advertised_metric(), Metric::from(300));
            assert_eq!(route.seqno, SeqNo(2));
        }
    }
}
