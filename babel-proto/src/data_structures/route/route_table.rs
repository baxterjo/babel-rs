use core::iter::zip;

use crate::data_structures::interface::{Interface, InterfaceTable};
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex, NeighbourTable};
use crate::data_structures::route::route_entry::Route;
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::{SourceIndex, SourceTable};
use crate::data_structures::updates::Update;
use crate::data_types::destination::RouteDestination;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::metric::Metric;
use crate::packet::parser::Parser;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::storage::{InsertError, InternallyKeyed, MaybeInUse, Recycle, Table, TableSlot};
use crate::utils::{Duration, DurationMultiplier, Instant, ManagedSlice};

pub const DEFAULT_SMOOTHING_MULTIPLE: DurationMultiplier = DurationMultiplier::new(3, 1);
pub const METRIC_DIFFERENCE_THRESHOLD: Metric = Metric::from_raw(100);

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    /// The inner slice for the table.
    inner: Table<'storage, MaybeInUse<Route<'storage, A>>>,

    /// The multiple of a route's update interval that will determine how long this table keeps the
    /// route.
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
    /// Initializes the route storage with update queue storage.
    pub(crate) fn init_storage<const R: usize, const N: usize>(
        route_storage: &mut [MaybeInUse<Route<'storage, A>>; R],
        update_queue: &'storage mut [[Option<Update<A>>; N]; R],
    ) {
        for (route_slot, update_queue) in zip(route_storage.iter_mut(), update_queue.iter_mut()) {
            update_queue.fill(None);
            *route_slot = MaybeInUse::new_free(update_queue.as_mut_slice().into())
        }
    }

    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of routes this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub(crate) fn new_with_storage<T>(storage: T, route_expiry: DurationMultiplier) -> Self
    where
        T: Into<ManagedSlice<'storage, MaybeInUse<Route<'storage, A>>>>,
    {
        Self {
            inner: Table::new(storage),
            route_expiry_time: route_expiry,
            smoothing_multiple: DEFAULT_SMOOTHING_MULTIPLE,
        }
    }

    pub(crate) fn retain_mut<F>(&mut self, f: F)
    where
        F: FnMut(&mut Route<A>) -> bool,
    {
        self.inner.retain_mut(f);
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route<'storage, A>> {
        self.inner.iter_mut()
    }

    pub(crate) fn get_mut_by_key(
        &mut self,
        key: &RouteIndex<A>,
    ) -> Option<&mut Route<'storage, A>> {
        self.inner.get_mut_by_key(key)
    }

    pub(crate) fn add_route(
        &mut self,
        now: Instant,
        source: SourceIndex<A>,
        neighbour: NeighbourIndex<A>,
        seqno: SeqNo,
        advertised_metric: Metric,
        computed_metric: Metric,
        next_hop: Address<A>,
        interval: Interval,
    ) -> Result<(), RouteError> {
        let storage = self
            .inner
            .get_storage()
            .ok_or(RouteError::NoStorageAvaliable)?;

        let route = Route::new(
            now,
            source,
            neighbour,
            seqno,
            advertised_metric,
            computed_metric,
            next_hop,
            // Routes are never added as selected; route selection runs after each update.
            false,
            interval,
            self.route_expiry_time,
            storage,
        );

        // If there is an error inserting the route then the storage needs to be returned to the
        // table.
        if let Err(err) = self.inner.insert(route) {
            match err {
                InsertError::Full(route) => {
                    self.inner.return_storage(route.release());
                    return Err(RouteError::Full);
                }
                InsertError::Duplicate(route) => {
                    self.inner.return_storage(route.release());
                    return Err(RouteError::Duplicate);
                }
            }
        };

        Ok(())
    }

    /// Recomputes the metric of every route `neighbour` advertised, and queues a triggered update
    /// for any of them still holding a destination whose metric moved significantly.
    ///
    /// `interfaces` and `neighbours` are only there for that queueing — a triggered update goes to
    /// every neighbour on every interface, not just the one whose link cost moved.
    pub(crate) fn update_metrics_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        interfaces: &InterfaceTable<A>,
        neighbours: &NeighbourTable<A>,
    ) {
        let smoothing_multiple = self.smoothing_multiple;
        let neighbour_idx = neighbour.key();

        for route in self
            .inner
            .iter_mut()
            .filter(|route| route.neigbour() == &neighbour_idx)
        {
            let old_computed = *route.computed_metric();
            route.compute_metric(now, interface, neighbour, &smoothing_multiple);

            // Every route over this neighbour has its metric recomputed, but only the selected one
            // can be worth relaying. 3.7.2 scopes the significant-metric trigger to the route that
            // holds its destination: an unselected route was never advertised onwards, so no
            // neighbour is holding a belief about it that the move would correct.
            if route.selected
                && route.computed_metric().abs_diff(old_computed) > METRIC_DIFFERENCE_THRESHOLD
            {
                route.broadcast_update(now, interfaces, neighbours, None);
            }
        }
    }

    /// Groups the routes in the table by the destination (prefix, plen) they lead to.
    //  `chunk_by` produces "runs" of elements. So this only works because one of the main
    //  predicates of `Table<'storage, MaybeInUse<V>>` is that it is always sorted. The key for
    // the items in this particular `Table` is a struct that consists of `(prefix,
    // prefix_len, neighbour)`. Sorting by a key is also sorting by a subset of that key, so
    // this grouping works.
    pub(crate) fn destination_groups_mut(
        &mut self,
    ) -> impl Iterator<Item = DestinationGroup<'_, 'storage, A>> {
        self.inner
            // Chunk by runs of the same destination
            .chunk_by_mut(|a, b| destination_of(a) == destination_of(b))
            // Filter out empty chunks and chunks that don't contain routes
            .filter(|group| group.first().is_some_and(|first| first.value().is_some()))
            // Map the chunk to a destination route.
            .map(DestinationGroup)
    }

    /// Writes out whatever the route updates this table owes on `interface`.
    pub(crate) fn poll_for_updates<'output, P>(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        sources: &mut SourceTable<'_, A>,
        update_interval: Interval,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    >
    where
        P: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
    {
        // Start the parser for the packet with the initial next hop equal to the address of the
        // interface this packet will be sent on.
        let mut parser: Parser<P> = Parser::new(interface.address);

        for route in self.inner.iter_mut() {
            writer = route.poll_for_updates::<P>(
                now,
                interface,
                sources,
                update_interval,
                active_dest,
                next_poll,
                &mut parser,
                writer,
            )?;
        }

        Ok(writer)
    }
}

/// A non-empty run of route table entries that all lead to the same destination.
pub(crate) struct DestinationGroup<'a, 'storage, A: AddressExt>(
    &'a mut [MaybeInUse<Route<'storage, A>>],
);

impl<'storage, A: AddressExt> DestinationGroup<'_, 'storage, A> {
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

    pub(crate) fn iter(&self) -> impl Iterator<Item = &Route<'storage, A>> {
        self.0.iter().filter_map(|r| r.value())
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Route<'storage, A>> {
        self.0.iter_mut().filter_map(|r| r.value_mut())
    }
}

/// The destination of an occupied slot, or `None` for a free one.
///
/// Free slots compare equal to each other and to nothing else, which is what collapses them into
/// the single leading group that [`RouteTable::destination_groups_mut`] discards.
fn destination_of<A: AddressExt>(entry: &MaybeInUse<Route<A>>) -> Option<RouteDestination<A>> {
    entry.value().map(|e| *e.destination())
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

    fn get_storage<'storage, const R: usize, const N: usize, A: AddressExt>() -> (
        [MaybeInUse<Route<'storage, A>>; R],
        [[Option<Update<A>>; N]; R],
    ) {
        ([const { MaybeInUse::Vacant }; R], [[const { None }; N]; R])
    }

    /// Adds a route to `table`, taking its update queue out of the table's own pool the way
    /// [`RouteTable::aquire_route`] does.
    ///
    /// A route owns the queue it was handed, so it can no longer be built standalone and handed to
    /// the table afterwards: the queue has to come from the table it is going to live in.
    fn insert_route(
        table: &mut RouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        prefix_len: u8,
        router_id: &str,
        neighbour: Ipv6Addr,
    ) {
        insert_route_with_metrics(
            table,
            prefix,
            prefix_len,
            router_id,
            neighbour,
            Metric::from(10),
            Metric::from(10),
        )
    }

    /// [`insert_route`], with the advertised and computed metrics the caller wants it settled at.
    /// The smoothed metric starts out equal to the computed one, as it does for any freshly created
    /// entry.
    fn insert_route_with_metrics(
        table: &mut RouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        prefix_len: u8,
        router_id: &str,
        neighbour: Ipv6Addr,
        advertised_metric: Metric,
        computed_metric: Metric,
    ) {
        table
            .add_route(
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
                INTERVAL,
            )
            .expect("the table has a free slot and update queue storage for the route");
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
        insert_route(&mut table, DEST_B, 64, "rtr-b", NEIGHBOUR_1);
        insert_route(&mut table, DEST_A, 64, "rtr-b", NEIGHBOUR_2);
        insert_route(&mut table, DEST_A, 32, "rtr-a", NEIGHBOUR_1);
        insert_route(&mut table, DEST_A, 64, "rtr-a", NEIGHBOUR_1);

        // A route owns its update queue, so it cannot be lifted out of the table to be inspected
        // later. Its source carries both things the assertions below are about -- destination and
        // router-id -- and is `Copy`, so that is what gets collected.
        let groups: Vec<(RouteDestination<NoExtension>, Vec<SourceIndex<NoExtension>>)> = table
            .destination_groups_mut()
            .map(|group| {
                (
                    group.destination(),
                    group.iter().map(|r| *r.source()).collect(),
                )
            })
            .collect();

        assert_eq!(
            groups.len(),
            3,
            "(DEST_A, 32), (DEST_A, 64) and (DEST_B, 64)"
        );

        for (destination, sources) in &groups {
            assert!(!sources.is_empty(), "empty slots must not be yielded");
            assert!(
                sources.iter().all(|s| &s.destination == destination),
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
            dest_a_64[0].router_id, dest_a_64[1].router_id,
            "router-id is not part of the destination"
        );
    }

    /// Free slots sort ahead of every occupied one, so they have to be dropped rather than yielded
    /// as a group of their own.
    #[test]
    fn skips_free_slots() {
        let (mut route_storage, mut update_queue) = get_storage::<'_, 4, 4, NoExtension>();
        RouteTable::init_storage(&mut route_storage, &mut update_queue);
        let mut table =
            RouteTable::new_with_storage(&mut route_storage[..], DEFAULT_ROUTE_EXPIRY_TIME);
        insert_route(&mut table, DEST_A, 64, "rtr-a", NEIGHBOUR_1);

        let groups: Vec<usize> = table.destination_groups_mut().map(|g| g.len()).collect();

        assert_eq!(groups, alloc::vec![1], "three free slots, one real group");
    }
}
