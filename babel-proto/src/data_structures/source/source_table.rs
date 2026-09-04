use crate::data_structures::route::Route;
use crate::data_structures::source::source_entry::SPEC_DEFAULT_SOURCE_GC_TIME;
use crate::data_structures::source::{Source, SourceError, SourceIndex};
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::utils::storage::Table;
use crate::utils::{Instant, ManagedSlice};

pub struct SourceTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: Table<'storage, SourceIndex<A>, Source<A>>,
}

impl<'storage, A> SourceTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of sources this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Source<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }
}

impl<A: AddressExt> SourceTable<'_, A> {
    /// This is a read only check to see if an incoming update is feasible. The source table will
    /// be updated when updates are sent to neighbours.
    pub fn is_feasible(&self, idx: &SourceIndex<A>, metric: &Metric, seqno: &SeqNo) -> bool {
        // If the update is a retraction then it is automatically feasible.
        if metric == &Metric::INFINITY {
            return true;
        }
        // If the table does not contain the source, then the update is automatically feasible.
        let Some(source) = self.inner.get_by_key(idx) else {
            return true;
        };

        // Otherwise, check against the best feasibility ever sent for this route.
        let incoming_feasibility = Feasibility::new(*seqno, *metric);
        incoming_feasibility < source.feasibility
    }

    /// Source table maintenance as described in
    /// [Section 3.7.3](https://datatracker.ietf.org/doc/html/rfc8966#name-maintaining-feasibility-dis)
    pub(crate) fn perform_maintenance(
        &mut self,
        now: Instant,
        route: &Route<A>,
    ) -> Result<(), SourceError> {
        b_trace!("Performing maintenance for {:?}", route);

        if route.computed_metric() == &Metric::INFINITY {
            return Ok(());
        }

        let Some(source) = self.inner.get_mut_by_key(route.source()) else {
            b_trace!("Route not in source table, adding.");
            // Just checked if there was something in the table.
            let _ = self.inner.insert(Source::new(
                now,
                route.source().prefix,
                route.source().prefix_len,
                route.source().router_id,
                route.seqno,
                *route.computed_metric(),
                SPEC_DEFAULT_SOURCE_GC_TIME,
            )?);
            return Ok(());
        };

        let advertised = route.feasibility();
        if advertised < source.feasibility {
            b_trace!("Updating {:?}", advertised);
            source.feasibility = advertised;
        }

        source.gc_timer.restart(now);

        b_trace!("Route maintenance complete");

        Ok(())
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::InterfaceHandle;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_types::{Address, Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::router::config::DEFAULT_ROUTE_EXPIRY_TIME;
    use crate::utils::Duration;

    /// Long enough that no route expires mid-test, still inside the `Timer` bound.
    const INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));

    const DEST_A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
    const DEST_B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0);
    const NEIGHBOUR_1: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    fn t0() -> Instant {
        Instant::from_secs(0)
    }

    fn router_id(name: &str) -> RouterId {
        RouterId::try_from(name).expect("bad router id")
    }

    fn neighbour(addr: Ipv6Addr) -> NeighbourIndex<NoExtension> {
        NeighbourIndex {
            iface: InterfaceHandle::try_from("eth0").expect("bad interface handle"),
            addr: addr.into(),
        }
    }

    fn source_index(
        prefix: impl Into<Address<NoExtension>>,
        prefix_len: u8,
        id: &str,
    ) -> SourceIndex<NoExtension> {
        SourceIndex {
            router_id: router_id(id),
            prefix: prefix.into(),
            prefix_len,
        }
    }

    /// A route whose *advertised* and *computed* metrics are the same, which is the ordinary case:
    /// what a neighbour told us and what we would pass on only diverge by the link cost.
    fn route(source: SourceIndex<NoExtension>, seqno: u16, metric: u16) -> Route<NoExtension> {
        route_advertising(source, seqno, metric, metric)
    }

    /// [`route`] with the two metrics pulled apart, for the tests that care which one is recorded.
    fn route_advertising(
        source: SourceIndex<NoExtension>,
        seqno: u16,
        advertised_metric: u16,
        computed_metric: u16,
    ) -> Route<NoExtension> {
        Route::new(
            t0(),
            source,
            neighbour(NEIGHBOUR_1),
            SeqNo(seqno),
            Metric::from(advertised_metric),
            Metric::from(computed_metric),
            NEIGHBOUR_1.into(),
            true,
            INTERVAL,
            DEFAULT_ROUTE_EXPIRY_TIME,
        )
        .expect("bad expiry")
    }

    fn empty_table() -> SourceTable<'static, NoExtension> {
        SourceTable::new_with_storage(Vec::new())
    }

    /// A table already holding one entry for `source`, recorded the way the code under test would
    /// have recorded it — every "existing entry" test starts from a real create.
    fn table_holding(
        source: SourceIndex<NoExtension>,
        seqno: u16,
        metric: u16,
    ) -> SourceTable<'static, NoExtension> {
        let mut table = empty_table();
        table
            .perform_maintenance(t0(), &route(source, seqno, metric))
            .expect("seeding a fresh table cannot fail");
        table
    }

    /// The feasibility distance recorded for `source`, or `None` if the table has no entry.
    fn fd(
        table: &SourceTable<'_, NoExtension>,
        source: &SourceIndex<NoExtension>,
    ) -> Option<Feasibility> {
        table.inner.get_by_key(source).map(|s| s.feasibility)
    }

    fn entry_count(table: &SourceTable<'_, NoExtension>) -> usize {
        table.inner.iter().count()
    }

    /// How long `source`'s garbage-collection timer has left as of `now`, or `None` once it has
    /// fired. A full [`SPEC_DEFAULT_SOURCE_GC_TIME`] means it was just restarted.
    fn gc_remaining(
        table: &SourceTable<'_, NoExtension>,
        source: &SourceIndex<NoExtension>,
        now: Instant,
    ) -> Option<Duration> {
        table
            .inner
            .get_by_key(source)
            .expect("entry should exist")
            .gc_timer
            .time_remaining(now)
    }

    //  ___ ___ _____ ___    _   ___ _____ ___ ___  _  _ ___
    // | _ \ __|_   _| _ \  /_\ / __|_   _|_ _/ _ \| \| / __|
    // |   / _|  | | |   / / _ \ (__  | |  | | (_) | .` \__ \
    // |_|_\___| |_| |_|_\/_/ \_\___| |_| |___\___/|_|\_|___/

    /// RFC 8966 3.7.3 scopes the whole procedure to updates "with finite metric (i.e., not a route
    /// retraction)". A retraction carries no distance to be feasible with respect to, so recording
    /// one would invent a feasibility distance out of a route we just told everyone is unusable.
    #[test]
    fn a_retraction_creates_no_source() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = empty_table();

        table
            .perform_maintenance(t0(), &route(source, 5, Metric::INFINITY.raw()))
            .expect("a retraction is a no-op, not an error");

        assert_eq!(fd(&table, &source), None);
        assert_eq!(entry_count(&table), 0);
    }

    /// The same exemption, with an entry already there: a retraction may not lower — or raise — a
    /// feasibility distance that a real advertisement established, however new its seqno looks.
    #[test]
    fn a_retraction_leaves_an_existing_source_alone() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 6, Metric::INFINITY.raw()))
            .expect("a retraction is a no-op, not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100))),
            "the retraction's newer seqno must not move the feasibility distance"
        );
    }

    //   ___ ___ ___   _ _____ ___
    //  / __| _ \ __| /_\_   _| __|
    // | (__|   / _| / _ \| | | _|
    //  \___|_|_\___/_/ \_\_| |___|

    /// "If no entry indexed by (prefix, plen, router-id) exists in the source table, then the node
    /// creates a new entry" — seeded with exactly the distance being advertised.
    #[test]
    fn an_unknown_source_is_created_with_the_advertised_distance() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = empty_table();

        table
            .perform_maintenance(t0(), &route(source, 7, 42))
            .expect("an owned table always has room");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(7), Metric::from(42)))
        );
    }

    /// The created entry is keyed by the triple the RFC names, so it is reachable by the same
    /// `SourceIndex` that `is_feasible` will later look up. Getting this wrong would file the
    /// feasibility distance somewhere no incoming update is ever checked against.
    #[test]
    fn the_created_entry_carries_the_full_source_triple() {
        let source = source_index(DEST_A, 48, "rtr-a");
        let mut table = empty_table();

        table
            .perform_maintenance(t0(), &route(source, 7, 42))
            .expect("an owned table always has room");

        let entry = table.inner.get_by_key(&source).expect("entry should exist");
        assert_eq!(*entry.prefix(), Address::<NoExtension>::from(DEST_A));
        assert_eq!(*entry.prefix_len(), 48);
        assert_eq!(*entry.router_id(), router_id("rtr-a"));
    }

    /// The garbage-collection timer is what eventually releases the entry, so a created entry must
    /// start one — an entry with no expiry is a table slot held for the life of the router.
    #[test]
    fn a_created_entry_starts_its_garbage_collection_timer() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = empty_table();

        table
            .perform_maintenance(t0(), &route(source, 7, 42))
            .expect("an owned table always has room");

        let entry = table.inner.get_by_key(&source).expect("entry should exist");
        assert_eq!(
            entry.gc_timer.time_remaining(t0()),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME),
            "the timer should be running, with a full interval left"
        );
    }

    /// The feasibility distance has to record the metric we *put on the wire*, which is the
    /// computed metric — the advertised metric is what the neighbour told us, before our own link
    /// cost was added. Recording the smaller advertised metric would claim a distance we never
    /// offered, and would make a genuinely better route from a neighbour look infeasible.
    #[test]
    fn the_computed_metric_is_recorded_not_the_advertised_one() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = empty_table();

        table
            .perform_maintenance(t0(), &route_advertising(source, 7, 42, 96))
            .expect("an owned table always has room");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(7), Metric::from(96)))
        );
    }

    //  _   _ ___ ___   _ _____ ___
    // | | | | _ \   \ /_\_   _| __|
    // | |_| |  _/ |) / _ \| | | _|
    //  \___/|_| |___/_/ \_\_| |___|

    /// The update half of 3.7.3: the entry moves only when the new distance is strictly better,
    /// i.e. `seqno' < seqno or (seqno = seqno' and metric < metric')`. Same seqno, lower metric.
    #[test]
    fn a_lower_metric_at_the_same_seqno_lowers_the_feasibility_distance() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 5, 60))
            .expect("updating in place cannot fail");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(60)))
        );
    }

    /// The seqno dominates the metric: a newer seqno is strictly better *whatever* the metric, so
    /// a worse metric under a bumped seqno still replaces the entry. This is the clause that lets
    /// a seqno request rescue a starved destination — without it, the answer to the request would
    /// itself be infeasible.
    #[test]
    fn a_newer_seqno_replaces_the_feasibility_distance_even_with_a_worse_metric() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 6, 500))
            .expect("updating in place cannot fail");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(6), Metric::from(500))),
            "a newer seqno wins outright, so the recorded metric goes up"
        );
    }

    /// The negative case that keeps the feasibility distance a *minimum*: re-advertising the same
    /// prefix on a worse path must not relax it. Relaxing it is what would let a route we are
    /// ourselves feeding come back to us as feasible, which is the loop 3.5.1 exists to prevent.
    #[test]
    fn a_worse_metric_at_the_same_seqno_leaves_the_feasibility_distance_alone() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 5, 200))
            .expect("a no-op is not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100)))
        );
    }

    /// An equal distance is not *strictly* better, so it is not an update either.
    #[test]
    fn an_identical_distance_leaves_the_feasibility_distance_alone() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 5, 100))
            .expect("a no-op is not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100)))
        );
    }

    /// An older seqno is worse however good its metric looks.
    #[test]
    fn an_older_seqno_leaves_the_feasibility_distance_alone() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        table
            .perform_maintenance(t0(), &route(source, 4, 1))
            .expect("a no-op is not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100)))
        );
    }

    /// Seqnos are compared modulo 2^16 (RFC 8966 3.2.1), so 0 is *newer* than 65535. A plain
    /// integer comparison would read this as a rollback and freeze the feasibility distance at the
    /// pre-wrap value, which would make every subsequent update from that source infeasible.
    #[test]
    fn seqno_comparison_wraps_around() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, u16::MAX, 100);

        table
            .perform_maintenance(t0(), &route(source, 0, 200))
            .expect("updating in place cannot fail");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(0), Metric::from(200))),
            "seqno 0 follows 65535, so it is the newer one"
        );
    }

    //  _  _____   __
    // | |/ / __\ \ / /
    // | ' <| _| \ V /
    // |_|\_\___| |_|

    /// The router-id is part of the key, so the same prefix originated by two routers is two
    /// feasibility distances. Collapsing them would let one router's distance gate the other's
    /// routes — and a router-id change is exactly how a node escapes a starved destination.
    #[test]
    fn the_same_prefix_from_two_routers_is_two_sources() {
        let (a, b) = (
            source_index(DEST_A, 64, "rtr-a"),
            source_index(DEST_A, 64, "rtr-b"),
        );
        let mut table = table_holding(a, 5, 100);

        table
            .perform_maintenance(t0(), &route(b, 5, 200))
            .expect("an owned table always has room");

        assert_eq!(entry_count(&table), 2);
        assert_eq!(
            fd(&table, &a),
            Some(Feasibility::new(SeqNo(5), Metric::from(100)))
        );
        assert_eq!(
            fd(&table, &b),
            Some(Feasibility::new(SeqNo(5), Metric::from(200)))
        );
    }

    /// The prefix length is part of the key too: a supernet and a subnet advertised by one router
    /// are separate sources, so the shorter one must not shadow the longer.
    #[test]
    fn one_prefix_at_two_lengths_is_two_sources() {
        let (short, long) = (
            source_index(DEST_A, 48, "rtr-a"),
            source_index(DEST_A, 64, "rtr-a"),
        );
        let mut table = table_holding(short, 5, 100);

        table
            .perform_maintenance(t0(), &route(long, 5, 200))
            .expect("an owned table always has room");

        assert_eq!(entry_count(&table), 2);
        assert_eq!(
            fd(&table, &long),
            Some(Feasibility::new(SeqNo(5), Metric::from(200)))
        );
    }

    /// And a different prefix is a different source, rather than an update to the first.
    #[test]
    fn a_second_prefix_is_a_second_source() {
        let (a, b) = (
            source_index(DEST_A, 64, "rtr-a"),
            source_index(DEST_B, 64, "rtr-a"),
        );
        let mut table = table_holding(a, 5, 100);

        table
            .perform_maintenance(t0(), &route(b, 5, 200))
            .expect("an owned table always has room");

        assert_eq!(entry_count(&table), 2);
    }

    //   ___  ___   _____ ___ __  __ ___ ___
    //  / __|/ __| |_   _|_ _|  \/  | __| _ \
    // | (_ | (__    | |  | || |\/| | _||   /
    //  \___|\___|   |_| |___|_|  |_|___|_|_\

    /// The garbage-collection timer is what releases an entry once the source stops being
    /// advertised, so every pass through 3.7.3 has to push it back out — otherwise a prefix this
    /// node re-advertises every 30s still ages out on a fixed clock measured from the *first*
    /// advertisement. When it does, `is_feasible` starts answering `true` unconditionally for that
    /// source (there is no entry left to check against), and the guarantee of 3.5.1 lapses until
    /// the next advertisement rebuilds the entry.
    #[test]
    fn updating_a_source_restarts_its_garbage_collection_timer() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        let later = t0() + Duration::from_secs(60);
        assert_eq!(
            gc_remaining(&table, &source, later),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME - Duration::from_secs(60)),
            "the timer should have been running down since the entry was created"
        );

        table
            .perform_maintenance(later, &route(source, 5, 60))
            .expect("updating in place cannot fail");

        assert_eq!(
            gc_remaining(&table, &source, later),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME),
            "a full interval again, measured from the advertisement that just went out"
        );
    }

    /// The reset is unconditional, which is the part that is easy to miss: 3.7.3 resets the timer
    /// on every pass, not only on the passes that move the feasibility distance. A route that is
    /// stably advertised at an unchanged distance is the *most* alive a source can be, and it is
    /// exactly the case that takes the no-op branch.
    #[test]
    fn a_repeated_advertisement_restarts_the_timer_even_though_the_distance_does_not_move() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        let later = t0() + Duration::from_secs(60);
        table
            .perform_maintenance(later, &route(source, 5, 100))
            .expect("a no-op is not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100))),
            "the distance is unchanged, as an equal one is not strictly better"
        );
        assert_eq!(
            gc_remaining(&table, &source, later),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME),
            "but the entry is still held open"
        );
    }

    /// A worse advertisement is still an advertisement. The comparison declines to relax the
    /// feasibility distance, and the timer is pushed back all the same.
    #[test]
    fn a_worse_advertisement_still_restarts_the_timer() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        let later = t0() + Duration::from_secs(60);
        table
            .perform_maintenance(later, &route(source, 5, 200))
            .expect("a no-op is not an error");

        assert_eq!(
            fd(&table, &source),
            Some(Feasibility::new(SeqNo(5), Metric::from(100)))
        );
        assert_eq!(
            gc_remaining(&table, &source, later),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME)
        );
    }

    /// The one case that must *not* refresh the timer. 3.7.3 scopes the whole procedure to updates
    /// with a finite metric, so a retraction never enters it and has nothing to say about whether
    /// the source is still live — it says the opposite. Keeping the entry alive on retractions
    /// would pin a feasibility distance open on a prefix nobody is advertising any more.
    #[test]
    fn a_retraction_does_not_restart_the_timer() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = table_holding(source, 5, 100);

        let later = t0() + Duration::from_secs(60);
        table
            .perform_maintenance(later, &route(source, 6, Metric::INFINITY.raw()))
            .expect("a retraction is a no-op, not an error");

        assert_eq!(
            gc_remaining(&table, &source, later),
            Some(SPEC_DEFAULT_SOURCE_GC_TIME - Duration::from_secs(60)),
            "the timer should still be running down from the entry's creation"
        );
    }

    //  ___  ___  _   _ _  _ ___    _____ ___ ___ ___
    // | _ \/ _ \| | | | \| |   \  |_   _| _ \_ _| _ \
    // |   / (_) | |_| | .` | |) |   | | |   /| ||  _/
    // |_|_\\___/ \___/|_|\_|___/    |_| |_|_\___|_|

    /// What the whole procedure is *for*: after we advertise (seqno, metric), an update coming
    /// back to us at that same distance — or worse — must be infeasible, because it may well be
    /// our own advertisement returning through a loop. Only a strictly better one is accepted.
    ///
    /// This is the one assertion that ties `perform_maintenance` to `is_feasible`; the tests above
    /// pin the recorded value, this pins what that value then does.
    #[test]
    fn advertising_a_route_makes_the_same_distance_infeasible_coming_back() {
        let source = source_index(DEST_A, 64, "rtr-a");
        let mut table = empty_table();

        assert!(
            table.is_feasible(&source, &Metric::from(100), &SeqNo(5)),
            "anything is feasible before we have advertised the source"
        );

        table
            .perform_maintenance(t0(), &route(source, 5, 100))
            .expect("an owned table always has room");

        assert!(
            !table.is_feasible(&source, &Metric::from(100), &SeqNo(5)),
            "our own distance coming back is not strictly better"
        );
        assert!(
            !table.is_feasible(&source, &Metric::from(101), &SeqNo(5)),
            "nor is a worse one"
        );
        assert!(
            table.is_feasible(&source, &Metric::from(99), &SeqNo(5)),
            "a strictly better metric at the same seqno is feasible"
        );
        assert!(
            table.is_feasible(&source, &Metric::from(65534), &SeqNo(6)),
            "as is any metric under a newer seqno"
        );
    }
}
