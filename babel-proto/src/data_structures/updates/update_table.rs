use crate::data_structures::updates::{Update, UpdateError};
use crate::extension::address::AddressExt;
use crate::utils::storage::Table;
use crate::utils::{InternallyKeyed, ManagedSlice};

/// The queue of updates one route owes its neighbours.
#[derive(Debug)]
pub(crate) struct UpdateTable<'storage, A: AddressExt> {
    pub(crate) inner: Table<'storage, Option<Update<A>>>,
}

impl<'storage, A: AddressExt> UpdateTable<'storage, A> {
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    /// Hands the backing storage back so it can be returned to the route table's pool.
    pub(crate) fn into_storage(self) -> ManagedSlice<'storage, Option<Update<A>>> {
        self.inner.into_inner()
    }

    /// Empties the queue, dropping every update still owed.
    pub(crate) fn clear(&mut self) {
        self.inner.retain(|_| false);
    }

    /// Adds an update destined to a neighbour.
    ///
    /// An update already pending for the same neighbour is refreshed in place rather
    /// than duplicated, neighbour is the table's key. Periodic updates lean on this: every
    /// poll re-queues every selected route to every neighbour, some of those could already be
    /// pending so this ensures there is no overwrite.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        if let Some(existing_update) = self.inner.get_mut_by_key(&update.key()) {
            if existing_update.send_count > update.send_count {
                // If the exising send count is higher than the incoming send count then we can
                // assume a higher priority update is in progress.
                return Ok(());
            }

            // Otherwise the pending update is superseded by this one.
            existing_update.refresh_from(update);
            return Ok(());
        }

        // The update is not pending yet, so it needs a slot of its own. A duplicate is
        // unreachable, the key was just looked up above.
        self.inner.insert(update).map_err(|_| {
            b_debug!("Update table is full");
            UpdateError::UpdateTableFull
        })?;

        Ok(())
    }

    /// Drops every update that has nothing left to send.
    pub(crate) fn purge_finished(&mut self) {
        self.inner.retain(|u| u.send_count != 0);
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::{Interface, InterfaceHandle};
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::route::{RouteIndex, RouteTable};
    use crate::data_structures::source::{SourceIndex, SourceTable};
    use crate::data_structures::updates::UpdateIndex;
    use crate::data_types::destination::RouteDestination;
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Address, Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::Metric;
    use crate::router::config::DEFAULT_ROUTE_EXPIRY_TIME;
    use crate::utils::destination::DestAddr;
    use crate::utils::{Duration, Instant};

    /// Long enough that nothing expires mid-test, still inside the Timer bound.
    const INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));
    const RETRY_INTERVAL: Duration = Duration::from_secs(1);

    /// Sorted ascending, which is also the order their updates sit in the table: the update key
    /// leads with the prefix.
    ///
    /// `DEST_SUPER` is a supernet of all three, so it sorts ahead of them, and `DEST_SUPER` at two
    /// different prefix lengths is the only way to separate two route keys by `plen` alone.
    const DEST_SUPER: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    const DEST_A: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0);
    const DEST_B: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 0);
    const DEST_C: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 3, 0, 0, 0, 0);

    const NEIGHBOUR_1: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_2: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);

    /// The interface every helper defaults to, and the one the group tests poll.
    const IFACE_1: &str = "eth0";
    /// A second interface, which sorts after [`IFACE_1`]: `InterfaceHandle` is a right-aligned
    /// byte array, so the handles compare by their trailing characters.
    const IFACE_2: &str = "eth1";

    fn t0() -> Instant {
        Instant::from_secs(0)
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    /// A neighbour on an explicit interface, for the tests that need more than one.
    fn nbr(iface: &str, addr: Ipv6Addr) -> NeighbourIndex<NoExtension> {
        NeighbourIndex {
            iface: iface_handle(iface),
            addr: addr.into(),
        }
    }

    fn neighbour(addr: Ipv6Addr) -> NeighbourIndex<NoExtension> {
        nbr(IFACE_1, addr)
    }

    fn dest(
        prefix: impl Into<Address<NoExtension>>,
        prefix_len: u8,
    ) -> RouteDestination<NoExtension> {
        RouteDestination::new(prefix.into(), prefix_len).expect("bad destination")
    }

    fn empty_routes() -> RouteTable<'static, NoExtension> {
        RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME)
    }

    /// [`route`], with the prefix length and the advertising neighbour — the two parts of the
    /// route key that sit between the prefix and the destination — chosen by the caller.
    ///
    /// The route is created inside the table, because its update queue is drawn from the table's
    /// pool; the key comes back so the queue can be reached again.
    fn route_with(
        routes: &mut RouteTable<'_, NoExtension>,
        prefix: impl Into<Address<NoExtension>>,
        prefix_len: u8,
        router_id: &str,
        learned_from: NeighbourIndex<NoExtension>,
    ) -> RouteIndex<NoExtension> {
        let source = SourceIndex {
            router_id: RouterId::try_from(router_id).expect("bad router id"),
            destination: dest(prefix, prefix_len),
        };
        routes
            .add_route(
                t0(),
                source,
                learned_from,
                SeqNo(0),
                Metric::from(10),
                Metric::from(10),
                learned_from.addr,
                INTERVAL,
            )
            .expect("owned storage grows");
        RouteIndex {
            destination: source.destination,
            neighbour: learned_from,
        }
    }

    fn route(
        routes: &mut RouteTable<'_, NoExtension>,
        prefix: Ipv6Addr,
        router_id: &str,
        learned_from: Ipv6Addr,
    ) -> RouteIndex<NoExtension> {
        route_with(routes, prefix, 64, router_id, neighbour(learned_from))
    }

    /// [`update`], with the destination neighbour — including its interface — chosen by the caller.
    fn update_to(
        routes: &mut RouteTable<'_, NoExtension>,
        route: &RouteIndex<NoExtension>,
        send_to: NeighbourIndex<NoExtension>,
    ) {
        update_with(routes, route, send_to, true, 1)
    }

    fn update(
        routes: &mut RouteTable<'_, NoExtension>,
        route: &RouteIndex<NoExtension>,
        send_to: Ipv6Addr,
    ) {
        update_to(routes, route, neighbour(send_to))
    }

    /// An update with the two knobs the write pass branches on: whether it may ride a multicast
    /// packet, and how many more times it is owed.
    fn update_with(
        routes: &mut RouteTable<'_, NoExtension>,
        route: &RouteIndex<NoExtension>,
        send_to: NeighbourIndex<NoExtension>,
        mcast: bool,
        send_count: u8,
    ) {
        let route = routes.get_mut_by_key(route).expect("route is in the table");
        let update = Update::new(t0(), send_to, mcast, false, RETRY_INTERVAL, send_count)
            .expect("bad retry interval");
        route.add_update(update).expect("owned storage grows");
    }

    /// Every update the router is holding, paired with the source of the route that holds it, in
    /// the order a poll walks them: the route table's order — (prefix, plen, advertising neighbour)
    /// — and then each route's own queue.
    ///
    /// The source rides along because an update no longer carries one: what it will advertise is
    /// only knowable from the route it hangs off.
    fn pending(
        routes: &mut RouteTable<'_, NoExtension>,
    ) -> Vec<(SourceIndex<NoExtension>, Update<NoExtension>)> {
        routes
            .iter_mut()
            .flat_map(|route| {
                let source = *route.source();
                route
                    .update_queue
                    .inner
                    .iter()
                    .map(move |update| (source, *update))
            })
            .collect()
    }

    /// Restarts the send timer of every update owed, putting a full retry interval back on each
    /// clock. [`Update::new`] builds an eager timer, so a freshly queued update is due immediately
    /// and a test that wants to exercise the deferral branch has to push it out again.
    fn defer_all(routes: &mut RouteTable<'_, NoExtension>, now: Instant) {
        for route in routes.iter_mut() {
            for update in route.update_queue.inner.iter_mut() {
                update.send_timer.restart(now);
            }
        }
    }

    fn router_id(name: &str) -> RouterId {
        RouterId::try_from(name).expect("bad router id")
    }

    /// Updates come out in route table order, which is led by the destination rather than by the
    /// router-id that originated it.
    ///
    /// This is what moving the queues onto the routes cost. While one table held every update it
    /// was keyed by [`UpdateIndex`], which leads with the router-id, so a router-id's updates sat
    /// together and one Router-Id TLV could cover the whole run. Queues now hang off routes, the
    /// route table is keyed by (prefix, plen, advertising neighbour), and a router-id's updates are
    /// interleaved with every other router's. Packets stay correct — the write pass compares each
    /// update against the packet's Router-Id context exactly — but a router-id can now be restated
    /// several times in one packet.
    #[test]
    fn updates_come_out_in_destination_order_not_router_id_order() {
        let mut routes = empty_routes();

        for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
            let route = route(&mut routes, prefix, id, NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);
        }

        let in_table_order: Vec<RouterId> = pending(&mut routes)
            .iter()
            .map(|(source, _)| source.router_id)
            .collect();
        assert_eq!(
            in_table_order,
            alloc::vec![router_id("rtr-a"), router_id("rtr-b"), router_id("rtr-a")],
            "DEST_A, DEST_B, DEST_C — rtr-b splits rtr-a's two updates"
        );
    }

    /// Updates are per (route, neighbour), so the same route owed to two neighbours is two entries
    /// in that route's own queue.
    #[test]
    fn one_route_owed_to_two_neighbours_holds_two_updates() {
        let mut routes = empty_routes();

        let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
        for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
            update(&mut routes, &route, send_to);
        }

        let updates_vec: Vec<(RouterId, Address<NoExtension>)> = pending(&mut routes)
            .iter()
            .map(|(source, _)| (source.router_id, *source.destination.prefix()))
            .collect();

        assert_eq!(
            updates_vec,
            alloc::vec![
                (router_id("rtr-a"), DEST_A.into()),
                (router_id("rtr-a"), DEST_A.into())
            ],
            "both updates advertise the one route, so both name its prefix"
        );
    }

    /// The contract the write pass in [`UpdateTable::poll_for_updates`] is built on. It walks the
    /// table once, front to back, and decides what to emit from the update it is holding plus the
    /// ones it has already seen — so it can only be correct if the table is ordered, and ordered
    /// the way the key says.
    ///
    /// The claims, and what would break if each stopped holding:
    ///
    /// 1. A repeated source is a *contiguous* run — this is what lets the multicast de-duplication
    ///    in the write pass compare against only the previous update instead of remembering the
    ///    whole packet. It survives the move onto the routes because a source names a destination
    ///    and the route table is sorted by destination.
    /// 2. Unique by (source, destination neighbour) *within one route's queue* — one route cannot
    ///    tell one neighbour about itself twice in a packet.
    ///
    /// A third claim held while a single table carried every update and does not any more: updates
    /// for one router-id sat together, so one Router-Id TLV covered the whole run. See
    /// [`super::updates_come_out_in_destination_order_not_router_id_order`]. Uniqueness has also
    /// narrowed from global to per-queue — see
    /// [`two_routes_to_one_destination_each_queue_their_own_update`].
    mod table_order {
        use super::*;

        /// The fields an update is ordered by, in the order they break ties: the destination's
        /// (prefix, plen) — which is what the route table sorts on — then the update's destination
        /// neighbour, which is what each route's own queue sorts on. The router-id rides along
        /// because it is what the Router-Id TLVs are driven from.
        type SortKey = (
            RouterId,
            Address<NoExtension>,
            u8,
            NeighbourIndex<NoExtension>,
        );

        fn sort_keys(routes: &mut RouteTable<'_, NoExtension>) -> Vec<SortKey> {
            pending(routes)
                .iter()
                .map(|(source, update)| {
                    (
                        source.router_id,
                        *source.destination.prefix(),
                        *source.destination.prefix_len(),
                        update.key().neighbour,
                    )
                })
                .collect()
        }

        /// Every tie-break exercised at once, from tables that were filled in an order deliberately
        /// unrelated to the one they must be read back in.
        ///
        /// Reading the expectation top to bottom: `DEST_SUPER` sorts ahead of everything on the
        /// prefix, its two entries are separated only by `plen`, and inside every route the
        /// destination neighbour orders the pair.
        #[test]
        fn is_sorted_by_destination_then_destination_neighbour() {
            let mut routes = empty_routes();

            // Every route below is originated by rtr-a except the decoy, which is a prefix from
            // another router sorting into the middle of rtr-a's range.
            let fixture = [
                (DEST_C, 64, "rtr-a", NEIGHBOUR_1),
                (DEST_B, 64, "rtr-b", NEIGHBOUR_1),
                (DEST_A, 64, "rtr-a", NEIGHBOUR_2),
                (DEST_SUPER, 64, "rtr-a", NEIGHBOUR_1),
                (DEST_A, 64, "rtr-a", NEIGHBOUR_1),
                (DEST_SUPER, 48, "rtr-a", NEIGHBOUR_1),
            ];
            // Inserted back to front, and each route's two updates with the higher-sorting
            // destination first, so nothing in the expectation below can be insertion order.
            for (prefix, plen, id, advertised_by) in fixture {
                let route = route_with(&mut routes, prefix, plen, id, neighbour(advertised_by));
                for send_to in [NEIGHBOUR_2, NEIGHBOUR_1] {
                    update(&mut routes, &route, send_to);
                }
            }

            let (a, b) = (router_id("rtr-a"), router_id("rtr-b"));
            let (n1, n2) = (neighbour(NEIGHBOUR_1), neighbour(NEIGHBOUR_2));
            assert_eq!(
                sort_keys(&mut routes),
                alloc::vec![
                    // Same prefix as the next pair, shorter, so `plen` decides.
                    (a, DEST_SUPER.into(), 48, n1),
                    (a, DEST_SUPER.into(), 48, n2),
                    (a, DEST_SUPER.into(), 64, n1),
                    (a, DEST_SUPER.into(), 64, n2),
                    // Two pairs, not one, for the destination two routes lead to: the routes sit
                    // side by side in the route table and each carries its own queue.
                    (a, DEST_A.into(), 64, n1),
                    (a, DEST_A.into(), 64, n2),
                    (a, DEST_A.into(), 64, n1),
                    (a, DEST_A.into(), 64, n2),
                    // rtr-b's DEST_B sorts between DEST_A and DEST_C on the prefix, and the prefix
                    // is now what leads, so it splits rtr-a's run rather than landing behind it.
                    (b, DEST_B.into(), 64, n1),
                    (b, DEST_B.into(), 64, n2),
                    (a, DEST_C.into(), 64, n1),
                    (a, DEST_C.into(), 64, n2),
                ],
            );
        }

        /// The de-duplication the write pass does is only sound because a repeated source is a
        /// *contiguous* run: it compares the update it is holding against the one before it, and
        /// never looks further back. Queues that merely held the right entries in some other order
        /// would silently emit the same source twice.
        #[test]
        fn repeated_sources_form_contiguous_runs() {
            let mut routes = empty_routes();

            for prefix in [DEST_A, DEST_C] {
                let route = route(&mut routes, prefix, "rtr-a", NEIGHBOUR_1);
                for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                    update(&mut routes, &route, send_to);
                }
            }

            let sources: Vec<SourceIndex<NoExtension>> = pending(&mut routes)
                .iter()
                .map(|(source, _)| *source)
                .collect();
            let mut runs = sources.clone();
            runs.dedup();
            assert_eq!(
                runs.len(),
                2,
                "each of the two sources should appear as one unbroken run, got {sources:?}"
            );
        }

        /// Uniqueness is what stops one neighbour being told the same source twice in one packet.
        /// It comes from the queue's key, so re-queueing an update that is already pending has to
        /// refresh the entry, not sit beside it.
        #[test]
        fn re_queueing_the_same_route_and_neighbour_does_not_duplicate() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            for _ in 0..3 {
                update(&mut routes, &route, NEIGHBOUR_1);
            }

            assert_eq!(
                pending(&mut routes).len(),
                1,
                "three queueings of one (route, neighbour) pair are one pending update"
            );
        }

        /// The limit of that uniqueness: it is per queue, and two routes towards one destination
        /// have two queues, so nothing at this level stops one destination being owed twice. One
        /// shared table keyed by (source, neighbour) used to collapse these into a single update.
        ///
        /// Nothing in the router reaches this state — route selection keeps one queue per
        /// destination by dropping the loser's when a destination changes hands, which
        /// `a_destination_changing_hands_drops_what_the_loser_owed` pins. This is here to say that
        /// the invariant is enforced up there rather than being a property of the queues.
        #[test]
        fn two_routes_to_one_destination_each_queue_their_own_update() {
            let mut routes = empty_routes();

            for advertised_by in [NEIGHBOUR_1, NEIGHBOUR_2] {
                let route = route(&mut routes, DEST_A, "rtr-a", advertised_by);
                update(&mut routes, &route, NEIGHBOUR_1);
            }

            // What the receiver would see: what the update advertises, which is the route's source,
            // paired with who it is owed to.
            let owed_to_n1: Vec<(SourceIndex<NoExtension>, UpdateIndex<NoExtension>)> =
                pending(&mut routes)
                    .iter()
                    .map(|(source, update)| (*source, update.key()))
                    .collect();
            assert_eq!(
                owed_to_n1.len(),
                2,
                "one destination, one destination neighbour, two pending updates: {owed_to_n1:?}"
            );
            assert_eq!(
                owed_to_n1[0], owed_to_n1[1],
                "and they advertise the same source to the same neighbour, so the receiver hears \
                 the destination twice"
            );
        }
    }

    //  _    _ ___ ___ _____ ___   ___  _   ___ ___
    // | |  | | _ \_ _|_   _| __| | _ \/_\ / __/ __|
    // | |/\| |   /| |  | | | _|  |  _/ _ \\__ \__ \
    // |__/\__|_|_\___| |_| |___| |_|/_/ \_\___/___/

    /// Branch coverage for [`UpdateTable::poll_for_updates`] — the pass that turns pending updates
    /// into Router-Id, Next-Hop and Update TLVs and advances each update's send state as its TLV
    /// lands.
    ///
    /// The decisions it makes, each of which has a test below:
    ///
    /// 1. The send timer has not fired → skip, and fold the remainder into `next_poll`.
    /// 2. The update may not ride the destination the packet already claimed → skip.
    /// 3. This route's TLV is already in the packet and both may go multicast → do not repeat it.
    /// 4. The packet's Router-Id context does not match this route's → emit a Router-Id TLV, and
    ///    claim the destination if it is still free.
    /// 5. The route is in a different address family than the interface → emit a Next-Hop TLV, or
    ///    drop the update outright if the interface has no address in that family to name.
    /// 6. The write succeeded → decrement `send_count` and restart the timer; on `BufferTooSmall`
    ///    leave both untouched so the update is still owed.
    /// 7. After the pass, updates that have been sent their full count — or dropped by 5, or whose
    ///    route has left the route table — are purged.
    mod poll_updates {
        use super::*;
        use crate::data_structures::interface::InterfaceConfig;
        use crate::extension::NoStateExtension;
        use crate::output::DatagramSend;
        use crate::packet::packet_header::PacketHeader;
        use crate::packet::packet_slice::PacketSlice;
        use crate::packet::tlv::{NextHopSlice, RouterIdSlice, Tlv, TypedTlv, UpdateSlice};
        use crate::packet::writer::{PacketWriter, PacketWriterError};

        /// The parser state used when no address-encoding extension is in play.
        type NoState = NoStateExtension<NoExtension>;

        /// The interval every Update TLV written here advertises.
        const UPDATE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(30));

        /// Seed for the running `next_poll` minimum, longer than anything a test schedules. A poll
        /// that leaves this untouched asked to be woken no sooner than it already was.
        const NEVER: Duration = Duration::from_secs(9999);

        /// The interface's own address — link-local, as every Babel source address must be — and
        /// so the next hop the parser starts out holding for the IPv6 family.
        const IFACE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        /// The interface's on-link IPv4 address. A v6-sourced packet leaves the receiver's v4 next
        /// hop empty, so this is the only thing a v4 route can be advertised through.
        const IFACE_V4_ADDR: core::net::Ipv4Addr = core::net::Ipv4Addr::new(192, 0, 2, 1);

        /// An IPv4 prefix, for the branch that turns on the route and the interface's primary
        /// address sitting in different address families.
        const DEST_V4: core::net::Ipv4Addr = core::net::Ipv4Addr::new(10, 0, 0, 0);

        /// A dual-stack interface: link-local IPv6 to speak Babel over, plus an on-link IPv4
        /// address so IPv4 routes can be given a next hop.
        fn interface(name: &str) -> Interface<NoExtension> {
            let mut config = InterfaceConfig::new_wired(iface_handle(name), IFACE_ADDR.into());
            config
                .add_other_address(IFACE_V4_ADDR.into())
                .expect("v4 is a fresh family");
            Interface::new(t0(), config).expect("bad interface config")
        }

        /// [`interface`], with no IPv4 address — an IPv6-only link, which cannot advertise IPv4
        /// routes at all.
        fn v6_only_interface(name: &str) -> Interface<NoExtension> {
            Interface::new(
                t0(),
                InterfaceConfig::new_wired(iface_handle(name), IFACE_ADDR.into()),
            )
            .expect("bad interface config")
        }

        /// A placeholder for the source table the write pass takes but does not yet read. Once the
        /// pass starts updating feasibility distances as it advertises, these tests will seed it
        /// and assert on what it holds afterwards.
        fn empty_sources() -> SourceTable<'static, NoExtension> {
            SourceTable::new_with_storage(Vec::new())
        }

        /// What one `poll_for_updates` call produced.
        struct Polled {
            /// The finished packet, or empty when the pass wrote no TLVs at all.
            packet: Vec<u8>,
            /// The destination the packet ended up claiming.
            dest: DestAddr<NoExtension>,
            /// The wake-up the pass asked for.
            next_poll: Duration,
        }

        impl Polled {
            /// The TLV type ids in the order they were written, which is the thing most of these
            /// tests are really about.
            fn tlv_types(&self) -> Vec<u8> {
                if self.packet.is_empty() {
                    return Vec::new();
                }
                PacketSlice::from_slice(&self.packet)
                    .expect("packet should parse")
                    .body_reader()
                    .map(|tlv| tlv.r#type())
                    .collect()
            }

            fn nth_tlv(&self, n: usize) -> Tlv<'_> {
                PacketSlice::from_slice(&self.packet)
                    .expect("packet should parse")
                    .body_reader()
                    .nth(n)
                    .expect("tlv should exist")
            }
        }

        /// Runs one poll against an owned buffer, which grows, so no write can fail for space.
        fn poll_seeded(
            routes: &mut RouteTable<'_, NoExtension>,
            iface: &Interface<NoExtension>,
            now: Instant,
            mut dest: DestAddr<NoExtension>,
            mut next_poll: Duration,
        ) -> Polled {
            let writer = PacketWriter::new_packet(
                PacketHeader::MAGIC_NUMBER,
                PacketHeader::VERSION_NUMBER,
                Vec::new(),
            )
            .expect("an owned buffer always holds a header");

            let writer = routes
                .poll_for_updates::<NoState>(
                    now,
                    iface,
                    &mut empty_sources(),
                    UPDATE_INTERVAL,
                    &mut dest,
                    &mut next_poll,
                    writer,
                )
                .map_err(|(err, _)| err)
                .expect("an owned buffer never fills");

            let packet = if writer.has_tlvs() {
                DatagramSend::from(writer.finish_packet().expect("body is not empty")).to_vec()
            } else {
                Vec::new()
            };

            Polled {
                packet,
                dest,
                next_poll,
            }
        }

        /// [`poll_seeded`] starting from a free destination and nothing else scheduled.
        fn poll(
            routes: &mut RouteTable<'_, NoExtension>,
            iface: &Interface<NoExtension>,
            now: Instant,
        ) -> Polled {
            poll_seeded(routes, iface, now, DestAddr::default(), NEVER)
        }

        /// The `(send_count, timer is pending)` of every update still owed, in poll order.
        fn send_state(routes: &mut RouteTable<'_, NoExtension>, now: Instant) -> Vec<(u8, bool)> {
            pending(routes)
                .iter()
                .map(|(_, u)| (u.send_count, u.send_timer.time_remaining(now).is_some()))
                .collect()
        }

        //  _  _  ___ _____ _  _ ___ _  _  ___    ___  _   _ ___
        // | \| |/ _ \_   _| || |_ _| \| |/ __|  |   \| | | | __|
        // | .` | (_) || | | __ || || .` | (_ |  | |) | |_| | _|
        // |_|\_|\___/ |_| |_||_|___|_|\_|\___|  |___/ \___/|___|

        /// No routes at all: the loop body never runs and the writer comes back untouched.
        #[test]
        fn an_empty_table_writes_nothing() {
            let mut routes = empty_routes();

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(out.dest, DestAddr::None, "nothing claimed the packet");
            assert_eq!(out.next_poll, NEVER, "nothing asked for a wake-up");
        }

        /// An update owed on another interface is filtered out of this interface's pass, so there
        /// is nothing to write.
        #[test]
        fn an_update_owed_on_another_interface_is_not_written() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_to(&mut routes, &route, nbr(IFACE_2, NEIGHBOUR_1));

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&mut routes, t0()), alloc::vec![(1, false)]);
        }

        //  ___ ___ _  _ ___    _____ ___ __  __ ___ ___
        // / __| __| \| |   \  |_   _|_ _|  \/  | __| _ \
        // \__ \ _|| .` | |) |   | |  | || |\/| | _||   /
        // |___/___|_|\_|___/    |_| |___|_|  |_|___|_|_\

        /// Branch 1, taken: a timer that has not fired holds the update back, and its remaining
        /// time becomes the wake-up so the poll that can send it is scheduled.
        #[test]
        fn a_pending_timer_defers_the_update_and_shortens_the_wake_up() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);
            defer_all(&mut routes, t0());

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty(), "nothing was due");
            assert_eq!(out.next_poll, RETRY_INTERVAL, "woken when the timer fires");
            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(1, true)],
                "still owed, still pending"
            );
        }

        /// Branch 1's `min`, the other way round: a timer further out than something already
        /// scheduled must not push the wake-up back.
        #[test]
        fn a_pending_timer_further_out_than_the_running_minimum_leaves_it_alone() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);
            defer_all(&mut routes, t0());

            let sooner = RETRY_INTERVAL / 2;
            let out = poll_seeded(
                &mut routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::default(),
                sooner,
            );

            assert_eq!(out.next_poll, sooner, "the nearer wake-up wins");
        }

        //  ___  ___ ___ _____ ___ _  _   _ _____ ___ ___  _  _
        // |   \| __/ __|_   _|_ _| \| | /_\_   _|_ _/ _ \| \| |
        // | |) | _|\__ \ | |  | || .` |/ _ \| |  | | (_) | .` |
        // |___/|___|___/ |_| |___|_|\_/_/ \_\_| |___\___/|_|\_|

        /// Branch 2, first arm: an update that may not go multicast cannot ride a packet that has
        /// already been claimed for multicast.
        #[test]
        fn a_unicast_only_update_is_skipped_when_the_packet_is_multicast() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(1, false)],
                "skipped, so still owed and still due"
            );
        }

        /// Branch 2, second arm: the packet is already addressed to a different neighbour.
        #[test]
        fn a_unicast_only_update_is_skipped_when_the_packet_is_for_another_neighbour() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Unicast(NEIGHBOUR_2.into()),
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&mut routes, t0()), alloc::vec![(1, false)]);
        }

        /// Branch 2, falling through: the packet is already addressed to exactly this update's
        /// neighbour, so it rides along.
        #[test]
        fn a_unicast_only_update_rides_a_packet_already_addressed_to_its_neighbour() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Unicast(NEIGHBOUR_1.into()),
                NEVER,
            );

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID]
            );
            assert_eq!(
                out.dest,
                DestAddr::Unicast(NEIGHBOUR_1.into()),
                "the claim it inherited is unchanged"
            );
        }

        /// Branch 4's nested claim: a unicast-only update on a free packet addresses the packet to
        /// its own neighbour.
        #[test]
        fn a_unicast_only_update_claims_the_packet_for_its_neighbour() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(out.dest, DestAddr::Unicast(NEIGHBOUR_1.into()));
        }

        /// The other side of that claim: an update that may go multicast takes multicast, which is
        /// what lets one packet serve every neighbour on the link.
        #[test]
        fn a_multicast_update_claims_the_packet_for_multicast() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), true, 1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(out.dest, DestAddr::Multicast);
        }

        //  ___  ___  _   _ _____ ___ ___     ___ ___
        // | _ \/ _ \| | | |_   _| __| _ \   |_ _|   \
        // |   / (_) | |_| | | | | _||   /    | || |) |
        // |_|_\\___/ \___/  |_| |___|_|_\   |___|___/

        /// Every Update TLV inherits the router-id from the last Router-Id TLV in front of it
        /// (RFC 8966 4.6.7). A packet starts with no router-id context at all, so the very first
        /// update in it must be preceded by one — otherwise the receiver cannot attribute it.
        #[test]
        fn the_first_update_in_a_packet_is_preceded_by_a_router_id_tlv() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID]
            );
            match out.nth_tlv(0) {
                Tlv::RouterId(tlv) => assert_eq!(
                    RouterId::from(tlv.router_id()),
                    router_id("rtr-a"),
                    "the Router-Id TLV should name the route's originator"
                ),
                other => panic!("should be a router-id, got {other:?}"),
            }
        }

        /// A run of consecutive updates from one router shares the single Router-Id TLV at its
        /// head, and the next router opens a new one.
        #[test]
        fn a_run_of_one_router_id_emits_one_router_id_tlv() {
            let mut routes = empty_routes();

            // Ordered by destination, so rtr-a's two prefixes are adjacent and rtr-b's sorts after
            // both of them.
            for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-a"), (DEST_C, "rtr-b")] {
                let route = route(&mut routes, prefix, id, NEIGHBOUR_1);
                update(&mut routes, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            // rtr-a's two updates behind one Router-Id TLV, then rtr-b's one behind its own.
            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                ]
            );
        }

        /// What that run costs now that it is ordered by destination: a router-id whose prefixes
        /// are separated by another router's is restated, and the packet carries one Router-Id TLV
        /// per Update TLV.
        ///
        /// The packet is still correct — every Update inherits the router-id immediately in front
        /// of it — but while one table carried every update, keyed by [`UpdateIndex`], the
        /// router-id led the key and this could not happen. It is the density that regressed, not
        /// the meaning.
        #[test]
        fn a_router_id_split_by_another_is_restated() {
            let mut routes = empty_routes();

            for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
                let route = route(&mut routes, prefix, id, NEIGHBOUR_1);
                update(&mut routes, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                ],
                "rtr-a is named twice because rtr-b's prefix sorts between its two"
            );
        }

        //  _  _ _____  _______ _  _  ___  ___
        // | \| | __\ \/ /_   _| || |/ _ \| _ \
        // | .` | _| >  <  | | | __ | (_) |  _/
        // |_|\_|___/_/\_\ |_| |_||_|\___/|_|

        /// Branch 5, not taken: the route and the interface are both IPv6, so the next hop the
        /// packet already implies is correct and no Next-Hop TLV is needed.
        #[test]
        fn a_route_in_the_interfaces_address_family_needs_no_next_hop_tlv() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert!(
                !out.tlv_types().contains(&NextHopSlice::TYPE_ID),
                "an IPv6 route over an IPv6 interface implies its own next hop"
            );
        }

        /// Branch 5, taken: an IPv4 route advertised over an IPv6 interface has no implied next hop
        /// in its own family, so one has to be stated before the Update TLV.
        #[test]
        fn a_route_in_another_address_family_gets_a_next_hop_tlv_first() {
            let mut routes = empty_routes();

            let route = route_with(&mut routes, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            update(&mut routes, &route, NEIGHBOUR_1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    NextHopSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID
                ],
                "the next hop has to be stated before the update that relies on it"
            );

            let next_hop = match out.nth_tlv(0) {
                Tlv::NextHop(tlv) => tlv,
                other => panic!("should be a next hop, got {other:?}"),
            };
            assert_eq!(
                next_hop.ae(),
                1,
                "the next hop must be in the route's family, not the interface's primary one"
            );
            assert_eq!(
                next_hop.next_hop(4).expect("should have a 4 byte address"),
                Address::<NoExtension>::from(IFACE_V4_ADDR).as_wire(),
                "and it must be the interface's own on-link v4 address"
            );
        }

        /// The counterpart: an IPv6-only link has no address to offer as an IPv4 next hop, so the
        /// receiver would have nothing to forward through. The route is simply not advertisable
        /// here — babeld bails the same way with `if(!ifp->ipv4) ... return;`.
        ///
        /// Emitting the Update anyway, or preceding it with a Next-Hop TLV naming our *IPv6*
        /// address, would both be worse than silence: the first is unusable, the second is a
        /// well-formed TLV that sets the wrong family's state.
        ///
        /// It is also *dropped*, not deferred. The link cannot grow an IPv4 address on its own, so
        /// an update left pending here is one no later poll could ever send either — it would sit
        /// in the table forever, holding a slot and being re-examined by every poll.
        #[test]
        fn a_route_in_a_family_the_interface_cannot_name_is_not_advertised() {
            let mut routes = empty_routes();

            let route = route_with(&mut routes, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            update(&mut routes, &route, NEIGHBOUR_1);

            let out = poll(&mut routes, &v6_only_interface(IFACE_1), t0());

            assert!(
                out.tlv_types().is_empty(),
                "nothing should go out, got {:?}",
                out.tlv_types()
            );
            assert!(
                send_state(&mut routes, t0()).is_empty(),
                "an update this link can never send is purged, not left pending"
            );
        }

        /// The drop is scoped to the update that could not be advertised, and to nothing else. The
        /// same route owed on a dual-stack link is a separate entry in the route's queue, and the
        /// poll that gives up on the v6-only link must leave it alone for the poll of its own
        /// interface to send.
        #[test]
        fn a_route_dropped_on_one_interface_is_still_owed_on_another() {
            let mut routes = empty_routes();

            let route = route_with(&mut routes, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            for send_to in [nbr(IFACE_1, NEIGHBOUR_1), nbr(IFACE_2, NEIGHBOUR_1)] {
                update_to(&mut routes, &route, send_to);
            }

            // IFACE_1 has no IPv4 address, so its update is dropped.
            let out = poll(&mut routes, &v6_only_interface(IFACE_1), t0());
            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(1, false)],
                "only the v6-only link's update was purged"
            );

            // IFACE_2 is dual stack, so the survivor still goes out — with the Next-Hop TLV that
            // names the v4 address the other link did not have.
            let out = poll(&mut routes, &interface(IFACE_2), t0());
            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    NextHopSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID
                ]
            );
            assert!(
                send_state(&mut routes, t0()).is_empty(),
                "and is purged for having been sent its full count"
            );
        }

        /// An IPv6 route needs no Next-Hop TLV even on a dual-stack interface: the packet's own
        /// source address already seeds the receiver's IPv6 next hop.
        #[test]
        fn a_dual_stack_interface_still_states_no_next_hop_for_ipv6_routes() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut routes, &route, NEIGHBOUR_1);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID],
                "having a v4 address must not make v6 routes state a next hop"
            );
        }

        /// A Next-Hop TLV sets parser state that every following Update TLV inherits, so a second
        /// route in the same family must not restate it.
        #[test]
        fn a_second_route_in_that_family_does_not_restate_the_next_hop() {
            let mut routes = empty_routes();

            for (prefix, plen) in [
                (core::net::Ipv4Addr::new(10, 0, 0, 0), 24u8),
                (core::net::Ipv4Addr::new(10, 0, 1, 0), 24),
            ] {
                let route = route_with(&mut routes, prefix, plen, "rtr-a", neighbour(NEIGHBOUR_1));
                update(&mut routes, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            let next_hops = out
                .tlv_types()
                .iter()
                .filter(|t| **t == NextHopSlice::TYPE_ID)
                .count();
            assert_eq!(
                next_hops,
                1,
                "both updates share one next hop, got TLVs {:?}",
                out.tlv_types()
            );
        }

        //  ___  ___ ___  _   _ ___
        // |   \| __|   \| | | | _ \
        // | |) | _|| |) | |_| |  _/
        // |___/|___|___/ \___/|_|

        /// One route owed to two neighbours on a multicast-capable link is one TLV, not two: the
        /// single multicast packet reaches both. Writing it twice wastes the packet and tells each
        /// neighbour the same thing twice.
        #[test]
        fn one_route_owed_to_two_neighbours_is_written_once_on_a_multicast_packet() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                update_with(&mut routes, &route, neighbour(send_to), true, 1);
            }

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID],
                "the multicast packet carries the route once for both neighbours"
            );
            assert_eq!(out.dest, DestAddr::Multicast);
            assert!(
                pending(&mut routes).is_empty(),
                "both updates are satisfied by the one TLV and purged"
            );
        }

        //  ___ ___ _  _ ___    ___ _____ _ _____ ___
        // / __| __| \| |   \  / __|_   _/_\_   _| __|
        // \__ \ _|| .` | |) | \__ \ | |/ _ \| | | _|
        // |___/___|_|\_|___/  |___/ |_/_/ \_\_| |___|

        /// The write is what advances the state, so an update owed twice comes back with one send
        /// left and a restarted timer rather than being purged.
        #[test]
        fn a_successful_write_decrements_the_send_count_and_restarts_the_timer() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), true, 2);

            let out = poll(&mut routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().contains(&UpdateSlice::TYPE_ID));
            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(1, true)],
                "one send left, and the timer holds it until the retry interval elapses"
            );
        }

        /// Branch 7: an update that has been sent its full count is finished, and leaving it in the
        /// queue would resend it forever.
        #[test]
        fn an_update_is_purged_once_its_send_count_reaches_zero() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), true, 1);

            poll(&mut routes, &interface(IFACE_1), t0());

            assert!(
                send_state(&mut routes, t0()).is_empty(),
                "the queue is empty once the last send lands"
            );
        }

        /// A skipped update must not be purged: it has not been sent, so its count never moved.
        #[test]
        fn a_skipped_update_survives_the_purge() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), false, 1);

            // Claimed for multicast, which a unicast-only update may not ride.
            poll_seeded(
                &mut routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(1, false)],
                "still owed after being skipped"
            );
        }

        //  ___ _   _ ___ ___ ___ ___    ___ _   _ _    _
        // | _ ) | | | __| __| __| _ \  | __| | | | |  | |
        // | _ \ |_| | _|| _|| _||   /  | _|| |_| | |__| |__
        // |___/\___/|_| |_| |___|_|_\  |_|  \___/|____|____|

        /// The counterpart of "state advances only on a successful write": when the buffer fills,
        /// the update that did not fit must still be owed, and still due, so the next poll picks it
        /// up. Nothing here may be advanced optimistically.
        #[test]
        fn a_buffer_that_fills_leaves_the_send_state_untouched() {
            let mut routes = empty_routes();

            let route = route(&mut routes, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut routes, &route, neighbour(NEIGHBOUR_1), true, 2);

            // 4 bytes of packet header and 2 bytes of slack — enough to start a TLV, nowhere near
            // enough for a Router-Id or an Update.
            let mut buf = [0u8; 6];
            let writer = PacketWriter::new_packet(
                PacketHeader::MAGIC_NUMBER,
                PacketHeader::VERSION_NUMBER,
                &mut buf[..],
            )
            .expect("buffer holds a header");

            let mut dest = DestAddr::default();
            let mut next_poll = NEVER;
            let err = routes
                .poll_for_updates::<NoState>(
                    t0(),
                    &interface(IFACE_1),
                    &mut empty_sources(),
                    UPDATE_INTERVAL,
                    &mut dest,
                    &mut next_poll,
                    writer,
                )
                .map(|_| ())
                .map_err(|(err, _)| err)
                .expect_err("the buffer cannot hold the TLVs");

            assert!(matches!(err, PacketWriterError::BufferTooSmall { .. }));
            assert_eq!(
                send_state(&mut routes, t0()),
                alloc::vec![(2, false)],
                "nothing was written, so nothing was advanced"
            );
        }
    }
}
