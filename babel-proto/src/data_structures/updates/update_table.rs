use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::route::{Route, RouteIndex, RouteTable};
use crate::data_structures::updates::{Update, UpdateError, UpdateIndex};
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::packet::parser::Parser;
use crate::packet::tlv::update_slice::UpdateFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::storage::Table;
use crate::utils::{Duration, Instant, InternallyKeyed, ManagedSlice};

/// Table for storing the state of triggered updates.
pub(crate) struct UpdateTable<'storage, A: AddressExt> {
    inner: Table<'storage, UpdateIndex<A>, Update<A>>,
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

    /// Adds an update destined to a neibour.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        if let Some(existing_update) = self.inner.get_by_key(&update.key())
            && existing_update.send_count > update.send_count
        {
            // If the exising send count is higher than the incoming send count then we can
            // assume a higher priority update is in progress.
            return Ok(());
        } else {
            // Otherwise either the update didn't exist or can be overwritten.
            self.inner
                .insert(update)
                .map_err(|_| UpdateError::UpdateTableFull)?;
        }

        Ok(())
    }

    /// Walks the updates in the table one router-id at a time, handing out each group with the
    /// table still mutably borrowed, so the write pass can advance an update's state in place.
    ///
    /// A packet carries the router-id once, in a Router-Id TLV that every Update behind it
    /// inherits ([Section 4.6.7](https://datatracker.ietf.org/doc/html/rfc8966#name-router-id)),
    /// so writing updates in these groups is what keeps the number of Router-Id TLVs down to one
    /// per distinct router-id rather than one per update.
    ///
    /// Unlike [`RouteTable::destination_groups_mut`], this cannot be a `chunk_by`: the table is
    /// sorted by [`UpdateIndex`], and the router-id is not part of that key — it lives on the
    /// route table entry the update points at — so the updates sharing a router-id are scattered
    /// through the table instead of sitting in one contiguous run. `chunk_by_mut` hands out
    /// disjoint sub-slices, and a scattered group is not a sub-slice of anything.
    ///
    /// Writes the Update TLVs owed on `interface` into `writer`, advancing each update's send
    /// state as its TLV lands.
    ///
    /// This lives on the table rather than on `BabelRouter` because the caller is part-way through
    /// iterating `self.iface_table` mutably: a `&mut self` method on the router would be a second
    /// borrow of the whole thing, while `self.update_table.poll_for_updates(..)` borrows one field
    /// and takes the rest — the route table, the interface, the update interval — as arguments the
    /// compiler can see are disjoint from it.
    ///
    /// `P` is only needed for the [`Parser`] tracking per-packet compression state, so it appears
    /// nowhere in the signature and callers must name it: `poll_for_updates::<P>(..)`.
    pub(crate) fn poll_for_updates<'output, P>(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        routes: &RouteTable<'_, A>,
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
        // Start a cursor over self that yeilds groups of router ids.
        let mut router_id_groups = self.router_id_groups_mut(interface.handle(), routes);
        // Start the parser for the packet with the initial next hop equal to the address of the
        // interface this packet will be sent on.
        let mut parser: Parser<P> = Parser::new(interface.address);
        while let Some(mut rid_group) = router_id_groups.next_group() {
            let mut sent_update: Option<RouteIndex<A>> = None;
            for (update, route) in rid_group.iter_mut() {
                // If the timer still needs to fire then update the next poll value and continue.
                if let Some(remaining) = update.send_timer.time_remaining(now) {
                    *next_poll = remaining.min(*next_poll);
                    continue;
                }

                // If the update cannot be sent via multicast and the active destination is either
                // multicast or doesn't match this update's destination address then skip.
                if !update.mcast
                    && (active_dest.is_multicast()
                        || active_dest
                            .unicast_addr()
                            .is_some_and(|addr| addr != &update.neighbour().addr))
                {
                    continue;
                }

                // If the update has already been written to the packet, can be sent via multicast,
                // AND is already destined for multicast, then decrement the update send count and
                // restart the timer.
                //
                // The TLV already in the packet reaches this neighbour too, so this update is
                // satisfied without writing anything more — hence the `continue`, which is also
                // what keeps the decrement below from running a second time on it.
                if active_dest.is_multicast()
                    && sent_update.is_some_and(|idx| idx == route.key())
                    && update.mcast
                {
                    update.send_count -= 1;
                    update.send_timer.restart(now);
                    continue;
                }

                // A this point we know an update TLV needs to be sent.

                // If the packet's router-id context is not this route's, write a router-id TLV.
                // A fresh packet has no context at all, so the first update in one always gets a
                // Router-Id TLV — without it the receiver cannot attribute the Updates behind it.
                if parser
                    .router_id()
                    .is_none_or(|id| id != &route.source().router_id)
                {
                    let router_id = route.source().router_id;
                    b_debug!(
                        "[SEND] RouterId - iface: {:?}, dest: {:?}, - router_id: {:?}",
                        interface,
                        active_dest,
                        router_id
                    );
                    writer = writer.write_router_id(router_id)?.finish_tlv()?;
                    parser.set_router_id(router_id);

                    if active_dest.is_free() {
                        if update.mcast {
                            active_dest
                                .claim(DestAddr::Multicast)
                                .expect("Just checked if it was free")
                        } else {
                            active_dest
                                .claim(DestAddr::Unicast(update.neighbour().addr))
                                .expect("Just checked if free")
                        }
                    }
                }

                // If the address family for the route does not match the sending interface's
                // address family
                // AND
                //   the parser does not have the next hop state for the route's address family
                //   OR
                //   the parser has the next hop state and it does not match the sending interface's
                //   address
                if route.source().prefix.encoding().address_family()
                    != interface.address.encoding().address_family()
                    && parser
                        .get_next_hop(&route.source().prefix.encoding())
                        .is_none_or(|val| val != interface.address)
                {
                    // A next hop TLV must be sent
                    writer = writer
                        .write_next_hop(
                            interface.address.encoding().into(),
                            interface.address.as_wire(),
                        )?
                        .finish_tlv()?;
                }

                // TODO: Address compression. To keep things simple I am going to bikeshed outgoing
                // address compression. This is still compliant with the spec as this router can
                // still RECEIVE compressed addresses, it just doesn't send them yet.
                //
                // TODO: Router ID optimization in update flags.

                writer = writer
                    .write_update(
                        route.source().prefix.encoding().into(),
                        UpdateFlags::new(false, false),
                        route.source().prefix_len,
                        0,
                        update_interval,
                        route.seqno,
                        route.computed_metric,
                        route.source().prefix.as_wire(),
                    )?
                    .finish_tlv()?;

                sent_update = Some(route.key());
                update.send_count -= 1;
                update.send_timer.restart(now);
            }
        }

        // Purge the updates that are finished sending.
        self.inner.retain(|u| u.send_count != 0);
        Ok(writer)
    }

    /// See [`RouterIdGroups`] for why the result is a cursor rather than an `Iterator`.
    pub(crate) fn router_id_groups_mut<'table, 'routes>(
        &'table mut self,
        interface: &'table InterfaceHandle,
        routes: &'table RouteTable<'routes, A>,
    ) -> RouterIdGroups<'table, 'storage, 'routes, A> {
        RouterIdGroups {
            updates: self,
            interface,
            routes,
            last: None,
        }
    }
}

/// A cursor over the update table's router-id groups, returned by
/// [`UpdateTable::router_id_groups_mut`].
///
/// This is not an `Iterator`, and cannot be one: every group borrows the update table mutably, so
/// two of them may not exist at once, which is exactly what `Iterator::next` would have to allow.
/// [`Self::next_group`] is that same iteration minus the promise — a group must be dropped before
/// the next one is asked for, and that is what lets the write pass mutate updates in place.
///
/// Groups come out in ascending router-id order, and the cursor remembers only the last router-id
/// it handed out rather than any position in the table. So the table may be re-sorted, or have
/// entries removed, between groups without the cursor losing its place or repeating a group; the
/// one thing it cannot see is an update *added* under a router-id it has already gone past.
pub(crate) struct RouterIdGroups<'table, 'updates, 'routes, A: AddressExt> {
    updates: &'table mut UpdateTable<'updates, A>,
    routes: &'table RouteTable<'routes, A>,
    interface: &'table InterfaceHandle,
    /// The router-id of the group handed out last, which the next one has to sort after.
    last: Option<RouterId>,
}

impl<'updates, 'routes, A: AddressExt> RouterIdGroups<'_, 'updates, 'routes, A> {
    /// The next group, or `None` once every router-id in the table has been handed out.
    ///
    /// An update whose route has since left the route table has no router-id to be grouped under,
    /// so it neither opens a group nor joins one.
    pub(crate) fn next_group(&mut self) -> Option<RouterIdGroup<'_, 'updates, 'routes, A>> {
        let (last, routes) = (self.last, self.routes);
        // The lowest router-id in the table that has not been handed out yet. Finding it costs a
        // pass over the table per group and nothing in memory, which is the trade this crate
        // wants — the alternative is a second copy of the table indexed by router-id.
        let router_id = self
            .updates
            .inner
            .iter()
            // Only look for updates with the given interface.
            .filter(|u| &u.neighbour().iface == self.interface)
            // Fetch the router id for the given route.
            .filter_map(|update| router_id_of(routes, update))
            // Filter all router ID's greater than the last
            .filter(|id| last.is_none_or(|last| *id > last))
            // Take the minimum router ID of the remainder
            .min()?;

        // This ratchets up the minimum.
        self.last = Some(router_id);
        Some(RouterIdGroup {
            router_id,
            interface: self.interface,
            updates: self.updates,
            routes,
        })
    }
}

/// The updates that advertise routes originated by one router-id, which are not necessarily
/// adjacent in the update table.
///
/// Yielded by [`RouterIdGroups::next_group`].
pub(crate) struct RouterIdGroup<'table, 'updates, 'routes, A: AddressExt> {
    router_id: RouterId,
    /// The interface being polled. A group is one packet's worth of updates, and a packet goes out
    /// one link, so this narrows the group the same way the router-id does.
    interface: &'table InterfaceHandle,
    updates: &'table mut UpdateTable<'updates, A>,
    routes: &'table RouteTable<'routes, A>,
}

/// An iterator that yields a group of updates with the same router id.
///
/// In this iterator:
/// * All elements have the same router-id
/// * All elements are going to the same interface
/// * All elements are unique by (route, neighbour) pairs
/// * All elements are sorted by:
///   * Route Index: (prefix, plen, advertising neighbour)
///   * Neighbour Index of the Destination Neighbour: (iface, address)
impl<A: AddressExt> RouterIdGroup<'_, '_, '_, A> {
    /// The router-id that originated every route in this group.
    pub(crate) fn router_id(&self) -> &RouterId {
        &self.router_id
    }

    /// The updates in this group, each paired with the route it advertises.
    ///
    /// The route rides along because the grouping had to look it up anyway, and writing the
    /// Update TLV needs it: prefix, seqno, metric and next hop all live on the route rather than
    /// on the update.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&Update<A>, &Route<A>)> {
        let (router_id, interface, routes) = (self.router_id, self.interface, self.routes);
        self.updates
            .inner
            .iter()
            .filter(move |update| &update.neighbour().iface == interface)
            .filter_map(move |update| {
                let route = routes.get_by_key(update.route())?;
                (route.source().router_id == router_id).then_some((update, route))
            })
    }

    /// [`Self::iter`], with the update mutable so that the state which may only advance on a
    /// successful write — [`Update::send_count`] and [`Update::send_timer`] — can be advanced at
    /// the point the TLV lands in the packet, and left untouched when the buffer fills first.
    ///
    /// The route stays shared: it is what the TLV is rendered from, and the update's own key is
    /// derived from it, so nothing on this path may change it.
    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = (&mut Update<A>, &Route<A>)> {
        let (router_id, interface, routes) = (self.router_id, self.interface, self.routes);
        self.updates
            .inner
            .iter_mut()
            .filter(move |update| &update.neighbour().iface == interface)
            .filter_map(move |update| {
                let route = routes.get_by_key(update.route())?;
                (route.source().router_id == router_id).then_some((update, route))
            })
    }
}

/// The router-id of the route an update advertises, or `None` if that route has left the route
/// table since the update was queued.
fn router_id_of<A: AddressExt>(routes: &RouteTable<'_, A>, update: &Update<A>) -> Option<RouterId> {
    routes
        .get_by_key(update.route())
        .map(|route| route.source().router_id)
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
    use crate::data_types::{Address, Interval};
    use crate::extension::NoExtension;
    use crate::metric::Metric;
    use crate::router::config::DEFAULT_ROUTE_EXPIRY_TIME;
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

    /// [`route`], with the prefix length and the advertising neighbour — the two parts of the
    /// route key that sit between the prefix and the destination — chosen by the caller.
    fn route_with(
        prefix: impl Into<Address<NoExtension>>,
        prefix_len: u8,
        router_id: &str,
        learned_from: NeighbourIndex<NoExtension>,
    ) -> Route<NoExtension> {
        Route::new(
            t0(),
            SourceIndex {
                router_id: RouterId::try_from(router_id).expect("bad router id"),
                prefix: prefix.into(),
                prefix_len,
            },
            learned_from,
            SeqNo(0),
            Metric::from(10),
            Metric::from(10),
            learned_from.addr,
            true,
            INTERVAL,
            DEFAULT_ROUTE_EXPIRY_TIME,
        )
        .expect("bad expiry")
    }

    fn route(prefix: Ipv6Addr, router_id: &str, learned_from: Ipv6Addr) -> Route<NoExtension> {
        route_with(prefix, 64, router_id, neighbour(learned_from))
    }

    /// [`update`], with the destination neighbour — including its interface — chosen by the caller.
    fn update_to(
        route: &Route<NoExtension>,
        send_to: NeighbourIndex<NoExtension>,
    ) -> Update<NoExtension> {
        Update::new(t0(), route.key(), send_to, true, false, RETRY_INTERVAL, 1)
            .expect("bad retry interval")
    }

    fn update(route: &Route<NoExtension>, send_to: Ipv6Addr) -> Update<NoExtension> {
        update_to(route, neighbour(send_to))
    }

    fn router_id(name: &str) -> RouterId {
        RouterId::try_from(name).expect("bad router id")
    }

    /// Drains the cursor into the prefixes each group covers, which is what the groups are for:
    /// one Router-Id TLV followed by an Update TLV per prefix behind it.
    fn grouped_prefixes(
        updates: &mut UpdateTable<'_, NoExtension>,
        routes: &RouteTable<'_, NoExtension>,
    ) -> Vec<(RouterId, Vec<Address<NoExtension>>)> {
        let iface = iface_handle(IFACE_1);
        let mut cursor = updates.router_id_groups_mut(&iface, routes);
        let mut out = Vec::new();
        while let Some(group) = cursor.next_group() {
            out.push((
                *group.router_id(),
                group
                    .iter()
                    .map(|(_, route)| route.source().prefix)
                    .collect(),
            ));
        }
        out
    }

    /// The point of the whole method: the update table is sorted by prefix, so two routes from one
    /// router-id with a third router's prefix sorting between them leave that router-id's updates
    /// split across the table. A `chunk_by` would call that three groups, two of which repeat a
    /// Router-Id TLV that is already in the packet.
    #[test]
    fn groups_updates_that_are_not_adjacent_in_the_table() {
        let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        let mut updates = UpdateTable::new_with_storage(Vec::new());

        for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
            let route = route(prefix, id, NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update(&route, NEIGHBOUR_1))
                .expect("owned storage grows");
        }

        // The premise, spelled out: in table order the router-ids alternate.
        let in_table_order: Vec<RouterId> = updates
            .inner
            .iter()
            .map(|u| router_id_of(&routes, u).expect("route should exist"))
            .collect();
        assert_eq!(
            in_table_order,
            alloc::vec![router_id("rtr-a"), router_id("rtr-b"), router_id("rtr-a")]
        );

        assert_eq!(
            grouped_prefixes(&mut updates, &routes),
            alloc::vec![
                (
                    router_id("rtr-a"),
                    alloc::vec![DEST_A.into(), DEST_C.into()]
                ),
                (router_id("rtr-b"), alloc::vec![DEST_B.into()]),
            ],
            "one group per router-id, in ascending router-id order"
        );
    }

    /// Updates are per (route, neighbour), so the same prefix owed to two neighbours is two
    /// entries — both under the one router-id that originated the route.
    #[test]
    fn one_route_owed_to_two_neighbours_stays_in_one_group() {
        let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        let mut updates = UpdateTable::new_with_storage(Vec::new());

        let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
        routes.insert(route).expect("owned storage grows");
        for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
            updates
                .add_update(update(&route, send_to))
                .expect("owned storage grows");
        }

        assert_eq!(
            grouped_prefixes(&mut updates, &routes),
            alloc::vec![(
                router_id("rtr-a"),
                alloc::vec![DEST_A.into(), DEST_A.into()]
            )],
            "both updates advertise the one route, so both name its prefix"
        );
    }

    /// A route can be flushed out of the route table between queueing an update and sending it,
    /// and there is nothing left to render an Update TLV from. Such an update has no router-id, so
    /// it can neither open a group nor join one — it is simply not yielded.
    #[test]
    fn skips_updates_whose_route_has_left_the_route_table() {
        let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        let mut updates = UpdateTable::new_with_storage(Vec::new());

        let live = route(DEST_A, "rtr-a", NEIGHBOUR_1);
        // Never inserted into the route table, standing in for a route that has been flushed.
        let gone = route(DEST_B, "rtr-b", NEIGHBOUR_1);
        routes.insert(live).expect("owned storage grows");
        for route in [&live, &gone] {
            updates
                .add_update(update(route, NEIGHBOUR_1))
                .expect("owned storage grows");
        }

        assert_eq!(
            grouped_prefixes(&mut updates, &routes),
            alloc::vec![(router_id("rtr-a"), alloc::vec![DEST_A.into()])]
        );
    }

    #[test]
    fn an_empty_table_yields_no_groups() {
        let routes: RouteTable<'_, NoExtension> =
            RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        let mut updates: UpdateTable<'_, NoExtension> = UpdateTable::new_with_storage(Vec::new());

        let iface = iface_handle(IFACE_1);
        assert!(
            updates
                .router_id_groups_mut(&iface, &routes)
                .next_group()
                .is_none()
        );
    }

    /// The whole reason the groups hand out a mutable borrow: the send state of an update may only
    /// advance where the TLV is actually written, and the write happens with the group in hand.
    ///
    /// The mutation must also stay inside the group — an update under another router-id is in a
    /// different packet, or no packet at all if the buffer fills first.
    #[test]
    fn mutating_through_a_group_touches_only_that_group() {
        let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
        let mut updates = UpdateTable::new_with_storage(Vec::new());

        for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
            let route = route(prefix, id, NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update(&route, NEIGHBOUR_1))
                .expect("owned storage grows");
        }

        let iface = iface_handle(IFACE_1);
        let mut cursor = updates.router_id_groups_mut(&iface, &routes);
        let mut first = cursor.next_group().expect("rtr-a should have a group");
        assert_eq!(*first.router_id(), router_id("rtr-a"));
        for (update, _) in first.iter_mut() {
            update.send_count += 1;
        }
        // The group has to be dropped before the next one can be asked for, which is the whole
        // reason this is a cursor rather than an `Iterator`.
        drop(first);
        assert_eq!(
            *cursor
                .next_group()
                .expect("rtr-b should have a group")
                .router_id(),
            router_id("rtr-b")
        );

        let sent: Vec<(Address<NoExtension>, u8)> = updates
            .inner
            .iter()
            .map(|u| {
                let route = routes.get_by_key(u.route()).expect("route should exist");
                (route.source().prefix, u.send_count)
            })
            .collect();
        assert_eq!(
            sent,
            alloc::vec![(DEST_A.into(), 2), (DEST_B.into(), 1), (DEST_C.into(), 2)],
            "only rtr-a's two updates were advanced"
        );
    }

    //   ___ ___  ___  _   _ ___    ___  ___ ___  ___ ___
    //  / __| _ \/ _ \| | | | _ \  / _ \| _ \   \| __| _ \
    // | (_ |   / (_) | |_| |  _/ | (_) |   / |) | _||   /
    //  \___|_|_\\___/ \___/|_|    \___/|_|_\___/|___|_|_\

    /// The contract the write pass in `BabelRouter::poll_for_updates` is built on. It walks a group
    /// once, front to back, and decides what to emit from the element it is holding plus the ones
    /// it has already seen — so it can only be correct if the group is ordered, and ordered the way
    /// the doc comment on [`RouterIdGroup`] says.
    ///
    /// The four claims, and what would break if each stopped holding:
    ///
    /// 1. One router-id per group — otherwise the single Router-Id TLV at the head of the packet
    ///    would not describe every Update TLV behind it.
    /// 2. One interface per group — otherwise a packet built for one link would carry updates owed
    ///    on another.
    /// 3. Unique by (route, destination neighbour) — otherwise a neighbour is sent the same route
    ///    twice in one packet.
    /// 4. Sorted by route key then destination neighbour — this is what makes runs of a repeated
    ///    route *contiguous*, which is what lets the multicast de-duplication in the write pass
    ///    compare against only the previous element instead of remembering the whole packet.
    mod group_order {
        use super::*;

        /// The four fields the group is sorted by, in the order they break ties: the route key's
        /// (prefix, plen, advertising neighbour), then the update's destination neighbour.
        type SortKey = (
            Address<NoExtension>,
            u8,
            NeighbourIndex<NoExtension>,
            NeighbourIndex<NoExtension>,
        );

        fn sort_keys(group: &RouterIdGroup<'_, '_, '_, NoExtension>) -> Vec<SortKey> {
            group
                .iter()
                .map(|(update, route)| {
                    let route = route.key();
                    (
                        route.prefix,
                        route.prefix_len,
                        route.neighbour,
                        *update.neighbour(),
                    )
                })
                .collect()
        }

        /// Every tie-break in the key, exercised at once, from a table that was filled in an order
        /// deliberately unrelated to the one it must be read back in.
        ///
        /// Reading the expectation top to bottom: `DEST_SUPER` sorts ahead of `DEST_A` on the
        /// prefix; its two entries are separated only by `plen`; the two `DEST_A` routes are
        /// separated only by the neighbour that advertised them; and inside every one of those, the
        /// destination neighbour is what orders the pair.
        #[test]
        fn is_sorted_by_route_key_then_destination_neighbour() {
            let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let mut updates = UpdateTable::new_with_storage(Vec::new());

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
                let route = route_with(prefix, plen, id, neighbour(advertised_by));
                routes.insert(route).expect("owned storage grows");
                for send_to in [NEIGHBOUR_2, NEIGHBOUR_1] {
                    updates
                        .add_update(update(&route, send_to))
                        .expect("owned storage grows");
                }
            }

            let iface = iface_handle(IFACE_1);
            let mut cursor = updates.router_id_groups_mut(&iface, &routes);
            let group = cursor.next_group().expect("rtr-a should have a group");
            assert_eq!(*group.router_id(), router_id("rtr-a"));

            let (n1, n2) = (neighbour(NEIGHBOUR_1), neighbour(NEIGHBOUR_2));
            assert_eq!(
                sort_keys(&group),
                alloc::vec![
                    // Same prefix as the next pair, shorter, so `plen` decides.
                    (DEST_SUPER.into(), 48, n1, n1),
                    (DEST_SUPER.into(), 48, n1, n2),
                    (DEST_SUPER.into(), 64, n1, n1),
                    (DEST_SUPER.into(), 64, n1, n2),
                    // Identical prefix and plen, so the advertising neighbour decides.
                    (DEST_A.into(), 64, n1, n1),
                    (DEST_A.into(), 64, n1, n2),
                    (DEST_A.into(), 64, n2, n1),
                    (DEST_A.into(), 64, n2, n2),
                    // rtr-b's DEST_B sorts in here and is not part of this group.
                    (DEST_C.into(), 64, n1, n1),
                    (DEST_C.into(), 64, n1, n2),
                ],
            );
        }

        /// The de-duplication the write pass does is only sound because a repeated route key is a
        /// *contiguous* run: it compares the element it is holding against the one before it, and
        /// never looks further back. A group that merely contained the right elements in some other
        /// order would silently emit the same route twice.
        #[test]
        fn repeated_route_keys_form_contiguous_runs() {
            let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let mut updates = UpdateTable::new_with_storage(Vec::new());

            for prefix in [DEST_A, DEST_C] {
                let route = route(prefix, "rtr-a", NEIGHBOUR_1);
                routes.insert(route).expect("owned storage grows");
                for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                    updates
                        .add_update(update(&route, send_to))
                        .expect("owned storage grows");
                }
            }

            let iface = iface_handle(IFACE_1);
            let mut cursor = updates.router_id_groups_mut(&iface, &routes);
            let group = cursor.next_group().expect("rtr-a should have a group");

            let route_keys: Vec<RouteIndex<NoExtension>> =
                group.iter().map(|(update, _)| *update.route()).collect();
            let mut runs = route_keys.clone();
            runs.dedup();
            assert_eq!(
                runs.len(),
                2,
                "each of the two routes should appear as one unbroken run, got {route_keys:?}"
            );
        }

        /// A packet is built for one link, so a group must not carry an update owed on a different
        /// one — the interface is the first thing `router_id_groups_mut` is given.
        ///
        /// The same route is owed to a neighbour on each interface here, which is exactly what a
        /// periodic update produces: `poll_tick` queues every selected route to every neighbour on
        /// every interface.
        #[test]
        fn contains_only_updates_owed_on_the_polled_interface() {
            let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let mut updates = UpdateTable::new_with_storage(Vec::new());

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            for send_to in [nbr(IFACE_1, NEIGHBOUR_1), nbr(IFACE_2, NEIGHBOUR_1)] {
                updates
                    .add_update(update_to(&route, send_to))
                    .expect("owned storage grows");
            }

            for iface in [IFACE_1, IFACE_2] {
                let handle = iface_handle(iface);
                let mut cursor = updates.router_id_groups_mut(&handle, &routes);
                let group = cursor
                    .next_group()
                    .expect("rtr-a owes this interface an update");

                let destinations: Vec<NeighbourIndex<NoExtension>> = group
                    .iter()
                    .map(|(update, _)| *update.neighbour())
                    .collect();
                assert_eq!(
                    destinations,
                    alloc::vec![nbr(iface, NEIGHBOUR_1)],
                    "polling {iface} should not yield the update owed on the other interface"
                );
            }
        }

        /// Uniqueness is what stops one neighbour being told the same route twice in one packet.
        /// It comes from the table key rather than from the group, so re-queueing an update that is
        /// already pending has to overwrite the entry, not sit beside it.
        #[test]
        fn re_queueing_the_same_route_and_neighbour_does_not_duplicate() {
            let mut routes = RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME);
            let mut updates = UpdateTable::new_with_storage(Vec::new());

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            for _ in 0..3 {
                updates
                    .add_update(update(&route, NEIGHBOUR_1))
                    .expect("owned storage grows");
            }

            let iface = iface_handle(IFACE_1);
            let mut cursor = updates.router_id_groups_mut(&iface, &routes);
            let group = cursor.next_group().expect("rtr-a should have a group");

            assert_eq!(
                group.iter().count(),
                1,
                "three queueings of one (route, neighbour) pair are one pending update"
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
    /// 5. The route is in a different address family than the interface → emit a Next-Hop TLV.
    /// 6. The write succeeded → decrement `send_count` and restart the timer; on `BufferTooSmall`
    ///    leave both untouched so the update is still owed.
    /// 7. After the pass, updates that have been sent their full count are purged.
    mod poll_updates {
        use super::*;
        use crate::data_structures::interface::InterfaceConfig;
        use crate::extension::NoStateExtension;
        use crate::output::DatagramSend;
        use crate::packet::packet_header::PacketHeader;
        use crate::packet::packet_slice::PacketSlice;
        use crate::packet::tlv::{NextHopSlice, RouterIdSlice, Tlv, TypedTlv, UpdateSlice};
        use crate::packet::writer::PacketWriter;

        /// The parser state used when no address-encoding extension is in play.
        type NoState = NoStateExtension<NoExtension>;

        /// The interval every Update TLV written here advertises.
        const UPDATE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(30));

        /// Seed for the running `next_poll` minimum, longer than anything a test schedules. A poll
        /// that leaves this untouched asked to be woken no sooner than it already was.
        const NEVER: Duration = Duration::from_secs(9999);

        /// The interface's own address, and so the next hop the parser starts out holding.
        const IFACE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        /// An IPv4 prefix, for the one branch that turns on the route and the interface sitting in
        /// different address families.
        const DEST_V4: core::net::Ipv4Addr = core::net::Ipv4Addr::new(10, 0, 0, 0);

        fn interface(name: &str) -> Interface<NoExtension> {
            Interface::new(
                t0(),
                InterfaceConfig::new_wired(iface_handle(name), IFACE_ADDR.into()),
            )
            .expect("bad interface config")
        }

        /// An update with the two knobs the write pass branches on: whether it may ride a multicast
        /// packet, and how many more times it is owed.
        fn update_with(
            route: &Route<NoExtension>,
            send_to: NeighbourIndex<NoExtension>,
            mcast: bool,
            send_count: u8,
        ) -> Update<NoExtension> {
            Update::new(
                t0(),
                route.key(),
                send_to,
                mcast,
                false,
                RETRY_INTERVAL,
                send_count,
            )
            .expect("bad retry interval")
        }

        fn empty_routes() -> RouteTable<'static, NoExtension> {
            RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME)
        }

        fn empty_updates() -> UpdateTable<'static, NoExtension> {
            UpdateTable::new_with_storage(Vec::new())
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
            updates: &mut UpdateTable<'_, NoExtension>,
            routes: &RouteTable<'_, NoExtension>,
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

            let writer = updates
                .poll_for_updates::<NoState>(
                    now,
                    iface,
                    routes,
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
            updates: &mut UpdateTable<'_, NoExtension>,
            routes: &RouteTable<'_, NoExtension>,
            iface: &Interface<NoExtension>,
            now: Instant,
        ) -> Polled {
            poll_seeded(updates, routes, iface, now, DestAddr::default(), NEVER)
        }

        /// The `(send_count, timer is pending)` of every update left in the table, in table order.
        fn send_state(
            updates: &UpdateTable<'_, NoExtension>,
            now: Instant,
        ) -> Vec<(u8, bool)> {
            updates
                .inner
                .iter()
                .map(|u| (u.send_count, u.send_timer.time_remaining(now).is_some()))
                .collect()
        }

        //  _  _  ___ _____ _  _ ___ _  _  ___    ___  _   _ ___
        // | \| |/ _ \_   _| || |_ _| \| |/ __|  |   \| | | | __|
        // | .` | (_) || | | __ || || .` | (_ |  | |) | |_| | _|
        // |_|\_|\___/ |_| |_||_|___|_|\_|\___|  |___/ \___/|___|

        /// No groups at all: the loop body never runs and the writer comes back untouched.
        #[test]
        fn an_empty_table_writes_nothing() {
            let routes = empty_routes();
            let mut updates = empty_updates();

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(out.dest, DestAddr::None, "nothing claimed the packet");
            assert_eq!(out.next_poll, NEVER, "nothing asked for a wake-up");
        }

        /// An update whose route has been flushed has no router-id, so it opens no group. It is
        /// also never purged, because the pass never reaches it — it just sits there inert.
        #[test]
        fn an_update_whose_route_is_gone_writes_nothing() {
            let routes = empty_routes();
            let mut updates = empty_updates();

            // Built from a route that is never inserted, standing in for one since flushed.
            let orphan = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            updates
                .add_update(update(&orphan, NEIGHBOUR_1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&updates, t0()),
                alloc::vec![(1, false)],
                "the orphan is untouched, not purged"
            );
        }

        /// An update owed on another interface is not in this interface's group, so the pass has
        /// nothing to write — the same filter [`group_order`] pins, seen from the write side.
        #[test]
        fn an_update_owed_on_another_interface_is_not_written() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_to(&route, nbr(IFACE_2, NEIGHBOUR_1)))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&updates, t0()), alloc::vec![(1, false)]);
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            // `Update::new` builds an eager timer, so this one would be due immediately. Restarting
            // it puts a full retry interval back on the clock.
            let mut pending = update(&route, NEIGHBOUR_1);
            pending.send_timer.restart(t0());
            updates.add_update(pending).expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty(), "nothing was due");
            assert_eq!(out.next_poll, RETRY_INTERVAL, "woken when the timer fires");
            assert_eq!(
                send_state(&updates, t0()),
                alloc::vec![(1, true)],
                "still owed, still pending"
            );
        }

        /// Branch 1's `min`, the other way round: a timer further out than something already
        /// scheduled must not push the wake-up back.
        #[test]
        fn a_pending_timer_further_out_than_the_running_minimum_leaves_it_alone() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            let mut pending = update(&route, NEIGHBOUR_1);
            pending.send_timer.restart(t0());
            updates.add_update(pending).expect("owned storage grows");

            let sooner = RETRY_INTERVAL / 2;
            let out = poll_seeded(
                &mut updates,
                &routes,
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), false, 1))
                .expect("owned storage grows");

            let out = poll_seeded(
                &mut updates,
                &routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&updates, t0()),
                alloc::vec![(1, false)],
                "skipped, so still owed and still due"
            );
        }

        /// Branch 2, second arm: the packet is already addressed to a different neighbour.
        #[test]
        fn a_unicast_only_update_is_skipped_when_the_packet_is_for_another_neighbour() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), false, 1))
                .expect("owned storage grows");

            let out = poll_seeded(
                &mut updates,
                &routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Unicast(NEIGHBOUR_2.into()),
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&updates, t0()), alloc::vec![(1, false)]);
        }

        /// Branch 2, falling through: the packet is already addressed to exactly this update's
        /// neighbour, so it rides along.
        #[test]
        fn a_unicast_only_update_rides_a_packet_already_addressed_to_its_neighbour() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), false, 1))
                .expect("owned storage grows");

            let out = poll_seeded(
                &mut updates,
                &routes,
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), false, 1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert_eq!(out.dest, DestAddr::Unicast(NEIGHBOUR_1.into()));
        }

        /// The other side of that claim: an update that may go multicast takes multicast, which is
        /// what lets one packet serve every neighbour on the link.
        #[test]
        fn a_multicast_update_claims_the_packet_for_multicast() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), true, 1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update(&route, NEIGHBOUR_1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

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

        /// The point of grouping by router-id: several updates from one router share the single
        /// Router-Id TLV at the head of their run, and a second router opens a new one.
        #[test]
        fn each_router_id_emits_exactly_one_router_id_tlv() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
                let route = route(prefix, id, NEIGHBOUR_1);
                routes.insert(route).expect("owned storage grows");
                updates
                    .add_update(update(&route, NEIGHBOUR_1))
                    .expect("owned storage grows");
            }

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

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

        //  _  _ _____  _______ _  _  ___  ___
        // | \| | __\ \/ /_   _| || |/ _ \| _ \
        // | .` | _| >  <  | | | __ | (_) |  _/
        // |_|\_|___/_/\_\ |_| |_||_|\___/|_|

        /// Branch 5, not taken: the route and the interface are both IPv6, so the next hop the
        /// packet already implies is correct and no Next-Hop TLV is needed.
        #[test]
        fn a_route_in_the_interfaces_address_family_needs_no_next_hop_tlv() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update(&route, NEIGHBOUR_1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

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
            let mut updates = empty_updates();

            let route = route_with(DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update(&route, NEIGHBOUR_1))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    NextHopSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID
                ],
                "the next hop has to be stated before the update that relies on it"
            );
        }

        /// A Next-Hop TLV sets parser state that every following Update TLV inherits, so a second
        /// route in the same family must not restate it.
        #[test]
        fn a_second_route_in_that_family_does_not_restate_the_next_hop() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            for (prefix, plen) in [(core::net::Ipv4Addr::new(10, 0, 0, 0), 24u8),
                                   (core::net::Ipv4Addr::new(10, 0, 1, 0), 24)] {
                let route = route_with(prefix, plen, "rtr-a", neighbour(NEIGHBOUR_1));
                routes.insert(route).expect("owned storage grows");
                updates
                    .add_update(update(&route, NEIGHBOUR_1))
                    .expect("owned storage grows");
            }

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            let next_hops = out
                .tlv_types()
                .iter()
                .filter(|t| **t == NextHopSlice::TYPE_ID)
                .count();
            assert_eq!(
                next_hops, 1,
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                updates
                    .add_update(update_with(&route, neighbour(send_to), true, 1))
                    .expect("owned storage grows");
            }

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID],
                "the multicast packet carries the route once for both neighbours"
            );
            assert_eq!(out.dest, DestAddr::Multicast);
            assert!(
                updates.inner.iter().next().is_none(),
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), true, 2))
                .expect("owned storage grows");

            let out = poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(out.tlv_types().contains(&UpdateSlice::TYPE_ID));
            assert_eq!(
                send_state(&updates, t0()),
                alloc::vec![(1, true)],
                "one send left, and the timer holds it until the retry interval elapses"
            );
        }

        /// Branch 7: an update that has been sent its full count is finished, and leaving it in the
        /// table would resend it forever.
        #[test]
        fn an_update_is_purged_once_its_send_count_reaches_zero() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), true, 1))
                .expect("owned storage grows");

            poll(&mut updates, &routes, &interface(IFACE_1), t0());

            assert!(
                send_state(&updates, t0()).is_empty(),
                "the table is empty once the last send lands"
            );
        }

        /// A skipped update must not be purged: it has not been sent, so its count never moved.
        #[test]
        fn a_skipped_update_survives_the_purge() {
            let mut routes = empty_routes();
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), false, 1))
                .expect("owned storage grows");

            // Claimed for multicast, which a unicast-only update may not ride.
            poll_seeded(
                &mut updates,
                &routes,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert_eq!(
                send_state(&updates, t0()),
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
            let mut updates = empty_updates();

            let route = route(DEST_A, "rtr-a", NEIGHBOUR_1);
            routes.insert(route).expect("owned storage grows");
            updates
                .add_update(update_with(&route, neighbour(NEIGHBOUR_1), true, 2))
                .expect("owned storage grows");

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
            let err = updates
                .poll_for_updates::<NoState>(
                    t0(),
                    &interface(IFACE_1),
                    &routes,
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
                send_state(&updates, t0()),
                alloc::vec![(2, false)],
                "nothing was written, so nothing was advanced"
            );
        }
    }
}
