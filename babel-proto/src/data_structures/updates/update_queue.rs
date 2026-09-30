use crate::data_structures::interface::{Interface, InterfaceHandle, InterfaceTable};
use crate::data_structures::neighbour::{NeighbourIndex, NeighbourTable};
use crate::data_structures::route::{Route, RouteTable};
use crate::data_structures::source::SourceTable;
use crate::data_structures::updates::{Update, UpdateError};
use crate::data_types::RouterId;
use crate::data_types::destination::RouteDestination;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::metric::Metric;
use crate::packet::parser::Parser;
use crate::packet::tlv::update_slice::UpdateFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::storage::Table;
use crate::utils::{Duration, Instant, InternallyKeyed, ManagedSlice};

/// The updates this router owes its neighbours, keyed by (destination, neighbour owed).
#[derive(Debug)]
pub(crate) struct UpdateQueue<'storage, A: AddressExt> {
    pub(crate) inner: Table<'storage, Option<Update<A>>>,
}

impl<'storage, A: AddressExt> UpdateQueue<'storage, A> {
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    /// Queues an update for this route to every neighbour on every interface.
    ///
    /// This is 3.7.2's triggered update: the callers are the points where what this node believes
    /// about the route changed in a way the neighbours are owed.
    pub(crate) fn queue_triggered_update(
        &mut self,
        now: Instant,
        route: &Route<A>,
        interfaces: &InterfaceTable<A>,
        neighbours: &NeighbourTable<A>,
    ) {
        for interface in interfaces.iter() {
            for neighbour in neighbours.neighbours_for_iface(&interface.key()) {
                if let Err(err) = self.add_update(
                    Update::new(
                        now,
                        *route.destination(),
                        neighbour.key(),
                        !interface.prefer_ucast,
                        false,
                        *interface.update_retry_interval,
                        interface.update_retry_limit,
                    ),
                    true,
                ) {
                    b_debug!("Failed to add update for {:?} - {:?}", route, err);
                };
            }
        }
    }

    /// Queues updates for all selected routes to all neighbours on the given interface.
    pub(crate) fn queue_periodic_update(
        &mut self,
        now: Instant,
        routes: &RouteTable<A>,
        interface: &Interface<A>,
        neighbours: &NeighbourTable<A>,
    ) {
        for route in routes.inner.iter().filter(|r| r.selected) {
            for neighbour in neighbours.neighbours_for_iface(&interface.key()) {
                if let Err(err) = self.add_update(
                    Update::new(
                        now,
                        *route.destination(),
                        neighbour.key(),
                        !interface.prefer_ucast,
                        false,
                        *interface.update_retry_interval,
                        1,
                    ),
                    false,
                ) {
                    b_debug!("Failed to add update for {:?} - {:?}", route.key(), err);
                };
            }
        }
    }

    pub(crate) fn queue_route_response(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        destination: RouteDestination<A>,
        neighbour: NeighbourIndex<A>,
    ) -> Result<(), UpdateError> {
        self.add_update(
            Update::new(
                now,
                destination,
                neighbour,
                !interface.prefer_ucast,
                false,
                *interface.update_retry_interval,
                // The spec does not hold route request responses to the same "urgency" standard as
                // triggered updates. So keep this at 1 to keep traffic low.
                1,
            ),
            false,
        )
    }

    /// Adds an update destined to a neighbour.
    ///
    /// An update already pending for the same neighbour is refreshed in place rather
    /// than duplicated, neighbour is the table's key. Periodic updates lean on this: every
    /// poll re-queues every selected route to every neighbour, some of those could already be
    /// pending so this ensures there is no overwrite.
    pub(crate) fn add_update(
        &mut self,
        update: Update<A>,
        urgent: bool,
    ) -> Result<(), UpdateError> {
        if let Some(existing_update) = self.inner.get_mut_by_key(&update.key()) {
            if existing_update.send_count > update.send_count {
                // If the exising send count is higher than the incoming send count then we can
                // assume a higher priority update is in progress.
                return Ok(());
            }

            // Otherwise the pending update is superseded by this one.
            existing_update.refresh_from(update, urgent);
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

    /// Writes out whatever this route owes on `interface`, advancing each update's send state as
    /// its TLV lands in the packet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn poll_for_updates<'output, P>(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        sources: &mut SourceTable<'_, A>,
        routes: &RouteTable<'storage, A>,
        //sent_update: &mut Option<SourceIndex<A>>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    >
    where
        P: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
    {
        b_trace!("Polling for updates for {:?}", interface.key());

        // First purge all expired updates.
        self.inner.retain(|update| {
            // Retain if send timer is still going or send count is greater than 0.
            !update.send_timer.is_finished(now) || update.send_count > 0
        });

        // Flush and sort the table after modifying.
        self.inner.flush();

        // First check to see if there are ANY updates due. This is a practical linear optimization
        // to short circuit the quadratic iterator that is RouterIdGroups below.
        //
        // This method is short-circuiting, so any iteration that returns true will stop the
        // iterator.
        let update_due = !self.inner.iter().any(|u| {
            if let Some(remaining) = u.send_timer.time_remaining(now) {
                // In the case that no updates are due, this will ensure the next poll is updated.
                *next_poll = remaining.min(*next_poll);
                // If there is time remaining, this update is not due.
                false
            } else {
                true
            }
        });

        if update_due {
            return Ok(writer);
        }

        // Start the parser for the packet with the initial next hop equal to the address of the
        // interface this packet will be sent on.
        let mut parser: Parser<P> = Parser::new(interface.address);

        let mut router_id_groups = self.router_id_groups_mut(interface.key(), routes);

        let mut sent_dest: Option<RouteDestination<A>> = None;

        while let Some(mut rid_group) = router_id_groups.next_group() {
            let router_id = rid_group.router_id_group;
            for (update, route_opt) in rid_group
                // Iterate over the slots, because this is where updates will be removed.
                .iter_mut()
            {
                // If the timer still needs to fire then update the next poll value and continue.
                if let Some(remaining) = update.send_timer.time_remaining(now) {
                    *next_poll = remaining.min(*next_poll);
                    continue;
                }

                debug_assert_eq!(
                    router_id,
                    route_opt.map(|r| r.source().router_id),
                    "Update router id does not match router id group"
                );

                let destination = update.destination();

                // If the update cannot be sent to the current destination, then skip it.
                if !update.can_send(active_dest) {
                    continue;
                }

                // If the update can piggyback on a TLV in the current packet, decrement the send
                // counter and restart the send timer.
                if update.can_piggyback(active_dest, &sent_dest) {
                    update.send_count = update.send_count.saturating_sub(1);
                    update.send_timer.restart(now);
                    *next_poll = update.send_timer.duration().min(*next_poll);
                    continue;
                }

                // Get the address that should be the next hop for the address family advertised in
                // this route. If this interface does not have an address of that family, then we
                // cannot advertise the route from this interface.
                let Some(next_hop) = destination
                    .prefix()
                    .encoding()
                    .address_family()
                    .and_then(|family| interface.address_for_family(&family).copied())
                else {
                    // Spending the count hands the unsendable update to the removal at the top of
                    // the loop, so the next poll past its timer reclaims the slot.
                    update.send_count = 0;
                    update.send_timer.restart(now);
                    continue;
                };

                // A this point we know an update TLV needs to be sent.
                b_trace!("Preparing Update TLV");

                // Try to claim the active destination before doing anything.
                if active_dest.is_free() {
                    let new_dest = if update.mcast_allowed {
                        DestAddr::Multicast
                    } else {
                        DestAddr::Unicast(update.neighbour().addr)
                    };
                    if let Err(err) = active_dest.claim(new_dest) {
                        b_debug!("Err - {}", err);
                        continue;
                    };
                }

                let (seqno, metric) = if let Some(route) = route_opt {
                    // Perform source table maintenance for this route.
                    if let Err(err) = sources.perform_maintenance(
                        now,
                        &route.source(),
                        route.seqno,
                        *route.computed_metric(),
                    ) {
                        b_debug!("Source Err: {}", err);
                        continue;
                    };
                    // If the packet's router-id context is not this route's, write a router-id TLV.
                    // A fresh packet has no context at all, so the first update in one always gets
                    // a Router-Id TLV — without it the receiver cannot
                    // attribute the Updates behind it.
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
                    }

                    (route.seqno, *route.computed_metric())
                } else {
                    // If there is no route for the queued update, then it can be assumed that it is
                    // a retraction, in which case the seqno and router_id don't matter.
                    (SeqNo(0), Metric::INFINITY)
                };

                // Check to see if the parser has a next_hop for this address family, a hit means
                // the route's family is already covered and its Update TLV can simply inherit it. A
                // miss means we have to state one, and we can only state an address we actually
                // have.
                if parser
                    .get_next_hop(&destination.prefix().encoding())
                    .is_none()
                {
                    // State the next hop this route's family is missing, resolved above.
                    b_debug!(
                        "[SEND] NextHop - iface: {:?}, dest: {:?} - next_hop: {:?}",
                        interface,
                        active_dest,
                        next_hop
                    );

                    writer = writer
                        .write_next_hop(next_hop.encoding().into(), next_hop.as_wire())?
                        .finish_tlv()?;
                    // Mirror the TLV into our copy of the receiver's state. Without this the
                    // same Next-Hop TLV is re-emitted ahead of every
                    // update in the family.
                    parser.set_next_hop(next_hop);
                }

                // TODO: Address compression. To keep things simple I am going to bikeshed outgoing
                // address compression. This is still compliant with the spec as this router can
                // still RECEIVE compressed addresses, it just doesn't send them yet.
                //
                // TODO: Router ID optimization in update flags.
                let flags = UpdateFlags::new(false, false);
                let ae = destination.prefix().encoding();
                let omitted = 0;
                let trim = destination.prefix_len().div_ceil(8);
                b_debug!(
                    "[SEND] Update - iface: {:?}, dest: {:?}, - \
                    {:?}, {:?}, plen: {}, omitted: {}, interval: {}, \
                    {:?}, {:?}, prefix: {:?}",
                    interface,
                    active_dest,
                    ae,
                    flags,
                    destination.prefix_len(),
                    omitted,
                    interface.update_timer.duration().as_centis(),
                    seqno,
                    metric,
                    destination.prefix()
                );

                writer = writer
                    .write_update(
                        ae.into(),
                        flags,
                        *destination.prefix_len(),
                        omitted,
                        interface.update_timer.interval(),
                        seqno,
                        metric,
                        &destination.prefix().as_wire()[..trim.into()],
                    )?
                    .finish_tlv()?;

                sent_dest = Some(*destination);
                update.send_count = update.send_count.saturating_sub(1);
                update.send_timer.restart(now);
            }
        }

        // Flush and sort the table after modifying.
        self.inner.flush();

        Ok(writer)
    }

    /// Get a [`RouterIdGroups`] cursor from self.
    fn router_id_groups_mut<'a>(
        &'a mut self,
        interface: InterfaceHandle,
        routes: &'a RouteTable<'storage, A>,
    ) -> RouterIdGroups<'a, 'storage, A> {
        RouterIdGroups {
            interface,
            update_queue: self,
            routes,
            last: None,
        }
    }
}

/// A cursor that groups routes by [`RouterId`] to optimize network traffic for sending updates.
///
/// Only iterates over updates that are destined for neighbours on `self.interface` to avoid
/// unnecessary route lookups.
///
/// This cannot be an iterator because [`RouteTable`] is not ordered by [`RouterId`] and
/// [`core::slice::chunk_by`] only yields contiguous chunks so it must first establish a starting
/// [`RouterId`] for all routes (the minimum) and then ratchet up for each call of
/// [`RouterIdGroups::next_group`]
struct RouterIdGroups<'a, 'storage, A: AddressExt> {
    interface: InterfaceHandle,
    update_queue: &'a mut UpdateQueue<'storage, A>,
    routes: &'a RouteTable<'storage, A>,
    /// The [`RouterId`] of the group handed out last.
    last: Option<Option<RouterId>>,
}

impl<'a, 'storage, A: AddressExt> RouterIdGroups<'a, 'storage, A> {
    /// Gets the next [`RouterIdGroup`] and advances the [`RouterId`] cursor.
    fn next_group(&mut self) -> Option<RouterIdGroup<'_, 'storage, A>> {
        let router_id_opt = self
            .update_queue
            .inner
            .iter()
            .filter(|u| u.neighbour().iface == self.interface)
            // Get the selected route's originating RouterId if it exists.
            .map(|u| {
                self.routes
                    .get_selected(u.destination())
                    .map(|ro| ro.source().router_id)
            })
            // On the first pass `self.last` will be None, so all reults of the above map will be
            // yielded. After that if there are queued updates that don't have routes (retractions),
            // those will be yielded. Then Updates with routes will be yielded in the order of
            // RouterId.
            .filter(|id| self.last.is_none_or(|ro| id > &ro))
            // Take the minimum router id of the filtered group.
            .min()?;

        // Ratchet up the minimum so no router id's less than this one can be yielded in subsequent
        // calls to next_group.
        self.last = Some(router_id_opt);

        Some(RouterIdGroup {
            interface: self.interface,
            router_id_group: router_id_opt,
            update_queue: self.update_queue,
            routes: self.routes,
        })
    }
}

/// The routes that were originated by one router-id.
struct RouterIdGroup<'a, 'storage, A: AddressExt> {
    interface: InterfaceHandle,
    router_id_group: Option<RouterId>,
    update_queue: &'a mut UpdateQueue<'storage, A>,
    routes: &'a RouteTable<'storage, A>,
}

impl<A: AddressExt> RouterIdGroup<'_, '_, A> {
    /// Yields all updates and corresponding routes that have this group's [`RouterId`]
    ///
    /// This iterates over the slots of the inner table to implement rate limiting of the update
    /// queue.
    fn iter_mut(&mut self) -> impl Iterator<Item = (&mut Update<A>, Option<&Route<A>>)> {
        self.update_queue
            .inner
            .iter_mut()
            // Filter out all updates that are not for this interface to avoid unnecessary lookups.
            .filter(|u| u.neighbour().iface == self.interface)
            .filter_map(|u| {
                // Fetch the selected route for this destination.
                let route_opt = self.routes.get_selected(u.destination());
                // If the selected route matches the router id group, yield it and the route.
                if route_opt.map(|r| r.source().router_id) == self.router_id_group {
                    Some((u, route_opt))
                } else {
                    // Otherwise skip it.
                    None
                }
            })
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

    /// The two tables a poll reads.
    ///
    /// The queue belongs to the router rather than to any one route, so queueing an update means
    /// touching both: the route supplies what the update will advertise, the queue holds it.
    struct Tables<'storage> {
        routes: RouteTable<'storage, NoExtension>,
        updates: UpdateQueue<'storage, NoExtension>,
    }

    fn empty_tables() -> Tables<'static> {
        Tables {
            routes: RouteTable::new_with_storage(Vec::new(), DEFAULT_ROUTE_EXPIRY_TIME),
            updates: UpdateQueue::new_with_storage(Vec::new()),
        }
    }

    /// [`route`], with the prefix length and the advertising neighbour — the two parts of the
    /// route key that sit between the prefix and the destination — chosen by the caller.
    ///
    /// The key comes back because that is what the update helpers name the route by.
    fn route_with(
        tables: &mut Tables<'_>,
        prefix: impl Into<Address<NoExtension>>,
        prefix_len: u8,
        router_id: &str,
        learned_from: NeighbourIndex<NoExtension>,
    ) -> RouteIndex<NoExtension> {
        let source = SourceIndex {
            router_id: RouterId::try_from(router_id).expect("bad router id"),
            destination: dest(prefix, prefix_len),
        };
        tables
            .routes
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

        // `add_route` never marks a route selected — real route selection runs afterwards — so
        // this stands in for it, with the route just added taking the destination from whatever
        // held it before. The write pass renders an update from the *selected* route for its
        // destination, so a table where nothing is selected would advertise nothing but
        // retractions.
        for route in tables.routes.inner.iter_mut() {
            if route.destination() == &source.destination {
                route.selected = route.neighbour() == &learned_from;
            }
        }

        RouteIndex {
            destination: source.destination,
            neighbour: learned_from,
        }
    }

    fn route(
        tables: &mut Tables<'_>,
        prefix: Ipv6Addr,
        router_id: &str,
        learned_from: Ipv6Addr,
    ) -> RouteIndex<NoExtension> {
        route_with(tables, prefix, 64, router_id, neighbour(learned_from))
    }

    /// [`update`], with the destination neighbour — including its interface — chosen by the caller.
    fn update_to(
        tables: &mut Tables<'_>,
        route: &RouteIndex<NoExtension>,
        send_to: NeighbourIndex<NoExtension>,
    ) {
        update_with(tables, route, send_to, true, 1)
    }

    fn update(tables: &mut Tables<'_>, route: &RouteIndex<NoExtension>, send_to: Ipv6Addr) {
        update_to(tables, route, neighbour(send_to))
    }

    /// An update with the two knobs the write pass branches on: whether it may ride a multicast
    /// packet, and how many more times it is owed.
    fn update_with(
        tables: &mut Tables<'_>,
        route: &RouteIndex<NoExtension>,
        send_to: NeighbourIndex<NoExtension>,
        mcast: bool,
        send_count: u8,
    ) {
        let route = tables
            .routes
            .inner
            .get_by_key(route)
            .expect("route is in the table");
        let update = Update::new(
            t0(),
            *route.destination(),
            send_to,
            mcast,
            false,
            RETRY_INTERVAL,
            send_count,
        );
        tables
            .updates
            .add_update(update, true)
            .expect("owned storage grows");
    }

    /// Every update the router is holding, paired with the source it would advertise, in the order
    /// a poll walks them: the queue's own order, which is (prefix, plen, destination neighbour).
    ///
    /// The source is not the update's own any more — an update names a destination, and the write
    /// pass resolves what to advertise from the selected route for it. So this resolves it the same
    /// way, and `None` is a destination with no selected route: the case the pass renders as a
    /// retraction.
    fn pending(
        tables: &Tables<'_>,
    ) -> Vec<(Option<SourceIndex<NoExtension>>, Update<NoExtension>)> {
        tables
            .updates
            .inner
            .iter()
            .map(|update| {
                (
                    tables
                        .routes
                        .get_selected(update.destination())
                        .map(|route| *route.source()),
                    *update,
                )
            })
            .collect()
    }

    /// Restarts the send timer of every update owed, putting a full retry interval back on each
    /// clock. [`Update::new`] builds an eager timer, so a freshly queued update is due immediately
    /// and a test that wants to exercise the deferral branch has to push it out again.
    fn defer_all(tables: &mut Tables<'_>, now: Instant) {
        for update in tables.updates.inner.iter_mut() {
            update.send_timer.restart(now);
        }
    }

    fn router_id(name: &str) -> RouterId {
        RouterId::try_from(name).expect("bad router id")
    }

    /// Updates come out in route table order, which is led by the destination rather than by the
    /// router-id that originated it.
    ///
    /// This is what moving the queues onto the routes changed. While one table held every update it
    /// was keyed by [`UpdateIndex`], which leads with the router-id, so a router-id's updates sat
    /// together in storage. Queues now hang off routes, the route table is keyed by (prefix, plen,
    /// advertising neighbour), and a router-id's updates are interleaved with every other router's.
    ///
    /// Storage order is not packet order, though: the write pass walks the table through a cursor
    /// that groups the routes by originator, so one Router-Id TLV still covers a whole run — see
    /// [`poll_updates::a_router_id_split_in_the_table_is_one_run_in_the_packet`].
    #[test]
    fn updates_come_out_in_destination_order_not_router_id_order() {
        let mut tables = empty_tables();

        for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
            let route = route(&mut tables, prefix, id, NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);
        }

        let in_table_order: Vec<RouterId> = pending(&tables)
            .iter()
            .map(|(source, _)| {
                source
                    .expect("every destination has a selected route")
                    .router_id
            })
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
        let mut tables = empty_tables();

        let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
        for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
            update(&mut tables, &route, send_to);
        }

        let updates_vec: Vec<(RouterId, Address<NoExtension>)> = pending(&tables)
            .iter()
            .map(|(source, _)| {
                let source = source.expect("DEST_A's route holds the destination");
                (source.router_id, *source.destination.prefix())
            })
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

    /// The contract the write pass in [`UpdateQueue::poll_for_updates`] is built on. It walks the
    /// queue once, front to back, and decides what to emit from the update it is holding plus the
    /// ones it has already seen — so it can only be correct if the queue is ordered, and ordered
    /// the way the key says.
    ///
    /// The claims, and what would break if each stopped holding:
    ///
    /// 1. A repeated source is a *contiguous* run — this is what lets the multicast de-duplication
    ///    in the write pass compare against only the previous update instead of remembering the
    ///    whole packet. It holds because the key leads with the destination and a source names one.
    /// 2. Unique by (destination, destination neighbour) — one neighbour cannot be told about one
    ///    destination twice in a packet, whichever route the update was queued from. See
    ///    [`two_routes_to_one_destination_collapse_into_one_update`].
    ///
    /// A claim that does *not* hold: updates for one router-id sitting together in storage. The key
    /// leads with the destination, so a router-id's updates are interleaved with every other
    /// router's — see [`super::updates_come_out_in_destination_order_not_router_id_order`] — and
    /// the router-id grouping a packet needs is the cursor's job rather than the key's.
    mod table_order {
        use super::*;
        use crate::data_structures::updates::UpdateIndex;

        /// The fields an update is ordered by, in the order they break ties: the destination's
        /// (prefix, plen), then the neighbour the update is owed to. The router-id rides along
        /// because it is what the Router-Id TLVs are driven from, and is deliberately not part of
        /// the ordering.
        type SortKey = (
            RouterId,
            Address<NoExtension>,
            u8,
            NeighbourIndex<NoExtension>,
        );

        fn sort_keys(tables: &Tables<'_>) -> Vec<SortKey> {
            pending(tables)
                .iter()
                .map(|(source, update)| {
                    let source = source.expect("every destination here has a selected route");
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
        /// prefix, its two entries are separated only by `plen`, and within one destination the
        /// neighbour owed orders the pair.
        #[test]
        fn is_sorted_by_destination_then_destination_neighbour() {
            let mut tables = empty_tables();

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
                let route = route_with(&mut tables, prefix, plen, id, neighbour(advertised_by));
                for send_to in [NEIGHBOUR_2, NEIGHBOUR_1] {
                    update(&mut tables, &route, send_to);
                }
            }

            let (a, b) = (router_id("rtr-a"), router_id("rtr-b"));
            let (n1, n2) = (neighbour(NEIGHBOUR_1), neighbour(NEIGHBOUR_2));
            assert_eq!(
                sort_keys(&tables),
                alloc::vec![
                    // Same prefix as the next pair, shorter, so `plen` decides.
                    (a, DEST_SUPER.into(), 48, n1),
                    (a, DEST_SUPER.into(), 48, n2),
                    (a, DEST_SUPER.into(), 64, n1),
                    (a, DEST_SUPER.into(), 64, n2),
                    // One pair, not two, for the destination two routes lead to: the second route
                    // queues under the same key and refreshes what the first one left.
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
            let mut tables = empty_tables();

            for prefix in [DEST_A, DEST_C] {
                let route = route(&mut tables, prefix, "rtr-a", NEIGHBOUR_1);
                for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                    update(&mut tables, &route, send_to);
                }
            }

            let sources: Vec<SourceIndex<NoExtension>> = pending(&tables)
                .iter()
                .map(|(source, _)| source.expect("both destinations are held"))
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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            for _ in 0..3 {
                update(&mut tables, &route, NEIGHBOUR_1);
            }

            assert_eq!(
                pending(&tables).len(),
                1,
                "three queueings of one (route, neighbour) pair are one pending update"
            );
        }

        /// The reach of that uniqueness: it is the queue's, and the queue is the router's, so two
        /// routes towards one destination cannot both be owed to one neighbour. The second queues
        /// under the same key and refreshes the first rather than sitting beside it, which is what
        /// stops the receiver hearing about the destination twice in one packet.
        ///
        /// Which of the two the survivor advertises is route selection's business rather than the
        /// queue's, and now entirely so: the update names only the destination, so what it carries
        /// is read off whichever route holds that destination when the packet is written.
        #[test]
        fn two_routes_to_one_destination_collapse_into_one_update() {
            let mut tables = empty_tables();

            for advertised_by in [NEIGHBOUR_1, NEIGHBOUR_2] {
                let route = route(&mut tables, DEST_A, "rtr-a", advertised_by);
                update(&mut tables, &route, NEIGHBOUR_1);
            }

            // What the receiver would see: what the update advertises, paired with who it is owed
            // to.
            let owed_to_n1: Vec<(Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>)> =
                pending(&tables)
                    .iter()
                    .map(|(source, update)| (*source, update.key()))
                    .collect();
            assert_eq!(
                owed_to_n1.len(),
                1,
                "one destination, one destination neighbour, one pending update: {owed_to_n1:?}"
            );
            assert_eq!(
                tables
                    .routes
                    .get_selected(&dest(DEST_A, 64))
                    .expect("the destination is held")
                    .neighbour(),
                &neighbour(NEIGHBOUR_2),
                "and it advertises the route that holds the destination, the one added last"
            );
        }
    }

    //  _    _ ___ ___ _____ ___   ___  _   ___ ___
    // | |  | | _ \_ _|_   _| __| | _ \/_\ / __/ __|
    // | |/\| |   /| |  | | | _|  |  _/ _ \\__ \__ \
    // |__/\__|_|_\___| |_| |___| |_|/_/ \_\___/___/

    /// Branch coverage for [`UpdateQueue::poll_for_updates`] — the pass that turns pending updates
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
    ///    spend the update outright if the interface has no address in that family to name.
    /// 6. The write succeeded → decrement `send_count` and restart the timer; on `BufferTooSmall`
    ///    leave both untouched so the update is still owed.
    /// 7. The timer has fired *and* the send count is spent → drop the update and reclaim its slot.
    ///
    /// 7 is reached only through 1, which is what makes removal deferred: a spent update waits out
    /// one more retry interval before any poll will take it out. That lingering entry is the rate
    /// limiter — a re-queue in the meantime lands on it rather than opening a fresh one — so
    /// nothing sweeps the queue at the end of the pass.
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
            Interface::new(t0(), config)
        }

        /// [`interface`], with no IPv4 address — an IPv6-only link, which cannot advertise IPv4
        /// routes at all.
        fn v6_only_interface(name: &str) -> Interface<NoExtension> {
            Interface::new(
                t0(),
                InterfaceConfig::new_wired(iface_handle(name), IFACE_ADDR.into()),
            )
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
            tables: &mut Tables<'_>,
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

            let writer = tables
                .updates
                .poll_for_updates::<NoState>(
                    now,
                    iface,
                    &mut dest,
                    &mut next_poll,
                    &mut empty_sources(),
                    &tables.routes,
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
        fn poll(tables: &mut Tables<'_>, iface: &Interface<NoExtension>, now: Instant) -> Polled {
            poll_seeded(tables, iface, now, DestAddr::default(), NEVER)
        }

        /// The `(send_count, timer is pending)` of every update still owed, in poll order.
        fn send_state(tables: &Tables<'_>, now: Instant) -> Vec<(u8, bool)> {
            pending(tables)
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
            let mut tables = empty_tables();

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(out.dest, DestAddr::None, "nothing claimed the packet");
            assert_eq!(out.next_poll, NEVER, "nothing asked for a wake-up");
        }

        /// An update owed on another interface is filtered out of this interface's pass, so there
        /// is nothing to write.
        #[test]
        fn an_update_owed_on_another_interface_is_not_written() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_to(&mut tables, &route, nbr(IFACE_2, NEIGHBOUR_1));

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&tables, t0()), alloc::vec![(1, false)]);
        }

        //  ___ ___ _  _ ___    _____ ___ __  __ ___ ___
        // / __| __| \| |   \  |_   _|_ _|  \/  | __| _ \
        // \__ \ _|| .` | |) |   | |  | || |\/| | _||   /
        // |___/___|_|\_|___/    |_| |___|_|  |_|___|_|_\

        /// Branch 1, taken: a timer that has not fired holds the update back, and its remaining
        /// time becomes the wake-up so the poll that can send it is scheduled.
        #[test]
        fn a_pending_timer_defers_the_update_and_shortens_the_wake_up() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);
            defer_all(&mut tables, t0());

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert!(out.tlv_types().is_empty(), "nothing was due");
            assert_eq!(out.next_poll, RETRY_INTERVAL, "woken when the timer fires");
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(1, true)],
                "still owed, still pending"
            );
        }

        /// Branch 1's `min`, the other way round: a timer further out than something already
        /// scheduled must not push the wake-up back.
        #[test]
        fn a_pending_timer_further_out_than_the_running_minimum_leaves_it_alone() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);
            defer_all(&mut tables, t0());

            let sooner = RETRY_INTERVAL / 2;
            let out = poll_seeded(
                &mut tables,
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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut tables,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(1, false)],
                "skipped, so still owed and still due"
            );
        }

        /// Branch 2, second arm: the packet is already addressed to a different neighbour.
        #[test]
        fn a_unicast_only_update_is_skipped_when_the_packet_is_for_another_neighbour() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut tables,
                &interface(IFACE_1),
                t0(),
                DestAddr::Unicast(NEIGHBOUR_2.into()),
                NEVER,
            );

            assert!(out.tlv_types().is_empty());
            assert_eq!(send_state(&tables, t0()), alloc::vec![(1, false)]);
        }

        /// Branch 2, falling through: the packet is already addressed to exactly this update's
        /// neighbour, so it rides along.
        #[test]
        fn a_unicast_only_update_rides_a_packet_already_addressed_to_its_neighbour() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll_seeded(
                &mut tables,
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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), false, 1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert_eq!(out.dest, DestAddr::Unicast(NEIGHBOUR_1.into()));
        }

        /// The other side of that claim: an update that may go multicast takes multicast, which is
        /// what lets one packet serve every neighbour on the link.
        #[test]
        fn a_multicast_update_claims_the_packet_for_multicast() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), true, 1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

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
            let mut tables = empty_tables();

            // Ordered by destination, so rtr-a's two prefixes are adjacent and rtr-b's sorts after
            // both of them.
            for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-a"), (DEST_C, "rtr-b")] {
                let route = route(&mut tables, prefix, id, NEIGHBOUR_1);
                update(&mut tables, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut tables, &interface(IFACE_1), t0());

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

        /// A router-id whose prefixes are separated by another router's in the table still gets
        /// one Router-Id TLV, because the write pass walks the routes grouped by originator rather
        /// than in table order.
        ///
        /// Table order is led by the destination, so rtr-b's prefix sits between rtr-a's two — see
        /// [`super::updates_come_out_in_destination_order_not_router_id_order`]. The router-id
        /// cursor hands out one originator at a time, in ascending order, so how the destinations
        /// interleave no longer costs the packet a Router-Id TLV per Update TLV.
        #[test]
        fn a_router_id_split_in_the_table_is_one_run_in_the_packet() {
            let mut tables = empty_tables();

            for (prefix, id) in [(DEST_A, "rtr-a"), (DEST_B, "rtr-b"), (DEST_C, "rtr-a")] {
                let route = route(&mut tables, prefix, id, NEIGHBOUR_1);
                update(&mut tables, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                    RouterIdSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID,
                ],
                "rtr-a's two updates share one Router-Id TLV even though rtr-b's prefix sorts \
                 between them in the table"
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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert!(
                !out.tlv_types().contains(&NextHopSlice::TYPE_ID),
                "an IPv6 route over an IPv6 interface implies its own next hop"
            );
        }

        /// Branch 5, taken: an IPv4 route advertised over an IPv6 interface has no implied next hop
        /// in its own family, so one has to be stated before the Update TLV.
        ///
        /// Both state-setting TLVs land ahead of the Update and their order between themselves is
        /// free — the Router-Id comes first only because the write pass emits it from the route
        /// lookup, which happens before the next hop is written.
        #[test]
        fn a_route_in_another_address_family_gets_a_next_hop_tlv_first() {
            let mut tables = empty_tables();

            let route = route_with(&mut tables, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            update(&mut tables, &route, NEIGHBOUR_1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    NextHopSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID
                ],
                "the next hop has to be stated before the update that relies on it"
            );

            let next_hop = match out.nth_tlv(1) {
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
        /// It is also *given up on*, not merely skipped. The link cannot grow an IPv4 address on
        /// its own, so an update left owed here is one no later poll could ever send either — it
        /// would be re-examined by every poll forever. Zeroing the send count instead hands it to
        /// the same deferred removal a fully sent update takes, so the slot comes back one retry
        /// interval later.
        #[test]
        fn a_route_in_a_family_the_interface_cannot_name_is_not_advertised() {
            let mut tables = empty_tables();

            let route = route_with(&mut tables, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            update(&mut tables, &route, NEIGHBOUR_1);

            let out = poll(&mut tables, &v6_only_interface(IFACE_1), t0());

            assert!(
                out.tlv_types().is_empty(),
                "nothing should go out, got {:?}",
                out.tlv_types()
            );
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true)],
                "an update this link can never send is spent where it stands, not left owed"
            );

            poll(
                &mut tables,
                &v6_only_interface(IFACE_1),
                t0() + RETRY_INTERVAL,
            );
            assert!(
                pending(&tables).is_empty(),
                "and it does not linger past the interval every spent update waits out"
            );
        }

        /// Giving up is scoped to the update that could not be advertised, and to nothing else. The
        /// same route owed on a dual-stack link is a separate entry in the queue — the neighbour
        /// carries the interface, so the two do not share a key — and the poll that gives up on the
        /// v6-only link must leave it alone for the poll of its own interface to send.
        #[test]
        fn a_route_dropped_on_one_interface_is_still_owed_on_another() {
            let mut tables = empty_tables();

            let route = route_with(&mut tables, DEST_V4, 24, "rtr-a", neighbour(NEIGHBOUR_1));
            for send_to in [nbr(IFACE_1, NEIGHBOUR_1), nbr(IFACE_2, NEIGHBOUR_1)] {
                update_to(&mut tables, &route, send_to);
            }

            // IFACE_1 has no IPv4 address, so its update is given up on and spent.
            let out = poll(&mut tables, &v6_only_interface(IFACE_1), t0());
            assert!(out.tlv_types().is_empty());
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true), (1, false)],
                "only the v6-only link's update was given up on; IFACE_2's is still owed and due"
            );

            // IFACE_2 is dual stack, so the survivor still goes out — with the Next-Hop TLV that
            // names the v4 address the other link did not have.
            let out = poll(&mut tables, &interface(IFACE_2), t0());
            assert_eq!(
                out.tlv_types(),
                alloc::vec![
                    RouterIdSlice::TYPE_ID,
                    NextHopSlice::TYPE_ID,
                    UpdateSlice::TYPE_ID
                ]
            );
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true), (0, true)],
                "and is spent for having been sent its full count"
            );
        }

        /// An IPv6 route needs no Next-Hop TLV even on a dual-stack interface: the packet's own
        /// source address already seeds the receiver's IPv6 next hop.
        #[test]
        fn a_dual_stack_interface_still_states_no_next_hop_for_ipv6_routes() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update(&mut tables, &route, NEIGHBOUR_1);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

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
            let mut tables = empty_tables();

            for (prefix, plen) in [
                (core::net::Ipv4Addr::new(10, 0, 0, 0), 24u8),
                (core::net::Ipv4Addr::new(10, 0, 1, 0), 24),
            ] {
                let route = route_with(&mut tables, prefix, plen, "rtr-a", neighbour(NEIGHBOUR_1));
                update(&mut tables, &route, NEIGHBOUR_1);
            }

            let out = poll(&mut tables, &interface(IFACE_1), t0());

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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            for send_to in [NEIGHBOUR_1, NEIGHBOUR_2] {
                update_with(&mut tables, &route, neighbour(send_to), true, 1);
            }

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert_eq!(
                out.tlv_types(),
                alloc::vec![RouterIdSlice::TYPE_ID, UpdateSlice::TYPE_ID],
                "the multicast packet carries the route once for both neighbours"
            );
            assert_eq!(out.dest, DestAddr::Multicast);
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true), (0, true)],
                "the one TLV satisfies both, so both go spent — the piggybacked one without \
                 having been written"
            );
        }

        //  ___ ___ _  _ ___    ___ _____ _ _____ ___
        // / __| __| \| |   \  / __|_   _/_\_   _| __|
        // \__ \ _|| .` | |) | \__ \ | |/ _ \| | | _|
        // |___/___|_|\_|___/  |___/ |_/_/ \_\_| |___|

        /// The write is what advances the state, so an update owed twice comes back with one send
        /// left and a restarted timer rather than spent.
        #[test]
        fn a_successful_write_decrements_the_send_count_and_restarts_the_timer() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), true, 2);

            let out = poll(&mut tables, &interface(IFACE_1), t0());

            assert!(out.tlv_types().contains(&UpdateSlice::TYPE_ID));
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(1, true)],
                "one send left, and the timer holds it until the retry interval elapses"
            );
        }

        /// Branch 7: an update that has been sent its full count is finished, but it is not taken
        /// out of the queue on the spot. It sits there spent for one more retry interval, and the
        /// first poll to find it both spent and due is the one that reclaims its slot.
        ///
        /// That gap is where rate limiting lives. While the spent entry is still in the queue, a
        /// re-queue of the same (destination, neighbour) lands on it — [`UpdateQueue::add_update`]
        /// finds it by key — instead of opening a fresh entry with a fresh eager timer, so the pair
        /// cannot be put back on the wire until the interval has run out.
        #[test]
        fn a_spent_update_is_held_for_its_retry_interval_before_being_dropped() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), true, 1);

            poll(&mut tables, &interface(IFACE_1), t0());

            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true)],
                "spent by the send, and holding its slot until the timer runs out"
            );

            // A poll inside the interval leaves it where it is: spent, but not yet due.
            poll(&mut tables, &interface(IFACE_1), t0());
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(0, true)],
                "still rate limiting, so still queued"
            );

            // The first poll that finds it both spent and due drops it.
            poll(&mut tables, &interface(IFACE_1), t0() + RETRY_INTERVAL);
            assert!(
                pending(&tables).is_empty(),
                "the queue is empty once the spent update's timer has elapsed"
            );
        }

        /// A skipped update must not be dropped: it has not been sent, so its count never moved and
        /// branch 7 cannot reach it.
        #[test]
        fn a_skipped_update_survives_the_poll() {
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), false, 1);

            // Claimed for multicast, which a unicast-only update may not ride.
            poll_seeded(
                &mut tables,
                &interface(IFACE_1),
                t0(),
                DestAddr::Multicast,
                NEVER,
            );

            assert_eq!(
                send_state(&tables, t0()),
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
            let mut tables = empty_tables();

            let route = route(&mut tables, DEST_A, "rtr-a", NEIGHBOUR_1);
            update_with(&mut tables, &route, neighbour(NEIGHBOUR_1), true, 2);

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
            let err = tables
                .updates
                .poll_for_updates::<NoState>(
                    t0(),
                    &interface(IFACE_1),
                    &mut dest,
                    &mut next_poll,
                    &mut empty_sources(),
                    &tables.routes,
                    writer,
                )
                .map(|_| ())
                .map_err(|(err, _)| err)
                .expect_err("the buffer cannot hold the TLVs");

            assert!(matches!(err, PacketWriterError::BufferTooSmall { .. }));
            assert_eq!(
                send_state(&tables, t0()),
                alloc::vec![(2, false)],
                "nothing was written, so nothing was advanced"
            );
        }
    }
}
