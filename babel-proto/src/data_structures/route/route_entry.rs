use crate::data_structures::interface::{Interface, InterfaceTable};
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex, NeighbourTable};
use crate::data_structures::route::updates::{Update, UpdateError, UpdateTable};
use crate::data_structures::source::{SourceIndex, SourceTable};
use crate::data_types::address::Address;
use crate::data_types::destination::RouteDestination;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::metric::Metric;
use crate::packet::parser::Parser;
use crate::packet::tlv::update_slice::UpdateFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::storage::{InternallyKeyed, Recycle};
use crate::utils::{Duration, DurationMultiplier, Instant, ManagedSlice, Timer};

/// Route index as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RouteIndex<A: AddressExt> {
    pub(crate) destination: RouteDestination<A>,
    pub(crate) neighbour: NeighbourIndex<A>,
}

/// Route entry as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
///
/// The route table contains the routes known to this node. It is indexed by triples of the
/// form (prefix, plen, neighbour) (See [`RouteIndex`]), and every route table entry contains the
/// following data:
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Route<'storage, A: AddressExt> {
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
    advertised_metric: Metric,

    /// The computed metric of this route.
    computed_metric: Metric,

    /// The smoothed metric for hysteresis
    smoothed_metric: Metric,

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

    /// The queue of pending updates for this route.
    pub(crate) update_queue: UpdateTable<'storage, A>,
}

impl<'storage, A: AddressExt> Recycle for Route<'storage, A> {
    type Storage = ManagedSlice<'storage, Option<Update<A>>>;
    fn release(mut self) -> Self::Storage {
        // Erase all items in the queue.
        self.update_queue.clear();

        self.update_queue.into_storage()
    }
}

impl<A: AddressExt> InternallyKeyed for Route<'_, A> {
    type Key = RouteIndex<A>;
    fn key(&self) -> Self::Key {
        RouteIndex {
            destination: self.source().destination,
            neighbour: self.neighbour,
        }
    }
}

impl<'storage, A: AddressExt> Route<'storage, A> {
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
        update_storage: ManagedSlice<'storage, Option<Update<A>>>,
    ) -> Self {
        let expiry = Timer::from_duration(now, Duration::from(interval) * hold_time);
        Self {
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
            update_queue: UpdateTable::new_with_storage(update_storage),
        }
    }

    /// Queues an update for this route to one neighbour.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        self.update_queue.add_update(update)
    }

    /// Drops every update this route still owes.
    pub(crate) fn clear_updates(&mut self) {
        self.update_queue.clear();
    }

    /// Queues an update for this route to every neighbour on every interface.
    ///
    /// This is 3.7.2's triggered update: the callers are the points where what this node believes
    /// about the route changed in a way the neighbours are owed.
    pub(crate) fn broadcast_update(
        &mut self,
        now: Instant,
        interfaces: &InterfaceTable<A>,
        neighbours: &NeighbourTable<A>,
        retry_override: Option<u8>,
    ) {
        for interface in interfaces.iter() {
            for neighbour in neighbours.neighbours_for_iface(&interface.key()) {
                if let Err(err) = self.add_update(Update::new(
                    now,
                    neighbour.key(),
                    !interface.prefer_ucast,
                    false,
                    *interface.update_retry_interval,
                    retry_override.unwrap_or(interface.update_retry_limit),
                )) {
                    b_debug!("Failed to add update for {:?} - {:?}", self.key(), err);
                };
            }
        }
    }

    /// Writes out whatever this route owes on `interface`, advancing each update's send state as
    /// its TLV lands in the packet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn poll_for_updates<'output, P>(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        sources: &mut SourceTable<'_, A>,
        update_interval: Interval,
        active_dest: &mut DestAddr<A>,
        next_poll: &mut Duration,
        parser: &mut Parser<P>,
        //sent_update: &mut Option<SourceIndex<A>>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    >
    where
        P: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
    {
        b_trace!("Polling for updates for {:?}", self.key());

        let source = self.source;
        let destination = source.destination;
        let seqno = self.seqno;
        let metric = self.computed_metric;
        let mut route_in_packet = false;

        for update in self.update_queue.inner.iter_mut() {
            // If the timer still needs to fire then update the next poll value and continue.
            if let Some(remaining) = update.send_timer.time_remaining(now) {
                *next_poll = remaining.min(*next_poll);
                continue;
            }

            // Only what is owed on the interface being polled.
            if update.neighbour().iface != interface.key() {
                continue;
            }

            // If the update cannot be sent to the current destination, then skip it.
            if !update.can_send(active_dest) {
                continue;
            }

            // If the update would be a duplicate TLV in the current packet, decrement the send
            // counter and restart the send timer.
            if update.would_duplicate(active_dest, route_in_packet) {
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
                // This purges the unsendable update from the queue so we don't see it again.
                update.send_count = 0;
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

            // Perform source table maintenance for this route.
            if let Err(err) = sources.perform_maintenance(now, &source, seqno, metric) {
                b_debug!("Source Err: {}", err);
                continue;
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

            // If the packet's router-id context is not this route's, write a router-id TLV.
            // A fresh packet has no context at all, so the first update in one always gets a
            // Router-Id TLV — without it the receiver cannot attribute the Updates behind it.
            if parser.router_id().is_none_or(|id| id != &source.router_id) {
                let router_id = source.router_id;
                b_debug!(
                    "[SEND] RouterId - iface: {:?}, dest: {:?}, - router_id: {:?}",
                    interface,
                    active_dest,
                    router_id
                );

                writer = writer.write_router_id(router_id)?.finish_tlv()?;
                parser.set_router_id(router_id);
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
                Duration::from(update_interval).as_centis(),
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
                    update_interval,
                    seqno,
                    metric,
                    &destination.prefix().as_wire()[..trim.into()],
                )?
                .finish_tlv()?;

            route_in_packet = true;
            update.send_count = update.send_count.saturating_sub(1);
            update.send_timer.restart(now);
        }

        // Purge the updates that are finished sending, plus the ones there is no longer anything
        // to send.
        self.update_queue.purge_finished();
        Ok(writer)
    }

    pub(crate) fn destination(&self) -> &RouteDestination<A> {
        &self.source().destination
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

    pub(crate) fn computed_metric(&self) -> &Metric {
        &self.computed_metric
    }

    pub(crate) fn advertised_metric(&self) -> &Metric {
        &self.advertised_metric
    }
    pub(crate) fn smoothed_metric(&self) -> &Metric {
        &self.smoothed_metric
    }

    /// Sets the advertised metric for this route.
    ///
    /// It is expected that compute metric will be called AFTER all metric mutations are complete
    /// for a given [`Instant`]. Doing otherwise could incorrectly bias the smoothing algorithm to
    /// "think" there were multiple datapoints entered at a given [`Instant`].
    pub(crate) fn set_advertised_metric(&mut self, value: Metric) {
        // Update the advertised_metric
        self.advertised_metric = value;
    }

    /// When a route has expired set all of its metrics to infinity.
    pub(crate) fn retract(&mut self) {
        self.advertised_metric = Metric::INFINITY;
        self.computed_metric = Metric::INFINITY;
        // Theoretically, a smoothed version of an infinite metric is infinite. This is not
        // technically true for our "simulated infinity", but we can make it true by just setting
        // it instead of running it through the smoothing procedure.
        self.smoothed_metric = Metric::INFINITY;
    }

    pub(crate) fn compute_metric(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        smoothing_multiple: &DurationMultiplier,
    ) {
        // Update computed metric from the advertised metric
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
