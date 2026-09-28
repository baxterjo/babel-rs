use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::data_types::Address;
use crate::data_types::address_encoding::AddressEncoding;
use crate::data_types::destination::RouteDestination;
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::input::{Receive, ReceiveDestination};
use crate::packet::packet_slice::PacketSlice;
use crate::packet::parser::Parser;
use crate::packet::tlv::reader::TlvReader;
use crate::packet::tlv::{HelloSlice, IhuSlice, RouteRequestSlice, Tlv, UpdateSlice};
use crate::router::BabelRouter;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
{
    /// Handles input for the Babel state machine.
    ///
    /// It is expected that [`BabelRouter::poll_output`] will be called **IMMEDIATELY** after this
    /// is called.
    pub fn handle_input<'input>(
        &mut self,
        now: Instant,
        input: Receive<'input, A>,
    ) -> Result<(), BabelError<A>> {
        b_trace!("{:?}", input);

        // Have to copy the interface here to avoid indexing the interface table for every TLV in
        // the loop below.
        let Some(interface) = self.iface_table.inner.get_by_key(&input.iface).copied() else {
            return Err(BabelError::InterfaceDoesntExist(input.iface));
        };

        let mut parser: Parser<P> = Parser::new(input.source_addr);
        let packet = PacketSlice::from_slice(input.contents)?;
        b_trace!("{:?}", packet);

        let magic = packet.magic();
        if magic != self.magic_number {
            return Err(BabelError::IncorrectMagicNumber {
                expected: self.magic_number,
                received: magic,
            });
        }

        let version = packet.version();
        if version != self.version_number {
            return Err(BabelError::IncorrectVersionNumber {
                expected: self.version_number,
                received: version,
            });
        }

        // Route selection is run:
        // * After receiving a hello or after the router has determined it has missed one (handled
        // in poll_output)
        // * After updating a neighbour's tx_cost (which does not necesarrily mean upon IHU receipt)
        // * After the route table is updated

        let mut neighbour_update: Option<NeighbourIndex<A>> = None;

        for tlv in TlvReader::new(packet.body()) {
            match tlv {
                Tlv::Pad1 | Tlv::PadN(_) => {
                    continue;
                }
                // A TLV that cannot be handled is skipped rather than aborting the packet. TLVs
                // are (mostly) independent of one another, so letting one bad TLV discard the valid
                // ones behind it hands any sender on the link a way to suppress
                // them.
                Tlv::Hello(hello) => {
                    b_debug!(
                        "[RECV] Hello - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        hello
                    );
                    let neighbour_opt = ok_or_continue!(self.handle_hello(
                        now,
                        &interface,
                        input.source_addr,
                        hello
                    ));
                    neighbour_update = neighbour_update.or(neighbour_opt);
                }
                Tlv::Ihu(ihu) => {
                    b_debug!(
                        "[RECV] IHU - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        ihu
                    );
                    let neighbour_opt = ok_or_continue!(self.handle_ihu(
                        now,
                        &interface,
                        input.source_addr,
                        input.destination,
                        ihu
                    ));
                    neighbour_update = neighbour_update.or(neighbour_opt);
                }
                Tlv::RouterId(router_id) => {
                    b_debug!(
                        "[RECV] RouterId - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        router_id
                    );
                    parser.handle_router_id_tlv(router_id);
                }
                Tlv::NextHop(next_hop) => {
                    b_debug!(
                        "[RECV] NextHop - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        next_hop
                    );
                    ok_or_continue!(parser.handle_next_hop_tlv(next_hop));
                }
                Tlv::Update(update) => {
                    b_debug!(
                        "[RECV] Update - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        update
                    );
                    let neighbour = ok_or_continue!(self.handle_update(
                        now,
                        &interface,
                        &input.source_addr,
                        &mut parser,
                        update
                    ));
                    neighbour_update = neighbour_update.or(Some(neighbour));
                }
                Tlv::RouteRequest(route_request) => {
                    b_debug!(
                        "[RECV] RouteRequest - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        route_request
                    );
                    ok_or_continue!(self.handle_route_request(
                        now,
                        &interface,
                        &input.source_addr,
                        route_request
                    ))
                }
                Tlv::SeqnoRequest(seqno_req) => {
                    b_debug!(
                        "[RECV] SeqnoRequest - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        seqno_req
                    );
                }
                Tlv::AckReq(ack_req) => {
                    b_debug!(
                        "[RECV] AckRequest - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        ack_req
                    );
                }
                // This covers the base-spec TLVs that are not implemented yet.
                Tlv::Ack(ack) => {
                    b_debug!(
                        "[RECV] Ack - iface: {:?}, source: {:?} - {:?}",
                        input.iface,
                        input.source_addr,
                        ack
                    );
                }
            }
        }

        // After all packets have been handled, metrics can be updated for this neighbour.
        if let Some(neighbour) = neighbour_update {
            self.update_metrics_for_neighbour(now, &interface, neighbour);
            self.route_selection_due = true;
        }

        Ok(())
    }

    //  _  _   _   _  _ ___  _    ___   _  _ ___ _    _    ___
    // | || | /_\ | \| |   \| |  | __| | || | __| |  | |  / _ \
    // | __ |/ _ \| .` | |) | |__| _|  | __ | _|| |__| |_| (_) |
    // |_||_/_/ \_\_|\_|___/|____|___| |_||_|___|____|____\___/

    fn handle_hello(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<Option<NeighbourIndex<A>>, BabelError<A>> {
        b_debug!(
            "[RECV] Hello - iface: {:?}, source: {:?} - {:?}",
            interface,
            address,
            hello
        );
        // Handle the incoming hello
        self.neighbor_table
            .handle_hello(now, interface, address, hello)?;

        Ok(self
            .neighbor_table
            .inner
            .get_by_key(&NeighbourIndex {
                iface: *interface.handle(),
                addr: address,
            })
            .map(|n| n.key()))
    }

    //  _  _   _   _  _ ___  _    ___   ___ _  _ _   _
    // | || | /_\ | \| |   \| |  | __| |_ _| || | | | |
    // | __ |/ _ \| .` | |) | |__| _|   | || __ | |_| |
    // |_||_/_/ \_\_|\_|___/|____|___| |___|_||_|\___/

    /// Handle an incoming IHU from a neighbour.
    fn handle_ihu(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        source_addr: Address<A>,
        destination: ReceiveDestination,
        ihu: IhuSlice<'_>,
    ) -> Result<Option<NeighbourIndex<A>>, BabelError<A>> {
        if !ihu_is_addressed_to_us(&ihu, destination, interface.address)? {
            b_debug!("Ignoring IHU addressed to another neighbour");
            return Ok(None);
        }

        b_debug!(
            "[RECV] Ihu - iface: {:?}, source: {:?} - {:?}",
            interface,
            source_addr,
            ihu
        );

        self.neighbor_table
            .handle_ihu(now, source_addr, interface, ihu)?;

        Ok(self
            .neighbor_table
            .inner
            .get_by_key(&NeighbourIndex {
                iface: *interface.handle(),
                addr: source_addr,
            })
            .map(|n| n.key()))
    }

    //  _  _   _   _  _ ___  _    ___   _   _ ___ ___   _ _____ ___
    // | || | /_\ | \| |   \| |  | __| | | | | _ \   \ /_\_   _| __|
    // | __ |/ _ \| .` | |) | |__| _|  | |_| |  _/ |) / _ \| | | _|
    // |_||_/_/ \_\_|\_|___/|____|___|  \___/|_| |___/_/ \_\_| |___|

    fn handle_update(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        source_addr: &Address<A>,
        parser: &mut Parser<P>,
        update: UpdateSlice<'_>,
    ) -> Result<NeighbourIndex<A>, BabelError<A>> {
        b_debug!(
            "[RECV] Update - iface: {:?}, source: {:?} - {:?}",
            interface,
            source_addr,
            update
        );

        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        // The following sections fenced with ~ are direct quotes from section 3.5.3:
        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

        // Fetch the neighbour the update is from.
        let idx = NeighbourIndex {
            iface: *interface.handle(),
            addr: *source_addr,
        };
        let neighbour = self
            .neighbor_table
            .inner
            .get_by_key(&idx)
            .ok_or(BabelError::TlvFromUnknownNeighbour("update_tlv", idx))?;

        //  ___ _      _   _  _ _  _____ _____
        // | _ ) |    /_\ | \| | |/ / __|_   _|
        // | _ \ |__ / _ \| .` | ' <| _|  | |
        // |___/____/_/ \_\_|\_|_|\_\___| |_|
        //
        //  ___ ___ _____ ___    _   ___ _____ ___ ___  _  _
        // | _ \ __|_   _| _ \  /_\ / __|_   _|_ _/ _ \| \| |
        // |   / _|  | | |   / / _ \ (__  | |  | | (_) | .` |
        // |_|_\___| |_| |_|_\/_/ \_\___| |_| |___\___/|_|\_|

        if update.is_blanket_retraction() {
            b_debug!("Update is a blanket retraction.");
            // Section 4.6.9: "If the metric is infinite and AE is 0, Plen and Omitted MUST both be
            // 0; Update TLVs that do not satisfy this requirement MUST be ignored."
            if update.plen() != 0 || update.ommitted() != 0 {
                return Err(BabelError::MalformedBlanketRetraction {
                    plen: update.plen(),
                    omitted: update.ommitted(),
                });
            }
            // A blanket retraction triggers an update to be sent for all routes this neighbour has
            // advertised.
            for route in self
                .route_table
                .inner
                .iter_mut()
                .filter(|r| r.neighbour() == &idx)
            {
                route.retract();
                if route.selected {
                    b_trace!("Selected route retracted, selection is due.");
                    self.route_selection_due = true;
                }
            }
            return Ok(neighbour.key());
        }

        //  ___ ___ _____ ___    _   ___ _____ ___ ___  _  _
        // | _ \ __|_   _| _ \  /_\ / __|_   _|_ _/ _ \| \| |
        // |   / _|  | | |   / / _ \ (__  | |  | | (_) | .` |
        // |_|_\___| |_| |_|_\/_/ \_\___| |_| |___\___/|_|\_|

        if update.is_retraction() {
            b_debug!("Update is a retraction.");
            // A retraction only has to name the entry it retracts. Section 4.6.9: "the router-id,
            // next hop, and seqno are not used" This means that the parser does not need to have
            // state for router-id or next hop in this branch.
            let prefix = parser.resolve_address(&update)?;

            if let Some(route) = self.route_table.inner.get_mut_by_key(&RouteIndex {
                destination: RouteDestination::new(prefix, update.plen())?,
                neighbour: neighbour.key(),
            }) {
                route.retract();
                if route.selected {
                    b_trace!("Selected route retracted, selection is due.");
                    self.route_selection_due = true;
                }
            } else {
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                // if the metric is infinite (the update is a retraction of a route we do not know
                // about), the update is ignored;
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            }

            return Ok(neighbour.key());
        }

        // Resolve the update (this also updates the parser state)
        let resolved_update = parser.handle_update(update)?;

        // Section 4.6.9: the Interval "MUST NOT be 0". It is the only thing an Update says about
        // when to stop believing it, so without one there is no hold time a route could be created
        // or refreshed under. Checked before the route table is touched so a rejected Update
        // leaves an existing entry exactly as it was, rather than half-updated with a new metric
        // under the old expiry.
        if resolved_update.slice.interval().is_zero() {
            return Err(BabelError::ZeroUpdateInterval);
        }

        let source = SourceIndex {
            router_id: resolved_update.router_id,
            destination: resolved_update.destination,
        };

        // Check if the update is feasible against the source table.
        let feasible = self.source_table.is_feasible(
            &source,
            &resolved_update.slice.metric(),
            &resolved_update.slice.seqno(),
        );

        //    _   ___ ___  _   _ ___ ___ ___
        //   /_\ / __/ _ \| | | |_ _| _ \ __|
        //  / _ \ (_| (_) | |_| || ||   / _|
        // /_/ \_\___\__\_\\___/|___|_|_\___|

        // Read out before the lookup below, which borrows the whole route table.
        let route_expiry_time = self.route_table.route_expiry_time;

        // Aquire the route
        match self.route_table.inner.get_mut_by_key(&RouteIndex {
            destination: resolved_update.destination,
            neighbour: neighbour.key(),
        }) {
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // When a Babel node receives an update (prefix, plen, router-id, seqno, metric) from
            // a neighbour neigh, it checks whether it already has a route table entry indexed by
            // (prefix, plen, neigh).
            // If no such entry exists:
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            None => {
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                // if the update is unfeasible, it **MAY** be ignored
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if !feasible {
                    // TODO: Local setting?
                }

                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                // otherwise, a new entry is created in the route table, indexed by (prefix, plen,
                // neigh), with source equal to (prefix, plen, router-id), seqno equal to seqno,
                // and an advertised metric equal to the metric carried by the update.
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                // Link cost must be calculated for new routes as the smooth metric must be seeded
                // with the computed metric at this moment. If computation is deffered until the
                // end of packet processing then the smoothed metric will be incorrectly biased
                // toward zero.
                let link_cost = interface.cost_calc.link_cost(
                    interface.cost_calc.rx_cost(
                        neighbour.mcast_hello_info.history,
                        neighbour.ucast_hello_info.history,
                    ),
                    neighbour.tx_cost,
                );
                let computed_metric = interface
                    .cost_calc
                    .metric(resolved_update.slice.metric(), link_cost);

                match self.route_table.add_route(
                    now,
                    SourceIndex {
                        destination: resolved_update.destination,
                        router_id: resolved_update.router_id,
                    },
                    neighbour.key(),
                    resolved_update.slice.seqno(),
                    resolved_update.slice.metric(),
                    computed_metric,
                    resolved_update.next_hop,
                    resolved_update.slice.interval(),
                ) {
                    Ok(()) => {}

                    Err(
                        err @ (RouteError::Full
                        | RouteError::Duplicate
                        | RouteError::NoStorageAvailable),
                    ) => {
                        // Running out of room is a local capacity limit, not a protocol error: the
                        // route is dropped and the sender will re-advertise it.
                        // TODO(#21): User defined full storage handline.
                        b_debug!("Route not added - Discarded: {:?}", err);
                    }
                    Err(err) => return Err(err.into()),
                }
                self.route_selection_due = true;
            }
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // If such an entry exists:
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
            Some(route) => {
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                // if the entry is currently selected, the update is unfeasible, and the router-id
                // of the update is equal to the router-id of the entry, then the update **MAY**
                // be ignored
                // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                if route.selected
                    && !feasible
                    && route.source().router_id == resolved_update.router_id
                {
                    // TODO: Local setting?
                } else {
                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    // otherwise, the entry's sequence number, advertised metric, metric, and
                    // router-id are updated,
                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

                    // ANALYSIS:
                    // The inverse of the if statement above is worth stating and examining
                    // (condition by condition) what would cause this block to execute in order to
                    // understand the implicit behaviors of this block.

                    // The inverse of the statement is:

                    // If the route is NOT selected
                    //   OR the update is feasible
                    //   OR the route does not match the update router ID.

                    // 1. IF the route is selected THEN the update is either feasible OR the router
                    // id has changed.
                    //   a. In the case that it is only feasible, then you want to update your
                    //   metric because this is the entire premise the Babel algorithm is based on.
                    //   Only update your metric when feasibility is better.
                    //   b. In the case that it is a router ID change, that means the originator of
                    //     the Seqno is no longer the same as the previous Seqno. So this node MUST
                    //     update its metric.
                    //   c. Since both of those cases require an update to the route, they are
                    //     collapsed into one.

                    // 2. IF the update is NOT feasible THEN the route is not selected OR the
                    // router id has changed.
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
                    // - Only update selected routes when update is feasible.
                    // - The premise of feasibility relies on the source of Seqno, which is tracked
                    // by router-id, if this changes then Seqno and metric require a hard reset.
                    // - Keep track of all non-selected routes (without regard to feasibility) for
                    // fast failover.

                    let expiry = Timer::from_duration(
                        now,
                        Duration::from(resolved_update.slice.interval()) * route_expiry_time,
                    );

                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    // and if the advertised metric is not infinite, the route's expiry
                    // timer is reset to a small multiple of the interval value included in the
                    // update (see "Route Expiry time" in Appendix B for
                    // suggested values).
                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    route.expiry = expiry;

                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    // If the update is unfeasible, then the (now unfeasible) entry MUST be
                    // immediately unselected.
                    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                    let was_selected = route.selected;
                    if !feasible {
                        route.selected = false;
                    }

                    if route.source().router_id != resolved_update.router_id {
                        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        // If the update caused the router-id of the entry to change, an update
                        // (possibly a retraction) MUST be sent in a timely manner as described in
                        // Section 3.7.2.
                        // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
                        route.set_router_id(resolved_update.router_id);

                        // If the router ID for this route was changed and it was selected, an
                        // update MUST be sent.
                        if was_selected {
                            self.update_queue.queue_triggered_update(
                                now,
                                route,
                                &self.iface_table,
                                &self.neighbor_table,
                            );
                        }
                    }

                    route.seqno = resolved_update.slice.seqno();

                    route.set_advertised_metric(resolved_update.slice.metric());
                }
            }
        };

        Ok(neighbour.key())
    }

    //  _  _   _   _  _ ___  _    ___   ___  ___  _   _ _____ ___   ___ ___ ___
    // | || | /_\ | \| |   \| |  | __| | _ \/ _ \| | | |_   _| __| | _ \ __/ _ \
    // | __ |/ _ \| .` | |) | |__| _|  |   / (_) | |_| | | | | _|  |   / _| (_) |
    // |_||_/_/ \_\_|\_|___/|____|___| |_|_\\___/ \___/  |_| |___| |_|_\___\__\_\

    /// Handles route request as specified in
    /// [Section 3.8.1.1](https://datatracker.ietf.org/doc/html/rfc8966#name-route-requests)
    ///
    /// Rate limiting is implemented per queued update (destination, neighbour).
    fn handle_route_request(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        source_addr: &Address<A>,
        route_req: RouteRequestSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        let idx = NeighbourIndex {
            iface: interface.key(),
            addr: *source_addr,
        };
        let Some(neighbour) = self.neighbor_table.inner.get_by_key(&idx) else {
            return Err(BabelError::TlvFromUnknownNeighbour("route_request", idx));
        };

        let (ae, plen) = (route_req.ae(), route_req.plen());

        if ae == 0 && plen != 0 {
            return Err(BabelError::MalformedRouteRequest(ae, plen));
        }

        if ae == 0 {
            // Wildcard update, send all routes.
            for route in self.route_table.inner.iter().filter(|r| r.selected) {
                self.update_queue.queue_route_response(
                    now,
                    interface,
                    *route.destination(),
                    neighbour.key(),
                )?;
            }
        } else {
            // Destination update, queue update for that destination.
            let prefix = Address::from_bytes(AddressEncoding::try_from(ae)?, route_req.prefix()?)?;
            self.update_queue.queue_route_response(
                now,
                interface,
                RouteDestination::new(prefix, plen)?,
                neighbour.key(),
            )?;
        }
        Ok(())
    }
}

/// Decides whether an IHU was meant for this node.
///
/// RFC 8966 [4.6.6](https://datatracker.ietf.org/doc/html/rfc8966#name-ihu): an IHU names its
/// destination explicitly so that IHUs for several neighbours can be aggregated into one multicast
/// packet, each receiver keeping only the one addressed to it. The Address field therefore holds
/// *our* address, not the sender's, and is purely a relevance filter.
fn ihu_is_addressed_to_us<A: AddressExt>(
    ihu: &IhuSlice<'_>,
    destination: ReceiveDestination,
    our_addr: Address<A>,
) -> Result<bool, BabelError<A>> {
    let ae = AddressEncoding::<A::Encoding>::try_from(ihu.ae())?;

    if matches!(ae, AddressEncoding::WildCard) {
        // The sender omitted the address. That is only unambiguous when the datagram was
        // addressed to us alone; in a multicast packet there is no way to tell which neighbour a
        // wildcard IHU was for, so it cannot be claimed.
        return Ok(destination == ReceiveDestination::Unicast);
    }

    let addr_len = ae.address_len();
    let address_bytes = ihu.address(addr_len)?;

    Ok(Address::from_bytes(ae, address_bytes)? == our_addr)
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::{InterfaceConfig, InterfaceHandle};
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::route::route_table::DEFAULT_SMOOTHING_MULTIPLE;
    use crate::data_structures::route::{Route, RouteIndex};
    use crate::data_structures::updates::{Update, UpdateIndex};
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::{Metric, RxCost, TxCost};
    use crate::output::DatagramSend;
    use crate::packet::packet_header::PacketHeader;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::packet::tlv::update_slice::UpdateFlags;
    use crate::packet::writer::ready::Ready;
    use crate::packet::writer::{PacketWriter, PacketWriterStep};
    use crate::router::config::{BabelRouterConfig, DEFAULT_ROUTE_EXPIRY_TIME};
    use crate::router::is_eligible;
    use crate::utils::{Duration, InternallyKeyed};

    // Long enough not to fire again mid-test, still inside the Timer bound.
    const IFACE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));

    const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_1_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_2_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    const NEIGHBOUR_3_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 4);

    /// Builds a router born at the same instant every test measures from.
    ///
    /// `Instant::now` is `std` only, and it would put the router's birth decades ahead of the `t0`
    /// every test below starts from.
    fn router(name: &'static str) -> BabelRouter<'static> {
        BabelRouter::new(
            Instant::from_secs(0),
            BabelRouterConfig::new(RouterId::try_from(name).expect("bad router id")),
        )
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    /// Builds a packet with the same writer the router emits packets through, so what arrives at
    /// [`BabelRouter::handle_input`] is framed the way a real Babel node would have framed it
    /// rather than by a second, test-only encoder that can drift from it.
    struct PacketBuilder(PacketWriterStep<'static, Ready>);

    impl PacketBuilder {
        fn new() -> Self {
            Self(
                PacketWriter::new_packet(
                    PacketHeader::MAGIC_NUMBER,
                    PacketHeader::VERSION_NUMBER,
                    Vec::new(),
                )
                .expect("packet writer should start"),
            )
        }

        fn hello(self, seqno: u16, interval_centis: u16) -> Self {
            Self(
                self.0
                    .write_hello(
                        HelloFlags::new_multicast(),
                        SeqNo(seqno),
                        Duration::from_centis(interval_centis.into()).into(),
                    )
                    .expect("hello should write")
                    .finish_tlv()
                    .expect("hello should finish"),
            )
        }

        /// An IHU carrying a full 16-octet IPv6 destination address (AE 2).
        fn ihu(self, rx_cost: u16, interval_centis: u16, address: Ipv6Addr) -> Self {
            self.ihu_inner(2, rx_cost, interval_centis, &address.octets())
        }

        /// An IHU with the wildcard encoding (AE 0), which omits the address entirely.
        fn wildcard_ihu(self, rx_cost: u16, interval_centis: u16) -> Self {
            self.ihu_inner(0, rx_cost, interval_centis, &[])
        }

        fn ihu_inner(self, ae: u8, rx_cost: u16, interval_centis: u16, address: &[u8]) -> Self {
            Self(
                self.0
                    .write_ihu(
                        ae,
                        RxCost::from_raw(rx_cost),
                        Duration::from_centis(interval_centis.into()).into(),
                        address,
                    )
                    .expect("ihu should write")
                    .finish_tlv()
                    .expect("ihu should finish"),
            )
        }

        /// `RouterId::from` rather than `RouterId::new`, so these tests can still send the
        /// all-zeroes and all-ones ids the constructor rejects.
        fn router_id(self, id: [u8; 8]) -> Self {
            Self(
                self.0
                    .write_router_id(RouterId::from(&id))
                    .expect("router id should write")
                    .finish_tlv()
                    .expect("router id should finish"),
            )
        }

        fn next_hop(self, ae: u8, address: &[u8]) -> Self {
            Self(
                self.0
                    .write_next_hop(ae, address)
                    .expect("next hop should write")
                    .finish_tlv()
                    .expect("next hop should finish"),
            )
        }

        fn update(self, update: &UpdateTlv) -> Self {
            Self(
                self.0
                    .write_update(
                        update.ae,
                        UpdateFlags::from(update.flags),
                        update.plen,
                        update.omitted,
                        Duration::from_centis(update.interval_centis.into()).into(),
                        SeqNo(update.seqno),
                        Metric::from_raw(update.metric),
                        &update.prefix,
                    )
                    .expect("update should write")
                    .finish_tlv()
                    .expect("update should finish"),
            )
        }

        /// `prefix` is the Prefix field as it goes on the wire: Plen/8 rounded upwards octets, less
        /// the ones `ae` implies, and never compressed.
        fn route_request(self, ae: u8, plen: u8, prefix: &[u8]) -> Self {
            Self(
                self.0
                    .write_route_request(ae, plen, prefix)
                    .expect("route request should write")
                    .finish_tlv()
                    .expect("route request should finish"),
            )
        }

        fn build(self) -> Vec<u8> {
            let datagram: DatagramSend<'_> =
                self.0.finish_packet().expect("packet should finish").into();
            datagram.into()
        }
    }

    fn receive<'a>(
        iface: InterfaceHandle,
        source: Ipv6Addr,
        destination: ReceiveDestination,
        contents: &'a [u8],
    ) -> Receive<'a, NoExtension> {
        Receive {
            iface,
            source_addr: source.into(),
            destination,
            contents,
        }
    }

    fn tx_cost(r: &BabelRouter<'static>, iface: InterfaceHandle, addr: Ipv6Addr) -> TxCost {
        r.neighbor_table
            .inner
            .get_by_key(&NeighbourIndex {
                iface,
                addr: addr.into(),
            })
            .expect("neighbour should exist")
            .tx_cost
    }

    //  _   _ ___ ___   _ _____ ___   ___ _____ _____ _   _ ___ ___
    // | | | | _ \   \ /_\_   _| __| | __|_   _|_   _| | | | _ \ __|
    // | |_| |  _/ |) / _ \| | | _|  | _|  | |   | | | |_| |   / _|
    //  \___/|_| |___/_/ \_\_| |___| |_|   |_|   |_|  \___/|_|_\___|

    /// The Interval every Update here advertises unless it is testing the Interval itself.
    const UPDATE_INTERVAL_CENTIS: u16 = 200;
    /// The Metric field value that makes an Update a retraction.
    const METRIC_INFINITY: u16 = 0xFFFF;
    /// The rxcost neighbours advertise in their IHUs here. It becomes our txcost toward them and,
    /// under the spec cost calculator, the link cost of the route as well.
    const LINK_COST: u16 = 20;

    const PREFIX_FLAG: u8 = 0x80;
    const ROUTER_ID_FLAG: u8 = 0x40;

    /// Two prefixes with the wire forms an AE 2 Update carries for a /64: the leading 8 octets.
    const PLEN: u8 = 64;
    const PREFIX_A_WIRE: [u8; 8] = [0xfd, 0x0a, 0, 0, 0, 0, 0, 0];
    const PREFIX_B_WIRE: [u8; 8] = [0xfd, 0x0b, 0, 0, 0, 0, 0, 0];
    const PREFIX_A: Ipv6Addr = Ipv6Addr::new(0xfd0a, 0, 0, 0, 0, 0, 0, 0);
    const PREFIX_B: Ipv6Addr = Ipv6Addr::new(0xfd0b, 0, 0, 0, 0, 0, 0, 0);

    /// The router-ids of the nodes the routes below originate from. Neither is this node.
    const ORIGIN_1: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x11];
    const ORIGIN_2: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0x22];

    /// An Update TLV laid out on the wire, so these tests reach `handle_update` through the same
    /// accessors a real packet does.
    #[derive(Clone)]
    struct UpdateTlv {
        ae: u8,
        flags: u8,
        plen: u8,
        omitted: u8,
        interval_centis: u16,
        seqno: u16,
        metric: u16,
        /// The prefix as it appears on the wire, i.e. already compressed: (Plen/8 rounded upwards
        /// - Omitted) octets.
        prefix: Vec<u8>,
    }

    impl UpdateTlv {
        /// A finite-metric IPv6 Update, which is what advertises a route.
        fn v6(plen: u8, prefix: &[u8], metric: u16) -> Self {
            Self {
                ae: 2,
                flags: 0,
                plen,
                omitted: 0,
                interval_centis: UPDATE_INTERVAL_CENTIS,
                seqno: 1,
                metric,
                prefix: prefix.to_vec(),
            }
        }

        /// The retraction of a single prefix: an ordinary Update whose Metric field is infinity.
        fn retraction_of(plen: u8, prefix: &[u8]) -> Self {
            Self::v6(plen, prefix, METRIC_INFINITY)
        }

        /// AE 0 with an infinite metric, which retracts every route the sender previously
        /// advertised on this interface. Plen and Omitted MUST both be 0.
        fn blanket_retraction() -> Self {
            Self {
                ae: 0,
                flags: 0,
                plen: 0,
                omitted: 0,
                interval_centis: UPDATE_INTERVAL_CENTIS,
                seqno: 0,
                metric: METRIC_INFINITY,
                prefix: Vec::new(),
            }
        }

        fn ae(mut self, ae: u8) -> Self {
            self.ae = ae;
            self
        }

        fn flags(mut self, flags: u8) -> Self {
            self.flags = flags;
            self
        }

        fn omitted(mut self, omitted: u8, prefix: &[u8]) -> Self {
            self.omitted = omitted;
            self.prefix = prefix.to_vec();
            self
        }

        fn plen(mut self, plen: u8) -> Self {
            self.plen = plen;
            self
        }

        fn seqno(mut self, seqno: u16) -> Self {
            self.seqno = seqno;
            self
        }

        fn interval(mut self, centis: u16) -> Self {
            self.interval_centis = centis;
            self
        }
    }

    /// The hold time a route advertising `interval_centis` should end up with.
    fn expected_expiry(interval_centis: u16) -> Duration {
        Duration::from_centis(interval_centis.into()) * DEFAULT_ROUTE_EXPIRY_TIME
    }

    /// Sends a packet carrying a Router-Id TLV followed by `updates`, which is the shape an Update
    /// normally arrives in.
    ///
    /// `handle_input` only brings the route table up to date; the expiry sweep and the route
    /// selection that follows it live in the poll, which its documentation requires the caller to
    /// run immediately afterwards. This helper does both through [`tick`] so that what a test
    /// observes is the state a real caller would see.
    fn send_updates(
        r: &mut BabelRouter<'static>,
        now: Instant,
        iface: InterfaceHandle,
        from: Ipv6Addr,
        router_id: [u8; 8],
        updates: &[UpdateTlv],
    ) {
        let mut builder = PacketBuilder::new().router_id(router_id);
        for update in updates {
            builder = builder.update(update);
        }
        let pkt = builder.build();

        r.handle_input(
            now,
            receive(iface, from, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");
        tick(r, now);
    }

    /// Runs the time based sweep and the route selection that follows it.
    ///
    /// `poll_tick` only marks selection as due; `poll_output` is where it actually runs. The tests
    /// below read the update table, which sending would drain, so they take the same two steps
    /// `poll_output` takes without the packet that would come after them.
    fn tick(r: &mut BabelRouter<'static>, now: Instant) {
        r.poll_tick(now).expect("poll should succeed");
        if r.route_selection_due {
            r.select_routes(now);
            r.route_selection_due = false;
        }
    }

    fn nbr_idx(iface: InterfaceHandle, addr: Ipv6Addr) -> NeighbourIndex<NoExtension> {
        NeighbourIndex {
            iface,
            addr: addr.into(),
        }
    }

    fn dest(prefix: Ipv6Addr, plen: u8) -> RouteDestination<NoExtension> {
        RouteDestination::new(prefix.into(), plen).expect("bad destination")
    }

    /// What a queued update for `prefix`, originated by `origin`, owed to `send_to` amounts to:
    /// the source it will advertise paired with the key it sits under in the router's queue.
    ///
    /// The key names the destination and the neighbour owed, and nothing about the originator, so
    /// the source has to be looked at alongside it to identify what is actually owed.
    fn update_key(
        origin: [u8; 8],
        prefix: Ipv6Addr,
        send_to: NeighbourIndex<NoExtension>,
    ) -> (Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>) {
        (
            Some(SourceIndex {
                router_id: RouterId::from(&origin),
                destination: dest(prefix, PLEN),
            }),
            UpdateIndex {
                destination: dest(prefix, PLEN),
                neighbour: send_to,
            },
        )
    }

    /// [`update_key`] for a destination nothing holds any more, which is what a retraction is.
    ///
    /// There is no originator to name: an update carries a destination, and the write pass reads
    /// what to advertise off the selected route for it. With no such route there is nothing to
    /// read, and the pass writes an infinite metric — RFC 8966 4.6.9 leaves the router-id and the
    /// seqno of a retraction unused, so the Update TLV needs neither.
    fn retraction_key(
        prefix: Ipv6Addr,
        send_to: NeighbourIndex<NoExtension>,
    ) -> (Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>) {
        (
            None,
            UpdateIndex {
                destination: dest(prefix, PLEN),
                neighbour: send_to,
            },
        )
    }

    /// A `Copy` snapshot of a route table entry.
    ///
    /// A [`Route`] cannot be lifted out of the table and held on to while the router is driven
    /// further — which is exactly what these tests do when they take a "before" and an "after".
    /// Everything the assertions reach for is `Copy`, so this carries those and nothing else,
    /// under the names [`Route`] gives them.
    #[derive(Debug, Clone, Copy)]
    struct RouteSnapshot {
        source: SourceIndex<NoExtension>,
        neighbour: NeighbourIndex<NoExtension>,
        pub(crate) seqno: SeqNo,
        advertised_metric: Metric,
        computed_metric: Metric,
        smoothed_metric: Metric,
        pub(crate) smoothed_metric_time: Instant,
        pub(crate) next_hop: Address<NoExtension>,
        pub(crate) selected: bool,
        pub(crate) expiry: Timer,
    }

    impl RouteSnapshot {
        fn of(route: &Route<NoExtension>) -> Self {
            Self {
                source: *route.source(),
                neighbour: *route.neighbour(),
                seqno: route.seqno,
                advertised_metric: *route.advertised_metric(),
                computed_metric: *route.computed_metric(),
                smoothed_metric: *route.smoothed_metric(),
                smoothed_metric_time: route.smoothed_metric_time,
                next_hop: route.next_hop,
                selected: route.selected,
                expiry: route.expiry,
            }
        }

        fn source(&self) -> &SourceIndex<NoExtension> {
            &self.source
        }

        fn neigbour(&self) -> &NeighbourIndex<NoExtension> {
            &self.neighbour
        }

        fn advertised_metric(&self) -> &Metric {
            &self.advertised_metric
        }

        fn computed_metric(&self) -> &Metric {
            &self.computed_metric
        }

        fn smoothed_metric(&self) -> &Metric {
            &self.smoothed_metric
        }

        fn key(&self) -> RouteIndex<NoExtension> {
            RouteIndex {
                destination: self.source.destination,
                neighbour: self.neighbour,
            }
        }
    }

    /// Snapshots the route table entry indexed by (prefix, plen, neighbour), if it exists.
    fn route_for(
        r: &mut BabelRouter<'static>,
        iface: InterfaceHandle,
        neighbour: Ipv6Addr,
        prefix: Ipv6Addr,
        plen: u8,
    ) -> Option<RouteSnapshot> {
        let idx = RouteIndex {
            destination: dest(prefix, plen),
            neighbour: NeighbourIndex {
                iface,
                addr: neighbour.into(),
            },
        };
        r.route_table
            .inner
            .get_mut_by_key(&idx)
            .map(|r| RouteSnapshot::of(r))
    }

    /// [`is_eligible`] applied to the entry still sitting in the table, which a [`RouteSnapshot`]
    /// cannot stand in for: eligibility is asked of a real route.
    fn is_eligible_in_table(r: &mut BabelRouter<'static>, key: &RouteIndex<NoExtension>) -> bool {
        let source_table = &r.source_table;
        r.route_table
            .inner
            .get_mut_by_key(key)
            .is_some_and(|route| is_eligible(source_table, route))
    }

    fn route_count(r: &mut BabelRouter<'static>) -> usize {
        r.route_table.inner.iter_mut().count()
    }

    /// The keys of every route currently holding a destination.
    fn selected_route_keys(r: &mut BabelRouter<'static>) -> Vec<RouteIndex<NoExtension>> {
        r.route_table
            .inner
            .iter_mut()
            .filter(|route| route.selected)
            .map(|route| route.key())
            .collect()
    }

    /// Every update the router still owes, paired with the source it would advertise, in the order
    /// a poll would walk them: the queue's order, which is (prefix, plen, neighbour owed).
    ///
    /// The source is not the update's own: an update names a destination, and the write pass reads
    /// what to advertise off the selected route for it. So this resolves it the same way, and
    /// `None` is a destination nothing holds — what the pass renders as a retraction.
    fn pending_updates(
        r: &mut BabelRouter<'static>,
    ) -> Vec<(Option<SourceIndex<NoExtension>>, Update<NoExtension>)> {
        let routes = &r.route_table;
        r.update_queue
            .inner
            .iter()
            .map(|update| {
                (
                    routes
                        .get_selected(update.destination())
                        .map(|route| *route.source()),
                    *update,
                )
            })
            .collect()
    }

    /// Whether the router owes nothing that would advertise `route`.
    ///
    /// An update no longer names a route at all — it names a destination, and the write pass
    /// renders it from whichever route holds that destination. So the question is whether any
    /// update owed for this route's destination resolves back to this route.
    fn owes_nothing(r: &mut BabelRouter<'static>, route: &RouteIndex<NoExtension>) -> bool {
        let routes = &r.route_table;
        !r.update_queue.inner.iter().any(|update| {
            update.destination() == &route.destination
                && routes.get_selected(update.destination()).map(|r| r.key()) == Some(*route)
        })
    }

    /// Drops every update the router is holding, so what a later step queues is measured on its
    /// own.
    fn drain_updates(r: &mut BabelRouter<'static>) {
        r.update_queue.inner.retain(|_| false);
    }

    /// Brings a neighbour to the state an Update needs to yield a finite route metric: enough
    /// hellos for a finite rxcost, and an IHU so the txcost — and with it the link cost — is finite
    /// too. Missing either one makes every route this neighbour advertises compute to infinity.
    fn established_neighbour(
        r: &mut BabelRouter<'static>,
        now: Instant,
        iface: InterfaceHandle,
        addr: Ipv6Addr,
    ) {
        for seqno in 0..2 {
            let pkt = PacketBuilder::new().hello(seqno, 100).build();
            r.handle_input(
                now,
                receive(iface, addr, ReceiveDestination::Multicast, &pkt),
            )
            .expect("hello should be handled");
        }

        let pkt = PacketBuilder::new().ihu(LINK_COST, 100, NODE_ADDR).build();
        r.handle_input(
            now,
            receive(iface, addr, ReceiveDestination::Multicast, &pkt),
        )
        .expect("ihu should be handled");
    }

    /// Registers an interface and drains its mandatory eager initial multicast hello.
    fn drained_iface(r: &mut BabelRouter<'static>, now: Instant, name: &str) -> InterfaceHandle {
        drained_iface_with_hello(r, now, name, IFACE_INTERVAL)
    }

    /// As [`drained_iface`], but with the multicast hello interval chosen by the caller. The
    /// smoothing time constant is derived from that interval, so the tests that exercise it need
    /// one short enough to step over.
    fn drained_iface_with_hello(
        r: &mut BabelRouter<'static>,
        now: Instant,
        name: &str,
        hello: Interval,
    ) -> InterfaceHandle {
        let mut config: InterfaceConfig<NoExtension> =
            InterfaceConfig::new_wired(iface_handle(name), NODE_ADDR.into());
        config.set_mcast_hello_interval(hello);
        let handle = r
            .register_interface(now, config)
            .expect("register should succeed");
        r.poll_output(now).expect("poll should succeed");
        handle
    }

    //  _   _ _  _ ___ ___ ___ ___ ___ _____ ___ ___ ___ ___    ___ ___ _   ___ ___
    // | | | | \| | _ \ __/ __|_ _/ __|_   _| __| _ \ __|   \  |_ _| __/_\ / __| __|
    // | |_| | .` |   / _| (_ || |\__ \ | | | _||   / _|| |) |  | || _/ _ \ (__| _|
    //  \___/|_|\_|_|_\___\___|___|___/ |_| |___|_|_\___|___/  |___|_/_/ \_\___|___|

    #[test]
    fn handle_input_on_an_unregistered_interface_is_rejected() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        drained_iface(&mut r, t0, "iface_1");

        let unknown = iface_handle("nope");
        let pkt = PacketBuilder::new().hello(0, 100).build();

        let err = r
            .handle_input(
                t0,
                receive(
                    unknown,
                    NEIGHBOUR_1_ADDR,
                    ReceiveDestination::Multicast,
                    &pkt,
                ),
            )
            .expect_err("an unregistered interface should be rejected");

        assert!(matches!(err, BabelError::InterfaceDoesntExist(h) if h == unknown));
        assert!(
            r.neighbor_table
                .inner
                .get_by_key(&NeighbourIndex {
                    iface: unknown,
                    addr: NEIGHBOUR_1_ADDR.into()
                })
                .is_none(),
            "no neighbour should have been created on an unknown interface"
        );

        // The rejection has to leave the router pollable rather than merely deferring the panic.
        r.poll_output(t0).expect("poll should still succeed");
    }

    #[test]
    fn add_neighbour_on_an_unregistered_interface_is_rejected() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        drained_iface(&mut r, t0, "iface_1");

        let unknown = iface_handle("nope");
        let err = r
            .add_neighbour(t0, unknown, NEIGHBOUR_1_ADDR.into())
            .expect_err("an unregistered interface should be rejected");

        assert!(matches!(err, BabelError::InterfaceDoesntExist(h) if h == unknown));
        r.poll_output(t0).expect("poll should still succeed");
    }

    //  ___ _  _ _   _    _   ___  ___  ___ ___ ___ ___ ___
    // |_ _| || | | | |  /_\ |   \|   \| _ \ __/ __/ __|_ _|
    //  | || __ | |_| | / _ \| |) | |) |   / _|\__ \__ \| |
    // |___|_||_|\___/ /_/ \_\___/|___/|_|_\___|___/___/___|

    /// The rxcost in an IHU is the sender's cost for hearing us, so it becomes our tx_cost toward
    /// the sender. Nothing inside a Babel packet names the sender, so the neighbour is always
    /// identified by the transport's source address — never by the TLV's Address field, which
    /// names the destination.
    #[test]
    fn ihu_rxcost_is_applied_to_the_sender() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            r.add_neighbour(t0, iface, addr.into())
                .expect("add_neighbour should succeed");
        }

        // Addressed to us (NODE_ADDR), sent by neighbour 1.
        let pkt = PacketBuilder::new().ihu(77, 100, NODE_ADDR).build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            tx_cost(&r, iface, NEIGHBOUR_1_ADDR),
            TxCost::from_raw(77),
            "neighbour 1 sent the IHU, so the rxcost is our cost toward neighbour 1"
        );
        assert_eq!(
            tx_cost(&r, iface, NEIGHBOUR_2_ADDR),
            TxCost::INFINITY,
            "neighbour 2 had nothing to do with this packet"
        );
    }

    /// The aggregation case the Address field exists for: one multicast packet carrying IHUs for
    /// several neighbours. Each receiver keeps the one naming its own address and ignores the
    /// rest, which are other nodes' business.
    #[test]
    fn aggregated_multicast_ihu_for_another_node_is_ignored() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        r.add_neighbour(t0, iface, NEIGHBOUR_1_ADDR.into())
            .expect("add_neighbour should succeed");

        // Neighbour 1 multicasts two IHUs: one for us, one for neighbour 2.
        let pkt = PacketBuilder::new()
            .ihu(11, 100, NODE_ADDR)
            .ihu(22, 100, NEIGHBOUR_2_ADDR)
            .build();

        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            tx_cost(&r, iface, NEIGHBOUR_1_ADDR),
            TxCost::from_raw(11),
            "only the IHU naming our own address should have been applied"
        );
        assert!(
            r.neighbor_table
                .inner
                .get_by_key(&NeighbourIndex {
                    iface,
                    addr: NEIGHBOUR_2_ADDR.into()
                })
                .is_none(),
            "an IHU addressed to another node must not create a neighbour for it"
        );
    }

    /// A wildcard IHU carries no address, so it can only be claimed when the datagram was
    /// addressed to us alone. Over multicast there is no way to tell which neighbour it was for.
    #[test]
    fn wildcard_ihu_is_accepted_over_unicast() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        let pkt = PacketBuilder::new().wildcard_ihu(33, 100).build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Unicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_1_ADDR), TxCost::from_raw(33));
    }

    #[test]
    fn wildcard_ihu_is_ignored_over_multicast() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        let pkt = PacketBuilder::new().wildcard_ihu(33, 100).build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert!(
            r.neighbor_table
                .inner
                .get_by_key(&NeighbourIndex {
                    iface,
                    addr: NEIGHBOUR_1_ADDR.into()
                })
                .is_none(),
            "an unaddressable IHU must not be claimed"
        );
    }

    //  ___   _   ___    _____ _ __   __  ___ _  _____ ___ ___
    // | _ ) /_\ |   \  |_   _| |\ \ / / / __| |/ /_ _| _ \ _ \
    // | _ \/ _ \| |) |   | | | |_\ V /  \__ \ ' < | ||  _/  _/
    // |___/_/ \_\___/    |_| |____|_|   |___/_|\_\___|_| |_|

    /// TLVs in a packet are independent, so one the router cannot handle must be skipped rather
    /// than aborting the rest. Otherwise a single malformed TLV placed at the front of a packet
    /// discards every valid TLV behind it.
    #[test]
    fn a_tlv_that_fails_to_handle_does_not_discard_the_rest_of_the_packet() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        // An interval of zero is rejected by the IHU hold timer, so this TLV fails to handle.
        let pkt = PacketBuilder::new()
            .ihu(50, 0, NODE_ADDR)
            .hello(0, 100)
            .build();

        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Unicast, &pkt),
        )
        .expect("a TLV that fails to handle should not fail the packet");

        let neighbour = r
            .neighbor_table
            .inner
            .get_by_key(&NeighbourIndex {
                iface,
                addr: NEIGHBOUR_1_ADDR.into(),
            })
            .expect("neighbour should exist");

        // Recording the hello advances the expected multicast seqno, so this proves the hello
        // behind the bad IHU was still processed.
        assert_eq!(
            neighbour
                .mcast_hello_info
                .expected_seqno
                .expect("Should have seqno"),
            SeqNo(1),
            "the hello behind the bad IHU should still have been handled"
        );
        assert_eq!(
            neighbour.tx_cost,
            TxCost::INFINITY,
            "the rejected IHU must not have applied its rxcost"
        );
    }

    /// A unicast IHU is already unambiguous, so the source address wins and the TLV's Address
    /// field is not consulted.
    #[test]
    fn unicast_ihu_is_attributed_to_the_source_address() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            r.add_neighbour(t0, iface, addr.into())
                .expect("add_neighbour should succeed");
        }

        // Sent directly to us: the Address field carries our own address, not the sender's.
        let pkt = PacketBuilder::new().ihu(42, 100, NODE_ADDR).build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Unicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_1_ADDR), TxCost::from_raw(42));
        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_2_ADDR), TxCost::INFINITY);
    }

    //  ___  ___  _   _ _____ ___     _   ___ ___  _   _ ___ ___ ___ _____ ___ ___  _  _
    // | _ \/ _ \| | | |_   _| __|   /_\ / __/ _ \| | | |_ _/ __|_ _|_   _|_ _/ _ \| \| |
    // |   / (_) | |_| | | | | _|   / _ \ (_| (_) | |_| || |\__ \| |  | |  | | (_) | .` |
    // |_|_\\___/ \___/  |_| |___| /_/ \_\___\__\_\\___/|___|___/___| |_| |___\___/|_|\_|

    /// RFC 8966 [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition): a
    /// first Update for (prefix, plen, neigh) creates an entry whose source is
    /// (prefix, plen, router-id), whose seqno and advertised metric come straight off the wire, and
    /// whose hold time is a small multiple of the Interval the Update carried.
    #[test]
    fn an_update_creates_a_route_entry() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(7)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the update should have created a route");

        assert_eq!(route.source().destination, dest(PREFIX_A, PLEN));
        assert_eq!(
            route.source().router_id,
            RouterId::from(&ORIGIN_1),
            "the source router-id comes from the preceding Router-Id TLV"
        );
        assert_eq!(
            *route.neigbour(),
            NeighbourIndex {
                iface,
                addr: NEIGHBOUR_1_ADDR.into()
            },
            "the route is attributed to the neighbour that advertised it"
        );
        assert_eq!(route.seqno, SeqNo(7));
        assert_eq!(
            *route.advertised_metric(),
            Metric::from_raw(100),
            "the advertised metric is the one the neighbour sent, unchanged"
        );
        assert_eq!(
            *route.computed_metric(),
            Metric::from_raw(100 + LINK_COST),
            "the computed metric adds the cost of the link the update arrived over"
        );
        assert_eq!(
            route.next_hop,
            NEIGHBOUR_1_ADDR.into(),
            "with no Next Hop TLV the next hop is the packet's source address"
        );
        assert_eq!(
            route.expiry.duration(),
            expected_expiry(UPDATE_INTERVAL_CENTIS),
            "the hold time is a small multiple of the advertised Interval"
        );
    }

    /// The route table is indexed by (prefix, plen, neigh), so the same prefix heard from two
    /// neighbours is two entries. Collapsing them would throw away the alternative the route
    /// selection procedure exists to choose between.
    #[test]
    fn one_prefix_from_two_neighbours_is_two_route_entries() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
        }

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
        );

        assert_eq!(route_count(&mut r), 2);
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("neighbour 1 should have a route")
                .advertised_metric(),
            &Metric::from_raw(100)
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN)
                .expect("neighbour 2 should have a route")
                .advertised_metric(),
            &Metric::from_raw(300)
        );
    }

    /// A route entry names the neighbour that advertised it, so there is nothing to index an Update
    /// from a node the neighbour table has never heard of.
    #[test]
    fn an_update_from_an_unknown_neighbour_creates_no_route() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        // No hello, no IHU, no `add_neighbour`: this address is a stranger.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        assert_eq!(route_count(&mut r), 0);
    }

    /// An Update with no Router-Id in scope has no source to be filed under, and RFC 8966
    /// [4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update) says such an update is
    /// ignored.
    #[test]
    fn an_update_with_no_router_id_in_scope_creates_no_route() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        // The packet body is the Update alone — no preceding Router-Id TLV.
        let pkt = PacketBuilder::new()
            .update(&UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100))
            .build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(route_count(&mut r), 0);
    }

    /// A Next Hop TLV names where packets for the advertised prefix should actually be sent, which
    /// need not be the node that sent the packet.
    #[test]
    fn a_next_hop_tlv_becomes_the_routes_next_hop() {
        const NEXT_HOP: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99);

        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        let pkt = PacketBuilder::new()
            .router_id(ORIGIN_1)
            .next_hop(2, &NEXT_HOP.octets())
            .update(&UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100))
            .build();

        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the update should have created a route");

        assert_eq!(
            route.next_hop,
            NEXT_HOP.into(),
            "the announced next hop should win over the packet's source address"
        );
        assert_eq!(
            route.neigbour().addr,
            NEIGHBOUR_1_ADDR.into(),
            "the next hop must not change which neighbour advertised the route"
        );
    }

    /// The parser state is threaded through the whole packet, so an Update that establishes a
    /// default prefix has to still be in force when the next Update in that packet omits octets.
    #[test]
    fn an_update_can_omit_octets_from_an_earlier_default_prefix_in_the_same_packet() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                // Sets fd0a::/64 as the default prefix for AE 2.
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).flags(PREFIX_FLAG),
                // fd0a:0:0:1::/64 with its first two octets taken from that default.
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 200).omitted(2, &[0, 0, 0, 0, 0, 1]),
            ],
        );

        assert_eq!(route_count(&mut r), 2);
        assert!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN).is_some(),
            "the default-setting update should have created its own route"
        );

        let compressed = route_for(
            &mut r,
            iface,
            NEIGHBOUR_1_ADDR,
            Ipv6Addr::new(0xfd0a, 0, 0, 1, 0, 0, 0, 0),
            PLEN,
        )
        .expect("the compressed update should have created a route");

        assert_eq!(*compressed.advertised_metric(), Metric::from_raw(200));
    }

    /// AE 3 implies `fe80::/64` and puts only the suffix on the wire, but Plen counts the whole
    /// prefix — so a link-local host route arrives as Plen 128 with 8 octets of Prefix field. The
    /// route table has to record the full 128, because a `(prefix, prefix_len)` pair is only
    /// meaningful as a CIDR: storing the 64 bits that reached the wire would turn every link-local
    /// host route into `fe80::/64`.
    ///
    /// This is the convention `babeld` implements (`message.c:network_prefix`, `AE_IPV6_LOCAL`).
    #[test]
    fn a_link_local_update_is_stored_with_its_full_prefix_length() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(128, &[0, 0, 0, 0, 0, 0, 0, 1], 100).ae(3),
                UpdateTlv::v6(128, &[0, 0, 0, 0, 0, 0, 0, 2], 100).ae(3),
            ],
        );

        assert_eq!(
            route_count(&mut r),
            2,
            "two link-local host routes are two entries"
        );

        for suffix in [1u16, 2] {
            let route = route_for(
                &mut r,
                iface,
                NEIGHBOUR_1_ADDR,
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, suffix),
                128,
            )
            .expect("the link-local host route should have been acquired");

            assert_eq!(
                *route.source().destination.prefix_len(),
                128,
                "the entry records the whole prefix, not the part that reached the wire"
            );
            assert_eq!(*route.advertised_metric(), Metric::from_raw(100));
        }
    }

    /// The other end of the AE 3 range: Plen 64 is the implied prefix by itself, so the Update
    /// carries no Prefix field at all and advertises `fe80::/64`.
    #[test]
    fn a_link_local_update_at_the_implied_prefix_carries_no_octets() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(64, &[], 100).ae(3)],
        );

        let route = route_for(
            &mut r,
            iface,
            NEIGHBOUR_1_ADDR,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0),
            64,
        )
        .expect("fe80::/64 should have been acquired");

        assert_eq!(*route.source().destination.prefix_len(), 64);
    }

    //  ___  ___  _   _ _____ ___   ___ ___ ___ ___ ___ ___ _  _
    // | _ \/ _ \| | | |_   _| __| | _ \ __| __| _ \ __/ __| || |
    // |   / (_) | |_| | | | | _|  |   / _|| _||   / _|\__ \ __ |
    // |_|_\\___/ \___/  |_| |___| |_|_\___|_| |_|_\___|___/_||_|

    /// A repeat Update for a prefix already heard from that neighbour refreshes the entry in place
    /// rather than adding a second one, and every field it carries is applied.
    #[test]
    fn a_second_update_for_the_same_prefix_refreshes_the_existing_entry() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(1)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300).seqno(2)],
        );

        assert_eq!(
            route_count(&mut r),
            1,
            "the second update names the same (prefix, plen, neigh)"
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(route.seqno, SeqNo(2));
        assert_eq!(*route.advertised_metric(), Metric::from_raw(300));
        assert_eq!(*route.computed_metric(), Metric::from_raw(300 + LINK_COST));
    }

    /// The route table key does not include the router-id, so a prefix that changes hands keeps its
    /// entry and updates the source it is advertised for.
    #[test]
    fn an_update_carrying_a_new_router_id_repoints_the_existing_entry() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_2,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        assert_eq!(route_count(&mut r), 1);
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the route should still exist")
                .source()
                .router_id,
            RouterId::from(&ORIGIN_2),
            "the entry should now be advertised for the new source"
        );
    }

    /// The hold time is derived from the Interval of the update that most recently refreshed the
    /// route, not from the one that created it.
    #[test]
    fn a_later_update_resets_the_expiry_timer_from_its_own_interval() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        // Well inside the first hold time, and advertising a longer interval than before.
        let t1 = t0 + Duration::from_secs(3);
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)
                .seqno(2)
                .interval(400)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(route.expiry.duration(), expected_expiry(400));
        assert_eq!(
            route.expiry.time_remaining(t1),
            Some(expected_expiry(400)),
            "the timer should run from the second update, not from the first"
        );
    }

    //  ___ ___ _____ ___    _   ___ _____ ___ ___  _  _
    // | _ \ __|_   _| _ \  /_\ / __|_   _|_ _/ _ \| \| |
    // |   / _|  | | |   / / _ \ (__  | |  | | (_) | .` |
    // |_|_\___| |_| |_|_\/_/ \_\___| |_| |___\___/|_|\_|

    /// A Metric of FFFF hexadecimal retracts the route. The entry stays in the table carrying an
    /// infinite metric — dropping it outright would lose the record that this neighbour has spoken
    /// about the prefix at all.
    #[test]
    fn a_retraction_drives_a_known_route_to_infinity_and_keeps_the_entry() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("a retraction should not remove the entry");

        assert_eq!(route_count(&mut r), 1);
        assert_eq!(*route.advertised_metric(), Metric::INFINITY);
        assert_eq!(*route.computed_metric(), Metric::INFINITY);
    }

    /// Retracting a prefix this neighbour never advertised is not an error — there is simply no
    /// entry to drive to infinity, and one must not be conjured up.
    #[test]
    fn a_retraction_for_an_unknown_route_creates_nothing() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        assert_eq!(route_count(&mut r), 0);
    }

    /// RFC 8966 [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition)
    /// resets a route's expiry timer only when the advertised metric is finite. A retracted route
    /// therefore runs out the hold time it already had and is flushed when it fires; handing it a
    /// fresh timer would keep it alive for another full hold time every time the neighbour repeats
    /// the retraction.
    #[test]
    fn a_retraction_leaves_the_expiry_timer_it_already_had() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        // Part way through the hold time the update bought, and the retraction advertises a much
        // longer Interval than the original update did.
        let t1 = t0 + Duration::from_secs(3);
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE).interval(60_000)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(
            route.expiry.duration(),
            expected_expiry(UPDATE_INTERVAL_CENTIS),
            "the retraction's own Interval must not become the hold time"
        );
        assert_eq!(
            route.expiry.time_remaining(t1),
            Some(expected_expiry(UPDATE_INTERVAL_CENTIS) - Duration::from_secs(3)),
            "the timer should still be running from the update that created the route"
        );
    }

    /// A blanket retraction is a retraction of every route from the neighbour, so it leaves their
    /// expiry timers alone for the same reason a single one does.
    #[test]
    fn a_blanket_retraction_leaves_the_expiry_timers_it_already_had() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        let t1 = t0 + Duration::from_secs(3);
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::blanket_retraction().interval(60_000)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(*route.computed_metric(), Metric::INFINITY);
        assert_eq!(
            route.expiry.time_remaining(t1),
            Some(expected_expiry(UPDATE_INTERVAL_CENTIS) - Duration::from_secs(3)),
            "the timer should still be running from the update that created the route"
        );
    }

    /// RFC 8966 [4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update): for a
    /// retraction "the router-id, next hop, and seqno are not used". A sender is free to put
    /// anything in those fields, so the entry keeps what its last real advertisement set.
    #[test]
    fn a_retraction_keeps_the_seqno_and_router_id_of_the_last_advertisement() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(7)],
        );
        // A retraction whose unused fields say something else entirely.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_2,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE).seqno(0)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(*route.computed_metric(), Metric::INFINITY);
        assert_eq!(route.seqno, SeqNo(7), "the retraction's seqno is not used");
        assert_eq!(
            route.source().router_id,
            RouterId::from(&ORIGIN_1),
            "the retraction's router-id is not used"
        );
    }

    /// A retraction is valid in a packet that established no router-id, because it does not use
    /// one. Demanding one would let a node's parting retraction be silently dropped.
    #[test]
    fn a_retraction_needs_no_router_id_in_scope() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        // The packet body is the retraction alone — no Router-Id TLV in front of it.
        let pkt = PacketBuilder::new()
            .update(&UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE))
            .build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the route should still exist")
                .computed_metric(),
            &Metric::INFINITY
        );
    }

    /// The Prefix flag "establishes a new default prefix for subsequent Update TLVs with a matching
    /// address encoding within the same packet" regardless of what the flagged TLV itself does, so
    /// a retraction carrying it still has that side effect.
    #[test]
    fn a_retraction_still_establishes_the_default_prefix_for_the_updates_behind_it() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE).flags(PREFIX_FLAG),
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).omitted(2, &[0, 0, 0, 0, 0, 1]),
            ],
        );

        assert!(
            route_for(
                &mut r,
                iface,
                NEIGHBOUR_1_ADDR,
                Ipv6Addr::new(0xfd0a, 0, 0, 1, 0, 0, 0, 0),
                PLEN
            )
            .is_some(),
            "the update behind the retraction should have resolved against its default prefix"
        );
    }

    /// A retraction names one (prefix, plen, neigh). Every other entry — another prefix from the
    /// same neighbour, or the same prefix from another one — is somebody else's route.
    #[test]
    fn a_retraction_only_touches_the_route_it_names() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
            send_updates(
                &mut r,
                t0,
                iface,
                addr,
                ORIGIN_1,
                &[
                    UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
                    UpdateTlv::v6(PLEN, &PREFIX_B_WIRE, 100),
                ],
            );
        }
        assert_eq!(route_count(&mut r), 4);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the retracted route should still exist")
                .computed_metric(),
            &Metric::INFINITY
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_B, PLEN)
                .expect("the other prefix should still exist")
                .computed_metric(),
            &Metric::from_raw(100 + LINK_COST),
            "a retraction of one prefix must not touch another prefix from the same neighbour"
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN)
                .expect("the other neighbour's route should still exist")
                .computed_metric(),
            &Metric::from_raw(100 + LINK_COST),
            "one neighbour cannot retract another neighbour's route"
        );
    }

    //  ___ _      _   _  _ _  _____ _____   ___ ___ _____ ___    _   ___ _____ ___ ___  _  _
    // | _ ) |    /_\ | \| | |/ / __|_   _| | _ \ __|_   _| _ \  /_\ / __|_   _|_ _/ _ \| \| |
    // | _ \ |__ / _ \| .` | ' <| _|  | |   |   / _|  | | |   / / _ \ (__  | |  | | (_) | .` |
    // |___/____/_/ \_\_|\_|_|\_\___| |_|   |_|_\___| |_| |_|_\/_/ \_\___| |_| |___\___/|_|\_|

    /// RFC 8966 [4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update): with an
    /// infinite metric, AE MAY be 0, "in which case this Update retracts all of the routes
    /// previously advertised by the sending interface". Routes learned from anybody else are
    /// untouched.
    #[test]
    fn a_blanket_retraction_retracts_every_route_from_the_sending_neighbour() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
            send_updates(
                &mut r,
                t0,
                iface,
                addr,
                ORIGIN_1,
                &[
                    UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
                    UpdateTlv::v6(PLEN, &PREFIX_B_WIRE, 100),
                ],
            );
        }
        assert_eq!(route_count(&mut r), 4);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::blanket_retraction()],
        );

        assert_eq!(
            route_count(&mut r),
            4,
            "a blanket retraction retracts routes, it does not remove their entries"
        );
        for prefix in [PREFIX_A, PREFIX_B] {
            let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, prefix, PLEN)
                .expect("the retracted route should still exist");
            assert_eq!(*route.advertised_metric(), Metric::INFINITY);
            assert_eq!(*route.computed_metric(), Metric::INFINITY);

            let other = route_for(&mut r, iface, NEIGHBOUR_2_ADDR, prefix, PLEN)
                .expect("the other neighbour's route should still exist");
            assert_eq!(
                *other.computed_metric(),
                Metric::from_raw(100 + LINK_COST),
                "one neighbour's blanket retraction must not touch another neighbour's routes"
            );
        }
    }

    /// For a retraction "the router-id, next hop, and seqno are not used", and a blanket retraction
    /// carries no prefix to decompress either. It therefore has to be honoured in a packet with no
    /// parser state at all — which is exactly the packet a node sends when it is going away.
    #[test]
    fn a_blanket_retraction_needs_no_router_id_in_scope() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        // The packet body is the blanket retraction alone — no Router-Id TLV in front of it.
        let pkt = PacketBuilder::new()
            .update(&UpdateTlv::blanket_retraction())
            .build();
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the route should still exist")
                .computed_metric(),
            &Metric::INFINITY
        );
    }

    //  __  __   _   _    ___ ___  ___ __  __ ___ ___
    // |  \/  | /_\ | |  | __/ _ \| _ \  \/  | __|   \
    // | |\/| |/ _ \| |__| _| (_) |   / |\/| | _|| |) |
    // |_|  |_/_/ \_\____|_| \___/|_|_\_|  |_|___|___/

    /// RFC 8966 [4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update): "If the metric
    /// is finite, AE MUST NOT be 0; Update TLVs with finite metric and AE equal to 0 MUST be
    /// ignored." There is no address for such an Update to be about.
    ///
    /// Ignoring it also has to be local: the Router-Id flag on a TLV with no address must not
    /// establish anything for the Updates behind it.
    #[test]
    fn a_finite_metric_update_with_the_wildcard_encoding_is_ignored() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(0, &[], 100).ae(0).flags(ROUTER_ID_FLAG),
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
            ],
        );

        assert_eq!(
            route_count(&mut r),
            1,
            "only the well-formed update should have created a route"
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the well-formed update should still have been handled")
                .source()
                .router_id,
            RouterId::from(&ORIGIN_1),
            "the ignored update must not have established a router-id for the one behind it"
        );
    }

    /// RFC 8966 [4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update): "If the metric
    /// is infinite and AE is 0, Plen and Omitted MUST both be 0; Update TLVs that do not satisfy
    /// this requirement MUST be ignored."
    ///
    /// A blanket retraction wipes out every route from the neighbour that sent it, so honouring a
    /// malformed one hands anybody on the link a cheap way to blackhole a neighbour's routes.
    #[test]
    fn a_malformed_blanket_retraction_is_ignored() {
        for malformed in [
            UpdateTlv::blanket_retraction().plen(64),
            UpdateTlv::blanket_retraction().omitted(2, &[]),
        ] {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1");
            established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
            );
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[malformed.clone()],
            );

            assert_eq!(
                route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                    .expect("the route should still exist")
                    .computed_metric(),
                &Metric::from_raw(100 + LINK_COST),
                "plen {} / omitted {} does not name a blanket retraction",
                malformed.plen,
                malformed.omitted
            );
        }
    }

    /// An Update the router rejects has to leave the entry it names exactly as it was. Applying the
    /// new metric and then bailing out on the Interval would leave a route advertising a metric
    /// under a hold time that was never agreed to, and skip the deselect that follows.
    #[test]
    fn a_rejected_update_leaves_an_existing_entry_untouched() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(7)],
        );
        let before = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the update should have created a route");

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_2,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 500)
                .seqno(8)
                .interval(0)],
        );
        let after = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still exist");

        assert_eq!(after.seqno, before.seqno);
        assert_eq!(after.advertised_metric(), before.advertised_metric());
        assert_eq!(after.computed_metric(), before.computed_metric());
        assert_eq!(after.source().router_id, before.source().router_id);
        assert_eq!(after.expiry.duration(), before.expiry.duration());
    }

    /// The Interval "MUST NOT be 0" — it is the only thing an Update says about when to stop
    /// believing it, so without one there is no hold time the route could be created with.
    #[test]
    fn an_update_with_a_zero_interval_creates_no_route() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).interval(0)],
        );

        assert_eq!(route_count(&mut r), 0);
    }

    /// Updates in a packet are independent, so one the router cannot handle must not discard the
    /// ones behind it. A /129 IPv6 prefix names bits the address does not have.
    #[test]
    fn a_malformed_update_does_not_discard_the_updates_behind_it() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(129, &[0xfd; 17], 100),
                UpdateTlv::v6(PLEN, &PREFIX_B_WIRE, 100),
            ],
        );

        assert_eq!(route_count(&mut r), 1);
        assert!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_B, PLEN).is_some(),
            "the update behind the malformed one should still have been handled"
        );
    }

    //  __  __ ___ _____ ___ ___ ___   ___ __  __  ___  ___ _____ _  _ ___ _  _  ___
    // |  \/  | __|_   _| _ \_ _/ __| / __|  \/  |/ _ \/ _ \_   _| || |_ _| \| |/ __|
    // | |\/| | _|  | | |   /| | (__  \__ \ |\/| | (_) | (_) || | | __ || || .` | (_ |
    // |_|  |_|___| |_| |_|_\___\___| |___/_|  |_|\___/ \___/ |_| |_||_|___|_|\_|\___|

    /// The smoothing time constant is `max(our mcast hello interval, the neighbour's ucast hello
    /// interval) * DEFAULT_SMOOTHING_MULTIPLE`. Nothing here sends unicast hellos, so a one second
    /// interface hello puts the constant at three seconds — short enough to step a whole time
    /// constant while staying well inside a route's hold time.
    const SMOOTHING_HELLO: Interval = Interval::from_duration(Duration::from_secs(1));
    const SMOOTHING_TAU: Duration = Duration::from_secs(3);

    /// Registers an interface whose hello interval yields [`SMOOTHING_TAU`], and an established
    /// neighbour on it.
    fn smoothing_setup(r: &mut BabelRouter<'static>, now: Instant) -> InterfaceHandle {
        assert_eq!(
            Duration::from(SMOOTHING_HELLO) * DEFAULT_SMOOTHING_MULTIPLE,
            SMOOTHING_TAU,
            "the time constant these tests assume has drifted from the router's"
        );
        let iface = drained_iface_with_hello(r, now, "iface_1", SMOOTHING_HELLO);
        established_neighbour(r, now, iface, NEIGHBOUR_1_ADDR);
        iface
    }

    /// A route has no history to smooth against when it is created, so Appendix A.3's smoothed
    /// metric has to start life equal to the real one. Starting it anywhere else would make a
    /// brand new route look better or worse than it is for the first few updates.
    #[test]
    fn a_new_route_starts_smoothed_at_its_computed_metric() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the update should have created a route");

        assert_eq!(*route.computed_metric(), Metric::from_raw(100 + LINK_COST));
        assert_eq!(
            route.smoothed_metric(),
            route.computed_metric(),
            "a new route is its own history"
        );
        assert_eq!(
            route.smoothed_metric_time, t0,
            "and the clock starts at the update that created it"
        );
    }

    /// The point of the smoothed metric is that it lags the real one. The first sample taken a
    /// whole time constant after the metric moved must close part of the gap, not all of it.
    ///
    /// The degradation is put in the same packet as the advertisement it replaces so that the step
    /// being measured is the one *after* the change. A metric change never moves ms(R) on the step
    /// it arrives on — that step belongs to the metric that preceded it (see
    /// [`Route::update_cost`]) — and the neighbour's IHU hold time is shorter than two time
    /// constants, so there is no room to spend one on the change and another on the sample.
    #[test]
    fn a_later_update_pulls_the_smoothed_metric_towards_the_new_one() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);

        // The route is born at 100 and immediately degrades to 300, so ms(R) starts at the route's
        // own metric of 120 while the real metric is already 320.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300),
            ],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the update should have created a route");
        assert_eq!(
            *route.computed_metric(),
            Metric::from_raw(300 + LINK_COST),
            "the computed metric follows the update immediately"
        );
        assert_eq!(
            *route.smoothed_metric(),
            Metric::from_raw(100 + LINK_COST),
            "but no time has passed, so the smoothed metric is still the one it was born with"
        );

        // One time constant later the neighbour repeats the metric it is already advertising.
        // Nothing about the route has changed, so this exists only to take a sample.
        let t1 = t0 + SMOOTHING_TAU;
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still be there");

        assert_eq!(
            *route.computed_metric(),
            Metric::from_raw(300 + LINK_COST),
            "the computed metric is unchanged by a repeat of the same advertisement"
        );
        // round(120 + (320 - 120) * 0.6321) == 246
        assert_eq!(
            *route.smoothed_metric(),
            Metric::from_raw(246),
            "the smoothed metric closes 1 - 1/e of the gap in one time constant"
        );
        assert_eq!(
            route.smoothed_metric_time, t1,
            "the step is measured from the last sample, so the stamp has to advance"
        );
    }

    /// Two updates for one prefix inside a single packet share an `Instant`. The second one must
    /// not be smoothed as though a step had elapsed, or a neighbour could drag the smoothed metric
    /// wherever it liked by repeating an update.
    #[test]
    fn updates_at_the_same_instant_do_not_advance_the_smoothed_metric() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        for _ in 0..5 {
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
            );
        }

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the route should still be there");

        assert_eq!(
            *route.computed_metric(),
            Metric::from_raw(300 + LINK_COST),
            "the computed metric still tracks the newest update"
        );
        assert_eq!(
            *route.smoothed_metric(),
            Metric::from_raw(100 + LINK_COST),
            "but no time passed, so the smoothed metric is untouched"
        );
    }

    //  ___  ___  _   _ _____ ___   ___ ___ _    ___ ___ _____ ___ ___  _  _
    // | _ \/ _ \| | | |_   _| __| / __| __| |  | __/ __|_   _|_ _/ _ \| \| |
    // |   / (_) | |_| | | | | _|  \__ \ _|| |__| _| (__  | |  | | (_) | .` |
    // |_|_\\___/ \___/  |_| |___| |___/___|____|___\___| |_| |___\___/|_|\_|

    /// Whether a route is selected is read straight off the entry.
    fn is_selected(
        r: &mut BabelRouter<'static>,
        iface: InterfaceHandle,
        neighbour: Ipv6Addr,
        prefix: Ipv6Addr,
        plen: u8,
    ) -> bool {
        route_for(r, iface, neighbour, prefix, plen)
            .expect("route should exist")
            .selected
    }

    /// Runs selection, and reports the destinations it queued triggered updates for.
    ///
    /// Section 3.7.2 wants an update sent when the selected route for a destination changes, and
    /// `select_routes` queues those itself rather than reporting back — so an empty result is a run
    /// that settled on the route it started from. The update table is emptied first so that what an
    /// earlier step left owed cannot be mistaken for what this run decided, and the result is
    /// deduplicated because one changed destination is queued once per neighbour. Which route the
    /// destination moved *to* is not visible here — the update names the destination alone — so the
    /// callers check that with [`is_selected`].
    fn selection_triggers(
        r: &mut BabelRouter<'static>,
        now: Instant,
    ) -> Vec<RouteDestination<NoExtension>> {
        drain_updates(r);
        r.select_routes(now);
        let mut destinations: Vec<RouteDestination<NoExtension>> = pending_updates(r)
            .iter()
            .map(|(_, update)| *update.destination())
            .collect();
        destinations.dedup();
        destinations
    }

    /// Selection runs in the poll that follows the packet that carried the Update, so a lone
    /// feasible route holds its destination as soon as that tick has run.
    #[test]
    fn the_only_route_to_a_destination_is_selected() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );

        assert!(is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN));
    }

    /// Section 3.6: a route with an infinite metric is never selected. With only a retracted route
    /// on offer the destination is left with nothing selected rather than falling back to it.
    #[test]
    fn a_retracted_route_is_never_selected() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "the route has to be selected first for the retraction to have something to undo"
        );

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("a retraction keeps the entry");
        assert_eq!(*route.computed_metric(), Metric::INFINITY);
        assert!(!route.selected, "an infinite metric is never selected");
    }

    /// Section 3.5.1's feasibility condition is what keeps Babel loop-free, and the route this node
    /// forwards over — the selected one — is the route that has to satisfy it. So a packet must
    /// never leave a selected route unfeasible, whatever it carries.
    ///
    /// The unfeasible update is the interesting case because 3.5.3 gives acquisition a choice about
    /// it: "if the entry is currently selected, the update is unfeasible, and the router-id of the
    /// update is equal to the router-id of the entry, then the update MAY be ignored". This crate
    /// takes that option, so the entry keeps the feasible distance it already had rather than being
    /// dragged past the feasibility distance and then rescued by the deselect in `select_routes`.
    ///
    /// The invariant is asserted over every selected route rather than the one route this test
    /// stages, because it is a property of the table and not of this particular entry.
    #[test]
    fn an_unfeasible_update_does_not_leave_a_selected_route_unfeasible() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        // Establish the route and let selection give it the destination.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(5)],
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "the route has to hold the destination for the invariant to have a subject"
        );

        // Advertising the route onwards is what records a feasibility distance for its source —
        // the source table is written by the send path, not by acquisition — so without this the
        // update below would have nothing to be unfeasible against.
        r.poll_output(t0).expect("poll should succeed");
        assert!(
            r.source_table
                .inner
                .get_by_key(&SourceIndex {
                    router_id: RouterId::from(&ORIGIN_1),
                    destination: dest(PREFIX_A, PLEN),
                })
                .is_some(),
            "sending the update should have recorded the feasibility distance"
        );

        // Same seqno, worse metric: (5, 200) is not strictly better than the (5, 120) just
        // recorded, so 3.5.1 calls it unfeasible.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 200).seqno(5)],
        );

        let selected = selected_route_keys(&mut r);
        assert!(
            !selected.is_empty(),
            "the destination should still be held by something"
        );
        for key in &selected {
            assert!(
                is_eligible_in_table(&mut r, key),
                "a selected route must satisfy the feasibility condition, {key:?} does not"
            );
        }

        // And specifically: the entry was left alone rather than updated and then unselected.
        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the entry survives an update it declined");
        assert!(route.selected, "it keeps the destination it was holding");
        assert_eq!(
            *route.advertised_metric(),
            Metric::from_raw(100),
            "the unfeasible metric was never recorded"
        );
    }

    /// The other half of the invariant. When the router-id changes, 3.5.3's escape hatch does not
    /// apply — "the router-id of the update is equal to the router-id of the entry" is one of its
    /// three conditions — so the entry *is* updated, unfeasible and all. What holds the line here
    /// is the other half of the same paragraph, "if the update is unfeasible, then the (now
    /// unfeasible) entry MUST be immediately unselected": acquisition gives the destination up as
    /// it applies the update, rather than leaving it to the eligibility filter in `select_routes`.
    ///
    /// Staging it takes a round trip through both router-ids. A feasibility distance is recorded
    /// per source, and [`SourceIndex`] includes the router-id, so an update carrying a router-id
    /// this node has never advertised has nothing to be unfeasible against and is feasible by
    /// default. `ORIGIN_2` therefore has to be advertised — and sent — before the entry moves to
    /// `ORIGIN_1`, so that coming back to `ORIGIN_2` can be judged against something.
    #[test]
    fn an_unfeasible_router_id_change_gives_up_the_destination() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);

        // Record a feasibility distance for ORIGIN_2 by advertising under it and sending it on.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_2,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(5)],
        );
        r.poll_output(t0).expect("poll should succeed");

        // Hand the prefix to ORIGIN_1. A router-id with no recorded distance is feasible, so this
        // is applied and the route keeps the destination.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).seqno(5)],
        );
        r.poll_output(t0).expect("poll should succeed");
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "the route has to hold the destination for the deselect to be worth anything"
        );

        // Back to ORIGIN_2, at a distance that is not better than the one recorded for it. The
        // router-id differs from the entry's, so acquisition applies this rather than ignoring it.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_2,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 200).seqno(5)],
        );

        let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("the entry is updated, not removed");
        assert_eq!(
            route.source().router_id,
            RouterId::from(&ORIGIN_2),
            "the router-id change is a hard reset, so the update was applied"
        );
        assert_eq!(
            *route.advertised_metric(),
            Metric::from_raw(200),
            "and the unfeasible metric was recorded with it"
        );
        assert!(
            !is_eligible_in_table(&mut r, &route.key()),
            "which leaves the entry unfeasible — the state the deselect below exists for"
        );
        assert!(
            !route.selected,
            "so selection must have taken the destination off it"
        );

        for key in &selected_route_keys(&mut r) {
            assert!(
                is_eligible_in_table(&mut r, key),
                "a selected route must satisfy the feasibility condition, {key:?} does not"
            );
        }
    }

    /// The lower computed metric wins. Asserted from both directions because the routes are walked
    /// in route table order — by neighbour address — and the outcome must not depend on which of
    /// the two the comparison happens to see first.
    #[test]
    fn the_lower_metric_route_wins_whichever_neighbour_offers_it() {
        for (better, worse) in [
            (NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR),
            (NEIGHBOUR_2_ADDR, NEIGHBOUR_1_ADDR),
        ] {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1");
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
                established_neighbour(&mut r, t0, iface, addr);
            }

            send_updates(
                &mut r,
                t0,
                iface,
                worse,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
            );
            send_updates(
                &mut r,
                t0,
                iface,
                better,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
            );

            assert!(
                is_selected(&mut r, iface, better, PREFIX_A, PLEN),
                "the metric 100 route from {better} should be selected"
            );
            assert!(
                !is_selected(&mut r, iface, worse, PREFIX_A, PLEN),
                "the metric 300 route from {worse} should not be"
            );
        }
    }

    /// Retracting the selected route has to hand the destination to the surviving alternative
    /// rather than leaving it unreachable. This is the case the route table keeps per-neighbour
    /// entries for.
    #[test]
    fn retracting_the_selected_route_hands_over_to_the_alternative() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
        }

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
        );
        assert!(is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN));

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        assert!(
            !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "the retracted route is dropped"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "and the worse but still usable route takes over"
        );
    }

    /// Selection is per destination: the groups the route table hands out must not let the winner
    /// for one prefix suppress the winner for another.
    #[test]
    fn each_destination_selects_its_own_route() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
        }

        // Neighbour 1 is the better way to PREFIX_A, neighbour 2 the better way to PREFIX_B.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
                UpdateTlv::v6(PLEN, &PREFIX_B_WIRE, 300),
            ],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300),
                UpdateTlv::v6(PLEN, &PREFIX_B_WIRE, 100),
            ],
        );

        assert!(is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN));
        assert!(!is_selected(
            &mut r,
            iface,
            NEIGHBOUR_2_ADDR,
            PREFIX_A,
            PLEN
        ));
        assert!(!is_selected(
            &mut r,
            iface,
            NEIGHBOUR_1_ADDR,
            PREFIX_B,
            PLEN
        ));
        assert!(is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_B, PLEN));
    }

    /// Section 3.7.2 wants an update sent when the selected route *changes*, so selection has to
    /// distinguish a change from a re-run that settled on the same route. Re-running selection over
    /// an unchanged table must not keep queueing updates.
    #[test]
    fn selection_queues_an_update_only_when_the_selected_route_moves() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");
        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            established_neighbour(&mut r, t0, iface, addr);
        }

        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
        );

        assert!(
            selection_triggers(&mut r, t0).is_empty(),
            "handle_input already ran selection, so a re-run settles on the same route"
        );

        // Drive the selected route to infinity behind selection's back, the way an expiry sweep
        // would, so the next run has a real change to report.
        for route in r
            .route_table
            .inner
            .iter_mut()
            .filter(|route| route.selected)
        {
            route.retract();
        }

        assert_eq!(
            selection_triggers(&mut r, t0),
            alloc::vec![dest(PREFIX_A, PLEN)],
            "the destination moved to a different route, which is what triggers an update"
        );
        assert!(
            selection_triggers(&mut r, t0).is_empty(),
            "and once queued the state is stable again"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "the alternative is what it moved to"
        );
    }

    /// Puts the two neighbours' routes towards PREFIX_A into the one state where the real metric
    /// and the smoothed metric disagree about which is better:
    ///
    /// * neighbour 1 at computed 320, smoothed 246 — it used to be the good route and the smoothing
    ///   has not caught up with how far it has fallen;
    /// * neighbour 2 at computed 270, smoothed 270 — brand new, so it has no history to lag.
    ///
    /// Neighbour 1 has the *worse* real metric and the *better* smoothed one, and it also sorts
    /// first in the route table, so it is the entry a scan over the group reaches first.
    ///
    /// Neighbour 1's fall is put in the same packet as the advertisement it replaces, and the
    /// update at `t1` only repeats it. A metric change never moves ms(R) on the step it arrives on
    /// — that step belongs to the metric that preceded it (see [`Route::update_cost`]) — so the
    /// fall needs a later sample to reach the smoothed metric, and the neighbours' IHU hold time
    /// leaves no room to spend a whole time constant on each. Neighbour 2 needs no such sample: its
    /// metric has never moved, so no amount of smoothing shifts it off 270.
    fn diverged_metrics(r: &mut BabelRouter<'static>, iface: InterfaceHandle, t0: Instant) {
        send_updates(
            r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100),
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300),
            ],
        );
        let t1 = t0 + SMOOTHING_TAU;
        send_updates(
            r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300)],
        );
        send_updates(
            r,
            t1,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 250)],
        );

        // Guard the premise. If the smoothing arithmetic moves, the tests below should fail here
        // rather than quietly turn into a test of something else.
        let n1 = route_for(r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN).expect("neighbour 1 route");
        let n2 = route_for(r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN).expect("neighbour 2 route");
        assert_eq!(
            (*n1.computed_metric(), *n1.smoothed_metric()),
            (Metric::from_raw(320), Metric::from_raw(246)),
            "neighbour 1 should be the worse route with the better history"
        );
        assert_eq!(
            (*n2.computed_metric(), *n2.smoothed_metric()),
            (Metric::from_raw(270), Metric::from_raw(270)),
            "neighbour 2 should be the better route with no history"
        );
    }

    /// Selects exactly the routes advertised by `neighbour`, bypassing selection itself, so a test
    /// can hand `select_routes` a starting point instead of having to manoeuvre the router into
    /// one. Every test using this has a single destination in the table.
    fn force_selected(r: &mut BabelRouter<'static>, iface: InterfaceHandle, neighbour: Ipv6Addr) {
        let idx = NeighbourIndex {
            iface,
            addr: neighbour.into(),
        };
        for route in r.route_table.inner.iter_mut() {
            route.selected = *route.neighbour() == idx;
        }
    }

    /// With nothing selected there is no incumbent to defend the destination, so the lowest metric
    /// takes it outright and the smoothed metric has no say.
    ///
    /// This is the case that went the other way while hysteresis was measured against the first
    /// entry the scan reached rather than against the selected route: neighbour 1 seeded the
    /// comparison, its lagging smoothed metric then vetoed the only challenger, and the route with
    /// the worse metric won a destination it had no claim on — purely because it sorted first.
    #[test]
    fn the_best_metric_wins_when_no_route_is_selected_yet() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        diverged_metrics(&mut r, iface, t0);

        // Clear the selection the updates left behind. This is the state a destination is in when
        // every route towards it has just come back from having been retracted.
        for route in r.route_table.inner.iter_mut() {
            route.selected = false;
        }

        assert_eq!(
            selection_triggers(&mut r, t0),
            alloc::vec![dest(PREFIX_A, PLEN)],
            "a destination going from nothing to a route is a change worth an update"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "metric 270 beats metric 320"
        );
        assert!(
            !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "a better smoothed metric does not entitle a worse route to an unheld destination"
        );
    }

    /// Hysteresis exists to keep the selected route where it is, so it must never be the reason
    /// the selection *moves*, least of all to a worse route. Neighbour 2 holds the destination
    /// with the better metric while neighbour 1 sorts first and has the better smoothed metric.
    #[test]
    fn hysteresis_never_moves_the_selection_to_a_worse_route() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        diverged_metrics(&mut r, iface, t0);
        force_selected(&mut r, iface, NEIGHBOUR_2_ADDR);

        assert!(
            selection_triggers(&mut r, t0).is_empty(),
            "the selected route is already the best on offer, so nothing changed"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "the selected route keeps the destination"
        );
        assert!(
            !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "a route that sorts first must not be able to take a destination off a better one"
        );
    }

    /// The other half of the rule. A challenger with the better real metric does not get the
    /// destination while the incumbent's smoothed metric says the incumbent has been the better
    /// route over time. Without this the rule would collapse into "always take the lowest metric",
    /// which is the oscillation Appendix A.3's hysteresis exists to damp.
    #[test]
    fn hysteresis_keeps_the_selected_route_against_a_challenger_with_no_history() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        diverged_metrics(&mut r, iface, t0);
        force_selected(&mut r, iface, NEIGHBOUR_1_ADDR);

        assert!(
            selection_triggers(&mut r, t0).is_empty(),
            "the selection did not move"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "metric 270 beats 320, but not by enough smoothed metric to be worth moving for"
        );
        assert!(!is_selected(
            &mut r,
            iface,
            NEIGHBOUR_2_ADDR,
            PREFIX_A,
            PLEN
        ));
    }

    /// A retracted incumbent has no claim to defend, so hysteresis must not keep it.
    ///
    /// [`Route::retract`] drives the smoothed metric to infinity alongside the computed one rather
    /// than letting it decay there: a smoothed average of an infinite metric is infinite, and
    /// leaving it at its old value would let a route that is gone keep looking like the better
    /// history for a whole time constant afterwards. That is what this pins — both measures go at
    /// once, so the destination moves whether selection is reading the real metric or the smoothed
    /// one.
    #[test]
    fn a_retracted_incumbent_does_not_hold_the_destination_through_hysteresis() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        diverged_metrics(&mut r, iface, t0);
        force_selected(&mut r, iface, NEIGHBOUR_1_ADDR);

        // Neighbour 1 retracts the prefix it was holding the destination with. Going in, its
        // smoothed metric (246) is the better of the two, so a retraction that left it alone would
        // still look like the better history.
        send_updates(
            &mut r,
            t0 + SMOOTHING_TAU,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
        );

        let n1 = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
            .expect("a retraction keeps the entry");
        assert_eq!(*n1.computed_metric(), Metric::INFINITY);
        assert_eq!(
            *n1.smoothed_metric(),
            Metric::INFINITY,
            "the retraction takes the smoothed metric with it rather than letting it decay, so \
             the better history neighbour 1 had does not outlive the route"
        );
        assert!(!n1.selected, "a retracted route is never selected");
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "the destination moves to the only route still eligible for it"
        );
    }

    /// Appendix A.3's `m(R') < m(R) && ms(R') < ms(R)` is a condition every candidate answers for
    /// itself, not a description of which single candidate to ask. Testing only the lowest-metric
    /// route lets a route that fails the smoothed half stand in front of one that passes both, and
    /// holds the destination on a route worse than either.
    ///
    /// It takes three routes to show this. With two, the lowest-metric route is the only one that
    /// could pass at all: passing requires beating the incumbent's metric, and if some route does
    /// that then either it is the minimum or the minimum is the incumbent itself.
    ///
    /// * neighbour 1 (incumbent) — 120, smoothed 120: steady, and the route to beat;
    /// * neighbour 2 — 90, smoothed 175: the lowest metric on offer, but it only just fell there
    ///   from 320, so the smoothed metric has not accepted it yet;
    /// * neighbour 3 — 115, smoothed 115: worse than neighbour 2 but better than the incumbent on
    ///   both measures, which is exactly what A.3 asks to be switched to.
    #[test]
    fn a_challenger_failing_on_the_smoothed_metric_does_not_shadow_one_that_passes() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_3_ADDR);

        // Neighbour 1 holds steady at 100. Neighbour 2 is born at 300 and falls to 70 in the same
        // packet, so its smoothed metric starts a long way above where its real metric ends up.
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t0,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 300),
                UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 70),
            ],
        );

        // One time constant on, both repeat what they are already advertising so that the fall
        // reaches neighbour 2's smoothed metric, and neighbour 3 turns up with no history at all.
        let t1 = t0 + SMOOTHING_TAU;
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
        );
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_2_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 70)],
        );
        send_updates(
            &mut r,
            t1,
            iface,
            NEIGHBOUR_3_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 95)],
        );

        // Guard the premise. If the smoothing arithmetic moves, this should fail here rather than
        // quietly turn into a test of something else.
        let n1 = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN).expect("n1 route");
        let n2 = route_for(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN).expect("n2 route");
        let n3 = route_for(&mut r, iface, NEIGHBOUR_3_ADDR, PREFIX_A, PLEN).expect("n3 route");
        assert_eq!(
            (*n1.computed_metric(), *n1.smoothed_metric()),
            (Metric::from_raw(120), Metric::from_raw(120)),
            "the incumbent is steady"
        );
        // round(320 + (90 - 320) * 0.6321) == 175
        assert_eq!(
            (*n2.computed_metric(), *n2.smoothed_metric()),
            (Metric::from_raw(90), Metric::from_raw(175)),
            "the lowest metric on offer, with a smoothed metric that has not caught up"
        );
        assert_eq!(
            (*n3.computed_metric(), *n3.smoothed_metric()),
            (Metric::from_raw(115), Metric::from_raw(115)),
            "a brand new route is its own history"
        );

        force_selected(&mut r, iface, NEIGHBOUR_1_ADDR);

        assert_eq!(
            selection_triggers(&mut r, t1),
            alloc::vec![dest(PREFIX_A, PLEN)],
            "the destination moves off the incumbent, which is what triggers an update"
        );
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_3_ADDR, PREFIX_A, PLEN),
            "neighbour 3 beats the incumbent on both measures, so it takes the destination"
        );
        assert!(
            !is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "the lowest metric still loses on the smoothed one, so it is refused as before"
        );
        assert!(
            !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
            "and the incumbent does not keep a destination two routes are better for"
        );

        assert!(
            selection_triggers(&mut r, t1).is_empty(),
            "and once queued the state is stable again"
        );
    }

    //  _____ ___ ___ ___  ___ ___ ___ ___ ___    _   _ ___ ___  _ _____ ___ ___
    // |_   _| _ \_ _/ __|/ __| __| _ \ __|   \  | | | | _ \   \/_\_   _| __/ __|
    //   | | |   /| | (_ | (_ | _||   / _|| |) | | |_| |  _/ |) / _ \| | | _|\__ \
    //   |_| |_|_\___\___|\___|___|_|_\___|___/   \___/|_| |___/_/ \_\_| |___|___/

    /// RFC 8966 [3.7.2](https://datatracker.ietf.org/doc/html/rfc8966#name-triggered-updates): some
    /// changes to the route table must not wait for the next periodic update, and are instead
    /// queued for sending "in a timely manner".
    ///
    /// Five things can ask for one, spread over three places:
    ///
    /// * `handle_update`, for a retraction, which is always relayed, because a route going away is
    ///   the change the rest of the network most needs to hear about promptly;
    /// * `handle_update`, for a blanket retraction, which is every route from that neighbour
    ///   retracted at once;
    /// * [`BabelRouter::select_routes`], when a destination changes which route it points at —
    ///   including a destination that had none until now;
    /// * the expiry sweep, when a selected route's hold time runs out, which is the only one of the
    ///   five that no neighbour announces.
    ///
    /// All five queue the update to every neighbour on the link, the one that advertised the route
    /// included. Babel does not use split horizon to stay loop-free — the feasibility condition of
    /// 3.5.1 is what rules out the loops — so there is nothing to be gained by keeping the news
    /// from the neighbour that happened to be the source of it, and one fewer special case for
    /// [`UpdateTable::broadcast_route_update`] to get wrong.
    mod triggered_updates {
        use super::*;
        use crate::data_structures::interface::config::DEFAULT_WIRED_UPDATE_RETRY_LIMIT;
        use crate::data_structures::route::route_table::METRIC_DIFFERENCE_THRESHOLD;

        /// The metric the routes below settle at before anything is asked to move them, chosen so
        /// that a move of the threshold in either direction stays finite and positive.
        const SETTLED_METRIC: u16 = 500;

        /// The smallest move of the advertised metric that route acquisition calls significant. The
        /// link cost is added to both the old and the new metric, so it cancels out of the
        /// difference and an advertised move of this size is a computed move of this size.
        const SIGNIFICANT_MOVE: u16 = METRIC_DIFFERENCE_THRESHOLD.raw() + 1;

        /// The (destination, destination neighbour) keys the router is holding updates for.
        ///
        /// In poll order, which is the queue's own: sorted by (prefix, plen) and then by the
        /// neighbour the update is owed to. The key is what collapses two routes towards one
        /// prefix into a single update per neighbour — only the selected one is ever advertised.
        fn pending(
            r: &mut BabelRouter<'static>,
        ) -> Vec<(Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>)> {
            pending_updates(r)
                .iter()
                .map(|(source, update)| (*source, update.key()))
                .collect()
        }

        /// An interface with [`NEIGHBOUR_1_ADDR`], [`NEIGHBOUR_2_ADDR`] and [`NEIGHBOUR_3_ADDR`]
        /// established on it.
        ///
        /// Three is the smallest number that separates "every other neighbour" from "the other
        /// neighbour": with two, a relay that went to the wrong one and a relay that went to the
        /// right one both produce a single update.
        fn three_neighbours(r: &mut BabelRouter<'static>, now: Instant) -> InterfaceHandle {
            let iface = drained_iface(r, now, "iface_1");
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR, NEIGHBOUR_3_ADDR] {
                established_neighbour(r, now, iface, addr);
            }
            iface
        }

        /// Sends one Update for `prefix` from [`NEIGHBOUR_1_ADDR`], under [`ORIGIN_1`] unless the
        /// caller wants the prefix to change hands.
        fn advertise(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            origin: [u8; 8],
            prefix: &[u8; 8],
            metric: u16,
        ) {
            send_updates(
                r,
                now,
                iface,
                NEIGHBOUR_1_ADDR,
                origin,
                &[UpdateTlv::v6(PLEN, prefix, metric)],
            );
        }

        /// A router whose only route is `(PREFIX_A, NEIGHBOUR_1)`, settled at [`SETTLED_METRIC`]
        /// and selected, with nothing owed to anybody.
        ///
        /// Taking the destination queued that route's first advertisement, which is selection's
        /// trigger rather than any of the ones the tests below are about — see
        /// [`a_brand_new_route_is_queued_by_selection_rather_than_acquisition`] for that one. It is
        /// drained here so what a test measures afterwards is only what its own step queued.
        fn settled(r: &mut BabelRouter<'static>, now: Instant) -> InterfaceHandle {
            let iface = three_neighbours(r, now);
            advertise(r, now, iface, ORIGIN_1, &PREFIX_A_WIRE, SETTLED_METRIC);
            assert!(
                is_selected(r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the only route to the destination should hold it"
            );
            drain_updates(r);
            iface
        }

        /// A prefix nobody has spoken about before is not a metric that changed significantly, and
        /// it is not selected at the point acquisition sees it, so neither of the triggers
        /// acquisition can see fires — it returns `false`. The update the route does deserve comes
        /// from the other trigger in 3.7.2, selection handing it the destination, one step later.
        ///
        /// So an empty update table here would not mean "correctly kept quiet"; it would mean the
        /// route was never advertised at all.
        ///
        /// The two stages are driven by hand rather than through [`advertise`], because which of
        /// them queues the update is the whole claim — a helper that runs both would only show the
        /// state they arrive at together.
        #[test]
        fn a_brand_new_route_is_queued_by_selection_rather_than_acquisition() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            let pkt = PacketBuilder::new()
                .router_id(ORIGIN_1)
                .update(&UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, SETTLED_METRIC))
                .build();
            r.handle_input(
                t0,
                receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
            )
            .expect("handle_input should succeed");

            assert_eq!(route_count(&mut r), 1, "the route itself was still created");
            assert_eq!(
                pending(&mut r),
                alloc::vec![],
                "acquisition sees neither of its triggers, so it queues nothing"
            );

            tick(&mut r, t0);

            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "the newly selected route, owed to every neighbour on the link"
            );
        }

        /// A metric that moves further than the threshold is relayed onwards, to the whole link.
        #[test]
        fn a_significant_metric_move_is_relayed_to_every_neighbour() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            advertise(
                &mut r,
                t0,
                iface,
                ORIGIN_1,
                &PREFIX_A_WIRE,
                SETTLED_METRIC + SIGNIFICANT_MOVE,
            );

            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "the route neighbour 1 advertised, owed to the whole link including neighbour 1"
            );
        }

        /// The comparison is on the absolute difference, so a route that gets *better* by more than
        /// the threshold is just as significant as one that gets worse. A node that only relayed
        /// degradations would leave the network on stale, worse routes.
        #[test]
        fn a_metric_improving_past_the_threshold_is_relayed() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            advertise(
                &mut r,
                t0,
                iface,
                ORIGIN_1,
                &PREFIX_A_WIRE,
                SETTLED_METRIC - SIGNIFICANT_MOVE,
            );

            assert_eq!(
                pending(&mut r).len(),
                3,
                "an improvement past the threshold is relayed to the whole link"
            );
            assert!(
                *route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                    .expect("the route should still exist")
                    .computed_metric()
                    < Metric::from_raw(SETTLED_METRIC),
                "the entry really did improve"
            );
        }

        /// The metric trigger is scoped to the selected route, the same way the router-id one is.
        /// An unselected route was never advertised onwards, so no neighbour is holding a stale
        /// belief that relaying its metric move would correct.
        #[test]
        fn a_metric_move_on_an_unselected_route_queues_nothing() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            // Neighbour 1 takes the destination on the lower metric, leaving neighbour 2's route
            // tracked but unselected.
            advertise(&mut r, t0, iface, ORIGIN_1, &PREFIX_A_WIRE, SETTLED_METRIC);
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, SETTLED_METRIC + 1)],
            );
            assert!(
                !is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
                "neighbour 2's route is the one that lost"
            );
            drain_updates(&mut r);

            // Move the loser's metric well past the threshold, but not far enough to win.
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(
                    PLEN,
                    &PREFIX_A_WIRE,
                    SETTLED_METRIC + SIGNIFICANT_MOVE,
                )],
            );

            assert!(
                !is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
                "it still holds nothing, so the move is nobody's business"
            );
            assert!(pending(&mut r).is_empty());
        }

        /// The other side of the threshold. Metrics drift constantly, and relaying every wobble
        /// would put the link back under the load periodic updates are batched to avoid.
        ///
        /// The comparison is strict, so a move of exactly the threshold is not past it — this pins
        /// the boundary from below, and [`a_significant_metric_move_is_relayed_to_every_neighbour`]
        /// pins it from above one raw unit away.
        #[test]
        fn a_metric_move_within_the_threshold_queues_nothing() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            advertise(
                &mut r,
                t0,
                iface,
                ORIGIN_1,
                &PREFIX_A_WIRE,
                SETTLED_METRIC + METRIC_DIFFERENCE_THRESHOLD.raw(),
            );

            assert!(pending(&mut r).is_empty());
        }

        /// 3.7.2's one MUST: "if the router-id of the selected route for a given prefix changes, a
        /// node MUST send an update". The metric is left alone here so the router-id is the only
        /// thing that moved.
        #[test]
        fn a_router_id_change_on_the_selected_route_is_relayed() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            advertise(&mut r, t0, iface, ORIGIN_2, &PREFIX_A_WIRE, SETTLED_METRIC);

            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    // The update names the *new* router-id: the entry's source moved with it.
                    update_key(ORIGIN_2, PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    update_key(ORIGIN_2, PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_key(ORIGIN_2, PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
            );
        }

        /// A destination that changes hands must not be owed twice — once by the route that was
        /// holding it and once by the route that just took it. Nothing has to sweep the loser for
        /// that: an update is keyed by (destination, neighbour owed), and the winner queues to
        /// every neighbour, so what the loser was still holding sits under those very keys and is
        /// superseded in place.
        ///
        /// The move is driven by retracting the incumbent, which queues a relay on it first — so at
        /// the moment selection runs, the loser really is holding something. A worsened metric
        /// would not do: hysteresis holds the destination against a challenger that has not also
        /// won on the smoothed metric, and at a single instant no smoothing has happened.
        #[test]
        fn a_destination_changing_hands_drops_what_the_loser_owed() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            // Neighbour 1 takes the destination on the lower metric, leaving neighbour 2's route
            // tracked and ready to take over.
            advertise(&mut r, t0, iface, ORIGIN_1, &PREFIX_A_WIRE, SETTLED_METRIC);
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, SETTLED_METRIC + 1)],
            );
            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the lower metric holds the destination to begin with"
            );
            drain_updates(&mut r);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
            );

            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
                "which hands the destination to neighbour 2's route"
            );
            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "one update per neighbour, from the winner — the relay the loser queued for its \
                 own retraction went with the destination"
            );
            let loser = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the loser is still in the table")
                .key();
            assert!(
                owes_nothing(&mut r, &loser),
                "and nothing owed still advertises the loser, so no second, infinite copy goes out"
            );
        }

        /// The other side of that supersede: it only happens where there is a winner to do it. A
        /// destination that has just lost its *last* eligible route has none, so the retraction its
        /// previous holder queued stays in the queue untouched — that retraction is the only thing
        /// telling the neighbours the destination is gone.
        #[test]
        fn a_destination_with_nothing_to_fail_over_to_keeps_its_retraction() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
            );

            assert!(
                !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the only route to the destination was retracted, so nothing holds it"
            );
            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "the retraction is still owed to the whole link"
            );
        }

        /// A retraction is relayed unconditionally — there is no threshold to clear, because a
        /// route going away is the change the rest of the network most needs to hear promptly.
        ///
        /// What goes out is itself a retraction, and the queue does not have to say so: the update
        /// names the destination, the write pass looks for the route holding it, and the retraction
        /// left it holding none — so the pass has no metric to advertise but infinity.
        #[test]
        fn a_retraction_is_relayed_to_every_neighbour() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
            );

            assert_eq!(
                route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                    .expect("the entry survives its retraction")
                    .computed_metric(),
                &Metric::INFINITY,
            );
            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
            );
        }

        /// A blanket retraction is every route from the sending neighbour retracted at once, so it
        /// queues a relay per (destination it held, other neighbour) — and only for destinations
        /// that neighbour was holding.
        ///
        /// This is also where both triggers land in one packet, because retracting a route the
        /// destination was pointing at is exactly what makes selection move it:
        ///
        /// * neighbour 1 held both destinations, so both are relayed to every neighbour on the
        ///   link;
        /// * `PREFIX_A` fails over to neighbour 2's route, and selection advertises that to the
        ///   whole link — dropping the retraction neighbour 1's route had queued as it goes, since
        ///   the winner's update supersedes it. That is what stops a retraction and its own
        ///   failover from both reaching the wire;
        /// * `PREFIX_B` has nothing to fail over to, so its retraction stays queued and selection
        ///   adds nothing.
        #[test]
        fn a_blanket_retraction_relays_every_route_that_neighbour_advertised() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            advertise(&mut r, t0, iface, ORIGIN_1, &PREFIX_A_WIRE, SETTLED_METRIC);
            advertise(&mut r, t0, iface, ORIGIN_1, &PREFIX_B_WIRE, SETTLED_METRIC);
            // The decoy: the same prefix, from a neighbour that is not going away.
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, SETTLED_METRIC)],
            );
            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the two routes to PREFIX_A tie on metric, so the lower route key holds it"
            );
            // Everything the setup queued is selection advertising the three new routes, which is
            // not what this test is measuring.
            drain_updates(&mut r);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::blanket_retraction()],
            );

            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    // PREFIX_A failed over, so its updates resolve to the winner and carry a
                    // finite metric; PREFIX_B has no holder left, so its are retractions.
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_key(ORIGIN_1, PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                    retraction_key(PREFIX_B, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    retraction_key(PREFIX_B, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    retraction_key(PREFIX_B, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "both destinations owed to the whole link, once each — the failover selection \
                 queued for PREFIX_A lands on the same key the relay already made"
            );
            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
                "neighbour 2's route was not retracted, and takes the destination"
            );
        }

        /// A malformed blanket retraction is ignored, and ignoring it has to include the relay:
        /// otherwise anybody on the link could have a neighbour's routes retracted across the
        /// network with a TLV this node itself refused to act on.
        #[test]
        fn a_malformed_blanket_retraction_queues_nothing() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            // Plen and Omitted MUST both be 0 in a blanket retraction.
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::blanket_retraction().plen(64)],
            );

            assert!(pending(&mut r).is_empty());
        }

        /// The fourth way a route can go away, and the only one no neighbour announces: its hold
        /// time runs out. Nothing arrives to relay, so the tick has to notice on its own —
        /// otherwise the rest of the network keeps believing a route this node has already stopped
        /// believing, until its own copy expires.
        ///
        /// [`tick`] is used rather than `poll_output`, which would send the queued updates and
        /// clear them back out before they could be looked at.
        #[test]
        fn an_expiring_route_is_retracted_to_every_neighbour() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            // One second past the hold time the route's Interval bought it.
            let expired = t0 + expected_expiry(UPDATE_INTERVAL_CENTIS) + Duration::from_secs(1);
            tick(&mut r, expired);

            let route = route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("an expired route is retracted before it is dropped");
            assert_eq!(*route.computed_metric(), Metric::INFINITY);
            assert!(!route.selected, "and it gives up the destination");
            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
            );
        }

        /// Only the selected route is worth a retraction. An unselected one was never advertised
        /// onwards in the first place, so retracting it would tell the link about a route it has
        /// never been offered.
        ///
        /// Both routes below expire on the same tick, so what separates them is which one held the
        /// destination — neighbour 1's, because the two tie on metric and its route key sorts
        /// first.
        #[test]
        fn an_expiring_route_that_held_nothing_is_not_retracted_onwards() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            advertise(&mut r, t0, iface, ORIGIN_1, &PREFIX_A_WIRE, SETTLED_METRIC);
            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                ORIGIN_1,
                &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, SETTLED_METRIC)],
            );
            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the lower route key holds the destination"
            );
            drain_updates(&mut r);

            let expired = t0 + expected_expiry(UPDATE_INTERVAL_CENTIS) + Duration::from_secs(1);
            tick(&mut r, expired);

            assert_eq!(
                pending(&mut r),
                alloc::vec![
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_1_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    retraction_key(PREFIX_A, nbr_idx(iface, NEIGHBOUR_3_ADDR)),
                ],
                "only the route that held the destination is retracted onwards"
            );
        }

        /// A triggered update is queued with the sending interface's retransmission policy, which
        /// is what gets it onto the wire more than once against a lossy link. Multicast is allowed
        /// because the interface does not prefer unicast, so one packet can serve every neighbour
        /// the update is owed to.
        #[test]
        fn a_queued_relay_carries_the_interfaces_retransmission_policy() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = settled(&mut r, t0);

            advertise(
                &mut r,
                t0,
                iface,
                ORIGIN_1,
                &PREFIX_A_WIRE,
                SETTLED_METRIC + SIGNIFICANT_MOVE,
            );

            let policy: Vec<(u8, bool)> = pending_updates(&mut r)
                .iter()
                .map(|(_, update)| (update.send_count, update.mcast_allowed))
                .collect();
            assert_eq!(
                policy,
                alloc::vec![
                    (DEFAULT_WIRED_UPDATE_RETRY_LIMIT, true),
                    (DEFAULT_WIRED_UPDATE_RETRY_LIMIT, true),
                    (DEFAULT_WIRED_UPDATE_RETRY_LIMIT, true)
                ],
            );
        }
    }

    //  ___  ___  _   _ _____ ___   ___ ___ ___  _   _ ___ ___ _____ ___
    // | _ \/ _ \| | | |_   _| __| | _ \ __/ _ \| | | | __/ __|_   _/ __|
    // |   / (_) | |_| | | | | _|  |   / _| (_) | |_| | _|\__ \ | | \__ \
    // |_|_\\___/ \___/  |_| |___| |_|_\___\__\_\\___/|___|___/ |_| |___/

    /// RFC 8966 [3.8.1.1](https://datatracker.ietf.org/doc/html/rfc8966#name-route-requests):
    ///
    /// > When a node receives a route request for a given prefix, it checks its route table for a
    /// > selected route to this exact prefix. If such a route exists, it MUST send an update (over
    /// > unicast or over multicast); if such a route does not exist, it MUST send a retraction for
    /// > that prefix.
    /// >
    /// > When a node receives a wildcard route request, it SHOULD send a full route table dump.
    /// > Full route dumps SHOULD be rate-limited, especially if they are sent over multicast.
    ///
    /// Three things separate an answer from the triggered updates of 3.7.2, and most of the tests
    /// below are about one of them:
    ///
    /// * it goes to the neighbour that asked, and to nobody else — a triggered update goes to the
    ///   whole link;
    /// * it is owed whether or not this node has anything to say, because "no route" is itself an
    ///   answer and has to be spelled out as a retraction;
    /// * it is owed for the *exact* prefix asked about. A supernet or a subnet of a prefix this
    ///   node holds is a prefix it does not hold.
    ///
    /// The queue does not record any of that. An answer is an ordinary entry keyed by (destination,
    /// neighbour owed), and what reaches the wire is read off the selected route for the
    /// destination at write time — which is what makes "no route" come out as an infinite metric
    /// without the queue having to say so. So the assertions here are split: the queue is checked
    /// for who is owed what, and the wire is checked for whether an answer is an update or a
    /// retraction.
    mod route_requests {
        use super::*;
        use crate::output::{Output, TransmitDestination};

        /// A wildcard request: "dump your route table". Plen must be 0 alongside it.
        const AE_WILDCARD: u8 = 0;
        /// A request naming an IPv6 prefix.
        const AE_IPV6: u8 = 2;

        /// The metric the route below is advertised at, and the metric it computes to once the
        /// link cost of an established neighbour is added.
        const ADVERTISED: u16 = 100;
        const COMPUTED: u16 = ADVERTISED + LINK_COST;

        /// [`PREFIX_A`] at prefix lengths either side of the /64 the route table holds it at, with
        /// the wire forms a Route Request carries for them: Plen/8 rounded upwards, uncompressed.
        const SUPERNET_PLEN: u8 = 48;
        const PREFIX_A_SUPERNET_WIRE: [u8; 6] = [0xfd, 0x0a, 0, 0, 0, 0];
        const HOST_PLEN: u8 = 128;
        const PREFIX_A_HOST_WIRE: [u8; 16] = [0xfd, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        /// An interface with [`NEIGHBOUR_1_ADDR`], [`NEIGHBOUR_2_ADDR`] and [`NEIGHBOUR_3_ADDR`]
        /// established on it.
        ///
        /// Three neighbours is what makes "answered the one that asked" different from "answered
        /// somebody": the requester below is always neighbour 2, so an answer that went to the
        /// whole link, or to the neighbour the route was learned from, is a different vector.
        fn three_neighbours(r: &mut BabelRouter<'static>, now: Instant) -> InterfaceHandle {
            let iface = drained_iface(r, now, "iface_1");
            for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR, NEIGHBOUR_3_ADDR] {
                established_neighbour(r, now, iface, addr);
            }
            iface
        }

        /// Advertises `prefix` at `plen` from `from`, under `origin`.
        fn advertise(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            from: Ipv6Addr,
            origin: [u8; 8],
            plen: u8,
            prefix: &[u8],
            metric: u16,
        ) {
            send_updates(
                r,
                now,
                iface,
                from,
                origin,
                &[UpdateTlv::v6(plen, prefix, metric)],
            );
        }

        /// A router holding one selected route, `PREFIX_A/64` learned from [`NEIGHBOUR_1_ADDR`],
        /// with nothing owed to anybody.
        ///
        /// Selection queued that route's first advertisement to the whole link, which is 3.7.2's
        /// business rather than a request's. It is drained here so that what a test measures
        /// afterwards is only what the request it sends asked for.
        fn one_route(r: &mut BabelRouter<'static>, now: Instant) -> InterfaceHandle {
            let iface = three_neighbours(r, now);
            advertise(
                r,
                now,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                PLEN,
                &PREFIX_A_WIRE,
                ADVERTISED,
            );
            assert!(
                is_selected(r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the only route to the destination should hold it"
            );
            drain_updates(r);
            iface
        }

        /// Sends a Route Request from `from` and runs the tick `handle_input` requires of its
        /// caller.
        ///
        /// Over unicast, which is how a node that wants one prefix asks for it — nothing in the
        /// handler reads the transport destination, but a request is not a thing a node broadcasts
        /// without meaning to.
        ///
        /// A TLV the router cannot handle is skipped rather than failing the packet, so this
        /// expects `Ok` even of the requests that are meant to be ignored; what became of one is
        /// read off the queue.
        fn request(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
            from: Ipv6Addr,
            ae: u8,
            plen: u8,
            prefix: &[u8],
        ) {
            let pkt = PacketBuilder::new().route_request(ae, plen, prefix).build();
            r.handle_input(now, receive(iface, from, ReceiveDestination::Unicast, &pkt))
                .expect("a route request must never fail the packet it arrived in");
            tick(r, now);
        }

        /// Every answer the router is holding, in the order a poll would walk them.
        fn answers(
            r: &mut BabelRouter<'static>,
        ) -> Vec<(Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>)> {
            pending_updates(r)
                .iter()
                .map(|(source, update)| (*source, update.key()))
                .collect()
        }

        /// The answer to a request for `prefix/plen`, owed to `send_to` and advertised under
        /// `origin`.
        ///
        /// [`update_key`] says the same thing, but only ever at [`PLEN`] — and the prefix length a
        /// request names is the whole point of half the tests here.
        fn update_answer(
            origin: [u8; 8],
            prefix: Ipv6Addr,
            plen: u8,
            send_to: NeighbourIndex<NoExtension>,
        ) -> (Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>) {
            (
                Some(SourceIndex {
                    router_id: RouterId::from(&origin),
                    destination: dest(prefix, plen),
                }),
                UpdateIndex {
                    destination: dest(prefix, plen),
                    neighbour: send_to,
                },
            )
        }

        /// [`update_answer`] for a prefix no route holds, which is what a retraction is: there is
        /// no selected route to read a router-id or a metric off, so the write pass has nothing to
        /// advertise but infinity.
        fn retraction_answer(
            prefix: Ipv6Addr,
            plen: u8,
            send_to: NeighbourIndex<NoExtension>,
        ) -> (Option<SourceIndex<NoExtension>>, UpdateIndex<NoExtension>) {
            (
                None,
                UpdateIndex {
                    destination: dest(prefix, plen),
                    neighbour: send_to,
                },
            )
        }

        /// An Update TLV the router put on the wire, reduced to what an answer is judged on: the
        /// prefix it names and whether it advertises or retracts it.
        #[derive(Debug, PartialEq, Eq)]
        struct SentUpdate {
            /// Where the packet carrying it was addressed. 3.8.1.1 allows either, so this is
            /// recorded rather than asserted on its own.
            to: TransmitDestination<NoExtension>,
            plen: u8,
            /// The Prefix field as it went on the wire.
            prefix: Vec<u8>,
            metric: Metric,
        }

        impl SentUpdate {
            /// An answer that advertises `prefix/plen` at `metric`.
            fn advertising(plen: u8, prefix: &[u8], metric: u16) -> Self {
                Self {
                    to: TransmitDestination::Multicast,
                    plen,
                    prefix: prefix.to_vec(),
                    metric: Metric::from_raw(metric),
                }
            }

            /// An answer that retracts `prefix/plen`.
            fn retracting(plen: u8, prefix: &[u8]) -> Self {
                Self {
                    to: TransmitDestination::Multicast,
                    plen,
                    prefix: prefix.to_vec(),
                    metric: Metric::INFINITY,
                }
            }
        }

        /// Drains the router's output on `iface` and collects every Update TLV it wrote.
        ///
        /// Polling is what actually puts an answer on the wire, and a poll writes the updates it
        /// owes before anything else, so the Hellos and IHUs the router also owes ride behind them
        /// and are dropped here. It runs until the router asks to be woken rather than for a fixed
        /// number of packets: how many packets the answers are split over is the writer's business,
        /// not a request's.
        fn sent_updates(
            r: &mut BabelRouter<'static>,
            now: Instant,
            iface: InterfaceHandle,
        ) -> Vec<SentUpdate> {
            let mut out = Vec::new();
            loop {
                let transmit = match r
                    .poll_output_for_iface(now, iface)
                    .expect("poll should succeed")
                {
                    Output::SetTimer(_) => return out,
                    Output::Transmit(transmit) => transmit,
                };

                let packet =
                    PacketSlice::from_slice(&transmit.contents).expect("packet should parse");
                for tlv in packet.body_reader() {
                    let Tlv::Update(update) = tlv else {
                        continue;
                    };
                    let ae = AddressEncoding::<NoExtension>::try_from(update.ae())
                        .expect("the router should not write an encoding it cannot read");
                    out.push(SentUpdate {
                        to: transmit.destination,
                        plen: update.plen(),
                        prefix: update
                            .prefix(ae.implied_prefix_octets())
                            .expect("the prefix field should be within the TLV")
                            .to_vec(),
                        metric: update.metric(),
                    });
                }
            }
        }

        /// The MUST in the first half of 3.8.1.1: a request for a prefix this node holds is owed an
        /// update naming that prefix, and it is owed to the neighbour that asked.
        #[test]
        fn a_request_for_a_selected_route_is_answered_with_an_update() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![update_answer(
                    ORIGIN_1,
                    PREFIX_A,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "the prefix that was asked about, advertised under the router-id that originated \
                 the selected route"
            );
        }

        /// The other half of that MUST, on the wire rather than in the queue: the Update TLV names
        /// the requested prefix and carries the selected route's real metric, so the answer is an
        /// advertisement rather than a retraction.
        #[test]
        fn the_answer_to_a_request_carries_the_selected_routes_metric() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::advertising(PLEN, &PREFIX_A_WIRE, COMPUTED)],
            );
        }

        /// An answer is owed to the neighbour that asked and to nobody else, which is what
        /// separates it from the triggered updates of 3.7.2 — those go to the whole link because
        /// every neighbour's belief about the route just went stale. Nothing went stale here; one
        /// neighbour asked a question.
        #[test]
        fn a_request_is_answered_to_the_requester_alone() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            let owed_to: Vec<NeighbourIndex<NoExtension>> = answers(&mut r)
                .iter()
                .map(|(_, update)| update.neighbour)
                .collect();
            assert_eq!(
                owed_to,
                alloc::vec![nbr_idx(iface, NEIGHBOUR_2_ADDR)],
                "neighbour 1 advertised the route and neighbour 3 is on the same link, but \
                 neither of them asked"
            );
        }

        /// The second MUST in 3.8.1.1. "I have never heard of that prefix" is an answer the
        /// requester needs, not a reason to stay quiet: a node asks because it is missing a route,
        /// and silence leaves it waiting out a timeout for news that was never coming.
        #[test]
        fn a_request_for_a_prefix_nobody_holds_is_answered_with_a_retraction() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_B_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![retraction_answer(
                    PREFIX_B,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "an answer is owed for a prefix this node has never held"
            );
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::retracting(PLEN, &PREFIX_B_WIRE)],
                "and it goes out as an infinite metric for the prefix that was asked about"
            );
        }

        /// A route table entry is not a selected route. The entry for a retracted prefix stays in
        /// the table carrying an infinite metric, and 3.8.1.1 asks about "a selected route to this
        /// exact prefix" — so the answer is a retraction, the same as for a prefix that was never
        /// heard of at all.
        #[test]
        fn a_request_for_a_retracted_prefix_is_answered_with_a_retraction() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            send_updates(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                &[UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE)],
            );
            assert!(
                !is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN),
                "the entry survives the retraction, but it holds nothing"
            );
            drain_updates(&mut r);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![retraction_answer(
                    PREFIX_A,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
            );
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::retracting(PLEN, &PREFIX_A_WIRE)],
            );
        }

        /// "a selected route to this exact prefix" — a supernet of a prefix this node holds is not
        /// that prefix. Answering `fd0a::/48` with the `fd0a::/64` route would tell the requester
        /// this node can carry traffic for 65535 prefixes it knows nothing about.
        #[test]
        fn a_request_for_a_supernet_of_a_held_prefix_is_answered_with_a_retraction() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                SUPERNET_PLEN,
                &PREFIX_A_SUPERNET_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![retraction_answer(
                    PREFIX_A,
                    SUPERNET_PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "the /64 this node holds is not an answer about the /48 that was asked for"
            );
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::retracting(
                    SUPERNET_PLEN,
                    &PREFIX_A_SUPERNET_WIRE
                )],
                "and the retraction names the prefix length that was asked about"
            );
        }

        /// The same rule from the other side: a host route inside a prefix this node holds is a
        /// prefix it does not hold.
        #[test]
        fn a_request_for_a_subnet_of_a_held_prefix_is_answered_with_a_retraction() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                HOST_PLEN,
                &PREFIX_A_HOST_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![retraction_answer(
                    PREFIX_A,
                    HOST_PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
            );
        }

        /// A prefix length that is not a whole number of octets still reaches the route table as
        /// the prefix it names. The Prefix field is `Plen/8` rounded upwards, so a `/60` arrives as
        /// 8 octets whose last one is only half prefix — RFC 8966
        /// [4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
        /// has the sender clear the bits past Plen, so what arrives is the prefix itself and the
        /// receiver has nothing to undo.
        #[test]
        fn a_request_at_a_prefix_length_inside_an_octet_is_answered() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            // A prefix length that stops four bits into the last octet of the field.
            const ODD_PLEN: u8 = 60;
            const ODD_WIRE: [u8; 8] = [0xfd, 0x0a, 0, 0, 0, 0, 0, 0x00];

            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                ODD_PLEN,
                &ODD_WIRE,
                ADVERTISED,
            );
            assert!(
                is_selected(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, ODD_PLEN),
                "the route the request below is about"
            );
            drain_updates(&mut r);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                ODD_PLEN,
                &ODD_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![update_answer(
                    ORIGIN_1,
                    PREFIX_A,
                    ODD_PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "the half-octet at the end of the field is matched against the route table the \
                 same as any other prefix"
            );
        }

        /// A wildcard request asks for everything this node would forward over, which is its
        /// selected routes — one answer per destination, all of them owed to the one neighbour that
        /// asked.
        #[test]
        fn a_wildcard_request_is_answered_with_every_selected_route() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                PLEN,
                &PREFIX_A_WIRE,
                ADVERTISED,
            );
            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_3_ADDR,
                ORIGIN_2,
                PLEN,
                &PREFIX_B_WIRE,
                ADVERTISED,
            );
            drain_updates(&mut r);

            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_WILDCARD, 0, &[]);

            assert_eq!(
                answers(&mut r),
                alloc::vec![
                    update_answer(ORIGIN_1, PREFIX_A, PLEN, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                    update_answer(ORIGIN_2, PREFIX_B, PLEN, nbr_idx(iface, NEIGHBOUR_2_ADDR)),
                ],
                "both destinations, each advertised under its own originator, owed to the \
                 requester alone"
            );
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![
                    SentUpdate::advertising(PLEN, &PREFIX_A_WIRE, COMPUTED),
                    SentUpdate::advertising(PLEN, &PREFIX_B_WIRE, COMPUTED),
                ],
            );
        }

        /// A dump is of the route *table*, not of everything this node has been told. A destination
        /// with two routes is advertised once, from the route that holds it: the loser was never
        /// advertised onwards, and putting it in the dump would tell the requester about a path
        /// this node does not use.
        #[test]
        fn a_wildcard_dump_advertises_each_destination_once_from_the_route_that_holds_it() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            // Neighbour 1 wins the destination on the lower metric; neighbour 3's route is tracked
            // for failover under a different originator, and loses.
            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                PLEN,
                &PREFIX_A_WIRE,
                ADVERTISED,
            );
            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_3_ADDR,
                ORIGIN_2,
                PLEN,
                &PREFIX_A_WIRE,
                ADVERTISED + 100,
            );
            assert!(
                !is_selected(&mut r, iface, NEIGHBOUR_3_ADDR, PREFIX_A, PLEN),
                "neighbour 3's route is the one that lost"
            );
            drain_updates(&mut r);

            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_WILDCARD, 0, &[]);

            assert_eq!(
                answers(&mut r),
                alloc::vec![update_answer(
                    ORIGIN_1,
                    PREFIX_A,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "one destination, one answer, under the winner's originator"
            );
        }

        /// A node with nothing selected still has an answer to give — it just has nothing to
        /// advertise. There is no prefix a wildcard request names, so there is no retraction to
        /// send either, and the dump is empty.
        #[test]
        fn a_wildcard_request_to_a_router_with_no_routes_is_answered_with_nothing() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = three_neighbours(&mut r, t0);

            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_WILDCARD, 0, &[]);

            assert_eq!(answers(&mut r), alloc::vec![]);
        }

        /// RFC 8966 [4.6.10](https://datatracker.ietf.org/doc/html/rfc8966#name-route-request): "A
        /// Request TLV with AE set to 0 and Plen not set to 0 MUST be ignored."
        ///
        /// The two fields disagree about what is being asked for — a table dump, or a prefix that
        /// was never sent — and there is no way to pick one. Guessing "dump" would hand anybody on
        /// the link a two-byte way to make this node recite its whole route table.
        #[test]
        fn a_wildcard_request_with_a_nonzero_plen_is_ignored() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_WILDCARD,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(
                answers(&mut r),
                alloc::vec![],
                "no dump, and no answer about the prefix the Plen and Prefix fields describe"
            );
        }

        /// An answer is owed to a *neighbour*, and a request from an address the neighbour table
        /// has never heard of names nobody to owe it to. Answering anyway would let an off-link
        /// address pull a route table dump out of this node.
        #[test]
        fn a_request_from_an_unknown_neighbour_is_answered_with_nothing() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = drained_iface(&mut r, t0, "iface_1");
            established_neighbour(&mut r, t0, iface, NEIGHBOUR_1_ADDR);
            advertise(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_1_ADDR,
                ORIGIN_1,
                PLEN,
                &PREFIX_A_WIRE,
                ADVERTISED,
            );
            drain_updates(&mut r);

            // Neighbour 2 was never established: no hello of its own has ever arrived.
            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(answers(&mut r), alloc::vec![]);
        }

        /// A prefix length longer than the encoding can name is not a prefix. Letting it through
        /// would file an answer under a destination no Update TLV could ever carry back out.
        #[test]
        fn a_request_whose_prefix_length_overruns_its_encoding_is_ignored() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            // 130 bits of an address that has 128, with a Prefix field long enough to match so
            // that the length is the only thing wrong with it.
            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_IPV6, 130, &[0; 17]);

            assert_eq!(answers(&mut r), alloc::vec![]);
        }

        /// TLVs in a packet are independent, so a request the router cannot handle must be skipped
        /// rather than aborting the ones behind it — otherwise a malformed request at the front of
        /// a packet suppresses every answer the rest of it was owed.
        #[test]
        fn a_malformed_request_does_not_discard_the_requests_behind_it() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            let pkt = PacketBuilder::new()
                .route_request(AE_WILDCARD, PLEN, &PREFIX_A_WIRE)
                .route_request(AE_IPV6, PLEN, &PREFIX_A_WIRE)
                .build();
            r.handle_input(
                t0,
                receive(iface, NEIGHBOUR_2_ADDR, ReceiveDestination::Unicast, &pkt),
            )
            .expect("a route request must never fail the packet it arrived in");
            tick(&mut r, t0);

            assert_eq!(
                answers(&mut r),
                alloc::vec![update_answer(
                    ORIGIN_1,
                    PREFIX_A,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "the second request was still answered"
            );
        }

        /// "Full route dumps SHOULD be rate-limited, especially if they are sent over multicast."
        ///
        /// An answer is an ordinary queue entry keyed by (destination, neighbour owed), and a
        /// second request for something already owed refreshes that entry without restarting its
        /// send timer. So asking twice does not get the answer sent twice: the repeat is absorbed,
        /// and the answer still goes out on the schedule the first one set.
        ///
        /// That is what keeps a node that asks in a loop from turning into a packet source — which
        /// is the whole point of the SHOULD, and matters most for the wildcard request, where one
        /// TLV is worth a whole table.
        #[test]
        fn a_repeated_request_does_not_get_the_answer_sent_again() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::advertising(PLEN, &PREFIX_A_WIRE, COMPUTED)],
                "the first request is answered straight away"
            );

            request(
                &mut r,
                t0,
                iface,
                NEIGHBOUR_2_ADDR,
                AE_IPV6,
                PLEN,
                &PREFIX_A_WIRE,
            );

            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![],
                "asking again at the same instant does not buy a second answer"
            );
            assert_eq!(
                answers(&mut r),
                alloc::vec![update_answer(
                    ORIGIN_1,
                    PREFIX_A,
                    PLEN,
                    nbr_idx(iface, NEIGHBOUR_2_ADDR)
                )],
                "the answer is still owed, and goes out again when its own timer says so"
            );
        }

        /// The same for the expensive case: a node asking for a table dump in a loop gets one
        /// dump's worth of packets, not one per request.
        #[test]
        fn a_repeated_wildcard_request_does_not_dump_the_table_again() {
            let mut r = router("node_1");
            let t0 = Instant::from_secs(0);
            let iface = one_route(&mut r, t0);

            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_WILDCARD, 0, &[]);
            assert_eq!(
                sent_updates(&mut r, t0, iface),
                alloc::vec![SentUpdate::advertising(PLEN, &PREFIX_A_WIRE, COMPUTED)],
            );

            request(&mut r, t0, iface, NEIGHBOUR_2_ADDR, AE_WILDCARD, 0, &[]);

            assert_eq!(sent_updates(&mut r, t0, iface), alloc::vec![]);
        }
    }
}
