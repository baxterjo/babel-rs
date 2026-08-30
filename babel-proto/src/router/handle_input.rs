use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::route::Route;
use crate::data_structures::source::{SourceIndex, SourceTable};
use crate::data_types::Address;
use crate::data_types::address_encoding::AddressEncoding;
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::input::{Receive, ReceiveDestination};
use crate::metric::Metric;
use crate::packet::packet_slice::PacketSlice;
use crate::packet::parser::Parser;
use crate::packet::tlv::reader::TlvReader;
use crate::packet::tlv::{HelloSlice, IhuSlice, Tlv, UpdateSlice};
use crate::router::BabelRouter;
use crate::utils::{Instant, InternallyKeyed, ManagedSliceExt};

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
{
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
        let mut run_selection = false;

        for tlv in TlvReader::new(packet.body()) {
            b_trace!("{:?}", tlv);
            match tlv {
                Tlv::Pad1 | Tlv::PadN(_) => {
                    continue;
                }
                // A TLV that cannot be handled is skipped rather than aborting the packet. TLVs
                // are (mostly) independent of one another, so letting one bad TLV discard the valid
                // ones behind it hands any sender on the link a way to suppress
                // them.
                Tlv::Hello(hello) => {
                    ok_or_continue!(self.handle_hello(now, &interface, input.source_addr, hello));
                    run_selection = true;
                }
                Tlv::Ihu(ihu) => {
                    run_selection |= ok_or_continue!(self.handle_ihu(
                        now,
                        &interface,
                        input.source_addr,
                        input.destination,
                        ihu
                    ));
                }
                Tlv::RouterId(router_id) => {
                    parser.handle_router_id_tlv(router_id);
                }
                Tlv::NextHop(next_hop) => {
                    ok_or_continue!(parser.handle_next_hop_tlv(next_hop));
                }
                Tlv::Update(update) => {
                    ok_or_continue!(self.handle_update(
                        now,
                        &interface,
                        &input.source_addr,
                        &mut parser,
                        update
                    ));
                    run_selection = true;
                }
                // This covers the base-spec TLVs that are not implemented yet.
                Tlv::AckReq(_) | Tlv::Ack(_) | Tlv::RouteRequest(_) | Tlv::SeqnoRequest(_) => {
                    unimplemented!("Unimplemented base spec TLV found, Type: {}", tlv.r#type());
                }
            }
        }

        if run_selection {
            // TODO: Triggered updates
            let _triggered_update = self.select_routes();
        }

        Ok(())
    }

    fn handle_hello(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        // Handle the incoming hello
        self.neighbor_table
            .handle_hello(now, interface, address, hello)?;

        // Update the cost for the routes associated with this neighbour.
        if let Some(neighbour) = self.neighbor_table.inner.get_by_key(&NeighbourIndex {
            iface: interface.handle,
            addr: address,
        }) {
            // This is behind a `Some` guard even after updating because if the neighbour table is
            // full the `handle_hello` method can silently succeed.
            self.route_table
                .update_cost_for_neighbour(now, interface, &neighbour);
        }
        Ok(())
    }

    /// Handle an incoming IHU from a neighbour.
    ///
    /// Returns `true` if the route selection procedure needs to be run
    fn handle_ihu(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        source_addr: Address<A>,
        destination: ReceiveDestination,
        ihu: IhuSlice<'_>,
    ) -> Result<bool, BabelError<A>> {
        if !ihu_is_addressed_to_us(&ihu, destination, interface.address)? {
            b_debug!("Ignoring IHU addressed to another neighbour");
            return Ok(false);
        }

        let updates = self
            .neighbor_table
            .handle_ihu(now, source_addr, interface, ihu)?;

        // Update the cost for the routes associated with this neighbour.
        if let Some(neighbour) = self.neighbor_table.inner.get_by_key(&NeighbourIndex {
            iface: interface.handle,
            addr: source_addr,
        }) {
            // This is behind a `Some` guard even after updating because if the neighbour table is
            // full the `handle_ihu` method can silently succeed.
            self.route_table
                .update_cost_for_neighbour(now, interface, &neighbour);
        }

        // The rxcost belongs to whoever sent the packet. Nothing inside a Babel packet names its
        // sender, so the transport's source address is the only thing that identifies them.
        Ok(updates)
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
    ) -> Result<(), BabelError<A>> {
        let idx = NeighbourIndex {
            iface: interface.handle,
            addr: *source_addr,
        };
        let neighbour = self
            .neighbor_table
            .inner
            .get_by_key(&idx)
            .ok_or(BabelError::TlvFromUnknownNeighbour("update_tlv", idx))?;

        if update.is_blanket_retraction() {
            // Section 4.6.9: "If the metric is infinite and AE is 0, Plen and Omitted MUST both be
            // 0; Update TLVs that do not satisfy this requirement MUST be ignored."
            if update.plen() != 0 || update.ommitted() != 0 {
                return Err(BabelError::MalformedBlanketRetraction {
                    plen: update.plen(),
                    omitted: update.ommitted(),
                });
            }
            self.route_table.handle_blanket_retraction(neighbour);
        } else if update.is_retraction() {
            // A retraction only has to name the entry it retracts. Section 4.6.9: "the router-id,
            // next hop, and seqno are not used" This means that the parser does not need to have
            // state for router-id or next hop in this branch.
            let prefix = parser.resolve_address(&update)?;

            self.route_table
                .handle_retraction(neighbour, prefix, update.plen());
        } else {
            // Resolve the update (this also updates the parser state)
            let resolved_update = parser.handle_update(update)?;

            // Check if the update is feasible against the source table.
            let feasible = self.source_table.is_feasible(
                &SourceIndex {
                    router_id: resolved_update.router_id,
                    prefix: resolved_update.address,
                    prefix_len: resolved_update.slice.plen(),
                },
                resolved_update.slice.metric(),
                resolved_update.slice.seqno(),
            );

            // Aquire the route
            self.route_table
                .aquire_route(now, interface, neighbour, feasible, resolved_update)?;
        }
        Ok(())
    }

    /// The recommended route selection procedure as defined in
    /// [Section 3.6](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    /// and [Appendix A.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    ///
    /// Returns `true` if the selection process triggered an update.
    pub(crate) fn select_routes(&mut self) -> bool {
        let mut send_update = false;
        // A shared borrow of one field while `route_table` is borrowed mutably below.
        let source_table = &self.source_table;

        for mut destination_group in self.route_table.destination_groups_mut() {
            // The route this destination was pointing at before this run, whether or not it is
            // still usable. Only the change detection at the bottom cares about that distinction.
            let previous: Option<Route<A>> = destination_group
                .iter()
                .find(|route| route.selected)
                .copied();

            // The incumbent for hysteresis purposes: the previously selected route, but only
            // while it still passes the hard rules. One that has been retracted or has gone
            // unfeasible has no claim on the destination at all.
            let incumbent = previous.filter(|route| is_eligible(source_table, route));

            // The best route on offer, hard rules applied. Ties break on the route index so that
            // the winner does not depend on where the entries happen to sit in the table.
            let challenger = destination_group
                .iter()
                .filter(|route| is_eligible(source_table, route))
                .min_by_key(|route| (route.computed_metric, route.key()))
                .copied();

            // Appendix A.3's hysteresis. The comparison is against the *incumbent* rather than
            // against whichever entry the scan reached first: the smoothed metric only says
            // something about whether it is worth moving away from the route already in use, so
            // measuring it against an arbitrary scan position both makes the outcome depend on
            // route table ordering and lets a worse route take a destination it never held.
            let winner = match (incumbent, challenger) {
                // A still-eligible incumbent keeps the destination unless the best route on offer
                // beats it on the real metric *and* on the smoothed one. Requiring both is what
                // stops a route whose metric is briefly flapping from taking over.
                (Some(incumbent), Some(challenger)) => Some(
                    if challenger.computed_metric < incumbent.computed_metric
                        && challenger.smoothed_metric < incumbent.smoothed_metric
                    {
                        challenger
                    } else {
                        incumbent
                    },
                ),
                // Nothing to defend the destination, so the best route takes it outright. This is
                // also the path a destination whose selected route was just retracted takes.
                (None, challenger) => challenger,
                // An eligible incumbent is itself a candidate, so this cannot happen. Keeping it
                // rather than dropping the selection is the harmless reading either way.
                (Some(incumbent), None) => Some(incumbent),
            };

            // Deselect everything, then switch the winner back on. Doing it in that order means a
            // destination that no longer has an eligible route ends up with nothing selected.
            for route in destination_group.iter_mut() {
                route.selected = false;
            }
            if let Some(winner) = winner {
                destination_group
                    .iter_mut()
                    .find(|route| route.key() == winner.key())
                    .expect("the winner was picked out of this same group")
                    .selected = true;
            }

            // Section 3.7.2 wants an update sent when the selected route changes, which is a
            // different question from whether this run had a candidate at all.
            send_update |= winner.map(|w| w.key()) != previous.map(|p| p.key());
        }
        send_update
    }
}

/// Section 3.6's hard rules, which no amount of hysteresis can talk a route past: a route with an
/// infinite metric has been retracted, and an unfeasible one risks a routing loop.
fn is_eligible<A: AddressExt>(source_table: &SourceTable<'_, A>, route: &Route<A>) -> bool {
    route.computed_metric != Metric::INFINITY
        && source_table.is_feasible(route.source(), route.advertised_metric, route.seqno)
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
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::{InterfaceConfig, InterfaceHandle};
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_structures::route::route_table::DEFAULT_SMOOTHING_MULTIPLE;
    use crate::data_structures::route::{Route, RouteIndex};
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::{Metric, TxCost};
    use crate::packet::packet_header::PacketHeader;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::packet::tlv::{NextHopSlice, RouterIdSlice, TypedTlv};
    use crate::router::config::{BabelRouterConfig, DEFAULT_ROUTE_EXPIRY_TIME};
    use crate::utils::{Duration, InternallyKeyed};

    // Long enough not to fire again mid-test, still inside the Timer bound.
    const IFACE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(600));

    const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_1_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_2_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);

    fn router(name: &'static str) -> BabelRouter<'static> {
        BabelRouter::new(BabelRouterConfig::new(
            RouterId::try_from(name).expect("bad router id"),
        ))
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    /// Wraps a TLV body in a Babel packet header.
    fn packet(body: &[u8]) -> Vec<u8> {
        let mut out = vec![PacketHeader::MAGIC_NUMBER, PacketHeader::VERSION_NUMBER];
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn hello_tlv(seqno: u16, interval_centis: u16) -> [u8; 8] {
        let flags = HelloFlags::new_multicast().to_wire();
        let seqno = seqno.to_be_bytes();
        let interval = interval_centis.to_be_bytes();
        [
            HelloSlice::TYPE_ID,
            HelloSlice::MIN_LEN as u8,
            flags[0],
            flags[1],
            seqno[0],
            seqno[1],
            interval[0],
            interval[1],
        ]
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

    /// An IHU with the wildcard encoding (AE=0), which omits the address entirely.
    fn wildcard_ihu_tlv(rx_cost: u16, interval_centis: u16) -> Vec<u8> {
        let mut out = vec![
            IhuSlice::TYPE_ID,
            IhuSlice::MIN_LEN as u8,
            0, // AE = wildcard
            0, // Reserved
        ];
        out.extend_from_slice(&rx_cost.to_be_bytes());
        out.extend_from_slice(&interval_centis.to_be_bytes());
        out
    }

    /// An IHU carrying a full 16-byte IPv6 destination address (AE=2).
    fn ihu_tlv(rx_cost: u16, interval_centis: u16, address: Ipv6Addr) -> Vec<u8> {
        let mut out = vec![
            IhuSlice::TYPE_ID,
            (IhuSlice::MIN_LEN + 16) as u8,
            2, // AE = Ipv6
            0, // Reserved
        ];
        out.extend_from_slice(&rx_cost.to_be_bytes());
        out.extend_from_slice(&interval_centis.to_be_bytes());
        out.extend_from_slice(&address.octets());
        out
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

        fn to_wire(&self) -> Vec<u8> {
            let mut out = vec![
                UpdateSlice::TYPE_ID,
                (UpdateSlice::MIN_LEN + self.prefix.len()) as u8,
                self.ae,
                self.flags,
                self.plen,
                self.omitted,
            ];
            out.extend_from_slice(&self.interval_centis.to_be_bytes());
            out.extend_from_slice(&self.seqno.to_be_bytes());
            out.extend_from_slice(&self.metric.to_be_bytes());
            out.extend_from_slice(&self.prefix);
            out
        }
    }

    fn router_id_tlv(id: [u8; 8]) -> Vec<u8> {
        let mut out = vec![
            RouterIdSlice::TYPE_ID,
            RouterIdSlice::MIN_LEN as u8,
            0, // Reserved
            0, // Reserved
        ];
        out.extend_from_slice(&id);
        out
    }

    fn next_hop_tlv(ae: u8, address: &[u8]) -> Vec<u8> {
        let mut out = vec![
            NextHopSlice::TYPE_ID,
            (NextHopSlice::MIN_LEN + address.len()) as u8,
            ae,
            0, // Reserved
        ];
        out.extend_from_slice(address);
        out
    }

    /// The hold time a route advertising `interval_centis` should end up with.
    fn expected_expiry(interval_centis: u16) -> Duration {
        Duration::from_centis(interval_centis.into()) * DEFAULT_ROUTE_EXPIRY_TIME
    }

    /// Sends a packet carrying a Router-Id TLV followed by `updates`, which is the shape an Update
    /// normally arrives in.
    fn send_updates(
        r: &mut BabelRouter<'static>,
        now: Instant,
        iface: InterfaceHandle,
        from: Ipv6Addr,
        router_id: [u8; 8],
        updates: &[UpdateTlv],
    ) {
        let mut body = router_id_tlv(router_id);
        for update in updates {
            body.extend_from_slice(&update.to_wire());
        }
        let pkt = packet(&body);

        r.handle_input(
            now,
            receive(iface, from, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");
    }

    /// Copies out the route table entry indexed by (prefix, plen, neighbour), if it exists.
    fn route_for(
        r: &mut BabelRouter<'static>,
        iface: InterfaceHandle,
        neighbour: Ipv6Addr,
        prefix: Ipv6Addr,
        plen: u8,
    ) -> Option<Route<NoExtension>> {
        let idx = RouteIndex {
            prefix: prefix.into(),
            prefix_len: plen,
            neighbour: NeighbourIndex {
                iface,
                addr: neighbour.into(),
            },
        };
        r.route_table
            .iter_mut_entries()
            .find(|route| route.key() == idx)
            .map(|route| *route)
    }

    fn route_count(r: &mut BabelRouter<'static>) -> usize {
        r.route_table.iter_mut_entries().count()
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
            let pkt = packet(&hello_tlv(seqno, 100));
            r.handle_input(
                now,
                receive(iface, addr, ReceiveDestination::Multicast, &pkt),
            )
            .expect("hello should be handled");
        }

        let pkt = packet(&ihu_tlv(LINK_COST, 100, NODE_ADDR));
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
        let pkt = packet(&hello_tlv(0, 100));

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
        let pkt = packet(&ihu_tlv(77, 100, NODE_ADDR));
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
        let mut body = ihu_tlv(11, 100, NODE_ADDR);
        body.extend_from_slice(&ihu_tlv(22, 100, NEIGHBOUR_2_ADDR));
        let pkt = packet(&body);

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

        let pkt = packet(&wildcard_ihu_tlv(33, 100));
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

        let pkt = packet(&wildcard_ihu_tlv(33, 100));
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
        let mut body = ihu_tlv(50, 0, NODE_ADDR);
        body.extend_from_slice(&hello_tlv(0, 100));
        let pkt = packet(&body);

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
        let pkt = packet(&ihu_tlv(42, 100, NODE_ADDR));
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

        assert_eq!(route.source().prefix, PREFIX_A.into());
        assert_eq!(route.source().prefix_len, PLEN);
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
            route.advertised_metric,
            Metric::from_raw(100),
            "the advertised metric is the one the neighbour sent, unchanged"
        );
        assert_eq!(
            route.computed_metric,
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
                .advertised_metric,
            Metric::from_raw(100)
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN)
                .expect("neighbour 2 should have a route")
                .advertised_metric,
            Metric::from_raw(300)
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
        let pkt = packet(&UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).to_wire());
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

        let mut body = router_id_tlv(ORIGIN_1);
        body.extend_from_slice(&next_hop_tlv(2, &NEXT_HOP.octets()));
        body.extend_from_slice(&UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100).to_wire());
        let pkt = packet(&body);

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

        assert_eq!(compressed.advertised_metric, Metric::from_raw(200));
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
                route.source().prefix_len,
                128,
                "the entry records the whole prefix, not the part that reached the wire"
            );
            assert_eq!(route.advertised_metric, Metric::from_raw(100));
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

        assert_eq!(route.source().prefix_len, 64);
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
        assert_eq!(route.advertised_metric, Metric::from_raw(300));
        assert_eq!(route.computed_metric, Metric::from_raw(300 + LINK_COST));
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
        assert_eq!(route.advertised_metric, Metric::INFINITY);
        assert_eq!(route.computed_metric, Metric::INFINITY);
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

        assert_eq!(route.computed_metric, Metric::INFINITY);
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

        assert_eq!(route.computed_metric, Metric::INFINITY);
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
        let pkt = packet(&UpdateTlv::retraction_of(PLEN, &PREFIX_A_WIRE).to_wire());
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the route should still exist")
                .computed_metric,
            Metric::INFINITY
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
                .computed_metric,
            Metric::INFINITY
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_B, PLEN)
                .expect("the other prefix should still exist")
                .computed_metric,
            Metric::from_raw(100 + LINK_COST),
            "a retraction of one prefix must not touch another prefix from the same neighbour"
        );
        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN)
                .expect("the other neighbour's route should still exist")
                .computed_metric,
            Metric::from_raw(100 + LINK_COST),
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
            assert_eq!(route.advertised_metric, Metric::INFINITY);
            assert_eq!(route.computed_metric, Metric::INFINITY);

            let other = route_for(&mut r, iface, NEIGHBOUR_2_ADDR, prefix, PLEN)
                .expect("the other neighbour's route should still exist");
            assert_eq!(
                other.computed_metric,
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
        let pkt = packet(&UpdateTlv::blanket_retraction().to_wire());
        r.handle_input(
            t0,
            receive(iface, NEIGHBOUR_1_ADDR, ReceiveDestination::Multicast, &pkt),
        )
        .expect("handle_input should succeed");

        assert_eq!(
            route_for(&mut r, iface, NEIGHBOUR_1_ADDR, PREFIX_A, PLEN)
                .expect("the route should still exist")
                .computed_metric,
            Metric::INFINITY
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
                    .computed_metric,
                Metric::from_raw(100 + LINK_COST),
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
        assert_eq!(after.advertised_metric, before.advertised_metric);
        assert_eq!(after.computed_metric, before.computed_metric);
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

        assert_eq!(route.computed_metric, Metric::from_raw(100 + LINK_COST));
        assert_eq!(
            route.smoothed_metric, route.computed_metric,
            "a new route is its own history"
        );
        assert_eq!(
            route.smoothed_metric_time, t0,
            "and the clock starts at the update that created it"
        );
    }

    /// The point of the smoothed metric is that it lags the real one. A single update one time
    /// constant later must move it part of the way, not all of it.
    #[test]
    fn a_later_update_pulls_the_smoothed_metric_towards_the_new_one() {
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

        // One time constant later the same neighbour advertises a much worse metric.
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
            route.computed_metric,
            Metric::from_raw(300 + LINK_COST),
            "the computed metric follows the update immediately"
        );
        // round(120 + (320 - 120) * 0.6321) == 246
        assert_eq!(
            route.smoothed_metric,
            Metric::from_raw(246),
            "the smoothed metric closes 1 - 1/e of the gap in one time constant"
        );
        assert_eq!(
            route.smoothed_metric_time, t1,
            "the step is measured from the last update, so the stamp has to advance"
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
            route.computed_metric,
            Metric::from_raw(300 + LINK_COST),
            "the computed metric still tracks the newest update"
        );
        assert_eq!(
            route.smoothed_metric,
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

    /// Selection runs at the end of any packet that carried an Update, so a lone feasible route is
    /// already selected by the time `handle_input` returns.
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
        assert_eq!(route.computed_metric, Metric::INFINITY);
        assert!(!route.selected, "an infinite metric is never selected");
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

    /// Section 3.7.2 wants an update sent when the selected route *changes*, so the return value
    /// has to distinguish a change from a re-run that settled on the same route. Re-running
    /// selection over an unchanged table must not keep asking for updates.
    #[test]
    fn selection_reports_a_change_only_when_the_selected_route_moves() {
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
            !r.select_routes(),
            "handle_input already ran selection, so a re-run settles on the same route"
        );

        // Drive the selected route to infinity behind selection's back, the way an expiry sweep
        // would, so the next run has a real change to report.
        for route in r
            .route_table
            .iter_mut_entries()
            .filter(|route| route.selected)
        {
            route.computed_metric = Metric::INFINITY;
        }

        assert!(
            r.select_routes(),
            "the destination moved to a different route, which is what triggers an update"
        );
        assert!(
            !r.select_routes(),
            "and once reported the state is stable again"
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
    fn diverged_metrics(r: &mut BabelRouter<'static>, iface: InterfaceHandle, t0: Instant) {
        send_updates(
            r,
            t0,
            iface,
            NEIGHBOUR_1_ADDR,
            ORIGIN_1,
            &[UpdateTlv::v6(PLEN, &PREFIX_A_WIRE, 100)],
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
            (n1.computed_metric, n1.smoothed_metric),
            (Metric::from_raw(320), Metric::from_raw(246)),
            "neighbour 1 should be the worse route with the better history"
        );
        assert_eq!(
            (n2.computed_metric, n2.smoothed_metric),
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
        for route in r.route_table.iter_mut_entries() {
            route.selected = *route.neigbour() == idx;
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
        for route in r.route_table.iter_mut_entries() {
            route.selected = false;
        }

        assert!(
            r.select_routes(),
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
            !r.select_routes(),
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

        assert!(!r.select_routes(), "the selection did not move");
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

    /// A retracted incumbent has no claim to defend, so hysteresis must not keep it. Without the
    /// eligibility filter on the incumbent this would leave the destination pointing at a route
    /// with an infinite metric.
    #[test]
    fn a_retracted_incumbent_does_not_hold_the_destination_through_hysteresis() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = smoothing_setup(&mut r, t0);
        established_neighbour(&mut r, t0, iface, NEIGHBOUR_2_ADDR);
        diverged_metrics(&mut r, iface, t0);
        force_selected(&mut r, iface, NEIGHBOUR_1_ADDR);

        // Neighbour 1 retracts the prefix it was holding the destination with. Its smoothed metric
        // is left where it was, so by that measure alone it still looks like the better route.
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
        assert_eq!(n1.computed_metric, Metric::INFINITY);
        assert!(
            n1.smoothed_metric < Metric::from_raw(270),
            "the retraction leaves the smoothed metric looking better than neighbour 2's"
        );
        assert!(!n1.selected, "a retracted route is never selected");
        assert!(
            is_selected(&mut r, iface, NEIGHBOUR_2_ADDR, PREFIX_A, PLEN),
            "the destination moves to the only route still eligible for it"
        );
    }
}
