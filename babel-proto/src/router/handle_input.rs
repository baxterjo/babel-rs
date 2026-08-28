use crate::data_structures::interface::Interface;
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
use crate::packet::tlv::{HelloSlice, IhuSlice, Tlv};
use crate::router::BabelRouter;
use crate::utils::{Instant, ManagedSliceExt};

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
                }
                Tlv::Ihu(ihu) => {
                    ok_or_continue!(self.handle_ihu(
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
                    if update.ae() != 0 && update.metric() != Metric::INFINITY {
                        let _update_info = ok_or_continue!(parser.handle_update(&update));
                    }
                }
                // This covers the base-spec TLVs that are not implemented yet.
                Tlv::AckReq(_) | Tlv::Ack(_) | Tlv::RouteRequest(_) | Tlv::SeqnoRequest(_) => {
                    unimplemented!("Unimplemented base spec TLV found, Type: {}", tlv.r#type());
                }
            }
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
        self.neighbor_table
            .handle_hello(now, interface, address, hello)?;
        Ok(())
    }

    fn handle_ihu(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        source_addr: Address<A>,
        destination: ReceiveDestination,
        ihu: IhuSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        if !ihu_is_addressed_to_us(&ihu, destination, interface.address)? {
            b_debug!("Ignoring IHU addressed to another neighbour");
            return Ok(());
        }

        // The rxcost belongs to whoever sent the packet. Nothing inside a Babel packet names its
        // sender, so the transport's source address is the only thing that identifies them.
        self.neighbor_table
            .handle_ihu(now, source_addr, interface, ihu)?;
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
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::interface::{InterfaceConfig, InterfaceHandle};
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_types::seqno::SeqNo;
    use crate::data_types::{Interval, RouterId};
    use crate::extension::NoExtension;
    use crate::metric::TxCost;
    use crate::packet::packet_header::PacketHeader;
    use crate::packet::tlv::TypedTlv;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::router::config::BabelRouterConfig;
    use crate::utils::Duration;

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

    /// Registers an interface and drains its mandatory eager initial multicast hello.
    fn drained_iface(r: &mut BabelRouter<'static>, now: Instant, name: &str) -> InterfaceHandle {
        let mut config: InterfaceConfig<NoExtension> =
            InterfaceConfig::new_wired(iface_handle(name), NODE_ADDR.into());
        config.set_mcast_hello_interval(IFACE_INTERVAL);
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
}
