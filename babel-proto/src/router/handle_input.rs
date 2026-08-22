use crate::data_structures::interface::InterfaceHandle;
use crate::data_types::Address;
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::input::Receive;
use crate::packet::packet_slice::PacketSlice;
use crate::packet::parser::Parser;
use crate::packet::tlv::reader::TlvReader;
use crate::packet::tlv::{HelloSlice, IhuSlice, TypedTlv};
use crate::router::BabelRouter;
use crate::utils::{Instant, ManagedSliceExt};

impl<'storage, A, P, const MN: u8, const V: u8> BabelRouter<'storage, P, A, MN, V>
where
    A: AddressExt,
    P: ParserStateExt,
{
    pub fn handle_input<'input>(
        &mut self,
        now: Instant,
        input: Receive<'input, A>,
    ) -> Result<(), BabelError<A>> {
        b_trace!("{:?}", input);

        if self.iface_table.inner.get_by_key(&input.iface).is_none() {
            return Err(BabelError::InterfaceDoesntExist(input.iface));
        }

        let _parser: Parser<P> = Parser::default();
        let packet = PacketSlice::from_slice(input.contents)?;
        b_trace!("{:?}", packet);

        let magic = packet.magic();
        if magic != MN {
            return Err(BabelError::IncorrectMagicNumber {
                expected: MN,
                received: magic,
            });
        }

        let version = packet.version();
        if version != V {
            return Err(BabelError::IncorrectVersionNumber {
                expected: V,
                received: version,
            });
        }

        for tlv_result in TlvReader::new(packet.body()) {
            let tlv = ok_or_continue!(tlv_result);
            b_trace!("{:?}", tlv);
            match tlv.r#type() {
                // A TLV that cannot be handled is skipped rather than aborting the packet. TLVs
                // are independent of one another, so letting one bad TLV discard the valid ones
                // behind it hands any sender on the link a way to suppress them.
                HelloSlice::TYPE_ID => {
                    let hello = ok_or_continue!(HelloSlice::from_untyped(tlv));
                    b_debug!("{:?}", hello);
                    ok_or_continue!(self.handle_hello(now, input.iface, input.source_addr, hello));
                }
                IhuSlice::TYPE_ID => {
                    let ihu = ok_or_continue!(IhuSlice::from_untyped(tlv));
                    b_debug!("{:?}", ihu);
                    ok_or_continue!(self.handle_ihu(now, input.iface, input.source_addr, ihu));
                }
                4..10 => {
                    unimplemented!("Unimplemented base spec TLV found, Type: {}", tlv.r#type());
                }
                other => {
                    b_debug!("Unrecognized TLV found: {}", other);
                }
            }
        }

        Ok(())
    }

    fn handle_hello(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
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
        interface: InterfaceHandle,
        address: Address<A>,
        ihu: IhuSlice<'_>,
    ) -> Result<(), BabelError<A>> {
        self.neighbor_table
            .handle_ihu(now, interface, address, ihu)?;
        Ok(())
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_structures::neighbour::NeighbourIndex;
    use crate::data_types::RouterId;
    use crate::packet::packet_header::BabelPacketHeader;
    use crate::packet::tlv::hello_slice::HelloFlags;
    use crate::utils::Duration;
    use crate::utils::rx_cost::RxCost;

    // Long enough not to fire again mid-test, still inside the Timer bound.
    const IFACE_INTERVAL: Duration = Duration::from_secs(600);

    const NODE_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    const NEIGHBOUR_1_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    const NEIGHBOUR_2_ADDR: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 3);
    /// The link-local all-nodes group an aggregated IHU packet would arrive on.
    const MULTICAST_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    fn router(name: &'static str) -> BabelRouter<'static> {
        BabelRouter::new(RouterId::try_from(name).expect("bad router id"))
    }

    fn iface_handle(name: &str) -> InterfaceHandle {
        InterfaceHandle::try_from(name).expect("bad interface handle")
    }

    /// Wraps a TLV body in a Babel packet header.
    fn packet(body: &[u8]) -> Vec<u8> {
        let mut out = vec![
            BabelPacketHeader::MAGIC_NUMBER,
            BabelPacketHeader::VERSION_NUMBER,
        ];
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

    fn tx_cost(r: &BabelRouter<'static>, iface: InterfaceHandle, addr: Ipv6Addr) -> RxCost {
        r.neighbor_table
            .inner
            .get_by_key(&NeighbourIndex(iface, addr.into()))
            .expect("neighbour should exist")
            .tx_cost
    }

    /// Registers an interface and drains its mandatory eager initial multicast hello.
    fn drained_iface(r: &mut BabelRouter<'static>, now: Instant, name: &str) -> InterfaceHandle {
        let handle = iface_handle(name);
        r.register_interface(now, handle, NODE_ADDR, Some(IFACE_INTERVAL), None)
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
                Receive {
                    iface: unknown,
                    source_addr: NEIGHBOUR_1_ADDR.into(),
                    contents: &pkt,
                },
            )
            .expect_err("an unregistered interface should be rejected");

        assert!(matches!(err, BabelError::InterfaceDoesntExist(h) if h == unknown));
        assert!(
            r.neighbor_table
                .inner
                .get_by_key(&NeighbourIndex(unknown, NEIGHBOUR_1_ADDR.into()))
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
            .add_neighbour(
                t0,
                unknown,
                NEIGHBOUR_1_ADDR.into(),
                Duration::from_secs(10),
                None,
            )
            .expect_err("an unregistered interface should be rejected");

        assert!(matches!(err, BabelError::InterfaceDoesntExist(h) if h == unknown));
        r.poll_output(t0).expect("poll should still succeed");
    }

    //  ___ _  _ _   _    _   ___  ___  ___ ___ ___ ___ ___
    // |_ _| || | | | |  /_\ |   \|   \| _ \ __/ __/ __|_ _|
    //  | || __ | |_| | / _ \| |) | |) |   / _|\__ \__ \| |
    // |___|_||_|\___/ /_/ \_\___/|___/|_|_\___|___/___/___|

    /// RFC 8966 4.6.6 allows IHUs to be sent to a multicast address so they can be aggregated for
    /// distinct neighbours; the explicit Address field is what disambiguates them. Attributing a
    /// multicast IHU to the packet's source address would credit one neighbour's rxcost to
    /// whichever neighbour happened to be looked up.
    #[test]
    fn multicast_ihu_is_attributed_to_the_address_in_the_tlv() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            r.add_neighbour(t0, iface, addr.into(), Duration::from_secs(10), None)
                .expect("add_neighbour should succeed");
        }

        let pkt = packet(&ihu_tlv(77, 100, NEIGHBOUR_2_ADDR));
        r.handle_input(
            t0,
            Receive {
                iface,
                source_addr: MULTICAST_ADDR.into(),
                contents: &pkt,
            },
        )
        .expect("handle_input should succeed");

        assert_eq!(
            tx_cost(&r, iface, NEIGHBOUR_2_ADDR),
            RxCost(77),
            "the IHU names neighbour 2, so its rxcost belongs to neighbour 2"
        );
        assert_eq!(
            tx_cost(&r, iface, NEIGHBOUR_1_ADDR),
            RxCost(u16::MAX),
            "neighbour 1 was not addressed and must stay at infinity"
        );
    }

    /// The aggregation case the multicast Address field exists for: one packet, two IHUs, two
    /// neighbours.
    #[test]
    fn aggregated_multicast_ihus_land_on_their_own_neighbours() {
        let mut r = router("node_1");
        let t0 = Instant::from_secs(0);
        let iface = drained_iface(&mut r, t0, "iface_1");

        for addr in [NEIGHBOUR_1_ADDR, NEIGHBOUR_2_ADDR] {
            r.add_neighbour(t0, iface, addr.into(), Duration::from_secs(10), None)
                .expect("add_neighbour should succeed");
        }

        let mut body = ihu_tlv(11, 100, NEIGHBOUR_1_ADDR);
        body.extend_from_slice(&ihu_tlv(22, 100, NEIGHBOUR_2_ADDR));
        let pkt = packet(&body);

        r.handle_input(
            t0,
            Receive {
                iface,
                source_addr: MULTICAST_ADDR.into(),
                contents: &pkt,
            },
        )
        .expect("handle_input should succeed");

        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_1_ADDR), RxCost(11));
        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_2_ADDR), RxCost(22));
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
            Receive {
                iface,
                source_addr: NEIGHBOUR_1_ADDR.into(),
                contents: &pkt,
            },
        )
        .expect("a TLV that fails to handle should not fail the packet");

        let neighbour = r
            .neighbor_table
            .inner
            .get_by_key(&NeighbourIndex(iface, NEIGHBOUR_1_ADDR.into()))
            .expect("neighbour should exist");

        // Only `handle_hello` arms the pending IHU timer, so this proves the hello behind the
        // bad IHU was still processed.
        assert!(
            neighbour.pending.ihu_timer.is_some(),
            "the hello behind the bad IHU should still have been handled"
        );
        assert_eq!(
            neighbour.tx_cost,
            RxCost(u16::MAX),
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
            r.add_neighbour(t0, iface, addr.into(), Duration::from_secs(10), None)
                .expect("add_neighbour should succeed");
        }

        // Sent directly to us: the Address field carries our own address, not the sender's.
        let pkt = packet(&ihu_tlv(42, 100, NODE_ADDR));
        r.handle_input(
            t0,
            Receive {
                iface,
                source_addr: NEIGHBOUR_1_ADDR.into(),
                contents: &pkt,
            },
        )
        .expect("handle_input should succeed");

        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_1_ADDR), RxCost(42));
        assert_eq!(tx_cost(&r, iface, NEIGHBOUR_2_ADDR), RxCost(u16::MAX));
    }
}
