use core::net::Ipv6Addr;

use crate::data_structures::interface::{InterfaceConfig, InterfaceHandle};
use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_types::RouterId;
use crate::input::{Receive, ReceiveDestination};
use crate::output::Output;
use crate::packet::packet_slice::PacketSlice;
use crate::router::BabelRouter;
use crate::router::config::BabelRouterConfig;
use crate::utils::Instant;

#[test]
fn two_nodes_say_hello_and_ihu() {
    let _ = env_logger::try_init();

    let t0 = Instant::now();

    // The two nodes must be distinguishable, otherwise the neighbour-table assertions below hold
    // trivially and would keep passing even if the addressing were wrong.
    // Create node 1
    let mut node_1: BabelRouter<'_> = BabelRouter::new(
        Instant::now(),
        BabelRouterConfig::new(RouterId::try_from("node_1").expect("bad router ID")),
    )
    .expect("bad router");
    let node_1_iface = InterfaceHandle::try_from("iface_1").expect("Bad interface");
    let node_1_addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    node_1
        .register_interface(
            t0,
            InterfaceConfig::new_wired(node_1_iface, node_1_addr.into()),
        )
        .expect("Could not register interface.");

    // Create node 2
    let mut node_2: BabelRouter<'_> = BabelRouter::new(
        Instant::now(),
        BabelRouterConfig::new(RouterId::try_from("node_2").expect("bad router ID")),
    )
    .expect("bad router");
    let node_2_iface = InterfaceHandle::try_from("iface_2").expect("Bad interface");
    let node_2_addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    node_2
        .register_interface(
            t0,
            InterfaceConfig::new_wired(node_2_iface, node_2_addr.into()),
        )
        .expect("Could not register interface.");

    // Poll node 1 for output
    let output = node_1.poll_output(t0).expect("Output should succeed.");
    let Output::Transmit(transmit) = output else {
        panic!("Expected a transmit on first poll of node 1");
    };

    // Feed output into node_2
    node_2
        .handle_input(
            t0,
            Receive {
                iface: node_2_iface,
                source_addr: node_1_addr.into(),
                destination: ReceiveDestination::Multicast,
                contents: &transmit.contents,
            },
        )
        .expect("node_1 failed to handle input.");
    node_2
        .neighbor_table
        .get(&NeighbourIndex {
            iface: node_2_iface,
            addr: node_1_addr.into(),
        })
        .expect("Node 1 should be in node 2's neighbour table");

    // Poll output for node 2
    let output = node_2.poll_output(t0).expect("Output should succeed.");
    let Output::Transmit(transmit) = output else {
        panic!("Expected a transmit on first poll of node 2");
    };

    let packet_slice = PacketSlice::from_slice(&transmit.contents).expect("failed to slice packet");
    // The reader stops iterating on a malformed TLV, so a short count is also a parse failure.
    let counter = packet_slice.body_reader().count();

    assert_eq!(counter, 2, "Should have got 2 TLVs from node 2");

    node_1
        .handle_input(
            t0,
            Receive {
                iface: node_1_iface,
                source_addr: node_2_addr.into(),
                destination: ReceiveDestination::Multicast,
                contents: &transmit.contents,
            },
        )
        .expect("Failed to process node 1 input");

    node_1
        .neighbor_table
        .get(&NeighbourIndex {
            iface: node_1_iface,
            addr: node_2_addr.into(),
        })
        .expect("Node 2 should be in node 1's neighbour table");

    let output = node_1
        .poll_output(t0)
        .expect("Node 1 failed to poll second output.");

    let Output::Transmit(_) = output else {
        panic!("Node 1 should have transmit on second output poll");
    };

    let Output::SetTimer(_) = node_1
        .poll_output(t0)
        .expect("Failed to poll output for node 1")
    else {
        panic!("Node 1 should have no output on final poll");
    };
    let Output::SetTimer(_) = node_2
        .poll_output(t0)
        .expect("Failed to poll output for node 2")
    else {
        panic!("Node 2 should have no output on final poll");
    };
}
