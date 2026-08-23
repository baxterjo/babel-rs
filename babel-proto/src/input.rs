use core::fmt::Debug;

use crate::data_structures::interface::InterfaceHandle;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::utils::Instant;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Input<'input, A: AddressExt> {
    Timeout(Instant),
    Receive(Instant, Receive<'input, A>),
}

/// How a received datagram was addressed by the sender.
///
/// Babel packets carry no sender address of their own, so the neighbour a packet came from is
/// always identified by [`Receive::source_addr`]. This says how the datagram *arrived*, which some
/// TLVs need in order to tell whether they were meant for this node — see
/// [`IhuSlice::ae`](crate::packet::tlv::IhuSlice::ae).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ReceiveDestination {
    /// The datagram was addressed directly to this node.
    Unicast,
    /// The datagram was sent to a multicast group this node is subscribed to, so it may carry
    /// TLVs intended for other nodes on the link.
    Multicast,
}

pub struct Receive<'input, A: AddressExt> {
    /// The interface the packet was received on.
    pub iface: InterfaceHandle,
    /// The address of the node that sent this packet.
    ///
    /// This **MUST** be the sender's own address, as reported by the transport, even when the
    /// datagram was sent to a multicast group. It is the only thing that identifies the
    /// neighbour: nothing inside a Babel packet names its sender. Use
    /// [`destination`](Self::destination) to convey that a datagram arrived over multicast.
    pub source_addr: Address<A>,
    /// How the datagram was addressed.
    pub destination: ReceiveDestination,
    /// The contents of the packet.
    pub contents: &'input [u8],
}

impl<A: AddressExt> Debug for Receive<'_, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receive")
            .field("iface", &self.iface)
            .field("source_addr", &self.source_addr)
            .field("destination", &self.destination)
            .field("content_len", &self.contents.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<A: AddressExt> defmt::Format for Receive<'_, A> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Receive{{ iface: {}, source_addr:{}, destination: {}, content_len: {}}}",
            &self.iface,
            &self.source_addr,
            &self.destination,
            &self.contents.len()
        )
    }
}
