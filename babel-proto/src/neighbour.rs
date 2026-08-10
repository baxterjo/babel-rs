use managed::ManagedSlice;

use crate::{
    interface::InterfaceHandle,
    storage::InternallyKeyed,
    time::{Duration as Interval, Instant},
    Address,
};

pub struct NeighbourTable<'storage, A>
where
    A: Address,
{
    inner: ManagedSlice<'storage, Neighbour<A>>,
    /// The hold time of a neighbour between receiving IHU TLVs.
    hold_time: HoldTimeMultiplier,
}

impl<'storage, A> NeighbourTable<'storage, A>
where
    A: Address,
{
    /// Create a new interface table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of neighbors this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment.
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Neighbour<A>>>,
    {
        Self {
            inner: table.into(),
            hold_time: HoldTimeMultiplier::SPEC_DEFAULT,
        }
    }

    /// Create a new interface table.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
            hold_time: HoldTimeMultiplier::SPEC_DEFAULT,
        }
    }
}

pub struct HoldTimeMultiplier {
    pub num: u8,
    pub den: u8,
}

impl HoldTimeMultiplier {
    /// appendix.b-4.12: "IHU Hold time: 3.5 times the advertised IHU interval."
    const SPEC_DEFAULT: Self = Self { num: 7, den: 2 };

    fn apply(&self, interval: u16) -> Interval {
        Interval::from_centis((interval as u64 * self.num as u64) / self.den as u64)
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct NeighbourIndex<A>(InterfaceHandle, A)
where
    A: Address;

pub struct Neighbour<A: Address> {
    /// 3.2.4-2.1: "the local node's interface over which this neighbour is reachable"
    iface: InterfaceHandle,
    /// 3.2.4-2.2: "the address of the neighbouring interface"
    address: A,
    /// 3.2.4-2.3: "a history of recently received Multicast Hello packets from this neighbour; this
    /// can, for example, be a sequence of n bits, for some small value n, indicating which of the n
    /// hellos most recently sent by this neighbour have been received by the local node."
    mcast_hello_history: u8,
    /// 3.2.4-2.4: "a history of recently received Unicast Hello packets from this neighbour"
    ucast_hello_history: u8,
    /// 3.2.4-2.5: "the 'transmission cost' value from the last IHU packet received from this
    /// neighbour, or FFFF hexadecimal (infinity) if the IHU hold timer for this neighbour has
    /// expired"
    tx_cost: u16,
    /// 3.2.4-2.6: "the expected incoming Multicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16"
    expected_mcast_seqno: u16,
    /// 3.2.4-2.7: "the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16"
    expected_ucast_seqno: u16,
    /// 3.2.4-2.8: "the outgoing Unicast Hello sequence number for this neighbour, an integer modulo
    /// 2^16 that is sent with each Unicast Hello TLV to this neighbour and is incremented (modulo
    /// 2^16) whenever a Unicast Hello is sent. (Note that the outgoing Unicast Hello seqno for a
    /// neighbour is distinct from the interface's outgoing Multicast Hello seqno.)"
    outgoing_ucast_seqno: u16,

    timers: NeighbourTimers,
}

/// 3.2.4-3: There are three timers associated with each neighbour entry -- the multicast hello
/// timer, which is set to the interval value carried by scheduled Multicast Hello TLVs sent by this
/// neighbour, the unicast hello timer, which is set to the interval value carried by scheduled
/// Unicast Hello TLVs, and the IHU timer, which is set to a small multiple of the interval carried
/// in IHU TLVs (see "IHU Hold time" in Appendix B for suggested values).
struct NeighbourTimers {
    mcast_hello_interval: Interval,
    last_mcast: Instant,

    ucast_hello_interval: Interval,
    last_ucast: Instant,

    ihu_interval: Interval,
    last_ihu: Instant,
}

impl<A: Address> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex(self.iface, self.address)
    }
}
