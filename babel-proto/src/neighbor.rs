/// Opaque transport-layer address identifying a neighbor. The encoding is
/// determined by the transport — IPv6 link-local, EUI-64, LoRa device address,
/// etc. Addresses are right-aligned: unused leading bytes should be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NeighborId(pub [u8; 16]);

/// Per-neighbor state maintained by the local router (RFC 8966 §3.4).
///
/// The state machine checks `hello_expiry` and `ihu_expiry` against
/// `now.as_millis()` to detect dead neighbors without external timer
/// management.
#[derive(Debug, Clone, Copy)]
pub struct Neighbor {
    pub id: NeighborId,
    pub hello_seqno: u16,
    pub ihu_interval: u16,
    pub txcost: u16,
    pub rxcost: u16,
    /// Bitmask of recently received Hello sequence numbers, used to compute
    /// the reception ratio for link cost (RFC 8966 §3.4.3).
    pub hello_history: u16,
    /// Deadline in milliseconds by which the next Hello must arrive before the
    /// neighbor is considered unreachable; compare against
    /// `Instant::as_millis()` (RFC 8966 §3.4.2).
    pub hello_expiry: u64,
    /// Deadline in milliseconds by which the next IHU must arrive; compare
    /// against `Instant::as_millis()` (RFC 8966 §3.4.3).
    pub ihu_expiry: u64,
}

pub trait NeighborStore {
    type Error;

    type NeighborIter<'a>: Iterator<Item = &'a Neighbor>
    where
        Self: 'a;

    fn insert(&mut self, neighbor: Neighbor) -> Result<(), Self::Error>;
    fn remove(&mut self, id: &NeighborId);
    fn get(&self, id: &NeighborId) -> Option<&Neighbor>;
    fn get_mut(&mut self, id: &NeighborId) -> Option<&mut Neighbor>;
    fn iter(&self) -> Self::NeighborIter<'_>;
}
