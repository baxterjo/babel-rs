use crate::{neighbor::NeighborId, prefix::Prefix, router_id::RouterId};

/// A single entry in the route table (RFC 8966 §3.2.5).
///
/// The state machine checks `expires_at` against `now.as_millis()` to expire
/// stale routes without external timer management.
#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub prefix: Prefix,
    pub router_id: RouterId,
    pub neighbor: NeighborId,
    /// `0xFFFF` signals retraction (infinite metric).
    pub metric: u16,
    pub seq_no: u16,
    /// Opaque transport-layer next-hop address. Same encoding contract as
    /// `NeighborId` — right-aligned, unused leading bytes should be zero.
    pub next_hop: [u8; 16],
    /// Expiry time in milliseconds; compare against `Instant::as_millis()`
    /// (RFC 8966 §3.5.2).
    pub expires_at: u64,
}

pub trait RouteTable {
    type Error;

    /// Insert or replace the selected route for `route.prefix`. The state
    /// machine is responsible for checking feasibility (RFC 8966 §3.5.1)
    /// before calling this.
    fn insert(&mut self, route: Route) -> Result<(), Self::Error>;
    fn remove(&mut self, prefix: &Prefix, neighbor: &NeighborId);
    fn get(&self, prefix: &Prefix) -> Option<&Route>;

    /// Returns all feasible routes for `prefix` — those whose metric satisfies
    /// `metric < feasibility_distance` (RFC 8966 §3.5.1).
    ///
    /// The default implementation yields only the single selected route if it
    /// is feasible. Implementations that track multiple routes per prefix
    /// (RFC 8966 §3.6 SHOULD) can override this to yield all of them.
    fn feasible_routes(
        &self,
        prefix: &Prefix,
        feasibility_distance: u16,
    ) -> impl Iterator<Item = &Route> {
        self.get(prefix)
            .filter(move |r| r.metric < feasibility_distance)
            .into_iter()
    }
}
