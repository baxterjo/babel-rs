use crate::{neighbor::NeighborStore, route::RouteTable, router_id::RouterId, source::SourceTable};

pub struct BabelRouter<N: NeighborStore, R: RouteTable, S: SourceTable> {
    router_id: RouterId,
    seq_no: u16,
    neighbors: N,
    routes: R,
    sources: S,
}

impl<N: NeighborStore, R: RouteTable, S: SourceTable> BabelRouter<N, R, S> {
    pub fn new(router_id: RouterId, neighbors: N, routes: R, sources: S) -> Self {
        Self {
            router_id,
            seq_no: 0,
            neighbors,
            routes,
            sources,
        }
    }
}
