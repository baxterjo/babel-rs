use crate::{prefix::Prefix, router_id::RouterId};

/// An entry in the source table, tracking the best (lowest) metric ever seen
/// for a given (prefix, router-id) pair. Used to evaluate the feasibility
/// condition for route selection (RFC 8966 §3.2.6).
#[derive(Debug, Clone, Copy)]
pub struct Source {
    pub prefix: Prefix,
    pub router_id: RouterId,
    /// The lowest metric observed for this source — used as the feasibility
    /// distance when evaluating candidate routes.
    pub feasibility_distance: u16,
    pub seq_no: u16,
}

pub trait SourceTable {
    type Error;

    fn get(&self, prefix: &Prefix, router_id: &RouterId) -> Option<&Source>;

    /// Insert or update the feasibility distance for `(prefix, router_id)`.
    ///
    /// Implementations should only lower the feasibility distance, never raise
    /// it — consistent with RFC 8966 §3.5.1. Callers are responsible for
    /// checking the feasibility condition before calling this.
    fn update(
        &mut self,
        prefix: Prefix,
        router_id: RouterId,
        metric: u16,
        seq_no: u16,
    ) -> Result<(), Self::Error>;

    fn feasibility_distance(&self, prefix: &Prefix, router_id: &RouterId) -> u16;
}
