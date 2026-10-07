use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::utils::Instant;
use crate::utils::storage::InternallyKeyed;
/// 3.2.7-1: The table of pending seqno requests contains a list of seqno requests that the local
///
/// node has sent (either because they have been originated locally, or because they were forwarded)
/// and to which no reply has been received yet. This table is indexed by triples of the form
/// (prefix, plen, router-id) (see [`SeqnoRequestIndex`]), and every entry in this table contains
/// the following data:
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SeqnoRequest<A: AddressExt> {
    /// 3.2.7-2.1: the prefix [...] being requested
    prefix: Address<A>,
    /// 3.2.7-2.1: the [...] plen [...] being requested
    prefix_len: u8,
    /// 3.2.7-2.1: the [...] router-id [...] being requested
    router_id: RouterId,
    /// 3.2.7-2.1: the [...] seqno being requested
    seqno: SeqNo,
    /// 3.2.7-2.2: the neighbour, if any, on behalf of which we are forwarding this request
    neighbor: Option<NeighbourIndex<A>>,
    /// 3.2.7-2.3: a small integer indicating the number of times that this request will be resent
    /// if it remains unsatisfied
    retries: u8,

    /// 3.2.7-3: There is one timer associated with each pending seqno request; it governs both the
    /// resending of requests and their expiry
    last_try: Instant,
    retry_interval: Interval,
}

/// 3.2.7-1: [...] This table is indexed by triples of the form (prefix, plen, router-id) [...]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SeqnoRequestIndex<A: AddressExt> {
    prefix: Address<A>,
    prefix_len: u8,
    router_id: RouterId,
}

impl<A: AddressExt> InternallyKeyed for SeqnoRequest<A> {
    type Key = SeqnoRequestIndex<A>;
    fn key(&self) -> Self::Key {
        SeqnoRequestIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            router_id: self.router_id,
        }
    }
}
