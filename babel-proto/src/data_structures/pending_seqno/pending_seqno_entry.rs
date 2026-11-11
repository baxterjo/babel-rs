use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::utils::storage::InternallyKeyed;
use crate::utils::{Instant, Timer};

/// 3.2.7-1: [...] This table is indexed by triples of the form (prefix, plen, router-id) [...]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SeqnoRequestIndex<A: AddressExt> {
    prefix: Address<A>,
    prefix_len: u8,
    router_id: RouterId,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
enum TryCounter {
    FirstGo(u8),
    Retry(u8),
}
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
    pub(crate) seqno: SeqNo,
    /// 3.2.7-2.2: the neighbour, if any, on behalf of which we are forwarding this request
    pub(crate) neighbour: Option<NeighbourIndex<A>>,
    /// 3.2.7-2.3: a small integer indicating the number of times that this request will be resent
    /// if it remains unsatisfied
    pub(crate) retries: TryCounter,

    /// 3.2.7-3: There is one timer associated with each pending seqno request; it governs both the
    /// resending of requests and their expiry
    pub(crate) retry_timer: Timer,

    /// The original hop count from this seqno request.
    hop_count: u8,
}

impl<A: AddressExt> SeqnoRequest<A> {
    pub(crate) fn new(
        now: Instant,
        prefix: Address<A>,
        prefix_len: u8,
        router_id: RouterId,
        seqno: SeqNo,
        neighbour: Option<NeighbourIndex<A>>,
        retries: u8,
        retry_interval: Interval,
        hop_count: u8,
    ) -> Self {
        Self {
            prefix,
            prefix_len,
            router_id,
            seqno,
            neighbour,
            retries: TryCounter::FirstGo(retries.min(3)),
            retry_timer: Timer::eager_from_interval(now, retry_interval),
            hop_count,
        }
    }

    pub(crate) fn prefix(&self) -> &Address<A> {
        &self.prefix
    }

    pub(crate) fn prefix_len(&self) -> &u8 {
        &self.prefix_len
    }

    pub(crate) fn router_id(&self) -> &RouterId {
        &self.router_id
    }

    pub(crate) fn hop_count(&self) -> &u8 {
        &self.hop_count
    }
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
