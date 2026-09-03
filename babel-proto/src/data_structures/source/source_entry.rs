use crate::data_structures::source::SourceError;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, RouterId};
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

pub const SPEC_DEFAULT_SOURCE_GC_TIME: Duration = Duration::from_secs(3 * 60);

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SourceIndex<A: AddressExt> {
    pub(crate) router_id: RouterId,
    pub(crate) prefix: Address<A>,
    pub(crate) prefix_len: u8,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Source<A: AddressExt> {
    /// the prefix (prefix, plen), where plen is the prefix length in bits, that this entry applies
    /// to
    prefix: Address<A>,
    /// the prefix (prefix, plen), where plen is the prefix length in bits, that this entry applies
    /// to
    prefix_len: u8,
    /// the router-id of a router originating this prefix
    router_id: RouterId,
    /// a pair (seqno, metric), this source's feasibility distance.
    pub(crate) feasibility: Feasibility,
    /// There is one timer associated with each entry in the source table -- the source
    /// garbage-collection timer. It is initialised to a time on the order of minutes and reset as
    /// specified in [Section 3.7.3](https://datatracker.ietf.org/doc/html/rfc8966#maintaining-fd).
    pub(crate) gc_timer: Timer,
}

impl<A: AddressExt> InternallyKeyed for Source<A> {
    type Key = SourceIndex<A>;
    fn key(&self) -> Self::Key {
        SourceIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            router_id: self.router_id,
        }
    }
}

impl<A: AddressExt> Source<A> {
    pub(crate) fn new(
        now: Instant,
        prefix: Address<A>,
        prefix_len: u8,
        router_id: RouterId,
        seqno: SeqNo,
        metric: Metric,
        gc_interval: Duration,
    ) -> Result<Self, SourceError> {
        Ok(Self {
            prefix,
            prefix_len,
            router_id,
            feasibility: Feasibility::new(seqno, metric),
            gc_timer: Timer::from_duration(now, gc_interval)?,
        })
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
}
