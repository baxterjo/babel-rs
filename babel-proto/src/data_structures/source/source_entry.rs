use crate::data_structures::source::SourceError;
use crate::data_types::RouterId;
use crate::data_types::destination::RouteDestination;
use crate::data_types::seqno::SeqNo;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

pub const SPEC_DEFAULT_SOURCE_GC_TIME: Duration = Duration::from_secs(3 * 60);

#[derive(Debug, PartialEq, PartialOrd, Eq, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SourceIndex<A: AddressExt> {
    pub(crate) router_id: RouterId,
    pub(crate) destination: RouteDestination<A>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Source<A: AddressExt> {
    /// the prefix (prefix, plen), where plen is the prefix length in bits, that this entry applies
    /// to
    destination: RouteDestination<A>,

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
            destination: self.destination,
            router_id: self.router_id,
        }
    }
}

impl<A: AddressExt> Source<A> {
    pub(crate) fn new(
        now: Instant,
        index: SourceIndex<A>,
        seqno: SeqNo,
        metric: Metric,
        gc_interval: Duration,
    ) -> Result<Self, SourceError<A>> {
        Ok(Self {
            destination: index.destination,
            router_id: index.router_id,
            feasibility: Feasibility::new(seqno, metric),
            gc_timer: Timer::from_duration(now, gc_interval)?,
        })
    }
    pub(crate) fn destination(&self) -> &RouteDestination<A> {
        &self.destination
    }

    pub(crate) fn router_id(&self) -> &RouterId {
        &self.router_id
    }
}
