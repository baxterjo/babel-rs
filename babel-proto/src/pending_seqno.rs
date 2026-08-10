use managed::ManagedSlice;

use crate::{
    router::RouterId,
    storage::InternallyKeyed,
    time::{Duration as Interval, Instant},
    Address,
};

pub struct PendingSeqnoRequestTable<'storage, A: Address> {
    inner: ManagedSlice<'storage, Option<SeqnoRequest<A>>>,
}

pub struct SeqnoRequest<A: Address> {
    prefix: A,
    prefix_len: u8,
    router_id: RouterId,
    seqno: u16,
    retries: u8,

    last_try: Instant,
    retry_interval: Interval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct SeqnoRequestIndex<A: Address> {
    prefix: A,
    prefix_len: u8,
    router_id: RouterId,
}

impl<A: Address> InternallyKeyed for SeqnoRequest<A> {
    type Key = SeqnoRequestIndex<A>;
    fn key(&self) -> Self::Key {
        SeqnoRequestIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            router_id: self.router_id,
        }
    }
}
