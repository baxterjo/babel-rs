use crate::data_structures::neighbour::NeighbourIndex;
<<<<<<< HEAD
use crate::data_structures::route::RouteIndex;
=======
>>>>>>> b0379f1 (chore: PR review comments)
use crate::data_structures::updates::{UpdateError, UpdateIndex};
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::utils::destination::DestAddr;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Update<A: AddressExt> {
    /// The destination (prefix, plen) this update is advertising
    prefix: Address<A>,
    prefix_len: u8,
    /// The neighbour that the update needs to go to.
    neighbour: NeighbourIndex<A>,
    /// Is mcast allowed for the update?
    ///
    /// This value is not prescriptive, just because mcast is allowed does not mean the update WILL
    /// be sent via mcast. It MAY buffer with a pre-existing unicast packet.
    ///
    /// Inversely, if this value is false this update WILL NOT be sent over mcast
    pub(crate) mcast_allowed: bool,
    /// If an ack request is to be sent, this will contain the opaque value.
    //
    pub(crate) _ack: Option<u16>,
    /// Timer for resending the update.
    pub(crate) send_timer: Timer,
    /// Counter for resending the update.
    pub(crate) send_count: u8,
}

impl<A: AddressExt> InternallyKeyed for Update<A> {
    type Key = UpdateIndex<A>;
    fn key(&self) -> Self::Key {
        UpdateIndex {
            prefix: self.prefix,
            prefix_len: self.prefix_len,
            neighbour: self.neighbour,
        }
    }
}

impl<A: AddressExt> Update<A> {
    pub(crate) fn new(
        now: Instant,
        prefix: Address<A>,
        prefix_len: u8,
        neighbour: NeighbourIndex<A>,
        mcast_allowed: bool,
        _ack: bool,
        retry_interval: Duration,
        send_count: u8,
    ) -> Result<Self, UpdateError> {
        // Retry count cannot be more than 5
        let send_count = send_count.min(5);
        Ok(Self {
            prefix,
            prefix_len,
            neighbour,
            mcast_allowed,
            _ack: None,
            send_timer: Timer::eager_from_duration(now, retry_interval)?,
            send_count,
        })
    }

<<<<<<< HEAD
    /// Takes over the send state of a newly queued update for the same (route, neighbour) pair.
    pub(crate) fn refresh_from(&mut self, incoming: Self) {
        // Destructured so that a new field on `Update` is a compile error here rather than a
        // silently stale value.
        let Self {
            route: _,
            neighbour: _,
            mcast_allowed,
            _ack,
            send_timer,
            send_count,
        } = incoming;

        self.mcast_allowed = mcast_allowed;
        self._ack = _ack;
        self.send_timer = send_timer;
        self.send_count = send_count;
    }

    pub(crate) fn route(&self) -> &RouteIndex<A> {
        &self.route
    }
=======
    //pub(crate) fn route(&self) -> &RouteIndex<A> {
    //    &self.route
    //}
>>>>>>> b0379f1 (chore: PR review comments)

    pub(crate) fn neighbour(&self) -> &NeighbourIndex<A> {
        &self.neighbour
    }

    pub(crate) fn can_send(&self, dest: &DestAddr<A>) -> bool {
        // Destination is free
        dest.is_free()
            // OR mcast is allowed and dest is mcast
            || (self.mcast_allowed && dest.is_multicast())
                // OR dest is already going to this neighbour.
                || dest
                    .unicast_addr()
                    .is_some_and(|addr| addr == &self.neighbour().addr)
    }

    pub(crate) fn would_duplicate(
        &self,
        dest: &DestAddr<A>,
        sent_update: &Option<(Address<A>, u8)>,
    ) -> bool {
        // Mcast is allowed for this update
        self.mcast_allowed
            // The destination is mcast
            && dest.is_multicast()
                // The update has been writen into the packet.
                && sent_update.is_some_and(|idx| &idx == &(self.prefix, self.prefix_len))
    }
}
