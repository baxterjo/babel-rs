use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::updates::UpdateIndex;
use crate::data_types::destination::RouteDestination;
use crate::extension::address::AddressExt;
use crate::utils::destination::DestAddr;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Update<A: AddressExt> {
    /// The source this update is going out for.
    destination: RouteDestination<A>,
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
            destination: self.destination,
            neighbour: self.neighbour,
        }
    }
}

impl<A: AddressExt> Update<A> {
    pub(crate) fn new(
        now: Instant,
        destination: RouteDestination<A>,
        neighbour: NeighbourIndex<A>,
        mcast_allowed: bool,
        _ack: bool,
        retry_interval: Duration,
        send_count: u8,
    ) -> Self {
        // Retry count cannot be more than 5
        let send_count = send_count.min(5);

        Self {
            destination,
            neighbour,
            mcast_allowed,
            _ack: None,
            send_timer: Timer::eager_from_duration(now, retry_interval),
            send_count,
        }
    }

    // Accessors

    pub(crate) fn destination(&self) -> &RouteDestination<A> {
        &self.destination
    }
    pub(crate) fn neighbour(&self) -> &NeighbourIndex<A> {
        &self.neighbour
    }

    /// Takes over the send state of a newly queued update for the same (destination, neighbour)
    /// pair.
    ///
    /// All other fields
    pub(crate) fn refresh_from(&mut self, incoming: Self, urgent: bool) {
        // Destructured so that a new field on `Update` is a compile error here rather than a
        // silently stale value.
        let Self {
            destination: _,
            neighbour: _,
            mcast_allowed,
            _ack,
            // Do not refresh the send timer, this is how rate limiting is implemented.
            send_timer,
            send_count,
        } = incoming;

        self.mcast_allowed = mcast_allowed;
        self._ack = _ack;
        self.send_count = send_count;

        if urgent {
            self.send_timer = send_timer;
        }
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

    /// Whether writing this update would repeat a TLV the packet already carries.
    pub(crate) fn can_piggyback(
        &self,
        dest: &DestAddr<A>,
        sent_dest: &Option<RouteDestination<A>>,
    ) -> bool {
        // Mcast is allowed for this update
        self.mcast_allowed
            // The destination is mcast
            && dest.is_multicast()
                // The update has been writen into the packet.
                && sent_dest.is_some_and(|dest|dest == self.destination)
    }
}
