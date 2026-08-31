use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::route::RouteIndex;
use crate::data_structures::updates::{UpdateError, UpdateIndex};
use crate::extension::address::AddressExt;
use crate::utils::{Duration, Instant, InternallyKeyed, Timer};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Update<A: AddressExt> {
    /// The route that is being sent in the update.
    route: RouteIndex<A>,
    /// The neighbour that the update needs to go to.
    neighbour: NeighbourIndex<A>,
    /// Is mcast allowed for the update?
    pub(crate) mcast: bool,
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
            route: self.route,
            neighbour: self.neighbour,
        }
    }
}

impl<A: AddressExt> Update<A> {
    pub(crate) fn new(
        now: Instant,
        route: RouteIndex<A>,
        neighbour: NeighbourIndex<A>,
        mcast: bool,
        _ack: bool,
        retry_interval: Duration,
        send_count: u8,
    ) -> Result<Self, UpdateError> {
        // Retry count cannot be more than 5
        let send_count = send_count.min(5);
        Ok(Self {
            route,
            neighbour,
            mcast,
            _ack: None,
            send_timer: Timer::eager_from_duration(now, retry_interval)?,
            send_count,
        })
    }

    fn route(&self) -> &RouteIndex<A> {
        &self.route
    }

    fn neighbour(&self) -> &NeighbourIndex<A> {
        &self.neighbour
    }
}
