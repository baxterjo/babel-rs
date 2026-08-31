use thiserror::Error;

use crate::data_structures::neighbour::NeighbourIndex;
use crate::data_structures::route::RouteIndex;
use crate::extension::address::AddressExt;
use crate::utils::{
    Duration, Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt, Timer, TimerError,
};

#[derive(Debug, Error)]
pub enum UpdateError {
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error("Triggered update table is full")]
    UpdateTableFull,
}

/// Table for storing the state of triggered updates.
pub(crate) struct TriggeredUpdateTable<'storage, A: AddressExt> {
    inner: ManagedSlice<'storage, Option<Update<A>>>,
}

impl<'storage, A: AddressExt> TriggeredUpdateTable<'storage, A> {
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            inner: storage.into(),
        }
    }

    /// Adds an update destined to a neibour.
    ///
    /// Duplicate updates will silently overwrite old ones. This is by design, a freshly triggered
    /// route udpate **SHOULD** supercede a stale one.
    pub(crate) fn add_update(&mut self, update: Update<A>) -> Result<(), UpdateError> {
        self.inner
            .insert(update)
            .map_err(|_| UpdateError::UpdateTableFull)?;
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct UpdateIndex<A: AddressExt> {
    route: RouteIndex<A>,
    neighbour: NeighbourIndex<A>,
}

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
    pub(crate) retry_timer: Timer,
    /// Counter for resending the update.
    pub(crate) retry_count: u8,
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
    fn new(
        now: Instant,
        route: RouteIndex<A>,
        neighbour: NeighbourIndex<A>,
        mcast: bool,
        _ack: bool,
        retry_interval: Duration,
        retry_count: u8,
    ) -> Result<Self, UpdateError> {
        // Retry count cannot be more than 5
        let retry_count = retry_count.min(5);
        Ok(Self {
            route,
            neighbour,
            mcast,
            _ack: None,
            retry_timer: Timer::from_duration(now, retry_interval)?,
            retry_count,
        })
    }

    fn route(&self) -> &RouteIndex<A> {
        &self.route
    }

    fn neighbour(&self) -> &NeighbourIndex<A> {
        &self.neighbour
    }
}
