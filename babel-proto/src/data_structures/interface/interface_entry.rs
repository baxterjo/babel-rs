use crate::data_structures::interface::{InterfaceConfig, InterfaceError, InterfaceHandle};
use crate::data_structures::seqno::SeqNo;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::{IhuRatio, LinkCostCalculator};
use crate::utils::{DurationMultiplier, Instant, InternallyKeyed, Timer};

/// Interfaces that speak the Babel Protocol
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Interface<A: AddressExt> {
    // Spec values
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    pub(crate) handle: InterfaceHandle,

    /// The address this node can be reached at on this iterface.
    pub(crate) address: Address<A>,

    /// Mcast hello seqno.
    pub(crate) hello_seqno: SeqNo,

    /// How often this interface should mcast send hello messages.
    pub(crate) hello_timer: Timer,

    /// How often this interface should send update messages
    pub(crate) update_timer: Timer,

    // User config
    /// Flag that indicates this interface should send unicast IHUs.
    pub(crate) unicast_ihu: bool,

    /// This interface gives this interval to new neighbour table entries when new neighbours are
    /// discovered. The router will then send unicast hellos to this neighbour at this interval.
    /// This defaults to None as most babel speakers should prefer multicast hellos.
    pub(crate) ucast_hello_interval: Option<Interval>,

    /// IHU hold time multipliers for neighbours heard on this interface.
    ///
    /// When a neighbour sends an IHU on this interface, the interval advertised in the IHU TLV is
    /// multiplied by this value to create an IHU hold timer.
    pub(crate) ihu_hold_time_multiple: DurationMultiplier,

    /// Link cost calculator
    pub(crate) cost_calc: &'static dyn LinkCostCalculator,
}

impl<A: AddressExt> InternallyKeyed for Interface<A> {
    type Key = InterfaceHandle;
    fn key(&self) -> Self::Key {
        self.handle
    }
}

impl<A: AddressExt> Interface<A> {
    /// Creates a new babel interface with the given interface ID.
    pub fn new(now: Instant, config: InterfaceConfig<A>) -> Result<Self, InterfaceError> {
        Ok(Self {
            handle: config.id,
            address: config.address,
            hello_timer: Timer::eager_from_interval(now, config.mcast_hello_interval)?,
            ucast_hello_interval: config.ucast_hello_interval,
            hello_seqno: SeqNo::default(),
            update_timer: Timer::from_interval(
                now,
                config
                    .update_interval_spec
                    .apply_to_interval(config.mcast_hello_interval),
            )?,
            unicast_ihu: config.unicast_ihu,
            ihu_hold_time_multiple: config.ihu_hold_time,
            cost_calc: config.cost_calc,
        })
    }
}
