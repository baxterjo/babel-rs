use crate::data_structures::interface::{DEFAULT_MULTICAST_HELLO_INTERVAL, InterfaceHandle};
use crate::data_structures::neighbour::DEFAULT_HOLD_TIME_MULTIPLIER;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::{KOutOfJ, LinkCostCalculator};
use crate::utils::DurationMultiplier;
use crate::utils::time::DurationSpec;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceConfig<A: AddressExt> {
    pub(crate) id: InterfaceHandle,
    pub(crate) address: Address<A>,
    pub(crate) mcast_hello_interval: Interval,
    pub(crate) ucast_hello_interval: Option<Interval>,
    pub(crate) update_interval_spec: DurationSpec,
    pub(crate) unicast_ihu: bool,
    pub(crate) ihu_hold_time: DurationMultiplier,
    pub(crate) cost_calc: &'static dyn LinkCostCalculator,
}

impl<A: AddressExt> InterfaceConfig<A> {
    /// Create a new InterfaceConfig.
    ///
    /// Arguments:
    /// * `id`: ID that will be used to reference this interface for debugging and packet routing.
    /// * `address`: Address that this node can be reached on through this interface.
    pub fn new_wired<I>(id: I, address: Address<A>) -> Self
    where
        I: Into<InterfaceHandle>,
    {
        let id = id.into();
        const COST_CALC: KOutOfJ = KOutOfJ::SPEC;
        Self {
            id,
            address,
            mcast_hello_interval: DEFAULT_MULTICAST_HELLO_INTERVAL.into(),
            ucast_hello_interval: None,
            update_interval_spec: DurationSpec::UPDATE_SPEC,
            ihu_hold_time: DEFAULT_HOLD_TIME_MULTIPLIER,
            unicast_ihu: false,
            cost_calc: &COST_CALC,
        }
    }

    /// Sets the multicast hello interval for this interface.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_mcast_hello_interval(&mut self, interval: Interval) {
        self.mcast_hello_interval = interval;
    }

    /// Sets the unicast hello interval for this interface.
    ///
    /// This defaults to None as most Babel speakers should prefer to send only mcast hellos.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_ucast_hello_interval(&mut self, interval: Interval) {
        self.ucast_hello_interval = Some(interval);
    }

    /// Sets whether IHUs coming from this interface should be unicast.
    ///
    /// When set to false, IHU's from this interface will be generated with a
    /// [`TransmitDestination::Multicast`](crate::output::TransmitDestination) destination.
    pub fn set_unicast_ihu(&mut self, value: bool) {
        self.unicast_ihu = value
    }

    /// Sets the cost calculator of this interface to a user provided struct.
    pub fn set_cost_calculator(&mut self, calculator: &'static dyn LinkCostCalculator) {
        self.cost_calc = calculator;
    }

    /// Sets the duration spec for update time
    pub fn set_update_duration_spec(&mut self, spec: DurationSpec) {
        self.update_interval_spec = spec;
    }

    /// Set the IHU hold time multiple for neighbours heard on this interface.
    ///
    /// When receiving an IHU from a neighbour on this interface, the interval advertised in the IHU
    /// TLV is multiplied by this value to create an IHU hold timer.
    pub fn set_ihu_hold_time_multiple(&mut self, mul: DurationMultiplier) {
        self.ihu_hold_time = mul;
    }
}
