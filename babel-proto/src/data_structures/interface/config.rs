use crate::data_structures::interface::interface_entry::MAX_OTHER_ADDRESSES;
use crate::data_structures::interface::{
    DEFAULT_MULTICAST_HELLO_INTERVAL, InterfaceError, InterfaceHandle,
};
use crate::data_structures::neighbour::DEFAULT_HOLD_TIME_MULTIPLIER;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::{KOutOfJ, LinkCostCalculator};
use crate::utils::time::DurationSpec;
use crate::utils::{Duration, DurationMultiplier};

/// Default interval between unicast retries of an update that has not been acknowledged.
///
/// Matches the retransmission interval recommended in
/// [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_RETRY_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(2));

/// Default number of times an unacknowledged unicast update is retried before being given up on.
pub const DEFAULT_WIRED_UPDATE_RETRY_LIMIT: u8 = 2;

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceConfig<A: AddressExt> {
    pub(crate) id: InterfaceHandle,
    pub(crate) address: Address<A>,
    pub(crate) other_addresses: [Option<Address<A>>; MAX_OTHER_ADDRESSES],
    pub(crate) mcast_hello_interval: Interval,
    pub(crate) ucast_hello_interval: Option<Interval>,
    pub(crate) update_interval_spec: DurationSpec,
    pub(crate) ihu_hold_time: DurationMultiplier,
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    pub(crate) cost_calc: &'static dyn LinkCostCalculator,
    pub(crate) prefer_ucast: bool,
    pub(crate) update_retry_interval: Interval,
    pub(crate) update_retry_limit: u8,
    pub(crate) request_acks: bool,
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
            other_addresses: [const { None }; MAX_OTHER_ADDRESSES],
            mcast_hello_interval: DEFAULT_MULTICAST_HELLO_INTERVAL.into(),
            ucast_hello_interval: None,
            update_interval_spec: DurationSpec::UPDATE_SPEC,
            ihu_hold_time: DEFAULT_HOLD_TIME_MULTIPLIER,
            cost_calc: &COST_CALC,
            prefer_ucast: false,
            update_retry_interval: DEFAULT_UPDATE_RETRY_INTERVAL,
            update_retry_limit: DEFAULT_WIRED_UPDATE_RETRY_LIMIT,
            request_acks: false,
        }
    }

    /// The handle used to reference this interface for debugging and packet routing.
    pub fn id(&self) -> InterfaceHandle {
        self.id
    }

    /// The address that this node can be reached on through this interface.
    pub fn address(&self) -> Address<A> {
        self.address
    }

    /// Sets the address that this node can be reached on through this interface.
    pub fn set_address(&mut self, address: Address<A>) {
        self.address = address;
    }

    /// Adds an address in another address family that this interface can be reached at.
    ///
    /// Babel traffic is never sent from these; they exist so that routes in a family other than
    /// [`Self::address`]'s can be advertised on this interface. A packet seeds the receiver's next
    /// hop for its own family only
    /// ([Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)),
    /// so a route in any other family needs an explicit Next-Hop TLV, rendered from the address
    /// added here. Without one, routes in that family cannot be advertised on this interface.
    ///
    /// Only the first address per family is meaningful, so adding a second in a family this
    /// interface already covers — including [`Self::address`]'s own — is rejected rather than
    /// silently ignored.
    pub fn add_other_address(&mut self, address: Address<A>) -> Result<(), InterfaceError> {
        let family = address.encoding().address_family();
        let covered = core::iter::once(&self.address)
            .chain(self.other_addresses.iter().flatten())
            .any(|existing| existing.encoding().address_family() == family);
        if covered {
            return Err(InterfaceError::DuplicateAddressFamily);
        }

        let slot = self
            .other_addresses
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(InterfaceError::TooManyOtherAddresses {
                max: MAX_OTHER_ADDRESSES,
            })?;
        *slot = Some(address);
        Ok(())
    }

    /// The addresses in other families this interface can be reached at, in insertion order.
    pub fn other_addresses(&self) -> impl Iterator<Item = &Address<A>> {
        self.other_addresses.iter().flatten()
    }

    /// The multicast hello interval for this interface.
    pub fn mcast_hello_interval(&self) -> Interval {
        self.mcast_hello_interval
    }

    /// Sets the multicast hello interval for this interface.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_mcast_hello_interval(&mut self, interval: Interval) {
        self.mcast_hello_interval = interval.max(Duration::from_centis(1).into());
    }

    /// The unicast hello interval for this interface, or `None` if only mcast hellos are sent.
    pub fn ucast_hello_interval(&self) -> Option<Interval> {
        self.ucast_hello_interval
    }

    /// Sets the unicast hello interval for this interface.
    ///
    /// This defaults to None as most Babel speakers should prefer to send only mcast hellos.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_ucast_hello_interval(&mut self, interval: Interval) {
        self.ucast_hello_interval = Some(interval.max(Duration::from_centis(1).into()));
    }

    /// Stops unicast hellos from being sent on this interface, returning it to the default of
    /// sending only mcast hellos.
    pub fn clear_ucast_hello_interval(&mut self) {
        self.ucast_hello_interval = None;
    }

    /// The cost calculator used to derive link costs for neighbours on this interface.
    pub fn cost_calculator(&self) -> &'static dyn LinkCostCalculator {
        self.cost_calc
    }

    /// Sets the cost calculator of this interface to a user provided struct.
    pub fn set_cost_calculator(&mut self, calculator: &'static dyn LinkCostCalculator) {
        self.cost_calc = calculator;
    }

    /// The duration spec for update time.
    pub fn update_duration_spec(&self) -> DurationSpec {
        self.update_interval_spec
    }

    /// Sets the duration spec for update time
    pub fn set_update_duration_spec(&mut self, spec: DurationSpec) {
        self.update_interval_spec = spec;
    }

    /// The IHU hold time multiple for neighbours heard on this interface.
    ///
    /// When receiving an IHU from a neighbour on this interface, the interval advertised in the IHU
    /// TLV is multiplied by this value to create an IHU hold timer.
    pub fn ihu_hold_time_multiple(&self) -> DurationMultiplier {
        self.ihu_hold_time
    }

    /// Set the IHU hold time multiple for neighbours heard on this interface.
    ///
    /// When receiving an IHU from a neighbour on this interface, the interval advertised in the IHU
    /// TLV is multiplied by this value to create an IHU hold timer.
    pub fn set_ihu_hold_time_multiple(&mut self, mul: DurationMultiplier) {
        self.ihu_hold_time = mul;
    }

    /// Whether updates on this interface are sent to each neighbour by unicast rather than to the
    /// interface by multicast.
    pub fn prefer_ucast(&self) -> bool {
        self.prefer_ucast
    }

    /// Sets whether updates on this interface are sent to each neighbour by unicast rather than to
    /// the interface by multicast.
    ///
    /// This defaults to `false`, as most Babel speakers should prefer multicast updates.
    pub fn set_prefer_ucast(&mut self, prefer_ucast: bool) {
        self.prefer_ucast = prefer_ucast;
    }

    /// The interval between retries of an unacknowledged unicast update on this interface.
    pub fn ucast_retry_interval(&self) -> Interval {
        self.update_retry_interval
    }

    /// Sets the interval between retries of an unacknowledged unicast update on this interface.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_ucast_retry_interval(&mut self, interval: Interval) {
        self.update_retry_interval = interval.max(Duration::from_centis(1).into());
    }

    /// The number of times an unacknowledged unicast update is retried before being given up on.
    pub fn ucast_retry_limit(&self) -> u8 {
        self.update_retry_limit
    }

    /// Sets the number of times an unacknowledged unicast update is retried before being given up
    /// on.
    ///
    /// A limit of `0` disables retries; the update is sent once regardless of acknowledgement.
    pub fn set_ucast_retry_limit(&mut self, limit: u8) {
        self.update_retry_limit = limit.min(5);
    }

    /// Whether unicast updates sent on this interface carry an Acknowledgment Request TLV.
    pub fn request_acks(&self) -> bool {
        self.request_acks
    }

    /// Sets whether unicast updates sent on this interface carry an Acknowledgment Request TLV.
    ///
    /// Acknowledgments only apply to unicast traffic, so this has no effect while
    /// [`Self::prefer_ucast`] is `false`.
    pub fn set_request_acks(&mut self, request_acks: bool) {
        self.request_acks = request_acks;
    }
}
