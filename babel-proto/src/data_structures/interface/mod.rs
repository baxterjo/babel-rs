use core::fmt::Display;

use thiserror::Error;

pub mod interface_entry;
pub(crate) mod interface_table;

pub use interface_entry::Interface;
pub(crate) use interface_table::InterfaceTable;

use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::metric::{KOutOfJ, LinkCostCalculator};
use crate::utils::short_id::fmt_short_id;
use crate::utils::time::DurationSpec;
use crate::utils::{Duration, TimerError};

/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
pub const DEFAULT_MULTICAST_HELLO_INTERVAL: Duration =
    Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS);
/// Recommended message intervals indicated in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4;
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(DEFAULT_UPDATE_INTERVAL_SECS);

/// An interface handle is used to reference a registered interface f:willor incoming and outgoing
/// operations.
///
/// Users should use this handle to index the interfaces that will speak Babel.
#[derive(Debug, Clone, Copy, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceHandle([u8; 8]);

impl TryFrom<&str> for InterfaceHandle {
    type Error = InterfaceError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value.len() > 8 {
            return Err(InterfaceError::IdTooLong { len: value.len() });
        }
        // At this point value is known to be <= 8 bytes.
        let in_bytes = value.as_bytes();
        let mut id_bytes = [0u8; 8];

        for (idx, byte) in in_bytes.iter().rev().enumerate() {
            id_bytes[id_bytes.len() - 1 - idx] = *byte;
        }
        Ok(Self(id_bytes))
    }
}

impl Display for InterfaceHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt_short_id(&self.0, f)
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct InterfaceConfig<A: AddressExt> {
    pub(crate) id: InterfaceHandle,
    pub(crate) address: Address<A>,
    pub(crate) mcast_hello_interval: Duration,
    pub(crate) ucast_hello_interval: Option<Duration>,
    pub(crate) update_interval_spec: DurationSpec,
    pub(crate) unicast_ihu: bool,
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
            mcast_hello_interval: DEFAULT_MULTICAST_HELLO_INTERVAL,
            ucast_hello_interval: None,
            update_interval_spec: DurationSpec::UPDATE_SPEC,
            unicast_ihu: false,
            cost_calc: &COST_CALC,
        }
    }

    /// Sets the multicast hello interval for this interface.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_mcast_hello_interval(&mut self, duration: Duration) {
        let mut new = duration;
        new.clamp_to_wire();
        if new != duration {
            b_debug!(
                "Clamping MCAST hello to 1 <= dur <= {} centiseconds",
                u16::MAX
            );
        }
        self.mcast_hello_interval = new;
    }

    /// Sets the unicast hello interval for this interface.
    ///
    /// This defaults to None as most Babel speakers should prefer to send only mcast hellos.
    ///
    /// The given interval will be clamped to `1 <= duration <= u16::MAX centiseconds`
    pub fn set_ucast_hello_interval(&mut self, duration: Duration) {
        let mut new = duration;
        new.clamp_to_wire();
        if new != duration {
            b_debug!(
                "Clamping UCAST hello to 1 <= dur <= {} centiseconds",
                u16::MAX
            );
        }
        self.ucast_hello_interval = Some(new);
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

    pub fn set_update_duration_spec(&mut self, spec: DurationSpec) {
        self.update_interval_spec = spec;
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum InterfaceError {
    /// The storage given for the interface table is full.
    #[error("Interface table is full")]
    Full,
    /// In this instance the interface is still registered in the interface table, and the handle
    /// inside the error is still valid for referencing the interface. The user can decide what
    /// they want to do with this error.
    #[error("An interface with the same ID was registered twice.")]
    DuplicateInterfaceId(InterfaceHandle),
    #[error("Given interface ID is too long - max: 8, len: {}", len)]
    IdTooLong { len: usize },
    /// The router was polled before any interface was registered, so it has nothing it could
    /// ever send.
    #[error("No interfaces are registered")]
    NoInterfacesRegistered,
    #[error(transparent)]
    Timer(#[from] TimerError),
}
