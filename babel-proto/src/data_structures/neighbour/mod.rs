use thiserror::Error;

pub(crate) mod neighbour_entry;
pub(crate) mod neighbour_table;

pub use neighbour_entry::{Neighbour, NeighbourIndex};
pub use neighbour_table::NeighbourTable;

use crate::data_structures::interface::{
    DEFAULT_MULTICAST_HELLO_INTERVAL, Interface, InterfaceHandle,
};
use crate::data_types::address::AddressError;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::IhuRatio;
use crate::packet::error::tlv_err::TlvError;
use crate::utils::{DurationMultiplier, TimerError};

/// Lossless link IHU ratio as defined in [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.8)
///
/// This is the ratio of Mcast Hellos to IHUs **SENT** to a neighbour.
///
/// The **advertised** IHU interval is always 3 times the Multicast Hello interval. IHUs are
/// actually sent with each Hello on lossy links (as determined from the Hello history), but only
/// with every third Multicast Hello on lossless links.
pub const DEFAULT_LOSSLESS_IHU_RATIO: IhuRatio = IhuRatio::new(3, 1);

/// Lossy link IHU ratio as defined in [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.8)
///
/// This is the ratio of Mcast Hellos to IHUs **SENT** to a neighbour.
///
/// The **advertised** IHU interval is always 3 times the Multicast Hello interval. IHUs are
/// actually sent with each Hello on lossy links (as determined from the Hello history), but only
/// with every third Multicast Hello on lossless links.
pub const DEFAULT_LOSSY_IHU_RATIO: IhuRatio = IhuRatio::new(1, 1);

/// [Appendix B](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.12) 3.5 times
/// the advertised IHU interval.
///
/// This is the jitter applied to the advertised IHU interval **RECEIVED** from a neighbour.
pub const DEFAULT_HOLD_TIME_MULTIPLIER: DurationMultiplier = DurationMultiplier::new(7, 2);

/// [Appendix A.1](https://datatracker.ietf.org/doc/html/rfc8966#section-a.1-4)
/// If the Interval field of the received Hello is not zero, it resets the neighbour's hello timer
/// to 1.5 times the advertised Interval (the extra margin allows for delay due to jitter).
pub const HELLO_INTERVAL_MULTIPLIER: DurationMultiplier = DurationMultiplier::new(3, 2);

pub struct NeighbourConfig<A: AddressExt> {
    /// The interface on which this neighbour can be reached.
    iface: InterfaceHandle,
    /// The address at which this neighbour can be reached on its interface.
    address: Address<A>,
    /// The interval at which the node should expect to receive inbound IHUs.
    inbound_ihu_interval: Interval,
    /// Interval at which this node should send IHU's to this neighbour.
    outbound_ihu_interval: Interval,
    /// Give a duration if the Babel router should send periodic unicast hellos to this neighbour.
    ucast_hello_interval: Option<Interval>,
}

impl<A: AddressExt> NeighbourConfig<A> {
    /// Gets the spec default config for a new neighbour.
    pub fn spec_default(iface: InterfaceHandle, address: Address<A>) -> Self {
        Self {
            iface,
            address,
            inbound_ihu_interval: (DEFAULT_LOSSLESS_IHU_RATIO
                .apply(*DEFAULT_MULTICAST_HELLO_INTERVAL)
                * DEFAULT_HOLD_TIME_MULTIPLIER)
                .into(),
            outbound_ihu_interval: (DEFAULT_LOSSLESS_IHU_RATIO
                .apply(*DEFAULT_MULTICAST_HELLO_INTERVAL))
            .into(),
            ucast_hello_interval: None,
        }
    }

    pub fn interface_default(address: Address<A>, interface: &Interface<A>) -> Self {
        Self {
            iface: interface.handle,
            address,
            // This is set by incoming IHU TLVs, so there is no interface default start at a
            // sensible defualt.
            inbound_ihu_interval: (DEFAULT_LOSSLESS_IHU_RATIO
                .apply(*DEFAULT_MULTICAST_HELLO_INTERVAL)
                * DEFAULT_HOLD_TIME_MULTIPLIER)
                .into(),
            // This is set as a ratio of mcast hellos to outbound IHUs
            outbound_ihu_interval: (DEFAULT_LOSSLESS_IHU_RATIO
                .apply(interface.hello_timer.duration()))
            .into(),
            ucast_hello_interval: interface.ucast_hello_interval,
        }
    }

    pub(crate) fn index(&self) -> NeighbourIndex<A> {
        NeighbourIndex(self.iface, self.address)
    }
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NeighbourError<A: AddressExt> {
    /// The storage given for the interface table is full.
    #[error("Neighbour table is full")]
    Full,
    /// In this instance the neighbour is still added to the neighbour table, and the index
    /// inside the error is still valid for referencing the neighbour. The user can decide what
    /// they want to do with this error.
    #[error("A neighbour with the same index was added twice: {0}")]
    DuplicateNeighbour(NeighbourIndex<A>),
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error(transparent)]
    AddressEncoding(#[from] AddressEncodingError<A::Encoding>),
    #[error(transparent)]
    Tlv(#[from] TlvError),
    #[error(transparent)]
    Address(#[from] AddressError<A>),
}

#[cfg(all(test, feature = "std"))]
mod test {

    use super::*;
    use crate::extension::NoExtension;
    use crate::utils::{Instant, Timer};
    #[test]
    fn regression_spec_defaults_create_timers_without_errors() {
        let test_addr = core::net::Ipv6Addr::LOCALHOST;
        let config: NeighbourConfig<NoExtension> = NeighbourConfig::spec_default(
            InterfaceHandle::try_from("test").expect("Interface handle should create"),
            test_addr.into(),
        );
        let now = Instant::now();
        assert!(
            config.ucast_hello_interval.is_none(),
            "Spec default does not send ucast hellos."
        );
        Timer::from_interval(now, config.inbound_ihu_interval).expect("Spec default should work");
        Timer::from_interval(now, config.outbound_ihu_interval).expect("Spec default should work");
    }
}
