use crate::data_structures::interface::DEFAULT_MULTICAST_HELLO_INTERVAL_SECS;
use crate::data_types::{Interval, RouterId};
use crate::packet::packet_header::PacketHeader;
use crate::utils::{Duration, DurationMultiplier};

/// Recommended update interval as defined in [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL: Interval = Interval::from_duration(Duration::from_secs(
    DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4,
));

/// Recommended route expiry time as defined [Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_ROUTE_EXPIRY_TIME: DurationMultiplier = DurationMultiplier::new(7, 2);

/// Config for the router.
pub struct BabelRouterConfig {
    pub(crate) id: RouterId,
    pub(crate) magic_number: u8,
    pub(crate) version: u8,
    pub(crate) update_interval: Interval,
    pub(crate) route_expiry_multiplier: DurationMultiplier,
}

impl BabelRouterConfig {
    pub fn new<I>(id: I) -> Self
    where
        I: Into<RouterId>,
    {
        let id = id.into();
        Self {
            id,
            magic_number: PacketHeader::MAGIC_NUMBER,
            version: PacketHeader::VERSION_NUMBER,
            update_interval: DEFAULT_UPDATE_INTERVAL,
            route_expiry_multiplier: DEFAULT_ROUTE_EXPIRY_TIME,
        }
    }

    /// Sets the magic number that identifies Babel packets as defined in
    /// [Section 4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
    ///
    /// Setting this to anything outside the default is out of spec.
    pub fn set_magic_number(&mut self, magic: u8) {
        self.magic_number = magic;
    }

    /// Sets the version number for Babel packets as defined in
    /// [Section 4.2](https://datatracker.ietf.org/doc/html/rfc8966#name-packet-format)
    ///
    /// Setting this to anything outside the default is out of spec.
    pub fn set_version(&mut self, version: u8) {
        self.version = version;
    }

    /// Sets the interval at which route updates are sent to all neighbours on all interfaces.
    pub fn set_update_interval(&mut self, interval: Interval) {
        self.update_interval = interval;
    }

    /// Sets the value for which to multiply incoming update intervals against to determine route
    /// expiry.
    pub fn set_route_expiry(&mut self, multiplier: DurationMultiplier) {
        self.route_expiry_multiplier = multiplier;
    }
}
