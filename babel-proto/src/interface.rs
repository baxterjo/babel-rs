use core::hash::Hash;

use crate::time::{Duration, Instant};

/// Recommended message intervals indicated in [RFC 8966 Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.2)
pub const DEFAULT_MULTICAST_HELLO_INTERVAL_SECS: u64 = 4;
/// Recommended message intervals indicated in [RFC 8966 Appendix B.](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.10)
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = DEFAULT_MULTICAST_HELLO_INTERVAL_SECS * 4;

/// Interfaces that speak the Babel Protocol
#[derive(Debug)]
pub struct Interface {
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    pub id: [u8; 8],
    hello_seqno: u16,

    /// How often this interface should send hello messages.
    hello_interval: Duration,
    last_hello: Option<Instant>,

    /// How often this interface should send update messages
    update_interval: Duration,
    last_update: Option<Instant>,
}

impl Hash for Interface {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl Interface {
    /// Creates a new interface with a given interface
    pub fn new<I, H, U>(id: I, hello_interval: Option<H>, update_interval: Option<U>) -> Self
    where
        I: Into<[u8; 8]> + From<[u8; 8]>,
        H: Into<Duration>,
        U: Into<Duration>,
    {
        Self {
            id: id.into(),
            hello_seqno: 0,
            hello_interval: hello_interval.map_or(
                Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS),
                |h| h.into(),
            ),
            last_hello: None,
            update_interval: update_interval
                .map_or(Duration::from_secs(DEFAULT_UPDATE_INTERVAL_SECS), |u| {
                    u.into()
                }),
            last_update: None,
        }
    }
}
