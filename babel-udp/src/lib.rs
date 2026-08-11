use std::net::{Ipv6Addr, UdpSocket};

use babel_proto::router::BabelRouter;
pub struct UdpBabelSpeaker {
    router: BabelRouter<'static>,
    socket: UdpSocket,
}
