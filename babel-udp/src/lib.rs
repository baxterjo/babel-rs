use std::net::{Ipv6Addr, UdpSocket};

use babel_proto::router::BabelRouter;
pub struct UdpBabelSpeaker {
    router: BabelRouter<'static, Ipv6Addr>,
    socket: UdpSocket,
}
