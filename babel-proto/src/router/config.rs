use crate::data_types::RouterId;
use crate::packet::packet_header::PacketHeader;

/// Config for the router.
pub struct BabelRouterConfig {
    pub(crate) id: RouterId,
    pub(crate) magic_number: u8,
    pub(crate) version: u8,
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
        }
    }

    pub fn set_magic_number(&mut self, magic: u8) {
        self.magic_number = magic
    }

    pub fn set_version(&mut self, version: u8) {
        self.version = version
    }
}
