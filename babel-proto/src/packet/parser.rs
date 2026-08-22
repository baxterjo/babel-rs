use core::net::{Ipv4Addr, Ipv6Addr};

use crate::data_types::RouterId;
use crate::extension::parser_state::ParserStateExt;

#[derive(Debug, Default)]
pub struct Parser<E>
where
    E: ParserStateExt,
{
    default_router_id: Option<RouterId>,
    default_v4_addr: Option<Ipv4Addr>,
    default_v6_addr: Option<Ipv6Addr>,
    extension: E,
}

// The `core::net` address types do not implement `defmt::Format`, so they are rendered from their
// octets instead of deriving.
#[cfg(feature = "defmt")]
impl<E> defmt::Format for Parser<E>
where
    E: ParserStateExt,
{
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "Parser{{ default_router_id: {}, default_v4_addr: {}, default_v6_addr: {}, extension: {}}}",
            self.default_router_id,
            self.default_v4_addr.map(|addr| addr.octets()),
            self.default_v6_addr.map(|addr| addr.octets()),
            self.extension
        )
    }
}

impl<E> Parser<E>
where
    E: ParserStateExt,
{
    pub(crate) fn default_router_id(&self) -> Option<&RouterId> {
        self.default_router_id.as_ref()
    }

    pub(crate) fn set_default_router_id(&mut self, id: RouterId) {
        self.default_router_id = Some(id)
    }

    pub(crate) fn default_v4(&self) -> Option<&Ipv4Addr> {
        self.default_v4_addr.as_ref()
    }

    pub(crate) fn set_default_v4(&mut self, address: Ipv4Addr) {
        self.default_v4_addr = Some(address)
    }

    pub(crate) fn default_v6(&self) -> Option<&Ipv6Addr> {
        self.default_v6_addr.as_ref()
    }

    pub(crate) fn set_default_v6(&mut self, address: Ipv6Addr) {
        self.default_v6_addr = Some(address)
    }

    pub(crate) fn default_ext(&self, ae: &E::AddressEncoding) -> Option<&E::Address> {
        self.extension.get_default_for_family(ae)
    }

    pub(crate) fn set_default_ext(&mut self, ae: &E::AddressEncoding, address: E::Address) {
        self.extension.set_default_for_family(ae, address);
    }
}
