use core::fmt::Debug;

use crate::data_structures::interface::InterfaceHandle;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::utils::Instant;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Input<'input, A: AddressExt> {
    Timeout(Instant),
    Receive(Instant, Receive<'input, A>),
}

pub struct Receive<'input, A: AddressExt> {
    /// The interface the packet was received on.
    pub iface: InterfaceHandle,
    /// The source address this packet was received from.
    pub source_addr: Address<A>,
    /// The contents of the packet.
    pub contents: &'input [u8],
}

impl<A: AddressExt> Debug for Receive<'_, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receive")
            .field("iface", &self.iface)
            .field("source_addr", &self.source_addr)
            .field("content_len", &self.contents.len())
            .finish()
    }
}

#[cfg(feature = "defmt")]
impl<A: AddressExt> defmt::Format for Receive<'_, A> {
    fn format(&self, fmt: defmt::Formatter) {
        defmt::write!(
            fmt,
            "Receive{{ iface: {}, source_addr:{}, content_len: {}}}",
            &self.iface,
            &self.source_addr,
            &self.contents.len()
        )
    }
}
