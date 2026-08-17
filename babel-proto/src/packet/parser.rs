use core::{
    array::TryFromSliceError,
    net::{Ipv4Addr, Ipv6Addr},
};

use thiserror::Error;

use crate::{
    data_structures::interface::InterfaceHandle,
    data_types::{address::AddressExtension, Address, RouterId},
    input::Receive,
    packet::{error::len_error::LenError, packet_slice::BabelPacketSlice},
};

/// Implements parser state and update encoding as described in section
/// [4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
#[derive(Debug)]
pub struct Parser<'input, E: AddressExtension, const MN: u8, const V: u8> {
    /// Interface the packet was received on.
    iface: InterfaceHandle,
    /// Source address of the received packet.
    source: Option<Address<E>>,
    packet: BabelPacketSlice<'input>,
    extension: E,
    default_router_id: Option<RouterId>,
    ae1_default_prefix: Option<Ipv4Addr>,
    ae2_default_prefix: Option<Ipv6Addr>,
}

impl<'input, E: AddressExtension, const MN: u8, const V: u8> Parser<'input, E, MN, V> {
    fn new(received: Receive<'input, E>) -> Result<Self, PacketParseError> {
        let packet = BabelPacketSlice::from_slice(received.contents)?;

        let magic = packet.magic();
        if magic != MN {
            return Err(PacketParseError::WrongMagicNumber(magic));
        }

        let version = packet.version();
        if version != V {
            return Err(PacketParseError::WrongVersion(version));
        }

        Ok(Self {
            iface: received.iface,
            source: received.source_addr,
            packet,
            extension: E::default(),
            default_router_id: None,
            ae1_default_prefix: None,
            ae2_default_prefix: None,
        })
    }

    /// Sets the default prefix for an update TLV for AE 1, this is the state that is used to decode
    /// compressed addresses.
    pub fn set_ae1_prefix(&mut self, value: Ipv4Addr) {
        self.ae1_default_prefix = Some(value)
    }

    /// Sets the default prefix for an update TLV for AE 2, this is the state that is used to decode
    /// compressed addresses.
    pub fn set_ae2_prefix(&mut self, value: Ipv6Addr) {
        self.ae2_default_prefix = Some(value)
    }
}

#[derive(Debug, Error)]
pub enum PacketParseError {
    #[error(transparent)]
    LenError(#[from] LenError),
    #[error("Could not parse packet headers")]
    HeaderParseError,
    #[error(transparent)]
    SliceTooSmall(#[from] TryFromSliceError),
    #[error("Not a magic number this babel router recognizes: {0}")]
    WrongMagicNumber(u8),
    #[error("Packet has the wrong babel version: {0}")]
    WrongVersion(u8),
}
