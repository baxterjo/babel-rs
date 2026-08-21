use core::{fmt::Debug, ops::Deref};

use managed::ManagedSlice;

use crate::{
    data_structures::interface::InterfaceHandle, data_types::address::Address,
    extension::address::AddressExt, utils::Duration,
};

#[derive(Debug)]
pub enum Output<'a, A: AddressExt> {
    SetTimer(Duration),
    Transmit(Transmit<'a, A>),
}

/// Transmit payload.
#[derive(Debug)]
pub struct Transmit<'a, A: AddressExt> {
    /// Interface to transmit on.
    pub iface: InterfaceHandle,
    /// Destination on the interface.
    pub destination: TransmitDestination<A>,
    pub contents: DatagramSend<'a>,
}

/// Destination of the transmitted datagram.
#[derive(Debug)]
pub enum TransmitDestination<A: AddressExt> {
    /// Send the datagram to a unicast address. On the well known Babel port for your routing
    /// domain.
    Unicast(Address<A>),
    /// Send the datagram to this interface's well known multicast address.
    ///
    /// If the interface this is to be sent on does not have multicast, the user **MUST** send this
    /// message to each neighbour on the interface via unicast. Since the
    /// [`BabelRouter`](crate::router::BabelRouter) internals do not have a method for neighbour
    /// discovery outside of multicast, it is assumed that the user knows the addresses of these
    /// neighbours through some out of band discovery method.
    Multicast,
}

// Attribution: str0m version 0.23.0 with modification to use managed slice instead of Vec
/// A wrapper for some payload that is to be sent.
///
/// The term datagram is used here as a generic term for "payloade to be sent over unreliable (or
/// reliable if you want) transport" and does not necessarily mean UDP.
pub struct DatagramSend<'a>(ManagedSlice<'a, u8>);

impl<'a> Debug for DatagramSend<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatagramSend")
            .field("len", &self.len())
            .finish()
    }
}

impl<'a> From<ManagedSlice<'a, u8>> for DatagramSend<'a> {
    fn from(value: ManagedSlice<'a, u8>) -> Self {
        Self(value)
    }
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl From<DatagramSend<'_>> for Vec<u8> {
    fn from(value: DatagramSend) -> Self {
        value.0.to_vec()
    }
}

impl Deref for DatagramSend<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
