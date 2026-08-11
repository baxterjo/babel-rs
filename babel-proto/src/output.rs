use crate::{
    address::{AddressExtension, RouterAddress},
    interface::InterfaceHandle,
    time::Duration,
};

pub enum Output<'a, A: AddressExtension> {
    SetTimer(Duration),
    Transmit(Transmit<'a, A>),
}

pub struct Transmit<'a, A: AddressExtension> {
    pub iface: InterfaceHandle,
    pub destination: RouterAddress<A>,
    pub contents: &'a [u8],
}
