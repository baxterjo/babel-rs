use crate::{
    data_structures::interface::InterfaceHandle,
    data_types::address::{Address, AddressExtension},
    utils::Duration,
};

pub enum Output<'a, A: AddressExtension> {
    SetTimer(Duration),
    Transmit(Transmit<'a, A>),
}

pub struct Transmit<'a, A: AddressExtension> {
    pub iface: InterfaceHandle,
    pub destination: Address<A>,
    pub contents: &'a [u8],
}
