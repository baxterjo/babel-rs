use crate::{
    data_structures::interface::InterfaceHandle, data_types::address::Address,
    extension::address::AddressExt, utils::Duration,
};

pub enum Output<'a, A: AddressExt> {
    SetTimer(Duration),
    Transmit(Transmit<'a, A>),
}

pub struct Transmit<'a, A: AddressExt> {
    pub iface: InterfaceHandle,
    pub destination: Address<A>,
    pub contents: &'a [u8],
}
