use crate::{
    data_structures::interface::InterfaceHandle, data_types::Address,
    extension::address::AddressExt, utils::Instant,
};

#[derive(Debug)]
pub enum Input<'input, E: AddressExt> {
    Timeout(Instant),
    Receive(Instant, Receive<'input, E>),
}

#[derive(Debug)]
pub struct Receive<'input, E: AddressExt> {
    pub iface: InterfaceHandle,
    pub source_addr: Option<Address<E>>,
    pub contents: &'input [u8],
}
