use crate::{
    data_structures::interface::InterfaceHandle,
    data_types::{address::AddressExtension, Address},
    utils::Instant,
};

#[derive(Debug)]
pub enum Input<'input, E: AddressExtension> {
    Timeout(Instant),
    Receive(Instant, Receive<'input, E>),
}

#[derive(Debug)]
pub struct Receive<'input, E: AddressExtension> {
    pub iface: InterfaceHandle,
    pub source_addr: Option<Address<E>>,
    pub contents: &'input [u8],
}
