use thiserror::Error;

use crate::{
    data_structures::{interface::InterfaceTableError, neighbour::NeighbourTableError},
    data_types::address_encoding::AddressEncodingError,
    extension::address::AddressExt,
    packet::{error::len_error::LenError, writer::PacketWriterError},
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BabelError<A>
where
    A: AddressExt,
{
    #[error(
        "Incorrect magic number \
        - expected: {expected}, received: {received}"
    )]
    IncorrectMagicNumber { expected: u8, received: u8 },
    #[error(
        "Incorrect version number\
        - expected: {expected}, received: {received}"
    )]
    IncorrectVersionNumber { expected: u8, received: u8 },
    #[error(transparent)]
    Len(#[from] LenError),
    #[error(transparent)]
    IfaceTable(#[from] InterfaceTableError),
    #[error(transparent)]
    NeighbourTable(#[from] NeighbourTableError<A>),
    #[error(transparent)]
    PacketWriter(#[from] PacketWriterError),
    #[error(transparent)]
    AddressEncoding(#[from] AddressEncodingError<A::Encoding>),
}
