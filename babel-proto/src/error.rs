use thiserror::Error;

use crate::data_structures::interface::InterfaceTableError;
use crate::data_structures::neighbour::NeighbourTableError;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::extension::address::AddressExt;
use crate::packet::error::len_error::LenError;
use crate::packet::writer::PacketWriterError;

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
