use thiserror::Error;

use crate::data_structures::interface::{InterfaceError, InterfaceHandle};
use crate::data_structures::neighbour::{NeighbourError, NeighbourIndex};
use crate::data_structures::route::RouteError;
use crate::data_structures::updates::UpdateError;
use crate::data_types::address::AddressError;
use crate::data_types::address_encoding::AddressEncodingError;
use crate::extension::address::AddressExt;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::parser::ParserError;
use crate::packet::writer::PacketWriterError;
use crate::utils::TimerError;

#[derive(Debug, Error)]
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
    #[error("Attempted to reference a non-existant interface: {0}")]
    InterfaceDoesntExist(InterfaceHandle),
    #[error("Polled for output but no interface reported a wake-up time")]
    NoWakeUpTime,
    #[error("Received {0} from an unregistered neighbour: {1}")]
    TlvFromUnknownNeighbour(&'static str, NeighbourIndex<A>),
    #[error(
        "Blanket retraction must have a Plen and Omitted of 0 - plen: {plen}, omitted: {omitted}"
    )]
    MalformedBlanketRetraction { plen: u8, omitted: u8 },
    #[error(transparent)]
    Len(#[from] LenError),
    #[error(transparent)]
    Interface(#[from] InterfaceError),
    #[error(transparent)]
    Neighbour(#[from] NeighbourError<A>),
    #[error(transparent)]
    Route(#[from] RouteError),
    #[error(transparent)]
    PacketWriter(#[from] PacketWriterError),
    #[error(transparent)]
    AddressEncoding(#[from] AddressEncodingError<A::Encoding>),
    #[error(transparent)]
    Tlv(#[from] TlvError),
    #[error(transparent)]
    Address(#[from] AddressError<A>),
    #[error(transparent)]
    Parser(#[from] ParserError<A>),
    #[error(transparent)]
    Timer(#[from] TimerError),
    #[error(transparent)]
    Update(#[from] UpdateError),
}
