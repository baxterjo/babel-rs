pub mod reader;
pub mod tlv_header;
pub mod tlv_header_slice;
pub mod tlv_slice;

#[doc(hidden)]
pub mod ack_req_slice;
#[doc(hidden)]
pub mod ack_slice;
#[doc(hidden)]
pub mod hello_slice;
#[doc(hidden)]
pub mod ihu_slice;
#[doc(hidden)]
pub mod next_hop_slice;
#[doc(hidden)]
pub mod pad_slice;
#[doc(hidden)]
pub mod route_request_slice;
#[doc(hidden)]
pub mod router_id_slice;
#[doc(hidden)]
pub mod seqno_request_slice;
#[doc(hidden)]
pub mod update_slice;

use core::any::type_name;

#[doc(inline)]
pub use ack_req_slice::AckReqSlice;
#[doc(inline)]
pub use ack_slice::AckSlice;
#[doc(inline)]
pub use hello_slice::HelloSlice;
#[doc(inline)]
pub use ihu_slice::IhuSlice;
#[doc(inline)]
pub use next_hop_slice::NextHopSlice;
#[doc(inline)]
pub use pad_slice::PadNSlice;
#[doc(inline)]
pub use route_request_slice::RouteRequestSlice;
#[doc(inline)]
pub use router_id_slice::RouterIdSlice;
#[doc(inline)]
pub use seqno_request_slice::SeqnoRequestSlice;
#[doc(inline)]
pub use update_slice::UpdateSlice;

use crate::packet::error::layer::Layer;
use crate::packet::error::len_error::LenError;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::len_source::LenSource;
use crate::packet::tlv::tlv_slice::TlvSlice;

/// All TLV types listed in RFC 8966
pub enum Tlv<'a> {
    Pad0,
    PadN(PadNSlice<'a>),
    AckReq(AckReqSlice<'a>),
    Ack(AckSlice<'a>),
    Hello(HelloSlice<'a>),
    Ihu(IhuSlice<'a>),
    RouterId(RouterIdSlice<'a>),
    NextHop(NextHopSlice<'a>),
    Update(UpdateSlice<'a>),
    RouteRequest(RouteRequestSlice<'a>),
    SeqnoRequest(SeqnoRequestSlice<'a>),
}

/// Trait that defines a TLV with a known `Type` value and structure.
// IMPORTANT: When accessing fields **BEYOND** TlvHeader::LEN + Self::MIN_LEN, all accessors MUST
// be checked and safe. These constructors DO NOT guarantee safety beyond that point.
pub trait TypedTlv<'a>: Sized
where
    Self: 'a,
{
    /// The type identifier of the TLV.
    const TYPE_ID: u8;
    /// The minimum length that the TLV could be exclusive of type and length fields.
    ///
    /// This is also the minimum value that could appear in the `Length` field.
    ///
    /// This is minimum because some packets use address compression and have variable size.
    const MIN_LEN: usize;

    fn slice(&self) -> &'a [u8];

    /// This method needs to be implemented to store a slice in the TLV.
    ///
    /// The method should never be called directly by users and will only be called by
    /// `<Self as TypedTlv>::from_slice()`. It can be assumed that length checks have been done on
    /// the slice before this function has been called.
    fn from_slice_unchecked(slice: &'a [u8]) -> Self;

    /// Converts the untyped TlvSlice into a typed slice. After checking the slice has at least the
    /// minimum length to be that Tlv.
    fn from_untyped(raw: TlvSlice<'a>) -> Result<Self, TlvError> {
        let raw_type = raw.r#type();

        if raw_type != Self::TYPE_ID {
            return Err(TlvError::WrongType {
                tlv_name: type_name::<Self>(),
                expected: Self::TYPE_ID,
                actual: raw_type,
            });
        }

        let length: usize = raw.length().into();
        if length < Self::MIN_LEN {
            Err(LenError {
                required_len: Self::MIN_LEN,
                len: length,
                len_source: LenSource::BabelTlvBodyLength,
                layer: Layer::BabelTlvBody,
                layer_start_offset: 0,
            })?;
        }

        Ok(Self::from_slice_unchecked(raw.slice()))
    }

    fn as_untyped(&'a self) -> TlvSlice<'a> {
        TlvSlice::from_typed(self)
    }
}
