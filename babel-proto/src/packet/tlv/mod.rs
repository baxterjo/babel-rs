pub mod ack_req;
#[doc(inline)]
pub use ack_req::AckReq;

pub enum Tlv<'a> {
    Pad1,
    PadN(&'a u8),
    AckReq(AckReq<'a>),
}

pub struct TlvIter<'a> {
    buf: &'a [u8],
}
