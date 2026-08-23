use core::fmt::Debug;

use crate::MaybeDefmt;
use crate::extension::NoStateExtension;
use crate::extension::address::AddressExt;
use crate::extension::address_encoding::AddressEncodingExt;

/// Extends the parser state to operate with address encoding extensions.
///
/// Babel parser state is **PER PACKET**. Types that implement this trait will be dropped and
/// re-initiated between Babel packets. (Hence the [`Default`] bound)
pub trait ParserStateExt
where
    Self: Debug + Sized + Default + MaybeDefmt,
{
    type AddressEncoding: AddressEncodingExt;
    type Address: AddressExt<Encoding = Self::AddressEncoding>;

    fn get_default_for_family(&self, ae: &Self::AddressEncoding) -> Option<&Self::Address>;
    fn set_default_for_family(&mut self, ae: &Self::AddressEncoding, address: Self::Address);
}

impl<A: AddressExt> ParserStateExt for NoStateExtension<A> {
    type Address = A;
    type AddressEncoding = A::Encoding;
    fn get_default_for_family(&self, _ae: &Self::AddressEncoding) -> Option<&Self::Address> {
        unreachable!("The NoExtension struct should not be constructable.")
    }
    fn set_default_for_family(&mut self, _ae: &Self::AddressEncoding, _address: Self::Address) {
        unreachable!("The NoExtension struct should not be constructable.")
    }
}
