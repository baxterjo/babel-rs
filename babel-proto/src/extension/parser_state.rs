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

    /// Sets the next hop address for the address family.
    ///
    /// This next hop address is indexed by the address family of this address. (This is not the
    /// same as address encoding.)
    ///
    /// The use of the next hop address is described in
    /// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
    fn set_next_hop_for_family(&mut self, next_hop: Self::Address);
    /// Returns the next hop address for the given address family.
    ///
    /// The use of the next hop address is described in
    /// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
    fn get_next_hop_for_family(&self, ae: &Self::AddressEncoding) -> Option<Self::Address>;
    /// Sets the default address for the address encoding.
    ///
    /// This address is indexed by the address encoding ([`Self::AddressEncoding`]) of this
    /// type.
    ///
    /// The use of the default address is described in
    /// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
    fn set_default_address_for_encoding(&mut self, address: Self::Address);
    /// Returns the default address for the address encoding.
    ///
    /// The use of the default address is described in
    /// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
    fn get_default_address_for_encoding(&self, ae: &Self::AddressEncoding)
    -> Option<Self::Address>;
}

impl<A: AddressExt> ParserStateExt for NoStateExtension<A> {
    type Address = A;
    type AddressEncoding = A::Encoding;

    fn set_next_hop_for_family(&mut self, _next_hop: Self::Address) {}
    fn get_next_hop_for_family(&self, _ae: &Self::AddressEncoding) -> Option<Self::Address> {
        None
    }

    fn set_default_address_for_encoding(&mut self, _address: Self::Address) {}
    fn get_default_address_for_encoding(
        &self,
        _ae: &Self::AddressEncoding,
    ) -> Option<Self::Address> {
        None
    }
}
