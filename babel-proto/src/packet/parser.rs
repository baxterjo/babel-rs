use thiserror::Error;

use crate::data_types::address::{AddressError, Ipv4Addr, Ipv6Addr};
use crate::data_types::address_encoding::{AddressEncoding, AddressEncodingError};
use crate::data_types::router_id::RouterIdError;
use crate::data_types::{Address, RouterId};
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::packet::error::tlv_err::TlvError;
use crate::packet::tlv::{NextHopSlice, RouterIdSlice, UpdateSlice};

/// This is arbitrarily chosen to be big enough to fit the possible addresses from many existing
/// transport protocols.
pub const MAX_ADDRESS_LEN: usize = 20;

/// Stateful parser as defined in
/// [Section 4.5](https://datatracker.ietf.org/doc/html/rfc8966#name-parser-state-and-encoding-o)
///
/// The name "parser" is a small misnomer, as this struct also performs the address compression for
/// outgoing update tlvs. So this is more like a codec, but the Babel spec uses the term "parser"
/// so thats what it is called here.
///
/// Default prefix state is per address *encoding*, while next hop state is per address *family*.
#[derive(Debug, Default)]
pub struct Parser<E>
where
    E: ParserStateExt,
{
    /// The current Router ID that updates are coming from.
    router_id: Option<RouterId>,
    /// Default address for address encoding 1
    default_v4_addr: Option<Ipv4Addr>,
    /// Default address for address encoding 2
    default_v6_addr: Option<Ipv6Addr>,
    /// Current next hop address for v4 address family
    v4_next_hop: Option<Ipv4Addr>,
    /// Current next hop address for v6 address family
    v6_next_hop: Option<Ipv6Addr>,
    /// Address parser extension.
    extension: E,
}

// The `core::net` address types do not implement `defmt::Format`, so they are rendered from their
// octets instead of deriving.
#[cfg(feature = "defmt")]
impl<E> defmt::Format for Parser<E>
where
    E: ParserStateExt,
{
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "Parser{{ default_router_id: {}, default_v4_addr: {}, default_v6_addr: {}, extension: {}}}",
            self.router_id,
            self.default_v4_addr.map(|addr| addr.octets()),
            self.default_v6_addr.map(|addr| addr.octets()),
            self.extension
        )
    }
}

impl<A, E> Parser<E>
where
    A: AddressExt,
    E: ParserStateExt<AddressEncoding = A::Encoding, Address = A>,
{
    pub(crate) fn new(next_hop: Address<A>) -> Self {
        let mut out = Self::default();
        out.set_next_hop(next_hop);
        out
    }

    pub(crate) fn handle_router_id_tlv(&mut self, router_id: RouterIdSlice<'_>) {
        self.router_id = Some(router_id.router_id().into())
    }

    pub(crate) fn handle_next_hop_tlv(
        &mut self,
        next_hop: NextHopSlice<'_>,
    ) -> Result<(), ParserError<A>> {
        let ae = next_hop.ae();
        if ae == 0 {
            return Err(ParserError::AeCannotBeZero);
        }
        let ae = AddressEncoding::try_from(ae)?;

        let addr_bytes = next_hop.next_hop(ae.address_len())?;
        let address = Address::from_bytes(ae, addr_bytes)?;
        self.set_next_hop(address);
        Ok(())
    }

    pub(crate) fn set_next_hop(&mut self, address: Address<A>) {
        match address {
            Address::V4(v4) => self.v4_next_hop = Some(v4),
            Address::V6(v6) => self.v6_next_hop = Some(v6),
            Address::Extension(ext) => self.extension.set_next_hop_for_family(ext),
        }
    }
    pub(crate) fn get_next_hop(
        &self,
        encoding: &AddressEncoding<A::Encoding>,
    ) -> Option<Address<A>> {
        match encoding {
            AddressEncoding::WildCard => {
                return None;
            }
            AddressEncoding::Ipv4 => self.v4_next_hop.map(Address::V4),
            // `set_next_hop` files every V6 address under one slot, so both IPv6 encodings read
            // back out of it.
            AddressEncoding::Ipv6 | AddressEncoding::LocalIpv6 => self.v6_next_hop.map(Address::V6),
            AddressEncoding::Extension(ext) => self
                .extension
                .get_next_hop_for_family(&ext)
                .map(Address::Extension),
        }
    }

    pub(crate) fn get_default_address(
        &self,
        encoding: &AddressEncoding<A::Encoding>,
    ) -> Option<Address<A>> {
        match encoding {
            // Cannot compress wildcard addresses
            AddressEncoding::WildCard => {
                return None;
            }
            AddressEncoding::Ipv4 => self.default_v4_addr.map(Address::V4),
            AddressEncoding::Ipv6 => self.default_v6_addr.map(Address::V6),
            // Cannot compress Local Ipv6 addresses
            AddressEncoding::LocalIpv6 => None,
            AddressEncoding::Extension(ext) => self
                .extension
                .get_default_address_for_encoding(&ext)
                .map(Address::Extension),
        }
    }

    pub(crate) fn set_default_address(&mut self, address: Address<A>) {
        match address {
            Address::V4(v4) => self.default_v4_addr = Some(v4),
            Address::V6(v6) => self.default_v6_addr = Some(v6),
            Address::Extension(ext) => self.extension.set_default_address_for_encoding(ext),
        }
    }

    /// Handle the compression part of the update and return the [`ResolvedUpdate`]
    ///
    /// The router-id and next hop are only meaningful for a finite metric, so a retraction should
    /// go through [`Self::resolve_address`] instead of being rejected here for lacking them.
    ///
    /// This method assumes the update is **NOT** a blanket retraction.
    /// (`metric == 0xFFFF && ae == 0`)
    pub(crate) fn handle_update<'a>(
        &mut self,
        update: UpdateSlice<'a>,
    ) -> Result<ResolvedUpdate<'a, A>, ParserError<A>> {
        let ae: AddressEncoding<A::Encoding> = update.ae().try_into()?;
        let address = self.resolve_address(&update)?;

        let router_id = self
            .router_id
            .ok_or(ParserError::MissingState("router_id", None))?;
        let next_hop = self
            .get_next_hop(&ae)
            .ok_or(ParserError::MissingState("next_hop", Some(ae)))?;

        Ok(ResolvedUpdate {
            router_id,
            address,
            next_hop,
            slice: update,
        })
    }
    /// Resolve the prefix an update advertises, applying the parser state side effects its flags
    /// ask for.
    ///
    /// This is everything an Update carries that does not depend on its Metric field, which makes
    /// it the whole of what a retraction needs:
    /// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update) says that for a
    /// retraction "the router-id, next hop, and seqno are not used", so a retraction stays valid in
    /// a packet that has established neither a router-id nor a next hop.
    ///
    /// This method assumes the update is **NOT** a blanket retraction.
    /// (`metric == 0xFFFF && ae == 0`)
    pub(crate) fn resolve_address(
        &mut self,
        update: &UpdateSlice<'_>,
    ) -> Result<Address<A>, ParserError<A>> {
        // Extract the necessary info.
        let ae: AddressEncoding<A::Encoding> = update.ae().try_into()?;
        let flags = update.flags();
        let omitted = update.ommitted();

        // Fail fast escape hatch.
        if !ae.can_compress() && omitted != 0 {
            return Err(ParserError::CannotOmitBytes);
        }

        let address = self.decompress_address(update)?;

        // If the router id flag is set, update the router ID. It is computed from the *advertised*
        // address rather than the Prefix field, so the omitted octets have to be filled back in
        // first — otherwise a compressed Update yields a router-id shifted right by however many
        // octets it happened to omit.
        if flags.is_router_id() {
            self.router_id = Some(RouterId::try_from(address.as_wire())?);
        }

        if flags.is_prefix() {
            self.set_default_address(address);
        }

        Ok(address)
    }

    fn decompress_address(&self, update: &UpdateSlice<'_>) -> Result<Address<A>, ParserError<A>> {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let ae: AddressEncoding<A::Encoding> = update.ae().try_into()?;
        let plen = update.plen();
        let addr_len = ae.address_len();

        let max_plen = ae.max_plen();
        if usize::from(plen) > max_plen {
            return Err(ParserError::PlenTooLong { plen, ae, max_plen });
        }

        if addr_len > MAX_ADDRESS_LEN {
            // This will not get hit with the base spec.
            //
            // TODO(#13): Need to create a way for users to test their extension types before
            // running a babel router.
            return Err(ParserError::AddressTooLong);
        }

        let prefix = update.prefix(ae.implied_prefix_octets())?;
        let omitted = update.ommitted() as usize;

        // If there are any omitted bytes, fetch them from the default
        if omitted > 0 {
            let default_addr = self
                .get_default_address(&ae)
                .ok_or_else(|| ParserError::NoDefaultAddress(ae))?;

            let pre_bytes = default_addr.as_wire().get(0..omitted.into()).ok_or(
                ParserError::TooManyOmitted {
                    omitted,
                    addr_len: default_addr.as_wire().len(),
                },
            )?;
            out[..omitted].copy_from_slice(&pre_bytes[..]);
        }
        out[omitted..omitted + prefix.len()].copy_from_slice(prefix);
        // If Plen is not a multiple of 8, then any bits beyond Plen (i.e., the low-order
        // (8 - Plen MOD 8) bits of the last octet) are cleared. (Because prefix.len() was rounded
        // upward from plen/8 - implied - omitted)
        if plen % 8 != 0 {
            let shift_in = 8 - (plen % 8);
            let mask = 0xFFu8.unbounded_shl(shift_in.into());
            out[omitted + prefix.len() - 1] &= mask;
        }

        Ok(Address::from_bytes(ae, &out[..addr_len])?)
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ResolvedUpdate<'a, A: AddressExt> {
    pub(crate) router_id: RouterId,
    pub(crate) address: Address<A>,
    pub(crate) next_hop: Address<A>,
    pub(crate) slice: UpdateSlice<'a>,
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum ParserError<A: AddressExt> {
    #[error(transparent)]
    Encoding(#[from] AddressEncodingError<A::Encoding>),
    #[error(transparent)]
    Tlv(#[from] TlvError),
    #[error(transparent)]
    Address(#[from] AddressError<A>),
    #[error(transparent)]
    RouterId(#[from] RouterIdError),
    #[error("Address encoding cannot be zero in a next hop TLV")]
    AeCannotBeZero,
    #[error("Cannot omit bytes with AE = 3")]
    CannotOmitBytes,
    #[error("No default address set for family: {0:?}")]
    NoDefaultAddress(AddressEncoding<A::Encoding>),
    #[error("Too many omitted bytes - omitted: {omitted}, addr_len: {addr_len}")]
    TooManyOmitted { omitted: usize, addr_len: usize },
    #[error("Prefix length of {plen} bits is longer than the {max_plen} bits of {ae:?}")]
    PlenTooLong {
        plen: u8,
        ae: AddressEncoding<A::Encoding>,
        max_plen: usize,
    },
    #[error("Max address length is {max} bytes.", max = MAX_ADDRESS_LEN)]
    AddressTooLong,
    #[error("Missing {0} for address family: {1:?}")]
    MissingState(&'static str, Option<AddressEncoding<A::Encoding>>),
}

#[cfg(test)]
mod test {
    use core::net::{Ipv4Addr as StdIpv4Addr, Ipv6Addr as StdIpv6Addr};

    use super::*;
    use crate::extension::{NoExtension, NoStateExtension};
    use crate::packet::tlv::TypedTlv;
    use crate::packet::tlv::tlv_header::TlvHeader;
    use crate::packet::tlv::tlv_slice::TlvSlice;

    type TestParser = Parser<NoStateExtension<NoExtension>>;
    type TestAddress = Address<NoExtension>;
    type TestEncoding = AddressEncoding<NoExtension>;

    const NO_FLAGS: u8 = 0x00;
    const PREFIX_FLAG: u8 = 0x80;
    const ROUTER_ID_FLAG: u8 = 0x40;

    const ROUTER_ID: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];

    /// The network-layer source address of the packet being parsed. In the absence of a Next Hop
    /// TLV this is the next hop for its address family, which is how `handle_input` seeds a parser.
    const SOURCE_V4: StdIpv4Addr = StdIpv4Addr::new(10, 0, 0, 1);
    const SOURCE_V6: StdIpv6Addr = StdIpv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    fn v4(addr: StdIpv4Addr) -> TestAddress {
        addr.into()
    }

    fn v6(addr: StdIpv6Addr) -> TestAddress {
        addr.into()
    }

    // Type + Length + the fixed Update body + the longest prefix the parser will assemble.
    const UPDATE_TLV_BUF: usize = 48;

    /// An Update TLV laid out on the wire, so the tests drive the parser through the same
    /// accessors `handle_input` does rather than through a hand-built struct.
    struct UpdateTlv {
        bytes: [u8; UPDATE_TLV_BUF],
        len: usize,
    }

    impl UpdateTlv {
        fn slice(&self) -> UpdateSlice<'_> {
            let untyped =
                TlvSlice::from_slice(&self.bytes[..self.len]).expect("untyped TLV should parse");
            UpdateSlice::from_untyped(untyped).expect("update TLV should parse")
        }
    }

    /// Builds a finite-metric (i.e. non-retraction) Update TLV.
    ///
    /// `prefix` is the prefix as it appears on the wire, so it is already compressed: it holds
    /// (Plen/8 rounded upwards - Omitted) octets.
    fn update_tlv(ae: u8, flags: u8, plen: u8, omitted: u8, prefix: &[u8]) -> UpdateTlv {
        let body_len = UpdateSlice::MIN_LEN + prefix.len();
        let mut bytes = [0u8; UPDATE_TLV_BUF];

        bytes[0] = UpdateSlice::TYPE_ID;
        bytes[1] = body_len as u8;
        bytes[TlvHeader::LEN] = ae;
        bytes[TlvHeader::LEN + 1] = flags;
        bytes[TlvHeader::LEN + 2] = plen;
        bytes[TlvHeader::LEN + 3] = omitted;
        // Interval and Seqno are carried through untouched by the parser, so any sane value does.
        bytes[TlvHeader::LEN + 4..TlvHeader::LEN + 6].copy_from_slice(&200u16.to_be_bytes());
        bytes[TlvHeader::LEN + 6..TlvHeader::LEN + 8].copy_from_slice(&1u16.to_be_bytes());
        // A finite metric, so this advertises a route rather than retracting one.
        bytes[TlvHeader::LEN + 8..TlvHeader::LEN + 10].copy_from_slice(&0x0100u16.to_be_bytes());

        let prefix_start = TlvHeader::LEN + UpdateSlice::MIN_LEN;
        bytes[prefix_start..prefix_start + prefix.len()].copy_from_slice(prefix);

        UpdateTlv {
            bytes,
            len: TlvHeader::LEN + body_len,
        }
    }

    /// A Next Hop TLV on the wire. Sized for the longest address it can carry (a full IPv6).
    struct NextHopTlv {
        bytes: [u8; TlvHeader::LEN + 2 + 16],
        len: usize,
    }

    impl NextHopTlv {
        fn slice(&self) -> NextHopSlice<'_> {
            let untyped =
                TlvSlice::from_slice(&self.bytes[..self.len]).expect("untyped TLV should parse");
            NextHopSlice::from_untyped(untyped).expect("next hop TLV should parse")
        }
    }

    fn next_hop_tlv(ae: u8, address: &[u8]) -> NextHopTlv {
        let body_len = NextHopSlice::MIN_LEN + address.len();
        let mut bytes = [0u8; TlvHeader::LEN + 2 + 16];

        bytes[0] = NextHopSlice::TYPE_ID;
        bytes[1] = body_len as u8;
        bytes[TlvHeader::LEN] = ae;
        // The Reserved octet stays zero.

        let addr_start = TlvHeader::LEN + NextHopSlice::MIN_LEN;
        bytes[addr_start..addr_start + address.len()].copy_from_slice(address);

        NextHopTlv {
            bytes,
            len: TlvHeader::LEN + body_len,
        }
    }

    /// A Router-Id TLV on the wire. It is fixed size, so no length bookkeeping is needed.
    struct RouterIdTlv {
        bytes: [u8; TlvHeader::LEN + 10],
    }

    impl RouterIdTlv {
        fn slice(&self) -> RouterIdSlice<'_> {
            let untyped = TlvSlice::from_slice(&self.bytes).expect("untyped TLV should parse");
            RouterIdSlice::from_untyped(untyped).expect("router-id TLV should parse")
        }
    }

    fn router_id_tlv(id: [u8; 8]) -> RouterIdTlv {
        let mut bytes = [0u8; TlvHeader::LEN + 10];

        bytes[0] = RouterIdSlice::TYPE_ID;
        bytes[1] = 10;
        // Two Reserved octets, then the router-id.
        bytes[TlvHeader::LEN + 2..].copy_from_slice(&id);

        RouterIdTlv { bytes }
    }

    //  ___  _   ___  ___ ___ ___   ___ _____ _ _____ ___
    // | _ \/_\ | _ \/ __| __| _ \ / __|_   _/_\_   _| __|
    // |  _/ _ \|   /\__ \ _||   / \__ \ | |/ _ \| | | _|
    // |_|/_/ \_\_|_\|___/___|_|_\ |___/ |_/_/ \_\_| |___|

    /// The default prefix is indexed by address encoding, so the three built-in encodings never
    /// borrow each other's state. `fe80::/64` is its own default (AE 3) even though it is an IPv6
    /// address, which is the case worth pinning down.
    #[test]
    fn default_prefix_is_tracked_per_address_encoding() {
        let mut parser = TestParser::default();

        let global = StdIpv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0xaa);
        let ipv4 = StdIpv4Addr::new(192, 168, 0, 0);

        parser.set_default_address(v4(ipv4));
        parser.set_default_address(v6(global));

        assert_eq!(
            parser.get_default_address(&TestEncoding::Ipv4),
            Some(v4(ipv4)),
            "AE 1 should hold the IPv4 default"
        );
        assert_eq!(
            parser.get_default_address(&TestEncoding::Ipv6),
            Some(v6(global)),
            "AE 2 should hold the global IPv6 default"
        );
    }

    /// The wildcard encoding names no single address, so it can never supply omitted octets.
    #[test]
    fn wildcard_encoding_has_no_default_prefix() {
        let mut parser = TestParser::default();
        parser.set_default_address(v4(StdIpv4Addr::new(192, 168, 0, 0)));

        assert_eq!(parser.get_default_address(&TestEncoding::WildCard), None);
        assert_eq!(parser.get_next_hop(&TestEncoding::WildCard), None);
    }

    //  _  _ _____  _______   _  _  ___  ___
    // | \| | __\ \/ /_   _| | || |/ _ \| _ \
    // | .` | _| >  <  | |   | __ | (_) |  _/
    // |_|\_|___/_/\_\ |_|   |_||_|\___/|_|

    /// In the absence of a Next Hop TLV the next hop is the packet's source address, and only for
    /// the family that address belongs to.
    #[test]
    fn new_seeds_the_next_hop_from_the_packet_source() {
        let parser = TestParser::new(v4(SOURCE_V4));

        assert_eq!(
            parser.get_next_hop(&TestEncoding::Ipv4),
            Some(v4(SOURCE_V4)),
            "the source address is the next hop for its own family"
        );
        assert_eq!(
            parser.get_next_hop(&TestEncoding::Ipv6),
            None,
            "an IPv4 source says nothing about the IPv6 next hop"
        );
    }

    /// A Next Hop TLV overrides the source address for its family and leaves the others alone.
    #[test]
    fn next_hop_tlv_replaces_the_next_hop_for_its_family() {
        let mut parser = TestParser::new(v6(SOURCE_V6));

        let announced = StdIpv4Addr::new(10, 0, 0, 9);
        let tlv = next_hop_tlv(1, &announced.octets());
        parser
            .handle_next_hop_tlv(tlv.slice())
            .expect("a well-formed IPv4 next hop should be accepted");

        assert_eq!(
            parser.get_next_hop(&TestEncoding::Ipv4),
            Some(v4(announced)),
            "the announced next hop should be used for AE 1"
        );
        assert_eq!(
            parser.get_next_hop(&TestEncoding::Ipv6),
            Some(v6(SOURCE_V6)),
            "an IPv4 Next Hop TLV must not disturb the IPv6 next hop"
        );
    }

    /// RFC 8966 4.6.8: the AE of a Next Hop TLV MUST NOT be 0. There is no address to establish.
    #[test]
    fn next_hop_tlv_with_the_wildcard_encoding_is_rejected() {
        let mut parser = TestParser::default();
        let tlv = next_hop_tlv(0, &[]);

        let err = parser
            .handle_next_hop_tlv(tlv.slice())
            .expect_err("AE 0 should be rejected");

        assert!(
            matches!(err, ParserError::AeCannotBeZero),
            "expected AeCannotBeZero, got {err:?}"
        );
    }

    #[test]
    fn next_hop_tlv_with_an_unknown_encoding_is_rejected() {
        let mut parser = TestParser::default();
        // Nothing implements the extension encodings in this build, so 200 is unknown.
        let tlv = next_hop_tlv(200, &[1, 2, 3, 4]);

        let err = parser
            .handle_next_hop_tlv(tlv.slice())
            .expect_err("an unknown AE should be rejected");

        assert!(
            matches!(
                err,
                ParserError::Encoding(AddressEncodingError::UnknownAddressEncoding)
            ),
            "expected UnknownAddressEncoding, got {err:?}"
        );
    }

    /// The AE decides how many octets to read, so a TLV that does not carry them is truncated and
    /// must not be read past its end.
    #[test]
    fn next_hop_tlv_too_short_for_its_encoding_is_rejected() {
        let mut parser = TestParser::default();
        // AE 2 promises 16 octets of address but only 4 are present.
        let tlv = next_hop_tlv(2, &[10, 0, 0, 1]);

        let err = parser
            .handle_next_hop_tlv(tlv.slice())
            .expect_err("a truncated next hop should be rejected");

        assert!(
            matches!(err, ParserError::Tlv(_)),
            "expected a TLV length error, got {err:?}"
        );
        assert_eq!(
            parser.get_next_hop(&TestEncoding::Ipv6),
            None,
            "a rejected TLV must not leave a half-applied next hop behind"
        );
    }

    //  ___  ___ ___ ___  __  __ ___ ___ ___ ___ ___ ___ ___  _  _
    // |   \| __/ __/ _ \|  \/  | _ \ _ \ __/ __/ __|_ _/ _ \| \| |
    // | |) | _| (_| (_) | |\/| |  _/   / _|\__ \__ \| | (_) | .` |
    // |___/|___\___\___/|_|  |_|_| |_|_\___|___/___/___\___/|_|\_|

    /// The baseline: nothing omitted, so the advertised prefix is exactly what is on the wire,
    /// zero-filled out to the length the encoding calls for.
    #[test]
    fn update_without_compression_resolves_the_full_prefix() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(1, NO_FLAGS, 24, 0, &[192, 168, 0]);
        let info = parser
            .handle_update(update.slice())
            .expect("an uncompressed update should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(192, 168, 0, 0)),
            "the three prefix octets should be padded out to a full IPv4 address"
        );
        assert_eq!(
            info.router_id,
            RouterId::from(&ROUTER_ID),
            "the router-id should come from the preceding Router-Id TLV"
        );
        assert_eq!(
            info.next_hop,
            v4(SOURCE_V4),
            "with no Next Hop TLV the next hop is the packet source"
        );
    }

    /// "the remaining octets are set to 0" — a prefix shorter than the address it names is padded,
    /// not rejected.
    #[test]
    fn update_shorter_than_its_encoding_is_zero_filled() {
        let mut parser = TestParser::new(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        // A /64 carries 8 of the 16 octets of an IPv6 address.
        let update = update_tlv(2, NO_FLAGS, 64, 0, &[0xfd, 0x00, 0x00, 0x2a, 0, 0, 0, 0]);
        let info = parser
            .handle_update(update.slice())
            .expect("a /64 update should resolve");

        assert_eq!(
            info.address,
            v6(StdIpv6Addr::new(0xfd00, 0x002a, 0, 0, 0, 0, 0, 0)),
            "the low half of the address should be zero-filled"
        );
    }

    /// "if Plen is not a multiple of 8, then any bits beyond Plen (i.e., the low-order
    /// (8 - Plen MOD 8) bits of the last octet) are cleared".
    ///
    /// The Prefix field is a whole number of octets, so a Plen that is not a multiple of 8 leaves
    /// the sender free to put anything in the tail of the last one. Those bits are not part of the
    /// advertised prefix and must not reach the route table.
    #[test]
    fn update_clears_the_bits_beyond_plen() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        // Every case sets all the bits below Plen in the last octet, so a mask that is off by a
        // byte in either direction changes the answer.
        for (plen, prefix, expected) in [
            // 4 significant bits in the third octet: 0x1f keeps 0x10.
            (20u8, [192, 168, 0x1f].as_slice(), [192, 168, 0x10, 0]),
            // 1 significant bit: 0xff keeps 0x80.
            (17, [10, 0, 0xff].as_slice(), [10, 0, 0x80, 0]),
            // 7 significant bits: 0xff keeps 0xfe.
            (23, [10, 0, 0xff].as_slice(), [10, 0, 0xfe, 0]),
            // The partial octet is the second one, not the last of the address.
            (9, [10, 0xff].as_slice(), [10, 0x80, 0, 0]),
        ] {
            let update = update_tlv(1, NO_FLAGS, plen, 0, prefix);
            let info = parser
                .handle_update(update.slice())
                .unwrap_or_else(|e| panic!("a /{plen} update should resolve: {e:?}"));

            assert_eq!(
                info.address,
                v4(StdIpv4Addr::from_octets(expected)),
                "the bits beyond /{plen} should have been cleared"
            );
        }
    }

    /// The mirror of the case above: when Plen lands on an octet boundary there are no bits beyond
    /// it, so the last octet has to survive untouched.
    #[test]
    fn update_with_a_byte_aligned_plen_keeps_every_prefix_bit() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(1, NO_FLAGS, 24, 0, &[10, 0, 0xff]);
        let info = parser
            .handle_update(update.slice())
            .expect("a /24 update should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(10, 0, 0xff, 0)),
            "a /24 ends on an octet boundary, so nothing should be masked off"
        );
    }

    /// The octet holding the Plen boundary can come from the default prefix rather than the wire,
    /// so the clearing has to happen after decompression, not against the Prefix field.
    #[test]
    fn bits_beyond_plen_are_cleared_even_in_an_omitted_octet() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());
        parser.set_default_address(v4(StdIpv4Addr::new(10, 20, 30, 40)));

        // A /12 is two octets, both of them omitted, so the Prefix field is empty and the octet
        // that straddles the boundary is the default's second one (20 = 0b0001_0100).
        let update = update_tlv(1, NO_FLAGS, 12, 2, &[]);
        let info = parser
            .handle_update(update.slice())
            .expect("a fully omitted /12 should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(10, 16, 0, 0)),
            "the low nibble of the omitted octet is beyond /12 and should be cleared"
        );
    }

    /// A Plen longer than the address its encoding names is malformed. Truncating it instead would
    /// advertise a shorter prefix than the sender asked for, which is a different route.
    #[test]
    fn update_with_a_plen_longer_than_its_encoding_is_rejected() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        // One bit past the 32 an IPv4 address has. The Prefix field is sized off Plen, so this
        // carries a fifth octet that no IPv4 address has room for.
        let update = update_tlv(1, NO_FLAGS, 33, 0, &[192, 168, 0, 1, 0x80]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("a /33 IPv4 prefix should be rejected");

        assert!(
            matches!(
                err,
                ParserError::PlenTooLong {
                    plen: 33,
                    ae: TestEncoding::Ipv4,
                    max_plen: 32
                }
            ),
            "expected PlenTooLong, got {err:?}"
        );
    }

    /// Each encoding's longest legal Plen has to stay legal — the check rejects what is past the
    /// end, not what sits on it.
    #[test]
    fn update_with_a_plen_filling_its_encoding_is_accepted() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        parser.set_next_hop(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let host_v4 = update_tlv(1, NO_FLAGS, 32, 0, &[192, 168, 0, 1]);
        assert_eq!(
            parser
                .handle_update(host_v4.slice())
                .expect("a /32 IPv4 prefix should resolve")
                .address,
            v4(StdIpv4Addr::new(192, 168, 0, 1)),
            "32 bits is exactly an IPv4 address"
        );

        let host_v6 = update_tlv(
            2,
            NO_FLAGS,
            128,
            0,
            &[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
        );
        assert_eq!(
            parser
                .handle_update(host_v6.slice())
                .expect("a /128 IPv6 prefix should resolve")
                .address,
            v6(StdIpv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9)),
            "128 bits is exactly an IPv6 address"
        );

        // AE 3 implies `fe80::/64` and puts only the 8-octet suffix on the wire, but Plen counts
        // the whole prefix — so a link-local host route is /128 with 8 octets of Prefix
        // field, and 128 is the longest Plen it can carry.
        let link_local = update_tlv(3, NO_FLAGS, 128, 0, &[0, 0, 0, 0, 0, 0, 0, 7]);
        assert_eq!(
            parser
                .handle_update(link_local.slice())
                .expect("a /128 link-local prefix should resolve")
                .address,
            v6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 7)),
            "128 bits is the whole address AE 3 names, 64 of them implied"
        );
    }

    /// The counterpart to the AE 3 case above: Plen 64 is the implied prefix on its own, so the
    /// Prefix field is empty. This is the boundary the implied-octet arithmetic turns on — one bit
    /// lower and there is no prefix left to describe.
    #[test]
    fn a_link_local_update_at_the_implied_prefix_carries_no_octets() {
        let mut parser = TestParser::new(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(3, NO_FLAGS, 64, 0, &[]);
        assert_eq!(
            parser
                .handle_update(update.slice())
                .expect("a /64 link-local prefix should resolve")
                .address,
            v6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)),
            "Plen 64 is exactly the implied fe80::/64, so nothing is sent"
        );
    }

    /// A Plen below the implied prefix names bits underneath the floor AE 3 sets. `babeld` rejects
    /// these too, so there is no interoperable meaning to salvage.
    #[test]
    fn a_link_local_update_below_the_implied_prefix_is_rejected() {
        let mut parser = TestParser::new(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        // 56 rounds up to 7 octets, one short of the 8 the encoding implies.
        let update = update_tlv(3, NO_FLAGS, 56, 0, &[]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("a /56 link-local prefix should be rejected");

        assert!(
            matches!(
                err,
                ParserError::Tlv(TlvError::PlenBelowImpliedPrefix {
                    plen: 56,
                    implied_octets: 8
                })
            ),
            "expected PlenBelowImpliedPrefix, got {err:?}"
        );
    }

    /// AE 3 tops out at 128, not at the 64 bits of suffix it puts on the wire.
    #[test]
    fn a_link_local_update_past_128_bits_is_rejected() {
        let mut parser = TestParser::new(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(3, NO_FLAGS, 129, 0, &[0; 9]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("a /129 link-local prefix should be rejected");

        assert!(
            matches!(
                err,
                ParserError::PlenTooLong {
                    plen: 129,
                    ae: TestEncoding::LocalIpv6,
                    max_plen: 128
                }
            ),
            "expected PlenTooLong with a 128 bit ceiling, got {err:?}"
        );
    }

    /// The implied octets shift the prefix boundary by a whole number of octets, so the masking of
    /// bits beyond Plen has to keep working unchanged for AE 3.
    #[test]
    fn a_link_local_update_clears_the_bits_beyond_plen() {
        let mut parser = TestParser::new(v6(SOURCE_V6));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        // /100 is 64 implied bits plus 36 on the wire: 5 octets of Prefix field, the last of which
        // keeps only its top 4 bits.
        let update = update_tlv(3, NO_FLAGS, 100, 0, &[0x11, 0x22, 0x33, 0x44, 0xff]);
        assert_eq!(
            parser
                .handle_update(update.slice())
                .expect("a /100 link-local prefix should resolve")
                .address,
            v6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0x1122, 0x3344, 0xf000, 0)),
            "the low 4 bits of the fifth suffix octet are beyond /100"
        );
    }

    /// The Plen check is what keeps the masking step inside the decompression buffer: 153 bits
    /// rounds up to 20 octets — the whole buffer — and is not a multiple of 8, so an unchecked Plen
    /// would put the masked octet one past the end.
    #[test]
    fn a_plen_that_would_fill_the_decompression_buffer_is_rejected() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(1, NO_FLAGS, 153, 0, &[0xff; 20]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("a 153-bit IPv4 prefix should be rejected");

        assert!(
            matches!(err, ParserError::PlenTooLong { plen: 153, .. }),
            "expected PlenTooLong, got {err:?}"
        );
    }

    /// The compression the parser exists for: an Update with the Prefix flag set becomes the
    /// default for its family, and a later Update omits its leading octets.
    #[test]
    fn update_omitting_octets_takes_them_from_the_default_prefix() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let default = update_tlv(1, PREFIX_FLAG, 24, 0, &[192, 168, 0]);
        parser
            .handle_update(default.slice())
            .expect("the default-setting update should resolve");

        // Two octets omitted, so 192.168 comes from the default and only the third is on the wire.
        let compressed = update_tlv(1, NO_FLAGS, 24, 2, &[7]);
        let info = parser
            .handle_update(compressed.slice())
            .expect("the compressed update should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(192, 168, 7, 0)),
            "the omitted octets should be taken from the default prefix"
        );
    }

    /// Only an Update with the Prefix flag set establishes a default, so an ordinary Update in
    /// between must not become the source of later omitted octets.
    #[test]
    fn update_without_the_prefix_flag_does_not_change_the_default() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let default = update_tlv(1, PREFIX_FLAG, 24, 0, &[192, 168, 0]);
        parser
            .handle_update(default.slice())
            .expect("the default-setting update should resolve");

        let ordinary = update_tlv(1, NO_FLAGS, 24, 0, &[10, 20, 30]);
        parser
            .handle_update(ordinary.slice())
            .expect("the ordinary update should resolve");

        let compressed = update_tlv(1, NO_FLAGS, 24, 2, &[9]);
        let info = parser
            .handle_update(compressed.slice())
            .expect("the compressed update should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(192, 168, 9, 0)),
            "the default should still be the flagged update's prefix, not the ordinary one's"
        );
    }

    /// "if the Omitted field is not zero and there is no such TLV, then this Update MUST be
    /// ignored".
    #[test]
    fn update_cannot_omit_octets_without_a_default_prefix() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());

        let update = update_tlv(1, NO_FLAGS, 24, 2, &[7]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("omitting octets with no default should be rejected");

        assert!(
            matches!(err, ParserError::NoDefaultAddress(TestEncoding::Ipv4)),
            "expected NoDefaultAddress for AE 1, got {err:?}"
        );
    }

    /// Omitting every octet of the prefix is legal — the whole prefix then comes from the default,
    /// and the Prefix field is empty. The boundary matters because one octet further is the
    /// `TooManyOmitted` case that only an extension encoding can still reach.
    #[test]
    fn update_can_omit_its_entire_prefix() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());
        parser.set_default_address(v4(StdIpv4Addr::new(192, 168, 0, 0)));

        // A /32 is four octets, all four of them omitted.
        let update = update_tlv(1, NO_FLAGS, 32, 4, &[]);
        let info = parser
            .handle_update(update.slice())
            .expect("a fully omitted prefix should resolve");

        assert_eq!(
            info.address,
            v4(StdIpv4Addr::new(192, 168, 0, 0)),
            "every octet should have come from the default prefix"
        );
    }

    /// RFC 8966 4.6.9: with the Router-Id flag set, the router-id is computed from the first
    /// address of the advertised prefix — for an IPv4 address, four zero octets followed by the
    /// address itself.
    #[test]
    fn update_with_the_router_id_flag_takes_it_from_the_advertised_address() {
        let mut parser = TestParser::new(v4(SOURCE_V4));

        // No preceding Router-Id TLV: the flag is the only source of a router-id here.
        let update = update_tlv(1, ROUTER_ID_FLAG, 24, 0, &[192, 168, 0]);
        let info = parser
            .handle_update(update.slice())
            .expect("the Router-Id flag should supply the router-id");

        assert_eq!(
            info.router_id,
            RouterId::from(&[0, 0, 0, 0, 192, 168, 0, 0]),
            "the router-id is the advertised address right-aligned in 8 octets"
        );

        // The flag also establishes the router-id for the Updates that follow it.
        let follower = update_tlv(1, NO_FLAGS, 24, 0, &[10, 20, 30]);
        let info = parser
            .handle_update(follower.slice())
            .expect("the follow-up update should resolve");

        assert_eq!(
            info.router_id,
            RouterId::from(&[0, 0, 0, 0, 192, 168, 0, 0]),
            "the flagged update should have established the router-id for later Updates"
        );
    }

    /// "if there is no suitable TLV, then this update is ignored".
    #[test]
    fn update_without_a_router_id_is_rejected() {
        let mut parser = TestParser::new(v4(SOURCE_V4));

        let update = update_tlv(1, NO_FLAGS, 24, 0, &[192, 168, 0]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("an update with no router-id in scope should be rejected");

        assert!(
            matches!(err, ParserError::MissingState("router_id", None)),
            "expected a missing router_id, got {err:?}"
        );
    }

    /// RFC 8966 4.6.9: "If AE is 3 (link-local IPv6), the Omitted field MUST be 0."
    #[test]
    fn link_local_update_cannot_omit_octets() {
        let mut parser = TestParser::new(v6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());
        parser.set_default_address(v6(StdIpv6Addr::new(0xfe80, 0, 0, 0, 0xaaaa, 0, 0, 0)));

        let update = update_tlv(3, NO_FLAGS, 64, 4, &[1, 2, 3, 4]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("AE 3 must not omit octets");

        assert!(
            matches!(err, ParserError::CannotOmitBytes),
            "expected CannotOmitBytes, got {err:?}"
        );
    }

    /// A malformed TLV — one omitting more octets than its own Plen accounts for — is rejected by
    /// the slice accessors, and that rejection has to reach the caller rather than being papered
    /// over during decompression.
    #[test]
    fn update_omitting_more_than_its_prefix_holds_is_rejected() {
        let mut parser = TestParser::new(v4(SOURCE_V4));
        let router_id = router_id_tlv(ROUTER_ID);
        parser.handle_router_id_tlv(router_id.slice());
        parser.set_default_address(v4(StdIpv4Addr::new(192, 168, 0, 0)));

        // Plen 24 is 3 octets; claiming 5 of them are omitted is nonsense.
        let update = update_tlv(1, NO_FLAGS, 24, 5, &[]);
        let err = parser
            .handle_update(update.slice())
            .expect_err("an inconsistent Plen/Omitted pair should be rejected");

        assert!(
            matches!(err, ParserError::Tlv(TlvError::OmittedTooLong { .. })),
            "expected OmittedTooLong, got {err:?}"
        );
    }
}
