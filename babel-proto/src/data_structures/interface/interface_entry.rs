use crate::data_structures::interface::{InterfaceConfig, InterfaceError, InterfaceHandle};
use crate::data_types::address_encoding::AddressFamily;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::LinkCostCalculator;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::writer::ready::Ready;
use crate::packet::writer::{PacketWriterError, PacketWriterStep};
use crate::utils::destination::DestAddr;
use crate::utils::{Duration, DurationMultiplier, Instant, InternallyKeyed, Timer};

/// The maximum amount of other addresses an interface can be reached at.
//
// TODO: Make this a const generic for interface?
pub const MAX_OTHER_ADDRESSES: usize = 3;

/// Interfaces that speak the Babel Protocol
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Interface<A: AddressExt> {
    // Spec values
    /// User defined interface ID. Used to correlate the router tracked interface with user defined
    /// interfaces.
    handle: InterfaceHandle,

    /// The address this node can be reached at on this interface, this is also the address that
    /// babel packets will be sent **FROM**.
    pub(crate) address: Address<A>,

    /// An array of other addresses that this interface can be dialed as. No Babel traffic will
    /// ever be sent on these addresses, they are only used for populating next_hop information for
    /// address families that are not the same as the primary address for this interface.
    pub(crate) other_addresses: [Option<Address<A>>; MAX_OTHER_ADDRESSES],

    /// Mcast hello seqno.
    pub(crate) hello_seqno: SeqNo,

    /// How often this interface should mcast send hello messages.
    pub(crate) hello_timer: Timer,

    /// How often this interface should send update messages
    pub(crate) update_timer: Timer,

    // User config
    /// This interface gives this interval to new neighbour table entries when new neighbours are
    /// discovered. The router will then send unicast hellos to this neighbour at this interval.
    /// This defaults to None as most babel speakers should prefer multicast hellos.
    pub(crate) ucast_hello_interval: Option<Interval>,

    /// IHU hold time multipliers for neighbours heard on this interface.
    ///
    /// When a neighbour sends an IHU on this interface, the interval advertised in the IHU TLV is
    /// multiplied by this value to create an IHU hold timer.
    pub(crate) ihu_hold_time_multiple: DurationMultiplier,

    /// Link cost calculator
    #[cfg_attr(feature = "defmt", defmt(Debug2Format))]
    pub(crate) cost_calc: &'static dyn LinkCostCalculator,

    pub(crate) prefer_ucast: bool,

    pub(crate) request_acks: bool,

    /// The number of retries that should be sent on a triggered update.
    ///
    /// This is **NOT** the number of retries that should be sent on a periodic update.
    pub(crate) update_retry_limit: u8,
    pub(crate) update_retry_interval: Interval,
}

impl<A: AddressExt> InternallyKeyed for Interface<A> {
    type Key = InterfaceHandle;
    fn key(&self) -> Self::Key {
        self.handle
    }
}

impl<A: AddressExt> Interface<A> {
    /// Creates a new babel interface with the given interface ID.
    pub fn new(now: Instant, config: InterfaceConfig<A>) -> Result<Self, InterfaceError> {
        Ok(Self {
            handle: config.id,
            address: config.address,
            other_addresses: config.other_addresses,
            hello_timer: Timer::eager_from_interval(now, config.mcast_hello_interval)?,
            ucast_hello_interval: config.ucast_hello_interval,
            hello_seqno: SeqNo::default(),
            update_timer: Timer::from_interval(
                now,
                config
                    .update_interval_spec
                    .apply_to_interval(config.mcast_hello_interval),
            )?,
            ihu_hold_time_multiple: config.ihu_hold_time,
            cost_calc: config.cost_calc,
            prefer_ucast: config.prefer_ucast,
            request_acks: config.request_acks,
            update_retry_limit: config.update_retry_limit,
            update_retry_interval: config.update_retry_interval,
        })
    }

    pub(crate) fn handle(&self) -> &InterfaceHandle {
        &self.handle
    }

    /// The address this interface can be reached at in `family`, or `None` if it has none.
    ///
    /// `None` means the interface cannot name itself in that family, and so cannot advertise
    /// routes in it at all.
    pub(crate) fn address_for_family(
        &self,
        family: &AddressFamily<A::Encoding>,
    ) -> Option<&Address<A>> {
        core::iter::once(&self.address)
            .chain(self.other_addresses.iter().flatten())
            .find(|address| address.encoding().address_family().as_ref() == Some(family))
    }

    pub(crate) fn can_send_mcast_hello(&self, dest: &DestAddr<A>) -> bool {
        dest.is_free() || dest.is_multicast()
    }

    /// Polls this interface for an mcast hello.
    ///
    /// If the write to the writer is successful it will also update the state for the interface.
    pub(crate) fn poll_for_mcast_hello<'output>(
        &mut self,
        now: Instant,
        next_poll: &mut Duration,
        active_dest: &mut DestAddr<A>,
        mut writer: PacketWriterStep<'output, Ready>,
    ) -> Result<
        PacketWriterStep<'output, Ready>,
        (PacketWriterError, PacketWriterStep<'output, Ready>),
    > {
        // If the timer on the interface hello has not fired, update the next_poll and return the
        // writer unchanged.
        if let Some(remaining) = self.hello_timer.time_remaining(now) {
            *next_poll = remaining.min(*next_poll);
            return Ok(writer);
        }

        if !self.can_send_mcast_hello(active_dest) {
            return Ok(writer);
        }

        // If there is no time remaining in the timer, send an mcast hello.
        let flags = HelloFlags::new_multicast();
        let seqno = self.hello_seqno;
        let duration = self.hello_timer.interval();

        b_trace!(
            "[SEND] MCAST HELLO - iface {} - {:?}, {:?}, interval: {}",
            self.handle,
            flags,
            seqno,
            duration.as_centis()
        );
        // Try to claim the destination BEFORE writing to the packet.
        if let Err(err) = active_dest.claim(DestAddr::Multicast) {
            b_debug!("Err: {}", err);
            return Ok(writer);
        }

        writer = writer
            .write_hello(flags, seqno, duration.into())?
            .finish_tlv()?;

        // If the write succeeds, update state.
        // Restart hello timer
        self.hello_timer.restart(now);
        *next_poll = self.hello_timer.duration().min(*next_poll);
        // Increment the seqno
        self.hello_seqno += 1;

        Ok(writer)
    }
}

#[cfg(test)]
mod test {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::data_types::address_encoding::AddressEncoding;
    use crate::extension::NoExtension;

    /// Link-local, so it is a legal Babel source address and carries the `LocalIpv6` encoding —
    /// which is the interesting case for the family collapse below.
    const LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    /// A global IPv6 address, so it carries the `Ipv6` encoding rather than `LocalIpv6`.
    const GLOBAL_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
    const ON_LINK_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const OTHER_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    fn t0() -> Instant {
        Instant::from_secs(0)
    }

    fn config(address: Address<NoExtension>) -> InterfaceConfig<NoExtension> {
        let handle = InterfaceHandle::try_from("eth0").expect("bad interface handle");
        InterfaceConfig::new_wired(handle, address)
    }

    fn interface(config: InterfaceConfig<NoExtension>) -> Interface<NoExtension> {
        Interface::new(t0(), config).expect("bad interface config")
    }

    /// The address a packet is sourced from covers its own family, so a route in that family
    /// inherits it and needs no Next-Hop TLV.
    #[test]
    fn the_primary_address_covers_its_own_family() {
        let iface = interface(config(LINK_LOCAL.into()));

        assert_eq!(
            iface.address_for_family(&AddressFamily::Ipv6),
            Some(&Address::from(LINK_LOCAL))
        );
    }

    /// A link-local and a global IPv6 address are one family, even though they are two encodings
    /// (AE 3 and AE 2). That collapse is what lets a link-local — the only legal Babel source
    /// address on IPv6 — serve as the next hop for globally scoped IPv6 routes.
    #[test]
    fn link_local_and_global_ipv6_are_the_same_family() {
        let iface = interface(config(LINK_LOCAL.into()));

        assert_eq!(
            Address::<NoExtension>::from(LINK_LOCAL).encoding(),
            AddressEncoding::LocalIpv6,
            "the premise: the primary address is AE 3, not AE 2"
        );
        assert_eq!(
            Address::<NoExtension>::from(GLOBAL_V6).encoding(),
            AddressEncoding::Ipv6
        );
        // Asking for the family a *global* v6 route lives in still finds the link-local.
        assert_eq!(
            iface.address_for_family(&AddressFamily::Ipv6),
            Some(&Address::from(LINK_LOCAL))
        );
    }

    /// The whole point of the array: an interface with no IPv4 address cannot name itself in the
    /// IPv4 family, so IPv4 routes are not advertisable on it.
    #[test]
    fn a_family_the_interface_has_no_address_in_is_not_covered() {
        let iface = interface(config(LINK_LOCAL.into()));

        assert_eq!(iface.address_for_family(&AddressFamily::Ipv4), None);
    }

    #[test]
    fn an_added_address_covers_its_family() {
        let mut config = config(LINK_LOCAL.into());
        config
            .add_other_address(ON_LINK_V4.into())
            .expect("v4 is a fresh family");
        let iface = interface(config);

        assert_eq!(
            iface.address_for_family(&AddressFamily::Ipv4),
            Some(&Address::from(ON_LINK_V4))
        );
        // The primary is still found for its own family.
        assert_eq!(
            iface.address_for_family(&AddressFamily::Ipv6),
            Some(&Address::from(LINK_LOCAL))
        );
    }

    /// Only one next hop per family is ever stated, so a second address in a covered family would
    /// never be read. Rejecting it is better than storing something inert.
    #[test]
    fn a_second_address_in_a_covered_family_is_rejected() {
        let mut config = config(LINK_LOCAL.into());
        config
            .add_other_address(ON_LINK_V4.into())
            .expect("v4 is a fresh family");

        assert!(matches!(
            config.add_other_address(OTHER_V4.into()),
            Err(InterfaceError::DuplicateAddressFamily)
        ));
    }

    /// The primary address's family counts as covered too — including across the AE 2 / AE 3 split,
    /// since both are the IPv6 family.
    #[test]
    fn an_address_in_the_primarys_family_is_rejected() {
        let mut config = config(LINK_LOCAL.into());

        assert!(
            matches!(
                config.add_other_address(GLOBAL_V6.into()),
                Err(InterfaceError::DuplicateAddressFamily)
            ),
            "a global v6 address adds nothing to an interface whose primary is link-local"
        );
    }

    #[test]
    fn other_addresses_reports_what_was_added() {
        let mut config = config(LINK_LOCAL.into());
        assert_eq!(config.other_addresses().count(), 0);

        config
            .add_other_address(ON_LINK_V4.into())
            .expect("v4 is a fresh family");

        assert!(config.other_addresses().eq([&Address::from(ON_LINK_V4)]));
    }
}
