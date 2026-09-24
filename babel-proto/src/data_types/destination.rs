use crate::data_types::Address;
use crate::data_types::address::AddressError;
use crate::extension::address::AddressExt;
use crate::packet::parser::MAX_ADDRESS_LEN;

#[derive(Debug, Hash, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RouteDestination<A: AddressExt> {
    prefix: Address<A>,
    prefix_len: u8,
}

impl<A: AddressExt> RouteDestination<A> {
    pub(crate) fn new(prefix: Address<A>, prefix_len: u8) -> Result<Self, AddressError<A>> {
        let byte_idx: usize = prefix_len.div_ceil(8).into();
        // The whole address, not the wire form: a link-local `fe80::/100` leaves its first 8 octets
        // implied on the wire, but the prefix length still counts them.
        let prefix_bytes = prefix.as_octets();

        if prefix_bytes.len() < byte_idx {
            return Err(AddressError::IncorrectByteLength {
                address_type: prefix.address_type(),
                required_len: byte_idx,
                len: prefix_bytes.len(),
            });
        }

        Ok(Self { prefix, prefix_len })
    }

    pub(crate) fn prefix(&self) -> &Address<A> {
        &self.prefix
    }

    pub(crate) fn prefix_len(&self) -> &u8 {
        &self.prefix_len
    }

    pub(crate) fn contains(&self, other: &Self) -> bool {
        let mut buf = [0u8; MAX_ADDRESS_LEN];
        if self == other {
            return true;
        }

        if self.prefix.address_type() != other.prefix.address_type() {
            return false;
        }

        if self.prefix_len > other.prefix_len {
            return false;
        }

        // Fetch the bytes in other that are part of the prefix len of self.
        let byte_idx: usize = self.prefix_len.div_ceil(8).into();

        let Some(other_bytes) = other.prefix.as_octets().get(0..byte_idx) else {
            return false;
        };

        buf[0..byte_idx].copy_from_slice(other_bytes);

        // If prefix len is not a multiple of 8, need to shift in erasing bits.
        if self.prefix_len % 8 != 0 {
            let shift_in = 8 - (self.prefix_len % 8);
            let mask = 0xFFu8.unbounded_shl(shift_in.into());
            buf[other_bytes.len() - 1] &= mask;
        }

        self.prefix.as_octets()[0..byte_idx] == buf[0..byte_idx]
    }

    pub(crate) fn is_part_of(&self, other: &Self) -> bool {
        other.contains(self)
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::extension::NoExtension;

    #[test]
    fn same_addresses_contain_eachother() {
        let addr_a: Address<NoExtension> = Address::from(core::net::Ipv4Addr::from([127, 0, 0, 1]));

        let dest_a = RouteDestination::new(addr_a, 20).expect("Bad destination");
        let dest_b = dest_a.clone();

        assert!(dest_a.contains(&dest_b));
        assert!(dest_b.contains(&dest_a));
    }

    #[test]
    fn prefix_addr_contains_specific_addr() {
        let addr_a: Address<NoExtension> = Address::from(core::net::Ipv4Addr::from([127, 0, 0, 1]));
        let addr_b = addr_a.clone();

        let dest_a = RouteDestination::new(addr_a, 10).expect("Bad destination");
        let dest_b = RouteDestination::new(addr_b, 20).expect("Bad destination");

        assert!(dest_a.contains(&dest_b));
        assert!(!dest_b.contains(&dest_a));

        assert!(dest_b.is_part_of(&dest_a));
        assert!(!dest_a.is_part_of(&dest_b));
    }
}
