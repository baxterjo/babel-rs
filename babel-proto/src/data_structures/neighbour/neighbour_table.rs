use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::neighbour::neighbour_entry::Neighbour;
use crate::data_structures::neighbour::{NeighbourConfig, NeighbourError, NeighbourIndex};
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::utils::storage::{InsertError, Table};
use crate::utils::{Instant, InternallyKeyed, ManagedSlice};

pub struct NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: Table<'storage, Option<Neighbour<A>>>,
}

impl<'storage, A> NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new [`NeighbourTable`] with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of neighbors this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment.
    pub(crate) fn new_with_storage<T>(storage: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
    {
        Self {
            inner: Table::new(storage),
        }
    }

    pub(crate) fn neighbours_for_iface(
        &self,
        iface: &InterfaceHandle,
    ) -> impl Iterator<Item = &Neighbour<A>> {
        self.inner.iter().filter(move |n| n.interface() == iface)
    }

    pub(crate) fn neighbours_mut_for_iface(
        &mut self,
        iface: &InterfaceHandle,
    ) -> impl Iterator<Item = &mut Neighbour<A>> {
        self.inner
            .iter_mut()
            .filter(move |n| n.interface() == iface)
    }

    fn get_or_insert_default(
        &mut self,
        now: Instant,
        address: Address<A>,
        interface: &Interface<A>,
    ) -> Result<&mut Neighbour<A>, NeighbourError<A>> {
        let config = NeighbourConfig::interface_default(address, interface);
        let index = config.index();
        // If the neighbour doesnt exist, create it.
        if self.inner.get_mut_by_key(&index).is_none() {
            self.add_neighbour(now, config)?;
        }

        // Now return a mutable reference
        let neighbour = self
            .inner
            .get_mut_by_key(&index)
            .expect("Could not get neighbour just inserted into table?");

        Ok(neighbour)
    }

    pub fn add_neighbour(
        &mut self,
        now: Instant,
        config: NeighbourConfig<A>,
    ) -> Result<(), NeighbourError<A>> {
        let neighbour = Neighbour::new(now, config)?;
        let index = neighbour.key();

        b_debug!("Registering neighbour: {:?}", index);

        match self.inner.insert(neighbour) {
            Ok(()) => Ok(()),
            Err(InsertError::Duplicate(_)) => {
                b_debug!("Duplicate neighbour registered");
                Err(NeighbourError::DuplicateNeighbour(index))
            }
            Err(InsertError::Full(_)) => {
                b_debug!("Neighbour table is full");
                Err(NeighbourError::Full)
            }
        }
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Neighbour<A>> {
        self.inner.iter_mut()
    }

    //  _    _          _   _ _____  _      ______
    // | |  | |   /\   | \ | |  __ \| |    |  ____|
    // | |__| |  /  \  |  \| | |  | | |    | |__
    // |  __  | / /\ \ | . ` | |  | | |    |  __|
    // | |  | |/ ____ \| |\  | |__| | |____| |____
    // |_|  |_/_/    \_\_| \_|_____/|______|______|
    //
    //
    //  _____ _   _ _____  _    _ _______
    // |_   _| \ | |  __ \| |  | |__   __|
    //   | | |  \| | |__) | |  | |  | |
    //   | | | . ` |  ___/| |  | |  | |
    //  _| |_| |\  | |    | |__| |  | |
    // |_____|_| \_|_|     \____/   |_|

    pub fn handle_hello(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<(), NeighbourError<A>> {
        let neighbour = self.get_or_insert_default(now, address, interface)?;
        b_debug!(
            "[RECV] Hello - iface: {:?}, addr: {:?} - {:?}",
            interface,
            address,
            hello
        );
        neighbour.handle_hello(now, hello);

        Ok(())
    }

    /// Applies an IHU that has already been confirmed as addressed to this node.
    ///
    /// `address` is the sender's address. The IHU's own Address field names its *destination*
    /// rather than its sender, so it plays no part in identifying the neighbour; the caller uses
    /// it to decide whether the IHU was meant for us at all.
    ///
    /// Returns `true` if the route selection procedure needs to be run.
    pub fn handle_ihu(
        &mut self,
        now: Instant,
        address: Address<A>,
        interface: &Interface<A>,
        ihu: IhuSlice<'_>,
    ) -> Result<bool, NeighbourError<A>> {
        let neighbour = self.get_or_insert_default(now, address, interface)?;
        b_debug!(
            "[RECV] IHU - iface: {:?}, addr: {:?} - {:?}",
            interface.handle(),
            address,
            ihu
        );
        neighbour.handle_ihu(now, ihu, interface.ihu_hold_time_multiple)
    }
}

#[cfg(all(test, any(feature = "std", feature = "alloc")))]
mod test {
    use alloc::vec::Vec;
    use core::net::Ipv6Addr;

    use super::*;
    use crate::data_types::Interval;
    use crate::extension::NoExtension;
    use crate::utils::Duration;

    const NEIGHBOUR_1: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);

    fn iface_handle() -> InterfaceHandle {
        InterfaceHandle::try_from("eth0").expect("bad interface handle")
    }

    fn index(addr: Ipv6Addr) -> NeighbourIndex<NoExtension> {
        NeighbourIndex {
            iface: iface_handle(),
            addr: addr.into(),
        }
    }

    fn config(addr: Ipv6Addr) -> NeighbourConfig<NoExtension> {
        NeighbourConfig::spec_default(iface_handle(), addr.into())
    }

    /// Registering an index the table already holds is a duplicate, not a full table.
    ///
    /// The two are worth keeping apart: `Full` says the deployment under-sized its storage, while
    /// `DuplicateNeighbour` says the caller asked for something it already has and hands back the
    /// index it can use to reach it. [`Table::insert`] reports both through the same `Err`, so
    /// nothing but this mapping stops a duplicate from being blamed on capacity.
    ///
    /// [`Table::insert`]: crate::utils::storage::Table::insert
    #[test]
    fn registering_the_same_neighbour_twice_is_a_duplicate_not_a_full_table() {
        let mut table: NeighbourTable<'_, NoExtension> =
            NeighbourTable::new_with_storage(Vec::new());
        let now = Instant::from_secs(0);

        table
            .add_neighbour(now, config(NEIGHBOUR_1))
            .expect("the first registration should succeed");

        let err = table
            .add_neighbour(now, config(NEIGHBOUR_1))
            .expect_err("the second registration should be rejected");

        assert!(
            matches!(err, NeighbourError::DuplicateNeighbour(idx) if idx == index(NEIGHBOUR_1)),
            "a duplicate on owned storage, which can always grow, must not report Full: {err:?}"
        );
    }

    /// A rejected duplicate leaves the table exactly as it was.
    ///
    /// The incoming config is dropped rather than written over the entry already there, so the
    /// live neighbour keeps the state it has accumulated — hello history, costs, timers — instead
    /// of being silently reset by a stray re-registration.
    #[test]
    fn a_rejected_duplicate_leaves_the_existing_neighbour_untouched() {
        let mut table: NeighbourTable<'_, NoExtension> =
            NeighbourTable::new_with_storage(Vec::new());
        let now = Instant::from_secs(0);

        // The spec default asks for no unicast hellos, so the entry starts without that timer.
        table
            .add_neighbour(now, config(NEIGHBOUR_1))
            .expect("the first registration should succeed");

        // Re-register the same index asking for unicast hellos. If the duplicate were to
        // overwrite, the surviving entry would carry this timer.
        let mut ucast_config = config(NEIGHBOUR_1);
        ucast_config.ucast_hello_interval = Some(Interval::from_duration(Duration::from_secs(600)));
        let _ = table.add_neighbour(now, ucast_config);

        assert_eq!(
            table.inner.iter().count(),
            1,
            "the duplicate must not add a row"
        );
        let neighbour = table
            .inner
            .get_by_key(&index(NEIGHBOUR_1))
            .expect("registered above");
        assert!(
            neighbour.pending.ucast_hello.is_none(),
            "the original entry should have survived, not been replaced by the incoming config"
        );
    }
}
