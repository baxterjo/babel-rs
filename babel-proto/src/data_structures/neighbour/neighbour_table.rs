use crate::data_structures::interface::{Interface, InterfaceHandle};
use crate::data_structures::neighbour::neighbour_entry::Neighbour;
use crate::data_structures::neighbour::{NeighbourConfig, NeighbourError};
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::utils::{Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt as _};

pub struct NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: ManagedSlice<'storage, Option<Neighbour<A>>>,
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl<'storage, A> Default for NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    fn default() -> Self {
        Self::new()
    }
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
    pub fn new_with_storage<T>(table: T) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
    {
        Self {
            inner: table.into(),
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
        }
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
            Ok(v) if v.is_some() => {
                b_debug!("Duplicate neighbour registered");
                Err(NeighbourError::DuplicateNeighbour(index))
            }
            Ok(_) => Ok(()),
            Err(_err) => {
                b_debug!("Neighbour table is full");
                Err(NeighbourError::Full)
            }
        }
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Neighbour<A>> {
        self.inner.iter_mut().filter_map(|v| v.as_mut())
    }

    pub(crate) fn neighbours_mut_for_iface(
        &mut self,
        iface: InterfaceHandle,
    ) -> impl Iterator<Item = &mut Neighbour<A>> {
        self.iter_mut().filter(move |n| n.iface == iface)
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
            interface.handle,
            address,
            ihu
        );
        neighbour.handle_ihu(now, ihu, interface.ihu_hold_time_multiple)
    }
}
