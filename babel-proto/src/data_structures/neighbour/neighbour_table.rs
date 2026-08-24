use crate::data_structures::interface::InterfaceHandle;
use crate::data_structures::neighbour::NeighbourTableError;
use crate::data_structures::neighbour::neighbour_entry::{
    DEFAULT_HOLD_TIME_MULTIPLIER, Neighbour, NeighbourIndex,
};
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::packet::tlv::{HelloSlice, IhuSlice};
use crate::utils::timer::Timer;
use crate::utils::{
    Duration, DurationMultiplier, Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt as _,
};

pub struct NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: ManagedSlice<'storage, Option<Neighbour<A>>>,
    /// The hold time of a neighbour between receiving IHU TLVs.
    pub(crate) hold_time: DurationMultiplier,
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
            hold_time: DEFAULT_HOLD_TIME_MULTIPLIER,
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
            hold_time: DEFAULT_HOLD_TIME_MULTIPLIER,
        }
    }

    fn get_or_insert_default(
        &mut self,
        now: Instant,
        index: &NeighbourIndex<A>,
    ) -> Result<&mut Neighbour<A>, NeighbourTableError<A>> {
        // If the neighbour doesnt exist, create it.
        if self.inner.get_mut_by_key(index).is_none() {
            self.add_neighbour(now, index, None)?;
        }

        // Now return a mutable reference
        let neighbour = self
            .inner
            .get_mut_by_key(index)
            .expect("Could not get neighbour just inserted into table?");

        Ok(neighbour)
    }

    pub fn add_neighbour(
        &mut self,
        now: Instant,
        index: &NeighbourIndex<A>,
        ucast_hello_interval: Option<Duration>,
    ) -> Result<(), NeighbourTableError<A>> {
        let timer_opt = ucast_hello_interval
            .map(|int| Timer::new(now, int))
            .transpose()?;

        let neighbour = Neighbour::new(now, index.0, index.1, timer_opt);
        let index = neighbour.key();

        b_debug!("Registering neighbour: {:?}", index);

        match self.inner.insert(neighbour) {
            Ok(v) if v.is_some() => {
                b_debug!("Duplicate neighbour registered");
                Err(NeighbourTableError::DuplicateNeighbour(index))
            }
            Ok(_) => Ok(()),
            Err(_err) => {
                b_debug!("Neighbour table is full");
                Err(NeighbourTableError::Full)
            }
        }
    }

    pub(crate) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Neighbour<A>> {
        self.inner.iter_mut().filter_map(|v| v.as_mut())
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
        interface: InterfaceHandle,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<(), NeighbourTableError<A>> {
        let neighbour = self.get_or_insert_default(now, &NeighbourIndex(interface, address))?;
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
    pub fn handle_ihu(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ihu: IhuSlice<'_>,
    ) -> Result<(), NeighbourTableError<A>> {
        let hold_time = self.hold_time;

        let neighbour = self.get_or_insert_default(now, &NeighbourIndex(interface, address))?;
        b_debug!(
            "[RECV] IHU - iface: {:?}, addr: {:?} - {:?}",
            interface,
            address,
            ihu
        );
        neighbour.handle_ihu(now, ihu, hold_time)?;
        Ok(())
    }
}
