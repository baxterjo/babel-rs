use crate::{
    data_structures::{
        interface::InterfaceHandle,
        neighbour::{
            NeighbourTableError,
            neighbour_entry::{
                DEFAULT_NEIGHBOUR_EXPIRY_SECS, Neighbour, NeighbourIndex, NeighbourInitState,
            },
        },
    },
    data_types::{Address, address_encoding::AddressEncoding},
    extension::address::AddressExt,
    packet::tlv::{HelloSlice, IhuSlice},
    utils::{
        Duration, HoldTimeMultiplier, Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt as _,
        timer::Timer,
    },
};

pub struct NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    pub(crate) inner: ManagedSlice<'storage, Option<Neighbour<A>>>,
    /// The hold time of a neighbour between receiving IHU TLVs.
    pub(crate) hold_time: HoldTimeMultiplier,
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
            hold_time: HoldTimeMultiplier::IHU_HOLD_TIME_SPEC_DEFAULT,
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new() -> Self {
        Self {
            inner: ManagedSlice::Owned(Default::default()),
            hold_time: HoldTimeMultiplier::IHU_HOLD_TIME_SPEC_DEFAULT,
        }
    }

    fn get_or_insert_default(
        &mut self,
        now: Instant,
        index: &NeighbourIndex<A>,
    ) -> Result<&mut Neighbour<A>, NeighbourTableError<A>> {
        // If the neighbour doesnt exist, create it.
        if self.inner.get_mut_by_key(index).is_none() {
            self.add_neighbour(
                now,
                index,
                Duration::from_secs(DEFAULT_NEIGHBOUR_EXPIRY_SECS),
                None,
            )?;
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
        expiry: Duration,
        ucast_hello_interval: Option<Duration>,
    ) -> Result<(), NeighbourTableError<A>> {
        let timer_opt = ucast_hello_interval
            .map(|int| Timer::new(now, int.into()))
            .transpose()?;

        let expiry = Timer::new(now, expiry)?;

        let neighbour = Neighbour::new(
            index.0,
            index.1,
            timer_opt,
            NeighbourInitState::Expiry(expiry),
        );
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

    pub fn handle_ihu(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ihu: IhuSlice<'_>,
    ) -> Result<(), NeighbourTableError<A>> {
        let hold_time = self.hold_time;

        // If the address the IHU was received on is a multicast address, then the neighbour
        // address needs to be resolved from the TLV.
        let resolved_address = if address.is_multicast() {
            let ae = AddressEncoding::try_from(ihu.ae())?;
            let addr_len = ae.address_len();
            let address_bytes = ihu.address(addr_len)?;
            Address::from_bytes(ae, address_bytes)?
        } else {
            address
        };
        let neighbour =
            self.get_or_insert_default(now, &NeighbourIndex(interface, resolved_address))?;
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
