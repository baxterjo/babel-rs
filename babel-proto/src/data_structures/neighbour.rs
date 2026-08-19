use managed::ManagedSlice;
use thiserror::Error;

use crate::{
    data_types::{address::Address, Interval},
    extension::address::AddressExt,
    packet::tlv::{HelloSlice, IhuSlice},
    utils::{
        bit_history::BitHistory,
        rx_cost::RxCost as TxCost,
        storage::{InternallyKeyed, ManagedSliceExt},
        timer::Timer,
        Duration, Instant, IntervalMultiplier as HoldTimeMultiplier,
    },
};

use super::{interface::InterfaceHandle, seqno::SeqNo};

pub struct NeighbourTable<'storage, A>
where
    A: AddressExt,
{
    inner: ManagedSlice<'storage, Option<Neighbour<A>>>,
    /// The hold time of a neighbour between receiving IHU TLVs.
    hold_time: HoldTimeMultiplier,
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
        ucast_hello_interval: Option<Interval>,
    ) -> Result<(), NeighbourTableError<A>> {
        let neighbour = Neighbour::new(now, index.0, index.1, ucast_hello_interval)?;
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

    pub fn handle_hello(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        hello: HelloSlice<'_>,
    ) -> Result<(), NeighbourTableError<A>> {
        let neighbour = self.get_or_insert_default(now, &NeighbourIndex(interface, address))?;

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
        let neighbour = self.get_or_insert_default(now, &NeighbourIndex(interface, address))?;
        Ok(())
    }
}

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct NeighbourIndex<A>(pub InterfaceHandle, pub Address<A>)
where
    A: AddressExt;

/// A neighbour table entry as defined in section
/// [3.2.4](https://datatracker.ietf.org/doc/html/rfc8966#name-the-neighbour-table)
///
/// Note: To drive the sans-io state machine for this crate additional state is required for event
/// driven TLVs.
#[derive(Debug)]
pub struct Neighbour<A: AddressExt> {
    // Protocol state as defined by SPEC
    /// the local node's interface over which this neighbour is reachable
    iface: InterfaceHandle,

    /// the address of the neighbouring interface
    address: Address<A>,

    /// a history of recently received Multicast Hello packets from this neighbour; this
    /// can, for example, be a sequence of n bits, for some small value n, indicating which of the n
    /// hellos most recently sent by this neighbour have been received by the local node.
    mcast_hello_history: BitHistory,

    /// a history of recently received Unicast Hello packets from this neighbour
    ucast_hello_history: BitHistory,

    /// the 'transmission cost' value from the last IHU packet received from this
    /// neighbour, or FFFF hexadecimal (infinity) if the IHU hold timer for this neighbour has
    /// expired
    ///
    /// None if this router has never received an IHU from this neighbour.
    tx_cost: Option<TxCost>,

    /// the expected incoming Multicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// None if this router has never received a multicast hello from theis neighbour.
    expected_mcast_seqno: Option<SeqNo>,

    /// the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// None if this router has never received a unicast hello from this neighbour.
    expected_ucast_seqno: Option<SeqNo>,

    /// the outgoing Unicast Hello sequence number for this neighbour, an integer modulo
    /// 2^16 that is sent with each Unicast Hello TLV to this neighbour and is incremented (modulo
    /// 2^16) whenever a Unicast Hello is sent. (Note that the outgoing Unicast Hello seqno for a
    /// neighbour is distinct from the interface's outgoing Multicast Hello seqno.)
    ///
    /// None if this router has never received a unicast hello from this neighbour.
    outgoing_ucast_seqno: SeqNo,

    /// There are three timers associated with each neighbour entry --
    /// the multicast hellotimer, which is set to the interval value carried by scheduled Multicast
    /// Hello TLVs sent by this neighbour
    ///
    /// None if this router has never received a multicast hello from this neighbour.
    mcast_hello_timer: Option<Timer>,

    /// the unicast hello timer, which is set to the interval value carried by scheduled Unicast
    /// Hello TLVs
    ucast_hello_timer: Option<Timer>,

    /// and the IHU timer, which is set to a small multiple of the interval carried in IHU TLVs
    /// (see "IHU Hold time" in Appendix B for suggested values).
    ///
    /// None if this router has never received an IHU from this neighbour.
    ihu_timer: Option<Timer>,
    // Scheduling state, required to drive Sans-IO state machine.
    /// Pending TLV's that need to go out during `poll_transmit`
    pending: NeighbourPending,
}

impl<A: AddressExt> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex(self.iface, self.address)
    }
}

impl<A: AddressExt> Neighbour<A> {
    fn new(
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
        ucast_hello: Option<Interval>,
    ) -> Result<Self, NeighbourTableError<A>> {
        Ok(Self {
            iface: interface,
            address,
            mcast_hello_history: BitHistory::new(),
            ucast_hello_history: BitHistory::new(),
            tx_cost: None,
            expected_mcast_seqno: None,
            expected_ucast_seqno: None,
            outgoing_ucast_seqno: SeqNo(0),
            mcast_hello_timer: None,
            ucast_hello_timer: None,
            ihu_timer: None,
            pending: NeighbourPending {
                ucast_hello: ucast_hello
                    .map(|i| Timer::new(now, i.into()).ok())
                    .ok_or(NeighbourTableError::IntervalCannotBeZero)?,
                ihu_due: false,
            },
        })
    }

    fn handle_hello(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        if flags.is_unicast() {
            // Handle Seqno.
            if let Some(hello_gap) = self.expected_ucast_seqno.map(|exp| seqno - exp) {
                // If expected equals sent, this will record zero misses.
                self.ucast_hello_history
                    .record_many(false, hello_gap.0.into());
            };
            self.expected_ucast_seqno = Some(seqno + 1);

            // Handle interval
            if interval.as_centis() > 0 {
                self.ucast_hello_timer = Some(
                    Timer::new(now, interval.into())
                        .expect("Just checked that interval is not zero"),
                );
            }
        } else {
            // Handle Seqno.
            if let Some(hello_gap) = self.expected_mcast_seqno.map(|exp| seqno - exp) {
                // If expected equals sent, this will record zero misses.
                self.mcast_hello_history
                    .record_many(false, hello_gap.0.into());
            };
            self.expected_mcast_seqno = Some(seqno + 1);

            // Handle interval
            if interval.as_centis() > 0 {
                self.mcast_hello_timer = Some(
                    Timer::new(now, interval.into())
                        .expect("Just checked that interval is not zero"),
                );
            }
        }

        self.pending.ihu_due = true;
    }

    fn handle_ihu(
        &mut self,
        now: Instant,
        ihu: IhuSlice<'_>,
        hold_time: HoldTimeMultiplier,
    ) -> Result<(), NeighbourTableError<A>> {
        let rx_cost = ihu.rx_cost();
        let interval = ihu.interval();

        let timer_dur: Duration = interval.into();

        self.ihu_timer = Some(
            Timer::new(now, timer_dur * hold_time)
                .map_err(|_| NeighbourTableError::IntervalCannotBeZero)?,
        );

        self.tx_cost = Some(rx_cost);

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct NeighbourPending {
    /// If this node should send unicast hellos to this neighbour, set its timer.
    ///
    /// The spec suggests never sending unicast hellos
    /// [Appendix B. - 4.4](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.4).
    /// But the spec is also written for only IP based transports where multicast can be assumed to
    /// work well.
    ucast_hello: Option<Timer>,
    /// An IHU is due to this neighbour
    ihu_due: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NeighbourTableError<A: AddressExt> {
    /// The storage given for the interface table is full.
    #[error("Neighbour table is full")]
    Full,
    /// In this instance the neighbour is still added to the neighbour table, and the index
    /// inside the error is still valid for referencing the neighbour. The user can decide what
    /// they want to do with this error.
    #[error("A neighbour with the same index was added twice: {0}")]
    DuplicateNeighbour(NeighbourIndex<A>),
    #[error("Interval cannot be zero")]
    IntervalCannotBeZero,
}
