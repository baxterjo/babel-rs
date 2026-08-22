use managed::ManagedSlice;
use thiserror::Error;

use crate::{
    data_structures::interface::DEFAULT_MULTICAST_HELLO_INTERVAL_SECS,
    data_types::address::Address,
    extension::address::AddressExt,
    packet::tlv::{HelloSlice, IhuSlice},
    utils::{
        bit_history::BitHistory,
        rx_cost::RxCost as TxCost,
        storage::{InternallyKeyed, ManagedSliceExt},
        timer::{Timer, TimerError},
        Duration, Instant, IntervalMultiplier as HoldTimeMultiplier,
    },
};

use super::{interface::InterfaceHandle, seqno::SeqNo};

pub const DEFAULT_NEIGHBOUR_EXPIRY_SECS: u64 = 10;

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

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourIndex<A>(pub InterfaceHandle, pub Address<A>)
where
    A: AddressExt;

/// A neighbour table entry as defined in section
/// [3.2.4](https://datatracker.ietf.org/doc/html/rfc8966#name-the-neighbour-table)
///
/// Note: To drive the sans-io state machine for this crate additional state is required for event
/// driven TLVs.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbour<A: AddressExt> {
    // Protocol state as defined by SPEC
    /// the local node's interface over which this neighbour is reachable
    pub(crate) iface: InterfaceHandle,

    /// the address of the neighbouring interface
    pub(crate) address: Address<A>,

    /// State data of a neighbour that has either been added manually or has recevied a hello.
    pub(crate) state: NeighbourInitState,

    /// the 'transmission cost' value from the last IHU packet received from this
    /// neighbour, or FFFF hexadecimal (infinity) if the IHU hold timer for this neighbour has
    /// expired
    ///
    /// Infinity if this router has never received an IHU from this neighbour.
    pub(crate) tx_cost: TxCost,

    /// and the IHU timer, which is set to a small multiple of the interval carried in IHU TLVs
    /// (see "IHU Hold time" in Appendix B for suggested values).
    ///
    /// None if this router has never received an IHU from this neighbour.
    pub(crate) ihu_timer: Option<Timer>,

    // Scheduling state, required to drive Sans-IO state machine.
    /// Pending TLV's that need to go out during `poll_transmit`
    pub(crate) pending: NeighbourPending,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum NeighbourInitState {
    /// If the neighbour was added through an out of band method. Then this router has never
    /// received a hello from it. So we set an expiry timer for it.
    Expiry(Timer),
    /// If the this router has recevied a hello for this neighbour, then the hello info is stored here.
    HelloReceived(HelloReceived),
}

#[derive(Debug, Default, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct HelloReceived {
    /// a history of recently received Unicast Hello packets from this neighbour
    ///
    /// the expected incoming Unicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// None if this router has never received a unicast hello from this neighbour
    ucast_hello: Option<RxHelloInfo>,
    /// a history of recently received Multicast Hello packets from this neighbour; this
    /// can, for example, be a sequence of n bits, for some small value n, indicating which of the n
    /// hellos most recently sent by this neighbour have been received by the local node.
    /// the expected incoming Multicast Hello sequence number for this neighbour, an
    /// integer modulo 2^16
    ///
    /// the multicast hellotimer, which is set to the interval value carried by scheduled Multicast
    /// Hello TLVs sent by this neighbour
    ///
    /// None if this router has never received a multicast hello from theis neighbour.
    mcast_hello: Option<RxHelloInfo>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct RxHelloInfo {
    history: BitHistory,
    expected_seqno: SeqNo,
    timer: Timer,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct TxHelloInfo {
    pub(crate) seqno: SeqNo,
    pub(crate) timer: Timer,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NeighbourPending {
    /// If this node should send unicast hellos to this neighbour, set its timer.
    ///
    /// The spec suggests never sending unicast hellos
    /// [Appendix B. - 4.4](https://datatracker.ietf.org/doc/html/rfc8966#section-appendix.b-4.4).
    /// But the spec is also written for only IP based transports where multicast can be assumed to
    /// work well.
    pub(crate) ucast_hello: Option<TxHelloInfo>,
    /// Timer for sending periodic IHU's to this neighbour.
    ///
    /// None if router has never received a hello from this neighbour.
    pub(crate) ihu_timer: Option<Timer>,
}

impl<A: AddressExt> InternallyKeyed for Neighbour<A> {
    type Key = NeighbourIndex<A>;
    fn key(&self) -> Self::Key {
        NeighbourIndex(self.iface, self.address)
    }
}

impl<A: AddressExt> Neighbour<A> {
    fn new(
        interface: InterfaceHandle,
        address: Address<A>,
        ucast_hello: Option<Timer>,
        init_state: NeighbourInitState,
    ) -> Self {
        Self {
            iface: interface,
            address,
            state: init_state,
            tx_cost: TxCost(u16::MAX),
            ihu_timer: None,
            pending: NeighbourPending {
                ucast_hello: ucast_hello.map(|t| TxHelloInfo {
                    seqno: SeqNo(0),
                    timer: t,
                }),
                ihu_timer: None,
            },
        }
    }

    fn handle_hello(&mut self, now: Instant, hello: HelloSlice<'_>) {
        let flags = hello.flags();
        let seqno = hello.seqno();
        let interval = hello.interval();

        // Duration to be used in periodic IHU's if no better duration is given.
        let ihu_dur: Duration;

        let mut hello_info = match self.state {
            // If a hello has been received in the past, grab it.
            NeighbourInitState::HelloReceived(hello_info) => hello_info,
            // Otherwise create a new one.
            _ => HelloReceived::default(),
        };

        if flags.is_unicast() {
            let history = match &mut hello_info.ucast_hello {
                // If the router has received a hello from this neighbour in the past. Calculate
                // any missed hellos that may have occured.
                Some(ucast_info) => {
                    let hello_gap = seqno - ucast_info.expected_seqno;
                    ucast_info.history.record_many(false, hello_gap.0.into());
                    ucast_info.history
                }
                None => BitHistory::new(),
            };

            let expected_seqno = seqno + 1;

            let timer_dur = match &mut hello_info.ucast_hello {
                // If the hello is scheduled, use the new interval.
                Some(_ucast_info) if hello.is_scheduled() => interval.into(),
                // If not, use the old interval or a default value.
                Some(ucast_info) => ucast_info.timer.duration(),
                None => Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS),
            };
            ihu_dur = timer_dur * 2;

            let timer = Timer::new(now, timer_dur).expect("Interval bounds were pre-checked");

            hello_info.ucast_hello = Some(RxHelloInfo {
                history,
                expected_seqno,
                timer,
            });
        } else {
            let history = match &mut hello_info.mcast_hello {
                // If the router has received a hello from this neighbour in the past. Calculate
                // any missed hellos that may have occured.
                Some(mcast_info) => {
                    let hello_gap = seqno - mcast_info.expected_seqno;
                    mcast_info.history.record_many(false, hello_gap.0.into());
                    mcast_info.history
                }
                None => BitHistory::new(),
            };

            let expected_seqno = seqno + 1;

            let timer_dur = match &mut hello_info.mcast_hello {
                // If the hello is scheduled, use the new interval.
                Some(mcast_info) if hello.is_scheduled() => interval.into(),
                // If not, use the old interval or a default value.
                Some(mcast_info) => mcast_info.timer.duration(),
                None => Duration::from_secs(DEFAULT_MULTICAST_HELLO_INTERVAL_SECS),
            };
            ihu_dur = timer_dur * 2;

            let timer = Timer::new(now, timer_dur).expect("Interval bounds were pre-checked");

            hello_info.mcast_hello = Some(RxHelloInfo {
                history,
                expected_seqno,
                timer,
            });
        }

        // Update the state
        self.state = NeighbourInitState::HelloReceived(hello_info);

        let new_ihu_timer = match self.pending.ihu_timer {
            Some(mut timer) => {
                // If there was already an IHU timer, set it under the spec rules (increase creates
                // an eager timer, decrease does not.)
                timer
                    .set_duration(ihu_dur)
                    .expect("Interval bounds were pre-checked");
                Some(timer)
            }
            // If no IHU timer was set, set an eager timer.
            None => Some(Timer::new_eager(now, ihu_dur).expect("Interval bounds were pre-checked")),
        };
        self.pending.ihu_timer = new_ihu_timer;
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

        // TODO: Need some tx cost calculation here.
        self.tx_cost = rx_cost;

        Ok(())
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    #[error(transparent)]
    Timer(#[from] TimerError),
}
