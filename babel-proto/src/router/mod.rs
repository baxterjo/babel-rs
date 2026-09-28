use core::marker::PhantomData;

use crate::BorrowedMemoryPool;
use crate::data_structures::interface::{
    Interface, InterfaceConfig, InterfaceHandle, InterfaceTable,
};
use crate::data_structures::neighbour::{
    Neighbour, NeighbourConfig, NeighbourIndex, NeighbourTable,
};
use crate::data_structures::pending_seqno::{PendingSeqnoRequestTable, SeqnoRequest};
use crate::data_structures::route::{Route, RouteIndex, RouteTable};
use crate::data_structures::source::{Source, SourceTable};
use crate::data_structures::updates::{Update, UpdateQueue};
use crate::data_types::{Address, RouterId};
use crate::error::BabelError;
use crate::extension::address::AddressExt;
use crate::extension::parser_state::ParserStateExt;
use crate::extension::{NoExtension, NoStateExtension};
use crate::metric::Metric;
use crate::router::config::BabelRouterConfig;
use crate::utils::{Instant, InternallyKeyed, ManagedSlice, Timer};

pub mod config;
pub mod handle_input;
pub mod poll_output;

pub struct BabelRouter<'storage, P = NoStateExtension, A = NoExtension>
where
    P: ParserStateExt,
    A: AddressExt,
{
    /// Router ID of this Babel router. This must be globally unique within your routing domain.
    pub(crate) id: RouterId,

    // Implementation config
    pub(crate) update_timer: Timer,

    pub(crate) magic_number: u8,

    pub(crate) version_number: u8,

    // Tables
    pub(crate) iface_table: InterfaceTable<'storage, A>,

    pub(crate) neighbor_table: NeighbourTable<'storage, A>,

    pub(crate) pending_seqno: PendingSeqnoRequestTable<'storage, A>,

    pub(crate) route_table: RouteTable<'storage, A>,

    pub(crate) source_table: SourceTable<'storage, A>,

    pub(crate) update_queue: UpdateQueue<'storage, A>,

    // Router state
    pub(crate) route_selection_due: bool,

    // Extension markers
    _state_ext_marker: PhantomData<P>,
    _addr_ext_marker: PhantomData<A>,
}

impl<'storage, A, P> BabelRouter<'storage, P, A>
where
    A: AddressExt,
    P: ParserStateExt,
{
    /// Create a new Babel Router from config.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn new(now: Instant, config: BabelRouterConfig) -> Self {
        use alloc::vec::Vec;
        Self::new_with_storage_inner(
            now,
            config,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// Create a new Babel Router with user provided, statically sized storage.
    pub fn new_with_storage(
        now: Instant,
        config: BabelRouterConfig,
        storage: BorrowedMemoryPool<'storage, A>,
    ) -> Self {
        Self::new_with_storage_inner(
            now,
            config,
            storage.interface_table,
            storage.neighbour_table,
            storage.pending_seqno_table,
            storage.route_table,
            storage.source_table,
            storage.update_queue,
        )
    }

    fn new_with_storage_inner<IF, N, PS, R, S, U>(
        now: Instant,
        config: BabelRouterConfig,
        interface_table: IF,
        neighbour_table: N,
        pending_seqno_table: PS,
        route_table: R,
        source_table: S,
        update_queue: U,
    ) -> Self
    where
        IF: Into<ManagedSlice<'storage, Option<Interface<A>>>>,
        N: Into<ManagedSlice<'storage, Option<Neighbour<A>>>>,
        PS: Into<ManagedSlice<'storage, Option<SeqnoRequest<A>>>>,
        R: Into<ManagedSlice<'storage, Option<Route<A>>>>,
        S: Into<ManagedSlice<'storage, Option<Source<A>>>>,
        U: Into<ManagedSlice<'storage, Option<Update<A>>>>,
    {
        Self {
            id: config.id,
            update_timer: Timer::from_interval(now, config.update_interval),
            magic_number: config.magic_number,
            version_number: config.version,
            iface_table: InterfaceTable::new_with_storage(interface_table),
            neighbor_table: NeighbourTable::new_with_storage(neighbour_table),
            pending_seqno: PendingSeqnoRequestTable::new_with_storage(pending_seqno_table),
            route_table: RouteTable::new_with_storage(route_table, config.route_expiry_multiplier),
            source_table: SourceTable::new_with_storage(source_table),
            update_queue: UpdateQueue::new_with_storage(update_queue),
            route_selection_due: false,
            _state_ext_marker: PhantomData,
            _addr_ext_marker: PhantomData,
        }
    }

    /// Register a new interface with the router.
    ///
    /// The returned handle will be used to refer to the real interface that packets will be sent
    /// and receieved on.
    pub fn register_interface(
        &mut self,
        now: Instant,
        config: InterfaceConfig<A>,
    ) -> Result<InterfaceHandle, BabelError<A>>
    where
        A: AddressExt,
    {
        Ok(self.iface_table.register_interface(now, config)?)
    }

    /// Add a new neighbour to the router.
    ///
    /// Babel is designed to discover neighbours through multicast hello TLVs. But it allows for
    /// neighbours to be discovered through methods outside of the routing protocol. If there is
    /// some out of band method for neighbour discovery in your application, this is where you will
    /// tell the router about the existance of the neighbour.
    ///
    /// Once the neighbour has been added through this method, it must still conform to the spec to
    /// stay in the neighbour table. If it does not receive any hellos, it will eventually be
    /// removed from the neighbour table.
    pub fn add_neighbour(
        &mut self,
        now: Instant,
        interface: InterfaceHandle,
        address: Address<A>,
    ) -> Result<(), BabelError<A>> {
        // If the interface doesn't exist then the neighbour can't be created.
        let Some(iface) = self.iface_table.inner.get_by_key(&interface) else {
            return Err(BabelError::InterfaceDoesntExist(interface));
        };

        let config = NeighbourConfig::interface_default(address, iface);

        Ok(self.neighbor_table.add_neighbour(now, config)?)
    }

    /// Runs metric updates for all of the routes advertised by this neighbour.
    ///
    /// The work is [`RouteTable::update_metrics_for_neighbour`]. This resolves the index its
    /// callers hold to the entry it names, and hands the route table the two tables a triggered
    /// update needs to reach every neighbour on every interface.
    pub(crate) fn update_metrics_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour_idx: NeighbourIndex<A>,
    ) {
        let Some(neighbour) = self.neighbor_table.inner.get_by_key(&neighbour_idx) else {
            b_debug!("Cannot update metrics for non-existant neighbour.");
            return;
        };

        self.route_table.update_metrics_for_neighbour(
            now,
            interface,
            neighbour,
            &self.iface_table,
            &self.neighbor_table,
            &mut self.update_queue,
        )
    }

    /// The recommended route selection procedure as defined in
    /// [Section 3.6](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    /// and [Appendix A.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-selection)
    ///
    /// This method selects routes and publishes updates triggered as a result of route selection.
    fn select_routes(&mut self, now: Instant) {
        // A shared borrow of one field while `route_table` is borrowed mutably below.
        let source_table = &self.source_table;

        b_debug!("Route selection...");

        for mut destination_group in self.route_table.destination_groups_mut() {
            let dest = destination_group.destination();
            b_debug!("{:?} options for {:?}", dest, destination_group.len());
            // The route this destination was pointing at before this run, whether or not it is
            // still usable. Only the change detection at the bottom cares about that distinction.
            let previous: Option<RouteIndex<A>> = destination_group
                .iter()
                .find(|route| route.selected)
                .map(|route| route.key());

            // The previously selected route, but only while it still passes the hard rules. One
            // that has been retracted or has gone unfeasible cannot be used.
            let incumbent = destination_group
                .iter()
                .find(|route| route.selected && is_eligible(source_table, route))
                .map(|route| {
                    (
                        route.key(),
                        *route.computed_metric(),
                        *route.smoothed_metric(),
                    )
                });

            let winner = match incumbent {
                // A still-eligible incumbent keeps the destination unless some route beats it on
                // the real metric *and* on the smoothed one.
                Some((incumbent, incumbent_computed, incumbent_smoothed)) => Some(
                    destination_group
                        .iter()
                        // A set of potential winners must be eligible
                        .filter(|route| is_eligible(source_table, route))
                        // A set of potential winners must have a computed and smoothed metric
                        // better than the incumbent. If there are any items in the iterator after
                        // this point, they are better than the incumbent.
                        .filter(|route| {
                            *route.computed_metric() < incumbent_computed
                                && *route.smoothed_metric() < incumbent_smoothed
                        })
                        // Take the route that is the minimum of the routes better than the
                        // incumbent. Breaking ties on the route index.
                        .min_by_key(|route| (route.computed_metric(), route.key()))
                        .map(|route| route.key())
                        // If none of these conditions are met, then the incumbent wins.
                        .unwrap_or(incumbent),
                ),
                // Nothing to defend the destination, so the best route takes it outright, with the
                // smoothed metric ignored entirely. This is also the path a destination whose
                // selected route was just retracted takes.
                None => destination_group
                    .iter()
                    // Potential winners must be eligible
                    .filter(|route| is_eligible(source_table, route))
                    // Take the route with the minimum metric. Breaking ties on the route index.
                    .min_by_key(|route| (route.computed_metric(), route.key()))
                    .map(|route| route.key()),
            };

            b_trace!(
                "previous: {:?}, incumbent: {:?}, winner: {:?}",
                previous,
                incumbent.map(|i| i.0),
                winner
            );

            b_debug!("{:?} -> {:?}", dest, winner);

            for route in destination_group.iter_mut() {
                // Deselect everything, then switch the winner back on. Doing it in that order means
                // a destination that no longer has an eligible route ends up with
                // nothing selected.
                route.selected = false;

                match (previous, winner) {
                    (prev_opt, Some(win)) => {
                        if win == route.key() {
                            // If this route is the winner then mark it selected.
                            route.selected = true;

                            // If a new winner has been selected OR a winner has been selected for
                            // the first time, broadcast an updated.
                            if prev_opt.is_none_or(|p| p != win) {
                                self.update_queue.queue_triggered_update(
                                    now,
                                    route,
                                    &self.iface_table,
                                    &self.neighbor_table,
                                );
                            }
                        }
                    }
                    (Some(prev), None) => {
                        // If this route WAS selected before and there are now no eligible routes
                        // due to a retraction, publish an update.
                        if prev == route.key() && route.computed_metric() == &Metric::INFINITY {
                            self.update_queue.queue_triggered_update(
                                now,
                                route,
                                &self.iface_table,
                                &self.neighbor_table,
                            );
                        }
                    }
                    (None, None) => {
                        // If no winner has been selected and no winner is selected this time, do
                        // nothing.
                    }
                }
            }
        }
    }
}

/// Section 3.6's hard rules: a route with an infinite metric has been retracted, and an
/// unfeasible one risks a routing loop.
fn is_eligible<A: AddressExt>(source_table: &SourceTable<'_, A>, route: &Route<A>) -> bool {
    route.computed_metric() != &Metric::INFINITY
        && source_table.is_feasible(route.source(), route.advertised_metric(), &route.seqno)
}
