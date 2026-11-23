use crate::data_structures::interface::{Interface, InterfaceTable};
use crate::data_structures::neighbour::{Neighbour, NeighbourIndex, NeighbourTable};
use crate::data_structures::route::RouteError;
use crate::data_structures::route::route_entry::Route;
use crate::data_structures::source::SourceIndex;
use crate::data_structures::updates::UpdateQueue;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Address, Interval};
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::utils::storage::{InsertError, InternallyKeyed, Table};
use crate::utils::{DurationMultiplier, Instant, ManagedSlice};

pub const DEFAULT_SMOOTHING_MULTIPLE: DurationMultiplier = DurationMultiplier::new(3, 1);
pub const METRIC_DIFFERENCE_THRESHOLD: Metric = Metric::from_raw(100);

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    /// The inner slice for the table.
    pub(crate) inner: Table<'storage, Option<Route<A>>>,

    /// The multiple of a route's update interval that will determine how long this table keeps the
    /// route.
    pub(crate) route_expiry_time: DurationMultiplier,

    /// Multiple of the hello timer of a given route that should be used to generate the time
    /// constant of a route's smoothed metric.
    ///
    /// The time constant will be taken from the max between mcast hello interval and ucast hello
    /// interval (if it exists)
    pub(crate) smoothing_multiple: DurationMultiplier,
}

impl<'storage, A> RouteTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new route table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of routes this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub(crate) fn new_with_storage<T>(storage: T, route_expiry: DurationMultiplier) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Route<A>>>>,
    {
        Self {
            inner: Table::new(storage),
            route_expiry_time: route_expiry,
            smoothing_multiple: DEFAULT_SMOOTHING_MULTIPLE,
        }
    }

    pub(crate) fn add_route(
        &mut self,
        now: Instant,
        source: SourceIndex<A>,
        neighbour: NeighbourIndex<A>,
        seqno: SeqNo,
        advertised_metric: Metric,
        computed_metric: Metric,
        next_hop: Address<A>,
        interval: Interval,
    ) -> Result<(), RouteError> {
        let route = Route::new(
            now,
            source,
            neighbour,
            seqno,
            advertised_metric,
            computed_metric,
            next_hop,
            // Routes are never added as selected; route selection runs after each update.
            false,
            interval,
            self.route_expiry_time,
        );

        // If there is an error inserting the route then the storage needs to be returned to the
        // table.
        if let Err(err) = self.inner.insert(route) {
            b_debug!("Error inserting route: {:?}", err);

            match err {
                InsertError::Full(_) => {
                    return Err(RouteError::Full);
                }
                InsertError::Duplicate(_) => {
                    return Err(RouteError::Duplicate);
                }
            }
        };

        Ok(())
    }

    /// Recomputes the metric of every route `neighbour` advertised, and queues a triggered update
    /// for any of them still holding a destination whose metric moved significantly.
    ///
    /// `interfaces` and `neighbours` are only there for that queueing — a triggered update goes to
    /// every neighbour on every interface, not just the one whose link cost moved.
    pub(crate) fn update_metrics_for_neighbour(
        &mut self,
        now: Instant,
        interface: &Interface<A>,
        neighbour: &Neighbour<A>,
        interfaces: &InterfaceTable<A>,
        neighbours: &NeighbourTable<A>,
        update_queue: &mut UpdateQueue<A>,
    ) {
        let smoothing_multiple = self.smoothing_multiple;
        let neighbour_idx = neighbour.key();

        for route in self
            .inner
            .iter_mut()
            .filter(|route| route.neighbour() == &neighbour_idx)
        {
            let old_computed = *route.computed_metric();
            route.compute_metric(now, interface, neighbour, &smoothing_multiple);

            // Every route over this neighbour has its metric recomputed, but only the selected one
            // can be worth relaying. 3.7.2 scopes the significant-metric trigger to the route that
            // holds its destination: an unselected route was never advertised onwards, so no
            // neighbour is holding a belief about it that the move would correct.
            if route.selected
                && route.computed_metric().abs_diff(old_computed) > METRIC_DIFFERENCE_THRESHOLD
            {
                update_queue.queue_triggered_update(
                    now,
                    route.destination(),
                    interfaces,
                    neighbours,
                );
            }
        }
    }

    /// Gets the selected learned route for the given destination.
    ///
    /// Only the tests read the learned table on its own. Everything else resolves a destination
    /// across both tables with [`crate::data_views::AllRoutes::get_selected`].
    #[cfg(test)]
    pub(crate) fn get_selected(
        &self,
        destination: &crate::data_types::destination::RouteDestination<A>,
    ) -> Option<&Route<A>> {
        let mut iter = self
            .inner
            .iter()
            .filter(|r| r.selected && r.destination() == destination);
        let out = iter.next();
        // This is a good spot to assert that only one route is selected for a given destination on
        // non-optimized builds.
        debug_assert!(
            iter.next().is_none(),
            "There should only be one selected route for a destination."
        );
        out
    }
}
