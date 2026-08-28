use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::route::route_entry::Route;
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::metric::distance::Feasibility;
use crate::packet::parser::UpdateInfo;
use crate::packet::tlv::UpdateSlice;
use crate::utils::{
    Duration, DurationMultiplier, Instant, InternallyKeyed, ManagedSlice, ManagedSliceExt, Timer,
};

/// Route table as defined in
/// [Section 3.2.6](https://datatracker.ietf.org/doc/html/rfc8966#name-the-route-table)
pub struct RouteTable<'storage, A: AddressExt> {
    inner: ManagedSlice<'storage, Option<Route<A>>>,

    pub(crate) route_expiry_time: DurationMultiplier,
}

impl<'storage, A> RouteTable<'storage, A>
where
    A: AddressExt,
{
    /// Create a new source table with user provided storage.
    ///
    /// While interfaces are generally well known at compile time, the number of routes this
    /// Babel speaker might see is specific to its deployment. So it is important to right size
    /// this number for your specfic deployment or do what you can to enable the alloc feature.
    pub(crate) fn new_with_storage<T>(table: T, route_expiry: DurationMultiplier) -> Self
    where
        T: Into<ManagedSlice<'storage, Option<Route<A>>>>,
    {
        Self {
            inner: table.into(),
            route_expiry_time: route_expiry,
        }
    }

    /// Create a new source table.
    #[cfg(any(feature = "std", feature = "alloc"))]
    pub(crate) fn new(route_expiry: DurationMultiplier) -> Self {
        Self::new_with_storage(Vec::new(), route_expiry)
    }

    /// Route aquisition as defined in section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition)
    ///
    /// When a Babel node receives an update (prefix, plen, router-id, seqno, metric) from a
    /// neighbour neigh, it checks whether it already has a route table entry indexed by (prefix,
    /// plen, neigh).
    pub(crate) fn handle_update(
        &mut self,
        now: Instant,
        neighbour: &Neighbour<A>,
        feasible: bool,
        update_info: UpdateInfo<A>,
        update: UpdateSlice<'_>,
        route_metric: Metric,
    ) -> Result<(), RouteError> {
        match self.inner.get_mut_by_key(&RouteIndex {
            prefix: update_info.address,
            prefix_len: update.plen(),
            neighbour: neighbour.key(),
        }) {
            // The following is a direct quote from section 3.5.3:
            // If no such entry exists:
            None => {
                // if the update is unfeasible, it **MAY** be ignored
                if !feasible {
                    // TODO: Local setting?
                }
                // if the metric is infinite (the update is a retraction of a route we do not know
                // about), the update is ignored;
                if update.is_retraction() {
                    return Ok(());
                }
                // otherwise, a new entry is created in the route table, indexed by (prefix, plen,
                // neigh), with source equal to (prefix, plen, router-id), seqno equal to seqno,
                // and an advertised metric equal to the metric carried by the update.
                // NOTE: Ignore returned value as we already checked the entry didn't exist above.
                let _ = self.inner.insert(Route {
                    source: SourceIndex {
                        prefix: update_info.address,
                        prefix_len: update.plen(),
                        router_id: update_info.router_id,
                    },
                    neigbour: neighbour.key(),
                    advertised_metric: update.metric(),
                    seqno: update.seqno(),
                    computed_metric: route_metric,
                    next_hop: update_info.next_hop,
                    selected: feasible,
                    expiry: Timer::from_duration(
                        now,
                        Duration::from(update.interval()) * self.route_expiry_time,
                    )?,
                });
            }
            // If such an entry exists:
            Some(route) => {
                // if the entry is currently selected, the update is unfeasible, and the router-id
                // of the update is equal to the router-id of the entry, then the update **MAY** be
                // ignored
                if route.selected && !feasible && route.source.router_id == update_info.router_id {
                    // TODO: Local setting?
                }
                route.seqno = update.seqno();
                route.advertised_metric = update.metric();
                route.source.router_id = update_info.router_id;
                route.computed_metric = route_metric;
                if !update.is_retraction() {
                    route.expiry.set_tick_duration(
                        Duration::from(update.interval()) * self.route_expiry_time,
                    )?
                }
                if !feasible {
                    route.selected = false
                }
                // TODO: Triggered updates
            }
        }

        Ok(())
    }
}
