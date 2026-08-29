use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::route::route_entry::Route;
use crate::data_structures::route::{RouteError, RouteIndex};
use crate::data_structures::source::SourceIndex;
use crate::data_types::address::Address;
use crate::extension::address::AddressExt;
use crate::metric::Metric;
use crate::packet::parser::ResolvedUpdate;
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

    pub(crate) fn iter_mut_entries(&mut self) -> impl Iterator<Item = &mut Route<A>> {
        self.inner.iter_mut().filter_map(|e| e.as_mut())
    }

    /// Route aquisition as defined in section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition)
    ///
    /// When a Babel node receives an update (prefix, plen, router-id, seqno, metric) from a
    /// neighbour neigh, it checks whether it already has a route table entry indexed by (prefix,
    /// plen, neigh).
    pub(crate) fn aquire_route(
        &mut self,
        now: Instant,
        neighbour: &Neighbour<A>,
        feasible: bool,
        update: ResolvedUpdate<'_, A>,
        route_metric: Metric,
    ) -> Result<(), RouteError> {
        match self.inner.get_mut_by_key(&RouteIndex {
            prefix: update.address,
            prefix_len: update.slice.plen(),
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
                if update.slice.is_retraction() {
                    // This is technically dead code since the logic of the calling function does
                    // not allow a retraction to reach this point. But I'm keeping it as a
                    // regression backstop.
                    return Ok(());
                }
                // otherwise, a new entry is created in the route table, indexed by (prefix, plen,
                // neigh), with source equal to (prefix, plen, router-id), seqno equal to seqno,
                // and an advertised metric equal to the metric carried by the update.
                // NOTE: Ignore returned value as we already checked the entry didn't exist above.
                let _ = self.inner.insert(Route {
                    source: SourceIndex {
                        prefix: update.address,
                        prefix_len: update.slice.plen(),
                        router_id: update.router_id,
                    },
                    neigbour: neighbour.key(),
                    advertised_metric: update.slice.metric(),
                    seqno: update.slice.seqno(),
                    computed_metric: route_metric,
                    next_hop: update.next_hop,
                    selected: feasible,
                    expiry: Timer::from_duration(
                        now,
                        Duration::from(update.slice.interval()) * self.route_expiry_time,
                    )?,
                });
            }
            // If such an entry exists:
            Some(route) => {
                // if the entry is currently selected, the update is unfeasible, and the router-id
                // of the update is equal to the router-id of the entry, then the update **MAY** be
                // ignored
                if route.selected && !feasible && route.source.router_id == update.router_id {
                    // TODO: Local setting?
                }
                // The new hold time is built before the entry is touched. An Interval the timer
                // rejects has to leave the entry exactly as it was, rather than half-updated with
                // a new metric under the old expiry and the deselect below never reached.
                let expiry = Timer::from_duration(
                    now,
                    Duration::from(update.slice.interval()) * self.route_expiry_time,
                )?;

                // otherwise, the entry's sequence number, advertised metric, metric, and router-id
                // are updated, and if the advertised metric is not infinite, the route's expiry
                // timer is reset to a small multiple of the interval value included in the update
                // (see "Route Expiry time" in Appendix B for suggested values). If the update is
                // unfeasible, then the (now unfeasible) entry MUST be immediately unselected. If
                // the update caused the router-id of the entry to change, an update (possibly a
                // retraction) MUST be sent in a timely manner as described in Section 3.7.2.
                route.seqno = update.slice.seqno();
                route.advertised_metric = update.slice.metric();
                route.source.router_id = update.router_id;
                route.computed_metric = route_metric;
                if !update.slice.is_retraction() {
                    // This if statement is redundant since the logic of the calling function does
                    // not allow a retraction to reach this point. But I'm keeping it as a
                    // regression backstop.
                    route.expiry = expiry;
                }
                if !feasible {
                    route.selected = false
                }
                // TODO: Triggered updates
            }
        }

        Ok(())
    }

    /// Retracts every route this neighbour advertised, which is what an Update with AE 0 and an
    /// infinite metric asks for.
    ///
    /// The expiry timers are deliberately left alone. Section
    /// [3.5.3](https://datatracker.ietf.org/doc/html/rfc8966#name-route-acquisition) resets a
    /// route's expiry timer only when the advertised metric is finite, so a retracted route runs
    /// out the hold time it already had and is flushed when that timer fires.
    pub(crate) fn handle_blanket_retraction(&mut self, neighbour: &Neighbour<A>) {
        for route in self
            .iter_mut_entries()
            .filter(|r| r.neigbour == neighbour.key())
        {
            route.advertised_metric = Metric::INFINITY;
            route.computed_metric = Metric::INFINITY;
        }
    }

    /// Retracts the single route indexed by (prefix, prefix_len, neighbour).
    ///
    /// The seqno and router-id of the entry are left as its last real advertisement set them:
    /// [Section 4.6.9](https://datatracker.ietf.org/doc/html/rfc8966#name-update) says that for a
    /// retraction "the router-id, next hop, and seqno are not used", so there is nothing
    /// meaningful on the wire to replace them with. See [`Self::handle_blanket_retraction`] for
    /// why the expiry timer is untouched.
    pub(crate) fn handle_retraction(
        &mut self,
        neighbour: &Neighbour<A>,
        prefix: Address<A>,
        prefix_len: u8,
    ) {
        let idx = RouteIndex {
            prefix,
            prefix_len,
            neighbour: neighbour.key(),
        };
        // If an unknown route is somehow retracted, silently ignore.
        if let Some(route) = self.inner.get_mut_by_key(&idx) {
            route.advertised_metric = Metric::INFINITY;
            route.computed_metric = Metric::INFINITY;
        }
    }
}
