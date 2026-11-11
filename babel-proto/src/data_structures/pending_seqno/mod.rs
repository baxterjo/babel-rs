pub(crate) mod pending_seqno_entry;
pub(crate) mod pending_seqno_table;
use super::neighbour::NeighbourIndex;
use crate::data_types::address::Address;
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::extension::address::AddressExt;
use crate::utils::storage::InternallyKeyed;
use crate::utils::{Instant, ManagedSlice};
