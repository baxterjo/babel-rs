use crate::data_structures::{interface::InterfaceTable, neighbour::NeighbourTable};
use crate::data_types::address::{AddressExtension, NoExtension};
use crate::data_types::RouterId;

pub struct BabelRouter<'storage, A = NoExtension>
where
    A: AddressExtension,
{
    id: RouterId,

    iface_table: InterfaceTable<'storage>,

    neighbor_table: NeighbourTable<'storage, A>,
}
