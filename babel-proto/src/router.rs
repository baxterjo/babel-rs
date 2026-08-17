use crate::data_structures::{interface::InterfaceTable, neighbour::NeighbourTable};
use crate::data_types::RouterId;
use crate::extension::address::AddressExt;
use crate::extension::NoExtension;
use crate::input::Input;
use crate::packet::packet_header::BabelPacketHeader;

pub struct BabelRouter<
    'storage,
    E = NoExtension,
    const MN: u8 = { BabelPacketHeader::MAGIC_NUMBER },
    const V: u8 = { BabelPacketHeader::VERSION_NUMBER },
> where
    E: AddressExt,
{
    id: RouterId,

    iface_table: InterfaceTable<'storage>,

    neighbor_table: NeighbourTable<'storage, E>,
}

impl<E: AddressExt, const MN: u8, const V: u8> BabelRouter<'_, E, MN, V> {
    fn handle_input<'input>(&mut self, input: Input<'input, E>) {}
}
