use core::fmt::Debug as DebugT;
use core::fmt::Display;

use managed::ManagedMap;
use managed::ManagedSlice;

use crate::interface::Interface;
use crate::neighbour::NeighbourIndex;

pub struct BabelRouter<'storage, I, A>
where
    I: Display + DebugT + for<'a> Into<&'a [u8; 8]>,
{
    id: RouterId<I>,

    iface_table: ManagedSlice<'storage, Interface>,

    neighbour_table: ManagedMap<'storage, NeighbourIndex>,
}

/// Newtype wrapper around a type that can be converted into 8 Octets.
#[derive(Debug)]
pub struct RouterId<T: Display + DebugT + for<'a> Into<&'a [u8; 8]>>(T);
