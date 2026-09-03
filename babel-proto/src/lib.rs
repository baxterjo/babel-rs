#![cfg_attr(not(any(feature = "std")), no_std)]
//#![cfg_attr(not(any(test, feature = "std")), no_std)]

use crate::data_structures::interface::Interface;
use crate::data_structures::neighbour::Neighbour;
use crate::data_structures::pending_seqno::SeqnoRequest;
use crate::data_structures::route::Route;
use crate::data_structures::source::Source;
use crate::data_structures::updates::Update;
use crate::extension::address::AddressExt;

//#[cfg(not(any(test, feature = "alloc")))]
#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(all(feature = "defmt", feature = "log"))]
compile_error!("You must enable at most one of the following features: defmt, log");

#[macro_use]
mod macros;

pub mod data_structures;
pub mod data_types;
pub mod error;
pub mod extension;
pub mod input;
pub mod metric;
pub mod output;
pub mod packet;
pub mod router;
pub mod utils;

#[cfg(test)]
/// Collection of white box tests that need access to `pub(crate)` visibility.
mod tests;

/// Conditional format trait for when defmt is active.
///
/// This is a blanket implemented bound used throughout the public extension traits, so it is
/// exported to keep those traits nameable by downstream users. It is not meant to be implemented
/// manually.
#[cfg(feature = "defmt")]
pub trait MaybeDefmt: defmt::Format {}
#[cfg(feature = "defmt")]
impl<T: defmt::Format> MaybeDefmt for T {}

/// Conditional format trait for when defmt is active.
///
/// This is a blanket implemented bound used throughout the public extension traits, so it is
/// exported to keep those traits nameable by downstream users. It is not meant to be implemented
/// manually.
#[cfg(not(feature = "defmt"))]
pub trait MaybeDefmt {}
#[cfg(not(feature = "defmt"))]
impl<T> MaybeDefmt for T {}

/// A memory pool for the different storage strucutres in Babel.
///
/// Consts:
/// * `I`: Maximum number of interfaces
/// * `N`: Maximum number of neighbours
/// * `R`: Maximum number of routes
/// * `S`: Maximum number of sources
/// * `PS`: Maximum number of pending seqno requests.
pub struct BabelMemoryPool<
    A: AddressExt,
    const I: usize,
    const N: usize,
    const R: usize,
    const S: usize,
    const PS: usize,
> {
    interface_table: [Option<Interface<A>>; I],
    neighbour_table: [Option<Neighbour<A>>; N],
    route_table: [Option<Route<A>>; R],
    source_table: [Option<Source<A>>; S],
    pending_seqno_table: [Option<SeqnoRequest<A>>; PS],
    /// The maximum possible number of updates is the maximum routes * maximum neighbours.
    update_table: [[Option<Update<A>>; N]; R],
}

pub struct BorrowedMemoryPool<'storage, A: AddressExt> {
    pub(crate) interface_table: &'storage mut [Option<Interface<A>>],
    pub(crate) neighbour_table: &'storage mut [Option<Neighbour<A>>],
    pub(crate) route_table: &'storage mut [Option<Route<A>>],
    pub(crate) source_table: &'storage mut [Option<Source<A>>],
    pub(crate) pending_seqno_table: &'storage mut [Option<SeqnoRequest<A>>],
    pub(crate) update_table: &'storage mut [Option<Update<A>>],
}

impl<
    'storage,
    A: AddressExt,
    const I: usize,
    const N: usize,
    const R: usize,
    const S: usize,
    const PS: usize,
> Default for BabelMemoryPool<A, I, N, R, S, PS>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    'storage,
    A: AddressExt,
    const I: usize,
    const N: usize,
    const R: usize,
    const S: usize,
    const PS: usize,
> BabelMemoryPool<A, I, N, R, S, PS>
where
    Self: 'storage,
{
    pub const fn new() -> Self {
        Self {
            interface_table: [const { None }; I],
            neighbour_table: [const { None }; N],
            route_table: [const { None }; R],
            source_table: [const { None }; S],
            pending_seqno_table: [const { None }; PS],
            update_table: [[const { None }; N]; R],
        }
    }

    pub fn borrowed(&'storage mut self) -> BorrowedMemoryPool<'storage, A> {
        BorrowedMemoryPool {
            interface_table: &mut self.interface_table,
            neighbour_table: &mut self.neighbour_table,
            route_table: &mut self.route_table,
            source_table: &mut self.source_table,
            pending_seqno_table: &mut self.pending_seqno_table,
            update_table: self.update_table.as_flattened_mut(),
        }
    }
}
