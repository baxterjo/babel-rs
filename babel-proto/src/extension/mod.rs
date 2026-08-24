use core::marker::PhantomData;

use crate::extension::address::AddressExt;

pub mod address;
pub mod address_encoding;
pub mod metric_calc;
pub mod parser_state;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoStateExtension<A: AddressExt = NoExtension> {
    _marker: PhantomData<A>,
}

impl<A: AddressExt> Default for NoStateExtension<A> {
    fn default() -> Self {
        NoStateExtension {
            _marker: PhantomData,
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct NoExtension;
