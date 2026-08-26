use core::fmt::Display;

use thiserror::Error;

use crate::data_structures::interface::InterfaceHandle;
use crate::data_types::Address;
use crate::extension::address::AddressExt;
use crate::output::TransmitDestination;

#[derive(Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum DestAddr<A: AddressExt> {
    #[default]
    None,
    Unicast(Address<A>),
    Multicast,
}

impl<A: AddressExt> Display for DestAddr<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Multicast => write!(f, "Multicast"),
            Self::Unicast(addr) => write!(f, "{}", addr),
        }
    }
}

impl<A: AddressExt> DestAddr<A> {
    pub(crate) fn is_free(&self) -> bool {
        *self == Self::None
    }

    pub(crate) fn claim(&mut self, new: Self) -> Result<(), DestinationError> {
        if *self != Self::None && *self != new {
            return Err(DestinationError::AlreadyClaimed);
        }
        *self = new;
        Ok(())
    }

    pub(crate) fn is_multicast(&self) -> bool {
        *self == Self::Multicast
    }

    /// Returns the inner unicast addr if it exists.
    pub(crate) fn unicast_addr(&self) -> Option<&Address<A>> {
        match self {
            Self::Unicast(addr) => Some(addr),
            _ => None,
        }
    }

    pub(crate) fn can_send_ihu(&self, addr: &Address<A>) -> bool {
        self.is_free() || self.is_multicast() || self.unicast_addr().is_some_and(|a| a == addr)
    }
}

impl<A: AddressExt> TryInto<TransmitDestination<A>> for DestAddr<A> {
    type Error = DestinationError;
    fn try_into(self) -> Result<TransmitDestination<A>, Self::Error> {
        let out = match self {
            Self::Unicast(addr) => TransmitDestination::Unicast(addr),
            Self::Multicast => TransmitDestination::Multicast,
            Self::None => {
                return Err(DestinationError::NoDestinationSet);
            }
        };
        Ok(out)
    }
}

#[derive(Debug, Error)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum DestinationError {
    #[error("Destination has already been claimed.")]
    AlreadyClaimed,
    #[error("Cannot create a destination from nothing")]
    NoDestinationSet,
}

pub(crate) trait Claim {
    fn claim(&mut self, new: InterfaceHandle) -> Result<(), DestinationError>;
}

impl Claim for Option<InterfaceHandle> {
    fn claim(&mut self, new: InterfaceHandle) -> Result<(), DestinationError> {
        if self.is_some() && *self != Some(new) {
            return Err(DestinationError::AlreadyClaimed);
        }
        *self = Some(new);
        Ok(())
    }
}
