use core::ops::Deref;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct RxCost(pub u16);

impl RxCost {
    pub fn from_wire(wire: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(wire.into()))
    }

    pub fn as_wire(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    pub fn is_infinite(&self) -> bool {
        self.0 == u16::MAX
    }

    pub fn is_reachable(&self) -> bool {
        !self.is_infinite()
    }
}

impl Deref for RxCost {
    type Target = u16;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub type TxCost = RxCost;
