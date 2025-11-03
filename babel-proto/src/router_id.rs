use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct RouterId(u64);

impl RouterId {
    pub fn new(raw_id: u64) -> Result<Self, RouterIdError> {
        if raw_id <= u64::MIN || raw_id >= u64::MAX {
            Err(RouterIdError::InvalidId(raw_id))
        } else {
            Ok(Self(raw_id))
        }
    }
}

#[derive(Debug, Error)]
pub enum RouterIdError {
    #[error(
        "RouterId must not be {:X} or {:X} - Given: {:X}",
        u64::MIN,
        u64::MAX,
        0
    )]
    InvalidId(u64),
}
