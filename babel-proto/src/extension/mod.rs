pub mod address;
pub mod address_encoding;
pub mod parser_state;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct NoExtension;
