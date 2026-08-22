// Attribution: etherparse 0.21.0

/// Sources of length limiting values (e.g. "packet body length field").
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LenSource {
    /// Limiting length was the slice length (we don't know what determined
    /// that one originally).
    Slice,
    /// Body length field in the Babel packet header.
    BabelPacketBodyLength,
    /// Body length field in the Babel TLV header.
    BabelTlvBodyLength,
    /// Expected address length based on address encoding
    AddressEncoding,
}
