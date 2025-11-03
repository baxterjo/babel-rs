/// This TLV is used for neighbour discovery and for determining a neighbour's reception cost.
pub struct Hello {
    /// The individual bits of this field specify special handling of this TLV (see below).
    flags: HelloFlags,
    /// If the Unicast flag is set, this is the value of the sending node's outgoing Unicast Hello seqno for this neighbour. Otherwise, it is the sending node's outgoing Multicast Hello seqno for this interface.
    seq_no: u16,
    /// If nonzero, this is an upper bound, expressed in centiseconds, on the time after which the sending node will send a new scheduled Hello TLV with the same setting of the Unicast flag. If this is 0, then this Hello represents an unscheduled Hello and doesn't carry any new information about times at which Hellos are sent.
    interval: u16,
}

impl Hello {
    /// Identifier used in the message header to determine its type.
    pub const TYPE_ID: u8 = 4;

    /// This TLV is self-terminating and allows sub TLVs.
    pub const SUB_TLV_ALLOWED: bool = true;
}

#[derive(Debug, Clone, Copy)]
pub struct HelloFlags(u16);
impl HelloFlags {
    const UNICAST_FLAG: u16 = 0b1000_0000_0000_0000;

    const fn is_unicast(&self) -> bool {
        self.0 & Self::UNICAST_FLAG != 0
    }
    const fn is_multicast(&self) -> bool {
        !self.is_unicast()
    }
}
