use crate::output::DatagramSend;
use crate::packet::writer::PacketWriterStep;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct FinishedPacketBody;

impl<'a> From<PacketWriterStep<'a, FinishedPacketBody>> for DatagramSend<'a> {
    fn from(value: PacketWriterStep<'a, FinishedPacketBody>) -> Self {
        DatagramSend::from(value.state.into_written())
    }
}
