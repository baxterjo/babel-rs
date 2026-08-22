use crate::{output::DatagramSend, packet::writer::PacketWriterStep};

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct FinishedPacketBody;

impl<'a> Into<DatagramSend<'a>> for PacketWriterStep<'a, FinishedPacketBody> {
    fn into(self) -> DatagramSend<'a> {
        DatagramSend::from(self.state.buf)
    }
}
