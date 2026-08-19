use crate::{
    data_structures::seqno::SeqNo,
    data_types::Interval,
    packet::{
        packet_header_slice::PacketHeaderSlice,
        tlv::hello_slice::HelloFlags,
        writer::{
            finished_packet_body::FinishedPacketBody, packet_headers::PacketHeaders, tlv::Tlv,
            PacketWriterError, PacketWriterStep,
        },
    },
    utils::rx_cost::RxCost,
};

#[derive(Debug)]
pub(crate) struct FinishedTlv;

impl<'a> PacketWriterStep<'a, FinishedTlv> {
    pub(crate) fn finish_packet(
        mut self,
    ) -> Result<PacketWriterStep<'a, FinishedPacketBody>, PacketWriterError> {
        let body_len = self.state.len() - PacketHeaderSlice::LEN;
        if body_len > u16::MAX.into() {
            return Err(PacketWriterError::PacketBodyLengthLargerThanMax(body_len));
        }

        self.state
            .backfill_at(2, &(body_len as u16).to_be_bytes())?;

        Ok(PacketWriterStep {
            state: self.state,
            step_state: FinishedPacketBody {},
        })
    }

    pub(crate) fn write_hello(
        self,
        flags: HelloFlags,
        seqno: SeqNo,
        interval: Interval,
    ) -> Result<PacketWriterStep<'a, Tlv<false>>, (PacketWriterError, Self)> {
        // Use packet headers implementation. The only difference is that it is no longer the first
        // TLV
        match (PacketWriterStep {
            state: self.state,
            step_state: PacketHeaders {},
        })
        .write_hello(flags, seqno, interval)
        {
            Ok(step) => Ok(PacketWriterStep {
                state: step.state,
                step_state: Tlv::<false> {
                    start_pos: step.step_state.start_pos,
                    length_pos: step.step_state.length_pos,
                    tlv_length: step.step_state.tlv_length,
                },
            }),
            Err((err, step)) => Err((
                err,
                Self {
                    state: step.state,
                    step_state: FinishedTlv {},
                },
            )),
        }
    }
    pub(crate) fn write_ihu(
        self,
        ae: u8,
        rx_cost: RxCost,
        interval: Interval,
        address: &[u8],
    ) -> Result<PacketWriterStep<'a, Tlv<false>>, (PacketWriterError, Self)> {
        // Use packet headers implementation. The only difference is that it is no longer the first
        // TLV
        match (PacketWriterStep {
            state: self.state,
            step_state: PacketHeaders {},
        })
        .write_ihu(ae, rx_cost, interval, address)
        {
            Ok(step) => Ok(PacketWriterStep {
                state: step.state,
                step_state: Tlv::<false> {
                    start_pos: step.step_state.start_pos,
                    length_pos: step.step_state.length_pos,
                    tlv_length: step.step_state.tlv_length,
                },
            }),
            Err((err, step)) => Err((
                err,
                Self {
                    state: step.state,
                    step_state: FinishedTlv {},
                },
            )),
        }
    }
}
