use super::tlv::Tlv;
use super::{PacketWriterError, PacketWriterStep};
use crate::data_types::seqno::SeqNo;
use crate::data_types::{Interval, RouterId};
use crate::metric::{Metric, RxCost};
use crate::packet::packet_header_slice::PacketHeaderSlice;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::tlv::tlv_header::TlvHeader;
use crate::packet::tlv::update_slice::UpdateFlags;
use crate::packet::tlv::{
    HelloSlice, IhuSlice, NextHopSlice, RouterIdSlice, TypedTlv, UpdateSlice,
};
use crate::packet::writer::finished_packet_body::FinishedPacketBody;

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Ready;

impl<'a> PacketWriterStep<'a, Ready> {
    pub(crate) fn finish_packet(
        mut self,
    ) -> Result<PacketWriterStep<'a, FinishedPacketBody>, PacketWriterError> {
        // Check body length to see if there is anything to send.
        let body_len = self.state.position() - PacketHeaderSlice::LEN;
        if body_len == 0 {
            // If there is nothing to send, then there was some failure in the router logic that
            // tried to finish an empty packet.
            return Err(PacketWriterError::CannotFinishEmptyPacket);
        } else if body_len > u16::MAX.into() {
            // There is currently no recovery for this failure mode. Every TLV in this packet will
            // be discarded and the router state will "think" the outgoing packet was dropped in
            // transit.
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
    ) -> Result<PacketWriterStep<'a, Tlv>, (PacketWriterError, Self)> {
        // Take self
        let step = self;

        // Early escape hatch
        if let Some(val) = step.state.remaining()
            && val < TlvHeader::LEN + HelloSlice::MIN_LEN
        {
            return Err((
                PacketWriterError::BufferTooSmall {
                    need: HelloSlice::MIN_LEN,
                    remaining: val,
                },
                step,
            ));
        }

        // Track starting position for backtrack.
        let start_pos = step.state.position();

        // Write type ID
        let (_, step) = step.write_or_backtrack(&[HelloSlice::TYPE_ID], start_pos)?;

        // Mark length position and write zero in its place.
        let (length_pos, step) = step.mark_and_skip_or_backtrack::<1>(start_pos)?;

        // Start keeping track of TLV length.
        let mut length = 0usize;

        // Write flags
        let (len, step) = step.write_or_backtrack(&flags.to_wire(), start_pos)?;
        length += len;

        // Write seqno
        let (len, step) = step.write_or_backtrack(&seqno.to_wire(), start_pos)?;
        length += len;

        // Write interval
        let (len, step) = step.write_or_backtrack(&interval.to_wire(), start_pos)?;
        length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: Tlv {
                start_pos,
                length_pos,
                tlv_length: length,
            },
        })
    }

    pub(crate) fn write_ihu(
        self,
        ae: u8,
        rx_cost: RxCost,
        interval: Interval,
        address: &[u8],
    ) -> Result<PacketWriterStep<'a, Tlv>, (PacketWriterError, Self)> {
        // Take self
        let step = self;

        // Early escape hatch
        if let Some(val) = step.state.remaining()
            && val < TlvHeader::LEN + IhuSlice::MIN_LEN
        {
            return Err((
                PacketWriterError::BufferTooSmall {
                    need: TlvHeader::LEN + IhuSlice::MIN_LEN,
                    remaining: val,
                },
                step,
            ));
        }

        // Track starting position for backtrack.
        let start_pos = step.state.position();

        // Write type ID
        let (_, step) = step.write_or_backtrack(&[IhuSlice::TYPE_ID], start_pos)?;

        // Mark length position and write zero in its place.
        let (length_pos, step) = step.mark_and_skip_or_backtrack::<1>(start_pos)?;

        // Start keeping track of tlv length.
        let mut length = 0usize;

        // Write AE
        let (len, step) = step.write_or_backtrack(&[ae], start_pos)?;
        length += len;

        // Write reserved
        let (len, step) = step.write_or_backtrack(&[0], start_pos)?;
        length += len;

        // Write rx cost
        let (len, step) = step.write_or_backtrack(&rx_cost.to_wire(), start_pos)?;
        length += len;

        // Write interval
        let (len, step) = step.write_or_backtrack(&interval.to_wire(), start_pos)?;
        length += len;

        // Write address
        let (len, step) = step.write_or_backtrack(address, start_pos)?;
        length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: Tlv {
                start_pos,
                length_pos,
                tlv_length: length,
            },
        })
    }

    pub(crate) fn write_next_hop(
        self,
        ae: u8,
        next_hop: &[u8],
    ) -> Result<PacketWriterStep<'a, Tlv>, (PacketWriterError, Self)> {
        let step = self;

        if let Some(val) = step.state.remaining()
            && val < TlvHeader::LEN + NextHopSlice::MIN_LEN
        {
            return Err((
                PacketWriterError::BufferTooSmall {
                    need: TlvHeader::LEN + NextHopSlice::MIN_LEN,
                    remaining: val,
                },
                step,
            ));
        }

        // Track starting position for backtrack.
        let start_pos = step.state.position();

        // Write type ID
        let (_, step) = step.write_or_backtrack(&[NextHopSlice::TYPE_ID], start_pos)?;

        // Mark length position and write zero in its place.
        let (length_pos, step) = step.mark_and_skip_or_backtrack::<1>(start_pos)?;

        // Start keeping track of tlv length.
        let mut length = 0usize;

        // Write AE
        let (len, step) = step.write_or_backtrack(&[ae], start_pos)?;
        length += len;

        // Write reserved
        let (len, step) = step.write_or_backtrack(&[0], start_pos)?;
        length += len;

        // Write next_hop
        let (len, step) = step.write_or_backtrack(next_hop, start_pos)?;
        length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: Tlv {
                start_pos,
                length_pos,
                tlv_length: length,
            },
        })
    }

    pub(crate) fn write_router_id(
        self,
        router_id: RouterId,
    ) -> Result<PacketWriterStep<'a, Tlv>, (PacketWriterError, Self)> {
        let step = self;

        if let Some(val) = step.state.remaining()
            && val < TlvHeader::LEN + RouterIdSlice::MIN_LEN
        {
            return Err((
                PacketWriterError::BufferTooSmall {
                    need: TlvHeader::LEN + RouterIdSlice::MIN_LEN,
                    remaining: val,
                },
                step,
            ));
        }

        // Track starting position for backtrack.
        let start_pos = step.state.position();

        // Write type ID
        let (_, step) = step.write_or_backtrack(&[RouterIdSlice::TYPE_ID], start_pos)?;

        // Mark length position and write zero in its place.
        let (length_pos, step) = step.mark_and_skip_or_backtrack::<1>(start_pos)?;

        // Start keeping track of tlv length.
        let mut length = 0usize;

        // Write reserved
        let (len, step) = step.write_or_backtrack(&[0, 0], start_pos)?;
        length += len;

        // Write router id
        let (len, step) = step.write_or_backtrack(router_id.as_octets(), start_pos)?;
        length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: Tlv {
                start_pos,
                length_pos,
                tlv_length: length,
            },
        })
    }

    /// Writes an Update TLV.
    ///
    /// `prefix` is the Prefix field exactly as it goes on the wire, so the caller owns every
    /// decision about how the address was compressed: the octets `ae` implies, the leading octets
    /// `ommitted` drops, and the trailing ones `prefix_len` does not reach. This writer copies what
    /// it is handed and never inspects it, which means a `prefix` that disagrees with those three
    /// fields produces a TLV the receiver mis-frames — it takes the field length from `prefix_len`
    /// and `ommitted`, not from the length of what was written.
    pub(crate) fn write_update(
        self,
        ae: u8,
        flags: UpdateFlags,
        prefix_len: u8,
        omitted: u8,
        interval: Interval,
        seqno: SeqNo,
        metric: Metric,
        prefix: &[u8],
    ) -> Result<PacketWriterStep<'a, Tlv>, (PacketWriterError, Self)> {
        let step = self;

        if let Some(val) = step.state.remaining()
            && val < TlvHeader::LEN + UpdateSlice::MIN_LEN
        {
            return Err((
                PacketWriterError::BufferTooSmall {
                    need: TlvHeader::LEN + UpdateSlice::MIN_LEN,
                    remaining: val,
                },
                step,
            ));
        }

        // Track starting position for backtrack.
        let start_pos = step.state.position();

        // Write type ID
        let (_, step) = step.write_or_backtrack(&[UpdateSlice::TYPE_ID], start_pos)?;

        // Mark length position and write zero in its place.
        let (length_pos, step) = step.mark_and_skip_or_backtrack::<1>(start_pos)?;

        // Start keeping track of tlv length.
        let mut length = 0usize;

        // Write ae
        let (len, step) = step.write_or_backtrack(&[ae], start_pos)?;
        length += len;

        // Write flags
        let (len, step) = step.write_or_backtrack(&flags.to_wire(), start_pos)?;
        length += len;

        // Write plen
        let (len, step) = step.write_or_backtrack(&[prefix_len], start_pos)?;
        length += len;

        // Write ommitted
        let (len, step) = step.write_or_backtrack(&[omitted], start_pos)?;
        length += len;

        // Write interval
        let (len, step) = step.write_or_backtrack(&interval.to_wire(), start_pos)?;
        length += len;

        // Write seqno
        let (len, step) = step.write_or_backtrack(&seqno.to_wire(), start_pos)?;
        length += len;

        // Write metric
        let (len, step) = step.write_or_backtrack(&metric.to_wire(), start_pos)?;
        length += len;

        // Write prefix
        let (len, step) = step.write_or_backtrack(prefix, start_pos)?;
        length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: Tlv {
                start_pos,
                length_pos,
                tlv_length: length,
            },
        })
    }
}
