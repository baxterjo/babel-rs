use crate::data_structures::seqno::SeqNo;
use crate::data_types::Interval;
use crate::packet::tlv::hello_slice::HelloFlags;
use crate::packet::tlv::{HelloSlice, IhuSlice, TypedTlv};
use crate::utils::rx_cost::RxCost;

use super::PacketWriterError;

use super::tlv::Tlv;
use super::PacketWriterStep;

#[derive(Debug)]
pub(crate) struct PacketHeaders;

impl<'a> PacketWriterStep<'a, PacketHeaders> {
    pub(crate) fn write_hello(
        self,
        flags: HelloFlags,
        seqno: SeqNo,
        interval: Interval,
    ) -> Result<PacketWriterStep<'a, Tlv<true>>, (PacketWriterError, Self)> {
        // Take self
        let step = self;

        // Early escape hatch
        if let Some(val) = step.state.remaining() {
            if val < HelloSlice::MIN_LEN {
                return Err((
                    PacketWriterError::BufferTooSmall {
                        need: HelloSlice::MIN_LEN,
                        remaining: val,
                    },
                    step,
                ));
            }
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
        let (l, step) = step.write_or_backtrack(&flags.to_wire(), start_pos)?;
        length += l;

        // Write seqno
        let (l, step) = step.write_or_backtrack(&seqno.to_wire(), start_pos)?;
        length += l;

        // Write interval
        let (l, step) = step.write_or_backtrack(&interval.to_wire(), start_pos)?;
        length += l;

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
    ) -> Result<PacketWriterStep<'a, Tlv<true>>, (PacketWriterError, Self)> {
        // Take self
        let step = self;

        // Early escape hatch
        if let Some(val) = step.state.remaining() {
            if val < IhuSlice::MIN_LEN {
                return Err((
                    PacketWriterError::BufferTooSmall {
                        need: HelloSlice::MIN_LEN,
                        remaining: val,
                    },
                    step,
                ));
            }
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
        let (l, step) = step.write_or_backtrack(&[ae], start_pos)?;
        length += l;

        // Write reserved
        let (l, step) = step.write_or_backtrack(&[0], start_pos)?;
        length += l;

        // Write rx cost
        let (l, step) = step.write_or_backtrack(&rx_cost.to_wire(), start_pos)?;
        length += l;

        // Write interval
        let (l, step) = step.write_or_backtrack(&interval.to_wire(), start_pos)?;
        length += l;

        // Write address
        let (l, step) = step.write_or_backtrack(address, start_pos)?;
        length += l;

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
