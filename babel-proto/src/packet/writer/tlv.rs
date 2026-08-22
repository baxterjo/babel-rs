use crate::packet::tlv::TypedTlv;
use crate::packet::tlv::pad_slice::PadNSlice;
use crate::packet::writer::ready::Ready;

use super::PacketWriterError;
use super::PacketWriterStep;

/// Tlv writer step.
///
/// The generic const indicates whether this is the first TLV or not.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) struct Tlv {
    pub(crate) start_pos: usize,
    pub(crate) length_pos: usize,
    pub(crate) tlv_length: usize,
}

impl<'a> PacketWriterStep<'a, Tlv> {
    /// State transitions for when finishing a TLV succeeds or fails when the current TLV is the first
    /// one.
    pub(crate) fn finish_tlv(
        self,
    ) -> Result<PacketWriterStep<'a, Ready>, (PacketWriterError, PacketWriterStep<'a, Ready>)> {
        let start = self.step_state.start_pos;
        match self.finish_inner() {
            Ok(v) => Ok(v),
            Err((err, mut writer)) => {
                // If there is an error finishing the TLV it needs to be erased.
                writer.state.roll_back(start);
                Err((
                    err,
                    PacketWriterStep {
                        state: writer.state,
                        step_state: Ready {},
                    },
                ))
            }
        }
    }
    /// Performs the inner length check and backfill function. Does not roll back the TLV on
    /// failure.
    fn finish_inner(mut self) -> Result<PacketWriterStep<'a, Ready>, (PacketWriterError, Self)> {
        if self.step_state.tlv_length > u8::MAX.into() {
            return Err((
                PacketWriterError::TlvLengthLargerThanMax(self.step_state.tlv_length),
                self,
            ));
        }

        // Truncation saftey: length less than u8::MAX checked above
        if let Err(err) = self.state.backfill_at(
            self.step_state.length_pos,
            &[self.step_state.tlv_length as u8],
        ) {
            return Err((err, self));
        };

        Ok(PacketWriterStep {
            state: self.state,
            step_state: Ready {},
        })
    }

    /// Writes the pad1 sub TLV into the buffer. Rolls back the TLV on failure.
    pub(crate) fn write_pad1_sub_tlv_inner(self) -> Result<Self, (PacketWriterError, Self)> {
        let step = self;
        // For sub TLV's there is no need to roll back the entire TLV on failure. Just back to the
        // end of the current TLV.
        let start_pos = step.state.position();
        let (len, mut step) = step.write_or_backtrack(&[0], start_pos)?;
        step.step_state.tlv_length += len;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: step.step_state,
        })
    }

    /// Writes padn sub TLV into the buffer. Rolls back the TLV on failure.
    pub(crate) fn write_padn_sub_tlv<const N: usize>(
        self,
    ) -> Result<Self, (PacketWriterError, Self)> {
        // Quick escape hatch.
        if N > u8::MAX.into() {
            return Err((PacketWriterError::TlvLengthLargerThanMax(N), self));
        }
        let step = self;

        // For sub TLV's there is no need to roll back the entire TLV on failure. Just back to the
        // end of the current TLV.
        let start_pos = step.state.position();

        // Write type field
        let (type_len, step) = step.write_or_backtrack(&[PadNSlice::TYPE_ID], start_pos)?;

        // Write length field
        // Truncation safety: Checked to make sure N is not larger than u8::MAX
        let (len_len, step) = step.write_or_backtrack(&[N as u8], start_pos)?;

        let (_mark, mut step) = step.mark_and_skip_or_backtrack::<N>(start_pos)?;

        step.step_state.tlv_length += type_len;
        step.step_state.tlv_length += len_len;
        step.step_state.tlv_length += N;

        Ok(PacketWriterStep {
            state: step.state,
            step_state: step.step_state,
        })
    }
}
