use core::fmt::Debug;
use core::ops::Deref;

use super::PacketWriterError;
use crate::utils::ManagedSlice;

pub(crate) struct PacketState<'a> {
    pub(super) buf: ManagedSlice<'a, u8>,
    pos: usize,
}

// `ManagedSlice` does not implement `defmt::Format`, so the buffer is rendered as a byte slice
// instead of deriving.
#[cfg(feature = "defmt")]
impl defmt::Format for PacketState<'_> {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(
            f,
            "PacketState{{ len: {}, pos: {}}}",
            self.buf.len(),
            self.pos
        )
    }
}

impl Debug for PacketState<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PacketState")
            .field("len", &self.buf.len())
            .field("pos", &self.pos)
            .finish()
    }
}

impl PartialEq<&[u8]> for PacketState<'_> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.buf.deref() == *other
    }
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl PartialEq<alloc::vec::Vec<u8>> for PacketState<'_> {
    fn eq(&self, other: &alloc::vec::Vec<u8>) -> bool {
        self.buf.deref() == *other
    }
}

impl<'a> Deref for PacketState<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<'a> PacketState<'a> {
    pub(crate) fn new(buf: ManagedSlice<'a, u8>) -> Self {
        Self { buf, pos: 0 }
    }
    /// Returns the remaining bytes in the buf if it is borrowed.
    ///
    /// Otherwise it is assumed the slice can allocate and returns None.
    pub(crate) fn remaining(&self) -> Option<usize> {
        match &self.buf {
            ManagedSlice::Borrowed(b) => Some(b.len() - self.pos),
            #[cfg(any(feature = "alloc", feature = "std"))]
            ManagedSlice::Owned(_v) => None,
        }
    }

    /// Writes to the buffer after checking it is big enough.
    ///
    /// Returns the number of bytes written.
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, PacketWriterError> {
        if let Some(remaining) = self.remaining()
            && data.len() > remaining
        {
            return Err(PacketWriterError::BufferTooSmall {
                need: data.len(),
                remaining: remaining,
            });
        }
        match &mut self.buf {
            ManagedSlice::Borrowed(b) => {
                b[self.pos..self.pos + data.len()].copy_from_slice(data);
            }
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(v) => {
                v.extend_from_slice(data);
            }
        }
        self.pos += data.len();
        Ok(data.len())
    }

    /// Marks the cursor's current position and writes N zeros in the buffer.
    ///
    /// Returns the marked position of the cursor.
    pub(crate) fn mark_and_skip<const N: usize>(&mut self) -> Result<usize, PacketWriterError> {
        let mark = self.position();
        self.write(&[0; N])?;
        Ok(mark)
    }

    /// Backfills data at the given index. This will not move the cursor position forward.
    ///
    /// It is expected that no allocation will be required to perform this backfill. The cursor
    /// position **WILL NOT** be moved as a result of this operation.
    pub(crate) fn backfill_at(
        &mut self,
        idx: usize,
        data: &[u8],
    ) -> Result<usize, PacketWriterError> {
        let backfill_slice = self
            .buf
            .get_mut(idx..idx + data.len())
            .ok_or(PacketWriterError::IndexError(idx, idx + data.len()))?;
        let out = data.len();
        backfill_slice.copy_from_slice(data);
        Ok(out)
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    /// Consumes the state, yielding the buffer trimmed to the bytes that were written.
    pub(crate) fn into_written(self) -> ManagedSlice<'a, u8> {
        let pos = self.pos;
        self.buf.truncate(pos)
    }

    /// Resets the position of the cursor and erases everything after that position.
    ///
    /// Panics if the new position is greater than the current position.
    pub(crate) fn roll_back(&mut self, pos: usize) {
        if pos > self.pos {
            panic!("Attempted to 'roll back' packet writer forward in buffer.")
        }
        self.pos = pos;
        let len = self.buf.len();

        match &mut self.buf {
            // If the buffer is pre-allocated, erase anything after position.
            ManagedSlice::Borrowed(borrowed) => {
                if let Some(tail_slice) = borrowed.get_mut(self.pos..len) {
                    tail_slice.fill(0);
                }
            }
            // If the buffer is owned, truncate it.
            #[cfg(any(feature = "std", feature = "alloc"))]
            ManagedSlice::Owned(owned) => {
                owned.truncate(self.pos);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn borrowed(buf: &mut [u8]) -> PacketState<'_> {
        PacketState::new(ManagedSlice::Borrowed(buf))
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    fn owned() -> PacketState<'static> {
        PacketState::new(ManagedSlice::Owned(alloc::vec::Vec::new()))
    }

    /// `write_padn_sub_tlv` marks `start_pos = position()` and then immediately performs a write
    /// that can fail with zero bytes remaining, rolling back to the position it is already at.
    /// A rollback to the current position is a no-op, not a programming error.
    #[test]
    fn rolling_back_to_the_current_position_is_a_no_op() {
        let mut buf = [0u8; 8];
        let mut state = borrowed(&mut buf);
        state.write(&[1, 2, 3]).expect("write should fit");

        let pos = state.position();
        state.roll_back(pos);

        assert_eq!(state.position(), pos);
        assert_eq!(&state[..3], &[1, 2, 3], "a no-op rollback must not erase");
    }

    #[test]
    #[should_panic(expected = "roll back")]
    fn rolling_forward_panics() {
        let mut buf = [0u8; 8];
        let mut state = borrowed(&mut buf);
        state.write(&[1, 2, 3]).expect("write should fit");

        state.roll_back(4);
    }

    #[test]
    fn borrowed_rollback_rewinds_and_zeroes_the_tail() {
        let mut buf = [0u8; 8];
        let mut state = borrowed(&mut buf);
        state.write(&[1, 2]).expect("write should fit");

        let mark = state.position();
        state.write(&[9, 9, 9]).expect("write should fit");
        state.roll_back(mark);

        assert_eq!(state.position(), 2);
        assert_eq!(
            &state[..],
            &[1, 2, 0, 0, 0, 0, 0, 0],
            "the abandoned bytes should be erased"
        );
    }

    /// `write` appends to an owned buffer with `extend_from_slice`, so a rollback that only
    /// rewinds `pos` would leave stale bytes behind: the next write would land past them while
    /// `pos` claimed otherwise, and `finish_packet`'s body-length backfill would then disagree
    /// with the bytes actually in the buffer.
    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn owned_rollback_truncates_so_the_next_write_lands_at_the_cursor() {
        let mut state = owned();
        state.write(&[1, 2]).expect("owned buffers grow");

        let mark = state.position();
        state.write(&[9, 9, 9]).expect("owned buffers grow");
        state.roll_back(mark);

        assert_eq!(state.position(), 2);
        assert_eq!(state.len(), 2, "the abandoned bytes should be dropped");

        state.write(&[3, 4]).expect("owned buffers grow");

        assert_eq!(state.position(), 4);
        assert_eq!(
            &state[..],
            &[1, 2, 3, 4],
            "the write after a rollback must land at the cursor"
        );
        assert_eq!(
            state.position(),
            state.len(),
            "position and buffer length must agree, or the length backfill is wrong"
        );
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    #[test]
    fn owned_rollback_keeps_backfill_targets_addressable() {
        let mut state = owned();
        // Stand in for a length field that gets backfilled after the body is written.
        let mark = state.mark_and_skip::<2>().expect("owned buffers grow");
        let body_start = state.position();
        state.write(&[7, 7, 7]).expect("owned buffers grow");
        state.roll_back(body_start);
        state.write(&[5]).expect("owned buffers grow");

        let body_len = (state.position() - body_start) as u16;
        state
            .backfill_at(mark, &body_len.to_be_bytes())
            .expect("the length field should still be addressable");

        assert_eq!(&state[..], &[0, 1, 5]);
    }
}
