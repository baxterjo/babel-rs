use core::fmt::Debug;
use core::ops::Deref;

use managed::ManagedSlice;

use super::PacketWriterError;

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
impl PartialEq<Vec<u8>> for PacketState<'_> {
    fn eq(&self, other: &Vec<u8>) -> bool {
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
        if self.remaining().is_some_and(|rem| data.len() > rem) {
            return Err(PacketWriterError::BufferTooSmall {
                need: data.len(),
                remaining: self.remaining().expect("Just checked if remaining is Some"),
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

    /// Resets the position of the cursor and erases everything after that position.
    ///
    /// Panics if the new position is greater than the current position.
    pub(crate) fn roll_back(&mut self, pos: usize) {
        if pos >= self.pos {
            panic!("Attempted to 'roll back' packet writer forward in buffer.")
        }
        self.pos = pos;
        let len = self.buf.len();

        if let Some(tail_slice) = self.buf.get_mut(self.pos..len) {
            tail_slice.fill(0);
        }
    }
}
