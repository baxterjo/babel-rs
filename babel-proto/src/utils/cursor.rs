use core::ops::Deref;

use managed::ManagedSlice;
use thiserror::Error;

/// A cursor utility to write to buffers easily.
#[derive(Debug)]
pub(crate) struct ManagedSliceCursor<'a> {
    buf: ManagedSlice<'a, u8>,
    pos: usize,
}

impl PartialEq<&[u8]> for ManagedSliceCursor<'_> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.buf.deref() == *other
    }
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl PartialEq<Vec<u8>> for ManagedSliceCursor<'_> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.buf.deref() == *other
    }
}

impl<'a> Deref for ManagedSliceCursor<'a> {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl<'a> ManagedSliceCursor<'a> {
    pub(crate) fn new<A: Into<ManagedSlice<'a, u8>>>(buf: A) -> Self {
        Self {
            buf: buf.into(),
            pos: 0,
        }
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
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<usize, ManagedSliceCursorError> {
        if self.remaining().is_some_and(|rem| data.len() > rem) {
            return Err(ManagedSliceCursorError::BufferTooSmall(
                data.len(),
                self.remaining().expect("Just checked if remaining is Some"),
            ));
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
    pub(crate) fn mark_and_skip<const N: usize>(
        &mut self,
    ) -> Result<usize, ManagedSliceCursorError> {
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
    ) -> Result<usize, ManagedSliceCursorError> {
        let backfill_slice = self
            .buf
            .get_mut(idx..idx + data.len())
            .ok_or(ManagedSliceCursorError::IndexError(idx, idx + data.len()))?;
        let out = data.len();
        backfill_slice.copy_from_slice(data);
        Ok(out)
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }
}

#[derive(Debug, Error)]
pub enum ManagedSliceCursorError {
    #[error("Buffer is too small, needed {0}, have {1}")]
    BufferTooSmall(usize, usize),
    #[error("Failed to index at bounds {0}..{1}")]
    IndexError(usize, usize),
}
