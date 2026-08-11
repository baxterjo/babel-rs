/// A cursor utility to write to buffers easily.
pub(crate) struct SliceCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceCursor<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Writes to the buffer after checking it is big enough.
    ///
    /// Returns Err(usize) with the number of bytes remaining in the buffer if it is too small.
    pub(crate) fn write(&mut self, data: &[u8]) -> Result<(), usize> {
        if data.len() > self.remaining() {
            return Err(self.remaining());
        }
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
        Ok(())
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }
}
