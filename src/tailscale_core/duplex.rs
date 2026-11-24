/// A blocking, bidirectional byte connection the control link runs over.
///
/// Errors carry no detail; the caller reports which step failed.
pub trait Duplex {
    /// Reads at least one byte, or returns `Ok(0)` at end of stream.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, ()>;
    fn write_all(&mut self, buf: &[u8]) -> Result<(), ()>;
}
