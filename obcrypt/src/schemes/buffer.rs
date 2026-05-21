//! `aead::Buffer` adapter that views a tail-slice of an existing
//! `Vec<u8>` as a growable buffer.
//!
//! Used by per-scheme `*_into` functions so AEAD `encrypt_in_place` /
//! `decrypt_in_place` can write ciphertext directly into a caller-
//! provided buffer without an intermediate allocation.

use aead::Buffer;

pub(crate) struct TailBuffer<'a> {
    vec: &'a mut Vec<u8>,
    start: usize,
}

impl<'a> TailBuffer<'a> {
    #[inline]
    pub(crate) fn new(vec: &'a mut Vec<u8>, start: usize) -> Self {
        debug_assert!(start <= vec.len(), "TailBuffer start out of bounds");
        TailBuffer { vec, start }
    }
}

impl AsRef<[u8]> for TailBuffer<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.vec[self.start..]
    }
}

impl AsMut<[u8]> for TailBuffer<'_> {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.vec[self.start..]
    }
}

impl Buffer for TailBuffer<'_> {
    #[inline]
    fn extend_from_slice(&mut self, other: &[u8]) -> Result<(), aead::Error> {
        self.vec.extend_from_slice(other);
        Ok(())
    }

    #[inline]
    fn truncate(&mut self, len: usize) {
        self.vec.truncate(self.start + len);
    }
}
