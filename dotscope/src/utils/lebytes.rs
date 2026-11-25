//! Stack-allocated byte buffer for small serialized values.
//!
//! Provides [`LeBytes`], an inline buffer that avoids heap allocation for the common
//! case of converting primitive CIL values to their little-endian byte representation.
//! All CIL primitives fit in 8 bytes or fewer, so this covers every case without
//! touching the allocator.

/// Stack-allocated byte buffer for small serialized values (max 8 bytes).
///
/// Replaces `Vec<u8>` in hot paths like `EmValue::to_le_bytes()` and `stind` handlers
/// where only 1–8 bytes are produced and immediately consumed as `&[u8]`.
///
/// Implements [`Deref<Target = [u8]>`](std::ops::Deref), [`AsRef<[u8]>`], and
/// [`IntoIterator`] so it can be used transparently wherever `&[u8]` or byte
/// iteration is expected.
///
/// # Examples
///
/// The `examples::le_bytes_example` test in this module runs this example.
#[derive(Debug, Clone, Copy)]
pub struct LeBytes {
    buf: [u8; 8],
    len: u8,
}

impl LeBytes {
    /// Creates a new `LeBytes` from a single byte.
    #[inline]
    pub const fn from_byte(b: u8) -> Self {
        Self {
            buf: [b, 0, 0, 0, 0, 0, 0, 0],
            len: 1,
        }
    }

    /// Creates a new `LeBytes` from a 2-byte array.
    #[inline]
    pub const fn from_2(bytes: [u8; 2]) -> Self {
        Self {
            buf: [bytes[0], bytes[1], 0, 0, 0, 0, 0, 0],
            len: 2,
        }
    }

    /// Creates a new `LeBytes` from a 4-byte array.
    #[inline]
    pub const fn from_4(bytes: [u8; 4]) -> Self {
        Self {
            buf: [bytes[0], bytes[1], bytes[2], bytes[3], 0, 0, 0, 0],
            len: 4,
        }
    }

    /// Creates a new `LeBytes` from an 8-byte array.
    #[inline]
    pub const fn from_8(bytes: [u8; 8]) -> Self {
        Self { buf: bytes, len: 8 }
    }

    /// Creates a `LeBytes` filled with zeros of the given length (clamped to 8).
    #[inline]
    pub const fn zeroed(len: usize) -> Self {
        let len = if len > 8 { 8 } else { len };
        Self {
            buf: [0; 8],
            len: len as u8,
        }
    }

    /// Returns the bytes as a slice.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY-equivalent: `self.len` is always <= 8 (clamped at construction).
        let len = (self.len as usize).min(self.buf.len());
        self.buf.get(..len).unwrap_or(&[])
    }

    /// Returns the number of bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns whether the buffer is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl std::ops::Deref for LeBytes {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for LeBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq<[u8]> for LeBytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Vec<u8>> for LeBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl IntoIterator for LeBytes {
    type Item = u8;
    type IntoIter = LeBytesIter;

    #[inline]
    fn into_iter(self) -> LeBytesIter {
        LeBytesIter {
            bytes: self,
            pos: 0,
        }
    }
}

/// Iterator over the bytes in a [`LeBytes`] buffer.
pub struct LeBytesIter {
    bytes: LeBytes,
    pos: u8,
}

impl Iterator for LeBytesIter {
    type Item = u8;

    #[inline]
    fn next(&mut self) -> Option<u8> {
        if self.pos < self.bytes.len {
            let b = *self.bytes.buf.get(self.pos as usize)?;
            self.pos = self.pos.saturating_add(1u8);
            Some(b)
        } else {
            None
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bytes.len.saturating_sub(self.pos) as usize;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for LeBytesIter {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_byte() {
        let b = LeBytes::from_byte(0xAB);
        assert_eq!(b.len(), 1);
        assert_eq!(&*b, &[0xAB]);
    }

    #[test]
    fn from_2() {
        let b = LeBytes::from_2(0x1234u16.to_le_bytes());
        assert_eq!(b.len(), 2);
        assert_eq!(&*b, &[0x34, 0x12]);
    }

    #[test]
    fn from_4() {
        let b = LeBytes::from_4(0x12345678i32.to_le_bytes());
        assert_eq!(b.len(), 4);
        assert_eq!(&*b, &[0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn from_8() {
        let b = LeBytes::from_8(0x0102030405060708i64.to_le_bytes());
        assert_eq!(b.len(), 8);
        assert_eq!(&*b, &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn zeroed() {
        let b = LeBytes::zeroed(4);
        assert_eq!(b.len(), 4);
        assert_eq!(&*b, &[0, 0, 0, 0]);
    }

    #[test]
    fn zeroed_clamps_to_8() {
        let b = LeBytes::zeroed(100);
        assert_eq!(b.len(), 8);
    }

    #[test]
    fn into_iterator() {
        let b = LeBytes::from_4([1, 2, 3, 4]);
        let collected: Vec<u8> = b.into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3, 4]);
    }

    #[test]
    fn flat_map_usage() {
        let values = [1i32, 2i32];
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|v| LeBytes::from_4(v.to_le_bytes()))
            .collect();
        assert_eq!(bytes, vec![1, 0, 0, 0, 2, 0, 0, 0]);
    }

    #[test]
    fn deref_to_slice() {
        let b = LeBytes::from_2([0xAA, 0xBB]);
        let slice: &[u8] = &b;
        assert_eq!(slice, &[0xAA, 0xBB]);
    }

    #[test]
    fn partial_eq_vec() {
        let b = LeBytes::from_4([1, 2, 3, 4]);
        assert_eq!(b, vec![1, 2, 3, 4]);
    }

    #[test]
    fn exact_size_iterator() {
        let b = LeBytes::from_4([1, 2, 3, 4]);
        let mut iter = b.into_iter();
        assert_eq!(iter.len(), 4);
        iter.next();
        assert_eq!(iter.len(), 3);
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    #[test]
    fn le_bytes_example() -> Result<()> {
        let b = LeBytes::from_4(42i32.to_le_bytes());
        assert_eq!(b.len(), 4);
        assert_eq!(&*b, &42i32.to_le_bytes());

        // Works with flat_map for byte streams
        let values = [1i32, 2, 3];
        let bytes: Vec<u8> = values
            .iter()
            .flat_map(|v| LeBytes::from_4(v.to_le_bytes()))
            .collect();
        assert_eq!(bytes.len(), 12);
        Ok(())
    }
}
