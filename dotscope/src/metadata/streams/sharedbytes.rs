//! Bytes of a `#Blob` heap entry, shared by every row that names the heap.
//!
//! [`SharedBytes`] is a view of one entry of a shared copy of the heap: a row keeping its blob
//! this way costs the same whatever the blob's length, and however many rows name it (see
//! [`crate::metadata::streams::Blob::get_shared`]). It reads as the `[u8]` it views.

use std::{fmt, ops::Deref, sync::Arc};

/// An immutable byte string viewing an entry of a shared copy of a `#Blob` heap.
///
/// Cloning is a reference count increment. Bytes from outside a heap convert with [`From`],
/// holding a copy of their own.
///
/// # Examples
///
/// ```
/// use dotscope::metadata::streams::SharedBytes;
///
/// let hash = SharedBytes::from(vec![0xDE, 0xAD]);
/// assert_eq!(&hash[..], &[0xDE, 0xAD]);
/// assert_eq!(hash, [0xDE, 0xAD]);
/// ```
#[derive(Clone)]
pub struct SharedBytes {
    /// The heap (or the copy) the bytes are part of
    heap: Arc<[u8]>,
    /// Where the bytes start in `heap`
    start: u32,
    /// How many bytes there are
    len: u32,
}

impl SharedBytes {
    /// The bytes `heap[start..start + len]`.
    ///
    /// # Returns
    /// `None` when the range is not inside `heap`.
    pub fn view(heap: Arc<[u8]>, start: usize, len: usize) -> Option<Self> {
        let end = start.checked_add(len)?;
        if end > heap.len() {
            return None;
        }
        Some(Self {
            heap,
            start: u32::try_from(start).ok()?,
            len: u32::try_from(len).ok()?,
        })
    }

    /// The bytes, as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        let start = usize::try_from(self.start).unwrap_or(usize::MAX);
        let len = usize::try_from(self.len).unwrap_or(0);
        start
            .checked_add(len)
            .and_then(|end| self.heap.get(start..end))
            .unwrap_or_default()
    }
}

impl Default for SharedBytes {
    fn default() -> Self {
        Self {
            heap: Arc::from(Vec::new()),
            start: 0,
            len: 0,
        }
    }
}

impl Deref for SharedBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for SharedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl fmt::Debug for SharedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

impl PartialEq for SharedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for SharedBytes {}

impl std::hash::Hash for SharedBytes {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl PartialEq<[u8]> for SharedBytes {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<&[u8]> for SharedBytes {
    fn eq(&self, other: &&[u8]) -> bool {
        self.as_slice() == *other
    }
}

impl<const N: usize> PartialEq<[u8; N]> for SharedBytes {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<Vec<u8>> for SharedBytes {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl From<Vec<u8>> for SharedBytes {
    fn from(bytes: Vec<u8>) -> Self {
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        Self {
            heap: Arc::from(bytes),
            start: 0,
            len,
        }
    }
}

impl From<&[u8]> for SharedBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::from(bytes.to_vec())
    }
}

impl From<SharedBytes> for Vec<u8> {
    fn from(bytes: SharedBytes) -> Self {
        bytes.as_slice().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_view_reads_its_range_and_shares_the_heap() {
        let heap: Arc<[u8]> = Arc::from(vec![1u8, 2, 3, 4, 5]);
        let view = SharedBytes::view(Arc::clone(&heap), 1, 3).unwrap();
        assert_eq!(view, [2, 3, 4]);
        assert_eq!(Arc::strong_count(&heap), 2);
        assert!(SharedBytes::view(Arc::clone(&heap), 4, 2).is_none());
        assert!(SharedBytes::view(heap, 5, 0).unwrap().is_empty());
        assert_eq!(Vec::from(SharedBytes::from(vec![9u8])), [9]);
        assert!(SharedBytes::default().is_empty());
    }
}
