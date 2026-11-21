//! Lazily-allocated append-only list.
//!
//! [`LazyList`] wraps `Arc<boxcar::Vec<T>>` behind a [`OnceLock`], allocating the backing vector
//! on first push rather than at construction.
//!
//! # Why this exists
//!
//! `boxcar::Vec` is not a thin handle. It is `{ inflight: AtomicUsize, buckets: [AtomicPtr; 58],
//! count: AtomicUsize }` — 480 bytes inline, and `Buckets::new` materialises all 58 slots as
//! null rather than allocating them lazily. With the `Arc` header that is ~496 bytes for an
//! empty list.
//!
//! Metadata rows carry many such lists that are almost always empty: a method rarely has
//! varargs, generic arguments, overrides, local variables or interface implementations. Eagerly
//! constructing them made a 14-byte MethodDef row cost roughly 4 KB of zeroed bucket arrays —
//! a 300–500× amplification from table bytes to resident memory, driven entirely by attacker-
//! controlled row counts.
//!
//! # Concurrency
//!
//! Unchanged from the eager form. `OnceLock` makes first-push initialisation race-free, and
//! `boxcar::Vec` itself provides the append-only concurrent semantics; [`push`](LazyList::push)
//! still takes `&self`.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

/// An append-only concurrent list whose backing storage is allocated on first use.
///
/// [`LazyList`] wraps `Arc<boxcar::Vec<T>>` behind a [`OnceLock`], allocating the backing vector
/// on first push rather than at construction.
///
/// # Why this exists
///
/// `boxcar::Vec` is not a thin handle. It is `{ inflight: AtomicUsize, buckets: [AtomicPtr; 58],
/// count: AtomicUsize }`: 480 bytes inline, and `Buckets::new` materialises all 58 slots as
/// null rather than allocating them lazily. With the `Arc` header that is ~496 bytes for an
/// empty list.
///
/// Metadata rows carry many such lists that are almost always empty: a method rarely has
/// varargs, generic arguments, overrides, local variables or interface implementations. Eagerly
/// constructing them made a 14-byte MethodDef row cost roughly 4 KB of zeroed bucket arrays,
/// a 300-500× amplification from table bytes to resident memory, driven entirely by attacker-
/// controlled row counts.
///
/// # Concurrency
///
/// Unchanged from the eager form. `OnceLock` makes first-push initialisation race-free, and
/// `boxcar::Vec` itself provides the append-only concurrent semantics; [`push`](LazyList::push)
/// still takes `&self`.
pub struct LazyList<T> {
    inner: OnceLock<Arc<boxcar::Vec<T>>>,
}

impl<T> LazyList<T> {
    /// Creates an empty list that has not allocated its backing storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    /// Returns the backing vector, allocating it if this is the first use.
    fn materialize(&self) -> &Arc<boxcar::Vec<T>> {
        self.inner.get_or_init(|| Arc::new(boxcar::Vec::new()))
    }

    /// Appends a value, returning its index.
    ///
    /// Allocates the backing vector on the first call.
    pub fn push(&self, value: T) -> usize {
        self.materialize().push(value)
    }

    /// Returns the number of elements.
    ///
    /// Does not allocate: an uninitialised list is empty by definition.
    #[must_use]
    pub fn count(&self) -> usize {
        self.inner.get().map_or(0, |list| list.count())
    }

    /// Returns the number of elements. Alias of [`count`](Self::count), matching `boxcar::Vec`,
    /// which exposes both.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count()
    }

    /// Returns whether the list has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Returns the element at `index`, or `None` if out of bounds.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&T> {
        self.inner.get()?.get(index)
    }

    /// Returns an iterator over `(index, &value)` pairs.
    ///
    /// Does not allocate when the list was never pushed to.
    #[must_use]
    pub fn iter(&self) -> LazyListIter<'_, T> {
        LazyListIter {
            inner: self.inner.get().map(|list| list.iter()),
        }
    }
}

impl<T> Default for LazyList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for LazyList<T> {
    /// Clones the handle, sharing storage with the original.
    ///
    /// Deliberately materialises the backing vector: the field this type replaces was an `Arc`,
    /// so clones shared their contents and a push through one was visible through the other.
    /// Cloning an uninitialised list lazily would hand back two independent lists and silently
    /// break that. Clones are rare compared with the empty lists this type exists to avoid, so
    /// paying an allocation here is the right side of the trade.
    fn clone(&self) -> Self {
        let shared = Arc::clone(self.materialize());
        Self {
            inner: OnceLock::from(shared),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for LazyList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter().map(|(_, v)| v)).finish()
    }
}

impl<'a, T> IntoIterator for &'a LazyList<T> {
    type Item = (usize, &'a T);
    type IntoIter = LazyListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> FromIterator<T> for LazyList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let list = Self::new();
        for value in iter {
            list.push(value);
        }
        list
    }
}

/// Iterator over a [`LazyList`], yielding `(index, &value)`.
///
/// Yields nothing when the list never allocated.
pub struct LazyListIter<'a, T> {
    inner: Option<boxcar::Iter<'a, T>>,
}

impl<'a, T> Iterator for LazyListIter<'a, T> {
    type Item = (usize, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.as_mut()?.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_does_not_allocate() {
        let list: LazyList<u32> = LazyList::new();

        assert!(list.is_empty());
        assert_eq!(list.count(), 0);
        assert_eq!(list.iter().count(), 0);
        assert!(list.get(0).is_none());
        assert!(
            list.inner.get().is_none(),
            "querying an empty list must not materialise the backing vector"
        );
    }

    #[test]
    fn push_materializes_and_stores() {
        let list = LazyList::new();

        assert_eq!(list.push(10), 0);
        assert_eq!(list.push(20), 1);

        assert_eq!(list.count(), 2);
        assert!(!list.is_empty());
        assert_eq!(list.get(0), Some(&10));
        assert_eq!(list.get(1), Some(&20));
        assert_eq!(list.get(2), None);

        let collected: Vec<(usize, u32)> = list.iter().map(|(i, v)| (i, *v)).collect();
        assert_eq!(collected, vec![(0, 10), (1, 20)]);
    }

    /// Clones must share storage, matching the `Arc<boxcar::Vec<_>>` this replaces.
    #[test]
    fn clones_share_storage() {
        let original = LazyList::new();
        original.push(1);

        let cloned = original.clone();
        cloned.push(2);

        assert_eq!(
            original.count(),
            2,
            "a push through the clone must be visible"
        );
        assert_eq!(cloned.count(), 2);
    }

    /// Sharing must hold even when the list had not been pushed to before cloning — the case a
    /// naive lazy clone would get wrong.
    #[test]
    fn clones_of_empty_lists_still_share() {
        let original: LazyList<u32> = LazyList::new();
        let cloned = original.clone();

        cloned.push(7);

        assert_eq!(original.count(), 1);
        assert_eq!(original.get(0), Some(&7));
    }

    #[test]
    fn collects_from_iterator() {
        let list: LazyList<u32> = (0..4).collect();
        assert_eq!(list.count(), 4);
        assert_eq!(list.get(3), Some(&3));
    }

    #[test]
    fn iterates_by_reference() {
        let list: LazyList<u32> = (0..3).collect();
        let mut total = 0;
        for (_, v) in &list {
            total += *v;
        }
        assert_eq!(total, 3);
    }
}
