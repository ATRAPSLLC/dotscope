//! Lazily-allocated list whose entries stay in metadata table order.
//!
//! [`RowList`] is a [`LazyList`](crate::utils::LazyList) for the lists metadata rows attach
//! themselves to: the custom attributes of a type, its interfaces, its nested types, its generic
//! parameters and their constraints, a method's overrides. The loaders build those rows in
//! parallel, so the rows arrive in whatever order the threads finish. A plain append-only list
//! kept that order, and the same file listed an owner's attributes differently from one load to
//! the next.
//!
//! Each entry is recorded under the token of the row it came from, and iteration walks entries by
//! that token, so the list reads in table order however it was filled. For generic parameters,
//! whose table is sorted by owner and number, that is also parameter order. Entries pushed without
//! a row (built in memory rather than read from a table) follow every row entry, in the order
//! they were pushed.
//!
//! # Concurrency
//!
//! As [`LazyList`](crate::utils::LazyList): the storage is allocated on first push, pushes take
//! `&self`, and clones share storage. The entries live in a `boxcar::Vec`, which hands out stable
//! references; a concurrent ordered index over them decides the order.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use crossbeam_skiplist::{map, SkipMap};

use crate::metadata::token::Token;

/// Where an entry sorts: the row it came from, then the slot it was stored in.
///
/// Entries without a row take the highest row key, so they follow every row entry; the slot
/// keeps them in push order among themselves.
type OrderKey = (u32, usize);

/// The storage behind a [`RowList`], allocated on first push.
struct Rows<T> {
    /// The entries, in the order they were pushed.
    entries: boxcar::Vec<T>,
    /// Every entry's slot in `entries`, ordered by [`OrderKey`].
    order: SkipMap<OrderKey, ()>,
}

/// An append-only concurrent list that iterates in metadata table order.
///
/// [`RowList`] is a [`LazyList`](crate::metadata::LazyList) for the lists metadata rows attach
/// themselves to: the custom attributes of a type, its interfaces, its nested types, its generic
/// parameters and their constraints, a method's overrides. The loaders build those rows in
/// parallel, so the rows arrive in whatever order the threads finish. A plain append-only list
/// kept that order, and the same file listed an owner's attributes differently from one load to
/// the next.
///
/// Each entry is recorded under the token of the row it came from, and iteration walks entries by
/// that token, so the list reads in table order however it was filled. For generic parameters,
/// whose table is sorted by owner and number, that is also parameter order. Entries pushed without
/// a row (built in memory rather than read from a table) follow every row entry, in the order
/// they were pushed.
///
/// # Concurrency
///
/// As [`LazyList`](crate::metadata::LazyList): the storage is allocated on first push, pushes take
/// `&self`, and clones share storage. The entries live in a `boxcar::Vec`, which hands out stable
/// references; a concurrent ordered index over them decides the order.
pub struct RowList<T> {
    inner: OnceLock<Arc<Rows<T>>>,
}

impl<T> RowList<T> {
    /// Creates an empty list that has not allocated its storage.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: OnceLock::new(),
        }
    }

    /// Returns the storage, allocating it if this is the first use.
    fn materialize(&self) -> &Arc<Rows<T>> {
        self.inner.get_or_init(|| {
            Arc::new(Rows {
                entries: boxcar::Vec::new(),
                order: SkipMap::new(),
            })
        })
    }

    /// Appends a value read from the row `row`; it sorts by that row.
    pub fn push_row(&self, row: Token, value: T) {
        self.insert(row.value(), value);
    }

    /// Appends a value that no row produced; it sorts after every row entry.
    pub fn push(&self, value: T) {
        self.insert(u32::MAX, value);
    }

    fn insert(&self, row: u32, value: T) {
        let rows = self.materialize();
        let slot = rows.entries.push(value);
        rows.order.insert((row, slot), ());
    }

    /// Returns the number of elements.
    ///
    /// Does not allocate: an uninitialised list is empty by definition.
    #[must_use]
    pub fn count(&self) -> usize {
        self.inner.get().map_or(0, |rows| rows.order.len())
    }

    /// Returns the number of elements. Alias of [`count`](Self::count).
    #[must_use]
    pub fn len(&self) -> usize {
        self.count()
    }

    /// Returns whether the list has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Returns the element at `position` in table order, or `None` if out of bounds.
    #[must_use]
    pub fn get(&self, position: usize) -> Option<&T> {
        self.iter().nth(position).map(|(_, value)| value)
    }

    /// Returns an iterator over `(position, &value)` pairs in table order.
    ///
    /// Does not allocate when the list was never pushed to.
    #[must_use]
    pub fn iter(&self) -> RowListIter<'_, T> {
        let rows = self.inner.get().map(Arc::as_ref);
        RowListIter {
            order: rows.map(|rows| rows.order.iter()),
            rows,
            position: 0,
        }
    }
}

impl<T> Default for RowList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Clone for RowList<T> {
    /// Clones the handle, sharing storage with the original, for the reason
    /// [`LazyList`](crate::utils::LazyList)'s clone gives: a push through one is visible through
    /// the other.
    fn clone(&self) -> Self {
        let shared = Arc::clone(self.materialize());
        Self {
            inner: OnceLock::from(shared),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for RowList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter().map(|(_, v)| v)).finish()
    }
}

impl<'a, T> IntoIterator for &'a RowList<T> {
    type Item = (usize, &'a T);
    type IntoIter = RowListIter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T> FromIterator<T> for RowList<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let list = Self::new();
        for value in iter {
            list.push(value);
        }
        list
    }
}

/// Iterator over a [`RowList`] in table order, yielding `(position, &value)`.
///
/// Yields nothing when the list never allocated.
pub struct RowListIter<'a, T> {
    rows: Option<&'a Rows<T>>,
    order: Option<map::Iter<'a, OrderKey, ()>>,
    position: usize,
}

impl<'a, T> Iterator for RowListIter<'a, T> {
    type Item = (usize, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        let rows = self.rows?;
        let (_, slot) = *self.order.as_mut()?.next()?.key();
        let value = rows.entries.get(slot)?;
        let position = self.position;
        self.position = position.saturating_add(1);
        Some((position, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_list_does_not_allocate() {
        let list: RowList<u32> = RowList::new();

        assert!(list.is_empty());
        assert_eq!(list.iter().count(), 0);
        assert!(list.get(0).is_none());
        assert!(list.inner.get().is_none());
    }

    #[test]
    fn rows_read_in_table_order_however_they_arrive() {
        let list = RowList::new();
        for row in [7u32, 2, 9, 1, 5] {
            list.push_row(Token::new(0x0C00_0000 | row), row);
        }

        let read: Vec<u32> = list.iter().map(|(_, v)| *v).collect();
        assert_eq!(read, vec![1, 2, 5, 7, 9]);
        assert_eq!(list.get(2), Some(&5));
        let positions: Vec<usize> = list.iter().map(|(i, _)| i).collect();
        assert_eq!(positions, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn entries_without_a_row_follow_the_rows_in_push_order() {
        let list = RowList::new();
        list.push(100);
        list.push_row(Token::new(0x0C00_0002), 2);
        list.push(101);
        list.push_row(Token::new(0x0C00_0001), 1);

        let read: Vec<u32> = list.iter().map(|(_, v)| *v).collect();
        assert_eq!(read, vec![1, 2, 100, 101]);
    }

    #[test]
    fn rows_pushed_from_many_threads_read_in_table_order() {
        let list = RowList::new();
        std::thread::scope(|scope| {
            for thread in 0..8u32 {
                let list = &list;
                scope.spawn(move || {
                    for row in (0..64u32).filter(|row| row % 8 == thread).rev() {
                        list.push_row(Token::new(0x0C00_0000 | (row + 1)), row);
                    }
                });
            }
        });

        let read: Vec<u32> = list.iter().map(|(_, v)| *v).collect();
        assert_eq!(read, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn clones_share_storage() {
        let original: RowList<u32> = RowList::new();
        let cloned = original.clone();
        cloned.push_row(Token::new(0x0C00_0001), 7);

        assert_eq!(original.count(), 1);
        assert_eq!(original.get(0), Some(&7));
    }
}
