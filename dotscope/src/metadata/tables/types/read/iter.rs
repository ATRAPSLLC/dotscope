//! Iterator implementations for sequential and parallel metadata table processing.
//!
//! This module provides iterator types that enable efficient traversal of metadata table rows
//! in both sequential and parallel modes. The iterators are designed to work seamlessly with
//! the Rust iterator ecosystem while providing specialized optimizations for metadata table
//! access patterns.
//!
//! ## Iterator Types
//!
//! - [`TableIterator`] - Sequential iterator for memory-efficient row-by-row processing
//! - [`TableParIterator`] - Parallel iterator leveraging Rayon for concurrent processing
//! - [`TableProducer`] - Internal work distribution for parallel iteration
//! - [`TableProducerIterator`] - Internal chunk processing for parallel iteration
//!
//! ## Design Goals
//!
//! The iterator design prioritizes:
//! - **Lazy evaluation**: Rows are parsed only when accessed, reducing memory usage
//! - **Error resilience**: Parse failures result in `None` rather than panics
//! - **Performance**: Optimal memory access patterns and parallel processing support
//!
//! ## Thread Safety
//!
//! All iterator types support concurrent access with appropriate safety guarantees:
//! - Sequential iterators are `Send` for thread transfer
//! - Parallel iterators require `Send + Sync` row types for safe concurrent processing
//! - Work-stealing algorithms ensure optimal load balancing across threads
//!
//! ## Related Modules
//!
//! - [`crate::metadata::tables::types::read::table`] - Table container that creates iterators
//! - [`crate::metadata::tables::types::read::traits`] - Core parsing traits
//! - [`crate::metadata::tables::types::read::access`] - Low-level access utilities

use rayon::iter::{plumbing, IndexedParallelIterator, ParallelIterator};

use crate::{
    metadata::tables::{MetadataTable, RowReadable},
    Result,
};

/// Discards a row that could not be parsed, after logging it.
///
/// For consumers that genuinely cannot propagate - an adapter chain inside a function
/// returning `Option`, or a scan that has no error channel. Written as a named function
/// rather than `.flatten()` or `.filter_map(Result::ok)` so that dropping a row is greppable
/// and leaves a trace: a silently short table is how a malformed row turns into missing
/// analysis output rather than an error.
///
/// Prefer `?` wherever the caller can carry an error.
///
/// # Position is not RID
///
/// Dropping a row shifts everything after it, so **the position of a row in a filtered
/// sequence is not its RID**. Never derive a RID from `enumerate()`, an index into a
/// collected `Vec`, `.first()`, or `.next()`:
///
/// ```no_run
/// # use dotscope::metadata::tables::{skip_unreadable, MetadataTable, ModuleRaw};
/// # fn example(table: &MetadataTable<ModuleRaw>) {
/// // Wrong: one unreadable row ahead of the match names a different row entirely.
/// for (index, row) in table.iter().filter_map(skip_unreadable).enumerate() {
///     let rid = index as u32 + 1;
/// }
///
/// // Right: the row carries its own RID.
/// for row in table.iter().filter_map(skip_unreadable) {
///     let rid = row.rid;
/// }
///
/// // Right, when a specific RID is wanted: `get` derives each row's offset from its RID,
/// // so an unreadable row cannot displace any other.
/// let module = table.get(1).ok().flatten();
/// # }
/// ```
///
/// Every raw row struct carries a `rid` field, and
/// [`MetadataTable::get`](super::MetadataTable::get) fetches by RID directly. This mattered
/// most where a row was read positionally and written back under the original RID, which
/// copied one row's contents onto a different row.
#[must_use]
pub fn skip_unreadable<T>(row: Result<T>) -> Option<T> {
    match row {
        Ok(row) => Some(row),
        Err(e) => {
            log::warn!("skipping unreadable metadata row: {e}");
            None
        }
    }
}

/// Sequential iterator for metadata table rows.
///
/// This iterator provides lazy, on-demand access to table rows in sequential order.
/// It maintains minimal state and parses rows only as they are requested, making
/// it memory-efficient for large tables.
///
/// ## Characteristics
///
/// - **Lazy evaluation**: Rows are parsed only when accessed
/// - **Memory efficient**: Constant memory usage regardless of table size
/// - **Honest about failure**: a row that does not parse is yielded as `Err`, not skipped
/// - **Cache friendly**: Sequential access pattern optimizes memory locality
///
/// ## Why the item type is a `Result`
///
/// Yielding `None` on a parse error would end the iteration, silently dropping every
/// remaining row - a row-hiding primitive on a hostile file, and one that reaches further
/// than it looks: the writer rebuilds tables by iterating them, so a table truncated this way
/// is re-emitted without the rows that were skipped. Every row is therefore reported, and the
/// iterator always yields exactly `row_count` items.
pub struct TableIterator<'a, T> {
    /// Reference to the table being iterated
    pub table: &'a MetadataTable<'a, T>,
    /// Current row number (0-based for internal tracking)
    pub current_row: u32,
}

impl<T: RowReadable> Iterator for TableIterator<'_, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_row >= self.table.row_count {
            return None;
        }

        let rid = self.current_row.saturating_add(1);
        self.current_row = rid;

        // `get` derives each row's offset from its index, so a failure here costs this row
        // and no other - which is what makes continuing after one sound.
        self.table.get(rid).transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .table
            .row_count
            .saturating_sub(self.current_row)
            .try_into()
            .unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl<T: RowReadable> ExactSizeIterator for TableIterator<'_, T> {}

/// Parallel iterator for metadata table rows.
///
/// This iterator enables concurrent processing of table rows across multiple threads
/// using the Rayon parallel processing framework. It automatically distributes work
/// and handles synchronization, providing significant performance improvements for
/// CPU-intensive operations on large tables.
///
/// ## Features
///
/// - **Automatic parallelization**: Work is distributed across available CPU cores
/// - **Load balancing**: Dynamic work stealing ensures optimal CPU utilization  
/// - **Error handling**: Built-in support for early termination on errors
/// - **Type safety**: Compile-time guarantees about thread safety requirements
///
/// ## Requirements
///
/// The row type `T` must implement `Send + Sync` to enable safe parallel processing.
/// This ensures that rows can be safely transferred between threads and accessed
/// concurrently.
///
/// ## Usage
///
/// Created through [`MetadataTable::par_iter()`] and supports all Rayon parallel
/// iterator operations
pub struct TableParIterator<'a, T> {
    /// Reference to the table being iterated
    pub table: &'a MetadataTable<'a, T>,
    /// Range of row indices to process
    pub range: std::ops::Range<u32>,
}

impl<T: RowReadable + Send + Sync> ParallelIterator for TableParIterator<'_, T> {
    type Item = Result<T>;

    fn drive_unindexed<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::UnindexedConsumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }
}

impl<T: RowReadable + Send + Sync> IndexedParallelIterator for TableParIterator<'_, T> {
    fn len(&self) -> usize {
        self.range.len()
    }

    fn drive<C>(self, consumer: C) -> C::Result
    where
        C: rayon::iter::plumbing::Consumer<Self::Item>,
    {
        plumbing::bridge(self, consumer)
    }

    fn with_producer<CB>(self, callback: CB) -> CB::Output
    where
        CB: rayon::iter::plumbing::ProducerCallback<Self::Item>,
    {
        callback.callback(TableProducer {
            table: self.table,
            range: self.range,
        })
    }
}

/// Internal producer for parallel iteration work distribution.
///
/// This struct implements the Rayon `Producer` trait to enable efficient work
/// distribution for parallel table iteration. It handles the splitting of table
/// ranges into smaller chunks that can be processed independently by different
/// threads.
///
/// ## Purpose
///
/// The producer is responsible for:
/// - Dividing table ranges into manageable chunks for parallel processing
/// - Creating iterators for each chunk that can be processed independently
/// - Supporting Rayon's work-stealing algorithm for optimal load balancing
///
/// ## Implementation Details
///
/// This is an internal implementation detail of the parallel iteration system
/// and is not intended for direct use by library consumers. It supports the
/// [`TableParIterator`] functionality transparently.
struct TableProducer<'a, T> {
    /// Reference to the table being processed
    table: &'a MetadataTable<'a, T>,
    /// Range of row indices for this producer to handle
    range: std::ops::Range<u32>,
}

/// The fewest rows a split leaves one task.
///
/// A row parses in nanoseconds, so a task of fewer rows costs more to schedule than to
/// run. And every split is a join, at which a worker waits for the other half and runs
/// whatever other work it finds meanwhile, on the stack it is waiting on: another
/// table's halves, another assembly's, each nesting the next. With every table split to
/// single rows, the loads a test suite runs side by side nested deep enough to overflow
/// a worker's stack. A table smaller than this is not split at all.
const ROWS_PER_TASK: usize = 512;

impl<'a, T: RowReadable + Send + Sync> rayon::iter::plumbing::Producer for TableProducer<'a, T> {
    type Item = Result<T>;
    type IntoIter = TableProducerIterator<'a, T>;

    fn min_len(&self) -> usize {
        ROWS_PER_TASK
    }

    fn into_iter(self) -> Self::IntoIter {
        TableProducerIterator {
            table: self.table,
            range: self.range,
        }
    }

    fn split_at(self, index: usize) -> (Self, Self) {
        // Index represents table row positions which are expected to fit in u32
        #[allow(clippy::cast_possible_truncation)]
        let mid = self.range.start.saturating_add(index as u32);
        let left = TableProducer {
            table: self.table,
            range: self.range.start..mid,
        };
        let right = TableProducer {
            table: self.table,
            range: mid..self.range.end,
        };
        (left, right)
    }
}

/// Internal iterator for parallel iteration chunks.
///
/// This iterator processes a specific range of table rows as part of the parallel
/// iteration system. Each thread in the parallel processing pool receives its own
/// instance of this iterator to process a subset of the total table rows.
///
/// ## Characteristics
///
/// - **Bounded range**: Processes only a specific subset of table rows
/// - **Double-ended**: Supports iteration from both ends for work stealing
/// - **Exact size**: Provides precise size information for optimization
/// - **Thread-local**: Each thread operates on its own iterator instance
///
/// ## Implementation Details
///
/// This is an internal component of the parallel iteration infrastructure and
/// is not exposed directly to library users. It enables the work-stealing
/// algorithm used by Rayon for optimal parallel performance.
struct TableProducerIterator<'a, T> {
    /// Reference to the table being processed
    table: &'a MetadataTable<'a, T>,
    /// Range of row indices for this iterator to process
    range: std::ops::Range<u32>,
}

impl<T: RowReadable + Send + Sync> Iterator for TableProducerIterator<'_, T> {
    type Item = Result<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }

        let row_index = self.range.start;
        self.range.start = self.range.start.saturating_add(1);

        // Get the row directly from the table
        // +1 because row indices start at 1
        //
        // A failing row is yielded as `Err`, so this chunk still produces exactly
        // `range.len()` items - which is what `ExactSizeIterator` below promises rayon, and
        // what `IndexedParallelIterator::len` reports.
        self.table.get(row_index.saturating_add(1)).transpose()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.range.len();
        (len, Some(len))
    }
}

impl<T: RowReadable + Send + Sync> ExactSizeIterator for TableProducerIterator<'_, T> {}

// Implement DoubleEndedIterator for compatibility with Rayon
impl<T: RowReadable + Send + Sync> DoubleEndedIterator for TableProducerIterator<'_, T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.range.start >= self.range.end {
            return None;
        }

        self.range.end = self.range.end.saturating_sub(1);

        // Get the row directly from the table
        // +1 because row indices start at 1
        self.table.get(self.range.end.saturating_add(1)).transpose()
    }
}
