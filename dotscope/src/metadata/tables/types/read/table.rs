//! Generic metadata table container with typed row access and iteration support.
//!
//! This module provides the [`MetadataTable`] type, which serves as the primary interface
//! for working with .NET metadata tables. It offers type-safe access to table rows,
//! supporting both sequential and parallel iteration patterns commonly used in metadata
//! processing scenarios.
//!
//! ## Key Features
//!
//! - **Type Safety**: Compile-time guarantees for row type correctness
//! - **Performance**: Zero-copy access to underlying table data
//! - **Concurrency**: Built-in support for parallel row processing
//! - **Memory Efficiency**: Lazy parsing of rows on access
//!
//! ## Usage Patterns
//!
//! The table container supports several common access patterns:
//! - **Direct Access**: Random access to specific rows by index
//! - **Sequential Iteration**: Forward iteration through all rows
//! - **Parallel Processing**: Concurrent processing of multiple rows
//! - **Filtered Processing**: Selective row processing with iterator combinators
//!
//! ## Thread Safety
//!
//! `MetadataTable` is designed for concurrent read access, allowing multiple threads
//! to safely iterate over and access table data simultaneously without synchronization.
//!
//! ## Related Types
//!
//! - [`crate::metadata::tables::types::read::iter`] - Iterator implementations
//! - [`crate::metadata::tables::types::read::access`] - Low-level access utilities
//! - [`crate::metadata::tables::types::read::traits`] - Core trait definitions

use std::{marker::PhantomData, sync::Arc};

use crate::{
    metadata::tables::{RowReadable, TableInfoRef, TableIterator, TableParIterator},
    Result,
};

/// Generic container for metadata table data with typed row access.
///
/// This structure provides a high-level interface for working with .NET metadata tables,
/// offering both sequential and parallel iteration capabilities. It wraps raw table data
/// and provides type-safe access to individual rows through the [`crate::metadata::tables::types::RowReadable`] trait.
///
/// ## Type Parameters
///
/// * `'a` - Lifetime of the underlying byte data
/// * `T` - The row type that implements [`crate::metadata::tables::types::RowReadable`]
///
/// ## Examples
///
/// ### Basic Usage
/// ```no_run
/// # use dotscope::metadata::tables::MetadataTable;
/// # use dotscope::metadata::tables::RowReadable;
/// # use dotscope::metadata::tables::TableInfoRef;
/// # use dotscope::metadata::tables::{TableId, TableRow};
/// # struct MyRow { id: u32 }
/// # impl TableRow for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// # }
/// # impl RowReadable for MyRow {
/// #     const TABLE_ID: TableId = TableId::Module;
/// #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
/// #         *offset += 4; Ok(MyRow { id: rid })
/// #     }
/// # }
/// # use dotscope::metadata::tables::skip_unreadable;
/// # fn example(data: &[u8], table_info: TableInfoRef) -> dotscope::Result<()> {
/// let table: MetadataTable<MyRow> = MetadataTable::new(data, 100, table_info)?;
///
/// // Access specific rows
/// if let Some(first_row) = table.get(1)? {
///     println!("First row ID: {}", first_row.id);
/// }
///
/// // Sequential iteration
/// for (index, row) in table.iter().filter_map(skip_unreadable).enumerate() {
///     println!("Row {}: ID = {}", index + 1, row.id);
/// }
/// # Ok(())
/// # }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ### Parallel Processing
/// ```no_run
/// # use dotscope::metadata::tables::MetadataTable;
/// # use dotscope::metadata::tables::RowReadable;
/// # use dotscope::metadata::tables::TableInfoRef;
/// # use rayon::prelude::*;
/// # use dotscope::metadata::tables::{TableId, TableRow};
/// # struct MyRow { id: u32 }
/// # impl TableRow for MyRow {
/// #     fn row_size(_: &TableInfoRef) -> u32 { 4 }
/// # }
/// # impl RowReadable for MyRow {
/// #     const TABLE_ID: TableId = TableId::Module;
/// #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> dotscope::Result<Self> {
/// #         *offset += 4; Ok(MyRow { id: rid })
/// #     }
/// # }
/// # fn example(data: &[u8], table_info: TableInfoRef) -> dotscope::Result<()> {
/// let table: MetadataTable<MyRow> = MetadataTable::new(data, 100, table_info)?;
///
/// // Parallel processing with automatic error handling
/// table.par_iter().try_for_each(|row| {
///     // A row that failed to parse is reported, not skipped.
///     let row = row?;
///     println!("Processing row: {}", row.id);
///     Ok::<(), dotscope::Error>(())
/// })?;
/// # Ok(())
/// # }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct MetadataTable<'a, T> {
    /// Reference to the raw table data bytes
    pub data: &'a [u8],
    /// Total number of rows in this table
    pub row_count: u32,
    /// Size in bytes of each row
    pub row_size: u32,
    /// Table configuration and size information
    pub sizes: TableInfoRef,
    /// Phantom data to maintain type information
    _phantom: Arc<PhantomData<T>>,
}

impl<'a, T: RowReadable> MetadataTable<'a, T> {
    /// Creates a new metadata table from raw byte data.
    ///
    /// This constructor initializes a new table wrapper around the provided byte data,
    /// calculating the appropriate row size based on the table configuration and
    /// setting up the necessary metadata for efficient access operations.
    ///
    /// ## Arguments
    ///
    /// * `data` - The raw byte buffer containing the table data
    /// * `row_count` - The total number of rows present in the table
    /// * `sizes` - Table configuration containing heap sizes and other metadata
    ///   required for proper row size calculation
    ///
    /// ## Returns
    ///
    /// Returns a [`Result`] containing the new [`MetadataTable`] instance on success.
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - The provided data buffer is too small for the specified row count
    /// - The table configuration is invalid or inconsistent
    /// - Row size calculation fails due to invalid size parameters
    pub fn new(data: &'a [u8], row_count: u32, sizes: TableInfoRef) -> Result<Self> {
        let row_size = T::row_size(&sizes);

        // `data` is the remainder of the whole `#~` stream, not this table's own extent, so a
        // row count larger than the table really has would read rows belonging to the tables
        // that follow it. Widened to `u64` because `row_count * row_size` overflows `u32` at
        // counts the raw validator still permits.
        let declared = u64::from(row_count)
            .checked_mul(u64::from(row_size))
            .ok_or_else(|| malformed_error!("Table extent overflows"))?;
        let available = u64::try_from(data.len())
            .map_err(|_| malformed_error!("Table buffer length exceeds the address width"))?;
        if declared > available {
            return Err(malformed_error!(
                "Table declares {} rows of {} bytes ({}) but only {} bytes remain",
                row_count,
                row_size,
                declared,
                available
            ));
        }

        // Truncate to the declared extent so no read can cross into the next table, whatever
        // the iterators do.
        let data = data
            .get(..usize::try_from(declared).unwrap_or(data.len()))
            .unwrap_or(data);

        Ok(MetadataTable {
            data,
            row_count,
            row_size,
            sizes,
            _phantom: Arc::new(PhantomData),
        })
    }

    /// Returns the total size of this table in bytes.
    ///
    /// Calculates the total memory footprint of the table by multiplying
    /// the number of rows by the size of each row.
    ///
    /// ## Returns
    ///
    /// The total size in bytes as a `u64` to accommodate large tables.
    #[must_use]
    pub fn size(&self) -> u64 {
        u64::from(self.row_count).saturating_mul(u64::from(self.row_size))
    }

    /// Retrieves a specific row by its 1-based index.
    ///
    /// This method provides direct access to individual table rows using the
    /// CLI specification's 1-based indexing scheme. Row 0 is reserved and
    /// represents a null reference in the metadata format.
    ///
    /// ## Arguments
    ///
    /// * `index` - The 1-based row index to retrieve (must be between 1 and `row_count` inclusive)
    ///
    /// ## Returns
    ///
    /// `Ok(Some(row))` when the row exists and parses, `Ok(None)` when the index is outside
    /// the table, and `Err` when the row exists but does not parse. Those are three different
    /// facts and callers act on them differently - a row that will not parse is a defect in
    /// the input, not an absent row.
    ///
    /// # Errors
    ///
    /// Returns an error if the row's bytes cannot be decoded.
    pub fn get(&self, index: u32) -> Result<Option<T>> {
        if index == 0 || self.row_count < index {
            return Ok(None);
        }

        // The offset is derived from the index rather than carried across calls, so a row
        // that fails to parse cannot desynchronise any other row. That independence is what
        // lets the iterators report a failure and keep going, instead of having to stop
        // because they no longer know where the next row begins.
        T::row_read(
            self.data,
            &mut (index as usize)
                .saturating_sub(1)
                .saturating_mul(self.row_size as usize),
            index,
            &self.sizes,
        )
        .map(Some)
    }

    /// Creates a sequential iterator over all rows in the table.
    ///
    /// This method returns an iterator that will process each row in the table
    /// sequentially, parsing rows on-demand as the iterator advances. The iterator
    /// follows standard Rust iterator conventions and can be used with iterator
    /// combinators and for-loops.
    ///
    /// ## Returns
    ///
    /// A [`TableIterator`] that yields each row in sequence.
    #[must_use]
    pub fn iter(&'a self) -> TableIterator<'a, T> {
        TableIterator {
            table: self,
            current_row: 0,
        }
    }

    /// Creates a parallel iterator over all rows in the table.
    ///
    /// This method returns a parallel iterator that can process rows concurrently
    /// across multiple threads, providing significant performance improvements for
    /// large tables. The iterator integrates with the Rayon parallel processing
    /// framework and supports all standard parallel iterator operations.
    ///
    /// ## Returns
    ///
    /// A [`TableParIterator`] that can process rows in parallel.
    #[must_use]
    pub fn par_iter(&'a self) -> TableParIterator<'a, T> {
        TableParIterator {
            table: self,
            range: 0..self.row_count,
        }
    }
}

impl<'a, T: RowReadable> IntoIterator for &'a MetadataTable<'a, T> {
    type Item = Result<T>;
    type IntoIter = TableIterator<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
