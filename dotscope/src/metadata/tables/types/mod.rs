//! Core infrastructure for .NET metadata table processing.
//!
//! This module provides the foundational types and traits for working with .NET CLI
//! metadata tables. It enables type-safe, efficient reading, iteration, and parallel
//! processing of metadata table entries from CLI assemblies, supporting both sequential
//! and concurrent access patterns.
//!
//! # Architecture
//!
//! The .NET metadata format organizes type, method, field, and other information in
//! structured tables following the ECMA-335 specification. This module provides generic
//! abstractions that work across all metadata table types while maintaining type safety
//! and performance. The design separates concerns between data access, iteration, and
//! row parsing to enable flexible usage patterns.
//!
//! # Organization
//!
//! This module is organized by capability:
//! - [`crate::metadata::tables::types::common`] - Shared types and infrastructure used by both read and write operations
//! - [`crate::metadata::tables::types::read`] - Read-only infrastructure for parsing and accessing metadata tables
//! - [`crate::metadata::tables::types::write`] - Write-capable infrastructure for creating and modifying metadata tables
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::MetadataTable`] - Generic container providing typed access to table data
//! - [`crate::metadata::tables::types::RowReadable`] - Trait for parsing table rows from byte data
//! - [`crate::metadata::tables::types::RowWritable`] - Trait for serializing table rows to byte data
//! - [`crate::metadata::tables::types::TableIterator`] - Sequential iterator for table rows
//! - [`crate::metadata::tables::types::TableParIterator`] - Parallel iterator for high-performance processing
//! - [`crate::metadata::tables::types::CodedIndex`] - Compact cross-table references with type safety
//! - [`crate::metadata::tables::types::TableId`] - Enumeration of all metadata table types
//! - [`crate::metadata::tables::types::TableInfo`] - Table size and configuration metadata
//! - [`crate::metadata::tables::types::TableData`] - Container for raw table data and metadata
//!
//! # Usage Examples
//!
//! ```no_run
//! use dotscope::metadata::tables::{MetadataTable, RowReadable, TableId, TableInfoRef, TableRow};
//! use dotscope::Result;
//! use rayon::prelude::*;
//!
//! # struct ExampleRow { id: u32 }
//! # impl TableRow for ExampleRow {
//! #     fn row_size(_: &TableInfoRef) -> u32 {
//! #         4 // Example fixed size for demonstration
//! #     }
//! # }
//! # impl RowReadable for ExampleRow {
//! #     const TABLE_ID: TableId = TableId::Module;
//! #     fn row_read(_: &[u8], offset: &mut usize, rid: u32, _: &TableInfoRef) -> Result<Self> {
//! #         *offset += 4;
//! #         Ok(ExampleRow { id: rid })
//! #     }
//! # }
//! # fn example(data: &[u8], table_info: TableInfoRef) -> Result<()> {
//! // Create a metadata table with typed row access
//! let table: MetadataTable<ExampleRow> = MetadataTable::new(data, 100, table_info)?;
//!
//! // Sequential iteration over all rows
//! for row in &table {
//!     println!("Processing row ID: {}", row?.id);
//! }
//!
//! // Parallel processing with error propagation
//! table.par_iter().try_for_each(|row| {
//!     // Each row processed in parallel threads
//!     process_row_data(&row?)?;
//!     Ok::<(), dotscope::Error>(())
//! })?;
//! # Ok(())
//! # }
//! # fn process_row_data(_: &ExampleRow) -> Result<()> { Ok(()) }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This module defines error conditions for table processing:
//! - Row parsing errors when table data is malformed or incomplete
//! - Index validation errors for out-of-bounds heap references
//! - Buffer size errors when insufficient data is available
//!
//! # Thread Safety
//!
//! All types in this module are designed for concurrent access:
//! - [`crate::metadata::tables::types::MetadataTable`] is [`Send`] and [`Sync`] for sharing across threads
//! - Row types must implement [`Send`] (for [`crate::metadata::tables::types::RowReadable`]) or [`Sync`] (for [`crate::metadata::tables::types::RowWritable`])
//! - Parallel iterators provide lock-free concurrent processing
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Concrete table implementations using these types
//! - [`crate::metadata::streams`] - String and blob heap access for resolving indices
//!
//! # References
//!
//! - [ECMA-335 Standard](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Partition II, Section 22
//! - [.NET Runtime Documentation](https://github.com/dotnet/runtime/tree/main/docs/design/coreclr/metadata)

pub use common::*;
pub use read::*;
pub use write::*;

mod common;
mod read;
mod write;

/// Trait for types that represent a row in a metadata table and can report their row size.
///
/// This trait provides the canonical method for determining the size in bytes of a single row
/// for a given table type, taking into account variable-sized fields.
pub trait TableRow: Send {
    /// Calculates the size in bytes of a single row for this table type.
    ///
    /// # Arguments
    ///
    /// * `sizes` - Table size information containing heap sizes and table row counts
    ///   used to determine the appropriate index sizes
    ///
    /// # Returns
    ///
    /// The size in bytes required for one complete row of this table type.
    fn row_size(sizes: &TableInfoRef) -> u32;
}
