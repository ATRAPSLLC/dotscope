//! Trait definitions for metadata table deserialization and binary parsing.
//!
//! This module provides the core trait abstractions for parsing metadata table entries
//! from their binary representation in .NET PE files. It enables the reading and
//! deserialization of CLI metadata tables, supporting the complete range of ECMA-335
//! metadata structures.
//!
//! ## Core Traits
//!
//! - [`RowReadable`] - Primary trait for deserializing individual table rows
//!
//! ## Design Principles
//!
//! The read traits follow these design principles:
//! - **Type Safety**: All parsing operations are compile-time checked
//! - **Memory Safety**: Buffer bounds are validated during read operations
//! - **Performance**: Traits support parallel processing of table entries
//! - **Specification Compliance**: All parsing follows ECMA-335 binary format
//!
//! ## Thread Safety
//!
//! All traits in this module are designed for concurrent use, with implementations
//! required to be `Send` to support parallel table processing during metadata loading.
//!
//! ## Related Modules
//!
//! - [`RowWritable`](crate::metadata::tables::types::RowWritable) - Corresponding write trait
//! - [`crate::metadata::tables::types::read::table`] - Table-level read operations
//! - [`crate::metadata::tables::types::read::data`] - Low-level data deserialization

use crate::{
    metadata::tables::{TableId, TableInfoRef, TableRow},
    Result,
};

/// Trait defining the interface for reading and parsing metadata table rows.
///
/// This trait must be implemented by any type that represents a row in a metadata table.
/// It provides the necessary methods for parsing row data from byte buffers, enabling generic table operations.
///
/// ## Implementation Requirements
///
/// Types implementing this trait must:
/// - Be `Send` to support parallel processing
/// - Handle parsing errors gracefully
/// - Support 1-based row indexing (as per CLI specification)
/// - Specify their `TABLE_ID` for generic table access
pub trait RowReadable: Sized + Send + TableRow {
    /// The table ID for this row type.
    ///
    /// This constant enables generic code to identify which metadata table
    /// a row type belongs to, enabling type-safe generic table operations.
    const TABLE_ID: TableId;

    /// Reads and parses a single row from the provided byte buffer.
    ///
    /// This method extracts and parses one complete row from the metadata table data,
    /// advancing the offset pointer to the next row position. The row ID follows
    /// the CLI specification's 1-based indexing scheme.
    ///
    /// ## Arguments
    ///
    /// * `data` - The byte buffer containing the table data to read from
    /// * `offset` - Mutable reference to the current read position, automatically
    ///   advanced by the number of bytes consumed
    /// * `rid` - The 1-based row identifier for this entry (starts at 1, not 0)
    /// * `sizes` - Table size information for parsing variable-sized fields
    ///
    /// ## Returns
    ///
    /// Returns a [`Result`] containing the parsed row instance on success.
    ///
    /// ## Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error`] - When the buffer contains insufficient data or malformed row structure
    /// - [`crate::Error`] - When heap indices reference invalid locations
    /// - [`crate::Error`] - When row identifiers are out of valid range
    fn row_read(data: &[u8], offset: &mut usize, rid: u32, sizes: &TableInfoRef) -> Result<Self>;
}
