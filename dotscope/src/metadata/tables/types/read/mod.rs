//! Read-only infrastructure for parsing and accessing metadata tables.
//!
//! This module provides the core functionality for reading .NET CLI metadata tables
//! from binary data. It includes traits, iterators, and containers that enable
//! type-safe, efficient access to table rows with support for both sequential
//! and parallel processing patterns.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::types::RowReadable`] - Trait for parsing table rows from byte data
//! - [`crate::metadata::tables::types::MetadataTable`] - Generic container providing typed access to table data
//! - [`crate::metadata::tables::types::TableIterator`] - Sequential iterator for table rows
//! - [`crate::metadata::tables::types::TableParIterator`] - Parallel iterator for high-performance processing
//! - [`crate::metadata::tables::types::TableAccess`] - Internal trait for table data access patterns
//! - [`crate::metadata::tables::types::TableData`] - Container for raw table data and metadata
//!
//! # Thread Safety
//!
//! All types in this module support concurrent read access:
//! - [`crate::metadata::tables::types::MetadataTable`] is [`Send`] and [`Sync`] for sharing across threads
//! - [`crate::metadata::tables::types::RowReadable`] types must be [`Send`] to support parallel iteration
//! - Parallel iterators provide lock-free concurrent processing

mod access;
mod data;
mod iter;
mod table;
mod traits;

pub use access::TableAccess;
pub use data::TableData;
pub use iter::{skip_unreadable, TableIterator, TableParIterator};
pub use table::MetadataTable;
pub use traits::RowReadable;
