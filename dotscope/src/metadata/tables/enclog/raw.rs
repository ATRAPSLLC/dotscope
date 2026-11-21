//! Raw `EncLog` table representation.
//!
//! This module provides low-level access to `EncLog` metadata table data through the
//! [`crate::metadata::tables::enclog::raw::EncLogRaw`] structure. The `EncLog` table
//! contains Edit-and-Continue log entries that track metadata modifications made during
//! debugging sessions.
//!
//! # Architecture
//!
//! Like `AssemblyOS`, `EncLog` contains only primitive integer values (metadata tokens and
//! operation codes), making the "raw" and "owned" representations functionally identical.
//! This simplifies the dual variant pattern used throughout the metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::enclog::raw::EncLogRaw`] - Raw table row structure
//! - [`crate::metadata::tables::enclog::EncLogRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::types::RowReadable`] - Table parsing interface implementation
//!
//! # `EncLog` Table Format
//!
//! The `EncLog` table (0x1E) contains Edit-and-Continue operation records:
//! - **Token** (4 bytes): Metadata token identifying the affected element
//! - **`FuncCode`** (4 bytes): Operation code (create=0, update=1, delete=2)
//!
//! # Edit-and-Continue Context
//!
//! This table is used by .NET's Edit-and-Continue debugging feature to track all metadata
//! changes made during debugging sessions. When developers modify code while debugging,
//! the compiler generates new metadata and records the changes in this table, allowing
//! the runtime to understand what has been modified.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{EncLogRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `EncLog` table row representing Edit-and-Continue operation log entries
///
/// Contains metadata change tracking information for debugging sessions that use
/// Edit-and-Continue functionality. Unlike most metadata tables, `EncLog` contains only
/// primitive integer values and requires no heap resolution, making this structure
/// immediately usable without further processing.
///
/// The `EncLog` table (0x1E) is optional and only present in assemblies that have been
/// modified during debugging sessions using Edit-and-Continue.
///
/// # Data Model
///
/// All fields contain direct integer values rather than heap indexes:
/// - No string heap references
/// - No blob heap references
/// - All data is self-contained within the table row
///
/// # Reference
/// - [ECMA-335 II.22.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `EncLog` table specification
pub struct EncLogRaw {
    /// Row identifier within the `EncLog` metadata table
    ///
    /// The 1-based index of this `EncLog` row. Multiple edit operations can be recorded,
    /// typically in chronological order of the debugging session.
    pub rid: u32,

    /// Metadata token for this `EncLog` row
    ///
    /// Combines the table identifier (0x1E for `EncLog`) with the row ID to create
    /// a unique token. Format: `0x1E000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `EncLog` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Metadata token identifying the affected element
    ///
    /// 4-byte metadata token that identifies which metadata element (type, method, field, etc.)
    /// was affected by this Edit-and-Continue operation. The token format follows the standard
    /// metadata token structure: `table_id` (upper byte) + `row_id` (lower 3 bytes).
    pub token_value: u32,

    /// Operation code indicating the type of edit performed
    ///
    /// 4-byte value specifying what type of Edit-and-Continue operation was performed:
    /// - 0: Create - New metadata item added during edit session
    /// - 1: Update - Existing metadata item modified during edit session
    /// - 2: Delete - Metadata item marked for deletion during edit session
    pub func_code: u32,
}

impl EncLogRaw {
    /// Convert raw `EncLog` data to owned representation
    ///
    /// Since the `EncLog` table contains only primitive values with no heap references,
    /// this method simply clones the data and wraps it in an [`Arc`] for consistency
    /// with the dual variant pattern used across all metadata tables.
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::EncLogRc`]`)` - Reference-counted `EncLog` data
    ///
    /// # Errors
    /// This method currently never returns an error but maintains the `Result` type for
    /// consistency with other table conversion methods.
    pub fn to_owned(&self) -> Result<EncLogRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply `EncLog` row data to update related metadata structures
    ///
    /// `EncLog` entries specify Edit-and-Continue operations and are self-contained.
    /// Unlike other metadata tables that may have cross-references, `EncLog` entries don't
    /// require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since `EncLog` data is purely tracking information.
    ///
    /// # Returns
    /// Always returns `Ok(())` since `EncLog` entries don't modify other tables
    ///
    /// # Errors
    /// This function never returns an error.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for EncLogRaw {
    /// Calculate the byte size of an `EncLog` table row
    ///
    /// Returns the fixed size since `EncLog` contains only primitive integer fields
    /// with no variable-size heap indexes. Total size is always 8 bytes (2 × 4-byte integers).
    ///
    /// # Row Layout
    /// - `token_value`: 4 bytes (metadata token)
    /// - `func_code`: 4 bytes (operation code)
    ///
    /// # Arguments
    /// * `_sizes` - Unused for `EncLog` since no heap indexes are present
    ///
    /// # Returns
    /// Fixed size of 8 bytes for all `EncLog` rows
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* token_value */ 4_u32 +
        /* func_code */   4_u32
    }
}
