//! Raw `EncMap` table implementation for .NET metadata.
//!
//! This module provides the [`EncMapRaw`] structure for representing rows in the `EncMap` table,
//! which manages token mapping during Edit-and-Continue debugging operations. Each row contains
//! a metadata token that represents the original token value before editing occurred.
//!
//! ## Table Structure
//! The `EncMap` table (`TableId` 0x1F) contains the following column:
//! - **Token** (4 bytes): Original metadata token value
//!
//! ## Token Mapping Process
//!
//! During Edit-and-Continue operations:
//! 1. Original tokens are preserved in the `EncMap` table
//! 2. New metadata is generated with updated token values
//! 3. The position in the `EncMap` table provides the mapping relationship
//! 4. Debuggers correlate original and new tokens using table position
//!
//! ## Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::EncMapRaw;
//! # use dotscope::metadata::token::Token;
//! # fn example(raw: EncMapRaw) -> dotscope::Result<()> {
//! // Access original token information
//! let original_token = raw.token;
//! println!("Original token: {:#010x}", original_token.value());
//!
//! // Extract table and row information
//! let table_id = original_token.table();
//! let row_id = original_token.row();
//! println!("Token maps table {} row {}", table_id, row_id);
//! # Ok(())
//! # }
//! ```
//!
//! ## ECMA-335 Reference
//!
//! See ECMA-335, Partition II, Section 22.13 for the complete `EncMap` table specification.

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{EncMapRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a row in the `EncMap` metadata table.
///
/// The `EncMap` table manages token mapping during Edit-and-Continue debugging operations.
/// Each row contains an original metadata token that was present before code editing occurred.
/// The table position provides an implicit mapping to the corresponding updated token.
///
/// ## Fields Overview
/// - **rid**: Row identifier within the `EncMap` table
/// - **token**: Metadata token for this mapping entry
/// - **offset**: Byte offset within the `EncMap` table data
/// - **`original_token`**: The original metadata token before editing
///
/// ## Token Correlation
/// The `EncMap` table provides implicit mapping through table position:
/// - Row N in `EncMap` contains the original token
/// - The updated token is determined by the debugger's token allocation
/// - Position-based correlation enables efficient token mapping
///
/// ## ECMA-335 Compliance
/// This structure directly corresponds to the `EncMap` table format specified in
/// ECMA-335, Partition II, Section 22.13.
///
/// **Table ID**: `0x1F`
pub struct EncMapRaw {
    /// Row identifier within the `EncMap` table.
    ///
    /// This 1-based index uniquely identifies this token mapping within the table.
    pub rid: u32,

    /// Metadata token for this `EncMap` entry.
    ///
    /// Constructed as `0x1F000000 | rid`, providing a unique identifier
    /// for this mapping entry within the metadata system.
    pub token: Token,

    /// Byte offset of this row within the `EncMap` table data.
    ///
    /// Used for debugging and low-level table operations.
    pub offset: usize,

    /// Original metadata token before Edit-and-Continue operation.
    ///
    /// This token represents the metadata element before any editing occurred.
    /// The debugger uses this value to correlate with updated tokens after editing.
    pub original_token: Token,
}

impl EncMapRaw {
    /// Converts this raw `EncMap` entry to its owned representation.
    ///
    /// `EncMap` entries contain self-contained token mapping information and don't require
    /// additional context for conversion. The conversion preserves all token mapping data
    /// with the dual variant pattern used across all metadata tables.
    ///
    /// ## Arguments
    /// This method doesn't require additional context as `EncMap` entries are self-contained.
    ///
    /// ## Returns
    /// Returns `Ok(`[`crate::metadata::tables::EncMapRc`]`)` - Reference-counted `EncMap` data
    ///
    /// # Errors
    /// This method currently cannot fail as `EncMap` entries are self-contained.
    ///
    /// ## Examples
    /// ```no_run
    /// # use dotscope::metadata::tables::EncMapRaw;
    /// # fn example(raw: EncMapRaw) -> dotscope::Result<()> {
    /// let owned = raw.to_owned()?;
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_owned(&self) -> Result<EncMapRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Applies this `EncMap` entry to update related metadata structures.
    ///
    /// `EncMap` entries provide token mapping information but don't directly modify
    /// other metadata structures. Token mapping is typically handled by debugger
    /// infrastructure during Edit-and-Continue operations.
    ///
    /// ## Returns
    /// Always returns `Ok(())` as `EncMap` entries don't modify other metadata directly.
    ///
    /// # Errors
    /// This method currently cannot fail as `EncMap` entries don't modify other metadata directly.
    ///
    /// ## ECMA-335 Reference
    /// See ECMA-335, Partition II, Section 22.13 for `EncMap` table semantics.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for EncMapRaw {
    /// Calculate the size in bytes of an `EncMap` table row.
    ///
    /// The `EncMap` table has a fixed structure with one 4-byte token field.
    /// Size calculation is independent of heap sizes since no heap references are used.
    ///
    /// ## Layout
    /// - **Token** (4 bytes): Original metadata token
    ///
    /// ## Arguments
    /// * `sizes` - Table size information (unused for `EncMap`)
    ///
    /// ## Returns
    /// Always returns 4 bytes for the fixed token field.
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        4 // token
    }
}
