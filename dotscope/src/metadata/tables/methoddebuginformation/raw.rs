//! Raw `MethodDebugInformation` table representation for Portable PDB format.
//!
//! This module provides the [`crate::metadata::tables::methoddebuginformation::raw::MethodDebugInformationRaw`] struct that represents
//! the binary format of `MethodDebugInformation` table entries as they appear in
//! the metadata tables stream. This is the low-level representation used during
//! the initial parsing phase, containing unresolved heap indices that enable efficient
//! batch processing of Portable PDB debugging metadata.
//!
//! # Architecture
//!
//! The raw implementation provides the foundation for Portable PDB debug information parsing:
//! - **Unresolved References**: Contains raw heap indices that require blob resolution
//! - **Memory Efficiency**: Minimal footprint during initial parsing phases
//! - **Binary Format**: Direct representation of ECMA-335 Portable PDB table structure
//! - **Batch Processing**: Optimized for parsing multiple debug entries efficiently
//!
//! # Binary Format
//!
//! Each `MethodDebugInformation` table row follows the Portable PDB specification:
//!
//! ```text
//! Offset | Size    | Field          | Description
//! -------|---------|----------------|------------------------------------------
//! 0x00   | 2-4     | Document       | Simple index into Document table
//! 0x02   | 2-4     | SequencePoints | Blob heap index containing sequence data
//! ```
//!
//! Index sizes are determined by metadata header flags and table/heap sizes.
//!
//! # Sequence Points Encoding
//!
//! The sequence points blob contains compressed data that maps IL instruction offsets
//! to source code locations using a variable-length encoding scheme:
//! - **Delta Compression**: Offsets and positions are delta-encoded for efficiency
//! - **Variable Length**: Values use LEB128 encoding to minimize storage
//! - **Source Mapping**: Links IL instructions to specific line/column positions
//! - **Debugging Support**: Enables step-through debugging and stack trace resolution
//!
//! # Processing Pipeline
//!
//! 1. **Parsing**: Raw entries are read from metadata tables stream
//! 2. **Validation**: Document indices and blob indices are validated
//! 3. **Resolution**: Blob heap indices are resolved to actual sequence data
//! 4. **Conversion**: Raw entries are converted to owned representations
//! 5. **Integration**: Debug information is integrated with method definitions
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe for concurrent read access:
//! - [`crate::metadata::tables::methoddebuginformation::raw::MethodDebugInformationRaw`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - Raw parsing operations can be performed concurrently
//! - Conversion methods are thread-safe with proper heap synchronization
//! - No shared mutable state during parsing operations
//!
//! # Integration
//!
//! This module integrates with:
//! - Method debug information owned types - Owned representation for runtime use
//! - [`crate::metadata::tables::document`] - Document table for source file references
//! - [`crate::metadata::streams::Blob`] - Blob heap for sequence points data resolution
//! - [`crate::metadata::method`] - Method definition association and debugging

use std::sync::Arc;

use crate::{
    metadata::{
        sequencepoints::parse_sequence_points,
        streams::Blob,
        tables::{
            MethodDebugInformation, MethodDebugInformationRc, TableId, TableInfoRef, TableRow,
        },
        token::Token,
    },
    Result,
};

/// Raw binary representation of a `MethodDebugInformation` table entry.
///
/// This structure matches the exact binary layout of `MethodDebugInformation` table
/// entries in the metadata tables stream. All heap references remain as unresolved
/// indices that must be resolved through the appropriate heap during the conversion
/// to the owned [`crate::metadata::tables::MethodDebugInformation`] variant.
///
/// # Binary Format
///
/// Each `MethodDebugInformation` table entry consists of:
/// - **Document**: Simple index into Document table (0 = no associated document)
/// - **SequencePoints**: Blob heap index containing compressed sequence point data
///
/// The exact byte size depends on whether large heap indices are used, determined
/// by the heap size flags in the metadata header and table row counts.
///
/// # Heap Index Resolution
///
/// - **`document`**: Simple table index into Document table (0 = no document)
/// - **`sequence_points`**: Must be resolved through blob heap to get encoded sequence data
///
/// # Usage Patterns
///
/// ```no_run
/// use dotscope::metadata::tables::MethodDebugInformationRaw;
/// use dotscope::metadata::streams::Blob;
///
/// # fn process_debug_entry(raw_entry: &MethodDebugInformationRaw, blobs: &Blob) -> dotscope::Result<()> {
/// // Check for associated document
/// if raw_entry.document != 0 {
///     println!("Method has source document: {}", raw_entry.document);
/// }
///
/// // Check for sequence points
/// if raw_entry.sequence_points != 0 {
///     let sequence_data = blobs.get(raw_entry.sequence_points as usize)?;
///     println!("Method has {} bytes of sequence data", sequence_data.len());
/// }
///
/// // Convert to owned representation
/// let owned = raw_entry.to_owned(blobs)?;
/// # Ok(())
/// # }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`MethodDebugInformationRaw`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data types.
/// Instances can be safely shared across threads and accessed concurrently without synchronization.
///
/// # Reference
/// - [Portable PDB Format - `MethodDebugInformation` Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)
/// - Table ID: 0x31
/// - Purpose: Associate methods with debugging information and source locations
#[derive(Debug, Clone)]
pub struct MethodDebugInformationRaw {
    /// Row identifier within the `MethodDebugInformation` metadata table
    pub rid: u32,

    /// Metadata token for this method debug information entry
    pub token: Token,

    /// Byte offset of this entry within the metadata tables stream
    pub offset: usize,

    /// Document table index (unresolved)
    ///
    /// Simple index into the Document table that identifies the source document
    /// containing this method. A value of 0 indicates no associated document.
    pub document: u32,

    /// Sequence points blob index (unresolved)
    ///
    /// Index into the blob heap containing encoded sequence point data.
    /// A value of 0 indicates no sequence points are available for this method.
    /// The blob contains compressed sequence point information mapping IL
    /// instructions to source code locations.
    pub sequence_points: u32,
}

impl MethodDebugInformationRaw {
    /// Convert raw method debug information to owned representation with resolved heap references
    ///
    /// Resolves all heap indices to their actual data values, creating a
    /// [`MethodDebugInformation`] instance with owned data that provides immediate
    /// access to debug information without requiring additional heap lookups.
    ///
    /// # Arguments
    /// * `blobs` - Blob heap for resolving sequence points data
    ///
    /// # Returns
    /// * `Ok(Arc<MethodDebugInformation>)` - Reference-counted owned method debug info
    /// * `Err(Error)` - If heap resolution fails
    ///
    /// # Heap Resolution
    /// - `document`: Preserved as table index for later resolution during loading
    /// - `sequence_points`: Resolved to `Option<Vec<u8>>` (None if index is 0)
    ///
    /// # Examples
    /// ```no_run
    /// # use dotscope::metadata::tables::MethodDebugInformationRaw;
    /// # use dotscope::metadata::streams::Blob;
    /// # fn example(raw: &MethodDebugInformationRaw, blobs: &Blob) -> dotscope::Result<()> {
    /// let method_debug_info = raw.to_owned(blobs)?;
    /// println!("Method debug info: {:?}", method_debug_info.document);
    /// # Ok(())
    /// # }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the blob heap index for sequence points is invalid or cannot be resolved.
    pub fn to_owned(&self, blobs: &Blob) -> Result<MethodDebugInformationRc> {
        let sequence_points = if self.sequence_points == 0 {
            None
        } else {
            Some(parse_sequence_points(
                blobs.get(self.sequence_points as usize)?,
                self.document,
            )?)
        };

        // ToDo: Resolve document index to actual Document entry if needed
        let method_debug_info = MethodDebugInformation {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            document: self.document,
            sequence_points,
        };

        Ok(Arc::new(method_debug_info))
    }
}

impl TableRow for MethodDebugInformationRaw {
    /// Calculate the row size for `MethodDebugInformation` table entries
    ///
    /// Returns the total byte size of a single `MethodDebugInformation` table row based on the
    /// table configuration. The size varies depending on the size of table indexes and heap
    /// references in the metadata.
    ///
    /// # Size Breakdown
    /// - `document`: 2 or 4 bytes (table index into `Document` table)
    /// - `sequence_points`: 2 or 4 bytes (blob heap index for sequence points data)
    ///
    /// Total: 4-8 bytes depending on table index and heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* document */        sizes.table_index_bytes(TableId::Document)
            /* sequence_points */ .saturating_add(sizes.blob_bytes())

        )
    }
}
