//! Owned `MethodDebugInformation` table representation for Portable PDB format.
//!
//! This module provides the [`MethodDebugInformation`] struct which contains
//! fully resolved method debugging metadata with owned data and resolved heap references.
//! This is the primary data structure for representing Portable PDB method debugging
//! information in a usable form, with parsed sequence points after the dual variant
//! resolution phase.
//!
//! # Architecture
//!
//! The owned representation provides several key advantages over the raw format:
//! - **Memory Independence**: All data is owned and can be used without lifetime constraints
//! - **Resolved References**: Heap indices are resolved to concrete data values
//! - **Structured Access**: Direct field access without additional parsing overhead
//! - **Integration Ready**: Compatible with debugger interfaces and analysis tools
//!
//! # Portable PDB Integration
//!
//! Method debug information is a core component of the Portable PDB format:
//! - **Source Mapping**: Links IL instructions to source code locations
//! - **Document References**: Associates methods with source files
//! - **Debugging Support**: Enables step-through debugging and stack trace resolution
//! - **Tool Compatibility**: Standard format supported by .NET debugging tools
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe for concurrent read access:
//! - [`MethodDebugInformation`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - All fields contain owned data with no shared mutable state
//! - Instances can be safely shared across threads and accessed concurrently
//! - No synchronization required for read operations
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::methoddebuginformation::raw`] - Raw table representation for parsing
//! - [`crate::metadata::tables::document`] - Document table for source file references
//! - [`crate::metadata::streams`] - Metadata streams for heap data resolution
//! - [`crate::metadata::token`] - Token system for metadata references

use crate::metadata::{sequencepoints::SequencePoints, token::Token};

/// Represents a Portable PDB method debug information entry with fully resolved metadata.
///
/// This structure contains the complete debugging information for a method from the
/// `MethodDebugInformation` metadata table (0x31), with all heap indices resolved to
/// concrete data values. Unlike [`crate::metadata::tables::methoddebuginformation::raw::MethodDebugInformationRaw`],
/// this provides immediate access to structured debug data without requiring additional parsing.
///
/// # Debug Information Structure
///
/// A method debug information entry consists of:
/// - **Document**: Simple index referencing the source document in the Document table
/// - **Sequence Points**: Optional binary data containing IL-to-source mappings
/// - **Metadata Context**: Token and offset information for cross-reference resolution
///
/// # Sequence Points Format
///
/// The sequence points blob contains compressed data that maps IL instruction offsets
/// to source code locations (line/column numbers). This enables debuggers to provide
/// accurate step-through debugging by correlating executable code with source text.
/// The format follows the Portable PDB specification for efficient storage and parsing.
///
/// # Usage Patterns
///
/// ```no_run
/// use dotscope::metadata::tables::MethodDebugInformation;
///
/// # fn process_debug_info(debug_info: &MethodDebugInformation) {
/// // Access document reference
/// if debug_info.document != 0 {
///     println!("Method has source document: {}", debug_info.document);
/// }
///
/// // Process sequence points if available
/// if let Some(sequence_data) = &debug_info.sequence_points {
///     println!("Method has {} sequence points", sequence_data.points.len());
/// }
///
/// // Use token for cross-references
/// println!("Method debug token: {}", debug_info.token);
/// # }
/// ```
///
/// # Thread Safety
///
/// [`MethodDebugInformation`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently without synchronization.
///
/// # Reference
/// - [Portable PDB Format - `MethodDebugInformation` Table](https://github.com/dotnet/core/blob/main/Documentation/diagnostics/portable_pdb.md#methoddebuginformation-table-0x31)
pub struct MethodDebugInformation {
    /// Row identifier within the `MethodDebugInformation` metadata table
    ///
    /// The 1-based index of this method debug information row. Used to uniquely
    /// identify this specific debugging entry within the table.
    pub rid: u32,

    /// Metadata token for this method debug information entry
    ///
    /// Combines the table identifier (0x31 for `MethodDebugInformation`) with the row ID
    /// to create a unique token that can be used to reference this debug information
    /// from other metadata.
    pub token: Token,

    /// Byte offset of this entry within the metadata tables stream
    ///
    /// Physical location of the raw method debug information data within the metadata
    /// binary format. Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Document table index
    ///
    /// Simple index that references the Document table entry containing the source
    /// document for this method. A value of 0 indicates no associated document.
    /// This index references a specific row in the Document table.
    pub document: u32,

    /// Sequence points data
    ///
    /// Optional binary data containing encoded sequence point information that maps
    /// IL instruction offsets to source code locations. None indicates no sequence
    /// points are available for this method. The data format is specific to the
    /// Portable PDB specification and requires specialized parsing.
    pub sequence_points: Option<SequencePoints>,
}
