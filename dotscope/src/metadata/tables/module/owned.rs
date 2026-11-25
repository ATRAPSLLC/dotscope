//! # Module Owned Implementation
//!
//! This module provides the owned variant of Module table entries with resolved
//! references and owned data structures for efficient runtime access.

use crate::metadata::{
    customattributes::CustomAttributeValueList, imports::ImportRc, streams::SharedStr, token::Token,
};

/// Owned representation of a Module table entry with resolved references.
///
/// This structure represents the processed entry from the Module metadata table,
/// which provides information about the current module including its name, GUID (Mvid),
/// and generation. Unlike [`ModuleRaw`](crate::metadata::tables::ModuleRaw), this version contains resolved references
/// to actual string and GUID data for efficient runtime access.
///
/// ## Purpose
///
/// The Module table entry provides fundamental identity information for the assembly:
/// - Module name for human-readable identification
/// - Module Version Identifier (Mvid) GUID for unique versioning
/// - Generation number for future versioning schemes
/// - ENC (Edit and Continue) GUIDs for development scenarios
/// - Import tracking for cross-module references
///
/// ## Uniqueness
///
/// The Module table always contains exactly one row per PE file, making this entry
/// the singular identity anchor for the entire assembly. All other metadata elements
/// reference this module either directly or indirectly.
pub struct Module {
    /// Row identifier within the Module table.
    ///
    /// This is always 1 since the Module table contains exactly one row per PE file.
    /// Combined with the table ID, it forms the metadata token 0x00000001.
    pub rid: u32,

    /// Metadata token for this Module entry.
    ///
    /// Always 0x00000001 since this is the unique module entry.
    /// This token uniquely identifies the module across the entire metadata.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Generation number for this module.
    ///
    /// A 2-byte value that is reserved and shall always be zero according to
    /// ECMA-335. Reserved for future versioning schemes.
    pub generation: u32,

    /// Name of this module.
    ///
    /// Human-readable string identifying the module, resolved from the string heap.
    /// Typically matches the assembly file name without extension.
    pub name: SharedStr,

    /// Module Version Identifier (Mvid) GUID.
    ///
    /// A GUID used to distinguish between different versions of the same module.
    /// This provides unique identification even when module names are identical.
    /// Essential for proper version management and module resolution.
    pub mvid: uguid::Guid,

    /// Edit and Continue identifier GUID.
    ///
    /// Optional GUID for Edit and Continue scenarios during development.
    /// Reserved field that is typically None in production assemblies.
    /// Resolved from the GUID heap when present.
    pub encid: Option<uguid::Guid>,

    /// Edit and Continue base identifier GUID.
    ///
    /// Optional GUID for Edit and Continue base version tracking.
    /// Reserved field that is typically None in production assemblies.
    /// Resolved from the GUID heap when present.
    pub encbaseid: Option<uguid::Guid>,

    /// All types and methods imported from this module.
    ///
    /// Collection of imported elements that reference types or methods
    /// defined in this module from external assemblies. Built during
    /// the metadata loading process as imports are resolved.
    pub imports: Vec<ImportRc>,

    /// Custom attributes attached to this module.
    ///
    /// Thread-safe collection of custom attributes that provide additional
    /// metadata for this module. Populated during custom attribute processing.
    pub custom_attributes: CustomAttributeValueList,
}
