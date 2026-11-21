//! # `ModuleRef` Owned Implementation
//!
//! This module provides the owned variant of `ModuleRef` table entries with resolved
//! references and owned data structures for efficient runtime access.

use crate::metadata::{
    customattributes::CustomAttributeValueList, streams::SharedStr, token::Token,
};

/// Owned representation of a `ModuleRef` table entry with resolved references.
///
/// This structure represents the processed entry from the `ModuleRef` metadata table,
/// which contains references to external modules required by the current assembly.
/// Unlike [`ModuleRefRaw`](crate::metadata::tables::ModuleRefRaw), this version contains resolved references
/// to actual module name strings for efficient runtime access.
///
/// ## Purpose
///
/// The `ModuleRef` table entry enables cross-module references in .NET assemblies:
/// - External module identification by name
/// - Support for multi-module assembly structures
/// - Foundation for resolving imported types and methods
/// - Dependency tracking between modules
///
/// ## Cross-Module References
///
/// `ModuleRef` entries serve as the foundation for several cross-module scenarios:
/// - Types defined in external modules referenced by `TypeRef`
/// - Methods defined in external modules referenced by `MemberRef`
/// - Multi-module assemblies with components in separate files
/// - Import resolution for external module dependencies
#[derive(Debug)]
pub struct ModuleRef {
    /// Row identifier within the `ModuleRef` table.
    ///
    /// Unique identifier for this `ModuleRef` entry within the table.
    /// Combined with the table ID, it forms the complete metadata token.
    pub rid: u32,

    /// Metadata token for this `ModuleRef` entry.
    ///
    /// Token in the format 0x1A??????, where the high byte 0x1A identifies
    /// the `ModuleRef` table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Name of the referenced external module.
    ///
    /// Human-readable string identifying the external module, resolved from the string heap.
    /// Typically contains the module file name or logical name used for cross-module references.
    pub name: SharedStr,

    /// Custom attributes attached to this module reference.
    ///
    /// Thread-safe collection of custom attributes that provide additional
    /// metadata for this module reference. Populated during custom attribute processing.
    pub custom_attributes: CustomAttributeValueList,
}
