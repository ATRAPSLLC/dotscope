//! Owned `ExportedType` entry representation.
//!
//! This module provides the [`crate::metadata::tables::exportedtype::owned::ExportedType`] struct
//! for working with resolved `ExportedType` metadata with owned data and resolved cross-references.
//! This represents the processed form of `ExportedType` entries after raw table data has been
//! converted and all heap references have been resolved during the dual variant resolution phase.
//!
//! # `ExportedType` Entry Structure
//!
//! Each `ExportedType` entry defines a type that is exported from this assembly but
//! may be implemented elsewhere. The entry contains:
//! - **Type Identity**: Name, namespace, and flags defining the exported type
//! - **Implementation Reference**: Points to where the type is actually defined
//! - **Type Hints**: Optional `TypeDef` ID for resolution optimization
//! - **Custom Attributes**: Metadata annotations applied to the export
//!
//! # Export Scenarios
//!
//! `ExportedType` entries support several assembly composition patterns:
//! - **Type Forwarding**: Redirecting type references to different assemblies
//! - **Multi-Module**: Exposing types from different files within an assembly
//! - **Assembly Facades**: Creating simplified public interfaces over complex implementations
//!
//! # Reference
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ExportedType` table specification

use std::sync::OnceLock;

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, streams::SharedStr, tables::TypeAttributes,
        token::Token, typesystem::CilTypeReference,
    },
    Result,
};

/// Resolved `ExportedType` entry with owned data and resolved cross-references
///
/// Represents a fully processed `ExportedType` table entry where all heap references
/// have been resolved and cross-table relationships have been established. Each
/// entry defines a type that is exported from this assembly for access by other
/// assemblies, with the actual implementation potentially located elsewhere.
///
/// `ExportedType` entries enable cross-assembly type access and support complex
/// assembly composition scenarios including type forwarding and multi-module
/// assemblies.
pub struct ExportedType {
    /// Row identifier within the `ExportedType` metadata table
    ///
    /// The 1-based index of this `ExportedType` row. Used for metadata token generation
    /// and cross-referencing with other metadata structures.
    pub rid: u32,

    /// Metadata token for this `ExportedType` row
    ///
    /// Combines the table identifier (0x27 for `ExportedType`) with the row ID to create
    /// a unique token. Format: `0x27000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `ExportedType` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Type attributes defining visibility and characteristics
    ///
    /// Strongly-typed wrapper around the 4-byte bitmask using [`crate::metadata::tables::TypeAttributes`]
    /// constants that control type visibility, inheritance, and runtime behavior.
    /// See [ECMA-335 II.23.1.15] for attribute definitions.
    pub flags: TypeAttributes,

    /// Optional `TypeDef` identifier for resolution optimization
    ///
    /// 4-byte hint into the target `TypeDef` table for faster type resolution.
    /// This is an optimization hint only; primary resolution uses name and namespace.
    /// May be 0 if no hint is available or applicable.
    pub type_def_id: u32,

    /// Resolved type name from the String heap
    ///
    /// The simple name of the exported type without namespace qualification.
    /// Combined with the namespace to form the full type identity.
    pub name: SharedStr,

    /// Optional resolved namespace from the String heap
    ///
    /// The namespace containing the exported type, or `None` for types in the
    /// global namespace. Combined with the name to form the full type identity.
    pub namespace: Option<SharedStr>,

    /// Resolved reference to the type implementation location
    ///
    /// Points to where the type is actually defined, which can be:
    /// - **File**: Another file within this assembly (multi-module scenario)
    /// - **`AssemblyRef`**: Different assembly entirely (type forwarding scenario)
    /// - **`ExportedType`**: Nested export reference (rare but possible)
    pub implementation: OnceLock<CilTypeReference>,

    /// Thread-safe collection of custom attributes applied to this export
    ///
    /// Contains all custom attribute values that have been applied to this
    /// `ExportedType` entry, providing additional metadata and annotations.
    pub custom_attributes: CustomAttributeValueList,
}

impl ExportedType {
    /// Sets the implementation reference for this exported type.
    ///
    /// This method is used during the second pass of two-phase loading to resolve
    /// intra-table ExportedType references that were deferred during initial loading.
    ///
    /// ## Arguments
    /// * `implementation` - The resolved implementation reference
    ///
    /// ## Returns
    /// * `Ok(())` - Implementation reference set successfully
    /// * `Err(_)` - Implementation was already set or other error occurred
    ///
    /// # Errors
    ///
    /// Returns an error if the implementation reference was already set.
    pub fn set_implementation(&self, implementation: CilTypeReference) -> Result<()> {
        self.implementation
            .set(implementation)
            .map_err(|_| malformed_error!("Implementation reference was already set"))
    }

    /// Gets the implementation reference for this exported type.
    ///
    /// ## Returns
    /// Returns the implementation reference if it has been set, or `None` if it's still pending resolution.
    pub fn get_implementation(&self) -> Option<&CilTypeReference> {
        self.implementation.get()
    }
}
