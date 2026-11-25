//! # `NestedClass` Owned Implementation
//!
//! This module provides the owned variant of `NestedClass` table entries with resolved
//! references and owned data structures for efficient runtime access.

use crate::{
    metadata::{token::Token, typesystem::CilTypeRc},
    Result,
};

/// Owned representation of a `NestedClass` table entry with resolved references.
///
/// This structure represents the processed entry from the `NestedClass` metadata table,
/// which defines the hierarchical relationship between nested types and their enclosing types.
/// Unlike [`NestedClassRaw`](crate::metadata::tables::NestedClassRaw), this version contains resolved references
/// to actual type objects for efficient runtime access.
///
/// ## Purpose
///
/// The `NestedClass` table entry establishes type containment relationships:
/// - Defines which types are nested within other types
/// - Establishes visibility and accessibility scoping rules
/// - Enables proper type resolution within nested contexts
/// - Supports complex type hierarchies and namespace organization
///
/// ## Type Relationships
///
/// `NestedClass` entries create several important relationships:
/// - **Containment**: The nested type is contained within the enclosing type
/// - **Visibility**: Nested types inherit access rules from their enclosing context
/// - **Resolution**: Type names are resolved relative to the enclosing type
/// - **Compilation**: Nested types share compilation context with their container
///
/// ## Validation
///
/// The `NestedClass` entry includes validation to ensure:
/// - No circular nesting relationships exist
/// - Nested and enclosing types are different
/// - Type references are valid and resolvable
/// - Nesting rules comply with .NET type system constraints
pub struct NestedClass {
    /// Row identifier within the `NestedClass` table.
    ///
    /// Unique identifier for this `NestedClass` entry within the table.
    /// Combined with the table ID, it forms the complete metadata token.
    pub rid: u32,

    /// Metadata token for this `NestedClass` entry.
    ///
    /// Token in the format 0x29??????, where the high byte 0x29 identifies
    /// the `NestedClass` table and the low 3 bytes contain the row ID.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Used for debugging and low-level metadata inspection.
    /// Points to the start of this entry's data in the file.
    pub offset: usize,

    /// Resolved reference to the nested type.
    ///
    /// The type that is nested within the enclosing type. This reference
    /// is resolved from `TypeDefOrRef` coded index to the actual type object.
    /// Contains the complete type information for the nested type.
    pub nested_class: CilTypeRc,

    /// Resolved reference to the enclosing type.
    ///
    /// The type that contains the nested type. This reference points to
    /// a `TypeDef` entry representing the containing type. The enclosing type
    /// provides the context and scope for the nested type.
    pub enclosing_class: CilTypeRc,
}

impl NestedClass {
    /// Applies the nested class relationship to update the enclosing type.
    ///
    /// This method establishes the containment relationship by adding the nested type
    /// to the enclosing type's nested types collection. The operation includes validation
    /// to ensure the nesting relationship is valid and does not create circular dependencies.
    ///
    /// ## Validation Rules
    ///
    /// - Nested and enclosing types must be different (no self-nesting)
    /// - No circular nesting relationships are allowed
    /// - Both types must be valid and resolvable
    /// - Nesting must comply with .NET type system constraints
    ///
    /// ## Effects
    ///
    /// After applying this relationship:
    /// - The enclosing type contains a reference to the nested type
    /// - Type resolution can find the nested type within its container
    /// - Visibility and accessibility rules are established
    /// - The type hierarchy reflects the containment structure
    ///
    /// ## Returns
    ///
    /// Returns `Ok(())` if the relationship is successfully applied.
    ///
    /// ## Errors
    ///
    /// - The enclosing class and nested class are the same type (circular nesting)
    /// - Nested class validation fails due to invalid relationships
    /// - Type references are invalid or cannot be resolved
    /// - The relationship violates .NET type system constraints
    pub fn apply(&self) -> Result<()> {
        self.enclosing_class
            .nested_types
            .push_row(self.token, self.nested_class.clone().into());

        self.nested_class
            .set_enclosing_type(&self.enclosing_class.clone().into())?;

        Ok(())
    }
}
