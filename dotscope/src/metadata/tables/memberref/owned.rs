//! Owned `MemberRef` table structure with resolved references and parsed signatures.
//!
//! This module provides the [`MemberRef`] struct, which represents external member references
//! with all coded indexes resolved and signatures parsed. Unlike [`MemberRefRaw`], this structure
//! contains resolved parent references, owned strings, parsed signature information, and
//! parameter metadata for complete member access.
//!
//! [`MemberRefRaw`]: crate::metadata::tables::MemberRefRaw

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    streams::SharedStr,
    tables::{MemberRefSignature, ParamList},
    token::Token,
    typesystem::CilTypeReference,
};

/// Owned `MemberRef` table entry with resolved references and parsed signatures.
///
/// This structure represents an external member reference with all coded indexes resolved
/// to their target structures and signatures parsed for type-safe member access. It provides
/// complete member metadata including declaring type, signature information, and parameter
/// details for method references.
///
/// # Member Types
/// `MemberRef` entries can reference different kinds of external members:
/// - **Method references**: External method calls with complete signature information
/// - **Field references**: External field access with type information
/// - **Constructor references**: Object creation with parameter specifications
/// - **Generic member references**: Generic methods and fields with type parameters
pub struct MemberRef {
    /// Row identifier within the `MemberRef` table.
    ///
    /// Unique identifier for this member reference entry, used for internal
    /// table management and cross-references.
    pub rid: u32,

    /// Metadata token identifying this `MemberRef` entry.
    ///
    /// The token enables efficient lookup and reference to this member
    /// from other metadata structures and runtime systems.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Resolved reference to the declaring type or module.
    ///
    /// Specifies the parent context where this member is declared:
    /// - `TypeDef`: Member declared in the current assembly
    /// - `TypeRef`: Member declared in an external assembly type
    /// - `ModuleRef`: Global member declared in an external module
    /// - `MethodDef`: Vararg method signature reference
    /// - `TypeSpec`: Member of a generic type instantiation
    pub declaredby: CilTypeReference,

    /// Member name identifier.
    ///
    /// Owned string containing the member name used for identification and lookup.
    /// For constructors, this is typically ".ctor" (instance) or ".cctor" (static).
    pub name: SharedStr,

    /// Parsed member signature information.
    ///
    /// Union type containing either method signature (with calling convention,
    /// parameters, and return type) or field signature (with type information).
    /// Parsed from the blob heap during reference resolution.
    pub signature: MemberRefSignature,

    /// Parameter metadata for method signatures.
    ///
    /// Thread-safe collection of parameter information including names, types,
    /// and attributes. Empty for field signatures, populated for method references
    /// with parameter metadata from associated Param table entries.
    pub params: ParamList,

    /// Custom attributes applied to this member reference.
    ///
    /// Collection of custom attribute values that provide additional metadata
    /// and annotation information for this member reference.
    pub custom_attributes: CustomAttributeValueList,
}

impl MemberRef {
    /// Determines if this member reference represents a constructor method.
    ///
    /// Constructors are identified by their special names and method signature type:
    /// - **Instance constructors**: Named ".ctor" for object initialization
    /// - **Static constructors**: Named ".cctor" for type initialization
    /// - **Method signature**: Must have a method signature (not field signature)
    ///
    /// # Returns
    /// * `true` - If this is a constructor reference (.ctor or .cctor with method signature)
    /// * `false` - If this is a regular method or field reference
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        (self.name.starts_with(".ctor") || self.name.starts_with(".cctor"))
            && matches!(self.signature, MemberRefSignature::Method(_))
    }
}
