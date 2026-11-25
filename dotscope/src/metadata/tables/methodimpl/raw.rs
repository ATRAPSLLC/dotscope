//! Raw `MethodImpl` table structure with unresolved coded indexes.
//!
//! This module provides the [`MethodImplRaw`] struct, which represents method implementation
//! mappings as stored in the metadata stream. The structure contains unresolved coded indexes
//! that require processing to establish complete implementation mapping information.
//!
//! # Purpose
//! [`MethodImplRaw`] serves as the direct representation of `MethodImpl` table entries from the
//! binary metadata stream, before reference resolution and type system integration. This raw
//! format is processed during metadata loading to create [`MethodImpl`] instances with resolved
//! references and complete implementation mapping information.
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access during metadata processing:
//!
//! - **[`MethodImplRaw`]**: All fields are immutable after construction, enabling safe concurrent read access
//! - **Clone Operations**: [`Clone`] implementation is thread-safe and supports parallel processing
//! - **Index Resolution**: Coded index processing can be performed concurrently across multiple threads
//! - **Type System Updates**: The [`apply`](MethodImplRaw::apply) method performs atomic updates to concurrent collections
//! - **Memory Management**: Reference counting in [`to_owned`](MethodImplRaw::to_owned) ensures safe sharing
//!
//! Raw implementation mappings can be safely processed and converted from multiple threads simultaneously,
//! enabling efficient parallel metadata loading and type system construction.
//!
//! # Integration
//!
//! This module integrates with several core components of the metadata system:
//!
//! - **[`crate::metadata::tables::methodimpl::owned`]**: Target for owned structure conversion via [`to_owned`](MethodImplRaw::to_owned)
//! - **[`crate::metadata::loader::tables::MethodImplLoader`]**: Coordinates the parsing and processing of raw table data
//! - **[`crate::metadata::typesystem`]**: Provides type registry for class resolution and type reference management
//! - **[`crate::metadata::tables::methoddef`]**: Resolves local method definitions for implementation mappings
//! - **[`crate::metadata::tables::memberref`]**: Handles external method references for cross-assembly scenarios
//! - **Internal loader context**: Provides coded index resolution during conversion
//!
//! The raw implementation mapping system serves as the foundation layer for method implementation processing,
//! enabling the transformation from binary metadata to semantic type system relationships.
//!
//! [`MethodImpl`]: crate::metadata::tables::MethodImpl

use std::sync::Arc;

use crate::{
    metadata::{
        method::MethodMap,
        tables::{
            CodedIndex, CodedIndexType, MemberRefMap, MethodImpl, MethodImplRc, TableId,
            TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    Result,
};

/// Raw `MethodImpl` table entry with unresolved indexes and coded references.
///
/// This structure represents a method implementation mapping as stored directly in the metadata
/// stream. All references are unresolved indexes or coded indexes that require processing during
/// metadata loading to establish complete implementation mapping information.
///
/// # Table Structure (ECMA-335 §22.27)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Class | `TypeDef` index | Type containing the implementation mapping |
/// | `MethodBody` | `MethodDefOrRef` coded index | Concrete method implementation |
/// | `MethodDeclaration` | `MethodDefOrRef` coded index | Method declaration being implemented |
///
/// # Coded Index Resolution
/// Both `method_body` and `method_declaration` use `MethodDefOrRef` coded index encoding:
/// - **Tag 0**: `MethodDef` table (methods defined in current assembly)
/// - **Tag 1**: `MemberRef` table (methods referenced from external assemblies)
///
/// # Implementation Mapping Logic
/// The mapping establishes the relationship:
/// - **Class**: Contains the concrete implementation method
/// - **`MethodBody`**: The actual implementation that provides the behavior
/// - **`MethodDeclaration`**: The interface or virtual method being implemented
#[derive(Clone, Debug)]
pub struct MethodImplRaw {
    /// Row identifier within the `MethodImpl` table.
    ///
    /// Unique identifier for this method implementation mapping entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `MethodImpl` entry (`TableId` 0x19).
    ///
    /// Computed as `0x19000000 | rid` to create the full token value
    /// for referencing this implementation mapping from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// `TypeDef` table index for the class containing the implementation mapping.
    ///
    /// References the type that provides the concrete implementation for the method
    /// declaration. The class contains the method body that implements the interface
    /// contract or overrides the virtual method.
    pub class: u32,

    /// `MethodDefOrRef` coded index for the concrete method implementation.
    ///
    /// Points to `MethodDef` or `MemberRef` tables to specify the actual method that
    /// provides the implementation behavior. This method belongs to the class and
    /// contains the IL code or native implementation.
    pub method_body: CodedIndex,

    /// `MethodDefOrRef` coded index for the method declaration being implemented.
    ///
    /// Points to `MethodDef` or `MemberRef` tables to specify the interface method,
    /// abstract method, or virtual method declaration that is being implemented.
    /// This establishes the contract that the implementation must fulfill.
    pub method_declaration: CodedIndex,
}

impl MethodImplRaw {
    /// Applies a `MethodImplRaw` entry to update type system implementation relationships.
    ///
    /// This method establishes bidirectional relationships between method declarations
    /// and their implementations by updating type system collections. It resolves
    /// coded indexes to concrete method references and updates both the implementing
    /// class and the declared method with cross-reference information.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all parsed `CilType` entries for class resolution
    /// * `memberrefs` - Collection of all `MemberRef` entries for external method resolution
    /// * `methods` - Collection of all `MethodDef` entries for local method resolution
    ///
    /// # Returns
    /// * `Ok(())` - If the implementation mapping was applied successfully
    /// * `Err(_)` - If class resolution, method resolution, or system updates fail
    ///
    /// # Errors
    ///
    /// Returns an error if class resolution, method resolution, or system updates fail.
    pub fn apply(
        &self,
        types: &TypeRegistry,
        memberrefs: &MemberRefMap,
        methods: &MethodMap,
    ) -> Result<()> {
        // ToDo: Implement resolving of MemberRefs, accross multiple binaries (if present and loaded)
        let interface_implementation = match self.method_body.tag {
            TableId::MethodDef => match methods.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MethodDef(parent.value().clone().into()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve methoddef method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            TableId::MemberRef => match memberrefs.get(&self.method_body.token) {
                Some(parent) => CilTypeReference::MemberRef(parent.value().clone()),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve memberref method_body token - {}",
                        self.method_body.token.value()
                    ))
                }
            },
            _ => {
                return Err(malformed_error!(
                    "Invalid method_body token - {}",
                    self.method_body.token.value()
                ))
            }
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(cil_type) => {
                cil_type
                    .overwrites
                    .push_row(self.token, interface_implementation.clone());

                // Resolve the declaration reference for .override emission and interface_impls tracking
                let decl_ref = match self.method_declaration.tag {
                    TableId::MethodDef => match methods.get(&self.method_declaration.token) {
                        Some(parent) => {
                            if let CilTypeReference::MethodDef(method_ref) =
                                &interface_implementation
                            {
                                parent
                                    .value()
                                    .interface_impls
                                    .push_row(self.token, method_ref.clone());
                            }
                            Some(CilTypeReference::MethodDef(parent.value().clone().into()))
                        }
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve methoddef method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    TableId::MemberRef => match memberrefs.get(&self.method_declaration.token) {
                        Some(parent) => Some(CilTypeReference::MemberRef(parent.value().clone())),
                        None => {
                            return Err(malformed_error!(
                                "Failed to resolve memberref method_declaration token - {}",
                                self.method_declaration.token.value()
                            ))
                        }
                    },
                    _ => {
                        return Err(malformed_error!(
                            "Invalid method_declaration token - {}",
                            self.method_declaration.token.value()
                        ))
                    }
                };

                // Store the declaration on the body method for .override emission
                if let Some(decl) = decl_ref {
                    if let CilTypeReference::MethodDef(body_ref) = &interface_implementation {
                        if let Some(body_method) = body_ref.upgrade() {
                            body_method.overrides.push_row(self.token, decl);
                        }
                    }
                }

                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class type token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Converts a `MethodImplRaw` entry into a `MethodImpl` with resolved references and implementation mappings.
    ///
    /// This method performs complete implementation mapping resolution, including class type resolution,
    /// method reference resolution through coded indexes, and creation of the owned structure with
    /// all references established. The resulting structure provides direct access to implementation
    /// mapping information for method resolution and virtual dispatch operations.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all parsed `CilType` entries for class resolution
    ///
    /// # Errors
    ///
    /// Returns an error if type or method reference resolution fails.
    pub fn to_owned<F>(&self, get_ref: F, types: &TypeRegistry) -> Result<MethodImplRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        Ok(Arc::new(MethodImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(cil_type) => cil_type.clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class type token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            method_body: {
                let result = get_ref(&self.method_body);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_body token - {}",
                        self.method_body.token.value()
                    ));
                }
                result
            },
            method_declaration: {
                let result = get_ref(&self.method_declaration);
                if matches!(result, CilTypeReference::None) {
                    return Err(malformed_error!(
                        "Failed to resolve method_declaration token - {}",
                        self.method_declaration.token.value()
                    ));
                }
                result
            },
        }))
    }
}

impl TableRow for MethodImplRaw {
    /// Calculate the byte size of a MethodImpl table row
    ///
    /// Computes the total size based on variable-size table indexes and coded indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.27)
    /// - `class`: 2 or 4 bytes (TypeDef table index)
    /// - `method_body`: 2 or 4 bytes (`MethodDefOrRef` coded index)
    /// - `method_declaration`: 2 or 4 bytes (`MethodDefOrRef` coded index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one MethodImpl table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */               sizes.table_index_bytes(TableId::TypeDef)
            /* method_body */         .saturating_add(sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef))
            /* method_declaration */  .saturating_add(sizes.coded_index_bytes(CodedIndexType::MethodDefOrRef))

        )
    }
}
