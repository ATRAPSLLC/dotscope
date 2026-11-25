//! Raw `InterfaceImpl` table structure with unresolved coded indexes.
//!
//! This module provides the [`crate::metadata::tables::InterfaceImplRaw`] struct, which represents interface implementation
//! entries as stored in the metadata stream. The structure contains unresolved coded indexes
//! and table references that require processing to become usable type relationships.
//!
//! # Purpose
//! [`crate::metadata::tables::InterfaceImplRaw`] serves as the direct representation of `InterfaceImpl` table entries from
//! the binary metadata stream, before type resolution and relationship establishment. This
//! raw format is processed during metadata loading to create [`crate::metadata::tables::InterfaceImpl`] instances
//! with resolved type references and applied relationships.
//!
//! [`InterfaceImpl`]: crate::metadata::tables::InterfaceImpl

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, InterfaceEntry, InterfaceImpl, InterfaceImplRc, TableId,
            TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::{CilTypeRef, TypeRegistry},
    },
    Result,
};

/// Raw `InterfaceImpl` table entry with unresolved indexes and type references.
///
/// This structure represents an interface implementation entry as stored directly
/// in the metadata stream. All references are unresolved table indexes that require
/// processing during metadata loading to establish type system relationships.
///
/// # Table Structure (ECMA-335 §22.23)
/// | Column | Size | Description |
/// |--------|------|-------------|
/// | Class | `TypeDef` index | Type that implements the interface |
/// | Interface | `TypeDefOrRef` coded index | Interface being implemented |
///
/// # Coded Index Resolution
/// The `interface` field uses the `TypeDefOrRef` coded index encoding:
/// - **Tag 0**: `TypeDef` table (interfaces in current assembly)
/// - **Tag 1**: `TypeRef` table (interfaces from other assemblies)
/// - **Tag 2**: `TypeSpec` table (generic interface instantiations)
///
/// # Compiler Quirks
/// The .NET compiler incorrectly places interface inheritance relationships in the
/// `InterfaceImpl` table instead of using proper base type relationships. This requires
/// special handling during processing to distinguish between true interface implementation
/// and interface-to-interface inheritance.
#[derive(Clone, Debug)]
pub struct InterfaceImplRaw {
    /// Row identifier within the `InterfaceImpl` table.
    ///
    /// Unique identifier for this interface implementation entry, used for internal
    /// table management and token generation.
    pub rid: u32,

    /// Metadata token for this `InterfaceImpl` entry (`TableId` 0x09).
    ///
    /// Computed as `0x09000000 | rid` to create the full token value
    /// for referencing this interface implementation from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// `TypeDef` table index for the implementing type.
    ///
    /// References the type (class or interface) that implements or extends the target interface.
    /// Requires token construction (`class | 0x02000000`) and `TypeDef` lookup during processing.
    pub class: u32,

    /// `TypeDefOrRef` coded index for the implemented interface.
    ///
    /// Points to the interface being implemented or extended. Uses coded index encoding
    /// to reference `TypeDef`, `TypeRef`, or `TypeSpec` tables for different interface sources.
    /// Requires coded index resolution during processing to obtain the actual interface type.
    pub interface: CodedIndex,
}

impl InterfaceImplRaw {
    /// Applies interface implementation directly to the type system.
    ///
    /// This method resolves type references and immediately establishes the interface
    /// implementation relationship in the type system. It's an alternative to the
    /// two-step process of conversion to owned structure followed by application.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all resolved type definitions
    ///
    /// # Returns
    /// * `Ok(())` - Interface implementation applied successfully
    /// * `Err(_)` - Type reference resolution failed
    ///
    /// # Errors
    /// - Invalid class token or type not found in registry
    /// - Invalid interface coded index or type resolution failure
    pub fn apply(&self, types: &TypeRegistry) -> Result<()> {
        let Some(interface) = types.get(&self.interface.token) else {
            return Err(malformed_error!(
                "Failed to resolve interface token - {}",
                self.interface.token.value()
            ));
        };

        match types.get(&Token::new(self.class | 0x0200_0000)) {
            Some(class) => {
                class.interfaces.push_row(
                    self.token,
                    InterfaceEntry {
                        interface: CilTypeRef::new(&interface),
                        custom_attributes: Default::default(),
                    },
                );
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve class token - {}",
                self.class | 0x0200_0000
            )),
        }
    }

    /// Converts raw `InterfaceImpl` entry to owned structure with resolved type references.
    ///
    /// This method processes the raw table entry by resolving all type references,
    /// creating an [`crate::metadata::tables::interfaceimpl::owned::InterfaceImpl`] instance with owned data suitable for runtime
    /// use and further processing.
    ///
    /// # Arguments
    /// * `types` - Type registry containing all resolved type definitions
    ///
    /// # Returns
    /// * `Ok(InterfaceImplRc)` - Successfully converted owned `InterfaceImpl` structure
    /// * `Err(_)` - Type reference resolution failed
    ///
    /// # Errors
    /// - Invalid class token or type not found in registry
    /// - Invalid interface coded index or type resolution failure
    ///
    /// [`InterfaceImpl`]: crate::metadata::tables::InterfaceImpl
    pub fn to_owned(&self, types: &TypeRegistry) -> Result<InterfaceImplRc> {
        Ok(Arc::new(InterfaceImpl {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            class: match types.get(&Token::new(self.class | 0x0200_0000)) {
                Some(class) => class,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve class token - {}",
                        self.class | 0x0200_0000
                    ))
                }
            },
            interface: match types.get(&self.interface.token) {
                Some(interface) => interface,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve interface token - {}",
                        self.interface.token.value()
                    ))
                }
            },
            custom_attributes: Default::default(),
        }))
    }
}

impl TableRow for InterfaceImplRaw {
    /// Calculate the byte size of an InterfaceImpl table row
    ///
    /// Returns the total size of one row in the InterfaceImpl table, including:
    /// - class: 2 or 4 bytes (TypeDef table index)
    /// - interface: 2 or 4 bytes (TypeDefOrRef coded index)
    ///
    /// The index sizes depend on the metadata table and coded index requirements.
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* class */     sizes.table_index_bytes(TableId::TypeDef)
            /* interface */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef))

        )
    }
}
