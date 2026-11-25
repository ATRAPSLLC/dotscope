//! Factory methods for CilAssembly table operations.
//!
//! Contains helper methods migrated from `src/cilassembly/mod.rs` tests
//! for creating test data related to CilAssembly table manipulation.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    Result,
};

/// Helper function to create a minimal TypeDef row for testing
///
/// Originally from: `src/cilassembly/mod.rs`
pub fn create_test_typedef_row() -> Result<TableDataOwned> {
    Ok(TableDataOwned::TypeDef(TypeDefRaw {
        rid: 0,                        // Will be set by the system
        token: Token::new(0x02000000), // Will be updated by the system
        offset: 0,                     // Will be set during binary generation
        flags: 0,
        type_name: 1,      // Placeholder string index
        type_namespace: 0, // Empty namespace
        extends: CodedIndex::new(TableId::TypeRef, 0, CodedIndexType::TypeDefOrRef), // No base type (0 = null reference)
        field_list: 1,  // Placeholder field list
        method_list: 1, // Placeholder method list
    }))
}

/// Helper function to create a test TypeDef row for remapping tests
///
/// Originally from: `src/cilassembly/remapping/index.rs`
pub fn create_test_row() -> TableDataOwned {
    TableDataOwned::TypeDef(TypeDefRaw {
        rid: 0,
        token: Token::new(0x02000000),
        offset: 0,
        flags: 0,
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 0, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    })
}
