//! Factory methods for raw modification integrity validation testing.
//!
//! Contains helper methods migrated from raw modification integrity validation source files
//! for creating test assemblies with various integrity validation scenarios.

use crate::{
    metadata::{
        tables::{CodedIndex, CodedIndexType, FieldRaw, MethodDefRaw, TableId, TypeDefRaw},
        token::Token,
    },
    testkit::{get_testfile_wb, TestAssembly},
    Result,
};

/// Test factory for RawChangeIntegrityValidator following the golden pattern.
///
/// Creates test assemblies covering basic integrity validation scenarios.
/// Note: This validator primarily uses direct corruption testing rather than file-based tests.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/integrity.rs`
pub fn raw_change_integrity_validator_file_factory() -> Result<Vec<TestAssembly>> {
    Ok(vec![TestAssembly::new(get_testfile_wb())])
}

/// Creates a dummy TypeDef for testing purposes.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/integrity.rs`
pub fn create_dummy_typedef(rid: u32) -> Result<TypeDefRaw> {
    Ok(TypeDefRaw {
        rid,
        token: Token::new(rid | 0x0200_0000),
        offset: 0,
        flags: 0,
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    })
}

/// Creates a dummy Field for testing purposes.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/integrity.rs`
pub fn create_dummy_field(rid: u32) -> Result<FieldRaw> {
    Ok(FieldRaw {
        rid,
        token: Token::new(rid | 0x0400_0000),
        offset: 0,
        flags: 0,
        name: 1,
        signature: 1,
    })
}

/// Creates a dummy MethodDef for testing purposes.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/integrity.rs`
pub fn create_dummy_method(rid: u32) -> Result<MethodDefRaw> {
    Ok(MethodDefRaw {
        rid,
        token: Token::new(rid | 0x0600_0000),
        offset: 0,
        rva: 0,
        impl_flags: 0,
        flags: 0,
        name: 1,
        signature: 1,
        param_list: 1,
    })
}
