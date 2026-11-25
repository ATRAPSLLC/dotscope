//! Factory methods for raw structure signature validation testing.
//!
//! Each crafted case adds one corrupted signature blob and points one existing row at it, so
//! the validator meets exactly that blob and every other signature stays valid.

use crate::{
    cilassembly::CilAssembly,
    metadata::tables::{FieldRaw, MethodDefRaw, TableDataOwned, TableId},
    testkit::{create_test_assembly, get_testfile_wb, Expect, TestAssembly},
    Error, Result,
};

/// Test factory for RawSignatureValidator following the golden pattern.
///
/// Tests calling convention validation, compressed integer format, and blob bounds.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/signature.rs`
pub fn raw_signature_validator_file_factory() -> Result<Vec<TestAssembly>> {
    Ok(vec![
        TestAssembly::new(get_testfile_wb()),
        create_assembly_with_invalid_method_calling_convention()?,
        create_assembly_with_field_signature_on_a_method()?,
        create_assembly_with_invalid_field_calling_convention()?,
        create_assembly_with_malformed_compressed_integer()?,
        create_assembly_with_large_signature_blob()?,
    ])
}

/// Points MethodDef row 1 at a new blob holding `signature`.
fn method_signature(assembly: &mut CilAssembly, signature: &[u8]) -> Result<()> {
    let blob = assembly.blob_add(signature)?;
    let row = assembly
        .view()
        .tables()
        .and_then(|tables| tables.table::<MethodDefRaw>())
        .ok_or_else(|| Error::Other("no MethodDef table".to_string()))?
        .get(1)?
        .ok_or_else(|| Error::Other("no MethodDef row 1".to_string()))?;
    assembly.table_row_update(
        TableId::MethodDef,
        1,
        TableDataOwned::MethodDef(MethodDefRaw {
            signature: blob.placeholder(),
            ..row
        }),
    )
}

/// A method signature whose calling convention (0x0D) ECMA-335 II.23.2.1 does not define.
pub fn create_assembly_with_invalid_method_calling_convention() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("Invalid method calling convention 0x0D"),
        |assembly| method_signature(assembly, &[0x0D, 0x00, 0x01]),
    )
}

/// A MethodDef whose signature is a field signature (0x06).
pub fn create_assembly_with_field_signature_on_a_method() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("Invalid method calling convention 0x06"),
        |assembly| method_signature(assembly, &[0x06, 0x08]),
    )
}

/// A field signature whose first byte is not FIELD (0x06), ECMA-335 II.23.2.4.
pub fn create_assembly_with_invalid_field_calling_convention() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("Invalid field signature marker 0x07"),
        |assembly| {
            let blob = assembly.blob_add(&[0x07, 0x08])?;
            let row = assembly
                .view()
                .tables()
                .and_then(|tables| tables.table::<FieldRaw>())
                .ok_or_else(|| Error::Other("no Field table".to_string()))?
                .get(1)?
                .ok_or_else(|| Error::Other("no Field row 1".to_string()))?;
            assembly.table_row_update(
                TableId::Field,
                1,
                TableDataOwned::Field(FieldRaw {
                    signature: blob.placeholder(),
                    ..row
                }),
            )
        },
    )
}

/// A method signature whose parameter count starts a four-byte compressed integer (0xE0)
/// the blob ends before.
pub fn create_assembly_with_malformed_compressed_integer() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("Invalid compressed integer encoding 0xE0"),
        |assembly| method_signature(assembly, &[0x00, 0xE0]),
    )
}

/// A method signature blob of 65537 bytes: a blob may hold up to 0x1FFFFFFF bytes, so it is
/// valid.
pub fn create_assembly_with_large_signature_blob() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_wb, Expect::Pass, |assembly| {
        let mut signature = vec![0x00, 0x00, 0x01];
        signature.resize(65537, 0x01);
        method_signature(assembly, &signature)
    })
}
