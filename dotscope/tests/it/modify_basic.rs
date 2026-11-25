#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Basic write pipeline integration tests.
//!
//! Tests for basic assembly writing functionality, including unmodified assemblies
//! and simple modifications to verify the core write pipeline works correctly.

use dotscope::{prelude::*, testkit::fixture, CleanupRequest};

const TEST_ASSEMBLY_PATH: &str = "crafted_2.exe";

#[test]
fn test_write_unmodified_assembly() -> Result<()> {
    // Load assembly without modifications
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Verify the written bytes can be loaded
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Basic integrity checks
    assert!(
        written_view.strings().is_some(),
        "Written assembly should have strings heap"
    );
    assert!(
        written_view.blobs().is_some(),
        "Written assembly should have blobs heap"
    );
    assert!(
        written_view.tables().is_some(),
        "Written assembly should have metadata tables"
    );

    // Verify basic metadata structure is preserved
    let tables = written_view.tables().unwrap();
    assert!(
        tables.table_row_count(TableId::Module) > 0,
        "Should have module table entries"
    );
    assert!(
        tables.table_row_count(TableId::TypeDef) > 0,
        "Should have type definition entries"
    );

    Ok(())
}

#[test]
fn test_write_with_minimal_modification() -> Result<()> {
    // Load assembly and make a minimal modification
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;

    // Add a single string - minimal modification to trigger write pipeline
    let test_string = "MinimalTestString";
    let _string_ref = assembly.string_add(test_string)?;
    // ChangeRef is valid if we got here without error

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Verify the written bytes can be loaded and contains our modification
    let written_view = CilAssemblyView::from_mem(bytes)?;

    let strings = written_view
        .strings()
        .ok_or_else(|| Error::Other("Written assembly should have strings heap".to_string()))?;

    // Verify our modification is present
    assert!(
        strings.contains(test_string),
        "Added string '{test_string}' should be present in written assembly"
    );

    // Verify basic structure is still intact
    assert!(
        written_view.tables().is_some(),
        "Written assembly should have metadata tables"
    );

    Ok(())
}

#[test]
fn test_write_preserves_existing_data() -> Result<()> {
    // Test that writing preserves existing assembly data
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;

    // Capture some original data
    let original_strings_count = assembly
        .view()
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let original_method_count = assembly
        .view()
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Make a modification
    let string_idx = assembly.string_add("PreservationTestString")?;

    // Write to memory and reload
    let bytes = assembly.to_memory()?;
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Verify existing data is preserved
    let new_strings_count = written_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let new_method_count = written_view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Strings should increase by 1, methods should stay the same
    assert_eq!(
        new_method_count, original_method_count,
        "Method count should be preserved"
    );
    assert!(
        new_strings_count >= original_strings_count,
        "String count should increase or stay the same"
    );

    // Verify the added string can be retrieved
    let strings = written_view.strings().unwrap();
    let retrieved_string = strings.get(string_idx.offset().unwrap() as usize)?;
    assert_eq!(
        retrieved_string, "PreservationTestString",
        "Added string should be retrievable after write"
    );

    Ok(())
}

#[test]
fn test_multiple_write_operations() -> Result<()> {
    // Test that an assembly can be written multiple times
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;

    // Write first time
    let bytes1 = assembly.to_memory()?;

    // Write second time (should work without issues)
    let bytes2 = assembly.to_memory()?;

    // Both should be valid and loadable
    let written_view1 = CilAssemblyView::from_mem(bytes1)?;
    let written_view2 = CilAssemblyView::from_mem(bytes2)?;

    // Both should have the same basic structure
    assert_eq!(
        written_view1
            .tables()
            .map(|t| t.table_row_count(TableId::Module)),
        written_view2
            .tables()
            .map(|t| t.table_row_count(TableId::Module)),
        "Both written files should have the same module count"
    );

    Ok(())
}

/// ConfuserEx's "invalid metadata" adds a DeclSecurity row whose parent's tag names no table
/// (issue #290). The CLR reads that parent as null; dotscope reads it the same way, and an
/// unmodified assembly holding it writes back, the parent as a null reference.
#[test]
fn an_unassigned_coded_index_writes_back_as_null() -> Result<()> {
    let path = fixture("packers/confuserex/1.6.0/mkaring_invalidmetadata.exe");
    let lenient = ValidationConfig {
        lenient: true,
        ..ValidationConfig::minimal()
    };
    let mut assembly = CilAssembly::from_bytes_with_validation(std::fs::read(path)?, lenient)?;
    let bytes = assembly.to_memory()?;

    let written = CilAssemblyView::from_mem_with_validation(bytes, ValidationConfig::disabled())?;
    let rows: Vec<DeclSecurityRaw> = written
        .tables()
        .unwrap()
        .table::<DeclSecurityRaw>()
        .unwrap()
        .into_iter()
        .collect::<Result<_>>()?;
    assert_eq!(rows.len(), 1, "the row is written back, not dropped");
    assert_eq!(rows[0].parent.row, 0, "its parent is the null reference");
    assert_eq!(rows[0].action, 0x7FFF);
    Ok(())
}

/// Validation names an unassigned coded-index tag for what it is.
#[test]
fn validation_reports_an_unassigned_coded_index_tag() {
    let path = fixture("packers/confuserex/1.6.0/mkaring_invalidmetadata.exe");
    let error = CilAssemblyView::from_path_with_validation(path, ValidationConfig::production())
        .err()
        .expect("production validation refuses the image");
    assert!(
        error.to_string().contains("whose tag names no table"),
        "unexpected error: {error}"
    );
}

/// Deleting a method its caller still calls fails the write, naming both; the call is never
/// retargeted to the method after it.
#[test]
fn deleting_a_called_method_without_its_caller_is_a_dangling_reference() -> Result<()> {
    let path = fixture("packers/confuserex/1.6.0/original.exe");
    let main = Token::new(0x0600_0003);
    let say_hello = Token::new(0x0600_0006);

    let mut request = CleanupRequest::new();
    request.add_method(say_hello);

    let mut assembly = CilAssembly::from_path(&path)?;
    assembly.add_cleanup(&request);
    let err = assembly.to_memory().unwrap_err();
    assert!(
        matches!(
            err,
            Error::DanglingReference {
                referrer: Referrer::Body(method),
                target,
            } if method == main && target == say_hello
        ),
        "{err}"
    );

    // Under the null policy the write goes through, with the call naming no method.
    let mut assembly = CilAssembly::from_path(path)?;
    assembly.add_cleanup(&request);
    let bytes = assembly
        .to_memory_with_config(GeneratorConfig::default().with_dangling(DanglingPolicy::Null))?;
    let written = CilObject::from_mem_with_validation(bytes, ValidationConfig::disabled())?;
    let calls: Vec<u32> = written
        .method(&main)?
        .instructions()
        .filter(|i| i.mnemonic == "callvirt")
        .filter_map(|i| i.get_token_operand())
        .map(|t| t.value())
        .collect();
    assert_eq!(
        calls.first(),
        Some(&0x0600_0000),
        "SayHello's call site holds the null MethodDef token, not SayGoodbye's: {calls:x?}"
    );
    Ok(())
}
