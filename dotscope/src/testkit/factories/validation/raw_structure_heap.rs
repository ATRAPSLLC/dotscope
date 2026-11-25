//! Factory methods for raw structure heap validation testing.
//!
//! Contains helper methods migrated from raw structure heap validation source files
//! for creating test assemblies with various heap validation scenarios.

use crate::{
    cilassembly::{DanglingPolicy, GeneratorConfig},
    metadata::tables::{TypeAttributes, TypeDefBuilder},
    testkit::{create_test_assembly, get_testfile_wb, load_test_assembly, Expect, TestAssembly},
    Error, Result,
};

/// Test factory for RawHeapValidator following the golden pattern.
///
/// Creates test assemblies covering basic heap validation scenarios.
/// Tests UTF-8, UTF-16, GUID alignment, and other heap integrity validations.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn raw_heap_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_wb();

    // 1. REQUIRED: Clean assembly - should pass all validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. UserString heap with non-UTF-16 data (spec-legal per ECMA-335 II.24.2.4)
    assemblies.push(create_assembly_with_non_utf16_userstring()?);

    // 3. String heap with one entry of invalid UTF-8
    assemblies.push(create_assembly_with_invalid_utf8_string()?);

    // 4. GUID heap with "invalid" size alignment input
    // When a user provides a replacement heap, we write it exactly as provided.
    // This test creates an invalid GUID heap (not 16-byte aligned) which should fail validation.
    assemblies.push(create_assembly_with_invalid_guid_alignment()?);

    // 5. GUID heap with valid content (tests our new validation logic)
    assemblies.push(create_assembly_with_valid_guid_content()?);

    // Note: Additional heap corruption tests for String heap (UTF-8) and Blob heap
    // require more sophisticated corruption techniques. The heap replacement approach
    // works well for GUID alignment and UserString UTF-16 validation, demonstrating
    // the effectiveness of direct heap manipulation for validation testing.

    Ok(assemblies)
}

/// Creates a test assembly with non-UTF-16 data in the userstring heap.
///
/// Per ECMA-335 II.24.2.4, the UserString heap can contain arbitrary binary data.
/// This test verifies that non-UTF-16 sequences (such as unpaired surrogates) are
/// accepted by the validator.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_non_utf16_userstring() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_wb, Expect::Pass, |assembly| {
        // Create a userstring heap with non-UTF-16 sequences (spec-legal)
        // Structure: null byte + length prefix + data with unpaired surrogate + terminator
        let mut userstring_heap = vec![0]; // Required null byte at index 0

        // Create a userstring entry with unpaired surrogate (valid per ECMA-335)
        // Length: 5 bytes (2 bytes high surrogate + 2 bytes regular char + 1 terminator)
        userstring_heap.push(0x05); // Length prefix
        userstring_heap.extend_from_slice(&[0x00, 0xD8]); // Unpaired high surrogate
        userstring_heap.extend_from_slice(&[0x41, 0x00]); // Valid 'A' character
        userstring_heap.push(0x01); // Terminator byte

        assembly.userstring_add_heap(userstring_heap)?;
        Ok(())
    })
}

/// Creates a test assembly with invalid GUID heap size alignment.
///
/// Creates a GUID heap that is not a multiple of 16 bytes using heap replacement.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_invalid_guid_alignment() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_wb,
        Expect::fail("GUID heap (#GUID) size 28 is not a multiple of 16 bytes"),
        |assembly| {
            // Create a GUID heap with invalid size (not multiple of 16 bytes)
            let mut guid_heap = Vec::new();
            // Add one complete GUID (16 bytes)
            guid_heap.extend_from_slice(&[0x12; 16]);
            // Add incomplete GUID (only 10 bytes) - violates 16-byte alignment requirement
            guid_heap.extend_from_slice(&[0x34; 10]);

            assembly.guid_add_heap(guid_heap)?;
            Ok(())
        },
    )
}

/// Creates a test assembly with valid GUID heap content to test
/// the new GUID content validation logic.
///
/// Creates a minimal test to validate the new GUID content validation logic
/// works correctly with valid GUID data.
///
/// Originally from: `src/metadata/validation/validators/raw/structure/heap.rs`
pub fn create_assembly_with_valid_guid_content() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_wb, Expect::Pass, |assembly| {
        // Create a very simple GUID heap with just one GUID that should pass basic validation
        // The real test is to ensure our new validation code runs without errors
        // on a valid GUID heap, demonstrating the implementation is working
        let mut guid_heap = Vec::new();

        // Add exactly 1 complete GUID (16 bytes)
        guid_heap.extend_from_slice(&[
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ]);

        assembly.guid_add_heap(guid_heap)?;
        Ok(())
    })
}

/// Creates an assembly whose string heap holds one entry of invalid UTF-8: a type named
/// `Utf8Probe_ZZZZ` is written, and the four `Z`s of its name become bytes no UTF-8 sequence
/// holds. The rest of the heap is as the writer made it.
pub fn create_assembly_with_invalid_utf8_string() -> Result<TestAssembly> {
    let mut assembly = load_test_assembly(get_testfile_wb)?;
    TypeDefBuilder::new()
        .name("Utf8Probe_ZZZZ")
        .namespace("Test")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::INTERFACE | TypeAttributes::ABSTRACT)
        .build(&mut assembly)?;
    let mut bytes = assembly
        .to_memory_with_config(GeneratorConfig::default().with_dangling(DanglingPolicy::Null))?;
    let marker = b"Utf8Probe_ZZZZ\0";
    let at = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or_else(|| Error::Other("the probe name in the written heap".to_string()))?;
    let tail = at + marker.len() - 5;
    bytes[tail..tail + 4].copy_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
    Ok(TestAssembly::from_bytes(
        bytes,
        Expect::fail("String heap contains invalid UTF-8 sequence at offset"),
    ))
}
