#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! True round-trip integration tests for assembly modification operations.
//!
//! These tests validate the complete write pipeline by:
//! 1. Loading an assembly
//! 2. Making modifications (add/modify/remove)
//! 3. Writing to memory
//! 4. Loading the written bytes again
//! 5. Verifying changes are correctly persisted

use std::path::PathBuf;

use dotscope::{prelude::*, testkit::fixture};

const TEST_ASSEMBLY_PATH: &str = "WindowsBase.dll";

/// Helper function to get test assembly path
fn get_test_assembly_path() -> PathBuf {
    fixture(TEST_ASSEMBLY_PATH)
}

/// Helper function to create a test assembly
fn create_test_assembly() -> Result<CilAssembly> {
    let path = get_test_assembly_path();

    CilAssembly::from_path(&path)
}

#[test]
fn test_string_addition_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Add new strings
    let test_strings = vec!["TestString1", "TestString2", "TestString3"];
    let mut added_refs = Vec::new();

    for test_string in &test_strings {
        let string_ref = assembly.string_add(test_string)?;
        added_refs.push(string_ref);
    }

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify each added string can be retrieved using resolved ChangeRef offsets
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    for (i, string_ref) in added_refs.iter().enumerate() {
        let offset = string_ref
            .offset()
            .expect("ChangeRef should be resolved after write");
        let retrieved_string = written_strings.get(offset as usize)?;
        assert_eq!(
            retrieved_string, test_strings[i],
            "String at offset {offset} should match added string '{}'",
            test_strings[i]
        );
    }

    Ok(())
}

#[test]
fn test_string_modification_round_trip() -> Result<()> {
    // Step 1: Load and add a string to modify
    let mut assembly = create_test_assembly()?;
    let original_string = "OriginalString";
    let modified_string = "ModifiedString";

    let string_ref = assembly.string_add(original_string)?;

    // Step 2: Modify the string
    assembly.string_update(string_ref.placeholder(), modified_string)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify modification is persisted
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    let string_offset = string_ref.offset().expect("ChangeRef should be resolved");
    let retrieved_string = written_strings.get(string_offset as usize)?;
    assert_eq!(
        retrieved_string, modified_string,
        "Modified string should be persisted at offset {string_offset}"
    );

    // Ensure we don't have the original string at that index
    assert_ne!(
        retrieved_string, original_string,
        "Original string should be replaced"
    );

    Ok(())
}

#[test]
fn test_string_removal_round_trip() -> Result<()> {
    // Step 1: Load and add strings
    let mut assembly = create_test_assembly()?;

    // Count non-empty strings to avoid padding bytes affecting the count
    // (heap alignment padding creates null bytes that may be counted as empty strings)
    let original_non_empty = {
        let original_view = assembly.view();
        original_view
            .strings()
            .map(|s| s.iter().filter(|(_, str)| !str.is_empty()).count())
            .unwrap_or(0)
    };

    let string_to_keep = "StringToKeep";
    let string_to_remove = "StringToRemove";
    let _keep_ref = assembly.string_add(string_to_keep)?;
    let remove_ref = assembly.string_add(string_to_remove)?;

    // Step 2: Remove one string
    assembly.string_remove(remove_ref.placeholder())?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 6: Verify removal is persisted
    let written_strings = written_view
        .strings()
        .expect("Written assembly should have strings heap");

    let written_non_empty = written_strings
        .iter()
        .filter(|(_, s)| !s.is_empty())
        .count();

    // Should have original non-empty count + 1 (the kept string)
    assert_eq!(
        written_non_empty,
        original_non_empty + 1,
        "Written assembly should have one additional non-empty string (original: {}, written: {})",
        original_non_empty,
        written_non_empty
    );

    // The kept string should be present in the heap (offset may have changed due to placement optimization)
    assert!(
        written_strings.contains(string_to_keep),
        "Kept string '{}' should be present in written heap",
        string_to_keep
    );

    // The removed string should NOT be present in the heap
    assert!(
        !written_strings.contains(string_to_remove),
        "Removed string '{}' should NOT be present in written heap",
        string_to_remove
    );

    Ok(())
}

#[test]
fn test_blob_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Add and modify blobs
    let blob1_data = vec![1, 2, 3, 4, 5];
    let blob2_data = vec![10, 20, 30];
    let modified_blob_data = vec![99, 88, 77, 66];

    let blob1_ref = assembly.blob_add(&blob1_data)?;
    let blob2_ref = assembly.blob_add(&blob2_data)?;

    // Modify the first blob
    assembly.blob_update(blob1_ref.placeholder(), &modified_blob_data)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify changes are persisted using resolved ChangeRef offsets
    let written_blobs = written_view
        .blobs()
        .expect("Written assembly should have blob heap");

    // Verify modified blob via its resolved offset
    let blob1_offset = blob1_ref
        .offset()
        .expect("blob1 ChangeRef should be resolved after write");
    let retrieved_blob1 = written_blobs.get(blob1_offset as usize)?;
    assert_eq!(
        retrieved_blob1, modified_blob_data,
        "Modified blob should be persisted at offset {blob1_offset}"
    );

    // Verify unmodified blob via its resolved offset
    let blob2_offset = blob2_ref
        .offset()
        .expect("blob2 ChangeRef should be resolved after write");
    let retrieved_blob2 = written_blobs.get(blob2_offset as usize)?;
    assert_eq!(
        retrieved_blob2, blob2_data,
        "Unmodified blob should be persisted at offset {blob2_offset}"
    );

    Ok(())
}

#[test]
fn test_guid_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;
    let original_view = assembly.view();
    let original_guids_count = original_view.guids().map(|g| g.iter().count()).unwrap_or(0);

    // Step 2: Add and modify GUIDs
    let guid1 = [1u8; 16];
    let guid2 = [2u8; 16];
    let modified_guid = [99u8; 16];

    let guid1_ref = assembly.guid_add(&guid1)?;
    let guid2_ref = assembly.guid_add(&guid2)?;

    // Modify the first GUID
    assembly.guid_update(guid1_ref.placeholder(), &modified_guid)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify changes are persisted
    let written_guids = written_view
        .guids()
        .expect("Written assembly should have GUID heap");

    let written_guids_count = written_guids.iter().count();

    assert_eq!(
        written_guids_count,
        original_guids_count + 2,
        "Should have 2 additional GUIDs"
    );

    // Verify modified GUID
    let guid1_offset = guid1_ref
        .offset()
        .expect("GUID1 ChangeRef should be resolved");
    let retrieved_guid1 = written_guids.get(guid1_offset as usize)?;
    assert_eq!(
        retrieved_guid1.to_bytes(),
        modified_guid,
        "Modified GUID should be persisted"
    );

    // Verify unmodified GUID
    let guid2_offset = guid2_ref
        .offset()
        .expect("GUID2 ChangeRef should be resolved");
    let retrieved_guid2 = written_guids.get(guid2_offset as usize)?;
    assert_eq!(
        retrieved_guid2.to_bytes(),
        guid2,
        "Unmodified GUID should be persisted unchanged"
    );

    Ok(())
}

#[test]
fn test_userstring_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Add and modify user strings
    let userstring1 = "UserString1";
    let userstring2 = "UserString2";
    let modified_userstring = "ModifiedUserString";

    let us1_ref = assembly.userstring_add(userstring1)?;
    let us2_ref = assembly.userstring_add(userstring2)?;

    // Modify the first user string
    assembly.userstring_update(us1_ref.placeholder(), modified_userstring)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify changes are persisted using resolved ChangeRef offsets
    let written_userstrings = written_view
        .userstrings()
        .expect("Written assembly should have user strings heap");

    // Verify modified user string via its resolved offset
    let us1_offset = us1_ref
        .offset()
        .expect("us1 ChangeRef should be resolved after write");
    let retrieved_us1 = written_userstrings.get(us1_offset as usize)?;
    assert_eq!(
        retrieved_us1.to_string_lossy(),
        modified_userstring,
        "Modified user string should be persisted at offset {us1_offset}"
    );

    // Verify unmodified user string via its resolved offset
    let us2_offset = us2_ref
        .offset()
        .expect("us2 ChangeRef should be resolved after write");
    let retrieved_us2 = written_userstrings.get(us2_offset as usize)?;
    assert_eq!(
        retrieved_us2.to_string_lossy(),
        userstring2,
        "Unmodified user string should be persisted at offset {us2_offset}"
    );

    Ok(())
}

#[test]
fn test_mixed_operations_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Perform mixed operations on all heap types
    let test_string = "MixedTestString";
    let test_blob = vec![1, 2, 3, 4];
    let test_guid = [42u8; 16];
    let test_userstring = "MixedTestUserString";

    let string_ref = assembly.string_add(test_string)?;
    let blob_ref = assembly.blob_add(&test_blob)?;
    let guid_ref = assembly.guid_add(&test_guid)?;
    let userstring_ref = assembly.userstring_add(test_userstring)?;

    // Modify some entries
    let modified_string = "ModifiedMixedString";
    let modified_blob = vec![99, 88, 77];

    assembly.string_update(string_ref.placeholder(), modified_string)?;
    assembly.blob_update(blob_ref.placeholder(), &modified_blob)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify all changes are persisted using resolved ChangeRef offsets
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let string_offset = string_ref
        .offset()
        .expect("string ChangeRef should be resolved");
    let retrieved_string = strings_heap.get(string_offset as usize)?;
    assert_eq!(
        retrieved_string, modified_string,
        "Modified string should be persisted"
    );

    let blobs_heap = written_view.blobs().expect("Should have blob heap");
    let blob_offset = blob_ref
        .offset()
        .expect("blob ChangeRef should be resolved");
    let retrieved_blob = blobs_heap.get(blob_offset as usize)?;
    assert_eq!(
        retrieved_blob, modified_blob,
        "Modified blob should be persisted"
    );

    let guids_heap = written_view.guids().expect("Should have GUID heap");
    let guid_offset = guid_ref
        .offset()
        .expect("guid ChangeRef should be resolved");
    let retrieved_guid = guids_heap.get(guid_offset as usize)?;
    assert_eq!(
        retrieved_guid.to_bytes(),
        test_guid,
        "GUID should be persisted unchanged"
    );

    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");
    let userstring_offset = userstring_ref
        .offset()
        .expect("userstring ChangeRef should be resolved");
    let retrieved_userstring = userstrings_heap.get(userstring_offset as usize)?;
    assert_eq!(
        retrieved_userstring.to_string_lossy(),
        test_userstring,
        "User string should be persisted unchanged"
    );

    Ok(())
}

#[test]
fn test_builder_context_round_trip() -> Result<()> {
    // Step 1: Load assembly
    let mut assembly = create_test_assembly()?;

    // Step 2: Use assembly APIs
    let str1 = assembly.string_add("BuilderString1")?;
    let str2 = assembly.string_get_or_add("BuilderString2")?;
    let str3 = assembly.string_get_or_add("BuilderString1")?; // Should deduplicate

    assert_eq!(
        str1.placeholder(),
        str3.placeholder(),
        "Assembly should deduplicate identical strings"
    );

    let blob_ref = assembly.blob_add(&[1, 2, 3])?;
    let guid_ref = assembly.guid_add(&[99u8; 16])?;
    let userstring_ref = assembly.userstring_add("BuilderUserString")?;

    // Modify through assembly
    assembly.string_update(str2.placeholder(), "UpdatedBuilderString")?;
    assembly.blob_update(blob_ref.placeholder(), &[4, 5, 6])?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;

    // Step 4: Load the written bytes
    let written_view = CilAssemblyView::from_mem(bytes)?;

    // Step 5: Verify builder operations are persisted using resolved ChangeRef offsets
    let strings_heap = written_view.strings().expect("Should have strings heap");
    let str1_offset = str1.offset().expect("str1 should be resolved");
    let retrieved_str1 = strings_heap.get(str1_offset as usize)?;
    assert_eq!(
        retrieved_str1, "BuilderString1",
        "First builder string should be persisted"
    );

    let str2_offset = str2.offset().expect("str2 should be resolved");
    let retrieved_str2 = strings_heap.get(str2_offset as usize)?;
    assert_eq!(
        retrieved_str2, "UpdatedBuilderString",
        "Updated builder string should be persisted"
    );

    // str3 should resolve to the same offset as str1 (deduplication)
    let str3_offset = str3.offset().expect("str3 should be resolved");
    assert_eq!(
        str1_offset, str3_offset,
        "Deduplicated strings should resolve to same offset"
    );

    let blobs_heap = written_view.blobs().expect("Should have blob heap");
    let blob_offset = blob_ref.offset().expect("blob should be resolved");
    let retrieved_blob = blobs_heap.get(blob_offset as usize)?;
    assert_eq!(
        retrieved_blob,
        vec![4, 5, 6],
        "Updated blob should be persisted"
    );

    let guids_heap = written_view.guids().expect("Should have GUID heap");
    let guid_offset = guid_ref.offset().expect("guid should be resolved");
    let retrieved_guid = guids_heap.get(guid_offset as usize)?;
    assert_eq!(
        retrieved_guid.to_bytes(),
        [99u8; 16],
        "GUID should be persisted"
    );

    let userstrings_heap = written_view
        .userstrings()
        .expect("Should have user strings heap");
    let userstring_offset = userstring_ref
        .offset()
        .expect("userstring should be resolved");
    let retrieved_userstring = userstrings_heap.get(userstring_offset as usize)?;
    assert_eq!(
        retrieved_userstring.to_string_lossy(),
        "BuilderUserString",
        "User string should be persisted"
    );

    Ok(())
}
