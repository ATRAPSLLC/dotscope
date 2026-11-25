#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Heap modification integration tests.
//!
//! Tests for modifying metadata heaps (strings, blobs, GUIDs, userstrings) and verifying
//! that changes are correctly persisted through the write pipeline.

use dotscope::{metadata::tables::TableDataOwned, prelude::*, testkit::fixture};

const TEST_ASSEMBLY_PATH: &str = "crafted_2.exe";

/// Helper function to perform a round-trip test with specific verification
fn perform_round_trip_test<F, V>(modify_fn: F, verify_fn: V) -> Result<()>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
    V: FnOnce(&CilAssemblyView) -> Result<()>,
{
    // Load original assembly
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;

    // Apply modifications
    modify_fn(&mut assembly)?;

    // Write to memory
    let bytes = assembly.to_memory()?;

    // Load written bytes and verify
    let written_view = CilAssemblyView::from_mem(bytes)?;
    verify_fn(&written_view)?;

    Ok(())
}

#[test]
fn test_string_heap_add_and_verify() -> Result<()> {
    let test_string = "TestAddedString";

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.string_add(test_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the specific string was added
            assert!(
                strings.contains(test_string),
                "Added string '{test_string}' should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_blob_heap_add_and_verify() -> Result<()> {
    let test_blob = vec![0x06, 0x08, 0xFF, 0xAA]; // Test blob data

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.blob_add(&test_blob)?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;

            // Verify the specific blob was added
            assert!(
                blobs.contains(&test_blob),
                "Added blob {test_blob:?} should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_guid_heap_add_and_verify() -> Result<()> {
    let test_guid = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.guid_add(&test_guid)?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;

            // Verify the specific GUID was added
            assert!(
                guids.contains(&uguid::Guid::from_bytes(test_guid)),
                "Added GUID {test_guid:?} should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_userstring_heap_add_and_verify() -> Result<()> {
    let test_userstring = "TestAddedUserString";

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;

            // Verify the specific userstring was added
            assert!(
                userstrings.contains(test_userstring),
                "Added userstring '{test_userstring}' should be present in written assembly"
            );
            Ok(())
        },
    )
}

#[test]
fn test_mixed_heap_additions() -> Result<()> {
    let test_string = "MixedTestString";
    let test_blob = vec![0x01, 0x02, 0x03];
    let test_guid = [0xFF; 16];
    let test_userstring = "MixedTestUserString";

    perform_round_trip_test(
        |assembly| {
            let _str_idx = assembly.string_add(test_string)?;
            let _blob_idx = assembly.blob_add(&test_blob)?;
            let _guid_idx = assembly.guid_add(&test_guid)?;
            let _us_idx = assembly.userstring_add(test_userstring)?;
            Ok(())
        },
        |written_view| {
            // Verify all additions are present
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;
            assert!(strings.contains(test_string), "String should be present");

            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;
            assert!(blobs.contains(&test_blob), "Blob should be present");

            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;
            assert!(
                guids.contains(&uguid::Guid::from_bytes(test_guid)),
                "GUID should be present"
            );

            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;
            assert!(
                userstrings.contains(test_userstring),
                "Userstring should be present"
            );

            Ok(())
        },
    )
}

#[test]
fn test_string_modification_and_verify() -> Result<()> {
    let original_string = "Task`1"; // Should exist in crafted_2.exe
    let modified_string = "System.Object.Modified";

    perform_round_trip_test(
        |assembly| {
            // Get the original view to find the string index
            let strings = assembly
                .view()
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            let original_index = strings
                .find(original_string)
                .ok_or_else(|| Error::Other(format!("String '{original_string}' not found")))?;

            assembly.string_update(original_index, modified_string)?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the modification was applied
            assert!(
                strings.contains(modified_string),
                "Modified string '{modified_string}' should be present"
            );

            // Verify original string is no longer present
            assert!(
                !strings.contains(original_string),
                "Original string '{original_string}' should be replaced"
            );

            Ok(())
        },
    )
}

#[test]
fn test_heap_data_persistence() -> Result<()> {
    // Test that heap modifications don't corrupt existing data
    let test_string = "PersistenceTestString";

    perform_round_trip_test(
        |assembly| {
            let _index = assembly.string_add(test_string)?;
            Ok(())
        },
        |written_view| {
            // Verify basic metadata structures are intact
            assert!(
                written_view.strings().is_some(),
                "Strings heap should exist"
            );
            assert!(written_view.blobs().is_some(), "Blobs heap should exist");
            assert!(written_view.tables().is_some(), "Tables should exist");

            // Verify our addition is there
            let strings = written_view.strings().unwrap();
            assert!(
                strings.contains(test_string),
                "Added string should be present"
            );

            // Verify some existing data is preserved (Task`1 should exist)
            assert!(
                strings.contains("Task`1"),
                "Existing string 'Task`1' should be preserved"
            );

            Ok(())
        },
    )
}

#[test]
fn test_string_heap_replacement() -> Result<()> {
    // Create a custom string heap with null byte at index 0 followed by two null-terminated strings
    let mut custom_heap = vec![0]; // Index 0 must always be null
    custom_heap.extend_from_slice(b"CustomString1\0AnotherString\0");

    perform_round_trip_test(
        |assembly| {
            assembly.string_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify the custom strings are present
            assert!(
                strings.contains("CustomString1"),
                "Custom string 'CustomString1' should be present in replaced heap"
            );
            assert!(
                strings.contains("AnotherString"),
                "Custom string 'AnotherString' should be present in replaced heap"
            );

            // Verify that original strings are no longer present (heap was replaced)
            assert!(
                !strings.contains("Task`1"),
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}

#[test]
fn test_blob_heap_replacement() -> Result<()> {
    // When replacing a blob heap, we must preserve the original blob data to maintain
    // existing references (method signatures, custom attributes, etc.) that point into
    // the blob heap. This test replaces the heap while preserving original content.

    // Load the assembly first to get the original blob heap
    let assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;
    let original_blob_data = assembly
        .view()
        .blobs()
        .map(|blobs| blobs.data().to_vec())
        .unwrap_or_else(|| vec![0]); // Ensure at least null byte at index 0
    let original_blob_count = assembly
        .view()
        .blobs()
        .map(|b| b.iter().count())
        .unwrap_or(0);
    drop(assembly);

    // Create replacement heap: original data + our custom blobs appended
    // Custom blobs: length=3, data=[0x01, 0x02, 0x03] and length=2, data=[0xAA, 0xBB]
    let mut custom_heap = original_blob_data.clone();
    custom_heap.extend_from_slice(&[0x03, 0x01, 0x02, 0x03, 0x02, 0xAA, 0xBB]);

    perform_round_trip_test(
        |assembly| {
            assembly.blob_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let blobs = written_view
                .blobs()
                .ok_or_else(|| Error::Other("No blobs heap found".to_string()))?;

            // Verify our custom blobs are present
            assert!(
                blobs.contains(&[0x01, 0x02, 0x03]),
                "Custom blob [0x01, 0x02, 0x03] should be present in replaced heap"
            );
            assert!(
                blobs.contains(&[0xAA, 0xBB]),
                "Custom blob [0xAA, 0xBB] should be present in replaced heap"
            );

            // Verify we have at least the original blobs plus our 2 custom ones
            let blob_count = blobs.iter().count();
            assert!(
                blob_count >= original_blob_count + 2,
                "Replaced heap should contain at least original ({}) + 2 custom blobs (found {})",
                original_blob_count,
                blob_count
            );

            Ok(())
        },
    )
}

#[test]
fn test_guid_heap_replacement() -> Result<()> {
    // Create a custom GUID heap with two GUIDs (32 bytes total)
    let guid1 = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    let guid2 = [
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];

    let mut custom_heap = Vec::new();
    custom_heap.extend_from_slice(&guid1);
    custom_heap.extend_from_slice(&guid2);

    perform_round_trip_test(
        |assembly| {
            assembly.guid_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let guids = written_view
                .guids()
                .ok_or_else(|| Error::Other("No GUIDs heap found".to_string()))?;

            // Verify the custom GUIDs are present
            assert!(
                guids.contains(&uguid::Guid::from_bytes(guid1)),
                "Custom GUID 1 should be present in replaced heap"
            );
            assert!(
                guids.contains(&uguid::Guid::from_bytes(guid2)),
                "Custom GUID 2 should be present in replaced heap"
            );

            // Since we replaced the entire heap, only our GUIDs should be present
            let guid_count = guids.iter().count();
            assert_eq!(
                guid_count, 2,
                "Replaced heap should only contain our 2 custom GUIDs (found {guid_count} GUIDs)",
            );

            Ok(())
        },
    )
}

#[test]
fn test_userstring_heap_replacement() -> Result<()> {
    // Create a custom user string heap with null byte at index 0 followed by length-prefixed UTF-16 strings
    // Index 0: null byte (required)
    // String "Hi": length=5 (4 bytes UTF-16 + 1 terminator), UTF-16 data: 0x48,0x00,0x69,0x00, terminator: 0x01
    let mut custom_heap = vec![0]; // Index 0 must always be null
    custom_heap.extend_from_slice(&[0x05, 0x48, 0x00, 0x69, 0x00, 0x01]);

    perform_round_trip_test(
        |assembly| {
            assembly.userstring_add_heap(custom_heap.clone())?;
            Ok(())
        },
        |written_view| {
            let userstrings = written_view
                .userstrings()
                .ok_or_else(|| Error::Other("No userstrings heap found".to_string()))?;

            // Verify the custom user string is present
            assert!(
                userstrings.contains("Hi"),
                "Custom user string 'Hi' should be present in replaced heap"
            );

            // Since we replaced the entire heap, original user strings should not be present
            let userstring_count = userstrings.iter().count();
            assert!(
                userstring_count <= 2, // Empty userstring at index 0 + our 1 userstring
                "Replaced heap should only contain our custom user string (found {userstring_count} userstrings)",
            );

            Ok(())
        },
    )
}

#[test]
fn test_heap_replacement_with_subsequent_additions() -> Result<()> {
    // Test that subsequent additions work with replaced heaps
    let mut custom_string_heap = vec![0]; // Index 0 must always be null
    custom_string_heap.extend_from_slice(b"ReplacedString\0");

    perform_round_trip_test(
        |assembly| {
            // Replace string heap
            assembly.string_add_heap(custom_string_heap.clone())?;

            // Add a new string after replacement
            let _new_index = assembly.string_add("AddedAfterReplacement")?;

            Ok(())
        },
        |written_view| {
            let strings = written_view
                .strings()
                .ok_or_else(|| Error::Other("No strings heap found".to_string()))?;

            // Verify both the replaced string and the newly added string are present
            assert!(
                strings.contains("ReplacedString"),
                "Replaced string should be present"
            );
            assert!(
                strings.contains("AddedAfterReplacement"),
                "String added after replacement should be present"
            );

            // Verify original strings are not present
            assert!(
                !strings.contains("Task`1"),
                "Original strings should not be present after heap replacement"
            );

            Ok(())
        },
    )
}

/// The text the first `ldstr` of `method` loads in `assembly`.
fn first_loaded_string(assembly: &CilObject, method: Token) -> String {
    let token = assembly
        .method(&method)
        .expect("the method")
        .instructions()
        .find(|instr| instr.mnemonic == "ldstr")
        .and_then(|instr| instr.get_token_operand())
        .expect("an ldstr");
    assembly
        .userstrings()
        .expect("#US")
        .get(token.row() as usize)
        .expect("the string")
        .to_string_lossy()
        .to_string()
}

/// A body a pass replaces keeps loading the strings it loaded. When an earlier user string
/// shrinks, every later one moves; the replaced body's `ldstr` follows its string as the
/// untouched bodies' do.
#[test]
fn a_replaced_body_follows_its_strings_when_the_heap_moves() -> Result<()> {
    let path = fixture("packers/confuserex/1.6.0/original.exe");
    let original = CilObject::from_path(&path)?;

    // A tiny-header method without exception clauses that loads a string other than the
    // first one, which is about to shrink.
    let (method, rva, size) = original
        .methods()
        .iter()
        .filter_map(|entry| {
            let method = entry.value();
            let body = method.body.get()?;
            let first = method
                .instructions()
                .find(|instr| instr.mnemonic == "ldstr")?
                .get_token_operand()?;
            (!body.is_fat && body.exception_handlers.is_empty() && first.row() > 1).then(|| {
                (
                    method.token,
                    method.rva.expect("a body"),
                    body.size_header + body.size_code,
                )
            })
        })
        .next()
        .expect("a method loading a string");
    let expected = first_loaded_string(&original, method);

    let mut assembly = CilAssembly::from_path(&path)?;
    assembly.userstring_update(1, "")?;

    // Replace the body with its own bytes, as a pass that rewrites it would store it.
    let offset = original.file().rva_to_offset(rva as usize)?;
    let body = original.file().data()[offset..offset + size].to_vec();
    let placeholder = assembly.store_method_body(body);
    let mut row = assembly
        .view()
        .tables()
        .unwrap()
        .table::<MethodDefRaw>()
        .unwrap()
        .get(method.row())?
        .expect("the MethodDef row");
    row.rva = placeholder;
    assembly.table_row_update(
        TableId::MethodDef,
        method.row(),
        TableDataOwned::MethodDef(row),
    )?;

    let written = CilObject::from_mem(assembly.to_memory()?)?;
    assert_eq!(first_loaded_string(&written, method), expected);
    Ok(())
}

/// The last row of the table of `$raw` rows in `$view`.
macro_rules! last_row {
    ($view:expr, $raw:ty) => {{
        let table = $view.tables().unwrap().table::<$raw>().unwrap();
        table.get(table.row_count).unwrap().expect("the row")
    }};
}

/// An entry added after a heap was replaced is named where the write puts it: after the
/// replacement's entries. Each replacement holds the original heap and one entry more, so the
/// original rows keep their names and an entry placed as if the original heap were written
/// would land on the extra one. Covers all four heaps: a new type's name, a new signature, a
/// module's new MVID and a new method's string literal.
#[test]
fn entries_added_after_a_heap_replacement_are_named_where_they_are_written() -> Result<()> {
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;
    let view = assembly.view();
    let mut strings = view.strings().unwrap().data().to_vec();
    strings.extend_from_slice(b"ReplacementPadding\0");
    let mut blobs = view.blobs().unwrap().data().to_vec();
    blobs.extend_from_slice(&[0x04, 0xEE, 0xEE, 0xEE, 0xEE]);
    let mut guids = view.guids().unwrap().data().to_vec();
    guids.extend_from_slice(&[0xEE; 16]);
    let mut userstrings = view.userstrings().unwrap().data().to_vec();
    // "pad": a length, three UTF-16 code units and the terminal byte
    userstrings.extend_from_slice(&[0x07, b'p', 0, b'a', 0, b'd', 0, 0]);
    assembly.string_add_heap(strings)?;
    assembly.blob_add_heap(blobs)?;
    assembly.guid_add_heap(guids)?;
    assembly.userstring_add_heap(userstrings)?;

    TypeDefBuilder::new()
        .name("AddedAfterReplacement")
        .namespace("")
        .flags(TypeAttributes::CLASS | TypeAttributes::NOT_PUBLIC)
        .build(&mut assembly)?;
    let signature = [0x06, 0x08];
    StandAloneSigBuilder::new()
        .signature(&signature)
        .build(&mut assembly)?;
    let mvid = [0x5A; 16];
    let mvid_ref = assembly.guid_add(&mvid)?;
    let mut module = last_row!(assembly.view(), ModuleRaw);
    module.mvid = mvid_ref.placeholder();
    assembly.table_row_update(TableId::Module, 1, TableDataOwned::Module(module))?;
    let literal = assembly.userstring_add("LiteralAfterReplacement")?;
    let literal = Token::new(0x7000_0000 | literal.placeholder());
    let method = MethodBuilder::new("LoadsTheLiteral")
        .public()
        .static_method()
        .returns(TypeSignature::String)
        .implementation(move |body| {
            body.implementation(move |asm| {
                asm.ldstr(literal)?.ret()?;
                Ok(())
            })
        })
        .build(&mut assembly)?;

    let bytes = assembly.to_memory()?;
    let method = method.token().expect("the write numbers the new method");
    let view = CilAssemblyView::from_mem(bytes.clone())?;
    let name = last_row!(view, TypeDefRaw).type_name;
    assert_eq!(
        view.strings().unwrap().get(name as usize)?,
        "AddedAfterReplacement"
    );
    let written = last_row!(view, StandAloneSigRaw).signature;
    assert_eq!(view.blobs().unwrap().get(written as usize)?, signature);
    let written = last_row!(view, ModuleRaw).mvid;
    assert_eq!(
        view.guids().unwrap().get(written as usize)?,
        uguid::Guid::from_bytes(mvid)
    );
    let object = CilObject::from_mem(bytes)?;
    assert_eq!(
        first_loaded_string(&object, method),
        "LiteralAfterReplacement"
    );
    Ok(())
}

/// Renaming a string leaves the entries of the other heaps alone, the ones no row names
/// included: a rename is not a request to compact the heaps.
#[test]
fn a_renamed_string_keeps_every_entry_of_the_other_heaps() -> Result<()> {
    // A first write gives the assembly a blob and a GUID no row names
    let mut assembly = CilAssembly::from_path(fixture(TEST_ASSEMBLY_PATH))?;
    let view = assembly.view();
    let mut blobs = view.blobs().unwrap().data().to_vec();
    blobs.extend_from_slice(&[0x02, 0xAA, 0xBB]);
    let mut guids = view.guids().unwrap().data().to_vec();
    guids.extend_from_slice(&[0xEE; 16]);
    assembly.blob_add_heap(blobs)?;
    assembly.guid_add_heap(guids)?;
    let view = CilAssemblyView::from_mem(assembly.to_memory()?)?;
    let guid_count = view.guids().unwrap().iter().count();

    let name = last_row!(view, TypeDefRaw).type_name;
    let mut assembly = CilAssembly::new(view);
    assembly.string_update(name, "RenamedType")?;
    let view = CilAssemblyView::from_mem(assembly.to_memory()?)?;

    assert_eq!(
        view.strings()
            .unwrap()
            .get(last_row!(view, TypeDefRaw).type_name as usize)?,
        "RenamedType"
    );
    assert!(
        view.blobs()
            .unwrap()
            .iter()
            .any(|(_, blob)| blob == [0xAA, 0xBB]),
        "the blob no row names is kept"
    );
    let written: Vec<_> = view.guids().unwrap().iter().map(|(_, guid)| guid).collect();
    assert_eq!(written.len(), guid_count);
    assert_eq!(
        written.last().copied(),
        Some(uguid::Guid::from_bytes([0xEE; 16]))
    );
    Ok(())
}
