#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

//! Integration tests for native import/export functionality.
//!
//! These tests verify the complete end-to-end functionality of adding
//! native PE imports and exports to assemblies, writing them to disk,
//! and ensuring they can be loaded back correctly with the modifications intact.

use std::fs;

use dotscope::{prelude::*, testkit::fixture, DataDirectoryType};

#[test]
fn test_native_imports_with_minimal_changes() -> Result<()> {
    // Test native imports with minimal metadata changes to trigger the write pipeline properly
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    // Add a minimal string to ensure we have some changes
    let _test_string_index = assembly.string_add("TestString")?;

    // Add native imports
    NativeImportsBuilder::new()
        .add_dll("kernel32.dll")?
        .add_function("kernel32.dll", "GetCurrentProcessId")?
        .build(&mut assembly)?;

    // Write to memory
    let bytes = assembly.to_memory()?;
    assert!(!bytes.is_empty(), "Written bytes should not be empty");

    // Load from memory and verify
    match CilAssemblyView::from_mem(bytes) {
        Ok(reloaded_view) => {
            // Verify the import directory exists
            let import_directory = reloaded_view
                .file()
                .get_data_directory(DataDirectoryType::ImportTable);
            assert!(import_directory.is_some(), "Should have import directory");
        }
        Err(e) => {
            panic!("Should have loaded! Error: {e:?}")
        }
    }

    Ok(())
}

#[test]
fn add_native_imports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    // Check if assembly already has native imports
    let _original_has_imports = assembly
        .view()
        .file()
        .get_data_directory(DataDirectoryType::ImportTable)
        .is_some();

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = assembly.string_add("NativeImportTest")?;

    // Step 2: Add native imports using NativeImportsBuilder
    NativeImportsBuilder::new()
        .add_dll("kernel32.dll")?
        .add_function("kernel32.dll", "GetCurrentProcessId")?
        .add_function("kernel32.dll", "ExitProcess")?
        .add_dll("user32.dll")?
        .add_function("user32.dll", "MessageBoxW")?
        .add_function("user32.dll", "GetActiveWindow")?
        .build(&mut assembly)?;

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;
    assert!(!bytes.is_empty(), "Written bytes should not be empty");

    // Step 4: Load the modified bytes and verify native imports
    let modified_view =
        CilAssemblyView::from_mem(bytes).expect("Modified assembly should load successfully");

    // Verify the assembly now has an import directory
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);

    assert!(
        import_directory.is_some(),
        "Modified assembly should have import directory"
    );

    let (import_rva, import_size) = import_directory.unwrap();
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");

    // Step 5: Now verify that our added imports can be parsed back correctly from the PE file
    let parsed_imports = modified_view.file().imports();

    assert!(
        parsed_imports.is_some(),
        "Native imports should be parsed successfully from modified PE file"
    );

    let imports = parsed_imports.unwrap();
    assert!(
        !imports.is_empty(),
        "Should have at least one import descriptor"
    );

    // Verify we have the DLLs we added by checking the import descriptors
    let dll_names: Vec<&str> = imports.iter().map(|imp| &*imp.dll).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll in import table"
    );
    assert!(
        dll_names.contains(&"user32.dll"),
        "Should have user32.dll in import table"
    );

    // Verify the kernel32.dll functions
    let kernel32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| &*imp.dll == "kernel32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        kernel32_functions.len(),
        2,
        "kernel32.dll should have 2 functions"
    );
    assert!(
        kernel32_functions.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_functions.contains(&"ExitProcess"),
        "Should have ExitProcess"
    );

    // Verify the user32.dll functions
    let user32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| &*imp.dll == "user32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        user32_functions.len(),
        2,
        "user32.dll should have 2 functions"
    );
    assert!(
        user32_functions.contains(&"MessageBoxW"),
        "Should have MessageBoxW"
    );
    assert!(
        user32_functions.contains(&"GetActiveWindow"),
        "Should have GetActiveWindow"
    );
    Ok(())
}

#[test]
fn add_native_exports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    // Check if assembly already has native exports
    let _original_has_exports = assembly
        .view()
        .file()
        .get_data_directory(DataDirectoryType::ExportTable)
        .is_some();

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = assembly.string_add("NativeExportTest")?;

    // Step 2: Add native exports using NativeExportsBuilder
    let export_result = NativeExportsBuilder::new("TestLibrary.dll")
        .add_function("TestFunction1", 1, 0x1000)
        .add_function("TestFunction2", 2, 0x2000)
        .add_function("AnotherFunction", 3, 0x3000)
        .build(&mut assembly);

    assert!(
        export_result.is_ok(),
        "Native export builder should succeed"
    );

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;
    assert!(!bytes.is_empty(), "Written bytes should not be empty");

    // Step 4: Load the modified bytes and verify native exports
    let modified_view =
        CilAssemblyView::from_mem(bytes).expect("Modified assembly should load successfully");

    // Verify the assembly now has an export directory
    let export_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable);

    assert!(
        export_directory.is_some(),
        "Modified assembly should have export directory"
    );

    let (export_rva, export_size) = export_directory.unwrap();
    assert!(export_rva > 0, "Export table RVA should be positive");
    assert!(export_size > 0, "Export table size should be positive");

    // Step 5: The exports the loaded image holds
    let reloaded = CilObject::from_mem(modified_view.file().data().to_vec())?;
    let exports = reloaded.exports();

    // Verify the DLL name we set
    assert_eq!(
        exports.native().dll_name(),
        "TestLibrary.dll",
        "Should have correct DLL name"
    );

    // Verify we have the expected number of functions
    assert_eq!(
        exports.native().function_count(),
        3,
        "Should have 3 exported functions"
    );

    // Verify the specific functions we added
    assert!(
        exports.native().has_function("TestFunction1"),
        "Should have TestFunction1"
    );
    assert!(
        exports.native().has_function("TestFunction2"),
        "Should have TestFunction2"
    );
    assert!(
        exports.native().has_function("AnotherFunction"),
        "Should have AnotherFunction"
    );

    // Verify function details
    let func1 = exports.native().get_function_by_ordinal(1).unwrap();
    assert_eq!(
        func1.name,
        Some("TestFunction1".to_string()),
        "TestFunction1 should have correct name"
    );
    assert_eq!(
        func1.address, 0x1000,
        "TestFunction1 should have correct address"
    );
    assert_eq!(
        func1.ordinal, 1,
        "TestFunction1 should have correct ordinal"
    );

    let func2 = exports.native().get_function_by_ordinal(2).unwrap();
    assert_eq!(
        func2.name,
        Some("TestFunction2".to_string()),
        "TestFunction2 should have correct name"
    );
    assert_eq!(
        func2.address, 0x2000,
        "TestFunction2 should have correct address"
    );
    assert_eq!(
        func2.ordinal, 2,
        "TestFunction2 should have correct ordinal"
    );

    let func3 = exports.native().get_function_by_ordinal(3).unwrap();
    assert_eq!(
        func3.name,
        Some("AnotherFunction".to_string()),
        "AnotherFunction should have correct name"
    );
    assert_eq!(
        func3.address, 0x3000,
        "AnotherFunction should have correct address"
    );
    assert_eq!(
        func3.ordinal, 3,
        "AnotherFunction should have correct ordinal"
    );

    // All added exports verified successfully

    Ok(())
}

#[test]
fn add_both_imports_and_exports_to_crafted_2() -> Result<()> {
    // Step 1: Load the original assembly
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = assembly.string_add("MixedNativeTest")?;

    // Step 2: Add both native imports and exports

    // Add imports
    NativeImportsBuilder::new()
        .add_dll("kernel32.dll")?
        .add_function("kernel32.dll", "GetCurrentProcessId")?
        .add_function("kernel32.dll", "GetModuleHandleW")?
        .build(&mut assembly)?;

    // Add exports
    let export_result = NativeExportsBuilder::new("MixedLibrary.dll")
        .add_function("ExportedFunction1", 1, 0x1000)
        .add_function("ExportedFunction2", 2, 0x2000)
        .build(&mut assembly);

    assert!(
        export_result.is_ok(),
        "Native export builder should succeed"
    );

    // Step 3: Write to memory
    let bytes = assembly.to_memory()?;
    assert!(!bytes.is_empty(), "Written bytes should not be empty");

    // Step 4: Load the modified bytes and verify both imports and exports
    let modified_view =
        CilAssemblyView::from_mem(bytes).expect("Modified assembly should load successfully");

    // Verify import directory
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);
    assert!(
        import_directory.is_some(),
        "Modified assembly should have import directory"
    );

    // Verify export directory
    let export_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ExportTable);
    assert!(
        export_directory.is_some(),
        "Modified assembly should have export directory"
    );

    let (import_rva, import_size) = import_directory.unwrap();
    let (export_rva, export_size) = export_directory.unwrap();

    // Verify both directories were created successfully
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");
    assert!(export_rva > 0, "Export table RVA should be positive");
    assert!(export_size > 0, "Export table size should be positive");

    // Step 5: Now verify that both imports and exports can be parsed back correctly

    // Verify imports using the file's parsed imports
    let parsed_imports = modified_view.file().imports();

    // Import table generation should work correctly
    assert!(
        parsed_imports.is_some(),
        "Native imports should be parsed successfully from modified PE file with both imports and exports"
    );

    let imports = parsed_imports.unwrap();
    assert!(
        !imports.is_empty(),
        "Should have at least one import descriptor"
    );

    // Verify we have kernel32.dll
    let dll_names: Vec<&str> = imports.iter().map(|imp| &*imp.dll).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll in import table"
    );

    let kernel32_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| &*imp.dll == "kernel32.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert_eq!(
        kernel32_functions.len(),
        2,
        "kernel32.dll should have 2 functions"
    );
    assert!(
        kernel32_functions.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_functions.contains(&"GetModuleHandleW"),
        "Should have GetModuleHandleW"
    );

    // Verify exports using the file's parsed exports
    let parsed_exports = modified_view.file().exports();

    let exports = parsed_exports.expect("the written export table reads back");
    assert_eq!(exports.len(), 2, "Should have 2 exported functions");

    // Find the exported functions by name
    let exported_names: Vec<&str> = exports
        .iter()
        .filter_map(|exp| exp.name.as_deref())
        .collect();

    assert!(
        exported_names.contains(&"ExportedFunction1"),
        "Should have ExportedFunction1"
    );
    assert!(
        exported_names.contains(&"ExportedFunction2"),
        "Should have ExportedFunction2"
    );

    // Verify specific function details
    let func1 = exports
        .iter()
        .find(|exp| exp.name.as_deref() == Some("ExportedFunction1"))
        .unwrap();
    assert_eq!(
        func1.name.as_ref().unwrap(),
        "ExportedFunction1",
        "ExportedFunction1 should have correct name"
    );

    let func2 = exports
        .iter()
        .find(|exp| exp.name.as_deref() == Some("ExportedFunction2"))
        .unwrap();
    assert_eq!(
        func2.name.as_ref().unwrap(),
        "ExportedFunction2",
        "ExportedFunction2 should have correct name"
    );

    // All added imports and exports verified successfully

    Ok(())
}

#[test]
fn round_trip_preserve_existing_data() -> Result<()> {
    // This test verifies that adding native imports/exports doesn't corrupt existing assembly data

    // Step 1: Load the original assembly and capture baseline data
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    let original_string_count = assembly
        .view()
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let original_method_count = assembly
        .view()
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Add a minimal metadata change to ensure write pipeline works properly
    let _test_string_index = assembly.string_add("PreserveDataTest")?;

    // Step 2: Add native functionality
    NativeImportsBuilder::new()
        .add_dll("kernel32.dll")?
        .add_function("kernel32.dll", "GetCurrentProcessId")?
        .build(&mut assembly)?;

    // Step 3: Write to memory and reload
    let bytes = assembly.to_memory()?;

    let modified_view =
        CilAssemblyView::from_mem(bytes).expect("Modified assembly should load successfully");

    // Step 4: Verify existing data is preserved

    // Check that original metadata is intact
    let new_string_count = modified_view
        .strings()
        .map(|s| s.iter().count())
        .unwrap_or(0);
    let new_method_count = modified_view
        .tables()
        .map(|t| t.table_row_count(TableId::MethodDef))
        .unwrap_or(0);

    // Original data should be preserved (may have slight increases due to internal bookkeeping)
    assert!(
        new_string_count >= original_string_count,
        "String count should be preserved or slightly increased"
    );
    assert_eq!(
        new_method_count, original_method_count,
        "Method count should be exactly preserved"
    );

    // Verify the assembly is still a valid .NET assembly
    let _metadata_root = modified_view.metadata_root(); // Should not panic
    assert!(
        modified_view.tables().is_some(),
        "Should still have metadata tables"
    );
    assert!(
        modified_view.strings().is_some(),
        "Should still have strings heap"
    );

    // Verify that an import directory was created (indicating native imports were written)
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);
    assert!(
        import_directory.is_some(),
        "Should have import directory indicating native imports were written"
    );

    Ok(())
}

#[test]
fn test_native_imports_parsing_from_existing_pe() -> Result<()> {
    // Test that existing native imports are correctly parsed when loading a CilAssemblyView
    // This test verifies the implementation of PE import/export parsing functionality

    let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))?;

    // Verify that native imports are accessible from the PE file
    // Note: With copy-on-write semantics, assembly.native_imports() only returns user modifications.
    // To access the original PE imports, we use the file's parsed imports.
    let parsed_imports = view.file().imports();
    assert!(
        parsed_imports.is_some(),
        "Should have parsed native imports from existing PE file"
    );

    let imports = parsed_imports.unwrap();
    assert!(!imports.is_empty(), "Parsed imports should not be empty");

    // Verify the specific import that should exist in crafted_2.exe
    let dll_names: Vec<&str> = imports.iter().map(|imp| &*imp.dll).collect();
    assert!(
        dll_names.contains(&"mscoree.dll"),
        "Should have parsed mscoree.dll"
    );

    let mscoree_functions: Vec<&str> = imports
        .iter()
        .filter(|imp| &*imp.dll == "mscoree.dll")
        .filter_map(|imp| imp.name.as_deref())
        .collect();

    assert!(
        !mscoree_functions.is_empty(),
        "mscoree.dll should have functions"
    );

    // Verify the _CorExeMain function exists
    let has_cor_exe_main = mscoree_functions.contains(&"_CorExeMain");
    assert!(has_cor_exe_main, "Should have parsed _CorExeMain function");

    Ok(())
}

#[test]
fn test_import_table_format_validation() -> Result<()> {
    // Test that import tables are correctly formatted and parseable

    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe"))?;

    // Add imports that should generate a valid import table
    let _test_string_index = assembly.string_add("ImportFormatTest")?;

    NativeImportsBuilder::new()
        .add_dll("kernel32.dll")?
        .add_function("kernel32.dll", "GetCurrentProcessId")?
        .add_function("kernel32.dll", "ExitProcess")?
        .add_dll("user32.dll")?
        .add_function("user32.dll", "MessageBoxW")?
        .add_function("user32.dll", "GetActiveWindow")?
        .build(&mut assembly)?;

    // Write to memory
    let bytes = assembly.to_memory()?;

    let modified_view = CilAssemblyView::from_mem(bytes)?;

    // Verify import directory exists and is valid
    let import_directory = modified_view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable);

    assert!(import_directory.is_some(), "Import directory should exist");

    let (import_rva, import_size) = import_directory.unwrap();
    assert!(import_rva > 0, "Import table RVA should be positive");
    assert!(import_size > 0, "Import table size should be positive");

    // Verify the import table can be read
    let import_offset = modified_view.file().rva_to_offset(import_rva as usize)?;
    let import_data = modified_view
        .file()
        .data_slice(import_offset, import_size as usize)?;
    assert!(
        !import_data.is_empty(),
        "Import table data should not be empty"
    );

    // Verify goblin can parse the generated PE with imports
    let pe = goblin::pe::PE::parse(modified_view.file().data())
        .expect("Goblin should successfully parse PE with generated import table");

    // Verify the specific imports we added are present and correct
    assert!(!pe.imports.is_empty(), "Should have imports in parsed PE");

    let dll_names: Vec<&str> = pe.imports.iter().map(|imp| imp.dll).collect();
    assert!(
        dll_names.contains(&"kernel32.dll"),
        "Should have kernel32.dll"
    );
    assert!(dll_names.contains(&"user32.dll"), "Should have user32.dll");

    let kernel32_funcs: Vec<&str> = pe
        .imports
        .iter()
        .filter(|imp| imp.dll == "kernel32.dll")
        .map(|imp| imp.name.as_ref())
        .collect();

    assert!(
        kernel32_funcs.contains(&"GetCurrentProcessId"),
        "Should have GetCurrentProcessId"
    );
    assert!(
        kernel32_funcs.contains(&"ExitProcess"),
        "Should have ExitProcess"
    );

    let user32_funcs: Vec<&str> = pe
        .imports
        .iter()
        .filter(|imp| imp.dll == "user32.dll")
        .map(|imp| imp.name.as_ref())
        .collect();

    assert!(
        user32_funcs.contains(&"MessageBoxW"),
        "Should have MessageBoxW"
    );
    assert!(
        user32_funcs.contains(&"GetActiveWindow"),
        "Should have GetActiveWindow"
    );

    Ok(())
}

/// An export as a written image reads it back: `(name, ordinal, rva, forwarder)`, a
/// forwarder's RVA left out (it moves with the table).
type ReadExport = (Option<String>, u16, Option<u32>, Option<String>);

/// What `bytes`' export directory reads back as: its header, and its exports, sorted.
fn read_exports(bytes: &[u8]) -> (Option<PeExportHeader>, Vec<ReadExport>) {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).unwrap();
    let pe = view.file().pe();
    assert_eq!(pe.export_error, None, "the export table reads in full");
    let mut exports: Vec<ReadExport> = pe
        .exports
        .iter()
        .map(|export| {
            (
                export.name.clone(),
                export.ordinal,
                export.forwarder.is_none().then_some(export.rva),
                export.forwarder.clone(),
            )
        })
        .collect();
    exports.sort();
    (pe.export_header.clone(), exports)
}

/// `bytes` written back unchanged.
fn rewritten(bytes: &[u8]) -> Vec<u8> {
    CilAssembly::new(CilAssemblyView::from_mem(bytes.to_vec()).unwrap())
        .to_memory()
        .unwrap()
}

/// The file offset of `rva` in `bytes`.
fn offset_of(bytes: &[u8], rva: u32) -> usize {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).unwrap();
    view.file().rva_to_offset(rva as usize).unwrap()
}

/// The file offset of `bytes`' `kind` directory.
fn directory_offset(bytes: &[u8], kind: DataDirectoryType) -> usize {
    let view = CilAssemblyView::from_mem(bytes.to_vec()).unwrap();
    let (rva, _) = view.file().get_data_directory(kind).unwrap();
    view.file().rva_to_offset(rva as usize).unwrap()
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn patch_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// crafted_2.exe exporting `First` at ordinal 1, a forwarder `Forwarded` at 2, and ordinal 4
/// without a name.
fn with_exports() -> Vec<u8> {
    let mut assembly = CilAssembly::from_path(fixture("crafted_2.exe")).unwrap();
    NativeExportsBuilder::new("TestLibrary.dll")
        .add_function("First", 1, 0x1000)
        .add_forwarder("Forwarded", 2, "Other.dll.Target")
        .add_function_by_ordinal(4, 0x2000)
        .build(&mut assembly)
        .unwrap();
    assembly.to_memory().unwrap()
}

/// Each export reads back with its own ordinal, and a second write keeps every one. The
/// exports were goblin's, which lists only named exports and has no ordinals: an export
/// without a name was dropped, and each ordinal was taken from the file offset.
#[test]
fn native_exports_keep_their_ordinals_through_a_second_write() {
    let first = with_exports();
    let (header, exports) = read_exports(&first);
    let header = header.expect("the image has an export directory");
    assert_eq!((header.name.as_str(), header.base), ("TestLibrary.dll", 1));
    assert_eq!(
        exports,
        vec![
            (None, 4, Some(0x2000), None),
            (Some("First".into()), 1, Some(0x1000), None),
            (
                Some("Forwarded".into()),
                2,
                None,
                Some("Other.dll.Target".into())
            ),
        ]
    );

    let object = CilObject::from_mem(first.clone()).unwrap();
    let native = object.exports().native();
    assert_eq!(native.dll_name(), "TestLibrary.dll");
    assert_eq!(
        native.get_function_by_ordinal(4).map(|f| f.address),
        Some(0x2000)
    );
    assert_eq!(
        native
            .get_forwarder_by_ordinal(2)
            .map(|f| f.target.as_str()),
        Some("Other.dll.Target")
    );

    assert_eq!(read_exports(&rewritten(&first)), read_exports(&first));
}

/// An ordinal under two names, and ordinal base 0, which makes the first slot ordinal 0,
/// read back and survive a write.
#[test]
fn export_aliases_and_ordinal_zero_survive_a_write() {
    let mut bytes = with_exports();
    let directory = directory_offset(&bytes, DataDirectoryType::ExportTable);
    patch_u32(&mut bytes, directory + 16, 0);
    // The names are sorted, "First" then "Forwarded": the second takes the first's slot
    let ordinals = offset_of(&bytes, read_u32(&bytes, directory + 36));
    let slot = [bytes[ordinals], bytes[ordinals + 1]];
    bytes[ordinals + 2..ordinals + 4].copy_from_slice(&slot);

    let (_, exports) = read_exports(&bytes);
    assert_eq!(
        exports,
        vec![
            (None, 1, None, Some("Other.dll.Target".into())),
            (None, 3, Some(0x2000), None),
            (Some("First".into()), 0, Some(0x1000), None),
            (Some("Forwarded".into()), 0, Some(0x1000), None),
        ]
    );
    assert_eq!(read_exports(&rewritten(&bytes)), read_exports(&bytes));
}

/// An export directory that lists no exports is written back under its name: the writer
/// dropped it.
#[test]
fn an_empty_export_directory_is_kept() {
    let mut bytes = with_exports();
    let directory = directory_offset(&bytes, DataDirectoryType::ExportTable);
    patch_u32(&mut bytes, directory + 20, 0);
    patch_u32(&mut bytes, directory + 24, 0);

    let (header, exports) = read_exports(&bytes);
    assert!(header.is_some() && exports.is_empty());
    assert_eq!(read_exports(&rewritten(&bytes)), (header, exports));
}

/// An export table that cannot be read in full loads, and is not written back without what
/// could not be read.
#[test]
fn an_unreadable_export_table_is_not_rebuilt() {
    let mut bytes = with_exports();
    let directory = directory_offset(&bytes, DataDirectoryType::ExportTable);
    // The DLL's name, at no RVA of the image
    patch_u32(&mut bytes, directory + 12, 0x7FFF_FFF0);

    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    assert!(view.file().pe().export_error.is_some());
    CilObject::from_mem(bytes).expect("the image loads");
    assert!(CilAssembly::new(view).to_memory().is_err());
}

/// crafted_2.exe's import reads as the loader reads it: mscoree.dll's `_CorExeMain` by name
/// (with no ordinal), its hint from the entry its lookup table names, at its import address
/// table slot. A descriptor without a lookup table is read from its import address table.
#[test]
fn an_import_reads_by_name_with_its_hint() {
    let bytes = fs::read(fixture("crafted_2.exe")).unwrap();
    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    let pe = view.file().pe();
    assert_eq!(pe.import_error, None);
    assert_eq!(pe.imports.len(), 1);
    let import = &pe.imports[0];
    assert_eq!(
        (&*import.dll, import.name.as_deref(), import.ordinal),
        ("mscoree.dll", Some("_CorExeMain"), None)
    );
    let (iat, _) = view
        .file()
        .get_data_directory(DataDirectoryType::ImportAddressTable)
        .unwrap();
    assert_eq!(import.rva, iat);
    let entry = offset_of(&bytes, u32::try_from(import.ilt_value).unwrap());
    assert_eq!(
        import.hint,
        u16::from_le_bytes([bytes[entry], bytes[entry + 1]])
    );

    let mut without_lookup = bytes.clone();
    let directory = directory_offset(&bytes, DataDirectoryType::ImportTable);
    patch_u32(&mut without_lookup, directory, 0);
    let view = CilAssemblyView::from_mem(without_lookup).unwrap();
    let read = &view.file().pe().imports;
    assert_eq!(read.len(), 1);
    assert_eq!(
        (read[0].name.as_deref(), read[0].rva),
        (Some("_CorExeMain"), import.rva)
    );
}

/// An import table with an entry that cannot be read loads, but is not written back: the
/// writer wrote the table without the entries goblin skipped, and without the table when it
/// skipped them all.
#[test]
fn an_unreadable_import_table_is_not_rebuilt() {
    let mut bytes = fs::read(fixture("crafted_2.exe")).unwrap();
    let directory = directory_offset(&bytes, DataDirectoryType::ImportTable);
    let lookup = offset_of(&bytes, read_u32(&bytes, directory));
    // The hint/name entry's RVA, at no RVA of the image
    patch_u32(&mut bytes, lookup, 0x7FFF_FFF0);

    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    assert!(view.file().pe().import_error.is_some());
    CilObject::from_mem(bytes).expect("the image loads");
    assert!(CilAssembly::new(view).to_memory().is_err());
}

/// An import table that names no import is written back as a table: the writer dropped the
/// import directory when it read no import, where the image has one.
#[test]
fn an_empty_import_table_is_kept() {
    let mut bytes = fs::read(fixture("crafted_2.exe")).unwrap();
    let directory = directory_offset(&bytes, DataDirectoryType::ImportTable);
    // The descriptor's name: the walk ends at it
    patch_u32(&mut bytes, directory + 12, 0);

    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    assert!(view.file().pe().imports.is_empty());
    assert_eq!(view.file().pe().import_error, None);
    let written = rewritten(&bytes);
    let view = CilAssemblyView::from_mem(written).unwrap();
    assert!(view
        .file()
        .get_data_directory(DataDirectoryType::ImportTable)
        .is_some_and(|(rva, _)| rva != 0));
}

/// An import directory whose size reads 0 (BitMono writes it so) is written back: the loader
/// goes by its RVA, and the writer dropped it.
#[test]
fn an_import_directory_of_size_zero_is_kept() {
    let mut bytes = fs::read(fixture("crafted_2.exe")).unwrap();
    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    let pe_offset = u32::from_le_bytes(bytes[0x3C..0x40].try_into().unwrap()) as usize;
    let directories = pe_offset + 24 + if view.file().pe().is_64bit { 112 } else { 96 };
    // The import directory is the second; its size follows its RVA
    patch_u32(&mut bytes, directories + 8 + 4, 0);

    let view = CilAssemblyView::from_mem(bytes.clone()).unwrap();
    assert_eq!(view.file().pe().imports.len(), 1);
    let written = rewritten(&bytes);
    let view = CilAssemblyView::from_mem(written).unwrap();
    assert_eq!(
        view.file()
            .pe()
            .imports
            .iter()
            .map(|import| import.name.as_deref())
            .collect::<Vec<_>>(),
        vec![Some("_CorExeMain")]
    );
}
