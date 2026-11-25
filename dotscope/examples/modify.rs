//! # .NET Assembly Modification Example
//!
//! **What this example teaches:**
//! - Loading assemblies for modification using `CilAssemblyView` and `CilAssembly`
//! - Adding and modifying heap content (strings, blobs, GUIDs, user strings)
//! - Using the high-level builder APIs (TypeDefBuilder, FieldBuilder, etc.)
//! - Adding native imports and exports for P/Invoke scenarios
//! - Proper validation and error handling for assembly modifications
//! - Writing modified assemblies to disk with full PE compliance
//!
//! **When to use this pattern:**
//! - Building .NET assembly editing tools
//! - Automated assembly patching and instrumentation
//! - Adding metadata for analysis frameworks
//! - Implementing code injection or hooking utilities
//! - Educational purposes to understand .NET assembly structure
//!
//! **Prerequisites:**
//! - Understanding of .NET metadata structures
//! - Familiarity with ECMA-335 specification concepts
//! - Basic knowledge of P/Invoke and native interoperability

use std::{env, path::Path};

use dotscope::{
    metadata::{
        signatures::TypeSignature,
        tables::{CodedIndex, CodedIndexType, FieldAttributes, TableId, TypeAttributes},
    },
    prelude::*,
    CilAssembly, CilAssemblyView,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map_or("modify", String::as_str);
    let (Some(source_arg), Some(output_arg)) = (args.get(1), args.get(2)) else {
        eprintln!("Usage: {prog} <source-assembly> <output-assembly>");
        eprintln!();
        eprintln!("This example demonstrates comprehensive .NET assembly modification:");
        eprintln!("  - Adding strings, blobs, GUIDs, and user strings to heaps");
        eprintln!("  - Using high-level builder APIs for type and method creation");
        eprintln!("  - Adding native imports for P/Invoke scenarios");
        eprintln!("  - Validating changes and writing modified assembly");
        eprintln!();
        eprintln!("Example:");
        eprintln!("  {prog} input.dll modified.dll");
        return Ok(());
    };

    let source_path = Path::new(source_arg);
    let output_path = Path::new(output_arg);

    println!(".NET Assembly Modification Tool");
    println!("Source: {}", source_path.display());
    println!("Output: {}", output_path.display());
    println!();

    // Load the assembly for modification
    println!("Loading assembly for modification...");
    let view = match CilAssemblyView::from_path(source_path) {
        Ok(view) => view,
        Err(e) => {
            eprintln!("x Failed to load assembly: {e}");
            eprintln!();
            eprintln!("Common causes:");
            eprintln!("  - File is not a valid .NET assembly");
            eprintln!("  - File is corrupted or in an unsupported format");
            eprintln!("  - Insufficient permissions to read the file");
            return Err(e);
        }
    };

    // Create mutable assembly for editing
    let mut assembly = CilAssembly::new(view);
    println!("  Assembly loaded successfully");
    println!();

    // Heap Modifications
    // Note: All add operations return ChangeRefRc which holds a reference to the
    // pending change. The actual heap offsets are resolved during write.
    // Use placeholder() when you need a u32 value for table row fields.

    println!("HEAP MODIFICATIONS");
    println!("==================");

    // Add strings to the string heap
    println!("Adding strings to #Strings heap...");
    let hello_ref = assembly.string_add("Hello from modified assembly!")?;
    let _debug_ref = assembly.string_add("DEBUG_MODIFIED")?;
    let _version_ref = assembly.string_add("v2.0.0-modified")?;
    println!("  Queued 3 strings for addition");

    // Add blobs to the blob heap
    println!("Adding blobs to #Blob heap...");
    let signature_blob = vec![0x07, 0x01, 0x0E]; // Sample method signature blob
    let custom_data_blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
    let _signature_ref = assembly.blob_add(&signature_blob)?;
    let _custom_data_ref = assembly.blob_add(&custom_data_blob)?;
    println!("  Queued 2 blobs for addition");

    // Add GUIDs to the GUID heap
    println!("Adding GUIDs to #GUID heap...");
    let module_guid = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];
    let type_guid = [
        0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F,
        0x90,
    ];
    let _module_guid_ref = assembly.guid_add(&module_guid)?;
    let _type_guid_ref = assembly.guid_add(&type_guid)?;
    println!("  Queued 2 GUIDs for addition");

    // Add user strings to the user string heap
    println!("Adding user strings to #US heap...");
    let _user_message_ref = assembly.userstring_add("This assembly has been modified!")?;
    let _user_warning_ref = assembly.userstring_add("WARNING: MODIFIED ASSEMBLY")?;
    println!("  Queued 2 user strings for addition");
    println!();

    // Native Import Management
    println!("NATIVE IMPORT MANAGEMENT");
    println!("========================");

    // Add native DLL imports
    println!("Adding native DLL imports...");
    assembly.add_native_import_dll("kernel32.dll")?;
    assembly.add_native_import_dll("user32.dll")?;
    assembly.add_native_import_dll("advapi32.dll")?;
    println!("  Added kernel32.dll, user32.dll, advapi32.dll");

    // Add native function imports
    println!("Adding native function imports...");
    assembly.add_native_import_function("kernel32.dll", "GetCurrentProcessId")?;
    assembly.add_native_import_function("kernel32.dll", "ExitProcess")?;
    assembly.add_native_import_function("user32.dll", "MessageBoxW")?;
    assembly.add_native_import_function("advapi32.dll", "RegOpenKeyExW")?;
    println!("  Added 4 function imports");

    // Add ordinal-based imports
    println!("Adding ordinal-based imports...");
    assembly.add_native_import_function_by_ordinal("user32.dll", 120)?;
    println!("  Added ordinal import (120 from user32.dll)");
    println!();

    // Using High-Level Builder APIs
    println!("METADATA TABLE OPERATIONS (Using Builder APIs)");
    println!("===============================================");

    // Create assembly reference for System.Runtime (needed for base types)
    println!("Creating assembly reference for System.Runtime...");
    let system_runtime_ref = AssemblyRefBuilder::new()
        .name("System.Runtime")
        .version(8, 0, 0, 0)
        .public_key_token(&[0xb0, 0x3f, 0x5f, 0x7f, 0x11, 0xd5, 0x0a, 0x3a])
        .build(&mut assembly)?;
    println!("  Created System.Runtime reference");

    // Create type reference for System.Object (base class for our new type)
    println!("Creating type reference for System.Object...");
    let object_typeref = TypeRefBuilder::new()
        .name("Object")
        .namespace("System")
        .resolution_scope(CodedIndex::new(
            TableId::AssemblyRef,
            system_runtime_ref.placeholder(),
            CodedIndexType::ResolutionScope,
        ))
        .build(&mut assembly)?;
    println!("  Created System.Object reference");

    // Add a new type using TypeDefBuilder
    println!("Adding new type 'DotScopeModifiedClass'...");
    let new_type_ref = TypeDefBuilder::new()
        .name("DotScopeModifiedClass")
        .namespace("DotScope.Generated")
        .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS | TypeAttributes::SEALED)
        .extends(CodedIndex::new(
            TableId::TypeRef,
            object_typeref.placeholder(),
            CodedIndexType::TypeDefOrRef,
        ))
        .build(&mut assembly)?;
    println!(
        "  Created type with placeholder token: {:#x}",
        new_type_ref.placeholder()
    );

    // Add a field to our new type
    println!("Adding field 'ModificationTimestamp'...");
    let field_signature = &[0x06, 0x08]; // Field signature: FIELD, ELEMENT_TYPE_I4 (int32)
    let _field_ref = FieldBuilder::new()
        .name("ModificationTimestamp")
        .flags(FieldAttributes::PUBLIC | FieldAttributes::STATIC)
        .signature(field_signature)
        .build(&mut assembly)?;
    println!("  Created static int field");

    // Add a simple method using MethodBuilder
    println!("Adding method 'GetModificationInfo'...");
    let _method_ref = MethodBuilder::new("GetModificationInfo")
        .public()
        .static_method()
        .returns(TypeSignature::I4)
        .implementation(|body| {
            body.implementation(|asm| {
                // Simple method that returns a constant value
                asm.ldc_i4(42)? // Load constant 42
                    .ret()?; // Return
                Ok(())
            })
        })
        .build(&mut assembly)?;
    println!("  Created static method returning int");
    println!();

    // Assembly Writing
    println!("WRITING ASSEMBLY");
    println!("================");

    // Write the modified assembly
    println!("Writing modified assembly to disk...");
    match assembly.to_file(output_path) {
        Ok(()) => {
            println!(
                "  Successfully wrote modified assembly to {}",
                output_path.display()
            );
        }
        Err(e) => {
            eprintln!("x Failed to write assembly: {e}");
            eprintln!();
            eprintln!("Common write issues:");
            eprintln!("  - Insufficient disk space or permissions");
            eprintln!("  - Invalid output path");
            eprintln!("  - PE structure generation errors");
            return Err(e);
        }
    }
    println!();

    // Verification
    println!("VERIFICATION");
    println!("============");

    // Re-load the written assembly to verify it's valid
    println!("Verifying the modified assembly can be loaded...");
    let verify_view = CilAssemblyView::from_path(output_path)?;
    println!("  Assembly loaded successfully");

    // Verify the string heap contains our added strings using the resolved offsets
    if let Some(strings) = verify_view.strings() {
        // After write, the ChangeRef has its offset resolved
        if let Some(offset) = hello_ref.offset() {
            match strings.get(offset as usize) {
                Ok(value) => {
                    let expected = "Hello from modified assembly!";
                    if value == expected {
                        println!("  ✓ Verified string at offset {:#x}: \"{}\"", offset, value);
                    } else {
                        println!(
                            "  ✗ String mismatch at offset {:#x}: expected \"{}\", got \"{}\"",
                            offset, expected, value
                        );
                    }
                }
                Err(e) => {
                    println!("  ✗ Failed to read string at offset {:#x}: {}", offset, e);
                }
            }
        } else {
            println!("  ✗ String offset was not resolved after write");
        }
    }

    // Verify our new type was added
    if let Some(tables) = verify_view.tables() {
        if let Some(typedef_table) = tables.table::<dotscope::metadata::tables::TypeDefRaw>() {
            // A row that fails to parse is not a match; the iterator reports it as `Err`.
            let found_type = typedef_table.iter().flatten().any(|t| {
                verify_view.strings().is_some_and(|s| {
                    s.get(t.type_name as usize)
                        .is_ok_and(|name| name == "DotScopeModifiedClass")
                })
            });
            if found_type {
                println!("  Found 'DotScopeModifiedClass' type definition");
            }
        }
    }
    println!();

    // Summary
    println!("MODIFICATION SUMMARY");
    println!("====================");
    println!("Successfully demonstrated:");
    println!("  - String heap modifications");
    println!("  - Blob heap operations");
    println!("  - GUID heap management");
    println!("  - User string heap operations");
    println!("  - Native import additions");
    println!("  - High-level builder APIs (TypeDefBuilder, FieldBuilder, MethodBuilder)");
    println!("  - Modified assembly generation");
    println!();

    println!("NEXT STEPS");
    println!("==========");
    println!("  - Verify the modified assembly with tools like:");
    println!("    ildasm.exe (Microsoft IL Disassembler)");
    println!("    dotPeek (JetBrains .NET Decompiler)");
    println!("    PEBear (PE structure analyzer)");
    println!("  - Test loading the modified assembly in .NET runtime");
    println!();

    println!("IMPORTANT NOTES");
    println!("===============");
    println!("  - Modified assemblies may not load if metadata integrity is violated");
    println!("  - Always validate assemblies before deployment");
    println!("  - Backup original assemblies before modification");
    println!("  - Some modifications may require code signing updates");

    Ok(())
}
