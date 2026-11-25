//! Factory methods for system assembly validation testing.
//!
//! Contains helper methods migrated from system assembly validation source files
//! for creating test assemblies with various assembly validation scenarios.

use crate::{
    metadata::{
        tables::{AssemblyRaw, TableDataOwned, TableId},
        token::Token,
    },
    testkit::{create_test_assembly, get_testfile_mscorlib, Expect, TestAssembly},
    Error, Result,
};

/// Test factory for OwnedAssemblyValidator following the golden pattern.
///
/// Creates test assemblies covering all assembly validation rules:
/// 1. Clean assembly (should pass)
/// 2. Assembly with empty name
/// 3. Assembly with invalid name format (invalid characters)
/// 4. Assembly with maximum valid version numbers (should pass)
/// 5. Assembly with invalid culture format
///
/// This follows the same pattern as raw validators: create corrupted raw assemblies
/// that when loaded by CilObject produce the assembly violations that the owned
/// validator should detect in the resolved metadata structures.
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn owned_assembly_validator_file_factory() -> Result<Vec<TestAssembly>> {
    let mut assemblies = Vec::new();

    let clean_testfile = get_testfile_mscorlib();

    // 1. REQUIRED: Clean assembly - should pass all assembly validation
    assemblies.push(TestAssembly::new(&clean_testfile));

    // 2. NEGATIVE: Test assembly with empty name
    assemblies.push(create_assembly_with_empty_name()?);

    // 3. POSITIVE: An assembly name with characters a file name cannot hold
    assemblies.push(create_assembly_with_unusual_name()?);

    // 4. BOUNDARY: Test assembly with maximum valid version numbers (should pass)
    assemblies.push(create_assembly_with_maximum_version_numbers()?);

    // 5. POSITIVE: A culture with a script subtag
    assemblies.push(create_assembly_with_script_culture()?);

    // Note: Other test cases (cross-assembly references, module file consistency)
    // require more complex assembly manipulation and will be added incrementally

    Ok(assemblies)
}

/// Creates an assembly with empty name - validation should fail
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_empty_name() -> Result<TestAssembly> {
    create_test_assembly(
        get_testfile_mscorlib,
        Expect::fail("Assembly has empty name"),
        |assembly| {
            // Create assembly with empty name
            let empty_name_index = assembly
                .string_add("")
                .map_err(|e| Error::Other(format!("Failed to add empty assembly name: {e}")))?;

            let assembly_rid = 1; // Assembly table always has RID 1

            let invalid_assembly = AssemblyRaw {
                rid: assembly_rid,
                token: Token::new(0x20000000 + assembly_rid),
                offset: 0,
                hash_alg_id: 0x8004, // SHA1
                major_version: 1,
                minor_version: 0,
                build_number: 0,
                revision_number: 0,
                flags: 0,
                public_key: 0,
                name: empty_name_index.placeholder(), // Empty name - should trigger validation failure
                culture: 0,
            };

            assembly
                .table_row_update(
                    TableId::Assembly,
                    1,
                    TableDataOwned::Assembly(invalid_assembly),
                )
                .map_err(|e| Error::Other(format!("Failed to update invalid assembly: {e}")))?;

            Ok(())
        },
    )
}

/// Creates an assembly whose name holds `/` and `*`: ECMA-335 requires only a non-empty
/// name, so it is valid.
pub fn create_assembly_with_unusual_name() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        // Create assembly name with invalid characters (contains /)
        let invalid_name = "Invalid/Assembly*Name";
        let invalid_name_index = assembly
            .string_add(invalid_name)
            .map_err(|e| Error::Other(format!("Failed to add invalid assembly name: {e}")))?;

        let assembly_rid = 1;

        let invalid_assembly = AssemblyRaw {
            rid: assembly_rid,
            token: Token::new(0x20000000 + assembly_rid),
            offset: 0,
            hash_alg_id: 0x8004, // SHA1
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key: 0,
            name: invalid_name_index.placeholder(), // Invalid name format - should trigger validation failure
            culture: 0,
        };

        assembly
            .table_row_update(
                TableId::Assembly,
                1,
                TableDataOwned::Assembly(invalid_assembly),
            )
            .map_err(|e| Error::Other(format!("Failed to update invalid assembly: {e}")))?;

        Ok(())
    })
}

/// Creates an assembly with maximum valid version numbers - validation should pass
///
/// Originally from: `src/metadata/validation/validators/owned/system/assembly.rs`
pub fn create_assembly_with_maximum_version_numbers() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        // Create valid assembly name
        let assembly_name_index = assembly
            .string_add("ValidAssemblyName")
            .map_err(|e| Error::Other(format!("Failed to add assembly name: {e}")))?;

        let assembly_rid = 1;

        let valid_assembly = AssemblyRaw {
            rid: assembly_rid,
            token: Token::new(0x20000000 + assembly_rid),
            offset: 0,
            hash_alg_id: 0x8004, // SHA1
            major_version: 999,  // Max before suspicious threshold - should be valid
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key: 0,
            name: assembly_name_index.placeholder(),
            culture: 0,
        };

        assembly
            .table_row_update(
                TableId::Assembly,
                1,
                TableDataOwned::Assembly(valid_assembly),
            )
            .map_err(|e| Error::Other(format!("Failed to update assembly: {e}")))?;

        Ok(())
    })
}

/// Creates an assembly with culture `sr-Latn-RS`, a real culture with a script subtag that
/// a two-part `xx-YY` rule would reject.
pub fn create_assembly_with_script_culture() -> Result<TestAssembly> {
    create_test_assembly(get_testfile_mscorlib, Expect::Pass, |assembly| {
        // Create valid assembly name
        let assembly_name_index = assembly
            .string_add("ValidAssemblyName")
            .map_err(|e| Error::Other(format!("Failed to add assembly name: {e}")))?;

        let invalid_culture = "sr-Latn-RS";
        let invalid_culture_index = assembly
            .string_add(invalid_culture)
            .map_err(|e| Error::Other(format!("Failed to add invalid culture: {e}")))?;

        let assembly_rid = 1;

        let invalid_assembly = AssemblyRaw {
            rid: assembly_rid,
            token: Token::new(0x20000000 + assembly_rid),
            offset: 0,
            hash_alg_id: 0x8004, // SHA1
            major_version: 1,
            minor_version: 0,
            build_number: 0,
            revision_number: 0,
            flags: 0,
            public_key: 0,
            name: assembly_name_index.placeholder(),
            culture: invalid_culture_index.placeholder(), // Invalid culture format - should trigger validation failure
        };

        assembly
            .table_row_update(
                TableId::Assembly,
                1,
                TableDataOwned::Assembly(invalid_assembly),
            )
            .map_err(|e| Error::Other(format!("Failed to update invalid assembly: {e}")))?;

        Ok(())
    })
}
