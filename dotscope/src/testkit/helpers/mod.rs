//! Helper functions and utilities for testing
//!
//! This module contains helper functions for creating test data structures
//! and mock objects. It includes both legacy helpers for backward compatibility
//! and new specialized helpers for different testing scenarios.
//!
//! # Assembly Loading Helpers
//!
//! Two primary helpers simplify test assembly creation:
//!
//! - [`load_test_assembly`] - Loads a `CilAssembly` from a test file path function
//! - [`create_test_assembly`] - Creates a `TestAssembly` with modifications applied
//! - [`test_assembly_arc`] - Returns a cached `Arc<CilObject>` for pass tests
//!
//! These helpers eliminate boilerplate in validation factory functions and integration tests.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock},
};

use crate::{
    cilassembly::{CilAssembly, DanglingPolicy, GeneratorConfig},
    metadata::{
        method::MethodRc,
        tables::{AssemblyRefRaw, AssemblyRefRc, FileRc, ModuleRefRc, TableId, TypeRefRaw},
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
        validation::ValidationConfig,
    },
    testkit::{
        builders::{
            AssemblyRefBuilder, CilTypeBuilder, FileBuilder, MethodBuilder, ModuleRefBuilder,
        },
        fixtures::fixture,
        validator::{Expect, TestAssembly},
    },
    CilObject, Result,
};

pub mod dependencies;

/// The fixtures (in `tests/samples/metadata/layouts`) that import `System.RuntimeTypeHandle`
/// from System.Private.CoreLib as well as from the program's own mscorlib, the foreign
/// TypeRef listed before the program's and after it.
pub const TWO_CORELIB_FIXTURES: [&str; 2] = [
    "two_corelibs_foreign_first.exe",
    "two_corelibs_foreign_last.exe",
];

/// The rows of the TypeRefs importing `System.RuntimeTypeHandle` in the assembly at `path`,
/// keyed by the name of the AssemblyRef scoping each, read from the raw tables.
pub fn runtime_type_handle_rows(path: &Path) -> HashMap<String, u32> {
    let assembly = CilObject::from_path(path).unwrap();
    let tables = assembly.tables().unwrap();
    let strings = assembly.strings().unwrap();
    let assembly_refs = tables.table::<AssemblyRefRaw>().unwrap();
    tables
        .table::<TypeRefRaw>()
        .unwrap()
        .into_iter()
        .map(|row| row.expect("row parses"))
        .filter(|row| {
            strings.get(row.type_namespace as usize).unwrap() == "System"
                && strings.get(row.type_name as usize).unwrap() == "RuntimeTypeHandle"
                && row.resolution_scope.tag == TableId::AssemblyRef
        })
        .map(|row| {
            let scope = assembly_refs
                .get(row.resolution_scope.row)
                .unwrap()
                .expect("scope row exists");
            (
                strings.get(scope.name as usize).unwrap().to_string(),
                row.rid,
            )
        })
        .collect()
}

// Helper function to create a ModuleRef
pub fn create_module_ref(rid: u32, name: &str) -> ModuleRefRc {
    ModuleRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create an AssemblyRef
pub fn create_assembly_ref(rid: u32, name: &str) -> AssemblyRefRc {
    AssemblyRefBuilder::new()
        .with_rid(rid)
        .with_name(name)
        .build()
}

// Helper function to create a File
pub fn create_file(rid: u32, name: &str) -> FileRc {
    FileBuilder::new().with_rid(rid).with_name(name).build()
}

// Helper function to create a Method
pub fn create_method(name: &str) -> MethodRc {
    MethodBuilder::simple_void_method(name).build()
}

// Helper function to create a CilType
pub fn create_cil_type(
    token: Token,
    namespace: &str,
    name: &str,
    external: Option<CilTypeReference>,
) -> CilTypeRc {
    CilTypeBuilder::new()
        .with_token(token)
        .with_namespace(namespace)
        .with_name(name)
        .with_external(external.unwrap_or_else(|| CilTypeReference::File(create_file(1, "test"))))
        .build()
}

/// Loads a [`CilAssembly`] from a test file path function.
///
/// This helper simplifies assembly loading in tests by wrapping the common pattern
/// of calling a test file function and loading the assembly from the resulting path.
///
/// # Arguments
///
/// * `testfile_fn` - A function that returns an optional path to a test file
///
/// # Returns
///
/// A `Result` containing the loaded `CilAssembly` or an error if:
/// - The test file function returns `None`
/// - The assembly fails to load
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::testkit::{load_test_assembly, get_testfile_mscorlib};
///
/// let assembly = load_test_assembly(get_testfile_mscorlib)?;
/// // Now you can work with the assembly
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn load_test_assembly(testfile_fn: fn() -> PathBuf) -> Result<CilAssembly> {
    CilAssembly::from_path(testfile_fn())
}

/// A [`TestAssembly`] made from a test file: `f` modifies the assembly `testfile_fn` names,
/// and the result is written to memory, with what the validator must do with it.
///
/// A crafted case may build metadata a write would refuse, so it is written with a reference
/// to a deleted row as null ([`DanglingPolicy::Null`]); a clean one is written as any
/// assembly is.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::testkit::{create_test_assembly, get_testfile_wb, Expect};
///
/// let test = create_test_assembly(get_testfile_wb, Expect::fail("GUID heap"), |asm| {
///     // Create invalid GUID heap
///     Ok(())
/// })?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[track_caller]
pub fn create_test_assembly<F>(
    testfile_fn: fn() -> PathBuf,
    expect: Expect,
    f: F,
) -> Result<TestAssembly>
where
    F: FnOnce(&mut CilAssembly) -> Result<()>,
{
    let mut assembly = load_test_assembly(testfile_fn)?;
    f(&mut assembly)?;
    let config = match expect {
        Expect::Pass => GeneratorConfig::default(),
        Expect::Fail(_) | Expect::Refused(_) => {
            GeneratorConfig::default().with_dangling(DanglingPolicy::Null)
        }
    };
    let bytes = assembly.to_memory_with_config(config)?;
    Ok(TestAssembly::from_bytes(bytes, expect))
}

/// Loads a [`CilObject`] from a relative sample path with analysis validation.
///
/// Used by deobfuscation technique tests to load obfuscated samples.
///
/// # Panics
///
/// Panics if the file cannot be loaded.
pub fn load_sample(rel: &str) -> CilObject {
    CilObject::from_path_with_validation(fixture(rel), ValidationConfig::analysis())
        .unwrap_or_else(|e| panic!("Failed to load test sample '{rel}': {e}"))
}

/// Returns a cached `Arc<CilObject>` for use in pass tests.
///
/// This helper loads a test assembly once and caches it for reuse across tests.
/// Useful for pass tests that need an assembly parameter but don't actually use it.
///
/// # Panics
///
/// Panics if the test assembly cannot be loaded.
pub fn test_assembly_arc() -> Arc<CilObject> {
    static TEST_ASSEMBLY: LazyLock<Arc<CilObject>> = LazyLock::new(|| {
        Arc::new(
            CilObject::from_path(fixture("crafted_2.exe")).expect("Failed to load test assembly"),
        )
    });

    Arc::clone(&TEST_ASSEMBLY)
}

/// Returns mono's `mscorlib.dll`, loaded once and shared by every test that
/// asks for it.
///
/// # Panics
///
/// Panics if the sample cannot be loaded.
pub fn mono_mscorlib() -> Arc<CilObject> {
    static MSCORLIB: LazyLock<Arc<CilObject>> = LazyLock::new(|| {
        Arc::new(CilObject::from_path(fixture("mono_4.8/mscorlib.dll")).expect("mscorlib loads"))
    });

    Arc::clone(&MSCORLIB)
}

/// Returns the `MethodDef` token of the method `declaring::name` taking
/// `params` parameters.
///
/// # Panics
///
/// Panics when `assembly` defines no such method.
pub fn method_token(assembly: &CilObject, declaring: &str, name: &str, params: u32) -> Token {
    assembly
        .methods()
        .iter()
        .find(|entry| {
            let method = entry.value();
            method.name == name
                && method.signature.param_count == params
                && assembly
                    .resolve_method_declaring_type(*entry.key())
                    .as_deref()
                    == Some(declaring)
        })
        .map(|entry| *entry.key())
        .unwrap_or_else(|| panic!("{declaring}::{name} with {params} parameters"))
}
