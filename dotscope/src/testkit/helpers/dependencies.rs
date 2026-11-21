//! Helper functions for dependency tracking tests.
//!
//! This module provides factory functions for creating test data structures
//! used in dependency tracking and analysis testing. These helpers create
//! properly initialized objects with all required fields for reliable testing.

use std::sync::{atomic::AtomicU32, Arc};

use crate::metadata::{
    dependencies::{
        AssemblyDependency, DependencyResolutionState, DependencySource, DependencyType,
        VersionRequirement,
    },
    identity::{AssemblyIdentity, AssemblyVersion},
    tables::{AssemblyFlags, AssemblyRef, AssemblyRefHash, File, FileAttributes, ModuleRef},
    token::Token,
};

/// Create a test assembly identity with basic version information.
pub fn create_test_identity(name: &str, major: u16, minor: u16) -> AssemblyIdentity {
    AssemblyIdentity {
        name: name.into(),
        version: AssemblyVersion::new(major, minor, 0, 0),
        culture: None,
        strong_name: None,
        processor_architecture: None,
    }
}

/// Create a test AssemblyRef with default version (1.0.0.0).
pub fn create_test_assembly_ref(name: &str) -> Arc<AssemblyRef> {
    create_test_assembly_ref_with_version(name, 1, 0, 0, 0)
}

/// Create a test AssemblyRef with custom version.
pub fn create_test_assembly_ref_with_version(
    name: &str,
    major: u32,
    minor: u32,
    build: u32,
    revision: u32,
) -> Arc<AssemblyRef> {
    create_test_assembly_ref_with_culture(name, major, minor, build, revision, None)
}

/// Create a test AssemblyRef with custom version and culture.
pub fn create_test_assembly_ref_with_culture(
    name: &str,
    major: u32,
    minor: u32,
    build: u32,
    revision: u32,
    culture: Option<String>,
) -> Arc<AssemblyRef> {
    Arc::new(AssemblyRef {
        name: name.into(),
        major_version: major,
        minor_version: minor,
        build_number: build,
        revision_number: revision,
        flags: AssemblyFlags::ZERO,
        culture: culture.map(Into::into),
        identifier: None,
        offset: 0,
        rid: 1,
        token: Token::new(0x23000001), // AssemblyRef table token (0x23 = table, 1 = row)
        custom_attributes: Default::default(),
        hash: None,
        os_platform_id: AtomicU32::new(0),
        os_major_version: AtomicU32::new(0),
        os_minor_version: AtomicU32::new(0),
        processor: AtomicU32::new(0),
    })
}

/// Create a test ModuleRef with all required fields.
pub fn create_test_module_ref(name: &str) -> Arc<ModuleRef> {
    Arc::new(ModuleRef {
        name: name.into(),
        offset: 0,
        rid: 1,
        token: Token::new(0x1A000001), // ModuleRef table token (0x1A = table, 1 = row)
        custom_attributes: Default::default(),
    })
}

/// Create a test File with all required fields.
pub fn create_test_file(name: &str) -> Arc<File> {
    Arc::new(File {
        flags: FileAttributes::ZERO,
        name: name.into(),
        hash_value: AssemblyRefHash::new(&[0x01, 0x02, 0x03, 0x04]).unwrap(),
        offset: 0,
        rid: 1,
        token: Token::new(0x26000001), // File table token (0x26 = table, 1 = row)
        custom_attributes: Default::default(),
    })
}

/// Create a test assembly dependency with default settings.
pub fn create_test_dependency(
    target_name: &str,
    dependency_type: DependencyType,
) -> AssemblyDependency {
    create_test_dependency_with_version(target_name, dependency_type, 1, 0)
}

/// Create a test assembly dependency with custom version.
pub fn create_test_dependency_with_version(
    target_name: &str,
    dependency_type: DependencyType,
    major: u16,
    minor: u16,
) -> AssemblyDependency {
    let assembly_ref =
        create_test_assembly_ref_with_version(target_name, major as u32, minor as u32, 0, 0);

    AssemblyDependency {
        source: DependencySource::AssemblyRef(assembly_ref),
        target_identity: create_test_identity(target_name, major, minor),
        dependency_type,
        version_requirement: VersionRequirement::Compatible,
        is_optional: false,
        resolution_state: DependencyResolutionState::Unresolved,
    }
}
