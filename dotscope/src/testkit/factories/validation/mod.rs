//! Validation factory modules for creating test assemblies and validation scenarios.
//!
//! Contains factory functions migrated from validation-related source files
//! that create corrupted or test assemblies for validation rule testing.

// Migrated validation factory modules:
pub mod attribute;
pub mod circularity;
pub mod constraints_types;
pub mod dependency;
pub mod inheritance;
pub mod members_accessibility;
pub mod members_field;
pub mod members_method;
pub mod ownership;
pub mod raw_constraints_generic;
pub mod raw_constraints_layout;
pub mod raw_modification_integrity;
pub mod raw_modification_operation;
pub mod raw_structure_heap;
pub mod raw_structure_signature;
pub mod raw_structure_table;
pub mod raw_structure_token;
pub mod signature;
pub mod system_assembly;
pub mod system_security;
pub mod type_circularity;
pub mod type_definition;
pub mod type_dependency;
pub mod type_ownership;
