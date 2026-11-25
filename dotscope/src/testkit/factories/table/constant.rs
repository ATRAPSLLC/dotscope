//! Factory methods for Constant table operations.
//!
//! Contains helper methods migrated from Constant table source files
//! for creating test data related to constant operations and field/property/parameter creation.

use std::sync::Arc;

use crate::{
    metadata::{
        signatures::TypeSignature,
        tables::{Field, Param, Property},
    },
    testkit::builders::{FieldBuilder, ParamBuilder, PropertyBuilder},
};

/// Helper function to create a simple i4 field
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_i4_field(name: &str) -> Arc<Field> {
    FieldBuilder::simple_i4_field(name).build()
}

/// Helper function to create a simple string field
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_string_field(name: &str) -> Arc<Field> {
    FieldBuilder::simple_string_field(name).build()
}

/// Helper function to create a simple boolean field
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_boolean_field(name: &str) -> Arc<Field> {
    FieldBuilder::simple_boolean_field(name).build()
}

/// Helper function to create a simple r4 field
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_r4_field(name: &str) -> Arc<Field> {
    FieldBuilder::simple_r4_field(name).build()
}

/// Helper function to create a simple object field
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_object_field(name: &str) -> Arc<Field> {
    FieldBuilder::simple_object_field(name).build()
}

/// Helper function to create a test property with a given type
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_test_property(name: &str, property_type: TypeSignature) -> Arc<Property> {
    PropertyBuilder::simple_property(name, property_type).build()
}

/// Helper function to create a test parameter
///
/// Originally from: `src/metadata/tables/constant/owned.rs`
pub fn create_test_param(name: &str) -> Arc<Param> {
    ParamBuilder::input_param(1, name).build(None)
}
