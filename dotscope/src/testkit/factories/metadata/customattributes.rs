//! Factory methods for custom attributes test data.
//!
//! Contains helper methods migrated from custom attributes source files
//! for creating test data related to custom attribute parsing and encoding.

use std::sync::Arc;

use crate::{
    metadata::{
        identity::AssemblyIdentity,
        method::{Method, MethodRc},
        typesystem::{CilFlavor, TypeRegistry},
    },
    testkit::MethodBuilder,
};

/// Helper to create a method with empty parameters for parsing tests
///
/// Originally from: `src/metadata/customattributes/mod.rs`
pub fn create_empty_method() -> Arc<Method> {
    MethodBuilder::new().with_name("TestConstructor").build()
}

/// Helper to create a method with specific parameter types
///
/// Originally from: `src/metadata/customattributes/mod.rs`
pub fn create_method_with_params(param_types: Vec<CilFlavor>) -> Arc<Method> {
    MethodBuilder::with_param_types("TestConstructor", param_types).build()
}

/// Helper function to create a simple method for basic parsing tests
///
/// Originally from: `src/metadata/customattributes/parser.rs`
pub fn create_empty_constructor() -> MethodRc {
    MethodBuilder::new().with_name("EmptyConstructor").build()
}

/// Helper function to create a method with specific parameter types using builders
///
/// Originally from: `src/metadata/customattributes/parser.rs`
pub fn create_constructor_with_params(param_types: Vec<CilFlavor>) -> MethodRc {
    MethodBuilder::with_param_types("AttributeConstructor", param_types).build()
}

/// Get or create a shared test TypeRegistry for custom attribute tests
///
/// This returns a TypeRegistry that persists across test calls within the same test run,
/// ensuring that types created by ParamBuilder remain accessible for custom attribute parsing.
pub fn get_test_type_registry() -> Arc<TypeRegistry> {
    static TEST_REGISTRY: std::sync::OnceLock<Arc<TypeRegistry>> = std::sync::OnceLock::new();

    TEST_REGISTRY
        .get_or_init(|| {
            let identity = AssemblyIdentity::parse("CustomAttributeTestAssembly, Version=1.0.0.0")
                .expect("Failed to parse test assembly identity");
            Arc::new(TypeRegistry::new(identity).expect("Failed to create TypeRegistry"))
        })
        .clone()
}

/// Helper function to create a method with specific parameter types using builders,
/// with TypeRegistry support for custom attribute parsing
///
/// This variant ensures the method's parameter types are registered in the provided
/// TypeRegistry, enabling proper custom attribute parsing with type resolution.
pub fn create_constructor_with_params_and_registry(
    param_types: Vec<CilFlavor>,
    registry: &Arc<TypeRegistry>,
) -> MethodRc {
    MethodBuilder::with_param_types("AttributeConstructor", param_types)
        .build_with_registry(Some(registry))
}
