//! TypeRefBuilder for creating type references.
//!
//! This module provides [`crate::metadata::tables::typeref::TypeRefBuilder`] for creating TypeRef table entries
//! with a fluent API. The TypeRef table contains references to types defined
//! in other assemblies or modules.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, TableDataOwned, TableId, TypeRefRaw},
        token::Token,
    },
    Result,
};

/// Builder for creating TypeRef metadata entries.
///
/// `TypeRefBuilder` provides a fluent API for creating TypeRef table entries
/// with validation and automatic heap management. TypeRef entries reference
/// types that are defined in external assemblies or modules.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{CodedIndex, TableId, TypeRefBuilder};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a reference to System.Object from mscorlib
/// let system_object = TypeRefBuilder::new()
///     .name("Object")
///     .namespace("System")
///     .resolution_scope(CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope)) // mscorlib
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct TypeRefBuilder {
    name: Option<String>,
    namespace: Option<String>,
    resolution_scope: Option<CodedIndex>,
}

impl Default for TypeRefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeRefBuilder {
    /// Creates a new TypeRefBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::typeref::TypeRefBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            namespace: None,
            resolution_scope: None,
        }
    }

    /// Sets the type name.
    ///
    /// # Arguments
    ///
    /// * `name` - The simple name of the type (without namespace)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the type namespace.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace containing this type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets the resolution scope where this type can be found.
    ///
    /// # Arguments
    ///
    /// * `resolution_scope` - CodedIndex pointing to Module, ModuleRef, AssemblyRef, or TypeRef
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn resolution_scope(mut self, resolution_scope: CodedIndex) -> Self {
        self.resolution_scope = Some(resolution_scope);
        self
    }

    /// Builds the TypeRef entry and adds it to the assembly.
    ///
    /// This method validates the configuration, adds required strings
    /// to the string heap, creates the TypeRefRaw entry, and adds it
    /// to the assembly via the CilAssembly.
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::token::Token`] for the newly created TypeRef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing (name, resolution_scope)
    /// - Heap operations fail
    /// - TypeRef table row creation fails
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| malformed_error!("TypeRef name is required"))?;

        let resolution_scope = self
            .resolution_scope
            .ok_or_else(|| malformed_error!("TypeRef resolution_scope is required"))?;

        // Add strings to heaps and get indices
        let name_index = assembly.string_add(&name)?.placeholder();

        let namespace_index = if let Some(namespace) = &self.namespace {
            if namespace.is_empty() {
                0 // Global namespace
            } else {
                assembly.string_get_or_add(namespace)?.placeholder()
            }
        } else {
            0 // Default to global namespace
        };

        // Get the next RID for the TypeRef table
        let rid = assembly.next_rid(TableId::TypeRef)?;

        // Create the TypeRefRaw entry
        let typeref_raw = TypeRefRaw {
            rid,
            token: Token::from_parts(TableId::TypeRef, rid),
            offset: 0, // Will be set during binary generation
            resolution_scope,
            type_name: name_index,
            type_namespace: namespace_index,
        };

        // Add the row to the assembly and return the token
        assembly.table_row_add(TableId::TypeRef, TableDataOwned::TypeRef(typeref_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        prelude::CodedIndexType,
        testkit::fixture,
    };

    #[test]
    fn test_typeref_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let mscorlib_ref =
            CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope);
        let ref_ = TypeRefBuilder::new()
            .name("String")
            .namespace("System")
            .resolution_scope(mscorlib_ref)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeRef));
    }

    #[test]
    fn test_typeref_builder_system_object() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Manually specify the core library reference
        let mscorlib_ref =
            CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope);
        let ref_ = TypeRefBuilder::new()
            .name("Object")
            .namespace("System")
            .resolution_scope(mscorlib_ref)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeRef));
    }

    #[test]
    fn test_typeref_builder_system_value_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Manually specify the core library reference
        let mscorlib_ref =
            CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope);
        let ref_ = TypeRefBuilder::new()
            .name("ValueType")
            .namespace("System")
            .resolution_scope(mscorlib_ref)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeRef));
    }

    #[test]
    fn test_typeref_builder_from_mscorlib() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Manually specify the core library reference
        let mscorlib_ref =
            CodedIndex::new(TableId::AssemblyRef, 1, CodedIndexType::ResolutionScope);
        let ref_ = TypeRefBuilder::new()
            .name("Int32")
            .namespace("System")
            .resolution_scope(mscorlib_ref)
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeRef));
    }

    #[test]
    fn test_typeref_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = TypeRefBuilder::new()
            .namespace("System")
            .resolution_scope(CodedIndex::new(
                TableId::AssemblyRef,
                1,
                CodedIndexType::ResolutionScope,
            ))
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_typeref_builder_missing_resolution_scope() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = TypeRefBuilder::new()
            .name("String")
            .namespace("System")
            .build(&mut assembly);

        // Should fail because resolution_scope is required
        assert!(result.is_err());
    }

    #[test]
    fn test_typeref_builder_global_namespace() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = TypeRefBuilder::new()
            .name("GlobalType")
            .namespace("") // Empty namespace = global
            .resolution_scope(CodedIndex::new(
                TableId::AssemblyRef,
                1,
                CodedIndexType::ResolutionScope,
            ))
            .build(&mut assembly)
            .unwrap();

        // Verify ref_ is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeRef));
    }
}
