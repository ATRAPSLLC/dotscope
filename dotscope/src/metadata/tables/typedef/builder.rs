//! TypeDefBuilder for creating type definitions.
//!
//! This module provides [`crate::metadata::tables::typedef::TypeDefBuilder`] for creating TypeDef table entries
//! with a fluent API. The TypeDef table defines types (classes, interfaces,
//! value types, enums) within the current module.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeAttributes, TypeDefRaw},
        token::Token,
    },
    Result,
};

/// Builder for creating TypeDef metadata entries.
///
/// `TypeDefBuilder` provides a fluent API for creating TypeDef table entries
/// with validation and automatic heap management. TypeDef entries define types
/// (classes, interfaces, value types, enums) within the current assembly.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{CodedIndex, CodedIndexType, TableId, TypeDefBuilder};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a simple class
/// let my_class = TypeDefBuilder::new()
///     .name("MyClass")
///     .namespace("MyNamespace")
///     .extends(CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef)) // System.Object
///     .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct TypeDefBuilder {
    name: Option<String>,
    namespace: Option<String>,
    extends: Option<CodedIndex>,
    flags: Option<TypeAttributes>,
    field_list: Option<u32>,
    method_list: Option<u32>,
}

impl Default for TypeDefBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TypeDefBuilder {
    /// Creates a new TypeDefBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::typedef::TypeDefBuilder`] ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            namespace: None,
            extends: None,
            flags: None,
            field_list: None,
            method_list: None,
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

    /// Sets the base type that this type extends.
    ///
    /// # Arguments
    ///
    /// * `extends` - CodedIndex pointing to the base type (TypeDef, TypeRef, or TypeSpec)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn extends(mut self, extends: CodedIndex) -> Self {
        self.extends = Some(extends);
        self
    }

    /// Sets the type flags (attributes).
    ///
    /// # Arguments
    ///
    /// * `flags` - Type attributes controlling visibility, layout, and semantics
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: TypeAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the field list starting index.
    ///
    /// # Arguments
    ///
    /// * `field_list` - Index into the Field table marking the first field of this type
    ///
    /// Without it, the type starts an empty list at the next Field row, so the fields added
    /// after it are its own (ECMA-335 II.22.37).
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn field_list(mut self, field_list: u32) -> Self {
        self.field_list = Some(field_list);
        self
    }

    /// Sets the method list starting index.
    ///
    /// # Arguments
    ///
    /// * `method_list` - Index into the MethodDef table marking the first method of this type
    ///
    /// Without it, the type starts an empty list at the next MethodDef row, so the methods
    /// added after it are its own (ECMA-335 II.22.37).
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn method_list(mut self, method_list: u32) -> Self {
        self.method_list = Some(method_list);
        self
    }

    /// Convenience method to set common class flags.
    ///
    /// Sets the type as a public class.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_class(mut self) -> Self {
        self.flags = Some(TypeAttributes::PUBLIC | TypeAttributes::BEFORE_FIELD_INIT);
        self
    }

    /// Convenience method to set common interface flags.
    ///
    /// Sets the type as a public interface.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_interface(mut self) -> Self {
        self.flags = Some(
            TypeAttributes::PUBLIC
                | TypeAttributes::INTERFACE
                | TypeAttributes::ABSTRACT
                | TypeAttributes::BEFORE_FIELD_INIT,
        );
        self
    }

    /// Convenience method to set common value type flags.
    ///
    /// Sets the type as a public sealed value type.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn public_value_type(mut self) -> Self {
        self.flags = Some(
            TypeAttributes::PUBLIC | TypeAttributes::SEALED | TypeAttributes::BEFORE_FIELD_INIT,
        );
        self
    }

    /// Builds the TypeDef entry and adds it to the assembly.
    ///
    /// This method validates the configuration, adds required strings
    /// to the string heap, creates the TypeDefRaw entry, and adds it
    /// to the assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly for heap management and table operations
    ///
    /// # Returns
    ///
    /// A [`ChangeRefRc`] for the newly created TypeDef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Required fields are missing (name)
    /// - Heap operations fail
    /// - TypeDef table row creation fails
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        // Validate required fields
        let name = self
            .name
            .ok_or_else(|| malformed_error!("TypeDef name is required"))?;

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

        // Get the next RID for the TypeDef table
        let rid = assembly.next_rid(TableId::TypeDef)?;

        // Create the TypeDefRaw entry
        let typedef_raw = TypeDefRaw {
            rid,
            token: Token::new(rid | 0x0200_0000), // TypeDef table token prefix
            offset: 0,                            // Will be set during binary generation
            flags: self
                .flags
                .unwrap_or(TypeAttributes::PUBLIC | TypeAttributes::BEFORE_FIELD_INIT)
                .bits(), // Default to public class
            type_name: name_index,
            type_namespace: namespace_index,
            extends: self
                .extends
                .unwrap_or_else(|| CodedIndex::null(CodedIndexType::TypeDefOrRef)), // No base type
            field_list: match self.field_list {
                Some(list) => list,
                None => assembly.next_rid(TableId::Field)?,
            },
            method_list: match self.method_list {
                Some(list) => list,
                None => assembly.next_rid(TableId::MethodDef)?,
            },
        };

        // Add the row to the assembly and return the token
        assembly.table_row_add(TableId::TypeDef, TableDataOwned::TypeDef(typedef_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{TableId, TypeAttributes},
        },
        testkit::fixture,
    };

    #[test]
    fn test_typedef_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = TypeDefBuilder::new()
            .name("TestClass")
            .namespace("TestNamespace")
            .public_class()
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    }

    #[test]
    fn test_typedef_builder_interface() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = TypeDefBuilder::new()
            .name("ITestInterface")
            .namespace("TestNamespace")
            .public_interface()
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    }

    #[test]
    fn test_typedef_builder_value_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = TypeDefBuilder::new()
            .name("TestStruct")
            .namespace("TestNamespace")
            .public_value_type()
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    }

    #[test]
    fn test_typedef_builder_with_base_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let base_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // Assume System.Object
        let ref_ = TypeDefBuilder::new()
            .name("DerivedClass")
            .namespace("TestNamespace")
            .extends(base_type)
            .flags(TypeAttributes::PUBLIC | TypeAttributes::CLASS)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    }

    #[test]
    fn test_typedef_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = TypeDefBuilder::new()
            .namespace("TestNamespace")
            .public_class()
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_typedef_builder_global_namespace() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = TypeDefBuilder::new()
            .name("GlobalClass")
            .namespace("") // Empty namespace = global
            .public_class()
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
    }
}
