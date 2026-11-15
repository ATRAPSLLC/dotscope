//! # ExportedType Builder
//!
//! Provides a fluent API for building ExportedType table entries that define types exported from assemblies.
//! The ExportedType table enables cross-assembly type access, type forwarding during assembly refactoring,
//! and public interface definition for complex assembly structures. It supports multi-module assemblies
//! and type forwarding scenarios.
//!
//! ## Overview
//!
//! The `ExportedTypeBuilder` enables creation of exported type entries with:
//! - Type name and namespace specification (required)
//! - Type visibility and attribute configuration
//! - Implementation location setup (file-based or external assembly)
//! - TypeDef ID hints for optimization
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create a type forwarding entry
//! let assembly_ref = AssemblyRefBuilder::new()
//!     .name("MyApp.Core")
//!     .version(2, 0, 0, 0)
//!     .build(&mut assembly)?;
//!
//! let forwarded_type_token = ExportedTypeBuilder::new()
//!     .name("Customer")
//!     .namespace("MyApp.Models")
//!     .public()
//!     .implementation_assembly_ref(assembly_ref.placeholder())
//!     .build(&mut assembly)?;
//!
//! // Create a multi-module assembly type export
//! let file_ref = FileBuilder::new()
//!     .name("DataLayer.netmodule")
//!     .contains_metadata()
//!     .build(&mut assembly)?;
//!
//! let module_type_token = ExportedTypeBuilder::new()
//!     .name("Repository")
//!     .namespace("MyApp.Data")
//!     .public()
//!     .type_def_id(0x02000001) // TypeDef hint
//!     .implementation_file(file_ref.placeholder())
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Type name is required, implementation must be valid
//! - **Heap Management**: Strings are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Implementation Support**: Methods for file-based and external assembly exports

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, ExportedTypeRaw, TableDataOwned, TableId, TypeAttributes,
        },
        token::Token,
    },
    Error, Result,
};

/// Represents the implementation target for an ExportedType entry.
///
/// This enum captures both the row index (which can be a placeholder or actual row ID)
/// and the target table type. The `CodedIndex` is constructed at write time, not at
/// builder time, to ensure proper placeholder resolution.
#[derive(Debug, Clone, Copy)]
enum ImplementationTarget {
    /// Reference to a File table entry (multi-module assembly)
    File(u32),
    /// Reference to an AssemblyRef table entry (type forwarding)
    AssemblyRef(u32),
    /// Reference to another ExportedType table entry (nested export)
    ExportedType(u32),
}

/// Builder for creating ExportedType table entries.
///
/// `ExportedTypeBuilder` provides a fluent API for creating entries in the ExportedType
/// metadata table, which contains information about types exported from assemblies for
/// cross-assembly access and type forwarding scenarios.
///
/// # Purpose
///
/// The ExportedType table serves several key functions:
/// - **Type Forwarding**: Redirecting type references during assembly refactoring
/// - **Multi-Module Assemblies**: Exposing types from different files within assemblies
/// - **Assembly Facades**: Creating simplified public interfaces over complex implementations
/// - **Cross-Assembly Access**: Enabling external assemblies to access exported types
/// - **Version Management**: Supporting type migration between assembly versions
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing ExportedType entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// let exported_type_token = ExportedTypeBuilder::new()
///     .name("Customer")
///     .namespace("MyApp.Models")
///     .public()
///     .type_def_id(0x02000001)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A type name must be provided
/// - **Name Not Empty**: Type names cannot be empty strings
/// - **Implementation Validity**: Implementation references must point to valid tables
/// - **Table Type Validation**: Implementation must reference File, AssemblyRef, or ExportedType
///
/// # Integration
///
/// ExportedType entries integrate with other metadata structures:
/// - **File**: Multi-module assembly types reference File table entries
/// - **AssemblyRef**: Type forwarding references AssemblyRef entries
/// - **TypeDef**: Optional hints for efficient type resolution
#[derive(Debug, Clone)]
pub struct ExportedTypeBuilder {
    /// The name of the exported type
    name: Option<String>,
    /// The namespace of the exported type
    namespace: Option<String>,
    /// Type visibility and attribute flags
    flags: TypeAttributes,
    /// Optional TypeDef ID hint for resolution optimization
    type_def_id: u32,
    /// Implementation target capturing the row index and target table type.
    /// The `CodedIndex` is constructed at write time.
    implementation: Option<ImplementationTarget>,
}

impl Default for ExportedTypeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExportedTypeBuilder {
    /// Creates a new `ExportedTypeBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. Type visibility defaults to
    /// `PUBLIC` and implementation defaults to None (must be set).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            namespace: None,
            flags: TypeAttributes::PUBLIC,
            type_def_id: 0,
            implementation: None,
        }
    }

    /// Sets the name of the exported type.
    ///
    /// Type names should be simple identifiers without namespace qualifiers
    /// (e.g., "Customer", "Repository", "ServiceProvider").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the exported type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the namespace of the exported type.
    ///
    /// Namespaces organize types hierarchically and typically follow
    /// dot-separated naming conventions (e.g., "MyApp.Models", "System.Data").
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace of the exported type
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .namespace("MyApp.Models");
    /// ```
    #[must_use]
    pub fn namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Sets type attributes using a bitmask.
    ///
    /// Type attributes control visibility, inheritance, and behavior characteristics.
    /// Use the `TypeAttributes` constants for standard values.
    ///
    /// # Arguments
    ///
    /// * `flags` - Type attributes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::TypeAttributes;
    /// let builder = ExportedTypeBuilder::new()
    ///     .flags(TypeAttributes::PUBLIC);
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: TypeAttributes) -> Self {
        self.flags = flags;
        self
    }

    /// Marks the type as public (accessible from external assemblies).
    ///
    /// Public types can be accessed by other assemblies and are part
    /// of the assembly's public API surface.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("PublicService")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.flags = TypeAttributes::PUBLIC;
        self
    }

    /// Marks the type as not public (internal to the assembly).
    ///
    /// Non-public types are not accessible from external assemblies
    /// and are considered internal implementation details.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("InternalHelper")
    ///     .not_public();
    /// ```
    #[must_use]
    pub fn not_public(mut self) -> Self {
        self.flags = TypeAttributes::NOT_PUBLIC;
        self
    }

    /// Sets the TypeDef ID hint for resolution optimization.
    ///
    /// The TypeDef ID provides a hint for efficient type resolution
    /// when the exported type maps to a specific TypeDef entry.
    /// This is optional and may be 0 if no hint is available.
    ///
    /// # Arguments
    ///
    /// * `type_def_id` - The TypeDef ID hint (without table prefix)
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .type_def_id(0x02000001); // TypeDef hint
    /// ```
    #[must_use]
    pub fn type_def_id(mut self, type_def_id: u32) -> Self {
        self.type_def_id = type_def_id;
        self
    }

    /// Sets the implementation to reference a File table entry.
    ///
    /// Use this for multi-module assembly scenarios where the type
    /// is defined in a different file within the same assembly.
    /// The `CodedIndex` is NOT created at builder time to ensure proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `file_row` - Row index or placeholder of the File table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let file_ref = FileBuilder::new()
    ///     .name("DataLayer.netmodule")
    ///     .build(&mut assembly)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Repository")
    ///     .implementation_file(file_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_file(mut self, file_row: u32) -> Self {
        self.implementation = Some(ImplementationTarget::File(file_row));
        self
    }

    /// Sets the implementation to reference an AssemblyRef table entry.
    ///
    /// Use this for type forwarding scenarios where the type has been
    /// moved to a different assembly and needs to be redirected.
    /// The `CodedIndex` is NOT created at builder time to ensure proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref_row` - Row index or placeholder of the AssemblyRef table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let assembly_ref = AssemblyRefBuilder::new()
    ///     .name("MyApp.Core")
    ///     .version(2, 0, 0, 0)
    ///     .build(&mut assembly)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .implementation_assembly_ref(assembly_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_assembly_ref(mut self, assembly_ref_row: u32) -> Self {
        self.implementation = Some(ImplementationTarget::AssemblyRef(assembly_ref_row));
        self
    }

    /// Sets the implementation to reference another ExportedType table entry.
    ///
    /// Use this for complex scenarios with nested export references,
    /// though this is rarely used in practice.
    /// The `CodedIndex` is NOT created at builder time to ensure proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `exported_type_row` - Row index or placeholder of the ExportedType table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let base_export = ExportedTypeBuilder::new()
    ///     .name("BaseType")
    ///     .build(&mut assembly)?;
    ///
    /// let builder = ExportedTypeBuilder::new()
    ///     .name("DerivedType")
    ///     .implementation_exported_type(base_export.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_exported_type(mut self, exported_type_row: u32) -> Self {
        self.implementation = Some(ImplementationTarget::ExportedType(exported_type_row));
        self
    }

    /// Builds the ExportedType entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings to the appropriate heaps,
    /// creates the ExportedType table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for the assembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created ExportedType entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The type name is not set
    /// - The type name is empty
    /// - The implementation reference is not set
    /// - The implementation reference has a row index of 0
    /// - There are issues adding strings to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    ///
    /// let exported_type_token = ExportedTypeBuilder::new()
    ///     .name("Customer")
    ///     .namespace("MyApp.Models")
    ///     .public()
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created ExportedType with token: {:?}", exported_type_token.placeholder_token());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid("Type name is required for ExportedType".to_string())
        })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalid(
                "Type name cannot be empty for ExportedType".to_string(),
            ));
        }

        let implementation_target = self.implementation.ok_or_else(|| {
            Error::ModificationInvalid("Implementation is required for ExportedType".to_string())
        })?;

        // Extract the row from the target for validation
        let implementation_row = match implementation_target {
            ImplementationTarget::File(row)
            | ImplementationTarget::AssemblyRef(row)
            | ImplementationTarget::ExportedType(row) => row,
        };

        // Validate implementation reference - 0 is invalid unless it's a placeholder
        // We allow placeholders (which have bit 31 set) to pass through
        if implementation_row == 0 {
            return Err(Error::ModificationInvalid(
                "Implementation reference row cannot be 0".to_string(),
            ));
        }

        // Construct the CodedIndex from the stored target information.
        // The row value may be a placeholder that will be resolved at write time
        // by the ResolvePlaceholders implementation.
        let implementation = match implementation_target {
            ImplementationTarget::File(row) => {
                CodedIndex::new(TableId::File, row, CodedIndexType::Implementation)
            }
            ImplementationTarget::AssemblyRef(row) => {
                CodedIndex::new(TableId::AssemblyRef, row, CodedIndexType::Implementation)
            }
            ImplementationTarget::ExportedType(row) => {
                CodedIndex::new(TableId::ExportedType, row, CodedIndexType::Implementation)
            }
        };

        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let namespace_index = if let Some(namespace) = self.namespace {
            if namespace.is_empty() {
                0
            } else {
                assembly.string_get_or_add(&namespace)?.placeholder()
            }
        } else {
            0
        };

        let exported_type = ExportedTypeRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            flags: self.flags.bits(),
            type_def_id: self.type_def_id,
            name: name_index,
            namespace: namespace_index,
            implementation,
        };

        assembly.table_row_add(
            TableId::ExportedType,
            TableDataOwned::ExportedType(exported_type),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind,
        metadata::tables::{TableId, TypeAttributes},
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_exported_type_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // First create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("TestType")
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        // Verify the reference has the correct kind
        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_default() -> Result<()> {
        let builder = ExportedTypeBuilder::default();
        assert!(builder.name.is_none());
        assert!(builder.namespace.is_none());
        assert_eq!(builder.flags, TypeAttributes::PUBLIC);
        assert_eq!(builder.type_def_id, 0);
        assert!(builder.implementation.is_none());
        Ok(())
    }

    #[test]
    fn test_exported_type_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let result = ExportedTypeBuilder::new()
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Type name is required"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_empty_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let result = ExportedTypeBuilder::new()
            .name("")
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Type name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_missing_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = ExportedTypeBuilder::new()
            .name("TestType")
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation is required"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_with_namespace() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("Customer")
            .namespace("MyApp.Models")
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_public() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("PublicType")
            .public()
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_not_public() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("InternalType")
            .not_public()
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_with_typedef_id() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("TypeWithHint")
            .type_def_id(0x02000001)
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_assembly_ref_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create an AssemblyRef to reference
        let assembly_ref = crate::metadata::tables::AssemblyRefBuilder::new()
            .name("MyApp.Core")
            .version(1, 0, 0, 0)
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("ForwardedType")
            .namespace("MyApp.Models")
            .implementation_assembly_ref(assembly_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_exported_type_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File for the first ExportedType
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        // Create a base exported type
        let base_ref = ExportedTypeBuilder::new()
            .name("BaseType")
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        // Create a derived exported type that references the base
        let derived_ref = ExportedTypeBuilder::new()
            .name("DerivedType")
            .implementation_exported_type(base_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            derived_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_zero_row_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a builder with a zero row implementation reference
        let mut builder = ExportedTypeBuilder::new().name("ZeroRowType");

        // Manually set an implementation with row 0 (invalid)
        builder.implementation = Some(ImplementationTarget::File(0));

        let result = builder.build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_multiple_types() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create Files to reference
        let file_ref1 = crate::metadata::tables::FileBuilder::new()
            .name("Module1.netmodule")
            .build(&mut assembly)?;

        let file_ref2 = crate::metadata::tables::FileBuilder::new()
            .name("Module2.netmodule")
            .build(&mut assembly)?;

        let ref1 = ExportedTypeBuilder::new()
            .name("Type1")
            .namespace("MyApp.A")
            .implementation_file(file_ref1.placeholder())
            .build(&mut assembly)?;

        let ref2 = ExportedTypeBuilder::new()
            .name("Type2")
            .namespace("MyApp.B")
            .implementation_file(file_ref2.placeholder())
            .build(&mut assembly)?;

        // Verify refs are different and have correct kind
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::ExportedType));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::ExportedType));

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_comprehensive() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("ComprehensiveModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("ComprehensiveType")
            .namespace("MyApp.Comprehensive")
            .public()
            .type_def_id(0x02000042)
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("FluentModule.netmodule")
            .build(&mut assembly)?;

        // Test fluent API chaining
        let exported_ref = ExportedTypeBuilder::new()
            .name("FluentType")
            .namespace("MyApp.Fluent")
            .not_public()
            .type_def_id(0x02000123)
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }

    #[test]
    fn test_exported_type_builder_clone() {
        let builder1 = ExportedTypeBuilder::new()
            .name("CloneTest")
            .namespace("MyApp.Test")
            .public();
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.namespace, builder2.namespace);
        assert_eq!(builder1.flags, builder2.flags);
        assert_eq!(builder1.type_def_id, builder2.type_def_id);
    }

    #[test]
    fn test_exported_type_builder_debug() {
        let builder = ExportedTypeBuilder::new()
            .name("DebugType")
            .namespace("MyApp.Debug");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ExportedTypeBuilder"));
        assert!(debug_str.contains("DebugType"));
        assert!(debug_str.contains("MyApp.Debug"));
    }

    #[test]
    fn test_exported_type_builder_empty_namespace() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a File to reference
        let file_ref = crate::metadata::tables::FileBuilder::new()
            .name("TestModule.netmodule")
            .build(&mut assembly)?;

        let exported_ref = ExportedTypeBuilder::new()
            .name("GlobalType")
            .namespace("") // Empty namespace should work
            .implementation_file(file_ref.placeholder())
            .build(&mut assembly)?;

        assert_eq!(
            exported_ref.kind(),
            ChangeRefKind::TableRow(TableId::ExportedType)
        );

        Ok(())
    }
}
