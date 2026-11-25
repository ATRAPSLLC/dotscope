//! InterfaceImplBuilder for creating interface implementation declarations.
//!
//! This module provides [`crate::metadata::tables::interfaceimpl::InterfaceImplBuilder`] for creating InterfaceImpl table entries
//! with a fluent API. Interface implementations establish the relationship between types
//! and the interfaces they implement, enabling .NET's interface-based polymorphism,
//! multiple inheritance support, and runtime type compatibility.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, InterfaceImplRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating InterfaceImpl metadata entries.
///
/// `InterfaceImplBuilder` provides a fluent API for creating InterfaceImpl table entries
/// with validation and automatic heap management. Interface implementations define the
/// relationship between implementing types and their interfaces, enabling polymorphic
/// dispatch, multiple inheritance scenarios, and runtime type compatibility checking.
///
/// # Interface Implementation Model
///
/// .NET interface implementations follow a standard pattern:
/// - **Implementing Type**: The class or interface that implements the target interface
/// - **Implemented Interface**: The interface being implemented or extended
/// - **Method Resolution**: Runtime mapping of interface methods to concrete implementations
/// - **Type Compatibility**: Enables casting between implementing types and interfaces
///
/// # Coded Index Types
///
/// Interface implementations use specific table references:
/// - **Class**: Direct `TypeDef` index referencing the implementing type
/// - **Interface**: `TypeDefOrRef` coded index for the implemented interface
///
/// # Implementation Scenarios
///
/// Interface implementations support several important scenarios:
/// - **Class Interface Implementation**: Classes implementing one or more interfaces
/// - **Interface Extension**: Interfaces extending other interfaces (inheritance)
/// - **Generic Interface Implementation**: Types implementing generic interfaces with specific type arguments
/// - **Multiple Interface Implementation**: Types implementing multiple unrelated interfaces
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{InterfaceImplBuilder, CodedIndex, TableId};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a class implementing an interface
/// let implementing_class = 1; // TypeDef RID for MyClass
/// let target_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // IDisposable from mscorlib
///
/// let impl_declaration = InterfaceImplBuilder::new()
///     .class(implementing_class)
///     .interface(target_interface)
///     .build(&mut assembly)?;
///
/// // Create an interface extending another interface
/// let derived_interface = 2; // TypeDef RID for IMyInterface
/// let base_interface = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IComparable from mscorlib
///
/// let interface_extension = InterfaceImplBuilder::new()
///     .class(derived_interface)
///     .interface(base_interface)
///     .build(&mut assembly)?;
///
/// // Create a generic interface implementation
/// let generic_class = 3; // TypeDef RID for MyGenericClass
/// let generic_interface = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // IEnumerable<string>
///
/// let generic_impl = InterfaceImplBuilder::new()
///     .class(generic_class)
///     .interface(generic_interface)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct InterfaceImplBuilder {
    class: Option<u32>,
    interface: Option<CodedIndex>,
}

impl Default for InterfaceImplBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceImplBuilder {
    /// Creates a new InterfaceImplBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::interfaceimpl::InterfaceImplBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            interface: None,
        }
    }

    /// Sets the implementing type (class or interface).
    ///
    /// The class must be a valid `TypeDef` RID that references a type definition
    /// in the current assembly. This type will be marked as implementing or extending
    /// the target interface specified in the interface field.
    ///
    /// Implementation scenarios:
    /// - **Class Implementation**: A class implementing an interface contract
    /// - **Interface Extension**: An interface extending another interface (inheritance)
    /// - **Generic Type Implementation**: Generic types implementing parameterized interfaces
    /// - **Value Type Implementation**: Structs and enums implementing interface contracts
    ///
    /// # Arguments
    ///
    /// * `class` - A `TypeDef` RID pointing to the implementing type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn class(mut self, class: u32) -> Self {
        self.class = Some(class);
        self
    }

    /// Sets the target interface being implemented.
    ///
    /// The interface must be a valid `TypeDefOrRef` coded index that references
    /// an interface type. This establishes which interface contract the implementing
    /// type must fulfill through method implementations.
    ///
    /// Valid interface types include:
    /// - `TypeDef` - Interfaces defined in the current assembly
    /// - `TypeRef` - Interfaces from external assemblies (e.g., system interfaces)
    /// - `TypeSpec` - Generic interface instantiations with specific type arguments
    ///
    /// # Arguments
    ///
    /// * `interface` - A `TypeDefOrRef` coded index pointing to the target interface
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn interface(mut self, interface: CodedIndex) -> Self {
        self.interface = Some(interface);
        self
    }

    /// Builds the interface implementation and adds it to the assembly.
    ///
    /// This method validates all required fields are set, creates the raw interface
    /// implementation structure, and adds it to the InterfaceImpl table with proper
    /// token generation and table management.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CIL assembly for managing metadata
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created interface implementation, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if class is not set
    /// - Returns error if interface is not set
    /// - Returns error if class RID is 0 (invalid RID)
    /// - Returns error if interface is not a valid TypeDefOrRef coded index
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let class = self.class.ok_or_else(|| {
            Error::ModificationInvalid("InterfaceImpl class is required".to_string())
        })?;

        let interface = self.interface.ok_or_else(|| {
            Error::ModificationInvalid("InterfaceImpl interface is required".to_string())
        })?;

        if class == 0 {
            return Err(Error::ModificationInvalid(
                "InterfaceImpl class RID cannot be 0".to_string(),
            ));
        }

        let valid_interface_tables = CodedIndexType::TypeDefOrRef.tables();
        if !valid_interface_tables.contains(&interface.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Interface must be a TypeDefOrRef coded index (TypeDef/TypeRef/TypeSpec), got {:?}",
                interface.tag
            )));
        }

        let rid = assembly.next_rid(TableId::InterfaceImpl)?;

        let token_value = ((TableId::InterfaceImpl as u32) << 24) | rid;
        let token = Token::new(token_value);

        let interface_impl_raw = InterfaceImplRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            class,
            interface,
        };

        assembly.table_row_add(
            TableId::InterfaceImpl,
            TableDataOwned::InterfaceImpl(interface_impl_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_interface_impl_builder_basic() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        // Create a basic interface implementation
        let implementing_class = 1; // TypeDef RID
        let target_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External interface

        let impl_ref = InterfaceImplBuilder::new()
            .class(implementing_class)
            .interface(target_interface)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            impl_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
    }

    #[test]
    fn test_interface_impl_builder_interface_extension() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        // Create an interface extending another interface
        let derived_interface = 2; // TypeDef RID for derived interface
        let base_interface = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base interface

        let impl_ref = InterfaceImplBuilder::new()
            .class(derived_interface)
            .interface(base_interface)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            impl_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
    }

    #[test]
    fn test_interface_impl_builder_generic_interface() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        // Create a generic interface implementation
        let implementing_class = 3; // TypeDef RID
        let generic_interface = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface instantiation

        let impl_ref = InterfaceImplBuilder::new()
            .class(implementing_class)
            .interface(generic_interface)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            impl_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
    }

    #[test]
    fn test_interface_impl_builder_missing_class() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        let target_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = InterfaceImplBuilder::new()
            .interface(target_interface)
            .build(&mut assembly);

        // Should fail because class is required
        assert!(result.is_err());
    }

    #[test]
    fn test_interface_impl_builder_missing_interface() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        let implementing_class = 1; // TypeDef RID

        let result = InterfaceImplBuilder::new()
            .class(implementing_class)
            .build(&mut assembly);

        // Should fail because interface is required
        assert!(result.is_err());
    }

    #[test]
    fn test_interface_impl_builder_zero_class_rid() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        let target_interface = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = InterfaceImplBuilder::new()
            .class(0) // Invalid RID
            .interface(target_interface)
            .build(&mut assembly);

        // Should fail because class RID cannot be 0
        assert!(result.is_err());
    }

    #[test]
    fn test_interface_impl_builder_invalid_interface_type() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        let implementing_class = 1; // TypeDef RID
                                    // Use a table type that's not valid for TypeDefOrRef
        let invalid_interface = CodedIndex::new(TableId::Field, 1, CodedIndexType::TypeDefOrRef); // Field not in TypeDefOrRef

        let result = InterfaceImplBuilder::new()
            .class(implementing_class)
            .interface(invalid_interface)
            .build(&mut assembly);

        // Should fail because interface type is not valid for TypeDefOrRef
        assert!(result.is_err());
    }

    #[test]
    fn test_interface_impl_builder_multiple_implementations() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        let class1 = 1; // TypeDef RID
        let class2 = 2; // TypeDef RID
        let class3 = 3; // TypeDef RID

        let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // IDisposable
        let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IComparable
        let interface3 = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface

        // Create multiple interface implementations
        let impl1_ref = InterfaceImplBuilder::new()
            .class(class1)
            .interface(interface1.clone())
            .build(&mut assembly)
            .unwrap();

        let impl2_ref = InterfaceImplBuilder::new()
            .class(class1) // Same class implementing multiple interfaces
            .interface(interface2.clone())
            .build(&mut assembly)
            .unwrap();

        let impl3_ref = InterfaceImplBuilder::new()
            .class(class2)
            .interface(interface1) // Same interface implemented by multiple classes
            .build(&mut assembly)
            .unwrap();

        let impl4_ref = InterfaceImplBuilder::new()
            .class(class3)
            .interface(interface3)
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different refs
        assert!(!std::sync::Arc::ptr_eq(&impl1_ref, &impl2_ref));
        assert!(!std::sync::Arc::ptr_eq(&impl1_ref, &impl3_ref));
        assert!(!std::sync::Arc::ptr_eq(&impl1_ref, &impl4_ref));
        assert!(!std::sync::Arc::ptr_eq(&impl2_ref, &impl3_ref));
        assert!(!std::sync::Arc::ptr_eq(&impl2_ref, &impl4_ref));
        assert!(!std::sync::Arc::ptr_eq(&impl3_ref, &impl4_ref));

        // All should have InterfaceImpl table kind
        assert_eq!(
            impl1_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
        assert_eq!(
            impl2_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
        assert_eq!(
            impl3_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
        assert_eq!(
            impl4_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
    }

    #[test]
    fn test_interface_impl_builder_complex_inheritance() {
        let mut assembly = get_test_assembly().expect("the fixture loads");
        // Create a complex inheritance scenario
        let base_class = 1; // TypeDef RID for base class
        let derived_class = 2; // TypeDef RID for derived class
        let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // Base interface
        let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // Derived interface

        // Base class implements interface1
        let base_impl_ref = InterfaceImplBuilder::new()
            .class(base_class)
            .interface(interface1)
            .build(&mut assembly)
            .unwrap();

        // Derived class implements interface2 (additional interface)
        let derived_impl_ref = InterfaceImplBuilder::new()
            .class(derived_class)
            .interface(interface2)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed with different refs
        assert!(!std::sync::Arc::ptr_eq(&base_impl_ref, &derived_impl_ref));
        assert_eq!(
            base_impl_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
        assert_eq!(
            derived_impl_ref.kind(),
            ChangeRefKind::TableRow(TableId::InterfaceImpl)
        );
    }
}
