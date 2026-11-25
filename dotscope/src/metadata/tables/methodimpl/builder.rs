//! MethodImplBuilder for creating method implementation mapping metadata entries.
//!
//! This module provides [`crate::metadata::tables::methodimpl::MethodImplBuilder`] for creating MethodImpl table entries
//! with a fluent API. Method implementation mappings define which concrete methods
//! provide the implementation for interface method declarations or virtual method
//! overrides, enabling polymorphic dispatch and interface implementation contracts.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, MethodImplRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Represents a method reference target for MethodImpl entries.
///
/// This enum captures both the row index (which can be a placeholder or actual row ID)
/// and the target table type. The `CodedIndex` is constructed at write time, not at
/// builder time, to ensure proper placeholder resolution.
#[derive(Debug, Clone, Copy)]
enum MethodRefTarget {
    /// Reference to a MethodDef table entry
    MethodDef(u32),
    /// Reference to a MemberRef table entry
    MemberRef(u32),
}

/// Builder for creating MethodImpl metadata entries.
///
/// `MethodImplBuilder` provides a fluent API for creating MethodImpl table entries
/// with validation and automatic relationship management. Method implementation mappings
/// are essential for interface implementation, method overriding, and virtual dispatch
/// in .NET object-oriented programming.
///
/// # Method Implementation Model
///
/// .NET method implementation mappings follow this pattern:
/// - **Implementation Class**: The type containing the concrete implementation
/// - **Method Body**: The actual method that provides the implementation behavior
/// - **Method Declaration**: The interface method or virtual method being implemented
/// - **Polymorphic Dispatch**: Runtime method resolution through the mapping
///
/// # Implementation Mapping Categories
///
/// Different categories of method implementation mappings serve various purposes:
/// - **Interface Implementation**: Maps interface methods to concrete class implementations
/// - **Virtual Method Override**: Specifies derived class methods that override base virtual methods
/// - **Explicit Interface Implementation**: Handles explicit implementation of interface members
/// - **Generic Method Specialization**: Links generic method declarations to specialized implementations
/// - **Abstract Method Implementation**: Connects abstract method declarations to concrete implementations
///
/// # Coded Index Management
///
/// Method implementation mappings use MethodDefOrRef coded indices:
/// - **MethodDef References**: Methods defined in the current assembly
/// - **MemberRef References**: Methods referenced from external assemblies
/// - **Cross-Assembly Scenarios**: Support for interface implementations across assembly boundaries
/// - **Type Safety**: Compile-time and runtime validation of implementation contracts
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # fn main() -> Result<()> {
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// let mut assembly = CilAssembly::new(view);
///
/// // Create interface implementation mapping
/// let implementing_class = 1; // MyClass row index
/// let implementation_method = 1; // MyClass.DoWork() row index
/// let interface_method = 1; // IWorker.DoWork() row index
///
/// let method_impl = MethodImplBuilder::new()
///     .class(implementing_class)
///     .method_body_from_method_def(implementation_method)
///     .method_declaration_from_member_ref(interface_method)
///     .build(&mut assembly)?;
///
/// // Create virtual method override mapping
/// let derived_class = 2; // DerivedClass row index
/// let override_method = 2; // DerivedClass.VirtualMethod() row index
/// let base_method = 3; // BaseClass.VirtualMethod() row index
///
/// let override_impl = MethodImplBuilder::new()
///     .class(derived_class)
///     .method_body_from_method_def(override_method)
///     .method_declaration_from_method_def(base_method)
///     .build(&mut assembly)?;
///
/// // Create explicit interface implementation
/// let explicit_class = 3; // ExplicitImpl row index
/// let explicit_method = 4; // ExplicitImpl.IInterface.Method() row index
/// let interface_decl = 2; // IInterface.Method() row index
///
/// let explicit_impl = MethodImplBuilder::new()
///     .class(explicit_class)
///     .method_body_from_method_def(explicit_method)
///     .method_declaration_from_member_ref(interface_decl)
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodImplBuilder {
    /// Row index of the implementing class in the TypeDef table.
    /// Can be a placeholder or actual row ID.
    class: Option<u32>,
    /// Method body target capturing the row index and target table type.
    /// The `CodedIndex` is constructed at write time.
    method_body: Option<MethodRefTarget>,
    /// Method declaration target capturing the row index and target table type.
    /// The `CodedIndex` is constructed at write time.
    method_declaration: Option<MethodRefTarget>,
}

impl Default for MethodImplBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodImplBuilder {
    /// Creates a new MethodImplBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::methodimpl::MethodImplBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            class: None,
            method_body: None,
            method_declaration: None,
        }
    }

    /// Sets the implementing class for this method implementation mapping.
    ///
    /// Specifies the type that contains the concrete implementation method.
    /// This class provides the actual method body that implements the interface
    /// contract or overrides the virtual method declaration.
    ///
    /// # Implementation Class Role
    ///
    /// The implementation class serves several purposes:
    /// - **Method Container**: Houses the concrete implementation method
    /// - **Type Context**: Provides the type context for method resolution
    /// - **Inheritance Chain**: Participates in virtual method dispatch
    /// - **Interface Contract**: Fulfills interface implementation requirements
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (RID) in the TypeDef table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let my_class = 1; // MyClass TypeDef row index
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .class(my_class)
    ///     // ... set method body and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn class(mut self, row: u32) -> Self {
        self.class = Some(row);
        self
    }

    /// Sets the method body from a MethodDef token.
    ///
    /// Specifies the concrete method implementation using a MethodDef token.
    /// This method contains the actual IL code or native implementation that
    /// provides the behavior for the method declaration.
    ///
    /// # Method Body Characteristics
    ///
    /// MethodDef method bodies have these properties:
    /// - **Local Definition**: Defined in the current assembly
    /// - **Implementation Code**: Contains actual IL or native code
    /// - **Direct Reference**: No additional resolution required
    /// - **Type Ownership**: Belongs to the implementing class
    ///
    /// # Arguments
    ///
    /// * `row` - Row index (RID) in the MethodDef table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let implementation_method = 1; // MyClass.DoWork() row index
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_body_from_method_def(implementation_method)
    ///     // ... set class and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_body_from_method_def(mut self, row: u32) -> Self {
        self.method_body = Some(MethodRefTarget::MethodDef(row));
        self
    }

    /// Sets the method body from a MemberRef row index or placeholder.
    ///
    /// Stores the MemberRef row index for later construction of a MethodDefOrRef coded index
    /// during the write phase. The `CodedIndex` is NOT created at builder time to ensure
    /// proper placeholder resolution.
    ///
    /// # Member Reference Characteristics
    ///
    /// MemberRef method bodies have these properties:
    /// - **External Definition**: Defined in external assembly or module
    /// - **Cross-Assembly**: Requires assembly boundary resolution
    /// - **Signature Matching**: Must match expected method signature
    /// - **Dynamic Resolution**: Resolved at runtime or link time
    ///
    /// # Arguments
    ///
    /// * `row` - Row index or placeholder in the MemberRef table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let external_method = 1; // External.DoWork() row index
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_body_from_member_ref(external_method)
    ///     // ... set class and declaration
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_body_from_member_ref(mut self, row: u32) -> Self {
        self.method_body = Some(MethodRefTarget::MemberRef(row));
        self
    }

    /// Sets the method declaration from a MethodDef row index or placeholder.
    ///
    /// Stores the MethodDef row index for later construction of a MethodDefOrRef coded index
    /// during the write phase. The `CodedIndex` is NOT created at builder time to ensure
    /// proper placeholder resolution.
    ///
    /// # Method Declaration Characteristics
    ///
    /// MethodDef method declarations have these properties:
    /// - **Local Declaration**: Declared in the current assembly
    /// - **Virtual Dispatch**: Supports polymorphic method calls
    /// - **Inheritance Chain**: Part of class inheritance hierarchy
    /// - **Override Semantics**: Enables method overriding behavior
    ///
    /// # Arguments
    ///
    /// * `row` - Row index or placeholder in the MethodDef table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let base_method = 2; // BaseClass.VirtualMethod() row index
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_declaration_from_method_def(base_method)
    ///     // ... set class and body
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_declaration_from_method_def(mut self, row: u32) -> Self {
        self.method_declaration = Some(MethodRefTarget::MethodDef(row));
        self
    }

    /// Sets the method declaration from a MemberRef row index or placeholder.
    ///
    /// Stores the MemberRef row index for later construction of a MethodDefOrRef coded index
    /// during the write phase. The `CodedIndex` is NOT created at builder time to ensure
    /// proper placeholder resolution.
    ///
    /// # Interface Declaration Characteristics
    ///
    /// MemberRef method declarations have these properties:
    /// - **External Declaration**: Declared in external assembly or module
    /// - **Interface Contract**: Defines implementation requirements
    /// - **Cross-Assembly**: Supports multi-assembly interfaces
    /// - **Signature Contract**: Establishes method signature requirements
    ///
    /// # Arguments
    ///
    /// * `row` - Row index or placeholder in the MemberRef table
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # fn main() -> Result<()> {
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let interface_method = 2; // IWorker.DoWork() row index
    ///
    /// let method_impl = MethodImplBuilder::new()
    ///     .method_declaration_from_member_ref(interface_method)
    ///     // ... set class and body
    ///     # ;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn method_declaration_from_member_ref(mut self, row: u32) -> Self {
        self.method_declaration = Some(MethodRefTarget::MemberRef(row));
        self
    }

    /// Builds the MethodImpl metadata entry.
    ///
    /// Creates a new MethodImpl entry in the metadata with the configured implementation
    /// mapping. The mapping establishes the relationship between a method declaration
    /// (interface method or virtual method) and its concrete implementation.
    ///
    /// # Validation
    ///
    /// The build process performs several validation checks:
    /// - **Class Required**: An implementing class must be specified
    /// - **Method Body Required**: A concrete implementation method must be specified
    /// - **Method Declaration Required**: A method declaration being implemented must be specified
    /// - **Coded Index Validity**: Both coded indices must be well-formed
    /// - **Token References**: Referenced tokens must be valid within their respective tables
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly for metadata operations
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] referencing the created MethodImpl entry.
    ///
    /// # Errors
    ///
    /// - Missing class, method body, or method declaration
    /// - Invalid token references in the coded indices
    /// - Table operations fail due to metadata constraints
    /// - Implementation mapping validation failed
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let class_rid = self.class.ok_or_else(|| {
            Error::ModificationInvalid("MethodImplBuilder requires a class row index".to_string())
        })?;

        let method_body_target = self.method_body.ok_or_else(|| {
            Error::ModificationInvalid("MethodImplBuilder requires a method body".to_string())
        })?;

        let method_declaration_target = self.method_declaration.ok_or_else(|| {
            Error::ModificationInvalid(
                "MethodImplBuilder requires a method declaration".to_string(),
            )
        })?;

        // Construct the CodedIndex from the stored target information.
        // The row value may be a placeholder that will be resolved at write time
        // by the ResolvePlaceholders implementation.
        let method_body = match method_body_target {
            MethodRefTarget::MethodDef(row) => {
                CodedIndex::new(TableId::MethodDef, row, CodedIndexType::MethodDefOrRef)
            }
            MethodRefTarget::MemberRef(row) => {
                CodedIndex::new(TableId::MemberRef, row, CodedIndexType::MethodDefOrRef)
            }
        };

        let method_declaration = match method_declaration_target {
            MethodRefTarget::MethodDef(row) => {
                CodedIndex::new(TableId::MethodDef, row, CodedIndexType::MethodDefOrRef)
            }
            MethodRefTarget::MemberRef(row) => {
                CodedIndex::new(TableId::MemberRef, row, CodedIndexType::MethodDefOrRef)
            }
        };

        let next_rid = assembly.next_rid(TableId::MethodImpl)?;
        let token = Token::new(((TableId::MethodImpl as u32) << 24) | next_rid);

        let method_impl_raw = MethodImplRaw {
            rid: next_rid,
            token,
            offset: 0, // Will be set during binary generation
            class: class_rid,
            method_body,
            method_declaration,
        };

        assembly.table_row_add(
            TableId::MethodImpl,
            TableDataOwned::MethodImpl(method_impl_raw),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        testkit::fixture,
    };

    #[test]
    fn test_methodimpl_builder_creation() {
        let builder = MethodImplBuilder::new();
        assert!(builder.class.is_none());
        assert!(builder.method_body.is_none());
        assert!(builder.method_declaration.is_none());
    }

    #[test]
    fn test_methodimpl_builder_default() {
        let builder = MethodImplBuilder::default();
        assert!(builder.class.is_none());
        assert!(builder.method_body.is_none());
        assert!(builder.method_declaration.is_none());
    }

    #[test]
    fn test_interface_implementation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Get the expected next RID for MethodImpl
        let _expected_rid = assembly.next_rid(TableId::MethodImpl).unwrap();

        let implementing_class = 1; // MyClass
        let implementation_method = 1; // MyClass.DoWork()
        let interface_method = 1; // IWorker.DoWork()

        let ref_ = MethodImplBuilder::new()
            .class(implementing_class)
            .method_body_from_method_def(implementation_method)
            .method_declaration_from_member_ref(interface_method)
            .build(&mut assembly)
            .expect("Should build MethodImpl");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
    }

    #[test]
    fn test_virtual_method_override() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Get the expected next RID for MethodImpl
        let _expected_rid = assembly.next_rid(TableId::MethodImpl).unwrap();

        let derived_class = 2; // DerivedClass
        let override_method = 2; // DerivedClass.VirtualMethod()
        let base_method = 3; // BaseClass.VirtualMethod()

        let ref_ = MethodImplBuilder::new()
            .class(derived_class)
            .method_body_from_method_def(override_method)
            .method_declaration_from_method_def(base_method)
            .build(&mut assembly)
            .expect("Should build virtual override MethodImpl");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
    }

    #[test]
    fn test_explicit_interface_implementation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Get the expected next RID for MethodImpl
        let _expected_rid = assembly.next_rid(TableId::MethodImpl).unwrap();

        let explicit_class = 3; // ExplicitImpl
        let explicit_method = 4; // ExplicitImpl.IInterface.Method()
        let interface_decl = 2; // IInterface.Method()

        let ref_ = MethodImplBuilder::new()
            .class(explicit_class)
            .method_body_from_method_def(explicit_method)
            .method_declaration_from_member_ref(interface_decl)
            .build(&mut assembly)
            .expect("Should build explicit interface MethodImpl");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
    }

    #[test]
    fn test_external_method_body() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Get the expected next RID for MethodImpl
        let _expected_rid = assembly.next_rid(TableId::MethodImpl).unwrap();

        let implementing_class = 1;
        let external_method = 3; // External method implementation
        let interface_method = 4;

        let ref_ = MethodImplBuilder::new()
            .class(implementing_class)
            .method_body_from_member_ref(external_method)
            .method_declaration_from_member_ref(interface_method)
            .build(&mut assembly)
            .expect("Should build external method MethodImpl");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
    }

    #[test]
    fn test_mixed_method_refs() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Get the expected next RID for MethodImpl
        let _expected_rid = assembly.next_rid(TableId::MethodImpl).unwrap();

        // Test using direct row indices with both MethodDef and MemberRef tables
        let implementing_class = 1;

        let ref_ = MethodImplBuilder::new()
            .class(implementing_class)
            .method_body_from_method_def(1)
            .method_declaration_from_member_ref(1)
            .build(&mut assembly)
            .expect("Should build mixed method ref MethodImpl");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
    }

    #[test]
    fn test_build_without_class_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodImplBuilder::new()
            .method_body_from_method_def(1)
            .method_declaration_from_member_ref(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires a class row index"));
    }

    #[test]
    fn test_build_without_method_body_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodImplBuilder::new()
            .class(1)
            .method_declaration_from_member_ref(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires a method body"));
    }

    #[test]
    fn test_build_without_method_declaration_fails() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = MethodImplBuilder::new()
            .class(1)
            .method_body_from_method_def(1)
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires a method declaration"));
    }

    #[test]
    fn test_multiple_method_impls() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref1 = MethodImplBuilder::new()
            .class(1)
            .method_body_from_method_def(1)
            .method_declaration_from_member_ref(1)
            .build(&mut assembly)
            .expect("Should build first MethodImpl");

        let ref2 = MethodImplBuilder::new()
            .class(1)
            .method_body_from_method_def(2)
            .method_declaration_from_member_ref(2)
            .build(&mut assembly)
            .expect("Should build second MethodImpl");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::MethodImpl));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
    }
}
