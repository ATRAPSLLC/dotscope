//! GenericParamConstraintBuilder for creating generic parameter constraint specifications.
//!
//! This module provides [`crate::metadata::tables::genericparamconstraint::GenericParamConstraintBuilder`] for creating GenericParamConstraint table entries
//! with a fluent API. Generic parameter constraints specify type restrictions on generic parameters,
//! enabling type-safe generic programming with base class constraints, interface requirements,
//! and complex type relationships in .NET assemblies.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{CodedIndex, CodedIndexType, GenericParamConstraintRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating GenericParamConstraint metadata entries.
///
/// `GenericParamConstraintBuilder` provides a fluent API for creating GenericParamConstraint table entries
/// with validation and automatic table management. Generic parameter constraints define type restrictions
/// on generic parameters, enabling sophisticated type-safe programming with inheritance constraints,
/// interface requirements, value/reference type restrictions, and constructor constraints.
///
/// # Generic Constraint Model
///
/// .NET generic parameter constraints follow a structured pattern:
/// - **Owner Parameter**: The generic parameter that has this constraint applied
/// - **Constraint Type**: The type that the parameter must satisfy (base class, interface, etc.)
/// - **Multiple Constraints**: A parameter can have multiple constraint entries
/// - **Constraint Hierarchy**: Constraints interact with variance and inheritance rules
///
/// # Coded Index Types
///
/// Generic parameter constraints use specific table references:
/// - **Owner**: Direct GenericParam table index (RID or Token)
/// - **Constraint**: `TypeDefOrRef` coded index for the constraint type
///
/// # Constraint Types and Scenarios
///
/// Generic parameter constraints support various type restriction scenarios:
/// - **Base Class Constraints**: `where T : BaseClass` (TypeDef/TypeRef)
/// - **Interface Constraints**: `where T : IInterface` (TypeDef/TypeRef)
/// - **Generic Type Constraints**: `where T : IComparable<T>` (TypeSpec)
/// - **Value Type Constraints**: `where T : struct` (handled via GenericParamAttributes)
/// - **Reference Type Constraints**: `where T : class` (handled via GenericParamAttributes)
/// - **Constructor Constraints**: `where T : new()` (handled via GenericParamAttributes)
///
/// # Multiple Constraints
///
/// A single generic parameter can have multiple constraint entries:
/// ```text
/// where T : BaseClass, IInterface1, IInterface2, new()
/// ```
/// This creates multiple GenericParamConstraint entries (one for BaseClass, one for each interface),
/// plus GenericParamAttributes flags for the constructor constraint.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{GenericParamConstraintBuilder, CodedIndex, TableId};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a base class constraint: where T : BaseClass
/// let generic_param_rid = 1; // GenericParam RID 1
/// let base_class_ref = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base class
///
/// let base_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_rid)
///     .constraint(base_class_ref)
///     .build(&mut assembly)?;
///
/// // Create an interface constraint: where T : IComparable
/// let interface_ref = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External interface
///
/// let interface_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_rid) // Same parameter can have multiple constraints
///     .constraint(interface_ref)
///     .build(&mut assembly)?;
///
/// // Create a generic interface constraint: where T : IEnumerable<string>
/// let generic_interface_spec = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic type spec
///
/// let generic_constraint = GenericParamConstraintBuilder::new()
///     .owner(generic_param_rid)
///     .constraint(generic_interface_spec)
///     .build(&mut assembly)?;
///
/// // Create constraints for a method-level generic parameter
/// let method_param_rid = 2; // GenericParam RID 2 (method parameter)
/// let system_object_ref = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // System.Object
///
/// let method_constraint = GenericParamConstraintBuilder::new()
///     .owner(method_param_rid)
///     .constraint(system_object_ref)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct GenericParamConstraintBuilder {
    owner: Option<u32>,
    constraint: Option<CodedIndex>,
}

impl Default for GenericParamConstraintBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericParamConstraintBuilder {
    /// Creates a new GenericParamConstraintBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::genericparamconstraint::GenericParamConstraintBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            owner: None,
            constraint: None,
        }
    }

    /// Sets the owning generic parameter.
    ///
    /// The owner must be a valid GenericParam RID that references a generic parameter
    /// defined in the current assembly. This establishes which generic parameter will
    /// have this constraint applied to it during type checking and instantiation.
    ///
    /// Multiple constraints can be applied to the same parameter by creating multiple
    /// GenericParamConstraint entries with the same owner RID.
    ///
    /// Parameter types that can own constraints:
    /// - **Type-level parameters**: Generic parameters defined on classes, interfaces, structs
    /// - **Method-level parameters**: Generic parameters defined on individual methods
    /// - **Delegate parameters**: Generic parameters defined on delegate types
    ///
    /// # Arguments
    ///
    /// * `owner` - A GenericParam RID pointing to the owning generic parameter
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn owner(mut self, owner: u32) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Sets the constraint type specification.
    ///
    /// The constraint must be a valid `TypeDefOrRef` coded index that references
    /// a type that the generic parameter must satisfy. This type becomes a compile-time
    /// and runtime constraint that limits which types can be used as arguments for
    /// the generic parameter.
    ///
    /// Valid constraint types include:
    /// - `TypeDef` - Base classes and interfaces defined in the current assembly
    /// - `TypeRef` - External base classes and interfaces from other assemblies
    /// - `TypeSpec` - Complex types including generic instantiations and constructed types
    ///
    /// Common constraint scenarios:
    /// - **Base Class**: Requires parameter to inherit from a specific class
    /// - **Interface**: Requires parameter to implement a specific interface
    /// - **Generic Interface**: Requires parameter to implement a generic interface with specific type arguments
    /// - **Constructed Type**: Complex type relationships involving arrays, pointers, or nested generics
    ///
    /// # Arguments
    ///
    /// * `constraint` - A `TypeDefOrRef` coded index pointing to the constraint type
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn constraint(mut self, constraint: CodedIndex) -> Self {
        self.constraint = Some(constraint);
        self
    }

    /// Builds the generic parameter constraint and adds it to the assembly.
    ///
    /// This method validates all required fields are set, verifies the coded index types
    /// are correct, creates the raw constraint structure, and adds it to the
    /// GenericParamConstraint table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CIL assembly for managing metadata
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created generic parameter constraint, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if owner is not set
    /// - Returns error if constraint is not set
    /// - Returns error if owner RID is 0
    /// - Returns error if constraint is not a valid TypeDefOrRef coded index
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let owner = self.owner.ok_or_else(|| {
            Error::ModificationInvalid("GenericParamConstraint owner is required".to_string())
        })?;

        let constraint = self.constraint.ok_or_else(|| {
            Error::ModificationInvalid("GenericParamConstraint constraint is required".to_string())
        })?;

        if owner == 0 {
            return Err(Error::ModificationInvalid(
                "GenericParamConstraint owner RID cannot be 0".to_string(),
            ));
        }

        let valid_constraint_tables = CodedIndexType::TypeDefOrRef.tables();
        if !valid_constraint_tables.contains(&constraint.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Constraint must be a TypeDefOrRef coded index (TypeDef/TypeRef/TypeSpec), got {:?}",
                constraint.tag
            )));
        }

        let rid = assembly.next_rid(TableId::GenericParamConstraint)?;

        let token_value = ((TableId::GenericParamConstraint as u32) << 24) | rid;
        let token = Token::new(token_value);

        let constraint_raw = GenericParamConstraintRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            owner,
            constraint,
        };

        assembly.table_row_add(
            TableId::GenericParamConstraint,
            TableDataOwned::GenericParamConstraint(constraint_raw),
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
    fn test_generic_param_constraint_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a basic generic parameter constraint
        let owner_rid = 1; // GenericParam RID 1
        let constraint_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // External base class

        let constraint_ref = GenericParamConstraintBuilder::new()
            .owner(owner_rid)
            .constraint(constraint_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_base_class() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a base class constraint
        let generic_param_rid = 1; // GenericParam RID 1
        let base_class = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Local base class

        let constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(base_class)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_interface() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an interface constraint
        let generic_param_rid = 2; // GenericParam RID 2
        let interface_ref = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // External interface

        let constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(interface_ref)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_generic_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a generic type constraint (e.g., IComparable<T>)
        let generic_param_rid = 3; // GenericParam RID 3
        let generic_interface = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface instantiation

        let constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(generic_interface)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_missing_owner() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let constraint_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = GenericParamConstraintBuilder::new()
            .constraint(constraint_type)
            .build(&mut assembly);

        // Should fail because owner is required
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_constraint_builder_missing_constraint() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let owner_rid = 1; // GenericParam RID 1

        let result = GenericParamConstraintBuilder::new()
            .owner(owner_rid)
            .build(&mut assembly);

        // Should fail because constraint is required
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_constraint_builder_zero_owner_rid() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use RID 0 (invalid)
        let invalid_owner = 0; // RID 0
        let constraint_type = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef);

        let result = GenericParamConstraintBuilder::new()
            .owner(invalid_owner)
            .constraint(constraint_type)
            .build(&mut assembly);

        // Should fail because owner RID cannot be 0
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_constraint_builder_invalid_constraint_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let owner_rid = 1; // GenericParam RID 1
                           // Use a table type that's not valid for TypeDefOrRef
        let invalid_constraint = CodedIndex::new(TableId::Field, 1, CodedIndexType::TypeDefOrRef); // Field not in TypeDefOrRef

        let result = GenericParamConstraintBuilder::new()
            .owner(owner_rid)
            .constraint(invalid_constraint)
            .build(&mut assembly);

        // Should fail because constraint type is not valid for TypeDefOrRef
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_constraint_builder_multiple_constraints() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_param_rid = 1; // GenericParam RID 1

        // Create multiple constraints for the same parameter
        let base_class = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeDefOrRef); // Base class constraint
        let interface1 = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // First interface
        let interface2 = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // Second interface
        let generic_interface = CodedIndex::new(TableId::TypeSpec, 1, CodedIndexType::TypeDefOrRef); // Generic interface

        let constraint1_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(base_class)
            .build(&mut assembly)
            .unwrap();

        let constraint2_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid) // Same parameter
            .constraint(interface1)
            .build(&mut assembly)
            .unwrap();

        let constraint3_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid) // Same parameter
            .constraint(interface2)
            .build(&mut assembly)
            .unwrap();

        let constraint4_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid) // Same parameter
            .constraint(generic_interface)
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different references
        assert!(!std::sync::Arc::ptr_eq(&constraint1_ref, &constraint2_ref));
        assert!(!std::sync::Arc::ptr_eq(&constraint1_ref, &constraint3_ref));
        assert!(!std::sync::Arc::ptr_eq(&constraint1_ref, &constraint4_ref));
        assert!(!std::sync::Arc::ptr_eq(&constraint2_ref, &constraint3_ref));
        assert!(!std::sync::Arc::ptr_eq(&constraint2_ref, &constraint4_ref));
        assert!(!std::sync::Arc::ptr_eq(&constraint3_ref, &constraint4_ref));

        // All should have GenericParamConstraint table kind
        assert_eq!(
            constraint1_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            constraint2_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            constraint3_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            constraint4_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_different_parameters() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create constraints for different generic parameters
        let type_param_rid = 1; // Type-level parameter
        let method_param_rid = 2; // Method-level parameter

        let type_constraint = CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef); // System.Object
        let method_constraint = CodedIndex::new(TableId::TypeRef, 2, CodedIndexType::TypeDefOrRef); // IDisposable

        let type_const_ref = GenericParamConstraintBuilder::new()
            .owner(type_param_rid)
            .constraint(type_constraint)
            .build(&mut assembly)
            .unwrap();

        let method_const_ref = GenericParamConstraintBuilder::new()
            .owner(method_param_rid)
            .constraint(method_constraint)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed with different references
        assert!(!std::sync::Arc::ptr_eq(&type_const_ref, &method_const_ref));
        assert_eq!(
            type_const_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            method_const_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_all_constraint_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_param_rid = 1; // GenericParam RID 1

        // Test all valid TypeDefOrRef coded index types

        // TypeDef constraint (local type)
        let typedef_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeDef,
                1,
                CodedIndexType::TypeDefOrRef,
            ))
            .build(&mut assembly)
            .unwrap();

        // TypeRef constraint (external type)
        let typeref_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeRef,
                1,
                CodedIndexType::TypeDefOrRef,
            ))
            .build(&mut assembly)
            .unwrap();

        // TypeSpec constraint (generic type instantiation)
        let typespec_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(generic_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeSpec,
                1,
                CodedIndexType::TypeDefOrRef,
            ))
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different references
        assert!(!std::sync::Arc::ptr_eq(
            &typedef_constraint_ref,
            &typeref_constraint_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &typedef_constraint_ref,
            &typespec_constraint_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &typeref_constraint_ref,
            &typespec_constraint_ref
        ));

        // All should have GenericParamConstraint table kind
        assert_eq!(
            typedef_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            typeref_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            typespec_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
    }

    #[test]
    fn test_generic_param_constraint_builder_realistic_scenario() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Realistic scenario: class MyClass<T> where T : BaseClass, IComparable<T>, IDisposable
        let type_param_rid = 1; // T parameter

        // Base class constraint: T : BaseClass
        let base_class_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(type_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeDef,
                1,
                CodedIndexType::TypeDefOrRef,
            )) // Local BaseClass
            .build(&mut assembly)
            .unwrap();

        // Generic interface constraint: T : IComparable<T>
        let comparable_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(type_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeSpec,
                1,
                CodedIndexType::TypeDefOrRef,
            )) // IComparable<T> type spec
            .build(&mut assembly)
            .unwrap();

        // Interface constraint: T : IDisposable
        let disposable_constraint_ref = GenericParamConstraintBuilder::new()
            .owner(type_param_rid)
            .constraint(CodedIndex::new(
                TableId::TypeRef,
                1,
                CodedIndexType::TypeDefOrRef,
            )) // External IDisposable
            .build(&mut assembly)
            .unwrap();

        // All constraints should be created successfully
        assert_eq!(
            base_class_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            comparable_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );
        assert_eq!(
            disposable_constraint_ref.kind(),
            ChangeRefKind::TableRow(TableId::GenericParamConstraint)
        );

        // All should be different references
        assert!(!std::sync::Arc::ptr_eq(
            &base_class_constraint_ref,
            &comparable_constraint_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &base_class_constraint_ref,
            &disposable_constraint_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &comparable_constraint_ref,
            &disposable_constraint_ref
        ));
    }
}
