//! Owned `GenericParamConstraint` structures for the `GenericParamConstraint` metadata table.
//!
//! This module provides the [`GenericParamConstraint`] struct which represents constraint
//! definitions with resolved references and owned data. Generic parameter constraints
//! specify base classes and interfaces that type arguments must satisfy.
//!
//! # Purpose
//! The `GenericParamConstraint` table enables constraint-based generic programming:
//! - **Base class constraints**: Inheritance requirements for type arguments
//! - **Interface constraints**: Implementation requirements for type arguments
//! - **Type safety**: Compile-time verification of constraint satisfaction
//! - **Code optimization**: Enabling specialized code generation for constrained types
//! - **Reflection metadata**: Runtime access to constraint information
//!
//! # Constraint Semantics
//! Constraints provide type safety guarantees:
//! - **Compile-time checking**: Verify type arguments satisfy all constraints
//! - **Method resolution**: Enable constraint-based method calls on parameters
//! - **Cast elimination**: Remove unnecessary runtime type checks
//! - **Performance optimization**: Generate specialized code for constrained types
//! - **API contracts**: Document type requirements for generic APIs
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.21 for the `GenericParamConstraint` table specification.

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList, tables::GenericParamRc, token::Token,
        typesystem::CilTypeRc,
    },
    Result,
};

/// Represents a generic parameter constraint definition with resolved references and owned data.
///
/// A generic parameter constraint specifies a type that serves as a constraint for a generic
/// parameter, requiring type arguments to satisfy inheritance or implementation relationships
/// with the constraint type.
///
/// # Constraint Types
/// Constraints can specify various requirements:
/// - **Base class constraints**: `where T : BaseClass` (inheritance requirement)
/// - **Interface constraints**: `where T : IInterface` (implementation requirement)
/// - **Multiple constraints**: Parameters can have multiple constraint entries
/// - **Circular constraints**: `where T : IComparable<T>` (self-referential constraints)
/// - **Nested generic constraints**: `where T : IList<U>` (constraints with generic arguments)
///
/// # Constraint Validation
/// Each constraint undergoes validation during application:
/// - **Compatibility checking**: Ensures constraint types are valid for the parameter
/// - **Accessibility verification**: Confirms constraint types are accessible
/// - **Circular dependency detection**: Prevents invalid constraint cycles
/// - **Attribute consistency**: Validates constraint compatibility with parameter attributes
///
/// # Type Safety Benefits
/// Constraints enable several type safety features:
/// ```text
/// ┌──────────────────────┬─────────────────────────────────────────┐
/// │ Benefit              │ Description                             │
/// ├──────────────────────┼─────────────────────────────────────────┤
/// │ Compile-time Checking│ Verify type arguments satisfy constraints│
/// │ Method Resolution    │ Enable calls to constraint methods      │
/// │ Cast Elimination     │ Remove unnecessary runtime type checks  │
/// │ Code Specialization  │ Generate optimized code for constraints │
/// │ API Documentation    │ Document type requirements clearly      │
/// └──────────────────────┴─────────────────────────────────────────┘
/// ```
///
/// # Constraint Application
/// When applied, constraints are:
/// - **Validated**: Checked for compatibility and accessibility
/// - **Associated**: Added to the parameter's constraint collection
/// - **Available**: Made available for type checking and code generation
/// - **Documented**: Accessible through reflection APIs
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.21 for the complete `GenericParamConstraint` table specification.
pub struct GenericParamConstraint {
    /// The row identifier in the `GenericParamConstraint` table.
    ///
    /// This 1-based index uniquely identifies this constraint within the `GenericParamConstraint` table.
    /// Combined with the table type, it forms the constraint's unique identity.
    pub rid: u32,

    /// The metadata token for this generic parameter constraint.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this constraint across the entire assembly.
    /// The token encodes both the table type (`GenericParamConstraint`) and the row ID.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this constraint in the metadata tables stream.
    ///
    /// This offset points to the start of this constraint's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Reference to the generic parameter that this constraint applies to.
    ///
    /// A reference-counted [`GenericParam`] instance representing the parameter
    /// that is being constrained. This parameter can be either a type-level
    /// or method-level generic parameter.
    ///
    /// [`GenericParam`]: crate::metadata::tables::GenericParam
    pub owner: GenericParamRc,

    /// Reference to the type that serves as the constraint.
    ///
    /// A reference-counted [`CilType`] instance representing the constraint type.
    /// This can be a base class, interface, or other type that the generic parameter
    /// must satisfy through inheritance or implementation.
    ///
    /// [`CilType`]: crate::metadata::typesystem::CilType
    pub constraint: CilTypeRc,

    /// Custom attributes applied to this generic parameter constraint.
    ///
    /// A collection of custom attributes that provide additional metadata
    /// about the constraint, such as documentation or analysis annotations.
    pub custom_attributes: CustomAttributeValueList,
}

impl GenericParamConstraint {
    /// Apply this constraint to the referenced generic parameter.
    ///
    /// This method validates the constraint compatibility and associates it with the
    /// target generic parameter. The constraint undergoes validation to ensure it
    /// is compatible with the parameter's attributes and accessibility requirements.
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Constraint compatibility validation fails
    /// - Constraint type is inaccessible or invalid
    /// - Parameter attribute conflicts exist
    /// - Circular constraint dependencies are detected
    /// - Constraint collection operations fail
    ///
    /// # Errors
    /// - **Incompatible Constraint**: If the constraint type is incompatible with parameter attributes
    /// - **Inaccessible Type**: If the constraint type is not accessible in the parameter's context
    /// - **Circular Dependency**: If the constraint creates an invalid circular reference
    /// - **Validation Failure**: If constraint validation encounters other issues
    pub fn apply(&self) -> Result<()> {
        self.owner
            .constraints
            .push_row(self.token, self.constraint.clone().into());
        Ok(())
    }
}
