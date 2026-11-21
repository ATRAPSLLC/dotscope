//! Owned `GenericParam` structures for the `GenericParam` metadata table.
//!
//! This module provides the [`GenericParam`] struct which represents generic parameter
//! definitions with resolved references and owned data. Generic parameters enable
//! type-safe generic programming in .NET assemblies.
//!
//! # Purpose
//! The `GenericParam` table enables generic programming support:
//! - **Generic types**: Type parameters for classes and interfaces (`List<T>`)
//! - **Generic methods**: Method-level type parameters (`Method<U>()`)
//! - **Constraint specification**: Base class and interface constraints
//! - **Variance annotations**: Covariance and contravariance for type safety
//! - **Reflection metadata**: Runtime access to generic parameter information
//!
//! # Generic Parameter Context
//! Generic parameters provide type parameterization:
//! - **Type abstraction**: Define types that work with multiple concrete types
//! - **Type safety**: Compile-time verification of generic type usage
//! - **Performance**: Avoid boxing/unboxing with value types
//! - **Code reuse**: Single implementation works with many types
//! - **Constraint enforcement**: Compile-time constraint checking
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the `GenericParam` table specification.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        streams::SharedStr,
        tables::GenericParamAttributes,
        token::Token,
        typesystem::{CilTypeRef, CilTypeReference},
    },
    utils::RowList,
    Result,
};

/// Represents a generic parameter definition with resolved references and owned data.
///
/// A generic parameter defines a type or method parameter that can be substituted with
/// concrete types during instantiation. This enables generic programming with type safety
/// and performance benefits.
///
/// # Generic Parameter Types
/// Parameters can be defined at different scopes:
/// - **Type parameters**: Defined on classes, interfaces, and delegates
/// - **Method parameters**: Defined on individual methods
/// - **Nested parameters**: Parameters within generic types can have their own parameters
///
/// # Parameter Characteristics
/// Each parameter has several important properties:
/// - **Position**: Ordinal position in the parameter list (0-based)
/// - **Name**: Identifier used in signatures and source code
/// - **Constraints**: Restrictions on acceptable type arguments
/// - **Variance**: Covariance/contravariance for assignment compatibility
/// - **Owner**: The type or method that declares the parameter
///
/// # Variance Support
/// Generic parameters can specify variance for type safety:
/// ```text
/// ┌──────────────┬─────────────────┬─────────────────────────────┐
/// │ Variance     │ Keyword         │ Assignment Compatibility    │
/// ├──────────────┼─────────────────┼─────────────────────────────┤
/// │ Invariant    │ (none)          │ Exact type match required   │
/// │ Covariant    │ out             │ Derived → Base allowed      │
/// │ Contravariant│ in              │ Base → Derived allowed      │
/// └──────────────┴─────────────────┴─────────────────────────────┘
/// ```
///
/// # Constraint Types
/// Parameters can have various constraints:
/// - **Class constraint**: `where T : class` (reference types only)
/// - **Struct constraint**: `where T : struct` (value types only)
/// - **Constructor constraint**: `where T : new()` (parameterless constructor)
/// - **Base class constraint**: `where T : BaseClass` (inheritance requirement)
/// - **Interface constraints**: `where T : IInterface` (implementation requirement)
///
/// # Owner Resolution
/// Generic parameters are owned by either types or methods:
/// - **Type ownership**: Parameters declared on generic types
/// - **Method ownership**: Parameters declared on generic methods
/// - **Lazy resolution**: Owner is resolved when first accessed
/// - **Type reference**: Uses `CilTypeReference` for unified handling
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.20 for the complete `GenericParam` table specification.
pub struct GenericParam {
    /// The row identifier in the `GenericParam` table.
    ///
    /// This 1-based index uniquely identifies this generic parameter within the `GenericParam` table.
    /// Combined with the table type, it forms the parameter's unique identity.
    pub rid: u32,

    /// The metadata token for this generic parameter.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this generic parameter across the entire assembly.
    /// The token encodes both the table type (`GenericParam`) and the row ID.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this generic parameter in the metadata tables stream.
    ///
    /// This offset points to the start of this parameter's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// The ordinal position of this parameter in the parameter list.
    ///
    /// A 2-byte index indicating the parameter's position, numbered left-to-right
    /// starting from zero. This determines the parameter's position in generic
    /// instantiations and signature matching.
    pub number: u32,

    /// Generic parameter attribute flags indicating constraints and variance.
    ///
    /// A 2-byte bitmask of [`GenericParamAttributes`] values that specify:
    /// - **Variance**: Covariant, contravariant, or invariant
    /// - **Constraints**: Reference type, value type, constructor constraints
    /// - **Special flags**: Additional constraint information
    ///
    /// [`GenericParamAttributes`]: crate::metadata::tables::genericparam::GenericParamAttributes
    pub flags: GenericParamAttributes,

    /// Reference to the owner of this generic parameter.
    ///
    /// A lazily-initialized [`CilTypeReference`] that points to either:
    /// - **`TypeDef`**: For type-level generic parameters
    /// - **`MethodDef`**: For method-level generic parameters
    ///
    /// Uses [`OnceLock`] for thread-safe lazy initialization during owner resolution.
    ///
    /// [`CilTypeReference`]: crate::metadata::typesystem::CilTypeReference
    /// [`OnceLock`]: std::sync::OnceLock
    pub owner: OnceLock<CilTypeReference>,

    /// List of constraint types that apply to this parameter.
    ///
    /// A collection of [`CilTypeReference`] entries that specify the constraints
    /// imposed on this generic parameter, such as base classes and interfaces
    /// that type arguments must satisfy.
    ///
    /// [`CilTypeReference`]: crate::metadata::typesystem::CilTypeReference
    pub constraints: RowList<CilTypeRef>,

    /// The name of the generic parameter.
    ///
    /// The parameter name as it appears in source code and metadata, resolved
    /// from the strings heap. Used for reflection and debugging purposes.
    pub name: SharedStr,

    /// Custom attributes applied to this generic parameter.
    ///
    /// A collection of custom attributes that provide additional metadata
    /// about the parameter, such as documentation or analysis annotations.
    pub custom_attributes: CustomAttributeValueList,
}

impl GenericParam {
    /// Apply this generic parameter to its owner type or method.
    ///
    /// This method associates the generic parameter with its owner by adding it to
    /// the owner's parameter collection. The owner can be either a generic type
    /// (`TypeDef`) or a generic method (`MethodDef`).
    ///
    /// # Owner Types
    /// The owner can be one of two types:
    /// - **`TypeDef`**: Generic types with type parameters (`List<T>`)
    /// - **`MethodDef`**: Generic methods with method parameters (`Method<U>()`)
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Owner reference is not set or invalid
    /// - Owner type is not `TypeDef` or `MethodDef`
    /// - Method reference is weak and has been dropped
    /// - Parameter collection operations fail
    ///
    /// # Errors
    /// - **No Owner**: If the owner type reference is not set
    /// - **Invalid Owner**: If the owner is not a supported type or method reference
    /// - **Weak Reference**: If a method reference has been dropped
    ///
    /// # Runtime Impact
    /// After successful application, the parameter will:
    /// - Be available in the owner's parameter collection
    /// - Participate in generic instantiation and signature matching
    /// - Support constraint checking during type resolution
    /// - Enable reflection and metadata queries
    pub fn apply(self: &Arc<Self>) -> Result<()> {
        match self.owner.get() {
            Some(owner) => match owner {
                CilTypeReference::TypeDef(cil_type) => {
                    if let Some(generic_params) = cil_type.generic_params() {
                        let mut already_exists = false;
                        for (_, existing_param) in generic_params.iter() {
                            if existing_param.name == self.name
                                && existing_param.number == self.number
                            {
                                already_exists = true;
                                break;
                            }
                        }

                        if !already_exists {
                            generic_params.push_row(self.token, self.clone());
                        }
                    }

                    Ok(())
                }
                CilTypeReference::MethodDef(method) => {
                    if let Some(method) = method.upgrade() {
                        let mut already_exists = false;
                        for (_, existing_param) in method.generic_params.iter() {
                            if existing_param.name == self.name
                                && existing_param.number == self.number
                            {
                                already_exists = true;
                                break;
                            }
                        }

                        if !already_exists {
                            method.generic_params.push_row(self.token, self.clone());
                        }
                    }

                    Ok(())
                }
                _ => Err(malformed_error!("Invalid owner type reference")),
            },
            None => Err(malformed_error!("No owner type reference")),
        }
    }
}

impl fmt::Display for GenericParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Variance prefix
        let vk = self.flags.variance_keyword();
        if !vk.is_empty() {
            write!(f, "{vk}")?;
        }

        // Flag constraints
        let mut constraints = Vec::new();
        if self
            .flags
            .contains(GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT)
        {
            constraints.push("class".to_string());
        }
        if self
            .flags
            .contains(GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT)
        {
            constraints.push("valuetype".to_string());
        }
        if self
            .flags
            .contains(GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT)
        {
            constraints.push(".ctor".to_string());
        }

        // Type/interface constraints
        for (_, constraint_ref) in self.constraints.iter() {
            if let Some(constraint_type) = constraint_ref.upgrade() {
                constraints.push(constraint_type.fullname().to_string());
            }
        }

        if !constraints.is_empty() {
            write!(f, "({}) ", constraints.join(", "))?;
        }

        // Use ILAsm positional notation: !N for type params, !!N for method params
        match self.owner.get() {
            Some(CilTypeReference::TypeDef(_)) => write!(f, "!{}", self.number),
            Some(CilTypeReference::MethodDef(_)) => write!(f, "!!{}", self.number),
            _ => write!(f, "!{}", self.number),
        }
    }
}
