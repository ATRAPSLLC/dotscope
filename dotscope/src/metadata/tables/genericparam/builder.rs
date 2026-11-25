//! GenericParamBuilder for creating generic parameter definitions.
//!
//! This module provides [`crate::metadata::tables::genericparam::GenericParamBuilder`] for creating GenericParam table entries
//! with a fluent API. Generic parameters enable type-safe generic programming in .NET
//! by defining type and method parameters with constraints, variance annotations, and
//! runtime reflection support for dynamic type operations.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamAttributes, GenericParamRaw, TableDataOwned,
            TableId,
        },
        token::Token,
    },
    Error, Result,
};

/// Builder for creating GenericParam metadata entries.
///
/// `GenericParamBuilder` provides a fluent API for creating GenericParam table entries
/// with validation and automatic heap management. Generic parameters define type and
/// method parameters that enable generic programming with type safety, performance
/// optimization, and comprehensive constraint specification for robust type systems.
///
/// # Generic Parameter Model
///
/// .NET generic parameters follow a standard pattern:
/// - **Parameter Identity**: Name and ordinal position within the parameter list
/// - **Owner Declaration**: The type or method that declares this parameter
/// - **Constraint Specification**: Type constraints and variance annotations
/// - **Runtime Support**: Reflection and type checking capabilities
///
/// # Coded Index Types
///
/// Generic parameters use the `TypeOrMethodDef` coded index to specify the owner:
/// - **TypeDef**: Type-level generic parameters (classes, interfaces, delegates)
/// - **MethodDef**: Method-level generic parameters (generic methods)
///
/// # Parameter Attributes
///
/// Generic parameters support various attributes for advanced type system features:
/// - **Variance**: Covariance (`out`) and contravariance (`in`) annotations
/// - **Reference Constraint**: `where T : class` requiring reference types
/// - **Value Constraint**: `where T : struct` requiring value types
/// - **Constructor Constraint**: `where T : new()` requiring parameterless constructors
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::{GenericParamBuilder, GenericParamAttributes, CodedIndex, TableId};
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a basic type parameter for a generic class
/// let generic_class = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef); // Generic class
///
/// let type_param = GenericParamBuilder::new()
///     .name("T")
///     .number(0)                    // First parameter
///     .owner(generic_class.clone())
///     .build(&mut assembly)?;
///
/// // Create a constrained generic parameter
/// let constrained_flags = GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT |
///                        GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT;
///
/// let constrained_param = GenericParamBuilder::new()
///     .name("TEntity")
///     .number(1)                    // Second parameter
///     .flags(constrained_flags)     // where TEntity : class, new()
///     .owner(generic_class.clone())
///     .build(&mut assembly)?;
///
/// // Create a covariant parameter for an interface
/// let generic_interface = CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeOrMethodDef); // Generic interface
///
/// let covariant_param = GenericParamBuilder::new()
///     .name("TResult")
///     .number(0)
///     .flags(GenericParamAttributes::COVARIANT)  // out TResult
///     .owner(generic_interface.clone())
///     .build(&mut assembly)?;
///
/// // Create a method-level generic parameter
/// let generic_method = CodedIndex::new(TableId::MethodDef, 5, CodedIndexType::TypeOrMethodDef); // Generic method
///
/// let method_param = GenericParamBuilder::new()
///     .name("U")
///     .number(0)
///     .owner(generic_method)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct GenericParamBuilder {
    name: Option<String>,
    number: Option<u32>,
    flags: Option<GenericParamAttributes>,
    owner: Option<CodedIndex>,
}

impl Default for GenericParamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GenericParamBuilder {
    /// Creates a new GenericParamBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::genericparam::GenericParamBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            number: None,
            flags: None,
            owner: None,
        }
    }

    /// Sets the name of the generic parameter.
    ///
    /// Parameter names are used for signature resolution, reflection operations,
    /// and debugging information. Common naming conventions include single letters
    /// for simple cases and descriptive names for complex scenarios.
    ///
    /// Naming conventions:
    /// - Single letters: `T`, `U`, `V` for simple generic types
    /// - Descriptive names: `TKey`, `TValue` for specific purposes
    /// - Interface prefixes: `TInterface`, `TImplementation` for design patterns
    /// - Constraint indicators: `TClass`, `TStruct` for constraint documentation
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the ordinal position of the parameter within the parameter list.
    ///
    /// Parameter numbers are 0-based and determine the order of type arguments
    /// in generic instantiations. The numbering must be consecutive starting
    /// from 0 within each owner (type or method).
    ///
    /// Parameter ordering:
    /// - **Type parameters**: `class Generic<T, U, V>` → T=0, U=1, V=2
    /// - **Method parameters**: `Method<T, U>()` → T=0, U=1
    /// - **Independent numbering**: Type and method parameters are numbered separately
    /// - **Instantiation order**: Determines type argument positions in generics
    ///
    /// # Arguments
    ///
    /// * `number` - The 0-based ordinal position of this parameter
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn number(mut self, number: u32) -> Self {
        self.number = Some(number);
        self
    }

    /// Sets the attribute flags for constraints and variance.
    ///
    /// Flags specify the parameter's variance and constraints using `GenericParamAttributes`
    /// constants. Multiple flags can be combined using bitwise OR operations to create
    /// complex constraint specifications.
    ///
    /// Available flags:
    /// - **Variance**: `COVARIANT` (out), `CONTRAVARIANT` (in)
    /// - **Type Constraints**: `REFERENCE_TYPE_CONSTRAINT` (class), `NOT_NULLABLE_VALUE_TYPE_CONSTRAINT` (struct)
    /// - **Constructor Constraints**: `DEFAULT_CONSTRUCTOR_CONSTRAINT` (new())
    ///
    /// # Arguments
    ///
    /// * `flags` - GenericParamAttributes specifying constraints and variance
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: GenericParamAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the owner (type or method) that declares this parameter.
    ///
    /// The owner must be a valid `TypeOrMethodDef` coded index that references
    /// either a type definition (for type parameters) or method definition
    /// (for method parameters). This establishes the scope and lifetime
    /// of the generic parameter.
    ///
    /// Valid owner types include:
    /// - `TypeDef` - Type-level generic parameters (classes, interfaces, delegates)
    /// - `MethodDef` - Method-level generic parameters (generic methods)
    ///
    /// # Arguments
    ///
    /// * `owner` - A `TypeOrMethodDef` coded index pointing to the declaring entity
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn owner(mut self, owner: CodedIndex) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Builds the generic parameter and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the parameter name
    /// to the string heap, creates the raw generic parameter structure, and adds
    /// it to the GenericParam table with proper token generation and validation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CIL assembly for managing metadata
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created generic parameter, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if name is not set
    /// - Returns error if number is not set
    /// - Returns error if owner is not set
    /// - Returns error if owner is not a valid TypeOrMethodDef coded index
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid("GenericParam name is required".to_string())
        })?;

        let number = self.number.ok_or_else(|| {
            Error::ModificationInvalid("GenericParam number is required".to_string())
        })?;

        let owner = self.owner.ok_or_else(|| {
            Error::ModificationInvalid("GenericParam owner is required".to_string())
        })?;

        let flags = self.flags.unwrap_or(GenericParamAttributes::ZERO);

        let valid_owner_tables = CodedIndexType::TypeOrMethodDef.tables();
        if !valid_owner_tables.contains(&owner.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Owner must be a TypeOrMethodDef coded index (TypeDef/MethodDef), got {:?}",
                owner.tag
            )));
        }

        if number > 65535 {
            return Err(Error::ModificationInvalid(format!(
                "GenericParam number {number} is too large (maximum 65535)"
            )));
        }

        let valid_flags_mask =
            GenericParamAttributes::VARIANCE_MASK | GenericParamAttributes::SPECIAL_CONSTRAINT_MASK;
        if (flags & !valid_flags_mask) != GenericParamAttributes::ZERO {
            return Err(Error::ModificationInvalid(format!(
                "Invalid GenericParam flags: 0x{:04X}. Unsupported flags detected",
                flags.bits()
            )));
        }

        let name_index = assembly.string_get_or_add(&name)?.placeholder();
        let rid = assembly.next_rid(TableId::GenericParam)?;

        let token = Token::from_parts(TableId::GenericParam, rid);

        let generic_param_raw = GenericParamRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            number,
            flags: flags.bits(),
            owner,
            name: name_index,
        };

        assembly.table_row_add(
            TableId::GenericParam,
            TableDataOwned::GenericParam(generic_param_raw),
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
    fn test_generic_param_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a basic type parameter
        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        let ref_ = GenericParamBuilder::new()
            .name("T")
            .number(0)
            .owner(generic_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
    }

    #[test]
    fn test_generic_param_builder_with_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);
        let constraint_flags: GenericParamAttributes =
            GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT
                | GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT;

        let ref_ = GenericParamBuilder::new()
            .name("TEntity")
            .number(0)
            .flags(constraint_flags)
            .owner(generic_type)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
    }

    #[test]
    fn test_generic_param_builder_covariant() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_interface =
            CodedIndex::new(TableId::TypeDef, 2, CodedIndexType::TypeOrMethodDef);

        let ref_ = GenericParamBuilder::new()
            .name("TResult")
            .number(0)
            .flags(GenericParamAttributes::COVARIANT)
            .owner(generic_interface)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
    }

    #[test]
    fn test_generic_param_builder_method_parameter() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_method =
            CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::TypeOrMethodDef);

        let ref_ = GenericParamBuilder::new()
            .name("U")
            .number(0)
            .owner(generic_method)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
    }

    #[test]
    fn test_generic_param_builder_missing_name() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        let result = GenericParamBuilder::new()
            .number(0)
            .owner(generic_type)
            .build(&mut assembly);

        // Should fail because name is required
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_missing_number() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        let result = GenericParamBuilder::new()
            .name("T")
            .owner(generic_type)
            .build(&mut assembly);

        // Should fail because number is required
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_missing_owner() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = GenericParamBuilder::new()
            .name("T")
            .number(0)
            .build(&mut assembly);

        // Should fail because owner is required
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_invalid_owner_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use a table type that's not valid for TypeOrMethodDef
        let invalid_owner = CodedIndex::new(TableId::Field, 1, CodedIndexType::TypeOrMethodDef); // Field not in TypeOrMethodDef

        let result = GenericParamBuilder::new()
            .name("T")
            .number(0)
            .owner(invalid_owner)
            .build(&mut assembly);

        // Should fail because owner type is not valid for TypeOrMethodDef
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_invalid_number() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        let result = GenericParamBuilder::new()
            .name("T")
            .number(100000) // Too large
            .owner(generic_type)
            .build(&mut assembly);

        // Should fail because number is too large
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_invalid_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        let result = GenericParamBuilder::new()
            .name("T")
            .number(0)
            .flags(GenericParamAttributes::new(0xFFFF)) // Invalid flags
            .owner(generic_type)
            .build(&mut assembly);

        // Should fail because flags are invalid
        assert!(result.is_err());
    }

    #[test]
    fn test_generic_param_builder_multiple_parameters() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);
        let generic_method =
            CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::TypeOrMethodDef);

        // Create multiple generic parameters
        let ref1 = GenericParamBuilder::new()
            .name("T")
            .number(0)
            .owner(generic_type.clone())
            .build(&mut assembly)
            .unwrap();

        let ref2 = GenericParamBuilder::new()
            .name("U")
            .number(1)
            .flags(GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT)
            .owner(generic_type.clone())
            .build(&mut assembly)
            .unwrap();

        let ref3 = GenericParamBuilder::new()
            .name("V")
            .number(0)
            .flags(GenericParamAttributes::COVARIANT)
            .owner(generic_method)
            .build(&mut assembly)
            .unwrap();

        // All should succeed and be different refs
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref3));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));

        // All should have GenericParam table kind
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::GenericParam));
    }

    #[test]
    fn test_generic_param_builder_all_constraint_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let generic_type = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::TypeOrMethodDef);

        // Test different constraint combinations
        let constraints = [
            (
                "TClass",
                0,
                GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT,
            ),
            (
                "TStruct",
                1,
                GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT,
            ),
            (
                "TNew",
                2,
                GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT,
            ),
            ("TOut", 3, GenericParamAttributes::COVARIANT),
            ("TIn", 4, GenericParamAttributes::CONTRAVARIANT),
            (
                "TComplex",
                5,
                GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT
                    | GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT,
            ),
        ];

        for (name, number, flags) in constraints.iter() {
            let _param = GenericParamBuilder::new()
                .name(*name)
                .number(*number)
                .flags(*flags)
                .owner(generic_type.clone())
                .build(&mut assembly)
                .unwrap();
        }

        // All constraints should be created successfully
    }
}
