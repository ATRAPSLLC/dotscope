//! Raw `GenericParamConstraint` structures for the `GenericParamConstraint` metadata table.
//!
//! This module provides the [`GenericParamConstraintRaw`] struct for reading constraint data
//! directly from metadata tables before index resolution. The `GenericParamConstraint` table
//! defines constraints that apply to generic parameters, specifying type requirements.
//!
//! # Table Structure
//! The `GenericParamConstraint` table (`TableId` = 0x2C) contains these columns:
//! - `Owner`: Index into `GenericParam` table for the constrained parameter
//! - `Constraint`: Coded index into `TypeDefOrRef` for the constraint type
//!
//! # Constraint Context
//! `GenericParamConstraint` entries enable constraint-based generic programming:
//! - **Base class constraints**: Inheritance requirements for type arguments
//! - **Interface constraints**: Implementation requirements for type arguments
//! - **Multiple constraints**: Parameters can have multiple constraint entries
//! - **Type safety**: Compile-time verification of constraint satisfaction
//! - **Code optimization**: Enabling specialized code generation for constrained types
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.21 for the `GenericParamConstraint` table specification.
use std::sync::Arc;

use crate::{
    metadata::{
        tables::{
            CodedIndex, CodedIndexType, GenericParamConstraint, GenericParamConstraintRc,
            GenericParamMap, TableId, TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::TypeRegistry,
    },
    Result,
};

/// Raw generic parameter constraint data read directly from the `GenericParamConstraint` metadata table.
///
/// This structure represents a constraint entry before index resolution and reference
/// dereferencing. Generic parameter constraints specify type requirements that must
/// be satisfied by type arguments for generic parameters.
///
/// # Binary Format
/// Each row in the `GenericParamConstraint` table has this layout:
/// ```text
/// Offset | Size | Field      | Description
/// -------|------|------------|----------------------------------
/// 0      | 2/4  | Owner      | GenericParam table index
/// 2/4    | 2/4  | Constraint | TypeDefOrRef coded index
/// ```
///
/// Index sizes depend on table sizes.
///
/// # Constraint Context
/// `GenericParamConstraint` entries are used for:
/// - **Base class constraints**: `where T : BaseClass` (inheritance requirement)
/// - **Interface constraints**: `where T : IInterface` (implementation requirement)
/// - **Multiple constraints**: Parameters can have multiple constraint entries
/// - **Circular constraints**: `where T : IComparable<T>` (self-referential constraints)
/// - **Nested generic constraints**: `where T : IList<U>` (constraints with generic arguments)
///
/// # Constraint Types
/// The Constraint field uses `TypeDefOrRef` coded index:
/// - **`TypeDef`**: For internal types defined in the assembly
/// - **`TypeRef`**: For external types from other assemblies
/// - **`TypeSpec`**: For complex type specifications (generics, arrays, etc.)
///
/// # Validation Process
/// Constraints undergo validation during application:
/// - **Compatibility checking**: Ensures constraint types are valid for the parameter
/// - **Accessibility verification**: Confirms constraint types are accessible
/// - **Circular dependency detection**: Prevents invalid constraint cycles
/// - **Attribute consistency**: Validates constraint compatibility with parameter attributes
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.21 for the complete `GenericParamConstraint` table specification.
#[derive(Clone, Debug)]
pub struct GenericParamConstraintRaw {
    /// The row identifier in the `GenericParamConstraint` table.
    ///
    /// This 1-based index uniquely identifies this constraint within the `GenericParamConstraint` table.
    pub rid: u32,

    /// The metadata token for this generic parameter constraint.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this constraint across the entire assembly.
    /// The token value is calculated as `0x2C000000 + rid`.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this constraint in the metadata tables stream.
    ///
    /// This offset points to the start of this constraint's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// Index into the `GenericParam` table for the constrained parameter.
    ///
    /// This index points to the generic parameter that this constraint applies to,
    /// which needs to be resolved during conversion to owned data.
    pub owner: u32,

    /// Coded index into the `TypeDefOrRef` tables for the constraint type.
    ///
    /// A [`CodedIndex`] that references the type that serves as the constraint:
    /// - **`TypeDef`**: For internal types defined in the assembly
    /// - **`TypeRef`**: For external types from other assemblies
    /// - **`TypeSpec`**: For complex type specifications
    ///
    /// [`CodedIndex`]: crate::metadata::tables::CodedIndex
    pub constraint: CodedIndex,
}

impl GenericParamConstraintRaw {
    /// Apply this constraint directly to the referenced generic parameter.
    ///
    /// This method resolves references and applies the constraint to the target parameter
    /// without creating an owned structure. The constraint undergoes validation to ensure
    /// compatibility with the parameter's attributes.
    ///
    /// # Arguments
    /// * `generic_params` - Collection of all generic parameters for resolving owners
    /// * `types` - Type registry for resolving constraint type references
    ///
    /// # Returns
    /// Returns `Ok(())` on successful application, or an error if:
    /// - Constraint type reference cannot be resolved
    /// - Generic parameter owner cannot be found
    /// - Constraint compatibility validation fails
    /// - Constraint application to parameter fails
    ///
    /// # Errors
    /// Returns an error if the constraint type reference cannot be resolved, the generic parameter owner cannot be found, constraint compatibility validation fails, or constraint application to the parameter fails.
    pub fn apply(&self, generic_params: &GenericParamMap, types: &TypeRegistry) -> Result<()> {
        let Some(constraint) = types.get(&self.constraint.token) else {
            return Err(malformed_error!(
                "Failed to resolve constraint token - {}",
                self.constraint.token
            ));
        };

        match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
            Some(owner) => {
                owner
                    .value()
                    .constraints
                    .push_row(self.token, constraint.into());
                Ok(())
            }
            None => Err(malformed_error!(
                "Invalid owner token - {}",
                self.owner | 0x2A00_0000
            )),
        }
    }

    /// Convert this raw constraint to an owned [`GenericParamConstraint`] with resolved references.
    ///
    /// This method resolves the parameter and type references to create a complete
    /// constraint structure with owned data. The resulting [`GenericParamConstraint`] contains
    /// resolved references to both the target parameter and constraint type.
    ///
    /// # Arguments
    /// * `generic_params` - Collection of all generic parameters for resolving owners
    /// * `types` - Type registry for resolving constraint type references
    ///
    /// # Returns
    /// Returns a reference-counted [`GenericParamConstraint`] with resolved data, or an error if:
    /// - Generic parameter owner reference cannot be resolved
    /// - Constraint type reference cannot be resolved
    /// - Memory allocation fails during conversion
    ///
    /// # Constraint Resolution
    /// The conversion process:
    /// 1. Resolves generic parameter owner from the parameter collection
    /// 2. Resolves constraint type from the type registry
    /// 3. Creates owned [`GenericParamConstraint`] with resolved references
    /// 4. Initializes empty custom attributes collection
    ///
    /// # Reference Resolution
    /// - **Parameter resolution**: Uses token calculation (owner | 0x2A000000) for `GenericParam` lookup
    /// - **Type resolution**: Uses coded index token for type registry lookup
    /// - **Error handling**: Returns detailed error messages for failed resolutions
    ///
    /// [`GenericParamConstraint`]: crate::metadata::tables::GenericParamConstraint
    /// [`GenericParamMap`]: crate::metadata::tables::GenericParamMap
    /// [`TypeRegistry`]: crate::metadata::typesystem::TypeRegistry
    ///
    /// # Errors
    /// Returns an error if the generic parameter owner or constraint type cannot be resolved, or if any step in the conversion process fails.
    pub fn to_owned(
        &self,
        generic_params: &GenericParamMap,
        types: &TypeRegistry,
    ) -> Result<GenericParamConstraintRc> {
        Ok(Arc::new(GenericParamConstraint {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            owner: match generic_params.get(&Token::new(self.owner | 0x2A00_0000)) {
                Some(owner) => owner.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to generic_param token - {}",
                        self.owner | 0x2A00_0000
                    ))
                }
            },
            constraint: match types.get(&self.constraint.token) {
                Some(constraint) => constraint,
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve constraint type token - {}",
                        self.constraint.token.value()
                    ))
                }
            },
            custom_attributes: Default::default(),
        }))
    }
}

impl TableRow for GenericParamConstraintRaw {
    /// Calculate the byte size of a GenericParamConstraint table row
    ///
    /// Computes the total size based on variable-size table and coded indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.21)
    /// - `owner`: 2 or 4 bytes (GenericParam table index)
    /// - `constraint`: 2 or 4 bytes (`TypeDefOrRef` coded index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one GenericParamConstraint table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* owner */      sizes.table_index_bytes(TableId::GenericParam)
            /* constraint */ .saturating_add(sizes.coded_index_bytes(CodedIndexType::TypeDefOrRef))

        )
    }
}
