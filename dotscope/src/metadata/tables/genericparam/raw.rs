//! Raw `GenericParam` structures for the `GenericParam` metadata table.
//!
//! This module provides the [`GenericParamRaw`] struct for reading generic parameter data
//! directly from metadata tables before index resolution. The `GenericParam` table defines
//! generic type and method parameters for .NET generic programming support.
//!
//! # Table Structure
//! The `GenericParam` table (`TableId` = 0x2A) contains these columns:
//! - `Number`: 2-byte ordinal position of the parameter (0-based)
//! - `Flags`: 2-byte `GenericParamAttributes` bitmask
//! - `Owner`: Coded index into `TypeOrMethodDef` (`TypeDef` or `MethodDef`)
//! - `Name`: Index into String heap containing parameter name
//!
//! # Generic Parameter Context
//! `GenericParam` entries enable generic programming scenarios:
//! - **Generic types**: Type parameters for classes and interfaces (`List<T>`)
//! - **Generic methods**: Method-level type parameters (`Method<U>()`)
//! - **Constraint specification**: Base class and interface constraints
//! - **Variance annotations**: Covariance and contravariance support
//! - **Reflection metadata**: Runtime access to parameter information
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the `GenericParam` table specification.

use std::sync::{Arc, OnceLock};

use crate::{
    metadata::{
        streams::Strings,
        tables::{
            CodedIndex, CodedIndexType, GenericParam, GenericParamAttributes, GenericParamRc,
            TableInfoRef, TableRow,
        },
        token::Token,
        typesystem::CilTypeReference,
    },
    Result,
};

/// Raw generic parameter data read directly from the `GenericParam` metadata table.
///
/// This structure represents a generic parameter entry before index resolution and
/// reference dereferencing. Generic parameters define type and method parameters
/// that enable generic programming with type safety and performance benefits.
///
/// # Binary Format
/// Each row in the `GenericParam` table has this layout:
/// ```text
/// Offset | Size | Field  | Description
/// -------|------|--------|----------------------------------
/// 0      | 2    | Number | Parameter ordinal position
/// 2      | 2    | Flags  | GenericParamAttributes bitmask
/// 4      | 2/4  | Owner  | TypeOrMethodDef coded index
/// 6/8    | 2/4  | Name   | String heap index
/// ```
///
/// Owner and Name index sizes depend on table and heap sizes.
///
/// # Generic Parameter Context
/// `GenericParam` entries are used for:
/// - **Type parameters**: Defined on generic types (`class List<T>`)
/// - **Method parameters**: Defined on generic methods (`void Method<U>()`)
/// - **Constraint definitions**: Specifying parameter constraints
/// - **Variance specification**: Covariance and contravariance annotations
/// - **Name resolution**: Parameter names for signatures and reflection
///
/// # Parameter Attributes
/// The Flags field contains `GenericParamAttributes` values:
/// - **Variance**: COVARIANT, CONTRAVARIANT for assignment compatibility
/// - **Constraints**: Reference type, value type, constructor constraints
/// - **Special flags**: Additional constraint and variance information
///
/// # Owner Types
/// The Owner field uses `TypeOrMethodDef` coded index:
/// - **`TypeDef`**: For type-level generic parameters (`class Generic<T>`)
/// - **`MethodDef`**: For method-level generic parameters (`Method<U>()`)
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.20 for the complete `GenericParam` table specification.
#[derive(Clone, Debug)]
pub struct GenericParamRaw {
    /// The row identifier in the `GenericParam` table.
    ///
    /// This 1-based index uniquely identifies this generic parameter within the `GenericParam` table.
    pub rid: u32,

    /// The metadata token for this generic parameter.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this generic parameter across the entire assembly.
    /// The token value is calculated as `0x2A000000 + rid`.
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
    /// starting from zero. This determines parameter order in generic instantiations.
    pub number: u32,

    /// Generic parameter attribute flags indicating constraints and variance.
    ///
    /// A 2-byte bitmask of `GenericParamAttributes` values that specify variance,
    /// constraints, and other parameter characteristics.
    pub flags: u32,

    /// Coded index into the `TypeOrMethodDef` tables for the parameter owner.
    ///
    /// A [`CodedIndex`] that references either:
    /// - **`TypeDef`**: For type-level generic parameters
    /// - **`MethodDef`**: For method-level generic parameters
    ///
    /// [`CodedIndex`]: crate::metadata::tables::CodedIndex
    pub owner: CodedIndex,

    /// Index into the String heap for the parameter name.
    ///
    /// This index points to the parameter name string in the strings heap,
    /// which needs to be resolved during conversion to owned data.
    pub name: u32,
}

impl GenericParamRaw {
    /// Convert this raw generic parameter to an owned [`GenericParam`] with resolved references.
    ///
    /// This method resolves the owner reference and string heap reference to create a complete
    /// generic parameter structure with owned data. The resulting [`GenericParam`] contains
    /// the actual parameter name and resolved owner reference.
    ///
    /// # Arguments
    /// * `get_ref` - Function to resolve coded index references to type references
    /// * `strings` - The string heap for resolving parameter names
    ///
    /// # Returns
    /// Returns a reference-counted [`GenericParam`] with resolved data, or an error if:
    /// - Owner reference resolution fails (returns `CilTypeReference::None`)
    /// - String heap lookup fails for the parameter name
    /// - Memory allocation fails during conversion
    ///
    /// # Errors
    /// Returns an error if the owner reference cannot be resolved, the parameter name cannot be found in the string heap, or if memory allocation fails during conversion.
    pub fn to_owned<F>(&self, get_ref: F, strings: &Strings) -> Result<GenericParamRc>
    where
        F: Fn(&CodedIndex) -> CilTypeReference,
    {
        let owner_ref = get_ref(&self.owner);
        if matches!(owner_ref, CilTypeReference::None) {
            return Err(malformed_error!(
                "Failed to resolve owner token - {}",
                self.owner.token.value()
            ));
        }

        let owner = OnceLock::new();
        owner.set(owner_ref).ok();

        Ok(Arc::new(GenericParam {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            number: self.number,
            flags: GenericParamAttributes::new(self.flags),
            owner,
            constraints: Default::default(),
            name: strings.get_shared(self.name as usize)?,
            custom_attributes: Default::default(),
        }))
    }
}

impl TableRow for GenericParamRaw {
    /// Calculate the byte size of a GenericParam table row
    ///
    /// Computes the total size based on fixed-size fields and variable-size indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte indexes.
    ///
    /// # Row Layout (ECMA-335 §II.22.20)
    /// - `number`: 2 bytes (fixed size ordinal position)
    /// - `flags`: 2 bytes (fixed size attribute flags)
    /// - `owner`: 2 or 4 bytes (`TypeOrMethodDef` coded index)
    /// - `name`: 2 or 4 bytes (String heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for index widths
    ///
    /// # Returns
    /// Total byte size of one GenericParam table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* number */ 2u8
            /* flags */  .saturating_add(2)
            /* owner */  .saturating_add(sizes.coded_index_bytes(CodedIndexType::TypeOrMethodDef))
            /* name */   .saturating_add(sizes.str_bytes())

        )
    }
}
