//! `GenericParam` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `GenericParam` metadata table,
//! which defines generic type and method parameters. This enables generic programming support
//! in .NET assemblies with type-safe parameterized types and methods.
//!
//! # Overview
//! The `GenericParam` table enables generic programming scenarios:
//! - **Generic types**: Class and interface type parameters (`List<T>`, `Dictionary<TKey, TValue>`)
//! - **Generic methods**: Method-level type parameters (`Method<U>()`)
//! - **Constraint specification**: Base class and interface constraints
//! - **Variance annotations**: Covariance and contravariance for type safety
//! - **Reflection support**: Runtime access to generic parameter metadata
//!
//! # Components
//! - [`GenericParamRaw`]: Raw generic parameter data read directly from metadata tables
//! - [`GenericParam`]: Owned generic parameter data with resolved references
//! - [`GenericParamLoader`](crate::metadata::loader::tables::GenericParamLoader): Processes and loads generic parameter metadata
//! - [`GenericParamMap`]: Thread-safe collection of parameters indexed by token
//! - [`GenericParamList`]: Vector-based collection of parameters
//! - [`GenericParamRc`]: Reference-counted parameter for shared ownership
//!
//! # Table Structure
//! Each `GenericParam` entry contains:
//! - **Number**: Ordinal position within the parameter list (0-based)
//! - **Flags**: Variance and constraint attributes
//! - **Owner**: Reference to the owning type or method (coded index)
//! - **Name**: String reference to the parameter name
//!
//! # Generic Parameter Types
//! Parameters can be defined at different scopes:
//! ```text
//! ┌──────────────┬─────────────────────────────────────────┐
//! │ Scope        │ Example                                 │
//! ├──────────────┼─────────────────────────────────────────┤
//! │ Type Level   │ class List<T> { ... }                   │
//! │ Method Level │ void Method<U>(U parameter) { ... }     │
//! │ Interface    │ interface IEnumerable<out T> { ... }    │
//! │ Delegate     │ delegate TResult Func<in T, out TResult>│
//! └──────────────┴─────────────────────────────────────────┘
//! ```
//!
//!
//! # Generic Parameter Attributes
//! The [`GenericParamAttributes`] module defines flags for parameter characteristics:
//! - **Variance**: COVARIANT, CONTRAVARIANT for type safety
//! - **Constraints**: Reference type, value type, constructor constraints
//! - **Special flags**: Various constraint and variance combinations
//!
//! # Variance and Constraints
//! Generic parameters support advanced type system features:
//! - **Covariance**: `IEnumerable<out T>` allows `IEnumerable<Derived>` → `IEnumerable<Base>`
//! - **Contravariance**: `Action<in T>` allows `Action<Base>` → `Action<Derived>`
//! - **Reference constraint**: `where T : class` requires reference types
//! - **Value constraint**: `where T : struct` requires value types
//! - **Constructor constraint**: `where T : new()` requires parameterless constructor
//!
//! # Owner Resolution
//! Generic parameters are owned by either types or methods:
//! - **Type parameters**: Owned by `TypeDef` entries (classes, interfaces)
//! - **Method parameters**: Owned by `MethodDef` entries (generic methods)
//! - **Coded index**: Uses `TypeOrMethodDef` coded index for owner resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.20 for the complete `GenericParam` table specification.

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{metadata::token::Token, utils::RowList};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of generic parameter entries indexed by parameter token.
///
/// This skip list-based map provides efficient concurrent access to generic parameter
/// metadata, allowing multiple threads to resolve parameter information during
/// generic type analysis and reflection operations.
pub type GenericParamMap = SkipMap<Token, GenericParamRc>;

/// Thread-safe vector of generic parameter entries.
///
/// This collection provides ordered access to generic parameter entries, useful for
/// sequential processing and bulk operations during generic type analysis and
/// parameter enumeration.
pub type GenericParamList = RowList<GenericParamRc>;

/// Reference-counted generic parameter entry.
///
/// Provides shared ownership of [`GenericParam`] instances, enabling efficient
/// sharing of parameter metadata across multiple data structures and threads.
pub type GenericParamRc = Arc<GenericParam>;

metadata_flags! {
    /// Generic parameter attribute flags for the `GenericParam.Flags` field (ECMA-335 §II.23.1.7).
    ///
    /// Strongly-typed wrapper around the 2-byte `GenericParam.Flags` bitmask that specifies
    /// variance, constraints, and other characteristics of generic type and method parameters.
    ///
    /// ## Variance Flags
    /// Control assignment compatibility through variance annotations:
    /// - [`GenericParamAttributes::COVARIANT`] - Enables `out` variance (`IEnumerable<out T>`)
    /// - [`GenericParamAttributes::CONTRAVARIANT`] - Enables `in` variance (`Action<in T>`)
    ///
    /// ## Constraint Flags
    /// Restrict acceptable type arguments:
    /// - [`GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT`] - `where T : class`
    /// - [`GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT`] - `where T : struct`
    /// - [`GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT`] - `where T : new()`
    ///
    /// # ECMA-335 Reference
    /// See ECMA-335, Partition II, §22.20 for `GenericParam` table flag specifications.
    pub struct GenericParamAttributes(u32);
}

impl GenericParamAttributes {
    /// Mask for extracting variance information.
    ///
    /// Use this mask with bitwise AND to extract the variance bits from the flags.
    /// The result can then be compared with COVARIANT or CONTRAVARIANT constants.
    pub const VARIANCE_MASK: Self = Self(0x0003);

    /// The generic parameter is covariant.
    ///
    /// Covariant parameters allow assignment compatibility in the direction of
    /// inheritance (e.g., `IEnumerable<Derived>` can be assigned to `IEnumerable<Base>`).
    /// Used with `out` keyword in C# (`IEnumerable<out T>`).
    pub const COVARIANT: Self = Self(0x0001);

    /// The generic parameter is contravariant.
    ///
    /// Contravariant parameters allow assignment compatibility in the reverse direction
    /// of inheritance (e.g., `Action<Base>` can be assigned to `Action<Derived>`).
    /// Used with `in` keyword in C# (`Action<in T>`).
    pub const CONTRAVARIANT: Self = Self(0x0002);

    /// Mask for extracting special constraint information.
    ///
    /// Use this mask with bitwise AND to extract the constraint bits from the flags.
    /// The result can then be compared with specific constraint constants.
    pub const SPECIAL_CONSTRAINT_MASK: Self = Self(0x003C);

    /// The generic parameter has a reference type constraint.
    ///
    /// This constraint requires the type argument to be a reference type (class).
    /// Corresponds to `where T : class` constraint in C#.
    pub const REFERENCE_TYPE_CONSTRAINT: Self = Self(0x0004);

    /// The generic parameter has a value type constraint.
    ///
    /// This constraint requires the type argument to be a non-nullable value type (struct).
    /// Corresponds to `where T : struct` constraint in C#.
    pub const NOT_NULLABLE_VALUE_TYPE_CONSTRAINT: Self = Self(0x0008);

    /// The generic parameter has a default constructor constraint.
    ///
    /// This constraint requires the type argument to have a public parameterless constructor.
    /// Corresponds to `where T : new()` constraint in C#.
    pub const DEFAULT_CONSTRUCTOR_CONSTRAINT: Self = Self(0x0010);

    /// The generic parameter allows `ByRefLike` type arguments.
    ///
    /// This constraint permits ref struct types as type arguments.
    /// Corresponds to `where T : allows ref struct` constraint in C# 13+ / .NET 9+.
    pub const ALLOW_BY_REF_LIKE: Self = Self(0x0020);

    /// Mask for reserved bits that should not be set.
    ///
    /// Reserved bits in the flags field that are not currently defined by the ECMA-335
    /// specification. These bits should be zero in valid metadata.
    pub const RESERVED_MASK: Self = Self(0xFFC0);

    /// Returns the variance classification of this generic parameter.
    ///
    /// Decodes the variance bits per ECMA-335 §II.22.20 and returns a typed
    /// [`GenericParamVariance`] enum so callers can pattern-match exhaustively
    /// instead of comparing against the [`COVARIANT`](Self::COVARIANT) /
    /// [`CONTRAVARIANT`](Self::CONTRAVARIANT) constants by hand.
    ///
    /// The mapping is: `0x00` → [`Invariant`](GenericParamVariance::Invariant),
    /// `0x01` → [`Covariant`](GenericParamVariance::Covariant),
    /// `0x02` → [`Contravariant`](GenericParamVariance::Contravariant). Bit
    /// pattern `0x03` is reserved/undefined; it is treated as `Invariant`.
    #[inline]
    #[must_use]
    pub const fn variance(self) -> GenericParamVariance {
        match self.0 & Self::VARIANCE_MASK.0 {
            0x0001 => GenericParamVariance::Covariant,
            0x0002 => GenericParamVariance::Contravariant,
            // 0x0000 (invariant) and 0x0003 (reserved/undefined) - both default to Invariant.
            _ => GenericParamVariance::Invariant,
        }
    }

    /// Extract the special constraint bits from the flags.
    ///
    /// Returns the constraint portion of the flags by masking with
    /// [`SPECIAL_CONSTRAINT_MASK`](Self::SPECIAL_CONSTRAINT_MASK).
    #[inline]
    #[must_use]
    pub const fn special_constraint(self) -> Self {
        Self(self.0 & Self::SPECIAL_CONSTRAINT_MASK.0)
    }

    /// Returns the ILAsm variance keyword for this parameter.
    ///
    /// - `"+"` for covariant (`out`)
    /// - `"-"` for contravariant (`in`)
    /// - `""` for invariant (no variance)
    #[must_use]
    pub fn variance_keyword(self) -> &'static str {
        match self.variance() {
            GenericParamVariance::Covariant => "+",
            GenericParamVariance::Contravariant => "-",
            GenericParamVariance::Invariant => "",
        }
    }

    /// Returns the ILAsm constraint keywords for this parameter as a space-separated string.
    ///
    /// Possible keywords: `"class"`, `"valuetype"`, `".ctor"`, `"allow(byreflike)"`,
    /// or combinations thereof. Returns an empty string if no constraint flags are set.
    #[must_use]
    pub fn constraint_keywords(self) -> String {
        let mut parts = Vec::new();

        if self.contains(Self::REFERENCE_TYPE_CONSTRAINT) {
            parts.push("class");
        }
        if self.contains(Self::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT) {
            parts.push("valuetype");
        }
        if self.contains(Self::DEFAULT_CONSTRUCTOR_CONSTRAINT) {
            parts.push(".ctor");
        }
        if self.contains(Self::ALLOW_BY_REF_LIKE) {
            parts.push("allow(byreflike)");
        }

        parts.join(" ")
    }
}

/// Variance classification of a generic parameter (ECMA-335 §II.22.20).
///
/// Returned by [`GenericParamAttributes::variance`]. The three variants are
/// fixed by the standard and mutually exclusive - exactly one applies to any
/// given generic parameter.
///
/// # Stability
///
/// The string returned by [`GenericParamVariance::as_str`] and by the
/// [`Display`] impl is part of the stable public API. It is safe to persist
/// (file, database, log line) and to parse.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GenericParamVariance {
    /// No variance - exact type match required.
    ///
    /// Corresponds to ECMA-335 variance bits `0x00` (and the reserved/undefined
    /// pattern `0x03`).
    Invariant,
    /// Covariant - type argument may be a more derived type.
    ///
    /// Corresponds to ECMA-335 variance bit `0x01` and the C# `out` keyword
    /// (e.g. `IEnumerable<out T>`).
    Covariant,
    /// Contravariant - type argument may be a less derived type.
    ///
    /// Corresponds to ECMA-335 variance bit `0x02` and the C# `in` keyword
    /// (e.g. `Action<in T>`).
    Contravariant,
}

impl GenericParamVariance {
    /// Returns a stable `&'static str` identifier for this variance.
    ///
    /// Identifiers are lowercase (`"invariant"`, `"covariant"`, `"contravariant"`).
    /// They are part of the stable public API and safe to persist.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            GenericParamVariance::Invariant => "invariant",
            GenericParamVariance::Covariant => "covariant",
            GenericParamVariance::Contravariant => "contravariant",
        }
    }
}

impl std::fmt::Display for GenericParamVariance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_param_attributes_variance() {
        assert_eq!(
            GenericParamAttributes::new(0).variance(),
            GenericParamVariance::Invariant
        );
        assert_eq!(
            GenericParamAttributes::COVARIANT.variance(),
            GenericParamVariance::Covariant
        );
        assert_eq!(
            GenericParamAttributes::CONTRAVARIANT.variance(),
            GenericParamVariance::Contravariant
        );
        // Reserved/undefined bit pattern 0x03 - defensively maps to Invariant.
        assert_eq!(
            GenericParamAttributes::new(0x0003).variance(),
            GenericParamVariance::Invariant
        );
        // Constraint bits in higher positions must not affect variance decoding.
        let with_constraints = GenericParamAttributes::COVARIANT
            | GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT
            | GenericParamAttributes::DEFAULT_CONSTRUCTOR_CONSTRAINT;
        assert_eq!(with_constraints.variance(), GenericParamVariance::Covariant);
    }

    #[test]
    fn test_generic_param_variance_stable_strings() {
        assert_eq!(GenericParamVariance::Invariant.as_str(), "invariant");
        assert_eq!(GenericParamVariance::Covariant.as_str(), "covariant");
        assert_eq!(
            GenericParamVariance::Contravariant.as_str(),
            "contravariant"
        );

        assert_eq!(format!("{}", GenericParamVariance::Invariant), "invariant");
        assert_eq!(format!("{}", GenericParamVariance::Covariant), "covariant");
        assert_eq!(
            format!("{}", GenericParamVariance::Contravariant),
            "contravariant"
        );
    }

    #[test]
    fn test_variance_keyword_after_enum_migration() {
        // Pre-existing keyword behavior must survive the variance() return-type change.
        assert_eq!(GenericParamAttributes::new(0).variance_keyword(), "");
        assert_eq!(GenericParamAttributes::COVARIANT.variance_keyword(), "+");
        assert_eq!(
            GenericParamAttributes::CONTRAVARIANT.variance_keyword(),
            "-"
        );
    }
}
