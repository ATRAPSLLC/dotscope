//! `GenericParamConstraint` metadata table implementation.
//!
//! This module provides structures and utilities for working with the `GenericParamConstraint` metadata table,
//! which defines constraints that apply to generic parameters. These constraints specify base classes
//! and interfaces that type arguments must satisfy, enabling type-safe generic programming.
//!
//! # Overview
//! The `GenericParamConstraint` table enables constraint-based generic programming:
//! - **Base class constraints**: Inheritance requirements for type arguments
//! - **Interface constraints**: Implementation requirements for type arguments
//! - **Multiple constraints**: Complex constraint combinations for parameters
//! - **Type safety**: Compile-time verification of constraint satisfaction
//! - **Code optimization**: Enabling specialized code generation for constrained types
//!
//! # Components
//! - [`GenericParamConstraintRaw`]: Raw constraint data read directly from metadata tables
//! - [`GenericParamConstraint`]: Owned constraint data with resolved references
//! - [`GenericParamConstraintLoader`](crate::metadata::loader::tables::GenericParamConstraintLoader): Processes and loads constraint metadata
//! - [`GenericParamConstraintMap`]: Thread-safe collection of constraints indexed by token
//! - [`GenericParamConstraintList`]: Vector-based collection of constraints
//! - [`GenericParamConstraintRc`]: Reference-counted constraint for shared ownership
//!
//! # Table Structure
//! Each `GenericParamConstraint` entry contains:
//! - **Owner**: Reference to the generic parameter being constrained
//! - **Constraint**: Reference to the type that serves as the constraint
//!
//! # Constraint Types
//! Constraints can specify various requirements:
//! ```text
//! ┌─────────────────────┬─────────────────────────────────────────┐
//! │ Constraint Type     │ Example                                 │
//! ├─────────────────────┼─────────────────────────────────────────┤
//! │ Base Class          │ where T : BaseClass                     │
//! │ Interface           │ where T : IInterface                    │
//! │ Multiple            │ where T : BaseClass, IInterface1        │
//! │ Circular            │ where T : IComparable<T>                │
//! │ Nested Generic      │ where T : IList<U>                      │
//! └─────────────────────┴─────────────────────────────────────────┘
//! ```
//!
//! # Constraint Resolution
//! Constraints are resolved during metadata loading:
//! - **Parameter resolution**: Links constraints to their target parameters
//! - **Type resolution**: Resolves constraint types to concrete type references
//! - **Application**: Associates constraints with parameters for constraint checking
//! - **Validation**: Ensures constraint types are valid and accessible
//!
//! # Constraint Semantics
//! Different constraint types have specific meanings:
//! - **Class constraints**: Require inheritance from a specific base class
//! - **Interface constraints**: Require implementation of specific interfaces
//! - **Value type constraints**: Implicit constraints on struct parameters
//! - **Reference type constraints**: Implicit constraints on class parameters
//! - **Constructor constraints**: Require parameterless constructor availability
//!
//! # Type Safety Benefits
//! Constraints enable several type safety features:
//! - **Compile-time checking**: Verify type arguments satisfy constraints
//! - **Method resolution**: Enable constraint-based method calls
//! - **Cast elimination**: Remove unnecessary runtime type checks
//! - **Performance optimization**: Generate specialized code for constrained types
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.21 for the complete `GenericParamConstraint` table specification.

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Thread-safe map of generic parameter constraint entries indexed by constraint token.
///
/// This skip list-based map provides efficient concurrent access to constraint metadata,
/// allowing multiple threads to resolve constraint information during generic type
/// analysis and constraint verification operations.
pub type GenericParamConstraintMap = SkipMap<Token, GenericParamConstraintRc>;

/// Thread-safe vector of generic parameter constraint entries.
///
/// This collection provides ordered access to constraint entries, useful for sequential
/// processing and bulk operations during constraint analysis and parameter validation.
pub type GenericParamConstraintList = Arc<boxcar::Vec<GenericParamConstraintRc>>;

/// Reference-counted generic parameter constraint entry.
///
/// Provides shared ownership of [`GenericParamConstraint`] instances, enabling efficient
/// sharing of constraint metadata across multiple data structures and threads.
pub type GenericParamConstraintRc = Arc<GenericParamConstraint>;
