//! Constant table module.
//!
//! This module provides complete support for the ECMA-335 Constant metadata table (0x0B),
//! which contains compile-time constant values associated with fields, properties, and parameters.
//! It includes raw table access, resolved data structures, collection types, and integration
//! with the broader metadata system.
//!
//! # Architecture
//!
//! The Constant module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved table indexes, while owned entries
//! provide fully resolved references integrated with parent metadata elements.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::constant::raw::ConstantRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::constant::owned::Constant`] - Owned variant with resolved references
//! - [`crate::metadata::loader::tables::ConstantLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::constant::ConstantMap`] - Token-based lookup map
//! - [`crate::metadata::tables::constant::ConstantList`] - Collection type
//! - [`crate::metadata::tables::constant::ConstantRc`] - Reference-counted pointer
//!
//! # Constant Table Structure
//!
//! The Constant table contains zero or more rows with these fields:
//! - **Type**: Element type of the constant value (`ELEMENT_TYPE_*` enumeration)
//! - **Parent**: Coded index referencing Field, Property, or Param tables
//! - **Value**: Blob heap reference containing the binary representation of the constant
//!
//! # Usage Context
//!
//! Constants are used for compile-time literal values:
//! - **Field constants**: Default values for const fields in C# (`const int MaxValue = 100`)
//! - **Parameter defaults**: Default parameter values in method signatures
//! - **Property constants**: Compile-time constant properties
//! - **Enum values**: Underlying primitive values for enumeration members
//! - **Attribute arguments**: Constant values used in custom attribute constructors
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::field`] - Field table entries
//! - [`crate::metadata::tables::property`] - Property table entries
//! - [`crate::metadata::tables::param`] - Parameter table entries
//! - [`crate::metadata::streams::Blob`] - Blob heap for constant data
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//!
//! # References
//!
//! - [ECMA-335 II.22.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Constant table specification

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

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::constant::Constant`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// Constant entries indexed by their metadata tokens.
pub type ConstantMap = SkipMap<Token, ConstantRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::constant::Constant`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of Constant collections.
pub type ConstantList = Arc<boxcar::Vec<ConstantRc>>;

/// Reference-counted smart pointer to a [`crate::metadata::tables::constant::Constant`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for Constant instances,
/// enabling safe sharing across multiple threads and contexts.
pub type ConstantRc = Arc<Constant>;
