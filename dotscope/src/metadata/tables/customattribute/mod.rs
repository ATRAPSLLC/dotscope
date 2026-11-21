//! `CustomAttribute` table module.
//!
//! This module provides complete support for the ECMA-335 `CustomAttribute` metadata table (0x0C),
//! which associates custom attributes with elements throughout the metadata system. It includes
//! raw table access, resolved data structures, attribute value parsing, and integration
//! with the broader metadata system.
//!
//! # Architecture
//!
//! The `CustomAttribute` module follows the standard dual variant pattern with raw and owned
//! representations. Raw entries contain unresolved coded indexes, while owned entries
//! provide fully resolved references integrated with target metadata elements and parsed
//! attribute data.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customattribute::raw::CustomAttributeRaw`] - Raw table structure with unresolved indexes
//! - [`crate::metadata::tables::customattribute::owned::CustomAttribute`] - Owned variant with resolved references
//! - [`crate::metadata::loader::tables::CustomAttributeLoader`] - Internal loader for processing table data
//! - [`crate::metadata::tables::customattribute::CustomAttributeMap`] - Token-based lookup map
//! - [`crate::metadata::tables::customattribute::CustomAttributeList`] - Collection type
//! - [`crate::metadata::tables::customattribute::CustomAttributeRc`] - Reference-counted pointer
//!
//! # `CustomAttribute` Table Structure
//!
//! Each `CustomAttribute` table row contains these fields:
//! - **Parent**: Target element that the attribute is applied to (coded index)
//! - **Type**: Constructor method for the custom attribute (coded index)
//! - **Value**: Serialized attribute arguments and named parameters (blob)
//!
//! The parent can be any metadata element that supports the `HasCustomAttribute` coded index,
//! including types, methods, fields, assemblies, modules, and parameters.
//!
//! # Usage Context
//!
//! Custom attributes are used throughout .NET assemblies for:
//! - **Metadata decoration**: Adding descriptive information to code elements
//! - **Framework integration**: Enabling framework-specific behaviors and processing
//! - **Code generation**: Providing data for compile-time and runtime code generation
//! - **Reflection support**: Enabling runtime discovery of attribute-based metadata
//! - **Tool integration**: Supporting development tools and static analysis
//!
//! # Attribute Value Processing
//!
//! Custom attributes support complex data serialization including:
//! - **Constructor arguments**: Positional parameters passed to attribute constructors
//! - **Named properties**: Property assignments specified as name-value pairs
//! - **Named fields**: Field assignments for public attribute fields
//! - **Type references**: References to types, including generic type instantiations
//! - **Array values**: One-dimensional arrays of supported primitive and reference types
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//! - [`crate::metadata::streams::Blob`] - Blob heap for attribute data
//! - [`crate::metadata::tables::methoddef`] - Method definition table entries
//! - [`crate::metadata::tables::memberref`] - Member reference table entries
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe through the use of atomic operations
//! and concurrent data structures. Custom attribute data can be safely accessed
//! and processed from multiple threads simultaneously.
//!
//! # References
//!
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `CustomAttribute` table specification
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom attribute encoding
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

/// Thread-safe map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::customattribute::CustomAttribute`] instances
///
/// Concurrent skip list-based map providing efficient lookups and insertions for
/// `CustomAttribute` entries indexed by their metadata tokens.
pub type CustomAttributeMap = SkipMap<Token, CustomAttributeRc>;

/// Thread-safe vector that holds a list of [`crate::metadata::tables::customattribute::CustomAttribute`] references for efficient access
///
/// Append-only vector using atomic operations for lock-free concurrent access,
/// optimized for scenarios with frequent reads of `CustomAttribute` collections.
pub type CustomAttributeList = Arc<boxcar::Vec<CustomAttributeRc>>;

/// Reference-counted smart pointer to a [`crate::metadata::tables::customattribute::CustomAttribute`] instance for shared ownership
///
/// Provides shared ownership and automatic memory management for `CustomAttribute` instances,
/// enabling safe sharing across multiple threads and contexts.
pub type CustomAttributeRc = Arc<CustomAttribute>;
