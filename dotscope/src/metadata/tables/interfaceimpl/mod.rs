//! `InterfaceImpl` table implementation for interface inheritance relationships.
//!
//! This module provides complete support for the `InterfaceImpl` metadata table, which defines
//! interface implementations by types. The `InterfaceImpl` table is fundamental to the .NET
//! type system, establishing inheritance hierarchies and enabling polymorphic behavior.
//!
//! # Module Components
//! - [`crate::metadata::tables::InterfaceImplRaw`] - Raw table structure with unresolved coded indexes
//! - [`crate::metadata::tables::InterfaceImpl`] - Owned variant with resolved type references and owned data
//! - [`crate::metadata::loader::tables::InterfaceImplLoader`] - Internal loader for processing table entries (crate-private)
//! - Type aliases for collections: [`crate::metadata::tables::InterfaceImplMap`], [`crate::metadata::tables::InterfaceImplList`], [`crate::metadata::tables::InterfaceImplRc`]
//!
//! # Table Structure (ECMA-335 §22.23)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Class | `TypeDef` index | Type that implements the interface |
//! | Interface | `TypeDefOrRef` coded index | Interface being implemented |
//!
//! # Interface Implementation System
//! The `InterfaceImpl` table enables .NET's interface-based polymorphism:
//! - **Inheritance hierarchy**: Maps types to their implemented interfaces
//! - **Polymorphic dispatch**: Enables method calls through interface references
//! - **Type compatibility**: Supports casting between types and their interfaces
//! - **Generic interfaces**: Handles interface implementations with type parameters
//! - **Multiple inheritance**: Allows types to implement multiple interfaces
//!
//! # Type System Integration
//! `InterfaceImpl` entries are crucial for:
//! - **Interface resolution**: Finding interface implementations at runtime
//! - **Method dispatch**: Routing interface method calls to concrete implementations
//! - **Type checking**: Validating interface compatibility during compilation and loading
//! - **Reflection**: Providing runtime access to interface inheritance information
//! - **Generic constraints**: Supporting where clauses that require interface implementation
//!
//! # Coded Index Resolution
//! The Interface column uses `TypeDefOrRef` encoding to reference:
//! - **`TypeDef`**: Interfaces defined in the current assembly
//! - **`TypeRef`**: Interfaces from other assemblies
//! - **`TypeSpec`**: Generic interface instantiations (e.g., `IEnumerable<T>`)
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.23: `InterfaceImpl` table specification
//! - ECMA-335, Partition II, §23.2.14: `TypeDefOrRef` coded index encoding
//! - ECMA-335, Partition I, §8.9.11: Interface type contracts and inheritance
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

/// Concurrent map for storing `InterfaceImpl` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of interface implementations by their
/// associated tokens during metadata processing and runtime type resolution.
pub type InterfaceImplMap = SkipMap<Token, InterfaceImplRc>;

/// Thread-safe list for storing collections of `InterfaceImpl` entries.
///
/// Used for maintaining ordered sequences of interface implementations during metadata
/// loading and for iteration over all interface relationships in a type system.
pub type InterfaceImplList = Arc<boxcar::Vec<InterfaceImplRc>>;

/// Reference-counted pointer to an [`InterfaceImpl`] instance.
///
/// Enables efficient sharing of interface implementation data across multiple contexts
/// without duplication, supporting concurrent access patterns in type system processing.
pub type InterfaceImplRc = Arc<InterfaceImpl>;
