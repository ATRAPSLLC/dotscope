//! # `PropertyMap` Table Module
//!
//! This module provides comprehensive access to the `PropertyMap` metadata table (ID 0x15),
//! which establishes the critical relationship between types and their properties in
//! .NET assemblies. The `PropertyMap` table enables property enumeration, reflection
//! operations, and type-property binding throughout the metadata system.
//!
//! ## Table Purpose
//!
//! The `PropertyMap` table provides:
//! - **Type-Property Binding**: Links types to their associated properties
//! - **Property Enumeration**: Enables discovery of all properties for a given type
//! - **Inheritance Support**: Facilitates property inheritance and override resolution
//! - **Reflection Foundation**: Supports property-based reflection and metadata queries
//!
//! ## Module Structure
//!
//! The module follows the standard dual-variant pattern for metadata tables:
//!
//! ### Raw Variant (`PropertyMapRaw`)
//! - Direct memory representation of table entries
//! - Contains unresolved table indexes for types and properties
//! - Minimal processing overhead during initial parsing
//! - Used for memory-efficient storage and initial metadata loading
//!
//! ### Owned Variant (`PropertyMapEntry`)
//! - Fully processed and validated table entries
//! - Contains resolved type and property references
//! - Provides high-level access methods and validation
//! - Used for application logic and metadata analysis
//!
//! ## Property Mapping Architecture
//!
//! `PropertyMap` entries establish one-to-many relationships:
//! - **Parent Type**: Reference to the type that owns the properties
//! - **Property List**: Collection of properties associated with the type
//! - **Range Mapping**: Efficient property range lookup within tables
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.35 - `PropertyMap` table specification
//! - [`crate::metadata::tables::Property`] - Property definitions
//! - [`crate::metadata::tables::TypeDefRaw`] - Type definitions
//! - [`crate::metadata::typesystem`] - Type system integration
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

/// A concurrent map that holds Token to `PropertyMapEntry` mappings.
///
/// This skip list-based map provides efficient concurrent access to loaded
/// `PropertyMapEntry` entries indexed by their metadata tokens. Used by the loader
/// for storing and retrieving property mapping entries.
pub type PropertyMapEntryMap = SkipMap<Token, PropertyMapEntryRc>;

/// A thread-safe vector containing `PropertyMapEntry` entries.
///
/// This concurrent vector provides sequential access to `PropertyMapEntry` entries
/// while supporting safe concurrent iteration and access from multiple threads.
pub type PropertyMapEntryList = Arc<boxcar::Vec<PropertyMapEntryRc>>;

/// A reference-counted pointer to a `PropertyMapEntry`.
///
/// This atomic reference-counted pointer enables safe sharing of `PropertyMapEntry`
/// instances across threads while providing automatic memory management.
pub type PropertyMapEntryRc = Arc<PropertyMapEntry>;
