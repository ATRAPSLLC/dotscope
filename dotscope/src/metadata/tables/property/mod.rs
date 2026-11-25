//! # Property Table Module
//!
//! This module provides comprehensive access to the Property metadata table (ID 0x17),
//! which defines properties exposed by types in .NET assemblies. Properties represent
//! named attributes that can be accessed through getter and setter methods, forming
//! a fundamental part of the .NET object model.
//!
//! ## Table Purpose
//!
//! The Property table provides:
//! - **Property Definitions**: Names, signatures, and attributes for type properties
//! - **Method Association**: Links properties to their getter/setter methods via `MethodSemantics`
//! - **Type Binding**: Associates properties with their declaring types through `PropertyMap`
//! - **Reflection Support**: Enables property-based reflection and metadata queries
//!
//! ## Module Structure
//!
//! The module follows the standard dual-variant pattern for metadata tables:
//!
//! ### Raw Variant (`PropertyRaw`)
//! - Direct memory representation of table entries
//! - Contains unresolved heap indexes for names and signatures
//! - Minimal processing overhead during initial parsing
//! - Used for memory-efficient storage and initial metadata loading
//!
//! ### Owned Variant (`Property`)
//! - Fully processed and validated table entries
//! - Contains resolved property names and parsed type signatures
//! - Provides high-level access methods and validation
//! - Used for application logic and metadata analysis
//!
//! ## Property Attributes
//!
//! Properties can have various attributes that control their behavior:
//! - **`SpecialName`**: Property has special naming conventions
//! - **`RTSpecialName`**: Runtime should verify name encoding
//! - **`HasDefault`**: Property has a default value defined
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.34 - Property table specification
//! - [`crate::metadata::tables::PropertyMap`] - Property to type mapping
//! - [`crate::metadata::tables::MethodSemantics`] - Property method associations
//! - [`crate::metadata::signatures`] - Property signature parsing
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::{metadata::token::Token, utils::LazyList};

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// A concurrent map that holds Token to Property mappings.
///
/// This skip list-based map provides efficient concurrent access to loaded
/// Property entries indexed by their metadata tokens. Used by the loader
/// for storing and retrieving property entries.
pub type PropertyMap = SkipMap<Token, PropertyRc>;

/// A thread-safe vector containing Property entries.
///
/// This concurrent vector provides sequential access to Property entries
/// while supporting safe concurrent iteration and access from multiple threads. A list
/// allocates its storage on its first push: most types hold none.
pub type PropertyList = LazyList<PropertyRc>;

/// A reference-counted pointer to a Property entry.
///
/// This atomic reference-counted pointer enables safe sharing of Property
/// instances across threads while providing automatic memory management.
pub type PropertyRc = Arc<Property>;

metadata_flags! {
    /// Property attribute flags as defined in ECMA-335 (§II.23.1.14).
    ///
    /// Strongly-typed wrapper around the 2-byte `Property.Flags` bitmask that controls
    /// various aspects of property behavior including special naming, default values,
    /// and runtime behavior characteristics.
    ///
    /// ## Reference
    /// - [ECMA-335 II.23.1.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `PropertyAttributes` specification
    pub struct PropertyAttributes(u32);
}

impl PropertyAttributes {
    /// Property has special naming conventions.
    ///
    /// Indicates that the property name follows special naming conventions
    /// and should be treated accordingly by tools and runtime systems.
    pub const SPECIAL_NAME: Self = Self(0x0200);

    /// Runtime should check name encoding.
    ///
    /// Instructs the runtime (metadata internal APIs) to verify that the
    /// property name encoding follows the expected format and conventions.
    pub const RT_SPECIAL_NAME: Self = Self(0x0400);

    /// Property has a default value.
    ///
    /// Indicates that this property has an associated default value defined
    /// in the Constant table, providing fallback behavior when no explicit
    /// value is set.
    pub const HAS_DEFAULT: Self = Self(0x1000);
}
