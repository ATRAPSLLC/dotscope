//!
//! This module provides comprehensive access to the `PropertyPtr` metadata table (ID 0x26),
//! which implements property indirection for optimized metadata layouts in .NET assemblies.
//! The `PropertyPtr` table enables efficient property access patterns and supports property
//! table compression in optimized assembly configurations.
//!
//! ## Table Purpose
//!
//! The `PropertyPtr` table provides:
//! - **Property Indirection**: Maps logical property indexes to physical table positions
//! - **Optimization Support**: Enables property table compression and reordering
//! - **Metadata Efficiency**: Reduces metadata size in optimized assemblies
//! - **Access Performance**: Provides efficient property lookup mechanisms
//!
//! ## Module Structure
//!
//! The module follows the standard dual-variant pattern for metadata tables:
//!
//! ### Raw Variant (`PropertyPtrRaw`)
//! - Direct memory representation of table entries
//! - Contains unresolved property table indexes
//! - Minimal processing overhead during initial parsing
//! - Used for memory-efficient storage and initial metadata loading
//!
//! ### Owned Variant (`PropertyPtr`)
//! - Fully processed and validated table entries
//! - Contains resolved property references and indirection mappings
//! - Provides high-level access methods and validation
//! - Used for application logic and property access operations
//!
//! ## Property Indirection Architecture
//!
//! `PropertyPtr` entries establish one-to-one mappings:
//! - **Logical Index**: The position where a property appears in logical order
//! - **Physical Index**: The actual position in the Property table
//! - **Indirection Mapping**: The relationship between logical and physical positions
//!
//! ## Optimization Context
//!
//! `PropertyPtr` tables are present when:
//! - The assembly uses uncompressed metadata streams (`#-`)
//! - Property table ordering differs from logical declaration order
//! - Property table compression has been applied during compilation
//! - Runtime property access patterns require indirection for efficiency
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.38 - `PropertyPtr` table specification
//! - [`crate::metadata::tables::Property`] - Target property table
//! - [`crate::metadata::streams`] - Metadata stream formats and compression

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

/// Type alias for shared ownership of [`PropertyPtr`] entries.
///
/// Provides thread-safe reference counting for property pointer entries,
/// enabling efficient sharing across multiple consumers without data duplication.
pub type PropertyPtrRc = std::sync::Arc<PropertyPtr>;

/// Concurrent map for property pointer storage indexed by metadata token.
///
/// Uses a lock-free skip list for high-performance concurrent access to property
/// pointer entries. The map supports efficient lookup, insertion, and iteration
/// operations across multiple threads.
pub type PropertyPtrMap = SkipMap<Token, Arc<PropertyPtr>>;

/// Thread-safe collection of property pointer entries.
///
/// Provides a growable vector implementation optimized for concurrent access
/// patterns, supporting efficient property pointer enumeration and batch operations.
pub type PropertyPtrList = Arc<boxcar::Vec<Arc<PropertyPtr>>>;
