//! `ManifestResource` table implementation for assembly resource management.
//!
//! This module provides complete support for the `ManifestResource` metadata table, which defines
//! resources embedded in or linked to .NET assemblies. The `ManifestResource` table is essential
//! for resource management, globalization, and access to non-code assets in .NET applications.
//!
//! # Module Components
//! - [`ManifestResourceRaw`] - Raw table structure with unresolved coded indexes
//! - [`ManifestResource`] - Owned variant with resolved references and resource data access
//! - [`ManifestResourceLoader`](crate::metadata::loader::tables::ManifestResourceLoader) - Internal loader for processing table entries (crate-private)
//! - [`ManifestResourceAttributes`] - Resource visibility and access control flags
//! - Type aliases for collections: [`ManifestResourceMap`], [`ManifestResourceList`], [`ManifestResourceRc`]
//!
//! # Table Structure (ECMA-335 §22.24)
//! | Column | Type | Description |
//! |--------|------|-------------|
//! | Offset | 4-byte offset | Location within resource data (0 for external) |
//! | Flags | 4-byte flags | Resource visibility attributes |
//! | Name | String heap index | Resource identifier name |
//! | Implementation | Implementation coded index | Location reference (null, File, or `AssemblyRef`) |
//!
//! # Resource Storage Models
//! The `ManifestResource` table supports multiple resource storage and access patterns:
//! - **Embedded resources**: Binary data stored directly in the assembly PE file
//! - **File-based resources**: External files referenced through the File table
//! - **Assembly-based resources**: Resources located in external assemblies via `AssemblyRef`
//! - **Satellite assemblies**: Culture-specific resources for internationalization
//! - **Streaming access**: Large resources accessed through streaming interfaces
//!
//! # Resource Visibility and Access
//! Resource access is controlled through [`ManifestResourceAttributes`]:
//! - **Public resources**: Accessible to external assemblies and runtime systems
//! - **Private resources**: Restricted to the declaring assembly's internal use
//! - **Assembly security**: Controlled access based on assembly trust levels
//!
//! # ECMA-335 References
//! - ECMA-335, Partition II, §22.24: `ManifestResource` table specification
//! - ECMA-335, Partition II, §23.2.7: Implementation coded index encoding
//! - ECMA-335, Partition II, §6.2.2: Resources and resource management
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

/// Concurrent map for storing `ManifestResource` entries indexed by [`crate::metadata::token::Token`].
///
/// This thread-safe map enables efficient lookup of resources by their
/// associated tokens during metadata processing and runtime resource access.
pub type ManifestResourceMap = SkipMap<Token, ManifestResourceRc>;

/// Thread-safe list for storing collections of `ManifestResource` entries.
///
/// Used for maintaining ordered sequences of resources during metadata
/// loading and for iteration over all resources in an assembly.
pub type ManifestResourceList = Arc<boxcar::Vec<ManifestResourceRc>>;

/// Reference-counted pointer to a [`ManifestResource`] instance.
///
/// Enables efficient sharing of resource data across multiple contexts
/// without duplication, supporting concurrent access patterns in resource processing.
pub type ManifestResourceRc = Arc<ManifestResource>;

metadata_flags! {
    /// Resource visibility and access control attributes for ManifestResource entries.
    ///
    /// These flags control the visibility and accessibility of resources within
    /// and across assembly boundaries, providing security and encapsulation for
    /// resource access in .NET applications.
    pub struct ManifestResourceAttributes(u32);
}

impl ManifestResourceAttributes {
    /// Resource is exported and accessible from external assemblies.
    ///
    /// Public resources can be accessed by other assemblies and runtime systems,
    /// enabling cross-assembly resource sharing and component integration.
    pub const PUBLIC: Self = Self(0x0001);

    /// Resource is private and restricted to the declaring assembly.
    ///
    /// Private resources are only accessible within the declaring assembly,
    /// providing encapsulation and preventing external access to sensitive data.
    pub const PRIVATE: Self = Self(0x0002);
}
