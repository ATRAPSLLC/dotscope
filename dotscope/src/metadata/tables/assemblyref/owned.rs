//! Owned `AssemblyRef` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyref::owned::AssemblyRef`] struct
//! which contains fully resolved assembly reference metadata with owned data and resolved heap
//! references. This is the primary data structure for representing external assembly dependencies
//! in a usable form after the dual variant resolution phase.
//!
//! # Architecture
//!
//! The owned representation stores fully resolved data from the `AssemblyRef` metadata table,
//! including resolved string and blob heap references. This eliminates the need for heap
//! lookups during runtime access, providing immediate access to assembly reference metadata.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyref::owned::AssemblyRef`] - Main owned assembly reference structure
//! - [`crate::metadata::identity::Identity`] - Strong name identity information
//! - [`crate::metadata::tables::assemblyref::AssemblyRefHash`] - Assembly hash verification data
//! - [`crate::metadata::customattributes::CustomAttributeValueList`] - Custom attribute collection
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyref::raw`] - Raw table representation
//! - [`crate::metadata::identity`] - Strong name identity handling
//! - [`crate::metadata::customattributes`] - Custom attribute processing
//! - [`crate::metadata::token`] - Token-based metadata references

use std::sync::atomic::AtomicU32;

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    identity::Identity,
    streams::SharedStr,
    tables::{AssemblyFlags, AssemblyRefHash},
    token::Token,
};

/// Represents a .NET assembly reference with fully resolved metadata and owned data
///
/// This structure contains the complete assembly reference information from the `AssemblyRef`
/// metadata table (0x23), with all heap references resolved to owned strings and byte arrays.
/// Unlike [`crate::metadata::tables::assemblyref::raw::AssemblyRefRaw`], this provides
/// immediate access to string data without requiring heap lookups.
///
/// # Assembly Reference Identity
///
/// An assembly reference's identity consists of:
/// - **Simple name**: The assembly name (e.g., "mscorlib", "System.Core")
/// - **Version**: Four-part version number (Major.Minor.Build.Revision)
/// - **Culture**: Localization culture (None for culture-neutral assemblies)
/// - **Public key or token**: Strong name verification data (optional)
/// - **Hash**: Optional hash value for assembly integrity verification
///
/// # Additional Metadata
///
/// This structure also includes data from related tables:
/// - **`AssemblyRefOS`**: Operating system compatibility information
/// - **`AssemblyRefProcessor`**: Processor architecture requirements
/// - **Custom attributes**: Additional metadata applied to the reference
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. Atomic fields (OS and processor data) can be
/// safely accessed and modified from multiple threads. Other fields are read-only
/// after construction and safe for concurrent access.
///
/// # References
/// - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification
/// - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification  
/// - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification
#[derive(Debug)]
pub struct AssemblyRef {
    /// Row identifier within the `AssemblyRef` table
    ///
    /// Unique identifier for this row within the metadata table. Used for internal
    /// referencing and debugging purposes.
    pub rid: u32,

    /// Metadata token for this assembly reference
    ///
    /// Contains the table ID (0x23) and row ID packed into a single value.
    /// Used for cross-referencing from other metadata tables.
    pub token: Token,

    /// File offset where this table entry begins
    ///
    /// Byte offset from the start of the PE file to the beginning of this
    /// `AssemblyRef` table entry. Used for low-level file analysis.
    pub offset: usize,

    /// Simple name of the referenced assembly
    ///
    /// The assembly name without file extension (e.g., "mscorlib", "System.Core").
    /// This is the primary identifier used during assembly resolution.
    pub name: SharedStr,

    /// Culture string for localized assemblies
    ///
    /// Specifies the culture for satellite assemblies containing localized resources.
    /// `None` indicates a culture-neutral assembly (the common case for most assemblies).
    pub culture: Option<SharedStr>,

    /// Major version number (first component of version)
    ///
    /// The first part of the four-part version number. Typically incremented
    /// for major releases with breaking changes.
    pub major_version: u32,

    /// Minor version number (second component of version)  
    ///
    /// The second part of the four-part version number. Typically incremented
    /// for minor releases with new features but no breaking changes.
    pub minor_version: u32,

    /// Build number (third component of version)
    ///
    /// The third part of the four-part version number. Often incremented
    /// for each build or compilation.
    pub build_number: u32,

    /// Revision number (fourth component of version)
    ///
    /// The fourth part of the four-part version number. Often used for
    /// patches or hotfixes.
    pub revision_number: u32,

    /// Assembly flags bit field
    ///
    /// Bitmask specifying assembly attributes using [`crate::metadata::tables::AssemblyFlags`]
    /// constants. Controls behavior like public key format and retargetability.
    pub flags: AssemblyFlags,

    /// Strong name identity information
    ///
    /// Contains either the full public key or public key token used for strong name
    /// verification. `None` indicates the assembly is not strongly named.
    pub identifier: Option<Identity>,

    /// Assembly integrity hash
    ///
    /// Optional cryptographic hash of the referenced assembly for integrity verification.
    /// The hash algorithm is typically SHA-1 or MD5, though Microsoft may have extended this.
    pub hash: Option<AssemblyRefHash>,

    // AssemblyRefOS table data
    /// Operating system platform identifier  
    ///
    /// Specifies the target operating system platform. Uses atomic access for thread safety.
    /// Corresponds to entries in the `AssemblyRefOS` table when present.
    pub os_platform_id: AtomicU32,

    /// Operating system major version
    ///
    /// Major version number of the target operating system. Uses atomic access for thread safety.
    /// Corresponds to entries in the `AssemblyRefOS` table when present.
    pub os_major_version: AtomicU32,

    /// Operating system minor version
    ///
    /// Minor version number of the target operating system. Uses atomic access for thread safety.
    /// Corresponds to entries in the `AssemblyRefOS` table when present.
    pub os_minor_version: AtomicU32,

    // AssemblyRefProcessor table data
    /// Target processor architecture
    ///
    /// Specifies the required processor architecture for the referenced assembly.
    /// Uses atomic access for thread safety. Corresponds to entries in the `AssemblyRefProcessor` table.
    pub processor: AtomicU32,

    /// Custom attributes applied to this assembly reference
    ///
    /// Collection of custom attributes that provide additional metadata for this assembly reference.
    /// Thread-safe collection supporting concurrent access.
    pub custom_attributes: CustomAttributeValueList,
}
