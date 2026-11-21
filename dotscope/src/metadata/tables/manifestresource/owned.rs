//! Owned `ManifestResource` table structure with resolved references and resource access.
//!
//! This module provides the [`ManifestResource`] struct, which represents resource entries
//! with all references resolved and resource data access established. Unlike [`ManifestResourceRaw`],
//! this structure contains resolved implementation references, owned strings, and direct
//! access to resource data.
//!
//! [`ManifestResourceRaw`]: crate::metadata::tables::ManifestResourceRaw

use crate::metadata::{
    streams::SharedStr, tables::ManifestResourceAttributes, token::Token,
    typesystem::CilTypeReference,
};

/// Owned `ManifestResource` table entry with resolved references and resource access.
///
/// This structure represents an assembly resource entry with all coded indexes resolved
/// to their target structures and resource data access established. It provides complete
/// resource metadata and enables runtime resource loading and access operations.
///
/// # Resource Storage Models
/// `ManifestResource` entries support different resource storage patterns:
/// - **Embedded resources**: Data stored directly in the current assembly PE file
/// - **File-based resources**: External files referenced through the File table
/// - **Assembly-based resources**: Resources located in external assemblies
/// - **Satellite resources**: Culture-specific resources for localization
pub struct ManifestResource {
    /// Row identifier within the `ManifestResource` table.
    ///
    /// Unique identifier for this resource entry, used for internal
    /// table management and cross-references.
    pub rid: u32,

    /// Metadata token identifying this `ManifestResource` entry.
    ///
    /// The token enables efficient lookup and reference to this resource
    /// from other metadata structures and runtime systems.
    pub token: Token,

    /// Byte offset of this entry within the raw table data.
    ///
    /// Used for efficient table navigation and binary metadata processing.
    pub offset: usize,

    /// Byte offset of the resource data within the target storage.
    ///
    /// For embedded resources, this is the offset within the current assembly's PE file
    /// relative to the resource section. For external resources, this value is 0 and
    /// the actual location is determined by the [`source`] reference.
    ///
    /// [`source`]: Self::source
    pub data_offset: usize,

    /// Size of the resource data in bytes.
    ///
    /// For embedded resources, this provides the exact data size for efficient reading.
    /// For external resources, this value is 0 and the size must be determined from
    /// the external source (file or assembly).
    pub data_size: usize,

    /// Resource visibility and access control attributes.
    ///
    /// Bitflags controlling resource visibility and accessibility, including
    /// public/private access levels and assembly boundary restrictions.
    pub flags: ManifestResourceAttributes,

    /// Resource identifier name.
    ///
    /// Owned string containing the unique name used to identify and access this resource
    /// at runtime. Resource names are typically hierarchical (e.g., "Resources.Images.Icon.png").
    pub name: SharedStr,

    /// Resolved reference to the resource implementation source.
    ///
    /// Specifies where the resource data is located:
    /// - `None`: Embedded in the current assembly (use [`data_offset`] and [`data_size`])
    /// - `Some(AssemblyRef)`: Located in an external assembly
    /// - `Some(File)`: Located in an external file referenced by the File table
    ///
    /// [`data_offset`]: Self::data_offset
    /// [`data_size`]: Self::data_size
    pub source: Option<CilTypeReference>,
}
