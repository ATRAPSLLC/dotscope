//! Owned File structures for the File metadata table.
//!
//! This module provides the [`File`] struct which represents file definitions
//! with resolved references and owned data. Files list the components of
//! multi-file assemblies including modules, resources, and native libraries.
//!
//! # Purpose
//! The File table enables multi-file assembly scenarios:
//! - **Multi-module assemblies**: Additional .netmodule files containing code
//! - **Resource files**: Binary data files (.resources, images, data)
//! - **Native libraries**: Unmanaged DLLs for P/Invoke operations
//! - **Documentation**: Associated help files and XML documentation
//! - **Satellite assemblies**: Localization and culture-specific resources
//!
//! # File Management
//! Files provide assembly composition information:
//! - **Component tracking**: Lists all files that comprise the assembly
//! - **Integrity verification**: Cryptographic hashes ensure file authenticity
//! - **Type classification**: Flags distinguish metadata from resource files
//! - **Reference resolution**: Names enable runtime file location
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.19 for the File table specification.

use crate::metadata::{
    customattributes::CustomAttributeValueList,
    streams::SharedStr,
    tables::{AssemblyRefHash, FileAttributes},
    token::Token,
};

/// Represents a file definition with resolved references and owned data.
///
/// A file entry describes a component of a multi-file assembly, providing metadata
/// about files that are part of the assembly but stored separately from the main
/// manifest. This includes modules, resources, and native libraries.
///
/// # File Types
/// Files can serve various purposes in assemblies:
/// - **Executable modules**: .netmodule files with executable code
/// - **Resource files**: .resources files with binary data
/// - **Native libraries**: .dll files with unmanaged code
/// - **Documentation**: .xml files with API documentation
/// - **Configuration**: Data files with application settings
///
/// # File Attributes
/// The flags field indicates file characteristics:
/// - **`CONTAINS_META_DATA`**: File contains .NET metadata (executable modules)
/// - **`CONTAINS_NO_META_DATA`**: Resource files without metadata
///
/// # Hash Verification
/// Each file includes a cryptographic hash for security:
/// - **SHA-1 or SHA-256**: Algorithm depends on assembly version
/// - **Integrity checking**: Verifies file hasn't been tampered with
/// - **Loading validation**: Runtime can verify file authenticity
/// - **Security assurance**: Prevents malicious file substitution
///
/// # Assembly Integration
/// Files integrate with the broader assembly structure:
/// - **Module loading**: Executable files loaded by the CLR
/// - **Resource access**: Resource files accessed through APIs
/// - **P/Invoke**: Native libraries used for interop
/// - **Documentation**: Help files displayed in IDEs
///
/// # ECMA-335 Reference
/// See ECMA-335, Partition II, §22.19 for the complete File table specification.
#[derive(Debug)]
pub struct File {
    /// The row identifier in the File table.
    ///
    /// This 1-based index uniquely identifies this file within the File table.
    /// Combined with the table type, it forms the file's unique identity.
    pub rid: u32,

    /// The metadata token for this file.
    ///
    /// A [`crate::metadata::token::Token`] that uniquely identifies this file across the entire assembly.
    /// The token encodes both the table type (File) and the row ID.
    ///
    /// [`crate::metadata::token::Token`]: crate::metadata::token::Token
    pub token: Token,

    /// The byte offset of this file in the metadata tables stream.
    ///
    /// This offset points to the start of this file's row data within the
    /// metadata tables stream, used for binary parsing and navigation.
    pub offset: usize,

    /// File attribute flags indicating type and characteristics.
    ///
    /// A 4-byte bitmask of [`FileAttributes`] values that specify the nature
    /// of the file, particularly whether it contains .NET metadata or is a
    /// resource file.
    ///
    /// # Common Values
    /// - **`CONTAINS_META_DATA` (0x0000)**: File contains .NET metadata
    /// - **`CONTAINS_NO_META_DATA` (0x0001)**: Resource file without metadata
    ///
    /// [`FileAttributes`]: crate::metadata::tables::file::FileAttributes
    pub flags: FileAttributes,

    /// The name of the file.
    ///
    /// The filename as it appears in the assembly manifest, resolved from
    /// the strings heap. This name is used to locate the file during
    /// assembly loading and verification.
    pub name: SharedStr,

    /// Cryptographic hash value for integrity verification.
    ///
    /// An [`AssemblyRefHash`] containing the hash data used to verify the
    /// file's integrity. The hash algorithm (SHA-1 or SHA-256) depends on
    /// the assembly version and security requirements.
    ///
    /// [`AssemblyRefHash`]: crate::metadata::tables::AssemblyRefHash
    pub hash_value: AssemblyRefHash,

    /// Custom attributes applied to this file.
    ///
    /// A collection of custom attributes that provide additional metadata
    /// about the file, such as versioning information, descriptions, or
    /// security attributes.
    pub custom_attributes: CustomAttributeValueList,
}
