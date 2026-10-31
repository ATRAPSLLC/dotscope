//! Owned Assembly table representation
//!
//! Provides the [`crate::metadata::tables::assembly::Assembly`] struct which contains fully resolved assembly metadata
//! with owned data and resolved heap references. This is the primary data structure
//! for representing assembly identity and versioning information in a usable form.

use crate::{
    metadata::{
        customattributes::CustomAttributeValueList,
        security::Security,
        tables::{AssemblyFlags, HashAlgorithmId},
        token::Token,
    },
    utils::RowList,
};

/// Represents a .NET CIL assembly with fully resolved metadata and owned data
///
/// This structure contains the complete assembly identity information from the Assembly
/// metadata table (0x20), with all heap references resolved to owned strings and byte arrays.
/// Unlike [`crate::metadata::tables::assembly::raw::AssemblyRaw`], this provides
/// immediate access to string data without requiring heap lookups.
///
/// # Assembly Identity
///
/// An assembly's identity consists of:
/// - **Simple name**: The filename without extension (e.g., "System.Core")
/// - **Version**: Four-part version number (Major.Minor.Build.Revision)
/// - **Culture**: Localization culture (None for culture-neutral assemblies)
/// - **Public key**: Strong name public key for verification (optional)
///
/// # Reference
/// - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification
pub struct Assembly {
    /// Row identifier within the Assembly metadata table
    ///
    /// The 1-based index of this assembly row. Since the Assembly table contains
    /// at most one row, this value is typically 1 when present.
    pub rid: u32,

    /// Metadata token for this assembly
    ///
    /// Combines the table identifier (0x20 for Assembly) with the row ID to create
    /// a unique token that can be used to reference this assembly from other metadata.
    pub token: Token,

    /// Byte offset of this assembly row within the metadata tables stream
    ///
    /// Physical location of the raw assembly data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Hash algorithm identifier for file integrity verification
    ///
    /// Specifies the cryptographic hash algorithm used to compute file hashes in the
    /// assembly manifest. See [`crate::metadata::tables::assembly::AssemblyHashAlgorithm`]
    /// for standard values. Common values:
    /// - `0x0000`: No hash algorithm
    /// - `0x8003`: MD5 (deprecated)
    /// - `0x8004`: SHA1 (deprecated)
    pub hash_alg_id: HashAlgorithmId,

    /// Major version number
    ///
    /// The first component of the four-part assembly version. Typically incremented
    /// for major releases with breaking changes.
    pub major_version: u32,

    /// Minor version number  
    ///
    /// The second component of the four-part assembly version. Typically incremented
    /// for minor releases with new features but backward compatibility.
    pub minor_version: u32,

    /// Build number
    ///
    /// The third component of the four-part assembly version. Often represents
    /// the build number or patch level.
    pub build_number: u32,

    /// Revision number
    ///
    /// The fourth component of the four-part assembly version. Often represents
    /// a hotfix or emergency patch level.
    pub revision_number: u32,

    /// Assembly flags bitmask
    ///
    /// Controls assembly loading behavior and characteristics. See
    /// [`crate::metadata::tables::assembly::AssemblyFlags`] for flag constants.
    /// Common flags:
    /// - `0x0001`: Contains full public key (not just token)
    /// - `0x0100`: Retargetable at runtime
    pub flags: AssemblyFlags,

    /// Strong name public key data
    ///
    /// Contains the complete public key for strong name verification when
    /// [`flags`](crate::metadata::tables::assembly::Assembly::flags) has `PUBLIC_KEY` set. If `None`, the assembly
    /// is not strong-named. For strong-named assemblies with only a public key token,
    /// this contains the 8-byte token rather than the full key.
    pub public_key: Option<Vec<u8>>,

    /// Simple assembly name
    ///
    /// The filename of the assembly without the file extension. For example,
    /// "System.Core" for the System.Core.dll assembly. This is the primary
    /// identifier used for assembly loading and binding.
    pub name: String,

    /// Localization culture
    ///
    /// Specifies the culture for localized assemblies (e.g., "en-US", "fr-FR").
    /// `None` indicates a culture-neutral assembly that can be used with any culture.
    /// Satellite assemblies typically have specific culture values.
    pub culture: Option<String>,

    /// The assembly's declarative security, a `DeclSecurity` row each, in table order: an
    /// assembly may request permissions under several actions (minimum, optional, refused).
    pub security: RowList<Security>,

    /// Custom attributes attached to this assembly
    ///
    /// Contains all custom attributes applied to the assembly, such as
    /// `AssemblyVersionAttribute`, `AssemblyDescriptionAttribute`, etc.
    /// These provide additional metadata beyond the core assembly identity.
    pub custom_attributes: CustomAttributeValueList,
}
