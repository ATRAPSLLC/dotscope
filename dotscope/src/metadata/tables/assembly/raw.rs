//! Raw Assembly table representation
//!
//! Provides the [`crate::metadata::tables::assembly::AssemblyRaw`] struct for low-level access to Assembly metadata table data
//! with unresolved heap indexes. This represents the binary format of assembly records as
//! they appear in the metadata tables stream.
//!
//! # Assembly Table Format
//!
//! The Assembly table (0x20) contains exactly one row (if present) with these fields:
//! - **`HashAlgId`** (4 bytes): Hash algorithm identifier
//! - **`MajorVersion`** (2 bytes): Major version number
//! - **`MinorVersion`** (2 bytes): Minor version number
//! - **`BuildNumber`** (2 bytes): Build number
//! - **`RevisionNumber`** (2 bytes): Revision number
//! - **Flags** (4 bytes): Assembly flags bitmask
//! - **`PublicKey`** (2/4 bytes): Blob heap index for public key data
//! - **`Name`** (2/4 bytes): String heap index for assembly name
//! - **`Culture`** (2/4 bytes): String heap index for culture name
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification

use std::sync::Arc;

use crate::{
    metadata::{
        streams::{Blob, Strings},
        tables::{Assembly, AssemblyFlags, AssemblyRc, HashAlgorithmId, TableInfoRef, TableRow},
        token::Token,
    },
    utils::RowList,
    Result,
};

#[derive(Clone, Debug)]
/// Raw Assembly table row with unresolved heap indexes
///
/// Represents the binary format of an Assembly metadata table entry (table ID 0x20) as stored
/// in the metadata tables stream. All string and blob references are stored as heap indexes
/// that must be resolved using the appropriate heaps to access the actual data.
///
/// The Assembly table contains the identity information for the current assembly, including
/// version numbers, flags, and references to the assembly name and public key data.
///
/// # Reference
/// - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification
pub struct AssemblyRaw {
    /// Row identifier within the Assembly metadata table
    ///
    /// The 1-based index of this assembly row. Since the Assembly table contains
    /// at most one row, this value is typically 1 when present.
    pub rid: u32,

    /// Metadata token for this assembly row
    ///
    /// Combines the table identifier (0x20 for Assembly) with the row ID to create
    /// a unique token. Format: `0x20000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw assembly data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Hash algorithm identifier (unresolved)
    ///
    /// 4-byte value specifying the cryptographic hash algorithm used for file integrity.
    /// See [`crate::metadata::tables::assembly::AssemblyHashAlgorithm`] for standard values.
    pub hash_alg_id: u32,

    /// Major version number (unresolved)
    ///
    /// 2-byte value stored as u32. First component of the four-part assembly version.
    pub major_version: u32,

    /// Minor version number (unresolved)
    ///
    /// 2-byte value stored as u32. Second component of the four-part assembly version.
    pub minor_version: u32,

    /// Build number (unresolved)
    ///
    /// 2-byte value stored as u32. Third component of the four-part assembly version.
    pub build_number: u32,

    /// Revision number (unresolved)
    ///
    /// 2-byte value stored as u32. Fourth component of the four-part assembly version.
    pub revision_number: u32,

    /// Assembly flags bitmask (unresolved)
    ///
    /// 4-byte bitmask controlling assembly behavior and characteristics.
    /// See [`crate::metadata::tables::assembly::AssemblyFlags`] for flag constants.
    pub flags: u32,

    /// Public key blob heap index (unresolved)
    ///
    /// Index into the blob heap containing the strong name public key data.
    /// Value of 0 indicates no public key (unsigned assembly).
    pub public_key: u32,

    /// Assembly name string heap index (unresolved)
    ///
    /// Index into the string heap containing the simple assembly name.
    /// This is the primary identifier for the assembly.
    pub name: u32,

    /// Culture string heap index (unresolved)
    ///
    /// Index into the string heap containing the culture name for localized assemblies.
    /// Value of 0 indicates a culture-neutral assembly.
    pub culture: u32,
}

impl AssemblyRaw {
    /// Convert raw assembly data to owned representation with resolved heap references
    ///
    /// Resolves all heap indexes to their actual string and blob data, creating an
    /// [`crate::metadata::tables::Assembly`] instance with owned data that doesn't
    /// require the original heaps for access.
    ///
    /// # Arguments
    /// * `strings` - The string heap for resolving name and culture indexes
    /// * `blobs` - The blob heap for resolving public key data
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::AssemblyRc`]`)` - Reference-counted owned assembly
    /// * `Err(`[`crate::Error`]`)` - If heap resolution fails
    ///
    /// # Errors
    /// This function will return an error if:
    /// - String heap lookup fails for the assembly name or culture
    /// - Blob heap lookup fails for the public key data
    ///
    /// # Heap Resolution
    /// - `name`: Resolved to owned String from string heap
    /// - `culture`: Resolved to optional String (None if index is 0)
    /// - `public_key`: Resolved to optional `Vec<u8>` (None if index is 0)
    pub fn to_owned(&self, strings: &Strings, blobs: &Blob) -> Result<AssemblyRc> {
        Ok(Arc::new(Assembly {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            hash_alg_id: HashAlgorithmId::new(self.hash_alg_id),
            major_version: self.major_version,
            minor_version: self.minor_version,
            build_number: self.build_number,
            revision_number: self.revision_number,
            flags: AssemblyFlags::new(self.flags),
            public_key: if self.public_key == 0 {
                None
            } else {
                Some(blobs.get(self.public_key as usize)?.to_vec())
            },
            name: strings.get(self.name as usize)?.to_string(),
            culture: if self.culture == 0 {
                None
            } else {
                Some(strings.get(self.culture as usize)?.to_string())
            },
            security: RowList::new(),
            custom_attributes: Default::default(),
        }))
    }

    /// Apply assembly row data to update related metadata structures
    ///
    /// Assembly entries are self-contained and represent the current assembly metadata.
    /// Unlike other metadata tables that may have cross-references, Assembly table entries
    /// don't require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since assembly data is purely descriptive.
    ///
    /// # Returns
    /// Always returns `Ok(())` since Assembly entries don't modify other tables
    ///
    /// # Note
    /// This is part of the internal metadata loading infrastructure and should not
    /// be called directly by user code.
    ///
    /// # Errors
    /// Currently returns `Ok(())` in all cases as this is a placeholder implementation.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for AssemblyRaw {
    /// Calculate the byte size of an Assembly table row
    ///
    /// Computes the total size based on fixed-size fields plus variable-size heap indexes.
    /// The size depends on whether the metadata uses 2-byte or 4-byte heap indexes.
    ///
    /// # Row Layout
    /// - `hash_alg_id`: 4 bytes (fixed)
    /// - `major_version`: 2 bytes (fixed)
    /// - `minor_version`: 2 bytes (fixed)
    /// - `build_number`: 2 bytes (fixed)
    /// - `revision_number`: 2 bytes (fixed)
    /// - `flags`: 4 bytes (fixed)
    /// - `public_key`: 2 or 4 bytes (blob heap index)
    /// - `name`: 2 or 4 bytes (string heap index)
    /// - `culture`: 2 or 4 bytes (string heap index)
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information for heap index widths
    ///
    /// # Returns
    /// Total byte size of one Assembly table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* hash_alg_id */     4u8
            /* major_version */   .saturating_add(2)
            /* minor_version */   .saturating_add(2)
            /* build_number */    .saturating_add(2)
            /* revision_number */ .saturating_add(2)
            /* flags */           .saturating_add(4)
            /* public_key */      .saturating_add(sizes.blob_bytes())
            /* name */            .saturating_add(sizes.str_bytes())
            /* culture */         .saturating_add(sizes.str_bytes())

        )
    }
}
