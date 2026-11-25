//! Raw `AssemblyRefOS` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw`] struct
//! for low-level access to `AssemblyRefOS` metadata table data with unresolved table indexes.
//! This represents the binary format of `AssemblyRefOS` records as they appear in the metadata
//! tables stream, requiring resolution to create usable data structures.
//!
//! # Architecture
//!
//! The raw representation maintains the exact binary layout from the metadata tables stream,
//! with unresolved table indexes that reference other metadata tables. This design allows
//! efficient parsing and deferred resolution until references are needed.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw`] - Raw table row structure with unresolved indexes
//! - [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw::to_owned`] - Resolution to owned representation
//! - [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw::apply`] - Direct application of OS data
//!
//! # `AssemblyRefOS` Table Format
//!
//! The `AssemblyRefOS` table (0x25) contains zero or more rows with these fields:
//! - **`OSPlatformId`** (4 bytes): Operating system platform identifier
//! - **`OSMajorVersion`** (4 bytes): Major version number of target OS
//! - **`OSMinorVersion`** (4 bytes): Minor version number of target OS
//! - **`AssemblyRef`** (2/4 bytes): Table index into `AssemblyRef` table
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::AssemblyRefOsRaw;
//! # use dotscope::metadata::tables::AssemblyRefMap;
//! # fn example(raw: AssemblyRefOsRaw, refs: &AssemblyRefMap) -> dotscope::Result<()> {
//! // Convert to owned representation
//! let owned = raw.to_owned(refs)?;
//!
//! // Or apply OS data directly
//! raw.apply(refs)?;
//! # Ok(())
//! # }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! Raw table operations can fail if:
//! - Referenced `AssemblyRef` entries are missing from the provided map
//! - Assembly reference tokens are invalid or malformed
//! - Table data is corrupted or incomplete
//!
//! # Thread Safety
//!
//! Raw table structures are [`Send`] and [`Sync`]. The `apply` method uses atomic operations
//! when updating assembly reference data, ensuring thread-safe modifications.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables::assemblyrefos::owned`] - Owned representation with resolved references
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//!
//! # References
//!
//! - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification

use std::sync::{atomic::Ordering, Arc};

use crate::{
    metadata::{
        tables::{AssemblyRefMap, AssemblyRefOs, AssemblyRefOsRc, TableId, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyRefOS` table row with unresolved table indexes
///
/// Represents the binary format of an `AssemblyRefOS` metadata table entry (table ID 0x25) as stored
/// in the metadata tables stream. The `AssemblyRef` field contains a table index that must be
/// resolved using the [`crate::metadata::tables::assemblyref::AssemblyRefMap`] to access the
/// referenced assembly data.
///
/// The `AssemblyRefOS` table specifies operating system compatibility requirements for external
/// assembly references, allowing assemblies to declare explicit OS version dependencies.
/// This table is rarely used in modern .NET assemblies and is considered legacy.
///
/// # Operating System Targeting
///
/// The `AssemblyRefOS` entry contains platform identification and version requirements:
/// - **Platform ID**: Operating system family (Windows 32-bit, 64-bit, etc.)
/// - **Major/Minor Version**: Target OS version numbers
/// - **Assembly Reference**: Link to the external assembly requiring these OS constraints
///
/// # Conversion and Usage
///
/// Raw entries should be converted to [`crate::metadata::tables::assemblyrefos::owned::AssemblyRefOs`]
/// via [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw::to_owned`] for practical use,
/// or have their OS data applied directly via [`crate::metadata::tables::assemblyrefos::raw::AssemblyRefOsRaw::apply`].
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. Methods that update assembly references use atomic
/// operations to ensure thread-safe modifications without additional synchronization.
///
/// # References
///
/// - [ECMA-335 II.22.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefOS` table specification
pub struct AssemblyRefOsRaw {
    /// Row identifier within the `AssemblyRefOS` metadata table
    ///
    /// The 1-based index of this `AssemblyRefOS` row within the table.
    pub rid: u32,

    /// Metadata token for this `AssemblyRefOS` entry
    ///
    /// Combines the table identifier (0x25 for `AssemblyRefOS`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `AssemblyRefOS` row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyRefOS` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Operating system platform identifier
    ///
    /// Specifies the target operating system family. Common values include:
    /// - 1: Windows 32-bit
    /// - 2: Windows 64-bit
    /// - Other values for various platform types
    pub os_platform_id: u32,

    /// Major version number of the target operating system
    ///
    /// The major version component of the required OS version (e.g., 6 for Windows Vista/7/8).
    pub os_major_version: u32,

    /// Minor version number of the target operating system
    ///
    /// The minor version component of the required OS version (e.g., 1 for Windows 7).
    pub os_minor_version: u32,

    /// Table index into the `AssemblyRef` table
    ///
    /// 1-based index referencing the [`crate::metadata::tables::assemblyref::AssemblyRefRaw`]
    /// entry that represents the external assembly these OS requirements apply to.
    /// Must be resolved using [`AssemblyRefMap`] to access the actual assembly reference.
    pub assembly_ref: u32,
}

impl AssemblyRefOsRaw {
    /// Convert raw `AssemblyRefOS` data to owned representation with resolved references
    ///
    /// Creates an [`crate::metadata::tables::assemblyrefos::AssemblyRefOsRc`] from this raw data
    /// by resolving the `AssemblyRef` table index to the actual assembly reference. The resulting
    /// structure contains all necessary data for representing OS compatibility requirements in
    /// a usable form without requiring further table lookups.
    ///
    /// The resolution process transforms the raw table index into a direct reference to the
    /// [`crate::metadata::tables::assemblyref::AssemblyRef`] entry, creating a self-contained
    /// structure suitable for runtime use.
    ///
    /// # Arguments
    ///
    /// * `refs` - Map of loaded [`crate::metadata::tables::assemblyref::AssemblyRef`] entities
    ///   keyed by their metadata tokens
    ///
    /// # Returns
    ///
    /// * `Ok(`[`crate::metadata::tables::assemblyrefos::AssemblyRefOsRc`]`)` - Successfully resolved `AssemblyRefOS` data
    /// * `Err(`[`crate::Error`]`)` - Assembly reference resolution failed
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The referenced `AssemblyRef` entry cannot be found in the provided map
    /// - The assembly reference token is invalid or malformed
    /// - The `AssemblyRef` table index is out of bounds
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The resulting owned structure is also thread-safe for concurrent access.
    pub fn to_owned(&self, refs: &AssemblyRefMap) -> Result<AssemblyRefOsRc> {
        Ok(Arc::new(AssemblyRefOs {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            os_platform_id: self.os_platform_id,
            os_major_version: self.os_major_version,
            os_minor_version: self.os_minor_version,
            assembly_ref: match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
                Some(refs) => refs.value().clone(),
                None => {
                    return Err(malformed_error!(
                        "Failed to resolve assemblyref token - {}",
                        self.assembly_ref | 0x2300_0000
                    ))
                }
            },
        }))
    }

    /// Apply operating system compatibility information directly to the referenced assembly
    ///
    /// Updates the assembly reference with OS platform and version information from this
    /// `AssemblyRefOS` entry without creating an owned representation. This is used when
    /// only the OS data needs to be applied without retaining the `AssemblyRefOS` structure,
    /// providing a more efficient path for bulk OS data application.
    ///
    /// The method resolves the `AssemblyRef` table index and uses atomic operations to update
    /// the OS compatibility fields in the referenced assembly entry, ensuring thread-safe
    /// modifications without requiring external synchronization.
    ///
    /// # Arguments
    ///
    /// * `refs` - Map of loaded [`crate::metadata::tables::assemblyref::AssemblyRef`] entities
    ///   keyed by their metadata tokens
    ///
    /// # Returns
    ///
    /// * `Ok(())` - OS information successfully applied to assembly reference
    /// * `Err(`[`crate::Error`]`)` - Assembly reference resolution or update failed
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if:
    /// - The referenced `AssemblyRef` entry cannot be found in the provided map
    /// - The assembly reference token is invalid or malformed
    /// - The `AssemblyRef` table index is out of bounds
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses atomic operations ([`std::sync::atomic::Ordering::Relaxed`])
    /// to update assembly reference fields. Multiple threads can safely call this method
    /// concurrently on different `AssemblyRefOS` entries.
    pub fn apply(&self, refs: &AssemblyRefMap) -> Result<()> {
        match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
            Some(entry) => {
                let entry = entry.value();
                entry
                    .os_major_version
                    .store(self.os_major_version, Ordering::Relaxed);
                entry
                    .os_minor_version
                    .store(self.os_minor_version, Ordering::Relaxed);
                entry
                    .os_platform_id
                    .store(self.os_platform_id, Ordering::Relaxed);

                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve assemblyref token - {}",
                self.assembly_ref | 0x2300_0000
            )),
        }
    }
}

impl TableRow for AssemblyRefOsRaw {
    /// Calculate the row size for `AssemblyRefOS` table entries
    ///
    /// Returns the total byte size of a single `AssemblyRefOS` table row based on the table
    /// configuration. The size varies depending on the size of table indexes in the metadata.
    ///
    /// # Size Breakdown
    /// - `os_platform_id`: 4 bytes (operating system platform identifier)
    /// - `os_major_version`: 4 bytes (major OS version number)
    /// - `os_minor_version`: 4 bytes (minor OS version number)
    /// - `assembly_ref`: 2 or 4 bytes (table index into `AssemblyRef` table)
    ///
    /// Total: 14-16 bytes depending on table index size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* os_platform_id */   4u8
            /* os_major_version */ .saturating_add(4)
            /* os_minor_version */ .saturating_add(4)
            /* assembly_ref */     .saturating_add(sizes.table_index_bytes(TableId::AssemblyRef))

        )
    }
}
