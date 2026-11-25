//! Raw `AssemblyOS` table representation.
//!
//! This module provides low-level access to `AssemblyOS` metadata table data through the
//! [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw`] structure. The `AssemblyOS` table
//! contains operating system targeting information for .NET assemblies, though it is rarely
//! used in modern applications.
//!
//! # Architecture
//!
//! Unlike other metadata tables that require heap resolution, `AssemblyOS` contains only primitive
//! integer values, making the "raw" and "owned" representations functionally identical. This
//! simplifies the dual variant pattern used throughout the metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw`] - Raw table row structure
//! - [`crate::metadata::tables::assemblyos::AssemblyOsRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::types::RowReadable`] - Table parsing interface implementation
//!
//! # `AssemblyOS` Table Format
//!
//! The `AssemblyOS` table (0x22) contains operating system targeting information:
//! - **`OSPlatformId`** (4 bytes): Operating system platform identifier
//! - **`OSMajorVersion`** (4 bytes): Major version number of the target OS
//! - **`OSMinorVersion`** (4 bytes): Minor version number of the target OS
//!
//! # Historical Context
//!
//! This table was designed for early .NET Framework scenarios where assemblies might
//! need explicit OS compatibility declarations. Modern .NET applications typically
//! rely on runtime platform abstraction instead of metadata-level OS targeting.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{AssemblyOsRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyOS` table row representing operating system targeting information
///
/// Contains platform identification data for assemblies that specify explicit OS compatibility.
/// Unlike most metadata tables, `AssemblyOS` contains only primitive integer values and requires
/// no heap resolution, making this structure immediately usable without further processing.
///
/// The `AssemblyOS` table (0x22) is optional and rarely present in modern .NET assemblies,
/// which typically rely on runtime platform abstraction rather than compile-time OS targeting.
///
/// # Data Model
///
/// All fields contain direct integer values rather than heap indexes:
/// - No string heap references (unlike Assembly.Name)
/// - No blob heap references (unlike Assembly.PublicKey)
/// - All data is self-contained within the table row
///
/// # Reference
/// - [ECMA-335 II.22.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyOS` table specification
pub struct AssemblyOsRaw {
    /// Row identifier within the `AssemblyOS` metadata table
    ///
    /// The 1-based index of this `AssemblyOS` row. Multiple OS targets can be specified,
    /// though this is rarely used in practice.
    pub rid: u32,

    /// Metadata token for this `AssemblyOS` row
    ///
    /// Combines the table identifier (0x22 for `AssemblyOS`) with the row ID to create
    /// a unique token. Format: `0x22000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyOS` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Operating system platform identifier
    ///
    /// 4-byte value identifying the target operating system platform. Common values
    /// may include platform-specific identifiers, though specific constants are not
    /// standardized in ECMA-335.
    pub os_platform_id: u32,

    /// Major version number of the target operating system
    ///
    /// 4-byte value specifying the major version of the target OS. Combined with
    /// [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw::os_minor_version`] to specify exact OS version requirements.
    pub os_major_version: u32,

    /// Minor version number of the target operating system
    ///
    /// 4-byte value specifying the minor version of the target OS. Combined with
    /// [`crate::metadata::tables::assemblyos::raw::AssemblyOsRaw::os_major_version`] to specify exact OS version requirements.
    pub os_minor_version: u32,
}

impl AssemblyOsRaw {
    /// Convert raw `AssemblyOS` data to owned representation
    ///
    /// Since the `AssemblyOS` table contains only primitive values with no heap references,
    /// this method simply clones the data and wraps it in an [`Arc`] for consistency
    /// with the dual variant pattern used across all metadata tables.
    ///
    /// # Returns
    /// * `Ok(`[`crate::metadata::tables::AssemblyOsRc`]`)` - Reference-counted `AssemblyOS` data
    ///
    /// # Errors
    /// This function never returns an error as cloning primitive values cannot fail.
    pub fn to_owned(&self) -> Result<AssemblyOsRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply `AssemblyOS` row data to update related metadata structures
    ///
    /// `AssemblyOS` entries specify operating system targeting information and are self-contained.
    /// Unlike other metadata tables that may have cross-references, `AssemblyOS` entries don't
    /// require updates to other tables during the dual variant resolution phase.
    ///
    /// This method exists to satisfy the metadata processing interface but performs
    /// no actual operations since `AssemblyOS` data is purely descriptive.
    ///
    /// # Returns
    /// Always returns `Ok(())` since `AssemblyOS` entries don't modify other tables
    ///
    /// # Errors
    /// This function never returns an error as no operations are performed.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for AssemblyOsRaw {
    /// Calculate the binary size of one `AssemblyOS` table row
    ///
    /// Computes the total byte size required for one `AssemblyOS` row. Since all fields
    /// are fixed-size 4-byte integers, the row size is always 12 bytes.
    ///
    /// # Arguments
    /// * `_sizes` - Table sizing information (unused for fixed-size table)
    ///
    /// # Returns
    /// Total byte size of one `AssemblyOS` table row (always 12 bytes)
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        4 + // os_platform_id
        4 + // os_major_version
        4   // os_minor_version
    }
}
