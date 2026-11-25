//! Raw `AssemblyRefProcessor` table representation.
//!
//! This module provides the [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw`] struct
//! for low-level access to `AssemblyRefProcessor` metadata table data with unresolved table indexes.
//! This represents the binary format of `AssemblyRefProcessor` records as they appear in the metadata
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
//! - [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw`] - Raw table row structure with unresolved indexes
//! - [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw::to_owned`] - Resolution to owned representation
//! - [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw::apply`] - Direct application of processor data
//!
//! # `AssemblyRefProcessor` Table Format
//!
//! The `AssemblyRefProcessor` table (0x24) contains zero or more rows with these fields:
//! - **Processor** (4 bytes): Processor architecture identifier
//! - **`AssemblyRef`** (2/4 bytes): Table index into `AssemblyRef` table
//!
//! # Usage Examples
//!
//! ```no_run
//! # use dotscope::metadata::tables::AssemblyRefProcessorRaw;
//! # use dotscope::metadata::tables::AssemblyRefMap;
//! # fn example(raw: AssemblyRefProcessorRaw, refs: &AssemblyRefMap) -> dotscope::Result<()> {
//! // Convert to owned representation
//! let owned = raw.to_owned(refs)?;
//!
//! // Or apply processor data directly
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
//! - [`crate::metadata::tables::assemblyrefprocessor::owned`] - Owned representation with resolved references
//! - [`crate::metadata::tables::assemblyref`] - Assembly reference table entries
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//!
//! # References
//!
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification

use std::sync::{atomic::Ordering, Arc};

use crate::{
    metadata::{
        tables::{
            AssemblyRefMap, AssemblyRefProcessor, AssemblyRefProcessorRc, TableId, TableInfoRef,
            TableRow,
        },
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyRefProcessor` table row with unresolved table indexes
///
/// Represents the binary format of an `AssemblyRefProcessor` metadata table entry (table ID 0x24) as stored
/// in the metadata tables stream. The `AssemblyRef` field contains a table index that must be
/// resolved using the [`crate::metadata::tables::assemblyref::AssemblyRefMap`] to access the
/// referenced assembly data.
///
/// The `AssemblyRefProcessor` table specifies processor architecture requirements for external
/// assembly references, allowing assemblies to declare explicit processor compatibility dependencies.
/// This table is rarely used in modern .NET assemblies and is considered legacy.
///
/// # Processor Architecture Targeting
///
/// The `AssemblyRefProcessor` entry contains processor identification requirements:
/// - **Processor**: Architecture identifier (x86, x64, ARM, etc.)
/// - **Assembly Reference**: Link to the external assembly requiring these processor constraints
///
/// # Conversion and Usage
///
/// Raw entries should be converted to [`crate::metadata::tables::assemblyrefprocessor::owned::AssemblyRefProcessor`]
/// via [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw::to_owned`] for practical use,
/// or have their processor data applied directly via [`crate::metadata::tables::assemblyrefprocessor::raw::AssemblyRefProcessorRaw::apply`].
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`]. Methods that update assembly references use atomic
/// operations to ensure thread-safe modifications without additional synchronization.
///
/// # References
///
/// - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRefProcessor` table specification
pub struct AssemblyRefProcessorRaw {
    /// Row identifier within the `AssemblyRefProcessor` metadata table
    ///
    /// The 1-based index of this `AssemblyRefProcessor` row within the table.
    pub rid: u32,

    /// Metadata token for this `AssemblyRefProcessor` entry
    ///
    /// Combines the table identifier (0x24 for `AssemblyRefProcessor`) with the row ID to create
    /// a unique token that can be used to reference this entry from other metadata.
    pub token: Token,

    /// Byte offset of this `AssemblyRefProcessor` row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyRefProcessor` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Processor architecture identifier
    ///
    /// Specifies the target processor architecture. Common values include:
    /// - `0x0000`: No specific processor requirement
    /// - `0x014C`: Intel 386 (x86)
    /// - `0x8664`: AMD64 (x64)
    /// - `0x01C0`: ARM (32-bit)
    /// - `0xAA64`: ARM64
    ///
    /// See processor architecture constants in PE specification for standard values.
    pub processor: u32,

    /// Table index into the `AssemblyRef` table
    ///
    /// 1-based index referencing the [`crate::metadata::tables::assemblyref::AssemblyRefRaw`]
    /// entry that represents the external assembly these processor requirements apply to.
    /// Must be resolved using [`AssemblyRefMap`] to access the actual assembly reference.
    pub assembly_ref: u32,
}

impl AssemblyRefProcessorRaw {
    /// Convert raw `AssemblyRefProcessor` data to owned representation with resolved references
    ///
    /// Creates an [`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorRc`] from this raw data
    /// by resolving the `AssemblyRef` table index to the actual assembly reference. The resulting
    /// structure contains all necessary data for representing processor compatibility requirements in
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
    /// * `Ok(`[`crate::metadata::tables::assemblyrefprocessor::AssemblyRefProcessorRc`]`)` - Successfully resolved `AssemblyRefProcessor` data
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
    pub fn to_owned(&self, refs: &AssemblyRefMap) -> Result<AssemblyRefProcessorRc> {
        Ok(Arc::new(AssemblyRefProcessor {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            processor: self.processor,
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

    /// Apply processor architecture information directly to the referenced assembly
    ///
    /// Updates the assembly reference with processor architecture information from this
    /// `AssemblyRefProcessor` entry without creating an owned representation. This is used when
    /// only the processor data needs to be applied without retaining the `AssemblyRefProcessor` structure,
    /// providing a more efficient path for bulk processor data application.
    ///
    /// The method resolves the `AssemblyRef` table index and uses atomic operations to update
    /// the processor compatibility field in the referenced assembly entry, ensuring thread-safe
    /// modifications without requiring external synchronization.
    ///
    /// # Arguments
    ///
    /// * `refs` - Map of loaded [`crate::metadata::tables::assemblyref::AssemblyRef`] entities
    ///   keyed by their metadata tokens
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Processor information successfully applied to assembly reference
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
    /// concurrently on different `AssemblyRefProcessor` entries.
    pub fn apply(&self, refs: &AssemblyRefMap) -> Result<()> {
        match refs.get(&Token::new(self.assembly_ref | 0x2300_0000)) {
            Some(refs) => {
                refs.value()
                    .processor
                    .store(self.processor, Ordering::Relaxed);
                Ok(())
            }
            None => Err(malformed_error!(
                "Failed to resolve assemblyref token - {}",
                self.assembly_ref | 0x2300_0000
            )),
        }
    }
}

impl TableRow for AssemblyRefProcessorRaw {
    /// Calculate the binary size of one `AssemblyRefProcessor` table row
    ///
    /// Computes the byte size required for one `AssemblyRefProcessor` row in the metadata tables stream.
    /// The row size depends on whether the `AssemblyRef` table uses 2-byte or 4-byte indexes.
    ///
    /// # Binary Layout
    /// - `processor` (4 bytes): Processor architecture identifier
    /// - `assembly_ref` (2/4 bytes): Table index into `AssemblyRef` table
    ///
    /// # Arguments
    /// * `sizes` - Table sizing information with heap and table index sizes
    ///
    /// # Returns
    /// Total byte size of one `AssemblyRefProcessor` table row
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* processor */    4u8
            /* assembly_ref */ .saturating_add(sizes.table_index_bytes(TableId::AssemblyRef))

        )
    }
}
