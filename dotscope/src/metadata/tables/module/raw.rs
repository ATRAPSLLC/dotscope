//! # Module Raw Implementation
//!
//! This module provides the raw variant of Module table entries with unresolved
//! indexes for initial parsing and memory-efficient storage.

use std::sync::Arc;

use crate::{
    metadata::{
        streams::{Guid, Strings},
        tables::{Module, ModuleRc, TableInfoRef, TableRow},
        token::Token,
    },
    Result,
};

#[derive(Clone, Debug)]
/// Raw representation of a Module table entry with unresolved indexes.
///
/// This structure represents the unprocessed entry from the Module metadata table
/// (ID 0x00), which provides information about the current module including its name,
/// GUID (Mvid), and generation. It contains raw index values that require resolution
/// to actual metadata objects.
///
/// ## Purpose
///
/// The Module table serves as the foundational identity table for .NET assemblies:
/// - Provides module name and unique identifier (Mvid)
/// - Contains generation and Edit and Continue information
/// - Always contains exactly one row per PE file
/// - Serves as an anchor for other metadata references
///
/// ## Raw vs Owned
///
/// This raw variant is used during initial metadata parsing and contains:
/// - Unresolved heap indexes requiring lookup
/// - Minimal memory footprint for storage
/// - Direct representation of file format
///
/// Use [`Module`] for resolved references and runtime access.
///
/// ## ECMA-335 Reference
///
/// Corresponds to ECMA-335 §II.22.30 Module table structure.
pub struct ModuleRaw {
    /// Row identifier within the Module table.
    ///
    /// This is always 1 since the Module table contains exactly one row per PE file.
    /// Combined with table ID 0x00, forms the metadata token 0x00000001.
    pub rid: u32,

    /// Metadata token for this Module entry.
    ///
    /// Always 0x00000001 since this is the unique module entry.
    /// Used for cross-referencing this entry from other metadata structures.
    pub token: Token,

    /// Byte offset of this entry in the original metadata stream.
    ///
    /// Points to the start of this entry's data in the metadata file.
    /// Used for debugging and low-level metadata inspection.
    pub offset: usize,

    /// Generation number for this module.
    ///
    /// A 2-byte value that is reserved and shall always be zero according to
    /// ECMA-335 §II.22.30. Reserved for future versioning schemes.
    pub generation: u32,

    /// Raw index into the string heap containing the module name.
    ///
    /// This unresolved index identifies the module name string in the #Strings heap.
    /// Must be resolved using the string heap to get the actual module name.
    /// Index size depends on string heap size (2 or 4 bytes).
    pub name: u32,

    /// Raw index into the GUID heap containing the module version identifier.
    ///
    /// This unresolved index identifies the Mvid GUID in the #GUID heap.
    /// The Mvid is used to distinguish between different versions of the same module.
    /// Must be resolved using the GUID heap to get the actual GUID.
    /// Index size depends on GUID heap size (2 or 4 bytes).
    pub mvid: u32,

    /// Raw index into the GUID heap for Edit and Continue identifier.
    ///
    /// This reserved field is typically 0 and points to the #GUID heap when present.
    /// Used for Edit and Continue scenarios during development.
    /// Index size depends on GUID heap size (2 or 4 bytes).
    pub encid: u32,

    /// Raw index into the GUID heap for Edit and Continue base identifier.
    ///
    /// This reserved field is typically 0 and points to the #GUID heap when present.
    /// Used for Edit and Continue base version tracking during development.
    /// Index size depends on GUID heap size (2 or 4 bytes).
    pub encbaseid: u32,
}

impl ModuleRaw {
    /// Converts this raw entry to an owned [`Module`] with resolved references.
    ///
    /// This method resolves the raw heap indexes to actual string and GUID data,
    /// creating a fully usable [`Module`] instance for runtime access. The module
    /// serves as the fundamental identity anchor for the entire assembly.
    ///
    /// ## Arguments
    ///
    /// * `strings` - The string heap for resolving the module name
    /// * `guids` - The GUID heap for resolving module and ENC identifiers
    ///
    /// ## Returns
    ///
    /// A reference-counted [`ModuleRc`] containing the resolved module entry.
    ///
    /// ## Errors
    ///
    /// - String heap entry cannot be resolved or is malformed
    /// - GUID heap entries cannot be resolved or are malformed
    /// - Heap indexes are out of bounds
    /// - Data corruption is detected
    pub fn to_owned(&self, strings: &Strings, guids: &Guid) -> Result<ModuleRc> {
        Ok(Arc::new(Module {
            rid: self.rid,
            token: self.token,
            offset: self.offset,
            generation: self.generation,
            name: strings.get_shared(self.name as usize)?,
            mvid: guids.get(self.mvid as usize)?,
            encid: if self.encid == 0 {
                None
            } else {
                Some(guids.get(self.encid as usize)?)
            },
            encbaseid: if self.encbaseid == 0 {
                None
            } else {
                Some(guids.get(self.encbaseid as usize)?)
            },
            imports: Vec::new(),
            custom_attributes: Default::default(),
        }))
    }

    /// Applies a Module entry to update related metadata structures.
    ///
    /// Module entries define the module information for the current assembly and are
    /// self-contained metadata descriptors. They don't require cross-table updates during
    /// the dual variant resolution phase as they serve as identity anchors rather than
    /// references to other tables.
    ///
    /// This method is provided for consistency with the metadata loading architecture
    /// but performs no operations since modules are identity tables.
    ///
    /// ## Returns
    ///
    /// Always returns `Ok(())` as Module entries don't modify other tables.
    ///
    /// # Errors
    ///
    /// This function does not return an error.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for ModuleRaw {
    /// Calculate the row size for `Module` table entries
    ///
    /// Returns the total byte size of a single `Module` table row based on the
    /// table configuration. The size varies depending on the size of heap indexes in the metadata.
    ///
    /// # Size Breakdown
    /// - `generation`: 2 bytes (reserved field, always zero)
    /// - `name`: 2 or 4 bytes (string heap index for module name)
    /// - `mvid`: 2 or 4 bytes (GUID heap index for module version identifier)
    /// - `encid`: 2 or 4 bytes (GUID heap index for edit-and-continue identifier)
    /// - `encbaseid`: 2 or 4 bytes (GUID heap index for edit-and-continue base identifier)
    ///
    /// Total: 10-18 bytes depending on heap size configuration
    #[rustfmt::skip]
    fn row_size(sizes: &TableInfoRef) -> u32 {
        u32::from(
            /* generation */ 2u8
            /* name */       .saturating_add(sizes.str_bytes())
            /* mvid */       .saturating_add(sizes.guid_bytes())
            /* encid */      .saturating_add(sizes.guid_bytes())
            /* encbaseid */  .saturating_add(sizes.guid_bytes())

        )
    }
}
