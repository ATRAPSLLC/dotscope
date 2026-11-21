//! `AssemblyRef` table loader implementation.
//!
//! This module provides the loader implementation for the `AssemblyRef` metadata table,
//! which contains references to external assemblies. The
//! [`crate::metadata::loader::tables::AssemblyRefLoader`] handles the
//! conversion from raw `AssemblyRef` table data to fully resolved instances with
//! heap-resolved string and blob references.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data during
//! the dual variant resolution phase. `AssemblyRef` entries require heap resolution
//! for string and blob references.
//!
//! # Key Components
//!
//! - [`crate::metadata::loader::tables::AssemblyRefLoader`] - Main loader implementation
//! - [`crate::metadata::tables::AssemblyRefRaw`] - Raw table row structure
//! - [`crate::metadata::tables::AssemblyRef`] - Resolved table entry
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # `AssemblyRef` Table Loading
//!
//! The `AssemblyRef` table (0x23) contains references to external assemblies that the current
//! assembly depends on. During loading, the following data is resolved:
//! - **Assembly name**: String heap index → UTF-8 string
//! - **Culture**: String heap index → Culture identifier string  
//! - **Public key token**: Blob heap index → Cryptographic token bytes
//! - **Hash value**: Blob heap index → Assembly hash bytes (optional)
//! - **Version information**: Major, minor, build, revision numbers
//! - **Assembly flags**: Platform targeting and processing flags
//!
//! # Dependencies
//!
//! The `AssemblyRef` loader has no table dependencies and can be loaded early in the
//! metadata loading pipeline. It only requires:
//! - **String heap**: For assembly names and culture identifiers
//! - **Blob heap**: For public key tokens and hash values
//! - **Tables header**: For raw `AssemblyRef` table access
//!
//! # Error Handling
//!
//! This module defines the following error categories:
//! - **Invalid heap indexes**: String or blob references outside heap bounds
//! - **Malformed metadata**: Corrupted `AssemblyRef` table structure
//! - **Memory allocation**: Insufficient memory during resolution
//! - **Concurrent access**: Parallel processing synchronization issues
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`crate::metadata::tables`] - Table structure definitions
//! - [`crate::metadata::streams`] - String and blob heap access
//!
//! # References
//!
//! - [ECMA-335 II.22.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyRef` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyRefRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Metadata loader for the `AssemblyRef` table (0x23)
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to handle loading and resolution
/// of `AssemblyRef` metadata table entries. This loader processes external assembly references,
/// resolving string and blob heap indexes to create fully populated
/// [`crate::metadata::tables::AssemblyRef`] instances.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing large `AssemblyRef` tables.
pub struct AssemblyRefLoader;

impl MetadataLoader for AssemblyRefLoader {
    /// Load and resolve all `AssemblyRef` table entries
    ///
    /// Processes the `AssemblyRef` metadata table by iterating through all raw entries,
    /// resolving heap references, and storing the resulting [`crate::metadata::tables::AssemblyRef`]
    /// instances in the loader context for subsequent access.
    ///
    /// # Arguments
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing heaps, tables, and storage collections
    ///
    /// # Returns
    /// * `Ok(())` - All `AssemblyRef` entries successfully loaded and resolved
    /// * `Err(`[`crate::Error`]`)` - Loading failed due to malformed data or resource constraints
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - String heap indexes are invalid (outside heap bounds)
    /// - Blob heap indexes are invalid (outside heap bounds)  
    /// - `AssemblyRef` table structure is malformed
    /// - Memory allocation fails during resolution
    /// - Parallel processing encounters synchronization issues
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Concurrent access to the context storage is handled through thread-safe collections.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blob), Some(strings)) =
            (context.meta, context.blobs, context.strings)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<AssemblyRefRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("assembly ref 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(strings, blob),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.assembly_ref.insert(row.token, res.clone());
                Ok(())
            })
    }

    /// Get the metadata table identifier for `AssemblyRef`
    ///
    /// Returns the table ID that this loader is responsible for processing.
    /// `AssemblyRef` uses table ID 0x23 as defined in ECMA-335.
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::AssemblyRef`] (0x23)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::AssemblyRef)
    }

    /// Get the list of metadata tables that must be loaded before `AssemblyRef`
    ///
    /// `AssemblyRef` entries are self-contained references to external assemblies
    /// and do not depend on other metadata tables for resolution. They only
    /// require heap access (strings and blobs) which is guaranteed to be
    /// available during the loading phase.
    ///
    /// # Returns
    /// Empty slice `&[]` - `AssemblyRef` has no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
