//! Assembly table loader implementation
//!
//! Provides the [`crate::metadata::loader::tables::AssemblyLoader`] implementation for loading assembly metadata from the
//! ECMA-335 Assembly table (0x20). This loader is responsible for processing the assembly's
//! core identity information including version, culture, and public key data.
//!
//! # Table Structure
//!
//! The Assembly table contains exactly one row (if present) that defines the current assembly:
//! - **`HashAlgId`**: Hash algorithm used for file integrity
//! - **`MajorVersion`**, **`MinorVersion`**, **`BuildNumber`**, **`RevisionNumber`**: Version components
//! - **Flags**: Assembly attributes and loading hints
//! - **`PublicKey`**: Strong name public key (blob heap reference)
//! - **Name**: Assembly simple name (string heap reference)
//! - **Culture**: Localization culture (string heap reference)
//!
//! # Reference
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table specification

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyRaw, TableId},
    },
    Result,
};

/// Loader for the Assembly metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the Assembly table (0x20)
/// which contains the current assembly's identity and version information. The Assembly table
/// can contain at most one row, representing the assembly being loaded.
pub struct AssemblyLoader;

impl MetadataLoader for AssemblyLoader {
    /// Load assembly metadata from the Assembly table
    ///
    /// Processes the single Assembly table row (if present) and stores the assembly information
    /// in the loader context. The Assembly table is optional but typically present in most
    /// .NET assemblies to define the assembly identity.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables and heaps
    ///
    /// # Returns
    /// * `Ok(())` - Assembly successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or duplicate assembly information
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<AssemblyRaw>() else {
            return Ok(());
        };
        let Some(row) = table.get(1)? else {
            return Ok(());
        };

        let token_msg = || format!("assembly 0x{:08x}", row.token.value());

        let Some(owned) = context.handle_result(
            row.to_owned(strings, blob),
            DiagnosticCategory::Table,
            token_msg,
        )?
        else {
            return Ok(());
        };

        context.handle_error(
            context
                .assembly
                .set(owned)
                .map_err(|_| malformed_error!("Assembly has already been set")),
            DiagnosticCategory::Table,
            token_msg,
        )
    }

    /// Returns the table identifier for the Assembly table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::Assembly`] (0x20)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Assembly)
    }

    /// Returns the list of table dependencies
    ///
    /// The Assembly table has no dependencies on other metadata tables, as it contains
    /// only direct references to heap data (strings and blobs).
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
