//! `AssemblyProcessor` table loader implementation.
//!
//! This module provides the loader implementation for the `AssemblyProcessor` metadata table,
//! which contains processor architecture targeting information for .NET assemblies. The
//! [`crate::metadata::loader::tables::AssemblyProcessorLoader`] processes
//! CPU architecture metadata that specifies target processor architectures.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and store
//! results in the loader context. Since `AssemblyProcessor` contains only primitive values,
//! no heap resolution is required.
//!
//! # Key Components
//!
//! - [`crate::metadata::loader::tables::AssemblyProcessorLoader`] - Main loader implementation
//! - [`crate::metadata::tables::AssemblyProcessorRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for storing loaded metadata
//!
//! # Table Structure
//!
//! The `AssemblyProcessor` table contains processor architecture information:
//! - **Processor**: Processor architecture identifier (4 bytes)
//!
//! # Usage Context
//!
//! Like the `AssemblyOS` table, `AssemblyProcessor` is rarely used in modern .NET assemblies
//! and is considered legacy. Most assemblies are designed to be architecture-neutral
//! (`AnyCPU`) and rely on the runtime to handle architecture-specific optimizations.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`crate::metadata::tables`] - Table structure definitions
//! - [`AssemblyProcessor`](crate::metadata::tables::AssemblyProcessor) / [`AssemblyProcessorRaw`] - `AssemblyProcessor` table types
//!
//! # References
//!
//! - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{AssemblyProcessorRaw, TableId},
    },
    Result,
};

/// Loader for the `AssemblyProcessor` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `AssemblyProcessor` table (0x21)
/// which contains processor architecture information for the current assembly. This table
/// specifies the target CPU architectures that the assembly is designed to support.
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase.
pub struct AssemblyProcessorLoader;

impl MetadataLoader for AssemblyProcessorLoader {
    /// Load processor architecture metadata from the `AssemblyProcessor` table
    ///
    /// Processes `AssemblyProcessor` table rows (if present) and stores the processor
    /// architecture information in the loader context. The `AssemblyProcessor` table is optional
    /// and rarely present in modern .NET assemblies that use `AnyCPU` targeting.
    ///
    /// # Arguments
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables
    ///
    /// # Returns
    /// * `Ok(())` - `AssemblyProcessor` successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data or duplicate `AssemblyProcessor` information
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe as it only reads from the context and performs
    /// atomic operations when setting the assembly processor data.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<AssemblyProcessorRaw>() else {
            return Ok(());
        };
        let Some(row) = table.get(1)? else {
            return Ok(());
        };

        let token_msg = || format!("assembly processor 0x{:08x}", row.token.value());

        let Some(owned) =
            context.handle_result(row.to_owned(), DiagnosticCategory::Table, token_msg)?
        else {
            return Ok(());
        };

        context.handle_error(
            context
                .assembly_processor
                .set(owned)
                .map_err(|_| malformed_error!("AssemblyProcessor has already been set")),
            DiagnosticCategory::Table,
            token_msg,
        )
    }

    /// Returns the table identifier for the `AssemblyProcessor` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::AssemblyProcessor`] (0x21)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::AssemblyProcessor)
    }

    /// Returns the list of table dependencies
    ///
    /// The `AssemblyProcessor` table has no dependencies on other metadata tables or heaps,
    /// as it contains only processor architecture identification integers.
    ///
    /// # Returns
    /// Empty slice - no table dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[]
    }
}
