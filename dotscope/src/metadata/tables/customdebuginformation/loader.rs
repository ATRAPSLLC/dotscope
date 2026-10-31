//! `CustomDebugInformation` table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::customdebuginformation::loader::CustomDebugInformationLoader`]
//! implementation for loading `CustomDebugInformation` metadata from the Portable PDB `CustomDebugInformation` table (0x37).
//! The loader processes custom debugging information that extends the standard debugging metadata
//! with compiler and language-specific debugging data.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and integrate
//! custom debugging information with previously loaded metadata elements.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::customdebuginformation::loader::CustomDebugInformationLoader`] - Main loader implementation
//! - [`crate::metadata::tables::customdebuginformation::CustomDebugInformationRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # Table Structure
//!
//! The `CustomDebugInformation` table contains zero or more rows with debugging extensions:
//! - **Parent**: Coded index referencing the metadata element with custom debug info
//! - **Kind**: GUID heap reference identifying the custom debug info format
//! - **Value**: Blob heap reference containing the custom debug data
//!
//! # Custom Debug Information Processing
//!
//! Custom debugging information provides extensible debugging metadata for:
//! - **State machine debugging**: Async/await and iterator state tracking
//! - **Dynamic type debugging**: Information for dynamically typed variables
//! - **Edit-and-continue**: Mapping information for debugging sessions
//! - **Embedded sources**: Source code embedding for portable debugging
//! - **Source link**: URL mapping for source server integration
//! - **Language-specific data**: Compiler-specific debugging extensions
//!
//! # Dependencies
//!
//! This loader depends on most other metadata tables being loaded first, as custom
//! debugging information can be applied to various metadata elements.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`crate::metadata::tables`] - Metadata table types for debug info targets
//! - [`crate::metadata::streams::Guid`] - GUID heap for debug info kind identification
//! - [`crate::metadata::streams::Blob`] - Blob heap for debug data
//! - [`crate::metadata::tables::customdebuginformation`] - `CustomDebugInformation` table types
//!
//! # Thread Safety
//!
//! The loader is thread-safe and uses parallel iteration for performance when processing
//! multiple `CustomDebugInformation` entries. Updates to storage collections are handled
//! through atomic operations.
//!
//! # References
//!
//! - [Portable PDB v1.1](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#customdebuginformation-table-0x37) - `CustomDebugInformation` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{CustomDebugInformationRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `CustomDebugInformation` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `CustomDebugInformation` table (0x37)
/// which contains custom debugging information that extends the standard Portable PDB debugging metadata
/// with compiler and language-specific debugging data.
///
/// # Debug Information Processing
///
/// The loader handles various custom debugging scenarios:
/// - **State machine debugging**: Async/await and iterator state tracking information
/// - **Dynamic type debugging**: Information for dynamically typed variables and expressions
/// - **Edit-and-continue**: Mapping information for debugging sessions and hot reload
/// - **Embedded sources**: Source code embedding for portable debugging scenarios
/// - **Source link**: URL mapping for source server integration and remote debugging
/// - **Language-specific data**: Compiler-specific debugging extensions and metadata
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing multiple `CustomDebugInformation` entries.
pub struct CustomDebugInformationLoader;

impl MetadataLoader for CustomDebugInformationLoader {
    /// Load `CustomDebugInformation` metadata and integrate with debugging system
    ///
    /// Processes all rows in the `CustomDebugInformation` table, resolving references to target metadata
    /// elements and parsing custom debug data from GUID and blob heaps. Each processed entry is stored
    /// in the loader context for subsequent access by debugging tools and analyzers.
    ///
    /// # Arguments
    ///
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables, heap references, and storage collections
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All `CustomDebugInformation` entries successfully processed and stored
    /// * `Err(`[`crate::Error`]`)` - Processing failed due to malformed data or missing dependencies
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - Target metadata element references are invalid or missing
    /// - GUID heap references are invalid or corrupted
    /// - Blob heap references are invalid or corrupted
    /// - `CustomDebugInformation` table structure is malformed
    /// - Custom debug data parsing fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Updates to storage collections are handled through atomic operations.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let (Some(header), Some(guids), Some(blobs)) = (pdb.meta, pdb.guids, pdb.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<CustomDebugInformationRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("custom debug info 0x{:08x}", row.token.value());

                let Some(custom_debug_info) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(|coded_index| context.get_ref(coded_index), guids, blobs),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target
                    .custom_debug_information
                    .insert(custom_debug_info.token, custom_debug_info);
                Ok(())
            })
    }

    /// Returns the table identifier for `CustomDebugInformation`
    ///
    /// Provides the [`crate::prelude::TableId::CustomDebugInformation`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::CustomDebugInformation)
    }

    /// Returns the table dependencies for `CustomDebugInformation` loading
    ///
    /// Specifies the extensive list of tables that `CustomDebugInformation` loading depends on.
    /// Custom debugging information can be applied to most metadata elements, requiring
    /// that target tables are loaded before debug associations are established.
    /// This dependency ordering prevents resolution failures during the loading process.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::Field,
            TableId::TypeRef,
            TableId::TypeDef,
            TableId::Param,
            TableId::InterfaceImpl,
            TableId::MemberRef,
            TableId::Module,
            TableId::DeclSecurity,
            TableId::Property,
            TableId::Event,
            TableId::StandAloneSig,
            TableId::ModuleRef,
            TableId::TypeSpec,
            TableId::Assembly,
            TableId::AssemblyRef,
            TableId::File,
            TableId::ExportedType,
            TableId::ManifestResource,
            TableId::GenericParam,
            TableId::GenericParamConstraint,
            TableId::MethodSpec,
            TableId::Document,
            TableId::LocalScope,
            TableId::LocalVariable,
            TableId::LocalConstant,
            TableId::ImportScope,
        ]
    }
}
