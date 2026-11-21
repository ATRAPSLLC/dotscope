//! `ClassLayout` table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::ClassLayoutLoader`]
//! implementation for loading `ClassLayout` metadata from the ECMA-335 `ClassLayout` table (0x0F).
//! The loader processes explicit memory layout information for value types and classes that
//! require specific field positioning and packing, integrating this data with existing type definitions.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and integrate
//! memory layout information with previously loaded [`crate::metadata::tables::TypeDefRaw`] entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::loader::tables::ClassLayoutLoader`] - Main loader implementation
//! - [`crate::metadata::tables::ClassLayoutRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # Table Structure
//!
//! The `ClassLayout` table contains zero or more rows that specify explicit layout for types:
//! - **`PackingSize`**: Byte boundary alignment for fields (1, 2, 4, 8, 16, etc.)
//! - **`ClassSize`**: Total size of the type in bytes (0 for auto-sizing)
//! - **Parent**: Reference to the `TypeDef` table entry for the type
//!
//! # Memory Layout Control
//!
//! `ClassLayout` entries provide precise control over memory representation for types that need:
//! - **Native Interoperability**: Types that must match C/C++ struct layouts
//! - **Performance Optimization**: Explicit packing to reduce memory overhead
//! - **Binary Compatibility**: Fixed layouts for serialization or persistence
//! - **Hardware Interfaces**: Types that map to hardware registers or protocols
//!
//! # Dependencies
//!
//! This loader depends on the `TypeDef` table being loaded first, as it needs to update
//! existing type definition entries with memory layout information.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`TypeDefRaw`](crate::metadata::tables::TypeDefRaw) / [`CilType`](crate::metadata::typesystem::CilType) - Type definition table entries
//! - [`ClassLayout`](crate::metadata::tables::ClassLayout) / [`ClassLayoutRaw`] - `ClassLayout` table types
//!
//! # References
//!
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `ClassLayout` table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::ClassLayoutRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `ClassLayout` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `ClassLayout` table (0x0F)
/// which contains explicit memory layout information for types that require specific field
/// positioning and packing. This table is used primarily for value types and classes that
/// interoperate with native code or have specific memory layout requirements.
///
/// # Layout Types
///
/// `ClassLayout` entries support various memory layout strategies:
/// - **Sequential**: Fields laid out in declaration order with automatic padding
/// - **Explicit**: Each field has an explicitly specified offset
/// - **Auto**: Runtime determines optimal layout (no `ClassLayout` entry needed)
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing multiple `ClassLayout` entries.
pub struct ClassLayoutLoader;

impl MetadataLoader for ClassLayoutLoader {
    /// Load `ClassLayout` metadata and integrate with type definitions
    ///
    /// Processes all rows in the `ClassLayout` table, resolving references to the
    /// `TypeDef` table and updating existing type definitions with explicit
    /// memory layout information. Each processed entry is stored in the
    /// loader context for subsequent access.
    ///
    /// # Arguments
    ///
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables and storage collections
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All `ClassLayout` entries successfully processed and integrated
    /// * `Err(`[`crate::Error`]`)` - Processing failed due to malformed data or missing dependencies
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - `TypeDef` table references are invalid or missing
    /// - `ClassLayout` table structure is malformed
    /// - Integration with existing type definitions fails
    /// - Invalid packing size or class size values
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Updates to type definitions are handled through atomic operations.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<ClassLayoutRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("class layout 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(context.types),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Type, token_msg)?;
                context.class_layout.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for `ClassLayout`
    ///
    /// Provides the [`crate::prelude::TableId::ClassLayout`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ClassLayout)
    }

    /// Returns the table dependencies for `ClassLayout` loading
    ///
    /// Specifies that `ClassLayout` loading depends on the `TypeDef` table,
    /// ensuring that type definitions are loaded before layout information
    /// is integrated. This dependency ordering prevents resolution failures
    /// during the loading process.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef]
    }
}
