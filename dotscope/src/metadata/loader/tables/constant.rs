//! Constant table loader implementation.
//!
//! This module provides the [`crate::metadata::loader::tables::ConstantLoader`]
//! implementation for loading Constant metadata from the ECMA-335 Constant table (0x0B).
//! The loader processes compile-time constant values associated with fields, properties,
//! and parameters, integrating this data with existing metadata entries.
//!
//! # Architecture
//!
//! The loader follows the standard metadata loading pattern, implementing the
//! [`crate::metadata::loader::MetadataLoader`] trait to process table data and integrate
//! constant values with previously loaded field, property, and parameter entries.
//!
//! # Key Components
//!
//! - [`crate::metadata::loader::tables::ConstantLoader`] - Main loader implementation
//! - [`crate::metadata::tables::ConstantRaw`] - Raw table row structure
//! - [`crate::metadata::loader::LoaderContext`] - Context for loading operations
//!
//! # Table Structure
//!
//! The Constant table contains zero or more rows that define constant values:
//! - **Type**: Element type of the constant (`ELEMENT_TYPE_*` values from ECMA-335)
//! - **Parent**: Coded index referencing Field, Property, or Param tables
//! - **Value**: Blob heap reference containing the constant's binary representation
//!
//! # Constant Types
//!
//! Supported constant types include:
//! - **Primitive types**: Boolean, integers, floating-point values
//! - **String literals**: Compile-time string constants
//! - **Null references**: Null values for reference types
//! - **Enumerations**: Named constant values
//!
//! # Dependencies
//!
//! This loader depends on Field, Property, and Param tables being loaded first,
//! as it needs to update existing metadata entries with constant values.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::loader`] - Core metadata loading infrastructure
//! - [`Field`](crate::metadata::tables::Field) / [`FieldRaw`](crate::metadata::tables::FieldRaw) - Field table entries
//! - [`Property`](crate::metadata::tables::Property) / [`PropertyRaw`](crate::metadata::tables::PropertyRaw) - Property table entries
//! - [`Param`](crate::metadata::tables::Param) / [`ParamRaw`](crate::metadata::tables::ParamRaw) - Parameter table entries
//! - [`crate::metadata::streams::Blob`] - Blob heap for constant data
//!
//! # References
//!
//! - [ECMA-335 II.22.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Constant table specification

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::ConstantRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the Constant metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the Constant table (0x0B)
/// which contains compile-time constant values for fields, properties, and parameters.
/// These constants represent literal values embedded in the metadata at compile time.
///
/// # Constant Value Processing
///
/// The loader handles various constant formats:
/// - **Primitive constants**: Direct binary encoding of numeric and boolean values
/// - **String constants**: UTF-16 encoded string literals in the blob heap
/// - **Null constants**: Special encoding for null reference values
/// - **Default values**: Compile-time default values for optional parameters
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no mutable state and all operations
/// are read-only during the metadata loading phase. The loader uses parallel iteration
/// for performance when processing multiple Constant entries.
pub struct ConstantLoader;

impl MetadataLoader for ConstantLoader {
    /// Load Constant metadata and associate with parent elements
    ///
    /// Processes all rows in the Constant table, resolving references to the Field,
    /// Property, and Param tables, as well as blob heap data containing the constant values.
    /// Each processed constant is applied to its parent element and stored in the
    /// loader context for subsequent access.
    ///
    /// # Arguments
    ///
    /// * `context` - [`crate::metadata::loader::LoaderContext`] containing metadata tables, heap references, and storage collections
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All Constant entries successfully processed and applied
    /// * `Err(`[`crate::Error`]`)` - Processing failed due to malformed data or missing dependencies
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - Parent table references are invalid or missing
    /// - Blob heap references are invalid or corrupted
    /// - Constant table structure is malformed
    /// - Constant value parsing fails
    /// - Integration with parent elements fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel iteration for performance.
    /// Updates to parent elements are handled through atomic operations.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blob)) = (context.meta, context.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<ConstantRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("constant 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), blob),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Table, token_msg)?;
                context.constant.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for Constant
    ///
    /// Provides the [`crate::prelude::TableId::Constant`] constant used to identify this table
    /// type within the metadata loading framework.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::Constant)
    }

    /// Returns the table dependencies for Constant loading
    ///
    /// Specifies that Constant loading depends on the Field, Param, and Property tables,
    /// ensuring that parent metadata elements are loaded before constant associations
    /// are established. This dependency ordering prevents resolution failures
    /// during the loading process.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Field, TableId::Param, TableId::Property]
    }
}
