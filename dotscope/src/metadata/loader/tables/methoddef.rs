//! `MethodDef` table loader implementation for .NET metadata processing.
//!
//! This module provides the [`crate::metadata::loader::tables::MethodDefLoader`] responsible for loading and processing
//! `MethodDef` metadata table entries. The `MethodDef` table defines method implementations
//! within types, including method signatures, implementation details, and parameter
//! information essential for method invocation and reflection in .NET applications.
//!
//! # Architecture
//!
//! The loader implements a comprehensive method processing pipeline:
//! - **Parallel Processing**: Uses rayon for concurrent method definition loading
//! - **Parameter Resolution**: Resolves method parameters through Param and ParamPtr tables
//! - **Signature Parsing**: Parses method signatures from blob heap for type information
//! - **Name Resolution**: Resolves method names and parameter names from strings heap
//! - **Ownership Management**: Converts raw entries to owned structures for runtime use
//!
//! # Purpose
//!
//! The `MethodDef` table is fundamental to type system implementation and method execution:
//! - **Method Implementation**: Concrete method definitions with IL code or native implementations
//! - **Signature Information**: Method parameters, return types, and calling conventions
//! - **Access Control**: Method visibility and security attributes
//! - **Virtual Dispatch**: Method overriding and interface implementation support
//! - **Reflection Support**: Runtime method discovery and dynamic invocation
//! - **P/Invoke Integration**: Platform invocation service for external library calls
//!
//! # Method Implementation Types
//!
//! `MethodDef` entries support different implementation patterns:
//! - **IL Methods**: Managed code with Common Intermediate Language implementation
//! - **Native Methods**: Platform-specific native code implementations
//! - **Abstract Methods**: Interface or abstract class method declarations
//! - **P/Invoke Methods**: Platform invocation service for external library calls
//! - **Runtime Methods**: Special methods implemented by the runtime system
//! - **Constructor Methods**: Instance and static constructor implementations
//! - **Property Accessors**: Getter, setter, and other property-related methods
//! - **Event Handlers**: Add, remove, and fire methods for event implementations
//!
//! # Loading Pipeline
//!
//! 1. **Dependency Validation**: Ensure Param and ParamPtr tables are loaded
//! 2. **Parallel Processing**: Process MethodDef entries concurrently using rayon
//! 3. **Parameter Resolution**: Resolve parameter information for each method
//! 4. **Signature Parsing**: Parse method signatures from blob heap
//! 5. **Name Resolution**: Resolve method and parameter names from strings heap
//! 6. **Storage**: Store completed method definitions in concurrent map
//!
//! # Table Dependencies
//!
//! - **Param**: Required for resolving method parameter metadata and names
//! - **ParamPtr**: Required for parameter pointer indirection (if present)
//!
//! # Thread Safety
//!
//! All components in this module are designed for safe concurrent access:
//! - [`crate::metadata::loader::tables::MethodDefLoader`] is [`std::marker::Send`] and [`std::marker::Sync`]
//! - Loading operations use parallel processing via rayon for optimal performance
//! - Method definition storage uses thread-safe concurrent data structures
//! - Parameter resolution is coordinated safely across multiple threads
//!
//! # Integration
//!
//! This module integrates with:
//! - [`MethodDefRaw`] - Raw MethodDef table representation
//! - [`Param`](crate::metadata::tables::Param) / [`ParamRaw`](crate::metadata::tables::ParamRaw) - Parameter table for method parameters
//! - [`crate::metadata::method`] - Method definition types and containers
//! - [`crate::metadata::loader`] - Metadata loading infrastructure and coordination
//!
//! # ECMA-335 Reference
//!
//! - [ECMA-335 Standard](https://www.ecma-international.org/publications-and-standards/standards/ecma-335/)
//! - Partition II, §22.26 for the `MethodDef` table specification
//! - Table ID: 0x06
//! - Purpose: Define method implementations within types

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{MemberList, MethodDefRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `MethodDef` metadata table.
///
/// This loader processes method definition metadata, establishing complete method
/// implementations with parameter information and signature details. It handles
/// parameter resolution, signature parsing, and creates comprehensive method
/// definition objects for type system integration.
///
/// # Loading Strategy
///
/// The loader implements a sophisticated processing strategy:
/// - **Concurrent Processing**: Uses parallel iteration for optimal performance
/// - **Dependency Management**: Ensures Param and ParamPtr tables are available
/// - **Memory Efficiency**: Converts raw entries to owned structures only when needed
/// - **Error Handling**: Provides detailed error information for troubleshooting
///
/// # Thread Safety
///
/// [`MethodDefLoader`] is [`std::marker::Send`] and [`std::marker::Sync`], enabling safe concurrent use.
/// All operations are thread-safe and can be called from multiple threads simultaneously.
pub struct MethodDefLoader;

impl MetadataLoader for MethodDefLoader {
    /// Loads `MethodDef` table entries and establishes complete method implementations.
    ///
    /// This method iterates through all `MethodDef` table entries, resolving parameter
    /// information and parsing method signatures to create comprehensive method
    /// definition objects. Each entry is converted to an owned structure with complete
    /// parameter metadata for method invocation and reflection operations.
    ///
    /// # Processing Steps
    ///
    /// 1. **Validation**: Verify required metadata streams are available
    /// 2. **Table Access**: Get MethodDef table from metadata header
    /// 3. **Parallel Iteration**: Process entries concurrently using rayon
    /// 4. **Parameter Resolution**: Resolve parameter information for each method
    /// 5. **Signature Processing**: Parse method signatures from blob heap
    /// 6. **Storage**: Insert completed method definitions into context map
    ///
    /// # Arguments
    ///
    /// * `context` - The loading context containing metadata tables, strings, and blob heap
    ///
    /// # Returns
    ///
    /// * `Ok(())` - If all `MethodDef` entries were processed successfully
    /// * `Err(_)` - If parameter resolution, signature parsing, or name resolution fails
    ///
    /// # Errors
    ///
    /// This method can fail due to:
    /// - **Missing Dependencies**: Required Param or ParamPtr tables not loaded
    /// - **Invalid Signatures**: Malformed method signatures in blob heap
    /// - **Name Resolution**: Failed to resolve method or parameter names
    /// - **Memory Allocation**: Insufficient memory for method definition objects
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and uses parallel processing internally for optimal performance.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings), Some(blobs)) =
            (context.meta, context.strings, context.blobs)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<MethodDefRaw>() else {
            return Ok(());
        };
        let param_ranges = context.member_ranges(header, MemberList::MethodDefParams);

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("method 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(
                        strings,
                        blobs,
                        &context.param,
                        &context.param_ptr,
                        &param_ranges,
                    ),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.method_def.insert(row.token, owned.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for `MethodDef`.
    ///
    /// # Returns
    ///
    /// The [`crate::metadata::tables::TableId::MethodDef`] identifier (0x06) for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::MethodDef)
    }

    /// Returns the dependencies required for loading `MethodDef` entries.
    ///
    /// `MethodDef` table loading requires other tables to resolve parameter information:
    /// - [`crate::metadata::tables::TableId::Param`] - For method parameter metadata, names, and attributes
    /// - [`crate::metadata::tables::TableId::ParamPtr`] - For parameter pointer indirection (if present in assembly)
    ///
    /// # Dependency Rationale
    ///
    /// **Param Table**: Essential for resolving method parameter information including:
    /// - Parameter names from strings heap
    /// - Parameter attributes and flags
    /// - Parameter ordering and sequence information
    /// - Default parameter values and marshalling information
    ///
    /// **ParamPtr Table**: Required when assemblies use parameter pointer indirection:
    /// - Provides level of indirection for parameter access
    /// - Used in optimized metadata layouts
    /// - May be empty in many assemblies but must be checked
    ///
    /// # Returns
    ///
    /// Static array of [`crate::metadata::tables::TableId`] values that must be loaded before `MethodDef` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::Param, TableId::ParamPtr]
    }
}
