//! `ImplMap` table loader implementation.
//!
//! This module provides the [`ImplMapLoader`] responsible for loading and processing
//! `ImplMap` metadata table entries. The `ImplMap` table defines Platform Invoke (P/Invoke)
//! mappings that enable managed code to call unmanaged functions in native libraries.
//!
//! # Purpose
//! The `ImplMap` table is used for native interoperability scenarios:
//! - **P/Invoke declarations**: Mapping managed methods to native functions
//! - **Native library integration**: Calling functions in unmanaged DLLs
//! - **System API access**: Accessing operating system APIs from managed code
//! - **Legacy code integration**: Interfacing with existing native libraries
//! - **Performance optimization**: Direct native calls for critical operations
//!
//! # P/Invoke Context
//! `ImplMap` entries enable native interoperability:
//! - **Function mapping**: Associates managed methods with native functions
//! - **Library specification**: Identifies target native libraries
//! - **Calling conventions**: Specifies parameter passing and stack management
//! - **Character encoding**: Handles string marshalling between managed and native code
//! - **Error handling**: Manages exceptions and error codes across boundaries
//!
//! # Table Dependencies
//! - **`MethodDef`**: Required for resolving managed method declarations
//! - **`ModuleRef`**: Required for resolving target native library references
//! - **`Module`**: Required for module context resolution
//! - **`MemberRef`**: Required for member reference resolution
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.22 for the `ImplMap` table specification.
use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{ImplMapRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `ImplMap` metadata table.
///
/// This loader processes P/Invoke mapping metadata, enabling managed code to call
/// native functions in unmanaged libraries. It resolves method and library references,
/// converts raw table entries to owned structures, and registers import mappings.
pub(crate) struct ImplMapLoader;

impl MetadataLoader for ImplMapLoader {
    /// Loads `ImplMap` table entries and processes P/Invoke mappings.
    ///
    /// This method iterates through all `ImplMap` table entries, resolving member references,
    /// string references for import names, and module references for target libraries.
    /// Each entry is converted to an owned structure and applied to establish P/Invoke mappings.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables, strings, and references
    ///
    /// # Returns
    /// * `Ok(())` - If all `ImplMap` entries were processed successfully
    /// * `Err(_)` - If reference resolution or mapping application fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<ImplMapRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("impl map 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        strings,
                        context.module_ref,
                    ),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Method, token_msg)?;
                context.handle_error(
                    context.imports.add_method(
                        owned.import_name.clone(),
                        &owned.token,
                        owned.member_forwarded.clone(),
                        &owned.import_scope,
                    ),
                    DiagnosticCategory::Method,
                    token_msg,
                )?;
                Ok(())
            })
    }

    /// Returns the table identifier for `ImplMap`.
    ///
    /// # Returns
    /// The [`TableId::ImplMap`] identifier for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::ImplMap)
    }

    /// Returns the dependencies required for loading `ImplMap` entries.
    ///
    /// `ImplMap` table loading requires several other tables to resolve references:
    /// - [`TableId::MethodDef`] - For managed method declarations being mapped
    /// - [`TableId::ModuleRef`] - For target native library references  
    /// - [`TableId::Module`] - For module context resolution
    /// - [`TableId::MemberRef`] - For member reference resolution
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `ImplMap` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::Field,
            TableId::MethodDef,
            TableId::ModuleRef,
            TableId::Module,
            TableId::MemberRef,
        ]
    }
}
