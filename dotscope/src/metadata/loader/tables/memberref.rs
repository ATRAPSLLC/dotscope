//! `MemberRef` table loader implementation.
//!
//! This module provides the [`MemberRefLoader`] responsible for loading and processing
//! `MemberRef` metadata table entries. The `MemberRef` table defines references to members
//! (fields and methods) defined in external assemblies or modules, enabling cross-assembly
//! member access and late binding in .NET applications.
//!
//! # Purpose
//! The `MemberRef` table is crucial for external member access and interoperability:
//! - **Cross-assembly references**: Access to fields and methods in external assemblies
//! - **Late binding**: Dynamic member resolution and invocation at runtime
//! - **Interop scenarios**: P/Invoke and COM interoperability member references
//! - **Type system integration**: Bridging between different type definition sources
//! - **Metadata resolution**: Converting member references to concrete implementations
//!
//! # Member Reference Types
//! `MemberRef` entries can reference different kinds of members:
//! - **Field references**: External field access with type information
//! - **Method references**: External method calls with parameter and return types
//! - **Constructor references**: Object creation with parameter specifications
//! - **Generic member references**: Generic methods and fields with type parameters
//!
//! # Table Dependencies
//! - **`ModuleRef`**: Required for resolving module-scoped member references
//! - **`TypeDef`**: Required for resolving local type member references
//! - **`TypeRef`**: Required for resolving external type member references
//! - **`TypeSpec`**: Required for resolving generic type instantiation member references
//! - **`MethodDef`**: Required for resolving vararg method overload references
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.25 for the `MemberRef` table specification.
//!
//! [`MemberRefLoader`]: crate::metadata::loader::tables::MemberRefLoader

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::MemberRefRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `MemberRef` metadata table.
///
/// This loader processes member reference metadata, resolving external member references
/// and establishing type-safe access to fields and methods across assembly boundaries.
/// It handles signature parsing, parent type resolution, and member name resolution.
pub struct MemberRefLoader;

impl MetadataLoader for MemberRefLoader {
    /// Loads `MemberRef` table entries and establishes external member reference resolution.
    ///
    /// This method iterates through all `MemberRef` table entries, resolving parent class
    /// references and parsing member signatures to create typed member reference objects.
    /// Each entry is converted to an owned structure for efficient member access operations.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables, strings, and blob heap
    ///
    /// # Returns
    /// * `Ok(())` - If all `MemberRef` entries were processed successfully
    /// * `Err(_)` - If parent resolution, signature parsing, or name resolution fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings), Some(blob)) =
            (context.meta, context.strings, context.blobs)
        else {
            return Ok(());
        };
        let Some(table) = header.table::<MemberRefRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("member ref 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(strings, blob, context.types, |coded_index| {
                        context.get_ref(coded_index)
                    }),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.member_ref.insert(row.token, res.clone());
                Ok(())
            })
    }

    /// Returns the table identifier for `MemberRef`.
    ///
    /// # Returns
    /// The [`TableId::MemberRef`] identifier for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::MemberRef)
    }

    /// Returns the dependencies required for loading `MemberRef` entries.
    ///
    /// `MemberRef` table loading requires other tables to resolve parent class references:
    /// - [`TableId::ModuleRef`] - For module-scoped member references
    /// - [`TableId::TypeDef`] - For local type member references  
    /// - [`TableId::TypeRef`] - For external type member references
    /// - [`TableId::TypeSpec`] - For generic type instantiation member references
    /// - [`TableId::MethodDef`] - For vararg method overload references
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `MemberRef` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::ModuleRef,
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::MethodDef,
        ]
    }
}
