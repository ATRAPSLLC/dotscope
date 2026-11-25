//! `InterfaceImpl` table loader implementation.
//!
//! This module provides the [`InterfaceImplLoader`] responsible for loading and processing
//! `InterfaceImpl` metadata table entries. The `InterfaceImpl` table defines interface
//! implementations by types, establishing the inheritance hierarchy for .NET types.
//!
//! # Purpose
//! The `InterfaceImpl` table is essential for type system functionality:
//! - **Interface inheritance**: Recording which types implement which interfaces
//! - **Type hierarchy**: Building complete inheritance chains including interfaces
//! - **Polymorphism support**: Enabling interface-based method dispatch
//! - **Type casting**: Supporting safe casting to implemented interface types
//! - **Reflection**: Providing runtime access to interface implementation information
//!
//! # Type System Integration
//! `InterfaceImpl` entries establish critical type relationships:
//! - **Class-to-interface mapping**: Associates classes with their implemented interfaces
//! - **Interface hierarchy**: Supports interface inheritance chains
//! - **Generic interfaces**: Handles generic interface implementations with type parameters
//! - **Explicit implementations**: Records explicit interface member implementations
//!
//! # Table Dependencies
//! - **`TypeDef`**: Required for resolving implementing class references
//! - **`TypeRef`**: Required for resolving interface references from other assemblies
//! - **`TypeSpec`**: Required for resolving generic interface instantiations
//!
//! # ECMA-335 Reference
//! See ECMA-335, Partition II, §22.23 for the `InterfaceImpl` table specification.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::InterfaceImplRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `InterfaceImpl` metadata table.
///
/// This loader processes interface implementation metadata, establishing the relationships
/// between types and the interfaces they implement. It resolves type references, converts
/// raw table entries to owned structures, and maintains the interface implementation map.
pub struct InterfaceImplLoader;

impl MetadataLoader for InterfaceImplLoader {
    /// Loads `InterfaceImpl` table entries and establishes interface implementation relationships.
    ///
    /// This method iterates through all `InterfaceImpl` table entries, resolving type references
    /// for both implementing classes and implemented interfaces. Each entry is converted to
    /// an owned structure and applied to establish type system relationships.
    ///
    /// # Arguments
    /// * `context` - The loading context containing metadata tables and type system references
    ///
    /// # Returns
    /// * `Ok(())` - If all `InterfaceImpl` entries were processed successfully
    /// * `Err(_)` - If type reference resolution or interface application fails
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<InterfaceImplRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("interface impl 0x{:08x}", row.token.value());

                let Some(res) = context.handle_result(
                    row.to_owned(context.types),
                    DiagnosticCategory::Type,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(res.apply(), DiagnosticCategory::Type, token_msg)?;
                context.interface_impl.insert(row.token, res);
                Ok(())
            })
    }

    /// Returns the table identifier for `InterfaceImpl`.
    ///
    /// # Returns
    /// The [`TableId::InterfaceImpl`] identifier for this table type.
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::InterfaceImpl)
    }

    /// Returns the dependencies required for loading `InterfaceImpl` entries.
    ///
    /// `InterfaceImpl` table loading requires several other tables to resolve type references:
    /// - [`TableId::TypeDef`] - For implementing class definitions in the current assembly
    /// - [`TableId::TypeRef`] - For interface references from other assemblies
    /// - [`TableId::TypeSpec`] - For generic interface instantiations and complex type specifications
    ///
    /// # Returns
    /// Array of table identifiers that must be loaded before `InterfaceImpl` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec]
    }
}
