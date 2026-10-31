//! # `MethodSemantics` Table Loader
//!
//! This module provides the loader implementation for the [`MethodSemantics`](crate::metadata::tables::MethodSemantics) table,
//! which specifies the relationship between methods and events or properties in .NET metadata.
//! It defines which methods are getters, setters, adders, removers, etc.
//!
//! ## Purpose
//!
//! The [`MethodSemanticsLoader`] processes raw [`MethodSemanticsRaw`] entries during metadata loading,
//! converting them to owned [`MethodSemantics`](crate::metadata::tables::MethodSemantics) instances with resolved references and applying
//! the semantic relationships to the associated properties and events.
//!
//! ## Table Dependencies
//!
//! The `MethodSemantics` table depends on:
//! - [`Event`](crate::metadata::tables::Event) - For event semantic associations
//! - [`EventMap`](crate::metadata::tables::EventMap) - For event mapping resolution
//! - [`Property`](crate::metadata::tables::Property) - For property semantic associations  
//! - [`PropertyMap`](crate::metadata::tables::PropertyMap) - For property mapping resolution
//!
//! ## Error Conditions
//!
//! - Method references cannot be resolved
//! - Association coded indexes are malformed
//! - Semantic relationships conflict (e.g., duplicate setters)
//! - Required dependency tables are missing or malformed

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::MethodSemanticsRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader implementation for the `MethodSemantics` metadata table.
///
/// This loader processes [`crate::metadata::tables::MethodSemanticsRaw`] entries, converting them to
/// owned [`crate::metadata::tables::MethodSemantics`] instances with resolved references and applying
/// semantic relationships to properties and events.
pub(crate) struct MethodSemanticsLoader;

impl MetadataLoader for MethodSemanticsLoader {
    /// Loads and processes all `MethodSemantics` table entries.
    ///
    /// ## Arguments
    /// * `context` - The loader context containing metadata tables and storage
    ///
    /// ## Errors
    ///
    /// - Method references cannot be resolved
    /// - Association coded indexes are malformed
    /// - Semantic relationships conflict (e.g., duplicate setters)
    /// - Required dependency tables are missing
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(header) = context.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<MethodSemanticsRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("method semantics 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(
                        |coded_index| context.get_ref(coded_index),
                        context.method_def,
                    ),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Method, token_msg)?;
                context.method_semantics.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for `MethodSemantics`.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::MethodSemantics`] (0x18)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::MethodSemantics)
    }

    /// Returns the table dependencies for `MethodSemantics` loading.
    ///
    /// The `MethodSemantics` table requires these tables to be loaded first for proper
    /// association resolution:
    /// - [`Event`](crate::metadata::tables::TableId::Event) - For event semantic associations
    /// - [`EventMap`](crate::metadata::tables::TableId::EventMap) - For event mapping resolution
    /// - [`Property`](crate::metadata::tables::TableId::Property) - For property semantic associations
    /// - [`PropertyMap`](crate::metadata::tables::TableId::PropertyMap) - For property mapping resolution
    ///
    /// ## Returns
    /// Array of required [`crate::metadata::tables::TableId`] dependencies
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::MethodDef,
            TableId::Event,
            TableId::EventMap,
            TableId::Property,
            TableId::PropertyMap,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            method::MethodAccessFlags,
            tables::{CodedIndex, CodedIndexType, TableDataOwned},
            token::Token,
            validation::ValidationConfig,
        },
        testkit::helpers::load_sample,
        CilObject,
    };

    /// A property or an event may have any number of other methods (ECMA-335 II.22.28): the
    /// second was refused as "already set", which a strict load turns into a failed load.
    #[test]
    fn every_other_method_of_a_property_and_an_event_is_kept() {
        let sample = load_sample("crafted_2.exe");
        let first = |table: TableId| -> (Token, usize) {
            sample
                .types()
                .iter()
                .find_map(|entry| {
                    let cil_type = entry.value();
                    match table {
                        TableId::Property => cil_type
                            .properties
                            .iter()
                            .next()
                            .map(|(_, p)| (p.token, p.fn_other.len())),
                        _ => cil_type
                            .events
                            .iter()
                            .next()
                            .map(|(_, e)| (e.token, e.fn_on_other.len())),
                    }
                })
                .unwrap_or_else(|| panic!("the sample declares a {table:?}"))
        };
        let (property, property_before) = first(TableId::Property);
        let (event, event_before) = first(TableId::Event);
        let mut others: Vec<Token> = sample
            .methods()
            .iter()
            .filter(|entry| entry.value().flags_access == MethodAccessFlags::PUBLIC)
            .map(|entry| *entry.key())
            .take(2)
            .collect();
        others.sort();
        assert_eq!(others.len(), 2);

        let mut assembly = sample.into_assembly();
        for (table, owner) in [(TableId::Property, property), (TableId::Event, event)] {
            for method in &others {
                assembly
                    .table_row_add(
                        TableId::MethodSemantics,
                        TableDataOwned::MethodSemantics(MethodSemanticsRaw {
                            rid: 0,
                            token: Token::new(0),
                            offset: 0,
                            semantics: 0x0004,
                            method: method.row(),
                            association: CodedIndex::new(
                                table,
                                owner.row(),
                                CodedIndexType::HasSemantics,
                            ),
                        }),
                    )
                    .unwrap();
            }
        }
        let reloaded = CilObject::from_mem_with_validation(
            assembly.to_memory().unwrap(),
            ValidationConfig::production(),
        )
        .unwrap();

        let mut property_others = Vec::new();
        let mut event_others = Vec::new();
        for entry in reloaded.types().iter() {
            for (_, p) in entry.value().properties.iter() {
                if p.token == property {
                    property_others.extend(
                        p.fn_other
                            .iter()
                            .filter_map(|(_, m)| m.upgrade())
                            .map(|m| m.token),
                    );
                }
            }
            for (_, e) in entry.value().events.iter() {
                if e.token == event {
                    event_others.extend(
                        e.fn_on_other
                            .iter()
                            .filter_map(|(_, m)| m.upgrade())
                            .map(|m| m.token),
                    );
                }
            }
        }
        for (kept, before) in [
            (&property_others, property_before),
            (&event_others, event_before),
        ] {
            assert_eq!(kept.len(), before + 2, "{kept:?}");
            assert!(
                others.iter().all(|method| kept.contains(method)),
                "{kept:?}"
            );
        }
    }
}
