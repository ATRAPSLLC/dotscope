//! Inheritance chain resolution for .NET metadata.
//!
//! This module provides comprehensive inheritance resolution that runs after TypeDef,
//! TypeRef and TypeSpec have been loaded, ensuring that complex inheritance
//! relationships involving generic type instantiations can be properly resolved.
//!
//! This resolver consolidates all inheritance resolution logic that was previously
//! scattered across individual table loaders, providing a unified and more robust
//! approach to handling circular dependencies.

use crate::{
    metadata::{
        loader::{LoaderContext, MetadataLoader},
        tables::{TableId, TypeDefRaw},
        typesystem::CilTypeReference,
    },
    utils::TryForEachInOrder,
    Error, Result,
};

/// Comprehensive inheritance resolver that runs after all type tables are loaded.
///
/// This resolver handles setting base types for TypeDef entries, consolidating
/// all inheritance resolution logic in one place to properly handle circular
/// dependencies and complex generic type instantiations.
pub struct InheritanceResolver;

impl MetadataLoader for InheritanceResolver {
    /// Resolves inheritance relationships after all type tables are loaded.
    ///
    /// This method processes all TypeDef entries and resolves their inheritance
    /// relationships in a unified manner, handling all types of base type references
    /// including TypeRef, TypeDef, and TypeSpec (generic instantiations) that could
    /// not be resolved during initial loading due to circular dependencies.
    ///
    /// # Arguments
    ///
    /// * `context` - The loader context containing type registries and metadata tables.
    ///
    /// # Returns
    ///
    /// `Ok(())` if all inheritance relationships are resolved successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if a required type reference was dropped during resolution.
    fn load(&self, context: &LoaderContext) -> Result<()> {
        if let Some(header) = context.meta {
            if let Some(typedef_table) = header.table::<TypeDefRaw>() {
                typedef_table
                    .par_iter()
                    .try_for_each_in_order(|raw_typedef| -> Result<()> {
                        let raw_typedef = raw_typedef?;
                        if raw_typedef.extends.row == 0 {
                            return Ok(());
                        }

                        if let Some(type_def) = context.types.get(&raw_typedef.token) {
                            match context.get_ref(&raw_typedef.extends) {
                                CilTypeReference::TypeDef(type_ref)
                                | CilTypeReference::TypeRef(type_ref)
                                | CilTypeReference::TypeSpec(type_ref) => {
                                    let base_type_ref = type_ref.upgrade().ok_or_else(|| {
                                        Error::TypeError(format!(
                                            "InheritanceResolver: Type reference was dropped for type {}",
                                            type_def.fullname()
                                        ))
                                    })?;

                                    // A type that extends itself is malformed, and it is the
                                    // cheapest inheritance cycle for a hostile assembly to
                                    // express. Leave the base unset rather than recording the
                                    // self-edge: every base walk is bounded by
                                    // `CilType::base_chain`, but keeping the trivial cycle out
                                    // of the graph entirely means consumers never observe it.
                                    //
                                    // This deliberately does not fail the load. Analysing
                                    // malformed and obfuscated binaries is the point of this
                                    // library, so the condition is reported by validation
                                    // rather than by refusing the file.
                                    //
                                    // Eliding the edge has a consequence that is easy to miss:
                                    // any validator that looks for inheritance cycles by
                                    // *walking the graph* can no longer see this one, because
                                    // the edge it would follow was never recorded.
                                    // `OwnedCircularityValidator` therefore re-reads the raw
                                    // `extends` column specifically for the self-edge; see
                                    // `validate_self_referential_bases`. Longer cycles
                                    // (`A -> B -> A`) are not elided and are still found by the
                                    // walk. If this elision is ever removed, that check becomes
                                    // redundant rather than wrong.
                                    if base_type_ref.token == type_def.token {
                                        log::warn!(
                                            "InheritanceResolver: type {} extends itself; \
                                             ignoring the self-referential base",
                                            type_def.token
                                        );
                                        return Ok(());
                                    }

                                    // Use the resolved base type directly by its token.
                                    // Do NOT lookup by fullname as that can return the wrong type
                                    // when multiple types share the same name (e.g., nested types
                                    // with the same simple name in different enclosing types).
                                    type_def.set_base(&base_type_ref.into())?;
                                }
                                _ => {} // Other types not supported
                            }

                            // Note: Failed resolution is not an error - some TypeSpec references
                            // may legitimately fail to resolve due to incomplete type information
                        }
                        Ok(())
                    })?;
            }
        }

        Ok(())
    }

    /// Returns the table ID for this loader.
    ///
    /// # Returns
    ///
    /// `None` since this is a special cross-table loader not tied to a specific table.
    fn table_id(&self) -> Option<TableId> {
        None
    }

    /// Returns the tables this loader depends on.
    ///
    /// This resolver must run after all type-related tables are loaded to ensure
    /// all type references can be properly resolved.
    ///
    /// # Returns
    ///
    /// A static slice of `TableId`s that must be loaded before this resolver runs.
    fn dependencies(&self) -> &'static [TableId] {
        &[
            TableId::TypeDef,
            TableId::TypeRef,
            TableId::TypeSpec,
            TableId::InterfaceImpl,
        ]
    }
}
