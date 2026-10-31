//! `DeclSecurity` table loader implementation.
//!
//! This module provides the [`crate::metadata::tables::declsecurity::loader::DeclSecurityLoader`]
//! implementation for loading declarative security metadata from the ECMA-335 `DeclSecurity` table (0x0E).
//! The loader processes security declarations that control code access security (CAS) permissions
//! at the assembly, type, and method levels, integrating this data with existing metadata entries.
//!
//! # Table Structure
//!
//! The `DeclSecurity` table contains security declarations with these fields:
//! - **Action**: Security action type (Demand, Assert, Deny, `InheritanceDemand`, etc.)
//! - **Parent**: Target element where security is applied (`HasDeclSecurity` coded index)
//! - **`PermissionSet`**: Serialized permission set data (blob heap reference)
//!
//! Each row represents a single security declaration that can specify required permissions,
//! permission assertions, denials, or inheritance demands for specific metadata elements.
//!
//! # Security Actions
//!
//! Common security actions include:
//! - **Demand**: Require callers to have specific permissions
//! - **Assert**: Temporarily escalate permissions for trusted code
//! - **Deny**: Prevent code from using certain permissions
//! - **`LinkDemand`**: Check permissions at JIT compile time
//! - **`InheritanceDemand`**: Require permissions for inheritance
//!
//! # Reference
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `DeclSecurity` table specification
//! - [ECMA-335 II.23.1.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `SecurityAction` enumeration

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::DeclSecurityRaw,
    },
    prelude::TableId,
    utils::TryForEachInOrder,
    Result,
};

/// Loader for the `DeclSecurity` metadata table
///
/// Implements [`crate::metadata::loader::MetadataLoader`] to process the `DeclSecurity` table (0x0E)
/// which contains declarative security declarations for assemblies, types, and methods. The loader
/// parses permission sets and applies them to their target metadata elements.
///
/// The `DeclSecurity` table depends on:
/// - **`TypeDef`**: For type-level security declarations
/// - **`MethodDef`**: For method-level security declarations  
/// - **Assembly**: For assembly-level security declarations
/// - **Blob Heap**: For permission set data resolution
///
/// # Errors
///
/// - `DeclSecurity` table row data is malformed or corrupted
/// - Coded index resolution fails for invalid parent references
/// - Permission set blob parsing encounters invalid or malformed data
/// - Security declaration application fails due to incompatible target types
/// - Thread synchronization issues occur during parallel processing
///
pub(crate) struct DeclSecurityLoader;

impl MetadataLoader for DeclSecurityLoader {
    /// Load declarative security metadata from the `DeclSecurity` table
    ///
    /// Processes all `DeclSecurity` table rows in parallel and stores resolved security declarations
    /// in the loader context. Each security declaration specifies permissions or constraints that
    /// apply to assemblies, types, or methods according to the .NET Code Access Security model.
    ///
    /// # Arguments
    /// * `context` - Loader context containing metadata tables, heaps, and resolved references
    ///
    /// # Returns
    /// * `Ok(())` - All security declarations successfully loaded or table not present
    /// * `Err(`[`crate::Error`]`)` - Malformed data, invalid references, or processing failures
    ///
    /// # Security Model Integration
    ///
    /// Security declarations are applied to their target elements, enabling:
    /// - Runtime permission checks for method calls
    /// - Assembly-level security policy enforcement  
    /// - Type inheritance security constraints
    /// - JIT-time security validation
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(blob)) = (context.meta, context.blobs) else {
            return Ok(());
        };
        let Some(table) = header.table::<DeclSecurityRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row(row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("decl security 0x{:08x}", row.token.value());

                let Some(owned) = context.handle_result(
                    row.to_owned(|coded_index| context.get_ref(coded_index), blob),
                    DiagnosticCategory::Table,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                context.handle_error(owned.apply(), DiagnosticCategory::Table, token_msg)?;
                context.decl_security.insert(row.token, owned);
                Ok(())
            })
    }

    /// Returns the table identifier for the `DeclSecurity` table
    ///
    /// # Returns
    /// [`crate::metadata::tables::TableId::DeclSecurity`] (0x0E)
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::DeclSecurity)
    }

    /// Returns the list of table dependencies required before loading `DeclSecurity`
    ///
    /// The `DeclSecurity` table depends on target metadata elements that can have security
    /// declarations applied to them. These dependencies ensure that parent references
    /// can be properly resolved during the loading process.
    ///
    /// # Returns
    /// Static slice containing:
    /// - [`TableId::TypeDef`] - For type-level security declarations
    /// - [`TableId::MethodDef`] - For method-level security declarations
    /// - [`TableId::Assembly`] - For assembly-level security declarations
    ///
    /// # Dependency Rationale
    ///
    /// Security declarations use the `HasDeclSecurity` coded index to reference their
    /// target elements. These target tables must be loaded first to ensure valid
    /// parent resolution during `DeclSecurity` processing.
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::TypeDef, TableId::MethodDef, TableId::Assembly]
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        metadata::{
            security::SecurityAction,
            tables::{DeclSecurityRaw, TableId},
        },
        testkit::fixture_bytes,
        CilObject,
    };

    /// Every DeclSecurity row of a type is kept, in table order: Mono's System.Web.Routing
    /// gives its types a link demand and an inheritance demand each, of which a single slot
    /// kept one, whichever thread set it first.
    #[test]
    fn every_declaration_of_a_parent_is_kept_in_table_order() {
        let assembly =
            CilObject::from_mem(fixture_bytes("mono_2.0/System.Web.Routing.dll").to_vec()).unwrap();
        let mut by_type: BTreeMap<u32, Vec<SecurityAction>> = BTreeMap::new();
        for row in assembly
            .tables()
            .unwrap()
            .table::<DeclSecurityRaw>()
            .unwrap()
            .iter()
            .flatten()
        {
            if row.parent.tag == TableId::TypeDef {
                by_type
                    .entry(row.parent.row)
                    .or_default()
                    .push(SecurityAction::from(row.action));
            }
        }
        assert!(by_type.values().any(|actions| actions.len() > 1));

        for (row, expected) in by_type {
            let ty = assembly
                .types()
                .all_types()
                .iter()
                .find(|ty| ty.token.table() == 0x02 && ty.token.row() == row)
                .cloned()
                .unwrap();
            let actions: Vec<_> = ty.security.iter().map(|(_, sec)| sec.action).collect();
            assert_eq!(actions, expected, "{}", ty.name);
        }
    }
}
