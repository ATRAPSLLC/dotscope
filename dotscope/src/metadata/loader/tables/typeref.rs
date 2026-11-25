//! `TypeRef` table loader implementation for .NET metadata.
//!
//! This module provides the [`crate::metadata::loader::tables::TypeRefLoader`] for processing `TypeRef` table entries,
//! which represent references to types defined in external assemblies or modules.
//! `TypeRef` entries are essential for type resolution in cross-assembly scenarios.
//!
//! ## Purpose
//! The `TypeRef` table contains references to types that are:
//! - Defined in other assemblies (referenced assemblies)
//! - Defined in other modules within the same assembly
//! - Required for type resolution and linking
//!
//! ## Type System Integration
//! - External type references are registered in the imports system
//! - Types are added to the global type registry for resolution
//! - Cross-assembly type linking is enabled
//!
//! ## ECMA-335 Reference
//! See ECMA-335, Partition II, Section 22.38 for `TypeRef` table specification.

use std::collections::HashSet;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        signatures::{
            parse_field_signature, parse_local_var_signature, parse_method_signature,
            parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
            SignatureMethod, TypeSignature,
        },
        streams::{Blob, TablesHeader},
        tables::{
            FieldRaw, MemberRefRaw, MethodDefRaw, MethodSpecRaw, PropertyRaw, StandAloneSigRaw,
            TypeSpecRaw,
        },
        token::Token,
    },
    prelude::{TableId, TypeRefRaw},
    Result,
};

/// Loader implementation for the `TypeRef` metadata table.
///
/// This loader processes `TypeRef` table entries (table ID 0x01) that represent
/// references to types defined in external assemblies or modules. It handles
/// type name resolution, parent assembly/module linking, and integration with
/// both the imports system and global type registry.
pub struct TypeRefLoader;

impl MetadataLoader for TypeRefLoader {
    /// Loads and processes all `TypeRef` table entries from the metadata.
    ///
    /// ## Arguments
    /// * `context` - Loading context with metadata access and storage facilities
    ///
    /// ## Returns
    /// * `Ok(())` - All `TypeRef` entries processed and registered successfully
    /// * `Err(_)` - Type reference loading or registration failed
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let (Some(header), Some(strings)) = (context.meta, context.strings) else {
            return Ok(());
        };
        let Some(table) = header.table::<TypeRefRaw>() else {
            return Ok(());
        };
        let value_types = context
            .blobs
            .map(|blobs| imported_value_types(header, blobs))
            .unwrap_or_default();

        // Sequential iteration is required here because TypeRef entries can
        // reference other TypeRef entries (for nested external types), and
        // ECMA-335 guarantees parent entries appear before children in the table.
        // Using parallel iteration could process children before parents,
        // causing resolution scope lookups to fail.
        for (index, row) in table.into_iter().enumerate() {
            let Some(row) = context.handle_row(row, index)? else {
                continue;
            };
            let token_msg = || format!("type ref 0x{:08x}", row.token.value());

            let Some(new_entry) = context.handle_result(
                row.to_owned(|coded_index| context.get_ref(coded_index), strings),
                DiagnosticCategory::Type,
                token_msg,
            )?
            else {
                continue;
            };

            if value_types.contains(&new_entry.token) {
                new_entry.mark_value_type();
            }
            context.types.insert(&new_entry);
            context.handle_result(
                context.imports.add_type(&new_entry),
                DiagnosticCategory::Type,
                token_msg,
            )?;
        }

        Ok(())
    }

    /// Returns the table identifier for the `TypeRef` table.
    ///
    /// ## Returns
    /// [`crate::metadata::tables::TableId::TypeRef`] (0x01) - The metadata table identifier for external type references
    fn table_id(&self) -> Option<TableId> {
        Some(TableId::TypeRef)
    }

    /// Returns the dependency list for `TypeRef` table loading.
    ///
    /// The `TypeRef` table depends on tables that can serve as parent scopes
    /// for external type references:
    ///
    /// - **`ModuleRef`**: For types defined in external modules of the same assembly
    /// - **`AssemblyRef`**: For types defined in external referenced assemblies
    ///
    /// These dependencies ensure that parent scope information is available
    /// before processing type references.
    ///
    /// ## Returns
    /// A slice containing the required table dependencies for `TypeRef` loading
    fn dependencies(&self) -> &'static [TableId] {
        &[TableId::ModuleRef, TableId::AssemblyRef]
    }
}

/// Every `TypeRef` that some signature in the image names as a `valuetype`.
///
/// A type imported from another assembly has no definition here to read its
/// kind from, and the element type each signature must use for it is the one
/// place metadata says whether it is a struct. Reading them before the
/// `TypeRef` rows are built fixes the kind when the type is created, before
/// anything can ask for it. A blob that does not parse is skipped: the loader
/// that owns it reports the fault.
fn imported_value_types(header: &TablesHeader, blobs: &Blob) -> HashSet<Token> {
    let mut found = HashSet::new();
    let mut note = |sig: &TypeSignature| {
        sig.for_each_value_type(&mut |token: Token| {
            if token.table() == 0x01 {
                found.insert(token);
            }
        });
    };
    let note_method = |sig: &SignatureMethod, note: &mut dyn FnMut(&TypeSignature)| {
        note(&sig.return_type.base);
        for param in sig.params.iter().chain(&sig.varargs) {
            note(&param.base);
        }
    };

    if let Some(table) = header.table::<FieldRaw>() {
        for row in table.into_iter().flatten() {
            if let Ok(sig) = blobs
                .get(row.signature as usize)
                .and_then(parse_field_signature)
            {
                note(&sig.base);
            }
        }
    }
    if let Some(table) = header.table::<MethodDefRaw>() {
        for row in table.into_iter().flatten() {
            if let Ok(sig) = blobs
                .get(row.signature as usize)
                .and_then(parse_method_signature)
            {
                note_method(&sig, &mut note);
            }
        }
    }
    if let Some(table) = header.table::<MemberRefRaw>() {
        for row in table.into_iter().flatten() {
            let Ok(data) = blobs.get(row.signature as usize) else {
                continue;
            };
            // 0x06 is FIELD in the calling-convention byte; anything else is
            // a method.
            if data.first().is_some_and(|b| b & 0x0F == 0x06) {
                if let Ok(sig) = parse_field_signature(data) {
                    note(&sig.base);
                }
            } else if let Ok(sig) = parse_method_signature(data) {
                note_method(&sig, &mut note);
            }
        }
    }
    if let Some(table) = header.table::<StandAloneSigRaw>() {
        for row in table.into_iter().flatten() {
            let Ok(data) = blobs.get(row.signature as usize) else {
                continue;
            };
            // 0x07 is LOCAL_SIG; the rest are `calli` method signatures.
            if data.first() == Some(&0x07) {
                if let Ok(sig) = parse_local_var_signature(data) {
                    for local in &sig.locals {
                        note(&local.base);
                    }
                }
            } else if let Ok(sig) = parse_method_signature(data) {
                note_method(&sig, &mut note);
            }
        }
    }
    if let Some(table) = header.table::<TypeSpecRaw>() {
        for row in table.into_iter().flatten() {
            if let Ok(sig) = blobs
                .get(row.signature as usize)
                .and_then(parse_type_spec_signature)
            {
                note(&sig.base);
            }
        }
    }
    if let Some(table) = header.table::<MethodSpecRaw>() {
        for row in table.into_iter().flatten() {
            if let Ok(sig) = blobs
                .get(row.instantiation as usize)
                .and_then(parse_method_spec_signature)
            {
                for arg in &sig.generic_args {
                    note(arg);
                }
            }
        }
    }
    if let Some(table) = header.table::<PropertyRaw>() {
        for row in table.into_iter().flatten() {
            if let Ok(sig) = blobs
                .get(row.signature as usize)
                .and_then(parse_property_signature)
            {
                note(&sig.base);
                for param in &sig.params {
                    note(&param.base);
                }
            }
        }
    }

    found
}

#[cfg(test)]
mod tests {
    use crate::{metadata::typesystem::CilFlavor, testkit::helpers::test_assembly_arc};

    #[test]
    fn an_imported_struct_is_a_value_type() {
        let assembly = test_assembly_arc();
        let flavor_of = |name: &str| {
            assembly
                .types()
                .iter()
                .map(|entry| entry.value().clone())
                .find(|ty| ty.token.table() == 0x01 && ty.fullname() == name)
                .map(|ty| ty.flavor().clone())
                .unwrap_or_else(|| panic!("{name} is imported"))
        };

        assert_eq!(flavor_of("System.DateTime"), CilFlavor::ValueType);
        assert_eq!(flavor_of("System.Exception"), CilFlavor::Class);
        assert_eq!(flavor_of("System.Object"), CilFlavor::Object);
    }
}
