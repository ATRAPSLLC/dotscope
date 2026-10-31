//! Field data writer for FieldRVA handling.
//!
//! This module provides functionality to handle FieldRVA entries when writing assemblies.
//! FieldRVA entries specify RVAs (Relative Virtual Addresses) for fields that have
//! initialization data stored in the PE file.
//!
//! # Purpose
//!
//! When rebuilding a .NET assembly, FieldRVA data must be handled explicitly:
//!
//! - **Original data**: Field initialization data from the source PE may need relocation
//! - **Modified data**: Entries modified via the changes API use placeholder RVAs
//! - **New data**: Newly added field data via `store_field_data()`
//!
//! # RVA Resolution
//!
//! The module builds a mapping from old/placeholder RVAs to new actual RVAs:
//!
//! ```text
//! Original RVA 0x2050  ──┐
//!                        ├──▶  New RVA 0x3000 (actual location in output)
//! Placeholder 0xE000_0001──┘
//! ```
//!
//! This mapping is used when writing FieldRVA table rows to update all RVA values.
//!
//! # ECMA-335 Reference
//!
//! See ECMA-335, Partition II, §22.19 for the FieldRVA table specification.

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{changes::AssemblyChanges, writer::context::WriteContext},
    file::File,
    metadata::{
        signatures::{parse_field_signature, TypeSignature},
        streams::TablesHeader,
        tables::{ClassLayoutRaw, FieldRaw, FieldRvaRaw},
        typesystem::PointerSize,
    },
    prelude::TableId,
    CilAssemblyView, Error, Result,
};

/// Field data entry: (source_rva, data_bytes)
/// Source RVA is either the original RVA or a placeholder RVA.
type FieldDataEntries = Vec<(u32, Vec<u8>)>;

/// Collects all FieldRVA data that needs to be written.
///
/// This function gathers field initialization data from:
/// 1. Original PE - FieldRVA entries that need relocation
/// 2. Changes - New field data stored via `store_field_data()`
fn collect_field_data(
    view: &CilAssemblyView,
    file: &File,
    changes: &AssemblyChanges,
    ptr_size: PointerSize,
) -> Result<FieldDataEntries> {
    let mut entries = Vec::new();

    // Collect original FieldRVA data
    collect_original_fieldrva_data(view, file, changes, &mut entries, ptr_size)?;

    // Collect new field data from changes
    collect_changes_field_data(changes, &mut entries);

    Ok(entries)
}

/// Calculates the size of a field's data based on its type.
///
/// Uses the signature parser and ClassLayout table to find explicit sizes for value types.
/// Returns an error if the size cannot be determined.
pub(crate) fn calculate_field_size(
    view: &CilAssemblyView,
    field_index: u32,
    ptr_size: PointerSize,
) -> Result<usize> {
    let tables = view.tables().ok_or_else(|| {
        Error::ModificationInvalid(format!(
            "Cannot access tables for field {field_index} size calculation"
        ))
    })?;

    // Get the Field row to find its signature
    let field_table = tables.table::<FieldRaw>().ok_or_else(|| {
        Error::ModificationInvalid(format!(
            "Cannot access Field table for field {field_index} size calculation"
        ))
    })?;
    let field_row = field_table
        .iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|r| r.rid == field_index)
        .ok_or_else(|| {
            Error::ModificationInvalid(format!("Field {field_index} not found in Field table"))
        })?;

    // Get and parse the field signature
    let blobs = view.blobs().ok_or_else(|| {
        Error::ModificationInvalid(format!(
            "Cannot access blob heap for field {field_index} size calculation"
        ))
    })?;
    let sig_data = blobs.get(field_row.signature as usize).map_err(|_| {
        Error::ModificationInvalid(format!(
            "Cannot read signature blob for field {field_index}"
        ))
    })?;
    let field_sig = parse_field_signature(sig_data).map_err(|e| {
        Error::ModificationInvalid(format!("Cannot parse field {field_index} signature: {e}"))
    })?;

    calculate_type_size(&field_sig.base, tables, field_index, ptr_size)
}

/// Calculates the size of a type signature.
///
/// Returns an error for types where size cannot be statically determined
/// (e.g., SzArray without known element count, reference types).
fn calculate_type_size(
    type_sig: &TypeSignature,
    tables: &TablesHeader,
    field_index: u32,
    ptr_size: PointerSize,
) -> Result<usize> {
    // Try primitive types first
    if let Some(size) = type_sig.byte_size(ptr_size) {
        return Ok(size);
    }

    match type_sig {
        // For value types, look up ClassLayout table
        TypeSignature::ValueType(token) => {
            // Token contains table ID in high byte, row in lower 24 bits
            // TypeDef table ID is 0x02
            let is_typedef = token.is_table(TableId::TypeDef);
            let row = token.row();

            // Only look up ClassLayout for TypeDef (not TypeRef or TypeSpec)
            if is_typedef {
                if let Some(class_layout_table) = tables.table::<ClassLayoutRaw>() {
                    for layout_row in class_layout_table {
                        let layout_row = layout_row?;
                        if layout_row.parent == row {
                            return Ok(layout_row.class_size as usize);
                        }
                    }
                }
            }
            Err(Error::ModificationInvalid(format!(
                "Field {} has ValueType (token 0x{:08x}) without ClassLayout - cannot determine size",
                field_index, token.value()
            )))
        }

        // Multi-dimensional arrays with known dimensions
        TypeSignature::Array(arr) => {
            // Need element size and all dimension sizes
            let element_size = calculate_type_size(&arr.base, tables, field_index, ptr_size)?;

            let mut total_elements: usize = 1;
            for dim in &arr.dimensions {
                let dim_size = dim.size.ok_or_else(|| {
                    Error::ModificationInvalid(format!(
                        "Field {field_index} has array with unknown dimension size"
                    ))
                })? as usize;
                total_elements = total_elements.checked_mul(dim_size).ok_or_else(|| {
                    Error::ModificationInvalid(format!("Field {field_index} array size overflow"))
                })?;
            }

            element_size.checked_mul(total_elements).ok_or_else(|| {
                Error::ModificationInvalid(format!("Field {field_index} array size overflow"))
            })
        }

        // SzArray (single-dimensional) - size not in signature
        TypeSignature::SzArray(_) => Err(Error::ModificationInvalid(format!(
            "Field {field_index} is SzArray - size not determinable from type signature. \
             Use FixedBufferAttribute or explicit ClassLayout for fixed-size arrays."
        ))),

        // Reference types, pointers - size depends on runtime
        _ => Err(Error::ModificationInvalid(format!(
            "Field {field_index} has type {type_sig:?} - cannot determine static size"
        ))),
    }
}

/// Collects original FieldRVA data that needs relocation.
fn collect_original_fieldrva_data(
    view: &CilAssemblyView,
    file: &File,
    changes: &AssemblyChanges,
    entries: &mut FieldDataEntries,
    ptr_size: PointerSize,
) -> Result<()> {
    // Get FieldRVA table
    let Some(fieldrva_table) = view
        .tables()
        .and_then(|t: &TablesHeader<'_>| t.table::<FieldRvaRaw>())
    else {
        return Ok(());
    };

    // Get modified RIDs from changes (these use placeholder RVAs, not original)
    let modified_rids: HashSet<u32> = changes
        .get_table_modifications(TableId::FieldRVA)
        .map(|mods| mods.change_refs().map(|(rid, _)| *rid).collect())
        .unwrap_or_default();

    // Get deleted RIDs from changes (these should be skipped entirely)
    let deleted_rids: HashSet<u32> = changes
        .get_table_modifications(TableId::FieldRVA)
        .map(|mods| mods.deleted_rids().collect())
        .unwrap_or_default();

    // Also check if the Field itself has been deleted (FieldRVA references a Field)
    let deleted_field_rids: HashSet<u32> = changes
        .get_table_modifications(TableId::Field)
        .map(|mods| mods.deleted_rids().collect())
        .unwrap_or_default();

    // Collect all entries that haven't been modified or deleted, along with field index for size calc
    let mut entries_to_process: Vec<(u32, u32, u32)> = Vec::new(); // (rva, rid, field_index)

    for row in fieldrva_table {
        let row = row?;
        if deleted_rids.contains(&row.rid)
            || deleted_field_rids.contains(&row.field)
            || modified_rids.contains(&row.rid)
        {
            continue;
        }

        let rva = row.rva;

        // Skip entries with no data (RVA 0)
        if rva == 0 {
            continue;
        }

        entries_to_process.push((rva, row.rid, row.field));
    }

    if entries_to_process.is_empty() {
        return Ok(());
    }

    // Sort by RVA
    entries_to_process.sort_by_key(|(rva, _, _)| *rva);

    // Process each entry
    for (rva, _rid, field_index) in entries_to_process {
        // PE field sizes are bounded by section sizes which fit in u32
        #[allow(clippy::cast_possible_truncation)]
        let size = calculate_field_size(view, field_index, ptr_size)? as u32;

        // The data as the loaded image holds it, zeros of a zero-filled part included
        let data = file.rva_slice(rva as usize, size as usize).map_err(|_| {
            Error::ModificationInvalid(format!(
                "Cannot read {size} bytes at RVA 0x{rva:08x} for field {field_index}"
            ))
        })?;

        entries.push((rva, data.to_vec()));
    }

    Ok(())
}

/// Collects new field data from changes.
fn collect_changes_field_data(changes: &AssemblyChanges, entries: &mut FieldDataEntries) {
    if !changes.has_field_data() {
        return;
    }

    let mut field_data_entries: Vec<_> = changes.field_data_entries().collect();
    field_data_entries.sort_by_key(|(placeholder, _)| *placeholder);

    for (placeholder_rva, data) in field_data_entries {
        entries.push((placeholder_rva, data.clone()));
    }
}

/// Writes field initialization data to output and builds RVA mapping.
///
/// This function collects and writes all FieldRVA data entries, handling:
/// - Original FieldRVA data (explicitly copied)
/// - New field data from changes (via `store_field_data()`)
///
/// The RVA mapping is stored in `ctx.field_data_rva_map` for later use when
/// writing FieldRVA table rows.
///
/// # Arguments
///
/// * `ctx` - The write context for output and tracking
///
/// # Returns
///
/// Ok(()) on success, populating `ctx.field_data_rva_map` with the mappings.
pub fn write_field_data(ctx: &mut WriteContext) -> Result<()> {
    let view = ctx.assembly.view();
    let file = view.file();
    let changes = ctx.changes;
    let ptr_size = PointerSize::from_is_64bit(file.pe().is_64bit);

    let entries = collect_field_data(view, file, changes, ptr_size)?;

    if entries.is_empty() {
        return Ok(());
    }

    ctx.align_to_4();

    for (source_rva, data) in &entries {
        // Calculate actual RVA for this field data
        let actual_rva = ctx.current_rva();
        ctx.field_data_rva_map.insert(*source_rva, actual_rva);

        ctx.write(data)?;
        ctx.align_to_4();
    }

    Ok(())
}

/// Resolves RVAs in FieldRVA row buffers.
///
/// Replaces RVA values with actual field data RVAs from the mapping. This handles:
/// - Placeholder RVAs (0xE000_0000-0xF000_0000 range) from `store_field_data()`
/// - Original RVAs that were relocated when method bodies region was skipped
///
/// The first 4 bytes of a FieldRVA row contain the RVA field.
///
/// # Arguments
///
/// * `buffer` - The raw FieldRVA row bytes
/// * `field_data_rva_map` - Mapping from old/placeholder RVAs to actual RVAs
pub fn resolve_field_data_rva(buffer: &mut [u8], field_data_rva_map: &HashMap<u32, u32>) {
    let Some(rva_bytes) = buffer.get(..4) else {
        return;
    };

    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(rva_bytes);
    let rva = u32::from_le_bytes(bytes);

    // RVA 0 means no data
    if rva == 0 {
        return;
    }

    // Check if this RVA needs to be remapped (either placeholder or relocated original)
    if let Some(&new_rva) = field_data_rva_map.get(&rva) {
        let new_bytes = new_rva.to_le_bytes();
        if let Some(dest) = buffer.get_mut(..4) {
            dest.copy_from_slice(&new_bytes);
        }
    }
    // RVAs not in the map are kept as-is (they point to sections that weren't relocated)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_field_data_rva_placeholder() {
        let mut buffer = [0x01, 0x00, 0x00, 0xE0, 0x00, 0x00]; // RVA = 0xE000_0001
        let mut map = HashMap::new();
        map.insert(0xE000_0001, 0x3000);

        resolve_field_data_rva(&mut buffer, &map);

        assert_eq!(
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            0x3000
        );
    }

    #[test]
    fn test_resolve_field_data_rva_original() {
        let mut buffer = [0x50, 0x20, 0x00, 0x00, 0x00, 0x00]; // RVA = 0x2050
        let mut map = HashMap::new();
        map.insert(0x2050, 0x4000);

        resolve_field_data_rva(&mut buffer, &map);

        assert_eq!(
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            0x4000
        );
    }

    #[test]
    fn test_resolve_field_data_rva_not_in_map() {
        let mut buffer = [0x00, 0x30, 0x00, 0x00, 0x00, 0x00]; // RVA = 0x3000
        let map = HashMap::new();

        resolve_field_data_rva(&mut buffer, &map);

        // Should remain unchanged
        assert_eq!(
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            0x3000
        );
    }

    #[test]
    fn test_resolve_field_data_rva_zero() {
        let mut buffer = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let mut map = HashMap::new();
        map.insert(0, 0x1000);

        resolve_field_data_rva(&mut buffer, &map);

        // Zero RVA should remain zero (means no data)
        assert_eq!(
            u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]),
            0
        );
    }
}
