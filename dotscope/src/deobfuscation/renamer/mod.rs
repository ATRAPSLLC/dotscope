//! Renaming of obfuscated .NET identifiers.
//!
//! Obfuscators replace type, method, field and parameter names with unprintable,
//! colliding or meaningless strings. This module gives every such identifier a short
//! sequential replacement from [`SimpleNameGenerator`]
//! (`A`, `B`, ... for types, `a`, `b`, ... for methods, `f_a` for fields, `p_a` for
//! parameters), so that decompiled output is legible. Each kind draws from its own
//! counter. Names already present in the assembly are not reserved, so a replacement can
//! coincide with an existing identifier.
//!
//! # Two-Phase Architecture
//!
//! Renaming is split into **collect** and **apply** phases to work around the
//! `CilObject` → `CilAssembly` consumption boundary in `execute_cleanup()`:
//!
//! 1. [`renames_collect()`] - runs on `&CilObject` (before consumption), walks metadata
//!    tables, identifies obfuscated names, and generates replacement entries.
//! 2. [`renames_apply()`] - runs on `&mut CilAssembly` (after consumption), applies
//!    string heap modifications and handles shared-offset splitting.

mod names;

use std::collections::{HashMap, HashSet};

use self::names::SimpleNameGenerator;
use crate::{
    cilassembly::CilAssembly,
    deobfuscation::utils::{is_obfuscated_name, is_special_name},
    metadata::tables::{FieldRaw, MethodDefRaw, ParamRaw, TableDataOwned, TableId, TypeDefRaw},
    CilObject, Result,
};

/// A single rename operation to be applied to the assembly.
#[derive(Debug, Clone)]
pub struct RenameEntry {
    /// Which metadata table contains the row to rename.
    pub table_id: TableId,
    /// Row ID within the table (1-based).
    pub rid: u32,
    /// Original string heap index of the name being replaced.
    pub string_index: u32,
    /// The new name to assign.
    pub new_name: String,
}

/// Collects rename entries for every obfuscated identifier in the assembly.
///
/// Walks the TypeDef, MethodDef, Field and Param tables in that order and gives each
/// obfuscated name (see [`is_obfuscated_name`]) that is not a special name (see
/// [`is_special_name`]) a sequential replacement from [`SimpleNameGenerator`]. The
/// `<Module>` type (TypeDef row 1) is never renamed. A string heap offset is renamed
/// once: rows sharing an offset with an earlier entry are skipped, since
/// [`renames_apply()`] rewrites the string in place and so renames every row that
/// points at it.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan for obfuscated names.
///
/// # Returns
///
/// A vector of rename entries with sequential alphabetic names, ready for
/// [`renames_apply()`].
///
/// # Errors
///
/// Returns an error if metadata table access fails.
pub fn renames_collect(assembly: &CilObject) -> Result<Vec<RenameEntry>> {
    let mut entries = Vec::new();
    let mut name_generator = SimpleNameGenerator::new();

    let Some(tables) = assembly.tables() else {
        return Ok(entries);
    };

    let Some(strings) = assembly.strings() else {
        return Ok(entries);
    };

    let mut seen_indices: HashSet<u32> = HashSet::new();

    // Collect obfuscated names from TypeDef
    if let Some(typedef_table) = tables.table::<TypeDefRaw>() {
        for rid in 1..=typedef_table.row_count {
            if let Some(typedef) = typedef_table.get(rid)? {
                // Skip <Module> (RID 1)
                if rid == 1 {
                    continue;
                }

                let name_index = typedef.type_name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::TypeDef,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_type_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated method names from MethodDef
    if let Some(methoddef_table) = tables.table::<MethodDefRaw>() {
        for rid in 1..=methoddef_table.row_count {
            if let Some(methoddef) = methoddef_table.get(rid)? {
                let name_index = methoddef.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::MethodDef,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_method_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated field names from Field
    if let Some(field_table) = tables.table::<FieldRaw>() {
        for rid in 1..=field_table.row_count {
            if let Some(field) = field_table.get(rid)? {
                let name_index = field.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::Field,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_field_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Collect obfuscated parameter names from Param
    if let Some(param_table) = tables.table::<ParamRaw>() {
        for rid in 1..=param_table.row_count {
            if let Some(param) = param_table.get(rid)? {
                let name_index = param.name;
                if name_index > 0 {
                    if let Ok(name) = strings.get(name_index as usize) {
                        if is_obfuscated_name(name)
                            && !is_special_name(name)
                            && seen_indices.insert(name_index)
                        {
                            entries.push(RenameEntry {
                                table_id: TableId::Param,
                                rid,
                                string_index: name_index,
                                new_name: name_generator.next_param_name(),
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(entries)
}

/// Applies collected rename entries to the assembly's string heap.
///
/// Handles shared string offsets correctly:
/// - **First rename** at an offset: uses `string_update()` (affects all rows at that offset).
/// - **Subsequent different names** at the same offset: uses `string_add()` to allocate a
///   new string, then `table_row_update()` to point the specific row at it.
///
/// # Arguments
///
/// * `cil_assembly` - The mutable assembly to apply renames to.
/// * `entries` - The rename entries to apply.
///
/// # Returns
///
/// The number of identifiers successfully renamed.
///
/// # Errors
///
/// Returns an error if string heap mutation or table row update fails.
pub fn renames_apply(cil_assembly: &mut CilAssembly, entries: Vec<RenameEntry>) -> Result<usize> {
    if entries.is_empty() {
        return Ok(0);
    }

    let mut renamed_count: usize = 0;

    // Track which string offsets have already been renamed and to what name
    let mut renamed_offsets: HashMap<u32, String> = HashMap::new();

    for entry in &entries {
        if let Some(existing_name) = renamed_offsets.get(&entry.string_index) {
            if *existing_name == entry.new_name {
                // Same name as first rename — string_update already covers this
                renamed_count = renamed_count.saturating_add(1);
                continue;
            }
            // Different name at same offset — allocate new string and update the row
            let change_ref = cil_assembly.string_add(&entry.new_name)?;
            let placeholder = change_ref.placeholder();
            update_row_name_field(cil_assembly, entry.table_id, entry.rid, placeholder)?;
            renamed_count = renamed_count.saturating_add(1);
        } else {
            // First rename at this offset — modify in place
            if cil_assembly
                .string_update(entry.string_index, &entry.new_name)
                .is_ok()
            {
                renamed_offsets.insert(entry.string_index, entry.new_name.clone());
                renamed_count = renamed_count.saturating_add(1);
            }
        }
    }

    Ok(renamed_count)
}

/// Updates the name field of a metadata row to point at a new string.
///
/// Reads the current row, replaces the name-bearing field with
/// `new_string_placeholder`, and writes the modified row back. Handles
/// TypeDef, MethodDef, Field, and Param tables.
///
/// # Arguments
///
/// * `cil_assembly` - The assembly containing the metadata table.
/// * `table_id` - Which metadata table to update.
/// * `rid` - Row ID within the table (1-based).
/// * `new_string_placeholder` - The placeholder value from [`string_add()`](crate::CilAssembly::string_add)
///   pointing to the new string.
///
/// # Errors
///
/// Returns an error if the table row cannot be read or updated.
fn update_row_name_field(
    cil_assembly: &mut CilAssembly,
    table_id: TableId,
    rid: u32,
    new_string_placeholder: u32,
) -> Result<()> {
    let row_data = {
        let view = cil_assembly.view();
        let Some(tables) = view.tables() else {
            return Ok(());
        };

        match table_id {
            TableId::TypeDef => {
                let table = tables.table::<TypeDefRaw>();
                table.and_then(|t| t.get(rid).ok().flatten()).map(|row| {
                    let mut row = row.clone();
                    row.type_name = new_string_placeholder;
                    TableDataOwned::TypeDef(row)
                })
            }
            TableId::MethodDef => {
                let table = tables.table::<MethodDefRaw>();
                table.and_then(|t| t.get(rid).ok().flatten()).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::MethodDef(row)
                })
            }
            TableId::Field => {
                let table = tables.table::<FieldRaw>();
                table.and_then(|t| t.get(rid).ok().flatten()).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::Field(row)
                })
            }
            TableId::Param => {
                let table = tables.table::<ParamRaw>();
                table.and_then(|t| t.get(rid).ok().flatten()).map(|row| {
                    let mut row = row.clone();
                    row.name = new_string_placeholder;
                    TableDataOwned::Param(row)
                })
            }
            _ => None,
        }
    };

    if let Some(data) = row_data {
        cil_assembly.table_row_update(table_id, rid, data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::GeneratorConfig, metadata::validation::ValidationConfig,
        testkit::helpers::load_sample,
    };

    const RENAMER_SAMPLE: &str = "packers/bitmono/0.39.0/bitmono_renamer.exe";
    const ORIGINAL_SAMPLE: &str = "packers/bitmono/0.39.0/original.exe";

    /// Regression test: renaming obfuscated names must preserve TypeRef substring
    /// references in the string heap.
    #[test]
    fn test_rename_preserves_typeref_substring_references() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let entries = renames_collect(&assembly).unwrap();
        assert!(!entries.is_empty(), "Expected at least one rename entry");

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renames_apply(&mut cil_assembly, entries).unwrap();
        assert!(count > 0, "Expected at least one rename");

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .expect("Generation with renames should produce valid assembly");

        let output_bytes = output.file().data();
        CilObject::from_mem_with_validation(output_bytes.to_vec(), ValidationConfig::production())
            .expect("Roundtrip after rename should pass production validation");
    }

    /// Clean binary should produce zero rename entries.
    #[test]
    fn test_no_renames_on_clean_assembly() {
        let assembly = load_sample(ORIGINAL_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();
        assert!(
            entries.is_empty(),
            "Clean binary should have no obfuscated names, got {}",
            entries.len()
        );
    }

    /// Exact per-table counts from the bitmono_renamer sample.
    #[test]
    fn test_collect_entry_counts() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        let types = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .count();
        let methods = entries
            .iter()
            .filter(|e| e.table_id == TableId::MethodDef)
            .count();
        let fields = entries
            .iter()
            .filter(|e| e.table_id == TableId::Field)
            .count();
        let params = entries
            .iter()
            .filter(|e| e.table_id == TableId::Param)
            .count();

        assert_eq!(types, 8, "TypeDef entries");
        assert_eq!(methods, 25, "MethodDef entries");
        assert_eq!(fields, 9, "Field entries");
        assert_eq!(params, 23, "Param entries");
    }

    /// Types are renamed in table order to the sequential names A through H.
    #[test]
    fn test_collect_sequential_type_names() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        let type_names: Vec<&str> = entries
            .iter()
            .filter(|e| e.table_id == TableId::TypeDef)
            .map(|e| e.new_name.as_str())
            .collect();

        assert_eq!(type_names.len(), 8);
        assert_eq!(type_names[0], "A");
        assert_eq!(type_names[1], "B");
        assert_eq!(type_names[2], "C");
        assert_eq!(type_names[3], "D");
        assert_eq!(type_names[4], "E");
        assert_eq!(type_names[5], "F");
        assert_eq!(type_names[6], "G");
        assert_eq!(type_names[7], "H");
    }

    /// All field entries should be prefixed with `f_`, all param entries with `p_`.
    #[test]
    fn test_collect_field_and_param_prefixes() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        for entry in entries.iter().filter(|e| e.table_id == TableId::Field) {
            assert!(
                entry.new_name.starts_with("f_"),
                "Field name '{}' should start with 'f_'",
                entry.new_name
            );
        }

        for entry in entries.iter().filter(|e| e.table_id == TableId::Param) {
            assert!(
                entry.new_name.starts_with("p_"),
                "Param name '{}' should start with 'p_'",
                entry.new_name
            );
        }
    }

    /// `.ctor` and `Main` must NOT appear in rename entries (special/non-obfuscated).
    #[test]
    fn test_collect_preserves_special_names() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        let strings = assembly
            .strings()
            .expect("assembly should have strings heap");

        // Collect original names for all entries
        let original_names: Vec<String> = entries
            .iter()
            .filter_map(|e| strings.get(e.string_index as usize).ok().map(String::from))
            .collect();

        assert!(
            !original_names.iter().any(|n| n == ".ctor"),
            ".ctor should not be in rename entries"
        );
        assert!(
            !original_names.iter().any(|n| n == "Main"),
            "Main should not be in rename entries"
        );
    }

    /// Full roundtrip: collect → apply → generate → reload.
    #[test]
    fn test_roundtrip_apply_and_reload() {
        let assembly = load_sample(RENAMER_SAMPLE);

        let entries = renames_collect(&assembly).unwrap();
        assert!(!entries.is_empty());

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renames_apply(&mut cil_assembly, entries.clone()).unwrap();
        assert_eq!(count, entries.len(), "All entries should be applied");

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .expect("Roundtrip generation should succeed");

        CilObject::from_mem_with_validation(
            output.file().data().to_vec(),
            ValidationConfig::production(),
        )
        .expect("Reloaded assembly should pass production validation");
    }

    /// Roundtrip then verify renamed type names in output.
    #[test]
    fn test_roundtrip_verifies_renamed_types() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();
        renames_apply(&mut cil_assembly, entries).unwrap();

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .unwrap();

        let tables = output.tables().expect("output should have tables");
        let strings = output.strings().expect("output should have strings");
        let typedef_table = tables.table::<TypeDefRaw>().expect("TypeDef table");

        let mut type_names = Vec::new();
        for rid in 1..=typedef_table.row_count {
            if let Some(row) = typedef_table.get(rid).ok().flatten() {
                if let Ok(name) = strings.get(row.type_name as usize) {
                    type_names.push(name.to_string());
                }
            }
        }

        assert!(
            type_names.contains(&"A".to_string()),
            "First renamed type 'A' should be present"
        );
        assert!(
            type_names.contains(&"<Module>".to_string()),
            "<Module> should be preserved"
        );
        assert!(
            !type_names.iter().any(|n| n.contains(' ')),
            "No type names should contain spaces after renaming, got: {:?}",
            type_names
                .iter()
                .filter(|n| n.contains(' '))
                .collect::<Vec<_>>()
        );
    }

    /// Roundtrip then verify renamed method names in output.
    /// BitMono's FullRenamer renames ALL methods (including `Main`), so the
    /// output should contain only `.ctor` (special name) and sequential names.
    #[test]
    fn test_roundtrip_verifies_renamed_methods() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();
        renames_apply(&mut cil_assembly, entries).unwrap();

        let output = cil_assembly
            .into_cilobject_with(ValidationConfig::production(), GeneratorConfig::default())
            .unwrap();

        let tables = output.tables().expect("output should have tables");
        let strings = output.strings().expect("output should have strings");
        let methoddef_table = tables.table::<MethodDefRaw>().expect("MethodDef table");

        let mut method_names = Vec::new();
        for rid in 1..=methoddef_table.row_count {
            if let Some(row) = methoddef_table.get(rid).ok().flatten() {
                if let Ok(name) = strings.get(row.name as usize) {
                    method_names.push(name.to_string());
                }
            }
        }

        assert!(
            method_names.contains(&".ctor".to_string()),
            ".ctor should be preserved, got: {:?}",
            method_names
        );
        // BitMono renames Main too, so after our renaming it becomes a sequential name.
        // Verify the first sequential method name is present.
        assert!(
            method_names.contains(&"a".to_string()),
            "First sequential method name 'a' should be present"
        );
        assert!(
            !method_names.iter().any(|n| n.contains(' ')),
            "No method names should contain spaces after renaming, got: {:?}",
            method_names
                .iter()
                .filter(|n| n.contains(' '))
                .collect::<Vec<_>>()
        );
    }

    /// Applying two entries with the same `string_index` and same `new_name` should
    /// succeed without error — the second is a no-op covered by `string_update`.
    #[test]
    fn test_apply_renames_idempotent_same_offset() {
        let assembly = load_sample(RENAMER_SAMPLE);
        let entries = renames_collect(&assembly).unwrap();
        assert!(!entries.is_empty());

        // Pick the first entry and duplicate it
        let first = entries[0].clone();
        let dup = vec![first.clone(), first.clone()];

        let bytes = assembly.file().data().to_vec();
        let mut cil_assembly = CilAssembly::from_bytes(bytes).unwrap();

        let count = renames_apply(&mut cil_assembly, dup).unwrap();
        assert_eq!(
            count, 2,
            "Both entries should count as renamed (second is a covered no-op)"
        );
    }
}
