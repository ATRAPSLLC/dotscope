//! Heap compaction for removing unreferenced heap entries.
//!
//! This module scans metadata tables to identify which heap entries are actually
//! referenced, then marks unreferenced entries for removal. The streaming heap
//! writers will skip these entries, resulting in compact heaps.
//!
//! # Background
//!
//! Metadata heaps (#Strings, #Blob, #GUID) often contain entries that are no
//! longer referenced after cleanup operations remove types, methods, or fields.
//! Heap compaction identifies and removes these orphaned entries.
//!
//! # Architecture
//!
//! Compaction runs as a phase in cleanup execution:
//!
//! 1. **Scan tables**: Iterate all remaining table rows, collect heap references
//! 2. **Mark unreferenced**: Compare against all heap entries, mark orphans
//! 3. **Streaming skips**: Heap writers skip entries marked as removed
//!
//! This approach reuses the existing `HeapChanges::remove()` mechanism rather
//! than adding new parameters to streaming functions.
//!
//! # Known Limitations
//!
//! **Currently disabled** due to substring reference handling:
//!
//! .NET metadata allows string references to point to ANY offset within the
//! #Strings heap, not just to the start of entries. For example, if "HelloWorld\0"
//! is stored at offset 100, a TypeRef might reference offset 105 to get "World\0".
//!
//! The current implementation iterates the strings heap by walking null-terminated
//! boundaries, which means it only sees "primary" entry offsets. When strings are
//! removed and others shift, the remapping only covers these primary offsets -
//! substring references (like offset 105 in the example) are not remapped.
//!
//! To fix this, we would need to:
//! 1. Track ALL referenced offsets (not just primary entry offsets)
//! 2. Ensure substring references get proper remapping when entries shift
//! 3. Potentially preserve substring relationships in the output heap

use std::{collections::HashSet, sync::Arc};

use strum::IntoEnumIterator;

use crate::{
    cilassembly::{changes::ChangeRef, CilAssembly, Operation, TableModifications},
    dispatch_table_type,
    metadata::{
        tablefields::{get_heap_fields, HeapFieldDescriptor, HeapType},
        tables::{RowWritable, TableDataOwned, TableId, TableInfoRef},
    },
    utils::{calculate_table_row_size, read_le_at_dyn},
    Result,
};

/// Result of heap compaction analysis.
#[derive(Debug, Default)]
pub struct CompactionStats {
    /// Number of unreferenced string entries marked for removal.
    pub strings: usize,
    /// Number of unreferenced blob entries marked for removal.
    pub blobs: usize,
    /// Number of unreferenced GUID entries marked for removal.
    pub guids: usize,
}

impl CompactionStats {
    /// Returns true if any entries were marked for removal.
    ///
    /// Checks all heap types (strings, blobs, GUIDs) for removals.
    #[must_use]
    pub fn has_removals(&self) -> bool {
        self.strings > 0 || self.blobs > 0 || self.guids > 0
    }

    /// Returns the total number of entries marked for removal.
    ///
    /// This is the sum of removed strings, blobs, and GUIDs.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.strings
            .saturating_add(self.blobs)
            .saturating_add(self.guids)
    }
}

/// Marks unreferenced heap entries for removal.
///
/// Scans all metadata tables to collect referenced heap entries, then marks
/// any unreferenced entries for removal via `HeapChanges`. The streaming
/// heap writers will skip these entries during generation.
///
/// For #Strings heap, this handles "substring references" where metadata can
/// reference any offset within a string entry, not just the start. A string is
/// kept if ANY referenced offset falls within its byte range.
///
/// # Arguments
///
/// * `assembly` - The assembly to compact (heap changes are modified in place)
///
/// # Returns
///
/// Statistics about entries marked for removal.
pub(crate) fn mark_unreferenced_heap_entries(
    assembly: &mut CilAssembly,
) -> Result<CompactionStats> {
    let mut stats = CompactionStats::default();

    // Collect all referenced heap offsets/indices from tables
    let (ref_strings, ref_blobs, ref_guids) = collect_referenced_heap_entries(assembly);

    // Store referenced string offsets for use during streaming (substring remapping)
    assembly
        .changes_mut()
        .referenced_string_offsets
        .clone_from(&ref_strings);

    // Collect unreferenced entries first (to avoid borrow conflicts)
    let unreferenced_strings: Vec<u32>;
    let unreferenced_blobs: Vec<u32>;
    let unreferenced_guids: Vec<u32>;

    {
        let view = assembly.view();

        // Find unreferenced strings
        // A string is unreferenced if NO referenced offset falls within its byte range.
        // This handles substring references correctly.
        unreferenced_strings = if let Some(strings) = view.strings() {
            strings
                .iter()
                .filter_map(|(offset, content)| {
                    // Safe: .NET heap offsets always fit in u32
                    #[allow(clippy::cast_possible_truncation)]
                    let offset_u32 = offset as u32;
                    // Skip offset 0 (null terminator) - always referenced implicitly
                    if offset_u32 == 0 {
                        return None;
                    }

                    // Calculate the byte range of this string entry
                    // Safe: .NET heap offsets always fit in u32
                    #[allow(clippy::cast_possible_truncation)]
                    let content_len = content.len() as u32;
                    // +1 for null terminator. Saturate on overflow (unreachable in practice).
                    let str_end = offset_u32.saturating_add(content_len).saturating_add(1);

                    // Check if ANY referenced offset falls within this string's range
                    let has_reference = ref_strings
                        .iter()
                        .any(|&ref_off| ref_off >= offset_u32 && ref_off < str_end);

                    if has_reference {
                        None
                    } else {
                        Some(offset_u32)
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        // Find unreferenced blobs
        unreferenced_blobs = if let Some(blobs) = view.blobs() {
            blobs
                .iter()
                .filter_map(|(offset, _)| {
                    // Safe: .NET heap offsets always fit in u32
                    #[allow(clippy::cast_possible_truncation)]
                    let offset_u32 = offset as u32;
                    // Skip offset 0 (null blob) - always referenced implicitly
                    if offset_u32 > 0 && !ref_blobs.contains(&offset_u32) {
                        Some(offset_u32)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };

        // Find unreferenced GUIDs
        unreferenced_guids = if let Some(guids) = view.guids() {
            guids
                .iter()
                .filter_map(|(index, _)| {
                    // Safe: .NET heap offsets always fit in u32
                    #[allow(clippy::cast_possible_truncation)]
                    let index_u32 = index as u32;
                    // GUID indices are 1-based, index 0 means "no GUID"
                    if index_u32 > 0 && !ref_guids.contains(&index_u32) {
                        Some(index_u32)
                    } else {
                        None
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
    }

    // Mark unreferenced entries for removal
    for offset in unreferenced_strings {
        assembly.string_remove(offset)?;
        stats.strings = stats.strings.saturating_add(1);
    }

    for offset in unreferenced_blobs {
        assembly.blob_remove(offset)?;
        stats.blobs = stats.blobs.saturating_add(1);
    }

    for index in unreferenced_guids {
        assembly.guid_remove(index)?;
        stats.guids = stats.guids.saturating_add(1);
    }

    Ok(stats)
}

/// Collects all heap entries referenced by metadata tables.
///
/// Scans every row in every table, extracting heap reference field values.
/// This includes:
/// - Original rows (from the view) that haven't been deleted
/// - Updated rows (from modifications)
/// - Inserted rows (from modifications)
/// - Replaced tables (all rows from the replacement)
///
/// Returns sets of referenced offsets/indices for each heap type.
pub(crate) fn collect_referenced_heap_entries(
    assembly: &CilAssembly,
) -> (HashSet<u32>, HashSet<u32>, HashSet<u32>) {
    let mut ref_strings: HashSet<u32> = HashSet::new();
    let mut ref_blobs: HashSet<u32> = HashSet::new();
    let mut ref_guids: HashSet<u32> = HashSet::new();

    // Always reference offset 0 (null entries)
    ref_strings.insert(0);
    ref_blobs.insert(0);

    let view = assembly.view();
    let Some(tables) = view.tables() else {
        return (ref_strings, ref_blobs, ref_guids);
    };

    // Rows are read back through a layout whose heap indices are all four bytes wide: a new
    // or updated row may hold a heap placeholder (`0x8000_0000 | id`), which a two-byte
    // column of the original layout would cut to its id, and the id would pass for an offset
    let wide = tables
        .info
        .with_modified_heap_sizes(usize::MAX, usize::MAX, usize::MAX);
    let table_info: &TableInfoRef = &Arc::new(wide);
    let changes = assembly.changes();

    // Iterate all table types
    for table_id in TableId::iter() {
        let heap_fields = get_heap_fields(table_id, table_info);
        if heap_fields.is_empty() {
            continue;
        }

        let row_count = tables.table_row_count(table_id);
        let row_size = calculate_table_row_size(table_id, table_info) as usize;

        // Check what kind of modifications we have for this table
        match changes.table_changes.get(&table_id) {
            Some(TableModifications::Replaced(replacement_rows)) => {
                // Table is fully replaced - scan only the replacement rows
                scan_table_data_owned_rows(
                    replacement_rows,
                    table_id,
                    table_info,
                    &heap_fields,
                    &mut ref_strings,
                    &mut ref_blobs,
                    &mut ref_guids,
                );
            }
            Some(TableModifications::Sparse {
                operations,
                deleted_rows,
                ..
            }) => {
                // Sparse modifications - scan original rows (skipping deleted) plus modifications

                // First, scan original rows that haven't been deleted or updated
                let updated_rids: HashSet<u32> = operations
                    .iter()
                    .filter_map(|op| match &op.operation {
                        Operation::Update(rid, _) => Some(*rid),
                        _ => None,
                    })
                    .collect();

                dispatch_table_type!(table_id, |RawType| {
                    if let Some(table) = tables.table::<RawType>() {
                        let mut row_buffer = vec![0u8; row_size];

                        for rid in 1..=row_count {
                            // Skip deleted rows
                            if deleted_rows.contains(&rid) {
                                continue;
                            }
                            // Skip updated rows (we'll scan the updated data instead)
                            if updated_rids.contains(&rid) {
                                continue;
                            }

                            // Get the row and serialize to bytes
                            let Some(row) = table.get(rid).ok().flatten() else {
                                continue;
                            };

                            // Serialize row to buffer
                            let mut offset = 0;
                            if row
                                .row_write(&mut row_buffer, &mut offset, rid, table_info)
                                .is_err()
                            {
                                continue;
                            }

                            // Extract heap references from the serialized row
                            extract_heap_refs_from_row(
                                &row_buffer,
                                &heap_fields,
                                &mut ref_strings,
                                &mut ref_blobs,
                                &mut ref_guids,
                            );
                        }
                    }
                });

                // Now scan Update and Insert operations
                for op in operations {
                    let row_data = match &op.operation {
                        Operation::Update(_, data) | Operation::Insert(_, data) => data,
                        Operation::Delete(_) => continue,
                    };

                    // Only scan if this row is for the current table
                    if row_data.table_id() != table_id {
                        continue;
                    }

                    let mut row_buffer = vec![0u8; row_size];
                    let mut offset = 0;
                    if row_data
                        .row_write(&mut row_buffer, &mut offset, 0, table_info)
                        .is_ok()
                    {
                        extract_heap_refs_from_row(
                            &row_buffer,
                            &heap_fields,
                            &mut ref_strings,
                            &mut ref_blobs,
                            &mut ref_guids,
                        );
                    }
                }
            }
            None => {
                // No modifications - scan all original rows
                if row_count == 0 {
                    continue;
                }

                dispatch_table_type!(table_id, |RawType| {
                    if let Some(table) = tables.table::<RawType>() {
                        let mut row_buffer = vec![0u8; row_size];

                        for rid in 1..=row_count {
                            // Get the row and serialize to bytes
                            let Some(row) = table.get(rid).ok().flatten() else {
                                continue;
                            };

                            // Serialize row to buffer
                            let mut offset = 0;
                            if row
                                .row_write(&mut row_buffer, &mut offset, rid, table_info)
                                .is_err()
                            {
                                continue;
                            }

                            // Extract heap references from the serialized row
                            extract_heap_refs_from_row(
                                &row_buffer,
                                &heap_fields,
                                &mut ref_strings,
                                &mut ref_blobs,
                                &mut ref_guids,
                            );
                        }
                    }
                });
            }
        }
    }

    (ref_strings, ref_blobs, ref_guids)
}

/// Scans a vector of TableDataOwned rows for heap references.
fn scan_table_data_owned_rows(
    rows: &[TableDataOwned],
    table_id: TableId,
    table_info: &TableInfoRef,
    heap_fields: &[HeapFieldDescriptor],
    ref_strings: &mut HashSet<u32>,
    ref_blobs: &mut HashSet<u32>,
    ref_guids: &mut HashSet<u32>,
) {
    let row_size = calculate_table_row_size(table_id, table_info) as usize;
    let mut row_buffer = vec![0u8; row_size];

    for (idx, row_data) in rows.iter().enumerate() {
        // Skip if this row is for a different table (shouldn't happen but be safe)
        if row_data.table_id() != table_id {
            continue;
        }

        // Safe: .NET heap offsets always fit in u32
        #[allow(clippy::cast_possible_truncation)]
        let rid = idx.saturating_add(1) as u32;
        let mut offset = 0;
        if row_data
            .row_write(&mut row_buffer, &mut offset, rid, table_info)
            .is_ok()
        {
            extract_heap_refs_from_row(&row_buffer, heap_fields, ref_strings, ref_blobs, ref_guids);
        }
    }
}

/// Extracts heap reference values from a serialized row buffer.
///
/// Skips placeholder values (ChangeRef placeholders) as those are resolved later
/// during generation and don't reference existing heap entries.
fn extract_heap_refs_from_row(
    row_buffer: &[u8],
    heap_fields: &[HeapFieldDescriptor],
    ref_strings: &mut HashSet<u32>,
    ref_blobs: &mut HashSet<u32>,
    ref_guids: &mut HashSet<u32>,
) {
    for field in heap_fields {
        let Some(field_end) = field.offset.checked_add(field.size) else {
            continue;
        };
        if field_end > row_buffer.len() {
            continue;
        }

        let is_large = field.size == 4;
        let mut read_offset = field.offset;

        if let Ok(value) = read_le_at_dyn(row_buffer, &mut read_offset, is_large) {
            // Skip zero (null reference) and placeholder values
            // Placeholders reference newly added heap entries that don't exist
            // in the original heap
            if value == 0 || ChangeRef::is_heap_placeholder(value) {
                continue;
            }

            match field.heap_type {
                HeapType::String => {
                    ref_strings.insert(value);
                }
                HeapType::Blob => {
                    ref_blobs.insert(value);
                }
                HeapType::Guid => {
                    ref_guids.insert(value);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{CodedIndex, CodedIndexType, TypeRefBuilder},
        },
        testkit::fixture,
    };

    #[test]
    fn test_compaction_stats_default() {
        let stats = CompactionStats::default();
        assert!(!stats.has_removals());
        assert_eq!(stats.total_removed(), 0);
    }

    #[test]
    fn test_compaction_stats_with_removals() {
        let stats = CompactionStats {
            strings: 5,
            blobs: 3,
            guids: 1,
        };
        assert!(stats.has_removals());
        assert_eq!(stats.total_removed(), 9);
    }

    /// A new row's string column holds a placeholder (`0x8000_0000 | id`) until the heap is
    /// written. Read back through a two-byte column, it was cut to its id, which counted as a
    /// referenced string offset: once the id fell inside another name, the writer kept a tail of
    /// that name cut mid-character.
    #[test]
    fn a_new_rows_placeholder_is_not_taken_for_a_string_offset() {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe")).unwrap();
        assert!(!view.tables().unwrap().info.is_large_str());
        let mut assembly = CilAssembly::new(view);
        let (before, _, _) = collect_referenced_heap_entries(&assembly);

        // Take ids until the next two (the new row's name and namespace) are offsets no row
        // references, so a truncated placeholder would show
        let mut taken = 0u32;
        while before.contains(&(taken + 1)) || before.contains(&(taken + 2)) || taken < 16 {
            assembly
                .string_add(&format!("unreferenced{taken}"))
                .unwrap();
            taken += 1;
        }
        TypeRefBuilder::new()
            .name("PlaceholderName")
            .namespace("PlaceholderNamespace")
            .resolution_scope(CodedIndex::new(
                TableId::Module,
                1,
                CodedIndexType::ResolutionScope,
            ))
            .build(&mut assembly)
            .unwrap();

        let (after, _, _) = collect_referenced_heap_entries(&assembly);
        assert_eq!(after, before);
    }
}
