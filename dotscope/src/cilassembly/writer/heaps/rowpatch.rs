//! Row byte patching for heap reference remapping.
//!
//! This module provides functionality to patch heap references in raw table row
//! bytes when heaps are rebuilt with new offsets. When a heap is reconstructed
//! (due to modifications, deletions, or optimization), entries may move to
//! different offsets. This module handles updating the raw table row bytes
//! to reflect those new offsets.
//!
//! # Background
//!
//! According to ECMA-335 §II.24.2.6, metadata tables contain references to
//! heap entries as indices/offsets. The size of these references (2 or 4 bytes)
//! depends on the heap size:
//!
//! - **#Strings heap**: References are offsets into the string heap
//! - **#Blob heap**: References are offsets into the blob heap
//! - **#GUID heap**: References are 1-based indices (each GUID is 16 bytes)
//!
//! When heaps are rebuilt, these offsets change and must be updated in all
//! table rows that reference them.
//!
//! # Architecture
//!
//! This module uses the centralized table field definitions from [`crate::metadata::tablefields`]
//! to determine which fields in each table row contain heap references, then
//! patches those fields using the provided remapping tables.
//!
//! # Usage
//!
//! This module is used internally by the assembly writer when copying original
//! table rows during heap rebuild mode. It's typically called from the generator
//! when writing metadata tables.
//!
//! The `examples::module_example` test in this module runs this example.

use std::collections::HashMap;

use crate::{
    metadata::{
        tablefields::{get_heap_fields, HeapType},
        tables::{TableId, TableInfoRef},
    },
    utils::{read_le_at_dyn, write_le_at_dyn},
    Result,
};

/// Patches heap references in a table row buffer.
///
/// This function modifies the row bytes in-place, replacing old heap offsets
/// with new offsets according to the provided remapping tables. It uses the
/// centralized table schema to determine which fields contain heap references.
///
/// The function automatically skips patching if all remapping tables are empty,
/// making it safe to call unconditionally.
///
/// # Arguments
///
/// * `table_id` - The type of metadata table this row belongs to (determines field layout)
/// * `row_data` - The raw row bytes to patch (modified in place)
/// * `table_info` - Table size information for determining heap reference field widths
///   (2 bytes for small heaps, 4 bytes for large heaps)
/// * `string_remap` - Mapping from old #Strings heap offsets to new offsets
/// * `blob_remap` - Mapping from old #Blob heap offsets to new offsets
/// * `guid_remap` - Mapping from old #GUID heap indices to new indices (1-based)
///
/// # Behavior
///
/// For each heap reference field in the row:
/// 1. Reads the current offset/index from the row bytes
/// 2. Looks up the old value in the appropriate remapping table
/// 3. If found, writes the new value back to the row bytes
/// 4. If not found, leaves the value unchanged
///
/// # Errors
///
/// When a heap field lies outside the row, or its new value does not fit the field.
pub fn patch_row_heap_refs(
    table_id: TableId,
    row_data: &mut [u8],
    table_info: &TableInfoRef,
    string_remap: &HashMap<u32, u32>,
    blob_remap: &HashMap<u32, u32>,
    guid_remap: &HashMap<u32, u32>,
) -> Result<()> {
    // Skip if no remapping needed
    if string_remap.is_empty() && blob_remap.is_empty() && guid_remap.is_empty() {
        return Ok(());
    }

    // Get heap field descriptors from the centralized schema
    let fields = get_heap_fields(table_id, table_info);

    for field in fields {
        // Select the appropriate remapping table based on heap type
        let remap = match field.heap_type {
            HeapType::String => string_remap,
            HeapType::Blob => blob_remap,
            HeapType::Guid => guid_remap,
        };

        // Skip if this heap type has no remapping
        if remap.is_empty() {
            continue;
        }

        // Patch the field
        patch_heap_field(row_data, field.offset, field.size, remap)?;
    }
    Ok(())
}

/// Patches a single heap reference field in row data.
///
/// Reads the heap index/offset at the specified position, looks it up in the
/// remapping table, and writes the new value if found.
///
/// # Arguments
///
/// * `row_data` - The raw row bytes (modified in place if remapping found)
/// * `offset` - Byte offset of the field within the row
/// * `size` - Size of the field (2 or 4 bytes)
/// * `remap` - Mapping from old heap offsets/indices to new values
///
/// # Errors
///
/// When the field lies outside the row, or the new value does not fit it: the row would keep
/// a reference to the entry's old place.
fn patch_heap_field(
    row_data: &mut [u8],
    offset: usize,
    size: usize,
    remap: &HashMap<u32, u32>,
) -> Result<()> {
    let is_large = size == 4;
    let mut read_offset = offset;
    let old_value = read_le_at_dyn(row_data, &mut read_offset, is_large)?;
    if let Some(&new_value) = remap.get(&old_value) {
        let mut write_offset = offset;
        write_le_at_dyn(row_data, &mut write_offset, new_value, is_large)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patch_heap_field_small() {
        let mut data = vec![0x00, 0x00, 0x64, 0x00, 0xFF, 0xFF]; // offset 2: value 100
        let mut remap = HashMap::new();
        remap.insert(100, 200);

        patch_heap_field(&mut data, 2, 2, &remap).unwrap();

        assert_eq!(data[2], 0xC8); // 200 = 0xC8
        assert_eq!(data[3], 0x00);
    }

    #[test]
    fn test_patch_heap_field_large() {
        let mut data = vec![0x00, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        let mut remap = HashMap::new();
        remap.insert(100, 0x12345678);

        patch_heap_field(&mut data, 4, 4, &remap).unwrap();

        assert_eq!(data[4], 0x78);
        assert_eq!(data[5], 0x56);
        assert_eq!(data[6], 0x34);
        assert_eq!(data[7], 0x12);
    }

    #[test]
    fn test_patch_heap_field_no_match() {
        let original = vec![0x00, 0x00, 0x64, 0x00, 0xFF, 0xFF];
        let mut data = original.clone();
        let remap = HashMap::new(); // Empty remap

        patch_heap_field(&mut data, 2, 2, &remap).unwrap();

        assert_eq!(data, original); // Unchanged
    }

    #[test]
    fn test_patch_heap_field_out_of_bounds() {
        let mut data = vec![0x00, 0x00];
        let mut remap = HashMap::new();
        remap.insert(100, 200);

        // A field outside the row is refused, not skipped: its reference would stay unpatched
        assert!(patch_heap_field(&mut data, 10, 2, &remap).is_err());
    }

    #[test]
    fn a_new_value_too_wide_for_the_field_is_refused() {
        let mut data = vec![0x00, 0x00, 0x64, 0x00];
        let mut remap = HashMap::new();
        remap.insert(100, 0x1_0000);

        assert!(patch_heap_field(&mut data, 2, 2, &remap).is_err());
        assert_eq!(data, [0x00, 0x00, 0x64, 0x00], "nothing is written");
    }
}

#[cfg(test)]
mod examples {
    use std::collections::HashMap;

    use super::*;
    use crate::{testkit::fixture, CilAssemblyView};

    /// A TypeDef row whose name string moved from offset 0x10 to 0x20: the name column is
    /// patched, the namespace column, whose string did not move, is left alone.
    #[test]
    fn module_example() -> Result<()> {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))?;
        let table_info = view.tables().expect("tables").info.clone();

        // Flags (4), Name, Namespace, Extends, FieldList, MethodList (two bytes each)
        let mut row_bytes = [0u8; 14];
        row_bytes[4..6].copy_from_slice(&0x10u16.to_le_bytes());
        row_bytes[6..8].copy_from_slice(&0x30u16.to_le_bytes());
        let string_remapping = HashMap::from([(0x10, 0x20)]);

        patch_row_heap_refs(
            TableId::TypeDef,
            &mut row_bytes,
            &table_info,
            &string_remapping,
            &HashMap::new(),
            &HashMap::new(),
        )?;

        assert_eq!(row_bytes[4..6], 0x20u16.to_le_bytes());
        assert_eq!(row_bytes[6..8], 0x30u16.to_le_bytes());
        Ok(())
    }
}
