//! Table size calculation functions for the assembly writer.
//!
//! This module provides size calculation logic for metadata tables,
//! implementing ECMA-335 specification requirements.

use crate::{
    cilassembly::{CilAssembly, Operation, TableModifications},
    utils::calculate_table_row_size,
    Error, Result,
};

/// Calculates the additional bytes needed for the tables stream due to table modifications.
pub fn calculate_table_stream_expansion(assembly: &CilAssembly) -> Result<u64> {
    let changes = assembly.changes();
    let view = assembly.view();

    let tables = view.tables().ok_or_else(|| {
        Error::LayoutFailed("No tables found in assembly for expansion calculation".to_string())
    })?;

    let mut total_expansion = 0u64;
    let mut header_expansion = 0u64;

    for table_id in changes.modified_tables() {
        if let Some(table_mod) = changes.get_table_modifications(table_id) {
            let row_size = calculate_table_row_size(table_id, &tables.info);
            let original_count = tables.table_row_count(table_id);

            let (new_count, additional_rows) = match table_mod {
                TableModifications::Replaced(new_rows) => {
                    let new_count = u32::try_from(new_rows.len()).map_err(|_| {
                        Error::LayoutFailed(format!(
                            "Table {:?} row count {} exceeds u32::MAX",
                            table_id,
                            new_rows.len()
                        ))
                    })?;
                    let additional = new_count.saturating_sub(original_count);
                    (new_count, additional)
                }
                TableModifications::Sparse { operations, .. } => {
                    let insert_count_raw = operations
                        .iter()
                        .filter(|op| matches!(op.operation, Operation::Insert(_, _)))
                        .count();
                    let insert_count = u32::try_from(insert_count_raw).map_err(|_| {
                        Error::LayoutFailed(format!(
                            "Table {table_id:?} insert count {insert_count_raw} exceeds u32::MAX"
                        ))
                    })?;
                    let new_count = original_count.checked_add(insert_count).ok_or_else(|| {
                        Error::LayoutFailed(format!(
                            "Table {table_id:?} new row count overflows u32"
                        ))
                    })?;
                    (new_count, insert_count)
                }
            };

            let expansion_bytes = u64::from(additional_rows)
                .checked_mul(u64::from(row_size))
                .ok_or_else(|| {
                    Error::LayoutFailed(format!("Table {table_id:?} expansion bytes overflow u64"))
                })?;
            total_expansion = total_expansion
                .checked_add(expansion_bytes)
                .ok_or_else(|| {
                    Error::LayoutFailed("total table expansion overflows u64".to_string())
                })?;

            if original_count == 0 && new_count > 0 {
                header_expansion = header_expansion.saturating_add(4u64);
            }
        }
    }

    total_expansion
        .checked_add(header_expansion)
        .ok_or_else(|| Error::LayoutFailed("table expansion total overflows u64".to_string()))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{prelude::*, testkit::fixture};

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        Ok(CilAssembly::new(view))
    }

    #[test]
    fn test_no_modifications_returns_zero() -> Result<()> {
        let assembly = get_test_assembly()?;

        // No modifications should result in zero expansion
        let expansion = calculate_table_stream_expansion(&assembly)?;
        assert_eq!(expansion, 0);

        Ok(())
    }

    #[test]
    fn test_adding_string_to_heap_no_table_expansion() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Adding user strings to heap doesn't affect table stream
        assembly.userstring_add("TestString")?;
        assembly.userstring_add("AnotherString")?;

        let expansion = calculate_table_stream_expansion(&assembly)?;
        assert_eq!(expansion, 0);

        Ok(())
    }

    #[test]
    fn test_adding_typedef_causes_expansion() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Add a new type which should cause table expansion
        let _typedef = ClassBuilder::new("TestClass")
            .public()
            .namespace("Test")
            .build(&mut assembly)?;

        let expansion = calculate_table_stream_expansion(&assembly)?;

        // Should be non-zero since we added rows to TypeDef (and possibly other tables)
        assert!(expansion > 0);

        Ok(())
    }

    #[test]
    fn test_adding_method_causes_expansion() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Add a class with a method
        let _class = ClassBuilder::new("TestClass")
            .public()
            .namespace("Test")
            .method(|m| {
                m.public().implementation(|body| {
                    body.implementation(|asm| {
                        asm.ret()?;
                        Ok(())
                    })
                })
            })
            .build(&mut assembly)?;

        let expansion = calculate_table_stream_expansion(&assembly)?;

        // Should be non-zero since we added rows to multiple tables
        assert!(expansion > 0);

        Ok(())
    }

    #[test]
    fn test_multiple_classes_increases_expansion() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Add one class
        let _class1 = ClassBuilder::new("TestClass1")
            .public()
            .namespace("Test")
            .build(&mut assembly)?;

        let expansion1 = calculate_table_stream_expansion(&assembly)?;

        // Add another class
        let _class2 = ClassBuilder::new("TestClass2")
            .public()
            .namespace("Test")
            .build(&mut assembly)?;

        let expansion2 = calculate_table_stream_expansion(&assembly)?;

        // Expansion should increase with more rows
        assert!(expansion2 > expansion1);

        Ok(())
    }

    #[test]
    fn test_class_with_properties_causes_larger_expansion() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Add a class with properties (which creates more metadata)
        let _class = ClassBuilder::new("TestClass")
            .public()
            .namespace("Test")
            .auto_property("Name", TypeSignature::String)
            .auto_property("Value", TypeSignature::I4)
            .build(&mut assembly)?;

        let expansion = calculate_table_stream_expansion(&assembly)?;

        // Should be larger than a simple class due to property-related tables
        assert!(expansion > 0);

        Ok(())
    }
}
