//! Metadata table and heap calculation utilities.
//!
//! This module provides utilities for calculating sizes and offsets in .NET metadata
//! structures. These utilities are used throughout the framework for layout planning,
//! binary generation, and validation.
//!
//! # Table Row Size Calculation
//!
//! The primary utility is dynamic metadata table row size calculation, which accounts
//! for variable-sized fields based on actual table row counts and heap sizes.
//!
//! # Examples
//!
//! The `examples::calculate_table_row_size_example` test in this module runs this example.

use crate::{
    dispatch_table_type,
    metadata::tables::{TableId, TableInfoRef, TableRow},
};

/// Calculates the exact row size for any ECMA-335 metadata table using dynamic schema information.
///
/// This function provides centralized, accurate row size calculation for all metadata table
/// types defined in ECMA-335 Partition II. It accounts for variable-sized fields based on
/// actual table row counts and heap sizes, ensuring consistent size calculations throughout
/// the framework.
///
/// The calculation is crucial for layout planning and binary generation because metadata
/// table row sizes are not fixed—they depend on the current state of the assembly being
/// processed. Index fields and references use variable sizes (2 or 4 bytes) based on whether
/// they can fit within 16-bit limits.
///
/// # Arguments
///
/// * `table_id` - The [`TableId`] identifying which metadata table type to calculate the row size for
/// * `table_info` - A [`TableInfoRef`] containing the current metadata state, including
///   row counts for all tables and heap sizes
///
/// # Returns
///
/// Returns the exact row size in bytes as a [`u32`] for the specified table type.
/// The size accounts for all fields in the table schema including:
/// - Fixed-size fields (flags, constants, etc.)
/// - Variable-size table indexes (2 or 4 bytes based on row count)
/// - Variable-size heap indexes (2 or 4 bytes based on heap size)
/// - Variable-size coded indexes (2 or 4 bytes based on multiple table sizes)
///
/// # Examples
///
/// The `examples::calculate_table_row_size_example` test in this module runs this example.
pub fn calculate_table_row_size(table_id: TableId, table_info: &TableInfoRef) -> u32 {
    dispatch_table_type!(table_id, |RawType| RawType::row_size(table_info))
}

#[cfg(test)]
mod tests {
    // Note: These tests would require actual metadata structures to be meaningful
    // For now, we include basic compilation tests

    #[test]
    fn test_calculate_table_row_size_compiles() {
        // This test ensures the function compiles and can be called
        // Real tests would require setting up TableInfoRef with actual data
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{
        metadata::tables::{FieldRaw, MethodDefRaw, TableId, TypeDefRaw},
        testkit::fixture,
        CilAssemblyView, Result,
    };

    /// crafted_2's heaps and tables are small, so every index is two bytes: a TypeDef row is
    /// Flags (4) and five two-byte columns, a MethodDef row RVA (4) and five two-byte columns,
    /// a Field row three two-byte columns (ECMA-335 II.22).
    #[test]
    fn calculate_table_row_size_example() -> Result<()> {
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))?;
        let tables = view.tables().expect("tables");
        let info = &tables.info;

        assert_eq!(calculate_table_row_size(TableId::TypeDef, info), 14);
        assert_eq!(calculate_table_row_size(TableId::MethodDef, info), 14);
        assert_eq!(calculate_table_row_size(TableId::Field, info), 6);

        // The parsed tables agree.
        assert_eq!(tables.table::<TypeDefRaw>().expect("TypeDef").row_size, 14);
        assert_eq!(
            tables.table::<MethodDefRaw>().expect("MethodDef").row_size,
            14
        );
        assert_eq!(tables.table::<FieldRaw>().expect("Field").row_size, 6);
        Ok(())
    }
}
