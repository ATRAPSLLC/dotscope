//! Factory methods for raw modification operation validation testing.
//!
//! Contains helper methods migrated from raw modification operation validation source files
//! for creating test assemblies with various operation validation scenarios.

use crate::{
    cilassembly::{AssemblyChanges, Operation, TableModifications, TableOperation},
    metadata::{
        tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
        token::Token,
    },
    testkit::{get_testfile_wb, TestAssembly},
    Result,
};
/// Test factory for RawOperationValidator following the golden pattern.
///
/// Creates test assemblies covering basic operation validation scenarios.
/// Note: This validator primarily uses direct corruption testing rather than file-based tests.
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn raw_operation_validator_file_factory() -> Result<Vec<TestAssembly>> {
    // A clean test assembly passes operation validation when it has no modifications.
    // File-based corruption testing is complex for modification validators since they only run
    // during modification validation contexts; the direct corruption test
    // (test_raw_operation_validator_direct_corruption) creates corrupted modifications in memory
    // and tests them directly.
    Ok(vec![TestAssembly::new(get_testfile_wb())])
}

/// Helper function to create a dummy TypeDef for testing purposes
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_dummy_typedef(rid: u32, flags: u32) -> TypeDefRaw {
    TypeDefRaw {
        rid,
        token: Token::new(0x02000000 | rid),
        offset: 0,
        flags,
        type_name: 1,
        type_namespace: 0,
        extends: CodedIndex::null(CodedIndexType::TypeDefOrRef),
        field_list: 1,
        method_list: 1,
    }
}

/// Creates corrupted changes with invalid RID zero
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_invalid_rid_zero() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with invalid RID 0
    let invalid_op = TableOperation::new(Operation::Insert(0, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with excessive RID
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_excessive_rid() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create operation with RID exceeding 0xFFFFFF (24-bit limit)
    let invalid_op = TableOperation::new(Operation::Insert(0x1000000, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with nonexistent target
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_nonexistent_target() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1); // original_row_count = 0

    let invalid_typedef = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(invalid_typedef);

    // Create update operation targeting RID 999 that doesn't exist
    let invalid_op = TableOperation::new(Operation::Update(999, table_data));

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(invalid_op);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with update after delete
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_update_after_delete() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(2); // original_row_count = 1

    let typedef_data = create_dummy_typedef(1, 0);
    let table_data = TableDataOwned::TypeDef(typedef_data);

    // Create delete operation followed by update operation (invalid sequence)
    let delete_op = TableOperation::new_with_timestamp(Operation::Delete(1), 1000);
    let update_op = TableOperation::new_with_timestamp(Operation::Update(1, table_data), 2000);

    if let TableModifications::Sparse {
        operations,
        deleted_rows,
        ..
    } = &mut table_mods
    {
        operations.push(delete_op);
        operations.push(update_op);
        deleted_rows.insert(1); // Mark as deleted
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with unordered operations
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_unordered_operations() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create operations with non-chronological timestamps
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        2000, // Later timestamp
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(2, TableDataOwned::TypeDef(typedef_data2)),
        1000, // Earlier timestamp
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        // Add in wrong order (later timestamp first)
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}

/// Creates corrupted changes with conflicting inserts
///
/// Originally from: `src/metadata/validation/validators/raw/modification/operation.rs`
pub fn create_corrupted_changes_with_conflicting_inserts() -> AssemblyChanges {
    let mut corrupted_changes = AssemblyChanges::empty();
    let mut table_mods = TableModifications::new_sparse(1);

    let typedef_data1 = create_dummy_typedef(1, 0);
    let typedef_data2 = create_dummy_typedef(2, 1);

    // Create multiple insert operations targeting the same RID
    let op1 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data1)),
        1000,
    );
    let op2 = TableOperation::new_with_timestamp(
        Operation::Insert(1, TableDataOwned::TypeDef(typedef_data2)),
        2000,
    );

    if let TableModifications::Sparse { operations, .. } = &mut table_mods {
        operations.push(op1);
        operations.push(op2);
    }

    corrupted_changes
        .table_changes
        .insert(TableId::TypeDef, table_mods);
    corrupted_changes
}
