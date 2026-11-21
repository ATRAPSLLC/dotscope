//! Table modification tracking and management.
//!
//! This module provides the [`crate::cilassembly::modifications::TableModifications`]
//! enumeration for tracking changes to metadata tables during assembly modification operations.
//! It supports two different modification strategies optimized for different usage patterns.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::modifications::TableModifications`] - Core table modification tracking with sparse and replacement strategies
//!
//! # Architecture
//!
//! The module implements two distinct strategies for tracking table modifications:
//!
//! ## Sparse Modifications
//! - Track individual operations (Insert/Update/Delete) with timestamps
//! - Memory-efficient for tables with few changes
//! - Supports conflict detection and resolution
//! - Operations are stored chronologically for proper ordering
//!
//! **RID Assumption:** Per ECMA-335, RIDs (Row IDs) in metadata tables are 1-based and
//! contiguous. A table with `n` rows contains RIDs 1 through n inclusive. This module
//! relies on this property when checking row existence via [`TableModifications::has_row`].
//!
//! ## Complete Replacement
//! - Replace entire table content with new data
//! - More efficient for heavily modified tables
//! - Simpler conflict resolution (no conflicts possible)
//! - Better performance for bulk operations
//!
//! # Usage Examples
//!
//! ```
//! use dotscope::{metadata::tables::TableId, CilAssembly};
//!
//! let mut assembly = CilAssembly::from_path("tests/samples/crafted_2.exe")?;
//!
//! // Removing a row records the operation in its table's modifications
//! assembly.table_row_remove(TableId::TypeRef, 1)?;
//!
//! // Check for modifications
//! if let Some(modifications) = assembly.changes().get_table_modifications(TableId::TypeRef) {
//!     if modifications.has_modifications() {
//!         println!("Table has {} operations", modifications.operation_count());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is not [`Send`] or [`Sync`] as it contains mutable state that is not
//! protected by synchronization primitives and is designed for single-threaded assembly modification.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Overall change tracking
//! - [`crate::cilassembly::operation`] - Operation definitions and management
//! - Assembly validation - Validation and conflict resolution

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{changes::ChangeRefRc, Operation, TableOperation},
    metadata::tables::TableDataOwned,
    Error, Result,
};

/// Represents modifications to a specific metadata table.
///
/// This enum provides two different strategies for tracking changes to metadata tables,
/// each optimized for different modification patterns. It integrates with
/// [`crate::cilassembly::operation::TableOperation`] to maintain chronological ordering
/// and conflict resolution capabilities.
///
/// # Modification Strategies
///
/// 1. **Sparse modifications** - Individual row operations (insert, update, delete)
/// 2. **Complete replacement** - Replace the entire table content
///
/// Sparse modifications are more memory-efficient for few changes, while
/// complete replacement is better for heavily modified tables.
///
/// # Usage Examples
///
/// ```
/// use dotscope::{metadata::tables::TableId, CilAssembly};
///
/// let mut assembly = CilAssembly::from_path("tests/samples/crafted_2.exe")?;
/// assembly.table_row_remove(TableId::TypeRef, 1)?;
///
/// if let Some(modifications) = assembly
///     .changes_mut()
///     .get_table_modifications_mut(TableId::TypeRef)
/// {
///     // The removed row no longer exists
///     assert!(!modifications.has_row(1));
///
///     // Consolidate the operations recorded so far
///     modifications.consolidate_operations();
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is not [`Send`] or [`Sync`] as it contains mutable collections
/// and is designed for single-threaded modification operations.
#[derive(Debug, Clone)]
pub enum TableModifications {
    /// Sparse modifications with ordered operation tracking.
    ///
    /// This variant tracks individual operations chronologically, allowing
    /// for conflict detection and resolution. Operations are applied in
    /// timestamp order during consolidation.
    Sparse {
        /// Chronologically ordered operations
        ///
        /// Operations are stored in timestamp order, equal timestamps in the order they
        /// were applied, for conflict resolution.
        operations: Vec<TableOperation>,

        /// Quick lookup for deleted RIDs
        ///
        /// This set is maintained for efficient deletion checks without
        /// scanning through all operations.
        deleted_rows: HashSet<u32>,

        /// Quick lookup for inserted RIDs
        ///
        /// This set is maintained for efficient insertion checks without
        /// scanning through all operations.
        inserted_rows: HashSet<u32>,

        /// ChangeRef tracking for inserted rows
        ///
        /// Maps RID to ChangeRefRc for rows that were inserted. This enables
        /// the writer to resolve placeholders to final RIDs/tokens.
        change_refs: HashMap<u32, ChangeRefRc>,

        /// Next available RID for new rows
        ///
        /// This tracks the next RID that would be assigned to a newly
        /// inserted row, accounting for both original and added rows.
        next_rid: u32,

        /// The number of rows in the original table before modifications.
        ///
        /// This is used to determine if a RID exists in the original table
        /// when validating operations.
        original_row_count: u32,
    },

    /// Complete table replacement - for heavily modified tables.
    ///
    /// When a table has been modified extensively, it's more efficient
    /// to replace the entire table content rather than tracking individual
    /// sparse operations.
    Replaced(Vec<TableDataOwned>),
}

impl TableModifications {
    /// Creates a new sparse table modifications tracker.
    ///
    /// Initializes a new sparse modification tracker that will track individual
    /// operations chronologically. The `next_rid` parameter determines where
    /// new row insertions will begin.
    ///
    /// # Arguments
    ///
    /// * `next_rid` - The next available RID for new row insertions
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::modifications::TableModifications::Sparse`] variant
    /// ready to track operations.
    pub fn new_sparse(next_rid: u32) -> Self {
        let original_row_count = next_rid.saturating_sub(1);
        Self::Sparse {
            operations: Vec::new(),
            deleted_rows: HashSet::new(),
            inserted_rows: HashSet::new(),
            change_refs: HashMap::new(),
            next_rid,
            original_row_count,
        }
    }

    /// Creates a table replacement with the given rows.
    ///
    /// Initializes a complete table replacement with the provided row data.
    /// This is more efficient than sparse modifications when replacing most
    /// or all of a table's content.
    ///
    /// # Arguments
    ///
    /// * `rows` - The complete set of rows to replace the table with
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::modifications::TableModifications::Replaced`] variant
    /// containing the provided rows.
    pub fn new_replaced(rows: Vec<TableDataOwned>) -> Self {
        Self::Replaced(rows)
    }

    /// Returns the number of operations tracked in this modification.
    pub fn operation_count(&self) -> usize {
        match self {
            Self::Sparse { operations, .. } => operations.len(),
            Self::Replaced(rows) => rows.len(),
        }
    }

    /// Returns true if this table has any modifications.
    pub fn has_modifications(&self) -> bool {
        match self {
            Self::Sparse { operations, .. } => !operations.is_empty(),
            Self::Replaced(rows) => !rows.is_empty(),
        }
    }

    /// Apply a new operation, handling conflicts and maintaining consistency.
    ///
    /// This method validates the operation, detects conflicts with existing
    /// operations, and applies appropriate conflict resolution.
    ///
    /// # Arguments
    ///
    /// * `op` - The operation to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the operation was applied successfully, or an error
    /// describing why the operation could not be applied.
    pub fn apply_operation(&mut self, op: TableOperation) -> Result<()> {
        // Reject Delete/Update on RIDs that have never existed in the
        // table (rid > original_count and not inserted). Stale RIDs from
        // upstream techniques marking tokens that have already been
        // shifted out of the table by intermediate regenerations would
        // otherwise inflate `calculate_table_row_count`'s delete count
        // without removing any actual row, shifting the header's row
        // counts out of sync with the bytes the writer emits — corrupting
        // every table that follows in the layout.
        //
        // Note: Update on a row that's been Deleted is intentionally
        // allowed (it implements the "un-delete via update" pattern);
        // duplicate Delete is handled below.
        if let Operation::Delete(rid) | Operation::Update(rid, _) = &op.operation {
            let rid = *rid;
            let in_table = rid != 0
                && match self {
                    Self::Sparse {
                        next_rid,
                        inserted_rows,
                        ..
                    } => rid < *next_rid || inserted_rows.contains(&rid),
                    Self::Replaced(rows) => (rid as usize) <= rows.len(),
                };
            if !in_table {
                let kind = match &op.operation {
                    Operation::Delete(_) => "delete",
                    Operation::Update(_, _) => "update",
                    _ => unreachable!(),
                };
                return Err(Error::ModificationInvalid(format!(
                    "RID {rid} not in table — cannot {kind} a row that never existed"
                )));
            }
        }

        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                inserted_rows,
                next_rid,
                ..
            } => {
                // Check for duplicate delete operations - skip if already deleted
                if let Operation::Delete(rid) = &op.operation {
                    if deleted_rows.contains(rid) {
                        return Ok(()); // Already deleted, no-op
                    }
                }

                // Insert in chronological order, maintaining FIFO for equal timestamps.
                // binary_search_by_key returns Ok(index) if found, which would insert BEFORE
                // existing entries with the same timestamp. We need to insert AFTER all
                // entries with the same timestamp to maintain insertion order.
                let insert_pos =
                    match operations.binary_search_by_key(&op.timestamp, |o| o.timestamp) {
                        Ok(mut pos) => {
                            // Found an entry with the same timestamp - scan forward to find the
                            // end of all entries with this timestamp (FIFO ordering)
                            while operations
                                .get(pos)
                                .is_some_and(|o| o.timestamp == op.timestamp)
                            {
                                pos = pos.saturating_add(1);
                            }
                            pos
                        }
                        Err(pos) => pos, // Not found - insert at the natural position
                    };
                operations.insert(insert_pos, op);

                // Update auxiliary data structures
                let inserted_op = operations.get(insert_pos).ok_or_else(|| {
                    crate::malformed_error!("inserted operation index out of bounds")
                })?;
                match &inserted_op.operation {
                    Operation::Insert(rid, _) => {
                        inserted_rows.insert(*rid);
                        if *rid >= *next_rid {
                            *next_rid = rid
                                .checked_add(1)
                                .ok_or_else(|| crate::malformed_error!("next_rid overflows u32"))?;
                        }
                    }
                    Operation::Delete(rid) => {
                        deleted_rows.insert(*rid);
                        inserted_rows.remove(rid);
                    }
                    Operation::Update(rid, _) => {
                        deleted_rows.remove(rid);
                    }
                }

                Ok(())
            }
            Self::Replaced(_) => Err(Error::CannotModifyReplacedTable),
        }
    }

    /// How far the table's sparse changes reach: the number of operations
    /// recorded and the next row an insert takes, or `None` for a replaced
    /// table.
    #[cfg(feature = "compiler")]
    pub fn extent(&self) -> Option<(usize, u32)> {
        match self {
            Self::Sparse {
                operations,
                next_rid,
                ..
            } => Some((operations.len(), *next_rid)),
            Self::Replaced(_) => None,
        }
    }

    /// The number of rows inserted at `rid` or after, as recorded operations.
    #[cfg(feature = "compiler")]
    pub fn inserted_since(&self, rid: u32) -> usize {
        match self {
            Self::Sparse { operations, .. } => operations
                .iter()
                .filter(
                    |op| matches!(op.operation, Operation::Insert(inserted, _) if inserted >= rid),
                )
                .count(),
            Self::Replaced(_) => 0,
        }
    }

    /// Undoes every insert made since [`Self::extent`] read `extent`.
    ///
    /// # Errors
    ///
    /// Returns an error, changing nothing, when the table changed in any other
    /// way since: it was replaced, or a row was updated or deleted, which only
    /// the operation's own inverse could undo.
    #[cfg(feature = "compiler")]
    pub fn rollback_inserts(&mut self, extent: (usize, u32)) -> Result<()> {
        let (operations_before, rid_before) = extent;
        let undone = self.inserted_since(rid_before);
        let Self::Sparse {
            operations,
            inserted_rows,
            change_refs,
            next_rid,
            ..
        } = self
        else {
            return Err(Error::ModificationInvalid(
                "a replaced table cannot be rolled back to its sparse extent".to_string(),
            ));
        };
        if operations.len().saturating_sub(undone) != operations_before {
            return Err(Error::ModificationInvalid(format!(
                "table changed by more than inserts since its extent ({operations_before} operations, next row {rid_before})"
            )));
        }
        operations
            .retain(|op| !matches!(op.operation, Operation::Insert(rid, _) if rid >= rid_before));
        inserted_rows.retain(|rid| *rid < rid_before);
        change_refs.retain(|rid, _| *rid < rid_before);
        *next_rid = rid_before;
        Ok(())
    }

    /// Consolidate operations to remove superseded operations and optimize memory.
    ///
    /// This method removes operations that have been superseded by later operations
    /// on the same RID, reducing memory usage and improving performance.
    /// This is critical for builder APIs that may generate many operations.
    pub fn consolidate_operations(&mut self) {
        match self {
            Self::Sparse {
                operations,
                deleted_rows,
                inserted_rows,
                ..
            } => {
                if operations.is_empty() {
                    return;
                }

                // Group operations by RID and keep only the latest operation for each RID
                let mut latest_ops: std::collections::HashMap<u32, usize> =
                    std::collections::HashMap::new();

                // Find the latest operation for each RID
                for (index, op) in operations.iter().enumerate() {
                    let rid = op.operation.get_rid();
                    latest_ops.insert(rid, index);
                }

                // Collect indices of operations to keep (in reverse order for efficient removal)
                let mut indices_to_remove: Vec<usize> = Vec::new();
                for (index, op) in operations.iter().enumerate() {
                    let rid = op.operation.get_rid();
                    if latest_ops.get(&rid) != Some(&index) {
                        indices_to_remove.push(index);
                    }
                }

                // Remove superseded operations (from highest index to lowest)
                indices_to_remove.sort_unstable();
                for &index in indices_to_remove.iter().rev() {
                    operations.remove(index);
                }

                // Rebuild auxiliary sets based on final operation state
                deleted_rows.clear();
                inserted_rows.clear();
                for op in operations {
                    match &op.operation {
                        Operation::Delete(rid) => {
                            deleted_rows.insert(*rid);
                        }
                        Operation::Insert(rid, _) => {
                            inserted_rows.insert(*rid);
                        }
                        Operation::Update(_, _) => {}
                    }
                }
            }
            Self::Replaced(_) => {
                // Replaced tables are already consolidated
            }
        }
    }

    /// Validate that an operation is safe to apply.
    ///
    /// This method checks various constraints to ensure the operation
    /// can be safely applied without violating metadata integrity.
    pub fn validate_operation(&self, op: &TableOperation) -> Result<()> {
        match &op.operation {
            Operation::Insert(rid, _) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalid(format!(
                        "RID cannot be zero: {rid}"
                    )));
                }

                // Check if we already have a row at this RID
                if self.has_row(*rid) {
                    return Err(Error::ModificationInvalid(format!(
                        "Cannot insert row: RID {rid} already exists in table (duplicate insert or existing row)"
                    )));
                }

                Ok(())
            }
            Operation::Update(rid, _) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalid(format!(
                        "RID cannot be zero: {rid}"
                    )));
                }

                // Check if the row exists to update
                if !self.has_row(*rid) {
                    return Err(Error::ModificationInvalid(format!(
                        "RID {rid} not found for update"
                    )));
                }

                Ok(())
            }
            Operation::Delete(rid) => {
                if *rid == 0 {
                    return Err(Error::ModificationInvalid(format!(
                        "RID cannot be zero: {rid}"
                    )));
                }

                // Check if the row exists to delete
                if !self.has_row(*rid) {
                    return Err(Error::ModificationInvalid(format!(
                        "RID {rid} not found for deletion"
                    )));
                }

                Ok(())
            }
        }
    }

    /// Check if a RID exists (considering all operations and original table state).
    ///
    /// This method checks if a row with the given RID exists, taking into account
    /// the original table row count and all applied operations.
    ///
    /// # RID Contiguity Assumption
    ///
    /// Per ECMA-335 §II.22, metadata table RIDs are 1-based and contiguous. A table
    /// with `n` rows contains RIDs 1 through n. This method relies on this property
    /// when checking if a RID exists in the original table: any RID in range `[1, original_row_count]`
    /// is considered to exist unless explicitly deleted.
    pub fn has_row(&self, rid: u32) -> bool {
        match self {
            Self::Sparse {
                deleted_rows,
                inserted_rows,
                ..
            } => {
                // Check if it's been explicitly deleted
                if deleted_rows.contains(&rid) {
                    return false;
                }

                // Check if there's an insert operation for this RID
                if inserted_rows.contains(&rid) {
                    return true;
                }

                // Check if it exists in the original table
                // Note: This assumes RIDs are 1-based and contiguous in the original table
                rid > 0 && rid <= self.original_row_count()
            }
            Self::Replaced(rows) => {
                // For replaced tables, check if the RID is within the row count
                rid > 0 && (rid as usize) <= rows.len()
            }
        }
    }

    /// Returns the original row count for this table (before modifications).
    ///
    /// This is used by `has_row` to determine if a RID exists in the original table.
    /// For sparse modifications, this is stored when creating the modifications.
    /// For replaced tables, this information is not relevant.
    fn original_row_count(&self) -> u32 {
        match self {
            Self::Sparse {
                original_row_count, ..
            } => *original_row_count,
            Self::Replaced(_) => 0, // Not applicable for replaced tables
        }
    }

    /// Registers a ChangeRef for an inserted row.
    ///
    /// This should be called after successfully inserting a row to track the
    /// ChangeRef for later resolution during the write phase.
    ///
    /// # Arguments
    ///
    /// * `rid` - The RID of the inserted row
    /// * `change_ref` - The ChangeRef to track for this row
    pub fn register_change_ref(&mut self, rid: u32, change_ref: ChangeRefRc) {
        if let Self::Sparse { change_refs, .. } = self {
            change_refs.insert(rid, change_ref);
        }
    }

    /// Gets the ChangeRef for a specific RID, if one exists.
    ///
    /// # Arguments
    ///
    /// * `rid` - The RID to look up
    ///
    /// # Returns
    ///
    /// The ChangeRef for the given RID if it was an inserted row with a tracked ChangeRef.
    pub fn get_change_ref(&self, rid: u32) -> Option<&ChangeRefRc> {
        match self {
            Self::Sparse { change_refs, .. } => change_refs.get(&rid),
            Self::Replaced(_) => None,
        }
    }

    /// Returns an iterator over all tracked ChangeRefs for inserted rows.
    ///
    /// This is used during the write phase to resolve all table row ChangeRefs.
    pub fn change_refs(&self) -> impl Iterator<Item = (&u32, &ChangeRefRc)> {
        match self {
            Self::Sparse { change_refs, .. } => {
                Box::new(change_refs.iter()) as Box<dyn Iterator<Item = (&u32, &ChangeRefRc)>>
            }
            Self::Replaced(_) => Box::new(std::iter::empty()),
        }
    }

    /// Returns an iterator over all deleted RIDs.
    ///
    /// This is used during the write phase to skip processing of deleted rows,
    /// including skipping field data for deleted FieldRVA entries.
    pub fn deleted_rids(&self) -> impl Iterator<Item = u32> + '_ {
        match self {
            Self::Sparse { deleted_rows, .. } => {
                Box::new(deleted_rows.iter().copied()) as Box<dyn Iterator<Item = u32>>
            }
            Self::Replaced(_) => Box::new(std::iter::empty()),
        }
    }

    /// Returns the next RID that will be assigned for new inserts.
    ///
    /// # Errors
    ///
    /// Returns an error if the number of rows exceeds u32::MAX, which would indicate
    /// an invalid assembly state (metadata tables use 32-bit RIDs per ECMA-335).
    pub fn next_rid(&self) -> crate::Result<u32> {
        match self {
            Self::Sparse { next_rid, .. } => Ok(*next_rid),
            Self::Replaced(rows) => {
                let len = u32::try_from(rows.len()).map_err(|_| {
                    Error::LayoutFailed(format!(
                        "Table row count {} exceeds maximum u32 value",
                        rows.len()
                    ))
                })?;
                len.checked_add(1).ok_or_else(|| {
                    Error::LayoutFailed(format!(
                        "Table row count {} + 1 exceeds u32::MAX",
                        rows.len()
                    ))
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::{Operation, TableOperation},
        metadata::{
            tables::{ModuleRaw, TableDataOwned},
            token::Token,
        },
    };

    /// Helper to create a simple ModuleRaw for testing
    fn make_test_row(name_idx: u32) -> TableDataOwned {
        TableDataOwned::Module(ModuleRaw {
            rid: 1,
            token: Token::new(0x00000001),
            offset: 0,
            generation: 0,
            name: name_idx,
            mvid: 1,
            encid: 0,
            encbaseid: 0,
        })
    }

    /// Helper to create a TableOperation with a specific timestamp
    fn make_op_with_timestamp(op: Operation, timestamp: u64) -> TableOperation {
        TableOperation::new_with_timestamp(op, timestamp)
    }

    #[test]
    fn test_table_modifications_creation() {
        let sparse = TableModifications::new_sparse(1);
        assert!(!sparse.has_modifications());
        assert_eq!(sparse.operation_count(), 0);

        let replaced = TableModifications::new_replaced(vec![]);
        assert!(!replaced.has_modifications());
        assert_eq!(replaced.operation_count(), 0);
    }

    #[test]
    fn test_sparse_with_existing_rows() {
        // Create sparse with 5 existing rows (next_rid = 6)
        let sparse = TableModifications::new_sparse(6);
        assert!(!sparse.has_modifications());

        // Original rows 1-5 should exist
        assert!(sparse.has_row(1));
        assert!(sparse.has_row(5));
        assert!(!sparse.has_row(6)); // Not yet inserted
        assert!(!sparse.has_row(0)); // RID 0 never exists
    }

    #[test]
    fn test_apply_insert_operation() {
        let mut mods = TableModifications::new_sparse(1);
        let row = make_test_row(100);
        let op = TableOperation::new(Operation::Insert(1, row));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(mods.has_row(1));
    }

    /// Rows inserted after an extent was read are undone, and the table's
    /// next row is the one it was then.
    #[cfg(feature = "compiler")]
    #[test]
    fn rollback_undoes_the_inserts_since_the_extent() {
        let mut mods = TableModifications::new_sparse(3);
        mods.apply_operation(TableOperation::new(Operation::Insert(3, make_test_row(1))))
            .unwrap();
        let extent = mods.extent().unwrap();
        for rid in 4..6 {
            mods.apply_operation(TableOperation::new(Operation::Insert(
                rid,
                make_test_row(rid),
            )))
            .unwrap();
        }
        assert_eq!(mods.inserted_since(extent.1), 2);
        mods.rollback_inserts(extent).unwrap();
        assert_eq!(mods.extent(), Some(extent));
        assert!(mods.has_row(3));
        assert!(!mods.has_row(4));
        assert_eq!(mods.next_rid().unwrap(), 4);
    }

    /// A table updated since its extent is refused, unchanged: an update is
    /// not an insert, and dropping it would lose a change made on purpose.
    #[cfg(feature = "compiler")]
    #[test]
    fn rollback_refuses_a_table_changed_by_more_than_inserts() {
        let mut mods = TableModifications::new_sparse(3);
        let extent = mods.extent().unwrap();
        mods.apply_operation(TableOperation::new(Operation::Insert(3, make_test_row(1))))
            .unwrap();
        mods.apply_operation(TableOperation::new(Operation::Update(1, make_test_row(2))))
            .unwrap();
        assert!(mods.rollback_inserts(extent).is_err());
        assert_eq!(mods.operation_count(), 2);
        assert!(mods.has_row(3));
    }

    #[test]
    fn test_apply_update_operation() {
        // Create with 5 existing rows
        let mut mods = TableModifications::new_sparse(6);
        let row = make_test_row(200);
        let op = TableOperation::new(Operation::Update(3, row));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(mods.has_row(3)); // Row still exists after update
    }

    #[test]
    fn test_apply_delete_operation() {
        // Create with 5 existing rows
        let mut mods = TableModifications::new_sparse(6);
        let op = TableOperation::new(Operation::Delete(3));

        assert!(mods.apply_operation(op).is_ok());
        assert!(mods.has_modifications());
        assert_eq!(mods.operation_count(), 1);
        assert!(!mods.has_row(3)); // Row no longer exists
        assert!(mods.has_row(2)); // Other rows still exist
        assert!(mods.has_row(4));
    }

    #[test]
    fn test_validate_operation_rid_zero() {
        let mods = TableModifications::new_sparse(6);

        // Insert with RID 0 should fail
        let insert_op = TableOperation::new(Operation::Insert(0, make_test_row(1)));
        assert!(mods.validate_operation(&insert_op).is_err());

        // Update with RID 0 should fail
        let update_op = TableOperation::new(Operation::Update(0, make_test_row(1)));
        assert!(mods.validate_operation(&update_op).is_err());

        // Delete with RID 0 should fail
        let delete_op = TableOperation::new(Operation::Delete(0));
        assert!(mods.validate_operation(&delete_op).is_err());
    }

    #[test]
    fn test_validate_insert_duplicate_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to insert at existing RID
        let op = TableOperation::new(Operation::Insert(3, make_test_row(1)));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_update_nonexistent_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to update non-existent RID
        let op = TableOperation::new(Operation::Update(10, make_test_row(1)));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_delete_nonexistent_rid() {
        let mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Try to delete non-existent RID
        let op = TableOperation::new(Operation::Delete(10));
        let result = mods.validate_operation(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_consolidate_operations_keeps_latest() {
        let mut mods = TableModifications::new_sparse(1);

        // Apply multiple operations on the same RID with increasing timestamps
        let op1 = make_op_with_timestamp(Operation::Insert(1, make_test_row(100)), 1000);
        let op2 = make_op_with_timestamp(Operation::Update(1, make_test_row(200)), 2000);
        let op3 = make_op_with_timestamp(Operation::Update(1, make_test_row(300)), 3000);

        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        assert_eq!(mods.operation_count(), 3);

        // Consolidate should keep only the latest operation
        mods.consolidate_operations();
        assert_eq!(mods.operation_count(), 1);

        // Verify it's the latest update
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations[0].timestamp, 3000);
            if let Operation::Update(rid, data) = &operations[0].operation {
                assert_eq!(*rid, 1);
                if let TableDataOwned::Module(row) = data {
                    assert_eq!(row.name, 300);
                }
            } else {
                panic!("Expected Update operation");
            }
        }
    }

    #[test]
    fn test_consolidate_operations_multiple_rids() {
        let mut mods = TableModifications::new_sparse(1);

        // Operations on different RIDs
        let op1 = make_op_with_timestamp(Operation::Insert(1, make_test_row(100)), 1000);
        let op2 = make_op_with_timestamp(Operation::Insert(2, make_test_row(200)), 2000);
        let op3 = make_op_with_timestamp(Operation::Update(1, make_test_row(150)), 3000);

        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        assert_eq!(mods.operation_count(), 3);

        mods.consolidate_operations();

        // Should have 2 operations (latest for RID 1 and RID 2)
        assert_eq!(mods.operation_count(), 2);
    }

    #[test]
    fn test_consolidate_updates_deleted_rows() {
        let mut mods = TableModifications::new_sparse(6); // Rows 1-5 exist

        // Delete row 3
        let op1 = make_op_with_timestamp(Operation::Delete(3), 1000);
        mods.apply_operation(op1).unwrap();
        assert!(!mods.has_row(3));

        // Later "un-delete" by updating (should remove from deleted_rows)
        let op2 = make_op_with_timestamp(Operation::Update(3, make_test_row(300)), 2000);
        mods.apply_operation(op2).unwrap();

        // After consolidation, deleted_rows should be updated correctly
        mods.consolidate_operations();

        // The latest operation is Update, so row should exist
        // Note: deleted_rows is rebuilt during consolidation based on final operations
        if let TableModifications::Sparse { deleted_rows, .. } = &mods {
            assert!(!deleted_rows.contains(&3));
        }
    }

    #[test]
    fn test_replaced_table_operations() {
        let rows = vec![make_test_row(1), make_test_row(2), make_test_row(3)];
        let mut replaced = TableModifications::new_replaced(rows);

        assert!(replaced.has_modifications());
        assert_eq!(replaced.operation_count(), 3);

        // Rows 1-3 should exist
        assert!(replaced.has_row(1));
        assert!(replaced.has_row(2));
        assert!(replaced.has_row(3));
        assert!(!replaced.has_row(4));
        assert!(!replaced.has_row(0));

        // Cannot apply operations to replaced table
        let op = TableOperation::new(Operation::Insert(4, make_test_row(4)));
        assert!(replaced.apply_operation(op).is_err());
    }

    #[test]
    fn test_has_row_after_insert() {
        let mut mods = TableModifications::new_sparse(1); // No existing rows

        assert!(!mods.has_row(1));

        let op = TableOperation::new(Operation::Insert(1, make_test_row(100)));
        mods.apply_operation(op).unwrap();

        assert!(mods.has_row(1));
    }

    #[test]
    fn test_next_rid_updates_on_insert() {
        let mut mods = TableModifications::new_sparse(1);

        // Insert at RID 5 (skipping 1-4)
        let op = TableOperation::new(Operation::Insert(5, make_test_row(100)));
        mods.apply_operation(op).unwrap();

        // Next RID should be updated to 6
        if let TableModifications::Sparse { next_rid, .. } = &mods {
            assert_eq!(*next_rid, 6);
        }
    }

    #[test]
    fn test_empty_consolidate() {
        let mut mods = TableModifications::new_sparse(1);

        // Consolidating empty modifications should not panic
        mods.consolidate_operations();
        assert!(!mods.has_modifications());
    }

    #[test]
    fn test_same_timestamp_fifo_ordering() {
        // Test that operations with the same timestamp maintain FIFO insertion order.
        // Explicit timestamps (`new_with_timestamp`) can be equal: an Insert followed by an
        // Update of the same RID at one timestamp must keep the Update after the Insert.
        let mut mods = TableModifications::new_sparse(1);

        let fixed_timestamp = 1000u64;

        // Create Insert operation with fixed timestamp
        let insert_op = TableOperation::new_with_timestamp(
            Operation::Insert(10, make_test_row(100)),
            fixed_timestamp,
        );

        // Create Update operation with the same timestamp
        let update_op = TableOperation::new_with_timestamp(
            Operation::Update(10, make_test_row(200)),
            fixed_timestamp,
        );

        // Apply in order: Insert first, then Update
        mods.apply_operation(insert_op).unwrap();
        mods.apply_operation(update_op).unwrap();

        // Verify FIFO ordering: Insert should be at index 0, Update at index 1
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations.len(), 2);
            assert!(operations[0].is_insert(), "Insert should be first");
            assert!(operations[1].is_update(), "Update should be second");
        } else {
            panic!("Expected Sparse modifications");
        }
    }

    #[test]
    fn test_same_timestamp_multiple_operations() {
        // Test with more operations at the same timestamp
        let mut mods = TableModifications::new_sparse(1);

        let fixed_timestamp = 1000u64;

        // Create three operations on different RIDs with the same timestamp
        let op1 = TableOperation::new_with_timestamp(
            Operation::Insert(10, make_test_row(100)),
            fixed_timestamp,
        );
        let op2 = TableOperation::new_with_timestamp(
            Operation::Insert(11, make_test_row(200)),
            fixed_timestamp,
        );
        let op3 = TableOperation::new_with_timestamp(
            Operation::Insert(12, make_test_row(300)),
            fixed_timestamp,
        );

        // Apply in order
        mods.apply_operation(op1).unwrap();
        mods.apply_operation(op2).unwrap();
        mods.apply_operation(op3).unwrap();

        // Verify FIFO ordering: operations should be in insertion order
        if let TableModifications::Sparse { operations, .. } = &mods {
            assert_eq!(operations.len(), 3);
            assert_eq!(
                operations[0].get_rid(),
                10,
                "First operation should be RID 10"
            );
            assert_eq!(
                operations[1].get_rid(),
                11,
                "Second operation should be RID 11"
            );
            assert_eq!(
                operations[2].get_rid(),
                12,
                "Third operation should be RID 12"
            );
        } else {
            panic!("Expected Sparse modifications");
        }
    }
}
