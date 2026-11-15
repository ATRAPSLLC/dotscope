//! Operation types for table row modifications.
//!
//! This module provides the fundamental operation types for modifying metadata table rows
//! during assembly editing operations. It defines both the raw operation variants and the
//! timestamped operation wrapper used for conflict resolution and ordering.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::operation::Operation`] - Core operation variants (Insert/Update/Delete)
//! - [`crate::cilassembly::operation::TableOperation`] - Timestamped operation wrapper for conflict resolution
//!
//! # Architecture
//!
//! The operation system is designed around a total order of operations and conflict resolution:
//!
//! ## Operation Types
//! Three fundamental operations are supported:
//! - **Insert**: Create new rows with specific RIDs
//! - **Update**: Modify existing row data while preserving RID
//! - **Delete**: Mark rows as deleted (soft deletion for RID stability)
//!
//! ## Ordering
//! Every operation carries a logical timestamp from a process-wide counter: an operation
//! created after another always has a larger one, and no two share one. Conflict
//! resolution is last-write-wins on these timestamps, so its result depends only on the
//! order the operations were made in, never on the system clock.
//!
//! ## Conflict Resolution
//! When operations conflict (multiple operations on the same RID), the later timestamp
//! takes precedence.
//!
//! # Usage Examples
//!
//! ```text
//! use crate::cilassembly::{Operation, TableOperation};
//!
//! // Create an operation: an insert or update also carries the row's data
//! // (a `TableDataOwned`), a delete names only the row
//! let delete_op = Operation::Delete(2);
//!
//! // Wrap with timestamps for conflict resolution
//! let table_op = TableOperation::new(delete_op);
//!
//! // Check operation properties
//! assert_eq!(table_op.get_rid(), 2);
//! assert!(table_op.is_delete() && !table_op.is_insert());
//! ```
//!
//! # Thread Safety
//!
//! Both [`crate::cilassembly::operation::Operation`] and [`crate::cilassembly::operation::TableOperation`]
//! are [`Send`] and [`Sync`] as they contain only owned data and immutable timestamps.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::modifications::TableModifications`] - Operation storage and application
//! - Assembly validation - Operation validation and conflict detection
//! - [`crate::metadata::tables`] - Table data structures and row types

use std::sync::atomic::{AtomicU64, Ordering};

use crate::metadata::tables::TableDataOwned;

/// The logical clock [`TableOperation::new`] stamps operations with: strictly increasing
/// across the process, so every operation orders after the ones created before it.
static OPERATION_CLOCK: AtomicU64 = AtomicU64::new(1);

/// Specific operation types that can be applied to table rows.
///
/// This enum defines the three fundamental operations supported by the assembly modification
/// system. Each operation targets a specific RID (Row ID) and maintains referential integrity
/// through the validation system. Operations are typically wrapped in [`crate::cilassembly::operation::TableOperation`]
/// for timestamp-based conflict resolution.
///
/// # Operation Types
///
/// - **Insert**: Add a new row with a specific RID and data
/// - **Update**: Modify an existing row's data while preserving the RID
/// - **Delete**: Mark a row as deleted (soft deletion for RID stability)
///
/// # Usage Examples
///
/// ```text
/// use crate::cilassembly::Operation;
///
/// // `Operation::Insert(rid, row)` and `Operation::Update(rid, row)` carry a
/// // `TableDataOwned` row; a delete names only the row it removes
/// let delete = Operation::Delete(1);
///
/// // Check operation properties
/// assert_eq!(delete.get_rid(), 1);
/// println!("{}", delete.operation_type());
/// assert!(delete.get_row_data().is_none());
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only owned data
/// with no interior mutability.
#[derive(Debug, Clone)]
pub enum Operation {
    /// Insert a new row with the specified RID and data.
    ///
    /// This operation creates a new row in the target table with the specified RID.
    /// The RID must be unique within the table, and the data must be valid for the
    /// target table type.
    ///
    /// # Parameters
    /// * `u32` - The RID (Row ID) to assign to the new row (must be > 0 and unique)
    /// * [`crate::metadata::tables::TableDataOwned`] - The row data to insert
    ///
    /// # Validation
    /// - RID must be greater than 0 (RID 0 is reserved)
    /// - RID must not already exist in the table
    /// - Row data must be compatible with the target table schema
    ///
    /// # Conflicts
    /// Attempting to insert with an existing RID will result in a conflict
    /// that must be resolved through the validation system.
    Insert(u32, TableDataOwned),

    /// Update an existing row with new data.
    ///
    /// This operation replaces the data of an existing row while preserving its RID.
    /// The target row must exist either in the original table or have been created
    /// by a previous Insert operation.
    ///
    /// # Parameters  
    /// * `u32` - The RID of the row to update (must exist)
    /// * [`crate::metadata::tables::TableDataOwned`] - The new row data
    ///
    /// # Validation
    /// - Target RID must exist in the table (original or inserted)
    /// - RID must be greater than 0
    /// - New row data must be compatible with the target table schema
    ///
    /// # Behavior
    /// - If multiple Update operations target the same RID, the last one (by timestamp) wins
    /// - Update operations can be applied to both original rows and previously inserted rows
    Update(u32, TableDataOwned),

    /// Delete an existing row.
    ///
    /// This operation marks a row as deleted without immediately removing it from
    /// the table structure. This soft deletion approach preserves RID stability
    /// and enables proper conflict resolution with other operations.
    ///
    /// # Parameters
    /// * `u32` - The RID of the row to delete (must exist)
    ///
    /// # Validation
    /// - Target RID must exist in the table (original or inserted)
    /// - RID must be greater than 0
    /// - Row must not already be deleted
    ///
    /// # Behavior
    /// - Rows are marked as deleted but not physically removed
    /// - RID space remains stable (no gaps are filled)
    /// - Delete operations can be superseded by later Insert/Update operations on the same RID
    /// - Multiple Delete operations on the same RID are idempotent
    Delete(u32),
}

impl Operation {
    /// Gets the RID that this operation targets.
    ///
    /// All operations target a specific RID, and this method extracts that RID
    /// regardless of the operation type.
    ///
    /// # Returns
    ///
    /// The target RID as a `u32`. RIDs are 1-based following ECMA-335 conventions.
    pub fn get_rid(&self) -> u32 {
        match self {
            Operation::Insert(rid, _) | Operation::Update(rid, _) | Operation::Delete(rid) => *rid,
        }
    }

    /// Returns a reference to the row data if this operation contains any.
    ///
    /// Insert and Update operations contain row data, while Delete operations do not.
    /// This method provides access to that data when available.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::tables::TableDataOwned`]`)` for Insert and Update operations
    /// - `None` for Delete operations
    pub fn get_row_data(&self) -> Option<&TableDataOwned> {
        match self {
            Operation::Insert(_, data) | Operation::Update(_, data) => Some(data),
            Operation::Delete(_) => None,
        }
    }

    /// Returns the operation type as a string for debugging/logging.
    pub fn operation_type(&self) -> &'static str {
        match self {
            Operation::Insert(_, _) => "Insert",
            Operation::Update(_, _) => "Update",
            Operation::Delete(_) => "Delete",
        }
    }
}

/// Individual table operation with its place in the order of operations.
///
/// This struct wraps an [`crate::cilassembly::operation::Operation`] with a logical timestamp
/// that orders it among all operations, for last-write-wins conflict resolution when several
/// operations target the same RID.
///
/// # Timestamps
///
/// [`TableOperation::new`] takes the next value of a process-wide counter, so timestamps are
/// strictly increasing in creation order and unique, whatever the system clock does.
/// [`TableOperation::new_with_timestamp`] sets one explicitly, for replay or tests; equal
/// explicit timestamps keep the order the operations were applied in.
///
/// # Conflict Resolution
///
/// When multiple operations target the same RID:
/// - Operations are ordered by timestamp (ascending)
/// - Later timestamps take precedence (last-write-wins)
///
/// # Usage Examples
///
/// ```text
/// use crate::cilassembly::{Operation, TableOperation};
///
/// // Create timestamped operations: each takes the next timestamp
/// let first = TableOperation::new(Operation::Delete(1));
/// let second = TableOperation::new(Operation::Delete(2));
///
/// // Check properties
/// assert_eq!(first.get_rid(), 1);
/// assert!(second.timestamp > first.timestamp);
/// assert!(first.is_delete());
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains only owned data
/// and immutable timestamps.
#[derive(Debug, Clone)]
pub struct TableOperation {
    /// Logical timestamp ordering this operation among all others.
    ///
    /// This timestamp is used for conflict resolution when multiple
    /// operations target the same RID. Later timestamps take precedence
    /// in last-write-wins conflict resolution.
    pub timestamp: u64,

    /// The actual operation to perform
    pub operation: Operation,
}

impl TableOperation {
    /// Creates a new table operation, ordered after every operation created before it.
    ///
    /// The operation takes the next value of a process-wide counter as its timestamp, which
    /// conflict resolution uses if multiple operations target the same RID.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::operation::Operation`] to wrap with a timestamp
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::operation::TableOperation`] with the next timestamp.
    pub fn new(operation: Operation) -> Self {
        Self {
            timestamp: OPERATION_CLOCK.fetch_add(1, Ordering::Relaxed),
            operation,
        }
    }

    /// Creates a new table operation with a specific timestamp.
    ///
    /// This method allows precise control over the timestamp, which is useful for
    /// testing scenarios, replaying operations from logs, or when deterministic
    /// ordering is required.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`crate::cilassembly::operation::Operation`] to wrap
    /// * `timestamp` - The logical timestamp to assign
    ///
    /// # Returns
    ///
    /// A new [`crate::cilassembly::operation::TableOperation`] with the specified timestamp.
    pub fn new_with_timestamp(operation: Operation, timestamp: u64) -> Self {
        Self {
            timestamp,
            operation,
        }
    }

    /// Gets the RID that this operation targets.
    ///
    /// Delegates to the wrapped operation's `get_rid()` method to extract
    /// the target RID.
    ///
    /// # Returns
    ///
    /// The target RID as a `u32`.
    pub fn get_rid(&self) -> u32 {
        self.operation.get_rid()
    }

    /// Returns true if this operation creates a new row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Insert`], `false` otherwise.
    pub fn is_insert(&self) -> bool {
        matches!(self.operation, Operation::Insert(_, _))
    }

    /// Returns true if this operation modifies an existing row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Update`], `false` otherwise.
    pub fn is_update(&self) -> bool {
        matches!(self.operation, Operation::Update(_, _))
    }

    /// Returns true if this operation deletes a row.
    ///
    /// # Returns
    ///
    /// `true` if the wrapped operation is an [`crate::cilassembly::operation::Operation::Delete`], `false` otherwise.
    pub fn is_delete(&self) -> bool {
        matches!(self.operation, Operation::Delete(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::factories::table::cilassembly::create_test_row;

    /// Each new table operation takes the next timestamp, and keeps its
    /// operation's row and kind.
    #[test]
    fn a_table_operation_takes_the_next_timestamp() {
        let first = TableOperation::new(Operation::Delete(1));
        let second = TableOperation::new(Operation::Delete(2));
        assert!(second.timestamp > first.timestamp);
        assert_eq!(first.get_rid(), 1);
        assert!(first.is_delete() && !first.is_insert() && !first.is_update());
    }

    #[test]
    fn test_operation_get_rid_for_all_variants() {
        let row_data = create_test_row();

        // Test Insert variant
        let insert_op = Operation::Insert(42, row_data.clone());
        assert_eq!(insert_op.get_rid(), 42);

        // Test Update variant
        let update_op = Operation::Update(100, row_data);
        assert_eq!(update_op.get_rid(), 100);

        // Test Delete variant
        let delete_op = Operation::Delete(10);
        assert_eq!(delete_op.get_rid(), 10);
    }

    #[test]
    fn test_operation_get_row_data_for_all_variants() {
        let row_data = create_test_row();

        // Insert should return Some
        let insert_op = Operation::Insert(1, row_data.clone());
        assert!(insert_op.get_row_data().is_some());

        // Update should return Some
        let update_op = Operation::Update(1, row_data);
        assert!(update_op.get_row_data().is_some());

        // Delete should return None
        let delete_op = Operation::Delete(1);
        assert!(delete_op.get_row_data().is_none());
    }

    #[test]
    fn test_operation_type_for_all_variants() {
        let row_data = create_test_row();

        let insert_op = Operation::Insert(1, row_data.clone());
        assert_eq!(insert_op.operation_type(), "Insert");

        let update_op = Operation::Update(1, row_data);
        assert_eq!(update_op.operation_type(), "Update");

        let delete_op = Operation::Delete(1);
        assert_eq!(delete_op.operation_type(), "Delete");
    }

    #[test]
    fn test_operation_edge_case_rid_zero() {
        // RID 0 is reserved but the Operation struct doesn't validate - that's up to callers
        let delete_op = Operation::Delete(0);
        assert_eq!(delete_op.get_rid(), 0);
    }

    #[test]
    fn test_operation_edge_case_max_rid() {
        let delete_op = Operation::Delete(u32::MAX);
        assert_eq!(delete_op.get_rid(), u32::MAX);
    }

    #[test]
    fn test_table_operation_new_captures_timestamp() {
        let op = TableOperation::new(Operation::Delete(1));
        assert!(op.timestamp > 0);
    }

    #[test]
    fn test_table_operation_new_with_timestamp() {
        let op = TableOperation::new_with_timestamp(Operation::Delete(1), 12345);
        assert_eq!(op.timestamp, 12345);
    }

    /// Operations created back to back, with nothing between them, still order strictly:
    /// a timestamp from the system clock repeats within one tick.
    #[test]
    fn operations_created_back_to_back_are_strictly_ordered() {
        let mut previous = TableOperation::new(Operation::Delete(1)).timestamp;
        for rid in 2..10_000 {
            let timestamp = TableOperation::new(Operation::Delete(rid)).timestamp;
            assert!(timestamp > previous, "{timestamp} after {previous}");
            previous = timestamp;
        }
    }

    #[test]
    fn test_table_operation_get_rid() {
        let row_data = create_test_row();
        let op = TableOperation::new(Operation::Insert(999, row_data));
        assert_eq!(op.get_rid(), 999);
    }

    #[test]
    fn test_table_operation_is_insert() {
        let row_data = create_test_row();

        let insert_op = TableOperation::new(Operation::Insert(1, row_data.clone()));
        assert!(insert_op.is_insert());
        assert!(!insert_op.is_update());
        assert!(!insert_op.is_delete());

        let update_op = TableOperation::new(Operation::Update(1, row_data));
        assert!(!update_op.is_insert());

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(!delete_op.is_insert());
    }

    #[test]
    fn test_table_operation_is_update() {
        let row_data = create_test_row();

        let update_op = TableOperation::new(Operation::Update(1, row_data.clone()));
        assert!(update_op.is_update());
        assert!(!update_op.is_insert());
        assert!(!update_op.is_delete());

        let insert_op = TableOperation::new(Operation::Insert(1, row_data));
        assert!(!insert_op.is_update());

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(!delete_op.is_update());
    }

    #[test]
    fn test_table_operation_is_delete() {
        let row_data = create_test_row();

        let delete_op = TableOperation::new(Operation::Delete(1));
        assert!(delete_op.is_delete());
        assert!(!delete_op.is_insert());
        assert!(!delete_op.is_update());

        let insert_op = TableOperation::new(Operation::Insert(1, row_data.clone()));
        assert!(!insert_op.is_delete());

        let update_op = TableOperation::new(Operation::Update(1, row_data));
        assert!(!update_op.is_delete());
    }

    #[test]
    fn test_table_operation_clone() {
        let row_data = create_test_row();
        let op = TableOperation::new_with_timestamp(Operation::Insert(42, row_data), 5000);
        let cloned = op.clone();

        assert_eq!(cloned.timestamp, 5000);
        assert_eq!(cloned.get_rid(), 42);
        assert!(cloned.is_insert());
    }
}
