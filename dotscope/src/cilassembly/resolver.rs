//! Conflict resolution strategies for assembly modification operations.
//!
//! This module provides conflict resolution strategies for handling conflicting operations
//! during assembly modification. When multiple operations target the same metadata
//! element, resolvers determine which operation should take precedence.
//!
//! # Key Components
//!
//! - [`LastWriteWinsResolver`] - Default conflict resolver using timestamp ordering
//! - [`ConflictResolver`] - Trait for implementing custom resolution strategies
//! - [`Conflict`] - Types of conflicts that can occur during modification
//! - [`Resolution`] - Conflict resolution results
//!
//! # Architecture
//!
//! The conflict resolution system is built around pluggable strategies that can be
//! configured based on application requirements:
//!
//! ## Timestamp-Based Resolution
//! The default [`LastWriteWinsResolver`] uses operation timestamps to determine
//! precedence, with later operations overriding earlier ones.
//!
//! ## Extensible Design
//! The [`ConflictResolver`] trait allows custom resolution strategies
//! to be implemented for specific use cases.
//!
//! # Usage Examples
//!
//! ```
//! use dotscope::{Conflict, ConflictResolver, LastWriteWinsResolver};
//!
//! // Create a resolver
//! let resolver = LastWriteWinsResolver;
//!
//! // Resolve conflicts (typically used by validation pipeline)
//! // The conflicts the validation pipeline detected: none here
//! let conflicts: Vec<Conflict> = Vec::new();
//! let resolution = resolver.resolve_conflict(&conflicts)?;
//! assert!(resolution.operations.is_empty());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] as it contains no mutable state and operates
//! purely on the input data.

use std::collections::HashMap;

use crate::{cilassembly::TableOperation, Error, Result};

/// Trait for conflict resolution strategies.
///
/// Different applications may need different conflict resolution strategies:
/// - **Last-write-wins (default)**: Most recent operation takes precedence
/// - **First-write-wins**: First operation takes precedence
/// - **Merge operations**: Combine compatible operations
/// - **Reject on conflict**: Fail validation on any conflict
///
/// Conflict resolution is essential for handling scenarios where multiple
/// operations target the same resource, ensuring deterministic behavior
/// and maintaining assembly integrity.
///
/// # Implementation Guidelines
///
/// Conflict resolvers should:
/// - Be deterministic and consistent
/// - Handle all conflict types appropriately
/// - Provide clear resolution decisions
/// - Be configurable for different use cases
/// - Maintain operation ordering guarantees
///
/// # Examples
///
/// ```
/// use dotscope::{Conflict, ConflictResolver, OperationResolution, Resolution};
///
/// /// Keeps the first operation on each row and drops the rest.
/// struct FirstWriteWinsResolver;
///
/// impl ConflictResolver for FirstWriteWinsResolver {
///     fn resolve_conflict(&self, conflicts: &[Conflict]) -> dotscope::Result<Resolution> {
///         let mut resolution = Resolution::default();
///         for conflict in conflicts {
///             if let Conflict::MultipleOperationsOnRid { rid, operations } = conflict {
///                 if let Some(first) = operations.first() {
///                     resolution
///                         .operations
///                         .insert(*rid, OperationResolution::UseOperation(first.clone()));
///                 }
///             }
///         }
///         Ok(resolution)
///     }
/// }
///
/// let resolution = FirstWriteWinsResolver.resolve_conflict(&[])?;
/// assert!(resolution.operations.is_empty());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub trait ConflictResolver {
    /// Resolves conflicts between operations.
    ///
    /// This method analyzes the provided conflicts and determines how to resolve
    /// them according to the resolver's strategy. The resolution specifies which
    /// operations should be applied and in what order.
    ///
    /// # Arguments
    ///
    /// * `conflicts` - Array of [`Conflict`] instances representing conflicting operations
    ///
    /// # Returns
    ///
    /// Returns a [`Resolution`] that specifies how to handle each conflict,
    /// including which operations to apply and which to reject.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if conflicts cannot be resolved or if the
    /// resolution strategy encounters invalid conflict states.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::{Conflict, ConflictResolver, LastWriteWinsResolver};
    ///
    /// let resolver = LastWriteWinsResolver;
    /// // The conflicts the validation pipeline detected: none here
    /// let conflicts: Vec<Conflict> = Vec::new();
    /// let resolution = resolver.resolve_conflict(&conflicts)?;
    /// for (rid, operation_resolution) in resolution.operations {
    ///     println!("RID {} resolved to: {:?}", rid, operation_resolution);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution>;
}

/// Types of conflicts that can occur during modification.
///
/// Conflicts arise when multiple operations target the same resource
/// or when operations have incompatible effects.
#[derive(Debug)]
pub enum Conflict {
    /// Multiple operations targeting the same RID.
    ///
    /// This occurs when multiple operations (insert, update, delete)
    /// are applied to the same table row.
    MultipleOperationsOnRid {
        /// The RID being modified.
        rid: u32,
        /// The conflicting operations.
        operations: Vec<TableOperation>,
    },

    /// Insert and delete operations on the same RID.
    ///
    /// This specific conflict occurs when a row is both inserted
    /// and deleted, which requires special resolution logic.
    InsertDeleteConflict {
        /// The RID being modified.
        rid: u32,
        /// The insert operation.
        insert_op: TableOperation,
        /// The delete operation.
        delete_op: TableOperation,
    },
}

/// Resolution of conflicts.
///
/// Contains the final resolved operations after conflict resolution.
/// This structure is used to apply the resolved operations to the assembly.
#[derive(Debug, Default)]
pub struct Resolution {
    /// Resolved operations keyed by RID.
    pub operations: HashMap<u32, OperationResolution>,
}

/// How to resolve a specific operation conflict.
///
/// Specifies the action to take for a conflicted operation.
#[derive(Debug)]
pub enum OperationResolution {
    /// Use the specified operation.
    UseOperation(TableOperation),
    /// Use the chronologically latest operation.
    UseLatest,
    /// Merge multiple operations into a sequence.
    Merge(Vec<TableOperation>),
    /// Reject the operation with an error message.
    Reject(String),
}

/// Default last-write-wins conflict resolver.
///
/// [`LastWriteWinsResolver`] implements a simple conflict resolution strategy that uses
/// operation timestamps to determine precedence. When multiple operations target the same
/// metadata element, the operation with the latest timestamp takes precedence.
///
/// This resolver handles two types of conflicts:
/// - **Multiple Operations on RID**: When several operations target the same table row
/// - **Insert/Delete Conflicts**: When both insert and delete operations target the same RID
///
/// # Usage Examples
///
/// ```
/// use dotscope::{Conflict, ConflictResolver, LastWriteWinsResolver};
///
/// let resolver = LastWriteWinsResolver;
///
/// // Typically used by validation pipeline
/// // The conflicts the validation pipeline detected: none here
/// let conflicts: Vec<Conflict> = Vec::new();
/// let resolution = resolver.resolve_conflict(&conflicts)?;
/// assert!(resolution.operations.is_empty());
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] as it contains no state and operates purely on
/// the input data provided to the resolution methods.
pub struct LastWriteWinsResolver;

impl ConflictResolver for LastWriteWinsResolver {
    /// Resolves conflicts using last-write-wins strategy.
    ///
    /// This method processes an array of conflicts and determines the winning operation
    /// for each conflicted RID based on timestamp ordering. For each conflict, the
    /// operation with the latest timestamp is selected as the winner.
    ///
    /// # Tie-Breaking Behavior
    ///
    /// When two operations have identical timestamps:
    /// - For `MultipleOperationsOnRid`: The first operation encountered with the maximum
    ///   timestamp wins (deterministic based on vector order).
    /// - For `InsertDeleteConflict`: Insert operations win over Delete operations when
    ///   timestamps are equal (using `>=` comparison). This favors data preservation.
    ///
    /// # Arguments
    ///
    /// * `conflicts` - Array of [`Conflict`] instances to resolve
    ///
    /// # Returns
    ///
    /// Returns a [`Resolution`] containing the winning operation
    /// for each conflicted RID.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if resolution processing fails, though this implementation
    /// is designed to always succeed with valid input.
    fn resolve_conflict(&self, conflicts: &[Conflict]) -> Result<Resolution> {
        let mut resolution_map = HashMap::new();

        for conflict in conflicts {
            match conflict {
                Conflict::MultipleOperationsOnRid { rid, operations } => {
                    if let Some(latest_op) = operations.iter().max_by_key(|op| op.timestamp) {
                        resolution_map
                            .insert(*rid, OperationResolution::UseOperation(latest_op.clone()));
                    }
                }
                Conflict::InsertDeleteConflict {
                    rid,
                    insert_op,
                    delete_op,
                } => {
                    if !insert_op.is_insert() {
                        return Err(Error::ConflictResolution(format!(
                            "InsertDeleteConflict for RID {rid}: insert_op is not an Insert operation"
                        )));
                    }
                    if !delete_op.is_delete() {
                        return Err(Error::ConflictResolution(format!(
                            "InsertDeleteConflict for RID {rid}: delete_op is not a Delete operation"
                        )));
                    }

                    let winning_op = if insert_op.timestamp >= delete_op.timestamp {
                        insert_op
                    } else {
                        delete_op
                    };
                    resolution_map
                        .insert(*rid, OperationResolution::UseOperation(winning_op.clone()));
                }
            }
        }

        Ok(Resolution {
            operations: resolution_map,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cilassembly::Operation, testkit::factories::table::cilassembly::create_test_row};

    #[test]
    fn test_last_write_wins_resolver_multiple_operations() {
        let operations = vec![
            {
                let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
                op.timestamp = 1000;
                op
            },
            {
                let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
                op.timestamp = 2000; // Later timestamp
                op
            },
        ];

        let conflict = Conflict::MultipleOperationsOnRid {
            rid: 100,
            operations,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_ok(), "Conflict resolution should succeed");

        if let Ok(resolution) = result {
            assert!(
                resolution.operations.contains_key(&100),
                "Should resolve RID 100"
            );

            if let Some(OperationResolution::UseOperation(op)) = resolution.operations.get(&100) {
                assert!(
                    matches!(op.operation, Operation::Update(100, _)),
                    "Should use Update operation"
                );
            } else {
                panic!("Expected UseOperation resolution");
            }
        }
    }

    #[test]
    fn test_last_write_wins_resolver_single_operation_in_conflict() {
        // Edge case: only one operation in the conflict vector
        let operations = vec![{
            let mut op = TableOperation::new(Operation::Delete(50));
            op.timestamp = 5000;
            op
        }];

        let conflict = Conflict::MultipleOperationsOnRid {
            rid: 50,
            operations,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]).unwrap();

        assert!(result.operations.contains_key(&50));
        if let Some(OperationResolution::UseOperation(op)) = result.operations.get(&50) {
            assert!(matches!(op.operation, Operation::Delete(50)));
            assert_eq!(op.timestamp, 5000);
        } else {
            panic!("Expected UseOperation resolution");
        }
    }

    #[test]
    fn test_last_write_wins_resolver_equal_timestamps() {
        // Edge case: equal timestamps - should still resolve (first one with max_by_key)
        let operations = vec![
            {
                let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
                op.timestamp = 1000;
                op
            },
            {
                let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
                op.timestamp = 1000; // Same timestamp
                op
            },
        ];

        let conflict = Conflict::MultipleOperationsOnRid {
            rid: 100,
            operations,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_ok(), "Should handle equal timestamps");

        let resolution = result.unwrap();
        assert!(resolution.operations.contains_key(&100));
    }

    /// A delete made right after an insert of the same row wins, however close together
    /// they were made.
    #[test]
    fn a_delete_made_right_after_an_insert_wins() {
        for rid in 1..1_000 {
            let insert_op = TableOperation::new(Operation::Insert(rid, create_test_row()));
            let delete_op = TableOperation::new(Operation::Delete(rid));
            let conflict = Conflict::InsertDeleteConflict {
                rid,
                insert_op,
                delete_op,
            };
            let resolution = LastWriteWinsResolver
                .resolve_conflict(&[conflict])
                .expect("resolves");
            assert!(
                matches!(
                    resolution.operations.get(&rid),
                    Some(OperationResolution::UseOperation(op)) if op.is_delete()
                ),
                "RID {rid}: the later delete must win"
            );
        }
    }

    #[test]
    fn test_last_write_wins_resolver_insert_delete_conflict() {
        let insert_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 1000;
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 2000; // Later timestamp
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_ok(), "Conflict resolution should succeed");

        if let Ok(resolution) = result {
            assert!(
                resolution.operations.contains_key(&100),
                "Should resolve RID 100"
            );

            if let Some(OperationResolution::UseOperation(op)) = resolution.operations.get(&100) {
                assert!(
                    matches!(op.operation, Operation::Delete(100)),
                    "Should use Delete operation (later timestamp)"
                );
            } else {
                panic!("Expected UseOperation resolution");
            }
        }
    }

    #[test]
    fn test_last_write_wins_resolver_insert_wins_over_delete() {
        // Insert has later timestamp, so insert should win
        let insert_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 3000; // Later timestamp
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 1000; // Earlier timestamp
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]).unwrap();

        if let Some(OperationResolution::UseOperation(op)) = result.operations.get(&100) {
            assert!(
                matches!(op.operation, Operation::Insert(100, _)),
                "Should use Insert operation (later timestamp)"
            );
        } else {
            panic!("Expected UseOperation resolution");
        }
    }

    #[test]
    fn test_last_write_wins_resolver_insert_delete_equal_timestamps() {
        // Equal timestamps - insert should win (>= comparison favors insert)
        let insert_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 1000;
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 1000; // Same timestamp
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]).unwrap();

        if let Some(OperationResolution::UseOperation(op)) = result.operations.get(&100) {
            // With >= comparison, insert wins on ties
            assert!(
                matches!(op.operation, Operation::Insert(100, _)),
                "Insert should win on equal timestamps"
            );
        } else {
            panic!("Expected UseOperation resolution");
        }
    }

    #[test]
    fn test_last_write_wins_resolver_empty_conflict_vector() {
        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[]);
        assert!(result.is_ok());

        let resolution = result.unwrap();
        assert!(
            resolution.operations.is_empty(),
            "Empty conflicts should produce empty resolution"
        );
    }

    #[test]
    fn test_last_write_wins_resolver_multiple_conflicts() {
        // Multiple conflicts for different RIDs
        let conflict1 = Conflict::MultipleOperationsOnRid {
            rid: 10,
            operations: vec![{
                let mut op = TableOperation::new(Operation::Delete(10));
                op.timestamp = 1000;
                op
            }],
        };

        let conflict2 = Conflict::InsertDeleteConflict {
            rid: 20,
            insert_op: {
                let mut op = TableOperation::new(Operation::Insert(20, create_test_row()));
                op.timestamp = 2000;
                op
            },
            delete_op: {
                let mut op = TableOperation::new(Operation::Delete(20));
                op.timestamp = 1000;
                op
            },
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict1, conflict2]).unwrap();

        // Both RIDs should be resolved
        assert!(result.operations.contains_key(&10));
        assert!(result.operations.contains_key(&20));

        // RID 10: Delete (only operation)
        if let Some(OperationResolution::UseOperation(op)) = result.operations.get(&10) {
            assert!(matches!(op.operation, Operation::Delete(10)));
        }

        // RID 20: Insert wins (later timestamp)
        if let Some(OperationResolution::UseOperation(op)) = result.operations.get(&20) {
            assert!(matches!(op.operation, Operation::Insert(20, _)));
        }
    }

    #[test]
    fn test_resolution_default() {
        let resolution = Resolution::default();
        assert!(resolution.operations.is_empty());
    }

    #[test]
    fn test_operation_resolution_variants() {
        let row_data = create_test_row();

        // UseOperation variant
        let use_op = OperationResolution::UseOperation(TableOperation::new(Operation::Delete(1)));
        assert!(matches!(use_op, OperationResolution::UseOperation(_)));

        // UseLatest variant
        let use_latest = OperationResolution::UseLatest;
        assert!(matches!(use_latest, OperationResolution::UseLatest));

        // Merge variant
        let merge = OperationResolution::Merge(vec![
            TableOperation::new(Operation::Insert(1, row_data.clone())),
            TableOperation::new(Operation::Update(1, row_data)),
        ]);
        if let OperationResolution::Merge(ops) = merge {
            assert_eq!(ops.len(), 2);
        }

        // Reject variant
        let reject = OperationResolution::Reject("Conflict cannot be resolved".to_string());
        if let OperationResolution::Reject(msg) = reject {
            assert_eq!(msg, "Conflict cannot be resolved");
        }
    }

    #[test]
    fn test_insert_delete_conflict_validation_invalid_insert_op() {
        // insert_op is actually a Delete - should fail validation
        let insert_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 1000;
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Delete(100));
            op.timestamp = 2000;
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_err(), "Should fail when insert_op is not Insert");

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("insert_op is not an Insert operation"),
            "Error message should indicate invalid insert_op"
        );
    }

    #[test]
    fn test_insert_delete_conflict_validation_invalid_delete_op() {
        // delete_op is actually an Insert - should fail validation
        let insert_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 1000;
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Insert(100, create_test_row()));
            op.timestamp = 2000;
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(result.is_err(), "Should fail when delete_op is not Delete");

        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("delete_op is not a Delete operation"),
            "Error message should indicate invalid delete_op"
        );
    }

    #[test]
    fn test_insert_delete_conflict_validation_update_operations() {
        // Both operations are Update - should fail on insert_op validation first
        let insert_op = {
            let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
            op.timestamp = 1000;
            op
        };

        let delete_op = {
            let mut op = TableOperation::new(Operation::Update(100, create_test_row()));
            op.timestamp = 2000;
            op
        };

        let conflict = Conflict::InsertDeleteConflict {
            rid: 100,
            insert_op,
            delete_op,
        };

        let resolver = LastWriteWinsResolver;
        let result = resolver.resolve_conflict(&[conflict]);
        assert!(
            result.is_err(),
            "Should fail when operations are not correct types"
        );

        // Should fail on insert_op validation first
        let err = result.unwrap_err();
        assert!(
            err.to_string()
                .contains("insert_op is not an Insert operation"),
            "Error should indicate insert_op validation failed first"
        );
    }
}
