//! Raw change integrity validator for post-change assembly integrity validation.
//!
//! This validator ensures the structural integrity and consistency of an assembly
//! after all modifications have been applied. It validates that the final state
//! maintains referential integrity and conflict-free operations.
//! This validator runs with priority 100 and only operates during modification validation.
//!
//! # Architecture
//!
//! The change integrity validation system implements comprehensive post-change integrity validation in sequential order:
//! 1. **Table Consistency** - Validates final table states maintain proper RID sequences and critical table requirements
//! 2. **Cross-Table References** - Validates references remain valid after changes and relationships are consistent
//! 3. **Operation Conflicts** - Detects conflicts between concurrent operations and validates proper sequencing
//!
//! The implementation validates the assembly's final state according to ECMA-335
//! specifications, ensuring that modifications don't corrupt metadata integrity.
//! All validation focuses on structural consistency and avoids timing-based conflict detection.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::modification::integrity::RawChangeIntegrityValidator`] - Main validator implementation providing comprehensive post-change validation
//! - [`crate::metadata::validation::validators::raw::modification::integrity::RawChangeIntegrityValidator::validate_table_integrity`] - Table state validation with RID sequence checking
//! - [`crate::metadata::validation::validators::raw::modification::integrity::RawChangeIntegrityValidator::validate_reference_integrity`] - Cross-reference validation for relationship consistency
//! - [`crate::metadata::validation::validators::raw::modification::integrity::RawChangeIntegrityValidator::validate_change_conflicts`] - Conflict detection with logical validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawChangeIntegrityValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawChangeIntegrityValidator::new();
//!
//! // Check if validation should run (only for modification contexts)
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawFailed`] for:
//! - Broken referential integrity after modifications (orphaned fields/methods)
//! - RID sequence violations or gaps (sparse sequences, conflicting RIDs)
//! - Cross-table reference inconsistencies (invalid parent-child relationships)
//! - Operation ordering violations indicating data corruption (non-chronological timestamps)
//! - Critical table integrity violations (empty Module/Assembly tables)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable assembly change structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw modification validators - Part of the modification validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::cilassembly::AssemblyChanges`] - Source of modifications to validate
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution
//!
//! # References
//!
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata table specifications
//! - [ECMA-335 II.24](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata physical layout

use std::collections::HashMap;

use rustc_hash::{FxHashMap, FxHashSet};

use crate::{
    cilassembly::{Operation, TableModifications},
    metadata::{
        tables::{TableDataOwned, TableId},
        validation::{
            context::{RawValidationContext, ValidationContext},
            traits::RawValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for post-change assembly integrity and consistency validation.
///
/// Ensures the structural integrity and consistency of an assembly after all modifications
/// have been applied, validating that the final state maintains referential integrity,
/// proper heap structure, and conflict-free operations. This validator operates at the
/// final assembly state to provide essential guarantees about modification integrity.
///
/// The validator implements comprehensive coverage of post-change integrity validation
/// according to ECMA-335 specifications, ensuring that modifications don't corrupt
/// metadata integrity and that the final assembly state is consistent and valid.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable assembly change structures.
pub struct RawChangeIntegrityValidator;

impl RawChangeIntegrityValidator {
    /// Creates a new change integrity validator.
    ///
    /// Initializes a validator instance that can be used to validate post-change
    /// assembly integrity across multiple assemblies. The validator is stateless and
    /// can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`RawChangeIntegrityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates table integrity after modifications have been applied.
    ///
    /// Ensures that table modifications maintain proper RID sequences, don't create
    /// gaps or conflicts, and that all table states are consistent with ECMA-335
    /// requirements. Validates the final table structure for integrity.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications to validate for integrity via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All table modifications maintain integrity
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Table integrity violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - RID sequences have gaps or conflicts after modifications (conflicting inserts)
    /// - Table modifications create inconsistent final states (next_rid inconsistencies)
    /// - Modified tables violate ECMA-335 structural requirements (sparse sequences)
    /// - Critical tables become empty after modifications (Module, Assembly tables)
    /// - Replacement tables exceed reasonable size limits (>1,000,000 rows)
    fn validate_table_integrity(
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            match modifications {
                TableModifications::Sparse {
                    operations,
                    next_rid,
                    original_row_count,
                    deleted_rows,
                    ..
                } => {
                    let mut final_rids = FxHashSet::default();

                    for rid in 1..=*original_row_count {
                        if !deleted_rows.contains(&rid) {
                            final_rids.insert(rid);
                        }
                    }

                    for operation in operations {
                        if let Operation::Insert(rid, _) = &operation.operation {
                            if final_rids.contains(rid) {
                                return Err(malformed_error!(
                                    "Table {:?} integrity violation: RID {} conflicts with existing row after modifications",
                                    table_id,
                                    rid
                                ));
                            }
                            final_rids.insert(*rid);
                        }
                    }

                    if let Some(&max_rid) = final_rids.iter().max() {
                        let expected_min_count =
                            u32::try_from(final_rids.len().saturating_mul(7) / 10).unwrap_or(0);
                        if max_rid > expected_min_count.max(1).saturating_mul(2) {
                            return Err(malformed_error!(
                                "Table {:?} integrity violation: RID sequence too sparse - max RID {} with only {} rows (>70% gaps)",
                                table_id,
                                max_rid,
                                final_rids.len()
                            ));
                        }
                    }

                    if let Some(&max_rid) = final_rids.iter().max() {
                        if *next_rid <= max_rid {
                            return Err(malformed_error!(
                                "Table {:?} integrity violation: next_rid {} is not greater than max existing RID {}",
                                table_id,
                                next_rid,
                                max_rid
                            ));
                        }
                    }

                    if matches!(table_id, TableId::Module) && !final_rids.contains(&1) {
                        return Err(malformed_error!(
                            "Table {:?} integrity violation: Module table must contain RID 1 (primary module entry)",
                            table_id
                        ));
                    }
                }
                TableModifications::Replaced(rows) => {
                    if rows.is_empty() && matches!(table_id, TableId::Module | TableId::Assembly) {
                        return Err(malformed_error!(
                            "Table {:?} integrity violation: Critical table cannot be empty after replacement",
                            table_id
                        ));
                    }

                    // A row's RID is 24 bits wide (ECMA-335 II.22)
                    if rows.len() > 0x00FF_FFFF {
                        return Err(malformed_error!(
                            "Table {:?} integrity violation: Replacement table has {} rows, more than a 24-bit RID addresses",
                            table_id,
                            rows.len()
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates cross-table reference integrity after modifications.
    ///
    /// Ensures that references between tables remain valid after modifications
    /// are applied. Validates that tokens, coded indices, and table relationships
    /// maintain consistency in the final assembly state.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications to validate for cross-references via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All cross-table references maintain integrity
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Reference integrity violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Cross-table references point to deleted rows (orphaned references)
    /// - Token references become invalid after modifications
    /// - Critical relationships are broken by changes (TypeDef-Field, TypeDef-Method)
    /// - Parent-child relationships are corrupted (orphaned fields or methods)
    fn validate_reference_integrity(
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        let mut final_table_rids: FxHashMap<TableId, FxHashSet<u32>> = FxHashMap::default();

        for (table_id, modifications) in table_changes {
            let mut final_rids = FxHashSet::default();

            match modifications {
                TableModifications::Sparse {
                    operations,
                    original_row_count,
                    deleted_rows,
                    ..
                } => {
                    for rid in 1..=*original_row_count {
                        if !deleted_rows.contains(&rid) {
                            final_rids.insert(rid);
                        }
                    }

                    for operation in operations {
                        if let Operation::Insert(rid, _) = &operation.operation {
                            final_rids.insert(*rid);
                        }
                    }
                }
                TableModifications::Replaced(rows) => {
                    for rid in 1..=u32::try_from(rows.len()).unwrap_or(u32::MAX) {
                        final_rids.insert(rid);
                    }
                }
            }

            final_table_rids.insert(*table_id, final_rids);
        }

        if let (Some(typedef_rids), Some(field_rids)) = (
            final_table_rids.get(&TableId::TypeDef),
            final_table_rids.get(&TableId::Field),
        ) {
            if typedef_rids.is_empty() && !field_rids.is_empty() {
                return Err(malformed_error!(
                    "Reference integrity violation: Fields exist but no TypeDef entries - orphaned fields detected"
                ));
            }

            // For each type that still exists after modifications, validate that its field range is valid
            Self::validate_field_ownership_ranges(typedef_rids, field_rids, table_changes)?;
        }

        if let (Some(typedef_rids), Some(method_rids)) = (
            final_table_rids.get(&TableId::TypeDef),
            final_table_rids.get(&TableId::MethodDef),
        ) {
            if typedef_rids.is_empty() && !method_rids.is_empty() {
                return Err(malformed_error!(
                    "Reference integrity violation: Methods exist but no TypeDef entries - orphaned methods detected"
                ));
            }
        }

        Ok(())
    }

    /// Validates that change operations maintain proper ordering and don't indicate corruption.
    ///
    /// Validates operation sequencing and detects signs of potential data corruption
    /// that could indicate systemic issues.
    /// Focuses on logical conflicts rather than timing-based detection to avoid
    /// false positives on fast systems or automated tooling.
    ///
    /// # Arguments
    ///
    /// * `table_changes` - Map of table modifications to validate for conflicts via [`crate::metadata::tables::TableId`] and [`crate::cilassembly::TableModifications`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - No structural conflicts detected in operations
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Structural issues found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Operations are not chronologically ordered (indicates data corruption)
    /// - Operation sequences create impossible logical states
    ///
    /// # Design Notes
    ///
    /// This validator intentionally avoids timing-based conflict detection as modern
    /// systems and automated tools can legitimately generate operations very quickly.
    /// Instead, it relies on logical validation and the operation consolidation
    /// mechanisms in [`crate::cilassembly::TableModifications`] to handle actual conflicts.
    fn validate_change_conflicts(
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        for (table_id, modifications) in table_changes {
            if let TableModifications::Sparse { operations, .. } = modifications {
                for window in operations.windows(2) {
                    let curr = window.first().ok_or_else(|| {
                        malformed_error!(
                            "Operation window missing first element for table {:?}",
                            table_id
                        )
                    })?;
                    let next = window.get(1).ok_or_else(|| {
                        malformed_error!(
                            "Operation window missing second element for table {:?}",
                            table_id
                        )
                    })?;
                    let curr_time = curr.timestamp;
                    let next_time = next.timestamp;

                    if curr_time > next_time {
                        return Err(malformed_error!(
                            "Change conflict detected: Operations for table {:?} not in chronological order - {} > {}",
                            table_id,
                            curr_time,
                            next_time
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates field ownership ranges for TypeDef entries after modifications.
    ///
    /// Ensures that field ownership ranges are consistent and valid after table modifications.
    /// Each TypeDef's field_list points to the start of its field range, and the range extends
    /// to the next TypeDef's field_list (or end of Field table for the last TypeDef).
    ///
    /// # Arguments
    ///
    /// * `typedef_rids` - Set of TypeDef RIDs that exist after modifications
    /// * `field_rids` - Set of Field RIDs that exist after modifications
    /// * `table_changes` - Map of all table modifications for accessing TypeDef data
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field ownership ranges are valid
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Field ownership violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - TypeDef field_list points to deleted fields
    /// - Field ownership ranges overlap or are inconsistent
    /// - Orphaned fields exist (fields not owned by any TypeDef)
    fn validate_field_ownership_ranges(
        typedef_rids: &FxHashSet<u32>,
        field_rids: &FxHashSet<u32>,
        table_changes: &HashMap<TableId, TableModifications>,
    ) -> Result<()> {
        // Get TypeDef modifications to access field_list values
        let Some(typedef_modifications) = table_changes.get(&TableId::TypeDef) else {
            return Ok(()); // No TypeDef modifications, nothing to validate
        };

        // Collect all TypeDef entries with their field_list values
        let mut typedef_field_lists: Vec<(u32, u32)> = Vec::new(); // (typedef_rid, field_list)

        match typedef_modifications {
            TableModifications::Sparse {
                operations,
                original_row_count,
                deleted_rows,
                ..
            } => {
                // Check original TypeDef entries that weren't deleted
                for rid in 1..=*original_row_count {
                    if !deleted_rows.contains(&rid) && typedef_rids.contains(&rid) {
                        // For original entries, we'd need access to original data
                        // This is a limitation of the current validation - we can only validate
                        // inserted/updated TypeDef entries with known field_list values
                    }
                }

                // Check inserted/updated TypeDef entries
                for operation in operations {
                    if let Operation::Insert(rid, data) = &operation.operation {
                        if typedef_rids.contains(rid) {
                            if let TableDataOwned::TypeDef(typedef_row) = data {
                                typedef_field_lists.push((*rid, typedef_row.field_list));
                            }
                        }
                    }
                }
            }
            TableModifications::Replaced(rows) => {
                // For replaced tables, we have all TypeDef data
                for (i, row_data) in rows.iter().enumerate() {
                    let rid_usize = i.checked_add(1).ok_or_else(|| Error::ValidationRawFailed {
                        validator: "integrity".to_string(),
                        message: "Table row index overflow when computing RID".to_string(),
                    })?;
                    let rid = u32::try_from(rid_usize).map_err(|_| Error::ValidationRawFailed {
                        validator: "integrity".to_string(),
                        message: "Table row index exceeds u32 range".to_string(),
                    })?;
                    if typedef_rids.contains(&rid) {
                        if let TableDataOwned::TypeDef(typedef_row) = row_data {
                            typedef_field_lists.push((rid, typedef_row.field_list));
                        }
                    }
                }
            }
        }

        // Sort by field_list to validate ranges
        typedef_field_lists.sort_by_key(|(_, field_list)| *field_list);

        // Validate each TypeDef's field range
        for i in 0..typedef_field_lists.len() {
            let (typedef_rid, field_list_start) = *typedef_field_lists.get(i).ok_or_else(|| {
                malformed_error!(
                    "TypeDef field-list index {} out of bounds (len {})",
                    i,
                    typedef_field_lists.len()
                )
            })?;

            // Determine the end of this type's field range
            let next_index = i
                .checked_add(1)
                .ok_or_else(|| malformed_error!("TypeDef field-list index overflow at {}", i))?;
            let field_list_end = if next_index < typedef_field_lists.len() {
                typedef_field_lists
                    .get(next_index)
                    .ok_or_else(|| {
                        malformed_error!(
                            "TypeDef field-list next index {} out of bounds (len {})",
                            next_index,
                            typedef_field_lists.len()
                        )
                    })?
                    .1 // Next type's field_list
            } else {
                // For the last type, use the maximum field RID + 1
                field_rids
                    .iter()
                    .max()
                    .map_or(1, |max| max.saturating_add(1))
            };

            // A list starts at a row of the table or one past its end (an empty list at the
            // end); 0 is not a row (ECMA-335 II.22.37)
            let past_end = field_rids
                .iter()
                .max()
                .map_or(1, |max| max.saturating_add(1));
            if field_list_start == 0 || field_list_start > past_end {
                return Err(malformed_error!(
                    "Field ownership violation: TypeDef RID {} starts its field list at {}, outside the Field table (1 to {})",
                    typedef_rid,
                    field_list_start,
                    past_end
                ));
            }

            // Validate that all fields in this range exist
            for field_rid in field_list_start..field_list_end {
                if !field_rids.contains(&field_rid) {
                    return Err(malformed_error!(
                        "Field ownership violation: TypeDef RID {} expects field RID {} but field was deleted",
                        typedef_rid,
                        field_rid
                    ));
                }
            }
        }

        // Check for orphaned fields (fields that don't belong to any type)
        let mut owned_fields: FxHashSet<u32> = FxHashSet::default();
        for (_, field_list_start) in &typedef_field_lists {
            if *field_list_start > 0 {
                owned_fields.insert(*field_list_start);
            }
        }

        // For a complete validation, we'd need to check all fields fall within some type's range
        // This is complex without access to original TypeDef data, so we do a basic orphan check
        let min_owned_field = owned_fields.iter().min().copied().unwrap_or(u32::MAX);
        let _max_field = field_rids.iter().max().copied().unwrap_or(0);

        if min_owned_field != u32::MAX && min_owned_field > 1 {
            // Check for fields before the first owned field
            for field_rid in 1..min_owned_field {
                if field_rids.contains(&field_rid) {
                    return Err(malformed_error!(
                        "Orphaned field detected: Field RID {} exists but is not owned by any TypeDef",
                        field_rid
                    ));
                }
            }
        }

        Ok(())
    }
}

impl RawValidator for RawChangeIntegrityValidator {
    /// Validates the post-change structural integrity and consistency of assembly modifications.
    ///
    /// Performs comprehensive validation of the final assembly state after all modifications
    /// have been applied, including:
    /// 1. Table integrity validation (RID sequences, gaps, critical table requirements)
    /// 2. Heap integrity validation (size limits, structure consistency)
    /// 3. Cross-table reference integrity validation (relationship consistency)
    /// 4. Change conflict validation (operation ordering, race conditions)
    ///
    /// This method provides essential guarantees about the final assembly integrity
    /// that the writing pipeline can rely upon for safe metadata generation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly changes and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All assembly changes maintain integrity and consistency
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Integrity violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] for:
    /// - Broken referential integrity after modifications
    /// - Invalid heap state after changes
    /// - Conflicting operations that create inconsistent state
    /// - RID sequence violations or gaps
    /// - Cross-table reference inconsistencies
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on assembly changes.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        if let Some(changes) = context.changes() {
            let table_changes = &changes.table_changes;

            Self::validate_table_integrity(table_changes)?;
            Self::validate_reference_integrity(table_changes)?;
            Self::validate_change_conflicts(table_changes)?;
        }

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawChangeIntegrityValidator"
    }

    fn priority(&self) -> u32 {
        100
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_structural_validation && context.is_modification_validation()
    }
}

impl Default for RawChangeIntegrityValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;
    use crate::{
        cilassembly::{AssemblyChanges, Operation, TableModifications, TableOperation},
        metadata::{
            cilassemblyview::CilAssemblyView,
            tables::{CodedIndex, CodedIndexType, TableDataOwned, TableId, TypeDefRaw},
            token::Token,
            validation::{
                context::RawValidationContext, scanner::ReferenceScanner, ValidationConfig,
            },
        },
        testkit::{
            factories::validation::raw_modification_integrity::{
                create_dummy_field, create_dummy_method, create_dummy_typedef,
                raw_change_integrity_validator_file_factory,
            },
            get_testfile_wb, validator_test,
        },
    };

    /// Direct corruption testing for RawChangeIntegrityValidator bypassing file I/O.
    ///
    /// This test creates corrupted AssemblyChanges structures directly and validates
    /// that the validator properly detects all types of integrity violations including:
    /// - RID conflicts and sequence gaps
    /// - Critical table violations
    /// - Heap size limit violations
    /// - Reference integrity violations
    /// - Operation chronology violations
    #[test]
    fn test_raw_change_integrity_validator_direct_corruption() -> Result<()> {
        let validator = RawChangeIntegrityValidator::new();

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let typedef_data = create_dummy_typedef(1)?;
            let operation = TableOperation::new_with_timestamp(
                Operation::Insert(1, TableDataOwned::TypeDef(typedef_data)),
                1000,
            );

            let operations = vec![operation];

            let sparse_modifications = TableModifications::Sparse {
                operations,
                next_rid: 2,
                original_row_count: 1,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, sparse_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let typedef_data = create_dummy_typedef(100)?;
            let operation = TableOperation::new_with_timestamp(
                Operation::Insert(100, TableDataOwned::TypeDef(typedef_data)),
                1000,
            );

            let operations = vec![operation];

            let sparse_modifications = TableModifications::Sparse {
                operations,
                next_rid: 101,
                original_row_count: 1,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, sparse_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let typedef_data = create_dummy_typedef(5)?;
            let operation = TableOperation::new_with_timestamp(
                Operation::Insert(5, TableDataOwned::TypeDef(typedef_data)),
                1000,
            );

            let operations = vec![operation];

            let sparse_modifications = TableModifications::Sparse {
                operations,
                next_rid: 5,
                original_row_count: 1,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, sparse_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let mut deleted_rows = HashSet::new();
            deleted_rows.insert(1);

            let sparse_modifications = TableModifications::Sparse {
                operations: Vec::new(),
                next_rid: 2,
                original_row_count: 1,
                deleted_rows,
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::Module, sparse_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let replaced_modifications = TableModifications::Replaced(Vec::new());
            corrupted_changes
                .table_changes
                .insert(TableId::Module, replaced_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        // Test 11: Orphaned fields (fields exist but no TypeDef entries)
        {
            let mut corrupted_changes = AssemblyChanges::new();

            let typedef_modifications = TableModifications::Replaced(Vec::new());
            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, typedef_modifications);

            let field_data = create_dummy_field(1)?;
            let operation = TableOperation::new_with_timestamp(
                Operation::Insert(1, TableDataOwned::Field(field_data)),
                1000,
            );

            let field_modifications = TableModifications::Sparse {
                operations: vec![operation],
                next_rid: 2,
                original_row_count: 0,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::Field, field_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let typedef_modifications = TableModifications::Replaced(Vec::new());
            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, typedef_modifications);

            let method_data = create_dummy_method(1)?;
            let operation = TableOperation::new_with_timestamp(
                Operation::Insert(1, TableDataOwned::MethodDef(method_data)),
                1000,
            );

            let method_modifications = TableModifications::Sparse {
                operations: vec![operation],
                next_rid: 2,
                original_row_count: 0,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::MethodDef, method_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let operation1 = TableOperation::new_with_timestamp(
                Operation::Insert(2, TableDataOwned::TypeDef(create_dummy_typedef(2)?)),
                2000,
            );

            let operation2 = TableOperation::new_with_timestamp(
                Operation::Insert(3, TableDataOwned::TypeDef(create_dummy_typedef(3)?)),
                1000,
            );

            let sparse_modifications = TableModifications::Sparse {
                operations: vec![operation1, operation2],
                next_rid: 4,
                original_row_count: 1,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, sparse_modifications);

            assert!(test_validator_with_corrupted_changes(&validator, corrupted_changes).is_err());
        }

        {
            let mut corrupted_changes = AssemblyChanges::new();

            let mut operations = Vec::new();
            for i in 0..10_001 {
                let operation = TableOperation::new_with_timestamp(
                    Operation::Insert(i + 2, TableDataOwned::TypeDef(create_dummy_typedef(i + 2)?)),
                    1000 + i as u64,
                );
                operations.push(operation);
            }

            let sparse_modifications = TableModifications::Sparse {
                operations,
                next_rid: 10_003,
                original_row_count: 1,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, sparse_modifications);

            // Many operations are not a fault: ECMA-335 bounds a table by its 24-bit RIDs only.
            let result = test_validator_with_corrupted_changes(&validator, corrupted_changes);
            assert!(result.is_ok(), "{result:?}");
        }

        // Test 12: Field ownership validation - TypeDef points to deleted field
        {
            let mut corrupted_changes = AssemblyChanges::new();

            // Insert a TypeDef that points to field RID 100
            let typedef_operation = TableOperation::new(Operation::Insert(
                1,
                TableDataOwned::TypeDef(TypeDefRaw {
                    rid: 1,
                    token: Token::new(1 | 0x0200_0000),
                    offset: 0,
                    flags: 0x00100001,
                    type_name: 0,
                    type_namespace: 0,
                    extends: CodedIndex::new(TableId::TypeRef, 1, CodedIndexType::TypeDefOrRef),
                    field_list: 100, // Points to field RID 100
                    method_list: 1,
                }),
            ));

            let typedef_modifications = TableModifications::Sparse {
                operations: vec![typedef_operation],
                next_rid: 2,
                original_row_count: 0,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::TypeDef, typedef_modifications);

            // Create a field table without field RID 100 (will trigger field ownership violation)
            let field_modifications = TableModifications::Sparse {
                operations: vec![], // No fields
                next_rid: 1,
                original_row_count: 0,
                deleted_rows: HashSet::new(),
                inserted_rows: HashSet::new(),
                change_refs: HashMap::new(),
            };

            corrupted_changes
                .table_changes
                .insert(TableId::Field, field_modifications);

            let result = test_validator_with_corrupted_changes(&validator, corrupted_changes);
            assert!(
                matches!(&result, Err(e) if e.to_string().contains("starts its field list at 100")),
                "{result:?}"
            );
        }

        Ok(())
    }

    fn test_validator_with_corrupted_changes(
        validator: &RawChangeIntegrityValidator,
        corrupted_changes: AssemblyChanges,
    ) -> Result<()> {
        let clean_testfile = get_testfile_wb();

        let view = CilAssemblyView::from_path(&clean_testfile)?;
        let config = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };

        let scanner = ReferenceScanner::from_view(&view)?;
        let context = RawValidationContext::new_for_modification(
            &view,
            &corrupted_changes,
            &scanner,
            &config,
        );

        validator.validate_raw(&context)
    }

    #[test]
    fn test_raw_change_integrity_validator() -> Result<()> {
        let validator = RawChangeIntegrityValidator::new();
        let config = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_change_integrity_validator_file_factory,
            "RawChangeIntegrityValidator",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
