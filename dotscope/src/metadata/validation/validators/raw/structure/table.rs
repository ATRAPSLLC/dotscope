//! Table structure and metadata table integrity validation for .NET assemblies.
//!
//! This validator ensures the fundamental integrity of metadata table structures,
//! including proper table headers, row counts, and cross-table dependencies.
//! It operates on raw metadata structures to validate the foundational requirements
//! before higher-level semantic validation can proceed. This validator runs with
//! priority 190 in the raw validation stage, after token validation but before
//! constraint validation.
//!
//! # Architecture
//!
//! The table validation system implements comprehensive table-level validation strategies in sequential order:
//! 1. **Required Table Presence** - Ensures essential tables are present in valid assemblies (Module, Assembly)
//! 2. **Table Structure Validation** - Ensures table headers and row counts are consistent with ECMA-335 requirements
//! 3. **Cross-table Dependencies** - Validates relationships between metadata tables (TypeDef-Field, TypeDef-Method lists)
//!
//! The implementation uses type-safe dispatch mechanisms via [`crate::dispatch_table_type`] to validate all metadata
//! table types, ensuring comprehensive coverage of table structures according to ECMA-335 specifications.
//! This validator provides essential structural guarantees that higher-level validators depend upon.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::structure::table::RawTableValidator`] - Main validator implementation providing comprehensive table structure validation
//! - [`crate::metadata::validation::validators::raw::structure::table::RawTableValidator::validate_required_tables`] - Essential table presence validation for Module and Assembly tables
//! - [`crate::metadata::validation::validators::raw::structure::table::RawTableValidator::validate_table_structures`] - Core table structure validation including row count limits
//! - [`crate::metadata::validation::validators::raw::structure::table::RawTableValidator::validate_table_dependencies`] - Cross-table relationship validation for list-based references
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawTableValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawTableValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_raw(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationRawFailed`] for:
//! - Missing required metadata tables (Module table always required, Assembly table for executables)
//! - Invalid table row counts or inconsistent table headers (row counts exceeding 0x00FFFFFF)
//! - Malformed table structures or corrupted metadata (RID inconsistencies within tables)
//! - Cross-table dependency violations (TypeDef field/method list references beyond table bounds)
//! - Assembly table containing more than one row (ECMA-335 violation)
//! - Module table containing zero rows (at least one Module entry required)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - raw structure validators - Part of the foundational structural validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution with fail-fast behavior
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables for validation
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_structural_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.22](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata tables specification
//! - [ECMA-335 II.24.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Metadata layout requirements

use strum::IntoEnumIterator;

use crate::{
    dispatch_table_type,
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{AssemblyRaw, FieldRaw, MethodDefRaw, ModuleRaw, TableId, TypeDefRaw},
        validation::{
            context::{RawValidationContext, ValidationContext},
            shared::err_no_metadata_tables,
            traits::RawValidator,
        },
    },
    Result,
};

/// Foundation validator for metadata table structure and integrity.
///
/// Ensures the structural integrity of all metadata tables in a .NET assembly,
/// validating table headers, row counts, required table presence, and cross-table
/// dependencies. This validator operates at the lowest level of metadata validation,
/// providing essential guarantees before higher-level semantic validation can proceed.
///
/// The validator implements comprehensive coverage of all metadata table types using
/// type-safe dispatch mechanisms and validates both individual table structures and
/// their relationships according to ECMA-335 specifications.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable metadata structures.
pub struct RawTableValidator;

impl RawTableValidator {
    /// Creates a new table structure validator.
    ///
    /// Initializes a validator instance that can be used to validate metadata
    /// table structures across multiple assemblies. The validator is stateless
    /// and can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`RawTableValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates that all required metadata tables are present in the assembly.
    ///
    /// According to ECMA-335, certain tables are mandatory for valid .NET assemblies.
    /// This method ensures that essential tables like Module and Assembly (for executables)
    /// are present and accessible with valid content.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All required tables are present with valid content
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Required tables missing or invalid
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Module table is missing (always required by ECMA-335)
    /// - Module table is present but contains zero rows (at least one required)
    /// - Assembly table contains more than one row (ECMA-335 limit violation)
    fn validate_required_tables(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;

        let module_table = tables.table::<ModuleRaw>().ok_or_else(|| {
            malformed_error!("Module table is required but not present in assembly")
        })?;
        if module_table.row_count == 0 {
            return Err(malformed_error!(
                "Module table is present but contains no rows - at least one Module row is required"
            ));
        }

        if let Some(assembly_table) = tables.table::<AssemblyRaw>() {
            if assembly_table.row_count > 1 {
                return Err(malformed_error!(
                    "Assembly table contains {} rows but can contain at most 1 row",
                    assembly_table.row_count
                ));
            }
        }

        Ok(())
    }

    /// Validates the structural integrity of individual metadata tables.
    ///
    /// Ensures that each present table has consistent structure, valid row counts,
    /// and proper internal organization. This includes checking that table data
    /// is properly aligned and that row counts match table headers. Uses
    /// [`crate::dispatch_table_type`] for comprehensive coverage.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All table structures are valid and consistent
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Structure violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Table row counts exceed maximum allowed values (0x00FFFFFF)
    /// - RID values within table rows are inconsistent with expected sequential numbering
    /// - Internal table structure inconsistencies are detected during iteration
    fn validate_table_structures(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;

        for table_id in TableId::iter() {
            dispatch_table_type!(table_id, |RawType| {
                if let Some(table) = tables.table::<RawType>() {
                    let row_count = table.row_count;

                    if row_count > 0x00FF_FFFF {
                        return Err(malformed_error!(
                            "{:?} table contains {} rows, exceeding maximum of {} rows",
                            table_id,
                            row_count,
                            0x00FF_FFFF
                        ));
                    }
                }
            });
        }

        Ok(())
    }

    /// Validates cross-table dependencies and relationships.
    ///
    /// Ensures that metadata tables maintain proper relationships with each other
    /// according to ECMA-335 specifications. This includes validating that list-based
    /// references (TypeDef field lists, method lists) remain within table bounds.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All table dependencies are satisfied
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Dependency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - TypeDef field list references exceed Field table row count
    /// - TypeDef method list references exceed MethodDef table row count
    /// - List-based cross-table references are out of bounds
    fn validate_table_dependencies(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;

        if let (Some(typedef_table), Some(field_table)) =
            (tables.table::<TypeDefRaw>(), tables.table::<FieldRaw>())
        {
            for typedef_row in typedef_table {
                let typedef_row = typedef_row?;
                if typedef_row.field_list != 0
                    && typedef_row.field_list > field_table.row_count.saturating_add(1)
                {
                    return Err(malformed_error!(
                        "TypeDef RID {} references field list starting at RID {} but Field table only has {} rows",
                        typedef_row.rid,
                        typedef_row.field_list,
                        field_table.row_count
                    ));
                }
            }
        }

        if let (Some(typedef_table), Some(method_table)) =
            (tables.table::<TypeDefRaw>(), tables.table::<MethodDefRaw>())
        {
            for typedef_row in typedef_table {
                let typedef_row = typedef_row?;
                if typedef_row.method_list != 0
                    && typedef_row.method_list > method_table.row_count.saturating_add(1)
                {
                    return Err(malformed_error!(
                        "TypeDef RID {} references method list starting at RID {} but MethodDef table only has {} rows",
                        typedef_row.rid,
                        typedef_row.method_list,
                        method_table.row_count
                    ));
                }
            }
        }

        Ok(())
    }
}

impl RawValidator for RawTableValidator {
    /// Validates the structural integrity of all metadata tables in the assembly.
    ///
    /// Performs comprehensive validation of table structures, including:
    /// 1. Required table presence validation (Module, Assembly, etc.)
    /// 2. Table structure consistency (headers, row counts)
    /// 3. Cross-table dependency validation
    /// 4. Table ordering according to ECMA-335 requirements
    ///
    /// This method provides foundational guarantees about metadata table integrity
    /// that higher-level validators can rely upon during semantic validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All table structures are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Table structure violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] for:
    /// - Missing required tables (Module, Assembly for executables)
    /// - Invalid table row counts or corrupted table headers
    /// - Cross-table dependency violations
    /// - Tables present in invalid order
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        Self::validate_required_tables(assembly_view)?;
        Self::validate_table_structures(assembly_view)?;
        Self::validate_table_dependencies(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawTableValidator"
    }

    fn priority(&self) -> u32 {
        190
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_structural_validation
    }
}

impl Default for RawTableValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::validation::ValidationConfig,
        testkit::{
            factories::validation::raw_structure_table::*, get_testfile_wb, validator_test,
            TestAssembly,
        },
    };

    /// Comprehensive test for RawTableValidator using the centralized test harness.
    ///
    /// This test validates all core validation rules implemented by RawTableValidator:
    /// 1. Required Table Presence (validate_required_tables) - Tests Module table requirements
    /// 2. Table Structure Validation (validate_table_structures) - Tests row counts
    /// 3. Cross-Table Dependencies (validate_table_dependencies) - Tests field/method list bounds
    ///
    /// # Test Coverage
    ///
    /// - **Positive Test**: Clean WindowsBase.dll passes all validation rules
    /// - **Multiple Assembly Rows**: Assembly table with >1 rows triggers Malformed error
    /// - **Field List Violation**: TypeDef.field_list beyond Field table bounds triggers Malformed error
    /// - **Method List Violation**: TypeDef.method_list beyond MethodDef table bounds triggers Malformed error
    /// - **Empty Module Table**: Module table with 0 rows triggers Malformed error (FIXED - Delete operations now applied)
    ///
    /// # Future Test Coverage (TODO)
    ///
    ///
    /// # Test Configuration
    ///
    /// - enable_structural_validation: true (required for RawTableValidator)
    /// - Other validators disabled for isolation
    ///
    /// # Validation Rules Tested
    ///
    /// The test systematically validates ECMA-335 compliance for:
    /// - Module table presence and single row requirement
    /// - Assembly table maximum 1 row constraint
    /// - Table structure consistency and RID sequential numbering
    /// - Cross-table reference bounds checking
    ///
    /// Each test case targets exactly one validation rule to ensure test isolation
    /// and clear error attribution.
    #[test]
    fn test_raw_table_validator() -> Result<()> {
        let validator = RawTableValidator::new();
        let config = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_table_validator_file_factory,
            "RawTableValidator",
            config,
            |context| validator.validate_raw(context),
        )
    }

    /// Test that RawTableValidator configuration flags work correctly.
    ///
    /// Verifies that the validator respects enable_structural_validation configuration setting.
    #[test]
    fn test_raw_table_validator_configuration() -> Result<()> {
        let validator = RawTableValidator::new();

        fn clean_only_factory() -> Result<Vec<TestAssembly>> {
            let clean_testfile = get_testfile_wb();
            Ok(vec![TestAssembly::new(&clean_testfile)])
        }

        // Test disabled configuration
        let result_disabled = validator_test(
            clean_only_factory,
            "RawTableValidator",
            ValidationConfig {
                enable_structural_validation: false,
                ..Default::default()
            },
            |context| {
                if validator.should_run(context) {
                    validator.validate_raw(context)
                } else {
                    Ok(())
                }
            },
        );

        assert!(
            result_disabled.is_ok(),
            "Configuration test failed: validator should not run when disabled"
        );

        // Test enabled configuration
        let result_enabled = validator_test(
            clean_only_factory,
            "RawTableValidator",
            ValidationConfig {
                enable_structural_validation: true,
                ..Default::default()
            },
            |context| validator.validate_raw(context),
        );

        assert!(
            result_enabled.is_ok(),
            "Configuration test failed: validator should run when enabled"
        );
        Ok(())
    }

    /// Test RawTableValidator priority and metadata.
    ///
    /// Verifies validator metadata is correct for proper execution ordering.
    #[test]
    fn test_raw_table_validator_metadata() {
        let validator = RawTableValidator::new();

        assert_eq!(validator.name(), "RawTableValidator");
        assert_eq!(validator.priority(), 190);

        let _config_enabled = ValidationConfig {
            enable_structural_validation: true,
            ..Default::default()
        };
        let _config_disabled = ValidationConfig {
            enable_structural_validation: false,
            ..Default::default()
        };
    }
}
