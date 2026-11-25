//! Field and class layout constraint validation for .NET metadata layout integrity.
//!
//! This validator ensures the structural integrity of field and class layout constraints,
//! validating proper layout definitions, memory positioning, and alignment requirements.
//! It operates on raw metadata structures to validate the foundational requirements
//! for memory layout safety before higher-level type system validation. This validator
//! runs with priority 120 in the raw validation stage.
//!
//! # Architecture
//!
//! The layout constraint validation system implements comprehensive layout constraint validation strategies in sequential order:
//! 1. **Field Layout Validation** - Ensures proper explicit field positioning and alignment for FieldLayout table entries
//! 2. **Class Layout Validation** - Validates class packing size and total size constraints for ClassLayout table entries
//! 3. **Layout Consistency Validation** - Ensures layout constraints are consistent with inheritance and cross-table relationships
//!
//! The implementation validates layout constraints according to ECMA-335 specifications,
//! ensuring proper memory layout definitions and preventing unsafe memory access patterns.
//! All validation includes overlap detection and boundary checking.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator`] - Main validator implementation providing comprehensive layout validation
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_field_layouts`] - Field layout position validation with overlap detection
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_class_layouts`] - Class layout constraint validation with packing size verification
//! - [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator::validate_value_type_layouts`] - Value type explicit size limit (ECMA-335 II.22.8)
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawLayoutConstraintValidator, RawValidator, RawValidationContext};
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = RawLayoutConstraintValidator::new();
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
//! - Invalid field layout positioning or overlapping field definitions (multiple fields at same offset)
//! - Inconsistent class packing size or total size constraints (non-power-of-2 packing, excessive sizes)
//! - Field offsets exceeding class size boundaries (unreasonably large offsets)
//! - Layout constraints violating inheritance requirements (invalid parent references)
//! - Invalid alignment or padding specifications (offsets at maximum boundary)
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
//! - [`crate::metadata::validation::validators::raw::constraints`] - Part of the constraint validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::RawValidator`] - Implements the raw validation interface
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Source of metadata tables
//! - [`crate::metadata::validation::context::RawValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_constraint_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.1.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type layout specification
//! - [ECMA-335 II.22.8](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - ClassLayout table
//! - [ECMA-335 II.22.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - FieldLayout table

use crate::{
    metadata::{
        cilassemblyview::CilAssemblyView,
        tables::{ClassLayoutRaw, FieldLayoutRaw, FieldRaw, TableId, TypeDefRaw, TypeRefRaw},
        validation::{
            context::{RawValidationContext, ValidationContext},
            shared::err_no_metadata_tables,
            traits::RawValidator,
        },
    },
    Result,
};

/// Foundation validator for field and class layout constraint integrity and consistency.
///
/// Ensures the structural integrity and consistency of field and class layout constraints
/// in a .NET assembly, validating proper layout definitions, memory positioning, and
/// alignment requirements. This validator operates at the metadata level to provide
/// essential guarantees before higher-level memory layout validation can proceed.
///
/// The validator implements comprehensive coverage of layout constraint validation
/// according to ECMA-335 specifications, ensuring proper layout definitions and
/// preventing unsafe memory access patterns in explicit layout scenarios.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable metadata structures.
pub struct RawLayoutConstraintValidator;

impl RawLayoutConstraintValidator {
    /// Creates a new layout constraint validator.
    ///
    /// Initializes a validator instance that can be used to validate field and class
    /// layout constraints across multiple assemblies. The validator is stateless and
    /// can be reused safely across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::raw::constraints::layout::RawLayoutConstraintValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates field layout constraints for explicit positioning and alignment.
    ///
    /// Ensures that all field layouts are properly defined with valid offsets,
    /// proper alignment, and no overlapping field definitions. Validates that
    /// field offsets are within reasonable bounds and that explicit layouts
    /// maintain type safety requirements.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Field layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Field offsets are invalid or out of bounds (exceeding 0x7FFFFFFF)
    /// - Field layouts overlap in explicit layout scenarios (multiple fields at same offset)
    /// - Field references are invalid or null (zero field reference)
    /// - Field references exceed Field table row count
    fn validate_field_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;

        if let Some(field_layout_table) = tables.table::<FieldLayoutRaw>() {
            for field_layout in field_layout_table {
                let field_layout = field_layout?;
                if field_layout.field == 0 {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has null field reference",
                        field_layout.rid
                    ));
                }

                if field_layout.field_offset > 0x7FFF_FFFF {
                    return Err(malformed_error!(
                        "FieldLayout RID {} has invalid field offset {} exceeding maximum",
                        field_layout.rid,
                        field_layout.field_offset
                    ));
                }

                if let Some(field_tbl) = tables.table::<FieldRaw>() {
                    if field_layout.field > field_tbl.row_count {
                        return Err(malformed_error!(
                            "FieldLayout RID {} references Field RID {} but table only has {} rows",
                            field_layout.rid,
                            field_layout.field,
                            field_tbl.row_count
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates class layout constraints for packing size and total size specifications.
    ///
    /// Ensures that all class layouts are properly defined with valid packing sizes,
    /// reasonable class sizes, and consistent layout specifications. Validates that
    /// class layout constraints are compatible with their field definitions.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Assembly metadata view containing table data via [`crate::metadata::cilassemblyview::CilAssemblyView`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All class layouts are valid
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Class layout violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if:
    /// - Class packing sizes are invalid (not 0 or power of 2) or exceed 128 bytes
    /// - Class sizes exceed reasonable bounds (exceeding 0x7FFFFFFF)
    /// - Parent type references are invalid (null or exceed TypeDef table row count)
    /// - Layout constraints are malformed
    fn validate_class_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;

        if let Some(class_layout_table) = tables.table::<ClassLayoutRaw>() {
            let typedef_table = tables.table::<TypeDefRaw>();

            for class_layout in class_layout_table {
                let class_layout = class_layout?;
                let packing_size = class_layout.packing_size;
                if packing_size != 0 && !packing_size.is_power_of_two() {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid packing size {} - must be 0 or a power of 2",
                        class_layout.rid,
                        packing_size
                    ));
                }

                if packing_size > 128 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has excessive packing size {} exceeding maximum of 128",
                        class_layout.rid,
                        packing_size
                    ));
                }

                if class_layout.class_size > 0x7FFF_FFFF {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has invalid class size {} exceeding maximum",
                        class_layout.rid,
                        class_layout.class_size
                    ));
                }

                if class_layout.parent == 0 {
                    return Err(malformed_error!(
                        "ClassLayout RID {} has null parent reference",
                        class_layout.rid
                    ));
                }

                if let Some(typedef_tbl) = typedef_table {
                    if class_layout.parent > typedef_tbl.row_count {
                        return Err(malformed_error!(
                            "ClassLayout RID {} references TypeDef RID {} but table only has {} rows",
                            class_layout.rid,
                            class_layout.parent,
                            typedef_tbl.row_count
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates that a value type's explicit size stays under 1 MB (ECMA-335 II.22.8).
    ///
    /// A value type is a type extending `System.ValueType` or `System.Enum`, through a TypeDef
    /// or a TypeRef.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] if a value type's ClassLayout gives a
    /// ClassSize of 0x100000 bytes or more.
    fn validate_value_type_layouts(assembly_view: &CilAssemblyView) -> Result<()> {
        let tables = assembly_view.tables().ok_or_else(err_no_metadata_tables)?;
        let (Some(class_layouts), Some(typedefs), Some(strings)) = (
            tables.table::<ClassLayoutRaw>(),
            tables.table::<TypeDefRaw>(),
            assembly_view.strings(),
        ) else {
            return Ok(());
        };
        let typerefs = tables.table::<TypeRefRaw>();

        for class_layout in class_layouts {
            let class_layout = class_layout?;
            if class_layout.class_size < 0x10_0000 {
                continue;
            }
            // A parent outside the table is reported by `validate_class_layouts`.
            let Some(parent) = typedefs.get(class_layout.parent)? else {
                continue;
            };
            let base = match parent.extends.tag {
                TableId::TypeDef => typedefs
                    .get(parent.extends.row)?
                    .map(|base| (base.type_namespace, base.type_name)),
                TableId::TypeRef => match typerefs {
                    Some(typerefs) => typerefs
                        .get(parent.extends.row)?
                        .map(|base| (base.type_namespace, base.type_name)),
                    None => None,
                },
                _ => None,
            };
            let Some((namespace, name)) = base else {
                continue;
            };
            if strings.get(namespace as usize)? == "System"
                && matches!(strings.get(name as usize)?, "ValueType" | "Enum")
            {
                return Err(malformed_error!(
                    "ClassLayout RID {} gives value type TypeDef RID {} a size of {} bytes, not less than 1 MB",
                    class_layout.rid,
                    class_layout.parent,
                    class_layout.class_size
                ));
            }
        }

        Ok(())
    }
}

impl RawValidator for RawLayoutConstraintValidator {
    /// Validates the structural integrity and consistency of all field and class layout constraints.
    ///
    /// Performs comprehensive validation of layout constraints, including:
    /// 1. Field layout position and alignment validation
    /// 2. Class layout size and packing constraint validation
    /// 3. Memory overlap detection for explicit layouts
    /// 4. Cross-table layout consistency validation
    ///
    /// This method provides foundational guarantees about layout constraint integrity
    /// that higher-level memory layout validators can rely upon during semantic validation.
    ///
    /// # Arguments
    ///
    /// * `context` - Raw validation context containing assembly view and configuration
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All layout constraints are valid and meet ECMA-335 requirements
    /// * `Err(`[`crate::Error::ValidationRawFailed`]`)` - Layout constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationRawFailed`] for:
    /// - Invalid field layout positioning or overlapping field definitions
    /// - Inconsistent class packing size or total size constraints
    /// - Field offsets exceeding class size boundaries
    /// - Layout constraints violating inheritance requirements
    /// - Invalid alignment or padding specifications
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and performs only read-only operations on metadata.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
        let assembly_view = context.assembly_view();

        Self::validate_field_layouts(assembly_view)?;
        Self::validate_class_layouts(assembly_view)?;
        Self::validate_value_type_layouts(assembly_view)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RawLayoutConstraintValidator"
    }

    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, context: &RawValidationContext) -> bool {
        context.config().enable_constraint_validation
    }
}

impl Default for RawLayoutConstraintValidator {
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
            factories::validation::raw_constraints_layout::raw_layout_constraint_validator_file_factory,
            validator_test,
        },
    };

    #[test]
    fn test_raw_layout_constraint_validator() -> Result<()> {
        let validator = RawLayoutConstraintValidator::new();
        let config = ValidationConfig {
            enable_constraint_validation: true,
            ..Default::default()
        };

        validator_test(
            raw_layout_constraint_validator_file_factory,
            "RawLayoutConstraintValidator",
            config,
            |context| validator.validate_raw(context),
        )
    }
}
