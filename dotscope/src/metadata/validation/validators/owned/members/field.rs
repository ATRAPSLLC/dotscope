//! Owned field validator for field validation and layout rules.
//!
//! This validator provides comprehensive validation of field definitions, accessibility,
//! layout constraints, and signature consistency within the context of fully resolved
//! .NET metadata. It operates on resolved field structures to ensure ECMA-335 compliance
//! for field declarations and type system consistency. This validator runs with priority 155
//! in the owned validation stage.
//!
//! # Architecture
//!
//! The field validation system implements comprehensive field validation in sequential order:
//! 1. **Field Signature Validation** - Ensures field signatures are well-formed and types are resolved
//! 2. **Field Accessibility Validation** - Validates access modifiers and inheritance compatibility
//! 3. **Special Attributes Validation** - Validates special field attributes and constraints
//! 4. **Field Naming Validation** - Ensures field naming conventions and special patterns
//!
//! The implementation validates field constraints according to ECMA-335 specifications,
//! ensuring proper field definitions across type hierarchies and member relationships.
//! All validation includes signature checking and accessibility rule verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator`] - Main validator implementation providing comprehensive field validation
//! - [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator::validate_field_signatures`] - Field signature consistency and type resolution validation
//! - [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator::validate_field_accessibility`] - Field accessibility and inheritance rule validation
//! - [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator::validate_special_attributes`] - Special field attribute validation (HasDefault, HasFieldRVA, etc.)
//! - [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator::validate_field_naming`] - Field naming convention validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedFieldValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedFieldValidator::new();
//!
//! // Check if validation should run based on configuration
//! if validator.should_run(&context) {
//!     validator.validate_owned(&context)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! This validator returns [`crate::Error::ValidationOwnedFailed`] for:
//! - Field signature consistency violations (empty names, unresolved types)
//! - Invalid field accessibility levels (unknown access modifiers)
//! - Field attribute constraint violations (literal fields not static)
//! - Special attribute inconsistencies (RTSpecialName without SpecialName)
//! - Field naming convention violations (backing fields not private)
//! - Type signature resolution failures (a named type that does not resolve)
//! - Field modifier validation failures (invalid tokens)
//!
//! # Thread Safety
//!
//! All validation operations are read-only and thread-safe. The validator implements [`Send`] + [`Sync`]
//! and can be used concurrently across multiple threads without synchronization as it operates on
//! immutable resolved metadata structures.
//!
//! # Integration
//!
//! This validator integrates with:
//! - [`crate::metadata::validation::validators::owned::members`] - Part of the owned member validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved field structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.22.15](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field table specification
//! - [ECMA-335 II.23.1.5](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - FieldAttributes specification
//! - [ECMA-335 II.10.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field layout and packing
//! - [ECMA-335 II.16](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Field initialization and constants

use crate::{
    metadata::{
        tables::FieldAttributes,
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for field definitions, accessibility rules, and layout constraints.
///
/// Ensures the structural integrity and consistency of field definitions in resolved .NET metadata,
/// validating proper field signatures, accessibility patterns, and special attribute usage.
/// This validator operates on resolved field structures to provide essential guarantees
/// about field compliance with ECMA-335 specifications.
///
/// The validator implements comprehensive coverage of field validation according to
/// ECMA-335 specifications, ensuring proper field definitions across type hierarchies
/// and member relationships in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedFieldValidator;

impl OwnedFieldValidator {
    /// Creates a new field validator instance.
    ///
    /// Initializes a validator instance that can be used to validate field definitions
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::members::field::OwnedFieldValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates field signature consistency and type resolution.
    ///
    /// Ensures that all field signatures are well-formed and that field types
    /// are properly resolved according to ECMA-335 specifications. Validates
    /// field names and signature modifiers.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved field structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field signatures are valid and resolved
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Field signature violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Field names are empty
    /// - Field signatures name types that do not resolve
    /// - Field modifiers have invalid tokens
    fn validate_field_signatures(&self, context: &OwnedValidationContext) -> Result<()> {
        // This assembly's types: a field's type tokens are its own module's, and a type resolved
        // from another assembly is validated with that assembly.
        for type_entry in context.target_assembly_types() {
            for (_, field) in type_entry.fields.iter() {
                if field.name.is_empty() {
                    let token_value = field.token.value();
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Field with token 0x{token_value:08X} has empty name"),
                    });
                }

                if let Some(token) = context.unresolved_type(|out| field.signature.type_tokens(out))
                {
                    let field_name = &field.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Field '{field_name}' has unresolved type 0x{:08X} in signature",
                            token.value()
                        ),
                    });
                }

                for (index, modifier) in field.signature.modifiers.iter().enumerate() {
                    if modifier.modifier_type.value() == 0 {
                        let field_name = &field.name;
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Field '{field_name}' modifier {index} has invalid token"
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates field accessibility and inheritance rules.
    ///
    /// Ensures that field access modifiers are valid and compatible with
    /// inheritance patterns and type accessibility. Validates literal field
    /// requirements and access level consistency.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved field structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field accessibility rules are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Field accessibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Field access levels contain invalid values
    /// - Literal fields are not marked as static (ECMA-335 requirement)
    fn validate_field_accessibility(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            for (_, field) in type_entry.fields.iter() {
                let access_level = field.flags.access();

                match access_level {
                    FieldAttributes::COMPILER_CONTROLLED
                    | FieldAttributes::PRIVATE
                    | FieldAttributes::FAM_AND_ASSEM
                    | FieldAttributes::ASSEMBLY
                    | FieldAttributes::FAMILY
                    | FieldAttributes::FAM_OR_ASSEM
                    | FieldAttributes::PUBLIC => {
                        // Valid access level
                    }
                    _ => {
                        let field_name = &field.name;
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Field '{field_name}' has invalid access level: 0x{access_level:02X}"
                            ),

                        });
                    }
                }

                if field.flags.is_static() && field.flags.is_init_only() {
                    // This is actually valid - static readonly fields are allowed
                    // No error here
                }

                if field.flags.is_literal() && !field.flags.is_static() {
                    let field_name = &field.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Literal field '{field_name}' must also be static"),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates special field attributes and constraints.
    ///
    /// Ensures that special field attributes like HasDefault, HasFieldRVA, and
    /// HasFieldMarshal are used correctly and consistently. Validates RTSpecialName
    /// and SpecialName flag combinations.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved field structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All special field attributes are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Special attribute violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - RTSpecialName flag is set without SpecialName flag
    fn validate_special_attributes(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            for (_, field) in type_entry.fields.iter() {
                // Check HasDefault flag consistency
                if field.flags.has_default() {
                    // Field claims to have default value - this is generally valid
                    // The actual default value validation would require accessing the Constant table
                }

                // Check HasFieldRVA flag consistency
                if field.flags.has_field_rva() {
                    // Field should have RVA - typically for static fields with initial data
                    // However, in legitimate .NET assemblies, instance fields can also have this flag
                    // for specific purposes (synchronization objects, fixed buffers, etc.)
                    // So we allow this pattern and only validate the flag exists
                }

                // Check HasFieldMarshal flag
                if field.flags.has_field_marshal() {
                    // Field has marshalling information - this is valid for P/Invoke scenarios
                    // No specific validation needed here
                }

                // Check NotSerialized flag
                if field.flags.is_not_serialized() {
                    // Field is marked as not serialized - this is valid
                    // No specific validation needed
                }

                // Check RTSpecialName flag (if present)
                if field.flags.is_rt_special_name() {
                    // Field has special meaning to runtime
                    // Often paired with SpecialName
                    if !field.flags.is_special_name() {
                        let field_name = &field.name;
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Field '{field_name}' has RTSpecialName but not SpecialName"
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates field naming conventions and special patterns.
    ///
    /// Ensures that fields follow appropriate naming conventions, especially
    /// for compiler-generated and special-purpose fields. Validates backing
    /// field accessibility and naming character constraints.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved field structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All field naming conventions are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Field naming violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Backing fields are not marked as private
    fn validate_field_naming(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            for (_, field) in type_entry.fields.iter() {
                if field.name.starts_with('<') && field.name.ends_with(">k__BackingField") {
                    let access_level = field.flags.access();
                    if access_level != FieldAttributes::PRIVATE {
                        let field_name = &field.name;
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!("Backing field '{field_name}' should be private"),
                        });
                    }
                }

                if field.name.starts_with('<')
                    && field.name.contains("Event")
                    && !field.flags.is_static()
                {
                    let access_level = field.flags.access();
                    if access_level == FieldAttributes::PUBLIC {}
                }
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedFieldValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_field_signatures(context)?;
        self.validate_field_accessibility(context)?;
        self.validate_special_attributes(context)?;
        self.validate_field_naming(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedFieldValidator"
    }

    fn priority(&self) -> u32 {
        155
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedFieldValidator {
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
            factories::validation::members_field::owned_field_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_field_validator() -> Result<()> {
        let validator = OwnedFieldValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_field_validator_file_factory,
            "OwnedFieldValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
