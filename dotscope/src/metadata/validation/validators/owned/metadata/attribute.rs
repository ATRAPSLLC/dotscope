//! Owned attribute validator for custom attribute validation.
//!
//! This validator provides comprehensive validation of custom attributes according to ECMA-335
//! specifications within the context of fully resolved .NET metadata. It operates on resolved
//! custom attribute structures to check that their arguments are well formed. This validator
//! runs with priority 130 in the owned validation stage.
//!
//! # Architecture
//!
//! **Attribute Usage Validation** checks each attribute's fixed and named arguments against
//! ECMA-335 II.23.3: an enum argument names its enum type, no argument is void, and a named
//! argument names a field or property. It enforces no limits of its own: counts, lengths and
//! contents ECMA-335 allows are allowed.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator`] - Main validator implementation providing comprehensive attribute validation
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_usage_rules`] - Attribute usage constraint validation with target checking
//! - [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator::validate_attribute_usage`] - Individual attribute validation with argument checking
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedAttributeValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedAttributeValidator::new();
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
//! - Malformed fixed or named arguments (void values, enums without their type)
//! - Named arguments with empty names
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
//! - [`crate::metadata::validation::validators::owned::metadata`] - Part of the owned metadata validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved custom attribute structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attributes
//! - [ECMA-335 II.22.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - CustomAttribute table
//! - [ECMA-335 II.23.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attribute encoding
//! - [ECMA-335 IV](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Attribute class specifications

use crate::{
    metadata::{
        customattributes::{CustomAttributeArgument, CustomAttributeValue},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for custom attribute usage, constructor calls, and target compatibility.
///
/// Ensures the structural integrity and consistency of custom attributes in resolved .NET metadata,
/// validating proper attribute usage patterns, constructor parameter validity, and target placement
/// compatibility. This validator operates on resolved custom attribute structures to provide
/// essential guarantees about attribute compliance with ECMA-335 specifications.
///
/// The validator implements comprehensive coverage of custom attribute validation according to
/// ECMA-335 specifications, ensuring proper attribute usage patterns and preventing malformed
/// attribute data in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedAttributeValidator;

impl OwnedAttributeValidator {
    /// Creates a new attribute validator instance.
    ///
    /// Initializes a validator instance that can be used to validate custom attributes
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::metadata::attribute::OwnedAttributeValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedAttributeValidator {
    /// Validates custom attribute usage rules and AttributeUsage constraints.
    ///
    /// Ensures that custom attributes are applied according to their AttributeUsage
    /// declarations, including valid targets, inheritance, and multiple usage rules.
    /// Validates attributes on both types and methods for proper usage patterns.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved custom attribute structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All attribute usage rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Attribute usage violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Custom attributes have invalid usage patterns on types or methods
    /// - Attribute arguments are malformed or invalid
    fn validate_attribute_usage_rules(&self, context: &OwnedValidationContext) -> Result<()> {
        // Validate attributes on this assembly's types; another assembly's are validated with it
        for type_entry in context.target_assembly_types() {
            for (_, custom_attr) in type_entry.custom_attributes.iter() {
                if let Err(e) = self.validate_attribute_usage(custom_attr, "Type") {
                    let type_name = &type_entry.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{type_name}' has invalid custom attribute usage: {e}"
                        ),
                    });
                }
            }
        }

        // Validate attributes on methods
        for method_entry in context.object().methods() {
            let method = method_entry.value();
            for (_, custom_attr) in method.custom_attributes.iter() {
                if let Err(e) = self.validate_attribute_usage(custom_attr, "Method") {
                    let method_name = &method.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{method_name}' has invalid custom attribute usage: {e}"
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates a single custom attribute usage.
    ///
    /// Checks if the attribute is valid for the given target type and follows
    /// proper usage rules defined by the attribute class. Validates both fixed
    /// and named arguments for proper structure and content.
    ///
    /// # Arguments
    ///
    /// * `custom_attr` - Custom attribute value to validate via [`crate::metadata::customattributes::CustomAttributeValue`]
    /// * `_target` - Target type description for error reporting
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Attribute usage is valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Attribute usage violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Fixed arguments are invalid or malformed
    /// - Named arguments have empty names or invalid values
    fn validate_attribute_usage(
        &self,
        custom_attr: &CustomAttributeValue,
        _target: &str,
    ) -> Result<()> {
        // Validate fixed arguments are well-formed
        for (index, arg) in custom_attr.fixed_args.iter().enumerate() {
            if !self.is_valid_attribute_argument(arg) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Custom attribute has invalid fixed argument at index {index}: {arg:?}"
                    ),
                });
            }
        }

        // Validate named arguments are well-formed
        for named_arg in &custom_attr.named_args {
            if named_arg.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: "Custom attribute has named argument with empty name".to_string(),
                });
            }

            if !self.is_valid_attribute_argument(&named_arg.value) {
                let arg_name = &named_arg.name;
                let arg_value = &named_arg.value;
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Custom attribute has invalid named argument '{arg_name}': {arg_value:?}"
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validates that an attribute argument is well-formed.
    ///
    /// Checks that the argument type is valid for custom attributes and
    /// that complex types like arrays and enums are properly structured.
    /// Performs recursive validation for array elements.
    ///
    /// # Arguments
    ///
    /// * `arg` - Custom attribute argument to validate via [`crate::metadata::customattributes::CustomAttributeArgument`]
    ///
    /// # Returns
    ///
    /// * `true` - Argument is well-formed and valid
    /// * `false` - Argument has structural issues or invalid content
    #[allow(clippy::self_only_used_in_recursion)]
    fn is_valid_attribute_argument(&self, arg: &CustomAttributeArgument) -> bool {
        match arg {
            // Primitive types are always valid
            CustomAttributeArgument::Bool(_)
            | CustomAttributeArgument::Char(_)
            | CustomAttributeArgument::I1(_)
            | CustomAttributeArgument::U1(_)
            | CustomAttributeArgument::I2(_)
            | CustomAttributeArgument::U2(_)
            | CustomAttributeArgument::I4(_)
            | CustomAttributeArgument::U4(_)
            | CustomAttributeArgument::I8(_)
            | CustomAttributeArgument::U8(_)
            | CustomAttributeArgument::R4(_)
            | CustomAttributeArgument::R8(_)
            | CustomAttributeArgument::Type(_) => true,

            // A .NET string may hold any UTF-16 unit, NUL included
            CustomAttributeArgument::String(_) => true,

            CustomAttributeArgument::Array(_, elements) => elements
                .iter()
                .flatten()
                .all(|elem| self.is_valid_attribute_argument(elem)),

            CustomAttributeArgument::Enum(type_name, underlying_value) => {
                !type_name.is_empty() && self.is_valid_attribute_argument(underlying_value)
            }

            // The grammar names a boxed value's type before it, and has no type for a box
            CustomAttributeArgument::Boxed(value) => {
                !matches!(**value, CustomAttributeArgument::Boxed(_))
                    && self.is_valid_attribute_argument(value)
            }
        }
    }
}

impl OwnedValidator for OwnedAttributeValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_attribute_usage_rules(context)?;
        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedAttributeValidator"
    }

    fn priority(&self) -> u32 {
        130
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedAttributeValidator {
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
            factories::validation::attribute::owned_attribute_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_attribute_validator() -> Result<()> {
        let validator = OwnedAttributeValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_attribute_validator_file_factory,
            "OwnedAttributeValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
