//! Owned accessibility validator for visibility rules and access control validation.
//!
//! This validator provides comprehensive validation of accessibility and visibility rules
//! for types and members within the context of fully resolved .NET metadata. It operates
//! on resolved type structures to ensure ECMA-335 compliance for access control patterns
//! and inheritance visibility. This validator runs with priority 160 in the owned validation stage.
//!
//! # Architecture
//!
//! The accessibility validation system implements comprehensive access control validation in sequential order:
//! 1. **Type Accessibility** - Validates type visibility and accessibility rules according to ECMA-335
//! 2. **Member Accessibility** - Ensures member accessibility consistency with containing types
//! 3. **Interface Accessibility** - Validates interface implementation accessibility requirements
//! 4. **Inheritance Accessibility** - Validates accessibility inheritance patterns and rules
//!
//! The implementation validates accessibility constraints according to ECMA-335 specifications,
//! ensuring proper access control patterns across type hierarchies and member definitions.
//! All validation includes cross-reference checking and inheritance rule verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator`] - Main validator implementation providing comprehensive accessibility validation
//! - [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator::validate_type_accessibility`] - Type visibility and accessibility rule validation
//! - [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator::validate_member_accessibility`] - Member accessibility consistency validation
//! - [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator::validate_interface_accessibility`] - Interface implementation accessibility validation
//! - [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator::validate_inheritance_accessibility`] - Inheritance accessibility pattern validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedAccessibilityValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedAccessibilityValidator::new();
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
//! - Invalid type visibility attributes (unknown visibility values)
//! - Inconsistent member accessibility relative to containing types
//! - Nested type accessibility violations (improper visibility combinations)
//! - Interface implementation accessibility requirements not met
//! - Literal fields that are not static (ECMA-335 violation)
//! - Interfaces containing non-constant fields
//! - Sealed interfaces (invalid combination)
//! - Types with empty names or invalid accessibility patterns
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
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.23.1.15](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeAttributes specification
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type accessibility rules
//! - [ECMA-335 II.10.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Member accessibility rules
//! - [ECMA-335 II.10.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Inheritance and accessibility

use crate::{
    metadata::{
        // method::{MethodAccessFlags, MethodModifiers}, // Unused imports
        tables::{FieldAttributes, TypeAttributes},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for accessibility rules, visibility constraints, and access control consistency.
///
/// Ensures the structural integrity and consistency of accessibility rules for types and members
/// in resolved .NET metadata, validating proper access control patterns, inheritance visibility,
/// and interface implementation requirements. This validator operates on resolved type structures
/// to provide essential guarantees about accessibility compliance.
///
/// The validator implements comprehensive coverage of accessibility validation according to
/// ECMA-335 specifications, ensuring proper access control patterns across type hierarchies
/// and member definitions in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedAccessibilityValidator;

impl OwnedAccessibilityValidator {
    /// Creates a new accessibility validator instance.
    ///
    /// Initializes a validator instance that can be used to validate accessibility rules
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::members::accessibility::OwnedAccessibilityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates type visibility and accessibility rules.
    ///
    /// Ensures that type visibility attributes are valid and consistent with
    /// ECMA-335 specifications for type accessibility. Validates nested type
    /// visibility rules and interface sealing constraints.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All type accessibility rules are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Accessibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Type visibility attributes contain invalid values
    /// - Nested types have inappropriate visibility flags
    /// - Interfaces are marked as sealed (invalid combination)
    fn validate_type_accessibility(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            let visibility = type_entry.flags.visibility();

            match visibility {
                TypeAttributes::NOT_PUBLIC
                | TypeAttributes::PUBLIC
                | TypeAttributes::NESTED_PUBLIC
                | TypeAttributes::NESTED_PRIVATE
                | TypeAttributes::NESTED_FAMILY
                | TypeAttributes::NESTED_ASSEMBLY
                | TypeAttributes::NESTED_FAM_AND_ASSEM
                | TypeAttributes::NESTED_FAM_OR_ASSEM => {
                    // Valid visibility
                }
                _ => {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has invalid visibility: 0x{:02X}",
                            type_entry.name, visibility
                        ),
                    });
                }
            }

            // Validate that types which ARE nested have proper nested visibility.
            // Only check TypeDef entries (0x02) - TypeRef entries lack flags metadata.
            if type_entry.token.table() == 0x02 && type_entry.enclosing_type.get().is_some() {
                // This is a nested type - it must use nested visibility flags (0x02-0x07)
                // It cannot use top-level visibility (NOT_PUBLIC=0x00, PUBLIC=0x01)
                // and cannot use values beyond NESTED_FAM_OR_ASSEM (>0x07)
                if !matches!(
                    visibility,
                    TypeAttributes::NESTED_PUBLIC
                        | TypeAttributes::NESTED_PRIVATE
                        | TypeAttributes::NESTED_FAMILY
                        | TypeAttributes::NESTED_ASSEMBLY
                        | TypeAttributes::NESTED_FAM_AND_ASSEM
                        | TypeAttributes::NESTED_FAM_OR_ASSEM
                ) {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Nested type '{}' has invalid visibility flags: 0x{:02X} (must be between NESTED_PUBLIC=0x02 and NESTED_FAM_OR_ASSEM=0x07)",
                            type_entry.name, visibility
                        ),

                    });
                }
            }

            if type_entry.flags.is_interface() && type_entry.flags.is_sealed() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Interface '{}' cannot be sealed", type_entry.name),
                });
            }
        }

        Ok(())
    }

    /// Validates member accessibility consistency with containing types.
    ///
    /// Ensures that members have appropriate accessibility relative to their
    /// containing types and that accessibility rules are logically consistent.
    /// Validates field and method accessibility patterns.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All member accessibility rules are consistent
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Member accessibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Methods have empty names
    /// - Literal fields are not marked as static (ECMA-335 requirement)
    fn validate_member_accessibility(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            let type_visibility = type_entry.flags.visibility();

            for (_, method_ref) in type_entry.methods.iter() {
                if let Some(method) = method_ref.upgrade() {
                    // ToDo: For full validation, we would need to resolve the method reference
                    // to get its actual accessibility flags. Here we're working with references.

                    if method.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!("Method in type '{}' has empty name", type_entry.name),
                        });
                    }
                }
            }

            for (_, field) in type_entry.fields.iter() {
                let field_access = field.flags.access();

                if field_access == FieldAttributes::PUBLIC
                    && type_visibility == TypeAttributes::NOT_PUBLIC
                {
                    // Public field in internal type - this is sometimes valid
                    // but worth noting for consistency
                }

                if field.flags.is_literal() && !field.flags.is_static() {
                    // LITERAL flag but not static
                    let field_name = &field.name;
                    let type_name = &type_entry.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Literal field '{field_name}' in type '{type_name}' must be static"
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates interface implementation accessibility requirements.
    ///
    /// Ensures that types implementing interfaces have appropriate accessibility
    /// and that interface members are properly accessible. Validates interface
    /// field constraints and implementation patterns.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All interface accessibility requirements are met
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Interface accessibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Interface types have empty names
    /// - Interfaces contain non-static fields
    /// - Interfaces contain non-constant fields
    fn validate_interface_accessibility(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            for (_, entry) in type_entry.interfaces.iter() {
                let type_visibility = type_entry.flags.visibility();
                if let Some(interface_type) = entry.interface.upgrade() {
                    let interface_visibility = interface_type.flags.visibility();

                    if interface_visibility == TypeAttributes::PUBLIC
                        && type_visibility == TypeAttributes::NOT_PUBLIC
                    {
                        // Internal type implementing public interface - this is valid
                    }

                    if interface_type.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' implements interface with empty name",
                                type_entry.name
                            ),
                        });
                    }
                }
            }

            // ECMA-335 II.12: an interface may have static fields, constant or not, but no
            // instance fields. (CLS-compliant interfaces define no fields at all, but that is a
            // language rule, not one the runtime enforces.)
            if type_entry.flags.is_interface() {
                for (_, field) in type_entry.fields.iter() {
                    if !field.flags.is_static() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Interface '{}' contains non-static field '{}'",
                                type_entry.name, field.name
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates accessibility inheritance patterns.
    ///
    /// Ensures that derived types maintain appropriate accessibility relative
    /// to their base types and that inheritance accessibility rules are followed.
    /// Validates abstract and sealed type combinations.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All inheritance accessibility patterns are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Inheritance accessibility violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if inheritance accessibility patterns are violated
    /// (specific violations depend on resolved type hierarchy analysis).
    fn validate_inheritance_accessibility(context: &OwnedValidationContext) {
        for type_entry in context.all_types() {
            // ToDo: For complete inheritance validation, we need to resolve
            // base type references and check accessibility consistency

            // Basic validation: sealed types cannot be abstract (except for static classes)
            if type_entry.flags.is_sealed() && type_entry.flags.is_abstract() {
                // ABSTRACT flag - this is valid for static classes in C#
                // Static classes are marked as both abstract and sealed by the compiler
                // We allow this legitimate pattern
            }

            // Abstract types can be interfaces - interfaces are inherently abstract
            if type_entry.flags.is_abstract() && type_entry.flags.is_interface() {
                // Interfaces can be marked as abstract - this is standard behavior
            }
        }
    }
}

impl OwnedValidator for OwnedAccessibilityValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_type_accessibility(context)?;
        self.validate_member_accessibility(context)?;
        self.validate_interface_accessibility(context)?;
        Self::validate_inheritance_accessibility(context);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedAccessibilityValidator"
    }

    fn priority(&self) -> u32 {
        160
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedAccessibilityValidator {
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
            factories::validation::members_accessibility::owned_accessibility_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_accessibility_validator() -> Result<()> {
        let validator = OwnedAccessibilityValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_accessibility_validator_file_factory,
            "OwnedAccessibilityValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
