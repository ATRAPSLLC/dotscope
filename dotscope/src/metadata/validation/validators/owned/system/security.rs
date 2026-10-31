//! Owned security validator for security constraint validation.
//!
//! This validator provides comprehensive validation of security constraints, permissions,
//! and security attributes within the context of fully resolved .NET metadata. It operates
//! on resolved security structures to validate permission declarations and security
//! transparency rules according to ECMA-335 and .NET security model
//! requirements. This validator runs with priority 120 in the owned validation stage.
//!
//! # Architecture
//!
//! The security validation system implements comprehensive security constraint validation in sequential order:
//! 1. **Security Permission Declaration Validation** - Ensures security declarations are properly formed according to ECMA-335
//! 2. **Security Transparency Validation** - Ensures security-critical and transparent code boundaries are respected
//!
//! The implementation validates security constraints according to ECMA-335 specifications
//! and .NET Framework security model requirements, ensuring proper security declaration
//! formation and preventing security vulnerabilities. All validation includes permission
//! set parsing and security attribute verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator`] - Main validator implementation providing comprehensive security validation
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_security_permission_declarations`] - Security permission declaration and syntax validation
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_security_transparency`] - Security transparency rule validation and boundary enforcement
//! - [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator::validate_permission_set_format`] - Permission set XML format and structure validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedSecurityValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedSecurityValidator::new();
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
//! - Security permission declaration violations (invalid actions, empty permission sets, invalid XML)
//! - Security transparency violations (conflicting critical/transparent attributes, invalid inheritance)
//! - Permission set format violations (malformed XML, missing elements)
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
//! - [`crate::metadata::validation::validators::owned::system`] - Part of the owned system validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved security structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.22.11](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - DeclSecurity table
//! - [ECMA-335 II.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Custom Attributes (security attributes)
//! - [ECMA-335 IV.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Security attributes
//! - [.NET Framework Security Model](https://docs.microsoft.com/en-us/dotnet/framework/security/) - Security model compliance

use crate::{
    metadata::{
        security::SecurityAction,
        typesystem::{CilType, CilTypeReference},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// `System.Security.SecurityCriticalAttribute`.
const SECURITY_CRITICAL: &str = "System.Security.SecurityCriticalAttribute";

/// `System.Security.SecurityTransparentAttribute`.
const SECURITY_TRANSPARENT: &str = "System.Security.SecurityTransparentAttribute";

/// Foundation validator for security constraints, permissions, and security attributes.
///
/// Ensures the structural integrity and consistency of security constraints in resolved .NET metadata,
/// validating security permission declarations, code access security attributes, and security transparency
/// rules. This validator operates on resolved security structures to provide essential guarantees
/// about security constraint integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of security validation according to
/// ECMA-335 specifications and .NET Framework security model requirements, ensuring proper
/// security declaration formation and preventing security vulnerabilities in the resolved
/// metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedSecurityValidator;

impl OwnedSecurityValidator {
    /// Creates a new security validator instance.
    ///
    /// Initializes a validator instance that can be used to validate security constraints
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::system::security::OwnedSecurityValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedSecurityValidator {
    /// Validates that every security declaration's action is one ECMA-335 II.22.11 defines
    /// (`System.Security.Permissions.SecurityAction`, 1 to 15). Its permission set is
    /// decoded when the row loads, which refuses a malformed one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] for an action outside that set.
    fn validate_security_permission_declarations(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        for entry in context.object().security_declarations().iter() {
            let decl_security = entry.value();
            if let SecurityAction::Unknown(action) = decl_security.action {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Security declaration has invalid action: {action:#06x}"),
                });
            }
        }
        Ok(())
    }

    /// Validates security-critical and security-transparent code.
    ///
    /// Ensures that security transparency attributes are properly applied
    /// and that critical/transparent boundaries are respected. Validates
    /// transparency inheritance and conflicting attribute usage.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved security structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All security transparency rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Transparency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Types are marked both SecurityCritical and SecurityTransparent
    /// - Transparent types inherit from critical base types
    fn validate_security_transparency(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.all_types() {
            let critical = Self::has_attribute(type_entry, SECURITY_CRITICAL);
            let transparent = Self::has_attribute(type_entry, SECURITY_TRANSPARENT);

            if critical && transparent {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Type '{}' cannot be both SecurityCritical and SecurityTransparent",
                        type_entry.name
                    ),
                });
            }

            // Transparent types cannot inherit from critical types
            if transparent {
                if let Some(base_type) = type_entry.base() {
                    if Self::has_attribute(&base_type, SECURITY_CRITICAL) {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Transparent type '{}' cannot inherit from critical base type",
                                type_entry.name
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Whether `type_entry` carries an attribute of type `attribute` (a full name): an
    /// attribute is its constructor's declaring type, never its arguments.
    fn has_attribute(type_entry: &CilType, attribute: &str) -> bool {
        type_entry.custom_attributes.iter().any(|(_, attr)| {
            let attribute_type = match &attr.constructor {
                CilTypeReference::MethodDef(ctor) => ctor
                    .upgrade()
                    .and_then(|ctor| ctor.declaring_type_fullname()),
                CilTypeReference::MemberRef(ctor) => ctor.declaredby.fullname(),
                _ => None,
            };
            attribute_type.as_deref() == Some(attribute)
        })
    }
}

impl OwnedValidator for OwnedSecurityValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_security_permission_declarations(context)?;
        self.validate_security_transparency(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedSecurityValidator"
    }

    fn priority(&self) -> u32 {
        120
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedSecurityValidator {
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
            factories::validation::system_security::owned_security_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_security_validator() -> Result<()> {
        let validator = OwnedSecurityValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_security_validator_file_factory,
            "OwnedSecurityValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
