//! Owned signature validator for method signature validation.
//!
//! This validator provides comprehensive validation of method signatures within the context
//! of fully resolved .NET metadata, ensuring that signature components are properly formed
//! and every type they name resolves. This validator runs with priority 140 in the owned
//! validation stage.
//!
//! # Architecture
//!
//! **Method Signature Format Validation** checks names, the types the return value and the
//! parameters name, and generic parameters, according to ECMA-335.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator`] - Main validator implementation providing comprehensive signature validation
//! - [`crate::metadata::validation::validators::owned::metadata::signature::OwnedSignatureValidator::validate_method_signature_format`] - Method signature format and encoding validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedSignatureValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedSignatureValidator::new();
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
//! - Method signature format violations (empty names, unresolved return types)
//! - Parameter signature issues (unresolved types)
//! - Generic parameter violations (empty names, invalid flags)
//! - Signature component validation failures (parameter count limits, name constraints)
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
//! - owned metadata validators - Part of the owned metadata validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved method signature structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_method_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures and calling conventions
//! - [ECMA-335 II.22.26](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - MethodDef table signature constraints
//! - [ECMA-335 II.23.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Blobs and signatures
//! - [ECMA-335 I.8.6](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assignment compatibility
//! - [ECMA-335 II.10.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method overriding and signatures

use rayon::prelude::*;

use crate::{
    metadata::validation::{
        context::{OwnedValidationContext, ValidationContext},
        traits::OwnedValidator,
    },
    Error, Result,
};

/// Foundation validator for method signatures, calling conventions, and signature compatibility.
///
/// Ensures the structural integrity and consistency of method signatures in resolved .NET metadata,
/// validating proper signature formation, inheritance compatibility, and calling convention
/// compliance. This validator operates on resolved signature structures to provide essential
/// guarantees about signature integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of method signature validation according to
/// ECMA-335 specifications, ensuring proper signature definitions and compatibility patterns
/// in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedSignatureValidator;

impl OwnedSignatureValidator {
    /// Creates a new signature validator instance.
    ///
    /// Initializes a validator instance that can be used to validate method signatures
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`OwnedSignatureValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedSignatureValidator {
    /// Validates method signature format and encoding.
    ///
    /// Ensures that method signatures are properly formed according to ECMA-335
    /// specifications and that all signature components are valid. Validates
    /// method names, return types, parameters, and generic parameters.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method signature structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method signature formats are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Signature format violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Method names are empty
    /// - Return or parameter types name types that do not resolve
    /// - Parameters have unresolved types
    /// - Generic parameters have empty names or invalid flags
    fn validate_method_signature_format(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        let results: Vec<Result<()>> =
            methods
                .iter()
                // In token order, so the first error found is the first method's
                .collect::<Vec<_>>()
                .into_par_iter()
                .map(|entry| {
                    let method = entry.value();

                    // Validate method name is not empty (basic signature validation)
                    if method.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method with token 0x{:08X} has empty name",
                                entry.key().value()
                            ),
                        });
                    }

                    // Validate return type is resolved: every type it names is loaded
                    if let Some(token) =
                        context.unresolved_type(|out| method.signature.return_type.type_tokens(out))
                    {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' has unresolved return type 0x{:08X}",
                                method.name,
                                token.value()
                            ),
                        });
                    }

                    // Every parameter's type must resolve, whether or not a Param row describes it.
                    for (index, param) in method.signature.params.iter().enumerate() {
                        if let Some(token) = context.unresolved_type(|out| param.type_tokens(out)) {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Method '{}' parameter {} has unresolved type 0x{:08X}",
                                    method.name,
                                    index,
                                    token.value()
                                ),
                            });
                        }
                    }

                    // Validate parameter signatures
                    for (param_index, (_, param)) in method.params.iter().enumerate() {
                        // Validate parameter has resolved type (copied from method validator)
                        if param.base.get().is_none() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Method '{}' parameter {} has unresolved type",
                                    method.name, param_index
                                ),
                            });
                        }
                    }

                    // Validate generic parameters if present
                    for (_, generic_param) in method.generic_params.iter() {
                        // Validate generic parameter name
                        if generic_param.name.is_empty() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Method '{}' has generic parameter with empty name",
                                    method.name
                                ),
                            });
                        }

                        // Validate generic parameter flags are reasonable: variance
                        // (0x0003) and the special constraints (0x003C), which since
                        // .NET 9 include AllowByRefLike (0x0020, `allows ref struct`).
                        if generic_param.flags.bits() > 0x003F {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                            "Method '{}' generic parameter '{}' has invalid flags: 0x{:04X}",
                            method.name, generic_param.name, generic_param.flags.bits()
                        ),
                            });
                        }
                    }
                    Ok(())
                })
                .collect();

        for result in results {
            result?;
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedSignatureValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_method_signature_format(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedSignatureValidator"
    }

    fn priority(&self) -> u32 {
        140
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_method_validation
    }
}

impl Default for OwnedSignatureValidator {
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
            factories::validation::signature::owned_signature_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_signature_validator() -> Result<()> {
        let validator = OwnedSignatureValidator::new();
        let config = ValidationConfig {
            enable_method_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_signature_validator_file_factory,
            "OwnedSignatureValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
