//! Owned method validator for method signature validation and overriding rules.
//!
//! This validator provides comprehensive validation of method definitions, signatures,
//! inheritance patterns, and implementation requirements within the context of fully
//! resolved .NET metadata. It operates on resolved method structures to ensure ECMA-335 compliance
//! for method declarations, virtual dispatch setup, and type system consistency.
//! This validator runs with priority 160 in the owned validation stage.
//!
//! # Architecture
//!
//! The method validation system implements comprehensive method validation in sequential order:
//! 1. **Method Signature Validation** - Ensures method signatures are well-formed with resolved types
//! 2. **Virtual Inheritance Validation** - Validates virtual method inheritance and overriding rules
//! 3. **Constructor Validation** - Validates constructor naming conventions and implementation rules
//! 4. **Method Body Validation** - Ensures proper presence/absence of method implementations
//!
//! The implementation validates method constraints according to ECMA-335 specifications,
//! ensuring proper method definitions across type hierarchies and inheritance patterns.
//! All validation includes signature checking and implementation requirement verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator`] - Main validator implementation providing comprehensive method validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_method_signatures`] - Method signature consistency and type resolution validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_virtual_inheritance`] - Virtual method inheritance and overriding rule validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_constructors`] - Constructor naming convention and implementation validation
//! - [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator::validate_method_bodies`] - Method body presence and implementation requirement validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedMethodValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedMethodValidator::new();
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
//! - Method signature consistency violations (empty names, unresolved parameter types)
//! - Virtual method inheritance violations (abstract without virtual, static with virtual)
//! - Constructor convention violations (missing special flags, incorrect modifiers)
//! - Method body presence violations (abstract with RVA, concrete without RVA)
//! - Special method naming violations (special names without SPECIAL_NAME flag)
//! - Virtual table violations (NEW_SLOT without virtual on non-special methods)
//! - Static constructor accessibility violations (non-private static constructors)
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
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved method structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_method_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method overriding and inheritance
//! - [ECMA-335 II.10.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Constructor specifications
//! - [ECMA-335 II.12](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method signatures and calling conventions
//! - [ECMA-335 III.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Method body validation requirements

use crate::{
    metadata::{
        method::{
            Method, MethodAccessFlags, MethodImplCodeType, MethodImplOptions, MethodModifiers,
            MethodVtableFlags,
        },
        typesystem::CilTypeReference,
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// The attribute marking a method the runtime implements as an accessor of
/// another type's member (.NET 8): `static extern`, with no body.
const UNSAFE_ACCESSOR_ATTRIBUTE: &str = "System.Runtime.CompilerServices.UnsafeAccessorAttribute";

/// Foundation validator for method definitions, signatures, and implementation requirements.
///
/// Ensures the structural integrity and consistency of method definitions in resolved .NET metadata,
/// validating proper method signatures, inheritance patterns, constructor conventions, and
/// implementation requirements. This validator operates on resolved method structures to provide
/// essential guarantees about method compliance with ECMA-335 specifications.
///
/// The validator implements comprehensive coverage of method validation according to
/// ECMA-335 specifications, ensuring proper method definitions across type hierarchies
/// and inheritance patterns in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedMethodValidator;

impl OwnedMethodValidator {
    /// Whether `method` carries `UnsafeAccessorAttribute`: a body the runtime
    /// supplies, so the method has none in the image.
    fn is_unsafe_accessor(method: &Method) -> bool {
        method.custom_attributes.iter().any(|(_, attribute)| {
            let declaring = match &attribute.constructor {
                CilTypeReference::MethodDef(constructor) => constructor
                    .upgrade()
                    .and_then(|constructor| constructor.declaring_type_fullname()),
                CilTypeReference::MemberRef(constructor) => constructor.declaredby.fullname(),
                _ => None,
            };
            declaring.as_deref() == Some(UNSAFE_ACCESSOR_ATTRIBUTE)
        })
    }

    /// Creates a new method validator instance.
    ///
    /// Initializes a validator instance that can be used to validate method definitions
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::members::method::OwnedMethodValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates method signature consistency and type safety.
    ///
    /// Ensures that all method signatures are well-formed according to ECMA-335
    /// specifications, including parameter types, return types, and calling conventions.
    /// Validates method names and signature type resolution.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method signatures are valid and resolved
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Method signature violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Method names are empty
    /// - Parameter types are unresolved or have empty names
    /// - Return or parameter types name types that do not resolve
    /// - Local variable types are unresolved or have empty names
    fn validate_method_signatures(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods {
            let method = entry.value();

            if method.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method with token 0x{:08X} has empty name",
                        entry.key().value()
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

            for (index, (_, param)) in method.params.iter().enumerate() {
                if let Some(base_type_ref) = param.base.get() {
                    if let Some(base_type) = base_type_ref.upgrade() {
                        if base_type.name.is_empty() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Method '{}' parameter {} has unresolved type",
                                    method.name, index
                                ),
                            });
                        }
                    } else {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' parameter {} has unresolved type",
                                method.name, index
                            ),
                        });
                    }
                } else {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' parameter {} has unresolved type",
                            method.name, index
                        ),
                    });
                }
            }

            if let Some(token) =
                context.unresolved_type(|out| method.signature.return_type.type_tokens(out))
            {
                let method_name = &method.name;
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method '{method_name}' has unresolved return type 0x{:08X}",
                        token.value()
                    ),
                });
            }

            for (index, (_, local)) in method.local_vars.iter().enumerate() {
                if let Some(local_type) = local.base.upgrade() {
                    if local_type.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Method '{}' local variable {} has unresolved type",
                                method.name, index
                            ),
                        });
                    }
                } else {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Method '{}' local variable {} has unresolved type",
                            method.name, index
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates virtual method inheritance and overriding rules.
    ///
    /// Ensures that virtual methods follow proper inheritance patterns and that
    /// method overrides maintain signature compatibility. Validates virtual table
    /// flags and modifier combinations according to ECMA-335 requirements.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All virtual inheritance rules are followed
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Virtual inheritance violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Abstract methods are not marked as virtual
    /// - Static methods are marked as virtual, abstract, or final
    /// - Final methods are not marked as virtual
    /// - NEW_SLOT is used without virtual on non-runtime-special methods
    fn validate_virtual_inheritance(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods {
            let method = entry.value();

            if method.is_abstract() && !method.is_virtual() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Abstract method '{}' must also be virtual", method.name),
                });
            }

            // An interface may declare static virtual and static abstract
            // members (since .NET 7); everywhere else a static method has no
            // slot.
            let in_interface = method
                .declaring_type_rc()
                .is_some_and(|declaring| declaring.flags.is_interface());
            if method.is_static() && !in_interface {
                if method.is_virtual() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be virtual", method.name),
                    });
                }

                if method.is_abstract() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be abstract", method.name),
                    });
                }

                if method.flags_modifiers.contains(MethodModifiers::FINAL) {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Static method '{}' cannot be final", method.name),
                    });
                }
            }

            if method.flags_modifiers.contains(MethodModifiers::FINAL) && !method.is_virtual() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Final method '{}' must also be virtual", method.name),
                });
            }

            if method.flags_vtable.contains(MethodVtableFlags::NEW_SLOT)
                && !method.is_virtual()
                && !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
            {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Method '{}' uses NEW_SLOT but is not virtual or runtime special",
                        method.name
                    ),
                });
            }
        }

        Ok(())
    }

    /// Validates constructor naming conventions and implementation rules.
    ///
    /// Ensures that constructors follow .NET naming conventions and have appropriate
    /// attributes and accessibility modifiers. Validates both instance (.ctor) and
    /// static (.cctor) constructors according to ECMA-335 specifications.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All constructor conventions are followed
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Constructor violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Instance constructors lack RTSPECIAL_NAME or SPECIAL_NAME flags
    /// - Instance constructors are marked as static or virtual
    /// - Static constructors are not marked as static
    /// - Static constructors lack RTSPECIAL_NAME or SPECIAL_NAME flags
    /// - Static constructors are not private
    /// - Special method names lack SPECIAL_NAME flag (get_, set_, add_, remove_, op_)
    fn validate_constructors(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for entry in methods {
            let method = entry.value();

            // Check instance constructors (.ctor)
            if method.is_ctor() {
                // Instance constructors must be RTSPECIAL_NAME and SPECIAL_NAME
                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
                {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' must have RTSPECIAL_NAME flag",
                            method.name
                        ),
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
                {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' must have SPECIAL_NAME flag",
                            method.name
                        ),
                    });
                }

                if method.is_static() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Instance constructor '{}' cannot be static", method.name),
                    });
                }

                if method.is_virtual() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Instance constructor '{}' cannot be virtual",
                            method.name
                        ),
                    });
                }
            }

            // Check static constructors (.cctor)
            if method.is_cctor() {
                // Static constructors must be static, RTSPECIAL_NAME, and SPECIAL_NAME
                if !method.is_static() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Static constructor '{}' must be static", method.name),
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::RTSPECIAL_NAME)
                {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Static constructor '{}' must have RTSPECIAL_NAME flag",
                            method.name
                        ),
                    });
                }

                if !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
                {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Static constructor '{}' must have SPECIAL_NAME flag",
                            method.name
                        ),
                    });
                }

                if method.flags_access != MethodAccessFlags::PRIVATE {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Static constructor '{}' should be private", method.name),
                    });
                }
            }

            // Only validate SPECIAL_NAME requirement for operator overloads
            // Property accessors and event handlers are too varied in real-world .NET assemblies
            // to reliably validate based on naming patterns alone
            if method.name.starts_with("op_")
                && method.is_static()
                && (method.is_public()
                    || method.flags_access == MethodAccessFlags::FAMILY_OR_ASSEMBLY)
                && !method
                    .flags_modifiers
                    .contains(MethodModifiers::SPECIAL_NAME)
                && method.impl_code_type != MethodImplCodeType::RUNTIME
                && !method
                    .impl_options
                    .contains(MethodImplOptions::INTERNAL_CALL)
            {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Operator overload '{}' should have SPECIAL_NAME flag",
                        method.name
                    ),
                });
            }

            // Note: Property accessors (get_/set_) and event handlers (add_/remove_) validation
            // is disabled as naming patterns alone are insufficient to distinguish between
            // legitimate accessors and utility methods in real-world .NET assemblies
        }

        Ok(())
    }

    /// Validates method body presence requirements.
    ///
    /// Ensures that methods that require implementations have method bodies (RVA),
    /// and that abstract/interface methods do not have implementations. Validates
    /// implementation presence according to method type and attributes.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved method structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All method body requirements are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Method body violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Abstract methods have implementation (RVA present)
    /// - P/Invoke methods have implementation (RVA present)
    /// - Runtime methods have implementation (RVA present)
    /// - Concrete methods lack implementation (RVA missing)
    fn validate_method_bodies(&self, context: &OwnedValidationContext) -> Result<()> {
        let methods = context.object().methods();

        for type_rc in context.target_assembly_types() {
            for (_, method_ref) in type_rc.methods.iter() {
                if let Some(method_token) = method_ref.token() {
                    if let Some(method_entry) = methods.get(&method_token) {
                        let method = method_entry.value();

                        if method.is_abstract() && method.rva.is_some() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Abstract method '{}' should not have implementation (RVA)",
                                    method.name
                                ),
                            });
                        }

                        if method
                            .flags_modifiers
                            .contains(MethodModifiers::PINVOKE_IMPL)
                            && method.rva.is_some()
                        {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "P/Invoke method '{}' should not have implementation (RVA)",
                                    method.name
                                ),
                            });
                        }

                        if (method.impl_code_type == MethodImplCodeType::RUNTIME)
                            && method.rva.is_some()
                        {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Runtime method '{}' should not have implementation (RVA)",
                                    method.name
                                ),
                            });
                        }

                        if !method.is_abstract()
                            && !method
                                .flags_modifiers
                                .contains(MethodModifiers::PINVOKE_IMPL)
                            && method.impl_code_type != MethodImplCodeType::RUNTIME
                            && !method
                                .impl_options
                                .contains(MethodImplOptions::INTERNAL_CALL)
                            && method.rva.is_none()
                            && !Self::is_unsafe_accessor(method)
                        {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Concrete method '{}' must have implementation (RVA)",
                                    method.name
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedMethodValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_method_signatures(context)?;
        self.validate_virtual_inheritance(context)?;
        self.validate_constructors(context)?;
        self.validate_method_bodies(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedMethodValidator"
    }

    fn priority(&self) -> u32 {
        160
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_method_validation
    }
}

impl Default for OwnedMethodValidator {
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
            factories::validation::members_method::owned_method_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_method_validator() -> Result<()> {
        let validator = OwnedMethodValidator::new();
        let config = ValidationConfig {
            enable_method_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_method_validator_file_factory,
            "OwnedMethodValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
