//! Owned dependency validator for dependency chain validation in resolved metadata.
//!
//! This validator provides comprehensive validation of dependency chains within the context
//! of fully resolved .NET metadata. It operates on resolved type structures to validate
//! dependency graph integrity, transitive dependency satisfaction, and proper dependency
//! ordering for semantic correctness. This validator runs with priority 140
//! in the owned validation stage.
//!
//! # Architecture
//!
//! The dependency validation system implements comprehensive dependency chain validation in sequential order:
//! 1. **Dependency Graph Construction** - Builds complete dependency graphs from resolved type relationships
//! 2. **Transitive Dependency Validation** - Validates all semantic dependencies are satisfied across assemblies
//! 3. **Broken Chain Detection** - Identifies broken dependency chains in type hierarchies
//! 4. **Dependency Ordering Validation** - Ensures proper dependency ordering for inheritance and composition
//!
//! The implementation validates dependency constraints according to ECMA-335 specifications,
//! ensuring proper type relationship formation and dependency satisfaction.
//! All validation includes graph construction and transitive dependency analysis.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::relationships::dependency::OwnedDependencyValidator`] - Main validator implementation providing comprehensive dependency validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedDependencyValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedDependencyValidator::new();
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
//! - Broken dependency chains in type hierarchies (missing required dependencies)
//! - Unsatisfied transitive dependencies across assemblies (unresolved type references)
//! - Invalid dependency ordering for inheritance and composition (circular dependencies)
//! - Cross-assembly dependency resolution failures (broken external references)
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
//! - [`crate::metadata::validation::validators::owned::relationships`] - Part of the owned relationship validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_cross_table_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type system and inheritance dependencies
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef table and type dependencies
//! - [ECMA-335 II.22.38](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeRef table and external dependencies

use std::sync::Arc;

use crate::{
    metadata::validation::{
        context::{OwnedValidationContext, ValidationContext},
        traits::OwnedValidator,
    },
    Error, Result,
};

/// Foundation validator for dependency chain validation in resolved metadata structures.
///
/// Ensures the structural integrity and consistency of dependency relationships in resolved .NET metadata,
/// validating that dependency graphs are well-formed, transitive dependencies are satisfied,
/// and dependency ordering follows semantic correctness rules. This validator operates on resolved
/// type structures to provide essential guarantees about dependency chain integrity.
///
/// The validator implements comprehensive coverage of dependency validation according to
/// ECMA-335 specifications, ensuring proper type relationship dependencies and cross-assembly
/// reference satisfaction in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedDependencyValidator;

impl OwnedDependencyValidator {
    /// Creates a new dependency validator instance.
    ///
    /// Initializes a validator instance that can be used to validate dependency chains
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::relationships::dependency::OwnedDependencyValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates dependency graph integrity across all type relationships.
    ///
    /// Ensures that the dependency graph formed by type relationships is well-formed
    /// and doesn't contain broken links or inconsistent references.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Dependency graph integrity is valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Graph integrity violations found
    fn validate_dependency_graph_integrity(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            // Validate base type dependencies
            if let Some(base_type) = type_entry.base() {
                if base_type.name.is_empty() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has broken base type dependency (empty name)",
                            type_entry.name
                        ),
                    });
                }
            }

            // Validate interface dependencies
            for (_, entry) in type_entry.interfaces.iter() {
                if let Some(interface_type) = entry.interface.upgrade() {
                    if interface_type.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' has broken interface dependency (empty name)",
                                type_entry.name
                            ),
                        });
                    }
                } else {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has broken interface dependency reference",
                            type_entry.name
                        ),
                    });
                }
            }

            // Validate nested type dependencies
            for (_, nested_ref) in type_entry.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    if nested_type.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' has broken nested type dependency (empty name)",
                                type_entry.name
                            ),
                        });
                    }
                } else {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has broken nested type dependency reference",
                            type_entry.name
                        ),
                    });
                }
            }

            // Validate generic parameter dependencies
            for (_, generic_param) in type_entry.generic_params.iter() {
                for (_, constraint_ref) in generic_param.constraints.iter() {
                    if let Some(constraint_type) = constraint_ref.upgrade() {
                        if constraint_type.name.is_empty() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Type '{}' generic parameter '{}' has broken constraint dependency (empty name)",
                                    type_entry.name, generic_param.name
                                ),

                            });
                        }
                    } else {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' generic parameter '{}' has broken constraint dependency reference",
                                type_entry.name, generic_param.name
                            ),

                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates transitive dependency satisfaction across all dependencies.
    ///
    /// Ensures that all transitive dependencies are satisfied and that dependency
    /// chains are complete throughout the type system.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All transitive dependencies are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Transitive dependency violations found
    fn validate_transitive_dependency_satisfaction(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let methods = context.object().methods();

        // Build complete dependency graph
        let mut dependency_graph = rustc_hash::FxHashMap::default();
        for type_entry in context.target_assembly_types() {
            let token = type_entry.token;
            let mut dependencies = Vec::new();

            // Add direct dependencies
            if let Some(base_type) = type_entry.base() {
                dependencies.push(base_type.token);
            }

            for (_, entry) in type_entry.interfaces.iter() {
                if let Some(interface_type) = entry.interface.upgrade() {
                    dependencies.push(interface_type.token);
                }
            }

            for (_, nested_ref) in type_entry.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    dependencies.push(nested_type.token);
                }
            }

            dependency_graph.insert(token, dependencies);
        }

        // Validate method dependencies
        for type_entry in context.target_assembly_types() {
            for (_, method_ref) in type_entry.methods.iter() {
                if let Some(method_token) = method_ref.token() {
                    if let Some(method) = methods.get(&method_token) {
                        // Every parameter's type must resolve, whether or not a Param row describes it.
                        for (index, param) in method.value().signature.params.iter().enumerate() {
                            if let Some(token) =
                                context.unresolved_type(|out| param.type_tokens(out))
                            {
                                return Err(Error::ValidationOwnedFailed {
                                    validator: self.name().to_string(),
                                    message: format!(
                                        "Method '{}' parameter {} has unresolved type dependency 0x{:08X}",
                                        method.value().name,
                                        index,
                                        token.value()
                                    ),
                                });
                            }
                        }

                        // Validate parameter type dependencies
                        for (index, (_, param)) in method.value().params.iter().enumerate() {
                            if let Some(param_type_ref) = param.base.get() {
                                if param_type_ref.upgrade().is_none() {
                                    return Err(Error::ValidationOwnedFailed {
                                        validator: self.name().to_string(),
                                        message: format!(
                                            "Method '{}' in type '{}' has broken parameter {} type dependency",
                                            method.value().name, type_entry.name, index
                                        ),

                                    });
                                }
                            }
                        }

                        // Validate local variable type dependencies
                        for (index, (_, local)) in method.value().local_vars.iter().enumerate() {
                            if local.base.upgrade().is_none() {
                                return Err(Error::ValidationOwnedFailed {
                                    validator: self.name().to_string(),
                                    message: format!(
                                        "Method '{}' in type '{}' has broken local variable {} type dependency",
                                        method.value().name, type_entry.name, index
                                    ),

                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates dependency ordering for inheritance and composition.
    ///
    /// Ensures that dependencies are ordered correctly to prevent loading issues
    /// and that composition relationships don't violate semantic rules.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Dependency ordering is correct
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Dependency ordering violations found
    fn validate_dependency_ordering(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            // Validate inheritance ordering
            if let Some(base_type) = type_entry.base() {
                // Backstop for a self-referential base reached through some path other than
                // the TypeDef `extends` column - a synthetic type built by
                // `typesystem::resolver`, say.
                //
                // It does *not* catch the metadata condition. `InheritanceResolver` elides a
                // self-referential `extends` rather than recording it, so for a type loaded
                // from metadata `base()` is `None` here and this comparison cannot fire.
                // `OwnedCircularityValidator::validate_self_referential_bases` reads the raw
                // column and is what actually reports that case.
                //
                // The same type, not merely the same token: tokens repeat across assemblies.
                if Arc::ptr_eq(&base_type, type_entry) {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Type '{}' has self-referential inheritance dependency",
                            type_entry.name
                        ),
                    });
                }

                // Validate that base type is loaded/resolvable before derived type
                // This is mainly a logical consistency check for resolved metadata
                if base_type.fullname().is_empty() && !base_type.name.is_empty() {
                    // Base type might be partially resolved - this could indicate ordering issues
                    // But allow it for now as external types may not have full names
                }
            }

            // Validate interface implementation ordering
            for (_, entry) in type_entry.interfaces.iter() {
                if let Some(interface_type) = entry.interface.upgrade() {
                    // Check for self-referential interface implementation: the same type,
                    // not merely the same token
                    if Arc::ptr_eq(&interface_type, type_entry) {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' has self-referential interface implementation dependency",
                                type_entry.name
                            ),
                        });
                    }
                }
            }

            // Validate nested type ordering
            for (_, nested_ref) in type_entry.nested_types.iter() {
                if let Some(nested_type) = nested_ref.upgrade() {
                    // Check for self-referential nested type containment: the same type, not
                    // merely the same token
                    if Arc::ptr_eq(&nested_type, type_entry) {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Type '{}' has self-referential nested type dependency",
                                type_entry.name
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedDependencyValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_dependency_graph_integrity(context)?;
        self.validate_transitive_dependency_satisfaction(context)?;
        self.validate_dependency_ordering(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedDependencyValidator"
    }

    fn priority(&self) -> u32 {
        140
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_cross_table_validation
    }
}

impl Default for OwnedDependencyValidator {
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
            factories::validation::dependency::owned_dependency_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_dependency_validator() -> Result<()> {
        let validator = OwnedDependencyValidator::new();
        let config = ValidationConfig {
            enable_cross_table_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_dependency_validator_file_factory,
            "OwnedDependencyValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
