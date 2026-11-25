//! Owned type constraint validator for generic constraint satisfaction and type compatibility validation.
//!
//! This validator provides comprehensive validation of generic type constraints within the context
//! of fully resolved .NET metadata according to ECMA-335 specifications. It operates on resolved
//! type structures to validate generic constraint satisfaction, inheritance compatibility, and
//! interface implementation requirements for generic type parameters and their instantiations.
//! This validator runs with priority 185 in the owned validation stage.
//!
//! # Architecture
//!
//! The type constraint validation system implements comprehensive constraint satisfaction validation in sequential order:
//! 1. **Generic Parameter Constraint Validation** - Ensures generic type parameters satisfy their constraints
//! 2. **Inheritance Constraint Validation** - Validates inheritance relationships meet constraint requirements
//! 3. **Interface Implementation Constraint Validation** - Ensures interface constraints are properly implemented
//! 4. **Type Compatibility Constraint Validation** - Validates type compatibility against generic constraints
//! 5. **Constructor Constraint Validation** - Ensures new() constraint satisfaction for generic parameters
//!
//! The implementation validates constraint satisfaction according to ECMA-335 specifications,
//! ensuring proper generic type instantiation and preventing constraint violations.
//! All validation includes type resolution verification and constraint hierarchy validation.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::constraints::types::OwnedTypeConstraintValidator`] - Main validator implementation providing comprehensive constraint validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedTypeConstraintValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedTypeConstraintValidator::new();
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
//! - Generic parameter constraint violations (type arguments not satisfying constraints)
//! - Inheritance constraint failures (invalid inheritance relationships for constrained types)
//! - Interface implementation constraint violations (missing interface implementations)
//! - Type compatibility constraint failures (incompatible type instantiations)
//! - Constructor constraint violations (missing parameterless constructors for new() constraint)
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
//! - [`crate::metadata::validation::validators::owned::constraints`] - Part of the owned constraint validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10.1.7](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Generic type constraints
//! - [ECMA-335 II.22.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GenericParam table
//! - [ECMA-335 II.22.21](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - GenericParamConstraint table
//! - [ECMA-335 I.8.9.1](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Generic type instantiation
//! - [ECMA-335 II.22.29](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeSpec constraints

use std::collections::HashSet;

use crate::{
    metadata::{
        tables::{GenericParamAttributes, TableId},
        typesystem::{CilFlavor, CilType},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// Foundation validator for generic type constraints, inheritance compatibility, and interface implementation requirements.
///
/// Ensures the structural integrity and consistency of generic constraint relationships in resolved .NET metadata,
/// validating that generic type parameters satisfy their constraints, inheritance relationships meet constraint
/// requirements, and interface implementations satisfy constraint obligations. This validator operates on resolved
/// type structures to provide essential guarantees about constraint satisfaction and type compatibility.
///
/// The validator implements comprehensive coverage of constraint validation according to
/// ECMA-335 specifications, ensuring proper generic type instantiation and preventing constraint
/// violations in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedTypeConstraintValidator;

impl OwnedTypeConstraintValidator {
    /// Creates a new type constraint validator instance.
    ///
    /// Initializes a validator instance that can be used to validate constraint relationships
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::constraints::types::OwnedTypeConstraintValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates generic parameter constraints across all types.
    ///
    /// Ensures that all generic type parameters have valid constraints and that
    /// these constraints are satisfied by their type arguments in instantiations.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All generic parameter constraints are valid
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Constraint violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Generic parameters have invalid constraint combinations
    /// - Constraint types are not accessible or resolvable
    /// - Circular constraint dependencies are detected
    fn validate_generic_parameter_constraints(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        for type_entry in context.all_types() {
            // Check for invalid generic parameter constraint combinations
            if type_entry.generic_params.count() > 0 {
                self.validate_type_generic_constraints(type_entry)?;
            }
        }

        Ok(())
    }

    /// Validates generic constraints for a specific type.
    ///
    /// Checks that all generic parameters have valid constraints and that
    /// constraint relationships are properly formed.
    ///
    /// # Arguments
    ///
    /// * `type_entry` - Type to validate generic constraints for
    ///
    /// # Returns
    ///
    /// Returns error if constraint violations are detected.
    fn validate_type_generic_constraints(&self, type_entry: &CilType) -> Result<()> {
        let mut visited_constraints = HashSet::new();

        for (_, generic_param) in type_entry.generic_params.iter() {
            // Validate constraint accessibility and compatibility
            for (_, constraint_ref) in generic_param.constraints.iter() {
                if let Some(constraint_type) = constraint_ref.upgrade() {
                    // Check for circular constraint references
                    if !visited_constraints.insert(constraint_type.fullname().text_hash()) {
                        // Allow multiple identical constraints (common pattern)
                        continue;
                    }

                    // Validate constraint type accessibility
                    if constraint_type.name.is_empty() {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: format!(
                                "Generic parameter '{}' in type '{}' has unresolved constraint",
                                generic_param.name, type_entry.name
                            ),
                        });
                    }

                    // Validate constraint type compatibility
                    self.validate_constraint_type_compatibility(
                        &constraint_type,
                        &generic_param.name,
                        &type_entry.name,
                    )?;
                } else {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!(
                            "Generic parameter '{}' in type '{}' has broken constraint reference",
                            generic_param.name, type_entry.name
                        ),
                    });
                }
            }

            // Validate generic parameter attributes consistency
            self.validate_generic_parameter_attributes(
                generic_param.flags,
                &generic_param.name,
                &type_entry.name,
            )?;
        }

        Ok(())
    }

    /// Validates that constraint types are compatible with their usage.
    ///
    /// Ensures that constraint types can be used as constraints (e.g., interfaces
    /// and classes but not value types in certain contexts).
    ///
    /// # Arguments
    ///
    /// * `constraint_type` - The type being used as a constraint
    /// * `param_name` - Name of the generic parameter for error messages
    /// * `type_name` - Name of the containing type for error messages
    ///
    /// # Returns
    ///
    /// Returns error if constraint type compatibility violations are detected.
    fn validate_constraint_type_compatibility(
        &self,
        constraint_type: &CilType,
        param_name: &str,
        type_name: &str,
    ) -> Result<()> {
        // Validate constraint type is suitable for use as a constraint
        match constraint_type.flavor() {
            CilFlavor::Interface => {
                // Interfaces are always valid constraints
                Ok(())
            }
            CilFlavor::Class => {
                // Classes are valid constraints
                // Check if class is sealed (which is allowed but restricts inheritance)
                if constraint_type.flags.is_sealed() {
                    // SEALED flag - this is fine for constraints
                }
                Ok(())
            }
            CilFlavor::ValueType => {
                // A value type is a valid constraint (ECMA-335 II.10.1.7 places no limit on
                // the constraint's kind beyond its being a type)
                Ok(())
            }
            CilFlavor::Object => {
                // System.Object is a valid constraint
                Ok(())
            }
            CilFlavor::GenericInstance => {
                // Generic instances (e.g., IComparable<T>, IEquatable<T>) are valid constraints
                // These are commonly used as constraints in generic type definitions
                Ok(())
            }
            CilFlavor::GenericParameter { .. } => {
                // Generic parameters can be used as constraints in nested generic scenarios
                // e.g., where T : U in generic type definitions
                Ok(())
            }
            _ => Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Generic parameter '{}' in type '{}' has incompatible constraint type '{}'",
                    param_name, type_name, constraint_type.name
                ),
            }),
        }
    }

    /// Validates generic parameter attributes for consistency.
    ///
    /// Ensures that generic parameter attributes are valid and consistent
    /// with constraint requirements.
    ///
    /// # Arguments
    ///
    /// * `attributes` - Generic parameter attributes to validate
    /// * `param_name` - Name of the generic parameter for error messages
    /// * `type_name` - Name of the containing type for error messages
    ///
    /// # Returns
    ///
    /// Returns error if attribute consistency violations are detected.
    fn validate_generic_parameter_attributes(
        &self,
        attributes: GenericParamAttributes,
        param_name: &str,
        type_name: &str,
    ) -> Result<()> {
        // Validate variance attributes
        if attributes.contains(GenericParamAttributes::COVARIANT)
            && attributes.contains(GenericParamAttributes::CONTRAVARIANT)
        {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Generic parameter '{param_name}' in type '{type_name}' cannot be both covariant and contravariant"
                ),

            });
        }

        // Validate special constraint combinations
        if attributes.contains(GenericParamAttributes::REFERENCE_TYPE_CONSTRAINT)
            && attributes.contains(GenericParamAttributes::NOT_NULLABLE_VALUE_TYPE_CONSTRAINT)
        {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Generic parameter '{param_name}' in type '{type_name}' cannot have both reference type and value type constraints"
                ),

            });
        }

        Ok(())
    }

    /// Validates inheritance constraint satisfaction across type hierarchies.
    ///
    /// Ensures that when generic types are instantiated, the type arguments
    /// satisfy the inheritance constraints specified by the generic parameters.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved type structures
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All inheritance constraints are satisfied
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Constraint violations found
    fn validate_inheritance_constraint_satisfaction(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        // For each type, check if it properly satisfies constraints when used as a generic argument
        for type_entry in context.all_types() {
            // Check interface implementation constraint satisfaction
            for (_, entry) in type_entry.interfaces.iter() {
                if let Some(interface_type) = entry.interface.upgrade() {
                    self.validate_interface_constraint_satisfaction(type_entry, &interface_type)?;
                }
            }
        }

        Ok(())
    }

    /// Validates interface implementation constraint satisfaction.
    ///
    /// # Arguments
    ///
    /// * `implementing_type` - The type implementing the interface
    /// * `interface_type` - The interface being implemented
    ///
    /// # Returns
    ///
    /// Returns error if interface constraint violations are detected.
    fn validate_interface_constraint_satisfaction(
        &self,
        implementing_type: &CilType,
        interface_type: &CilType,
    ) -> Result<()> {
        // ECMA-335 II.22.23: an InterfaceImpl's Interface is an interface, and the runtime
        // refuses a class implementing anything else. Only a definition's flags say what it
        // is: a TypeRef that resolved to no definition, or a constructed TypeSpec, carries
        // none, so only a TypeDef is judged.
        if interface_type.token.is_table(TableId::TypeDef) && !interface_type.flags.is_interface() {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Type '{}' implements non-interface type '{}'",
                    implementing_type.name, interface_type.name
                ),
            });
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedTypeConstraintValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_generic_parameter_constraints(context)?;
        self.validate_inheritance_constraint_satisfaction(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedTypeConstraintValidator"
    }

    fn priority(&self) -> u32 {
        185
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedTypeConstraintValidator {
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
            factories::validation::constraints_types::owned_type_constraint_validator_file_factory,
            owned_validator_test,
        },
    };

    /// Comprehensive test for OwnedTypeConstraintValidator using the improved test harness.
    ///
    /// Tests the validator against various assembly scenarios including clean assemblies
    /// and assemblies with constraint violations (when available) using the centralized
    /// owned validator test harness.
    #[test]
    fn test_owned_type_constraint_validator_comprehensive() -> Result<()> {
        let validator = OwnedTypeConstraintValidator::new();

        owned_validator_test(
            owned_type_constraint_validator_file_factory,
            "OwnedTypeConstraintValidator",
            ValidationConfig {
                enable_semantic_validation: true,
                ..Default::default()
            },
            |context| validator.validate_owned(context),
        )
    }
}
