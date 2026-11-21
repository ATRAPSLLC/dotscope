//! Owned type definition validator for basic type structure validation.
//!
//! This validator provides comprehensive validation of type definitions within the context
//! of fully resolved .NET metadata. It operates on resolved type structures to validate
//! type structure, attributes, flags, and metadata consistency according to ECMA-335
//! specifications. This validator ensures proper type system semantics and runs with
//! priority 190 in the owned validation stage.
//!
//! # Architecture
//!
//! The type definition validation system implements comprehensive type structure validation in sequential order:
//! 1. **Type Definition Structure Validation** - Ensures type definitions are properly structured with valid names and tokens
//! 2. **Type Attribute Consistency Validation** - Validates type attribute flag combinations and mutual compatibility
//! 3. **Type Flavor Consistency Validation** - Ensures computed type flavors match attributes and structural characteristics
//! 4. **Special Type Constraints Validation** - Validates special type modifiers and constraint usage
//!
//! The implementation validates type constraints according to ECMA-335 specifications,
//! ensuring proper type definition formation and type system semantics.
//! All validation includes attribute checking and flavor consistency verification.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator`] - Main validator implementation providing comprehensive type definition validation
//! - [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator::validate_type_definition_structure`] - Type definition structure and well-formedness validation
//! - [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator::validate_type_attribute_consistency`] - Type attribute flag consistency and validity validation
//! - [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator::validate_type_flavor_consistency`] - Type flavor consistency validation with attributes and structure
//! - [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator::validate_special_type_constraints`] - Special type constraints and modifier validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedTypeDefinitionValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedTypeDefinitionValidator::new();
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
//! - Type definition structure violations (empty names, invalid tokens)
//! - Type attribute consistency failures (invalid visibility, layout, or semantics attributes)
//! - Type flavor inconsistencies (interface flavor without interface flag, invalid base types)
//! - Special constraint violations (RTSpecialName without SpecialName, sealed interfaces)
//! - Naming pattern violations (malformed special names, invalid compiler-generated patterns)
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
//! - [`crate::metadata::validation::validators::owned::types`] - Part of the owned type validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved type structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.10](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type definitions
//! - [ECMA-335 II.23.1.15](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeAttributes
//! - [ECMA-335 II.22.37](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - TypeDef table
//! - [ECMA-335 I.8.9](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Type definitions

use rayon::prelude::*;

use crate::{
    metadata::{
        tables::TypeAttributes,
        typesystem::CilFlavor,
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    utils::TryForEachInOrder,
    Error, Result,
};

/// Foundation validator for basic type definition structure, attributes, and metadata consistency.
///
/// Ensures the structural integrity and consistency of type definitions in resolved .NET metadata,
/// validating type structure, attribute flag combinations, flavor consistency, and special
/// constraint usage. This validator operates on resolved type structures to provide essential
/// guarantees about type definition integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of type definition validation according to
/// ECMA-335 specifications, ensuring proper type structure formation and type system
/// semantics in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedTypeDefinitionValidator;

impl OwnedTypeDefinitionValidator {
    /// Creates a new type definition validator instance.
    ///
    /// Initializes a validator instance that can be used to validate type definitions
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::validation::validators::owned::types::definition::OwnedTypeDefinitionValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedTypeDefinitionValidator {
    /// Validates basic type definition structure and well-formedness.
    ///
    /// Ensures that type definitions are properly structured with valid names,
    /// tokens, and basic metadata according to ECMA-335 specifications.
    fn validate_type_definition_structure(&self, context: &OwnedValidationContext) -> Result<()> {
        context
            .target_assembly_types()
            .par_iter()
            .try_for_each_in_order(|type_entry| -> Result<()> {
                // Validate type name is not empty (except for special cases)
                if type_entry.name.is_empty() && type_entry.namespace != "<Module>" {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: {
                            let token_value = type_entry.token.value();
                            format!("Type with token 0x{token_value:08X} has empty name")
                        },
                    });
                }

                // Validate type token is valid
                if type_entry.token.value() == 0 {
                    let type_name = &type_entry.name;
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: format!("Type '{type_name}' has invalid token (0)"),
                    });
                }

                // Validate special naming patterns (but allow legitimate compiler-generated types)
                if type_entry.name.starts_with('<') && !type_entry.name.ends_with('>') {
                    // A leading '<' opens a compiler- or tool-generated name, and the property
                    // that makes such a name well formed is that the bracket is *closed*. What
                    // follows the '>' is chosen by whatever emitted it, so enumerating suffixes
                    // cannot be exhaustive: Roslyn appends 'd__N'/'b__N'/'c__DisplayClassN', and
                    // both Roslyn and .NET Reactor append '{GUID}' to '<PrivateImplementationDetails>'
                    // and '<Module>'. The previous allowlist rejected that last shape, which is
                    // present in shipped assemblies and in every .NET Reactor sample -- so real
                    // input failed validation, before any rewriting was involved.
                    //
                    // An unterminated '<' is still rejected, which is what this check is for.
                    let is_compiler_generated = type_entry.name.contains('>');

                    if !is_compiler_generated {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: {
                                let type_name = &type_entry.name;
                                format!("Type '{type_name}' has malformed special name pattern")
                            },
                        });
                    }
                }

                Ok(())
            })
    }

    /// Validates type attribute flags for consistency and validity.
    ///
    /// Ensures that type attribute combinations are valid and mutually
    /// compatible according to .NET type system rules.
    fn validate_type_attribute_consistency(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            let flags = type_entry.flags;

            // Validate visibility attributes
            let visibility = flags.visibility();
            if !Self::is_valid_visibility_attribute(visibility) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!("Type '{type_name}' has invalid visibility attribute: 0x{visibility:02X}")
                    },
                });
            }

            // Validate layout attributes
            let layout = flags.layout();
            if !Self::is_valid_layout_attribute(layout) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!("Type '{type_name}' has invalid layout attribute: 0x{layout:02X}")
                    },
                });
            }

            // Validate class semantics attributes
            let class_semantics = flags & TypeAttributes::CLASS_SEMANTICS_MASK;
            if !Self::is_valid_class_semantics_attribute(class_semantics) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!("Type '{type_name}' has invalid class semantics attribute: 0x{class_semantics:02X}")
                    },
                });
            }

            // Validate string format attributes
            let string_format = flags.string_format();
            if !Self::is_valid_string_format_attribute(string_format) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!("Type '{type_name}' has invalid string format attribute: 0x{string_format:02X}")
                    },
                });
            }

            // Validate mutually exclusive flags (but allow static classes: abstract + sealed)
            if flags.is_abstract() && flags.is_sealed() {
                // SEALED - this is valid for static classes in C#
                // Static classes are marked as both abstract and sealed by the compiler
                // We allow this legitimate pattern
            }

            // Validate interface constraints
            if flags.is_interface() {
                // Interfaces must be abstract
                if !flags.is_abstract() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: {
                            let type_name = &type_entry.name;
                            format!("Interface '{type_name}' must be abstract")
                        },
                    });
                }

                // Interfaces cannot be sealed
                if flags.is_sealed() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: {
                            let type_name = &type_entry.name;
                            format!("Interface '{type_name}' cannot be sealed")
                        },
                    });
                }
            }
        }

        Ok(())
    }

    /// Validates type flavor consistency with attributes and structure.
    ///
    /// Ensures that the computed type flavor matches the type's attributes
    /// and structural characteristics.
    fn validate_type_flavor_consistency(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            let flavor = type_entry.flavor();
            let flags = type_entry.flags;

            // Validate interface flavor consistency
            if *flavor == CilFlavor::Interface && !flags.is_interface() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!(
                            "Type '{type_name}' has Interface flavor but missing Interface flag"
                        )
                    },
                });
            }

            // Validate that interfaces don't have conflicting flavors
            // GenericInstance is also valid for interface types (e.g., IList<T> instantiations)
            if flags.is_interface()
                && !matches!(flavor, CilFlavor::Interface | CilFlavor::GenericInstance)
            {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: {
                        let type_name = &type_entry.name;
                        format!("Interface type '{type_name}' has inconsistent flavor: {flavor:?}")
                    },
                });
            }

            // Validate value type flavor consistency
            if *flavor == CilFlavor::ValueType {
                // Value types should typically inherit from System.ValueType or System.Enum
                if let Some(base_type) = type_entry.base() {
                    let base_fullname = base_type.fullname();
                    if base_fullname != "System.ValueType"
                        && base_fullname != "System.Enum"
                        && base_fullname != "System.Object"
                    {
                        // Object is allowed for primitives
                        // Allow some flexibility for special cases
                        if !type_entry.namespace.starts_with("System") {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: {
                                    let type_name = &type_entry.name;
                                    format!("Value type '{type_name}' has unexpected base type: {base_fullname}")
                                },
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Validates special type constraints and modifiers.
    ///
    /// Ensures that special type modifiers like abstract, sealed, and
    /// special name are used appropriately.
    fn validate_special_type_constraints(&self, context: &OwnedValidationContext) -> Result<()> {
        for type_entry in context.target_assembly_types() {
            let flags = type_entry.flags;

            // Validate BeforeFieldInit usage
            if flags.contains(TypeAttributes::BEFORE_FIELD_INIT) {
                // This flag can appear on interfaces in legitimate .NET assemblies
                // especially for compiler-generated or system interfaces
                // We allow this pattern
            }

            // Validate SpecialName usage
            if flags.contains(TypeAttributes::SPECIAL_NAME) {
                // Special names should follow specific patterns
                if !type_entry.name.starts_with('<')
                    && !type_entry.name.contains('$')
                    && !type_entry.name.starts_with("__")
                {
                    // Allow some flexibility for legitimate special names
                    if !type_entry.namespace.starts_with("System") {
                        return Err(Error::ValidationOwnedFailed {
                            validator: self.name().to_string(),
                            message: {
                                let type_name = &type_entry.name;
                                format!("Type '{type_name}' has SpecialName flag but doesn't follow special naming pattern")
                            },
                        });
                    }
                }
            }

            // Validate RTSpecialName usage
            if flags.contains(TypeAttributes::RT_SPECIAL_NAME) {
                // RTSpecialName requires SpecialName
                if !flags.contains(TypeAttributes::SPECIAL_NAME) {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: {
                            let type_name = &type_entry.name;
                            format!("Type '{type_name}' has RTSpecialName but not SpecialName")
                        },
                    });
                }
            }

            // Validate Import flag usage
            if flags.contains(TypeAttributes::IMPORT) {
                // Import types can be classes or interfaces in legitimate .NET assemblies
                // The IMPORT flag indicates the type is imported from another module
                // This is valid for various types, not just interfaces
            }
        }

        Ok(())
    }

    /// Checks if a visibility attribute is valid.
    fn is_valid_visibility_attribute(visibility: TypeAttributes) -> bool {
        matches!(
            visibility,
            TypeAttributes::NOT_PUBLIC
                | TypeAttributes::PUBLIC
                | TypeAttributes::NESTED_PUBLIC
                | TypeAttributes::NESTED_PRIVATE
                | TypeAttributes::NESTED_FAMILY
                | TypeAttributes::NESTED_ASSEMBLY
                | TypeAttributes::NESTED_FAM_AND_ASSEM
                | TypeAttributes::NESTED_FAM_OR_ASSEM
        )
    }

    /// Checks if a layout attribute is valid.
    fn is_valid_layout_attribute(layout: TypeAttributes) -> bool {
        matches!(
            layout,
            TypeAttributes::AUTO_LAYOUT
                | TypeAttributes::SEQUENTIAL_LAYOUT
                | TypeAttributes::EXPLICIT_LAYOUT
        )
    }

    /// Checks if a class semantics attribute is valid.
    fn is_valid_class_semantics_attribute(class_semantics: TypeAttributes) -> bool {
        matches!(
            class_semantics,
            TypeAttributes::CLASS | TypeAttributes::INTERFACE
        )
    }

    /// Checks if a string format attribute is valid.
    fn is_valid_string_format_attribute(string_format: TypeAttributes) -> bool {
        matches!(
            string_format,
            TypeAttributes::ANSI_CLASS | TypeAttributes::UNICODE_CLASS | TypeAttributes::AUTO_CLASS
        )
    }
}

impl OwnedValidator for OwnedTypeDefinitionValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_type_definition_structure(context)?;
        self.validate_type_attribute_consistency(context)?;
        self.validate_type_flavor_consistency(context)?;
        self.validate_special_type_constraints(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedTypeDefinitionValidator"
    }

    fn priority(&self) -> u32 {
        190
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedTypeDefinitionValidator {
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
            factories::validation::type_definition::owned_type_definition_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_type_definition_validator() -> Result<()> {
        let validator = OwnedTypeDefinitionValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_type_definition_validator_file_factory,
            "OwnedTypeDefinitionValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
