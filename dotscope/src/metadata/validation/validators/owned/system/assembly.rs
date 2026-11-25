//! Owned assembly validator for assembly-level validation.
//!
//! This validator provides comprehensive validation of assembly-level metadata within the context
//! of fully resolved .NET metadata. It operates on resolved assembly structures to validate
//! the assembly's identity, its references, and its module.
//! This validator ensures that assemblies are properly formed and don't violate ECMA-335
//! assembly model requirements. This validator runs with priority 110 in the owned validation stage.
//!
//! # Architecture
//!
//! The assembly validation system implements comprehensive assembly-level validation in sequential order:
//! 1. **Assembly Metadata Consistency Validation** - The assembly has a name and a version in range
//! 2. **Cross-Assembly Reference Validation** - References have names, defined flags and well-formed keys
//! 3. **Module File Consistency Validation** - Defined assembly flags and hash algorithm, a named module with a non-null MVID
//!
//! Every rule is an ECMA-335 requirement or a value the runtime defines; names, versions,
//! cultures, keys and file sizes are not judged by any limit of the validator's own.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator`] - Main validator implementation providing comprehensive assembly validation
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_assembly_metadata_consistency`] - Assembly metadata consistency and completeness validation
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_cross_assembly_references`] - Cross-assembly reference validation and resolution checking
//! - [`crate::metadata::validation::validators::owned::system::assembly::OwnedAssemblyValidator::validate_module_file_consistency`] - Module and file consistency validation within assemblies
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{OwnedAssemblyValidator, OwnedValidator, OwnedValidationContext};
//!
//! # fn get_context() -> OwnedValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//! let validator = OwnedAssemblyValidator::new();
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
//! - An assembly, assembly reference, type reference, member reference or module without a name
//! - Undefined assembly or assembly reference flags, or an undefined hash algorithm
//! - An empty public key, or an ECMA key that is not 16 bytes
//! - A module whose MVID is null
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
//! - owned system validators - Part of the owned system validation stage
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Implements the owned validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved assembly structures
//! - [`crate::metadata::validation::context::OwnedValidationContext`] - Provides validation execution context
//! - [`crate::metadata::validation::config::ValidationConfig`] - Controls validation execution via enable_semantic_validation flag
//!
//! # References
//!
//! - [ECMA-335 II.6.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assemblies and modules
//! - [ECMA-335 II.22.2](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - AssemblyRef table
//! - [ECMA-335 II.22.20](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Assembly table
//! - [ECMA-335 II.22.14](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - File table
//! - [ECMA-335 I.6.3](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - Application domains and assemblies

use std::sync::Arc;

use crate::{
    metadata::{
        identity::Identity,
        tables::{HashAlgorithmId, TableId},
        validation::{
            context::{OwnedValidationContext, ValidationContext},
            traits::OwnedValidator,
        },
    },
    Error, Result,
};

/// The `CorAssemblyFlags` bits the runtime defines (corhdr.h): PublicKey, the processor
/// architecture field and its Specified bit, Retargetable, the content type field and the
/// two JIT flags.
const DEFINED_ASSEMBLY_FLAGS: u32 = 0xCFF1;

/// Foundation validator for assembly-level metadata, references, and integrity constraints.
///
/// Ensures the structural integrity and consistency of assembly-level metadata in resolved .NET metadata,
/// validating assembly metadata completeness, cross-assembly references and module file
/// consistency. This validator operates on resolved assembly structures to provide
/// essential guarantees about assembly integrity and ECMA-335 compliance.
///
/// The validator implements comprehensive coverage of assembly validation according to
/// ECMA-335 specifications, ensuring proper assembly formation and dependency management
/// in the resolved metadata object model.
///
/// # Thread Safety
///
/// This validator is [`Send`] and [`Sync`] as all validation operations are read-only
/// and operate on immutable resolved metadata structures.
pub struct OwnedAssemblyValidator;

impl OwnedAssemblyValidator {
    /// Creates a new assembly validator instance.
    ///
    /// Initializes a validator instance that can be used to validate assembly-level metadata
    /// across multiple assemblies. The validator is stateless and can be reused safely
    /// across multiple validation operations.
    ///
    /// # Returns
    ///
    /// A new [`OwnedAssemblyValidator`] instance ready for validation operations.
    ///
    /// # Thread Safety
    ///
    /// The returned validator is thread-safe and can be used concurrently.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl OwnedAssemblyValidator {
    /// Validates assembly metadata consistency and completeness.
    ///
    /// Ensures that assembly-level metadata is properly formed and contains
    /// all required information according to ECMA-335 specifications.
    /// Validates the assembly name and version.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All assembly metadata is consistent and complete
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Metadata consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Assembly has an empty name
    /// - Assembly version components exceed their 16-bit columns
    fn validate_assembly_metadata_consistency(
        &self,
        context: &OwnedValidationContext,
    ) -> Result<()> {
        let assembly_info = context.object().assembly();

        if let Some(assembly) = assembly_info {
            // Validate basic assembly properties
            if assembly.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: "Assembly has empty name".to_string(),
                });
            }

            // Validate version information
            self.validate_assembly_version(assembly)?;
        }

        Ok(())
    }

    /// Validates assembly version information.
    fn validate_assembly_version(
        &self,
        assembly: &Arc<crate::metadata::tables::Assembly>,
    ) -> Result<()> {
        // Version components should be reasonable
        if assembly.major_version > 65535
            || assembly.minor_version > 65535
            || assembly.build_number > 65535
            || assembly.revision_number > 65535
        {
            return Err(Error::ValidationOwnedFailed {
                validator: self.name().to_string(),
                message: format!(
                    "Assembly '{}' has invalid version components: {}.{}.{}.{}",
                    assembly.name,
                    assembly.major_version,
                    assembly.minor_version,
                    assembly.build_number,
                    assembly.revision_number
                ),
            });
        }

        Ok(())
    }

    /// Validates cross-assembly reference validation and resolution.
    ///
    /// Ensures that all assembly references can be resolved and that
    /// cross-assembly dependencies are properly formed and accessible.
    /// Validates assembly references, type references, and member references.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All cross-assembly references are valid and resolvable
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Cross-assembly reference violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Assembly references have empty names or undefined flags
    /// - Public keys are empty, or ECMA keys are not 16 bytes
    /// - Type references or member references have empty names
    fn validate_cross_assembly_references(&self, context: &OwnedValidationContext) -> Result<()> {
        // Validate external assembly references
        let assembly_refs = context.object().refs_assembly();
        for (index, entry) in assembly_refs.iter().enumerate() {
            let assembly_ref = entry.value();
            // Validate assembly reference name
            if assembly_ref.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Assembly reference {index} has empty name"),
                });
            }

            if assembly_ref.flags.bits() & !DEFINED_ASSEMBLY_FLAGS != 0 {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly reference '{}' has undefined flags: 0x{:08X}",
                        assembly_ref.name,
                        assembly_ref.flags.bits()
                    ),
                });
            }

            // Validate identity (public key/token) if present
            if let Some(identity) = &assembly_ref.identifier {
                match identity {
                    Identity::Token(_) => {}
                    Identity::PubKey(public_key) => {
                        if public_key.is_empty() {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has empty public key",
                                    assembly_ref.name
                                ),
                            });
                        }
                    }
                    Identity::EcmaKey(ecma_key) => {
                        if ecma_key.len() != 16 {
                            return Err(Error::ValidationOwnedFailed {
                                validator: self.name().to_string(),
                                message: format!(
                                    "Assembly reference '{}' has invalid ECMA key size: {} bytes. Expected exactly 16 bytes",
                                    assembly_ref.name,
                                    ecma_key.len()
                                ),

                            });
                        }
                    }
                }
            }
        }

        // Validate cross-assembly type references
        for type_entry in context.target_assembly_types() {
            let type_ref = type_entry.as_ref();
            // Only validate type references
            if type_ref.token.is_table(TableId::TypeRef) {
                // Validate type reference has valid name
                if type_ref.name.is_empty() {
                    return Err(Error::ValidationOwnedFailed {
                        validator: self.name().to_string(),
                        message: "Cross-assembly type reference has empty name".to_string(),
                    });
                }
            }
        }

        // Validate cross-assembly member references
        let member_refs = context.object().refs_members();
        for entry in member_refs {
            let member_ref = entry.value();
            // Validate member reference has valid name
            if member_ref.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: "Cross-assembly member reference has empty name".to_string(),
                });
            }
        }

        Ok(())
    }

    /// Validates module and file consistency within assemblies.
    ///
    /// Ensures that modules and files are properly registered and consistent
    /// within the assembly structure. Validates module metadata and PE file structure.
    ///
    /// # Arguments
    ///
    /// * `context` - Owned validation context containing resolved assembly structures via [`crate::metadata::validation::context::OwnedValidationContext`]
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All modules and files are consistent within the assembly
    /// * `Err(`[`crate::Error::ValidationOwnedFailed`]`)` - Module file consistency violations found
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ValidationOwnedFailed`] if:
    /// - Assembly flags or hash algorithm IDs are undefined
    /// - The module name is empty
    /// - The module ID (MVID) is all-zero (ECMA-335 II.22.30)
    fn validate_module_file_consistency(&self, context: &OwnedValidationContext) -> Result<()> {
        // Validate basic assembly structure
        if let Some(assembly) = context.object().assembly() {
            if assembly.flags.bits() & !DEFINED_ASSEMBLY_FLAGS != 0 {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has undefined flags: 0x{:08X}",
                        assembly.name,
                        assembly.flags.bits()
                    ),
                });
            }

            // The hash algorithms ECMA-335 II.23.1.1 and .NET define
            if ![
                HashAlgorithmId::NONE,
                HashAlgorithmId::MD5,
                HashAlgorithmId::SHA1,
                HashAlgorithmId::SHA256,
                HashAlgorithmId::SHA384,
                HashAlgorithmId::SHA512,
            ]
            .contains(&assembly.hash_alg_id)
            {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Assembly '{}' has unknown hash algorithm: 0x{:08X}",
                        assembly.name, assembly.hash_alg_id
                    ),
                });
            }
        }

        // Validate modules within the assembly
        if let Some(module) = context.object().module() {
            let index = 0;
            // Validate module name
            if module.name.is_empty() {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!("Module {index} has empty name"),
                });
            }

            // Validate module ID is not all zeros
            if module.mvid.to_bytes().iter().all(|&b| b == 0) {
                return Err(Error::ValidationOwnedFailed {
                    validator: self.name().to_string(),
                    message: format!(
                        "Module '{}' has all-zero MVID (Module Version ID)",
                        module.name
                    ),
                });
            }
        }

        Ok(())
    }
}

impl OwnedValidator for OwnedAssemblyValidator {
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
        self.validate_assembly_metadata_consistency(context)?;
        self.validate_cross_assembly_references(context)?;
        self.validate_module_file_consistency(context)?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "OwnedAssemblyValidator"
    }

    fn priority(&self) -> u32 {
        110
    }

    fn should_run(&self, context: &OwnedValidationContext) -> bool {
        context.config().enable_semantic_validation
    }
}

impl Default for OwnedAssemblyValidator {
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
            factories::validation::system_assembly::owned_assembly_validator_file_factory,
            owned_validator_test,
        },
    };

    #[test]
    fn test_owned_assembly_validator() -> Result<()> {
        let validator = OwnedAssemblyValidator::new();
        let config = ValidationConfig {
            enable_semantic_validation: true,
            ..Default::default()
        };

        owned_validator_test(
            owned_assembly_validator_file_factory,
            "OwnedAssemblyValidator",
            config,
            |context| validator.validate_owned(context),
        )
    }
}
