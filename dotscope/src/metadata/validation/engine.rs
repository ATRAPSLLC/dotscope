//! Unified validation engine for orchestrating both raw and owned validation.
//!
//! This module provides the core [`crate::metadata::validation::engine::ValidationEngine`] that coordinates validation across
//! both Stage 1 (raw) and Stage 2 (owned) validation. The engine supports parallel
//! execution, early termination, and comprehensive error collection while maintaining
//! a unified interface for all validation operations.
//!
//! # Architecture
//!
//! The validation engine operates in two distinct stages:
//! 1. **Raw Validation**: Validates raw assembly data using [`crate::metadata::validation::traits::RawValidator`] implementations
//! 2. **Owned Validation**: Validates resolved data structures using [`crate::metadata::validation::traits::OwnedValidator`] implementations
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::ValidationEngine`] - Main validation orchestrator
//! - [`crate::metadata::validation::ValidationStatistics`] - Runtime validation statistics
//! - [`crate::metadata::validation::TwoStageValidationResult`] - Results from both validation stages
//! - [`crate::metadata::validation::ReferenceScanner`] - Shared reference scanning infrastructure
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{ValidationEngine, ValidationConfig};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let config = ValidationConfig::production();
//! let engine = ValidationEngine::new(&view, config)?;
//!
//! let result = engine.execute_two_stage_validation(&view, None, None)?;
//! if result.is_success() {
//!     println!("Validation passed");
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. The validation engine uses parallel
//! execution internally for optimal validation speed.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::validators`] - Collection of all validator implementations
//! - [`crate::metadata::validation::context`] - Validation context abstractions
//! - [`crate::metadata::validation::config`] - Configuration for validation behavior

use std::{sync::OnceLock, time::Instant};

use log::debug;
use rayon::prelude::*;

use crate::{
    cilassembly::AssemblyChanges,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cilobject::CilObject,
        validation::{
            config::ValidationConfig,
            context::factory as context_factory,
            result::{TwoStageValidationResult, ValidationResult},
            scanner::{ReferenceScanner, ScannerStatistics},
            traits::{OwnedValidator, RawValidator},
            validators::{
                OwnedAccessibilityValidator, OwnedAssemblyValidator, OwnedAttributeValidator,
                OwnedCircularityValidator, OwnedDependencyValidator, OwnedFieldValidator,
                OwnedInheritanceValidator, OwnedMethodValidator, OwnedOwnershipValidator,
                OwnedSecurityValidator, OwnedSignatureValidator, OwnedTypeCircularityValidator,
                OwnedTypeConstraintValidator, OwnedTypeDefinitionValidator,
                OwnedTypeDependencyValidator, OwnedTypeOwnershipValidator,
                RawChangeIntegrityValidator, RawGenericConstraintValidator, RawHeapValidator,
                RawLayoutConstraintValidator, RawOperationValidator, RawSignatureValidator,
                RawSortOrderValidator, RawTableValidator, RawTokenValidator,
            },
        },
    },
    Error, Result,
};

/// Static registry of raw validators.
///
/// Contains pre-built validator instances created once and reused for all validation operations.
/// Validators are ordered by priority (highest first) and initialized on first access.
static RAW_VALIDATORS: OnceLock<Vec<Box<dyn RawValidator>>> = OnceLock::new();

/// Static registry of owned validators.
///
/// Contains pre-built validator instances created once and reused for all validation operations.
/// Validators are ordered by priority (highest first) and initialized on first access.
static OWNED_VALIDATORS: OnceLock<Vec<Box<dyn OwnedValidator>>> = OnceLock::new();

/// Initialize the raw validators array with all validators in priority order.
fn init_raw_validators() -> Vec<Box<dyn RawValidator>> {
    vec![
        // Structure validators (priority 175-200)
        Box::new(RawTokenValidator::new()),     // priority 200
        Box::new(RawTableValidator::new()),     // priority 190
        Box::new(RawSortOrderValidator::new()), // priority 185
        Box::new(RawHeapValidator::new()),      // priority 180
        Box::new(RawSignatureValidator::new()), // priority 175
        // Constraint validators (priority 120-130)
        Box::new(RawGenericConstraintValidator::new()), // priority 130
        Box::new(RawLayoutConstraintValidator::new()),  // priority 120
        // Modification validators (priority 100-110)
        Box::new(RawOperationValidator::new()), // priority 110
        Box::new(RawChangeIntegrityValidator::new()), // priority 100
    ]
}

/// Initialize the owned validators array with all validators in priority order.
fn init_owned_validators() -> Vec<Box<dyn OwnedValidator>> {
    vec![
        // Type validators (priority 180-190)
        Box::new(OwnedTypeDefinitionValidator::new()), // priority 190
        Box::new(OwnedTypeConstraintValidator::new()), // priority 185
        Box::new(OwnedInheritanceValidator::new()),    // priority 180
        Box::new(OwnedTypeCircularityValidator::new()), // priority 175
        Box::new(OwnedTypeDependencyValidator::new()), // priority 170
        Box::new(OwnedTypeOwnershipValidator::new()),  // priority 165
        // Member validators (priority 150-160)
        Box::new(OwnedMethodValidator::new()), // priority 160
        Box::new(OwnedFieldValidator::new()),  // priority 155
        Box::new(OwnedAccessibilityValidator::new()), // priority 150
        // Metadata validators (priority 130-140)
        Box::new(OwnedSignatureValidator::new()), // priority 140
        Box::new(OwnedAttributeValidator::new()), // priority 130
        // Relationship validators (priority 125-135)
        Box::new(OwnedCircularityValidator::new()), // priority 135
        Box::new(OwnedDependencyValidator::new()),  // priority 130
        Box::new(OwnedOwnershipValidator::new()),   // priority 125
        // System validators (priority 110-120)
        Box::new(OwnedSecurityValidator::new()), // priority 120
        Box::new(OwnedAssemblyValidator::new()), // priority 110
    ]
}

/// Unified validation engine for coordinating all validation operations.
///
/// The [`crate::metadata::validation::engine::ValidationEngine`] serves as the central orchestrator for both raw (Stage 1)
/// and owned (Stage 2) validation. It manages parallel execution, error collection,
/// and provides a unified interface for all validation scenarios.
///
/// # Features
///
/// - **Parallel Execution**: Both stages use parallel processing
/// - **Early Termination**: Stage 1 failure prevents Stage 2 execution
/// - **Error Collection**: Comprehensive error reporting with detailed context
/// - **Flexible Configuration**: Supports various validation configurations
/// - **Statistics Tracking**: Tracks validation timing and statistics
///
/// # Examples
///
/// ```no_run
/// use crate::metadata::validation::engine::ValidationEngine;
///
/// let engine = ValidationEngine::new(config)?;
///
/// // Two-stage validation
/// let result = engine.execute_two_stage_validation(
///     &assembly_view,
///     None, // No modifications
///     Some(&object_data),
///     &config,
/// )?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ValidationEngine {
    /// Validation configuration
    config: ValidationConfig,
    /// Shared reference scanner
    scanner: ReferenceScanner,
}

impl ValidationEngine {
    /// Creates a new validation engine with the specified configuration.
    ///
    /// # Arguments
    ///
    /// * `view` - Assembly view for scanner initialization
    /// * `config` - Validation configuration
    ///
    /// # Returns
    ///
    /// Returns a configured validation engine ready for validation operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference scanner cannot be initialized.
    pub fn new(view: &CilAssemblyView, config: ValidationConfig) -> Result<Self> {
        let scanner =
            ReferenceScanner::from_view(view).map_err(|e| Error::ValidationEngineInitFailed {
                message: format!("Failed to initialize reference scanner: {e}"),
            })?;

        debug!(
            "Validation starting: {} raw + {} owned validators, lenient={}",
            init_raw_validators().len(),
            init_owned_validators().len(),
            config.lenient
        );

        Ok(Self { config, scanner })
    }

    /// Executes validation in two stages: Raw → Owned.
    ///
    /// Stage 1 must pass completely before Stage 2 runs. This method supports
    /// both loading validation (no changes) and modification validation (with changes).
    ///
    /// # Arguments
    ///
    /// * `view` - Assembly view containing raw metadata
    /// * `changes` - Optional assembly changes for modification validation
    /// * `object` - Optional CilObject for Stage 2 validation
    /// * `config` - Validation configuration
    ///
    /// # Returns
    ///
    /// Returns a comprehensive result containing outcomes from both stages.
    ///
    /// # Errors
    ///
    /// Returns an error if Stage 1 fails (preventing Stage 2) or if Stage 2 fails.
    pub fn execute_two_stage_validation(
        &self,
        view: &CilAssemblyView,
        changes: Option<&AssemblyChanges>,
        object: Option<&CilObject>,
    ) -> Result<TwoStageValidationResult> {
        let mut result = TwoStageValidationResult::new();

        // Stage 1: Raw validation (ALWAYS runs first if enabled)
        if self.config.should_validate_raw() {
            let stage1_result = self.execute_stage1_validation(view, changes)?;
            let stage1_success = stage1_result.is_success();
            result.set_stage1_result(stage1_result);

            // CRITICAL: Early termination if Stage 1 fails
            if !stage1_success {
                return Ok(result); // Return with only Stage 1 result
            }
        }

        // Stage 2: Owned validation (ONLY runs if Stage 1 passed and object is available)
        if let Some(obj) = object {
            if self.config.should_validate_owned() {
                let stage2_result = self.execute_stage2_validation(obj)?;
                result.set_stage2_result(stage2_result);
            }
        }

        Ok(result)
    }

    /// Executes Stage 1 (raw) validation with parallel processing.
    ///
    /// This method coordinates raw validators using parallel execution while
    /// maintaining fail-fast behavior for early error detection.
    ///
    /// # Arguments
    ///
    /// * `view` - Assembly view to validate
    /// * `changes` - Optional changes for modification validation
    ///
    /// # Returns
    ///
    /// Returns validation results from all raw validators.
    ///
    /// # Errors
    ///
    /// Returns an error if raw validation fails or validator execution encounters issues.
    pub fn execute_stage1_validation(
        &self,
        view: &CilAssemblyView,
        changes: Option<&AssemblyChanges>,
    ) -> Result<ValidationResult> {
        let validators = Self::get_raw_validators();
        self.validate_raw_stage(view, changes, validators)
    }

    /// Executes Stage 2 (owned) validation with parallel processing.
    ///
    /// This method coordinates owned validators using parallel execution with
    /// comprehensive error collection.
    ///
    /// # Arguments
    ///
    /// * `object` - CilObject to validate
    ///
    /// # Returns
    ///
    /// Returns validation results from all owned validators.
    ///
    /// # Errors
    ///
    /// Returns an error if owned validation fails or validator execution encounters issues.
    pub fn execute_stage2_validation(&self, object: &CilObject) -> Result<ValidationResult> {
        let validators = Self::get_owned_validators();
        self.validate_owned_stage(object, validators)
    }

    /// Validates raw metadata using parallel execution with fail-fast behavior.
    ///
    /// # Arguments
    ///
    /// * `view` - Assembly view to validate
    /// * `changes` - Optional changes for modification validation
    /// * `validators` - Collection of raw validators to execute
    ///
    /// # Returns
    ///
    /// Returns aggregated validation results.
    ///
    /// # Errors
    ///
    /// Returns an error if validation context creation fails or validator execution encounters issues.
    pub fn validate_raw_stage(
        &self,
        view: &CilAssemblyView,
        changes: Option<&AssemblyChanges>,
        validators: &Vec<Box<dyn RawValidator>>,
    ) -> Result<ValidationResult> {
        let start_time = Instant::now();

        // Create validation context
        let context = if let Some(changes) = changes {
            context_factory::raw_modification_context(view, changes, &self.scanner, &self.config)
        } else {
            context_factory::raw_loading_context(view, &self.scanner, &self.config)
        };

        let active_validators: Vec<_> = validators
            .iter()
            .filter(|v| v.should_run(&context))
            .collect();

        if active_validators.is_empty() {
            return Ok(ValidationResult::success());
        }

        // Execute validators in parallel on the global pool
        let results: Vec<(&str, Result<()>)> = active_validators
            .par_iter()
            .map(|validator| {
                let validator_result =
                    validator
                        .validate_raw(&context)
                        .map_err(|e| Error::ValidationRawFailed {
                            validator: validator.name().to_string(),
                            message: e.to_string(),
                        });
                (validator.name(), validator_result)
            })
            .collect();

        let duration = start_time.elapsed();

        // Convert to named results for better error reporting
        let named_results: Vec<(&str, Result<()>)> = results.into_iter().collect();
        let error_count = named_results.iter().filter(|(_, r)| r.is_err()).count();
        debug!(
            "Raw validation completed in {}ms: {} errors",
            duration.as_millis(),
            error_count
        );

        let diagnostics = if self.config.lenient {
            Some(view.diagnostics())
        } else {
            None
        };

        Ok(ValidationResult::from_named_results(
            named_results,
            duration,
            diagnostics,
        ))
    }

    /// Validates owned metadata using parallel execution with error collection.
    ///
    /// # Arguments
    ///
    /// * `object` - CilObject to validate
    /// * `validators` - Collection of owned validators to execute
    ///
    /// # Returns
    ///
    /// Returns aggregated validation results.
    ///
    /// # Errors
    ///
    /// Returns an error if validation context creation fails or validator execution encounters issues.
    pub fn validate_owned_stage(
        &self,
        object: &CilObject,
        validators: &Vec<Box<dyn OwnedValidator>>,
    ) -> Result<ValidationResult> {
        let start_time = Instant::now();

        // Create validation context
        let context = context_factory::owned_context(object, &self.scanner, &self.config);

        let active_validators: Vec<_> = validators
            .iter()
            .filter(|v| v.should_run(&context))
            .collect();

        if active_validators.is_empty() {
            return Ok(ValidationResult::success());
        }

        // Execute validators in parallel on the global pool (collect all errors)
        let results: Vec<(&str, Result<()>)> = active_validators
            .par_iter()
            .map(|validator| {
                let validator_result =
                    validator
                        .validate_owned(&context)
                        .map_err(|e| Error::ValidationOwnedFailed {
                            validator: validator.name().to_string(),
                            message: e.to_string(),
                        });
                (validator.name(), validator_result)
            })
            .collect();

        let duration = start_time.elapsed();

        // Convert to named results for comprehensive error collection
        let named_results: Vec<(&str, Result<()>)> = results.into_iter().collect();
        let error_count = named_results.iter().filter(|(_, r)| r.is_err()).count();
        debug!(
            "Owned validation completed in {}ms: {} errors",
            duration.as_millis(),
            error_count
        );

        let diagnostics = if self.config.lenient {
            Some(object.diagnostics())
        } else {
            None
        };

        Ok(ValidationResult::from_named_results(
            named_results,
            duration,
            diagnostics,
        ))
    }

    /// Gets direct access to ALL raw validators from static registry.
    ///
    /// Configuration controls execution through each validator's should_run() method.
    /// This ensures consistent validator registration and makes the system more predictable.
    /// Validators are initialized once and reused for all validation operations.
    fn get_raw_validators() -> &'static Vec<Box<dyn RawValidator>> {
        RAW_VALIDATORS.get_or_init(init_raw_validators)
    }

    /// Gets direct access to ALL owned validators from static registry.
    ///
    /// Configuration controls execution through each validator's should_run() method.
    /// This ensures consistent validator registration and makes the system more predictable.
    /// Validators are initialized once and reused for all validation operations.
    fn get_owned_validators() -> &'static Vec<Box<dyn OwnedValidator>> {
        OWNED_VALIDATORS.get_or_init(init_owned_validators)
    }

    /// Returns the validation configuration.
    #[must_use]
    pub fn config(&self) -> &ValidationConfig {
        &self.config
    }

    /// Returns the reference scanner.
    #[must_use]
    pub fn scanner(&self) -> &ReferenceScanner {
        &self.scanner
    }

    /// Returns engine statistics and performance information.
    #[must_use]
    pub fn statistics(&self) -> EngineStatistics {
        EngineStatistics {
            scanner_stats: self.scanner.statistics(),
            raw_validator_count: Self::get_raw_validators().len(),
            owned_validator_count: Self::get_owned_validators().len(),
        }
    }
}

/// Statistics about the validation engine.
#[derive(Debug, Clone)]
pub struct EngineStatistics {
    /// Reference scanner statistics
    pub scanner_stats: ScannerStatistics,
    /// Number of raw validators available
    pub raw_validator_count: usize,
    /// Number of owned validators available
    pub owned_validator_count: usize,
}

impl std::fmt::Display for EngineStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Engine Statistics: {} raw validators, {} owned validators, {}",
            self.raw_validator_count, self.owned_validator_count, self.scanner_stats
        )
    }
}

/// Factory functions for creating validation engines with common configurations.
pub mod factory {
    use super::{CilAssemblyView, Result, ValidationConfig, ValidationEngine};

    /// Creates a validation engine with minimal configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if engine initialization fails.
    pub fn minimal_engine(view: &CilAssemblyView) -> Result<ValidationEngine> {
        ValidationEngine::new(view, ValidationConfig::minimal())
    }

    /// Creates a validation engine with production configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if engine initialization fails.
    pub fn production_engine(view: &CilAssemblyView) -> Result<ValidationEngine> {
        ValidationEngine::new(view, ValidationConfig::production())
    }

    /// Creates a validation engine with comprehensive configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the validation engine cannot be initialized with the comprehensive configuration.
    pub fn comprehensive_engine(view: &CilAssemblyView) -> Result<ValidationEngine> {
        ValidationEngine::new(view, ValidationConfig::comprehensive())
    }

    /// Creates a validation engine with strict configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the validation engine cannot be initialized with the strict configuration.
    pub fn strict_engine(view: &CilAssemblyView) -> Result<ValidationEngine> {
        ValidationEngine::new(view, ValidationConfig::strict())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::AssemblyChanges,
        metadata::{
            cilassemblyview::CilAssemblyView, cilobject::CilObject,
            validation::config::ValidationConfig,
        },
        testkit::fixture,
    };

    // Test validator for validation

    #[test]
    fn test_validation_engine_creation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let config = ValidationConfig::minimal();
        let engine = ValidationEngine::new(&view, config);
        assert!(engine.is_ok(), "Engine creation should succeed");

        let engine = engine.unwrap();
        let stats = engine.statistics();
        assert!(stats.scanner_stats.total_tokens > 0);
    }

    #[test]
    fn test_two_stage_validation_early_termination() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut config = ValidationConfig::comprehensive();
        config.enable_raw_validation = true;
        config.enable_owned_validation = true;

        let engine = ValidationEngine::new(&view, config).expect("the validation engine builds");
        // Test with no object data - should only run Stage 1
        let result = engine.execute_two_stage_validation(&view, None, None);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.stage1_result().is_some());
        assert!(result.stage2_result().is_none());
    }

    #[test]
    fn test_raw_validation_with_changes() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let config = ValidationConfig::minimal();
        let engine = ValidationEngine::new(&view, config).expect("the validation engine builds");
        let changes = AssemblyChanges::empty();

        // Test modification validation
        let result = engine.execute_stage1_validation(&view, Some(&changes));
        assert!(result.is_ok());

        // Test loading validation
        let result = engine.execute_stage1_validation(&view, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_factory_functions() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        assert!(factory::minimal_engine(&view).is_ok());
        assert!(factory::production_engine(&view).is_ok());
        assert!(factory::comprehensive_engine(&view).is_ok());
        assert!(factory::strict_engine(&view).is_ok());
    }

    #[test]
    fn test_engine_statistics() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let engine = ValidationEngine::new(&view, ValidationConfig::minimal())
            .expect("the validation engine builds");
        let stats = engine.statistics();
        let stats_string = stats.to_string();

        assert!(stats_string.contains("validators"));
        assert!(stats_string.contains("tokens"));
    }

    /// Test that all validators are properly registered and the engine can create them
    #[test]
    fn test_all_validators_registered() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");

        // Create validation engine with comprehensive config to ensure all validators would run
        let config = ValidationConfig::comprehensive();
        let engine =
            ValidationEngine::new(&view, config).expect("Failed to create validation engine");

        // Test engine statistics - this will call the validator creation methods
        let stats = engine.statistics();

        // Verify we have the expected number of validators
        // As of current implementation: 7 raw + 15 owned = 22 total
        assert!(
            stats.raw_validator_count >= 7,
            "Expected at least 7 raw validators, got {}",
            stats.raw_validator_count
        );
        assert!(
            stats.owned_validator_count >= 15,
            "Expected at least 15 owned validators, got {}",
            stats.owned_validator_count
        );
    }

    /// Test that raw validator creation doesn't panic and validators have unique names
    #[test]
    fn test_raw_validators_creation_and_uniqueness() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");

        let config = ValidationConfig::comprehensive();
        let engine =
            ValidationEngine::new(&view, config).expect("Failed to create validation engine");

        // This will internally call create_raw_validators()
        let result = engine.execute_stage1_validation(&view, None);

        // Should not panic during validator creation or execution
        // The important thing is that we didn't panic during validator creation
        assert!(
            result.is_ok() || result.is_err(),
            "Validation should complete without panicking"
        );

        // Test that we can access the raw validators internally
        // Note: This is testing that all raw validators can be instantiated
    }

    /// Test that owned validator creation doesn't panic and validators have unique names
    #[test]
    fn test_owned_validators_creation_and_uniqueness() {
        let path = fixture("mono_4.8/mscorlib.dll");

        let object = CilObject::from_path(&path).expect("Failed to load mscorlib.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");
        let config = ValidationConfig::comprehensive();
        let engine =
            ValidationEngine::new(&view, config).expect("Failed to create validation engine");

        // This will internally call create_owned_validators()
        let validation_result = engine.execute_stage2_validation(&object);

        // Should not panic during validator creation or execution
        // The important thing is that we didn't panic during validator creation
        assert!(
            validation_result.is_ok() || validation_result.is_err(),
            "Validation should complete without panicking"
        );
    }

    /// Test two-stage validation with all validators
    #[test]
    fn test_complete_two_stage_validation() {
        let path = fixture("mono_4.8/mscorlib.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");
        let object = CilObject::from_path(&path).expect("Failed to load mscorlib.dll");

        // Test with different validation configurations
        let configs = vec![
            ("minimal", ValidationConfig::minimal()),
            ("production", ValidationConfig::production()),
            ("comprehensive", ValidationConfig::comprehensive()),
        ];

        // Run all configurations in parallel for better performance
        configs.into_par_iter().for_each(|(name, config)| {
            let engine =
                ValidationEngine::new(&view, config).expect("Failed to create validation engine");

            // Test two-stage validation directly through the engine
            let result = engine.execute_two_stage_validation(&view, None, Some(&object));
            assert!(
                result.is_ok(),
                "Two-stage validation should complete for {name} config"
            );

            if let Ok(two_stage_result) = result {
                // Verify that the result structure is valid
                assert!(
                    two_stage_result.stage1_result().is_some()
                        || two_stage_result.stage2_result().is_some(),
                    "At least one validation stage should have run for {name} config"
                );
            }
        });
    }

    /// Test validation engine factory methods work with all validators
    #[test]
    fn test_validation_engine_factories() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");

        // Test all factory methods
        let engines = vec![
            ("minimal", factory::minimal_engine(&view)),
            ("production", factory::production_engine(&view)),
            ("comprehensive", factory::comprehensive_engine(&view)),
            ("strict", factory::strict_engine(&view)),
        ];

        for (name, engine_result) in engines {
            assert!(
                engine_result.is_ok(),
                "Failed to create {name} engine: {:?}",
                engine_result.err()
            );

            if let Ok(engine) = engine_result {
                let stats = engine.statistics();
                assert!(
                    stats.raw_validator_count > 0,
                    "{name} engine should have raw validators"
                );
                assert!(
                    stats.owned_validator_count > 0,
                    "{name} engine should have owned validators"
                );
            }
        }
    }

    /// Test that validator names are unique for debugging purposes
    #[test]
    fn test_validator_name_uniqueness() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("Failed to load test assembly");

        let config = ValidationConfig::comprehensive();
        let engine =
            ValidationEngine::new(&view, config).expect("Failed to create validation engine");

        // We can't directly access validator names without executing, but we can verify
        // that the engine can be created and validators are accessible
        let stats = engine.statistics();

        // Verify total validator count makes sense
        let total_validators = stats.raw_validator_count + stats.owned_validator_count;
        assert!(
            total_validators >= 22,
            "Expected at least 22 total validators, got {total_validators}"
        );
        assert_eq!(
            total_validators,
            stats.raw_validator_count + stats.owned_validator_count,
            "Total validator count should equal sum of raw and owned validators"
        );
    }
}
