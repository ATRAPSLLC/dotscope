//! Validator trait definitions for the unified validation framework.
//!
//! This module defines the core traits that all validators must implement. The trait system
//! supports both raw validation (Stage 1) and owned validation (Stage 2) while providing
//! a unified interface for the validation engine.
//!
//! # Architecture
//!
//! The validation system uses two main trait hierarchies:
//! - [`crate::metadata::validation::traits::RawValidator`] - For Stage 1 validation on raw metadata
//! - [`crate::metadata::validation::traits::OwnedValidator`] - For Stage 2 validation on resolved data
//!
//! Both traits provide priority-based execution ordering and conditional execution through
//! the `should_run()` method, allowing validators to adapt to different validation contexts.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::traits::RawValidator`] - Trait for raw metadata validation
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Trait for owned metadata validation
//! - [`crate::metadata::validation::traits::ValidatorCollection`] - Helper trait for managing validator collections
//! - [`crate::raw_validators`] - Macro for creating raw validator collections
//! - [`crate::owned_validators`] - Macro for creating owned validator collections
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{RawValidator, OwnedValidator, RawValidationContext, OwnedValidationContext};
//! use dotscope::Result;
//!
//! struct ExampleRawValidator;
//!
//! impl RawValidator for ExampleRawValidator {
//!     fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
//!         // Perform raw validation
//!         Ok(())
//!     }
//!
//!     fn name(&self) -> &'static str {
//!         "ExampleRawValidator"
//!     }
//!
//!     fn priority(&self) -> u32 {
//!         150  // Higher priority than default
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All validator traits require [`Send`] + [`Sync`] implementations to support parallel
//! execution in the validation engine. This ensures validators can be safely executed
//! across multiple threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Uses traits to execute validators
//! - [`crate::metadata::validation::context`] - Provides context types for validator methods
//! - [`crate::metadata::validation::validators`] - Contains concrete validator implementations

use crate::{
    metadata::validation::context::{OwnedValidationContext, RawValidationContext},
    Result,
};

/// Trait for validators that operate on raw metadata (Stage 1).
///
/// Raw validators are responsible for validating basic structural integrity,
/// schema compliance, and modification validity. They work with [`crate::metadata::cilassemblyview::CilAssemblyView`]
/// and optionally assembly changes for modification validation.
///
/// Raw validators support two use cases:
/// 1. **Loading validation** - Validate [`crate::metadata::cilassemblyview::CilAssemblyView`] structure during loading
/// 2. **Modification validation** - Validate assembly changes against original assembly
///
/// # Thread Safety
///
/// All raw validators must be [`Send`] + [`Sync`] to support parallel execution in the
/// validation engine.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{RawValidator, RawValidationContext};
/// use dotscope::Result;
///
/// struct MyRawValidator;
///
/// impl RawValidator for MyRawValidator {
///     fn validate_raw(&self, context: &RawValidationContext) -> Result<()> {
///         if context.is_modification_validation() {
///             // Validate changes
///             if let Some(_changes) = context.changes() {
///                 // Perform modification validation
///             }
///         } else {
///             // Validate raw assembly structure
///             let _view = context.assembly_view();
///             // Perform loading validation
///         }
///         Ok(())
///     }
///
///     fn name(&self) -> &'static str {
///         "MyRawValidator"
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub trait RawValidator: Send + Sync {
    /// Validates raw metadata in the provided context.
    ///
    /// This method is called by the validation engine to perform raw validation.
    /// The context provides access to the assembly view, optional changes,
    /// reference scanner, and configuration.
    ///
    /// # Arguments
    ///
    /// * `context` - The [`crate::metadata::validation::context::RawValidationContext`] containing all necessary data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error describing the validation failure.
    ///
    /// # Errors
    ///
    /// Should return validation-specific errors from the [`crate::Error`] enum,
    /// such as `ValidationRawFailed` or domain-specific validation errors.
    fn validate_raw(&self, context: &RawValidationContext) -> Result<()>;

    /// Returns the name of this validator for error reporting and logging.
    ///
    /// The name should be a static string that uniquely identifies this validator
    /// within the raw validation stage.
    fn name(&self) -> &'static str;

    /// Returns the priority of this validator for execution ordering.
    ///
    /// Validators with higher priority values are executed first. This allows
    /// critical validators (like schema validation) to run before more complex
    /// validators that depend on basic structural integrity.
    ///
    /// Default priority is 100 (medium priority).
    fn priority(&self) -> u32 {
        100
    }

    /// Returns whether this validator should run for the given context.
    ///
    /// This allows validators to selectively enable themselves based on the
    /// validation context (e.g., only run for modification validation).
    ///
    /// Default implementation returns `true` (always run).
    fn should_run(&self, _context: &RawValidationContext) -> bool {
        true
    }
}

/// Trait for validators that operate on owned metadata (Stage 2).
///
/// Owned validators are responsible for validating semantic correctness,
/// type system consistency, and cross-reference integrity. They work with
/// fully resolved [`crate::metadata::cilobject::CilObject`] while maintaining access to raw metadata
/// through the validation context.
///
/// # Thread Safety
///
/// All owned validators must be [`Send`] + [`Sync`] to support parallel execution in the
/// validation engine.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{OwnedValidator, OwnedValidationContext};
/// use dotscope::Result;
///
/// struct MyOwnedValidator;
///
/// impl OwnedValidator for MyOwnedValidator {
///     fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()> {
///         let object = context.object();
///         let types = object.types();
///
///         // Validate type system consistency
///         for type_entry in types.all_types() {
///             // Perform validation on each type
///             let _name = &type_entry.name;
///         }
///
///         Ok(())
///     }
///
///     fn name(&self) -> &'static str {
///         "MyOwnedValidator"
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub trait OwnedValidator: Send + Sync {
    /// Validates owned metadata in the provided context.
    ///
    /// This method is called by the validation engine to perform owned validation.
    /// The context provides access to both raw assembly view and resolved object data,
    /// along with the reference scanner and configuration.
    ///
    /// # Arguments
    ///
    /// * `context` - The [`crate::metadata::validation::context::OwnedValidationContext`] containing all necessary data
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error describing the validation failure.
    ///
    /// # Errors
    ///
    /// Should return validation-specific errors from the [`crate::Error`] enum,
    /// such as `ValidationOwnedFailed` or domain-specific validation errors.
    fn validate_owned(&self, context: &OwnedValidationContext) -> Result<()>;

    /// Returns the name of this validator for error reporting and logging.
    ///
    /// The name should be a static string that uniquely identifies this validator
    /// within the owned validation stage.
    fn name(&self) -> &'static str;

    /// Returns the priority of this validator for execution ordering.
    ///
    /// Validators with higher priority values are executed first. This allows
    /// fundamental validators (like token validation) to run before more complex
    /// validators that depend on basic consistency.
    ///
    /// Default priority is 100 (medium priority).
    fn priority(&self) -> u32 {
        100
    }

    /// Returns whether this validator should run for the given context.
    ///
    /// This allows validators to selectively enable themselves based on the
    /// validation context or configuration.
    ///
    /// Default implementation returns `true` (always run).
    fn should_run(&self, _context: &OwnedValidationContext) -> bool {
        true
    }
}

/// Helper trait for creating validator collections with type erasure.
///
/// This trait provides utilities for building collections of validators with automatic
/// priority-based sorting and type erasure through [`Box`] wrappers.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::{ValidatorCollection, RawValidator, RawValidationContext};
/// use dotscope::Result;
///
/// struct TestValidator;
/// impl RawValidator for TestValidator {
///     fn validate_raw(&self, _context: &RawValidationContext) -> Result<()> { Ok(()) }
///     fn name(&self) -> &'static str { "TestValidator" }
/// }
///
/// let mut validators: Vec<Box<dyn RawValidator>> = Vec::new();
/// let validators = validators
///     .add_validator(Box::new(TestValidator))
///     .sort_by_priority();
/// # Ok::<(), dotscope::Error>(())
/// ```
pub trait ValidatorCollection<V> {
    /// Adds a validator to the collection.
    ///
    /// # Arguments
    ///
    /// * `validator` - The validator to add to the collection
    ///
    /// # Returns
    ///
    /// Returns the updated collection with the validator added.
    #[must_use]
    fn add_validator(self, validator: V) -> Self;

    /// Sorts validators by priority (highest first).
    ///
    /// Validators with higher priority values are placed first in the collection,
    /// ensuring they execute before lower-priority validators.
    ///
    /// # Returns
    ///
    /// Returns the collection sorted by validator priority in descending order.
    #[must_use]
    fn sort_by_priority(self) -> Self;
}

impl ValidatorCollection<Box<dyn RawValidator>> for Vec<Box<dyn RawValidator>> {
    fn add_validator(mut self, validator: Box<dyn RawValidator>) -> Self {
        self.push(validator);
        self
    }

    fn sort_by_priority(mut self) -> Self {
        self.sort_by_key(|validator| std::cmp::Reverse(validator.priority()));
        self
    }
}

impl ValidatorCollection<Box<dyn OwnedValidator>> for Vec<Box<dyn OwnedValidator>> {
    fn add_validator(mut self, validator: Box<dyn OwnedValidator>) -> Self {
        self.push(validator);
        self
    }

    fn sort_by_priority(mut self) -> Self {
        self.sort_by_key(|validator| std::cmp::Reverse(validator.priority()));
        self
    }
}

/// Convenience macros for creating validator collections.
#[macro_export]
macro_rules! raw_validators {
    ($($validator:expr),* $(,)?) => {
        {
            use $crate::metadata::validation::traits::ValidatorCollection;
            Vec::<Box<dyn $crate::metadata::validation::traits::RawValidator>>::new()
                $(
                    .add_validator(Box::new($validator))
                )*
                .sort_by_priority()
        }
    };
}

/// Creates a collection of owned validators with automatic priority sorting.
///
/// This macro simplifies the creation of validator collections by automatically
/// boxing validators and sorting them by priority (highest first).
///
/// # Examples
///
/// ```no_run
/// use crate::owned_validators;
///
/// let validators = owned_validators![
///     TokenValidator::new(),
///     SemanticValidator::new(),
///     MethodValidator::new(),
/// ];
/// ```
#[macro_export]
macro_rules! owned_validators {
    ($($validator:expr),* $(,)?) => {
        {
            use $crate::metadata::validation::traits::ValidatorCollection;
            Vec::<Box<dyn $crate::metadata::validation::traits::OwnedValidator>>::new()
                $(
                    .add_validator(Box::new($validator))
                )*
                .sort_by_priority()
        }
    };
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        metadata::{
            cilassemblyview::CilAssemblyView,
            validation::{config::ValidationConfig, context::factory, scanner::ReferenceScanner},
        },
        testkit::fixture,
    };

    struct TestRawValidator {
        name: &'static str,
        priority: u32,
    }

    impl RawValidator for TestRawValidator {
        fn validate_raw(&self, _context: &RawValidationContext) -> Result<()> {
            Ok(())
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> u32 {
            self.priority
        }
    }

    struct TestOwnedValidator {
        name: &'static str,
        priority: u32,
    }

    impl OwnedValidator for TestOwnedValidator {
        fn validate_owned(&self, _context: &OwnedValidationContext) -> Result<()> {
            Ok(())
        }

        fn name(&self) -> &'static str {
            self.name
        }

        fn priority(&self) -> u32 {
            self.priority
        }
    }

    #[test]
    fn test_raw_validator_trait() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).unwrap();
        let config = ValidationConfig::minimal();
        let context = factory::raw_loading_context(&view, &scanner, &config);

        let validator = TestRawValidator {
            name: "TestValidator",
            priority: 150,
        };

        assert_eq!(validator.name(), "TestValidator");
        assert_eq!(validator.priority(), 150);
        assert!(validator.should_run(&context));
        assert!(validator.validate_raw(&context).is_ok());
    }

    #[test]
    fn test_validator_collection_sorting() {
        let validators = raw_validators![
            TestRawValidator {
                name: "Low",
                priority: 50
            },
            TestRawValidator {
                name: "High",
                priority: 200
            },
            TestRawValidator {
                name: "Medium",
                priority: 100
            },
        ];

        assert_eq!(validators[0].name(), "High");
        assert_eq!(validators[1].name(), "Medium");
        assert_eq!(validators[2].name(), "Low");
    }

    #[test]
    fn test_validator_macros() {
        let raw_validators = raw_validators![
            TestRawValidator {
                name: "Test1",
                priority: 100
            },
            TestRawValidator {
                name: "Test2",
                priority: 200
            },
        ];

        assert_eq!(raw_validators.len(), 2);
        assert_eq!(raw_validators[0].name(), "Test2"); // Higher priority first

        let owned_validators = owned_validators![TestOwnedValidator {
            name: "Test1",
            priority: 100
        },];

        assert_eq!(owned_validators.len(), 1);
        assert_eq!(owned_validators[0].name(), "Test1");
    }
}
