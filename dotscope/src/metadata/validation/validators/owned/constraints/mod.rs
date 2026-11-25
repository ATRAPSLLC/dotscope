//! Owned constraint validators for generic constraints and type compatibility validation.
//!
//! This module provides validators that ensure constraint satisfaction and type compatibility
//! within fully resolved .NET metadata according to ECMA-335 specifications. These validators
//! operate on resolved type structures to validate generic constraints, inheritance requirements,
//! and interface implementation obligations.
//!
//! # Architecture
//!
//! The constraint validation system is organized into specialized validators:
//!
//! - **Type Constraints** - Generic parameter constraint satisfaction and type compatibility
//!
//! Each validator focuses on specific constraint validation aspects while maintaining
//! integration with the broader validation framework through shared interfaces and context.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::validators::owned::constraints::types::OwnedTypeConstraintValidator`] - Generic type constraint validation
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::metadata::validation::OwnedTypeConstraintValidator;
//! use dotscope::metadata::validation::OwnedValidator;
//!
//! use dotscope::metadata::validation::OwnedValidationContext;
//!
//! # fn example(context: &OwnedValidationContext<'_>) -> dotscope::Result<()> {
//! let validator = OwnedTypeConstraintValidator::new();
//!
//! if validator.should_run(context) {
//!     validator.validate_owned(context)?;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - Owned validation stage - Parent module for owned validation
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Orchestrates validator execution
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Common validation interface
//! - [`crate::metadata::cilobject::CilObject`] - Source of resolved metadata structures

mod types;

pub use types::OwnedTypeConstraintValidator;
