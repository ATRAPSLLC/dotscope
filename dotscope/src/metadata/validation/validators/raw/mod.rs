//! Raw validation stage (Stage 1) validators for the fine-grained validation framework.
//!
//! This module contains fine-grained validators that operate on raw metadata through [`crate::metadata::cilassemblyview::CilAssemblyView`].
//! Raw validators perform specific validation tasks and can handle both assembly loading
//! validation and assembly modification validation through [`crate::cilassembly::AssemblyChanges`]. These validators
//! ensure basic structural integrity and ECMA-335 compliance before proceeding to semantic validation.
//!
//! # Architecture
//!
//! The raw validation system operates on unresolved metadata structures in three functional categories:
//! 1. **Structure Validators** ([`crate::metadata::validation::validators::raw::structure`]) - Basic metadata format and integrity
//! 2. **Constraint Validators** ([`crate::metadata::validation::validators::raw::constraints`]) - Layout and generic constraints
//! 3. **Modification Validators** ([`crate::metadata::validation::validators::raw::modification`]) - Assembly change validation
//!
//! Each validator implements [`crate::metadata::validation::traits::RawValidator`] and operates through
//! [`crate::metadata::validation::context::RawValidationContext`] for coordinated validation with fail-fast behavior.
//!
//! # Key Components
//!
//! ## Structure Validators
//! - [`RawTokenValidator`] - Token format, RID bounds, coded index validation
//! - [`RawTableValidator`] - Table structure, row counts, column validation
//! - [`RawHeapValidator`] - Heap bounds, string validation, data integrity
//!
//! ## Constraint Validators
//! - [`RawGenericConstraintValidator`] - Generic parameter constraints and bounds
//! - [`RawLayoutConstraintValidator`] - Field and class layout constraints
//!
//! ## Modification Validators
//! - [`RawOperationValidator`] - Change operation validation (insert, update, delete)
//! - [`RawChangeIntegrityValidator`] - Post-change integrity and consistency validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{
//!     RawTokenValidator, RawTableValidator, RawValidationContext, RawValidator
//! };
//!
//! # fn get_context() -> RawValidationContext<'static> { unimplemented!() }
//! let context = get_context();
//!
//! // Validate token format and bounds
//! let token_validator = RawTokenValidator::new();
//! token_validator.validate_raw(&context)?;
//!
//! // Validate table structure
//! let table_validator = RawTableValidator::new();
//! table_validator.validate_raw(&context)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All raw validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. The validation context provides thread-safe access to raw metadata.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::engine`] - Coordinates raw validator execution with fail-fast behavior
//! - [`crate::metadata::validation::context`] - Provides raw validation contexts for both loading and modification scenarios
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::RawValidator`] trait
//! - [`crate::metadata::cilassemblyview`] - Validates raw assembly metadata structures

mod constraints;
mod modification;
mod structure;

pub use constraints::{RawGenericConstraintValidator, RawLayoutConstraintValidator};
pub use modification::{RawChangeIntegrityValidator, RawOperationValidator};
pub use structure::{
    RawHeapValidator, RawSignatureValidator, RawSortOrderValidator, RawTableValidator,
    RawTokenValidator,
};
