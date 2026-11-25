//! Raw structure validators for Stage 1 validation.
//!
//! This module contains specialized validators that ensure basic structural integrity and ECMA-335
//! compliance for raw metadata structures. These validators operate on [`crate::metadata::cilassemblyview::CilAssemblyView`]
//! and perform fundamental validation of tokens, tables, and heaps that forms the foundation
//! for all subsequent validation stages. These validators run with the highest priority to ensure
//! basic structural integrity before any semantic analysis.
//!
//! # Architecture
//!
//! The structure validation system provides four key areas of structural validation:
//! 1. **Token Validation** ([`token`]) - Token format, RID bounds, and coded index validation
//! 2. **Signature Validation** ([`signature`]) - Signature blob format, calling convention, and ECMA-335 compliance
//! 3. **Table Validation** ([`table`]) - Table structure, row counts, and column validation
//! 4. **Heap Validation** ([`heap`]) - Heap bounds, string validation, and data integrity
//!
//! These validators ensure that raw metadata structures conform to ECMA-335 format requirements
//! and can be safely processed by higher-level validators and the .NET runtime.
//!
//! # Key Components
//!
//! - [`RawTokenValidator`] - Validates token format, RID bounds, coded indices, and token type constraints
//! - [`RawSignatureValidator`] - Validates signature blob format, calling convention compliance, and ECMA-335 structural integrity
//! - [`RawTableValidator`] - Validates table structure, row counts, column integrity, and table relationships
//! - [`RawHeapValidator`] - Validates heap bounds, string integrity, blob format, and GUID structure
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
//! // Validate token structure (highest priority)
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
//! All structure validators implement [`Send`] + [`Sync`] and are designed for parallel execution
//! in the validation engine. Structure validation provides the foundation for concurrent validation.
//!
//! # Integration
//!
//! This module integrates with:
//! - Raw validation stage - Part of the raw validation stage with highest priority
//! - [`crate::metadata::validation::engine`] - Coordinated by the validation engine with fail-fast behavior
//! - [`crate::metadata::validation::traits`] - Implements [`crate::metadata::validation::traits::RawValidator`] trait
//! - [`crate::metadata::validation::shared`] - Uses shared validation utilities for consistency

mod heap;
mod signature;
mod sortorder;
mod table;
mod token;

pub use heap::RawHeapValidator;
pub use signature::RawSignatureValidator;
pub use sortorder::RawSortOrderValidator;
pub use table::RawTableValidator;
pub use token::RawTokenValidator;
