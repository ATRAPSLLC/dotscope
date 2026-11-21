//! Shared validation utilities for the unified validation framework.
//!
//! This module provides common validation operations that can be used by both
//! raw and owned validators. It centralizes validation logic to avoid code
//! duplication and ensure consistency across the validation framework. The shared
//! utilities implement core ECMA-335 compliance checks and provide reusable validation
//! components for token integrity, schema validation, and reference consistency.
//!
//! # Architecture
//!
//! The shared validation system provides three main categories of utilities:
//! 1. **Token Validation** ([`tokens`]) - Token format and integrity validation
//! 2. **Schema Validation** ([`schema`]) - ECMA-335 schema compliance validation
//! 3. **Reference Validation** ([`references`]) - Cross-table reference integrity validation
//!
//! These utilities are designed to be composed into higher-level validators without
//! duplicating validation logic across the raw and owned validation stages.
//!
//! # Key Components
//!
//! - [`tokens`] - Token format validation and consistency checks
//! - [`schema`] - ECMA-335 specification compliance validation
//! - [`references`] - Cross-table reference integrity validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{TokenValidator, ReferenceValidator, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::token::Token;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//!
//! // Token validation example
//! let token_validator = TokenValidator::new(&scanner);
//! let token = Token::new(0x02000001);
//! if token_validator.validate_token_bounds(token).is_ok() {
//!     println!("Token bounds are valid");
//! }
//!
//! // Reference validation example
//! let ref_validator = ReferenceValidator::new(&scanner);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All shared validation utilities are stateless and implement [`Send`] + [`Sync`],
//! making them safe for concurrent use across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - Raw validators - Used by raw validators for basic validation
//! - Owned validators - Used by owned validators for consistency checks
//! - [`crate::metadata::validation::scanner`] - Provides reference scanning infrastructure
//! - [`crate::metadata::validation::engine`] - Coordinates shared utility usage

mod references;
mod schema;
mod tokens;

pub use references::{ReferenceAnalysis, ReferenceStatistics, ReferenceValidator};
pub use schema::{SchemaValidationStatistics, SchemaValidator};
pub use tokens::{TokenValidationResult, TokenValidator};

/// Returns the canonical [`crate::Error::Parse`] error used by raw validators
/// when the assembly view does not contain the expected `#~` metadata-tables
/// stream. Centralized so all 14+ raw-validator call sites surface the same
/// structured failure.
pub fn err_no_metadata_tables() -> crate::Error {
    crate::Error::Parse(crate::ParseFailure::InvalidField {
        stage: crate::ParseStage::Validation,
        field: "metadata_tables",
        reason: "assembly view does not contain metadata tables".into(),
    })
}
