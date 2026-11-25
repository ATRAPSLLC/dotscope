//! Metadata validation system for .NET assemblies.
//!
//! This module provides a comprehensive validation framework for ensuring metadata integrity,
//! type safety, and ECMA-335 compliance across .NET assembly structures. The validation system
//! operates at multiple levels, from basic structural validation to complex semantic analysis,
//! ensuring that loaded metadata conforms to runtime requirements and specification constraints.
//!
//! # Key Components
//!
//! - `ValidationConfig` - Configuration for validation behavior
//! - `ValidationEngine` - Main validation orchestrator
//! - `ValidationContext` - Validation context abstractions
//! - `RawValidator` and `OwnedValidator` traits - Validator trait definitions
//! - validator implementations - Collection of all validator implementations
//! - `ValidationResult` and `ValidationOutcome` - Validation result types
//! - `ReferenceScanner` - Reference scanning infrastructure
//!
//! ## Architecture Overview
//!
//! The validation system is designed as a modular, configurable framework:
//!
//! ```text
//! ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │ ValidationConfig│───▶│   Orchestrator   │───▶│ Specific        │
//! │                 │    │                  │    │ Validators      │
//! └─────────────────┘    └──────────────────┘    └─────────────────┘
//!                                 │                        │
//!                                 ▼                        ▼
//!                        ┌─────────────────┐    ┌─────────────────┐
//!                        │ Error Collection│    │ Parallel        │
//!                        │ & Reporting     │    │ Processing      │
//!                        └─────────────────┘    └─────────────────┘
//! ```
//!
//! ## Validation Categories
//!
//! ### Structural Validation
//! - **Token Validation**: Format, consistency, and reference integrity
//! - **Table Structure**: Row counts, column validation, heap references
//! - **Signature Parsing**: Type signatures, method signatures, field types
//! - **PE Structure**: Headers, section alignment, file format compliance
//!
//! ### Semantic Validation
//! - **Type System Consistency**: Inheritance rules, interface implementation
//! - **Method Constraints**: Abstract/concrete rules, constructor validation
//! - **Field Layout**: Memory layout, overlap detection, alignment validation
//! - **Access Control**: Visibility rules, accessibility constraints
//!
//! ### Cross-Table Validation
//! - **Reference Consistency**: Cross-table token references
//! - **Relationship Integrity**: Parent-child relationships, ownership
//! - **Index Validation**: Coded indexes, table relationships
//! - **Constraint Satisfaction**: Generic constraints, type compatibility
//!
//! ## Validation Components
//!
//! | Component | Purpose | Validation Scope |
//! |-----------|---------|------------------|
//! | `ValidationConfig` | Configuration and control | Validation behavior and performance |
//! | `Orchestrator` | Coordination and execution | Overall validation workflow |
//! | `TokenValidator` | Token integrity | Token format and reference validation |
//! | `FieldValidator` | Field layout | Memory layout and overlap detection |
//! | `MethodValidator` | Method constraints | Constructor and abstract method rules |
//! | `LayoutValidator` | Class layout | Packing and size validation |
//! | `SemanticValidator` | Type semantics | Inheritance and interface validation |
//! | `ConstraintValidator` | Generic constraints | Generic parameter validation |
//! | `NestedClassValidator` | Nested classes | Nesting rules and circular detection |
//!
//! ## Validation Levels
//!
//! The validation system supports multiple validation levels to balance thoroughness
//! with performance:
//!
//! ### Disabled (`ValidationConfig::disabled()`)
//! - **Use case**: Maximum performance, trusted input
//! - **Validation**: None (unsafe for untrusted assemblies)
//!
//! ### Minimal (`ValidationConfig::minimal()`)
//! - **Use case**: High performance with basic safety
//! - **Validation**: Essential structural validation only
//!
//! ### Production (`ValidationConfig::production()`)
//! - **Use case**: Production environments, balanced validation
//! - **Validation**: Runtime-equivalent validation rules
//!
//! ### Comprehensive (`ValidationConfig::comprehensive()`)
//! - **Use case**: Development, debugging, thorough analysis
//! - **Validation**: All available validation rules
//!
//! ### Strict (`ValidationConfig::strict()`)
//! - **Use case**: Security analysis, format compliance checking
//! - **Validation**: Strictest possible validation (may have false positives)
//!
//! ## Error Reporting
//!
//! Validation errors are collected and reported with comprehensive context:
//!
//! - **Error Location**: Type, method, field, or table where error occurred
//! - **Error Category**: Structural, semantic, or compliance violation
//! - **Error Details**: Specific constraint violated and diagnostic information
//! - **Corrective Guidance**: Suggestions for fixing validation issues
//! - **Token Context**: Relevant metadata tokens for debugging
//!
//! ## Runtime Compliance
//!
//! The validation system implements validation rules that match .NET runtime behavior:
//!
//! - **CoreCLR Compatibility**: Validation rules derived from .NET Core runtime
//! - **ECMA-335 Compliance**: Full specification compliance checking
//! - **Error Parity**: Similar error messages to runtime validation
//! - **Performance Matching**: Validation overhead similar to runtime loading
//!
//! ## Completed Validation Features
//!
//! - **Cross-table validation**: Token consistency, semantic validation, method validation
//! - **Field layout validation**: Overlap detection, boundary checking for explicit layouts
//! - **Type system validation**: Inheritance rules, sealed/abstract constraints
//! - **Semantic validation**: Interface rules, inheritance validation, type system consistency
//! - **Method validation**: Constructor rules, abstract method validation, parameter validation
//! - **Nested class validation**: Circular reference detection and depth limits
//! - **Configuration system**: Flexible validation configuration and performance tuning
//! - **Parallel processing**: Multi-core validation for large assemblies
//!
//! ## Future Validation Enhancements
//!
//! ### Infrastructure & Core Validation
//! - [ ] **Coded Index Runtime Validation** - Enhanced coded index validation
//! - [ ] **UTF-8 String Validation** - Comprehensive string heap validation
//! - [ ] **Malformed Assembly Recovery** - Better handling of corrupted assemblies
//!
//! ### PE & File Structure Validation
//! - [ ] **Comprehensive PE Header Validation** - Thorough PE file validation
//! - [ ] **Security Validation** - Additional security constraint checking
//! - [ ] **File Format Recovery** - Improved corrupted file handling
//!
//! ### IL & Method Validation
//! - [ ] **IL Instruction Sequence Validation** - CIL instruction flow validation
//! - [ ] **Stack Depth Validation** - Operand stack validation
//! - [ ] **CIL Verification Rules** - Full CIL verification implementation
//!
//! ### Table-Specific Validation
//! - [ ] **Parameter Type Compatibility** - Enhanced parameter validation
//! - [ ] **Signature Type Validation** - Type compatibility in signatures
//! - [ ] **Range Validation** - Bounds checking for computed ranges
//! - [ ] **Semantic Attribute Validation** - Method signature compatibility
//!
//! **Total: ~18 remaining validation enhancements** across different categories,
//! ranging from critical infrastructure validation to table-specific edge case validation.
//!
//! ## Thread Safety
//!
//! All validation components are designed for thread safety:
//! - Stateless validators safe for concurrent use
//! - Parallel processing using Rayon for internal operations
//! - Thread-safe error collection and reporting
//! - No shared mutable state in validation logic
//!
//! ## References
//!
//! - ECMA-335: Common Language Infrastructure (CLI) Standard
//! - .NET Core Runtime: Validation implementation analysis
//! - ISO/IEC 23271: Common Language Infrastructure specification
//! - Microsoft .NET Documentation: Assembly loading and validation

mod config;
mod context;
mod engine;
mod result;
mod scanner;
mod shared;
mod traits;
mod validators;

pub use config::ValidationConfig;
pub use context::{
    FirstUnresolved, MethodTypeMapping, OwnedValidationContext, RawValidationContext,
    ValidationContext, ValidationStage,
};
pub use engine::{factory, EngineStatistics, ValidationEngine};
pub use result::{TwoStageValidationResult, ValidationOutcome, ValidationResult};
pub use scanner::{HeapSizes, ReferenceScanner, ScannerStatistics};
pub use shared::{
    ReferenceAnalysis, ReferenceStatistics, ReferenceValidator, SchemaValidationStatistics,
    SchemaValidator, TokenValidationResult, TokenValidator,
};
pub use traits::{OwnedValidator, RawValidator, ValidatorCollection};
pub use validators::*;
