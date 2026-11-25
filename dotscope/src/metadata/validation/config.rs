//! Validation configuration for metadata loading and assembly validation.
//!
//! This module provides comprehensive configuration options for metadata validation during
//! .NET assembly loading. The validation system operates in multiple layers, from basic
//! structural integrity to complex semantic consistency checks, allowing fine-grained
//! control over validation depth and scope.
//!
//! # Architecture
//!
//! The validation system is organized into several categories with increasing complexity:
//!
//! - **Structural Validation**: Basic format integrity, token validity, heap references
//! - **Cross-Table Validation**: Consistency between related metadata tables
//! - **Field Layout Validation**: Memory layout validation and overlap detection
//! - **Type System Validation**: Inheritance chains, generic constraints, type compatibility
//! - **Semantic Validation**: ECMA-335 semantic rules, access modifiers, abstract/concrete rules
//! - **Method Validation**: Constructor rules, virtual method consistency, signature validation
//! - **Token Validation**: Cross-reference consistency and relationship validation
//!
//! The system operates in two stages:
//! 1. **Raw Validation**: Validates raw assembly data during [`crate::metadata::cilassemblyview::CilAssemblyView`] loading
//! 2. **Owned Validation**: Validates resolved data structures during [`crate::metadata::cilobject::CilObject`] creation
//!
//! # Field-to-Validator Map
//!
//! Each `enable_*` field on [`ValidationConfig`] gates a specific group of
//! validators. The table below summarizes what each field controls, what kind
//! of malformed input it catches, and roughly how expensive it is. Use this as
//! ground truth when picking a preset or building a custom config.
//!
//! | Field                              | Stage           | Gates                                                                                                                            | Catches                                                                                                                | Cost class                              |
//! |------------------------------------|-----------------|----------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------|-----------------------------------------|
//! | `enable_raw_validation`            | meta (stage 1)  | enables/disables the entire raw pipeline                                                                                         | n/a - gates the structural/token/constraint validators below                                                           | n/a                                     |
//! | `enable_owned_validation`          | meta (stage 2)  | enables/disables the entire owned pipeline                                                                                       | n/a - gates the cross-table/semantic/method validators below                                                           | n/a                                     |
//! | `enable_structural_validation`     | raw (1)         | `RawTokenValidator`, `RawTableValidator`, `RawHeapValidator`                                                                     | malformed token format, RID overflow, table-structure breakage, heap offsets out of bounds                             | cheap (linear scan)                     |
//! | `enable_token_validation`          | raw (1)         | `RawSignatureValidator`                                                                                                          | malformed signature blobs, invalid coded-index tag values                                                              | cheap (linear scan)                     |
//! | `enable_constraint_validation`     | raw (1) + owned (2) | `RawGenericConstraintValidator`, `RawLayoutConstraintValidator`                                                              | invalid constraint targets, circular constraints, layout overlap violations on `[StructLayout(LayoutKind.Explicit)]`   | cheap–moderate (table walk)             |
//! | `enable_cross_table_validation`    | owned (2)       | `OwnedCircularityValidator`, `OwnedDependencyValidator`, `OwnedOwnershipValidator`                                               | broken cross-references, circular type hierarchies, orphaned metadata                                                  | moderate (table walk + graph analysis)  |
//! | `enable_semantic_validation`       | owned (2)       | `OwnedFieldValidator`, `OwnedAccessibilityValidator`, `OwnedTypeDefinitionValidator`, `OwnedTypeCircularityValidator`, `OwnedTypeDependencyValidator`, `OwnedTypeOwnershipValidator`, `OwnedAttributeValidator`, `OwnedSecurityValidator`, `OwnedAssemblyValidator` | ECMA-335 semantic rules: access-modifier breaches, SpecialName violations, abstract/sealed conflicts, naming convention breaches, duplicate fields | moderate–expensive (multi-pass type-system walk) |
//! | `enable_method_validation`         | owned (2)       | `OwnedMethodValidator`, `OwnedSignatureValidator`                                                                                | concrete types declaring abstract methods, final-override attempts, signature incompatibilities, invalid constructors  | moderate (signature resolution + inheritance walk) |
//! | `enable_type_system_validation`    | owned (2)       | reserved - currently subsumed by `enable_semantic_validation`                                                                    | n/a until wired                                                                                                        | n/a                                     |
//! | `enable_field_layout_validation`   | owned (2)       | reserved - currently subsumed by `enable_owned_validation`                                                                       | n/a until wired                                                                                                        | n/a                                     |
//! | `max_nesting_depth`                | owned (2)       | nested-type depth ceiling                                                                                                        | over-deep nested-class chains (default `64`; set `0` to disable the check)                                             | cheap (counter)                         |
//! | `lenient`                          | both stages     | error handling mode                                                                                                              | n/a - when `true`, errors become diagnostics instead of aborting load                                                  | n/a                                     |
//!
//! Two of the fields above (`enable_type_system_validation`,
//! `enable_field_layout_validation`) are accepted for forward compatibility but
//! not yet observed by any validator's `should_run()` check. Setting them is
//! safe; the validators they would gate are currently controlled by
//! `enable_semantic_validation` / `enable_owned_validation`.
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::config::ValidationConfig`] - Main configuration struct with predefined presets
//! - [`crate::metadata::validation::engine::ValidationEngine`] - Executes validation using the configuration
//! - [`crate::metadata::validation::traits::RawValidator`] - Trait for raw validation implementations
//! - [`crate::metadata::validation::traits::OwnedValidator`] - Trait for owned validation implementations
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::ValidationConfig;
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! // Use production configuration for balanced validation
//! let config = ValidationConfig::production();
//! let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path_with_validation(&path, config)?;
//!
//! // Use minimal configuration for maximum performance
//! let config = ValidationConfig::minimal();
//! let view = CilAssemblyView::from_path_with_validation(&path, config)?;
//!
//! // Use comprehensive configuration for maximum safety
//! let config = ValidationConfig::comprehensive();
//! let view = CilAssemblyView::from_path_with_validation(&path, config)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are [`Send`] and [`Sync`]. [`crate::metadata::validation::config::ValidationConfig`]
//! is [`Copy`] and immutable, making it safe to share between threads. Configuration is typically
//! set once and used across multiple assembly loading operations.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::cilassemblyview`] - Provides validation during assembly view creation
//! - [`crate::metadata::cilobject`] - Provides validation during object model creation
//! - [`crate::metadata::validation::engine`] - Core validation execution engine
//!
//! # References
//!
//! - [ECMA-335 CLI Standard specification](https://www.ecma-international.org/publications/standards/Ecma-335.htm)
//! - [.NET Runtime validation behavior analysis](https://github.com/dotnet/runtime)

/// Configuration for metadata validation during assembly loading.
///
/// Controls the depth and scope of validation performed during .NET assembly loading.
/// The loading process already performs essential structural validation (token format,
/// table structure, heap references, signature format, basic type references). This
/// configuration controls additional semantic validation that requires cross-table analysis.
///
/// # Design Philosophy
///
/// The validation system provides configurable validation depth:
/// - Basic structural validation is always recommended
/// - Semantic validations can be selectively disabled
/// - Configuration presets provide common validation scenarios
/// - Fine-grained control allows optimization for specific use cases
///
/// # Validation Layers
///
/// 1. **Structural**: Token integrity, heap references
/// 2. **Cross-table**: Reference consistency between tables
/// 3. **Semantic**: ECMA-335 compliance, logical consistency
/// 4. **Type system**: Inheritance, generics, constraints
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::metadata::validation::ValidationConfig;
///
/// // Use production configuration for balanced validation
/// let config = ValidationConfig::production();
/// assert!(config.enable_structural_validation);
/// assert!(config.enable_semantic_validation);
///
/// // Create custom configuration
/// let config = ValidationConfig {
///     enable_structural_validation: true,
///     enable_semantic_validation: false,
///     ..ValidationConfig::minimal()
/// };
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This struct is [`Copy`] and all fields are simple values, making it inherently
/// thread-safe for concurrent use across multiple assembly loading operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct ValidationConfig {
    /// Enable basic structural validation during table loading (recommended: always true)
    /// Note: Most structural validation is done during loading; this adds extra safety checks
    pub enable_structural_validation: bool,

    /// Enable expensive cross-table validation after loading (can be disabled for performance)
    /// Validates semantic consistency across metadata tables
    pub enable_cross_table_validation: bool,

    /// Enable field layout validation (overlap detection, offset validation).
    ///
    /// Only useful for types with explicit layout; detects problematic overlaps.
    ///
    /// **Reserved for forward compatibility.** No validator currently checks this
    /// flag in `should_run()`. Field-layout validation is presently controlled by
    /// `enable_owned_validation`. Setting this flag is safe but has no effect
    /// until the dedicated layout validators are wired through it.
    pub enable_field_layout_validation: bool,

    /// Enable type system validation (inheritance chains, generic constraints).
    ///
    /// Validates logical consistency of type hierarchies and generic constraints.
    ///
    /// **Reserved for forward compatibility.** No validator currently checks this
    /// flag in `should_run()`. Type-system validation is presently controlled by
    /// `enable_semantic_validation`. Setting this flag is safe but has no effect
    /// until the dedicated type-system validators are wired through it.
    pub enable_type_system_validation: bool,

    /// Enable semantic validation (method consistency, access modifiers, abstract/concrete rules)
    /// Validates logical consistency of type and method semantics
    pub enable_semantic_validation: bool,

    /// Enable method validation (constructor rules, virtual method consistency)
    /// Validates method-specific semantic rules
    pub enable_method_validation: bool,

    /// Enable token validation (cross-reference consistency, token relationship validation)
    /// Validates token references and relationships beyond basic loading
    pub enable_token_validation: bool,

    /// Enable constraint validation (generic constraints, layout constraints)
    /// Validates generic parameter constraints and field/class layout constraints
    pub enable_constraint_validation: bool,

    /// Maximum nesting depth for nested classes (default: 64)
    pub max_nesting_depth: usize,

    /// Enable raw assembly validation during CilAssemblyView loading (stage 1)
    /// This enables the validation pipeline to run on raw assembly data
    pub enable_raw_validation: bool,

    /// Enable owned data validation during CilObject loading (stage 2)
    /// This enables validation of resolved, owned data structures
    pub enable_owned_validation: bool,

    /// Require every table the header marks sorted to be in its sort order
    /// (ECMA-335 §II.22, §II.24.2.6). The runtime binary-searches those
    /// tables without checking them, so a row out of place is one it silently
    /// does not find. On in every preset but [`disabled`](Self::disabled).
    pub enable_sort_order_validation: bool,

    /// Enable lenient loading mode for obfuscated/malformed assemblies.
    /// When true, parsing errors are logged to diagnostics instead of aborting.
    /// Default is false (strict mode) - errors will abort loading.
    /// Use `ValidationConfig::analysis()` for a preset that enables this.
    pub lenient: bool,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: true,
            enable_sort_order_validation: true,
            lenient: false,
        }
    }
}

impl ValidationConfig {
    /// Creates a disabled validation configuration.
    ///
    /// **Warning**: This disables ALL validation checks, including basic structural
    /// validation. Use only when you already trust the assembly format.
    ///
    /// It does not disable bounds checking: parsers are individually bounds-checked and the
    /// crate denies `panic`, `unwrap_used`, `expect_used`, `indexing_slicing` and
    /// `arithmetic_side_effects`, so a malformed assembly still yields an `Err` rather than a
    /// panic. What is lost is *semantic* rejection - a file with contradictory metadata is
    /// accepted and analysed as if it were coherent, so anything derived from it (type
    /// hierarchies, signatures, method bodies) may be wrong without any error being reported.
    ///
    /// # Returns
    ///
    /// Returns a [`ValidationConfig`] with all validation disabled.
    ///
    /// # Use Cases
    ///
    /// - Parsing known-good assemblies in performance-critical loops
    /// - Bulk processing of trusted assembly collections
    /// - Scenarios where external validation has already been performed
    ///
    /// # Risks
    ///
    /// - No protection against semantically malformed metadata
    /// - Silent acceptance of ECMA-335 violations
    /// - Analysis results derived from incoherent metadata, with no diagnostic
    ///
    /// # Field values
    ///
    /// All validation fields are `false`, including the stage gates. Every
    /// `enable_*` flag is off, `lenient = false`, `max_nesting_depth = 0`.
    /// The two pipelines never run.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::disabled();
    /// assert!(!config.enable_structural_validation);
    /// assert!(!config.enable_semantic_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enable_structural_validation: false,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            enable_constraint_validation: false,
            max_nesting_depth: 0,
            enable_raw_validation: false,
            enable_owned_validation: false,
            enable_sort_order_validation: false,
            lenient: false,
        }
    }

    /// Creates a minimal validation configuration.
    ///
    /// Enables only essential structural validation while disabling semantic
    /// checks. Provides a good balance between safety and functionality for most use cases.
    ///
    /// # Returns
    ///
    /// Returns a [`ValidationConfig`] with minimal validation enabled.
    ///
    /// # What's Validated
    ///
    /// - Basic token format and resolution
    /// - Table structure integrity
    /// - Heap reference validity
    /// - Signature format correctness
    ///
    /// # What's Skipped
    ///
    /// - Cross-table relationship validation
    /// - Type system consistency checks
    /// - Semantic rule enforcement
    /// - Method signature validation
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = false`
    /// - **Raw validators on:** `enable_structural_validation`
    /// - **Raw validators off:** `enable_token_validation`, `enable_constraint_validation`
    /// - **Owned validators off:** `enable_cross_table_validation`,
    ///   `enable_field_layout_validation`, `enable_type_system_validation`,
    ///   `enable_semantic_validation`, `enable_method_validation`
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::minimal();
    /// assert!(config.enable_structural_validation);
    /// assert!(!config.enable_semantic_validation);
    /// assert!(config.enable_raw_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            enable_constraint_validation: false,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: false,
            enable_sort_order_validation: true,
            lenient: false,
        }
    }

    /// Creates a comprehensive validation configuration for maximum safety.
    ///
    /// Enables all validation features to catch every possible metadata issue.
    /// Recommended for development, testing, and scenarios where correctness
    /// is the primary concern.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with all validation enabled.
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = true`
    /// - **All `enable_*` validators on**
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// Identical in field values to [`production`](Self::production) and
    /// [`strict`](Self::strict); the three exist as named entry points so
    /// downstream code can document intent. Pick whichever name best matches
    /// the calling context.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::comprehensive();
    /// assert!(config.enable_structural_validation);
    /// assert!(config.enable_semantic_validation);
    /// assert!(config.enable_type_system_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn comprehensive() -> Self {
        Self::default()
    }

    /// Creates a validation configuration suitable for production use.
    ///
    /// This configuration mirrors the validation performed by the .NET runtime,
    /// focusing on checks that would cause actual runtime failures. Based on
    /// analysis of [`CoreCLR`](https://github.com/dotnet/runtime) and runtime source code.
    /// Updated to reflect complete validation framework implementation.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] matching runtime validation.
    ///
    /// # Validation Profile (.NET Runtime Equivalence)
    ///
    /// - Structural: Essential for basic safety and metadata integrity
    /// - Cross-table: Runtime validates cross-references during loading
    /// - Field layout: Runtime validates explicit layout constraints
    /// - Type system: Runtime validates inheritance and generic constraints
    /// - Semantic: Runtime enforces ECMA-335 semantic rules
    /// - Method: Runtime enforces method signature and override constraints
    /// - Token: Runtime validates token references for security
    /// - Constraint: Runtime validates generic and layout constraints
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = true`
    /// - **All `enable_*` validators on**
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// Identical in field values to [`comprehensive`](Self::comprehensive) and
    /// [`strict`](Self::strict). Use `production` when you specifically want
    /// to communicate that you are matching .NET runtime validation behavior.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::production();
    /// assert!(config.enable_structural_validation);
    /// assert!(config.enable_semantic_validation);
    /// assert!(config.enable_field_layout_validation);
    /// assert!(config.enable_constraint_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn production() -> Self {
        Self {
            enable_structural_validation: true, // Runtime validates metadata structure and format
            enable_cross_table_validation: true, // Runtime validates cross-references during loading
            enable_field_layout_validation: true, // Runtime validates explicit layout constraints
            enable_type_system_validation: true, // Runtime validates inheritance and generic constraints
            enable_semantic_validation: true,    // Runtime enforces ECMA-335 semantic rules
            enable_method_validation: true, // Runtime enforces method signature and override constraints
            enable_token_validation: true,  // Runtime validates token references for security
            enable_constraint_validation: true, // Runtime validates generic and layout constraints
            max_nesting_depth: 64,          // Standard runtime nesting limit
            enable_raw_validation: true,    // Enable raw validation for safety and format integrity
            enable_owned_validation: true,  // Enable owned validation for semantic completeness
            enable_sort_order_validation: true,
            lenient: false, // Strict mode by default
        }
    }

    /// Creates a validation configuration with all checks enabled.
    ///
    /// Similar to [`comprehensive()`](Self::comprehensive) but with explicit emphasis
    /// on strictness. All validation categories are enabled with maximum sensitivity.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] with strict validation enabled.
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = true`
    /// - **All `enable_*` validators on**
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// Identical in field values to [`comprehensive`](Self::comprehensive) and
    /// [`production`](Self::production). The strict alias exists to call out
    /// that field-layout validation can flag legitimate overlapping fields
    /// (see note below) - pick this name when that risk is acceptable.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::strict();
    /// assert!(config.enable_field_layout_validation);
    /// assert!(config.enable_constraint_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// **Note**: Field layout validation may produce false positives on legitimate
    /// overlapping fields (unions, explicit layout structs). Review results carefully
    /// when working with low-level interop types.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: true,
            enable_sort_order_validation: true,
            lenient: false,
        }
    }

    /// Returns true if raw validation should be performed during [`crate::metadata::cilassemblyview::CilAssemblyView`] loading.
    ///
    /// # Returns
    ///
    /// Returns `true` if raw validation stage should be executed, `false` otherwise.
    #[must_use]
    pub fn should_validate_raw(&self) -> bool {
        self.enable_raw_validation
    }

    /// Returns true if owned validation should be performed during [`crate::metadata::cilobject::CilObject`] loading.
    ///
    /// # Returns
    ///
    /// Returns `true` if owned validation stage should be executed, `false` otherwise.
    #[must_use]
    pub fn should_validate_owned(&self) -> bool {
        self.enable_owned_validation
    }

    /// Creates a configuration for raw validation only (stage 1).
    ///
    /// This configuration is suitable for scenarios where you only need basic
    /// structural validation of the raw assembly data without full semantic validation.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] configured for raw validation only.
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = false`
    /// - **Raw validators on:** `enable_structural_validation`
    /// - **Raw validators off:** `enable_token_validation`, `enable_constraint_validation`
    /// - **Owned validators all off**
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::raw_only();
    /// assert!(config.should_validate_raw());
    /// assert!(!config.should_validate_owned());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn raw_only() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: false,
            enable_field_layout_validation: false,
            enable_type_system_validation: false,
            enable_semantic_validation: false,
            enable_method_validation: false,
            enable_token_validation: false,
            enable_constraint_validation: false,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: false,
            enable_sort_order_validation: true,
            lenient: false,
        }
    }

    /// Creates a configuration for owned validation only (stage 2).
    ///
    /// This configuration assumes that raw validation has already been performed
    /// and focuses on validating the resolved, owned data structures.
    ///
    /// # Returns
    ///
    /// Returns a [`crate::metadata::validation::config::ValidationConfig`] configured for owned validation only.
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = false`, `enable_owned_validation = true`
    /// - **Raw validators all off** (`enable_structural_validation`,
    ///   `enable_token_validation` are skipped along with the stage)
    /// - **Owned validators on:** `enable_cross_table_validation`,
    ///   `enable_field_layout_validation`, `enable_type_system_validation`,
    ///   `enable_semantic_validation`, `enable_method_validation`,
    ///   `enable_constraint_validation`
    /// - **Other:** `lenient = false`, `max_nesting_depth = 64`
    ///
    /// Caller is responsible for guaranteeing the raw stage already passed
    /// (or is being deliberately skipped). Loading malformed metadata with
    /// the raw stage off may surface garbage as validation errors at
    /// stage 2 instead of clean parse failures.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::validation::ValidationConfig;
    ///
    /// let config = ValidationConfig::owned_only();
    /// assert!(!config.should_validate_raw());
    /// assert!(config.should_validate_owned());
    /// assert!(config.enable_semantic_validation);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn owned_only() -> Self {
        Self {
            enable_structural_validation: false,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: false,
            enable_owned_validation: true,
            enable_sort_order_validation: true,
            lenient: false,
        }
    }

    /// Creates an analysis configuration for examining obfuscated/malformed assemblies.
    ///
    /// This configuration enables ALL validation checks in lenient mode, which continues
    /// loading and validation even when errors are encountered. All errors are logged to
    /// diagnostics instead of aborting, providing a comprehensive picture of what's wrong
    /// with the assembly. This is ideal for analyzing obfuscated assemblies, malware samples,
    /// or assemblies with intentionally corrupted metadata.
    ///
    /// # Returns
    ///
    /// Returns a [`ValidationConfig`] configured for comprehensive analysis with lenient loading.
    ///
    /// # What's Different
    ///
    /// - **Lenient mode**: All errors (loading and validation) are logged as warnings, not fatal
    /// - **Comprehensive validation**: ALL validation checks enabled to collect maximum diagnostic info
    /// - **Complete error collection**: Continues through all checks to build full diagnostic report
    ///
    /// # Field values
    ///
    /// - **Stage gates:** `enable_raw_validation = true`, `enable_owned_validation = true`
    /// - **All `enable_*` validators on** (same as [`comprehensive`](Self::comprehensive))
    /// - **Other:** `lenient = true` (the load-bearing differentiator),
    ///   `max_nesting_depth = 64`
    ///
    /// The single distinguishing field versus `comprehensive`/`production`/`strict`
    /// is `lenient = true`: errors from the loader and the validation engine
    /// flow into [`crate::metadata::diagnostics::Diagnostics`] instead of
    /// short-circuiting the load.
    ///
    /// # Use Cases
    ///
    /// - Analyzing obfuscated assemblies (ConfuserEx, etc.)
    /// - Examining malware samples with corrupted metadata
    /// - Recovering data from damaged assemblies
    /// - Security research and reverse engineering
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilObject, ValidationConfig};
    ///
    /// // Load an obfuscated assembly that may have invalid metadata
    /// let config = ValidationConfig::analysis();
    /// let assembly = CilObject::from_path_with_validation(
    ///     "obfuscated.exe",
    ///     config
    /// )?;
    ///
    /// // Check what issues were encountered
    /// if assembly.diagnostics().has_any() {
    ///     println!("Loading issues:");
    ///     for diag in assembly.diagnostics().iter() {
    ///         println!("  {}", diag);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn analysis() -> Self {
        Self {
            enable_structural_validation: true,
            enable_cross_table_validation: true,
            enable_field_layout_validation: true,
            enable_type_system_validation: true,
            enable_semantic_validation: true,
            enable_method_validation: true,
            enable_token_validation: true,
            enable_constraint_validation: true,
            max_nesting_depth: 64,
            enable_raw_validation: true,
            enable_owned_validation: true,
            enable_sort_order_validation: true,
            lenient: true, // Key difference: continue on errors, collect all diagnostics
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_config_presets() {
        let disabled = ValidationConfig::disabled();
        assert!(!disabled.enable_structural_validation);
        assert!(!disabled.enable_cross_table_validation);
        assert!(!disabled.enable_field_layout_validation);
        assert!(!disabled.enable_type_system_validation);
        assert!(!disabled.enable_semantic_validation);
        assert!(!disabled.enable_method_validation);
        assert!(!disabled.enable_token_validation);
        assert_eq!(disabled.max_nesting_depth, 0);
        assert!(!disabled.enable_raw_validation);
        assert!(!disabled.enable_owned_validation);

        let minimal = ValidationConfig::minimal();
        assert!(minimal.enable_structural_validation);
        assert!(!minimal.enable_cross_table_validation);
        assert!(!minimal.enable_semantic_validation);
        assert!(!minimal.enable_method_validation);
        assert!(!minimal.enable_token_validation);
        assert!(minimal.enable_raw_validation);
        assert!(!minimal.enable_owned_validation);

        let comprehensive = ValidationConfig::comprehensive();
        assert!(comprehensive.enable_structural_validation);
        assert!(comprehensive.enable_cross_table_validation);
        assert!(comprehensive.enable_field_layout_validation);
        assert!(comprehensive.enable_type_system_validation);
        assert!(comprehensive.enable_semantic_validation);
        assert!(comprehensive.enable_method_validation);
        assert!(comprehensive.enable_token_validation);
        assert!(comprehensive.enable_raw_validation);
        assert!(comprehensive.enable_owned_validation);

        let production = ValidationConfig::production();
        assert!(production.enable_structural_validation);
        assert!(production.enable_cross_table_validation);
        assert!(production.enable_field_layout_validation);
        assert!(production.enable_type_system_validation);
        assert!(production.enable_semantic_validation);
        assert!(production.enable_method_validation);
        assert!(production.enable_token_validation);
        assert!(production.enable_constraint_validation);
        assert!(production.enable_raw_validation);
        assert!(production.enable_owned_validation);
    }

    #[test]
    fn test_default_config() {
        let default = ValidationConfig::default();
        let comprehensive = ValidationConfig::comprehensive();
        assert_eq!(default, comprehensive);
    }

    #[test]
    fn test_validation_stage_methods() {
        let production = ValidationConfig::production();
        assert!(production.should_validate_raw());
        assert!(production.should_validate_owned());

        let disabled = ValidationConfig::disabled();
        assert!(!disabled.should_validate_raw());
        assert!(!disabled.should_validate_owned());

        let raw_only = ValidationConfig::raw_only();
        assert!(raw_only.should_validate_raw());
        assert!(!raw_only.should_validate_owned());
        assert!(raw_only.enable_structural_validation);
        assert!(!raw_only.enable_cross_table_validation);

        let owned_only = ValidationConfig::owned_only();
        assert!(!owned_only.should_validate_raw());
        assert!(owned_only.should_validate_owned());
        assert!(!owned_only.enable_structural_validation);
        assert!(owned_only.enable_cross_table_validation);
    }
}
