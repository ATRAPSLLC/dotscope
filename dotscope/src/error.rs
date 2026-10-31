//! Error types and handling for the dotscope library.
//!
//! This module defines the comprehensive error handling system for the dotscope library,
//! providing detailed error types for .NET assembly parsing, metadata analysis, and
//! disassembly operations. The error types are designed to provide meaningful context
//! for different failure modes to enable appropriate error handling and debugging.
//!
//! # Architecture
//!
//! The error system is built around a single comprehensive [`crate::Error`] enum that
//! covers all possible error conditions. This approach provides a unified error handling
//! experience while maintaining detailed error categorization. The system includes:
//!
//! - Structured error variants for different failure modes
//! - Source location tracking for malformed file errors
//! - Integration with external library errors through automatic conversion
//! - Thread-safe error propagation for concurrent operations
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::Error`] - Main error enum covering all possible error conditions
//! - [`crate::Result`] - Convenience type alias for `Result<T, Error>`
//!
//! ## Error Categories
//! - **File Parsing Errors**: Invalid offsets, malformed data, out-of-bounds access
//! - **I/O Errors**: Filesystem operations, permission issues
//! - **Type System Errors**: Type registration, resolution, and conversion failures
//! - **Analysis Errors**: Recursion limits, synchronization failures, dependency graph issues
//!
//! # Usage Examples
//!
//! ## Basic Error Handling
//!
//! ```rust
//! use dotscope::{Error, Result};
//!
//! fn parse_data() -> Result<String> {
//!     // Function that might fail
//!     Err(Error::NotSupported)
//! }
//!
//! match parse_data() {
//!     Ok(data) => println!("Success: {}", data),
//!     Err(Error::NotSupported) => println!("Feature not supported"),
//!     Err(e) => println!("Other error: {}", e),
//! }
//! ```
//!
//! ## Advanced Error Handling
//!
//! ```rust,no_run
//! use dotscope::{Error, metadata::cilobject::CilObject};
//! use std::path::Path;
//!
//! match CilObject::from_path(Path::new("assembly.dll")) {
//!     Ok(assembly) => {
//!         println!("Successfully loaded assembly");
//!     }
//!     Err(Error::NotSupported) => {
//!         eprintln!("File format is not supported");
//!     }
//!     Err(Error::Parse(parse_err)) => {
//!         eprintln!("Malformed file: {}", parse_err);
//!     }
//!     Err(Error::Io(io_err)) => {
//!         eprintln!("I/O error: {}", io_err);
//!     }
//!     Err(e) => {
//!         eprintln!("Other error: {}", e);
//!     }
//! }
//! ```
//!
//! ## Using the Malformed Error Macro
//!
//! ```rust,no_run
//! use dotscope::malformed_error;
//!
//! fn validate_header(size: usize) -> dotscope::Result<()> {
//!     if size < 4 {
//!         return Err(malformed_error!("Header too small: {} bytes", size));
//!     }
//!     Ok(())
//! }
//! ```
//!
//! # Thread Safety
//!
//! All error types in this module are thread-safe. The [`crate::Error`] enum implements
//! [`std::marker::Send`] and [`std::marker::Sync`], allowing errors to be safely passed
//! between threads and shared across thread boundaries. This enables proper error
//! propagation in concurrent parsing and analysis operations.
//!

use std::{io, sync::Arc};

use thiserror::Error;

#[cfg(feature = "emulation")]
use crate::emulation::EmulationError;
use crate::metadata::{tables::TableId, token::Token};

// Stub type for EmulationError when emulation feature is disabled.
// This allows the Error enum to remain stable across feature configurations.
// The type is public to match the visibility of the Error::Emulation variant.
#[cfg(not(feature = "emulation"))]
#[derive(Debug, Clone, PartialEq)]
pub struct EmulationError(String);

#[cfg(not(feature = "emulation"))]
impl std::fmt::Display for EmulationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Emulation not available: {}", self.0)
    }
}

/// Helper macro for creating malformed data errors with source location information.
///
/// This macro simplifies the creation of malformed-data errors by automatically capturing the
/// current file and line number. It supports both simple string messages and format string
/// patterns with arguments.
///
/// # Arguments
///
/// * `$msg` - A string or expression that can be converted to a string
/// * `$fmt, $($arg)*` - A format string and its arguments (like `format!` macro)
///
/// # Returns
///
/// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] at
/// [`crate::ParseStage::Generic`], with the provided message and automatically captured
/// source location information.
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::malformed_error;
/// // Simple string message
/// let error = malformed_error!("Invalid data format");
///
/// // Format string with arguments
/// let expected = 4;
/// let actual = 2;
/// let error = malformed_error!("Expected {} bytes, got {}", expected, actual);
/// ```
#[macro_export]
macro_rules! malformed_error {
    // A format string literal: its inline arguments (`{name}`) are formatted
    ($msg:literal) => {
        $crate::Error::Parse($crate::ParseFailure::Other {
            stage: $crate::ParseStage::Generic,
            message: format!("{} ({}:{})", format!($msg), file!(), line!()),
        })
    };

    // A message built elsewhere
    ($msg:expr) => {
        $crate::Error::Parse($crate::ParseFailure::Other {
            stage: $crate::ParseStage::Generic,
            message: format!("{} ({}:{})", $msg, file!(), line!()),
        })
    };

    // Format string with arguments version
    ($fmt:expr, $($arg:tt)*) => {
        $crate::Error::Parse($crate::ParseFailure::Other {
            stage: $crate::ParseStage::Generic,
            message: format!("{} ({}:{})", format!($fmt, $($arg)*), file!(), line!()),
        })
    };
}

/// Helper macro for creating [`crate::ParseFailure::OutOfBounds`] errors.
///
/// Convenience constructor for the structured out-of-bounds parse failure.
/// The expanded form is `Error::Parse(ParseFailure::OutOfBounds { stage:
/// ParseStage::Generic })` — call sites that can supply a more specific stage
/// should construct the variant directly instead of using this macro.
///
/// Source-location capture (`file!()`/`line!()`) was previously embedded in
/// the rendered message; it's no longer included because the structured
/// variant is intended to be matched on, not stringified for debugging. If
/// you need source-location info, use a structured `Error::Parse(...)`
/// expression and panic/`tracing::error!` with `Location::caller()` at the
/// call site.
///
/// # Examples
///
/// ```no_run
/// # use dotscope::out_of_bounds_error;
/// if index >= data.len() {
///     return Err(out_of_bounds_error!());
/// }
/// ```
#[macro_export]
macro_rules! out_of_bounds_error {
    () => {
        $crate::Error::Parse($crate::ParseFailure::OutOfBounds {
            stage: $crate::ParseStage::Generic,
        })
    };
}

/// The generic Error type, which provides coverage for all errors this library can potentially
/// return.
///
/// This enum covers all possible error conditions that can occur during .NET assembly parsing,
/// metadata analysis, and disassembly operations. Each variant provides specific context about
/// the failure mode to enable appropriate error handling.
///
/// # Error Categories
///
/// ## File Parsing Errors
/// - [`crate::Error::Parse`] - Corrupted structure, truncation, or a read past the end of the
///   input; the [`crate::ParseFailure`] it carries says which, and its [`crate::ParseStage`]
///   says where
/// - [`crate::Error::NotSupported`] - Unsupported file format or feature
///
/// ## I/O and External Errors
/// - [`crate::Error::Io`] - Filesystem I/O errors
/// - [`crate::Error::Goblin`] - PE/ELF parsing errors from goblin crate
///
/// ## Type System Errors
/// - [`crate::Error::TypeNotFound`] - Requested type not found in type system
/// - [`crate::Error::TypeError`] - General type system operation error
/// - [`crate::Error::TypeMissingParent`] - Type inheritance chain broken
/// - [`crate::Error::TypeNotPrimitive`] - Expected primitive type
/// - [`crate::Error::TypeConversionInvalid`] - Invalid type conversion requested
///
/// ## Analysis Errors
/// - [`crate::Error::RecursionLimit`] - Maximum recursion depth exceeded
/// - [`crate::Error::DepthLimitExceeded`] - Maximum nesting depth exceeded in iterative parsing
/// - [`crate::Error::GraphError`] - Dependency graph analysis error
/// - [`crate::Error::SsaError`] - SSA construction error
///
/// # Thread Safety
///
/// This error enum is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain thread-safe types.
/// This includes owned strings, primitive values, and errors from external crates that are themselves
/// thread-safe. Errors can be safely passed between threads and shared across thread boundaries.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    // File parsing Errors
    /// This file type is not supported.
    ///
    /// Indicates that the input file is not a supported .NET PE executable,
    /// or uses features that are not yet implemented in this library.
    #[error("This file type is not supported")]
    NotSupported,

    /// File I/O error.
    ///
    /// Wraps standard I/O errors that can occur during file operations
    /// such as reading from disk, permission issues, or filesystem errors.
    ///
    /// Held behind an `Arc` because [`io::Error`] is not [`Clone`], and this enum is. Without
    /// it `Clone` cannot be derived, and a hand-written one has to decide what to do with
    /// this variant — the answer being to flatten it into a string, which loses the
    /// [`io::ErrorKind`] a caller matches on.
    #[error("{0}")]
    Io(Arc<io::Error>),

    /// Other errors that don't fit specific categories.
    ///
    /// NOTE: Prefer specific error types. Use this only for:
    /// - Wrapping external library errors with context
    /// - Temporary errors during development
    /// - Truly miscellaneous errors
    #[error("{0}")]
    Other(String),

    /// Error from the goblin crate during PE/ELF parsing.
    ///
    /// The goblin crate is used for low-level PE format parsing.
    /// This error wraps any failures from that parsing layer.
    ///
    /// `Arc`-wrapped for the same reason as [`Io`](Self::Io).
    #[error("{0}")]
    Goblin(Arc<goblin::error::Error>),

    /// Failed to find type in `TypeSystem`.
    ///
    /// This error occurs when looking up a type by token that doesn't
    /// exist in the loaded metadata or type system registry.
    ///
    /// The associated [`Token`] identifies which type was not found.
    #[error("Failed to find type in TypeSystem - {0}")]
    TypeNotFound(Token),

    /// Method or method-spec lookup failure.
    ///
    /// Returned by [`crate::CilObject::method`] and
    /// [`crate::CilObject::method_spec`] when the supplied token does not
    /// resolve to a row in the corresponding metadata table. See
    /// [`MethodLookupError`] for the variant set.
    #[error(transparent)]
    LookupMethod(#[from] MethodLookupError),

    /// Structured parse-pipeline failure.
    ///
    /// Wraps a [`ParseFailure`] so consumers can categorize parse failures
    /// (truncated headers, bad magic, unsupported schemas, heap corruption,
    /// invalid fields) without parsing string messages. Returned by every
    /// parse-pipeline error site in the file, metadata-root and stream parsers.
    ///
    /// Match on `Error::Parse(_)` to recover the structured failure, or on a
    /// specific variant of [`ParseFailure`] to react to a particular failure
    /// class (e.g. `ParseFailure::Truncated { .. }`).
    #[error(transparent)]
    Parse(#[from] ParseFailure),

    /// General error during `TypeSystem` usage.
    ///
    /// Covers various type system operations that can fail, such as
    /// type resolution, inheritance chain analysis, or generic instantiation.
    #[error("{0}")]
    TypeError(String),

    /// The parent of the current type is missing.
    ///
    /// This error occurs when analyzing type inheritance and the parent
    /// type referenced by a type definition cannot be found or resolved.
    #[error("The parent of the current type is missing")]
    TypeMissingParent,

    /// This type can not be converted to a primitive.
    ///
    /// Occurs when attempting to convert a complex type to a primitive
    /// type representation, but the type is not compatible with primitive
    /// type semantics.
    #[error("This type can not be converted to a primitive")]
    TypeNotPrimitive,

    /// The requested type conversion is not possible.
    ///
    /// This error occurs when attempting type conversions that are
    /// semantically invalid in the .NET type system.
    #[error("The requested type conversion is not possible")]
    TypeConversionInvalid,

    /// Recursion limit reached.
    ///
    /// To prevent stack overflow during recursive operations like type
    /// resolution or dependency analysis, a maximum recursion depth is
    /// enforced. This error indicates that limit was exceeded.
    ///
    /// The associated value shows the recursion limit that was reached.
    #[error("Reach the maximum recursion level allowed - {0}")]
    RecursionLimit(usize),

    /// Marshalling descriptor encoding error.
    ///
    /// This error occurs when encoding marshalling information fails due
    /// to invalid or inconsistent marshalling descriptor data, such as
    /// sequential parameter constraints being violated.
    ///
    /// The associated string contains details about what failed during encoding.
    #[error("Marshalling error: {0}")]
    MarshallingError(String),

    ///
    /// To prevent resource exhaustion and stack overflow during iterative parsing
    /// operations, a maximum nesting depth is enforced. This error indicates that
    /// the depth limit was exceeded while parsing complex nested structures.
    ///
    /// This applies to iterative stack-based parsing in:
    /// - Signature type parsing (nested generic types, arrays, pointers)
    /// - Custom attribute parsing (nested arrays, tagged objects)
    /// - Any other iterative parser with explicit depth limiting
    ///
    /// The associated value shows the nesting depth limit that was reached.
    #[error("Reached the maximum nesting depth allowed - {0}")]
    DepthLimitExceeded(usize),

    /// `LoaderGraph` error.
    ///
    /// Errors related to dependency graph analysis and metadata loading
    /// order resolution. This can occur when circular dependencies are
    /// detected or when the dependency graph cannot be properly constructed.
    #[error("{0}")]
    GraphError(String),

    /// SSA construction error.
    ///
    /// Errors related to Static Single Assignment form construction,
    /// including stack simulation failures and phi node placement issues.
    #[error("SSA error: {0}")]
    SsaError(String),

    /// Code generation error.
    ///
    /// Errors that occur during SSA-to-CIL code generation, such as
    /// missing type information for local variables or invalid instruction encoding.
    #[error("Codegen error: {0}")]
    CodegenFailed(String),

    /// An exception region the generated layout does not keep in one piece.
    ///
    /// A clause names one contiguous span of bytes for each of its regions, so
    /// a layout that places code outside a region between the region's blocks
    /// cannot be described. Code generation refuses the method rather than
    /// dropping the clause, which would leave the code it guards unprotected.
    #[error("Codegen error: exception region of blocks {start}..{end} is not contiguous in the layout: {intruder} falls inside it")]
    EhRegionNotContiguous {
        /// The region's first block.
        start: usize,
        /// The block after its last.
        end: usize,
        /// The layout entry that falls inside the region.
        intruder: String,
    },

    /// Cannot modify replaced table.
    ///
    /// This error occurs when attempting to apply sparse modifications
    /// to a table that has been completely replaced.
    #[error("Cannot modify replaced table")]
    CannotModifyReplacedTable,

    /// Invalid modification operation.
    ///
    /// This error occurs when attempting an operation that is not
    /// valid for the current state or context.
    #[error("Invalid modification: {0}")]
    ModificationInvalid(String),

    /// Invalid RID for table during validation.
    ///
    /// This error occurs when a RID is invalid for the target table,
    /// such as zero-valued RIDs or RIDs exceeding table bounds.
    #[error("Invalid RID {rid} for table {table:?}")]
    InvalidRid {
        /// The table with the invalid RID
        table: TableId,
        /// The invalid RID
        rid: u32,
    },

    /// Cross-reference validation failed.
    ///
    /// This error occurs when validation detects broken cross-references
    /// between metadata tables.
    #[error("Cross-reference error: {0}")]
    CrossReferenceError(String),

    /// Conflict resolution failed.
    ///
    /// This error occurs when the conflict resolution system cannot
    /// automatically resolve detected conflicts.
    #[error("Conflict resolution failed: {0}")]
    ConflictResolution(String),

    /// Stage 1 (raw) validation failed, preventing Stage 2 execution.
    ///
    /// This error occurs when the first stage of validation (raw metadata validation)
    /// fails, causing the unified validation engine to terminate early without
    /// proceeding to Stage 2 (owned validation).
    #[error("Validation Stage 1 failed: {message}")]
    ValidationStage1Failed {
        /// The underlying error that caused Stage 1 to fail
        #[source]
        source: Box<Error>,
        /// Details about the Stage 1 failure
        message: String,
    },

    /// Stage 2 (owned) validation failed with multiple errors.
    ///
    /// This error occurs when Stage 2 validation (owned metadata validation)
    /// encounters multiple validation failures during parallel execution.
    #[error("Validation Stage 2 failed with {error_count} errors: {summary}")]
    ValidationStage2Failed {
        /// All validation errors collected during Stage 2
        errors: Vec<Error>,
        /// Number of errors for quick reference
        error_count: usize,
        /// Summary of the validation failures
        summary: String,
    },

    /// Raw validation failed for a specific validator.
    ///
    /// This error occurs when a specific raw validator (Stage 1) fails during
    /// the validation process on CilAssemblyView data.
    #[error("Raw validation failed in {validator}: {message}")]
    ValidationRawFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
    },

    /// Owned validation failed for a specific validator.
    ///
    /// This error occurs when a specific owned validator (Stage 2) fails during
    /// the validation process on CilObject data.
    #[error("Owned validation failed in {validator}: {message}")]
    ValidationOwnedFailed {
        /// Name of the validator that failed
        validator: String,
        /// Details about the validation failure
        message: String,
    },

    /// Validation engine initialization failed.
    ///
    /// This error occurs when the unified validation engine cannot be properly
    /// initialized due to invalid configuration or missing dependencies.
    #[error("Validation engine initialization failed: {message}")]
    ValidationEngineInitFailed {
        /// Details about the initialization failure
        message: String,
    },

    /// Invalid token or token reference.
    ///
    /// This error occurs when token format or cross-reference validation fails
    /// during either raw or owned validation stages.
    #[error("Invalid token {token}: {message}")]
    InvalidToken {
        /// The token that failed validation
        token: Token,
        /// Details about the token validation failure
        message: String,
    },

    /// Layout planning failed during binary generation.
    ///
    /// This error occurs when the write planner cannot determine a valid
    /// layout for the output file, such as when the file would exceed
    /// configured size limits.
    #[error("Layout failed: {0}")]
    LayoutFailed(String),

    /// A row the write deletes is still named by something the write keeps.
    ///
    /// The writer never retargets such a reference to a neighbouring row. Under
    /// [`DanglingPolicy::Null`](crate::cilassembly::DanglingPolicy::Null) it writes a null
    /// reference instead of failing.
    #[error("{referrer} names {target}, which the write deletes")]
    DanglingReference {
        /// What names the deleted row; its tokens are the ones the input assembly has.
        referrer: Referrer,
        /// The deleted row, as the input assembly numbers it.
        target: Token,
    },

    /// Memory mapping failed during binary reading or writing.
    ///
    /// This error occurs when memory-mapped file operations fail,
    /// either for creating new mappings or accessing existing ones.
    #[error("Memory mapping failed: {0}")]
    MmapFailed(String),

    /// File finalization failed during binary writing.
    ///
    /// This error occurs when the final step of writing (such as flushing,
    /// syncing, or closing the output file) fails.
    #[error("Finalization failed: {0}")]
    FinalizationFailed(String),

    /// Invalid instruction mnemonic.
    ///
    /// This error occurs when attempting to encode an instruction with
    /// a mnemonic that is not recognized in the CIL instruction set.
    #[error("Invalid instruction mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Wrong operand type for instruction.
    ///
    /// This error occurs when the provided operand type doesn't match
    /// the expected operand type for the instruction being encoded.
    #[error("Wrong operand type for instruction - expected {expected}")]
    WrongOperandType {
        /// The expected operand type
        expected: String,
    },

    /// Unexpected operand provided.
    ///
    /// This error occurs when an operand is provided for an instruction
    /// that doesn't expect any operand.
    #[error("Unexpected operand provided for instruction that expects none")]
    UnexpectedOperand,

    /// Invalid branch instruction or operand.
    ///
    /// This error occurs when:
    /// - Attempting to use the branch instruction encoding method with a non-branch instruction
    /// - A branch instruction has an operand type not valid for branch offset encoding
    /// - An invalid offset size is specified for branch instruction encoding
    #[error("Invalid branch: {0}")]
    InvalidBranch(String),

    /// Undefined label referenced.
    ///
    /// This error occurs when attempting to finalize encoding with
    /// unresolved label references.
    #[error("Undefined label referenced: {0}")]
    UndefinedLabel(String),

    /// Duplicate label definition.
    ///
    /// This error occurs when attempting to define a label that has
    /// already been defined in the current encoding context.
    #[error("Duplicate label definition: {0}")]
    DuplicateLabel(String),

    /// Lock or synchronization error.
    ///
    /// This error occurs when synchronization primitives like barriers, locks,
    /// or cache locks fail during concurrent operations.
    ///
    /// # Examples
    ///
    /// - Barrier wait failures during parallel loading
    /// - Lock acquisition failures for cache updates
    /// - Thread synchronization failures
    #[error("Lock error: {0}")]
    LockError(String),

    /// Configuration or setup error.
    ///
    /// This error occurs when there are issues with configuration, project setup,
    /// file paths, or other setup-related operations.
    ///
    /// # Examples
    ///
    /// - Missing primary file specification
    /// - Invalid search paths
    /// - Duplicate assembly identities
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Emulation error.
    ///
    /// This error wraps errors from the CIL emulation engine, including
    /// interpreter errors, memory access violations, and execution limit
    /// violations.
    #[error("{0}")]
    Emulation(Box<EmulationError>),

    /// Deobfuscation error.
    ///
    /// This error occurs during deobfuscation passes, such as control flow
    /// unflattening, when the analysis or transformation cannot be completed.
    #[error("Deobfuscation error: {0}")]
    Deobfuscation(String),

    /// x86/x64 native code analysis error.
    ///
    /// This error occurs during x86/x64 native code decoding or SSA translation,
    /// including invalid instructions, unsupported operations, or translation failures.
    #[error("x86 error: {0}")]
    X86Error(String),

    /// Tracing error.
    ///
    /// This error occurs when trace file creation or writing fails.
    /// This includes permission errors, disk full, or invalid paths.
    #[error("Tracing error: {0}")]
    TracingError(String),
}

/// Failure modes for method-by-token lookups.
///
/// Returned by [`crate::CilObject::method`] and
/// [`crate::CilObject::method_spec`]. Propagates into [`enum@Error`] via the
/// [`Error::LookupMethod`] variant — call sites that already use
/// `Result<_, Error>` can propagate with `?` without manual conversion.
///
/// # Stability
///
/// `#[non_exhaustive]` so additional failure modes (e.g. partial resolution,
/// stale weak references) can be added without a breaking change. Consumers
/// must include a wildcard arm when matching.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum MethodLookupError {
    /// The supplied token does not appear in the [`MethodDef`] table.
    ///
    /// This is distinct from "method exists but has no body" — for an abstract
    /// or P/Invoke method the call returns `Ok(method)` and the caller can
    /// inspect [`crate::metadata::method::Method::rva_kind`] to see why no IL
    /// is present.
    ///
    /// [`MethodDef`]: crate::metadata::tables::MethodDefRaw
    #[error("MethodDef token {0} not found")]
    NotFound(Token),

    /// The supplied token does not appear in the [`MethodSpec`] table.
    ///
    /// [`MethodSpec`]: crate::metadata::tables::MethodSpec
    #[error("MethodSpec token {0} not found")]
    SpecNotFound(Token),
}

/// Pipeline stage at which a parse error originated.
///
/// Returned as part of [`ParseFailure`]. Lets consumers act on the error
/// category (e.g. retry an upgrade only for `Cor20Header`/`MetadataRoot`
/// failures) without parsing string messages.
///
/// `#[non_exhaustive]` — additional stages may be added as the parser
/// surface grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParseStage {
    /// DOS / MZ header at the very start of the PE file.
    DosHeader,
    /// PE signature ("PE\0\0") immediately following the DOS stub.
    PeSignature,
    /// COFF file header following the PE signature.
    CoffHeader,
    /// Optional header (PE32 / PE32+).
    OptionalHeader,
    /// Section table immediately after the optional header.
    SectionTable,
    /// CLI / COR20 runtime header located via the data-directory entry.
    Cor20Header,
    /// Metadata root header (signature, versions, stream count).
    MetadataRoot,
    /// Per-stream header inside the metadata root.
    StreamHeader,
    /// Tilde (`#~`) stream containing metadata table rows.
    TildeStream,
    /// A Portable PDB's `#Pdb` stream.
    PdbStream,
    /// Per-table row layout/decoding within the tilde stream.
    TableRow,
    /// One of the heap streams (`#Strings`, `#US`, `#Blob`, `#GUID`).
    Heap,
    /// Generic data-directory entry traversal.
    DataDirectory,
    /// Resource directory (.NET embedded resources).
    Resources,
    /// VTableFixup directory.
    VTableFixup,
    /// Strong-name signature blob.
    StrongName,
    /// Signature parsing within blobs (method/field/etc.).
    Signature,
    /// Method body header / code / EH-clause parsing.
    MethodBody,
    /// Custom-attribute decoding from the blob heap.
    CustomAttribute,
    /// DeclSecurity permission-set decoding.
    PermissionSet,
    /// CIL instruction decoding (disassembly).
    InstructionDecoder,
    /// CIL instruction encoding (assembler/serializer write paths).
    InstructionEncoder,
    /// Assembly / metadata writer paths (`crate::cilassembly::writer`).
    AssemblyWriter,
    /// Imports/exports table decoding.
    ImportsExports,
    /// Type system construction post-parse (`crate::metadata::tables`,
    /// owned-type construction).
    TypeSystem,
    /// Validation passes (`crate::metadata::validation`).
    Validation,
    /// Emulation/runtime loader (`crate::emulation::loader`).
    EmulationLoader,
    /// Generic byte-parser primitives — used by helpers that have no
    /// inherent stage (e.g. `crate::file::parser::Parser`).
    Generic,
}

impl std::fmt::Display for ParseStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ParseStage::DosHeader => "DOS header",
            ParseStage::PeSignature => "PE signature",
            ParseStage::CoffHeader => "COFF header",
            ParseStage::OptionalHeader => "PE optional header",
            ParseStage::SectionTable => "PE section table",
            ParseStage::Cor20Header => "COR20 header",
            ParseStage::MetadataRoot => "metadata root",
            ParseStage::StreamHeader => "stream header",
            ParseStage::TildeStream => "tilde (#~) stream",
            ParseStage::PdbStream => "#Pdb stream",
            ParseStage::TableRow => "metadata table row",
            ParseStage::Heap => "heap",
            ParseStage::DataDirectory => "data directory",
            ParseStage::Resources => "resources",
            ParseStage::VTableFixup => "VTable fixup",
            ParseStage::StrongName => "strong-name signature",
            ParseStage::Signature => "signature blob",
            ParseStage::MethodBody => "method body",
            ParseStage::CustomAttribute => "custom attribute",
            ParseStage::PermissionSet => "permission set",
            ParseStage::InstructionDecoder => "CIL decoder",
            ParseStage::InstructionEncoder => "CIL encoder",
            ParseStage::AssemblyWriter => "assembly writer",
            ParseStage::ImportsExports => "imports/exports",
            ParseStage::TypeSystem => "type system",
            ParseStage::Validation => "validation",
            ParseStage::EmulationLoader => "emulation loader",
            ParseStage::Generic => "generic byte parser",
        };
        f.write_str(s)
    }
}

/// Heap stream kind.
///
/// Carried by [`ParseFailure::HeapOutOfBounds`] /
/// [`ParseFailure::HeapCorrupt`] so consumers can pinpoint which heap
/// failed without parsing a message string. `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeapKind {
    /// `#Strings` heap — null-terminated UTF-8 identifier names.
    Strings,
    /// `#US` heap — length-prefixed UTF-16 user strings.
    UserStrings,
    /// `#Blob` heap — length-prefixed binary blobs.
    Blob,
    /// `#GUID` heap — packed 16-byte GUIDs.
    Guid,
}

impl std::fmt::Display for HeapKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            HeapKind::Strings => "#Strings",
            HeapKind::UserStrings => "#US",
            HeapKind::Blob => "#Blob",
            HeapKind::Guid => "#GUID",
        })
    }
}

/// Stream kind inside the metadata root.
///
/// Carried by [`ParseFailure::TruncatedStream`] and similar variants.
/// `#[non_exhaustive]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamKind {
    /// Compressed metadata-table stream (`#~`).
    Tilde,
    /// Uncompressed metadata-table stream (`#-`).
    TildeUncompressed,
    /// `#Strings` heap.
    Strings,
    /// `#US` heap.
    UserStrings,
    /// `#Blob` heap.
    Blob,
    /// `#GUID` heap.
    Guid,
    /// Portable PDB (`#Pdb`) stream.
    Pdb,
}

impl std::fmt::Display for StreamKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StreamKind::Tilde => "#~",
            StreamKind::TildeUncompressed => "#-",
            StreamKind::Strings => "#Strings",
            StreamKind::UserStrings => "#US",
            StreamKind::Blob => "#Blob",
            StreamKind::Guid => "#GUID",
            StreamKind::Pdb => "#Pdb",
        })
    }
}

/// What names a row in a write: a column of another row, a method body, or the CLI header.
///
/// Carried by [`Error::DanglingReference`]. Its tokens are the ones the input assembly has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Referrer {
    /// A column of a metadata row.
    Column {
        /// The row.
        row: Token,
        /// The column, by its ECMA-335 name.
        column: &'static str,
    },
    /// A method body: an instruction operand, its local variable signature or a catch type.
    Body(Token),
    /// The entry point in the CLI header.
    EntryPoint,
}

impl std::fmt::Display for Referrer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Referrer::Column { row, column } => write!(f, "{column} of {row}"),
            Referrer::Body(method) => write!(f, "the body of {method}"),
            Referrer::EntryPoint => f.write_str("the entry point"),
        }
    }
}

/// Structured parse-pipeline failure.
///
/// Reported through [`Error::Parse`] for every error site in the file, metadata-root and
/// stream parsers, plus per-table parse paths that read raw
/// PE/metadata bytes. This replaced the stringly-typed `Malformed` / `OutOfBounds` /
/// `HeapBoundsError` variants, which no longer exist; every parse site reports through
/// [`ParseFailure`].
///
/// # Stability
///
/// `#[non_exhaustive]` — additional well-known failure classes can be added
/// without a breaking change. Consumers must include a wildcard arm when
/// matching.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ParseFailure {
    /// Header / structure bytes were not present at the expected offset.
    ///
    /// `expected` and `found` are byte counts when the gap is over a known
    /// header. For partial reads where exact byte counts are unknown, both
    /// fields may be 0.
    #[error("truncated {stage} (expected {expected} bytes, found {found})")]
    Truncated {
        /// Pipeline stage in which truncation was detected.
        stage: ParseStage,
        /// Bytes the parser needed.
        expected: usize,
        /// Bytes that were actually available.
        found: usize,
    },

    /// A magic number or signature did not match the expected value.
    #[error("bad {stage} magic: expected 0x{expected:08X}, found 0x{found:08X}")]
    BadMagic {
        /// Pipeline stage that performed the magic check.
        stage: ParseStage,
        /// Expected magic value.
        expected: u32,
        /// Magic value actually read.
        found: u32,
    },

    /// A header field was outside the acceptable range or otherwise invalid.
    #[error("invalid {stage} field `{field}`: {reason}")]
    InvalidField {
        /// Pipeline stage in which the field appears.
        stage: ParseStage,
        /// Field name (static — derived from struct definition).
        field: &'static str,
        /// Human-readable description of why the value was rejected.
        reason: String,
    },

    /// A schema version is recognized but not supported by this parser.
    #[error("unsupported {stage} schema version `{version}`")]
    UnsupportedSchema {
        /// Pipeline stage that surfaced the schema mismatch.
        stage: ParseStage,
        /// Schema version string (e.g. ECMA-335 §II.24.2.1 form).
        version: String,
    },

    /// A read crossed the end of the parse buffer.
    #[error("read past end of buffer in {stage}")]
    OutOfBounds {
        /// Pipeline stage in which the OOB read was attempted.
        stage: ParseStage,
    },

    /// A stream's declared offset/size exceeds the surrounding buffer.
    #[error("truncated stream `{stream}` at offset {offset}")]
    TruncatedStream {
        /// Stream that could not be fully read.
        stream: StreamKind,
        /// File offset at which the read ran out of bytes.
        offset: u32,
    },

    /// A heap reference was outside the bounds of its stream.
    #[error("heap `{heap}` index {index} out of bounds")]
    HeapOutOfBounds {
        /// Heap whose bounds were violated.
        heap: HeapKind,
        /// Index that exceeded the heap.
        index: u32,
    },

    /// A heap's byte content did not satisfy its format invariant.
    #[error("heap `{heap}` corrupt: {reason}")]
    HeapCorrupt {
        /// Heap whose content was rejected.
        heap: HeapKind,
        /// Human-readable description of the corruption.
        reason: String,
    },

    /// Free-form parse failure used as a migration fallback for sites whose
    /// failure shape does not yet fit a structured variant.
    ///
    /// New code should prefer one of the structured variants; this one is
    /// retained so partial migrations do not block on unusual call sites.
    #[error("{stage}: {message}")]
    Other {
        /// Pipeline stage in which the error occurred.
        stage: ParseStage,
        /// Free-form description of the failure.
        message: String,
    },
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(Arc::new(err))
    }
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Self {
        Error::Goblin(Arc::new(err))
    }
}

impl From<cowfile::Error> for Error {
    fn from(err: cowfile::Error) -> Self {
        match err {
            cowfile::Error::Io(io_err) => Error::Io(Arc::new(io_err)),
            cowfile::Error::OutOfBounds { .. } => Error::Parse(ParseFailure::OutOfBounds {
                stage: ParseStage::Generic,
            }),
            cowfile::Error::LockPoisoned(msg) => Error::LockError(msg),
        }
    }
}

#[cfg(feature = "emulation")]
impl From<EmulationError> for Error {
    fn from(err: EmulationError) -> Self {
        Error::Emulation(Box::new(err))
    }
}

impl From<analyssa::GraphError> for Error {
    fn from(err: analyssa::GraphError) -> Self {
        Error::GraphError(err.0)
    }
}

impl From<Error> for analyssa::Error {
    fn from(err: Error) -> Self {
        analyssa::Error::new(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message's inline arguments are formatted: the single-literal form printed `{name}`
    /// as it is written.
    #[test]
    fn malformed_error_formats_inline_arguments() {
        let value = 0x1234;
        let name = "column";
        let error = malformed_error!("{value:#x} does not fit the {name}");
        assert!(
            error.to_string().contains("0x1234 does not fit the column"),
            "{error}"
        );
        let built = format!("built {}", 7);
        assert!(malformed_error!(built).to_string().contains("built 7"));
        assert!(malformed_error!("{} and {}", 1, 2)
            .to_string()
            .contains("1 and 2"));
    }

    /// `Clone` must preserve the variant.
    ///
    /// A hand-written `Clone` with a wildcard arm flattens most variants into
    /// `Error::Other(String)`, so `matches!(e, Error::NotSupported)` is true before the clone
    /// and false after — a contract violation no compiler catches. Deriving `Clone` is what
    /// makes that impossible; this pins the property rather than the derive.
    #[test]
    fn clone_preserves_the_variant() {
        let cases = [
            Error::NotSupported,
            Error::TypeNotFound(Token::new(0x0200_0001)),
            Error::RecursionLimit(32),
            Error::Other("plain".to_string()),
        ];

        for error in cases {
            let cloned = error.clone();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&cloned),
                "clone changed the variant of {error:?}"
            );
            assert_eq!(error.to_string(), cloned.to_string());
        }
    }

    /// The nested error list of a stage-2 failure must survive a clone; a wildcard arm keeps
    /// only the one-line summary and discards every nested `Error`.
    #[test]
    fn clone_preserves_nested_validation_errors() {
        let nested = Error::ValidationStage2Failed {
            errors: vec![Error::NotSupported, Error::RecursionLimit(32)],
            error_count: 2,
            summary: "two failures".to_string(),
        };

        let Error::ValidationStage2Failed { errors, .. } = nested.clone() else {
            panic!("clone changed the variant");
        };
        assert_eq!(errors.len(), 2);
    }

    /// An `io::Error`'s kind must survive a clone; stringifying it loses what callers match on.
    #[test]
    fn clone_preserves_the_io_error_kind() {
        let error = Error::from(io::Error::new(io::ErrorKind::PermissionDenied, "denied"));

        let Error::Io(cloned) = error.clone() else {
            panic!("clone changed the variant");
        };
        assert_eq!(cloned.kind(), io::ErrorKind::PermissionDenied);
    }
}
