//! Method representation and analysis for .NET assemblies.
//!
//! This module provides comprehensive support for analyzing .NET methods, including
//! method metadata, IL code, exception handlers, and control flow structures.
//! It integrates closely with the disassembler to provide complete method analysis.
//!
//! # Architecture Overview
//!
//! The method analysis system uses a streamlined architecture centered around the
//! [`crate::metadata::method::Method`] struct with lazy-initialized basic blocks. Key design principles:
//!
//! - **Thread-safe lazy initialization**: Basic blocks are computed once and cached
//!   using `OnceLock<Vec<crate::assembly::BasicBlock>>` for efficient concurrent access
//! - **Zero-copy iteration**: The [`crate::metadata::method::InstructionIterator`] yields references to
//!   instructions without copying, enabling efficient analysis of large methods
//! - **Unified storage**: All instruction data is stored in basic blocks, eliminating
//!   redundant caching layers and simplifying the architecture
//!
//! # Key Components
//!
//! - [`crate::metadata::method::Method`] - Complete method representation with metadata and lazily-loaded IL code
//! - [`crate::metadata::method::MethodBody`] - Method body containing IL instructions and exception handlers
//! - [`crate::metadata::method::ExceptionHandler`] - Try/catch/finally exception handling regions
//! - [`crate::metadata::method::InstructionIterator`] - Efficient iterator over method instructions
//! - [`crate::metadata::method::MethodMap`] - Token-indexed collection of all methods in an assembly
//!
//! # Usage Patterns
//!
//! ## Basic Method Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! for entry in assembly.methods().iter().take(10) {
//!     let method = entry.value();
//!     
//!     println!("Method: {} (Token: {:?})", method.name, method.token);
//!     println!("  Blocks: {}, Instructions: {}",
//!              method.block_count(), method.instruction_count());
//!     
//!     // Analyze control flow
//!     for (block_idx, block) in method.blocks() {
//!         println!("  Block {}: {} instructions at RVA 0x{:X}",
//!                  block_idx, block.instructions.len(), block.rva);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Instruction-Level Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! for entry in assembly.methods().iter().take(5) {
//!     let method = entry.value();
//!     
//!     // Count different instruction types
//!     let mut call_count = 0;
//!     let mut branch_count = 0;
//!     
//!     for instruction in method.instructions() {
//!         match instruction.mnemonic {
//!             s if s.starts_with("call") => call_count += 1,
//!             s if s.contains("br") => branch_count += 1,
//!             _ => {}
//!         }
//!     }
//!     
//!     println!("{}: {} calls, {} branches", method.name, call_count, branch_count);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All method analysis operations are thread-safe:
//! - Methods can be safely shared across threads via `Arc<Method>`
//! - Basic block initialization uses `OnceLock` for thread-safe lazy loading
//! - Multiple threads can safely iterate over the same method simultaneously
//! - Iterator creation and consumption can happen concurrently
//!
//! # ECMA-335 References
//!
//! - §II.22.26 - MethodDef table (method metadata)
//! - §II.23.1.10 - MethodAttributes and MethodImplAttributes flags
//! - §II.25.4 - Method body format (tiny and fat headers)
//! - §II.25.4.6 - Exception handling clauses

mod body;
mod encode;
mod exceptions;
mod iter;
mod types;

use std::sync::{atomic::AtomicU32, Arc, OnceLock, Weak};

pub use body::*;
use crossbeam_skiplist::SkipMap;
pub use encode::encode_method_body_header;
pub use exceptions::*;
pub use iter::InstructionIterator;
pub use types::*;

use crate::{
    analysis::{
        BlockRange, ControlFlowGraph, SsaConverter, SsaExceptionHandler, SsaFunction, TypeContext,
    },
    assembly::{self, BasicBlock, DecodedBodies, InstructionEncoder},
    file::File,
    metadata::{
        customattributes::CustomAttributeValueList,
        security::Security,
        signatures::{
            parse_local_var_signature, SignatureLocalVariable, SignatureMethod, TypeSignature,
        },
        streams::Blob,
        tables::{GenericParamList, MetadataTable, MethodSpecList, ParamList, StandAloneSigRaw},
        token::Token,
        typesystem::{
            CilModifier, CilTypeRc, CilTypeRef, CilTypeReference, TypeRegistry, TypeResolver,
        },
    },
    utils::{LazyList, RowList},
    CilObject,
    Error::SsaError,
    Result,
};

/// A map that holds the mapping of Token to parsed `Method`.
pub type MethodMap = SkipMap<Token, MethodRc>;
/// A vector that holds several parsed `Method`s.
pub type MethodList = Arc<boxcar::Vec<MethodRc>>;
/// A vector that holds `MethodRef` instances (weak references)
pub type MethodRefList = LazyList<MethodRef>;
/// A reference-counted pointer to a `Method`.
pub type MethodRc = Arc<Method>;

/// Returns the name of the method definition for the given token, if it exists in the map.
///
/// This is a convenience function that performs a lookup in a [`MethodMap`] and extracts
/// the method name without requiring callers to deal with the `Entry` guard returned
/// by the underlying [`crossbeam_skiplist::SkipMap`].
///
/// # Arguments
///
/// * `map` - The method map to search in.
/// * `token` - The metadata token (table 0x06) identifying the method.
///
/// # Returns
///
/// The method name as a `String` if a method with the given token exists, `None` otherwise.
pub fn method_name_by_token(map: &MethodMap, token: &Token) -> Option<String> {
    map.get(token).map(|e| e.value().name.clone())
}

/// A smart reference to a Method that automatically handles weak references
/// to prevent circular reference memory leaks while providing a clean API.
///
/// `MethodRef` provides a safe way to reference methods without creating strong
/// reference cycles that could lead to memory leaks. This is particularly useful
/// when methods reference other methods (e.g., through inheritance or interfaces)
/// where circular dependencies might occur.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Create weak references to avoid circular dependencies
/// for entry in assembly.methods().iter().take(5) {
///     let method = entry.value();
///     let weak_ref = dotscope::metadata::method::MethodRef::new(&method);
///     
///     // Check if the reference is still valid
///     if weak_ref.is_valid() {
///         if let Some(name) = weak_ref.name() {
///             println!("Referenced method: {}", name);
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct MethodRef {
    /// Weak reference to the actual method to avoid reference cycles
    weak_ref: Weak<Method>,
}

impl MethodRef {
    /// Create a new `MethodRef` from a strong reference.
    ///
    /// This method creates a weak reference to the provided method, allowing
    /// safe referencing without creating strong reference cycles.
    ///
    /// # Arguments
    ///
    /// * `strong_ref` - A strong reference (`Arc<Method>`) to the method
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     println!("Created weak reference to method: {}", method.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn new(strong_ref: &MethodRc) -> Self {
        Self {
            weak_ref: Arc::downgrade(strong_ref),
        }
    }

    /// Get a strong reference to the method, returning None if the method has been dropped.
    ///
    /// This method attempts to upgrade the weak reference to a strong reference.
    /// If the original method has been dropped, this returns `None`.
    ///
    /// # Returns
    ///
    /// - `Some(Arc<Method>)` if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     // Later, try to access the method
    ///     if let Some(method) = method_ref.upgrade() {
    ///         println!("Method is still available: {}", method.name);
    ///     } else {
    ///         println!("Method has been dropped");
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn upgrade(&self) -> Option<MethodRc> {
        self.weak_ref.upgrade()
    }

    /// Get a strong reference to the method, returning an error if it has been dropped.
    ///
    /// Use this when you expect the method to still exist. The provided message is
    /// included in the returned error if the underlying weak reference can no longer
    /// be upgraded.
    ///
    /// # Arguments
    ///
    /// * `msg` - Diagnostic message included in the returned error if the method has been dropped
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] if the underlying method has been dropped.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///
    ///     let method = method_ref.expect("Method should still be available")?;
    ///     println!("Accessed method: {}", method.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn expect(&self, msg: &str) -> Result<MethodRc> {
        self.weak_ref
            .upgrade()
            .ok_or_else(|| malformed_error!("{}", msg))
    }

    /// Check if the referenced method is still alive.
    ///
    /// This provides a quick way to test if the weak reference can still be
    /// upgraded to a strong reference without actually performing the upgrade.
    ///
    /// # Returns
    ///
    /// `true` if the method is still alive, `false` if it has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut method_refs = Vec::new();
    ///
    /// // Collect weak references
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     method_refs.push(dotscope::metadata::method::MethodRef::new(&method));
    /// }
    ///
    /// // Check which references are still valid
    /// let valid_count = method_refs.iter().filter(|r| r.is_valid()).count();
    /// println!("{} out of {} method references are still valid",
    ///          valid_count, method_refs.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.weak_ref.strong_count() > 0
    }

    /// Get the token of the referenced method (if still alive).
    ///
    /// This is a convenience method that upgrades the reference and extracts
    /// the method token in a single operation.
    ///
    /// # Returns
    ///
    /// - `Some(Token)` if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// if let Some(entry) = assembly.methods().iter().next() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if let Some(token) = method_ref.token() {
    ///         println!("Method token: {:?}", token);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        self.upgrade().map(|m| m.token)
    }

    /// Get the name of the referenced method (if still alive).
    ///
    /// This is a convenience method that upgrades the reference and extracts
    /// the method name in a single operation.
    ///
    /// # Returns
    ///
    /// - `Some(String)` containing the method name if the method is still alive
    /// - `None` if the method has been dropped
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut method_names = Vec::new();
    ///
    /// for entry in assembly.methods().iter().take(5) {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if let Some(name) = method_ref.name() {
    ///         method_names.push(name);
    ///     }
    /// }
    ///
    /// println!("Collected {} method names", method_names.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn name(&self) -> Option<String> {
        self.upgrade().map(|m| m.name.clone())
    }

    /// Check if the referenced method is a constructor (.ctor or .cctor).
    ///
    /// This is a convenience method that upgrades the reference and checks
    /// if the method is a constructor in a single operation.
    ///
    /// # Returns
    ///
    /// `true` if the method is still alive and is a constructor, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut constructor_count = 0;
    ///
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     let method_ref = dotscope::metadata::method::MethodRef::new(&method);
    ///     
    ///     if method_ref.is_constructor() {
    ///         constructor_count += 1;
    ///     }
    /// }
    ///
    /// println!("Found {} constructors", constructor_count);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        if let Some(method) = self.upgrade() {
            method.is_constructor()
        } else {
            false
        }
    }
}

impl From<MethodRc> for MethodRef {
    fn from(strong_ref: MethodRc) -> Self {
        Self::new(&strong_ref)
    }
}

/// Disambiguated reason for a [`Method`]'s RVA value.
///
/// Returned by [`Method::rva_kind`]. Lets callers distinguish between a method
/// with a real IL body (`Resolved(addr)`), one of the legitimate "no IL"
/// cases (`Abstract`, `PInvoke`, `Runtime`), and a malformed-input case
/// (`UnresolvedZero` - RVA is `None` with no flag explaining why).
///
/// `Method.rva` carried `Option<u32>` does not surface this distinction;
/// `rva_kind()` is the recommended accessor for downstream code that needs
/// to log a meaningful reason or take a code path based on the RVA's
/// provenance.
///
/// # Stability
///
/// `#[non_exhaustive]` so additional well-known classifications (e.g. an
/// unmanaged-export variant) can be added later without a breaking change.
/// Consumers must include a wildcard arm when matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MethodRvaKind {
    /// IL code lives at the given RVA. Equivalent to `Method.rva == Some(addr)`.
    Resolved(u32),
    /// Method is declared abstract - body is supplied by an overriding type
    /// in this or another assembly.
    Abstract,
    /// Method is implemented via Platform Invoke - body lives in an external
    /// native module referenced by `MethodModifiers::PINVOKE_IMPL`.
    PInvoke,
    /// Method is runtime-managed - implemented by the CLR rather than by IL
    /// in this assembly. Identified by `MethodImplCodeType::RUNTIME`.
    Runtime,
    /// `Method.rva` is `None` but no flag explains why. Indicates malformed
    /// metadata or an unsupported method-implementation form.
    UnresolvedZero,
}

impl MethodRvaKind {
    /// Returns a stable `&'static str` identifier for this RVA kind.
    ///
    /// Variants render as `"resolved"`, `"abstract"`, `"pinvoke"`,
    /// `"runtime"`, `"unresolved_zero"`. The strings are part of the stable
    /// public API and safe to persist.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            MethodRvaKind::Resolved(_) => "resolved",
            MethodRvaKind::Abstract => "abstract",
            MethodRvaKind::PInvoke => "pinvoke",
            MethodRvaKind::Runtime => "runtime",
            MethodRvaKind::UnresolvedZero => "unresolved_zero",
        }
    }
}

impl std::fmt::Display for MethodRvaKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MethodRvaKind::Resolved(addr) => write!(f, "resolved(0x{addr:08X})"),
            other => f.write_str(other.as_str()),
        }
    }
}

/// Represents all the information about a CIL method.
///
/// The `Method` struct contains all metadata, code, and analysis results for a single .NET method.
/// It includes method attributes, parameters, generic arguments, IL code, exception handlers, and analysis results.
///
/// # Invariants
///
/// The following invariants should be maintained for a valid `Method`:
///
/// - **Token/RID consistency**: `token.value() == (0x06000000 | rid)` - The token must match the row ID
/// - **RVA validity**: If `rva.is_some()` and the method is not runtime-provided, `body` should be set
/// - **Parameter correlation**: After [`Method::parse()`] is called, `params` entries have correlated signatures
/// - **Block dependency**: `blocks` depends on `body` being set (decoding requires body data)
///
/// # Initialization Sequence
///
/// Methods go through several initialization phases:
///
/// 1. **Basic construction** - Created from `MethodDef` table row with metadata fields populated
/// 2. **[`Method::parse()`]** - Loads method body, local variables, and applies parameter signatures
/// 3. **`decode_method()`** - Disassembles IL bytecode and builds basic blocks
///
/// After phase 1, the method has metadata but no IL code. After phase 2, the body and local variables
/// are available. After phase 3, instructions can be iterated via [`Method::instructions()`].
///
/// # Thread Safety
///
/// The struct uses [`OnceLock`] for lazy-initialized fields (`body`, `blocks`, `overrides`, `security`)
/// which provides thread-safe one-time initialization. The `flags_pinvoke` field uses [`AtomicU32`]
/// because it's populated from a separate table after the method may already be shared.
pub struct Method {
    /// The row this method has in the `MetadataTable`
    pub rid: u32,
    /// The token of this method
    pub token: Token,
    /// The offset in the `MetadataTable`
    pub meta_offset: usize,
    /// This methods name
    pub name: String,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_code_type: MethodImplCodeType,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_management: MethodImplManagement,
    /// `MethodImplAttributes`, §II.23.1.10
    pub impl_options: MethodImplOptions,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_access: MethodAccessFlags,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_vtable: MethodVtableFlags,
    /// `MethodAttributes`, §II.23.1.10
    pub flags_modifiers: MethodModifiers,
    /// P/Invoke mapping flags from the `ImplMap` table, §II.23.1.8.
    pub flags_pinvoke: AtomicU32,
    /// The parameters (from `Param` table, enhanced with information from the `SignatureMethod`)
    /// sequence 0, is the return value (if there is a count 0).
    pub params: ParamList,
    /// All generic parameters this type has (type information, not the instantiated version)
    pub generic_params: GenericParamList,
    /// `MethodSpec` instances that provide generic instantiations for this method
    pub generic_args: MethodSpecList,
    /// The signature of this method
    pub signature: SignatureMethod,
    /// The RVA of this method
    pub rva: Option<u32>,
    /// The `MethodBody`
    pub body: OnceLock<MethodBody>,
    /// The local variables, allocated on the first one
    pub local_vars: LazyList<LocalVariable>,
    /// Overridden method declarations for `.override` directive emission
    /// (from `MethodImpl` table where `MethodBody` points to this method).
    /// A method can implement multiple interface methods via separate MethodImpl rows.
    pub overrides: RowList<CilTypeReference>,
    /// Implemented interface methods
    /// (from `MethodImpl` table entries for this type)
    pub interface_impls: RowList<MethodRef>,
    /// The method's declarative security, a `DeclSecurity` row each, in table order: a method
    /// may demand permissions under several actions (a link demand and an inheritance
    /// demand, say).
    pub security: RowList<Security>,
    /// The basic blocks of this method, lazily initialized
    pub blocks: OnceLock<Vec<BasicBlock>>,
    /// Custom attributes attached to this method
    pub custom_attributes: CustomAttributeValueList,
    /// The type that declares this method (lazy-loaded).
    ///
    /// Contains a weak reference to the [`crate::metadata::typesystem::CilType`] that owns this method.
    /// This is set during TypeDef loading after the owning type is constructed.
    /// Use [`CilTypeRef::upgrade()`] to obtain a strong reference when needed.
    pub declaring_type: OnceLock<CilTypeRef>,
}

impl Method {
    /// Returns an iterator over all instructions in this method.
    ///
    /// Instructions are yielded in execution order across all basic blocks, providing
    /// a linear view of the method's IL code. This method handles uninitialized state
    /// gracefully by returning an empty iterator if blocks haven't been decoded yet.
    ///
    /// The iterator implements efficient traversal without copying instruction data,
    /// making it suitable for analysis of large methods. Each instruction maintains
    /// its original metadata including RVA, operands, and flow control information.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently. If the method hasn't
    /// been disassembled yet, all threads will receive an empty iterator.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(3) {
    ///     let method = entry.value();
    ///     println!("Method: {} ({} instructions)",
    ///              method.name, method.instruction_count());
    ///
    ///     for (i, instruction) in method.instructions().enumerate() {
    ///         println!("  [{}] {} {:?}", i, instruction.mnemonic, instruction.operand);
    ///         if i >= 10 { break; } // Limit output for readability
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn instructions(&self) -> InstructionIterator<'_> {
        if let Some(blocks) = self.blocks.get() {
            InstructionIterator::new(blocks.as_slice())
        } else {
            InstructionIterator::new(&[])
        }
    }

    /// Returns an iterator over all basic blocks containing the instructions.
    ///
    /// This method provides access to the control flow structure of the method by yielding
    /// each basic block along with its sequential index. Basic blocks represent straight-line
    /// sequences of instructions with a single entry point and single exit point.
    ///
    /// The iterator yields tuples of `(block_index, &BasicBlock)` where `block_index` is the
    /// zero-based position in the blocks vector. Returns an empty iterator if the method
    /// hasn't been disassembled yet.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    /// Multiple threads can safely iterate over blocks simultaneously.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(3) {
    ///     let method = entry.value();
    ///     println!("Method: {} has {} basic blocks",
    ///              method.name, method.block_count());
    ///     
    ///     for (block_index, block) in method.blocks() {
    ///         println!("  Block {}: RVA 0x{:X}, {} instructions, {} exceptions",
    ///                 block_index, block.rva, block.instructions.len(), block.exceptions.len());
    ///         
    ///         // Show control flow information
    ///         if !block.instructions.is_empty() {
    ///             let last_instr = &block.instructions[block.instructions.len() - 1];
    ///             println!("    Ends with: {} (flow: {:?})",
    ///                     last_instr.mnemonic, last_instr.flow_type);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Control Flow Analysis
    ///
    /// Each basic block contains:
    /// - Sequential instructions with no internal jumps
    /// - Exception handler associations
    /// - RVA and offset information for debugging
    /// - Flow control termination (branch, return, throw, etc.)
    pub fn blocks(&self) -> Box<dyn Iterator<Item = (usize, &BasicBlock)> + '_> {
        if let Some(blocks) = self.blocks.get() {
            Box::new(blocks.iter().enumerate())
        } else {
            Box::new([].iter().enumerate())
        }
    }

    /// Returns the number of basic blocks in this method.
    ///
    /// This provides an efficient way to get the block count without iterating through
    /// all blocks. Returns 0 if the method hasn't been disassembled yet or contains
    /// no executable code.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     let block_count = method.block_count();
    ///     let instr_count = method.instruction_count();
    ///     
    ///     println!("Method: {} - {} blocks, {} instructions (avg {:.1} instr/block)",
    ///              method.name, block_count, instr_count,
    ///              if block_count > 0 { instr_count as f64 / block_count as f64 } else { 0.0 });
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn block_count(&self) -> usize {
        if let Some(blocks) = self.blocks.get() {
            blocks.len()
        } else {
            0
        }
    }

    /// Returns the total number of instructions across all basic blocks.
    ///
    /// This method efficiently calculates the total instruction count by summing
    /// the length of instruction vectors in each basic block. This is more efficient
    /// than calling `method.instructions().count()` as it avoids creating and
    /// consuming the iterator.
    ///
    /// Returns 0 if the method hasn't been disassembled yet or contains no executable code.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and handles the `OnceLock` access pattern internally.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let mut total_instructions = 0;
    /// let mut method_count = 0;
    ///
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     let count = method.instruction_count();
    ///     total_instructions += count;
    ///     method_count += 1;
    ///     
    ///     if count > 100 {
    ///         println!("Large method: {} with {} instructions", method.name, count);
    ///     }
    /// }
    ///
    /// println!("Assembly has {} methods with {} total instructions",
    ///          method_count, total_instructions);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn instruction_count(&self) -> usize {
        if let Some(blocks) = self.blocks.get() {
            blocks.iter().map(|block| block.instructions.len()).sum()
        } else {
            0
        }
    }

    /// Returns true if the method has IL code.
    ///
    /// This checks the `MethodImplCodeType::IL` flag in the method's implementation
    /// attributes to determine if the method contains Common Intermediate Language (CIL)
    /// instructions that can be disassembled and analyzed.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(10) {
    ///     let method = entry.value();
    ///     if method.is_code_il() {
    ///         println!("Method '{}' contains IL code", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_il(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::IL)
    }

    /// Returns true if the method has native code (P/Invoke).
    ///
    /// This checks the `MethodImplCodeType::NATIVE` flag to determine if the method
    /// is implemented in native code rather than IL. This is typical for P/Invoke
    /// methods that call into unmanaged libraries.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let native_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_code_native())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} native methods", native_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_native(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::NATIVE)
    }

    /// Returns true if the method has optimized IL code.
    ///
    /// This checks the `MethodImplCodeType::OPTIL` flag to determine if the method
    /// contains optimized Common Intermediate Language that may have been transformed
    /// by the runtime or tools for better performance.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_code_opt_il() {
    ///         println!("Method '{}' has optimized IL code", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_opt_il(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::OPTIL)
    }

    /// Returns true if the method is implemented in the runtime.
    ///
    /// This checks the `MethodImplCodeType::RUNTIME` flag to determine if the method
    /// is implemented directly by the .NET runtime rather than containing user code.
    /// This is common for intrinsic methods and runtime-provided functionality.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let runtime_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_code_runtime())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} runtime-implemented methods", runtime_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_runtime(&self) -> bool {
        self.impl_code_type.contains(MethodImplCodeType::RUNTIME)
    }

    /// Returns true if the method is unmanaged.
    ///
    /// This checks the `MethodImplManagement::UNMANAGED` flag to determine if the
    /// method runs outside the managed execution environment, typically for P/Invoke
    /// methods or COM interop scenarios.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_code_unmanaged() {
    ///         println!("Unmanaged method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_code_unmanaged(&self) -> bool {
        self.impl_management
            .contains(MethodImplManagement::UNMANAGED)
    }

    /// Returns true if the method is a forward reference (used in merge scenarios).
    ///
    /// This checks the `MethodImplOptions::FORWARD_REF` flag to determine if the
    /// method is declared but not yet defined, which can occur during incremental
    /// compilation or when working with incomplete assemblies.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let forward_refs: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_forward_ref())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// if !forward_refs.is_empty() {
    ///     println!("Found {} forward reference methods", forward_refs.len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_forward_ref(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::FORWARD_REF)
    }

    /// Returns true if the method is synchronized.
    ///
    /// This checks the `MethodImplOptions::SYNCHRONIZED` flag to determine if the
    /// method automatically acquires a lock before execution, providing thread-safe
    /// access to the method body. This is equivalent to marking a method with the
    /// `synchronized` keyword in some languages.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_synchronized() {
    ///         println!("Synchronized method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_synchronized(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::SYNCHRONIZED)
    }

    /// Returns true if the method preserves signature for P/Invoke.
    ///
    /// This checks the `MethodImplOptions::PRESERVE_SIG` flag to determine if the
    /// method signature should be preserved exactly as declared when calling into
    /// unmanaged code, rather than applying standard .NET marshalling transformations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_pinvoke() {
    ///         println!("P/Invoke method with preserved signature: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_pinvoke(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::PRESERVE_SIG)
    }

    /// Returns true if the method is an internal call.
    ///
    /// This checks the `MethodImplOptions::INTERNAL_CALL` flag to determine if the
    /// method is implemented internally by the runtime with special handling for
    /// parameter type checking and validation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let internal_methods: Vec<_> = assembly.methods().iter()
    ///     .filter(|entry| entry.value().is_internal_call())
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("Found {} internal call methods", internal_methods.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn is_internal_call(&self) -> bool {
        self.impl_options.contains(MethodImplOptions::INTERNAL_CALL)
    }

    /// Returns true if the method implementation is forwarded through P/Invoke.
    ///
    /// This checks the `MethodImplOptions::MAX_METHOD_IMPL_VAL` flag to determine
    /// if the method implementation is forwarded to an external library through
    /// the Platform Invoke (P/Invoke) mechanism.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_forwarded_pinvoke() {
    ///         println!("Forwarded P/Invoke method: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_forwarded_pinvoke(&self) -> bool {
        self.impl_options
            .contains(MethodImplOptions::MAX_METHOD_IMPL_VAL)
    }

    /// Returns true if the method is a constructor (.ctor or .cctor).
    #[must_use]
    pub fn is_constructor(&self) -> bool {
        self.name.starts_with(".ctor") || self.name.starts_with(".cctor")
    }

    /// Returns true if the method is an instance constructor (.ctor).
    #[must_use]
    pub fn is_ctor(&self) -> bool {
        self.name == ".ctor"
    }

    /// Returns true if the method is a static constructor (.cctor).
    #[must_use]
    pub fn is_cctor(&self) -> bool {
        self.name == ".cctor"
    }

    /// Returns true if the method has a parsed body.
    #[must_use]
    pub fn has_body(&self) -> bool {
        self.body.get().is_some()
    }

    /// Returns true if the method is static.
    #[must_use]
    pub fn is_static(&self) -> bool {
        self.flags_modifiers.contains(MethodModifiers::STATIC)
    }

    /// Returns true if the method is virtual.
    #[must_use]
    pub fn is_virtual(&self) -> bool {
        self.flags_modifiers.contains(MethodModifiers::VIRTUAL)
    }

    /// Returns true if the method is abstract.
    #[must_use]
    pub fn is_abstract(&self) -> bool {
        self.flags_modifiers.contains(MethodModifiers::ABSTRACT)
    }

    /// Returns the disambiguated reason for this method's RVA value.
    ///
    /// `Method.rva` is `Some(addr)` for methods with IL bodies and `None`
    /// for methods that legitimately have no IL (abstract, P/Invoke,
    /// runtime-managed) - but the bare `Option` cannot tell consumers *why*
    /// a method has no body. This accessor classifies by examining the
    /// method's `MethodModifiers` and `MethodImplCodeType` flags so callers
    /// can log a meaningful reason instead of treating "RVA = 0" as
    /// generic missing-data.
    ///
    /// The classification follows ECMA-335 §II.23.1.10: `ABSTRACT` and
    /// `PINVOKE_IMPL` are method-attribute bits (`MethodModifiers`), and the
    /// `RUNTIME` impl-code-type bits live in `MethodImplCodeType`. Variants
    /// are tested in priority order - `Abstract` first, then `PInvoke`, then
    /// `Runtime` - so a method tagged with multiple flags reports the most
    /// informative reason.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::method::MethodRvaKind;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let token = Token::new(0x06000001);
    ///
    /// if let Ok(method) = assembly.method(&token) {
    ///     match method.rva_kind() {
    ///         MethodRvaKind::Resolved(addr) => {
    ///             println!("IL at 0x{addr:08X}");
    ///         }
    ///         MethodRvaKind::Abstract => {
    ///             println!("abstract - no body in this assembly");
    ///         }
    ///         MethodRvaKind::PInvoke => {
    ///             println!("P/Invoke - body lives in a native module");
    ///         }
    ///         MethodRvaKind::Runtime => {
    ///             println!("runtime-managed - implemented by the CLR");
    ///         }
    ///         MethodRvaKind::UnresolvedZero => {
    ///             println!("RVA = 0 with no flag explanation; suspicious metadata");
    ///         }
    ///         _ => {}
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn rva_kind(&self) -> MethodRvaKind {
        if let Some(addr) = self.rva {
            return MethodRvaKind::Resolved(addr);
        }
        if self.flags_modifiers.contains(MethodModifiers::ABSTRACT) {
            return MethodRvaKind::Abstract;
        }
        if self.flags_modifiers.contains(MethodModifiers::PINVOKE_IMPL) {
            return MethodRvaKind::PInvoke;
        }
        if self.impl_code_type.contains(MethodImplCodeType::RUNTIME) {
            return MethodRvaKind::Runtime;
        }
        MethodRvaKind::UnresolvedZero
    }

    /// Returns true if the method has public access.
    #[must_use]
    pub fn is_public(&self) -> bool {
        self.flags_access == MethodAccessFlags::PUBLIC
    }

    /// Returns the declaring type as a strong reference, if available.
    ///
    /// This upgrades the internal weak reference to the declaring type,
    /// returning `None` if the type has been dropped or was never set.
    #[must_use]
    pub fn declaring_type_rc(&self) -> Option<CilTypeRc> {
        self.declaring_type.get().and_then(CilTypeRef::upgrade)
    }

    /// Returns the fully-qualified name of the declaring type, if available.
    #[must_use]
    pub fn declaring_type_fullname(&self) -> Option<String> {
        self.declaring_type_rc().map(|t| t.fullname().to_string())
    }

    /// Returns the fully-qualified method name in `"DeclaringType::MethodName"` format.
    ///
    /// If the declaring type is available and has a non-empty fullname, returns
    /// `"Namespace.TypeName::MethodName"`. Otherwise returns just the method name.
    #[must_use]
    pub fn fullname(&self) -> String {
        match self.declaring_type_fullname() {
            Some(type_name) if !type_name.is_empty() => format!("{}::{}", type_name, self.name),
            _ => self.name.clone(),
        }
    }

    /// Builds and returns the control flow graph for this method.
    ///
    /// The CFG is constructed from the method's basic blocks, providing graph-based
    /// access to control flow with support for dominator computation, loop detection,
    /// and various traversal algorithms.
    ///
    /// The returned CFG borrows the method's blocks (zero-copy). If you need an
    /// owned CFG that outlives the method, use [`into_owned()`](ControlFlowGraph::into_owned)
    /// on the result.
    ///
    /// # Returns
    ///
    /// A [`ControlFlowGraph`] for this method, or `None` if:
    /// - The method hasn't been disassembled yet
    /// - The method has no basic blocks (e.g., abstract or native methods)
    /// - CFG construction fails
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe. The CFG is built from a snapshot of the
    /// method's blocks at call time.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// for entry in assembly.methods().iter().take(5) {
    ///     let method = entry.value();
    ///     if let Some(cfg) = method.cfg() {
    ///         println!("Method: {} has {} blocks, {} loops",
    ///                  method.name, cfg.block_count(), cfg.loops().len());
    ///
    ///         // Access dominators
    ///         let dominators = cfg.dominators();
    ///         println!("  Entry dominates all: {}",
    ///                  cfg.node_ids().all(|n| cfg.dominates(cfg.entry(), n)));
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn cfg(&self) -> Option<ControlFlowGraph<'_>> {
        let blocks = self.blocks.get()?;
        if blocks.is_empty() {
            return None;
        }
        ControlFlowGraph::from_blocks_ref(blocks).ok()
    }

    /// Parse provided data, and extract additional information from the binary. e.g. Disassembly,
    /// method body, local variables, exception handlers, etc.
    ///
    /// # Arguments
    /// * `file`    - The input file
    /// * `blobs`   - The processed Blobs
    /// * `sigs`    - The table of signatures
    /// * `types`   - The type registry
    /// * `bodies`  - The bodies decoded so far in this load, shared by the methods naming them
    ///
    /// # Errors
    /// Returns an error if parsing fails or if referenced types/signatures cannot be resolved.
    pub fn parse(
        &self,
        file: &File,
        blobs: &Blob,
        sigs: Option<&MetadataTable<StandAloneSigRaw>>,
        types: &Arc<TypeRegistry>,
        bodies: &DecodedBodies,
    ) -> Result<()> {
        // Native and runtime methods don't have CIL method bodies - their RVA
        // points to x86/x64 machine code or runtime-provided implementations,
        // not to a CIL method header. Skip body parsing and IL decoding for these.
        let has_il_body = !self.is_code_native() && !self.is_code_runtime();
        if has_il_body {
            if let Some(rva) = self.rva {
                let body = self.parse_method_body(file, blobs, sigs, types, rva)?;
                self.body.set(body).ok();
            }
        }

        self.resolve_parameter_signatures(types)?;

        if has_il_body {
            assembly::decode_method(self, file, bodies)?;
        }
        Ok(())
    }

    /// Parses the method body including local variables and exception handlers.
    ///
    /// # Arguments
    /// * `file` - The input file
    /// * `blobs` - The blob heap
    /// * `sigs` - The standalone signatures table
    /// * `types` - The type registry
    /// * `rva` - The relative virtual address of the method
    ///
    /// # Errors
    /// Returns an error if the method body cannot be parsed or local variables cannot be resolved.
    fn parse_method_body(
        &self,
        file: &File,
        blobs: &Blob,
        sigs: Option<&MetadataTable<StandAloneSigRaw>>,
        types: &Arc<TypeRegistry>,
        rva: u32,
    ) -> Result<MethodBody> {
        // The runtimes read a body only within its section's VirtualSize
        let mut body = MethodBody::from(file.section_bounded(rva as usize)?)?;
        if body.local_var_sig_token != 0 {
            self.parse_local_variables(&body, blobs, sigs, types)?;
        }

        Self::resolve_exception_handlers(&mut body, types)?;
        Ok(body)
    }

    /// Parses local variable signatures and populates the local_vars collection.
    ///
    /// # Arguments
    /// * `body` - The method body containing the local var signature token
    /// * `blobs` - The blob heap
    /// * `sigs` - The standalone signatures table
    /// * `types` - The type registry
    ///
    /// # Errors
    /// Returns an error if the signature cannot be resolved or types cannot be found.
    fn parse_local_variables(
        &self,
        body: &MethodBody,
        blobs: &Blob,
        sigs: Option<&MetadataTable<StandAloneSigRaw>>,
        types: &Arc<TypeRegistry>,
    ) -> Result<()> {
        let Some(sigs_table) = sigs else {
            return Ok(());
        };

        let local_var_sig_data = match sigs_table.get(body.local_var_sig_token & 0x00FF_FFFF)? {
            Some(var_sig_row) => blobs.get(var_sig_row.signature as usize)?,
            None => {
                return Err(malformed_error!(
                    "Failed to resolve local variable signature - token 0x{:08X}",
                    body.local_var_sig_token
                ))
            }
        };

        let mut resolver = TypeResolver::new(types.clone());
        let local_var_sig = parse_local_var_signature(local_var_sig_data)?;

        for local_var in &local_var_sig.locals {
            let mut modifiers = Vec::with_capacity(local_var.modifiers.len());
            for var_mod in &local_var.modifiers {
                match types.get(&var_mod.modifier_type) {
                    Some(var_mod_type) => modifiers.push(CilModifier {
                        required: var_mod.is_required,
                        modifier: var_mod_type.into(),
                    }),
                    None => {
                        return Err(malformed_error!(
                            "Failed to resolve local variable modifier type - token 0x{:08X}",
                            var_mod.modifier_type.value()
                        ))
                    }
                }
            }

            self.local_vars.push(LocalVariable {
                modifiers,
                is_byref: local_var.is_byref,
                is_pinned: local_var.is_pinned,
                base: resolver.resolve(&local_var.base)?.into(),
            });
        }

        Ok(())
    }

    /// Resolves exception handler types for catch blocks.
    ///
    /// For EXCEPTION handlers, this resolves the type token stored in `filter_offset`
    /// to the actual type reference and clears the offset field.
    ///
    /// # Arguments
    /// * `body` - The method body with exception handlers to resolve
    /// * `types` - The type registry
    ///
    /// # Errors
    /// Returns an error if an exception type cannot be resolved.
    fn resolve_exception_handlers(body: &mut MethodBody, types: &Arc<TypeRegistry>) -> Result<()> {
        for (index, exception_handler) in body.exception_handlers.iter_mut().enumerate() {
            if exception_handler.flags == ExceptionHandlerFlags::EXCEPTION {
                let type_token = Token::new(exception_handler.filter_offset);
                let Some(handler_type) = types.get(&type_token) else {
                    return Err(malformed_error!(
                        "Failed to resolve exception handler {} type - token 0x{:08X}",
                        index,
                        exception_handler.filter_offset
                    ));
                };

                exception_handler.handler = Some(handler_type);
                exception_handler.filter_offset = 0;
            }
        }

        Ok(())
    }

    /// Resolves parameter signatures from the method signature.
    ///
    /// Maps each parameter from the Param table to its corresponding type
    /// information from the method signature.
    ///
    /// # Arguments
    /// * `types` - The type registry
    ///
    /// # Errors
    /// Returns an error if a parameter signature cannot be applied.
    fn resolve_parameter_signatures(&self, types: &Arc<TypeRegistry>) -> Result<()> {
        let method_param_count = Some(self.signature.params.len());

        for (_, parameter) in self.params.iter() {
            if parameter.sequence == 0 {
                // Sequence 0 is the return value
                parameter.apply_signature(
                    &self.signature.return_type,
                    types.clone(),
                    method_param_count,
                )?;
            } else {
                // Regular parameters (1-indexed in metadata)
                let index = parameter
                    .sequence
                    .checked_sub(1)
                    .ok_or_else(|| malformed_error!("Parameter sequence underflow"))?
                    as usize;
                if let Some(param_signature) = self.signature.params.get(index) {
                    parameter.apply_signature(
                        param_signature,
                        types.clone(),
                        method_param_count,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Checks if this method appears to be an event handler based on its signature.
    ///
    /// Event handlers typically follow a specific pattern:
    /// - Name starts with "On" or ends with "Handler", "_Click", "_Load", "_Changed"
    /// - Takes exactly 2 parameters (sender and event args)
    /// - Returns void
    ///
    /// This heuristic is useful for deobfuscation to identify methods that are likely
    /// entry points or callbacks that should be preserved.
    ///
    /// # Returns
    ///
    /// `true` if the method matches the event handler pattern.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if method.is_event_handler() {
    ///         println!("Event handler: {}", method.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_event_handler(&self) -> bool {
        // Check for typical event handler patterns:
        // 1. Name patterns (OnX, X_Handler, etc.)
        let has_handler_name = self.name.starts_with("On")
            || self.name.ends_with("Handler")
            || self.name.ends_with("_Click")
            || self.name.ends_with("_Load")
            || self.name.ends_with("_Changed")
            || self.name.contains('_');

        // 2. Parameter count (typically 2: sender + event args)
        let has_two_params = self.signature.params.len() == 2;

        // 3. Void return type is typical but not required
        let is_void = matches!(self.signature.return_type.base, TypeSignature::Void);

        // A method is likely an event handler if it has the naming pattern
        // and the right parameter count
        has_handler_name && has_two_params && is_void
    }

    /// Builds and returns the SSA (Static Single Assignment) form for this method.
    ///
    /// SSA form is a program representation where each variable is assigned exactly
    /// once and defined before it is used. This is useful for dataflow analysis,
    /// optimization, and deobfuscation.
    ///
    /// The SSA is built from the method's control flow graph, using the method's
    /// parameter count and local variable count to properly set up the function.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The [`CilObject`] containing this method for resolving method
    ///   signatures in call instructions. This enables correct argument tracking for
    ///   call/callvirt/newobj instructions.
    ///
    /// # Returns
    ///
    /// An [`SsaFunction`] representing this method in SSA form.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The method has no basic blocks or control flow graph
    /// - SSA construction fails (e.g., unresolvable `calli` signature)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for entry in assembly.methods().iter().take(5) {
    ///     let method = entry.value();
    ///     match method.ssa(&assembly) {
    ///         Ok(ssa) => println!("Method {} has {} SSA blocks",
    ///                             method.name, ssa.block_count()),
    ///         Err(e) => eprintln!("SSA construction failed for {}: {}", method.name, e),
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn ssa(&self, assembly: &CilObject) -> Result<SsaFunction> {
        let blocks = self.blocks.get().ok_or_else(|| {
            SsaError(format!(
                "Method {} (0x{:08X}) has no basic blocks",
                self.name,
                self.token.value()
            ))
        })?;

        // Get CFG from method
        let cfg = self.cfg().ok_or_else(|| {
            SsaError(format!(
                "Method {} (0x{:08X}) has no control flow graph",
                self.name,
                self.token.value()
            ))
        })?;

        // Compute argument and local counts
        let num_args = self
            .signature
            .params
            .len()
            .saturating_add(usize::from(self.signature.has_this));
        let declared_locals = self.local_vars.count();

        // If no locals are declared (e.g., Tiny Format method body), infer from IL usage.
        // Some obfuscators (JIEJIE.NET) emit Tiny Format methods that use stloc/ldloc
        // without a LocalVarSig - technically invalid per ECMA-335 §II.25.4.1, but the
        // CLR tolerates it by implicitly allocating locals.
        let num_locals = if declared_locals == 0 {
            Self::infer_local_count_from_blocks(blocks)
        } else {
            declared_locals
        };

        // Create type context for type lookup during SSA construction
        let type_context = TypeContext::new(self, assembly);

        // The exception table first, because construction reads it: where
        // control can enter decides where the dominator walk is rooted, which
        // blocks are reachable, and what a phi at a handler entry merges.
        let ssa_handlers = self.ssa_exception_handlers(blocks)?;

        // Build SSA from CFG with type context (also sets original local types)
        let ssa = SsaConverter::build(&cfg, num_args, num_locals, &type_context, ssa_handlers)?;

        Ok(ssa)
    }

    /// Maps the method body's exception clauses onto block ranges.
    ///
    /// The IL table addresses its regions by byte offset and everything above
    /// addresses blocks by index, so this is where the two meet. A clause whose
    /// parts cannot both be resolved to a block range contributes nothing
    /// rather than a half-stated region: a start without an end describes
    /// nothing an IL table could be regenerated from.
    ///
    /// # Arguments
    ///
    /// * `blocks` - The method's basic blocks, in layout order.
    ///
    /// # Returns
    ///
    /// One [`SsaExceptionHandler`] per clause, empty when the body has none.
    ///
    /// # Errors
    ///
    /// Returns an error when a clause's offsets overflow.
    fn ssa_exception_handlers(&self, blocks: &[BasicBlock]) -> Result<Vec<SsaExceptionHandler>> {
        match self.body.get() {
            Some(body) => Self::ssa_handlers_for_clauses(&body.exception_handlers, blocks),
            None => Ok(Vec::new()),
        }
    }

    /// Maps exception clauses onto the block ranges SSA construction reads.
    ///
    /// The clause table addresses its regions by byte offset and SSA addresses
    /// blocks by index, so this is where the two meet. A clause whose parts
    /// cannot both be resolved to a block range contributes nothing rather than
    /// a half-stated region: a start without an end describes nothing an IL
    /// table could be regenerated from.
    ///
    /// For code decoded outside a method - by
    /// [`decode_blocks_with_handlers`](crate::assembly::decode_blocks_with_handlers),
    /// say - this is the step between decoding and
    /// [`SsaConverter::build`](crate::analysis::SsaConverter::build).
    ///
    /// # Arguments
    ///
    /// * `clauses` - The exception clauses, offsets relative to the first block.
    /// * `blocks` - The blocks they cover, in layout order, decoded with the
    ///   clauses so that each handler entry is a block.
    ///
    /// # Returns
    ///
    /// One [`SsaExceptionHandler`] per clause.
    ///
    /// # Errors
    ///
    /// Returns an error when a clause's offsets overflow.
    pub fn ssa_handlers_for_clauses(
        clauses: &[ExceptionHandler],
        blocks: &[BasicBlock],
    ) -> Result<Vec<SsaExceptionHandler>> {
        if clauses.is_empty() {
            return Ok(Vec::new());
        }
        {
            {
                // Exception handler offsets are relative to method body start.
                // Block offsets are absolute file offsets. Get base offset from first block.
                let base_offset = blocks.first().map_or(0, |b| b.offset);

                let mut ssa_handlers: Vec<SsaExceptionHandler> = Vec::with_capacity(clauses.len());
                for (handler_idx, eh) in clauses.iter().enumerate() {
                    let try_offset_abs = base_offset
                        .checked_add(eh.try_offset as usize)
                        .ok_or_else(|| malformed_error!("Exception handler try_offset overflow"))?;
                    let try_end_rel = (eh.try_offset as usize)
                        .checked_add(eh.try_length as usize)
                        .ok_or_else(|| malformed_error!("Exception handler try region overflow"))?;
                    let try_end_abs = base_offset
                        .checked_add(try_end_rel)
                        .ok_or_else(|| malformed_error!("Exception handler try end overflow"))?;
                    let handler_offset_abs = base_offset
                        .checked_add(eh.handler_offset as usize)
                        .ok_or_else(|| {
                            malformed_error!("Exception handler handler_offset overflow")
                        })?;
                    let handler_end_rel = (eh.handler_offset as usize)
                        .checked_add(eh.handler_length as usize)
                        .ok_or_else(|| malformed_error!("Exception handler region overflow"))?;
                    let handler_end_abs = base_offset
                        .checked_add(handler_end_rel)
                        .ok_or_else(|| malformed_error!("Exception handler end overflow"))?;

                    // Map offsets to block indices (add base_offset to convert relative to absolute)
                    let try_start_block = Self::find_block_at_offset(blocks, try_offset_abs);
                    let try_end_block = Some(Self::find_region_end_block(blocks, try_end_abs));

                    // The filter expression is resolved first because the handler's own
                    // start depends on it: the decoder marks the filter's entry block with
                    // the same handler index as the handler body's, and the filter comes
                    // first in layout order, so a search by index alone answers with the
                    // filter block for every filter clause.
                    let filter_start_block = if eh.flags.kind() == ExceptionHandlerKind::Filter {
                        let filter_offset_abs = base_offset
                            .checked_add(eh.filter_offset as usize)
                            .ok_or_else(|| {
                                malformed_error!("Exception handler filter_offset overflow")
                            })?;
                        Self::find_block_at_offset(blocks, filter_offset_abs)
                    } else {
                        None
                    };

                    // For handler blocks, use the handler_entry info from decoder if available
                    let handler_start_block =
                        Self::find_handler_entry_block(blocks, handler_idx, filter_start_block)
                            .or_else(|| Self::find_block_at_offset(blocks, handler_offset_abs));
                    let handler_end_block =
                        Some(Self::find_region_end_block(blocks, handler_end_abs));

                    // Get the class token for catch handlers
                    let class_token_or_filter = match eh.flags.kind() {
                        // The resolved type's token, or the raw clause field
                        // when the type was not resolved: a catch clause stores
                        // its class token in the same slot a filter stores its
                        // offset.
                        ExceptionHandlerKind::Catch => eh
                            .handler
                            .as_ref()
                            .map_or(eh.filter_offset, |t| t.token.value()),
                        ExceptionHandlerKind::Filter => eh.filter_offset,
                        ExceptionHandlerKind::Finally | ExceptionHandlerKind::Fault => 0,
                    };

                    // Each part is a half-open block range or nothing at all: a start
                    // without an end never described a region anyone could regenerate an
                    // IL table from, and `BlockRange` makes that state unrepresentable.
                    let range = |start: Option<usize>, end: Option<usize>| {
                        start.zip(end).and_then(|(s, e)| BlockRange::new(s, e))
                    };

                    ssa_handlers.push(SsaExceptionHandler {
                        flags: eh.flags,
                        try_offset: eh.try_offset,
                        try_length: eh.try_length,
                        handler_offset: eh.handler_offset,
                        handler_length: eh.handler_length,
                        class_token_or_filter,
                        protected_range: range(try_start_block, try_end_block),
                        handler_range: range(handler_start_block, handler_end_block),
                        // A CIL filter expression occupies [filter_offset, handler_offset),
                        // so its exclusive end is wherever the handler begins. Taking the
                        // handler's resolved start rather than re-deriving one from
                        // `handler_offset_abs` keeps the two parts from claiming the same
                        // block when the decoder's marker and the IL offset disagree - an
                        // overlap analyssa reports as a malformed clause.
                        filter_range: range(filter_start_block, handler_start_block),
                    });
                }

                Ok(ssa_handlers)
            }
        }
    }

    /// Infers the number of local variables from IL usage in the basic blocks.
    ///
    /// Scans all instructions for `stloc`/`ldloc`/`ldloca` opcodes and returns
    /// `max_index + 1`. Returns 0 if no local variable instructions are found.
    ///
    /// This handles Tiny Format method bodies that use locals without declaring
    /// a LocalVarSig token - technically invalid per ECMA-335 §II.25.4.1, but
    /// tolerated by the CLR.
    fn infer_local_count_from_blocks(blocks: &[BasicBlock]) -> usize {
        let mut max_index: Option<usize> = None;

        for block in blocks {
            for instr in &block.instructions {
                let idx = if instr.prefix == 0 {
                    match instr.opcode {
                        // Short forms: index encoded in the opcode
                        assembly::opcodes::LDLOC_0 | assembly::opcodes::STLOC_0 => Some(0),
                        assembly::opcodes::LDLOC_1 | assembly::opcodes::STLOC_1 => Some(1),
                        assembly::opcodes::LDLOC_2 | assembly::opcodes::STLOC_2 => Some(2),
                        assembly::opcodes::LDLOC_3 | assembly::opcodes::STLOC_3 => Some(3),
                        // Byte-index forms: index in operand
                        assembly::opcodes::LDLOC_S
                        | assembly::opcodes::LDLOCA_S
                        | assembly::opcodes::STLOC_S => match &instr.operand {
                            assembly::Operand::Local(idx) => Some(*idx as usize),
                            _ => None,
                        },
                        _ => None,
                    }
                } else if instr.prefix == 0xFE {
                    match instr.opcode {
                        // Two-byte forms (0xFE prefix): u16 index in operand
                        assembly::opcodes::FE_LDLOC
                        | assembly::opcodes::FE_LDLOCA
                        | assembly::opcodes::FE_STLOC => match &instr.operand {
                            assembly::Operand::Local(idx) => Some(*idx as usize),
                            _ => None,
                        },
                        _ => None,
                    }
                } else {
                    None
                };

                if let Some(i) = idx {
                    max_index = Some(max_index.map_or(i, |prev| prev.max(i)));
                }
            }
        }

        max_index.map_or(0, |i| i.saturating_add(1))
    }

    /// Finds the block index that starts at or contains the given offset.
    fn find_block_at_offset(blocks: &[BasicBlock], offset: usize) -> Option<usize> {
        // First try exact match (block starting at this offset)
        if let Some(idx) = blocks.iter().position(|b| b.offset == offset) {
            return Some(idx);
        }

        // If no exact match, find block containing the offset
        blocks
            .iter()
            .position(|b| offset >= b.offset && offset < b.offset.saturating_add(b.size))
    }

    /// Finds the exclusive end block of a region ending at `offset`.
    ///
    /// `offset` is one past the region's last IL byte, so the answer is the first
    /// block at or after it. Usually one begins exactly there. When none does, the
    /// bytes after the region are ones nothing reaches - an obfuscator's junk
    /// after an `endfinally`, which decoding by control flow never turns into a
    /// block - and the region still ends where the next decoded block begins. A
    /// region running to the end of the method body ends one past the last block.
    ///
    /// Blocks are in layout order. A block that straddles `offset` is taken as
    /// the end, as a region boundary never falls inside a decoded block.
    fn find_region_end_block(blocks: &[BasicBlock], offset: usize) -> usize {
        Self::find_block_at_offset(blocks, offset).unwrap_or_else(|| {
            blocks
                .iter()
                .position(|b| b.offset >= offset)
                .unwrap_or(blocks.len())
        })
    }

    /// Finds the block that is marked as an entry point for the given handler index.
    ///
    /// A filter clause marks two blocks with the same handler index - the filter
    /// expression's entry and the handler body's - and the filter is laid out
    /// first, so `filter_block` names the one to skip. Without it the handler
    /// body of every filter clause would resolve to its filter expression.
    fn find_handler_entry_block(
        blocks: &[BasicBlock],
        handler_index: usize,
        filter_block: Option<usize>,
    ) -> Option<usize> {
        blocks.iter().enumerate().find_map(|(idx, b)| {
            let marks_this_handler = b
                .handler_entry
                .as_ref()
                .is_some_and(|info| info.handler_index == handler_index);
            (marks_this_handler && Some(idx) != filter_block).then_some(idx)
        })
    }

    /// Extracts the local variable types in signature format for code generation.
    ///
    /// This converts the resolved `LocalVariable` types back to `SignatureLocalVariable`
    /// format, preserving the modifier semantics (required vs optional) that are needed
    /// for correct signature encoding.
    ///
    /// # Returns
    ///
    /// `Some(Vec<SignatureLocalVariable>)` if all local variables could be converted,
    /// `None` if the method has no locals or conversion failed.
    #[must_use]
    pub fn get_local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        if self.local_vars.is_empty() {
            return None;
        }

        // Convert each LocalVariable to SignatureLocalVariable
        // Note: boxcar::Vec::iter() yields (index, &value) tuples
        self.local_vars
            .iter()
            .map(|(_, local)| local.to_signature_local())
            .collect()
    }

    /// Encodes the method body to a byte vector (ECMA-335 II.25.4), ready for a PE file's
    /// `.text` section: the header as it was read (its format, its declared stack depth,
    /// which the instructions alone cannot recompute since a call's stack effect is its
    /// signature's), the instructions of every block at their places in the code, and the
    /// exception section as it was laid out. Bytes no block covers, code no path reaches,
    /// are written as `nop`s.
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the complete encoded method body,
    /// or `Err` if the method has no body or encoding fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The method has no body (abstract, native, or runtime methods)
    /// - Instruction encoding fails
    /// - Exception handler encoding fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("test.dll"))?;
    /// for entry in assembly.methods().iter() {
    ///     let method = entry.value();
    ///     if let Ok(bytes) = method.encode_body() {
    ///         println!("Method {} encoded to {} bytes", method.name, bytes.len());
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode_body(&self) -> Result<Vec<u8>> {
        // Get the method body - if no body, this is an abstract/native/runtime method
        let body = self
            .body
            .get()
            .ok_or_else(|| malformed_error!("Method {} has no body to encode", self.name))?;

        // Get the basic blocks containing instructions
        let blocks = self
            .blocks
            .get()
            .ok_or_else(|| malformed_error!("Method {} has no decoded blocks", self.name))?;

        // The instructions of every block, each at its place in the code, where the exception
        // handlers' offsets find them. Bytes no block covers (code no path reaches) are not
        // kept with the method: they are written as `nop`s.
        let instructions: Vec<_> = blocks
            .iter()
            .flat_map(|block| block.instructions.iter().cloned())
            .collect();
        let code_rva = instructions
            .iter()
            .map(|instruction| instruction.rva)
            .min()
            .unwrap_or_default();
        let il_code = InstructionEncoder::encode_decoded(
            &instructions,
            &vec![0x00; body.size_code],
            code_rva,
        )?;

        // The body as it was read: its header format, its exception section's layout and its
        // declared stack depth, which the instructions alone cannot recompute (a call's
        // effect on the stack is its signature's)
        let mut result = Vec::new();
        body.write_to(&mut result, &il_code)?;
        Ok(result)
    }

    /// The size [`Self::encode_body`] encodes the method body to, in bytes: header, code,
    /// alignment padding and exception section.
    ///
    /// # Returns
    ///
    /// `None` when the method has no body or it does not encode.
    #[must_use]
    pub fn encoded_size(&self) -> Option<usize> {
        self.encode_body().ok().map(|bytes| bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assembly::{
            BasicBlock, FlowType, Instruction, InstructionCategory, Operand, StackBehavior,
        },
        testkit::builders::MethodBuilder,
    };

    #[test]
    fn test_instructions_iterator_empty_method() {
        // Create a method with no basic blocks
        let blocks = Vec::new();
        let method = create_test_method(blocks);

        let mut instruction_count = 0;
        for _instruction in method.instructions() {
            instruction_count += 1;
        }

        assert_eq!(instruction_count, 0);
        assert_eq!(method.instruction_count(), 0);
    }

    /// A block of `size` bytes at `offset`, for clause-mapping tests.
    fn block_at(id: usize, offset: usize, size: usize) -> BasicBlock {
        let mut block = BasicBlock::new(id, 0x1000 + offset as u64, offset);
        block.size = size;
        block
    }

    #[test]
    fn a_handler_ending_before_undecoded_bytes_keeps_its_range() {
        // try [0x00, 0x10), finally [0x10, 0x16), then junk nothing reaches up
        // to the leave target at 0x20. No block begins where the handler ends,
        // and the handler still ends there.
        let blocks = vec![
            block_at(0, 0x00, 0x10),
            block_at(1, 0x10, 0x06),
            block_at(2, 0x20, 0x05),
        ];
        let clause = ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset: 0x00,
            try_length: 0x10,
            handler_offset: 0x10,
            handler_length: 0x06,
            handler: None,
            filter_offset: 0,
        };

        let handlers = Method::ssa_handlers_for_clauses(&[clause], &blocks).unwrap();
        let handler = &handlers[0];
        assert_eq!(
            handler.protected_range.map(|r| (r.start(), r.end())),
            Some((0, 1))
        );
        assert_eq!(
            handler.handler_range.map(|r| (r.start(), r.end())),
            Some((1, 2)),
            "a handler whose end falls in a gap must not lose its range"
        );
    }

    #[test]
    fn test_instructions_iterator_single_block() {
        // Create a method with one basic block containing multiple instructions
        let block = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 10,
            instructions: vec![
                create_test_instruction(0x00, "nop"),     // nop
                create_test_instruction(0x02, "ldarg.0"), // ldarg.0
                create_test_instruction(0x2A, "ret"),     // ret
            ],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        };

        let blocks = vec![block];
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 3);
        assert_eq!(method.instruction_count(), 3);

        // Verify the instructions are returned in order
        assert_eq!(instructions[0].mnemonic, "nop");
        assert_eq!(instructions[1].mnemonic, "ldarg.0");
        assert_eq!(instructions[2].mnemonic, "ret");
    }

    #[test]
    fn test_instructions_iterator_multiple_blocks() {
        // Create a method with multiple basic blocks
        let block1 = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 5,
            instructions: vec![
                create_test_instruction(0x02, "ldarg.0"),
                create_test_instruction(0x03, "ldarg.1"),
            ],
            predecessors: vec![],
            successors: vec![1],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        };

        let block2 = BasicBlock {
            id: 1,
            rva: 0x1010,
            offset: 5,
            size: 5,
            instructions: vec![
                create_test_instruction(0x58, "add"),
                create_test_instruction(0x2A, "ret"),
            ],
            predecessors: vec![0],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        };

        let blocks = vec![block1, block2];
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 4);
        assert_eq!(method.instruction_count(), 4);

        // Verify the instructions are returned in block order
        assert_eq!(instructions[0].mnemonic, "ldarg.0");
        assert_eq!(instructions[1].mnemonic, "ldarg.1");
        assert_eq!(instructions[2].mnemonic, "add");
        assert_eq!(instructions[3].mnemonic, "ret");
    }

    #[test]
    fn test_instruction_iterator_size_hint() {
        let block = BasicBlock {
            id: 0,
            rva: 0x1000,
            offset: 0,
            size: 3,
            instructions: vec![
                create_test_instruction(0x00, "nop"),
                create_test_instruction(0x00, "nop"),
                create_test_instruction(0x2A, "ret"),
            ],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        };

        let blocks = vec![block];
        let method = create_test_method(blocks);
        let mut iter = method.instructions();

        // Initial size hint should be (3, Some(3))
        assert_eq!(iter.size_hint(), (3, Some(3)));

        // After consuming one instruction
        iter.next();
        assert_eq!(iter.size_hint(), (2, Some(2)));

        // After consuming all instructions
        iter.next();
        iter.next();
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    // Helper function to create a test method with the given blocks
    fn create_test_method(blocks: Vec<BasicBlock>) -> MethodRc {
        let method = MethodBuilder::new().with_name("TestMethod").build();

        // Set the blocks in the method (this is test-specific setup)
        method.blocks.set(blocks).ok();

        method
    }

    // Helper function to create a test instruction
    fn create_test_instruction(opcode: u8, mnemonic: &'static str) -> Instruction {
        Instruction {
            rva: 0x1000,
            offset: 0,
            size: 1,
            opcode,
            prefix: 0,
            mnemonic,
            category: InstructionCategory::Misc,
            flow_type: FlowType::Sequential,
            operand: Operand::None,
            stack_behavior: StackBehavior {
                pops: 0,
                pushes: 0,
                net_effect: 0,
            },
            branch_targets: vec![],
        }
    }

    // Helper function to create an empty basic block
    fn create_empty_block(id: usize) -> BasicBlock {
        BasicBlock {
            id,
            rva: 0x1000 + (id as u64 * 0x10),
            offset: id * 10,
            size: 0,
            instructions: vec![],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        }
    }

    #[test]
    fn test_instructions_iterator_with_empty_blocks() {
        // Test that the iterator handles empty blocks correctly (MTH-H001 fix verification)
        let block1 = create_empty_block(0);
        let block2 = BasicBlock {
            id: 1,
            rva: 0x1010,
            offset: 10,
            size: 3,
            instructions: vec![
                create_test_instruction(0x00, "nop"),
                create_test_instruction(0x2A, "ret"),
            ],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        };
        let block3 = create_empty_block(2);

        let blocks = vec![block1, block2, block3];
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 2);
        assert_eq!(instructions[0].mnemonic, "nop");
        assert_eq!(instructions[1].mnemonic, "ret");
    }

    #[test]
    fn test_instructions_iterator_many_empty_blocks() {
        // Stress test: many consecutive empty blocks should not cause stack overflow
        // This verifies the MTH-H001 fix (recursive -> iterative)
        let mut blocks: Vec<BasicBlock> = (0..100).map(create_empty_block).collect();

        // Add one block with instructions at the end
        blocks.push(BasicBlock {
            id: 100,
            rva: 0x2000,
            offset: 1000,
            size: 1,
            instructions: vec![create_test_instruction(0x2A, "ret")],
            predecessors: vec![],
            successors: vec![],
            exceptions: vec![],
            handler_entry: None,
            exception_successors: vec![],
        });

        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].mnemonic, "ret");
    }

    #[test]
    fn test_instructions_iterator_all_empty_blocks() {
        // Edge case: all blocks are empty
        let blocks: Vec<BasicBlock> = (0..10).map(create_empty_block).collect();
        let method = create_test_method(blocks);

        let instructions: Vec<_> = method.instructions().collect();
        assert_eq!(instructions.len(), 0);
        assert_eq!(method.instruction_count(), 0);
    }

    #[test]
    fn test_method_ref_basic_operations() {
        let method = MethodBuilder::new().with_name("TestMethod").build();

        let method_ref = MethodRef::new(&method);

        // Test is_valid
        assert!(method_ref.is_valid());

        // Test upgrade
        let upgraded = method_ref.upgrade();
        assert!(upgraded.is_some());
        assert_eq!(upgraded.unwrap().name, "TestMethod");

        // Test token - uses the default token from MethodBuilder (rid=1 => 0x06000001)
        assert_eq!(method_ref.token(), Some(Token::new(0x06000001)));

        // Test name
        assert_eq!(method_ref.name(), Some("TestMethod".to_string()));
    }

    #[test]
    fn test_method_ref_after_drop() {
        let method_ref = {
            let method = MethodBuilder::new().with_name("TemporaryMethod").build();
            MethodRef::new(&method)
            // method is dropped here
        };

        // After the method is dropped, MethodRef should return None/false
        assert!(!method_ref.is_valid());
        assert!(method_ref.upgrade().is_none());
        assert!(method_ref.token().is_none());
        assert!(method_ref.name().is_none());
    }

    #[test]
    fn test_method_is_constructor() {
        let ctor = MethodBuilder::new().with_name(".ctor").build();
        let cctor = MethodBuilder::new().with_name(".cctor").build();
        let regular = MethodBuilder::new().with_name("DoSomething").build();

        assert!(ctor.is_constructor());
        assert!(cctor.is_constructor());
        assert!(!regular.is_constructor());
    }

    #[test]
    fn test_is_forwarded_pinvoke() {
        // Test that the renamed method works correctly
        let method = MethodBuilder::new().with_name("TestMethod").build();

        // Default method should not have forwarded pinvoke flag
        assert!(!method.is_forwarded_pinvoke());
    }

    #[test]
    fn test_method_rva_kind() {
        // Default: rva = Some(0x1000) → Resolved.
        let resolved = MethodBuilder::new().with_rva(0x1234).build();
        assert_eq!(resolved.rva_kind(), MethodRvaKind::Resolved(0x1234));

        // Abstract: no rva, ABSTRACT modifier set.
        let abstract_m = MethodBuilder::new()
            .without_rva()
            .with_modifiers(MethodModifiers::ABSTRACT)
            .build();
        assert_eq!(abstract_m.rva_kind(), MethodRvaKind::Abstract);

        // P/Invoke: no rva, PINVOKE_IMPL modifier set.
        let pinvoke = MethodBuilder::new()
            .without_rva()
            .with_modifiers(MethodModifiers::PINVOKE_IMPL)
            .build();
        assert_eq!(pinvoke.rva_kind(), MethodRvaKind::PInvoke);

        // Runtime: no rva, MethodImplCodeType::RUNTIME.
        let runtime = MethodBuilder::new()
            .without_rva()
            .with_impl_code_type(MethodImplCodeType::RUNTIME)
            .build();
        assert_eq!(runtime.rva_kind(), MethodRvaKind::Runtime);

        // UnresolvedZero: no rva, no flag explanation - malformed metadata.
        let unresolved = MethodBuilder::new().without_rva().build();
        assert_eq!(unresolved.rva_kind(), MethodRvaKind::UnresolvedZero);

        // Priority: when both ABSTRACT and a runtime-managed flag are set,
        // Abstract takes precedence (it's the most informative reason).
        let abstract_runtime = MethodBuilder::new()
            .without_rva()
            .with_modifiers(MethodModifiers::ABSTRACT)
            .with_impl_code_type(MethodImplCodeType::RUNTIME)
            .build();
        assert_eq!(abstract_runtime.rva_kind(), MethodRvaKind::Abstract);
    }

    #[test]
    fn test_method_rva_kind_stable_strings() {
        // Strings are part of the stable public API.
        assert_eq!(MethodRvaKind::Resolved(0).as_str(), "resolved");
        assert_eq!(MethodRvaKind::Abstract.as_str(), "abstract");
        assert_eq!(MethodRvaKind::PInvoke.as_str(), "pinvoke");
        assert_eq!(MethodRvaKind::Runtime.as_str(), "runtime");
        assert_eq!(MethodRvaKind::UnresolvedZero.as_str(), "unresolved_zero");

        // Display renders Resolved with the address; other variants delegate to as_str.
        assert_eq!(
            format!("{}", MethodRvaKind::Resolved(0x1234)),
            "resolved(0x00001234)"
        );
        assert_eq!(format!("{}", MethodRvaKind::Abstract), "abstract");
        assert_eq!(
            format!("{}", MethodRvaKind::UnresolvedZero),
            "unresolved_zero"
        );
    }
}
