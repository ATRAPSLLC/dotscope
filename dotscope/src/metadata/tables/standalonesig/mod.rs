//! # `StandAloneSig` Table Module
//!
//! This module provides comprehensive access to the `StandAloneSig` metadata table (ID 0x11),
//! which contains standalone signatures that are not directly associated with specific
//! methods, fields, or properties. These signatures support complex scenarios including
//! method pointers, local variables, and dynamic signature generation in .NET assemblies.
//!
//! ## Table Purpose
//!
//! The `StandAloneSig` table provides:
//! - **Method Signatures**: Standalone method pointer and delegate signatures
//! - **Local Variable Signatures**: Local variable type declarations for methods
//! - **Dynamic Signatures**: Runtime signature generation and manipulation support
//! - **CIL Instruction Support**: Signatures referenced by CIL instructions and opcodes
//!
//! ## Module Structure
//!
//! The module follows the standard dual-variant pattern for metadata tables:
//!
//! ### Raw Variant (`StandAloneSigRaw`)
//! - Direct memory representation of table entries
//! - Contains unresolved blob indexes to signature data
//! - Minimal processing overhead during initial parsing
//! - Used for memory-efficient storage and initial metadata loading
//!
//! ### Owned Variant (`StandAloneSig`)
//! - Fully processed and validated table entries
//! - Contains parsed signature data and resolved type references
//! - Provides high-level access methods and validation
//! - Used for application logic and signature analysis operations
//!
//! ## Signature Types and Architecture
//!
//! `StandAloneSig` entries can contain various signature types:
//! - **Method Signatures**: Function pointer signatures with calling conventions
//! - **Local Variable Signatures**: Method local variable type declarations
//! - **Field Signatures**: Standalone field type specifications
//! - **Generic Signatures**: Generic type and method instantiation signatures
//!
//! ## Signature Parsing and Validation
//!
//! `StandAloneSig` entries undergo comprehensive parsing:
//! - **Blob Validation**: Ensures signature blob format compliance
//! - **Type Resolution**: Resolves all type references within signatures
//! - **Generic Validation**: Validates generic parameter constraints
//! - **Calling Convention**: Validates method calling conventions and parameter types
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.39 - `StandAloneSig` table specification
//! - [`crate::metadata::signatures`] - Signature parsing and types
//! - [`crate::metadata::streams::Blob`] - Blob stream access for signature data

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod owned;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use owned::*;
pub use raw::*;

/// Concurrent map for standalone signature storage indexed by metadata token.
///
/// Uses a lock-free skip list for high-performance concurrent access to standalone
/// signature entries. The map supports efficient lookup, insertion, and iteration
/// operations across multiple threads.
pub type StandAloneSigMap = SkipMap<Token, StandAloneSigRc>;

/// Thread-safe collection of standalone signature entries.
///
/// Provides a growable vector implementation optimized for concurrent access
/// patterns, supporting efficient signature enumeration and batch operations.
pub type StandAloneSigList = Arc<boxcar::Vec<StandAloneSigRc>>;

/// Type alias for shared ownership of [`StandAloneSig`] entries.
///
/// Provides thread-safe reference counting for standalone signature entries,
/// enabling efficient sharing across multiple consumers without data duplication.
pub type StandAloneSigRc = Arc<StandAloneSig>;
