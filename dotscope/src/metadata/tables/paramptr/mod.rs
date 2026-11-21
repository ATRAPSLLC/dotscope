//! # `ParamPtr` Table Module
//!
//! This module provides comprehensive access to the `ParamPtr` metadata table (ID 0x04),
//! which serves as an indirection mechanism for parameter table entries in optimized
//! metadata layouts. The `ParamPtr` table enables parameter table compression and
//! reordering while maintaining logical parameter access patterns.
//!
//! ## Table Purpose
//!
//! The `ParamPtr` table provides:
//! - **Indirection**: Maps logical parameter indexes to physical parameter locations
//! - **Optimization**: Enables parameter table compression in optimized metadata
//! - **Flexibility**: Allows parameter reordering without breaking logical references
//! - **Efficiency**: Supports efficient parameter lookup in compressed assemblies
//!
//! ## Module Structure
//!
//! The module follows the standard dual-variant pattern for metadata tables:
//!
//! ### Raw Variant (`ParamPtrRaw`)
//! - Direct memory representation of table entries
//! - Minimal processing overhead during initial parsing
//! - Contains unresolved references requiring further processing
//! - Used for memory-efficient storage and initial metadata loading
//!
//! ### Owned Variant (`ParamPtr`)
//! - Fully processed and validated table entries
//! - Contains resolved references and complete parameter information
//! - Provides high-level access methods and validation
//! - Used for application logic and metadata analysis
//!
//! ## References
//!
//! - ECMA-335, Partition II, §22.26 - `ParamPtr` table specification
//! - [`crate::metadata::tables::Param`] - Target parameter table entries
//! - [`crate::metadata::loader`] - Metadata loading and resolution system
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

/// A concurrent map that holds Token to `ParamPtr` mappings.
///
/// This skip list-based map provides efficient concurrent access to loaded
/// `ParamPtr` entries indexed by their metadata tokens. Used by the loader
/// for storing and retrieving parameter pointer entries.
pub type ParamPtrMap = SkipMap<Token, ParamPtrRc>;

/// A thread-safe vector containing `ParamPtr` entries.
///
/// This concurrent vector provides sequential access to `ParamPtr` entries
/// while supporting safe concurrent iteration and access from multiple threads.
pub type ParamPtrList = Arc<boxcar::Vec<ParamPtrRc>>;

/// A reference-counted pointer to a `ParamPtr` entry.
///
/// This atomic reference-counted pointer enables safe sharing of `ParamPtr`
/// instances across threads while providing automatic memory management.
pub type ParamPtrRc = Arc<ParamPtr>;
