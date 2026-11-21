//! `AssemblyProcessor` table module.
//!
//! This module provides complete support for the ECMA-335 `AssemblyProcessor` metadata table (0x21),
//! which contains processor architecture information for assemblies. It includes raw table access,
//! collection types, and CPU architecture identification utilities for processing processor
//! targeting metadata.
//!
//! # Architecture
//!
//! The `AssemblyProcessor` module follows the standard dual variant pattern but simplifies it since
//! the table contains only primitive values. No heap resolution is required, making the raw and
//! owned representations functionally identical.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyprocessor::raw::AssemblyProcessorRaw`] - Raw table structure
//! - [`crate::metadata::tables::assemblyprocessor::AssemblyProcessor`] - Type alias to Raw
//! - [`crate::metadata::loader::tables::AssemblyProcessorLoader`] - Internal loader
//! - [`crate::metadata::tables::assemblyprocessor::AssemblyProcessorMap`] - Token-based lookup map
//! - [`crate::metadata::tables::assemblyprocessor::AssemblyProcessorList`] - Collection type
//! - [`crate::metadata::tables::assemblyprocessor::AssemblyProcessorRc`] - Reference-counted pointer
//!
//! # `AssemblyProcessor` Table Structure
//!
//! The `AssemblyProcessor` table contains CPU architecture targeting information:
//! - **Processor**: Processor architecture identifier (4 bytes)
//!
//! # Historical Context
//!
//! This table was designed for early .NET Framework scenarios where assemblies might need
//! to specify explicit CPU architecture targeting. Modern .NET applications typically use
//! `AnyCPU` compilation and rely on runtime JIT compilation to optimize for the target architecture.
//!
//! # CPU Architecture Evolution
//!
//! - **Early .NET**: Explicit x86/x64/IA64 targeting via metadata
//! - **Modern .NET**: `AnyCPU` with runtime architecture detection
//! - **Current Practice**: Platform-agnostic IL with JIT optimization
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token-based metadata references
//! - [`crate::metadata::loader`] - Metadata loading system
//!
//! # References
//!
//! - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification
use std::sync::Arc;

use crossbeam_skiplist::SkipMap;

use crate::metadata::token::Token;

mod builder;
mod raw;
mod reader;
mod writer;

pub use builder::*;
pub use raw::*;

/// A map that holds the mapping of [`crate::metadata::token::Token`] to parsed [`crate::metadata::tables::assemblyprocessor::AssemblyProcessor`]
///
/// Thread-safe concurrent map using skip list data structure for efficient lookups
/// and insertions. Used to cache resolved `AssemblyProcessor` entries by their metadata tokens.
pub type AssemblyProcessorMap = SkipMap<Token, AssemblyProcessorRc>;

/// A vector that holds a list of [`crate::metadata::tables::assemblyprocessor::AssemblyProcessor`] references
///
/// Thread-safe append-only vector for storing `AssemblyProcessor` collections. Uses atomic operations
/// for lock-free concurrent access and is optimized for scenarios with frequent reads.
pub type AssemblyProcessorList = Arc<boxcar::Vec<AssemblyProcessorRc>>;

/// A reference-counted pointer to an [`crate::metadata::tables::assemblyprocessor::AssemblyProcessor`]
///
/// Provides shared ownership and automatic memory management for `AssemblyProcessor` instances.
/// Multiple references can safely point to the same `AssemblyProcessor` data across threads.
pub type AssemblyProcessorRc = Arc<AssemblyProcessor>;

/// Processor architecture targeting information for assemblies
///
/// Type alias to [`crate::metadata::tables::assemblyprocessor::raw::AssemblyProcessorRaw`] since the `AssemblyProcessor` table contains only primitive values
/// that don't require heap resolution. All data in the raw structure is immediately usable.
///
/// The `AssemblyProcessor` table specifies which CPU architectures this assembly is designed to run on,
/// though this information is rarely used in modern .NET applications which rely on `AnyCPU` compilation
/// and runtime JIT optimization instead.
///
/// # Data Model
///
/// Unlike other metadata tables that reference string or blob heaps, `AssemblyProcessor` contains
/// only integer values, making the "raw" and "owned" representations identical.
///
/// # Architecture Evolution
///
/// - **Legacy**: Explicit x86, x64, IA64 targeting in metadata
/// - **Modern**: `AnyCPU` with runtime architecture detection
/// - **Current**: Platform-agnostic IL with JIT compilation
///
/// # References
/// - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification (Table ID = 0x21)
pub type AssemblyProcessor = AssemblyProcessorRaw;
