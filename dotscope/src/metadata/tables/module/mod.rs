//! # Module Table Module
//!
//! This module provides comprehensive access to the **Module** metadata table (ID 0x00),
//! which contains information about the current module including its name, GUID (Mvid), and
//! generation. The Module table is fundamental to .NET metadata as it provides the identity
//! information for the current assembly module.
//!
//! ## Overview
//!
//! The Module table serves as the foundational identity table for .NET assemblies:
//! - **Unique Entry**: Always contains exactly one row per PE file
//! - **Module Identity**: Provides name and GUID for module identification
//! - **Version Management**: Includes generation and ENC (Edit and Continue) support
//! - **Foundation Table**: One of the first tables loaded with no dependencies
//!
//! The table establishes the basic identity that other metadata tables reference and build upon.
//!
//! ## Components
//!
//! The module implements a dual-representation pattern for optimal performance:
//!
//! - [`ModuleRaw`] - Raw table data with unresolved indexes for initial parsing
//! - [`Module`] - Processed data with resolved strings and GUIDs
//! - [`ModuleLoader`](crate::metadata::loader::tables::ModuleLoader) - Handles conversion between raw and processed representations
//! - [`ModuleMap`] - Thread-safe storage mapping tokens to processed entries
//! - [`ModuleList`] - Thread-safe collection (though only one entry exists)
//!
//! ## Table Structure
//!
//! | Field | Type | Description |
//! |-------|------|-------------|
//! | `Generation` | `u16` | Reserved field, always zero |
//! | `Name` | `u32` | Index into string heap containing module name |
//! | `Mvid` | `u32` | Index into GUID heap containing module version identifier |
//! | `EncId` | `u32` | Index into GUID heap for Edit and Continue (reserved) |
//! | `EncBaseId` | `u32` | Index into GUID heap for Edit and Continue base (reserved) |
//!
//! The `Mvid` (Module Version Identifier) is a GUID that uniquely distinguishes between
//! different versions of the same module, enabling proper version management and resolution.
//!
//! ## Module Identity
//!
//! The Module table provides several levels of identity:
//!
//! 1. **Name Identity**: Human-readable module name from string heap
//! 2. **Version Identity**: GUID-based unique identifier (Mvid)
//! 3. **Generation**: Reserved for future versioning schemes
//! 4. **ENC Support**: Reserved GUIDs for Edit and Continue scenarios
//!
//! ## ECMA-335 Specification
//!
//! This implementation follows the ECMA-335 specification:
//! - **§II.22.30** - Module table structure and semantics
//! - **§II.23.2.6** - Module metadata token format
//! - **§II.24.2.1** - String and GUID heap references
//!
//! For detailed specifications, see [ECMA-335 6th Edition](https://www.ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf).

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

/// Thread-safe map holding the mapping of [`Token`] to parsed [`Module`] entries.
///
/// This concurrent skip list provides efficient O(log n) access to module entries
/// by their metadata token. Since the Module table contains only one entry, this
/// map will typically contain a single element.
pub type ModuleMap = SkipMap<Token, ModuleRc>;

/// Thread-safe vector holding a list of [`Module`] entries.
///
/// Uses a lock-free vector implementation for efficient concurrent access.
/// Since the Module table contains only one entry, this list will contain
/// exactly one element representing the current module.
pub type ModuleList = Arc<boxcar::Vec<ModuleRc>>;

/// Reference-counted pointer to a [`Module`] entry.
///
/// Enables efficient sharing of module data across multiple contexts
/// while maintaining memory safety through automatic reference counting.
pub type ModuleRc = Arc<Module>;
