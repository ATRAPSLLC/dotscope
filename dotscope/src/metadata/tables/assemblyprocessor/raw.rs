//! Raw `AssemblyProcessor` table representation.
//!
//! This module provides low-level access to `AssemblyProcessor` metadata table data through the
//! [`crate::metadata::tables::assemblyprocessor::raw::AssemblyProcessorRaw`] structure. The
//! `AssemblyProcessor` table contains CPU architecture targeting information for .NET assemblies,
//! though it is rarely used in modern applications.
//!
//! # Architecture
//!
//! Like [`crate::metadata::tables::assemblyos::AssemblyOsRaw`], `AssemblyProcessor` contains only primitive
//! values and requires no heap resolution, making the "raw" and "owned" representations
//! functionally identical. This simplifies the dual variant pattern used throughout the
//! metadata system.
//!
//! # Key Components
//!
//! - [`crate::metadata::tables::assemblyprocessor::raw::AssemblyProcessorRaw`] - Raw table row structure
//! - [`crate::metadata::tables::assemblyprocessor::AssemblyProcessorRc`] - Reference-counted owned representation
//! - [`crate::metadata::tables::types::RowReadable`] - Table parsing interface implementation
//!
//! # `AssemblyProcessor` Table Format
//!
//! The `AssemblyProcessor` table (0x21) contains CPU architecture targeting information:
//! - **Processor** (4 bytes): Processor architecture identifier
//!
//! # Historical Context
//!
//! This table was designed for early .NET Framework scenarios where assemblies might need
//! explicit CPU architecture declarations. Modern .NET applications typically use `AnyCPU`
//! compilation and rely on runtime JIT optimization for architecture-specific code generation.
//!
//! # Architecture Evolution
//!
//! - **Early .NET**: Explicit x86, x64, IA64 targeting in metadata
//! - **Framework Era**: Platform-specific compilation with runtime detection
//! - **Modern .NET**: `AnyCPU` with runtime JIT optimization and cross-platform support
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::tables`] - Core metadata table infrastructure
//! - [`crate::metadata::token`] - Token representation for metadata references
//! - [`crate::io`] - Binary data reading utilities
//!
//! # References
//!
//! - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification

use std::sync::Arc;

use crate::{
    metadata::{
        tables::{AssemblyProcessorRc, TableRow},
        token::Token,
    },
    prelude::TableInfoRef,
    Result,
};

#[derive(Clone, Debug)]
/// Raw `AssemblyProcessor` table row representing CPU architecture targeting information
///
/// Contains processor architecture identification data for assemblies that specify explicit CPU targeting.
/// Like [`crate::metadata::tables::AssemblyOsRaw`], this structure contains only
/// primitive integer values and requires no heap resolution, making it immediately usable.
///
/// The `AssemblyProcessor` table (0x21) is optional and rarely present in modern .NET assemblies,
/// which typically use `AnyCPU` compilation and rely on runtime JIT optimization for architecture-specific
/// code generation rather than compile-time CPU targeting.
///
/// # Data Model
///
/// All fields contain direct integer values rather than heap indexes:
/// - No string heap references
/// - No blob heap references
/// - All data is self-contained within the table row
///
/// # Architecture Identifiers
///
/// While ECMA-335 doesn't specify exact processor constants, common values historically included:
/// - x86 architectures (32-bit Intel)
/// - x64 architectures (64-bit AMD/Intel)
/// - IA64 architectures (Intel Itanium, deprecated)
///
/// # Reference
/// - [ECMA-335 II.22.4](https://ecma-international.org/wp-content/uploads/ECMA-335_6th_edition_june_2012.pdf) - `AssemblyProcessor` table specification
pub struct AssemblyProcessorRaw {
    /// Row identifier within the `AssemblyProcessor` metadata table
    ///
    /// The 1-based index of this `AssemblyProcessor` row. Multiple processor targets can be specified,
    /// though this is rarely used in modern .NET assemblies.
    pub rid: u32,

    /// Metadata token for this `AssemblyProcessor` row
    ///
    /// Combines the table identifier (0x21 for `AssemblyProcessor`) with the row ID to create
    /// a unique token. Format: `0x21000000 | rid`
    pub token: Token,

    /// Byte offset of this row within the metadata tables stream
    ///
    /// Physical location of the raw `AssemblyProcessor` data within the metadata binary format.
    /// Used for debugging and low-level metadata analysis.
    pub offset: usize,

    /// Processor architecture identifier
    ///
    /// 4-byte value identifying the target CPU architecture. The specific values are not
    /// standardized in ECMA-335, but historically included identifiers for x86, x64, and IA64.
    /// Modern assemblies typically avoid explicit processor targeting in favor of `AnyCPU` compilation.
    pub processor: u32,
}

impl AssemblyProcessorRaw {
    /// Convert an `AssemblyProcessorRaw` into an `AssemblyProcessor` which has indexes resolved and owns the referenced data.
    ///
    /// Since `AssemblyProcessor` is a type alias for `AssemblyProcessorRaw` (no resolution needed), this simply wraps
    /// the raw data in an Arc for consistency with the dual variant pattern.
    ///
    /// # Errors
    /// This method currently never fails and always returns `Ok`.
    pub fn to_owned(&self) -> Result<AssemblyProcessorRc> {
        Ok(Arc::new(self.clone()))
    }

    /// Apply an `AssemblyProcessorRaw` entry to update related metadata structures.
    ///
    /// `AssemblyProcessor` entries specify processor architecture information for the current assembly.
    /// They are self-contained and don't require cross-table updates during the dual variant
    /// resolution phase.
    ///
    /// # Errors
    /// Always returns `Ok(())` as `AssemblyProcessor` entries don't modify other tables.
    pub fn apply(&self) -> Result<()> {
        Ok(())
    }
}

impl TableRow for AssemblyProcessorRaw {
    /// Calculate the byte size of an `AssemblyProcessor` table row
    ///
    /// Returns the fixed size since `AssemblyProcessor` contains only a single primitive integer field.
    /// Total size is always 4 bytes (1 × 4-byte integer).
    ///
    /// # Row Layout
    /// - processor: 4 bytes (fixed)
    ///
    /// # Arguments
    /// * `_sizes` - Unused for `AssemblyProcessor` since no heap indexes are present
    ///
    /// # Returns
    /// Fixed size of 4 bytes for all `AssemblyProcessor` rows
    #[rustfmt::skip]
    fn row_size(_sizes: &TableInfoRef) -> u32 {
        /* processor */ 4
    }
}
