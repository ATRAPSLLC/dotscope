//! Write infrastructure for serializing metadata table rows to binary format.
//!
//! This module provides the core types for constructing and serializing .NET CLI
//! metadata table rows. It works in conjunction with the streaming PE writer in
//! [`crate::cilassembly::writer`] which handles the full tables stream layout
//! (header, row counts, coded index sizes) during PE generation.
//!
//! # Key Components
//!
//! - [`RowWritable`] - Trait for serializing individual table rows to byte buffers
//! - [`TableDataOwned`] - Type-erased enum over all 48 raw row types, used by the
//!   modification pipeline for sparse updates, replacements, and insertions
//!
//! # Serialization Pipeline
//!
//! During PE generation, each row goes through a multi-stage pipeline before
//! being written to the output stream:
//!
//! 1. **Placeholder resolution** - heap offsets are resolved from [`crate::cilassembly::ChangeRefRc`] values
//! 2. **RID remapping** - row references are adjusted for deletions via [`crate::cilassembly::writer::remapper::RidRemapper`]
//! 3. **Row serialization** - [`RowWritable::row_write()`] encodes the row into ECMA-335 binary format
//! 4. **RVA fixups** - method body and field RVA values are patched to final addresses
//!
//! The streaming generator in [`crate::cilassembly::writer`] orchestrates this pipeline,
//! handling the tables stream header, dynamic `TableInfo` recalculation, and three
//! modification modes (fully replaced tables, sparse edits, and unmodified pass-through).

mod data;
mod traits;

pub use data::TableDataOwned;
pub use traits::RowWritable;
