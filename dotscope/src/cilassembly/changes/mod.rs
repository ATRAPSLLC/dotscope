//! Change tracking infrastructure for CIL assembly modifications.
//!
//! This module provides comprehensive change tracking capabilities for .NET assembly
//! modifications, supporting both metadata table changes and heap additions. It enables
//! efficient sparse modification tracking with minimal memory overhead.
//!
//! # Key Components
//!
//! - [`ChangeRef`] - Universal reference to any modification (heap entry or table row)
//! - [`AssemblyChanges`] - Core change tracking structure for assembly modifications
//! - [`HeapChanges`] - Heap-specific change tracking for metadata heaps
//!
//! # ChangeRef System
//!
//! The [`ChangeRef`] type provides stable references to modifications that survive
//! heap rebuilding and deduplication. Instead of returning raw offsets that become
//! invalid after write, APIs return `Arc<ChangeRef>` which resolves to the final
//! location after assembly write completes.
//!
//! ```no_run
//! // Old API (problematic - offset may be invalid after write)
//! let offset = context.string_add("MyString")?;  // u32
//!
//! // New API (stable reference)
//! let string_ref = context.string_add("MyString")?;  // Arc<ChangeRef>
//! assembly.to_file(path)?;
//! let final_offset = string_ref.offset().unwrap();  // Resolved after write
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Architecture
//!
//! The change tracking system is designed around sparse storage principles:
//! - Only modified elements are tracked, not entire data structures
//! - Lazy allocation ensures minimal overhead for read-heavy operations
//! - Changes can be efficiently merged during binary output generation
//! - All four metadata heaps (#Strings, #Blob, #GUID, #US) are fully supported
//! - [`ChangeRef`] provides thread-safe deferred resolution of final locations
//!
//! # Usage Examples
//!
//! ```no_run
//! use crate::cilassembly::changes::{AssemblyChanges, HeapChanges, ChangeRef};
//! use crate::metadata::cilassemblyview::CilAssemblyView;
//! use std::path::Path;
//!
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! // Create change tracker for an assembly
//! let mut changes = AssemblyChanges::new(&view);
//!
//! // Track modifications
//! if changes.has_changes() {
//!     println!("Assembly has {} table modifications",
//!              changes.modified_table_count());
//! }
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::CilAssembly`] - Primary assembly modification interface
//! - [`crate::cilassembly::write`] - Binary output generation system

mod assembly;
mod changeref;
mod composite;
mod heap;

pub use assembly::*;
pub use changeref::*;
pub(crate) use composite::{BlobComposite, CompositeImport};
pub use heap::*;
