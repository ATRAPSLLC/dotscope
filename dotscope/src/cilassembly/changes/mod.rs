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
//! use dotscope::{CilAssemblyView, CilAssembly};
//!
//! let view = CilAssemblyView::from_path(std::path::Path::new("tests/samples/crafted_2.exe"))?;
//! let mut assembly = view.to_owned();
//! // A stable reference, not a raw offset the write would invalidate.
//! let string_ref = assembly.string_add("MyString")?;
//! assembly.to_file("modified.dll")?;
//! let final_offset = string_ref.offset();  // Resolved after write
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
//! ```
//! use dotscope::CilAssembly;
//!
//! // An assembly tracks its own changes
//! let mut assembly = CilAssembly::from_path("tests/samples/crafted_2.exe")?;
//! let added = assembly.userstring_add("hello")?;
//!
//! // Track modifications
//! let changes = assembly.changes();
//! if changes.has_changes() {
//!     println!("Assembly has {} table modifications",
//!              changes.modified_table_count());
//! }
//! // The reference resolves to its final location once the assembly is written
//! println!("pending: {:?}", added.kind());
//! # Ok::<(), dotscope::Error>(())
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
