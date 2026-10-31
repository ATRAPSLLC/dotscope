//! Assembly cleanup infrastructure for removing unused metadata.
//!
//! This module provides generic cleanup capabilities for [`CilAssembly`](crate::CilAssembly),
//! enabling removal of metadata entries and their cascading dependents. This is useful for:
//!
//! - **Deobfuscation**: Removing protection infrastructure (types, methods, fields)
//! - **Dead code elimination**: Removing unused types and methods
//! - **Assembly optimization**: Compacting metadata after modifications
//!
//! # Architecture
//!
//! The cleanup system uses a **cascade-from-deleted** approach rather than
//! garbage-collection-style orphan removal:
//!
//! ## 1. Pre-deletion Reference Collection
//!
//! Before deleting entities, the executor scans their method bodies, signatures,
//! and extends clauses to record what tokens they reference. This captures the
//! "blast radius" of the deletion.
//!
//! ## 2. Explicit Deletions + Parent-Child Cascade
//!
//! After applying explicit deletions, dependent metadata (Params, ClassLayout,
//! FieldRVA, NestedClass, CustomAttributes, etc.) is automatically removed.
//!
//! ## 3. Reference Cascade
//!
//! TypeRef, MemberRef, TypeSpec, ModuleRef, and AssemblyRef entries are only
//! removed if they were referenced by a deleted entity AND are no longer
//! referenced by any surviving entity. This is fundamentally safer than
//! removing all unreferenced entries, because it preserves pre-existing
//! orphans that may be used via reflection or dynamic code generation.
//!
//! ## 4. General Optimization (during PE generation)
//!
//! The PE generator automatically:
//! - Compacts heaps (only emits referenced entries)
//! - Deduplicates StandAloneSig entries
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::CilAssembly;
//! use dotscope::CleanupRequest;
//!
//! let mut assembly = CilAssembly::new(view);
//!
//! // Build a cleanup request
//! let mut request = CleanupRequest::new();
//! request.add_type(protection_type_token);
//! request.add_method(decryptor_method_token);
//! request.exclude_section(".confuser");
//!
//! // Execute cleanup (modifies AssemblyChanges)
//! let stats = assembly.execute_cleanup(&request)?;
//! println!("{}", stats);
//!
//! // Generate assembly (cleanup is applied)
//! assembly.write_to_file("output.exe")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # What Gets Cleaned Up
//!
//! When a **type** is deleted:
//! - All its methods (MethodDef)
//! - All its fields (Field)
//! - NestedClass entries
//! - InterfaceImpl entries
//! - ClassLayout entries
//! - EventMap entries and their Event rows
//! - PropertyMap entries and their Property rows
//! - DeclSecurity entries
//! - MethodImpl entries
//! - MethodSemantics entries (for deleted events/properties)
//! - GenericParam entries (and their constraints)
//! - CustomAttributes targeting the type
//!
//! When a **method** is deleted:
//! - All its parameters (Param)
//! - Its StandAloneSig (local variables, cascade-from-deleted)
//! - MethodSemantics entries
//! - MethodImpl entries
//! - GenericParam entries (and their constraints)
//! - ImplMap entries (P/Invoke)
//! - DeclSecurity entries
//! - CustomAttributes targeting the method
//!
//! When a **field** is deleted:
//! - FieldRVA entries
//! - FieldLayout entries
//! - FieldMarshal entries
//! - Constant entries
//! - CustomAttributes targeting the field
//!
//! When an **AssemblyRef** or **File** is cascade-deleted:
//! - ExportedType entries referencing the deleted scope
//! - ManifestResource entries referencing the deleted scope
//! - File entries no longer referenced by surviving ExportedType/ManifestResource

#[cfg(feature = "deobfuscation")]
mod analysis;
mod compaction;
mod executor;
mod orphans;
mod references;
mod request;
mod stats;
mod utils;

#[cfg(feature = "deobfuscation")]
pub use analysis::{compute_entry_points, expand_type_tokens, find_unreferenced_types, TypeNames};
pub(crate) use compaction::{collect_referenced_heap_entries, mark_unreferenced_heap_entries};
pub use executor::execute_cleanup;
pub use request::CleanupRequest;
pub use stats::CleanupStats;
#[cfg(feature = "deobfuscation")]
pub(crate) use utils::{extract_local_var_sig_rid, with_method_body};
