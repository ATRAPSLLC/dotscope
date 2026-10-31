//! Mutable assembly representation for editing and modification operations.
//!
//! This module provides [`crate::cilassembly::CilAssembly`], a comprehensive editing layer for .NET assemblies
//! that enables type-safe, efficient modification of metadata tables, heap content, and
//! cross-references while maintaining ECMA-335 compliance.
//!
//! # Design Philosophy
//!
//! ## **Copy-on-Write Semantics**
//! - Original [`crate::metadata::cilassemblyview::CilAssemblyView`] remains immutable and unchanged
//! - Modifications are tracked separately in [`crate::cilassembly::changes::AssemblyChanges`]
//! - Changes are lazily allocated only when modifications are made
//! - Read operations efficiently merge original data with changes
//!
//! ## **Memory Efficiency**
//! - **Sparse Tracking**: Only modified tables/heaps consume memory
//! - **Lazy Initialization**: Change structures created on first modification
//! - **Efficient Storage**: Operations stored chronologically with timestamps
//! - **Memory Estimation**: Built-in memory usage tracking and reporting
//!
//! # Core Components
//!
//! ## **Change Tracking ([`crate::cilassembly::changes::AssemblyChanges`])**
//! Central structure that tracks all modifications:
//! ```text
//! AssemblyChanges
//! ├── string_heap_changes: Option<HeapChanges<String>>      // #Strings (UTF-8)
//! ├── blob_heap_changes: Option<HeapChanges<Vec<u8>>>       // #Blob (binary)
//! ├── guid_heap_changes: Option<HeapChanges<[u8; 16]>>      // #GUID (16-byte)
//! ├── userstring_heap_changes: Option<HeapChanges<String>>  // #US (UTF-16)
//! └── table_changes: HashMap<TableId, TableModifications>
//! ```
//!
//! ## **Table Modifications ([`crate::cilassembly::modifications::TableModifications`])**
//! Two strategies for tracking table changes:
//! - **Sparse**: Individual operations (Insert/Update/Delete) with timestamps
//! - **Replaced**: Complete table replacement for heavily modified tables
//!
//! ## **Operation Types ([`crate::cilassembly::operation::Operation`])**
//! - **Insert(rid, data)**: Add new row with specific RID
//! - **Update(rid, data)**: Modify existing row data  
//! - **Delete(rid)**: Mark row as deleted
//!
//! ## **Validation System**
//! - **Configurable Pipeline**: Multiple validation stages
//! - **Conflict Detection**: Identifies conflicting operations
//! - **Resolution Strategies**: Last-write-wins, merge, reject, etc.
//! - **Cross-Reference Validation**: Ensures referential integrity
//!
//! ## **Index Remapping**
//! - **Heap Index Management**: Tracks new heap indices
//! - **RID Remapping**: Maps original RIDs to final RIDs after consolidation
//! - **Cross-Reference Updates**: Updates all references during binary generation
//!
//! # Usage Patterns
//!
//! ## **Basic Heap Modification**
//! ```rust,no_run
//! # use dotscope::{CilAssemblyView, CilAssembly};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Heap operations return indices for cross-referencing
//! let string_idx = assembly.string_add("MyString")?;
//! let blob_idx = assembly.blob_add(&[0x01, 0x02, 0x03])?;
//! let guid_idx = assembly.guid_add(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
//!                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])?;
//! let userstring_idx = assembly.userstring_add("User String Literal")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## **Table Row Operations**
//! ```rust,no_run
//! # use dotscope::{CilAssemblyView, CilAssembly, metadata::tables::{TableId, TableDataOwned}};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Low-level table modification
//! // let row_data = TableDataOwned::TypeDef(/* ... */);
//! // let rid = assembly.add_table_row(TableId::TypeDef, row_data)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## **Validation and Consistency**
//! ```rust,no_run
//! # use dotscope::{CilAssemblyView, CilAssembly};
//! # let view = CilAssemblyView::from_mem(vec![])?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Make modifications...
//!
//! // Write to file or memory
//! assembly.to_file("output.dll")?;
//! // Or: let bytes = assembly.to_memory()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Module Organization
//!
//! Following "one type per file" for maintainability:
//!
//! ## **Core Types**
//! - [`crate::cilassembly::CilAssembly`] - Main mutable assembly (this file)
//! - [`crate::cilassembly::changes::AssemblyChanges`] - Central change tracking
//! - [`crate::cilassembly::changes::heap::HeapChanges`] - Heap modification tracking
//! - [`crate::cilassembly::modifications::TableModifications`] - Table change strategies
//! - [`crate::cilassembly::operation::TableOperation`] - Timestamped operations
//! - [`crate::cilassembly::operation::Operation`] - Operation variants
//!
//! ## **Conflict Resolution ([`crate::cilassembly::resolver`])**
//! Conflict resolution for handling competing operations:
//! - [`crate::cilassembly::resolver::ConflictResolver`] - Conflict resolution strategies
//! - [`crate::cilassembly::resolver::LastWriteWinsResolver`] - Default timestamp-based resolver
//! - [`crate::cilassembly::resolver::Conflict`] & [`crate::cilassembly::resolver::Resolution`] - Conflict types and results
//!
//! # Examples
//!
//! ```rust,no_run
//! use dotscope::{CilAssemblyView, CilAssembly};
//! use std::{fmt, path::Path};
//!
//! // Load and convert to mutable assembly
//! let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
//! let mut assembly = CilAssembly::new(view);
//!
//! // Add a string to the heap
//! let string_index = assembly.string_add("Hello, World!")?;
//!
//! // Write modified assembly to new file
//! assembly.to_file(Path::new("modified.dll"))?;
//! # Ok::<(), dotscope::Error>(())
//! ```
use std::{fmt, path::Path};

use crate::{
    file::File,
    metadata::{
        cilassemblyview::CilAssemblyView,
        exports::UnifiedExportContainer,
        imports::UnifiedImportContainer,
        signatures::{
            encode_field_signature, encode_local_var_signature, encode_method_signature,
            encode_property_signature, encode_typespec_signature, SignatureField,
            SignatureLocalVariables, SignatureMethod, SignatureProperty, SignatureTypeSpec,
        },
        tables::{
            skip_unreadable, AssemblyRefRaw, CodedIndex, CodedIndexType, TableDataOwned, TableId,
            TypeDefRaw, TypeRefRaw,
        },
        token::Token,
    },
    CilObject, Error, Result, ValidationConfig,
};

mod builders;
mod changes;
mod cleanup;
mod modifications;
mod operation;
mod resolver;
mod writer;

pub use builders::{
    ClassBuilder, EnumBuilder, EventBuilder, InterfaceBuilder, MethodBodyBuilder, MethodBuilder,
    PropertyBuilder,
};
pub use changes::{AssemblyChanges, ChangeIds, ChangeRef, ChangeRefKind, ChangeRefRc, HeapChanges};
pub(crate) use changes::{BlobComposite, CompositeImport};
pub use cleanup::CleanupRequest;
#[cfg(feature = "deobfuscation")]
pub(crate) use cleanup::{
    compute_entry_points, execute_cleanup, expand_type_tokens, extract_local_var_sig_rid,
    find_unreferenced_types, with_method_body, TypeNames,
};
pub use modifications::TableModifications;
pub use operation::{Operation, TableOperation};
pub use resolver::{
    Conflict, ConflictResolver, LastWriteWinsResolver, OperationResolution, Resolution,
};
use writer::PeGenerator;
pub(crate) use writer::ResolvePlaceholders;
#[cfg(any(test, feature = "testkit"))]
pub(crate) use writer::{calculate_field_size, debug_blobs, signature_blobs, BlobKind};
pub use writer::{DanglingPolicy, GeneratorConfig};

/// A mutable view of a .NET assembly that tracks changes for editing operations.
///
/// `CilAssembly` provides an editing layer on top of [`crate::metadata::cilassemblyview::CilAssemblyView`], using
/// a copy-on-write strategy to track modifications while preserving the original
/// assembly data. Changes are stored separately and merged when writing to disk.
///
/// # Thread Safety
///
/// `CilAssembly` is **not thread-safe** by default. For concurrent access, wrap in
/// appropriate synchronization primitives.
pub struct CilAssembly {
    view: CilAssemblyView,
    changes: AssemblyChanges,
    pending_cleanup: cleanup::CleanupRequest,
    /// Whether [`Self::add_cleanup`] has been called since the last generation: until then
    /// the pending request's settings are the defaults, not anyone's choice.
    cleanup_added: bool,
}

impl CilAssembly {
    /// Creates a new mutable assembly from a read-only view.
    ///
    /// This consumes the `CilAssemblyView` and creates a mutable editing layer
    /// on top of it.
    ///
    /// # Arguments
    ///
    /// * `view` - The read-only assembly view to wrap
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// let assembly = CilAssembly::new(view);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new(view: CilAssemblyView) -> Self {
        Self {
            changes: AssemblyChanges::new(),
            view,
            pending_cleanup: cleanup::CleanupRequest::new(),
            cleanup_added: false,
        }
    }

    /// Creates a new mutable assembly by loading from a file path.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .NET assembly file to load
    ///
    /// # Returns
    ///
    /// Returns a `CilAssembly` ready for modification operations.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssembly;
    /// use std::path::Path;
    ///
    /// let mut assembly = CilAssembly::from_path(Path::new("assembly.dll"))?;
    ///
    /// // Now ready to modify
    /// let string_index = assembly.string_add("Hello, World!")?;
    /// assembly.to_file(Path::new("modified.dll"))?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be loaded or parsed as a valid
    /// .NET assembly.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let view = CilAssemblyView::from_path(path)?;
        Ok(Self::new(view))
    }

    /// Creates a new mutable assembly by loading from a byte vector.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes of the .NET assembly
    ///
    /// # Returns
    ///
    /// Returns a `CilAssembly` ready for modification operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be parsed as a valid .NET assembly.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let view = CilAssemblyView::from_mem(bytes)?;
        Ok(Self::new(view))
    }

    /// Creates a new mutable assembly by loading from a byte vector with custom validation.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The raw bytes of the .NET assembly
    /// * `validation_config` - Validation configuration
    ///
    /// # Returns
    ///
    /// Returns a `CilAssembly` ready for modification operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be parsed as a valid .NET assembly.
    pub fn from_bytes_with_validation(
        bytes: Vec<u8>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let view = CilAssemblyView::from_mem_with_validation(bytes, validation_config)?;
        Ok(Self::new(view))
    }

    /// Adds a cleanup request to be executed before PE generation.
    ///
    /// Multiple cleanup requests can be added and will be merged together. The first request's
    /// settings ([`CleanupRequest::with_settings`]) apply, and each later request can only
    /// narrow them: orphans and empty types are removed when every request asks for it.
    /// The cleanup is executed once when `to_file()`, `to_memory()`, or similar
    /// generation methods are called.
    ///
    /// # Arguments
    ///
    /// * `request` - The cleanup request specifying what to remove
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::CilAssembly;
    /// # use dotscope::metadata::token::Token;
    /// # let mut assembly = CilAssembly::from_path("input.dll")?;
    /// # let protection_type_token = Token::new(0x02000001);
    /// # let decryptor_method_token = Token::new(0x06000001);
    /// let mut request = dotscope::CleanupRequest::new();
    /// request.add_type(protection_type_token);
    /// request.add_method(decryptor_method_token);
    ///
    /// assembly.add_cleanup(&request);
    ///
    /// // Cleanup executes automatically during generation
    /// assembly.to_file("output.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_cleanup(&mut self, request: &cleanup::CleanupRequest) {
        if self.cleanup_added {
            self.pending_cleanup.merge(request);
            self.pending_cleanup.narrow_settings(request);
        } else {
            self.pending_cleanup = request.clone();
            self.cleanup_added = true;
        }
    }

    /// Returns a reference to the pending cleanup request.
    ///
    /// This can be used to inspect what cleanup operations are queued.
    #[must_use]
    pub fn pending_cleanup(&self) -> &cleanup::CleanupRequest {
        &self.pending_cleanup
    }

    /// Executes pending cleanup, adding deletions to AssemblyChanges.
    ///
    /// This is called internally before PE generation. It can only be called
    /// once because row deletions cause RID shifting.
    ///
    /// # Returns
    ///
    /// Statistics about what was removed during cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error if cleanup execution fails.
    fn finalize_for_generation(&mut self) -> Result<cleanup::CleanupStats> {
        if self.pending_cleanup.is_empty() {
            // Even without cleanup deletions, string heap modifications require
            // referenced_string_offsets to be populated for correct substring remapping.
            // The .NET string heap uses substring sharing (e.g., "Console" as a suffix
            // of "writeToConsole"). When the heap is rebuilt after modifications, all
            // table references (including TypeRef) need correct offset remapping.
            if self.changes.string_heap_changes.modifications_count() > 0 {
                let _ = cleanup::mark_unreferenced_heap_entries(self)?;
            }
            return Ok(cleanup::CleanupStats::new());
        }

        // Take ownership of the request (clears pending_cleanup and avoids borrow conflict)
        let request = std::mem::take(&mut self.pending_cleanup);
        self.cleanup_added = false;

        // Execute cleanup ONCE - this adds all deletions to self.changes
        let stats = cleanup::execute_cleanup(self, &request)?;
        Ok(stats)
    }

    /// Adds a string to the string heap (#Strings) and returns its index.
    ///
    /// The string is appended to the string heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// string from metadata table rows.
    ///
    /// **Note**: Strings in the #Strings heap are UTF-8 encoded when written
    /// to the binary. This method stores the logical string value
    /// during the editing phase.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this string.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let hello_ref = assembly.string_add("Hello")?;
    /// let world_ref = assembly.string_add("World")?;
    ///
    /// // Each addition returns a unique reference
    /// assert_ne!(hello_ref, world_ref);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently this function does not return errors, but the Result type is
    /// reserved for future enhancements that may require error handling.
    pub fn string_add(&mut self, value: &str) -> Result<ChangeRefRc> {
        let change_ref = self.changes.string_heap_changes.append(value.to_string());
        Ok(change_ref)
    }

    /// Adds a blob to the blob heap and returns its index.
    ///
    /// The blob data is appended to the blob heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// blob from metadata table rows.
    ///
    /// # Arguments
    ///
    /// * `data` - The blob data to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this blob.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be added to the heap.
    pub fn blob_add(&mut self, data: &[u8]) -> Result<ChangeRefRc> {
        let change_ref = self.changes.blob_heap_changes.append(data.to_vec());
        Ok(change_ref)
    }

    /// Adds a blob whose content names other blobs (a document name, an imports blob), which
    /// the writer encodes once the blobs it names have offsets.
    ///
    /// The blob takes an entry of the heap like any other, and its reference resolves to its
    /// offset when the assembly is written.
    pub(crate) fn blob_add_composite(&mut self, composite: BlobComposite) -> ChangeRefRc {
        let change_ref = self.changes.blob_heap_changes.append(Vec::new());
        self.changes
            .blob_composites
            .insert(change_ref.id(), composite);
        change_ref
    }

    /// Adds a GUID to the GUID heap and returns its index.
    ///
    /// The GUID is appended to the GUID heap, maintaining the original
    /// heap structure. The returned index can be used to reference this
    /// GUID from metadata table rows.
    ///
    /// # Arguments
    ///
    /// * `guid` - The 16-byte GUID to add to the heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this GUID.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let guid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// let guid_index = assembly.guid_add(&guid)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the GUID cannot be added to the heap.
    pub fn guid_add(&mut self, guid: &[u8; 16]) -> Result<ChangeRefRc> {
        let change_ref = self.changes.guid_heap_changes.append(*guid);
        Ok(change_ref)
    }

    /// Adds a user string to the user string heap (#US) and returns its index.
    ///
    /// The user string is appended to the user string heap (#US), maintaining
    /// the original heap structure. User strings are used for string literals
    /// in IL code (e.g., `ldstr` instruction operands) and are stored with
    /// length prefixes and UTF-16 encoding when written to the binary.
    ///
    /// **Note**: User strings in the #US heap are UTF-16 encoded with compressed
    /// length prefixes when written to the binary. This method calculates API
    /// indices based on final string sizes after considering modifications to
    /// ensure consistency with the writer and size calculation logic.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to add to the user string heap
    ///
    /// # Returns
    ///
    /// Returns the heap index that can be used to reference this user string.
    /// Indices are 1-based following ECMA-335 conventions.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let userstring_index = assembly.userstring_add("Hello, World!")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the user string cannot be added to the heap.
    pub fn userstring_add(&mut self, value: &str) -> Result<ChangeRefRc> {
        let change_ref = self
            .changes
            .userstring_heap_changes
            .append(value.to_string());
        Ok(change_ref)
    }

    /// Adds resource data to the CLR resources section and returns its offset.
    ///
    /// This stores the resource data in the CLR resources section (not the blob heap)
    /// with the proper .NET format: 4-byte little-endian length prefix followed by the data.
    /// The returned offset should be used as the `offset_field` in ManifestResource table entries.
    ///
    /// The offset is automatically adjusted to account for any existing resources in the
    /// original assembly, since new resources are appended after original ones.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw resource data bytes to store
    ///
    /// # Returns
    ///
    /// Returns the offset within the resources section where this resource starts.
    /// This offset points to the length prefix, which is how ManifestResource.offset_field works.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let resource_data = b"Hello, Resource!";
    /// let offset = assembly.resource_data_add(resource_data);
    /// // Use offset as ManifestResource.offset_field
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn resource_data_add(&mut self, data: &[u8]) -> u32 {
        // Get the offset within our new resource data buffer
        let new_offset = self.changes.store_resource_data(data);

        // Add the original resource size since new resources are appended after original ones
        // This ensures ManifestResource.offset_field points to the correct location
        let original_size = self.view.cor20header().resource_size;
        new_offset.saturating_add(original_size)
    }

    /// Updates an existing string in the string heap at the specified index.
    ///
    /// This modifies the string at the given heap index. The reference handling
    /// is not needed for modifications since the index remains the same.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_value` - The new string value to store at that index
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the modification was successful.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Modify an existing string at index 42
    /// assembly.string_update(42, "Updated String")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be updated.
    pub fn string_update(&mut self, index: u32, new_value: &str) -> Result<()> {
        self.changes
            .string_heap_changes
            .add_modification(index, new_value.to_string());
        Ok(())
    }

    /// Removes a string from the string heap at the specified index.
    ///
    /// This marks the string at the given heap index for removal.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the removal was successful.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssembly, CilAssemblyView};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Remove string at index 42
    /// assembly.string_remove(42)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be removed.
    pub fn string_remove(&mut self, index: u32) -> Result<()> {
        let original_heap_size = self
            .view()
            .metadata_root()
            .stream("#Strings")
            .map_or(0, |s| s.size);

        if index >= original_heap_size {
            self.changes
                .string_heap_changes
                .mark_appended_for_removal(index);
        } else {
            self.changes.string_heap_changes.add_removal(index);
        }
        Ok(())
    }

    /// Updates an existing blob in the blob heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_data` - The new blob data to store at that index
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be updated.
    pub fn blob_update(&mut self, index: u32, new_data: &[u8]) -> Result<()> {
        self.changes
            .blob_heap_changes
            .add_modification(index, new_data.to_vec());
        Ok(())
    }

    /// Removes a blob from the blob heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    ///
    /// # Errors
    ///
    /// Returns an error if the blob cannot be removed.
    pub fn blob_remove(&mut self, index: u32) -> Result<()> {
        self.changes.blob_heap_changes.add_removal(index);
        Ok(())
    }

    /// Updates an existing GUID in the GUID heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify. This can be either:
    ///   - A 1-based sequential index (following ECMA-335 conventions) for existing GUIDs
    ///   - A placeholder value from a ChangeRef for newly added GUIDs
    /// * `new_guid` - The new 16-byte GUID to store at that index
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_update(&mut self, index: u32, new_guid: &[u8; 16]) -> Result<()> {
        // Check if this is a placeholder value (from a newly added GUID)
        // Placeholders have the high bit or marker bit set
        let lookup_key = if ChangeRef::is_heap_placeholder(index) {
            // For placeholders, use directly - the streaming code looks up by placeholder
            index
        } else {
            // For existing GUIDs, convert 1-based sequential index to byte offset
            // GUID heap uses byte offsets internally: byte_offset = (index - 1) * 16
            index.saturating_sub(1).saturating_mul(16)
        };
        self.changes
            .guid_heap_changes
            .add_modification(lookup_key, *new_guid);
        Ok(())
    }

    /// Removes a GUID from the GUID heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove. This can be either:
    ///   - A 1-based sequential index (following ECMA-335 conventions) for existing GUIDs
    ///   - A placeholder value from a ChangeRef for newly added GUIDs
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_remove(&mut self, index: u32) -> Result<()> {
        // Check if this is a placeholder value (from a newly added GUID)
        let lookup_key = if ChangeRef::is_heap_placeholder(index) {
            index
        } else {
            // Convert 1-based sequential index to byte offset
            index.saturating_sub(1).saturating_mul(16)
        };
        self.changes.guid_heap_changes.add_removal(lookup_key);
        Ok(())
    }

    /// Updates an existing user string in the user string heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to modify (1-based, following ECMA-335 conventions)
    /// * `new_value` - The new string value to store at that index
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_update(&mut self, index: u32, new_value: &str) -> Result<()> {
        self.changes
            .userstring_heap_changes
            .add_modification(index, new_value.to_string());
        Ok(())
    }

    /// Removes a user string from the user string heap at the specified index.
    ///
    /// # Arguments
    ///
    /// * `index` - The heap index to remove (1-based, following ECMA-335 conventions)
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_remove(&mut self, index: u32) -> Result<()> {
        self.changes.userstring_heap_changes.add_removal(index);
        Ok(())
    }

    /// Replaces the entire string heap (#Strings) with the provided raw data.
    ///
    /// This completely replaces the string heap content, ignoring the original heap.
    /// If there is no existing string heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// A heap that does not parse is written as it is while nothing else changes in it; a write
    /// that would apply changes to one fails with [`Error::LayoutFailed`].
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new string heap
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // The empty string first, then "Hello" and "World"
    /// let custom_heap = b"\0Hello\0World\0".to_vec();
    /// assembly.string_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn string_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.string_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire blob heap (#Blob) with the provided raw data.
    ///
    /// This completely replaces the blob heap content, ignoring the original heap.
    /// If there is no existing blob heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// A heap that does not parse is written as it is while nothing else changes in it; a write
    /// that would apply changes to one fails with [`Error::LayoutFailed`].
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new blob heap
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // The empty blob first, then two length-prefixed blobs
    /// let custom_heap = vec![0x00, 0x03, 0x01, 0x02, 0x03, 0x02, 0xFF, 0xFE];
    /// assembly.blob_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn blob_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.blob_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire GUID heap (#GUID) with the provided raw data.
    ///
    /// This completely replaces the GUID heap content, ignoring the original heap.
    /// If there is no existing GUID heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// A heap that does not parse is written as it is while nothing else changes in it; a write
    /// that would apply changes to one fails with [`Error::LayoutFailed`].
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new GUID heap (must be 16-byte aligned)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Replace with custom GUID heap containing one GUID
    /// let guid = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    ///             0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    /// assembly.guid_add_heap(guid.to_vec())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn guid_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.guid_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Replaces the entire user string heap (#US) with the provided raw data.
    ///
    /// This completely replaces the user string heap content, ignoring the original heap.
    /// If there is no existing user string heap, a new one will be created. All subsequent
    /// append/modify/remove operations will be applied to this replacement heap
    /// instead of the original.
    ///
    /// A heap that does not parse is written as it is while nothing else changes in it; a write
    /// that would apply changes to one fails with [`Error::LayoutFailed`].
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new user string heap
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(&Path::new("assembly.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // The empty entry first, then "Hel": a length, UTF-16 code units and the terminal byte
    /// let custom_heap = vec![0x00, 0x07, 0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x00];
    /// assembly.userstring_add_heap(custom_heap)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Currently always succeeds, but returns `Result` for future extensibility.
    pub fn userstring_add_heap(&mut self, heap_data: Vec<u8>) -> Result<()> {
        self.changes.userstring_heap_changes.replace_heap(heap_data);
        Ok(())
    }

    /// Updates an existing table row at the specified RID.
    ///
    /// This modifies the row data at the given RID in the specified table.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the row to modify
    /// * `rid` - The Row ID to modify (1-based, following ECMA-335 conventions)
    /// * `new_row` - The new row data to store at that RID
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the modification was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the table operation fails or the provided row data is invalid.
    pub fn table_row_update(
        &mut self,
        table_id: TableId,
        rid: u32,
        new_row: TableDataOwned,
    ) -> Result<()> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count.saturating_add(1)));

        let operation = Operation::Update(rid, new_row);
        let table_operation = TableOperation::new(operation);
        table_changes.apply_operation(table_operation)?;
        Ok(())
    }

    /// Removes a table row at the specified RID.
    ///
    /// This marks the row at the given RID for deletion.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table containing the row to remove
    /// * `rid` - The Row ID to remove (1-based, following ECMA-335 conventions)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the removal was successful.
    ///
    /// # Errors
    ///
    /// Returns an error if the table operation fails or the specified row does not exist.
    pub fn table_row_remove(&mut self, table_id: TableId, rid: u32) -> Result<()> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count.saturating_add(1)));

        let operation = Operation::Delete(rid);
        let table_operation = TableOperation::new(operation);
        table_changes.apply_operation(table_operation)?;

        Ok(())
    }

    /// Basic table row addition.
    ///
    /// This is the foundational method for adding rows to tables.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to add the row to
    /// * `row` - The row data to add
    ///
    /// # Returns
    ///
    /// Returns a [`ChangeRefRc`] that will be resolved to the final token/RID after
    /// the assembly is written. Use `placeholder()` on the returned reference to get
    /// a value that can be stored in other table rows and will be resolved at write time.
    ///
    /// # Errors
    ///
    /// Returns an error if the table cannot be converted to sparse mode.
    pub fn table_row_add(&mut self, table_id: TableId, row: TableDataOwned) -> Result<ChangeRefRc> {
        let original_count = self.original_table_row_count(table_id);
        let table_changes = self
            .changes
            .table_changes
            .entry(table_id)
            .or_insert_with(|| TableModifications::new_sparse(original_count.saturating_add(1)));

        let new_rid = table_changes.next_rid()?;
        let operation = Operation::Insert(new_rid, row);
        let table_operation = TableOperation::new(operation);
        table_changes.apply_operation(table_operation)?;

        // Create and register the ChangeRef for this inserted row
        // Resolve the token immediately since we know both the table ID and RID
        let change_ref = ChangeRef::new_table_row(table_id, self.changes.change_ids.next())?;
        let token = Token::from_parts(table_id, new_rid);
        change_ref.resolve_to_token(token);
        let change_ref_rc = change_ref.into_rc();
        table_changes.register_change_ref(new_rid, change_ref_rc.clone());

        Ok(change_ref_rc)
    }

    /// Writes the assembly to a file.
    ///
    /// This method generates a complete PE file with all modifications applied.
    /// Uses default generator configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the assembly should be written
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or if the assembly is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("input.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    /// assembly.to_file("output.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<()> {
        self.finalize_for_generation()?;
        PeGenerator::new(self).to_file(path)
    }

    /// Writes the assembly to a file with custom configuration.
    ///
    /// This method generates a complete PE file with all modifications applied,
    /// using the specified generator configuration for heap optimization and
    /// other settings.
    ///
    /// # Arguments
    ///
    /// * `path` - The path where the assembly should be written
    /// * `config` - Configuration options for the generator
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written or if the assembly is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use dotscope::prelude::GeneratorConfig;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("input.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    /// assembly.to_file_with_config("output.dll", GeneratorConfig::default())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_file_with_config<P: AsRef<std::path::Path>>(
        &mut self,
        path: P,
        config: GeneratorConfig,
    ) -> Result<()> {
        self.finalize_for_generation()?;
        PeGenerator::with_config(self, config).to_file(path)
    }

    /// Generates the assembly to memory as a byte vector.
    ///
    /// This method generates a complete PE file in memory, useful for:
    /// - In-memory assembly manipulation pipelines
    /// - Testing and validation without file I/O
    /// - Streaming assembly data to network or other outputs
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the complete PE file bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if generation fails or the assembly is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("input.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    /// let pe_bytes = assembly.to_memory()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_memory(&mut self) -> Result<Vec<u8>> {
        self.finalize_for_generation()?;
        PeGenerator::new(self).to_memory()
    }

    /// Generates the assembly to memory with custom configuration.
    ///
    /// This method generates a complete PE file in memory using the specified
    /// generator configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - Configuration options for the generator
    ///
    /// # Returns
    ///
    /// Returns `Ok(Vec<u8>)` containing the complete PE file bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if generation fails or the assembly is invalid.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, CilAssembly};
    /// use dotscope::prelude::GeneratorConfig;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("input.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    /// let pe_bytes = assembly.to_memory_with_config(GeneratorConfig::default())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn to_memory_with_config(&mut self, config: GeneratorConfig) -> Result<Vec<u8>> {
        self.finalize_for_generation()?;
        PeGenerator::with_config(self, config).to_memory()
    }

    /// Converts this `CilAssembly` into a [`CilObject`](crate::CilObject) for analysis.
    ///
    /// This method writes all modifications to memory, then parses the result
    /// as a `CilObject`. Use this after making modifications to obtain a
    /// fully-parsed assembly ready for analysis.
    ///
    /// # Returns
    ///
    /// A [`CilObject`](crate::CilObject) containing the modified assembly.
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("input.dll")?;
    /// let mut mutable = assembly.into_assembly();
    ///
    /// // Perform modifications
    /// mutable.string_add("NewString")?;
    ///
    /// // Convert back to CilObject for analysis
    /// let modified = mutable.into_cilobject()?;
    ///
    /// // Now we can analyze the modified assembly
    /// println!("Types: {}", modified.types().len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if writing modifications fails or if the result
    /// cannot be parsed as a valid .NET assembly.
    pub fn into_cilobject(mut self) -> Result<CilObject> {
        self.finalize_for_generation()?;
        let bytes = PeGenerator::new(&self).to_memory()?;
        CilObject::from_mem_with_validation(bytes, ValidationConfig::production())
    }

    /// Converts this `CilAssembly` into a [`CilObject`](crate::CilObject) with custom options.
    ///
    /// Like [`into_cilobject`](Self::into_cilobject) but allows specifying both
    /// the validation configuration and generator configuration for the resulting assembly.
    ///
    /// # Arguments
    ///
    /// * `validation_config` - Validation configuration for the output
    /// * `generator_config` - Generator configuration for PE file creation (controls optimizations
    ///   like heap deduplication, dead reference elimination, and section exclusion)
    ///
    /// # Returns
    ///
    /// A [`CilObject`](crate::CilObject) containing the modified assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if writing modifications fails or if the result
    /// fails validation.
    pub fn into_cilobject_with(
        mut self,
        validation_config: ValidationConfig,
        generator_config: GeneratorConfig,
    ) -> Result<CilObject> {
        self.finalize_for_generation()?;
        let bytes = PeGenerator::with_config(&self, generator_config).to_memory()?;
        CilObject::from_mem_with_validation(bytes, validation_config)
    }

    /// Discards all changes and recovers the underlying view.
    ///
    /// This is O(1) — it just moves the view out, dropping the changes layer.
    /// The original view is still backed by the unmodified CoW/mmap data.
    #[must_use]
    pub fn into_view(self) -> CilAssemblyView {
        self.view
    }

    /// Gets the original row count for a table
    pub fn original_table_row_count(&self, table_id: TableId) -> u32 {
        if let Some(tables) = self.view.tables() {
            tables.table_row_count(table_id)
        } else {
            0
        }
    }

    /// Gets the next available RID for a table.
    ///
    /// This returns the RID that will be assigned to the next row added to the table.
    /// It accounts for both the original table size and any modifications that have been made.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to query
    ///
    /// # Returns
    ///
    /// The next RID that would be assigned (1-based).
    ///
    /// # Errors
    ///
    /// Returns an error if the row count exceeds u32::MAX.
    pub fn next_rid(&self, table_id: TableId) -> Result<u32> {
        if let Some(modifications) = self.changes.table_changes.get(&table_id) {
            modifications.next_rid()
        } else {
            // No modifications yet - next RID is original count + 1
            self.original_table_row_count(table_id)
                .checked_add(1)
                .ok_or_else(|| Error::LayoutFailed("table row count overflow".to_string()))
        }
    }

    /// Gets a reference to the underlying view for read operations.
    pub fn view(&self) -> &CilAssemblyView {
        &self.view
    }

    /// Gets a reference to the underlying PE file.
    ///
    /// This is a convenience method equivalent to `self.view().file()`.
    pub fn file(&self) -> &File {
        self.view.file()
    }

    /// Gets a reference to the changes for write operations.
    pub fn changes(&self) -> &AssemblyChanges {
        &self.changes
    }

    /// Gets a mutable reference to the changes for write operations.
    pub fn changes_mut(&mut self) -> &mut AssemblyChanges {
        &mut self.changes
    }

    /// Adds a DLL to the native import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// This method provides the foundation for native PE import functionality by managing
    /// DLL dependencies at the assembly level.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Returns
    ///
    /// `Ok(())` if the DLL was added successfully, or if it already exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// assembly.add_native_import_dll("kernel32.dll")?;
    /// assembly.add_native_import_dll("user32.dll")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_dll(&mut self, dll_name: &str) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.native_mut().add_dll(dll_name)
    }

    /// Adds a named function import from a specific DLL to the native import table.
    ///
    /// Adds a function import that uses name-based lookup. The DLL will be automatically
    /// added to the import table if it doesn't already exist. This method handles the
    /// complete import process including IAT allocation and Import Lookup Table setup.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name or function name is empty
    /// - The function is already imported from this DLL
    /// - There are issues with IAT allocation
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Add kernel32 functions
    /// assembly.add_native_import_function("kernel32.dll", "GetCurrentProcessId")?;
    /// assembly.add_native_import_function("kernel32.dll", "ExitProcess")?;
    ///
    /// // Add user32 functions  
    /// assembly.add_native_import_function("user32.dll", "MessageBoxW")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function(
        &mut self,
        dll_name: &str,
        function_name: &str,
    ) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.add_native_function(dll_name, function_name)
    }

    /// Adds an ordinal-based function import to the native import table.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient and result in smaller import tables, but is less
    /// portable across DLL versions. The DLL will be automatically added if it
    /// doesn't exist.
    ///
    /// # Arguments
    ///
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL name is empty
    /// - The ordinal is 0 (invalid)
    /// - A function with the same ordinal is already imported from this DLL
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Import MessageBoxW by ordinal (more efficient)
    /// assembly.add_native_import_function_by_ordinal("user32.dll", 120)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_import_function_by_ordinal(
        &mut self,
        dll_name: &str,
        ordinal: u16,
    ) -> Result<()> {
        let imports = self.changes.native_imports_mut();
        imports.add_native_function_by_ordinal(dll_name, ordinal)
    }

    /// Adds a named function export to the native export table.
    ///
    /// Creates a function export that can be called by other modules. The function
    /// will be accessible by both name and ordinal. This method handles the complete
    /// export process including Export Address Table and Export Name Table setup.
    ///
    /// # Arguments
    ///
    /// * `function_name` - Name of the function to export
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `address` - Function address (RVA) in the image
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was exported successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The function name is empty
    /// - The ordinal is 0 (invalid) or already in use
    /// - The function name is already exported
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Export library functions
    /// assembly.add_native_export_function("MyLibraryInit", 1, 0x1000)?;
    /// assembly.add_native_export_function("ProcessData", 2, 0x2000)?;
    /// assembly.add_native_export_function("MyLibraryCleanup", 3, 0x3000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function(
        &mut self,
        function_name: &str,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_function(function_name, ordinal, address)
    }

    /// Adds an ordinal-only function export to the native export table.
    ///
    /// Creates a function export that is accessible by ordinal number only,
    /// without a symbolic name. This can reduce the size of the export table
    /// but makes the exports less discoverable.
    ///
    /// # Arguments
    ///
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `address` - Function address (RVA) in the image
    ///
    /// # Returns
    ///
    /// `Ok(())` if the function was exported successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if the ordinal is 0 (invalid) or already in use.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Export internal functions by ordinal only
    /// assembly.add_native_export_function_by_ordinal(100, 0x5000)?;
    /// assembly.add_native_export_function_by_ordinal(101, 0x6000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_function_by_ordinal(
        &mut self,
        ordinal: u16,
        address: u32,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_function_by_ordinal(ordinal, address)
    }

    /// Adds an export forwarder to the native export table.
    ///
    /// Creates a function export that forwards calls to a function in another DLL.
    /// The Windows loader resolves forwarders at runtime by loading the target
    /// DLL and finding the specified function. This is useful for implementing
    /// compatibility shims or redirecting calls.
    ///
    /// # Arguments
    ///
    /// * `function_name` - Name of the exported function (can be empty for ordinal-only)
    /// * `ordinal` - Ordinal number for the export (must be unique)
    /// * `target` - Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    ///
    /// # Returns
    ///
    /// `Ok(())` if the forwarder was added successfully.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ordinal is 0 (invalid) or already in use
    /// - The function name is already exported (if name is provided)
    /// - The target specification is empty or malformed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// // Forward to functions in other DLLs
    /// assembly.add_native_export_forwarder("GetProcessId", 10, "kernel32.dll.GetCurrentProcessId")?;
    /// assembly.add_native_export_forwarder("MessageBox", 11, "user32.dll.MessageBoxW")?;
    /// assembly.add_native_export_forwarder("OrdinalForward", 12, "mydll.dll.#50")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn add_native_export_forwarder(
        &mut self,
        function_name: &str,
        ordinal: u16,
        target: &str,
    ) -> Result<()> {
        let exports = self.changes.native_exports_mut();
        exports.add_native_forwarder(function_name, ordinal, target)
    }

    /// Sets the name the native export table exports under, which the written image's export
    /// directory holds in place of the original's.
    ///
    /// # Errors
    ///
    /// When the name is empty or holds a null byte.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    /// assembly.set_native_export_dll_name("MyLibrary.dll")?;
    /// assembly.add_native_export_function("MyFunction", 1, 0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn set_native_export_dll_name(&mut self, dll_name: &str) -> Result<()> {
        self.changes.native_exports_mut().set_dll_name(dll_name)
    }

    /// Gets read-only access to the unified import container.
    ///
    /// Returns the unified import container that provides access to both CIL and native
    /// PE imports. Returns `None` if no native import operations have been performed.
    ///
    /// # Returns
    ///
    /// Optional reference to the unified import container.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    ///
    /// let imports = assembly.native_imports();
    /// let dll_names = imports.get_all_dll_names();
    /// println!("DLL dependencies: {:?}", dll_names);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_imports(&self) -> &UnifiedImportContainer {
        self.changes.native_imports()
    }

    /// Gets read-only access to the unified export container.
    ///
    /// Returns the unified export container that provides access to both CIL and native
    /// PE exports. Returns `None` if no native export operations have been performed.
    ///
    /// # Returns
    ///
    /// Optional reference to the unified export container.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    ///
    /// let exports = assembly.native_exports();
    /// let function_names = exports.get_native_function_names();
    /// println!("Exported functions: {:?}", function_names);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn native_exports(&self) -> &UnifiedExportContainer {
        self.changes.native_exports()
    }

    /// Stores a method body and allocates a placeholder RVA for it.
    ///
    /// This method stores the method body with a placeholder RVA that will be resolved
    /// to the actual RVA during PE writing when the code section layout is determined.
    /// Used by method builders to store compiled method bodies and get placeholder RVAs
    /// for use in method definition metadata.
    ///
    /// # Arguments
    ///
    /// * `body_bytes` - The complete method body bytes including header and exception handlers
    ///
    /// # Returns
    ///
    /// A placeholder RVA that will be resolved to the actual RVA during binary writing.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let mut assembly = CilAssembly::new(view);
    ///
    /// let method_body = vec![0x02, 0x17, 0x2A]; // Tiny header + ldc.i4.1 + ret
    /// let placeholder_rva = assembly.store_method_body(method_body);
    /// // placeholder_rva will be resolved to actual RVA during binary writing
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn store_method_body(&mut self, body_bytes: Vec<u8>) -> u32 {
        self.changes.store_method_body(body_bytes)
    }

    /// Stores field initialization data and returns a placeholder RVA.
    ///
    /// The returned placeholder RVA is a temporary identifier that will later
    /// be resolved to the actual RVA during PE writing when the section layout
    /// is determined. This is used for FieldRVA entries that point to static
    /// field initialization data.
    ///
    /// # Arguments
    ///
    /// * `data` - The field initialization data bytes
    ///
    /// # Returns
    ///
    /// A placeholder RVA that will be resolved to the actual RVA during binary writing.
    pub fn store_field_data(&mut self, data: Vec<u8>) -> u32 {
        self.changes.store_field_data(data)
    }

    /// Gets or adds a string to the string heap, reusing existing strings when possible.
    ///
    /// This method first checks if the string already exists in the heap changes
    /// and reuses it if found. This helps avoid duplicate namespace strings and
    /// other common strings.
    ///
    /// # Arguments
    ///
    /// * `value` - The string to get or add to the heap
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the string offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the string cannot be added to the heap.
    pub fn string_get_or_add(&mut self, value: &str) -> Result<ChangeRefRc> {
        if let Some(existing_ref) = self.string_find(value) {
            return Ok(existing_ref);
        }
        self.string_add(value)
    }

    /// Helper method to find an existing string in the current heap changes.
    ///
    /// This searches through the strings added in the current session
    /// to avoid duplicates within the same session.
    fn string_find(&self, value: &str) -> Option<ChangeRefRc> {
        let heap_changes = &self.changes.string_heap_changes;
        for (existing_string, change_ref) in heap_changes.appended_iter() {
            if existing_string == value {
                return Some(change_ref.clone());
            }
        }
        None
    }

    /// Finds an AssemblyRef by its name.
    ///
    /// This method searches the AssemblyRef table to find an assembly reference
    /// with the specified name. This is useful for locating specific dependencies
    /// or core libraries.
    ///
    /// # Arguments
    ///
    /// * `name` - The exact name of the assembly to find (case-sensitive)
    ///
    /// # Returns
    ///
    /// A [`CodedIndex`] pointing to the matching AssemblyRef, or None if not found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::{CilAssemblyView, CilAssembly};
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// let assembly = CilAssembly::new(view);
    ///
    /// // Find a specific library
    /// if let Some(newtonsoft_ref) = assembly.find_assembly_ref_by_name("Newtonsoft.Json") {
    ///     println!("Found Newtonsoft.Json reference");
    /// }
    ///
    /// // Find core library
    /// if let Some(mscorlib_ref) = assembly.find_assembly_ref_by_name("mscorlib") {
    ///     println!("Found mscorlib reference");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn find_assembly_ref_by_name(&self, name: &str) -> Option<CodedIndex> {
        if let (Some(assembly_ref_table), Some(strings)) = (
            self.view.tables()?.table::<AssemblyRefRaw>(),
            self.view.strings(),
        ) {
            for assemblyref in assembly_ref_table.iter().filter_map(skip_unreadable) {
                if let Ok(assembly_name) = strings.get(assemblyref.name as usize) {
                    if assembly_name == name {
                        return Some(CodedIndex::new(
                            TableId::AssemblyRef,
                            assemblyref.rid,
                            CodedIndexType::Implementation,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Finds the AssemblyRef for the core library.
    ///
    /// The core library is the assembly defining `System.Object`, so the scope
    /// of the module's own `System.Object` reference names it (its
    /// `System.ValueType` reference in a module declaring only value types),
    /// whatever the library is called on the runtime the module targets. Among
    /// several such references the lowest row decides, as the compiler emits
    /// its rows before anything appended to the image later.
    ///
    /// # Returns
    ///
    /// A [`CodedIndex`] pointing to the core library AssemblyRef, or None when
    /// the module imports neither type from another assembly (the core library
    /// itself, for instance).
    pub fn find_core_library_ref(&self) -> Option<CodedIndex> {
        let scope = self.core_library_scope()?;
        (scope.tag == TableId::AssemblyRef).then(|| {
            CodedIndex::new(
                TableId::AssemblyRef,
                scope.row,
                CodedIndexType::Implementation,
            )
        })
    }

    /// Finds the TypeRef through which the module imports `namespace.name` from
    /// its core library (see [`CilAssembly::find_core_library_ref`]).
    ///
    /// A module can import one type from several scopes - an obfuscator built
    /// against another runtime adds references to that runtime's core library -
    /// and only the reference into the module's core library resolves wherever
    /// the module runs. Falls back to the lowest TypeRef of that name when the
    /// core library does not provide the type.
    ///
    /// # Returns
    ///
    /// A `TypeDefOrRef` [`CodedIndex`] for the TypeRef, or None when the module
    /// does not import the type.
    pub fn find_corelib_typeref(&self, namespace: &str, name: &str) -> Option<CodedIndex> {
        let corelib = self.core_library_scope();
        let mut rows = self.typeref_rows_named(namespace, name);
        let first = rows.next()?;
        let row = match corelib {
            Some(scope) if scope != first.resolution_scope => rows
                .find(|row| row.resolution_scope == scope)
                .unwrap_or(first),
            _ => first,
        };
        Some(CodedIndex::new(
            TableId::TypeRef,
            row.rid,
            CodedIndexType::TypeDefOrRef,
        ))
    }

    /// Finds the core library type `namespace.name` as this module names it: its TypeRef into
    /// the core library ([`CilAssembly::find_corelib_typeref`]), or, in a module that references
    /// no core library (the core library itself), its own TypeDef of that name.
    ///
    /// # Returns
    ///
    /// A `TypeDefOrRef` [`CodedIndex`], or None when the module neither imports the type nor,
    /// being the core library, defines it.
    #[must_use]
    pub fn find_corelib_type(&self, namespace: &str, name: &str) -> Option<CodedIndex> {
        if let Some(found) = self.find_corelib_typeref(namespace, name) {
            return Some(found);
        }
        if self.find_core_library_ref().is_some() {
            return None;
        }
        let view = self.view();
        let (tables, strings) = (view.tables()?, view.strings()?);
        tables
            .table::<TypeDefRaw>()
            .into_iter()
            .flat_map(|table| table.iter().filter_map(skip_unreadable))
            .find(|row| {
                strings
                    .get(row.type_name as usize)
                    .is_ok_and(|found| found == name)
                    && strings
                        .get(row.type_namespace as usize)
                        .is_ok_and(|found| found == namespace)
            })
            .map(|row| CodedIndex::new(TableId::TypeDef, row.rid, CodedIndexType::TypeDefOrRef))
    }

    /// Returns the resolution scope of the module's core library imports.
    ///
    /// That is the scope of its `System.Object` reference, or of its
    /// `System.ValueType` reference in a module declaring only value types;
    /// the core library defines both.
    fn core_library_scope(&self) -> Option<CodedIndex> {
        self.typeref_rows_named("System", "Object")
            .next()
            .or_else(|| self.typeref_rows_named("System", "ValueType").next())
            .map(|root| root.resolution_scope)
    }

    /// Returns the original TypeRef rows naming `namespace.name`, lowest row first.
    fn typeref_rows_named<'a>(
        &'a self,
        namespace: &'a str,
        name: &'a str,
    ) -> impl Iterator<Item = TypeRefRaw> + 'a {
        let strings = self.view.strings();
        let is_named = move |row: &TypeRefRaw| {
            strings.is_some_and(|strings| {
                strings.get(row.type_name as usize).is_ok_and(|n| n == name)
                    && strings
                        .get(row.type_namespace as usize)
                        .is_ok_and(|ns| ns == namespace)
            })
        };
        self.view
            .tables()
            .and_then(|tables| tables.table::<TypeRefRaw>())
            .into_iter()
            .flat_map(|table| table.iter().filter_map(skip_unreadable))
            .filter(is_named)
    }

    /// Adds a method signature to the blob heap and returns its index.
    ///
    /// This encodes the method signature using the dedicated method signature encoder.
    /// The encoder handles all ECMA-335 method signature format requirements including
    /// calling conventions, parameter counts, and type encoding.
    ///
    /// # Arguments
    ///
    /// * `signature` - The method signature to encode and store
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the blob heap offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature cannot be encoded or added to the blob heap.
    pub fn add_method_signature(&mut self, signature: &SignatureMethod) -> Result<ChangeRefRc> {
        let encoded_data = encode_method_signature(signature)?;
        self.blob_add(&encoded_data)
    }

    /// Adds a field signature to the blob heap and returns its index.
    ///
    /// This encodes the field signature using the dedicated field signature encoder.
    /// The encoder handles ECMA-335 field signature format requirements including
    /// custom modifiers and field type encoding.
    ///
    /// # Arguments
    ///
    /// * `signature` - The field signature to encode and store
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the blob heap offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature cannot be encoded or added to the blob heap.
    pub fn add_field_signature(&mut self, signature: &SignatureField) -> Result<ChangeRefRc> {
        let encoded_data = encode_field_signature(signature)?;
        self.blob_add(&encoded_data)
    }

    /// Adds a property signature to the blob heap and returns its index.
    ///
    /// This encodes the property signature using the dedicated property signature encoder.
    /// The encoder handles ECMA-335 property signature format requirements including
    /// instance/static properties and indexer parameters.
    ///
    /// # Arguments
    ///
    /// * `signature` - The property signature to encode and store
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the blob heap offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature cannot be encoded or added to the blob heap.
    pub fn add_property_signature(&mut self, signature: &SignatureProperty) -> Result<ChangeRefRc> {
        let encoded_data = encode_property_signature(signature)?;
        self.blob_add(&encoded_data)
    }

    /// Adds a local variable signature to the blob heap and returns its index.
    ///
    /// This encodes the local variable signature using the dedicated local variable encoder.
    /// The encoder handles ECMA-335 local variable signature format requirements including
    /// pinned and byref modifiers.
    ///
    /// # Arguments
    ///
    /// * `signature` - The local variable signature to encode and store
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the blob heap offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature cannot be encoded or added to the blob heap.
    pub fn add_local_var_signature(
        &mut self,
        signature: &SignatureLocalVariables,
    ) -> Result<ChangeRefRc> {
        let encoded_data = encode_local_var_signature(signature)?;
        self.blob_add(&encoded_data)
    }

    /// Adds a type specification signature to the blob heap and returns its index.
    ///
    /// This encodes the type specification signature using the dedicated type specification
    /// encoder. Type specification signatures encode complex type signatures for generic
    /// instantiations, arrays, pointers, and other complex types.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type specification signature to encode and store
    ///
    /// # Returns
    ///
    /// A ChangeRef that will resolve to the blob heap offset after write.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature cannot be encoded or added to the blob heap.
    pub fn add_typespec_signature(&mut self, signature: &SignatureTypeSpec) -> Result<ChangeRefRc> {
        let encoded_data = encode_typespec_signature(signature)?;
        self.blob_add(&encoded_data)
    }
}

/// Conversion from `CilAssemblyView` to `CilAssembly`.
///
/// This provides the `view.to_owned()` syntax mentioned in the documentation.
impl From<CilAssemblyView> for CilAssembly {
    fn from(view: CilAssemblyView) -> Self {
        Self::new(view)
    }
}

impl fmt::Debug for CilAssembly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CilAssembly")
            .field("original_view", &"<CilAssemblyView>")
            .field("has_changes", &self.changes.has_changes())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        metadata::{tables::TypeDefBuilder, validation::ValidationConfig},
        testkit::{
            factories::table::cilassembly::create_test_typedef_row,
            fixture,
            helpers::{load_sample, runtime_type_handle_rows, TWO_CORELIB_FIXTURES},
        },
        CilObject, Error,
    };

    /// A cleanup request's settings are the cleanup's: a request that keeps empty types keeps
    /// them, where merging it into the default pending request removed them anyway (the
    /// deobfuscator's `remove_empty_types: false` did nothing). A later request narrows them.
    #[test]
    fn a_cleanup_request_keeps_its_settings() {
        let surviving = |requests: &[CleanupRequest]| -> Vec<String> {
            let mut assembly = load_sample("packers/confuserex/1.6.0/original.exe").into_assembly();
            for name in ["Removed", "Empty"] {
                TypeDefBuilder::new()
                    .name(name)
                    .namespace("Cleanup")
                    .build(&mut assembly)
                    .unwrap();
            }
            let written = CilObject::from_mem_with_validation(
                assembly.to_memory().unwrap(),
                ValidationConfig::analysis(),
            )
            .unwrap();
            let removed = written
                .types()
                .iter()
                .find(|entry| entry.value().name == "Removed")
                .map(|entry| *entry.key())
                .unwrap();
            let mut assembly = written.into_assembly();
            for request in requests {
                let mut request = request.clone();
                request.add_type(removed);
                assembly.add_cleanup(&request);
            }
            let cleaned = CilObject::from_mem_with_validation(
                assembly.to_memory().unwrap(),
                ValidationConfig::analysis(),
            )
            .unwrap();
            cleaned
                .types()
                .iter()
                .filter(|entry| entry.value().namespace == "Cleanup")
                .map(|entry| entry.value().name.clone())
                .collect()
        };
        let keeps_empty = CleanupRequest::with_settings(true, false);
        assert_eq!(surviving(std::slice::from_ref(&keeps_empty)), ["Empty"]);
        assert!(surviving(&[CleanupRequest::new()]).is_empty());
        assert_eq!(
            surviving(&[CleanupRequest::new(), keeps_empty]),
            ["Empty"],
            "a later request narrows the settings"
        );
    }

    /// A replacement heap that does not parse is written as it is, but changes cannot be
    /// applied to it: the writer dropped it and kept only the additions, leaving every
    /// reference into it dangling, where it must refuse.
    #[test]
    fn changes_to_a_heap_that_does_not_parse_are_refused() {
        type Edit = fn(&mut CilAssembly) -> Result<()>;
        let cases: [(&str, Edit); 4] = [
            ("#Strings", |a| {
                a.string_add_heap(b"Hello\0World\0".to_vec())?;
                a.string_add("added").map(drop)
            }),
            ("#Blob", |a| {
                a.blob_add_heap(vec![1, 2, 3])?;
                a.blob_add(&[4, 5]).map(drop)
            }),
            ("#GUID", |a| {
                a.guid_add_heap(vec![7; 8])?;
                a.guid_add(&[9; 16]).map(drop)
            }),
            ("#US", |a| {
                a.userstring_add_heap(vec![3, b'a', 0, 0])?;
                a.userstring_add("added").map(drop)
            }),
        ];
        let mut wrong = Vec::new();
        for (heap, edit) in cases {
            let mut assembly = load_sample("crafted_2.exe").into_assembly();
            edit(&mut assembly).unwrap();
            match assembly.to_memory() {
                Err(Error::LayoutFailed(message)) if message.contains(heap) => {}
                other => wrong.push(format!("{heap}: {:?}", other.map(|bytes| bytes.len()))),
            }
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    #[test]
    fn test_convert_from_view() {
        let path = fixture("WindowsBase.dll");
        let _assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Basic smoke test - conversion should succeed
    }

    #[test]
    fn test_add_string() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let ref1 = assembly.string_add("Hello").unwrap();
        let ref2 = assembly.string_add("World").unwrap();

        assert_ne!(ref1.placeholder(), ref2.placeholder());
        assert!(ref2.placeholder() > ref1.placeholder());
    }

    #[test]
    fn test_add_blob() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let ref1 = assembly.blob_add(&[1, 2, 3]).unwrap();
        let ref2 = assembly.blob_add(&[4, 5, 6]).unwrap();

        assert_ne!(ref1.placeholder(), ref2.placeholder());
        assert!(ref2.placeholder() > ref1.placeholder());
    }

    #[test]
    fn test_add_guid() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let guid1 = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let guid2 = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];

        let ref1 = assembly.guid_add(&guid1).unwrap();
        let ref2 = assembly.guid_add(&guid2).unwrap();

        assert_ne!(ref1.placeholder(), ref2.placeholder());
        assert!(ref2.placeholder() > ref1.placeholder());
    }

    #[test]
    fn test_add_userstring() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        let ref1 = assembly.userstring_add("Hello").unwrap();
        let ref2 = assembly.userstring_add("World").unwrap();

        assert_ne!(ref1.placeholder(), ref2.placeholder());
        assert!(ref2.placeholder() > ref1.placeholder());
    }

    #[test]
    fn test_table_row_assignment_uses_correct_rid() {
        let path = fixture("WindowsBase.dll");
        let mut assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Create a minimal TypeDef row for testing
        let typedef_row = create_test_typedef_row().expect("the TypeDef row builds");
        let change_ref = assembly
            .table_row_add(TableId::TypeDef, typedef_row)
            .expect("the row is added");
        assert!(
            change_ref.kind().is_table(),
            "ChangeRef should be a table row reference"
        );
        assert_eq!(
            change_ref.kind().table_id(),
            Some(TableId::TypeDef),
            "ChangeRef should be for TypeDef table"
        );

        // Another row gets a different ChangeRef.
        let typedef_row2 = create_test_typedef_row().expect("the TypeDef row builds");
        let change_ref2 = assembly
            .table_row_add(TableId::TypeDef, typedef_row2)
            .expect("the second row is added");
        assert_ne!(
            change_ref.id(),
            change_ref2.id(),
            "Different rows should have different ChangeRef IDs"
        );
    }

    #[test]
    fn test_heap_changes_initialized() {
        let path = fixture("WindowsBase.dll");
        let assembly = CilAssembly::from_path(&path).expect("the fixture loads");
        // Verify heap changes are properly initialized
        // The additions count should be 0 initially
        assert_eq!(assembly.changes.string_heap_changes.additions_count(), 0);
        assert_eq!(assembly.changes.blob_heap_changes.additions_count(), 0);
        assert_eq!(assembly.changes.guid_heap_changes.additions_count(), 0);
        assert_eq!(
            assembly.changes.userstring_heap_changes.additions_count(),
            0
        );
    }

    /// Mono runtime compatibility tests for assembly modification and execution
    mod mono_tests {
        use super::*;
        use crate::{
            metadata::{
                signatures::{
                    encode_method_signature, SignatureMethod, SignatureParameter, TypeSignature,
                },
                tables::{CodedIndex, CodedIndexType, MemberRefBuilder, TableId, TypeRefBuilder},
                token::Token,
            },
            testkit::mono::*,
        };

        #[test]
        fn test_mono_runtime_compatibility() -> Result<()> {
            // Create test runner using the new utilities
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            // Define the assembly modification that adds a simple method
            let modify_assembly = |assembly: &mut CilAssembly| -> Result<()> {
                let _method_token = MethodBuilder::new("DotScopeAddedMethod")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;
                Ok(())
            };

            // Run the complete test workflow
            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                |_| Vec::new(),
            )?;

            // Assert all architectures passed all tests
            for result in &results {
                assert!(
                    result.compilation_success,
                    "Compilation failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.modification_success,
                    "Assembly modification failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.execution_success,
                    "Execution failed for {}: {:?}",
                    result.architecture.name, result.errors
                );
                assert!(
                    result.disassembly_success != Some(false),
                    "Disassembly verification failed for {}: {:?}",
                    result.architecture.name,
                    result.errors
                );
                assert!(
                    result.reflection_success,
                    "Reflection test failed for {}: {:?}",
                    result.architecture.name, result.errors
                );

                // Assert overall success
                assert!(
                    result.is_fully_successful(),
                    "Overall test failed for {} architecture with errors: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            // Assert we tested all available architectures
            let expected_arch_count = runner.architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );

            Ok(())
        }

        #[test]
        fn test_mono_enhanced_modifications() -> Result<()> {
            // Create test runner using the new utilities
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            // Test string modification by adding a simple method
            let modify_assembly = |assembly: &mut CilAssembly| -> Result<()> {
                // Create method that prints the modified message using Console.WriteLine
                let new_string = "MODIFIED: Hello from enhanced dotscope test!";
                let new_string_ref = assembly.userstring_add(new_string)?;
                // Use placeholder value - bit 31 marks it as placeholder, resolved during write
                let new_string_token = Token::new(0x70000000 | new_string_ref.placeholder());

                // Find the assembly reference containing System.Console
                // .NET 8+ uses separate System.Console assembly, while older frameworks use mscorlib
                let console_assembly_ref = assembly
                    .find_assembly_ref_by_name("System.Console")
                    .or_else(|| assembly.find_core_library_ref())
                    .ok_or_else(|| {
                        Error::TypeError(
                            "Could not find System.Console or core library reference".to_string(),
                        )
                    })?;
                let console_assembly_token =
                    Token::new((TableId::AssemblyRef as u32) << 24 | console_assembly_ref.row);
                let console_writeline_ref =
                    create_console_writeline_ref(assembly, console_assembly_token)?;

                // Add a method that prints the modified string
                let new_string_token_copy = new_string_token;
                let console_writeline_ref_copy = console_writeline_ref;
                let _method_token = MethodBuilder::new("PrintModifiedMessage")
                    .public()
                    .static_method()
                    .returns(TypeSignature::Void)
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldstr(new_string_token_copy)?
                                .call(console_writeline_ref_copy)?
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                Ok(())
            };

            // Run the complete test workflow
            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                |_| Vec::new(),
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "String test execution failed for {}: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            Ok(())
        }

        fn create_writeline_signature() -> Result<Vec<u8>> {
            let signature = SignatureMethod {
                has_this: false, // Static method
                explicit_this: false,
                default: true, // Default managed calling convention
                vararg: false,
                cdecl: false,
                stdcall: false,
                thiscall: false,
                fastcall: false,
                unmanaged: false,
                param_count_generic: 0,
                param_count: 1, // One string parameter
                return_type: SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::Void, // void return type
                },
                params: vec![SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::String, // string parameter
                }],
                varargs: Vec::new(),
            };

            encode_method_signature(&signature)
        }

        fn create_console_writeline_ref(
            assembly: &mut CilAssembly,
            mscorlib_ref: Token,
        ) -> Result<Token> {
            // Create TypeRef for System.Console
            let console_typeref_ref = TypeRefBuilder::new()
                .name("Console")
                .namespace("System")
                .resolution_scope(CodedIndex::new(
                    TableId::AssemblyRef,
                    mscorlib_ref.row(),
                    CodedIndexType::ResolutionScope,
                ))
                .build(assembly)?;
            let console_typeref_token = console_typeref_ref.placeholder_token().unwrap();

            // Create method signature for Console.WriteLine(string) using the working implementation
            let writeline_signature = create_writeline_signature()?;

            // Create MemberRef for Console.WriteLine method
            let memberref_ref = MemberRefBuilder::new()
                .name("WriteLine")
                .class(CodedIndex::new(
                    TableId::TypeRef,
                    console_typeref_token.row(),
                    CodedIndexType::MemberRefParent,
                ))
                .signature(&writeline_signature)
                .build(assembly)?;

            Ok(memberref_ref.placeholder_token().unwrap())
        }

        #[test]
        fn test_mono_mathematical_operations() -> Result<()> {
            // Test advanced mathematical operations and complex arithmetic
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            let modify_assembly = |assembly: &mut CilAssembly| -> Result<()> {
                // Create method that performs multiple arithmetic operations
                // ComplexMath: (x * y) + (x - y) * 2
                let _complex_math_method = MethodBuilder::new("ComplexMath")
                    .public()
                    .static_method()
                    .parameter("x", TypeSignature::I4)
                    .parameter("y", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?
                                .ldarg_1()?
                                .mul()?
                                .ldarg_0()?
                                .ldarg_1()?
                                .sub()?
                                .ldc_i4_2()?
                                .mul()?
                                .add()?
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                // DivideAndRemainder: (dividend / divisor) + (dividend % divisor)
                let _division_method = MethodBuilder::new("DivideAndRemainder")
                    .public()
                    .static_method()
                    .parameter("dividend", TypeSignature::I4)
                    .parameter("divisor", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?
                                .ldarg_1()?
                                .div()?
                                .ldarg_0()?
                                .ldarg_1()?
                                .rem()?
                                .add()?
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                Ok(())
            };

            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                |_assembly_path| {
                    vec![
                        // Test ComplexMath: (x * y) + (x - y) * 2
                        // With x=5, y=3: (5*3) + (5-3)*2 = 15 + 4 = 19
                        MethodTest::new("ComplexMath")
                            .arg_int(5)
                            .arg_int(3)
                            .expect_int(19)
                            .describe("ComplexMath(5, 3) = 19"),
                        // With x=10, y=4: (10*4) + (10-4)*2 = 40 + 12 = 52
                        MethodTest::new("ComplexMath")
                            .arg_int(10)
                            .arg_int(4)
                            .expect_int(52)
                            .describe("ComplexMath(10, 4) = 52"),
                        // Test DivideAndRemainder: (dividend / divisor) + (dividend % divisor)
                        // With dividend=17, divisor=5: (17/5) + (17%5) = 3 + 2 = 5
                        MethodTest::new("DivideAndRemainder")
                            .arg_int(17)
                            .arg_int(5)
                            .expect_int(5)
                            .describe("DivideAndRemainder(17, 5) = 5"),
                        // With dividend=20, divisor=4: (20/4) + (20%4) = 5 + 0 = 5
                        MethodTest::new("DivideAndRemainder")
                            .arg_int(20)
                            .arg_int(4)
                            .expect_int(5)
                            .describe("DivideAndRemainder(20, 4) = 5"),
                    ]
                },
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Mathematical operations test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            Ok(())
        }

        #[test]
        fn test_mono_local_variables_and_stack_operations() -> Result<()> {
            // Test local variable manipulation and stack operations
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            let modify_assembly = |assembly: &mut CilAssembly| -> Result<()> {
                // TestLocalVariables: temp1=input*2, temp2=temp1+5, return temp2-temp1 (always 5)
                let _local_vars_method = MethodBuilder::new("TestLocalVariables")
                    .public()
                    .static_method()
                    .parameter("input", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.local("temp1", TypeSignature::I4)
                            .local("temp2", TypeSignature::I4)
                            .implementation(|asm| {
                                asm.ldarg_0()?
                                    .ldc_i4_2()?
                                    .mul()?
                                    .stloc_0()?
                                    .ldloc_0()?
                                    .ldc_i4_5()?
                                    .add()?
                                    .stloc_1()?
                                    .ldloc_1()?
                                    .ldloc_0()?
                                    .sub()?
                                    .ret()?;
                                Ok(())
                            })
                    })
                    .build(assembly)?;

                // StackOperations: 2a + b (uses dup to duplicate 'a' on stack)
                let _stack_ops_method = MethodBuilder::new("StackOperations")
                    .public()
                    .static_method()
                    .parameter("a", TypeSignature::I4)
                    .parameter("b", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.dup()?.ldarg_1()?.add()?.add()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                Ok(())
            };

            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                |_assembly_path| {
                    vec![
                        // TestLocalVariables: temp1=input*2, temp2=temp1+5, return temp2-temp1
                        // With input=10: temp1=20, temp2=25, return 25-20=5
                        MethodTest::new("TestLocalVariables")
                            .arg_int(10)
                            .expect_int(5)
                            .describe("TestLocalVariables(10) = 5"),
                        // With input=7: temp1=14, temp2=19, return 19-14=5
                        MethodTest::new("TestLocalVariables")
                            .arg_int(7)
                            .expect_int(5)
                            .describe("TestLocalVariables(7) = 5"),
                        // StackOperations: 2a + b
                        // With a=3, b=4: 2*3 + 4 = 10
                        MethodTest::new("StackOperations")
                            .arg_int(3)
                            .arg_int(4)
                            .expect_int(10)
                            .describe("StackOperations(3, 4) = 10"),
                        // With a=5, b=7: 2*5 + 7 = 17
                        MethodTest::new("StackOperations")
                            .arg_int(5)
                            .arg_int(7)
                            .expect_int(17)
                            .describe("StackOperations(5, 7) = 17"),
                    ]
                },
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Local variables test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            Ok(())
        }

        #[test]
        fn test_mono_multiple_method_cross_references() -> Result<()> {
            // Test multiple methods that call each other
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            let modify_assembly = |assembly: &mut CilAssembly| -> Result<()> {
                // DoubleNumber: value * 2
                let double_method = MethodBuilder::new("DoubleNumber")
                    .public()
                    .static_method()
                    .parameter("value", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldc_i4_2()?.mul()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                // AddTen: value + 10
                let add_ten_method = MethodBuilder::new("AddTen")
                    .public()
                    .static_method()
                    .parameter("value", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.implementation(|asm| {
                            asm.ldarg_0()?.ldc_i4_s(10)?.add()?.ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                // ProcessNumber: calls DoubleNumber then AddTen => (input * 2) + 10
                let double_token = double_method.placeholder_token().unwrap();
                let add_ten_token = add_ten_method.placeholder_token().unwrap();
                let _main_method = MethodBuilder::new("ProcessNumber")
                    .public()
                    .static_method()
                    .parameter("input", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(move |body| {
                        body.implementation(move |asm| {
                            asm.ldarg_0()?
                                .call(double_token)?
                                .call(add_ten_token)?
                                .ret()?;
                            Ok(())
                        })
                    })
                    .build(assembly)?;

                // Factorial: iterative implementation with loop
                let _factorial_method = MethodBuilder::new("Factorial")
                    .public()
                    .static_method()
                    .parameter("n", TypeSignature::I4)
                    .returns(TypeSignature::I4)
                    .implementation(|body| {
                        body.local("result", TypeSignature::I4)
                            .local("counter", TypeSignature::I4)
                            .implementation(|asm| {
                                asm.ldc_i4_1()?
                                    .stloc_0()?
                                    .ldc_i4_1()?
                                    .stloc_1()?
                                    .label("loop_start")?
                                    .ldloc_1()?
                                    .ldarg_0()?
                                    .bgt_s("loop_end")?
                                    .ldloc_0()?
                                    .ldloc_1()?
                                    .mul()?
                                    .stloc_0()?
                                    .ldloc_1()?
                                    .ldc_i4_1()?
                                    .add()?
                                    .stloc_1()?
                                    .br_s("loop_start")?
                                    .label("loop_end")?
                                    .ldloc_0()?
                                    .ret()?;
                                Ok(())
                            })
                    })
                    .build(assembly)?;

                Ok(())
            };

            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                modify_assembly,
                |_assembly_path| {
                    vec![
                        // DoubleNumber: value * 2
                        MethodTest::new("DoubleNumber")
                            .arg_int(5)
                            .expect_int(10)
                            .describe("DoubleNumber(5) = 10"),
                        // AddTen: value + 10
                        MethodTest::new("AddTen")
                            .arg_int(7)
                            .expect_int(17)
                            .describe("AddTen(7) = 17"),
                        // ProcessNumber: (input * 2) + 10
                        // With input=5: (5*2) + 10 = 20
                        MethodTest::new("ProcessNumber")
                            .arg_int(5)
                            .expect_int(20)
                            .describe("ProcessNumber(5) = 20"),
                        // With input=15: (15*2) + 10 = 40
                        MethodTest::new("ProcessNumber")
                            .arg_int(15)
                            .expect_int(40)
                            .describe("ProcessNumber(15) = 40"),
                        // Factorial tests
                        // 5! = 120
                        MethodTest::new("Factorial")
                            .arg_int(5)
                            .expect_int(120)
                            .describe("Factorial(5) = 120"),
                        // 6! = 720
                        MethodTest::new("Factorial")
                            .arg_int(6)
                            .expect_int(720)
                            .describe("Factorial(6) = 720"),
                        // 1! = 1
                        MethodTest::new("Factorial")
                            .arg_int(1)
                            .expect_int(1)
                            .describe("Factorial(1) = 1"),
                    ]
                },
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Cross-reference test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = runner.architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }

        #[test]
        fn test_mono_blob_heap_and_complex_signatures() -> Result<()> {
            // Test blob heap modifications with complex method signatures
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                |assembly: &mut CilAssembly| -> Result<()> {
                    // ComplexMethod with mixed parameter types (int, string, bool)
                    let _complex_method = MethodBuilder::new("ComplexMethod")
                        .public()
                        .static_method()
                        .parameter("intParam", TypeSignature::I4)
                        .parameter("stringParam", TypeSignature::String)
                        .parameter("boolParam", TypeSignature::Boolean)
                        .returns(TypeSignature::String)
                        .implementation(|body| {
                            body.local("result", TypeSignature::String)
                                .implementation(|asm| {
                                    asm.ldstr(Token::new(0x70000001))?
                                        .stloc_0()?
                                        .ldloc_0()?
                                        .ret()?;
                                    Ok(())
                                })
                        })
                        .build(assembly)?;

                    let result_string_ref =
                        assembly.userstring_add("ComplexMethod executed successfully")?;
                    let _result_string_token =
                        Token::new(0x70000000 | result_string_ref.placeholder());

                    // TestParameters: (a + b) * c
                    let _param_test_method = MethodBuilder::new("TestParameters")
                        .public()
                        .static_method()
                        .parameter("a", TypeSignature::I4)
                        .parameter("b", TypeSignature::I4)
                        .parameter("c", TypeSignature::I4)
                        .returns(TypeSignature::I4)
                        .implementation(|body| {
                            body.implementation(|asm| {
                                asm.ldarg_0()?.ldarg_1()?.add()?.ldarg_2()?.mul()?.ret()?;
                                Ok(())
                            })
                        })
                        .build(assembly)?;

                    // BooleanLogic: flag1 AND flag2
                    let _bool_method = MethodBuilder::new("BooleanLogic")
                        .public()
                        .static_method()
                        .parameter("flag1", TypeSignature::Boolean)
                        .parameter("flag2", TypeSignature::Boolean)
                        .returns(TypeSignature::Boolean)
                        .implementation(|body| {
                            body.implementation(|asm| {
                                asm.ldarg_0()?.ldarg_1()?.and()?.ret()?;
                                Ok(())
                            })
                        })
                        .build(assembly)?;

                    Ok(())
                },
                |_assembly_path| {
                    vec![
                        // TestParameters: (a + b) * c
                        // (2 + 3) * 4 = 20
                        MethodTest::new("TestParameters")
                            .arg_int(2)
                            .arg_int(3)
                            .arg_int(4)
                            .expect_int(20)
                            .describe("TestParameters(2, 3, 4) = 20"),
                        // (10 + 5) * 2 = 30
                        MethodTest::new("TestParameters")
                            .arg_int(10)
                            .arg_int(5)
                            .arg_int(2)
                            .expect_int(30)
                            .describe("TestParameters(10, 5, 2) = 30"),
                        // BooleanLogic: flag1 AND flag2
                        // true AND false = false
                        MethodTest::new("BooleanLogic")
                            .arg_bool(true)
                            .arg_bool(false)
                            .expect_bool(false)
                            .describe("BooleanLogic(true, false) = false"),
                        // true AND true = true
                        MethodTest::new("BooleanLogic")
                            .arg_bool(true)
                            .arg_bool(true)
                            .expect_bool(true)
                            .describe("BooleanLogic(true, true) = true"),
                        // false AND false = false
                        MethodTest::new("BooleanLogic")
                            .arg_bool(false)
                            .arg_bool(false)
                            .expect_bool(false)
                            .describe("BooleanLogic(false, false) = false"),
                    ]
                },
            )?;

            // Assert all tests passed
            for result in &results {
                assert!(
                    result.is_fully_successful(),
                    "Blob heap/Complex signature test failed for {} architecture: {:?}",
                    result.architecture.name,
                    result.errors
                );
            }

            let expected_arch_count = runner.architectures().len();
            assert_eq!(
                results.len(),
                expected_arch_count,
                "Expected to test {} architectures",
                expected_arch_count
            );
            Ok(())
        }

        #[test]
        fn test_mono_reflection_detects_wrong_results() -> Result<()> {
            // Negative test: verify that our test framework actually detects wrong results
            // This ensures we're not just passing everything blindly
            let Some(runner) = TestRunner::new()? else {
                return Ok(());
            };

            // Create a simple Add method: returns a + b
            let results = run_complete_test(
                &runner,
                compilation::templates::HELLO_WORLD,
                |assembly: &mut CilAssembly| -> Result<()> {
                    let _add_method = MethodBuilder::new("Add")
                        .public()
                        .static_method()
                        .parameter("a", TypeSignature::I4)
                        .parameter("b", TypeSignature::I4)
                        .returns(TypeSignature::I4)
                        .implementation(|body| {
                            body.implementation(|asm| {
                                asm.ldarg_0()?.ldarg_1()?.add()?.ret()?;
                                Ok(())
                            })
                        })
                        .build(assembly)?;
                    Ok(())
                },
                |_assembly_path| {
                    vec![
                        // INTENTIONALLY WRONG: Add(2, 3) should be 5, not 999
                        MethodTest::new("Add")
                            .arg_int(2)
                            .arg_int(3)
                            .expect_int(999)
                            .describe("Add(2, 3) should NOT equal 999"),
                    ]
                },
            )?;

            // The reflection test should FAIL because 2+3=5, not 999
            for result in &results {
                assert!(
                    !result.reflection_success,
                    "Reflection should have FAILED for {} because we expected wrong result",
                    result.architecture.name
                );
                // Verify the error message mentions the mismatch
                let has_mismatch_error = result
                    .errors
                    .iter()
                    .any(|e| e.contains("Expected") || e.contains("999") || e.contains("5"));
                assert!(
                    has_mismatch_error,
                    "Error should mention result mismatch for {}: {:?}",
                    result.architecture.name, result.errors
                );
            }

            Ok(())
        }
    }

    #[test]
    fn a_type_imported_from_two_core_libraries_resolves_to_the_modules_own() {
        // A module importing `System.RuntimeTypeHandle` from System.Private.CoreLib as
        // well as from its own mscorlib takes its core library, and the type, from
        // mscorlib, whichever of the two TypeRefs the table lists first.
        for name in TWO_CORELIB_FIXTURES {
            let path = fixture(&format!("metadata/layouts/{name}"));
            let rows = runtime_type_handle_rows(&path);
            let (own, foreign) = (rows["mscorlib"], rows["System.Private.CoreLib"]);
            assert_eq!(
                foreign < own,
                name.contains("foreign_first"),
                "{name} lists the foreign TypeRef where its name says"
            );

            let assembly = CilAssembly::from_path(&path).unwrap();
            let corelib = assembly.find_core_library_ref().unwrap();
            assert_eq!(
                Some(corelib.row),
                assembly
                    .find_assembly_ref_by_name("mscorlib")
                    .map(|mscorlib| mscorlib.row),
                "{name}"
            );
            let handle = assembly
                .find_corelib_typeref("System", "RuntimeTypeHandle")
                .unwrap();
            assert_eq!((handle.tag, handle.row), (TableId::TypeRef, own), "{name}");
            assert!(
                assembly.find_corelib_typeref("No.Such", "Type").is_none(),
                "{name}"
            );
        }
    }
}
