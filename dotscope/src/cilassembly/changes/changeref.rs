//! Universal reference system for assembly modifications.
//!
//! This module provides [`ChangeRef`], a universal identifier for any modification
//! made to an assembly during building. Unlike raw offsets or indices that change
//! during heap rebuilding and deduplication, `ChangeRef` provides a stable reference
//! that is resolved to its final location after the assembly is written.
//!
//! # Design
//!
//! The `ChangeRef` system solves several problems with raw offset-based APIs:
//!
//! 1. **Stability**: Raw heap offsets become invalid after heap rebuilding/deduplication
//! 2. **Deduplication**: Two strings with identical content should resolve to the same offset
//! 3. **Type Safety**: Different heap types shouldn't be accidentally mixed
//! 4. **Deferred Resolution**: Final locations are only known after write completes
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::prelude::*;
//!
//! let mut assembly = CilAssembly::new(view);
//!
//! // Add items - returns ChangeRef instead of raw offsets
//! let string_ref = assembly.string_add("MyClass")?;
//! let blob_ref = assembly.blob_add(&signature_bytes)?;
//!
//! // Use in builders - accepts ChangeRef
//! FieldBuilder::new()
//!     .name(string_ref.clone())
//!     .signature(blob_ref.clone())
//!     .build(&mut assembly)?;
//!
//! // Write assembly
//! assembly.to_file(path)?;
//!
//! // After write, query final locations
//! let final_offset = string_ref.offset()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! `ChangeRef` uses atomic operations for resolution state, making it safe to
//! share across threads. Use `Arc<ChangeRef>` (aliased as `ChangeRefRc`) for
//! cheap cloning and sharing.

use std::sync::{
    atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    Arc,
};

// Re-export hash functions from utils for backwards compatibility
pub use crate::utils::{hash_blob, hash_guid, hash_string};
use crate::{
    metadata::{tables::TableId, token::Token},
    Error, Result,
};

/// The ids an assembly's changes take, shared by its heaps and tables: unique within the
/// assembly, which is all a placeholder is looked up in, and counted from 1 for each one, so
/// they stay small (a row placeholder holds 23 bits of one) and the same from run to run.
#[derive(Debug, Clone)]
pub struct ChangeIds(Arc<AtomicU64>);

impl ChangeIds {
    /// A fresh id source, starting at 1.
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(AtomicU64::new(1)))
    }

    /// The next id.
    pub fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for ChangeIds {
    fn default() -> Self {
        Self::new()
    }
}

/// The largest id a row placeholder holds (`0x0080_0000 | id`, below the bit marking a heap
/// placeholder).
const MAX_ROW_ID: u64 = 0x007F_FFFF;

/// Sentinel value indicating an unresolved offset/token
const UNRESOLVED: u32 = u32::MAX;

/// The kind of change a `ChangeRef` refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeRefKind {
    /// Reference to a #Strings heap entry
    String,
    /// Reference to a #Blob heap entry
    Blob,
    /// Reference to a #GUID heap entry
    Guid,
    /// Reference to a #US (UserString) heap entry
    UserString,
    /// Reference to a metadata table row
    TableRow(TableId),
}

impl ChangeRefKind {
    /// Returns true if this is a heap reference kind.
    #[must_use]
    pub fn is_heap(&self) -> bool {
        matches!(
            self,
            Self::String | Self::Blob | Self::Guid | Self::UserString
        )
    }

    /// Returns true if this is a table row reference kind.
    #[must_use]
    pub fn is_table(&self) -> bool {
        matches!(self, Self::TableRow(_))
    }

    /// Returns the table ID if this is a table row reference.
    #[must_use]
    pub fn table_id(&self) -> Option<TableId> {
        match self {
            Self::TableRow(id) => Some(*id),
            _ => None,
        }
    }
}

/// Universal reference to any assembly modification.
///
/// `ChangeRef` provides a stable identifier for modifications that survives
/// heap rebuilding, deduplication, and reordering. The reference is created
/// when an item is added and resolved to its final location after the
/// assembly is written.
///
/// # Resolution
///
/// A `ChangeRef` starts in an unresolved state. After the assembly write
/// pipeline completes, the reference is resolved with the final offset
/// (for heaps) or token (for table rows).
///
/// # Equality
///
/// Two `ChangeRef` instances are equal if they have the same unique ID,
/// regardless of resolution state. After deduplication, multiple `ChangeRef`s
/// may resolve to the same final offset.
///
/// # Thread Safety
///
/// All operations are atomic and safe for concurrent access. Use `Arc<ChangeRef>`
/// for sharing references across threads.
#[derive(Debug)]
pub struct ChangeRef {
    /// Unique identifier for this change reference
    id: u64,

    /// What kind of change this refers to
    kind: ChangeRefKind,

    /// Original content hash for deduplication detection
    /// (Two ChangeRefs with same hash may resolve to same offset)
    content_hash: u64,

    /// Whether this reference has been resolved
    resolved: AtomicBool,

    /// Final heap offset (for heap references)
    /// Set to UNRESOLVED until resolution completes
    resolved_offset: AtomicU32,

    /// Final token value (for table row references)
    /// Set to UNRESOLVED until resolution completes
    resolved_token: AtomicU32,
}

/// Reference-counted pointer to a `ChangeRef`.
///
/// This is the primary way to work with `ChangeRef` instances.
/// Cloning is cheap (just incrementing a reference count).
pub type ChangeRefRc = Arc<ChangeRef>;

impl ChangeRef {
    /// Creates a new unresolved change reference for a heap entry.
    ///
    /// # Arguments
    ///
    /// * `kind` - The type of heap this reference points to
    /// * `content_hash` - Hash of the content for deduplication detection
    /// * `id` - The change id, from the assembly's [`ChangeIds`]
    #[must_use]
    pub fn new_heap(kind: ChangeRefKind, content_hash: u64, id: u64) -> Self {
        debug_assert!(kind.is_heap(), "new_heap called with non-heap kind");
        Self {
            id,
            kind,
            content_hash,
            resolved: AtomicBool::new(false),
            resolved_offset: AtomicU32::new(UNRESOLVED),
            resolved_token: AtomicU32::new(UNRESOLVED),
        }
    }

    /// Creates a new unresolved change reference for a row of `table_id`, with change id `id`
    /// (from the assembly's [`ChangeIds`]).
    ///
    /// # Errors
    ///
    /// When `id` exceeds what a row placeholder holds: the assembly has made more changes than
    /// its placeholders can tell apart.
    pub fn new_table_row(table_id: TableId, id: u64) -> Result<Self> {
        if id > MAX_ROW_ID {
            return Err(Error::Other(format!(
                "Change {id} exceeds the {MAX_ROW_ID:#x} a row placeholder holds"
            )));
        }
        Ok(Self {
            id,
            kind: ChangeRefKind::TableRow(table_id),
            content_hash: 0, // Table rows don't use content hashing
            resolved: AtomicBool::new(false),
            resolved_offset: AtomicU32::new(UNRESOLVED),
            resolved_token: AtomicU32::new(UNRESOLVED),
        })
    }

    /// Creates a change reference from an existing heap offset.
    ///
    /// This is used when referencing items that already exist in the
    /// original assembly. The reference is immediately resolved.
    ///
    /// # Arguments
    ///
    /// * `kind` - The type of heap
    /// * `offset` - The existing heap offset
    #[must_use]
    pub fn from_heap_offset(kind: ChangeRefKind, offset: u32, id: u64) -> Self {
        debug_assert!(kind.is_heap(), "from_heap_offset called with non-heap kind");
        Self {
            id,
            kind,
            content_hash: 0,
            resolved: AtomicBool::new(true),
            resolved_offset: AtomicU32::new(offset),
            resolved_token: AtomicU32::new(UNRESOLVED),
        }
    }

    /// Creates a change reference from an existing token.
    ///
    /// This is used when referencing items that already exist in the
    /// original assembly. The reference is immediately resolved.
    ///
    /// # Arguments
    ///
    /// * `token` - The existing metadata token
    ///
    /// # Errors
    ///
    /// Returns an error if the token's table type is not recognized.
    pub fn from_token(token: Token, id: u64) -> Result<Self> {
        let table_id = TableId::from_token_type(token.table()).ok_or_else(|| {
            Error::Other(format!(
                "Token has unrecognized table type: 0x{:02X}",
                token.table()
            ))
        })?;
        Ok(Self {
            id,
            kind: ChangeRefKind::TableRow(table_id),
            content_hash: 0,
            resolved: AtomicBool::new(true),
            resolved_offset: AtomicU32::new(UNRESOLVED),
            resolved_token: AtomicU32::new(token.value()),
        })
    }

    /// Returns the unique ID of this change reference.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the kind of change this reference points to.
    #[must_use]
    pub fn kind(&self) -> ChangeRefKind {
        self.kind
    }

    /// Returns the content hash for deduplication.
    #[must_use]
    pub fn content_hash(&self) -> u64 {
        self.content_hash
    }

    /// Returns true if this reference has been resolved.
    #[must_use]
    pub fn is_resolved(&self) -> bool {
        self.resolved.load(Ordering::Acquire)
    }

    /// Returns the resolved heap offset, if resolved.
    ///
    /// Returns `None` if:
    /// - The reference is not yet resolved
    /// - This is not a heap reference
    #[must_use]
    pub fn offset(&self) -> Option<u32> {
        if !self.kind.is_heap() {
            return None;
        }
        if !self.is_resolved() {
            return None;
        }
        let offset = self.resolved_offset.load(Ordering::Acquire);
        if offset == UNRESOLVED {
            None
        } else {
            Some(offset)
        }
    }

    /// Returns the resolved token, if resolved.
    ///
    /// Returns `None` if:
    /// - The reference is not yet resolved
    /// - This is not a table row reference
    #[must_use]
    pub fn token(&self) -> Option<Token> {
        if !self.kind.is_table() {
            return None;
        }
        if !self.is_resolved() {
            return None;
        }
        let token_val = self.resolved_token.load(Ordering::Acquire);
        if token_val == UNRESOLVED {
            None
        } else {
            Some(Token::new(token_val))
        }
    }

    /// Resolves this reference to a heap offset.
    ///
    /// This should only be called by the write pipeline after the
    /// final heap layout is determined.
    ///
    /// # Arguments
    ///
    /// * `offset` - The final heap offset
    ///
    /// # Panics
    ///
    /// Panics if this is not a heap reference.
    pub fn resolve_to_offset(&self, offset: u32) {
        debug_assert!(
            self.kind.is_heap(),
            "resolve_to_offset called on non-heap ChangeRef"
        );
        self.resolved_offset.store(offset, Ordering::Release);
        self.resolved.store(true, Ordering::Release);
    }

    /// Resolves this reference to a token.
    ///
    /// This should only be called by the write pipeline after the
    /// final table layout is determined.
    ///
    /// # Arguments
    ///
    /// * `token` - The final metadata token
    ///
    /// # Panics
    ///
    /// Panics if this is not a table row reference.
    pub fn resolve_to_token(&self, token: Token) {
        debug_assert!(
            self.kind.is_table(),
            "resolve_to_token called on non-table ChangeRef"
        );
        self.resolved_token.store(token.value(), Ordering::Release);
        self.resolved.store(true, Ordering::Release);
    }

    /// Creates an `Arc<ChangeRef>` wrapper for this reference.
    #[must_use]
    pub fn into_rc(self) -> ChangeRefRc {
        Arc::new(self)
    }

    /// Returns a placeholder value for use before resolution.
    ///
    /// This returns a unique value derived from the ChangeRef's ID that can be
    /// used in table row fields, token operands, or coded indices. The format
    /// depends on the ChangeRef kind:
    ///
    /// - **Heap refs**: `0x8000_0000 | id` (bit 31 marker, supports heaps up to 2GB)
    /// - **Table refs**: `0x0080_0000 | id` (bit 23 marker, fits in 24-bit token rows)
    ///
    /// At write time, the writer scans for these placeholders and resolves them
    /// to actual offsets/rows using the AssemblyChanges lookup.
    ///
    /// # Usage
    ///
    /// ```no_run
    /// // For heap references (strings, blobs, guids, userstrings)
    /// let string_ref = assembly.string_add("MyClass")?;
    /// let name_field = string_ref.placeholder(); // Use in table row field
    ///
    /// // For table references (in IL tokens)
    /// let method_ref = assembly.table_row_add(/* ... */)?;
    /// let token = Token::from_parts(TableId::MemberRef, method_ref.placeholder());
    ///
    /// // For userstring tokens in IL
    /// let us_ref = assembly.userstring_add("Hello")?;
    /// let ldstr_token = Token::new(0x70000000 | us_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn placeholder(&self) -> u32 {
        if self.kind.is_heap() {
            // Heap placeholder: use bit 31 (heaps can be up to 2GB)
            0x8000_0000 | ((self.id & 0x7FFF_FFFF) as u32)
        } else {
            // Row placeholder: use bit 23 (fits in 24-bit token rows)
            0x0080_0000 | ((self.id & 0x007F_FFFF) as u32)
        }
    }

    /// Returns true if a value looks like a placeholder.
    ///
    /// Detects both placeholder formats:
    /// - Heap placeholders: bit 31 set (`0x80000000 | id`)
    /// - Row placeholders: value >= 0x800000 (bit 23 marker)
    #[must_use]
    pub fn is_placeholder(value: u32) -> bool {
        value & 0x8000_0000 != 0 || value >= 0x0080_0000
    }

    /// Whether a heap index is a heap placeholder (`0x8000_0000 | id`): bit 31, which no heap
    /// offset has. A heap offset past `0x0080_0000` is an offset, not a row placeholder.
    #[must_use]
    pub fn is_heap_placeholder(value: u32) -> bool {
        value & 0x8000_0000 != 0
    }

    /// Extracts the ID portion from a placeholder value.
    ///
    /// Handles both placeholder formats:
    /// - Heap placeholders: extracts lower 31 bits
    /// - Row placeholders: extracts lower 23 bits
    ///
    /// Returns `None` if the value is not a placeholder.
    #[must_use]
    pub fn id_from_placeholder(value: u32) -> Option<u64> {
        if value & 0x8000_0000 != 0 {
            // Heap placeholder: ID in lower 31 bits
            Some(u64::from(value & 0x7FFF_FFFF))
        } else if value >= 0x0080_0000 {
            // Row placeholder: ID in lower 23 bits
            Some(u64::from(value & 0x007F_FFFF))
        } else {
            None
        }
    }

    /// Returns a placeholder token for use in IL instructions before resolution.
    ///
    /// This is a convenience method that creates a complete Token with the
    /// correct table ID and placeholder row. Equivalent to:
    /// ```no_run
    /// Token::from_parts(table_id, change_ref.placeholder())
    /// ```
    ///
    /// Returns `None` if this is not a table row reference.
    #[must_use]
    pub fn placeholder_token(&self) -> Option<Token> {
        let table_id = self.kind.table_id()?;
        Some(Token::from_parts(table_id, self.placeholder()))
    }

    /// Returns true if a token looks like a placeholder token (row >= 0x800000).
    #[must_use]
    pub fn is_placeholder_token(token: Token) -> bool {
        token.row() >= 0x0080_0000
    }

    /// Alias for `placeholder()` when used for table row references.
    ///
    /// Returns the placeholder value for use in coded indices. For table
    /// row references, this is the same as `placeholder()`.
    ///
    /// Returns 0 if this is not a table row reference.
    ///
    /// # Usage
    ///
    /// ```no_run
    /// let change_ref = assembly.table_row_add(/* ... */)?;
    /// let coded_index = CodedIndex::new(
    ///     TableId::TypeDef,
    ///     change_ref.row(),  // Returns placeholder row
    ///     CodedIndexType::TypeDefOrRef,
    /// );
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn row(&self) -> u32 {
        if self.kind.is_table() {
            self.placeholder()
        } else {
            0
        }
    }
}

impl PartialEq for ChangeRef {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for ChangeRef {}

impl std::hash::Hash for ChangeRef {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

/// Helper functions for creating `Arc<ChangeRef>` directly.
impl ChangeRef {
    /// Creates a new string heap reference wrapped in Arc.
    #[must_use]
    pub fn new_string(content_hash: u64, id: u64) -> ChangeRefRc {
        Arc::new(Self::new_heap(ChangeRefKind::String, content_hash, id))
    }

    /// Creates a new blob heap reference wrapped in Arc.
    #[must_use]
    pub fn new_blob(content_hash: u64, id: u64) -> ChangeRefRc {
        Arc::new(Self::new_heap(ChangeRefKind::Blob, content_hash, id))
    }

    /// Creates a new GUID heap reference wrapped in Arc.
    #[must_use]
    pub fn new_guid(content_hash: u64, id: u64) -> ChangeRefRc {
        Arc::new(Self::new_heap(ChangeRefKind::Guid, content_hash, id))
    }

    /// Creates a new user string heap reference wrapped in Arc.
    #[must_use]
    pub fn new_userstring(content_hash: u64, id: u64) -> ChangeRefRc {
        Arc::new(Self::new_heap(ChangeRefKind::UserString, content_hash, id))
    }

    /// Creates a new table row reference wrapped in Arc.
    ///
    /// # Errors
    ///
    /// When `id` exceeds what a row placeholder holds (see [`Self::new_table_row`]).
    pub fn new_row(table_id: TableId, id: u64) -> Result<ChangeRefRc> {
        Self::new_table_row(table_id, id).map(Arc::new)
    }

    /// Creates a reference from an existing heap offset, wrapped in Arc.
    #[must_use]
    pub fn existing_heap(kind: ChangeRefKind, offset: u32, id: u64) -> ChangeRefRc {
        Arc::new(Self::from_heap_offset(kind, offset, id))
    }

    /// Creates a reference from an existing token, wrapped in Arc.
    ///
    /// # Errors
    ///
    /// Returns an error if the token's table type is not recognized.
    pub fn existing_token(token: Token, id: u64) -> Result<ChangeRefRc> {
        Ok(Arc::new(Self::from_token(token, id)?))
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;

    #[test]
    fn test_changeref_heap_creation() {
        let ref1 = ChangeRef::new_string(12345, 1);
        assert_eq!(ref1.kind(), ChangeRefKind::String);
        assert!(!ref1.is_resolved());
        assert!(ref1.offset().is_none());
        assert!(ref1.token().is_none());
    }

    #[test]
    fn test_changeref_table_creation() {
        let ref1 = ChangeRef::new_row(TableId::TypeDef, 1).unwrap();
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::TypeDef));
        assert!(!ref1.is_resolved());
        assert!(ref1.offset().is_none());
        assert!(ref1.token().is_none());
    }

    #[test]
    fn test_changeref_from_existing_offset() {
        let ref1 = ChangeRef::existing_heap(ChangeRefKind::String, 100, 1);
        assert!(ref1.is_resolved());
        assert_eq!(ref1.offset(), Some(100));
    }

    #[test]
    fn test_changeref_from_existing_token() {
        let token = Token::new(0x0200_0001); // TypeDef row 1
        let ref1 = ChangeRef::existing_token(token, 1).unwrap();
        assert!(ref1.is_resolved());
        assert_eq!(ref1.token(), Some(token));
    }

    #[test]
    fn test_changeref_resolve_offset() {
        let ref1 = ChangeRef::new_string(12345, 1);
        assert!(!ref1.is_resolved());

        ref1.resolve_to_offset(500);
        assert!(ref1.is_resolved());
        assert_eq!(ref1.offset(), Some(500));
    }

    #[test]
    fn test_changeref_resolve_token() {
        let ref1 = ChangeRef::new_row(TableId::MethodDef, 1).unwrap();
        assert!(!ref1.is_resolved());

        let token = Token::new(0x0600_0042);
        ref1.resolve_to_token(token);
        assert!(ref1.is_resolved());
        assert_eq!(ref1.token(), Some(token));
    }

    #[test]
    fn test_changeref_unique_ids() {
        // An assembly's changes take distinct ids from 1, whatever another assembly has made
        let ids = ChangeIds::new();
        let ref1 = ChangeRef::new_string(100, ids.next());
        let ref2 = ChangeRef::new_string(100, ids.next());
        let ref3 = ChangeRef::new_blob(200, ids.next());
        assert_eq!((ref1.id(), ref2.id(), ref3.id()), (1, 2, 3));
        assert_eq!(ChangeIds::new().next(), 1);
    }

    /// A heap placeholder is bit 31 alone: an offset into a heap larger than 8 MB is an
    /// offset, where the row placeholders' marker would have taken it for a change.
    #[test]
    fn a_large_heap_offset_is_not_a_heap_placeholder() {
        assert!(!ChangeRef::is_heap_placeholder(0x0090_0000));
        assert!(ChangeRef::is_heap_placeholder(
            ChangeRef::new_string(1, 7).placeholder()
        ));
    }

    /// A row placeholder holds 23 bits of its id: an id past them is refused, where it would
    /// name another change.
    #[test]
    fn a_row_id_past_its_placeholder_is_refused() {
        assert!(ChangeRef::new_table_row(TableId::TypeDef, 0x007F_FFFF).is_ok());
        assert!(ChangeRef::new_table_row(TableId::TypeDef, 0x0080_0000).is_err());
    }

    #[test]
    fn test_changeref_equality() {
        let ref1 = ChangeRef::new_heap(ChangeRefKind::String, 100, 1);
        let id1 = ref1.id();

        // Same ID means equal
        assert_eq!(ref1, ref1);

        // Different ID means not equal, even with same content hash
        let ref2 = ChangeRef::new_heap(ChangeRefKind::String, 100, 2);
        assert_ne!(ref1, ref2);

        // ID should be stable
        assert_eq!(ref1.id(), id1);
    }

    #[test]
    fn test_changeref_kind_methods() {
        let string_kind = ChangeRefKind::String;
        assert!(string_kind.is_heap());
        assert!(!string_kind.is_table());
        assert!(string_kind.table_id().is_none());

        let table_kind = ChangeRefKind::TableRow(TableId::TypeDef);
        assert!(!table_kind.is_heap());
        assert!(table_kind.is_table());
        assert_eq!(table_kind.table_id(), Some(TableId::TypeDef));
    }

    #[test]
    fn test_hash_functions() {
        let hash1 = hash_string("hello");
        let hash2 = hash_string("hello");
        let hash3 = hash_string("world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);

        let blob1 = hash_blob(&[1, 2, 3]);
        let blob2 = hash_blob(&[1, 2, 3]);
        let blob3 = hash_blob(&[4, 5, 6]);

        assert_eq!(blob1, blob2);
        assert_ne!(blob1, blob3);
    }

    #[test]
    fn test_changeref_thread_safety() {
        let ref1 = ChangeRef::new_string(100, 1);
        let ref1_arc = Arc::new(ref1);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let ref_clone = Arc::clone(&ref1_arc);
                thread::spawn(move || {
                    // Read operations should be safe
                    let _ = ref_clone.is_resolved();
                    let _ = ref_clone.offset();
                    let _ = ref_clone.kind();

                    // Only one thread should resolve
                    if i == 0 {
                        ref_clone.resolve_to_offset(999);
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        assert!(ref1_arc.is_resolved());
        assert_eq!(ref1_arc.offset(), Some(999));
    }
}
