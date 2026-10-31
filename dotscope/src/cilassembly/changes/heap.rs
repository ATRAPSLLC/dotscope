//! Heap change tracking for metadata heaps.
//!
//! This module provides the [`HeapChanges`] structure for tracking additions to .NET
//! metadata heaps during assembly modification operations. It supports all standard
//! .NET metadata heaps: #Strings, #Blob, #GUID, and #US (user strings).
//!
//! # ChangeRef Integration
//!
//! All heap additions return [`ChangeRefRc`] (`Arc<ChangeRef>`) which provides stable
//! references that survive heap rebuilding and deduplication. After the assembly is
//! written, these references resolve to their final heap offsets.
//!
//! The `examples::module_example` test in this module runs this example.
//!
//! # Architecture
//!
//! Each heap type has specialized sizing and indexing behavior:
//!
//! - **#Strings heap**: UTF-8 null-terminated strings
//! - **#Blob heap**: Length-prefixed binary data with compressed lengths
//! - **#GUID heap**: Raw 16-byte GUIDs
//! - **#US heap**: Length-prefixed UTF-16 strings with compressed lengths
//!
//! # Thread Safety
//!
//! This type is [`Send`] and [`Sync`] when `T` is [`Send`] and [`Sync`].

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    cilassembly::changes::{
        hash_blob, hash_guid, hash_string, ChangeIds, ChangeRef, ChangeRefKind, ChangeRefRc,
    },
    utils::compressed_uint_size,
};

/// Reference handling strategy for heap item removal operations.
///
/// Tracks changes to metadata heaps (strings, blobs, GUIDs, user strings).
///
/// This structure tracks additions, modifications, and removals to .NET metadata heaps.
/// All additions return [`ChangeRefRc`] which provides stable references that resolve
/// to final heap offsets after assembly write.
///
/// # Type Parameters
///
/// * `T` - The type of items stored in this heap:
///   - [`String`] for #Strings and #US heaps
///   - [`Vec<u8>`] for #Blob heap
///   - `[u8; 16]` for #GUID heap
///
/// # Thread Safety
///
/// This type is [`Send`] and [`Sync`] when `T` is [`Send`] and [`Sync`].
#[derive(Debug, Clone)]
pub struct HeapChanges<T> {
    /// Items appended to the heap with their ChangeRef references
    ///
    /// Each tuple contains the item value and its associated ChangeRef.
    /// The ChangeRef will be resolved to the final heap offset after write.
    appended: Vec<(T, ChangeRefRc)>,

    /// Items modified in the original heap
    ///
    /// Maps heap index to new value. These modifications override the
    /// original heap content at the specified indices during binary generation.
    modified_items: HashMap<u32, T>,

    /// Indices of items removed from the original heap
    ///
    /// Items at these indices will be skipped during binary generation.
    removed_indices: HashSet<u32>,

    /// Complete heap replacement data
    ///
    /// When set, this raw data completely replaces the entire heap.
    replacement_heap: Option<Vec<u8>>,

    /// The kind of heap this tracks changes for
    heap_kind: ChangeRefKind,

    /// The ids the assembly's changes take, shared with its other heaps and its tables
    ids: ChangeIds,
}

impl<T> HeapChanges<T> {
    /// Creates a new heap changes tracker.
    ///
    /// # Arguments
    ///
    /// * `heap_kind` - The kind of heap this tracks changes for.
    /// * `ids` - The ids the assembly's changes take.
    fn new(heap_kind: ChangeRefKind, ids: ChangeIds) -> Self {
        Self {
            appended: Vec::new(),
            modified_items: HashMap::new(),
            removed_indices: HashSet::new(),
            replacement_heap: None,
            heap_kind,
            ids,
        }
    }

    /// Returns the heap kind this tracker is for.
    pub fn heap_kind(&self) -> ChangeRefKind {
        self.heap_kind
    }

    /// Drops the items appended after the first `len`, which the writer then
    /// never sees.
    #[cfg(feature = "compiler")]
    pub(crate) fn truncate_appended(&mut self, len: usize) {
        self.appended.truncate(len);
    }

    /// Returns the number of items that have been added to this heap.
    pub fn additions_count(&self) -> usize {
        self.appended.len()
    }

    /// Returns true if any items have been added to this heap.
    pub fn has_additions(&self) -> bool {
        !self.appended.is_empty()
    }

    /// Returns the number of items that have been modified in this heap.
    pub fn modifications_count(&self) -> usize {
        self.modified_items.len()
    }

    /// Returns true if any items have been modified in this heap.
    pub fn has_modifications(&self) -> bool {
        !self.modified_items.is_empty()
    }

    /// Returns the number of items that have been removed from this heap.
    pub fn removals_count(&self) -> usize {
        self.removed_indices.len()
    }

    /// Returns true if any items have been removed from this heap.
    pub fn has_removals(&self) -> bool {
        !self.removed_indices.is_empty()
    }

    /// Returns true if any changes have been made.
    pub fn has_changes(&self) -> bool {
        self.has_additions()
            || self.has_modifications()
            || self.has_removals()
            || self.has_replacement()
    }

    /// Returns true if the heap has been completely replaced.
    pub fn has_replacement(&self) -> bool {
        self.replacement_heap.is_some()
    }

    /// Replaces the entire heap with the provided raw data.
    ///
    /// This completely replaces the heap content. All subsequent operations
    /// will be applied to this replacement heap instead of the original.
    ///
    /// # Arguments
    ///
    /// * `heap_data` - The raw bytes that will form the new heap
    pub fn replace_heap(&mut self, heap_data: Vec<u8>) {
        self.replacement_heap = Some(heap_data);

        // Clear existing changes since they would apply to the original heap
        self.appended.clear();
        self.modified_items.clear();
        self.removed_indices.clear();
    }

    /// Gets a reference to the replacement heap data, if any.
    pub fn replacement_heap(&self) -> Option<&Vec<u8>> {
        self.replacement_heap.as_ref()
    }

    /// Adds a modification to the heap at the specified index.
    pub fn add_modification(&mut self, index: u32, new_value: T) {
        self.modified_items.insert(index, new_value);
    }

    /// Adds a removal to the heap at the specified index.
    pub fn add_removal(&mut self, index: u32) {
        self.removed_indices.insert(index);
    }

    /// Gets the modification at the specified index, if any.
    pub fn get_modification(&self, index: u32) -> Option<&T> {
        self.modified_items.get(&index)
    }

    /// Returns true if the specified index has been removed.
    pub fn is_removed(&self, index: u32) -> bool {
        self.removed_indices.contains(&index)
    }

    /// Returns an iterator over all appended items with their ChangeRefs.
    pub fn appended_iter(&self) -> impl Iterator<Item = &(T, ChangeRefRc)> {
        self.appended.iter()
    }

    /// Returns an iterator over all modified items and their indices.
    pub fn modified_items_iter(&self) -> impl Iterator<Item = (&u32, &T)> {
        self.modified_items.iter()
    }

    /// Returns an iterator over all removed indices.
    pub fn removed_indices_iter(&self) -> impl Iterator<Item = &u32> {
        self.removed_indices.iter()
    }

    /// Marks a ChangeRef as removed (won't be written to output).
    ///
    /// This finds the appended item by its ChangeRef ID and marks it for removal.
    pub fn mark_ref_removed(&mut self, change_ref: &ChangeRefRc) {
        // We track removal by ChangeRef ID - the write pipeline will skip these
        // For now we use the id as a pseudo-index in removed_indices
        // ToDo: This is a temporary solution until we refactor the removal system
        let pseudo_index = (change_ref.id() & 0xFFFF_FFFF) as u32 | 0x8000_0000;
        self.removed_indices.insert(pseudo_index);
    }

    /// Checks if a ChangeRef has been marked for removal.
    pub fn is_ref_removed(&self, change_ref: &ChangeRefRc) -> bool {
        let pseudo_index = (change_ref.id() & 0xFFFF_FFFF) as u32 | 0x8000_0000;
        self.removed_indices.contains(&pseudo_index)
    }

    /// Marks an appended item for removal by its index.
    ///
    /// This is used when removing an item that was appended (index >= original heap size).
    /// The index should be the position within the appended items list, not the heap offset.
    pub fn mark_appended_for_removal(&mut self, index: u32) {
        // For appended items, we just track the index with a special flag
        // The write pipeline will skip these when rebuilding the heap
        self.removed_indices.insert(index | 0x8000_0000);
    }

    /// Checks if an appended item at the given index is marked for removal.
    pub fn is_appended_removed(&self, index: u32) -> bool {
        self.removed_indices.contains(&(index | 0x8000_0000))
    }
}

impl HeapChanges<String> {
    /// Creates a new string heap changes tracker.
    pub fn new_strings(ids: ChangeIds) -> Self {
        Self::new(ChangeRefKind::String, ids)
    }

    /// Creates a new user string heap changes tracker.
    pub fn new_userstrings(ids: ChangeIds) -> Self {
        Self::new(ChangeRefKind::UserString, ids)
    }

    /// Appends a string and returns a ChangeRef for it.
    ///
    /// The ChangeRef will be resolved to the final heap offset after
    /// the assembly is written.
    pub fn append(&mut self, value: String) -> ChangeRefRc {
        let content_hash = hash_string(&value);
        let change_ref = Arc::new(ChangeRef::new_heap(
            self.heap_kind,
            content_hash,
            self.ids.next(),
        ));
        self.appended.push((value, Arc::clone(&change_ref)));
        change_ref
    }

    /// Calculates the binary size for #Strings heap additions.
    ///
    /// Each string contributes: UTF-8 byte length + 1 null terminator
    pub fn binary_string_heap_size(&self) -> usize {
        self.appended
            .iter()
            .map(|(s, _)| s.len().saturating_add(1))
            .sum()
    }

    /// Calculates the binary size for #US heap additions.
    ///
    /// Each string contributes: compressed_length + UTF-16 bytes + terminal byte
    pub fn binary_userstring_heap_size(&self) -> usize {
        self.appended
            .iter()
            .map(|(s, _)| {
                let utf16_bytes = s.encode_utf16().count().saturating_mul(2);
                let total_length = utf16_bytes.saturating_add(1);
                // compressed_uint_size returns at most 4, so cast is always safe
                #[allow(clippy::cast_possible_truncation)]
                let compressed_length_size = compressed_uint_size(total_length) as usize;
                compressed_length_size.saturating_add(total_length)
            })
            .sum()
    }
}

impl HeapChanges<Vec<u8>> {
    /// Creates a new blob heap changes tracker.
    pub fn new_blobs(ids: ChangeIds) -> Self {
        Self::new(ChangeRefKind::Blob, ids)
    }

    /// Appends a blob and returns a ChangeRef for it.
    pub fn append(&mut self, value: Vec<u8>) -> ChangeRefRc {
        let content_hash = hash_blob(&value);
        let change_ref = Arc::new(ChangeRef::new_heap(
            self.heap_kind,
            content_hash,
            self.ids.next(),
        ));
        self.appended.push((value, Arc::clone(&change_ref)));
        change_ref
    }

    /// Calculates the binary size for #Blob heap additions.
    ///
    /// Each blob contributes: compressed_length + blob data
    pub fn binary_blob_heap_size(&self) -> usize {
        self.appended
            .iter()
            .map(|(blob, _)| {
                let length = blob.len();
                // compressed_uint_size returns at most 4, so cast is always safe
                #[allow(clippy::cast_possible_truncation)]
                let compressed_length_size = compressed_uint_size(length) as usize;
                compressed_length_size.saturating_add(length)
            })
            .sum()
    }
}

impl HeapChanges<[u8; 16]> {
    /// Creates a new GUID heap changes tracker.
    pub fn new_guids(ids: ChangeIds) -> Self {
        Self::new(ChangeRefKind::Guid, ids)
    }

    /// Appends a GUID and returns a ChangeRef for it.
    pub fn append(&mut self, value: [u8; 16]) -> ChangeRefRc {
        let content_hash = hash_guid(&value);
        let change_ref = Arc::new(ChangeRef::new_heap(
            self.heap_kind,
            content_hash,
            self.ids.next(),
        ));
        self.appended.push((value, Arc::clone(&change_ref)));
        change_ref
    }

    /// Calculates the binary size for #GUID heap additions.
    ///
    /// Each GUID contributes exactly 16 bytes.
    pub fn binary_guid_heap_size(&self) -> usize {
        self.appended.len().saturating_mul(16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_heap_changes() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        assert!(!changes.has_additions());
        assert!(!changes.has_changes());

        let ref1 = changes.append("hello".to_string());
        let ref2 = changes.append("world".to_string());

        assert!(changes.has_additions());
        assert!(changes.has_changes());
        assert_eq!(changes.additions_count(), 2);

        // ChangeRefs should be unique
        assert_ne!(ref1.id(), ref2.id());

        // Binary size: "hello\0" (6) + "world\0" (6) = 12
        assert_eq!(changes.binary_string_heap_size(), 12);
    }

    #[test]
    fn test_blob_heap_changes() {
        let mut changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());

        let ref1 = changes.append(vec![1, 2, 3]);
        let ref2 = changes.append(vec![4, 5, 6, 7]);

        assert_eq!(changes.additions_count(), 2);
        assert_ne!(ref1.id(), ref2.id());

        // Binary size: 1 (length) + 3 (data) + 1 (length) + 4 (data) = 9
        assert_eq!(changes.binary_blob_heap_size(), 9);
    }

    #[test]
    fn test_guid_heap_changes() {
        let mut changes = HeapChanges::<[u8; 16]>::new_guids(ChangeIds::new());

        let guid1 = [0u8; 16];
        let guid2 = [1u8; 16];
        let ref1 = changes.append(guid1);
        let ref2 = changes.append(guid2);

        assert_eq!(changes.additions_count(), 2);
        assert_ne!(ref1.id(), ref2.id());

        // Binary size: 16 + 16 = 32
        assert_eq!(changes.binary_guid_heap_size(), 32);
    }

    #[test]
    fn test_userstring_heap_changes() {
        let mut changes = HeapChanges::<String>::new_userstrings(ChangeIds::new());
        assert_eq!(changes.heap_kind(), ChangeRefKind::UserString);

        let _ref1 = changes.append("test".to_string());
        assert_eq!(changes.additions_count(), 1);

        // "test" = 4 UTF-16 code units = 8 bytes + 1 terminal = 9 bytes
        // Length 9 fits in 1 byte compressed = 1 + 9 = 10
        assert_eq!(changes.binary_userstring_heap_size(), 10);
    }

    #[test]
    fn test_modifications() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        assert!(!changes.has_modifications());

        changes.add_modification(50, "modified".to_string());

        assert!(changes.has_modifications());
        assert_eq!(changes.modifications_count(), 1);
        assert_eq!(changes.get_modification(50), Some(&"modified".to_string()));
        assert_eq!(changes.get_modification(99), None);
    }

    #[test]
    fn test_removals() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        assert!(!changes.has_removals());

        changes.add_removal(25);

        assert!(changes.has_removals());
        assert_eq!(changes.removals_count(), 1);
        assert!(changes.is_removed(25));
        assert!(!changes.is_removed(30));
    }

    #[test]
    fn test_replacement_heap() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let _ref1 = changes.append("will be cleared".to_string());
        assert_eq!(changes.additions_count(), 1);

        changes.replace_heap(vec![0, b'h', b'i', 0]);

        assert!(changes.has_replacement());
        assert_eq!(changes.additions_count(), 0); // Cleared
        assert_eq!(changes.replacement_heap().unwrap(), &vec![0, b'h', b'i', 0]);
    }

    #[test]
    fn test_mark_ref_removed() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let ref1 = changes.append("test".to_string());

        assert!(!changes.is_ref_removed(&ref1));

        changes.mark_ref_removed(&ref1);

        assert!(changes.is_ref_removed(&ref1));
    }

    #[test]
    fn test_appended_iter() {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        changes.append("one".to_string());
        changes.append("two".to_string());

        let items: Vec<_> = changes.appended_iter().collect();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].0, "one");
        assert_eq!(items[1].0, "two");
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::Result;

    /// An appended string is tracked with a reference that resolves to its heap offset only
    /// when the assembly is written.
    #[test]
    fn module_example() -> Result<()> {
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let string_ref = changes.append("MyString".to_string());

        assert_eq!(changes.appended_iter().count(), 1);
        assert!(!string_ref.is_resolved());
        Ok(())
    }
}
