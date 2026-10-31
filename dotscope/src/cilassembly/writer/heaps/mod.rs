//! Metadata heap writers for assembly serialization.
//!
//! This module provides streaming heap writers that process entries directly to output
//! without intermediate buffering.
//!
//! # Background
//!
//! .NET assemblies contain four metadata heaps as defined in ECMA-335 §II.24.2:
//!
//! - **#Strings**: Null-terminated UTF-8 strings for identifiers (type names, method names, etc.)
//! - **#Blob**: Binary data with length-prefixed encoding (signatures, custom attribute values)
//! - **#GUID**: Array of 16-byte GUIDs (module identifiers)
//! - **#US (User Strings)**: Length-prefixed UTF-16 strings for string literals in code
//!
//! # Architecture
//!
//! ## Streaming Writers (Preferred)
//!
//! The streaming writers in the [`streaming`] module provide zero-copy heap processing:
//! - [`streaming::stream_strings_heap`] - Stream #Strings heap with deduplication
//! - [`streaming::stream_blob_heap`] - Stream #Blob heap with deduplication
//! - [`streaming::stream_guid_heap`] - Stream #GUID heap with deduplication
//! - [`streaming::stream_userstring_heap`] - Stream #US heap with deduplication
//!
//! These functions:
//! 1. Iterate through source data without copying
//! 2. Apply deletions, modifications, and appends
//! 3. Deduplicate by content (the entries themselves, never a hash of them)
//! 4. Write directly to output
//! 5. Return (bytes_written, remapping) for table patching
//!
//! # Module Structure
//!
//! - [`streaming`] - Zero-copy streaming heap writers (primary API)
//! - [`rowpatch`] - Patching heap references in table rows

mod rowpatch;
mod streaming;

// Streaming writers (primary API)
use std::collections::HashMap;

// Row patching utilities
pub(crate) use rowpatch::patch_row_heap_refs;
pub use streaming::{
    compute_blob_heap_offsets, compute_guid_heap_offsets, compute_strings_heap_offsets,
    compute_userstring_heap_offsets, stream_blob_heap, stream_guid_heap, stream_strings_heap,
    stream_userstring_heap,
};

use crate::{
    cilassembly::{
        changes::AssemblyChanges,
        writer::{blobs::BlobRemap, context::WriteContext},
    },
    CilAssemblyView, Result,
};

/// Captures the mapping from old heap offsets to new offsets after heap rebuilding.
///
/// When heaps are rebuilt with deduplication, compaction, or modifications, entries
/// may move to different offsets. This struct captures those mappings so that
/// metadata table references and IL instructions can be updated.
#[derive(Debug, Default, Clone)]
pub struct HeapRemapping {
    /// Mapping from old #Strings heap offset to new offset.
    pub strings: HashMap<u32, u32>,

    /// Mapping from old #Blob heap offset to new offset.
    pub blobs: HashMap<u32, u32>,

    /// Mapping from old #GUID heap index to new index.
    pub guids: HashMap<u32, u32>,

    /// Mapping from old #US (User String) heap offset to new offset.
    pub userstrings: HashMap<u32, u32>,
}

impl HeapRemapping {
    /// Creates an empty remapping with no offset mappings.
    ///
    /// # Returns
    ///
    /// A new `HeapRemapping` with empty mappings for all heaps.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns true if there are any remappings in any heap.
    ///
    /// This is useful for optimization - if no remappings exist, table patching
    /// can be skipped entirely.
    ///
    /// # Returns
    ///
    /// `true` if any heap has at least one offset remapping, `false` otherwise.
    pub fn has_changes(&self) -> bool {
        !self.strings.is_empty()
            || !self.blobs.is_empty()
            || !self.guids.is_empty()
            || !self.userstrings.is_empty()
    }

    /// Remaps a string heap offset to its new location.
    ///
    /// # Arguments
    ///
    /// * `offset` - The original offset in the #Strings heap
    ///
    /// # Returns
    ///
    /// The new offset if a mapping exists, or the original offset unchanged.
    pub fn remap_string(&self, offset: u32) -> u32 {
        self.strings.get(&offset).copied().unwrap_or(offset)
    }

    /// Remaps a blob heap offset to its new location.
    ///
    /// # Arguments
    ///
    /// * `offset` - The original offset in the #Blob heap
    ///
    /// # Returns
    ///
    /// The new offset if a mapping exists, or the original offset unchanged.
    pub fn remap_blob(&self, offset: u32) -> u32 {
        self.blobs.get(&offset).copied().unwrap_or(offset)
    }

    /// Remaps a GUID heap index to its new location.
    ///
    /// Note: GUID heap uses 1-based indices, not byte offsets.
    ///
    /// # Arguments
    ///
    /// * `index` - The original 1-based index in the #GUID heap
    ///
    /// # Returns
    ///
    /// The new index if a mapping exists, or the original index unchanged.
    pub fn remap_guid(&self, index: u32) -> u32 {
        self.guids.get(&index).copied().unwrap_or(index)
    }

    /// Remaps a user string heap offset to its new location.
    ///
    /// # Arguments
    ///
    /// * `offset` - The original offset in the #US heap
    ///
    /// # Returns
    ///
    /// The new offset if a mapping exists, or the original offset unchanged.
    pub fn remap_userstring(&self, offset: u32) -> u32 {
        self.userstrings.get(&offset).copied().unwrap_or(offset)
    }
}

/// Pre-computes heap offsets and resolves ChangeRefs without writing.
///
/// This follows dnlib's approach: calculate all heap offsets first, so that when
/// we write table rows, `resolve_placeholders()` can successfully resolve the
/// placeholder values to actual offsets.
///
/// This function must be called early in the generation process (before method
/// bodies are written) because:
/// 1. Method bodies may contain `ldstr` instructions referencing newly added userstrings
/// 2. Table rows reference heap entries via ChangeRef placeholders
///
/// # Arguments
///
/// * `view` - The assembly view providing source heap data
/// * `ctx` - The write context where remapping will be stored
/// * `changes` - The assembly changes containing heap modifications
///
/// # Returns
///
/// Returns `Ok(())` after populating `ctx.heap_remapping` with all offset mappings.
///
/// # Errors
///
/// Returns an error if heap offset computation fails due to:
/// - Invalid heap data in the source assembly
/// - Corrupted length-prefixed entries in blob or userstring heaps
pub fn precompute_heap_offsets(
    view: &CilAssemblyView,
    ctx: &mut WriteContext,
    changes: &AssemblyChanges,
) -> Result<()> {
    // Get source heap data
    let empty: &[u8] = &[];
    let strings_data = view.strings().map_or(empty, crate::Strings::data);
    let blob_data = view.blobs().map_or(empty, crate::Blob::data);
    let guid_data = view.guids().map_or(empty, crate::Guid::data);
    let us_data = view.userstrings().map_or(empty, crate::UserStrings::data);

    // Pre-compute offsets for each heap (this resolves ChangeRefs).
    //
    // These must be given exactly the inputs the real write pass will use. Running the pre-pass
    // with empty remap sets makes the two passes disagree: RID remapping rewrites TypeDefOrRef
    // tokens as compressed uints, so a RID crossing the 0x80/0x4000 compression boundary changes
    // a blob's encoded length — and two distinct blobs can collapse into one, changing the dedup
    // outcome. Either shifts `pos` for every later entry, so appended blobs land at different
    // offsets in the two passes. The `#Strings` heap diverges the same way, because a non-empty
    // `referenced_offsets` makes `emit_orphaned_substrings` allocate extra entries.
    //
    // The tables are serialised from the pre-pass values, so any disagreement is baked into the
    // emitted file — silently, since generation still returns `Ok`.
    let strings_result = compute_strings_heap_offsets(
        strings_data,
        &changes.string_heap_changes,
        &ctx.referenced_string_offsets,
    )?;
    let blob_result = compute_blob_heap_offsets(
        blob_data,
        &changes.blob_heap_changes,
        &BlobRemap {
            blobs: &ctx.typed_blobs,
            tokens: &ctx.tokens,
            changes,
        },
        &ctx.referenced_blob_offsets,
    )?;
    let guid_result = compute_guid_heap_offsets(guid_data, &changes.guid_heap_changes)?;
    let us_result = compute_userstring_heap_offsets(
        us_data,
        &changes.userstring_heap_changes,
        &ctx.referenced_userstring_offsets,
    )?;

    // Record the emitted heap sizes so the tables stream can pick matching index widths.
    // `usize::try_from` cannot fail for a heap that fits in memory; saturating keeps the
    // failure direction safe (a larger value only widens the index).
    ctx.output_heap_sizes = Some((
        usize::try_from(strings_result.bytes_written).unwrap_or(usize::MAX),
        usize::try_from(guid_result.bytes_written).unwrap_or(usize::MAX),
        usize::try_from(blob_result.bytes_written).unwrap_or(usize::MAX),
    ));

    // Store the remapping for later patching of existing table rows
    ctx.heap_remapping.strings = strings_result.remapping;
    ctx.heap_remapping.blobs = blob_result.remapping;
    ctx.heap_remapping.guids = guid_result.remapping;
    ctx.heap_remapping.userstrings = us_result.remapping;

    Ok(())
}
