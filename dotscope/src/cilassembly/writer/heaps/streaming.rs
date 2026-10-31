//! Streaming heap writers for metadata heaps.
//!
//! This module provides streaming writers that process heap entries directly to output
//! without intermediate buffering. The design supports:
//!
//! - **Zero-copy for unmodified entries**: Original data written directly to output
//! - **Deduplication**: Identical entries share the same offset
//! - **Modification support**: Entries can be modified, deleted, or appended
//! - **Remapping**: Returns old→new offset mapping for patching table references
//!
//! # Architecture
//!
//! Each heap processor can operate in two modes:
//! - **Write mode**: Streams data to output while computing offsets
//! - **Compute mode**: Only computes offsets without writing (for pre-computation)
//!
//! Both modes share the same core logic to avoid duplication. The public API provides
//! separate functions for clarity, but internally they use unified implementations.

use std::collections::{HashMap, HashSet};

use rustc_hash::FxHashMap;

use crate::{
    cilassembly::{
        changes::{ChangeRef, ChangeRefRc, HeapChanges},
        writer::{blobs::BlobRemap, output::Output},
    },
    metadata::streams::{Blob, Guid, Strings, UserStrings},
    utils::{compressed_uint_size, to_u32, write_compressed_uint},
    Error, ParseFailure, ParseStage, Result,
};

#[inline]
fn writer_overflow(field: &'static str) -> Error {
    Error::Parse(ParseFailure::InvalidField {
        stage: ParseStage::AssemblyWriter,
        field,
        reason: "arithmetic overflow".into(),
    })
}

/// Result of streaming a heap to output.
#[derive(Debug)]
pub struct StreamResult {
    /// Number of bytes written to output.
    pub bytes_written: u64,
    /// Mapping from old heap offsets/indices to new offsets/indices.
    pub remapping: HashMap<u32, u32>,
}

impl StreamResult {
    /// Creates a new empty stream result.
    ///
    /// # Returns
    ///
    /// A new `StreamResult` with zero bytes written and empty remapping.
    pub fn new() -> Self {
        Self {
            bytes_written: 0,
            remapping: HashMap::new(),
        }
    }
}

impl Default for StreamResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Streams the #Strings heap to output with deduplication and modifications.
///
/// Processes the source string heap data, applying any modifications from the changes,
/// and writes the result to the output file with deduplication. When `referenced_offsets`
/// is provided, substring remappings are generated for any referenced offset that falls
/// within a string entry's byte range.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #Strings heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `referenced_offsets` - Set of all offsets referenced by metadata tables (for substring remapping)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_strings_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced_offsets: &HashSet<u32>,
) -> Result<StreamResult> {
    process_strings_heap(
        Some(output),
        start_offset,
        source_data,
        changes,
        referenced_offsets,
    )
}

/// Pre-computes string heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written. It computes what offsets entries will have
/// without actually writing to the output.
///
/// # Arguments
///
/// * `source_data` - The original #Strings heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_strings_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced_offsets: &HashSet<u32>,
) -> Result<StreamResult> {
    process_strings_heap(None, 0, source_data, changes, referenced_offsets)
}

/// Emits original substrings as standalone entries when their parent string was
/// modified or removed.
///
/// When a string is renamed (e.g., "writeToConsole" → "a") or removed, other
/// tables (TypeRef, etc.) may reference substring offsets within the original
/// string's byte range. Those substrings must be preserved as standalone entries
/// in the new heap so the references remain valid.
///
/// Uses deduplication: if the substring content already exists in the heap
/// (from a prior entry or another substring), it reuses the existing offset.
#[allow(clippy::too_many_arguments)]
fn emit_orphaned_substrings(
    output: &mut Option<&mut Output>,
    start_offset: u64,
    old_offset_u32: u32,
    original_end: u32,
    original_bytes: &[u8],
    referenced_offsets: &HashSet<u32>,
    dedup_map: &mut FxHashMap<Vec<u8>, u32>,
    pos: &mut u64,
    result: &mut StreamResult,
) -> Result<()> {
    for &ref_offset in referenced_offsets {
        if ref_offset > old_offset_u32 && ref_offset < original_end {
            // Already mapped by a prior entry — skip
            if result.remapping.contains_key(&ref_offset) {
                continue;
            }

            let delta = ref_offset
                .checked_sub(old_offset_u32)
                .ok_or_else(|| writer_overflow("substring_delta"))?
                as usize;
            if delta >= original_bytes.len() {
                continue;
            }

            // The substring runs from the referenced byte to the entry's terminator; its bytes
            // are copied as they are, UTF-8 or not
            let sub_bytes = original_bytes.get(delta..).ok_or(out_of_bounds_error!())?;
            if sub_bytes.is_empty() {
                result.remapping.insert(ref_offset, 0);
                continue;
            }

            if let Some(&existing) = dedup_map.get(sub_bytes) {
                result.remapping.insert(ref_offset, existing);
                continue;
            }

            let new_sub_offset = u32::try_from(*pos).map_err(|_| {
                Error::LayoutFailed(format!("Heap position {} exceeds u32 range", *pos))
            })?;

            let sub_pos = start_offset
                .checked_add(*pos)
                .ok_or_else(|| writer_overflow("heap_write_offset"))?;
            let sub_end = sub_pos
                .checked_add(sub_bytes.len() as u64)
                .ok_or_else(|| writer_overflow("heap_write_offset"))?;
            if let Some(out) = output.as_mut() {
                out.write_at(sub_pos, sub_bytes)?;
                out.write_at(sub_end, &[0u8])?;
            }

            *pos = pos
                .checked_add(sub_bytes.len() as u64)
                .and_then(|p| p.checked_add(1))
                .ok_or_else(|| writer_overflow("heap_position"))?;
            dedup_map.insert(sub_bytes.to_vec(), new_sub_offset);
            result.remapping.insert(ref_offset, new_sub_offset);
        }
    }
    Ok(())
}

/// Unified string heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
/// When `referenced_offsets` is non-empty, substring remappings are added
/// for any referenced offset that falls within a written string's byte range.
fn process_strings_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced_offsets: &HashSet<u32>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    let mut pos: u64 = 1; // Start after null byte

    // Content -> new offset, for deduplication; offset 0 is the empty string
    let mut dedup_map: FxHashMap<Vec<u8>, u32> = FxHashMap::default();
    dedup_map.insert(Vec::new(), 0);

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    // Process source heap
    // Every entry, as bytes: one that is not UTF-8 is written as it was, and does not end
    // the heap for the entries after it
    // A source that does not parse cannot have changes applied to it: dropping it would
    // leave every reference into it dangling. Only an absent heap starts empty.
    let source = match Strings::from(source_data) {
        Ok(heap) => Some(heap),
        Err(_) if source_data.is_empty() => None,
        Err(e) => {
            return Err(Error::LayoutFailed(format!(
                "the #Strings heap to write does not parse ({e}), so its changes cannot be applied"
            )))
        }
    };
    if let Some(strings) = source {
        for (old_offset, original_bytes) in strings.entries() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                Error::LayoutFailed(format!("String offset {old_offset} exceeds u32 range"))
            })?;

            // Calculate the original string's byte range for substring detection.
            // This must use the ORIGINAL length, not the modified length, because
            // other tables may reference substring offsets within the original range.
            let original_end = old_offset_u32
                .checked_add(to_u32(original_bytes.len())?)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| writer_overflow("string_range"))?; // +1 for null

            if changes.is_removed(old_offset_u32) {
                // Even though this entry is removed, emit any referenced substrings
                // as standalone entries so TypeRef/other tables can still resolve them.
                emit_orphaned_substrings(
                    &mut output,
                    start_offset,
                    old_offset_u32,
                    original_end,
                    original_bytes,
                    referenced_offsets,
                    &mut dedup_map,
                    &mut pos,
                    &mut result,
                )?;
                continue;
            }

            let modification = changes.get_modification(old_offset_u32);
            let final_bytes = modification.map_or(original_bytes, |s| s.as_bytes());

            if let Some(&existing_offset) = dedup_map.get(final_bytes) {
                if old_offset_u32 != existing_offset {
                    result.remapping.insert(old_offset_u32, existing_offset);
                }
                // Even when deduplicated, emit orphaned substrings if the string was modified
                if modification.is_some() {
                    emit_orphaned_substrings(
                        &mut output,
                        start_offset,
                        old_offset_u32,
                        original_end,
                        original_bytes,
                        referenced_offsets,
                        &mut dedup_map,
                        &mut pos,
                        &mut result,
                    )?;
                }
                continue;
            }

            let new_offset = u32::try_from(pos).map_err(|_| {
                Error::LayoutFailed(format!("Heap position {pos} exceeds u32 range"))
            })?;
            let str_bytes = final_bytes;
            let entry_size = (str_bytes.len() as u64)
                .checked_add(1)
                .ok_or_else(|| writer_overflow("heap_entry_size"))?; // +1 for null terminator

            // Write if in write mode
            let write_pos = start_offset
                .checked_add(pos)
                .ok_or_else(|| writer_overflow("heap_write_offset"))?;
            let null_pos = write_pos
                .checked_add(str_bytes.len() as u64)
                .ok_or_else(|| writer_overflow("heap_write_offset"))?;
            if let Some(out) = output.as_mut() {
                out.write_at(write_pos, str_bytes)?;
                out.write_at(null_pos, &[0u8])?;
            }

            pos = pos
                .checked_add(entry_size)
                .ok_or_else(|| writer_overflow("heap_position"))?;
            dedup_map.insert(final_bytes.to_vec(), new_offset);

            // Add primary offset remapping if changed
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }

            // Add substring remappings for any referenced offset within the ORIGINAL range.
            if modification.is_some() {
                // Parent string was modified — substrings at the original deltas may no
                // longer exist in the new entry. Emit them as standalone entries.
                emit_orphaned_substrings(
                    &mut output,
                    start_offset,
                    old_offset_u32,
                    original_end,
                    original_bytes,
                    referenced_offsets,
                    &mut dedup_map,
                    &mut pos,
                    &mut result,
                )?;
            } else {
                // Unmodified: substrings are at the same delta in the new entry
                for &ref_offset in referenced_offsets {
                    if ref_offset > old_offset_u32 && ref_offset < original_end {
                        let substring_delta = ref_offset
                            .checked_sub(old_offset_u32)
                            .ok_or_else(|| writer_overflow("substring_delta"))?;
                        let new_substring_offset = new_offset
                            .checked_add(substring_delta)
                            .ok_or_else(|| writer_overflow("substring_offset"))?;
                        result.remapping.insert(ref_offset, new_substring_offset);
                    }
                }
            }
        }
    }

    // Process appended strings
    // Note: We need to skip positions that are keys in the remapping, as those old offsets
    // would cause newly allocated entries to be incorrectly remapped when heap patching
    // is applied to table rows. This is more space-efficient than starting after max_old_offset.
    for (new_string, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let final_str = changes
            .get_modification(placeholder)
            .map_or(new_string.as_str(), |s| s.as_str());

        if let Some(&existing_offset) = dedup_map.get(final_str.as_bytes()) {
            change_ref.resolve_to_offset(existing_offset);
            continue;
        }

        // Skip positions that are remapping keys to avoid collision with old offsets
        // that would be incorrectly remapped when heap patching is applied
        // PE and metadata heap sizes are limited to 4GB, so this cast is safe
        #[allow(clippy::cast_possible_truncation)]
        while result.remapping.contains_key(&(pos as u32)) {
            pos = pos
                .checked_add(1)
                .ok_or_else(|| writer_overflow("heap_position"))?;
        }

        let new_offset = u32::try_from(pos)
            .map_err(|_| Error::LayoutFailed(format!("Heap position {pos} exceeds u32 range")))?;
        let str_bytes = final_str.as_bytes();
        let entry_size = (str_bytes.len() as u64)
            .checked_add(1)
            .ok_or_else(|| writer_overflow("heap_entry_size"))?;

        let write_pos = start_offset
            .checked_add(pos)
            .ok_or_else(|| writer_overflow("heap_write_offset"))?;
        let null_pos = write_pos
            .checked_add(str_bytes.len() as u64)
            .ok_or_else(|| writer_overflow("heap_write_offset"))?;
        if let Some(out) = output.as_mut() {
            out.write_at(write_pos, str_bytes)?;
            out.write_at(null_pos, &[0u8])?;
        }

        pos = pos
            .checked_add(entry_size)
            .ok_or_else(|| writer_overflow("heap_position"))?;
        dedup_map.insert(final_str.as_bytes().to_vec(), new_offset);
        change_ref.resolve_to_offset(new_offset);
    }

    result.bytes_written = pos;
    Ok(result)
}

/// Streams the #Blob heap to output with deduplication and modifications.
///
/// Processes the source blob heap data, applying any modifications from the changes,
/// and writes the result to the output file with deduplication. The blobs `blobs` names as
/// naming rows have those rows renumbered, and the blobs it names as naming blobs are written
/// last, with the offsets the rebuilt heap gives the blobs they name.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #Blob heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `blobs` - Which blobs name rows or blobs, and how the write renumbers tokens
/// * `referenced` - Every blob offset the written tables name
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails, if the source heap cannot be read, or if
/// the rebuilt heap reaches a referenced offset that names nothing.
pub fn stream_blob_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
    blobs: &BlobRemap<'_>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    process_blob_heap(
        Some(output),
        start_offset,
        source_data,
        changes,
        blobs,
        referenced,
    )
}

/// Pre-computes blob heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #Blob heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `blobs` - Which blobs name rows or blobs, and how the write renumbers tokens
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_blob_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
    blobs: &BlobRemap<'_>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    process_blob_heap(None, 0, source_data, changes, blobs, referenced)
}

/// The referenced offsets the heap's own walk does not start an entry at (an offset inside
/// another entry's bytes), in order; placeholders of entries a change adds are not offsets.
fn interior_offsets(referenced: &HashSet<u32>, walked: &HashSet<u32>) -> Vec<u32> {
    let mut interior: Vec<u32> = referenced
        .iter()
        .copied()
        .filter(|&offset| {
            offset != 0 && !ChangeRef::is_heap_placeholder(offset) && !walked.contains(&offset)
        })
        .collect();
    interior.sort_unstable();
    interior
}

/// Checks that the referenced offsets which named nothing in the source heap still name
/// nothing: they are written as they are, so the rebuilt heap must end before each, its
/// padding to four bytes included (a zero byte of padding reads as an empty entry). An offset
/// the rebuilt heap reaches would name whatever landed there.
///
/// # Errors
///
/// When the rebuilt heap, `end` bytes long, reaches one of `nameless`.
fn still_nameless(nameless: &[u32], end: u64, heap: &str) -> Result<()> {
    let padded = end
        .checked_next_multiple_of(4)
        .ok_or_else(|| writer_overflow("heap_end"))?;
    match nameless.iter().find(|&&offset| u64::from(offset) < padded) {
        Some(offset) => Err(Error::LayoutFailed(format!(
            "{heap} offset {offset:#x} names nothing, and the rebuilt heap reaches it"
        ))),
        None => Ok(()),
    }
}

/// Writes `blob` as the heap's next entry at `*pos`, or names the entry already holding the
/// same bytes, and returns its offset.
fn emit_blob(
    output: &mut Option<&mut Output>,
    start_offset: u64,
    pos: &mut u64,
    dedup_map: &mut FxHashMap<Vec<u8>, u32>,
    blob: &[u8],
) -> Result<u32> {
    if let Some(&existing) = dedup_map.get(blob) {
        return Ok(existing);
    }
    let new_offset = u32::try_from(*pos)
        .map_err(|_| Error::LayoutFailed(format!("Heap position {pos} exceeds u32 range")))?;
    let entry_size = compressed_uint_size(blob.len())
        .checked_add(blob.len() as u64)
        .ok_or_else(|| writer_overflow("blob_entry_size"))?;
    let write_pos = start_offset
        .checked_add(*pos)
        .ok_or_else(|| writer_overflow("heap_write_offset"))?;
    if let Some(out) = output.as_mut() {
        let blob_len_u32 = u32::try_from(blob.len()).map_err(|_| {
            Error::LayoutFailed(format!("Blob length {} exceeds u32 range", blob.len()))
        })?;
        let mut len_bytes = Vec::with_capacity(4);
        write_compressed_uint(blob_len_u32, &mut len_bytes)?;
        let data_pos = write_pos
            .checked_add(len_bytes.len() as u64)
            .ok_or_else(|| writer_overflow("heap_write_offset"))?;
        out.write_at(write_pos, &len_bytes)?;
        out.write_at(data_pos, blob)?;
    }
    *pos = pos
        .checked_add(entry_size)
        .ok_or_else(|| writer_overflow("heap_position"))?;
    dedup_map.insert(blob.to_vec(), new_offset);
    Ok(new_offset)
}

/// Unified blob heap processor.
///
/// The blobs `blobs` names as naming rows have those rows renumbered; every other blob is
/// written as it is. Every entry of the heap's walk is written, and so is the blob at every
/// `referenced` offset the walk does not start an entry at: a table may name an offset inside
/// another blob's bytes, whose bytes then move when the heap is rebuilt. A referenced offset
/// that names no blob is written as it is, while it still names none.
///
/// A blob that names blobs (a document name, an imports blob, a composite a change adds) is
/// held back: it is written after every other blob, encoded with the offsets the blobs it
/// names were given. A blob it names that no other entry placed (one inside another blob's
/// bytes) is written then, so that it has an offset to name.
fn process_blob_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<Vec<u8>>,
    blobs: &BlobRemap<'_>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();
    let mut pos: u64 = 1; // Start after null byte

    // Content -> new offset, for deduplication. The empty blob at offset 0 is not reused: an
    // empty blob elsewhere is a real entry (an empty signature), which offset 0 would make a
    // null reference.
    let mut dedup_map: FxHashMap<Vec<u8>, u32> = FxHashMap::default();
    let mut nameless = Vec::new();
    // The input offsets whose blob is placed: at its own offset, or where the remapping says
    let mut placed: HashSet<u32> = HashSet::new();
    // The blobs that name blobs, written last: their index, the change that adds an appended
    // one, and their bytes
    let mut deferred: Vec<(u32, Option<&ChangeRefRc>, Vec<u8>)> = Vec::new();

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    // Process source heap
    // A source that does not parse cannot have changes applied to it: dropping it would
    // leave every reference into it dangling. Only an absent heap starts empty.
    let source = match Blob::from(source_data) {
        Ok(heap) => Some(heap),
        Err(_) if source_data.is_empty() => None,
        Err(e) => {
            return Err(Error::LayoutFailed(format!(
                "the #Blob heap to write does not parse ({e}), so its changes cannot be applied"
            )))
        }
    };
    if let Some(heap) = &source {
        let mut walked = HashSet::new();
        for (old_offset, original_blob) in heap.iter() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                Error::LayoutFailed(format!("Blob offset {old_offset} exceeds u32 range"))
            })?;
            walked.insert(old_offset_u32);

            if changes.is_removed(old_offset_u32) {
                continue;
            }

            // Get the blob content (original or modified)
            let base_blob: &[u8] = changes
                .get_modification(old_offset_u32)
                .map_or(original_blob, Vec::as_slice);

            if blobs.defers(old_offset_u32, None) {
                deferred.push((old_offset_u32, None, base_blob.to_vec()));
                continue;
            }

            // Renumber the rows a blob names
            let remapped_blob = blobs.remap(old_offset_u32, base_blob)?;
            let final_blob: &[u8] = remapped_blob.as_deref().unwrap_or(base_blob);

            let new_offset = emit_blob(
                &mut output,
                start_offset,
                &mut pos,
                &mut dedup_map,
                final_blob,
            )?;
            placed.insert(old_offset_u32);
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }
        }

        for offset in interior_offsets(referenced, &walked) {
            // An offset that names no blob (past the heap: junk an obfuscator leaves in a
            // column) has nothing at it to keep, and is written as it is
            let Ok(blob) = heap.get(offset as usize) else {
                nameless.push(offset);
                continue;
            };
            if blobs.defers(offset, None) {
                deferred.push((offset, None, blob.to_vec()));
                continue;
            }
            let remapped_blob = blobs.remap(offset, blob)?;
            let final_blob: &[u8] = remapped_blob.as_deref().unwrap_or(blob);
            let new_offset = emit_blob(
                &mut output,
                start_offset,
                &mut pos,
                &mut dedup_map,
                final_blob,
            )?;
            placed.insert(offset);
            if offset != new_offset {
                result.remapping.insert(offset, new_offset);
            }
        }
    }

    // Process appended blobs
    // Note: We need to skip positions that are keys in the remapping, as those old offsets
    // would cause newly allocated entries to be incorrectly remapped when heap patching
    // is applied to table rows. This is more space-efficient than starting after max_old_offset.
    for (new_blob, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let base_blob: &[u8] = changes
            .get_modification(placeholder)
            .map_or(new_blob.as_slice(), Vec::as_slice);

        if blobs.defers(placeholder, Some(change_ref.id())) {
            deferred.push((placeholder, Some(change_ref), base_blob.to_vec()));
            continue;
        }

        // Renumber the rows new blobs name as well: regenerated methods' local signatures
        // name types whose rows a deletion shifts, and a builder's blob names the rows a
        // change adds by placeholder
        let remapped_blob = blobs.remap(placeholder, base_blob)?;

        let final_blob: &[u8] = remapped_blob.as_deref().unwrap_or(base_blob);

        if let Some(&existing_offset) = dedup_map.get(final_blob) {
            change_ref.resolve_to_offset(existing_offset);
            continue;
        }

        skip_remapping_keys(&result, &mut pos)?;

        let new_offset = emit_blob(
            &mut output,
            start_offset,
            &mut pos,
            &mut dedup_map,
            final_blob,
        )?;
        change_ref.resolve_to_offset(new_offset);
    }

    // The blobs that name blobs, now that every blob they name has its offset
    for (index, change_ref, bytes) in deferred {
        let final_blob = blobs.encode_deferred(
            index,
            change_ref.map(|change_ref| change_ref.id()),
            &bytes,
            &mut |offset| {
                if offset == 0 {
                    return Ok(0);
                }
                if placed.contains(&offset) {
                    return Ok(result.remapping.get(&offset).copied().unwrap_or(offset));
                }
                if changes.is_removed(offset) {
                    return Err(Error::LayoutFailed(format!(
                        "a blob names #Blob offset {offset:#x}, which the write removes"
                    )));
                }
                // A blob no entry placed (inside another blob's bytes): written now
                let named = source
                    .as_ref()
                    .and_then(|heap| heap.get(offset as usize).ok())
                    .ok_or_else(|| {
                        Error::LayoutFailed(format!(
                            "a blob names #Blob offset {offset:#x}, which holds no blob"
                        ))
                    })?;
                skip_remapping_keys(&result, &mut pos)?;
                emit_blob(&mut output, start_offset, &mut pos, &mut dedup_map, named)
            },
        )?;
        let new_offset = match dedup_map.get(final_blob.as_slice()) {
            Some(&existing) => existing,
            None => {
                skip_remapping_keys(&result, &mut pos)?;
                emit_blob(
                    &mut output,
                    start_offset,
                    &mut pos,
                    &mut dedup_map,
                    &final_blob,
                )?
            }
        };
        match change_ref {
            Some(change_ref) => change_ref.resolve_to_offset(new_offset),
            None => {
                if index != new_offset {
                    result.remapping.insert(index, new_offset);
                }
            }
        }
    }

    still_nameless(&nameless, pos, "#Blob")?;
    result.bytes_written = pos;
    Ok(result)
}

/// Moves `pos` past every offset the remapping has a key for: an entry written there would
/// be taken for the old entry the key names when the tables' heap columns are patched.
fn skip_remapping_keys(result: &StreamResult, pos: &mut u64) -> Result<()> {
    while u32::try_from(*pos).is_ok_and(|offset| result.remapping.contains_key(&offset)) {
        *pos = pos
            .checked_add(1)
            .ok_or_else(|| writer_overflow("heap_position"))?;
    }
    Ok(())
}

/// Streams the #GUID heap to output with deduplication and modifications.
///
/// GUID entries are fixed 16-byte values. Unlike other heaps, GUID indices are 1-based.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #GUID heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new index remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails.
pub fn stream_guid_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    process_guid_heap(Some(output), start_offset, source_data, changes)
}

/// Pre-computes GUID heap indices and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #GUID heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new index remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_guid_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    process_guid_heap(None, 0, source_data, changes)
}

/// Unified GUID heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
fn process_guid_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<[u8; 16]>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();
    let mut pos: u64 = 0;

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    // Track content → new_index for deduplication (1-based indices)
    let mut dedup_map: FxHashMap<[u8; 16], u32> = FxHashMap::default();
    let mut current_index: u32 = 1;

    // A source that does not parse cannot have changes applied to it: dropping it would
    // leave every reference into it dangling. Only an absent heap starts empty.
    let source = match Guid::from(source_data) {
        Ok(heap) => Some(heap),
        Err(_) if source_data.is_empty() => None,
        Err(e) => {
            return Err(Error::LayoutFailed(format!(
                "the #GUID heap to write does not parse ({e}), so its changes cannot be applied"
            )))
        }
    };
    if let Some(guids) = source {
        for (old_index, guid) in guids.iter() {
            let old_index_u32 = u32::try_from(old_index).map_err(|_| {
                Error::LayoutFailed(format!("GUID index {old_index} exceeds u32 range"))
            })?;

            // For GUIDs, changes use byte offset = (index - 1) * 16
            let byte_offset = old_index_u32
                .saturating_sub(1)
                .checked_mul(16)
                .ok_or_else(|| writer_overflow("guid_byte_offset"))?;

            // Check if deleted
            if changes.is_removed(byte_offset) {
                continue;
            }

            // Check if modified
            let final_guid: [u8; 16] = changes
                .get_modification(byte_offset)
                .copied()
                .unwrap_or_else(|| guid.to_bytes());

            // Deduplicate by content
            if let Some(&existing_index) = dedup_map.get(&final_guid) {
                // Only add to remapping if the index actually changed
                if old_index_u32 != existing_index {
                    result.remapping.insert(old_index_u32, existing_index);
                }
                continue;
            }

            // Write if in write mode
            let write_pos = start_offset
                .checked_add(pos)
                .ok_or_else(|| writer_overflow("guid_heap_write_offset"))?;
            if let Some(out) = output.as_mut() {
                out.write_at(write_pos, &final_guid)?;
            }
            pos = pos
                .checked_add(16)
                .ok_or_else(|| writer_overflow("guid_heap_position"))?;

            dedup_map.insert(final_guid, current_index);
            // Only add to remapping if the index actually changed
            if old_index_u32 != current_index {
                result.remapping.insert(old_index_u32, current_index);
            }
            current_index = current_index
                .checked_add(1)
                .ok_or_else(|| writer_overflow("guid_index"))?;
        }
    }

    // Append new GUIDs from changes
    for (new_guid, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        // Check if this appended GUID was modified (update after add)
        let placeholder = change_ref.placeholder();
        let final_guid = changes.get_modification(placeholder).unwrap_or(new_guid);

        if let Some(&existing_index) = dedup_map.get(final_guid) {
            change_ref.resolve_to_offset(existing_index);
            continue;
        }

        let write_pos = start_offset
            .checked_add(pos)
            .ok_or_else(|| writer_overflow("guid_heap_write_offset"))?;
        if let Some(out) = output.as_mut() {
            out.write_at(write_pos, final_guid)?;
        }
        pos = pos
            .checked_add(16)
            .ok_or_else(|| writer_overflow("guid_heap_position"))?;

        dedup_map.insert(*final_guid, current_index);
        change_ref.resolve_to_offset(current_index);
        current_index = current_index
            .checked_add(1)
            .ok_or_else(|| writer_overflow("guid_index"))?;
    }

    result.bytes_written = pos;
    Ok(result)
}

/// Streams the #US (user strings) heap to output with deduplication and modifications.
///
/// User strings are stored in UTF-16 format with a trailing flag byte. They are
/// referenced by `ldstr` IL instructions.
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to write to
/// * `start_offset` - The file offset where the heap should start
/// * `source_data` - The original #US heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
/// * `referenced` - Every `#US` offset an `ldstr` of a written body names
///
/// # Returns
///
/// A [`StreamResult`] containing bytes written and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if writing to the output fails, if the source heap cannot be read, or if
/// the rebuilt heap reaches a referenced offset that names nothing.
pub fn stream_userstring_heap(
    output: &mut Output,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    process_userstring_heap(Some(output), start_offset, source_data, changes, referenced)
}

/// Pre-computes userstring heap offsets and resolves ChangeRefs WITHOUT writing.
///
/// This is used during the early generation phase to resolve ChangeRef placeholders
/// for `ldstr` instructions before method bodies are written.
///
/// # Arguments
///
/// * `source_data` - The original #US heap data
/// * `changes` - Heap modifications (additions, removals, modifications)
///
/// # Returns
///
/// A [`StreamResult`] containing calculated bytes and old→new offset remapping.
///
/// # Errors
///
/// Returns an error if heap processing fails.
pub fn compute_userstring_heap_offsets(
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    process_userstring_heap(None, 0, source_data, changes, referenced)
}

/// Writes the string of UTF-16 `units` as the heap's next entry at `*pos`, or names the entry
/// already holding the same string, and returns its offset.
fn emit_userstring(
    output: &mut Option<&mut Output>,
    start_offset: u64,
    pos: &mut u64,
    dedup_map: &mut FxHashMap<Vec<u16>, u32>,
    units: Vec<u16>,
) -> Result<u32> {
    if let Some(&existing) = dedup_map.get(&units) {
        return Ok(existing);
    }
    let new_offset = u32::try_from(*pos)
        .map_err(|_| Error::LayoutFailed(format!("Heap position {pos} exceeds u32 range")))?;
    let entry_size = userstring_entry_size(&units)?;
    let write_pos = start_offset
        .checked_add(*pos)
        .ok_or_else(|| writer_overflow("userstring_write_offset"))?;
    if let Some(out) = output.as_mut() {
        write_userstring_entry(out, write_pos, &units)?;
    }
    *pos = pos
        .checked_add(entry_size)
        .ok_or_else(|| writer_overflow("userstring_heap_position"))?;
    dedup_map.insert(units, new_offset);
    Ok(new_offset)
}

/// Unified userstring heap processor.
///
/// When `output` is `Some(output)`, writes to output at `start_offset`.
/// When `output` is `None`, only computes offsets (for pre-computation).
///
/// Every entry of the heap's walk is written, and so is the string at every `referenced`
/// offset the walk does not start an entry at: an `ldstr` may name an offset inside another
/// entry's bytes, whose bytes then move when the heap is rebuilt. A referenced offset that
/// names no string is written as it is, while it still names none.
fn process_userstring_heap(
    mut output: Option<&mut Output>,
    start_offset: u64,
    source_data: &[u8],
    changes: &HeapChanges<String>,
    referenced: &HashSet<u32>,
) -> Result<StreamResult> {
    let mut result = StreamResult::new();

    // If this is a raw heap replacement with no modifications or appends,
    // write the source data directly. This is needed for tests that create
    // intentionally malformed heaps that won't parse correctly.
    if changes.has_replacement()
        && changes.additions_count() == 0
        && changes.modifications_count() == 0
        && changes.removals_count() == 0
    {
        if let Some(out) = output.as_mut() {
            out.write_at(start_offset, source_data)?;
        }
        result.bytes_written = source_data.len() as u64;
        return Ok(result);
    }

    let mut pos: u64 = 1; // Start after null byte

    // Content (UTF-16 code units, unpaired surrogates included) -> new offset, for
    // deduplication. The zero-length entry at offset 0 is no string: an `ldstr ""` names an
    // entry of its own.
    let mut dedup_map: FxHashMap<Vec<u16>, u32> = FxHashMap::default();
    let mut nameless = Vec::new();

    // Write null byte if in write mode
    if let Some(out) = output.as_mut() {
        out.write_at(start_offset, &[0u8])?;
    }

    // A source that does not parse cannot have changes applied to it: dropping it would
    // leave every reference into it dangling. Only an absent heap starts empty.
    let source = match UserStrings::from(source_data) {
        Ok(heap) => Some(heap),
        Err(_) if source_data.is_empty() => None,
        Err(e) => {
            return Err(Error::LayoutFailed(format!(
                "the #US heap to write does not parse ({e}), so its changes cannot be applied"
            )))
        }
    };
    if let Some(userstrings) = source {
        let mut walked = HashSet::new();
        for (old_offset, original) in userstrings.iter() {
            let old_offset_u32 = u32::try_from(old_offset).map_err(|_| {
                Error::LayoutFailed(format!("UserString offset {old_offset} exceeds u32 range"))
            })?;
            walked.insert(old_offset_u32);

            if changes.is_removed(old_offset_u32) {
                continue;
            }

            let units = changes
                .get_modification(old_offset_u32)
                .map_or_else(|| original.into_vec(), |s| s.encode_utf16().collect());
            let new_offset =
                emit_userstring(&mut output, start_offset, &mut pos, &mut dedup_map, units)?;
            // Only add to remapping if the offset actually changed
            if old_offset_u32 != new_offset {
                result.remapping.insert(old_offset_u32, new_offset);
            }
        }

        for offset in interior_offsets(referenced, &walked) {
            // An `ldstr` that names no string (in code that never runs) has nothing at it to
            // keep, and is written as it is
            let Ok(units) = userstrings
                .get(offset as usize)
                .map(|string| string.into_vec())
            else {
                nameless.push(offset);
                continue;
            };
            let new_offset =
                emit_userstring(&mut output, start_offset, &mut pos, &mut dedup_map, units)?;
            if offset != new_offset {
                result.remapping.insert(offset, new_offset);
            }
        }
    }

    // Process appended userstrings
    for (new_string, change_ref) in changes.appended_iter() {
        if changes.is_ref_removed(change_ref) {
            continue;
        }

        let placeholder = change_ref.placeholder();
        let units: Vec<u16> = changes
            .get_modification(placeholder)
            .unwrap_or(new_string)
            .encode_utf16()
            .collect();

        let new_offset =
            emit_userstring(&mut output, start_offset, &mut pos, &mut dedup_map, units)?;
        change_ref.resolve_to_offset(new_offset);
    }

    still_nameless(&nameless, pos, "#US")?;
    result.bytes_written = pos;
    Ok(result)
}

/// Calculates the size of a userstring entry without writing.
fn userstring_entry_size(units: &[u16]) -> Result<u64> {
    let utf16_len = units
        .len()
        .checked_mul(2)
        .ok_or_else(|| writer_overflow("userstring_utf16_length"))?;
    let total_len = utf16_len
        .checked_add(1)
        .ok_or_else(|| writer_overflow("userstring_total_length"))?; // +1 for terminal byte
    compressed_uint_size(total_len)
        .checked_add(total_len as u64)
        .ok_or_else(|| writer_overflow("userstring_entry_size"))
}

/// The terminal byte of a user string (ECMA-335 II.24.2.4): 1 when a character has a bit set
/// in its top byte, or a low byte of 0x01-0x08, 0x0E-0x1F, 0x27, 0x2D or 0x7F; 0 otherwise.
fn userstring_terminal(units: &[u16]) -> u8 {
    u8::from(
        units.iter().any(|&unit| {
            unit > 0xFF || matches!(unit, 0x01..=0x08 | 0x0E..=0x1F | 0x27 | 0x2D | 0x7F)
        }),
    )
}

/// Writes a single user string entry to output.
///
/// Format: compressed_length + UTF-16LE bytes + terminal byte
fn write_userstring_entry(output: &mut Output, pos: u64, units: &[u16]) -> Result<()> {
    let utf16_bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    let total_len = utf16_bytes
        .len()
        .checked_add(1)
        .ok_or_else(|| writer_overflow("userstring_total_length"))?;

    // Write compressed length
    let total_len_u32 = u32::try_from(total_len).map_err(|_| {
        Error::LayoutFailed(format!("UserString length {total_len} exceeds u32 range"))
    })?;
    let mut len_bytes = Vec::with_capacity(4);
    write_compressed_uint(total_len_u32, &mut len_bytes)?;
    output.write_at(pos, &len_bytes)?;

    // Write UTF-16LE bytes
    let utf16_pos = pos
        .checked_add(len_bytes.len() as u64)
        .ok_or_else(|| writer_overflow("userstring_write_offset"))?;
    output.write_at(utf16_pos, &utf16_bytes)?;

    let terminal_pos = utf16_pos
        .checked_add(utf16_bytes.len() as u64)
        .ok_or_else(|| writer_overflow("userstring_write_offset"))?;
    output.write_at(terminal_pos, &[userstring_terminal(units)])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use crate::{
        cilassembly::{
            writer::{
                blobs::{BlobKind, TypedBlob},
                remapper::TokenRemap,
            },
            AssemblyChanges, ChangeIds,
        },
        metadata::{pdb::document_name, token::Token},
        Referrer,
    };

    /// The #US heap `stream_userstring_heap` writes for `source` and `changes`.
    fn written_userstrings(
        source: &[u8],
        changes: &HeapChanges<String>,
    ) -> (Vec<u8>, StreamResult) {
        let mut output = Output::create_in_memory(4096).unwrap();
        let result =
            stream_userstring_heap(&mut output, 0, source, changes, &HashSet::new()).unwrap();
        let len = usize::try_from(result.bytes_written).unwrap();
        (output.as_slice()[..len].to_vec(), result)
    }

    #[test]
    fn test_stream_strings_heap_empty() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        let changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &[0u8], &changes, &empty_refs).unwrap();

        assert_eq!(result.bytes_written, 1); // Just null byte
        assert!(result.remapping.is_empty());
    }

    #[test]
    fn test_stream_strings_heap_with_source() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        // Source heap: null + "Hello" + "World"
        let source = [
            0x00, // null
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            b'W', b'o', b'r', b'l', b'd', 0x00, // "World" at offset 7
        ];

        let changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &source, &changes, &empty_refs).unwrap();

        // Should write: null + Hello\0 + World\0 = 1 + 6 + 6 = 13
        assert_eq!(result.bytes_written, 13);
    }

    #[test]
    fn test_stream_strings_heap_deduplication() {
        let temp_file = NamedTempFile::new().unwrap();
        let mut output = Output::create(temp_file.path(), 4096).unwrap();

        // Source heap with duplicate: null + "Hello" + "Hello"
        let source = [
            0x00, b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 1
            b'H', b'e', b'l', b'l', b'o', 0x00, // "Hello" at offset 7 (duplicate)
        ];

        let changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let empty_refs = HashSet::new();
        let result = stream_strings_heap(&mut output, 0, &source, &changes, &empty_refs).unwrap();

        // Should write only one "Hello": null + Hello\0 = 1 + 6 = 7
        assert_eq!(result.bytes_written, 7);
        // Second occurrence should remap to first
        assert_eq!(result.remapping.get(&7), Some(&1));
    }

    /// The #Strings heap `stream_strings_heap` writes for `source`, with `referenced` the
    /// offsets tables name.
    fn written_strings(source: &[u8], referenced: &[u32]) -> (Vec<u8>, StreamResult) {
        let mut output = Output::create_in_memory(4096).unwrap();
        let changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        let referenced: HashSet<u32> = referenced.iter().copied().collect();
        let result = stream_strings_heap(&mut output, 0, source, &changes, &referenced).unwrap();
        let len = usize::try_from(result.bytes_written).unwrap();
        (output.as_slice()[..len].to_vec(), result)
    }

    #[test]
    fn a_string_that_is_not_utf8_is_written_with_those_after_it() {
        // null + "A" at 1 + 0xFF 0xFE at 3 + "B" at 6
        let source = [0x00, b'A', 0x00, 0xFF, 0xFE, 0x00, b'B', 0x00];
        let (heap, result) = written_strings(&source, &[]);
        assert_eq!(heap, source);
        assert!(result.remapping.is_empty());
    }

    #[test]
    fn a_substring_of_a_string_that_is_not_utf8_keeps_its_bytes() {
        // A removed entry 0xFF 'x' 'y' at 1, whose tail "xy" at 2 a table still names
        let source = [0x00, 0xFF, b'x', b'y', 0x00];
        let mut changes = HeapChanges::<String>::new_strings(ChangeIds::new());
        changes.add_removal(1);
        let mut output = Output::create_in_memory(4096).unwrap();
        let referenced = HashSet::from([2u32]);
        let result = stream_strings_heap(&mut output, 0, &source, &changes, &referenced).unwrap();
        let tail = *result.remapping.get(&2).expect("the tail is kept");
        assert_ne!(tail, 0, "the tail is not the empty string");
        let start = usize::try_from(tail).unwrap();
        assert_eq!(&output.as_slice()[start..start + 3], b"xy\0");
    }

    #[test]
    fn an_empty_user_string_keeps_an_entry_of_its_own() {
        // null + "x" at 1 + "" at 5: offset 0 is no string, so `ldstr ""` cannot move there.
        let source = [0x00, 0x03, b'x', 0x00, 0x00, 0x01, 0x00];
        let mut changes = HeapChanges::<String>::new_userstrings(ChangeIds::new());
        let appended = changes.append(String::new());

        let (heap, result) = written_userstrings(&source, &changes);

        assert_eq!(heap, source);
        assert!(result.remapping.is_empty());
        assert_eq!(appended.offset(), Some(5));
    }

    #[test]
    fn user_strings_with_unpaired_surrogates_are_written_as_they_are() {
        // null + "\u{D800}" at 1 + "\u{DC00}" at 5: neither is valid UTF-16, and the two differ.
        let source = [0x00, 0x03, 0x00, 0xD8, 0x01, 0x03, 0x00, 0xDC, 0x01];
        let changes = HeapChanges::<String>::new_userstrings(ChangeIds::new());

        let (heap, result) = written_userstrings(&source, &changes);

        assert_eq!(heap, source);
        assert!(result.remapping.is_empty());
    }

    #[test]
    fn a_user_string_terminal_byte_follows_ecma_335() {
        for (text, terminal) in [
            ("A", 0),
            ("\u{FC}", 0),
            ("\u{100}", 1),
            ("'", 1),
            ("-", 1),
            ("\u{7F}", 1),
            ("\u{1}", 1),
            ("\u{E}", 1),
            ("\t", 0),
            ("\r\n", 0),
        ] {
            let units: Vec<u16> = text.encode_utf16().collect();
            assert_eq!(userstring_terminal(&units), terminal, "{text:?}");
        }
    }

    #[test]
    fn an_appended_empty_blob_is_not_the_null_blob() {
        let mut changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        let appended = changes.append(Vec::new());
        let blobs = HashMap::new();
        let tokens = TokenRemap::default();
        let assembly_changes = AssemblyChanges::new();
        let signatures = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &assembly_changes,
        };
        let mut output = Output::create_in_memory(4096).unwrap();

        let result = stream_blob_heap(
            &mut output,
            0,
            &[0x00],
            &changes,
            &signatures,
            &HashSet::new(),
        )
        .unwrap();

        assert_eq!(result.bytes_written, 2);
        assert_eq!(appended.offset(), Some(1));
    }

    /// A blob a table names inside another blob's bytes keeps its bytes when the heap is
    /// rebuilt. The walk reads `AA` at 1 and 3, `01 02 00` at 5 and an empty blob at 9, and
    /// deduplicates the second `AA`, so every later entry moves; a table also names offset 7,
    /// where the byte `02` is the length of the blob `00 00`, which no entry of the walk holds.
    #[test]
    fn a_blob_inside_another_keeps_its_bytes() {
        let source = [0x00, 0x01, 0xAA, 0x01, 0xAA, 0x03, 0x01, 0x02, 0x00, 0x00];
        let changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        let blobs = HashMap::new();
        let tokens = TokenRemap::default();
        let assembly_changes = AssemblyChanges::new();
        let signatures = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &assembly_changes,
        };
        // 0x7FFF is past the heap: it names nothing, and is written as it is
        let referenced: HashSet<u32> = [1, 3, 5, 7, 9, 0x7FFF].into_iter().collect();
        let mut output = Output::create_in_memory(4096).unwrap();

        let result =
            stream_blob_heap(&mut output, 0, &source, &changes, &signatures, &referenced).unwrap();

        let len = usize::try_from(result.bytes_written).unwrap();
        let written = Blob::from(&output.as_slice()[..len]).unwrap();
        let read = |offset: u32| {
            let offset = result.remapping.get(&offset).copied().unwrap_or(offset);
            written.get(offset as usize).unwrap().to_vec()
        };
        assert!(!result.remapping.contains_key(&0x7FFF));
        let original = Blob::from(&source[..]).unwrap();
        for offset in referenced.into_iter().filter(|&offset| offset != 0x7FFF) {
            assert_eq!(
                read(offset),
                original.get(offset as usize).unwrap(),
                "offset {offset}"
            );
        }
    }

    /// A document name follows the parts it names when the heap is rebuilt. The walk reads
    /// `AA` at 1 and 3, "src" at 5, "a.cs" at 9 and the name `/ 5 9` at 14; the second `AA`
    /// is deduplicated, so the parts move, and the name, held back until they are placed, is
    /// written naming their new offsets.
    #[test]
    fn a_document_name_follows_its_parts() {
        let source = [
            0x00, 0x01, 0xAA, 0x01, 0xAA, 0x03, b's', b'r', b'c', 0x04, b'a', b'.', b'c', b's',
            0x03, b'/', 0x05, 0x09,
        ];
        let changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        let mut blobs = HashMap::new();
        blobs.insert(
            14,
            TypedBlob {
                kind: BlobKind::DocumentName,
                referrer: Referrer::Column {
                    row: Token::new(0x3000_0001),
                    column: "Name",
                },
            },
        );
        let tokens = TokenRemap::default();
        let assembly_changes = AssemblyChanges::new();
        let remap = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &assembly_changes,
        };
        let referenced: HashSet<u32> = [1, 3, 5, 9, 14].into_iter().collect();
        let mut output = Output::create_in_memory(4096).unwrap();

        let result =
            stream_blob_heap(&mut output, 0, &source, &changes, &remap, &referenced).unwrap();

        let len = usize::try_from(result.bytes_written).unwrap();
        let written = Blob::from(&output.as_slice()[..len]).unwrap();
        assert_eq!(result.remapping.get(&5), Some(&3));
        let name = result.remapping.get(&14).copied().unwrap();
        assert_eq!(
            document_name(written.get(name as usize).unwrap(), &written).unwrap(),
            "src/a.cs"
        );
    }

    /// rebuilt. The walk reads "A" at 1 and 5 and a seven-byte entry at 9, and deduplicates
    /// the second "A", so the long entry moves; an `ldstr` names offset 12, where the byte `03`
    /// is the length of the string "B" (`42 00`) and its terminal byte.
    #[test]
    fn a_user_string_inside_another_keeps_its_text() {
        let source = [
            0x00, 0x03, 0x41, 0x00, 0x00, 0x03, 0x41, 0x00, 0x00, 0x07, 0x41, 0x00, 0x03, 0x42,
            0x00, 0x00, 0x00,
        ];
        let changes = HeapChanges::<String>::new_userstrings(ChangeIds::new());
        // 0x7FFF is past the heap: it names nothing, and is written as it is
        let referenced: HashSet<u32> = [1, 5, 9, 12, 0x7FFF].into_iter().collect();
        let mut output = Output::create_in_memory(4096).unwrap();

        let result =
            stream_userstring_heap(&mut output, 0, &source, &changes, &referenced).unwrap();

        let len = usize::try_from(result.bytes_written).unwrap();
        let written = UserStrings::from(&output.as_slice()[..len]).unwrap();
        assert!(!result.remapping.contains_key(&0x7FFF));
        let original = UserStrings::from(&source[..]).unwrap();
        for offset in referenced.into_iter().filter(|&offset| offset != 0x7FFF) {
            let moved = result.remapping.get(&offset).copied().unwrap_or(offset);
            assert_eq!(
                written.get(moved as usize).unwrap(),
                original.get(offset as usize).unwrap(),
                "offset {offset}"
            );
        }
    }

    /// A referenced offset past the heap names nothing and is written as it is, so a heap that
    /// grows over it is refused: the offset would name what landed there. Padding counts,
    /// since a zero byte of it reads as an empty entry.
    #[test]
    fn a_heap_that_grows_over_an_offset_naming_nothing_is_refused() {
        let blobs = HashMap::new();
        let tokens = TokenRemap::default();
        let assembly_changes = AssemblyChanges::new();
        let signatures = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &assembly_changes,
        };
        let mut output = Output::create_in_memory(4096).unwrap();
        let source = [0x00, 0x01, 0xAA];
        // Past the source heap, and past the rebuilt one's padding: written as it is
        let changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        let referenced = HashSet::from([4u32]);
        assert!(
            stream_blob_heap(&mut output, 0, &source, &changes, &signatures, &referenced).is_ok()
        );
        // Past the source heap, inside the rebuilt one's padding
        let referenced = HashSet::from([3u32]);
        assert!(
            stream_blob_heap(&mut output, 0, &source, &changes, &signatures, &referenced).is_err()
        );
        // Past the source heap, inside an entry a change appends
        let mut changes = HeapChanges::<Vec<u8>>::new_blobs(ChangeIds::new());
        changes.append(vec![0xBB; 8]);
        let referenced = HashSet::from([6u32]);
        assert!(
            stream_blob_heap(&mut output, 0, &source, &changes, &signatures, &referenced).is_err()
        );

        let source = [0x00, 0x03, 0x41, 0x00, 0x00];
        let changes = HeapChanges::<String>::new_userstrings(ChangeIds::new());
        assert!(
            stream_userstring_heap(&mut output, 0, &source, &changes, &HashSet::from([8u32]))
                .is_ok()
        );
        assert!(
            stream_userstring_heap(&mut output, 0, &source, &changes, &HashSet::from([6u32]))
                .is_err()
        );
    }

    /// A heap that cannot be read is an error, whichever heap it is: writing it without its
    /// entries would leave every reference into it naming other bytes.
    #[test]
    fn an_unreadable_heap_is_refused() {
        let ids = ChangeIds::new();
        let blobs = HashMap::new();
        let tokens = TokenRemap::default();
        let assembly_changes = AssemblyChanges::new();
        let signatures = BlobRemap {
            blobs: &blobs,
            tokens: &tokens,
            changes: &assembly_changes,
        };
        let none = HashSet::new();
        let mut output = Output::create_in_memory(4096).unwrap();
        // #Strings, #US and #Blob start with an empty entry; #GUID holds whole GUIDs
        let unreadable = [0x05u8, 0x01];
        assert!(stream_strings_heap(
            &mut output,
            0,
            &unreadable,
            &HeapChanges::new_strings(ids.clone()),
            &none
        )
        .is_err());
        assert!(stream_userstring_heap(
            &mut output,
            0,
            &unreadable,
            &HeapChanges::new_userstrings(ids.clone()),
            &none
        )
        .is_err());
        assert!(stream_blob_heap(
            &mut output,
            0,
            &unreadable,
            &HeapChanges::new_blobs(ids.clone()),
            &signatures,
            &none
        )
        .is_err());
        assert!(
            stream_guid_heap(&mut output, 0, &unreadable, &HeapChanges::new_guids(ids)).is_err()
        );
        assert!(
            stream_guid_heap(
                &mut output,
                0,
                &[],
                &HeapChanges::new_guids(ChangeIds::new())
            )
            .is_ok(),
            "an absent heap starts empty"
        );
    }
}
