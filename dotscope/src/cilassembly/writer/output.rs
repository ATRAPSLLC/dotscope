//! Memory-mapped file handling for efficient binary output.
//!
//! This module provides the [`crate::cilassembly::writer::output::Output`] type for managing
//! memory-mapped files during binary generation. It implements atomic file operations
//! with proper cleanup and cross-platform compatibility for the dotscope binary writing pipeline.
//!
//! # Key Components
//!
//! - [`crate::cilassembly::writer::output::Output`] - Memory-mapped output file with atomic finalization
//!
//! # Architecture
//!
//! The output system is built around safe memory-mapped file operations:
//!
//! ## Atomic Operations
//! Files are written to temporary locations and atomically moved to their final destination
//! to prevent corruption from interrupted operations or system failures.
//!
//! ## Memory Mapping
//! Large binary files are handled through memory mapping for efficient random access
//! without loading entire files into memory at once.
//!
//! ## Resource Management
//! Proper cleanup is ensured through RAII patterns and explicit finalization steps
//! that handle both success and error cases.
//!
//! # Usage Examples
//!
//! ```no_run
//! use crate::cilassembly::writer::output::Output;
//! use std::path::Path;
//!
//! // Create a memory-mapped output file
//! let mut output = Output::create("output.dll", 4096)?;
//!
//! // Write data at specific offsets
//! output.write_at(0, b"MZ")?; // DOS signature
//! output.write_u32_le_at(100, 0x12345678)?; // Little-endian value
//!
//! // Atomically finalize the file (None = keep original size)
//! output.finalize(None)?;
//! # Ok::<(), crate::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! The [`crate::cilassembly::writer::output::Output`] type is not [`Send`] or [`Sync`] as it contains
//! memory-mapped file handles and temporary file resources that are tied to the creating thread.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::cilassembly::writer::layout`] - Layout planning for file size calculation
//! - [`crate::cilassembly::writer::executor`] - Execution engine that uses output files
//! - [`crate::cilassembly::writer`] - Main write pipeline coordination

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use memmap2::{MmapMut, MmapOptions};

use crate::{utils::write_compressed_uint, Error, Result};

/// Internal backing storage for output data.
///
/// This enum allows the Output struct to efficiently handle both file-backed
/// and in-memory operations without unnecessary copies.
enum OutputBacking {
    /// File-backed memory mapping for efficient large file I/O.
    ///
    /// Writes go to a temporary file alongside the target; [`Output::finalize`] renames it into
    /// place. The destination is not touched until generation has fully succeeded.
    File {
        /// The temporary file, kept to grow it
        file: File,
        /// The memory mapping of the temporary file
        mmap: MmapMut,
        /// Where the finished file will be renamed to
        target_path: PathBuf,
        /// The temporary file being written, adjacent to `target_path`
        temp_path: PathBuf,
    },
    /// In-memory vector for zero-copy memory output.
    Memory {
        /// The data buffer
        data: Vec<u8>,
    },
}

/// A dual-mode output that supports both file-backed and in-memory operations.
///
/// This wrapper provides safe and efficient access to large binary data during generation.
/// It supports two modes of operation:
///
/// - **File-backed**: Creates a file and memory-maps it for efficient random access
/// - **In-memory**: Uses a `Vec<u8>` for zero-copy memory generation
///
/// # Features
///
/// - **Dual-mode operation**: File-backed uses mmap, in-memory uses Vec
/// - **Zero-copy memory output**: `into_vec()` returns the Vec directly without copying
/// - **Atomic finalization**: File-backed output uses atomic operations
/// - **Proper cleanup**: Automatic cleanup on error or drop through RAII patterns
/// - **Cross-platform compatibility**: Works consistently across different operating systems
/// - **Bounds checking**: All write operations are bounds-checked for safety
///
/// # Memory Management
///
/// For file-backed output, the file is memory-mapped for access, allowing efficient
/// writing to arbitrary offsets without loading entire content into application memory.
///
/// For in-memory output, a `Vec<u8>` is used directly, which avoids the overhead of
/// memory mapping and allows zero-copy extraction via `into_vec()`.
///
/// # Usage Patterns
///
/// ```no_run
/// // File-backed output
/// let output = Output::create("output.dll", 4096)?;
/// // ... write data ...
/// output.finalize(Some(actual_size))?;
///
/// // In-memory output (zero-copy)
/// let output = Output::create_in_memory(4096)?;
/// // ... write data ...
/// let bytes = output.into_vec(Some(actual_size))?; // No copy!
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct Output {
    /// The backing storage (file mmap or in-memory vec)
    backing: OutputBacking,

    /// Whether the output has been finalized
    finalized: bool,
}

/// Maps `file`, an output's own temporary file, for writing: when it is created and each time
/// it grows.
///
/// # Errors
///
/// When the mapping cannot be created.
fn map_file(file: &File) -> Result<MmapMut> {
    // SAFETY: `map_mut` is unsafe because the mapping aliases the file's contents, and Rust
    // cannot rule out another process mutating or truncating the file underneath us: doing so
    // would let safe code observe a torn value or take SIGBUS. The file is one `Output::create`
    // just created beside `target_path` and sized with `set_len`; it is not handed to anything
    // else, and the mapping is owned by the `Output` that owns the `File`, so it cannot outlive
    // it. Concurrent external modification of a caller-chosen output path is outside the threat
    // model this crate defends against: an attacker who can write that path can simply replace
    // the artefact.
    #[allow(unsafe_code)]
    unsafe {
        MmapOptions::new()
            .map_mut(file)
            .map_err(|e| Error::MmapFailed(format!("Failed to create memory mapping: {e}")))
    }
}

impl Output {
    /// Creates a new file-backed memory-mapped output.
    ///
    /// Writes go to a temporary file alongside `target_path`, which [`finalize`](Self::finalize)
    /// renames into place. The destination is therefore never modified until generation has
    /// fully succeeded; if finalization fails or the output is dropped without being finalized,
    /// only the temporary file is removed and any existing artefact at `target_path` survives.
    ///
    /// # Arguments
    ///
    /// * `target_path` - The path where the file should be created
    /// * `size` - The size to create the file with: a write past it grows the file
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::cilassembly::writer::output::Output`] ready for writing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::MmapFailed`] in the following cases:
    /// - Target file creation fails
    /// - File size setting fails
    /// - Memory mapping creation fails
    pub fn create<P: AsRef<Path>>(target_path: P, size: u64) -> Result<Self> {
        let target_path = target_path.as_ref().to_path_buf();

        // Write to a temporary file beside the target, renamed into place by `finalize`.
        //
        // Truncating the destination up front and deleting it on failure — the previous
        // behaviour — destroys the existing artefact the moment generation starts, and leaves
        // nothing behind if any later step fails. When the caller writes back over the file the
        // assembly was loaded from, that is the input as well as the output.
        //
        // Same directory as the target so the final step is a rename within one filesystem,
        // which is atomic; a temp file in the system temp dir could land on another mount and
        // degrade to a copy.
        let parent = target_path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::MmapFailed(format!("Failed to create output directory: {e}")))?;

        let temp = tempfile::Builder::new()
            .prefix(".dotscope-")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|e| Error::MmapFailed(format!("Failed to create temporary file: {e}")))?;

        // Keep the path and hand back the `File`; the guard is dropped so it does not delete
        // the file behind us. Cleanup on failure is `Output::drop`'s job.
        let (file, temp_path) = temp
            .keep()
            .map_err(|e| Error::MmapFailed(format!("Failed to persist temporary file: {e}")))?;

        // Set the file size
        file.set_len(size)
            .map_err(|e| Error::MmapFailed(format!("Failed to set file size: {e}")))?;

        let mmap = map_file(&file)?;

        Ok(Self {
            backing: OutputBacking::File {
                file,
                mmap,
                target_path,
                temp_path,
            },
            finalized: false,
        })
    }

    /// Creates a new in-memory output using a pre-allocated vector.
    ///
    /// This creates an in-memory buffer without any file backing, useful for
    /// generating PE data that will be used in-memory rather than saved to disk.
    /// Use [`into_vec`](Self::into_vec) to extract the data after generation
    /// is complete - this is a zero-copy operation that moves the Vec.
    ///
    /// # Arguments
    ///
    /// * `size` - The total size of the memory region to allocate
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::cilassembly::writer::output::Output`] ready for writing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::MmapFailed`] if the size is too large for the architecture.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let mut output = Output::create_in_memory(4096)?;
    /// output.write_at(0, b"MZ")?;
    /// // ... more writes ...
    /// let bytes = output.into_vec(Some(actual_size))?; // Zero-copy!
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn create_in_memory(size: u64) -> Result<Self> {
        let size_usize = usize::try_from(size).map_err(|_| {
            Error::MmapFailed(format!("Size {size} too large for target architecture"))
        })?;

        // Create zero-initialized vector
        let data = vec![0u8; size_usize];

        Ok(Self {
            backing: OutputBacking::Memory { data },
            finalized: false,
        })
    }

    /// Returns `true` if this is an in-memory output (no file backing).
    ///
    /// In-memory outputs should be finalized with [`into_vec`](Self::into_vec)
    /// rather than [`finalize`](Self::finalize).
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        matches!(self.backing, OutputBacking::Memory { .. })
    }

    /// Gets an immutable slice to the entire buffer contents.
    ///
    /// Provides direct read-only access to the entire buffer.
    /// This is useful for operations like checksum calculation that need
    /// to read the entire content without modifying it.
    pub fn as_slice(&self) -> &[u8] {
        match &self.backing {
            OutputBacking::File { mmap, .. } => &mmap[..],
            OutputBacking::Memory { data } => &data[..],
        }
    }

    /// Gets a mutable slice to the entire buffer contents.
    ///
    /// Provides direct access to the entire buffer for bulk operations.
    /// Use with caution as this bypasses bounds checking.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.backing {
            OutputBacking::File { mmap, .. } => &mut mmap[..],
            OutputBacking::Memory { data } => &mut data[..],
        }
    }

    /// Grows the output to hold `end` bytes when it holds fewer: the size it was created with
    /// is an estimate, and the bytes past it are zeros until written. It at least doubles, so a
    /// run of writes past the end grows it a few times, not once per write.
    ///
    /// # Errors
    ///
    /// When the file cannot be extended or mapped again.
    fn grow_to(&mut self, end: usize) -> Result<()> {
        let len = self.size();
        if end <= len {
            return Ok(());
        }
        let target = end.max(len.saturating_mul(2));
        match &mut self.backing {
            OutputBacking::Memory { data } => data.resize(target, 0),
            OutputBacking::File { file, mmap, .. } => {
                file.set_len(target as u64)
                    .map_err(|e| Error::MmapFailed(format!("Failed to grow the file: {e}")))?;
                // The new mapping replaces the old one, which no reference outlives (`&mut self`)
                *mmap = map_file(file)?;
            }
        }
        Ok(())
    }

    /// Gets a mutable slice to a specific range of the buffer.
    ///
    /// Provides bounds-checked access to a specific range within the buffer.
    ///
    /// # Arguments
    /// * `start` - Starting byte offset (inclusive)
    /// * `end` - Ending byte offset (exclusive)
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the range is invalid, or if the output cannot grow
    /// to hold it (a range past the end grows it).
    pub fn get_mut_range(&mut self, start: usize, end: usize) -> Result<&mut [u8]> {
        if start > end {
            return Err(Error::MmapFailed(format!(
                "Range start {start} is greater than end {end}"
            )));
        }

        self.grow_to(end)?;
        let len = self.size();
        self.as_mut_slice().get_mut(start..end).ok_or_else(|| {
            Error::LayoutFailed(format!("Range {start}..{end} exceeds buffer of size {len}"))
        })
    }

    /// Gets a mutable slice starting at the given offset with the specified size.
    ///
    /// Convenience method for getting a slice by offset and length rather than start/end.
    ///
    /// # Arguments
    /// * `start` - Starting byte offset
    /// * `size` - Number of bytes to include in the slice
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the range is invalid, or if the output cannot grow
    /// to hold it (a range past the end grows it).
    pub fn get_mut_slice(&mut self, start: usize, size: usize) -> Result<&mut [u8]> {
        let end = start.checked_add(size).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Slice end overflows usize: start={start}, size={size}"
            ))
        })?;
        self.get_mut_range(start, end)
    }

    /// Writes data at a specific offset in the buffer.
    ///
    /// Performs bounds-checked writing of arbitrary data to the specified offset.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the data
    /// * `data` - Byte slice to write
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the output cannot grow to hold the write (a write
    /// past the end grows it).
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| {
            Error::MmapFailed(format!("Offset {offset} too large for target architecture"))
        })?;
        let end = start.checked_add(data.len()).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Write end overflows usize: offset={}, len={}",
                offset,
                data.len()
            ))
        })?;
        self.grow_to(end)?;
        let len = self.size();
        let dest = self.as_mut_slice().get_mut(start..end).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Slice {start}..{end} out of bounds for buffer size {len}"
            ))
        })?;
        dest.copy_from_slice(data);
        Ok(())
    }

    /// Reads data from the buffer at a specific offset.
    ///
    /// This method reads existing data from the buffer, useful for inspecting
    /// values before modifying them (e.g., reading debug directory RVA before clearing).
    ///
    /// # Arguments
    /// * `offset` - Buffer offset to read from
    /// * `buffer` - Buffer to read data into
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the read would exceed buffer bounds.
    pub fn read_at(&self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| {
            Error::MmapFailed(format!("Offset {offset} too large for target architecture"))
        })?;
        let end = start.checked_add(buffer.len()).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Read end overflows usize: offset={}, len={}",
                offset,
                buffer.len()
            ))
        })?;
        let len = self.size();

        if end > len {
            return Err(Error::MmapFailed(format!(
                "Read would exceed buffer size: offset={}, len={}, buffer_size={}",
                offset,
                buffer.len(),
                len
            )));
        }

        let src = self.as_slice().get(start..end).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Slice {start}..{end} out of bounds for buffer size {len}"
            ))
        })?;
        buffer.copy_from_slice(src);
        Ok(())
    }

    /// Copies data from the source offset to the target offset within the same buffer.
    ///
    /// This method provides efficient in-buffer copying for relocating existing content.
    /// It's used extensively during the binary generation process to move sections
    /// and preserve existing data in new locations.
    ///
    /// # Arguments
    /// * `source_offset` - Source offset to copy from
    /// * `target_offset` - Target offset to copy to
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the source range is past the end, or if the
    /// output cannot grow to hold the target range
    /// or if the ranges overlap in a way that would cause data corruption.
    pub fn copy_range(&mut self, source_offset: u64, target_offset: u64, size: u64) -> Result<()> {
        let source_start = usize::try_from(source_offset).map_err(|_| {
            Error::MmapFailed(format!(
                "Source offset {source_offset} too large for target architecture"
            ))
        })?;
        let target_start = usize::try_from(target_offset).map_err(|_| {
            Error::MmapFailed(format!(
                "Target offset {target_offset} too large for target architecture"
            ))
        })?;
        let copy_size = usize::try_from(size).map_err(|_| {
            Error::MmapFailed(format!("Size {size} too large for target architecture"))
        })?;

        let source_end = source_start.checked_add(copy_size).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Source range end overflows usize: start={source_start}, size={copy_size}"
            ))
        })?;
        let target_end = target_start.checked_add(copy_size).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Target range end overflows usize: start={target_start}, size={copy_size}"
            ))
        })?;
        let len = self.size();

        // Validate bounds
        if source_end > len {
            return Err(Error::MmapFailed(format!(
                "Source range would exceed buffer size: {source_start}..{source_end} (buffer size: {len})"
            )));
        }

        self.grow_to(target_end)?;

        // For safety, use copy_within which handles overlapping ranges correctly
        self.as_mut_slice()
            .copy_within(source_start..source_end, target_start);
        Ok(())
    }

    /// Fills a region with zeros.
    ///
    /// Efficient method for zeroing out large regions, commonly used for
    /// clearing old metadata locations after they've been relocated.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset
    /// * `size` - Number of bytes to zero
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the output cannot grow to hold the region.
    pub fn zero_range(&mut self, offset: u64, size: u64) -> Result<()> {
        let start = usize::try_from(offset).map_err(|_| {
            Error::MmapFailed(format!("Offset {offset} too large for target architecture"))
        })?;
        let zero_size = usize::try_from(size).map_err(|_| {
            Error::MmapFailed(format!("Size {size} too large for target architecture"))
        })?;

        let slice = self.get_mut_slice(start, zero_size)?;
        slice.fill(0);
        Ok(())
    }

    /// Writes a single byte at a specific offset.
    ///
    /// Convenience method for writing a single byte value.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the byte
    /// * `byte` - Byte value to write
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the output cannot grow to hold the byte.
    pub fn write_byte_at(&mut self, offset: u64, byte: u8) -> Result<()> {
        let index = usize::try_from(offset).map_err(|_| {
            Error::MmapFailed(format!("Offset {offset} too large for target architecture"))
        })?;
        self.grow_to(index.checked_add(1).ok_or_else(|| {
            Error::LayoutFailed(format!("Byte offset {offset} overflows usize"))
        })?)?;
        let len = self.size();
        let cell = self.as_mut_slice().get_mut(index).ok_or_else(|| {
            Error::LayoutFailed(format!("Index {index} out of bounds for buffer size {len}"))
        })?;
        *cell = byte;
        Ok(())
    }

    /// Writes a little-endian u16 at a specific offset.
    ///
    /// Convenience method for writing 16-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 16-bit value to write in little-endian format
    pub fn write_u16_le_at(&mut self, offset: u64, value: u16) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a little-endian u32 at a specific offset.
    ///
    /// Convenience method for writing 32-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 32-bit value to write in little-endian format
    pub fn write_u32_le_at(&mut self, offset: u64, value: u32) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a little-endian u64 at a specific offset.
    ///
    /// Convenience method for writing 64-bit values in little-endian byte order.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the value
    /// * `value` - 64-bit value to write in little-endian format
    pub fn write_u64_le_at(&mut self, offset: u64, value: u64) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a compressed unsigned integer at the specified offset.
    ///
    /// Uses ECMA-335 compressed integer encoding:
    /// - Values < 0x80: 1 byte
    /// - Values < 0x4000: 2 bytes (with high bit set)
    /// - Larger values: 4 bytes (with high 2 bits set)
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the compressed integer
    /// * `value` - 32-bit value to encode and write
    ///
    /// # Returns
    /// Returns the new offset after writing (offset + bytes_written).
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the output cannot grow to hold the write.
    pub fn write_compressed_uint_at(&mut self, offset: u64, value: u32) -> Result<u64> {
        let mut buffer = Vec::new();
        write_compressed_uint(value, &mut buffer)?;

        self.write_at(offset, &buffer)?;
        offset.checked_add(buffer.len() as u64).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Offset {} + buffer length {} overflows u64",
                offset,
                buffer.len()
            ))
        })
    }

    /// Writes data with automatic 4-byte alignment padding.
    ///
    /// Writes the data at the specified offset and adds 0xFF padding bytes to align
    /// to the next 4-byte boundary. The 0xFF bytes are safe for all heap types as
    /// they create invalid entries that won't be parsed.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where to write the data
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Returns the new aligned offset after writing and padding.
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the write would exceed file bounds.
    pub fn write_aligned_data(&mut self, offset: u64, data: &[u8]) -> Result<u64> {
        // Write the data
        self.write_at(offset, data)?;
        let data_end = offset.checked_add(data.len() as u64).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Offset {} + data length {} overflows u64",
                offset,
                data.len()
            ))
        })?;

        // Calculate padding needed for 4-byte alignment.
        // `data.len() % 4` is in [0, 3]; subtraction from 4 yields [1, 4]; final
        // `% 4` brings it back to [0, 3]. Use checked operations to satisfy lints.
        let rem = data.len() % 4;
        let padding_needed = 4usize.saturating_sub(rem) % 4;

        if padding_needed > 0 {
            // Fill padding with 0xFF bytes to prevent creation of valid heap entries
            let padding_slice = self.get_mut_slice(
                usize::try_from(data_end).map_err(|_| {
                    Error::MmapFailed(format!(
                        "Data end offset {data_end} too large for target architecture"
                    ))
                })?,
                padding_needed,
            )?;
            padding_slice.fill(0xFF);
        }

        data_end.checked_add(padding_needed as u64).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Aligned end overflows u64: data_end={data_end}, padding={padding_needed}"
            ))
        })
    }

    /// Writes data and returns the next position for sequential writing.
    ///
    /// Convenience method that combines writing data with position tracking,
    /// eliminating the common pattern of manual position updates.
    ///
    /// # Arguments
    /// * `position` - Current write position, will be updated to point after the written data
    /// * `data` - Data to write
    ///
    /// # Returns
    /// Returns the new position after writing.
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the write would exceed file bounds.
    pub fn write_and_advance(&mut self, position: &mut usize, data: &[u8]) -> Result<()> {
        let slice = self.get_mut_slice(*position, data.len())?;
        slice.copy_from_slice(data);
        *position = position.checked_add(data.len()).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Position {} + data length {} overflows usize",
                *position,
                data.len()
            ))
        })?;
        Ok(())
    }

    /// Fills a region with the specified byte value.
    ///
    /// Efficient method for filling large regions with a single byte value,
    /// commonly used for padding and zero-initialization.
    ///
    /// # Arguments
    /// * `offset` - Starting byte offset
    /// * `size` - Number of bytes to fill
    /// * `fill_byte` - Byte value to fill with
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the region would exceed file bounds.
    pub fn fill_region(&mut self, offset: u64, size: usize, fill_byte: u8) -> Result<()> {
        let slice = self.get_mut_slice(
            usize::try_from(offset).map_err(|_| {
                Error::MmapFailed(format!("Offset {offset} too large for target architecture"))
            })?,
            size,
        )?;
        slice.fill(fill_byte);
        Ok(())
    }

    /// Adds heap padding to align written data to 4-byte boundary.
    ///
    /// Calculates the padding needed based on the number of bytes written since heap_start
    /// and fills the padding with 0xFF bytes to prevent creation of valid heap entries.
    /// This matches the existing heap padding pattern used throughout the writers.
    ///
    /// # Arguments
    /// * `current_pos` - Current write position after writing heap data
    /// * `heap_start` - Starting position of the heap being written
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the padding would exceed file bounds.
    pub fn add_heap_padding(&mut self, current_pos: usize, heap_start: usize) -> Result<()> {
        let bytes_written = current_pos.checked_sub(heap_start).ok_or_else(|| {
            Error::LayoutFailed(format!(
                "Heap padding called with current_pos={current_pos} < heap_start={heap_start}"
            ))
        })?;
        // `bytes_written % 4` is in [0, 3]; final modulo brings the result to [0, 3].
        let rem = bytes_written % 4;
        let padding_needed = 4usize.saturating_sub(rem) % 4;

        if padding_needed > 0 {
            self.fill_region(current_pos as u64, padding_needed, 0xFF)?;
        }

        Ok(())
    }

    /// Gets the total size of the file.
    ///
    /// Returns the size in bytes of the memory-mapped file as specified during creation.
    #[must_use]
    pub fn size(&self) -> usize {
        match &self.backing {
            OutputBacking::File { mmap, .. } => mmap.len(),
            OutputBacking::Memory { data } => data.len(),
        }
    }

    /// Flushes any pending writes to disk.
    ///
    /// Forces any cached writes in the memory mapping to be written to the underlying file.
    /// This does not guarantee durability until [`crate::cilassembly::writer::output::Output::finalize`] is called.
    ///
    /// # Errors
    /// Returns [`crate::Error::MmapFailed`] if the flush operation fails.
    pub fn flush(&mut self) -> Result<()> {
        match &mut self.backing {
            OutputBacking::File { mmap, .. } => mmap
                .flush()
                .map_err(|e| Error::MmapFailed(format!("Failed to flush memory mapping: {e}"))),
            OutputBacking::Memory { .. } => {
                // No-op for in-memory output
                Ok(())
            }
        }
    }

    /// Finalizes the file-backed output, optionally truncating to a specified size.
    ///
    /// This operation ensures data durability and marks the file as complete:
    /// 1. Flushes the memory mapping to write cached data to disk
    /// 2. Optionally truncates the file to the specified size
    /// 3. Marks the output as finalized to prevent cleanup on drop
    ///
    /// The truncation feature supports the over-allocation pattern: create a file larger
    /// than needed, write content, then shrink to actual size at the end. This avoids
    /// the need for precise size estimation upfront.
    ///
    /// After calling this method, the file is complete and will remain at the target path.
    /// This method can only be called once per [`crate::cilassembly::writer::output::Output`] instance.
    ///
    /// # Arguments
    ///
    /// * `actual_size` - If `Some(size)`, truncate the file to this size before finalizing.
    ///   If `None`, keep the original allocated size.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::FinalizationFailed`] in the following cases:
    /// - Output has already been finalized
    /// - Output is in-memory (use [`into_vec`](Self::into_vec) instead)
    /// - Memory mapping flush fails
    /// - File truncation fails (if size is specified)
    pub fn finalize(mut self, actual_size: Option<u64>) -> Result<()> {
        if self.finalized {
            return Err(Error::FinalizationFailed(
                "Output has already been finalized".to_string(),
            ));
        }

        // Extract the backing to work with it
        let backing = std::mem::replace(
            &mut self.backing,
            OutputBacking::Memory { data: Vec::new() }, // Placeholder
        );

        match backing {
            OutputBacking::File {
                file,
                mmap,
                target_path,
                temp_path,
            } => {
                // Flush memory mapping
                mmap.flush().map_err(|e| {
                    Error::FinalizationFailed(format!("Failed to flush memory mapping: {e}"))
                })?;

                // Release the mapping before touching the file through the filesystem: on
                // Windows a mapped file cannot be renamed.
                drop(mmap);
                drop(file);

                // Truncate if requested
                if let Some(size) = actual_size {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&temp_path)
                        .map_err(|e| {
                            Error::FinalizationFailed(format!(
                                "Failed to reopen file for truncation: {e}"
                            ))
                        })?;

                    file.set_len(size).map_err(|e| {
                        Error::FinalizationFailed(format!(
                            "Failed to truncate file to {size} bytes: {e}"
                        ))
                    })?;
                }

                // Rename into place. This is the only point at which the destination changes,
                // so a failure anywhere earlier leaves the previous artefact untouched.
                std::fs::rename(&temp_path, &target_path).map_err(|e| {
                    // Leave the temp file for inspection only if removing it also fails.
                    let _ = std::fs::remove_file(&temp_path);
                    Error::FinalizationFailed(format!(
                        "Failed to move generated file into place at {}: {e}",
                        target_path.display()
                    ))
                })?;

                // Mark as finalized
                self.finalized = true;
                Ok(())
            }
            OutputBacking::Memory { .. } => Err(Error::FinalizationFailed(
                "Cannot finalize in-memory output to file; use into_vec() instead".to_string(),
            )),
        }
    }

    /// Extracts the data as a `Vec<u8>`, consuming the output.
    ///
    /// This is the finalization method for in-memory outputs. For in-memory outputs,
    /// this is a zero-copy operation that moves the internal Vec. For file-backed
    /// outputs, this copies the data from the mmap.
    ///
    /// # Arguments
    ///
    /// * `actual_size` - If `Some(size)`, truncate to this many bytes.
    ///   If `None`, return the entire buffer.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the output data.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::FinalizationFailed`] in the following cases:
    /// - Output has already been finalized
    /// - Requested size exceeds the allocated buffer size
    ///
    /// # Example
    ///
    /// ```no_run
    /// let mut output = Output::create_in_memory(4096)?;
    /// output.write_at(0, b"MZ")?;
    /// // ... more writes ...
    /// let bytes = output.into_vec(Some(256))?; // Zero-copy, truncated to 256 bytes
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn into_vec(mut self, actual_size: Option<u64>) -> Result<Vec<u8>> {
        if self.finalized {
            return Err(Error::FinalizationFailed(
                "Output has already been finalized".to_string(),
            ));
        }

        // Extract the backing
        let backing = std::mem::replace(
            &mut self.backing,
            OutputBacking::Memory { data: Vec::new() }, // Placeholder
        );

        let mut data = match backing {
            OutputBacking::Memory { data } => {
                // Zero-copy: just move the Vec
                data
            }
            OutputBacking::File { mmap, .. } => {
                // Need to copy from mmap
                mmap[..].to_vec()
            }
        };

        // Truncate if requested
        if let Some(size) = actual_size {
            let size_usize = usize::try_from(size).map_err(|_| {
                Error::FinalizationFailed(format!(
                    "Requested size {size} too large for target architecture"
                ))
            })?;
            if size_usize > data.len() {
                return Err(Error::FinalizationFailed(format!(
                    "Requested size {} exceeds buffer size {}",
                    size_usize,
                    data.len()
                )));
            }
            data.truncate(size_usize);
        }

        // Mark as finalized to prevent cleanup
        self.finalized = true;

        Ok(data)
    }

    /// Gets the target path where the file will be created.
    ///
    /// Returns the final destination path if this is a file-backed output,
    /// or `None` for in-memory outputs.
    pub fn target_path(&self) -> Option<&Path> {
        match &self.backing {
            OutputBacking::File { target_path, .. } => Some(target_path.as_path()),
            OutputBacking::Memory { .. } => None,
        }
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        if !self.finalized {
            // Output was not finalized, so we should clean up
            // First try to flush any pending writes
            let _ = self.flush();

            // For file-backed outputs, delete the incomplete *temporary* file. The target is
            // deliberately left alone: it was never written to, so an abandoned generation
            // leaves whatever was already there intact.
            if let OutputBacking::File { temp_path, .. } = &self.backing {
                let _ = std::fs::remove_file(temp_path);
            }
            // For in-memory outputs, the Vec will be dropped automatically
        }
        // If finalized, the file should remain at the target location (for file-backed)
        // or the data was extracted (for in-memory)
    }
}

/// A sequential writer wrapper around [`Output`] that implements [`std::io::Write`].
///
/// This wrapper provides a position-tracked interface to the memory-mapped output file,
/// allowing the existing `write_to` methods (which use `std::io::Write`) to work directly
/// with the mmap-based output. The wrapper tracks the current write position and advances
/// it after each write operation.
///
/// # Usage
///
/// Create an `OutputWriter` at a specific offset, then use it with any method that
/// accepts `impl Write`:
///
/// ```no_run
/// let mut output = Output::create("output.dll", 4096)?;
/// let mut writer = output.writer_at(0x80); // Start at PE header offset
///
/// // Now use with existing write_to methods
/// coff_header.write_to(&mut writer)?;
/// optional_header.write_to(&mut writer)?;
///
/// // Get final position after writing
/// let end_pos = writer.position();
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// `OutputWriter` is not thread-safe as it holds a mutable reference to the underlying
/// `Output` and maintains internal position state.
pub struct OutputWriter<'a> {
    /// Reference to the underlying output file
    output: &'a mut Output,
    /// Current write position
    position: u64,
}

impl<'a> OutputWriter<'a> {
    /// Creates a new writer starting at the specified offset.
    ///
    /// # Arguments
    ///
    /// * `output` - The output file to write to
    /// * `offset` - The starting position for writes
    pub fn new(output: &'a mut Output, offset: u64) -> Self {
        Self {
            output,
            position: offset,
        }
    }

    /// Returns the current write position.
    ///
    /// This is the offset where the next write will occur.
    #[must_use]
    pub fn position(&self) -> u64 {
        self.position
    }

    /// Sets the current write position.
    ///
    /// # Arguments
    ///
    /// * `position` - The new write position
    pub fn set_position(&mut self, position: u64) {
        self.position = position;
    }

    /// Returns the number of bytes written since the initial offset.
    ///
    /// # Arguments
    ///
    /// * `start_offset` - The offset where writing began
    #[must_use]
    pub fn bytes_written_since(&self, start_offset: u64) -> u64 {
        self.position.saturating_sub(start_offset)
    }
}

impl std::io::Write for OutputWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output
            .write_at(self.position, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.position = self.position.checked_add(buf.len() as u64).ok_or_else(|| {
            std::io::Error::other(format!(
                "Position {} + buffer length {} overflows u64",
                self.position,
                buf.len()
            ))
        })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output
            .flush()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

impl Output {
    /// Creates a sequential writer starting at the specified offset.
    ///
    /// This returns an [`OutputWriter`] that implements [`std::io::Write`], allowing
    /// the existing `write_to` methods to work directly with the mmap-based output.
    ///
    /// # Arguments
    ///
    /// * `offset` - The starting position for writes
    ///
    /// # Example
    ///
    /// ```no_run
    /// let mut output = Output::create("output.dll", 4096)?;
    /// let mut writer = output.writer_at(0x80);
    ///
    /// // Use with write_to methods
    /// coff_header.write_to(&mut writer)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn writer_at(&mut self, offset: u64) -> OutputWriter<'_> {
        OutputWriter::new(self, offset)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::File,
        io::{Read, Write},
    };

    use tempfile::tempdir;

    use super::*;
    use crate::file::pe::DosHeader;

    #[test]
    fn test_mmap_file_creation() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mmap_file = Output::create(&target_path, 1024).unwrap();
        assert_eq!(mmap_file.size(), 1024);
        assert!(!mmap_file.finalized);
    }

    #[test]
    fn test_write_operations() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Test byte write
        mmap_file.write_byte_at(0, 0x42).unwrap();

        // Test u32 write
        mmap_file.write_u32_le_at(4, 0x12345678).unwrap();

        // Test slice write
        mmap_file.write_at(8, b"Hello, World!").unwrap();

        // Verify the data
        let slice = mmap_file.as_mut_slice();
        assert_eq!(slice[0], 0x42);
        assert_eq!(&slice[4..8], &[0x78, 0x56, 0x34, 0x12]); // Little endian
        assert_eq!(&slice[8..21], b"Hello, World!");
    }

    #[test]
    fn test_copy_range() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Write some data
        mmap_file.write_at(0, b"Hello, World!").unwrap();

        // Copy it to another location
        mmap_file.copy_range(0, 100, 13).unwrap();

        // Verify the copy
        let slice = mmap_file.as_mut_slice();
        assert_eq!(&slice[100..113], b"Hello, World!");
    }

    #[test]
    fn test_zero_range() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 1024).unwrap();

        // Write some data
        mmap_file.write_at(0, b"Hello, World!").unwrap();

        // Zero part of it
        mmap_file.zero_range(5, 5).unwrap();

        // Verify the zeroing
        let slice = mmap_file.as_mut_slice();
        assert_eq!(&slice[0..5], b"Hello");
        assert_eq!(&slice[5..10], &[0, 0, 0, 0, 0]);
        assert_eq!(&slice[10..13], b"ld!");
    }

    #[test]
    fn test_finalization() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        {
            let mut mmap_file = Output::create(&target_path, 16).unwrap();
            mmap_file.write_at(0, b"Test content").unwrap();
            mmap_file.finalize(None).unwrap();
        }

        // Verify the file was created and contains the expected data
        assert!(target_path.exists());

        let mut file = File::open(&target_path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        assert_eq!(&contents[0..12], b"Test content");
    }

    #[test]
    fn test_bounds_checking() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut mmap_file = Output::create(&target_path, 10).unwrap();

        // A read past the end fails: nothing was written there
        let mut buffer = [0u8; 4];
        assert!(mmap_file.read_at(8, &mut buffer).is_err());
        // A copy from past the end fails the same way
        assert!(mmap_file.copy_range(8, 0, 4).is_err());
    }

    #[test]
    fn test_output_writer() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&target_path, 1024).unwrap();

        // Test OutputWriter with std::io::Write
        {
            let mut writer = output.writer_at(0x10);
            assert_eq!(writer.position(), 0x10);

            // Write some data
            writer.write_all(b"Hello").unwrap();
            assert_eq!(writer.position(), 0x15);

            writer.write_all(b", World!").unwrap();
            assert_eq!(writer.position(), 0x1D);

            // Test bytes_written_since
            assert_eq!(writer.bytes_written_since(0x10), 0x0D); // 13 bytes
        }

        // Verify the data was written correctly
        let slice = output.as_mut_slice();
        assert_eq!(&slice[0x10..0x1D], b"Hello, World!");
    }

    #[test]
    fn test_output_writer_with_pe_header() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let mut output = Output::create(&target_path, 1024).unwrap();

        // Write standard DOS header using OutputWriter
        {
            let mut writer = output.writer_at(0);
            DosHeader::write_standard(&mut writer).unwrap();
            assert_eq!(writer.position(), 128); // DOS header + stub = 128 bytes
        }

        // Verify the DOS header signature
        let slice = output.as_mut_slice();
        assert_eq!(slice[0], 0x4D); // 'M'
        assert_eq!(slice[1], 0x5A); // 'Z'
                                    // Verify e_lfanew field at offset 0x3C points to 0x80
        assert_eq!(&slice[0x3C..0x40], &[0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_finalize_with_truncation() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("truncate_test.bin");

        // Create over-allocated file
        let initial_size = 1024 * 1024; // 1MB
        let actual_content_size = 100u64;

        {
            let mut output = Output::create(&target_path, initial_size).unwrap();

            // Write only 100 bytes of content
            output.write_at(0, &[0x42u8; 100]).unwrap();

            // Finalize with truncation to actual size
            output.finalize(Some(actual_content_size)).unwrap();
        }

        // Verify file was truncated to actual size
        let metadata = std::fs::metadata(&target_path).unwrap();
        assert_eq!(metadata.len(), actual_content_size);

        // Verify content is intact
        let mut file = File::open(&target_path).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();
        assert_eq!(contents.len(), 100);
        assert!(contents.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn test_finalize_without_truncation() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("no_truncate_test.bin");

        let initial_size = 1024u64;

        {
            let mut output = Output::create(&target_path, initial_size).unwrap();
            output.write_at(0, b"Hello").unwrap();

            // Finalize without truncation (None)
            output.finalize(None).unwrap();
        }

        // Verify file keeps original size
        let metadata = std::fs::metadata(&target_path).unwrap();
        assert_eq!(metadata.len(), initial_size);
    }

    /// A write past the size the output was created with grows it, keeping what was written,
    /// in memory and in a file: the size is the writer's estimate, which a change set can
    /// exceed (a thousand methods added to a small assembly did).
    #[test]
    fn a_write_past_the_end_grows_the_output() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("grown.bin");
        for mut output in [
            Output::create_in_memory(8).unwrap(),
            Output::create(&target_path, 8).unwrap(),
        ] {
            output.write_at(0, b"head").unwrap();
            output.write_at(100, b"tail").unwrap();
            output.write_byte_at(200, 0x42).unwrap();
            output.fill_region(300, 4, 0xFF).unwrap();
            output.copy_range(0, 400, 4).unwrap();
            assert!(output.size() >= 404);
            let mut read = [0u8; 4];
            for (offset, expected) in [(0, b"head"), (100, b"tail"), (400, b"head")] {
                output.read_at(offset, &mut read).unwrap();
                assert_eq!(&read, expected);
            }
            output.read_at(50, &mut read).unwrap();
            assert_eq!(read, [0; 4], "the bytes between writes are zeros");
            if output.is_in_memory() {
                assert_eq!(output.into_vec(Some(404)).unwrap().len(), 404);
            } else {
                output.finalize(Some(404)).unwrap();
                let written = std::fs::read(&target_path).unwrap();
                assert_eq!((written.len(), &written[100..104]), (404, &b"tail"[..]));
            }
        }
    }

    #[test]
    fn test_create_in_memory() {
        let output = Output::create_in_memory(1024).unwrap();
        assert_eq!(output.size(), 1024);
        assert!(output.is_in_memory());
        assert!(output.target_path().is_none());
        assert!(!output.finalized);
    }

    #[test]
    fn test_in_memory_write_operations() {
        let mut output = Output::create_in_memory(1024).unwrap();

        // Test byte write
        output.write_byte_at(0, 0x4D).unwrap(); // 'M'
        output.write_byte_at(1, 0x5A).unwrap(); // 'Z'

        // Test u32 write
        output.write_u32_le_at(4, 0xDEADBEEF).unwrap();

        // Test slice write
        output.write_at(8, b"Hello, Memory!").unwrap();

        // Verify the data
        let slice = output.as_slice();
        assert_eq!(slice[0], 0x4D);
        assert_eq!(slice[1], 0x5A);
        assert_eq!(&slice[4..8], &[0xEF, 0xBE, 0xAD, 0xDE]); // Little endian
        assert_eq!(&slice[8..22], b"Hello, Memory!");
    }

    #[test]
    fn test_into_vec_basic() {
        let mut output = Output::create_in_memory(1024).unwrap();

        // Write some data
        output.write_at(0, b"Test data").unwrap();

        // Extract to vec (full buffer)
        let data = output.into_vec(None).unwrap();
        assert_eq!(data.len(), 1024);
        assert_eq!(&data[0..9], b"Test data");
    }

    #[test]
    fn test_into_vec_with_truncation() {
        let mut output = Output::create_in_memory(1024).unwrap();

        // Write some data
        output.write_at(0, b"Test data here").unwrap();

        // Extract only first 14 bytes (actual content size)
        let data = output.into_vec(Some(14)).unwrap();
        assert_eq!(data.len(), 14);
        assert_eq!(&data, b"Test data here");
    }

    #[test]
    fn test_into_vec_size_validation() {
        let output = Output::create_in_memory(100).unwrap();

        // Try to extract more than allocated - should fail
        let result = output.into_vec(Some(200));
        assert!(result.is_err());
    }

    #[test]
    fn test_in_memory_finalize_fails() {
        let output = Output::create_in_memory(1024).unwrap();

        // Calling finalize() on in-memory output should fail
        let result = output.finalize(None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("in-memory output"));
    }

    #[test]
    fn test_file_backed_is_not_in_memory() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.bin");

        let output = Output::create(&target_path, 1024).unwrap();
        assert!(!output.is_in_memory());
        assert!(output.target_path().is_some());
        assert_eq!(output.target_path().unwrap(), target_path);
    }

    #[test]
    fn test_in_memory_copy_range() {
        let mut output = Output::create_in_memory(256).unwrap();

        // Write some data
        output.write_at(0, b"Source Data").unwrap();

        // Copy it to another location
        output.copy_range(0, 100, 11).unwrap();

        // Verify both locations have the data
        let slice = output.as_slice();
        assert_eq!(&slice[0..11], b"Source Data");
        assert_eq!(&slice[100..111], b"Source Data");
    }

    #[test]
    fn test_in_memory_zero_range() {
        let mut output = Output::create_in_memory(64).unwrap();

        // Fill with non-zero data
        output.fill_region(0, 32, 0xFF).unwrap();

        // Zero a range
        output.zero_range(8, 8).unwrap();

        // Verify
        let slice = output.as_slice();
        assert!(slice[0..8].iter().all(|&b| b == 0xFF));
        assert!(slice[8..16].iter().all(|&b| b == 0x00));
        assert!(slice[16..32].iter().all(|&b| b == 0xFF));
    }
}
