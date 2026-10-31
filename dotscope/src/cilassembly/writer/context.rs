//! Write context for streaming PE file generation.
//!
//! This module provides [`WriteContext`], a unified context that carries all state
//! needed during PE file generation. It replaces the previous `Layout` struct with
//! a streaming approach where values are collected during writing and fixups are
//! applied at the end.
//!
//! # Architecture
//!
//! The generation process has three phases:
//!
//! 1. **Initialize**: Create context with assembly reference and output
//! 2. **Write**: Stream all content sequentially, tracking positions
//! 3. **Fixup**: Patch headers with final values (sizes, RVAs, checksum)
//!
//! # Example
//!
//! ```no_run
//! let mut ctx = WriteContext::new(assembly, output)?;
//!
//! // Write all content - ctx tracks positions
//! ctx.write_dos_header()?;
//! ctx.write_pe_headers()?;
//! ctx.write_sections()?;
//!
//! // Apply fixups and finalize
//! ctx.apply_fixups()?;
//! ctx.finalize()?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::collections::{HashMap, HashSet};

use crate::{
    cilassembly::{
        changes::AssemblyChanges,
        writer::{blobs::TypedBlob, heaps::HeapRemapping, output::Output, remapper::TokenRemap},
        CilAssembly,
    },
    file::pe::{OptionalHeader, SectionTable},
    prelude::NativeImports,
    CilAssemblyView, Error, Result,
};

/// Alignment constants
pub const FILE_ALIGNMENT_DEFAULT: u32 = 0x200;
pub const SECTION_ALIGNMENT_DEFAULT: u32 = 0x2000;

/// PE header sizes
pub const DOS_HEADER_SIZE: u64 = 128;
pub const PE_SIGNATURE_SIZE: u64 = 4;
pub const COFF_HEADER_SIZE: u64 = 20;
pub const SECTION_HEADER_SIZE: u64 = 40;

/// Information about a section being written.
///
/// Tracks both the header location and the data written for each section,
/// indexed by the original section order in the PE file.
#[derive(Debug, Clone, Default)]
pub struct SectionWriteInfo {
    /// Original section name (e.g., ".text", ".rsrc", ".reloc")
    pub name: String,
    /// Original section characteristics
    pub characteristics: u32,
    /// File offset where this section's header was written
    pub header_offset: u64,
    /// File offset where this section's data was written (None if not yet written)
    pub data_offset: Option<u64>,
    /// RVA assigned to this section's data
    pub rva: Option<u32>,
    /// The section's extent in address space — its `VirtualSize`, and what the next section's
    /// RVA is placed after.
    ///
    /// For sections the writer regenerates (`.text`) this is the generated size. For sections
    /// copied verbatim it is the input's `VirtualSize`, which may differ from the number of
    /// bytes on disk in either direction.
    pub data_size: Option<u32>,
    /// Number of bytes actually written to the file for this section.
    ///
    /// The source of truth for `SizeOfRawData`, which is otherwise derived from
    /// [`data_size`](Self::data_size) — a different quantity. A section carrying uninitialised
    /// data has `VirtualSize > SizeOfRawData`, so deriving one from the other emits a header
    /// describing an extent that does not match the bytes present.
    ///
    /// Must not be conflated with `data_size`: that value also drives RVA placement, and
    /// shrinking it to the written length overlaps the following section.
    pub raw_size: Option<u32>,
    /// Whether this section should be removed (header zeroed, count decremented)
    pub removed: bool,
}

/// Unified write context for PE file generation.
///
/// This struct carries all state needed during PE file generation, using a streaming
/// approach where content is written sequentially and forward-referenced values are
/// patched via fixups at the end.
///
/// # Overview
///
/// The context tracks:
/// - **Source references**: Assembly and changes being written
/// - **Output state**: Memory-mapped file and current write position
/// - **PE format info**: Alignment values, image base, PE32/PE32+ format
/// - **Header positions**: File offsets for fixup patching after write
/// - **Section tracking**: Dynamic section info collected during write
/// - **Metadata positions**: Heap and stream offsets for CLR metadata
/// - **Native import/export**: Optional P/Invoke and native export data
/// - **Remapping tables**: Method RVA and heap offset translations
///
/// # Lifecycle
///
/// 1. **Construction**: [`WriteContext::new`] initializes from source assembly
/// 2. **Write phase**: Generator writes content, context tracks positions
/// 3. **Fixup phase**: Headers patched with collected values
/// 4. **Finalization**: Output truncated to actual size, checksum written
///
/// # Section Tracking
///
/// The `sections` vector is populated during section table writing and updated
/// as each section's data is written. This allows proper handling of:
/// - Variable section ordering (not all PEs have sections in the same order)
/// - Section removal (e.g., filtered .reloc sections)
/// - Section table rebuilding during fixup
pub struct WriteContext<'a> {
    /// Reference to the assembly being written. Provides access to original metadata,
    /// method bodies, and PE structure for copying unchanged content.
    pub assembly: &'a CilAssembly,

    /// Assembly changes to apply during generation. Contains table modifications,
    /// new heap entries, and method body updates.
    pub changes: &'a AssemblyChanges,

    /// Memory-mapped output file. Provides random-access writes for both streaming
    /// content and fixup patching.
    pub output: Output,

    /// Current sequential write position in the file. Advanced by [`write`](Self::write)
    /// and alignment methods. Used for streaming content.
    pub position: u64,

    /// PE format flag. True for PE32+ (64-bit), false for PE32 (32-bit).
    /// Affects optional header size and address field widths.
    pub is_pe32_plus: bool,

    /// File alignment for section data (typically 0x200 = 512 bytes).
    /// Section raw data must start at file offsets aligned to this value.
    pub file_alignment: u32,

    /// Section alignment for RVAs (typically 0x2000 = 8KB).
    /// Section virtual addresses must be aligned to this value.
    pub section_alignment: u32,

    /// Preferred load address for the image. Used for relocation calculations.
    pub image_base: u64,

    /// File offset where DOS header was written (always 0).
    pub dos_header_offset: u64,

    /// File offset of PE signature ("PE\0\0"). Stored for e_lfanew fixup.
    pub pe_signature_offset: u64,

    /// File offset of COFF header. Used to patch section count during fixup.
    pub coff_header_offset: u64,

    /// File offset of Optional header. Used to patch sizes, checksum, and data directories.
    pub optional_header_offset: u64,

    /// File offset of section table (array of section headers).
    pub section_table_offset: u64,

    /// Original number of sections from source PE. May differ from final count
    /// if sections are removed during generation.
    pub section_count: u16,

    /// Section write information indexed by original section order.
    /// Populated during `write_section_table`, updated as section data is written.
    /// Used during fixup to rebuild section table with correct values.
    pub sections: Vec<SectionWriteInfo>,

    /// File offset where .text section data begins.
    pub text_section_offset: u64,

    /// RVA of .text section (typically section_alignment, e.g., 0x2000).
    pub text_section_rva: u32,

    /// Total size of .text section content (before file alignment).
    pub text_section_size: u64,

    /// File offset of Import Address Table within .text section.
    pub iat_offset: u64,

    /// Size of Import Address Table in bytes.
    /// This is dynamic based on the number of imports.
    pub iat_size: u64,

    /// File offset of COR20 (CLR) header within .text section.
    pub cor20_header_offset: u64,

    /// File offset where method bodies region starts.
    pub method_bodies_offset: u64,

    /// Total size of method bodies region.
    pub method_bodies_size: u64,

    /// File offset where CLR resources section starts.
    /// This is the section pointed to by COR20 header's resource_rva/resource_size.
    pub resource_data_offset: u64,

    /// Total size of CLR resources section in bytes.
    pub resource_data_size: u64,

    /// File offset of metadata root header.
    pub metadata_offset: u64,

    /// Total size of metadata (all streams).
    pub metadata_size: u64,

    /// File offset where #~ (tables) stream data begins.
    pub tables_stream_offset: u64,
    /// Size of #~ (tables) stream in bytes.
    pub tables_stream_size: u64,

    /// File offset where #Strings heap data begins.
    pub strings_heap_offset: u64,
    /// Size of #Strings heap in bytes.
    pub strings_heap_size: u64,

    /// File offset where #US (user strings) heap data begins.
    pub us_heap_offset: u64,
    /// Size of #US (user strings) heap in bytes.
    pub us_heap_size: u64,

    /// File offset where #GUID heap data begins.
    pub guid_heap_offset: u64,
    /// Size of #GUID heap in bytes (always multiple of 16).
    pub guid_heap_size: u64,

    /// File offset where #Blob heap data begins.
    pub blob_heap_offset: u64,
    /// Size of #Blob heap in bytes.
    pub blob_heap_size: u64,

    /// File offset of native import table data.
    pub import_data_offset: Option<u64>,
    /// RVA of native import table.
    pub import_data_rva: Option<u32>,

    /// Byte sizes of the heaps as they will be emitted: `(#Strings, #GUID, #Blob)`.
    ///
    /// Recorded by the heap pre-pass so the tables stream can declare heap index widths that
    /// match the heaps actually written. ECMA-335 II.24.2.6 selects a 4-byte index once a heap
    /// exceeds 0xFFFF; inheriting the input's `HeapSizes` byte instead silently truncates every
    /// offset past that point once the writer appends enough.
    pub output_heap_sizes: Option<(usize, usize, usize)>,
    /// Size of native import table in bytes.
    pub import_data_size: Option<u32>,

    /// Pending imports built during IAT writing, used for import table generation.
    /// Contains mscoree.dll (first) + any additional native imports.
    pub pending_imports: Option<NativeImports>,

    /// RVA of native entry point stub (jmp to IAT).
    /// This is the AddressOfEntryPoint for the PE file.
    pub native_entry_rva: Option<u32>,

    /// File offset of native export table data.
    pub export_data_offset: Option<u64>,
    /// RVA of native export table.
    pub export_data_rva: Option<u32>,
    /// Size of native export table in bytes.
    pub export_data_size: Option<u32>,
    /// Serialized export table bytes for mixed-mode assemblies with native exports.
    pub export_table_bytes: Option<Vec<u8>>,

    /// Original debug directory location (RVA, size). A write that changes nothing copies
    /// the directory and its data; any other write drops them, since the debug data no
    /// longer describes the code.
    pub original_debug_dir: Option<(u32, u32)>,

    /// Where the copied debug directory sits in the output (RVA, size), when it was kept.
    pub debug_dir: Option<(u32, u32)>,

    /// Original certificate directory location (file offset, size). Certificates
    /// are invalidated by any modification. Unlike other directories, this uses
    /// a file offset rather than RVA.
    pub original_certificate_dir: Option<(u32, u32)>,

    /// File offset where embedded PE resources were written in the new .text section.
    /// Some assemblies (e.g., WindowsBase.dll) embed Win32 PE resources directly in
    /// .text rather than in a separate .rsrc section. When rewriting .text, these
    /// must be carried over and the Resource data directory updated.
    pub pe_resource_offset: u64,

    /// Size of embedded PE resource data written to .text (0 if none).
    pub pe_resource_size: u32,

    /// Mapping from placeholder method RVAs to actual RVAs. During table writing,
    /// method RVAs are written as placeholders. After method bodies are written,
    /// this map is used to patch the correct RVAs.
    pub method_body_rva_map: HashMap<u32, u32>,

    /// Mapping from placeholder field data RVAs to actual RVAs. Field initialization
    /// data (from FieldRVA table) is written to a data section, and this map is used
    /// to patch the correct RVAs in the FieldRVA table.
    pub field_data_rva_map: HashMap<u32, u32>,

    /// Delta to add to original method RVAs when the method body section moves.
    /// Original methods keep their relative positions but the section base may shift.
    pub original_method_rva_delta: i32,

    /// Mapping from original ManifestResource offset_field values to new offsets
    /// after resource data compaction. When ManifestResource rows are deleted,
    /// the resource data section is compacted and surviving entries get new offsets.
    pub resource_offset_remap: HashMap<u32, u32>,

    /// Heap offset remapping from streaming writes. When heaps are written with
    /// deduplication, original offsets map to new offsets. Used to patch table
    /// rows that reference heap entries.
    pub heap_remapping: HeapRemapping,

    /// How the tokens outside the tables (instruction operands, local signatures, catch
    /// types, the entry point) are renumbered once rows are deleted or deduplicated.
    pub tokens: TokenRemap,

    /// The blobs whose content names rows or blobs (signatures, and the Portable PDB blobs),
    /// by the index the blob heap writer meets them at: the rows they name are renumbered
    /// with [`tokens`](Self::tokens), and the blobs they name follow the rebuilt heap.
    pub typed_blobs: HashMap<u32, TypedBlob>,

    /// Every `#Strings` offset a row of the written tables names, an offset inside another
    /// string's bytes (a shared tail) among them: the heap writer keeps each one pointing at
    /// the same string when the heap is rebuilt.
    pub referenced_string_offsets: HashSet<u32>,

    /// Every `#Blob` offset a row of the written tables names: the heap writer writes each one
    /// that is not an entry of the heap's own walk (an offset inside another blob) as an entry
    /// of its own, so it keeps naming the same bytes.
    pub referenced_blob_offsets: HashSet<u32>,

    /// Every `#US` offset an `ldstr` of a written body names, kept the same way.
    pub referenced_userstring_offsets: HashSet<u32>,

    /// StandAloneSig RIDs to skip during table writing (duplicates).
    /// When multiple StandAloneSig entries have identical blob content,
    /// only one is kept and the rest are added here.
    pub standalonesig_skip: HashSet<u32>,

    /// Entry point method token from COR20 header.
    pub entry_point_token: u32,

    /// Total bytes written to output. Used for final file truncation since the
    /// memory-mapped file is over-allocated.
    pub bytes_written: u64,

    /// Placeholder fixups for heap references added via ChangeRef. After heaps
    /// are written, these locations are patched with resolved offsets.
    pub placeholder_fixups: Vec<PlaceholderFixup>,

    /// Whether IMAGE_FILE_RELOCS_STRIPPED should be set in COFF characteristics.
    /// True for x64 IL-only EXEs that need no relocations.
    pub relocs_stripped: bool,
}

/// A placeholder fixup that needs to be applied after heaps are written.
#[derive(Debug, Clone)]
pub struct PlaceholderFixup {
    /// File offset where the field was written.
    pub file_offset: u64,
    /// Size of the field (2 or 4 bytes).
    pub field_size: usize,
    /// The original placeholder value (full 32-bit, used to look up ChangeRef).
    pub placeholder_value: u32,
}

/// Information needed to copy an original section to output.
#[derive(Debug, Clone)]
pub struct SectionCopyInfo {
    /// Original file offset (pointer_to_raw_data).
    pub source_offset: u32,
    /// Original size on disk (size_of_raw_data).
    pub source_size: u32,
    /// Original virtual address.
    pub source_rva: u32,
    /// Original virtual size.
    pub source_virtual_size: u32,
    /// Section characteristics.
    pub characteristics: u32,
}

impl SectionCopyInfo {
    /// Creates copy info from a section table entry.
    ///
    /// # Arguments
    ///
    /// * `section` - The source section table entry
    ///
    /// # Returns
    ///
    /// A new `SectionCopyInfo` with all values copied from the section.
    pub fn from_section(section: &SectionTable) -> Self {
        Self {
            source_offset: section.pointer_to_raw_data,
            source_size: section.size_of_raw_data,
            source_rva: section.virtual_address,
            source_virtual_size: section.virtual_size,
            characteristics: section.characteristics,
        }
    }
}

impl<'a> WriteContext<'a> {
    /// Creates a new write context for the given assembly.
    ///
    /// This initializes the context with information from the source assembly
    /// and prepares for sequential writing.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly being written
    /// * `changes` - The assembly changes to apply
    /// * `output` - The memory-mapped output file
    ///
    /// # Returns
    ///
    /// A new `WriteContext` initialized with PE format info from the source assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly has no optional header.
    pub fn new(
        assembly: &'a CilAssembly,
        changes: &'a AssemblyChanges,
        output: Output,
    ) -> Result<Self> {
        let view = assembly.view();
        let file = view.file();

        // Get PE format info from original assembly
        let optional_header = file
            .header_optional()
            .as_ref()
            .ok_or_else(|| Error::LayoutFailed("Assembly has no optional header".to_string()))?;

        let is_pe32_plus = optional_header.standard_fields.magic == 0x20b;
        let file_alignment = optional_header.windows_fields.file_alignment;
        let section_alignment = optional_header.windows_fields.section_alignment;
        let image_base = optional_header.windows_fields.image_base;

        // Get original section count from COFF header
        let section_count = file.header().number_of_sections;

        // Entry point token from COR20 header
        let entry_point_token = view.cor20header().entry_point_token;

        Ok(Self {
            assembly,
            changes,
            output,
            position: 0,

            is_pe32_plus,
            file_alignment,
            section_alignment,
            image_base,

            // These will be set during write
            dos_header_offset: 0,
            pe_signature_offset: 0,
            coff_header_offset: 0,
            optional_header_offset: 0,
            section_table_offset: 0,

            section_count,
            sections: Vec::new(),

            text_section_offset: 0,
            text_section_rva: section_alignment,
            text_section_size: 0,

            iat_offset: 0,
            iat_size: 0,
            cor20_header_offset: 0,
            method_bodies_offset: 0,
            method_bodies_size: 0,
            resource_data_offset: 0,
            resource_data_size: 0,
            metadata_offset: 0,
            metadata_size: 0,

            tables_stream_offset: 0,
            tables_stream_size: 0,
            strings_heap_offset: 0,
            strings_heap_size: 0,
            us_heap_offset: 0,
            us_heap_size: 0,
            guid_heap_offset: 0,
            guid_heap_size: 0,
            blob_heap_offset: 0,
            blob_heap_size: 0,

            import_data_offset: None,
            import_data_rva: None,
            output_heap_sizes: None,
            import_data_size: None,
            pending_imports: None,
            native_entry_rva: None,

            export_data_offset: None,
            export_data_rva: None,
            export_data_size: None,
            export_table_bytes: None,

            original_debug_dir: None,
            debug_dir: None,
            original_certificate_dir: None,
            pe_resource_offset: 0,
            pe_resource_size: 0,

            method_body_rva_map: HashMap::new(),
            field_data_rva_map: HashMap::new(),
            original_method_rva_delta: 0,
            resource_offset_remap: HashMap::new(),
            heap_remapping: HeapRemapping::default(),
            tokens: TokenRemap::default(),
            typed_blobs: HashMap::new(),
            referenced_string_offsets: HashSet::new(),
            referenced_blob_offsets: HashSet::new(),
            referenced_userstring_offsets: HashSet::new(),
            standalonesig_skip: HashSet::new(),

            entry_point_token,
            bytes_written: 0,
            placeholder_fixups: Vec::new(),
            relocs_stripped: false,
        })
    }

    /// Returns the current write position.
    ///
    /// # Returns
    ///
    /// The current file offset position.
    pub fn pos(&self) -> u64 {
        self.position
    }

    /// Advances the position by the given amount.
    ///
    /// Also updates `bytes_written` if the new position exceeds it.
    ///
    /// # Arguments
    ///
    /// * `amount` - The number of bytes to advance
    pub fn advance(&mut self, amount: u64) {
        self.position = self.position.saturating_add(amount);
        if self.position > self.bytes_written {
            self.bytes_written = self.position;
        }
    }

    /// Aligns the current position to the given boundary.
    ///
    /// Note: This only advances the position; it does not write any padding bytes.
    /// Use [`align_to_with_padding`](Self::align_to_with_padding) to also write zeros.
    ///
    /// # Arguments
    ///
    /// * `alignment` - The alignment boundary (must be a power of 2)
    pub fn align_to(&mut self, alignment: u64) {
        let Some(remainder) = self.position.checked_rem(alignment) else {
            return;
        };
        if remainder != 0 {
            let padding = alignment.saturating_sub(remainder);
            self.position = self.position.saturating_add(padding);
        }
    }

    /// Aligns to file alignment (typically 0x200) and writes zero padding.
    ///
    /// This ensures the file contains actual padding bytes to match
    /// the section's declared `SizeOfRawData` in the PE header.
    pub fn align_to_file(&mut self) -> Result<()> {
        self.align_to_with_padding(u64::from(self.file_alignment))
    }

    /// Aligns to 4-byte boundary.
    pub fn align_to_4(&mut self) {
        self.align_to(4);
    }

    /// Aligns to the given boundary and writes zero padding.
    ///
    /// Unlike [`align_to`](Self::align_to) which only advances the position, this method
    /// actually writes zeros to fill the gap. This is important for heaps
    /// where the metadata reports aligned sizes.
    ///
    /// # Arguments
    ///
    /// * `alignment` - The alignment boundary (must be a power of 2)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the padding bytes fails.
    pub fn align_to_with_padding(&mut self, alignment: u64) -> Result<()> {
        let Some(remainder) = self.position.checked_rem(alignment) else {
            return Ok(());
        };
        if remainder != 0 {
            let padding = alignment.checked_sub(remainder).ok_or_else(|| {
                Error::LayoutFailed("Alignment underflow computing padding".to_string())
            })?;
            // Safety: padding is always < alignment, and alignment is typically 4, 8, or 512
            // so this will never exceed usize range
            let padding_usize = usize::try_from(padding).map_err(|_| {
                Error::LayoutFailed(format!("Padding {padding} exceeds usize range"))
            })?;
            let zeros = vec![0u8; padding_usize];
            self.write(&zeros)?;
        }
        Ok(())
    }

    /// Aligns to 4-byte boundary and writes zero padding.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing the padding bytes fails.
    pub fn align_to_4_with_padding(&mut self) -> Result<()> {
        self.align_to_with_padding(4)
    }

    /// Writes bytes at the current position and advances.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes to write
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        self.output.write_at(self.position, data)?;
        self.advance(data.len() as u64);
        Ok(())
    }

    /// Writes bytes at a specific offset (for fixups), doesn't change position.
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to write at
    /// * `data` - The bytes to write
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        self.output.write_at(offset, data)?;
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(|| Error::LayoutFailed("write_at end offset overflow".to_string()))?;
        if end > self.bytes_written {
            self.bytes_written = end;
        }
        Ok(())
    }

    /// Writes a u16 at a specific offset (little-endian).
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to write at
    /// * `value` - The value to write
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_u16_at(&mut self, offset: u64, value: u16) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a u32 at a specific offset (little-endian).
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to write at
    /// * `value` - The value to write
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_u32_at(&mut self, offset: u64, value: u32) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a u64 at a specific offset (little-endian).
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to write at
    /// * `value` - The value to write
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_u64_at(&mut self, offset: u64, value: u64) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Calculates the RVA for a file offset within .text section.
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to convert
    ///
    /// # Returns
    ///
    /// The corresponding RVA, or 0 if the offset is before the .text section.
    pub fn offset_to_rva(&self, offset: u64) -> u32 {
        if offset >= self.text_section_offset {
            // In practice, PE files have sections well under 4GB, so this conversion is safe.
            // If the offset difference somehow exceeds u32, we saturate to avoid panic.
            let diff = offset.saturating_sub(self.text_section_offset);
            let diff_u32 = u32::try_from(diff).unwrap_or(u32::MAX);
            self.text_section_rva.saturating_add(diff_u32)
        } else {
            0
        }
    }

    /// Returns the current position as an RVA (within .text section).
    ///
    /// # Returns
    ///
    /// The RVA corresponding to the current write position.
    pub fn current_rva(&self) -> u32 {
        self.offset_to_rva(self.position)
    }

    /// Returns the assembly view.
    ///
    /// # Returns
    ///
    /// A reference to the underlying [`CilAssemblyView`].
    pub fn view(&self) -> &CilAssemblyView {
        self.assembly.view()
    }

    /// Returns the optional header size for this format.
    ///
    /// # Returns
    ///
    /// The size in bytes (224 for PE32, 240 for PE32+).
    pub fn optional_header_size(&self) -> u64 {
        OptionalHeader::size_for_format(self.is_pe32_plus) as u64
    }

    /// Finds the index of a section by name prefix.
    ///
    /// # Arguments
    ///
    /// * `name_prefix` - The prefix to match (e.g., ".text", ".rsrc")
    ///
    /// # Returns
    ///
    /// The index of the first matching section, or None if not found.
    pub fn find_section_index(&self, name_prefix: &str) -> Option<usize> {
        self.sections
            .iter()
            .position(|s| s.name.starts_with(name_prefix))
    }

    /// Updates a section's write info by index.
    ///
    /// # Arguments
    ///
    /// * `index` - The section index
    /// * `data_offset` - File offset where section data was written
    /// * `rva` - RVA assigned to the section
    /// * `data_size` - Size of data written
    pub fn update_section(
        &mut self,
        index: usize,
        data_offset: u64,
        rva: u32,
        data_size: u32,
        raw_size: u32,
    ) {
        if let Some(section) = self.sections.get_mut(index) {
            section.data_offset = Some(data_offset);
            section.rva = Some(rva);
            section.data_size = Some(data_size);
            section.raw_size = Some(raw_size);
        }
    }

    /// Marks a section as removed by index.
    ///
    /// The section header will be zeroed and section count decremented during fixup.
    pub fn mark_section_removed(&mut self, index: usize) {
        if let Some(section) = self.sections.get_mut(index) {
            section.removed = true;
        }
    }

    /// Returns the number of sections that are not marked as removed.
    pub fn active_section_count(&self) -> u16 {
        self.sections
            .iter()
            .filter(|s| !s.removed)
            .count()
            .try_into()
            .unwrap_or(0)
    }
}

impl std::io::Write for WriteContext<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output
            .write_at(self.position, buf)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.advance(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output
            .flush()
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        cilassembly::writer::{context::SectionCopyInfo, heaps::HeapRemapping},
        file::pe::SectionTable,
    };

    #[test]
    fn test_heap_remapping_has_changes() {
        let mut remapping = HeapRemapping::default();
        assert!(!remapping.has_changes());

        remapping.strings.insert(1, 2);
        assert!(remapping.has_changes());
    }

    #[test]
    fn test_section_copy_info() {
        let section = SectionTable {
            name: ".rsrc".to_string(),
            virtual_size: 0x1000,
            virtual_address: 0x4000,
            size_of_raw_data: 0x1000,
            pointer_to_raw_data: 0x2000,
            pointer_to_relocations: 0,
            pointer_to_line_numbers: 0,
            number_of_relocations: 0,
            number_of_line_numbers: 0,
            characteristics: 0x40000040,
        };

        let info = SectionCopyInfo::from_section(&section);
        assert_eq!(info.source_offset, 0x2000);
        assert_eq!(info.source_size, 0x1000);
        assert_eq!(info.source_rva, 0x4000);
    }
}
