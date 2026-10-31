//! Header fixup pass for PE file generation.
//!
//! This module provides functions to update PE headers after all content has been written.
//! Fixups are applied as the final step before checksum calculation, patching headers
//! with values that were unknown at initial write time.
//!
//! # Overview
//!
//! The fixup pass runs after all PE sections, metadata, and method bodies have been written
//! to the output file. It performs final header adjustments that require knowledge of the
//! complete file content:
//!
//! - **Optional Header**: Updates `SizeOfCode`, `SizeOfImage`, and `SizeOfHeaders`
//! - **Section Table**: Patches section headers with final sizes, RVAs, and offsets
//! - **COR20 Header**: Updates metadata RVA and size
//! - **Data Directories**: Patches directory entries for IAT, CLR header, imports/exports, etc.
//! - **Stripped Regions**: Zeros debug and certificate data for better compression
//! - **PE Checksum**: Calculated from all file bytes after all other modifications
//!
//! # Architecture
//!
//! All fixup functions operate on [`WriteContext`] which carries the positions and values
//! collected during the write phase. The functions use `write_u32_at()` to patch specific
//! offsets without changing the write position.
//!
//! ```text
//! ┌─────────────────┐
//! │  Write Phase    │ ── Collects positions, sizes, RVAs
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Fixup Phase    │ ── Patches headers with final values
//! │  (this module)  │
//! └────────┬────────┘
//!          │
//!          ▼
//! ┌─────────────────┐
//! │  Checksum       │ ── Final step: calculate PE checksum
//! └─────────────────┘
//! ```
//!
//! # PE Checksum Algorithm
//!
//! The PE checksum is a 32-bit sum computed over all 16-bit words in the file, with the
//! checksum field itself excluded. The algorithm handles carry-out by adding it back
//! (similar to IP checksum). After summing all words, the file size is added.
//!
//! The checksum is stored in the Optional Header at offset 64 from the start of the
//! Optional Header, regardless of PE32 or PE32+ format.
//!
//! # References
//!
//! - [PE Format: Optional Header](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only)
//! - [PE Format: Data Directories](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-data-directories-image-only)
//! - ECMA-335 §II.25 - File format extensions to PE

use crate::{
    cilassembly::writer::{context::WriteContext, output::Output},
    file::pe::{constants::COR20_HEADER_SIZE, SectionTable},
    utils::align_to,
    Error, Referrer, Result,
};

/// Standard metadata stream names in the order they are written.
const METADATA_STREAM_NAMES: [&str; 5] = ["#~", "#Strings", "#US", "#GUID", "#Blob"];

/// Applies all header fixups to the output file.
///
/// This is the main entry point for the fixup phase. It calls all individual fixup
/// functions in the correct order, with checksum calculation always last.
///
/// # Arguments
///
/// * `ctx` - The write context containing all positions and values from the write phase
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if any fixup operation fails.
///
/// # Order of Operations
///
/// 1. DOS header e_lfanew fixup
/// 2. Optional header fixups (sizes)
/// 3. Section table fixups (RVAs, sizes, offsets)
/// 4. COR20 header fixup (metadata location)
/// 5. Data directory fixups
/// 6. Zero stripped data regions (debug, certificate)
/// 7. PE checksum calculation (must be last)
pub fn apply_all_fixups(ctx: &mut WriteContext) -> Result<()> {
    // Fix e_lfanew in DOS header (offset 0x3C points to PE signature)
    let pe_sig_offset = u32::try_from(ctx.pe_signature_offset)
        .map_err(|_| Error::LayoutFailed("PE signature offset exceeds u32 range".to_string()))?;
    let lfanew_pos = ctx
        .dos_header_offset
        .checked_add(0x3C)
        .ok_or_else(|| Error::LayoutFailed("DOS header offset overflow".to_string()))?;
    ctx.write_u32_at(lfanew_pos, pe_sig_offset)?;

    // Fix header fields
    fixup_optional_header(ctx)?;
    fixup_section_table(ctx)?;
    fixup_cor20_header(ctx)?;
    fixup_data_directories(ctx)?;

    // Nothing of the input's debug data or certificate needs scrubbing: `.text` is rebuilt,
    // so neither is copied unless `write_debug_data` keeps the debug data of a write that
    // changes nothing, and their directory entries are zeroed or re-pointed above.

    // Fix COFF characteristics if relocations were stripped
    fixup_coff_characteristics(ctx)?;

    // Calculate and write PE checksum (must be last)
    fixup_checksum(ctx)?;

    Ok(())
}

/// Fixes up the Optional Header with final size values.
///
/// Updates the following fields:
/// - `SizeOfCode` (offset +4): Size of .text section aligned to file alignment
/// - `SizeOfImage` (offset +56): Total image size in memory, aligned to section alignment
/// - `SizeOfHeaders` (offset +60): Combined size of all headers up to first section
///
/// # Arguments
///
/// * `ctx` - The write context with section information
///
/// # PE Format Reference
///
/// The offsets are the same for both PE32 and PE32+ formats for these fields:
/// - Standard fields magic is 2 bytes, so SizeOfCode is at offset 4
/// - SizeOfImage and SizeOfHeaders are in the Windows-specific fields
pub fn fixup_optional_header(ctx: &mut WriteContext) -> Result<()> {
    let text_file_size = u32::try_from(align_to(
        ctx.text_section_size,
        u64::from(ctx.file_alignment),
    ))
    .map_err(|_| Error::LayoutFailed("Text file size exceeds u32 range".to_string()))?;

    // Calculate total image size from all active sections
    let mut end_rva: u32 = 0;
    for section in &ctx.sections {
        if section.removed {
            continue;
        }
        if let (Some(rva), Some(size)) = (section.rva, section.data_size) {
            let section_end = rva.saturating_add(size);
            if section_end > end_rva {
                end_rva = section_end;
            }
        }
    }

    let image_size = u32::try_from(align_to(
        u64::from(end_rva),
        u64::from(ctx.section_alignment),
    ))
    .map_err(|_| Error::LayoutFailed("Image size exceeds u32 range".to_string()))?;

    let oh = ctx.optional_header_offset;
    let oh_field = |off: u64| -> Result<u64> {
        oh.checked_add(off)
            .ok_or_else(|| Error::LayoutFailed("Optional header offset overflow".to_string()))
    };

    // SizeOfCode at offset 4 (after magic field)
    ctx.write_u32_at(oh_field(4)?, text_file_size)?;

    // AddressOfEntryPoint at offset 16
    // This is the RVA of the native entry point stub that jumps to _CorExeMain/_CorDllMain
    if let Some(entry_rva) = ctx.native_entry_rva {
        ctx.write_u32_at(oh_field(16)?, entry_rva)?;
    }

    // SizeOfImage at offset 56
    ctx.write_u32_at(oh_field(56)?, image_size)?;

    // SizeOfHeaders at offset 60
    let headers_size = u32::try_from(ctx.text_section_offset)
        .map_err(|_| Error::LayoutFailed("Headers size exceeds u32 range".to_string()))?;
    ctx.write_u32_at(oh_field(60)?, headers_size)?;

    Ok(())
}

/// Fixes up the Section Table with final values.
///
/// Rebuilds the section table by:
/// 1. Collecting all non-removed sections with updated values
/// 2. Writing them contiguously (no gaps from removed sections)
/// 3. Updating section count in COFF header
///
/// Each section header is updated with:
/// - `VirtualSize` (offset +8): Actual size of section content
/// - `VirtualAddress` (offset +12): RVA where section is loaded
/// - `SizeOfRawData` (offset +16): Size on disk, aligned to file alignment
/// - `PointerToRawData` (offset +20): File offset of section data
pub fn fixup_section_table(ctx: &mut WriteContext) -> Result<()> {
    // Build the new section table, excluding removed sections
    let mut section_headers: Vec<[u8; SectionTable::SIZE]> = Vec::new();

    for section in &ctx.sections {
        if section.removed {
            continue;
        }
        // Get section data or use original values for sections without write info
        let (Some(data_offset), Some(rva), Some(data_size)) =
            (section.data_offset, section.rva, section.data_size)
        else {
            continue; // Skip sections without data
        };

        // SizeOfRawData must be a multiple of FileAlignment per PE spec, and must describe the
        // bytes actually written — not `data_size`, which is the section's *virtual* extent and
        // also drives RVA placement. The two differ whenever a section carries uninitialised
        // data (VirtualSize > SizeOfRawData) or trailing alignment padding (the reverse).
        //
        // Falls back to `data_size` only for sections that recorded no written length.
        let raw_size = section.raw_size.unwrap_or(data_size);
        let file_size = u32::try_from(align_to(u64::from(raw_size), u64::from(ctx.file_alignment)))
            .map_err(|_| {
                Error::LayoutFailed(format!(
                    "Section {} file size exceeds u32 range",
                    section.name
                ))
            })?;

        let offset_u32 = u32::try_from(data_offset).map_err(|_| {
            Error::LayoutFailed(format!("Section {} offset exceeds u32 range", section.name))
        })?;

        // Build section header
        let mut header = [0u8; SectionTable::SIZE];

        // Name (8 bytes, null-padded)
        let name_bytes = section.name.as_bytes();
        let copy_len = std::cmp::min(name_bytes.len(), 8);
        let name_src = name_bytes.get(..copy_len).ok_or(out_of_bounds_error!())?;
        header
            .get_mut(..copy_len)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(name_src);

        // VirtualSize
        header
            .get_mut(8..12)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&data_size.to_le_bytes());
        // VirtualAddress
        header
            .get_mut(12..16)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&rva.to_le_bytes());
        // SizeOfRawData
        header
            .get_mut(16..20)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&file_size.to_le_bytes());
        // PointerToRawData
        header
            .get_mut(20..24)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&offset_u32.to_le_bytes());
        // COFF relocation and line number fields are always 0 for PE executables.
        // These are legacy fields from COFF object files used during linking.
        // PointerToRelocations
        header
            .get_mut(24..28)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&0u32.to_le_bytes());
        // PointerToLinenumbers (deprecated)
        header
            .get_mut(28..32)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&0u32.to_le_bytes());
        // NumberOfRelocations
        header
            .get_mut(32..34)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&0u16.to_le_bytes());
        // NumberOfLinenumbers (deprecated)
        header
            .get_mut(34..36)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&0u16.to_le_bytes());
        // Characteristics
        header
            .get_mut(36..40)
            .ok_or(out_of_bounds_error!())?
            .copy_from_slice(&section.characteristics.to_le_bytes());

        section_headers.push(header);
    }

    // Write the rebuilt section table
    let mut offset = ctx.section_table_offset;
    for header in &section_headers {
        ctx.write_at(offset, header)?;
        offset = offset
            .checked_add(SectionTable::SIZE as u64)
            .ok_or_else(|| Error::LayoutFailed("Section table offset overflow".to_string()))?;
    }

    // Zero any remaining space (from removed sections)
    let original_table_size = ctx
        .sections
        .len()
        .checked_mul(SectionTable::SIZE)
        .ok_or_else(|| Error::LayoutFailed("Section table size overflow".to_string()))?;
    let new_table_size = section_headers
        .len()
        .checked_mul(SectionTable::SIZE)
        .ok_or_else(|| Error::LayoutFailed("Section table size overflow".to_string()))?;
    if new_table_size < original_table_size {
        let zero_len = original_table_size
            .checked_sub(new_table_size)
            .ok_or_else(|| Error::LayoutFailed("Section table size underflow".to_string()))?;
        let zeros = vec![0u8; zero_len];
        ctx.write_at(offset, &zeros)?;
    }

    // Update section count in COFF header
    let new_count = u16::try_from(section_headers.len()).unwrap_or(0);
    let coff_count_pos = ctx
        .coff_header_offset
        .checked_add(2)
        .ok_or_else(|| Error::LayoutFailed("COFF header offset overflow".to_string()))?;
    ctx.write_u16_at(coff_count_pos, new_count)?;

    Ok(())
}

/// Fixes up the COR20 (CLR) header with metadata location.
///
/// Updates:
/// - `MetaData.VirtualAddress` (offset +8): RVA of metadata root
/// - `MetaData.Size` (offset +12): Size of entire metadata section
///
/// # Arguments
///
/// * `ctx` - The write context with metadata position information
///
/// # CLR Header Layout
///
/// The COR20 header (IMAGE_COR20_HEADER) has a fixed structure defined in ECMA-335.
/// The MetaData field is a data directory (RVA + Size) at offset 8.
pub fn fixup_cor20_header(ctx: &mut WriteContext) -> Result<()> {
    // MetaData directory (offset 8-15)
    let metadata_rva = ctx.offset_to_rva(ctx.metadata_offset);
    let metadata_size = u32::try_from(ctx.metadata_size)
        .map_err(|_| Error::LayoutFailed("Metadata size exceeds u32 range".to_string()))?;

    let cor20 = ctx.cor20_header_offset;
    let cor20_field = |off: u64| -> Result<u64> {
        cor20
            .checked_add(off)
            .ok_or_else(|| Error::LayoutFailed("COR20 header offset overflow".to_string()))
    };

    ctx.write_u32_at(cor20_field(8)?, metadata_rva)?; // MetaData RVA
    ctx.write_u32_at(cor20_field(12)?, metadata_size)?; // MetaData Size

    // Resources directory (offset 24-31)
    // COR20 header layout:
    //   0-3: cb (header size)
    //   4-5: MajorRuntimeVersion
    //   6-7: MinorRuntimeVersion
    //   8-11: MetaData RVA
    //   12-15: MetaData Size
    //   16-19: Flags
    //   20-23: EntryPointToken
    //   24-27: Resources RVA
    //   28-31: Resources Size

    // Entry point token (offset 20-23) - may need remapping if methods were deleted
    if ctx.entry_point_token != 0 && !ctx.tokens.is_empty() {
        let new_token = ctx
            .tokens
            .remap(Referrer::EntryPoint, ctx.entry_point_token)?;
        if new_token != ctx.entry_point_token {
            ctx.write_u32_at(cor20_field(20)?, new_token)?;
        }
    }

    if ctx.resource_data_size > 0 {
        let resource_rva = ctx.offset_to_rva(ctx.resource_data_offset);
        let resource_size = u32::try_from(ctx.resource_data_size)
            .map_err(|_| Error::LayoutFailed("Resource size exceeds u32 range".to_string()))?;

        ctx.write_u32_at(cor20_field(24)?, resource_rva)?; // Resources RVA
        ctx.write_u32_at(cor20_field(28)?, resource_size)?; // Resources Size
    }

    Ok(())
}

/// Fixes up the Data Directories in the Optional Header.
///
/// Data directories are an array of (RVA, Size) pairs that point to various PE
/// structures. This function updates directories for:
///
/// - **Index 0**: Export Table (if native exports present)
/// - **Index 1**: Import Table (if native imports present)
/// - **Index 2**: Resource Table (if .rsrc section present)
/// - **Index 5**: Base Relocation Table (if .reloc section present)
/// - **Index 12**: IAT (Import Address Table) - always at start of .text
/// - **Index 14**: CLR Runtime Header - always 8 bytes after .text start
///
/// # Arguments
///
/// * `ctx` - The write context with data directory information
///
/// # Directory Offsets
///
/// Data directories start at different offsets in the Optional Header:
/// - PE32: offset 96 (28 standard + 68 windows-specific fields)
/// - PE32+: offset 112 (24 standard + 88 windows-specific fields)
///
/// Each directory entry is 8 bytes (4-byte RVA + 4-byte Size).
///
/// # Note
///
/// Debug (index 6) and Certificate (index 4) directories are zeroed during the
/// write phase because they become invalid after assembly modification.
pub fn fixup_data_directories(ctx: &mut WriteContext) -> Result<()> {
    let dd_offset: u64 = if ctx.is_pe32_plus { 112 } else { 96 };
    let dd_base = ctx
        .optional_header_offset
        .checked_add(dd_offset)
        .ok_or_else(|| Error::LayoutFailed("Data directory offset overflow".to_string()))?;

    // Each directory entry is 8 bytes: index N → offset N*8 (RVA), N*8+4 (Size)
    let dd_entry = |index: u64| -> Result<(u64, u64)> {
        let rva_off = index
            .checked_mul(8)
            .and_then(|v| dd_base.checked_add(v))
            .ok_or_else(|| {
                Error::LayoutFailed("Data directory entry offset overflow".to_string())
            })?;
        let size_off = rva_off.checked_add(4).ok_or_else(|| {
            Error::LayoutFailed("Data directory entry offset overflow".to_string())
        })?;
        Ok((rva_off, size_off))
    };

    // IAT (index 12) and CLR Runtime Header (index 14)
    // When the assembly has native imports (IAT was written), the layout is:
    //   .text start → IAT → COR20 header → ...
    // When no native imports exist (.NET Core PE32+ without mscoree.dll):
    //   .text start → COR20 header → ...
    let has_iat = ctx.iat_size > 0;
    let (iat_rva_off, iat_size_off) = dd_entry(12)?;
    let (clr_rva_off, clr_size_off) = dd_entry(14)?;
    if has_iat {
        let iat_rva = ctx.text_section_rva;
        let iat_size = u32::try_from(ctx.iat_size).unwrap_or(8);
        ctx.write_u32_at(iat_rva_off, iat_rva)?;
        ctx.write_u32_at(iat_size_off, iat_size)?;

        // CLR header sits immediately after IAT
        let clr_rva = ctx
            .text_section_rva
            .checked_add(iat_size)
            .ok_or_else(|| Error::LayoutFailed("CLR header RVA overflow".to_string()))?;
        ctx.write_u32_at(clr_rva_off, clr_rva)?;
        ctx.write_u32_at(clr_size_off, COR20_HEADER_SIZE)?;
    } else {
        // No IAT - zero the IAT data directory
        ctx.write_u32_at(iat_rva_off, 0)?;
        ctx.write_u32_at(iat_size_off, 0)?;

        // CLR header sits at the very start of .text section
        let clr_rva = ctx.text_section_rva;
        ctx.write_u32_at(clr_rva_off, clr_rva)?;
        ctx.write_u32_at(clr_size_off, COR20_HEADER_SIZE)?;
    }

    // Debug (index 6), when a write that changes nothing kept it
    if let Some((rva, size)) = ctx.debug_dir {
        let (debug_rva_off, debug_size_off) = dd_entry(6)?;
        ctx.write_u32_at(debug_rva_off, rva)?;
        ctx.write_u32_at(debug_size_off, size)?;
    }

    // Import Table (index 1)
    let (imp_rva_off, imp_size_off) = dd_entry(1)?;
    if let (Some(rva), Some(size)) = (ctx.import_data_rva, ctx.import_data_size) {
        ctx.write_u32_at(imp_rva_off, rva)?;
        ctx.write_u32_at(imp_size_off, size)?;
    } else {
        // No import table - zero the directory entry
        ctx.write_u32_at(imp_rva_off, 0)?;
        ctx.write_u32_at(imp_size_off, 0)?;
    }

    // Export Table (index 0)
    let (exp_rva_off, exp_size_off) = dd_entry(0)?;
    if let (Some(rva), Some(size)) = (ctx.export_data_rva, ctx.export_data_size) {
        ctx.write_u32_at(exp_rva_off, rva)?;
        ctx.write_u32_at(exp_size_off, size)?;
    }

    // Resource Table (index 2) - find .rsrc section or embedded PE resources
    let (rsrc_rva_off, rsrc_size_off) = dd_entry(2)?;
    let rsrc_section = ctx
        .sections
        .iter()
        .find(|s| s.name.starts_with(".rsrc") && !s.removed);
    if let Some(section) = rsrc_section {
        if let (Some(rva), Some(size)) = (section.rva, section.data_size) {
            ctx.write_u32_at(rsrc_rva_off, rva)?;
            ctx.write_u32_at(rsrc_size_off, size)?;
        }
    } else if ctx.pe_resource_size > 0 {
        // Resources were embedded in .text and carried over
        let rva = ctx.offset_to_rva(ctx.pe_resource_offset);
        ctx.write_u32_at(rsrc_rva_off, rva)?;
        ctx.write_u32_at(rsrc_size_off, ctx.pe_resource_size)?;
    } else {
        // No resources at all - zero the directory entry
        ctx.write_u32_at(rsrc_rva_off, 0)?;
        ctx.write_u32_at(rsrc_size_off, 0)?;
    }

    // Base Relocation Table (index 5) - find .reloc section in sections vector
    let (reloc_rva_off, reloc_size_off) = dd_entry(5)?;
    let reloc_section = ctx
        .sections
        .iter()
        .find(|s| s.name.starts_with(".reloc") && !s.removed);
    if let Some(section) = reloc_section {
        if let (Some(rva), Some(size)) = (section.rva, section.data_size) {
            ctx.write_u32_at(reloc_rva_off, rva)?;
            ctx.write_u32_at(reloc_size_off, size)?;
        } else {
            // Section exists but no data written - zero the directory
            ctx.write_u32_at(reloc_rva_off, 0)?;
            ctx.write_u32_at(reloc_size_off, 0)?;
        }
    } else {
        // No reloc section or it was removed - zero out the data directory entry
        ctx.write_u32_at(reloc_rva_off, 0)?;
        ctx.write_u32_at(reloc_size_off, 0)?;
    }

    Ok(())
}

/// Fixes up the metadata root stream headers with actual offsets and sizes.
///
/// The metadata root header contains an array of stream headers, each with:
/// - `offset` (u32): Offset from metadata root to stream data
/// - `size` (u32): Size of stream data (aligned to 4 bytes)
/// - `name`: Null-terminated string, padded to 4-byte boundary
///
/// During initial write, these headers contain placeholder values. This function
/// patches them with the actual offsets and sizes after all streams are written.
///
/// # Arguments
///
/// * `ctx` - The write context with stream positions
/// * `metadata_root_offset` - File offset of the metadata root header
/// * `stream_headers_offset` - File offset where stream headers begin
///
/// # Returns
///
/// Returns `Ok(())` on successful fixup of all stream headers.
///
/// # Errors
///
/// Returns an error if writing to the output file fails.
///
/// # Stream Order
///
/// Streams are written and fixed up in this order:
/// 1. `#~` - Tables stream
/// 2. `#Strings` - String heap
/// 3. `#US` - User string heap
/// 4. `#GUID` - GUID heap
/// 5. `#Blob` - Blob heap
pub fn fixup_metadata_stream_headers(
    ctx: &mut WriteContext,
    metadata_root_offset: u64,
    stream_headers_offset: u64,
) -> Result<()> {
    let mut offset = stream_headers_offset;

    // Stream order: #~, #Strings, #US, #GUID, #Blob
    let streams = [
        (
            ctx.tables_stream_offset,
            ctx.tables_stream_size,
            METADATA_STREAM_NAMES[0],
        ),
        (
            ctx.strings_heap_offset,
            ctx.strings_heap_size,
            METADATA_STREAM_NAMES[1],
        ),
        (
            ctx.us_heap_offset,
            ctx.us_heap_size,
            METADATA_STREAM_NAMES[2],
        ),
        (
            ctx.guid_heap_offset,
            ctx.guid_heap_size,
            METADATA_STREAM_NAMES[3],
        ),
        (
            ctx.blob_heap_offset,
            ctx.blob_heap_size,
            METADATA_STREAM_NAMES[4],
        ),
    ];

    for (stream_offset, stream_size, name) in &streams {
        // Calculate offset relative to metadata root
        let rel = stream_offset
            .checked_sub(metadata_root_offset)
            .ok_or_else(|| Error::LayoutFailed("Stream offset before metadata root".to_string()))?;
        let relative_offset = u32::try_from(rel).map_err(|_| {
            Error::LayoutFailed("Stream relative offset exceeds u32 range".to_string())
        })?;
        let aligned_size = u32::try_from(align_to(*stream_size, 4)).map_err(|_| {
            Error::LayoutFailed("Stream aligned size exceeds u32 range".to_string())
        })?;

        // Write offset
        ctx.write_u32_at(offset, relative_offset)?;
        // Write size
        let size_off = offset
            .checked_add(4)
            .ok_or_else(|| Error::LayoutFailed("Stream header offset overflow".to_string()))?;
        ctx.write_u32_at(size_off, aligned_size)?;

        // Advance past this stream header (offset + size + name with alignment)
        let name_with_null = name
            .len()
            .checked_add(1)
            .ok_or_else(|| Error::LayoutFailed("Stream name length overflow".to_string()))?;
        let aligned_name = align_to(name_with_null as u64, 4);
        offset = aligned_name
            .checked_add(8)
            .and_then(|v| offset.checked_add(v))
            .ok_or_else(|| Error::LayoutFailed("Stream header offset overflow".to_string()))?;
    }

    Ok(())
}

/// Fixes up COFF characteristics when relocations are stripped.
///
/// Sets the `IMAGE_FILE_RELOCS_STRIPPED` flag (0x0001) in the COFF header
/// characteristics field when the assembly has no relocations. This is
/// required by CoreCLR for IL-only x64 EXEs without relocations.
///
/// # Arguments
///
/// * `ctx` - The write context with relocs_stripped flag
///
/// # CoreCLR Requirements
///
/// From CoreCLR's `CheckILOnlyBaseRelocations()`:
/// - If no base relocation directory AND not a DLL, RELOCS_STRIPPED must be set
/// - This applies to IL-only x64 EXEs where no relocations are needed
///
/// # COFF Header Layout
///
/// The characteristics field is at offset 18 (0x12) from the start of the
/// COFF header. It's a 16-bit field containing various PE flags.
pub fn fixup_coff_characteristics(ctx: &mut WriteContext) -> Result<()> {
    if ctx.relocs_stripped {
        const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

        // Read current characteristics (offset +18 from COFF header)
        let chars_offset = ctx
            .coff_header_offset
            .checked_add(18)
            .ok_or_else(|| Error::LayoutFailed("COFF header offset overflow".to_string()))?;

        // Read the current value from the output
        let current_bytes = ctx.output.as_slice();
        #[allow(clippy::cast_possible_truncation)]
        let chars_offset_usize = chars_offset as usize;
        let chars_end = chars_offset_usize.checked_add(2).ok_or_else(|| {
            Error::LayoutFailed("COFF characteristics offset overflow".to_string())
        })?;
        if chars_end <= current_bytes.len() {
            let chars_slice = current_bytes
                .get(chars_offset_usize..chars_end)
                .ok_or(out_of_bounds_error!())?;
            let current = u16::from_le_bytes([
                *chars_slice.first().ok_or(out_of_bounds_error!())?,
                *chars_slice.get(1).ok_or(out_of_bounds_error!())?,
            ]);

            // Set the RELOCS_STRIPPED flag
            ctx.write_u16_at(chars_offset, current | IMAGE_FILE_RELOCS_STRIPPED)?;
        }
    }

    Ok(())
}

/// Calculates and writes the PE checksum.
///
/// This must be the last fixup operation since the checksum covers all file content.
/// The checksum field itself is excluded from the calculation.
///
/// # Arguments
///
/// * `ctx` - The write context with output file reference
///
/// # Algorithm
///
/// 1. Sum all 16-bit words in the file using 32-bit arithmetic
/// 2. Skip the checksum field (4 bytes at optional_header_offset + 64)
/// 3. Fold carry bits back into the lower 16 bits
/// 4. Add file size to get final checksum
///
/// # Checksum Location
///
/// The checksum is at offset 64 from the start of the Optional Header,
/// which is the same for both PE32 and PE32+ formats.
///
/// # Note
///
/// Uses `ctx.bytes_written` as the actual file size, not the over-allocated
/// mmap size. This ensures the checksum matches what the final truncated
/// file will contain.
pub fn fixup_checksum(ctx: &mut WriteContext) -> Result<()> {
    let checksum_offset = ctx
        .optional_header_offset
        .checked_add(64)
        .ok_or_else(|| Error::LayoutFailed("Checksum offset overflow".to_string()))?;
    let actual_size = usize::try_from(ctx.bytes_written)
        .map_err(|_| Error::LayoutFailed("File size exceeds usize range".to_string()))?;
    let checksum = calculate_pe_checksum(&ctx.output, checksum_offset, actual_size);
    ctx.write_u32_at(checksum_offset, checksum)?;

    Ok(())
}

/// Calculates the PE checksum for the file.
///
/// This implements the standard Windows PE checksum algorithm used by the
/// `MapFileAndCheckSum` API and the Windows loader.
///
/// # Algorithm Details
///
/// 1. Sum all 16-bit words in the file using 32-bit arithmetic
/// 2. Skip the checksum field itself (4 bytes = 2 words at checksum_offset)
/// 3. Fold any carry bits back into the lower 16 bits
/// 4. Add the file length to get the final checksum
///
/// # Arguments
///
/// * `output` - The memory-mapped output file to calculate checksum for
/// * `checksum_offset` - File offset of the checksum field (to exclude from sum)
/// * `actual_size` - The actual file size (may be less than the mmap size due to over-allocation)
///
/// # Returns
///
/// The calculated PE checksum value.
///
/// # Performance
///
/// Since the output is memory-mapped, we access the data directly without
/// any buffer allocation or copying. This is significantly faster than
/// chunked I/O for large files.
fn calculate_pe_checksum(output: &Output, checksum_offset: u64, actual_size: usize) -> u32 {
    let data = output.as_slice();
    let file_size = actual_size.min(data.len()); // Don't exceed mmap bounds
                                                 // Safe: checksum_offset is a small PE header offset that always fits in usize
    let checksum_offset_usize = usize::try_from(checksum_offset).unwrap_or(usize::MAX);
    let checksum_end_usize = checksum_offset_usize.saturating_add(4);

    let mut sum: u64 = 0;

    // Process 16-bit words directly from the memory-mapped file.
    // The bounds (file_size) are clamped to the slice length above, so all
    // index/saturating arithmetic stays within `data`.
    let mut i: usize = 0;
    while i.saturating_add(1) < file_size {
        // Skip the checksum field (4 bytes = 2 words)
        if i >= checksum_offset_usize && i < checksum_end_usize {
            i = i.saturating_add(2);
            continue;
        }

        let word = match data
            .get(i..i.saturating_add(2))
            .and_then(|s| s.try_into().ok())
        {
            Some(arr) => u16::from_le_bytes(arr),
            None => break,
        };
        sum = sum.saturating_add(u64::from(word));
        i = i.saturating_add(2);
    }

    // Handle odd byte at the end of file (if any) - pad with zero
    if i < file_size && (i < checksum_offset_usize || i >= checksum_end_usize) {
        if let Some(&byte) = data.get(i) {
            sum = sum.saturating_add(u64::from(byte));
        }
    }

    // Fold the sum to 16 bits (add carry to low 16 bits)
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF).saturating_add(sum >> 16);
    }

    // Add file size - the PE checksum spec defines `(sum & 0xFFFF) + file_size`;
    // wrap is part of the algorithm for files near 4 GiB.
    #[allow(clippy::cast_possible_truncation)]
    let checksum = (sum as u32).wrapping_add(file_size as u32);

    checksum
}

#[cfg(test)]
mod tests {

    use tempfile::NamedTempFile;

    use super::*;
    use crate::{
        cilassembly::{writer::generator::PeGenerator, CilAssembly},
        testkit::fixture,
        CilAssemblyView,
    };

    #[test]
    fn test_checksum_excludes_checksum_field() {
        // Create a small test output
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let mut output = Output::create(temp_file.path(), 256).expect("Failed to create output");

        // Fill with known pattern
        let pattern: Vec<u8> = (0..256).map(|i| i as u8).collect();
        output.write_at(0, &pattern).expect("Failed to write data");

        // Calculate checksum with exclusion at offset 64, using full 256 bytes as actual size
        let checksum1 = calculate_pe_checksum(&output, 64, 256);

        // Modify bytes at checksum offset
        output
            .write_at(64, &[0xFF, 0xFF, 0xFF, 0xFF])
            .expect("Failed to modify checksum area");

        // Recalculate - should be the same since checksum area is excluded
        let checksum2 = calculate_pe_checksum(&output, 64, 256);

        assert_eq!(
            checksum1, checksum2,
            "Checksum should be the same regardless of checksum field content"
        );
    }

    #[test]
    fn test_apply_fixups_integration() {
        // Load a test assembly
        let view = CilAssemblyView::from_path(fixture("crafted_2.exe"))
            .expect("Failed to load test assembly");
        let assembly: CilAssembly = view.to_owned();

        // Generate to a temp file
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let generator = PeGenerator::new(&assembly);
        generator
            .to_file(temp_file.path())
            .expect("PE generation should succeed");

        // Reload and verify
        let reloaded = CilAssemblyView::from_path(temp_file.path())
            .expect("Should be able to reload generated PE");

        // Verify basic structure is intact
        assert!(
            reloaded.tables().is_some(),
            "Reloaded PE should have tables"
        );
    }
}
