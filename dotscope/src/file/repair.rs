//! PE pre-load repair for corrupted .NET binaries.
//!
//! This module provides standalone repair functions that fix known PE/CLR header
//! corruption patterns applied by packers like BitMono. The repairs are applied
//! to raw bytes before PE parsing, enabling loading of files that would otherwise
//! be rejected by the parser.
//!
//! # Supported Corruption Patterns
//!
//! - **PE signature corruption** (BitDotNet): `0x00014550` → `0x00004550`
//! - **CLR header zeroing** (BitDotNet/BitDecompiler): cb, runtime version, metadata size zeroed
//! - **Data directory inflation** (BitMono packer and others): `NumberOfRvaAndSizes` above `0x10`
//!   (BitMono writes `0x13`); the loader reads only the first 16 directories
//! - **CLR directory size zeroing** (BitMono packer): .NET directory size set to 0
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::{repair_pe, RepairResult};
//!
//! let mut bytes = std::fs::read("corrupted.exe")?;
//! let result = repair_pe(&mut bytes);
//!
//! if !result.repairs.is_empty() {
//!     println!("Applied {} repairs", result.repairs.len());
//!     for repair in &result.repairs {
//!         println!("  {:?}", repair);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

use cowfile::CowFile;
use log::debug;

use crate::{
    file::{
        pe::{
            constants::{
                CLR_DIRECTORY_INDEX, CLR_MAJOR_RUNTIME_VERSION, COR20_HEADER_SIZE, PE32PLUS_MAGIC,
                PE32_MAGIC, PE_SIGNATURE, STANDARD_DATA_DIRECTORY_COUNT,
            },
            SectionTable,
        },
        sectionmap::{RvaMapping, SectionMap},
    },
    metadata::root::CIL_HEADER_MAGIC,
    utils::{read_le_at, write_le_at},
};

/// Result of a PE repair attempt, recording all repairs made.
#[derive(Debug, Clone, Default)]
pub struct RepairResult {
    /// List of individual repair actions that were performed.
    pub repairs: Vec<RepairAction>,
}

/// A specific repair action that was performed on the PE bytes.
#[derive(Debug, Clone)]
pub enum RepairAction {
    /// PE signature restored (BitDotNet: `0x00014550` → `0x00004550`).
    PeSignature {
        /// Original (corrupted) signature value.
        original: u32,
        /// Restored (valid) signature value.
        restored: u32,
    },
    /// CLR header size restored (BitDotNet/BitDecompiler: 0 → 72).
    ClrHeaderSize {
        /// Original (corrupted) header size.
        original: u32,
        /// Restored header size.
        restored: u32,
    },
    /// CLR runtime major version restored (BitDotNet/BitDecompiler: 0 → 2).
    ClrHeaderVersion {
        /// Original (corrupted) major runtime version.
        original_major: u16,
        /// Restored major runtime version.
        restored_major: u16,
    },
    /// CLR metadata RVA reconstructed via BSJB signature scan.
    ClrMetadataRva {
        /// Restored metadata RVA.
        restored_rva: u32,
        /// Restored metadata size.
        restored_size: u32,
    },
    /// `NumberOfRvaAndSizes` above 16 corrected to 16, the directories the loader reads
    /// (BitMono packer: `0x13` → `0x10`).
    DataDirectoryCount {
        /// Original (corrupted) data directory count.
        original: u32,
        /// Restored data directory count.
        restored: u32,
    },
    /// .NET data directory size restored (BitMono packer: 0 → 72).
    DotNetDirectorySize {
        /// Original (corrupted) directory size.
        original: u32,
        /// Restored directory size.
        restored: u32,
    },
}

/// BitDotNet's corrupted PE signature (byte at offset +2 changed from 0x00 to 0x01).
const BITDOTNET_PE_SIGNATURE: u32 = 0x0001_4550;

/// Attempt all known PE repairs on raw bytes, in place.
///
/// Returns a [`RepairResult`] recording what was repaired. If no repairs were
/// needed or possible, returns an empty result.
///
/// Repairs are applied in order:
/// 1. PE signature (must run first - goblin needs a valid PE signature)
/// 2. Optional header / data directories (fix count before navigating to .NET dir)
/// 3. CLR header (uses .NET data directory RVA which may have been fixed in step 2)
pub fn repair_pe(bytes: &mut [u8]) -> RepairResult {
    repair(&mut SliceBytes(bytes))
}

/// Attempt all known PE repairs using the CowFile overlay.
///
/// Writes are applied to the CowFile's overlay without modifying the base data.
/// Reads through the CowFile see pending overlay writes, so repair step 2 can
/// read step 1's writes correctly. The section table and the BSJB scan read
/// the base data.
///
/// Returns a [`RepairResult`] recording what was repaired.
pub fn repair_pe_cow(cowfile: &CowFile) -> RepairResult {
    repair(&mut CowBytes(cowfile))
}

/// The byte access the repairs need: the integers they read and write, and the
/// bytes the section table and the metadata scan are read from.
trait PeBytes {
    /// The bytes the section table and the metadata signature are found in.
    fn data(&self) -> &[u8];
    /// A little-endian `u16` at `offset`, as written so far.
    fn read_u16(&self, offset: usize) -> Option<u16>;
    /// A little-endian `u32` at `offset`, as written so far.
    fn read_u32(&self, offset: usize) -> Option<u32>;
    /// Writes a little-endian `u16` at `offset`.
    fn write_u16(&mut self, offset: usize, value: u16);
    /// Writes a little-endian `u32` at `offset`.
    fn write_u32(&mut self, offset: usize, value: u32);
}

/// Repairs written straight into a byte slice.
struct SliceBytes<'a>(&'a mut [u8]);

impl PeBytes for SliceBytes<'_> {
    fn data(&self) -> &[u8] {
        self.0
    }

    fn read_u16(&self, offset: usize) -> Option<u16> {
        read_u16(self.0, offset)
    }

    fn read_u32(&self, offset: usize) -> Option<u32> {
        read_u32(self.0, offset)
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        let mut off = offset;
        let _ = write_le_at(self.0, &mut off, value);
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        let mut off = offset;
        let _ = write_le_at(self.0, &mut off, value);
    }
}

/// Repairs written to a CowFile's overlay; its base data stays as loaded.
struct CowBytes<'a>(&'a CowFile);

impl PeBytes for CowBytes<'_> {
    fn data(&self) -> &[u8] {
        self.0.data()
    }

    fn read_u16(&self, offset: usize) -> Option<u16> {
        self.0.read_le::<u16>(offset).ok()
    }

    fn read_u32(&self, offset: usize) -> Option<u32> {
        self.0.read_le::<u32>(offset).ok()
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        let _ = self.0.write_le::<u16>(offset, value);
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        let _ = self.0.write_le::<u32>(offset, value);
    }
}

/// Runs every repair over `bytes`, in the order [`repair_pe`] documents.
fn repair(bytes: &mut impl PeBytes) -> RepairResult {
    let mut result = RepairResult::default();

    // Bail fast: not a PE file or too small for a DOS header
    let data = bytes.data();
    if data.len() < 64 || data.first() != Some(&b'M') || data.get(1) != Some(&b'Z') {
        return result;
    }
    let len = data.len();
    let Some(pe_off) = bytes.read_u32(0x3C).map(|v| v as usize) else {
        return result;
    };
    let Some(end) = pe_off.checked_add(4) else {
        return result;
    };
    if end > len {
        return result;
    }

    repair_pe_signature(bytes, pe_off, &mut result);
    repair_pe_optional_header(bytes, pe_off, &mut result);
    repair_clr_header(bytes, pe_off, &mut result);

    result
}

fn repair_pe_signature(bytes: &mut impl PeBytes, pe_off: usize, result: &mut RepairResult) {
    let Some(signature) = bytes.read_u32(pe_off) else {
        return;
    };
    if signature != BITDOTNET_PE_SIGNATURE {
        return;
    }
    debug!(
        "PE signature repair: 0x{:08X} → 0x{:08X} at offset 0x{:X}",
        signature, PE_SIGNATURE, pe_off
    );
    bytes.write_u32(pe_off, PE_SIGNATURE);
    result.repairs.push(RepairAction::PeSignature {
        original: signature,
        restored: PE_SIGNATURE,
    });
}

fn repair_pe_optional_header(bytes: &mut impl PeBytes, pe_off: usize, result: &mut RepairResult) {
    let Some(optional_header_offset) = pe_off.checked_add(24) else {
        return;
    };
    let Some(magic) = bytes.read_u16(optional_header_offset) else {
        return;
    };
    let num_rva_sizes_offset = match magic {
        PE32_MAGIC => optional_header_offset.checked_add(0x5C),
        PE32PLUS_MAGIC => optional_header_offset.checked_add(0x6C),
        _ => return,
    };
    let Some(num_rva_sizes_offset) = num_rva_sizes_offset else {
        return;
    };

    if let Some(num_rva_sizes) = bytes.read_u32(num_rva_sizes_offset) {
        // The loader reads the first 16 directories whatever the count says past them
        if num_rva_sizes > STANDARD_DATA_DIRECTORY_COUNT {
            debug!(
                "Data directory count repair: 0x{:X} → 0x{:X}",
                num_rva_sizes, STANDARD_DATA_DIRECTORY_COUNT
            );
            bytes.write_u32(num_rva_sizes_offset, STANDARD_DATA_DIRECTORY_COUNT);
            result.repairs.push(RepairAction::DataDirectoryCount {
                original: num_rva_sizes,
                restored: STANDARD_DATA_DIRECTORY_COUNT,
            });
        }
    }

    let Some(clr_dir_offset) = clr_directory_offset(bytes, pe_off, num_rva_sizes_offset) else {
        return;
    };
    let Some(clr_size_offset) = clr_dir_offset.checked_add(4) else {
        return;
    };
    let clr_rva = bytes.read_u32(clr_dir_offset);
    let clr_size = bytes.read_u32(clr_size_offset);
    if let (Some(rva), Some(0)) = (clr_rva.filter(|&r| r != 0), clr_size) {
        debug!(
            ".NET directory size repair: 0 → {} (RVA=0x{:X})",
            COR20_HEADER_SIZE, rva
        );
        bytes.write_u32(clr_size_offset, COR20_HEADER_SIZE);
        result.repairs.push(RepairAction::DotNetDirectorySize {
            original: 0,
            restored: COR20_HEADER_SIZE,
        });
    }
}

/// The file offset of the CLR data directory entry, when the image has one: its directory
/// count reaches it and the optional header holds it. A count of 14 or fewer declares no CLR
/// directory, and the bytes where it would be belong to whatever follows the directories.
fn clr_directory_offset(
    bytes: &impl PeBytes,
    pe_off: usize,
    num_rva_sizes_offset: usize,
) -> Option<usize> {
    if usize::try_from(bytes.read_u32(num_rva_sizes_offset)?).ok()? <= CLR_DIRECTORY_INDEX {
        return None;
    }
    let optional_header_size = bytes.read_u16(pe_off.checked_add(20)?)?;
    let optional_header_end = pe_off
        .checked_add(24)?
        .checked_add(usize::from(optional_header_size))?;
    let entry = num_rva_sizes_offset
        .checked_add(4)?
        .checked_add(CLR_DIRECTORY_INDEX.checked_mul(8)?)?;
    (entry.checked_add(8)? <= optional_header_end).then_some(entry)
}

fn repair_clr_header(bytes: &mut impl PeBytes, pe_off: usize, result: &mut RepairResult) {
    let Some(optional_header_offset) = pe_off.checked_add(24) else {
        return;
    };
    let Some(magic) = bytes.read_u16(optional_header_offset) else {
        return;
    };
    let num_rva_sizes_offset = match magic {
        PE32_MAGIC => optional_header_offset.checked_add(0x5C),
        PE32PLUS_MAGIC => optional_header_offset.checked_add(0x6C),
        _ => return,
    };
    let Some(num_rva_sizes_offset) = num_rva_sizes_offset else {
        return;
    };
    let Some(clr_dir_offset) = clr_directory_offset(bytes, pe_off, num_rva_sizes_offset) else {
        return;
    };
    let Some(clr_rva) = bytes.read_u32(clr_dir_offset) else {
        return;
    };
    if clr_rva == 0 {
        return;
    }

    let Some(clr_file_offset) = rva_to_file_offset(bytes.data(), pe_off, clr_rva) else {
        return;
    };
    let clr_offset = clr_file_offset as usize;
    let Some(version_offset) = clr_offset.checked_add(4) else {
        return;
    };
    let Some(metadata_rva_offset) = clr_offset.checked_add(8) else {
        return;
    };
    let Some(metadata_size_offset) = clr_offset.checked_add(12) else {
        return;
    };

    if bytes.read_u32(clr_offset) == Some(0) {
        debug!("CLR header size repair: 0 → {}", COR20_HEADER_SIZE);
        bytes.write_u32(clr_offset, COR20_HEADER_SIZE);
        result.repairs.push(RepairAction::ClrHeaderSize {
            original: 0,
            restored: COR20_HEADER_SIZE,
        });
    }

    if bytes.read_u16(version_offset) == Some(0) {
        debug!(
            "CLR runtime version repair: 0 → {}",
            CLR_MAJOR_RUNTIME_VERSION
        );
        bytes.write_u16(version_offset, CLR_MAJOR_RUNTIME_VERSION);
        result.repairs.push(RepairAction::ClrHeaderVersion {
            original_major: 0,
            restored_major: CLR_MAJOR_RUNTIME_VERSION,
        });
    }

    let metadata_rva = bytes.read_u32(metadata_rva_offset);
    let metadata_size = bytes.read_u32(metadata_size_offset);

    if metadata_rva == Some(0) || metadata_size == Some(0) {
        if let Some((found_rva, found_size)) = find_metadata_by_bsjb_scan(bytes.data(), pe_off) {
            debug!(
                "CLR metadata repair via BSJB scan: RVA=0x{:X}, size=0x{:X}",
                found_rva, found_size
            );
            bytes.write_u32(metadata_rva_offset, found_rva);
            bytes.write_u32(metadata_size_offset, found_size);
            result.repairs.push(RepairAction::ClrMetadataRva {
                restored_rva: found_rva,
                restored_size: found_size,
            });
        }
    }
}

/// Reads a little-endian u16 from the given offset, or `None` if out of bounds.
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let mut off = offset;
    read_le_at::<u16>(bytes, &mut off).ok()
}

/// Reads a little-endian u32 from the given offset, or `None` if out of bounds.
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let mut off = offset;
    read_le_at::<u32>(bytes, &mut off).ok()
}

/// Where the runtime finds `rva` in the file, by the section table (see [`SectionMap`]).
fn rva_to_file_offset(bytes: &[u8], pe_off: usize, rva: u32) -> Option<u32> {
    let sections = parse_section_table(bytes, pe_off)?;
    match SectionMap::new(&sections, bytes.len()).map(rva) {
        RvaMapping::File(offset) => u32::try_from(offset).ok(),
        RvaMapping::ZeroFill | RvaMapping::Unmapped => None,
    }
}

/// The RVA the file byte at `offset` is loaded at, by the section table (see [`SectionMap`]).
fn file_offset_to_rva(bytes: &[u8], pe_off: usize, offset: u32) -> Option<u32> {
    let sections = parse_section_table(bytes, pe_off)?;
    SectionMap::new(&sections, bytes.len()).offset_to_rva(offset as usize)
}

/// Parses the section table from raw PE bytes into [`SectionTable`] entries.
fn parse_section_table(bytes: &[u8], pe_off: usize) -> Option<Vec<SectionTable>> {
    // COFF header starts at pe_off + 4
    let coff_offset = pe_off.checked_add(4)?;

    // Number of sections at COFF offset + 2
    let num_sections = read_u16(bytes, coff_offset.checked_add(2)?)? as usize;

    // Size of optional header at COFF offset + 16
    let opt_header_size = read_u16(bytes, coff_offset.checked_add(16)?)? as usize;

    // Section table starts after PE sig (4) + COFF header (20) + optional header
    let section_table_offset = pe_off
        .checked_add(4)?
        .checked_add(20)?
        .checked_add(opt_header_size)?;

    let mut sections = Vec::with_capacity(num_sections);

    for i in 0..num_sections {
        // Each section header is 40 bytes (SectionTable::SIZE)
        let entry_offset = section_table_offset.checked_add(i.checked_mul(SectionTable::SIZE)?)?;

        let read_field_u32 = |delta: usize| read_u32(bytes, entry_offset.checked_add(delta)?);
        let read_field_u16 = |delta: usize| read_u16(bytes, entry_offset.checked_add(delta)?);

        // Name at offset 0 (8 bytes)
        let name_end = entry_offset.checked_add(8)?;
        let name = bytes
            .get(entry_offset..name_end)
            .and_then(|b| std::str::from_utf8(b).ok())
            .map(|s| s.trim_end_matches('\0').to_string())
            .unwrap_or_default();

        sections.push(SectionTable {
            name,
            virtual_size: read_field_u32(8)?,
            virtual_address: read_field_u32(12)?,
            size_of_raw_data: read_field_u32(16)?,
            pointer_to_raw_data: read_field_u32(20)?,
            pointer_to_relocations: read_field_u32(24)?,
            pointer_to_line_numbers: read_field_u32(28)?,
            number_of_relocations: read_field_u16(32)?,
            number_of_line_numbers: read_field_u16(34)?,
            characteristics: read_field_u32(36)?,
        });
    }

    Some(sections)
}

/// Scans the entire file for the BSJB metadata signature and converts the
/// file offset to an RVA. Also estimates metadata size from the BSJB header.
fn find_metadata_by_bsjb_scan(bytes: &[u8], pe_off: usize) -> Option<(u32, u32)> {
    let bsjb_bytes = CIL_HEADER_MAGIC.to_le_bytes();
    let len = bytes.len();
    if len < 4 {
        return None;
    }

    for i in 0..len.saturating_sub(3) {
        let end = i.checked_add(4)?;
        let Some(window) = bytes.get(i..end) else {
            break;
        };
        if window == bsjb_bytes {
            let file_offset = i as u32;

            // Convert file offset to RVA
            let rva = file_offset_to_rva(bytes, pe_off, file_offset)?;

            // Estimate metadata size from the BSJB header.
            // The metadata root header structure:
            //   +0: Signature (4 bytes, "BSJB")
            //   +4: MajorVersion (2 bytes)
            //   +6: MinorVersion (2 bytes)
            //   +8: Reserved (4 bytes)
            //   +12: VersionLength (4 bytes)
            //   +12+4: Version string (VersionLength bytes, padded to 4)
            //   Then: Flags (2 bytes), NumberOfStreams (2 bytes)
            //   Then for each stream: Offset (4), Size (4), Name (null-terminated, padded to 4)
            //
            // We estimate size by finding the last stream's offset + size.
            let size = estimate_metadata_size(bytes, i);

            return Some((rva, size));
        }
    }

    None
}

/// Estimates metadata size from the BSJB metadata root header.
///
/// Parses the stream headers to find the maximum extent of metadata.
fn estimate_metadata_size(bytes: &[u8], bsjb_offset: usize) -> u32 {
    const FALLBACK: u32 = 0x1000;
    // Minimum: at least the fixed header fields
    let base = bsjb_offset;

    // Read version length at offset 12
    let Some(version_offset) = base.checked_add(12) else {
        return FALLBACK;
    };
    let Some(version_length) = read_u32(bytes, version_offset) else {
        return FALLBACK;
    };

    // Version string follows (padded to 4-byte boundary)
    let padded_version_len = (version_length.saturating_add(3) & !3) as usize;
    let Some(streams_header_offset) = base
        .checked_add(16)
        .and_then(|v| v.checked_add(padded_version_len))
    else {
        return FALLBACK;
    };

    // Read number of streams
    let Some(num_streams_offset) = streams_header_offset.checked_add(2) else {
        return FALLBACK;
    };
    let Some(num_streams) = read_u16(bytes, num_streams_offset) else {
        return FALLBACK;
    };

    // Parse stream headers to find maximum extent
    let mut max_extent: u32 = 0;
    // Skip flags (2) + num_streams (2)
    let Some(mut cursor) = streams_header_offset.checked_add(4) else {
        return FALLBACK;
    };

    for _ in 0..num_streams {
        let Some(stream_offset) = read_u32(bytes, cursor) else {
            break;
        };
        let Some(size_cursor) = cursor.checked_add(4) else {
            break;
        };
        let Some(stream_size) = read_u32(bytes, size_cursor) else {
            break;
        };

        let extent = stream_offset.saturating_add(stream_size);
        if extent > max_extent {
            max_extent = extent;
        }

        // Skip past offset (4) + size (4) + name (null-terminated, padded to 4)
        let Some(after_size) = cursor.checked_add(8) else {
            break;
        };
        cursor = after_size;
        // Read stream name (scan for null terminator)
        while let Some(&b) = bytes.get(cursor) {
            if b == 0 {
                break;
            }
            let Some(next) = cursor.checked_add(1) else {
                return if max_extent > 0 { max_extent } else { FALLBACK };
            };
            cursor = next;
        }
        // Skip null terminator
        let Some(after_null) = cursor.checked_add(1) else {
            break;
        };
        cursor = after_null;
        // Align to 4-byte boundary
        let Some(aligned) = cursor.checked_add(3) else {
            break;
        };
        cursor = aligned & !3;
    }

    if max_extent > 0 {
        max_extent
    } else {
        FALLBACK
    }
}

#[cfg(test)]
mod tests {
    use cowfile::CowFile;

    use crate::{
        file::{
            pe::constants::{
                CLR_MAJOR_RUNTIME_VERSION, COR20_HEADER_SIZE, PE_SIGNATURE,
                STANDARD_DATA_DIRECTORY_COUNT,
            },
            repair::{repair_pe, repair_pe_cow, RepairAction, BITDOTNET_PE_SIGNATURE},
        },
        testkit::fixture,
    };

    /// BitMono packer's inflated data directory count.
    const BITMONO_INFLATED_DATA_DIRECTORY_COUNT: u32 = 0x13;

    /// Helper to build a minimal valid PE32 with known layout.
    ///
    /// Layout:
    /// - DOS header at 0x00 (64 bytes minimum, e_lfanew at 0x3C → 0x80)
    /// - PE signature at 0x80
    /// - COFF header at 0x84 (20 bytes)
    /// - Optional header at 0x98 (PE32 magic, NumberOfRvaAndSizes at 0xF4)
    /// - Data directories at 0xF8 (16 × 8 = 128 bytes)
    /// - Section table at 0x178 (1 section × 40 bytes = 40 bytes)
    /// - Section ".text" starts at file offset 0x200, virtual address 0x2000
    /// - CLR header at file offset 0x208 (= RVA 0x2008)
    fn build_minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 0x300];

        // DOS header
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew = 0x80
        pe[0x3C..0x40].copy_from_slice(&0x0000_0080u32.to_le_bytes());

        // PE signature at 0x80
        pe[0x80..0x84].copy_from_slice(&PE_SIGNATURE.to_le_bytes());

        // COFF header at 0x84
        // Machine = 0x14C (i386)
        pe[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes());
        // NumberOfSections = 1
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        // SizeOfOptionalHeader = 0xE0 (224 bytes for PE32)
        pe[0x94..0x96].copy_from_slice(&0x00E0u16.to_le_bytes());

        // Optional header at 0x98
        // Magic = 0x10B (PE32)
        pe[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes());

        // NumberOfRvaAndSizes at 0xF4 = 0x10
        pe[0xF4..0xF8].copy_from_slice(&STANDARD_DATA_DIRECTORY_COUNT.to_le_bytes());

        // CLR data directory (14th entry) at 0xF8 + 14*8 = 0x168
        // RVA = 0x2008, Size = 72
        pe[0x168..0x16C].copy_from_slice(&0x0000_2008u32.to_le_bytes());
        pe[0x16C..0x170].copy_from_slice(&COR20_HEADER_SIZE.to_le_bytes());

        // Section table at 0x178 (pe_off=0x80, + 4 + 20 + 0xE0 = 0x178)
        // Section name ".text\0\0\0"
        pe[0x178..0x180].copy_from_slice(b".text\0\0\0");
        // VirtualSize = 0x100
        pe[0x180..0x184].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        // VirtualAddress = 0x2000
        pe[0x184..0x188].copy_from_slice(&0x0000_2000u32.to_le_bytes());
        // SizeOfRawData = 0x100
        pe[0x188..0x18C].copy_from_slice(&0x0000_0100u32.to_le_bytes());
        // PointerToRawData = 0x200
        pe[0x18C..0x190].copy_from_slice(&0x0000_0200u32.to_le_bytes());

        // CLR header at file offset 0x208 (= RVA 0x2008, 0x2008 - 0x2000 + 0x200 = 0x208)
        // cb = 72
        pe[0x208..0x20C].copy_from_slice(&COR20_HEADER_SIZE.to_le_bytes());
        // MajorRuntimeVersion = 2
        pe[0x20C..0x20E].copy_from_slice(&2u16.to_le_bytes());
        // MinorRuntimeVersion = 5
        pe[0x20E..0x210].copy_from_slice(&5u16.to_le_bytes());
        // Metadata RVA = 0x2050
        pe[0x210..0x214].copy_from_slice(&0x0000_2050u32.to_le_bytes());
        // Metadata Size = 0x100
        pe[0x214..0x218].copy_from_slice(&0x0000_0100u32.to_le_bytes());

        pe
    }

    #[test]
    fn test_clean_pe_no_repairs() {
        let mut pe = build_minimal_pe();
        let result = repair_pe(&mut pe);
        assert!(
            result.repairs.is_empty(),
            "Clean PE should not need any repairs"
        );
    }

    #[test]
    fn test_pe_signature_repair() {
        let mut pe = build_minimal_pe();

        // Corrupt PE signature (BitDotNet pattern)
        pe[0x80..0x84].copy_from_slice(&BITDOTNET_PE_SIGNATURE.to_le_bytes());

        let result = repair_pe(&mut pe);

        // Verify signature was repaired
        let sig = u32::from_le_bytes([pe[0x80], pe[0x81], pe[0x82], pe[0x83]]);
        assert_eq!(sig, PE_SIGNATURE, "PE signature should be restored");

        // Verify repair was recorded
        let sig_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::PeSignature { .. }))
            .collect();
        assert_eq!(sig_repairs.len(), 1, "Should have one PE signature repair");

        if let RepairAction::PeSignature { original, restored } = &sig_repairs[0] {
            assert_eq!(*original, BITDOTNET_PE_SIGNATURE);
            assert_eq!(*restored, PE_SIGNATURE);
        }
    }

    #[test]
    fn test_clr_header_size_repair() {
        let mut pe = build_minimal_pe();

        // Zero out CLR header cb
        pe[0x208..0x20C].copy_from_slice(&0u32.to_le_bytes());

        let result = repair_pe(&mut pe);

        let cb = u32::from_le_bytes([pe[0x208], pe[0x209], pe[0x20A], pe[0x20B]]);
        assert_eq!(cb, COR20_HEADER_SIZE, "CLR header size should be restored");

        let cb_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::ClrHeaderSize { .. }))
            .collect();
        assert_eq!(cb_repairs.len(), 1);
    }

    #[test]
    fn test_clr_runtime_version_repair() {
        let mut pe = build_minimal_pe();

        // Zero out CLR MajorRuntimeVersion
        pe[0x20C..0x20E].copy_from_slice(&0u16.to_le_bytes());

        let result = repair_pe(&mut pe);

        let major = u16::from_le_bytes([pe[0x20C], pe[0x20D]]);
        assert_eq!(
            major, CLR_MAJOR_RUNTIME_VERSION,
            "CLR major version should be restored"
        );

        let ver_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::ClrHeaderVersion { .. }))
            .collect();
        assert_eq!(ver_repairs.len(), 1);
    }

    #[test]
    fn test_data_directory_count_repair() {
        let mut pe = build_minimal_pe();

        // Inflate NumberOfRvaAndSizes to 0x13 (BitMono packer pattern)
        pe[0xF4..0xF8].copy_from_slice(&BITMONO_INFLATED_DATA_DIRECTORY_COUNT.to_le_bytes());

        let result = repair_pe(&mut pe);

        let count = u32::from_le_bytes([pe[0xF4], pe[0xF5], pe[0xF6], pe[0xF7]]);
        assert_eq!(
            count, STANDARD_DATA_DIRECTORY_COUNT,
            "Data directory count should be restored"
        );

        let count_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::DataDirectoryCount { .. }))
            .collect();
        assert_eq!(count_repairs.len(), 1);

        if let RepairAction::DataDirectoryCount { original, restored } = &count_repairs[0] {
            assert_eq!(*original, BITMONO_INFLATED_DATA_DIRECTORY_COUNT);
            assert_eq!(*restored, STANDARD_DATA_DIRECTORY_COUNT);
        }
    }

    /// A count of 14 or fewer declares no CLR directory: the CLR-slot repairs leave the bytes
    /// where it would be, which belong to what follows the directories, as they are.
    #[test]
    fn no_clr_directory_is_repaired_where_none_is_declared() {
        for count in [0u32, 10, 14] {
            let mut pe = build_minimal_pe();
            pe[0xF4..0xF8].copy_from_slice(&count.to_le_bytes());
            // The CLR slot (directory 14) with an RVA and a zero size
            pe[0x168..0x16C].copy_from_slice(&0x2008u32.to_le_bytes());
            pe[0x16C..0x170].copy_from_slice(&0u32.to_le_bytes());
            let before = pe.clone();
            let result = repair_pe(&mut pe);
            assert_eq!(pe, before, "count {count}");
            assert!(
                result.repairs.is_empty(),
                "count {count}: {:?}",
                result.repairs
            );
        }
    }

    /// A CLR slot past the optional header's declared size is not the optional header's.
    #[test]
    fn no_clr_directory_is_repaired_past_the_optional_header() {
        let mut pe = build_minimal_pe();
        pe[0x16C..0x170].copy_from_slice(&0u32.to_le_bytes());
        // SizeOfOptionalHeader ends before directory 14's entry
        pe[0x94..0x96].copy_from_slice(&0x00D0u16.to_le_bytes());
        let before = pe.clone();
        repair_pe(&mut pe);
        assert_eq!(pe[0x168..0x170], before[0x168..0x170]);
    }

    /// Any count past 16 is repaired, not only BitMono's 0x13; 16 and below are left as
    /// they are.
    #[test]
    fn every_data_directory_count_past_16_is_repaired() {
        for count in [0x11, 0x14, 0x20, 0xFFFF, u32::MAX] {
            let mut pe = build_minimal_pe();
            pe[0xF4..0xF8].copy_from_slice(&count.to_le_bytes());
            let result = repair_pe(&mut pe);
            assert_eq!(
                u32::from_le_bytes(pe[0xF4..0xF8].try_into().unwrap()),
                STANDARD_DATA_DIRECTORY_COUNT,
                "count {count:#x}"
            );
            assert!(result.repairs.iter().any(|repair| matches!(
                repair,
                RepairAction::DataDirectoryCount { original, .. } if *original == count
            )));
        }
        for count in [0x0F, STANDARD_DATA_DIRECTORY_COUNT] {
            let mut pe = build_minimal_pe();
            pe[0xF4..0xF8].copy_from_slice(&count.to_le_bytes());
            let result = repair_pe(&mut pe);
            assert_eq!(
                u32::from_le_bytes(pe[0xF4..0xF8].try_into().unwrap()),
                count
            );
            assert!(!result
                .repairs
                .iter()
                .any(|repair| matches!(repair, RepairAction::DataDirectoryCount { .. })));
        }
    }

    #[test]
    fn test_dotnet_directory_size_repair() {
        let mut pe = build_minimal_pe();

        // Zero the .NET directory size but keep the RVA
        pe[0x16C..0x170].copy_from_slice(&0u32.to_le_bytes());

        let result = repair_pe(&mut pe);

        let size = u32::from_le_bytes([pe[0x16C], pe[0x16D], pe[0x16E], pe[0x16F]]);
        assert_eq!(
            size, COR20_HEADER_SIZE,
            ".NET directory size should be restored"
        );

        let dir_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::DotNetDirectorySize { .. }))
            .collect();
        assert_eq!(dir_repairs.len(), 1);
    }

    #[test]
    fn test_bsjb_metadata_scan() {
        let mut pe = build_minimal_pe();

        // Zero metadata RVA and size in CLR header
        pe[0x210..0x214].copy_from_slice(&0u32.to_le_bytes());
        pe[0x214..0x218].copy_from_slice(&0u32.to_le_bytes());

        // Place BSJB signature at file offset 0x250 (= RVA 0x2050)
        pe[0x250] = 0x42; // 'B'
        pe[0x251] = 0x53; // 'S'
        pe[0x252] = 0x4A; // 'J'
        pe[0x253] = 0x42; // 'B'

        // Minimal BSJB header for size estimation
        // Major/Minor version
        pe[0x254..0x256].copy_from_slice(&1u16.to_le_bytes());
        pe[0x256..0x258].copy_from_slice(&1u16.to_le_bytes());
        // Reserved
        pe[0x258..0x25C].copy_from_slice(&0u32.to_le_bytes());
        // Version length = 12
        pe[0x25C..0x260].copy_from_slice(&12u32.to_le_bytes());
        // Version string (12 bytes, padded to 12 which is already 4-aligned)
        pe[0x260..0x26C].copy_from_slice(b"v4.0.30319\0\0");
        // Flags = 0, NumberOfStreams = 1
        pe[0x26C..0x26E].copy_from_slice(&0u16.to_le_bytes());
        pe[0x26E..0x270].copy_from_slice(&1u16.to_le_bytes());
        // Stream 0: offset=0x40, size=0x20, name="#~\0\0"
        pe[0x270..0x274].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x274..0x278].copy_from_slice(&0x20u32.to_le_bytes());
        pe[0x278..0x27C].copy_from_slice(b"#~\0\0");

        let result = repair_pe(&mut pe);

        // Check that metadata RVA was restored
        let metadata_rva = u32::from_le_bytes([pe[0x210], pe[0x211], pe[0x212], pe[0x213]]);
        assert_eq!(
            metadata_rva, 0x2050,
            "Metadata RVA should point to BSJB location"
        );

        let rva_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::ClrMetadataRva { .. }))
            .collect();
        assert_eq!(rva_repairs.len(), 1);

        if let RepairAction::ClrMetadataRva {
            restored_rva,
            restored_size,
        } = &rva_repairs[0]
        {
            assert_eq!(*restored_rva, 0x2050);
            assert!(*restored_size > 0, "Metadata size should be non-zero");
        }
    }

    #[test]
    fn test_combined_repairs() {
        let mut pe = build_minimal_pe();

        // Apply all BitMono corruptions simultaneously
        // 1. BitDotNet: corrupt PE signature
        pe[0x80..0x84].copy_from_slice(&BITDOTNET_PE_SIGNATURE.to_le_bytes());
        // 2. BitMono packer: inflate data directory count
        pe[0xF4..0xF8].copy_from_slice(&BITMONO_INFLATED_DATA_DIRECTORY_COUNT.to_le_bytes());
        // 3. BitMono packer: zero .NET directory size
        pe[0x16C..0x170].copy_from_slice(&0u32.to_le_bytes());
        // 4. BitDecompiler: zero CLR header fields
        pe[0x208..0x20C].copy_from_slice(&0u32.to_le_bytes()); // cb
        pe[0x20C..0x20E].copy_from_slice(&0u16.to_le_bytes()); // major version

        let result = repair_pe(&mut pe);

        // Verify all fields were repaired
        let sig = u32::from_le_bytes([pe[0x80], pe[0x81], pe[0x82], pe[0x83]]);
        assert_eq!(sig, PE_SIGNATURE);

        let count = u32::from_le_bytes([pe[0xF4], pe[0xF5], pe[0xF6], pe[0xF7]]);
        assert_eq!(count, STANDARD_DATA_DIRECTORY_COUNT);

        let dir_size = u32::from_le_bytes([pe[0x16C], pe[0x16D], pe[0x16E], pe[0x16F]]);
        assert_eq!(dir_size, COR20_HEADER_SIZE);

        let cb = u32::from_le_bytes([pe[0x208], pe[0x209], pe[0x20A], pe[0x20B]]);
        assert_eq!(cb, COR20_HEADER_SIZE);

        let major = u16::from_le_bytes([pe[0x20C], pe[0x20D]]);
        assert_eq!(major, CLR_MAJOR_RUNTIME_VERSION);

        // Should have at least 5 repairs
        assert!(
            result.repairs.len() >= 5,
            "Should have at least 5 repairs, got {}",
            result.repairs.len()
        );
    }

    #[test]
    fn test_too_small_buffer() {
        let mut tiny = vec![0u8; 10];
        let result = repair_pe(&mut tiny);
        assert!(
            result.repairs.is_empty(),
            "Tiny buffer should produce no repairs"
        );
    }

    #[test]
    fn test_not_pe_file() {
        let mut elf = vec![0u8; 256];
        elf[0] = 0x7F;
        elf[1] = b'E';
        elf[2] = b'L';
        elf[3] = b'F';
        let result = repair_pe(&mut elf);
        assert!(
            result.repairs.is_empty(),
            "ELF file should produce no repairs"
        );
    }

    #[test]
    fn test_bitdotnet_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_bitdotnet.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read BitDotNet sample");

        // Verify the file is currently corrupted
        let pe_off =
            u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;
        let sig_before = u32::from_le_bytes([
            bytes[pe_off],
            bytes[pe_off + 1],
            bytes[pe_off + 2],
            bytes[pe_off + 3],
        ]);
        assert_eq!(
            sig_before, BITDOTNET_PE_SIGNATURE,
            "BitDotNet sample should have corrupted PE signature"
        );

        let result = repair_pe(&mut bytes);

        // Verify PE signature was fixed
        let sig_after = u32::from_le_bytes([
            bytes[pe_off],
            bytes[pe_off + 1],
            bytes[pe_off + 2],
            bytes[pe_off + 3],
        ]);
        assert_eq!(sig_after, PE_SIGNATURE);

        // Should have PE signature repair + CLR header repairs
        assert!(
            !result.repairs.is_empty(),
            "BitDotNet sample should need repairs"
        );

        let has_sig_repair = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::PeSignature { .. }));
        assert!(has_sig_repair, "Should have PE signature repair");
    }

    #[test]
    fn test_bitdecompiler_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_bitdecompiler.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read BitDecompiler sample");

        let result = repair_pe(&mut bytes);

        assert!(
            !result.repairs.is_empty(),
            "BitDecompiler sample should need repairs"
        );

        let has_clr_repair = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::ClrHeaderSize { .. }));
        assert!(has_clr_repair, "Should have CLR header size repair");
    }

    #[test]
    fn test_packer_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_packer.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read Packer sample");

        let result = repair_pe(&mut bytes);

        assert!(
            !result.repairs.is_empty(),
            "Packer sample should need repairs"
        );

        let has_dir_count_repair = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::DataDirectoryCount { .. }));
        assert!(
            has_dir_count_repair,
            "Should have data directory count repair"
        );

        let has_dir_size_repair = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::DotNetDirectorySize { .. }));
        assert!(
            has_dir_size_repair,
            "Should have .NET directory size repair"
        );
    }

    #[test]
    fn test_pe_combined_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_pe_combined.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read pe_combined sample");

        let result = repair_pe(&mut bytes);

        // pe_combined has BitDotNet + BitDecompiler
        let has_sig = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::PeSignature { .. }));
        let has_clr = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::ClrHeaderSize { .. }));
        assert!(has_sig, "pe_combined should have PE signature repair");
        assert!(has_clr, "pe_combined should have CLR header repair");
    }

    #[test]
    fn test_maximum_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_maximum.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read maximum sample");

        let result = repair_pe(&mut bytes);

        // maximum has all three protections
        assert!(
            result.repairs.len() >= 3,
            "Maximum sample should have at least 3 repairs, got {}",
            result.repairs.len()
        );

        let has_sig = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::PeSignature { .. }));
        let has_dir_count = result
            .repairs
            .iter()
            .any(|r| matches!(r, RepairAction::DataDirectoryCount { .. }));
        assert!(has_sig, "Maximum should have PE signature repair");
        assert!(
            has_dir_count,
            "Maximum should have data directory count repair"
        );
    }

    #[test]
    fn test_original_sample_no_repairs() {
        let path = fixture("packers/bitmono/0.39.0/original.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read original sample");

        let result = repair_pe(&mut bytes);

        assert!(
            result.repairs.is_empty(),
            "Original (clean) sample should not need any repairs"
        );
    }

    #[test]
    fn test_repaired_bitdotnet_loads_as_pe() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_bitdotnet.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read BitDotNet sample");

        repair_pe(&mut bytes);

        // After repair, goblin should be able to parse it
        let pe = goblin::pe::PE::parse(&bytes);
        assert!(
            pe.is_ok(),
            "Repaired BitDotNet PE should parse: {:?}",
            pe.err()
        );
    }

    #[test]
    fn test_repaired_bitdecompiler_loads_as_pe() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_bitdecompiler.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read BitDecompiler sample");

        repair_pe(&mut bytes);

        let pe = goblin::pe::PE::parse(&bytes);
        assert!(
            pe.is_ok(),
            "Repaired BitDecompiler PE should parse: {:?}",
            pe.err()
        );
    }

    #[test]
    fn test_repaired_packer_loads_as_pe() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_packer.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read Packer sample");

        repair_pe(&mut bytes);

        let pe = goblin::pe::PE::parse(&bytes);
        assert!(
            pe.is_ok(),
            "Repaired Packer PE should parse: {:?}",
            pe.err()
        );
    }

    #[test]
    fn test_repaired_maximum_loads_as_pe() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_maximum.exe");
        let mut bytes = std::fs::read(path).expect("Failed to read Maximum sample");

        repair_pe(&mut bytes);

        let pe = goblin::pe::PE::parse(&bytes);
        assert!(
            pe.is_ok(),
            "Repaired Maximum PE should parse: {:?}",
            pe.err()
        );
    }

    // CowFile-based repair tests

    #[test]
    fn test_cow_clean_pe_no_repairs() {
        let pe = build_minimal_pe();
        let cowfile = CowFile::from_vec(pe);
        let result = repair_pe_cow(&cowfile);
        assert!(
            result.repairs.is_empty(),
            "Clean PE should not need any repairs"
        );
    }

    #[test]
    fn test_cow_pe_signature_repair() {
        let mut pe = build_minimal_pe();
        pe[0x80..0x84].copy_from_slice(&BITDOTNET_PE_SIGNATURE.to_le_bytes());

        let cowfile = CowFile::from_vec(pe);
        let result = repair_pe_cow(&cowfile);

        let bytes = cowfile.to_vec().unwrap();
        let sig = u32::from_le_bytes([bytes[0x80], bytes[0x81], bytes[0x82], bytes[0x83]]);
        assert_eq!(sig, PE_SIGNATURE, "PE signature should be restored");

        let sig_repairs: Vec<_> = result
            .repairs
            .iter()
            .filter(|r| matches!(r, RepairAction::PeSignature { .. }))
            .collect();
        assert_eq!(sig_repairs.len(), 1);
    }

    #[test]
    fn test_cow_combined_repairs() {
        let mut pe = build_minimal_pe();
        pe[0x80..0x84].copy_from_slice(&BITDOTNET_PE_SIGNATURE.to_le_bytes());
        pe[0xF4..0xF8].copy_from_slice(&BITMONO_INFLATED_DATA_DIRECTORY_COUNT.to_le_bytes());
        pe[0x16C..0x170].copy_from_slice(&0u32.to_le_bytes());
        pe[0x208..0x20C].copy_from_slice(&0u32.to_le_bytes());
        pe[0x20C..0x20E].copy_from_slice(&0u16.to_le_bytes());

        let cowfile = CowFile::from_vec(pe);
        let result = repair_pe_cow(&cowfile);

        let bytes = cowfile.to_vec().unwrap();

        let sig = u32::from_le_bytes([bytes[0x80], bytes[0x81], bytes[0x82], bytes[0x83]]);
        assert_eq!(sig, PE_SIGNATURE);

        let count = u32::from_le_bytes([bytes[0xF4], bytes[0xF5], bytes[0xF6], bytes[0xF7]]);
        assert_eq!(count, STANDARD_DATA_DIRECTORY_COUNT);

        let dir_size = u32::from_le_bytes([bytes[0x16C], bytes[0x16D], bytes[0x16E], bytes[0x16F]]);
        assert_eq!(dir_size, COR20_HEADER_SIZE);

        let cb = u32::from_le_bytes([bytes[0x208], bytes[0x209], bytes[0x20A], bytes[0x20B]]);
        assert_eq!(cb, COR20_HEADER_SIZE);

        let major = u16::from_le_bytes([bytes[0x20C], bytes[0x20D]]);
        assert_eq!(major, CLR_MAJOR_RUNTIME_VERSION);

        assert!(
            result.repairs.len() >= 5,
            "Should have at least 5 repairs, got {}",
            result.repairs.len()
        );
    }

    #[test]
    fn test_cow_bitdotnet_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_bitdotnet.exe");
        let bytes = std::fs::read(path).expect("Failed to read BitDotNet sample");
        let mut cowfile = CowFile::from_vec(bytes);
        let result = repair_pe_cow(&cowfile);

        assert!(
            !result.repairs.is_empty(),
            "BitDotNet sample should need repairs"
        );

        cowfile.commit().unwrap();
        let pe = goblin::pe::PE::parse(cowfile.data());
        assert!(
            pe.is_ok(),
            "Repaired BitDotNet PE should parse: {:?}",
            pe.err()
        );
    }

    #[test]
    fn test_cow_maximum_sample() {
        let path = fixture("packers/bitmono/0.39.0/bitmono_maximum.exe");
        let bytes = std::fs::read(path).expect("Failed to read maximum sample");
        let mut cowfile = CowFile::from_vec(bytes);
        let result = repair_pe_cow(&cowfile);

        assert!(
            result.repairs.len() >= 3,
            "Maximum sample should have at least 3 repairs"
        );

        cowfile.commit().unwrap();
        let pe = goblin::pe::PE::parse(cowfile.data());
        assert!(
            pe.is_ok(),
            "Repaired Maximum PE should parse: {:?}",
            pe.err()
        );
    }
}
