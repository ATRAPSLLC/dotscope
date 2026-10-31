//! Owned PE file structures and serialization support.
//!
//! This module provides owned versions of PE (Portable Executable) structures that don't
//! require borrowing from the original file data. These structures support both parsing
//! from goblin PE objects and serialization back to binary format for the write pipeline.
//!
//! # Architecture
//!
//! The module provides owned alternatives to goblin's borrowed structures:
//! - [`Pe`] - Main PE file representation
//! - [`DosHeader`] - DOS header with signature and PE offset
//! - [`CoffHeader`] - COFF header with machine type and characteristics
//! - [`OptionalHeader`] - Optional header with data directories and Windows fields
//! - [`SectionTable`] - Section table entries with names and addresses
//! - [`DataDirectories`] - Data directory entries as owned map
//! - [`Import`]/[`Export`] - Owned import/export table entries
//!
//! Each structure implements:
//! - Conversion from corresponding goblin types
//! - Binary serialization methods for the write pipeline
//! - Accessor methods matching the original File API
//!
//! # Usage Examples
//!
//! ## Parsing from Goblin PE
//! ```no_run
//! use goblin::pe::PE;
//! use dotscope::Pe;
//!
//! let goblin_pe = PE::parse(data)?;
//! let owned_pe = Pe::from_goblin_pe(&goblin_pe, data)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Serialization for Write Pipeline
//! ```no_run
//! let mut buffer = Vec::new();
//! owned_pe.write_headers(&mut buffer)?;
//! owned_pe.write_section_table(&mut buffer)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    file::{native, sectionmap::SectionMap},
    utils::{read_le_at, write_le_at},
    Error, ParseFailure, ParseStage, Result,
};

#[inline]
fn pe_invalid(field: &'static str, reason: String) -> Error {
    ParseFailure::InvalidField {
        stage: ParseStage::OptionalHeader,
        field,
        reason,
    }
    .into()
}
use std::{
    collections::{HashMap, HashSet},
    fmt,
    io::Write,
    sync::Arc,
};

metadata_flags! {
    /// PE machine type identifier.
    ///
    /// Identifies the target CPU architecture for the PE file.
    /// Stored in the COFF header's Machine field.
    pub struct Machine(u16);
}

impl Machine {
    /// Intel 386 or later processors (x86).
    pub const I386: Self = Self(0x014C);
    /// AMD64 / Intel EM64T (x86-64).
    pub const AMD64: Self = Self(0x8664);
    /// ARM little endian.
    pub const ARM: Self = Self(0x01C0);
    /// ARM64 / AArch64 little endian.
    pub const ARM64: Self = Self(0xAA64);
    /// ARMv7 (or higher) Thumb mode only.
    pub const ARMV7: Self = Self(0x01C4);
}

impl fmt::Display for Machine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::I386 => write!(f, "i386"),
            Self::AMD64 => write!(f, "AMD64"),
            Self::ARM => write!(f, "ARM"),
            Self::ARM64 => write!(f, "ARM64"),
            Self::ARMV7 => write!(f, "ARMv7"),
            _ => write!(f, "0x{:04X}", self.bits()),
        }
    }
}

metadata_flags! {
    /// PE subsystem identifier.
    ///
    /// Specifies the subsystem required to run the PE image.
    /// Stored in the optional header's Subsystem field.
    pub struct Subsystem(u16);
}

impl Subsystem {
    /// Image doesn't require a subsystem (device drivers and native system processes).
    pub const NATIVE: Self = Self(1);
    /// Image runs in the Windows graphical user interface (GUI) subsystem.
    pub const WINDOWS_GUI: Self = Self(2);
    /// Image runs in the Windows character-mode user interface (CUI) subsystem.
    pub const WINDOWS_CUI: Self = Self(3);
    /// Image runs in the Windows CE graphical subsystem.
    pub const WINDOWS_CE_GUI: Self = Self(9);
}

impl fmt::Display for Subsystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NATIVE => write!(f, "Native"),
            Self::WINDOWS_GUI => write!(f, "Windows GUI"),
            Self::WINDOWS_CUI => write!(f, "Windows CUI"),
            Self::WINDOWS_CE_GUI => write!(f, "Windows CE GUI"),
            _ => write!(f, "0x{:04X}", self.bits()),
        }
    }
}

metadata_flags! {
    /// PE COFF characteristics bitfield.
    ///
    /// Flags indicating attributes of the PE file such as whether it is
    /// an executable, a DLL, or supports large addresses.
    pub struct PeCharacteristics(u16);
}

impl PeCharacteristics {
    /// Image is an executable (no unresolved external references).
    pub const EXECUTABLE: Self = Self(0x0002);
    /// Application can handle addresses larger than 2 GB.
    pub const LARGE_ADDRESS_AWARE: Self = Self(0x0020);
    /// Machine is based on a 32-bit word architecture.
    pub const BIT32: Self = Self(0x0100);
    /// Image is a dynamic-link library (DLL).
    pub const DLL: Self = Self(0x2000);
}

impl fmt::Display for PeCharacteristics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.contains(Self::EXECUTABLE) {
            parts.push("Executable");
        }
        if self.contains(Self::LARGE_ADDRESS_AWARE) {
            parts.push("LargeAddressAware");
        }
        if self.contains(Self::BIT32) {
            parts.push("32Bit");
        }
        if self.contains(Self::DLL) {
            parts.push("DLL");
        }
        if parts.is_empty() {
            write!(f, "0x{:04X}", self.bits())
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

/// PE file format constants
pub mod constants {
    /// Size of the COR20 (.NET CLR) header in bytes per ECMA-335 §II.25.3.3.
    ///
    /// The COR20 header (also known as CLI header or CLR runtime header) is a fixed-size
    /// 72-byte structure that describes the .NET assembly's metadata location, entry point,
    /// and runtime requirements. This size has remained constant across all .NET versions.
    ///
    /// Key fields within the 72-byte header:
    /// - Bytes 0-3: Header size (always 72)
    /// - Bytes 4-5: Major runtime version
    /// - Bytes 6-7: Minor runtime version
    /// - Bytes 8-15: Metadata RVA and size
    /// - Bytes 16-19: Flags
    /// - Bytes 20-23: Entry point token
    /// - Remaining bytes: Resources, strong name, code manager, etc.
    pub const COR20_HEADER_SIZE: u32 = 72;

    /// Section characteristic: IMAGE_SCN_MEM_EXECUTE
    pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    /// Section characteristic: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    pub const IMAGE_SCN_METADATA: u32 = 0x4000_0040;

    /// Maximum reasonable RVA value for validation
    pub const MAX_REASONABLE_RVA: u32 = 0x1000_0000;

    /// Size of the `ImageResourceDirectory` structure in bytes.
    pub const IMAGE_RESOURCE_DIRECTORY_SIZE: usize = 16;

    /// Size of a `ResourceEntry` structure in bytes.
    pub const RESOURCE_ENTRY_SIZE: usize = 8;

    /// Size of a `ResourceDataEntry` structure in bytes.
    pub const RESOURCE_DATA_ENTRY_SIZE: usize = 16;

    /// Indicates that the resource entry's offset points to a subdirectory.
    /// Used in `ResourceEntry::offset_to_data_or_directory`.
    pub const IMAGE_RESOURCE_DATA_IS_DIRECTORY: u32 = 0x8000_0000;

    /// Indicates that the resource entry's name is a string offset.
    /// Used in `ResourceEntry::name_or_id`.
    pub const IMAGE_RESOURCE_NAME_IS_STRING: u32 = 0x8000_0000;

    /// Mask to extract the offset/ID value from resource entry fields.
    pub const IMAGE_RESOURCE_MASK: u32 = 0x7FFF_FFFF;

    /// Valid PE signature ("PE\0\0").
    pub const PE_SIGNATURE: u32 = 0x0000_4550;

    /// PE32 optional header magic.
    pub const PE32_MAGIC: u16 = 0x10B;

    /// PE32+ optional header magic.
    pub const PE32PLUS_MAGIC: u16 = 0x20B;

    /// Standard number of data directory entries per PE specification.
    pub const STANDARD_DATA_DIRECTORY_COUNT: u32 = 0x10;

    /// CLR runtime header data directory index (14th entry).
    pub const CLR_DIRECTORY_INDEX: usize = 14;

    /// Standard CLR major runtime version.
    pub const CLR_MAJOR_RUNTIME_VERSION: u16 = 2;
}

use constants::{IMAGE_RESOURCE_DIRECTORY_SIZE, RESOURCE_ENTRY_SIZE};

/// Owned PE file representation that doesn't require borrowing from source data.
///
/// This struct contains all the essential PE file information needed for both
/// analysis and generation operations. Unlike goblin's PE struct which borrows
/// from the source data, this structure owns all its data, eliminating lifetime
/// dependencies and enabling flexible usage patterns.
///
/// The structure is designed to support the write pipeline by providing binary
/// serialization methods for all PE components.
#[derive(Debug, Clone)]
pub struct Pe {
    /// DOS header information
    pub dos_header: DosHeader,

    /// COFF header with machine type and characteristics
    pub coff_header: CoffHeader,

    /// Optional header with Windows-specific fields and data directories
    pub optional_header: Option<OptionalHeader>,

    /// Section table entries
    pub sections: Vec<SectionTable>,

    /// Computed image base address
    pub image_base: u64,

    /// Whether this is a 64-bit PE file
    pub is_64bit: bool,

    /// Imported symbols and DLLs, in import table order
    pub imports: Vec<Import>,

    /// Why the import table could not be read in full, when it could not: `imports` holds
    /// the entries before the one that could not be read.
    pub import_error: Option<String>,

    /// The export directory's header, when the image has one
    pub export_header: Option<ExportHeader>,

    /// Exported symbols, by ordinal
    pub exports: Vec<Export>,

    /// Why the export table could not be read in full, when it could not: `exports` holds
    /// what was read before it.
    pub export_error: Option<String>,

    /// List of imported library names
    pub libraries: Vec<String>,

    /// Data directories as owned map for easy lookup
    pub data_directories: HashMap<DataDirectoryType, DataDirectory>,
}

/// Owned DOS header structure.
#[derive(Debug, Clone)]
pub struct DosHeader {
    /// DOS signature (usually "MZ")
    pub signature: u16,
    /// Number of bytes on last page of file
    pub bytes_on_last_page: u16,
    /// Number of pages in file
    pub pages_in_file: u16,
    /// Number of relocation entries
    pub relocations: u16,
    /// Size of header in paragraphs
    pub size_of_header_paragraphs: u16,
    /// Minimum extra paragraphs needed
    pub minimum_extra_paragraphs: u16,
    /// Maximum extra paragraphs needed
    pub maximum_extra_paragraphs: u16,
    /// Initial relative SS value
    pub initial_relative_ss: u16,
    /// Initial SP value
    pub initial_sp: u16,
    /// Checksum
    pub checksum: u16,
    /// Initial IP value
    pub initial_ip: u16,
    /// Initial relative CS value
    pub initial_relative_cs: u16,
    /// Address of relocation table
    pub address_of_relocation_table: u16,
    /// Overlay number
    pub overlay_number: u16,
    /// PE header offset
    pub pe_header_offset: u32,
}

/// Owned COFF header structure.
#[derive(Debug, Clone)]
pub struct CoffHeader {
    /// Machine type (e.g., IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64)
    pub machine: Machine,
    /// Number of sections
    pub number_of_sections: u16,
    /// Time and date stamp
    pub time_date_stamp: u32,
    /// File pointer to symbol table
    pub pointer_to_symbol_table: u32,
    /// Number of symbols
    pub number_of_symbols: u32,
    /// Size of optional header
    pub size_of_optional_header: u16,
    /// Characteristics flags
    pub characteristics: PeCharacteristics,
}

/// Owned optional header structure.
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// Standard fields (PE32/PE32+ common)
    pub standard_fields: StandardFields,
    /// Windows-specific fields
    pub windows_fields: WindowsFields,
    /// Data directories
    pub data_directories: DataDirectories,
}

/// Standard fields common to PE32 and PE32+.
#[derive(Debug, Clone)]
pub struct StandardFields {
    /// Magic number (0x10b for PE32, 0x20b for PE32+)
    pub magic: u16,
    /// Major linker version
    pub major_linker_version: u8,
    /// Minor linker version  
    pub minor_linker_version: u8,
    /// Size of code section
    pub size_of_code: u32,
    /// Size of initialized data
    pub size_of_initialized_data: u32,
    /// Size of uninitialized data
    pub size_of_uninitialized_data: u32,
    /// Address of entry point
    pub address_of_entry_point: u32,
    /// Base of code section
    pub base_of_code: u32,
    /// Base of data section (PE32 only)
    pub base_of_data: Option<u32>,
}

/// Windows-specific fields.
#[derive(Debug, Clone)]
pub struct WindowsFields {
    /// Image base address
    pub image_base: u64,
    /// Section alignment in memory
    pub section_alignment: u32,
    /// File alignment
    pub file_alignment: u32,
    /// Major OS version
    pub major_operating_system_version: u16,
    /// Minor OS version
    pub minor_operating_system_version: u16,
    /// Major image version
    pub major_image_version: u16,
    /// Minor image version
    pub minor_image_version: u16,
    /// Major subsystem version
    pub major_subsystem_version: u16,
    /// Minor subsystem version
    pub minor_subsystem_version: u16,
    /// Win32 version value
    pub win32_version_value: u32,
    /// Size of image
    pub size_of_image: u32,
    /// Size of headers
    pub size_of_headers: u32,
    /// Checksum
    pub checksum: u32,
    /// Subsystem
    pub subsystem: Subsystem,
    /// DLL characteristics
    pub dll_characteristics: u16,
    /// Size of stack reserve
    pub size_of_stack_reserve: u64,
    /// Size of stack commit
    pub size_of_stack_commit: u64,
    /// Size of heap reserve
    pub size_of_heap_reserve: u64,
    /// Size of heap commit
    pub size_of_heap_commit: u64,
    /// Loader flags
    pub loader_flags: u32,
    /// Number of RVA and sizes
    pub number_of_rva_and_sizes: u32,
}

/// Data directories as an owned map for easy lookup.
#[derive(Debug, Clone)]
pub struct DataDirectories {
    directories: HashMap<DataDirectoryType, DataDirectory>,
}

/// Data directory entry.
#[derive(Debug, Clone, Copy)]
pub struct DataDirectory {
    /// Virtual address of the data
    pub virtual_address: u32,
    /// Size of the data
    pub size: u32,
}

/// Data directory types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataDirectoryType {
    /// Export table directory.
    ExportTable = 0,
    /// Import table directory.
    ImportTable = 1,
    /// Resource table directory.
    ResourceTable = 2,
    /// Exception table directory.
    ExceptionTable = 3,
    /// Certificate table directory.
    CertificateTable = 4,
    /// Base relocation table directory.
    BaseRelocationTable = 5,
    /// Debug directory.
    Debug = 6,
    /// Architecture-specific data directory.
    Architecture = 7,
    /// Global pointer directory.
    GlobalPtr = 8,
    /// Thread local storage table directory.
    TlsTable = 9,
    /// Load configuration table directory.
    LoadConfigTable = 10,
    /// Bound import table directory.
    BoundImport = 11,
    /// Import address table directory.
    ImportAddressTable = 12,
    /// Delay import descriptor directory.
    DelayImportDescriptor = 13,
    /// CLR runtime header directory.
    ClrRuntimeHeader = 14,
    /// Reserved directory entry.
    Reserved = 15,
}

/// Owned section table entry.
#[derive(Debug, Clone)]
pub struct SectionTable {
    /// Section name (up to 8 bytes)
    pub name: String,
    /// Virtual size
    pub virtual_size: u32,
    /// Virtual address (RVA)
    pub virtual_address: u32,
    /// Size of raw data
    pub size_of_raw_data: u32,
    /// Pointer to raw data
    pub pointer_to_raw_data: u32,
    /// Pointer to relocations
    pub pointer_to_relocations: u32,
    /// Pointer to line numbers
    pub pointer_to_line_numbers: u32,
    /// Number of relocations
    pub number_of_relocations: u16,
    /// Number of line numbers
    pub number_of_line_numbers: u16,
    /// Section characteristics
    pub characteristics: u32,
}

/// Import entry representing a function imported from an external DLL.
///
/// This structure serves as the single source of truth for both PE parsing and metadata
/// processing, eliminating the need for type conversion between different layers of the
/// system. It captures all information needed to resolve and call imported functions
/// at runtime through the Windows PE loader.
///
/// # Import Resolution Mechanism
///
/// Windows PE imports use a two-table system:
/// - **Import Lookup Table (ILT)**: Template containing original import information
/// - **Import Address Table (IAT)**: Runtime-patched table with actual function addresses
///
/// The loader patches the IAT at runtime, replacing import descriptors with actual
/// function addresses from the target DLL.
///
/// # Import Types
///
/// Functions can be imported in two ways:
/// - **By Name**: Using function name and optional hint for optimization
/// - **By Ordinal**: Using only ordinal number (more efficient but less portable)
///
/// # Field Relationships
///
/// - `name` and `ordinal` are mutually exclusive (one will be None)
/// - `rva` points to the slot in the Import Address Table
/// - `hint` optimizes name lookups in the target DLL's export table
/// - `ilt_value` preserves the original Import Lookup Table entry value (the import address
///   table's, for a descriptor without a lookup table)
#[derive(Debug, Clone)]
pub struct Import {
    /// Name of the DLL containing the imported function (e.g., "kernel32.dll"), one string
    /// shared by the imports of a descriptor
    pub dll: Arc<str>,
    /// Function name if imported by name (None for ordinal-only imports)
    pub name: Option<String>,
    /// Ordinal number if imported by ordinal (None for name-only imports)
    pub ordinal: Option<u16>,
    /// Relative Virtual Address of the Import Address Table slot for this import
    pub rva: u32,
    /// Hint value for optimizing name lookups in the target DLL's export table (0 for an
    /// import by ordinal)
    pub hint: u16,
    /// Original Import Lookup Table entry value preserving import metadata (0 for an import
    /// a change adds)
    pub ilt_value: u64,
}

/// Owned export entry: one exported ordinal, under one of its names. An ordinal with
/// several names is an entry per name.
#[derive(Debug, Clone)]
pub struct Export {
    /// Function name (None for ordinal-only exports)
    pub name: Option<String>,
    /// The export's ordinal: the directory's ordinal base plus its slot in the export address
    /// table
    pub ordinal: u16,
    /// Export RVA: the exported code or data, or for a forwarder its forwarder string
    pub rva: u32,
    /// The file offset `rva` is read from, when the file holds it
    pub offset: Option<u32>,
    /// What a forwarder forwards to (`"DLL.Function"` or `"DLL.#ordinal"`), for an export
    /// whose address is inside the export directory
    pub forwarder: Option<String>,
}

/// The export directory's own fields: the DLL's name and where its ordinals start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportHeader {
    /// The name the DLL exports under
    pub name: String,
    /// The ordinal of the export address table's first slot
    pub base: u32,
    /// The directory's time stamp
    pub timestamp: u32,
    /// The directory's major version
    pub major_version: u16,
    /// The directory's minor version
    pub minor_version: u16,
}

impl Pe {
    /// Create Pe from goblin PE structure, with `data`, the bytes goblin parsed, for the
    /// import and export tables, which are read entry by entry from them (see
    /// `file::native`): goblin's lists leave out what they cannot read.
    ///
    /// # Errors
    ///
    /// Returns an error if the PE structure contains invalid data or if conversion fails.
    /// Validation includes:
    /// - Presence of optional header
    /// - Image base is non-zero
    pub fn from_goblin_pe(goblin_pe: &goblin::pe::PE, data: &[u8]) -> Result<Self> {
        let dos_header = DosHeader::from_goblin(&goblin_pe.header.dos_header);
        let coff_header = CoffHeader::from_goblin(&goblin_pe.header.coff_header);
        let optional_header = goblin_pe
            .header
            .optional_header
            .as_ref()
            .map(OptionalHeader::from_goblin)
            .transpose()?;

        if optional_header.is_none() {
            return Err(pe_invalid(
                "optional_header",
                "PE file does not have an OptionalHeader".into(),
            ));
        }

        if goblin_pe.image_base == 0 {
            return Err(pe_invalid(
                "image_base",
                "PE has invalid zero image base".into(),
            ));
        }

        let sections = goblin_pe
            .sections
            .iter()
            .map(SectionTable::from_goblin)
            .collect::<Result<Vec<_>>>()?;

        let data_directories = optional_header
            .as_ref()
            .map_or_else(DataDirectories::new, |oh| oh.data_directories.clone());

        let map = SectionMap::new(&sections, data.len());
        let imports = native::read_imports(
            map,
            data,
            data_directories
                .directories
                .get(&DataDirectoryType::ImportTable),
            goblin_pe.is_64,
        );
        let exports = native::read_exports(
            map,
            data,
            data_directories
                .directories
                .get(&DataDirectoryType::ExportTable),
        );

        Ok(Pe {
            dos_header,
            coff_header,
            optional_header,
            sections,
            image_base: goblin_pe.image_base,
            is_64bit: goblin_pe.is_64,
            imports: imports.imports,
            import_error: imports.error,
            export_header: exports.header,
            exports: exports.exports,
            export_error: exports.error,
            libraries: imports.libraries,
            data_directories: data_directories.directories,
        })
    }

    /// Write DOS header to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_dos_header<W: Write>(&self, writer: &mut W) -> Result<()> {
        self.dos_header.write_to(writer)
    }

    /// Write PE signature and COFF header to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_pe_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        // PE signature
        writer.write_all(b"PE\x00\x00")?;

        // COFF header
        self.coff_header.write_to(writer)?;

        // Optional header
        if let Some(ref oh) = self.optional_header {
            oh.write_to(writer)?;
        }

        Ok(())
    }

    /// Write section table to buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if writing to the buffer fails.
    pub fn write_section_table<W: Write>(&self, writer: &mut W) -> Result<()> {
        for section in &self.sections {
            section.write_to(writer)?;
        }
        Ok(())
    }

    /// Get data directory by type.
    #[must_use]
    pub fn get_data_directory(&self, dir_type: DataDirectoryType) -> Option<DataDirectory> {
        self.data_directories.get(&dir_type).copied()
    }

    /// Get CLR runtime header directory.
    #[must_use]
    pub fn get_clr_runtime_header(&self) -> Option<DataDirectory> {
        self.get_data_directory(DataDirectoryType::ClrRuntimeHeader)
    }

    /// Calculates the total size of PE headers (PE signature + COFF header + Optional header).
    ///
    /// This method computes the complete size needed for all PE headers based on
    /// the actual header contents, which is useful for layout planning during write operations.
    ///
    /// # Returns
    /// Total size in bytes of all PE headers
    #[must_use]
    pub fn calculate_headers_size(&self) -> u64 {
        // PE signature (4 bytes) + COFF header (20 bytes) + optional header size
        let optional_header_size = self
            .optional_header
            .as_ref()
            .map_or(0, |_| u64::from(self.coff_header.size_of_optional_header));

        4u64.saturating_add(CoffHeader::SIZE as u64)
            .saturating_add(optional_header_size)
    }

    /// Calculates the total size of all file headers (DOS header + PE headers).
    ///
    /// This method computes the complete size needed for DOS header plus all PE headers,
    /// which is useful for file layout calculations where the total header space is needed.
    ///
    /// # Returns
    /// Total size in bytes of DOS header + PE headers
    #[must_use]
    pub fn calculate_total_file_headers_size(&self) -> u64 {
        (DosHeader::SIZE as u64).saturating_add(self.calculate_headers_size())
    }

    /// Calculates the total size of all current sections' raw data.
    ///
    /// This method sums the `size_of_raw_data` field from all sections, which represents
    /// the total space occupied by section content in the file.
    ///
    /// # Returns
    /// Total size in bytes of all section raw data
    #[must_use]
    pub fn get_sections_total_raw_data_size(&self) -> u64 {
        self.sections
            .iter()
            .map(|section| u64::from(section.size_of_raw_data))
            .sum()
    }

    /// Gets the PE headers offset from the DOS header.
    ///
    /// # Returns
    /// Offset where PE headers start in the file
    #[must_use]
    pub fn get_pe_headers_offset(&self) -> u64 {
        u64::from(self.dos_header.pe_header_offset)
    }

    /// Gets the file alignment from the original PE headers.
    ///
    /// # Returns
    /// File alignment in bytes from the original PE headers
    #[must_use]
    pub fn get_file_alignment(&self) -> u64 {
        self.optional_header
            .as_ref()
            .map_or(0x200, |oh| u64::from(oh.windows_fields.file_alignment)) // Fallback to common default
    }

    /// Gets the section alignment from the original PE headers.
    ///
    /// # Returns
    /// Section alignment in bytes from the original PE headers
    #[must_use]
    pub fn get_section_alignment(&self) -> u64 {
        self.optional_header
            .as_ref()
            .map_or(0x1000, |oh| u64::from(oh.windows_fields.section_alignment))
        // Fallback to common default
    }

    /// Adds a new section to the PE file.
    ///
    /// This method adds a new section entry and automatically updates the section count
    /// in the COFF header to maintain consistency.
    ///
    /// # Arguments
    /// * `section` - The section to add
    pub fn add_section(&mut self, section: SectionTable) {
        self.sections.push(section);
        if let Ok(section_count) = u16::try_from(self.sections.len()) {
            self.coff_header.update_section_count(section_count);
        }
    }

    /// Removes a section by name from the PE file.
    ///
    /// This method removes the first section with the given name and automatically
    /// updates the section count in the COFF header.
    ///
    /// # Arguments
    /// * `name` - The name of the section to remove
    ///
    /// # Returns
    /// Returns `true` if a section was removed, `false` if no section with the given name was found
    pub fn remove_section(&mut self, name: &str) -> bool {
        if let Some(index) = self.sections.iter().position(|s| s.name == name) {
            self.sections.remove(index);
            if let Ok(section_count) = u16::try_from(self.sections.len()) {
                self.coff_header.update_section_count(section_count);
            }
            true
        } else {
            false
        }
    }

    /// Finds a mutable reference to a section by name.
    ///
    /// This allows direct modification of section properties while maintaining
    /// the section within the PE structure.
    ///
    /// # Arguments
    /// * `name` - The name of the section to find
    ///
    /// # Returns
    /// Returns a mutable reference to the section if found, None otherwise
    pub fn get_section_mut(&mut self, name: &str) -> Option<&mut SectionTable> {
        self.sections.iter_mut().find(|s| s.name == name)
    }

    /// Finds a reference to a section by name.
    ///
    /// # Arguments
    /// * `name` - The name of the section to find
    ///
    /// # Returns
    /// Returns a reference to the section if found, None otherwise
    #[must_use]
    pub fn get_section(&self, name: &str) -> Option<&SectionTable> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// Updates the CLR runtime header data directory.
    ///
    /// This method updates the CLR data directory entry to point to a new location,
    /// maintaining consistency between the optional header and main data directories map.
    ///
    /// # Arguments
    /// * `rva` - The new RVA for the CLR runtime header
    /// * `size` - The new size of the CLR runtime header
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_clr_data_directory(&mut self, rva: u32, size: u32) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header.data_directories.update_clr_entry(rva, size);
            // Also update the main data_directories map
            self.data_directories.insert(
                DataDirectoryType::ClrRuntimeHeader,
                DataDirectory {
                    virtual_address: rva,
                    size,
                },
            );
            Ok(())
        } else {
            Err(pe_invalid(
                "optional_header",
                "cannot update CLR data directory: PE has no optional header".into(),
            ))
        }
    }

    /// Updates a specific data directory entry.
    ///
    /// This method updates any data directory entry while maintaining consistency
    /// between the optional header and main data directories map.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to update
    /// * `rva` - The new RVA for the directory
    /// * `size` - The new size of the directory
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_data_directory(
        &mut self,
        dir_type: DataDirectoryType,
        rva: u32,
        size: u32,
    ) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header
                .data_directories
                .update_entry(dir_type, rva, size);
            // Also update the main data_directories map
            self.data_directories.insert(
                dir_type,
                DataDirectory {
                    virtual_address: rva,
                    size,
                },
            );
            Ok(())
        } else {
            Err(pe_invalid(
                "optional_header",
                "cannot update data directory: PE has no optional header".into(),
            ))
        }
    }

    /// Updates the SizeOfImage field in the PE optional header.
    ///
    /// SizeOfImage must be updated when sections are added or modified to ensure
    /// the PE image size encompasses all sections. This value represents the total
    /// size of the image when loaded in memory, including all sections aligned to
    /// the section alignment boundary.
    ///
    /// # Arguments
    /// * `new_size` - The new SizeOfImage value
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_size_of_image(&mut self, new_size: u32) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header.windows_fields.size_of_image = new_size;
            Ok(())
        } else {
            Err(pe_invalid(
                "optional_header",
                "cannot update SizeOfImage: PE has no optional header".into(),
            ))
        }
    }

    /// Updates the SizeOfHeaders field in the PE optional header.
    ///
    /// SizeOfHeaders must be updated when sections are added to ensure the value
    /// encompasses all headers including the expanded section table. This value
    /// represents the combined size of DOS header, PE headers, and section table,
    /// rounded up to FileAlignment.
    ///
    /// # Arguments
    /// * `new_size` - The new SizeOfHeaders value (must be aligned to FileAlignment)
    ///
    /// # Errors
    /// Returns an error if the PE has no optional header
    pub fn update_size_of_headers(&mut self, new_size: u32) -> Result<()> {
        if let Some(ref mut optional_header) = self.optional_header {
            optional_header.windows_fields.size_of_headers = new_size;
            Ok(())
        } else {
            Err(pe_invalid(
                "optional_header",
                "cannot update SizeOfHeaders: PE has no optional header".into(),
            ))
        }
    }

    /// Writes the complete PE headers in their current state.
    ///
    /// This method serializes the PE signature, COFF header, and optional header
    /// using their current values. No modifications are made during the write operation.
    ///
    /// # Arguments
    /// * `writer` - Writer to output the headers to
    ///
    /// # Errors
    /// Returns an error if writing fails
    pub fn write_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write PE signature
        writer.write_all(b"PE\x00\x00")?;

        // Write COFF header in current state
        self.coff_header.write_to(writer)?;

        // Write optional header in current state
        if let Some(ref optional_header) = self.optional_header {
            optional_header.write_to(writer)?;
        }

        Ok(())
    }

    /// Writes all section headers in their current state.
    ///
    /// This method serializes all sections in the sections vector using their
    /// current values. The section count in the COFF header should already reflect
    /// the correct number of sections.
    ///
    /// # Arguments
    /// * `writer` - Writer to output the section table to
    ///
    /// # Errors
    /// Returns an error if writing fails
    pub fn write_section_headers<W: Write>(&self, writer: &mut W) -> Result<()> {
        for section in &self.sections {
            section.write_to(writer)?;
        }
        Ok(())
    }
}

impl DosHeader {
    /// Size of DOS header in bytes.
    pub const SIZE: usize = 64;

    /// Size of standard DOS header with stub (128 bytes per ECMA-335 §II.25.2.1).
    pub const STANDARD_SIZE: usize = 128;

    /// Standard DOS header with stub from ECMA-335 Partition II §25.2.1.
    ///
    /// This 128-byte block contains the DOS MZ header and a minimal DOS stub that
    /// prints "This program cannot be run in DOS mode." and exits. The e_lfanew
    /// field at offset 0x3C points to offset 0x80 (128) where the PE header begins.
    ///
    /// This is the canonical DOS header used by all .NET assemblies and matches
    /// what the CLR runtime expects. Using this standard header ensures maximum
    /// compatibility with all .NET runtime implementations.
    #[rustfmt::skip]
    pub const STANDARD_DOS_HEADER: [u8; 128] = [
        // DOS Header (64 bytes)
        0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, // MZ signature + header fields
        0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, // More header fields
        0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Stack pointer, etc.
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Relocation table address
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Reserved
        0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // e_lfanew = 0x80 (offset 0x3C)
        // DOS Stub (64 bytes) - prints "This program cannot be run in DOS mode."
        0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, // PUSH CS; POP DS; MOV DX, 0x0E; MOV AH, 9; INT 21h
        0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, // INT 21h; MOV AX, 0x4C01; INT 21h; "Th"
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, // "is progr"
        0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, // "am canno"
        0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, // "t be run"
        0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, // " in DOS "
        0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, // "mode.\r\r\n"
        0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // "$" + padding
    ];

    fn from_goblin(goblin_dos: &goblin::pe::header::DosHeader) -> Self {
        Self {
            signature: goblin_dos.signature,
            bytes_on_last_page: goblin_dos.bytes_on_last_page,
            pages_in_file: goblin_dos.pages_in_file,
            relocations: goblin_dos.relocations,
            size_of_header_paragraphs: goblin_dos.size_of_header_in_paragraphs,
            minimum_extra_paragraphs: goblin_dos.minimum_extra_paragraphs_needed,
            maximum_extra_paragraphs: goblin_dos.maximum_extra_paragraphs_needed,
            initial_relative_ss: goblin_dos.initial_relative_ss,
            initial_sp: goblin_dos.initial_sp,
            checksum: goblin_dos.checksum,
            initial_ip: goblin_dos.initial_ip,
            initial_relative_cs: goblin_dos.initial_relative_cs,
            address_of_relocation_table: goblin_dos.file_address_of_relocation_table,
            overlay_number: goblin_dos.overlay_number,
            pe_header_offset: goblin_dos.pe_pointer,
        }
    }

    /// Writes this DOS header's fields to the writer.
    ///
    /// This writes just the 64-byte DOS header fields without the DOS stub.
    /// For most use cases, prefer [`Self::write_standard`] or [`Self::write_with_stub`]
    /// which include the required DOS stub.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the DOS header fields to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.signature.to_le_bytes())?;
        writer.write_all(&self.bytes_on_last_page.to_le_bytes())?;
        writer.write_all(&self.pages_in_file.to_le_bytes())?;
        writer.write_all(&self.relocations.to_le_bytes())?;
        writer.write_all(&self.size_of_header_paragraphs.to_le_bytes())?;
        writer.write_all(&self.minimum_extra_paragraphs.to_le_bytes())?;
        writer.write_all(&self.maximum_extra_paragraphs.to_le_bytes())?;
        writer.write_all(&self.initial_relative_ss.to_le_bytes())?;
        writer.write_all(&self.initial_sp.to_le_bytes())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        writer.write_all(&self.initial_ip.to_le_bytes())?;
        writer.write_all(&self.initial_relative_cs.to_le_bytes())?;
        writer.write_all(&self.address_of_relocation_table.to_le_bytes())?;
        writer.write_all(&self.overlay_number.to_le_bytes())?;
        // Reserved fields (4 words)
        for _ in 0..4 {
            writer.write_all(&0u16.to_le_bytes())?;
        }
        // OEM fields
        writer.write_all(&0u16.to_le_bytes())?; // OEM identifier
        writer.write_all(&0u16.to_le_bytes())?; // OEM information
                                                // Reserved2 fields (10 words)
        for _ in 0..10 {
            writer.write_all(&0u16.to_le_bytes())?;
        }
        writer.write_all(&self.pe_header_offset.to_le_bytes())?;

        Ok(())
    }

    /// Writes the standard DOS header with stub.
    ///
    /// This writes the canonical 128-byte DOS header from ECMA-335 Partition II §25.2.1,
    /// which includes the DOS MZ header and a stub that prints "This program cannot be
    /// run in DOS mode." This is the standard header used by all .NET assemblies.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the DOS header to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::DosHeader;
    ///
    /// let mut writer = Vec::new();
    /// DosHeader::write_standard(&mut writer)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn write_standard<W: Write>(writer: &mut W) -> Result<()> {
        writer.write_all(&Self::STANDARD_DOS_HEADER)?;
        Ok(())
    }

    /// Writes this DOS header instance followed by the standard DOS stub.
    ///
    /// Unlike [`Self::write_standard`], this method writes the current header's field values
    /// followed by the DOS stub. This is useful when preserving an existing header's
    /// specific field values while regenerating the file.
    ///
    /// The total size written is 128 bytes (64-byte header + 64-byte stub).
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the DOS header to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_with_stub<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write the DOS header fields
        self.write_to(writer)?;

        // Write DOS stub (64 bytes starting at offset 64)
        writer.write_all(&Self::STANDARD_DOS_HEADER[64..128])?;

        Ok(())
    }
}

impl CoffHeader {
    /// Size of COFF header in bytes (20 bytes).
    pub const SIZE: usize = 20;

    fn from_goblin(goblin_coff: &goblin::pe::header::CoffHeader) -> Self {
        Self {
            machine: Machine::new(goblin_coff.machine),
            number_of_sections: goblin_coff.number_of_sections,
            time_date_stamp: goblin_coff.time_date_stamp,
            pointer_to_symbol_table: goblin_coff.pointer_to_symbol_table,
            number_of_symbols: goblin_coff.number_of_symbol_table,
            size_of_optional_header: goblin_coff.size_of_optional_header,
            characteristics: PeCharacteristics::new(goblin_coff.characteristics),
        }
    }

    /// Updates the number of sections in the COFF header.
    ///
    /// This method is used during write operations when adding new sections
    /// (like the .meta section) to ensure the COFF header reflects the
    /// correct section count.
    ///
    /// # Arguments
    /// * `new_count` - The new number of sections
    pub fn update_section_count(&mut self, new_count: u16) {
        self.number_of_sections = new_count;
    }

    /// Updates the size of optional header field in the COFF header.
    ///
    /// This method is used during write operations when the optional header
    /// size changes to ensure the COFF header reflects the correct size.
    ///
    /// # Arguments
    /// * `new_size` - The new size of the optional header in bytes
    pub fn update_optional_header_size(&mut self, new_size: u16) {
        self.size_of_optional_header = new_size;
    }

    /// Writes this COFF header to the writer.
    ///
    /// The COFF header is 20 bytes and immediately follows the PE signature ("PE\0\0").
    /// It describes the target machine architecture, number of sections, and file characteristics.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the COFF header to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.machine.to_le_bytes())?;
        writer.write_all(&self.number_of_sections.to_le_bytes())?;
        writer.write_all(&self.time_date_stamp.to_le_bytes())?;
        writer.write_all(&self.pointer_to_symbol_table.to_le_bytes())?;
        writer.write_all(&self.number_of_symbols.to_le_bytes())?;
        writer.write_all(&self.size_of_optional_header.to_le_bytes())?;
        writer.write_all(&self.characteristics.to_le_bytes())?;

        Ok(())
    }
}

impl OptionalHeader {
    fn from_goblin(goblin_oh: &goblin::pe::optional_header::OptionalHeader) -> Result<Self> {
        let standard_fields = StandardFields::from_goblin(&goblin_oh.standard_fields)?;
        let windows_fields = WindowsFields::from_goblin(&goblin_oh.windows_fields);
        let data_directories = DataDirectories::from_goblin(&goblin_oh.data_directories);

        Ok(Self {
            standard_fields,
            windows_fields,
            data_directories,
        })
    }

    /// Writes this optional header to the writer.
    ///
    /// The optional header contains the PE format magic, linker version, code/data sizes,
    /// entry point, image base, alignments, subsystem info, and all 16 data directories.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the optional header to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The magic value is invalid (not 0x10b or 0x20b)
    /// - Writing fails
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        let is_pe32_plus = match self.standard_fields.magic {
            0x10b => false, // PE32
            0x20b => true,  // PE32+
            magic => {
                return Err(ParseFailure::BadMagic {
                    stage: ParseStage::OptionalHeader,
                    expected: 0x10b,
                    found: u32::from(magic),
                }
                .into())
            }
        };

        self.standard_fields.write_to(writer)?;
        self.windows_fields.write_to(writer, is_pe32_plus)?;
        self.data_directories.write_to(writer)?;

        Ok(())
    }

    /// Returns the serialized size of this optional header in bytes.
    ///
    /// The size varies based on PE format:
    /// - PE32 (magic 0x10b): 224 bytes (28 standard + 68 windows + 128 data dirs)
    /// - PE32+ (magic 0x20b): 240 bytes (24 standard + 88 windows + 128 data dirs)
    #[must_use]
    pub fn size(&self) -> usize {
        Self::size_for_format(self.standard_fields.magic == 0x20b)
    }

    /// Returns the serialized size of an optional header for the given PE format.
    ///
    /// # Arguments
    ///
    /// * `is_pe32_plus` - `true` for PE32+ (64-bit), `false` for PE32 (32-bit)
    #[must_use]
    pub const fn size_for_format(is_pe32_plus: bool) -> usize {
        let std_size = if is_pe32_plus {
            StandardFields::SIZE_PE32_PLUS
        } else {
            StandardFields::SIZE_PE32
        };
        let win_size = if is_pe32_plus {
            WindowsFields::SIZE_PE32_PLUS
        } else {
            WindowsFields::SIZE_PE32
        };
        std_size
            .saturating_add(win_size)
            .saturating_add(DataDirectories::SIZE)
    }
}

impl StandardFields {
    /// Size of standard fields for PE32 (32-bit): 28 bytes (includes base_of_data).
    pub const SIZE_PE32: usize = 28;
    /// Size of standard fields for PE32+ (64-bit): 24 bytes (no base_of_data).
    pub const SIZE_PE32_PLUS: usize = 24;
    /// Size of standard fields, indexed by `is_pe32_plus as usize`.
    pub const SIZE_FOR_FORMAT: [usize; 2] = [Self::SIZE_PE32, Self::SIZE_PE32_PLUS];

    fn from_goblin(goblin_sf: &goblin::pe::optional_header::StandardFields) -> Result<Self> {
        Ok(Self {
            magic: goblin_sf.magic,
            major_linker_version: goblin_sf.major_linker_version,
            minor_linker_version: goblin_sf.minor_linker_version,
            size_of_code: u32::try_from(goblin_sf.size_of_code)
                .map_err(|_| pe_invalid("size_of_code", "value too large".into()))?,
            size_of_initialized_data: u32::try_from(goblin_sf.size_of_initialized_data)
                .map_err(|_| pe_invalid("size_of_initialized_data", "value too large".into()))?,
            size_of_uninitialized_data: u32::try_from(goblin_sf.size_of_uninitialized_data)
                .map_err(|_| pe_invalid("size_of_uninitialized_data", "value too large".into()))?,
            address_of_entry_point: goblin_sf.address_of_entry_point,
            base_of_code: u32::try_from(goblin_sf.base_of_code)
                .map_err(|_| pe_invalid("base_of_code", "value too large".into()))?,
            base_of_data: if goblin_sf.magic == 0x10b {
                Some(goblin_sf.base_of_data)
            } else {
                None
            },
        })
    }

    /// Writes this standard fields structure to the writer.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the standard fields to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or if PE32 format is missing `base_of_data`.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.major_linker_version.to_le_bytes())?;
        writer.write_all(&self.minor_linker_version.to_le_bytes())?;
        writer.write_all(&self.size_of_code.to_le_bytes())?;
        writer.write_all(&self.size_of_initialized_data.to_le_bytes())?;
        writer.write_all(&self.size_of_uninitialized_data.to_le_bytes())?;
        writer.write_all(&self.address_of_entry_point.to_le_bytes())?;
        writer.write_all(&self.base_of_code.to_le_bytes())?;

        // base_of_data only exists in PE32 (magic == 0x10b)
        if self.magic == 0x10b {
            if let Some(base_of_data) = self.base_of_data {
                writer.write_all(&base_of_data.to_le_bytes())?;
            } else {
                return Err(pe_invalid(
                    "base_of_data",
                    "PE32 file missing base_of_data field".into(),
                ));
            }
        }

        Ok(())
    }
}

impl WindowsFields {
    /// Size of Windows-specific fields for PE32 (32-bit): 68 bytes (4-byte image_base and stack/heap sizes).
    pub const SIZE_PE32: usize = 68;
    /// Size of Windows-specific fields for PE32+ (64-bit): 88 bytes (8-byte image_base and stack/heap sizes).
    pub const SIZE_PE32_PLUS: usize = 88;
    /// Size of Windows-specific fields, indexed by `is_pe32_plus as usize`.
    pub const SIZE_FOR_FORMAT: [usize; 2] = [Self::SIZE_PE32, Self::SIZE_PE32_PLUS];

    fn from_goblin(goblin_wf: &goblin::pe::optional_header::WindowsFields) -> Self {
        Self {
            image_base: goblin_wf.image_base,
            section_alignment: goblin_wf.section_alignment,
            file_alignment: goblin_wf.file_alignment,
            major_operating_system_version: goblin_wf.major_operating_system_version,
            minor_operating_system_version: goblin_wf.minor_operating_system_version,
            major_image_version: goblin_wf.major_image_version,
            minor_image_version: goblin_wf.minor_image_version,
            major_subsystem_version: goblin_wf.major_subsystem_version,
            minor_subsystem_version: goblin_wf.minor_subsystem_version,
            win32_version_value: goblin_wf.win32_version_value,
            size_of_image: goblin_wf.size_of_image,
            size_of_headers: goblin_wf.size_of_headers,
            checksum: goblin_wf.check_sum,
            subsystem: Subsystem::new(goblin_wf.subsystem),
            dll_characteristics: goblin_wf.dll_characteristics,
            size_of_stack_reserve: goblin_wf.size_of_stack_reserve,
            size_of_stack_commit: goblin_wf.size_of_stack_commit,
            size_of_heap_reserve: goblin_wf.size_of_heap_reserve,
            size_of_heap_commit: goblin_wf.size_of_heap_commit,
            loader_flags: goblin_wf.loader_flags,
            number_of_rva_and_sizes: goblin_wf.number_of_rva_and_sizes,
        }
    }

    /// Writes this Windows-specific fields structure to the writer.
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the fields to
    /// * `is_pe32_plus` - `true` for PE32+ (64-bit), `false` for PE32 (32-bit)
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails or if PE32 format has values exceeding u32 range.
    pub fn write_to<W: Write>(&self, writer: &mut W, is_pe32_plus: bool) -> Result<()> {
        // Write image_base with appropriate size
        if is_pe32_plus {
            writer.write_all(&self.image_base.to_le_bytes())?;
        } else {
            writer.write_all(
                &u32::try_from(self.image_base)
                    .map_err(|_| pe_invalid("image_base", "exceeds u32 range".into()))?
                    .to_le_bytes(),
            )?;
        }

        writer.write_all(&self.section_alignment.to_le_bytes())?;
        writer.write_all(&self.file_alignment.to_le_bytes())?;
        writer.write_all(&self.major_operating_system_version.to_le_bytes())?;
        writer.write_all(&self.minor_operating_system_version.to_le_bytes())?;
        writer.write_all(&self.major_image_version.to_le_bytes())?;
        writer.write_all(&self.minor_image_version.to_le_bytes())?;
        writer.write_all(&self.major_subsystem_version.to_le_bytes())?;
        writer.write_all(&self.minor_subsystem_version.to_le_bytes())?;
        writer.write_all(&self.win32_version_value.to_le_bytes())?;
        writer.write_all(&self.size_of_image.to_le_bytes())?;
        writer.write_all(&self.size_of_headers.to_le_bytes())?;
        writer.write_all(&self.checksum.to_le_bytes())?;
        writer.write_all(&self.subsystem.to_le_bytes())?;
        writer.write_all(&self.dll_characteristics.to_le_bytes())?;

        // Write stack/heap size fields with appropriate size based on PE format
        if is_pe32_plus {
            // PE32+: 8-byte fields
            writer.write_all(&self.size_of_stack_reserve.to_le_bytes())?;
            writer.write_all(&self.size_of_stack_commit.to_le_bytes())?;
            writer.write_all(&self.size_of_heap_reserve.to_le_bytes())?;
            writer.write_all(&self.size_of_heap_commit.to_le_bytes())?;
        } else {
            // PE32: 4-byte fields
            writer.write_all(
                &u32::try_from(self.size_of_stack_reserve)
                    .map_err(|_| pe_invalid("stack_reserve_size", "exceeds u32 range".into()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_stack_commit)
                    .map_err(|_| pe_invalid("stack_commit_size", "exceeds u32 range".into()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_heap_reserve)
                    .map_err(|_| pe_invalid("heap_reserve_size", "exceeds u32 range".into()))?
                    .to_le_bytes(),
            )?;
            writer.write_all(
                &u32::try_from(self.size_of_heap_commit)
                    .map_err(|_| pe_invalid("heap_commit_size", "exceeds u32 range".into()))?
                    .to_le_bytes(),
            )?;
        }

        writer.write_all(&self.loader_flags.to_le_bytes())?;

        writer.write_all(&self.number_of_rva_and_sizes.to_le_bytes())?;

        Ok(())
    }
}

impl Default for DataDirectories {
    fn default() -> Self {
        Self::new()
    }
}

impl DataDirectories {
    /// Number of data directory entries (16 per PE specification).
    pub const COUNT: usize = 16;

    /// Size of data directories in bytes (128 bytes = 16 entries × 8 bytes each).
    pub const SIZE: usize = Self::COUNT * 8;

    /// Creates a new empty `DataDirectories` structure.
    ///
    /// Use [`Self::update_entry`] to populate individual directory entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            directories: HashMap::new(),
        }
    }

    /// Get CLR runtime header directory.
    #[must_use]
    pub fn get_clr_runtime_header(&self) -> Option<&DataDirectory> {
        self.directories.get(&DataDirectoryType::ClrRuntimeHeader)
    }

    /// Updates a data directory entry.
    ///
    /// This method allows updating specific data directory entries during write
    /// operations, such as updating the CLR runtime header when adding new metadata.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to update
    /// * `rva` - The new RVA (Relative Virtual Address) for the directory
    /// * `size` - The new size in bytes for the directory
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::{DataDirectories, DataDirectoryType};
    ///
    /// # let mut data_directories = DataDirectories::new();
    /// // Update CLR runtime header location
    /// data_directories.update_entry(
    ///     DataDirectoryType::ClrRuntimeHeader,
    ///     0x2000, // new RVA
    ///     72      // CLR header size
    /// );
    /// ```
    pub fn update_entry(&mut self, dir_type: DataDirectoryType, rva: u32, size: u32) {
        self.directories.insert(
            dir_type,
            DataDirectory {
                virtual_address: rva,
                size,
            },
        );
    }

    /// Updates the CLR runtime header data directory entry.
    ///
    /// This is a convenience method specifically for updating the CLR runtime header
    /// directory entry, which is commonly done during .NET assembly write operations.
    ///
    /// # Arguments
    /// * `rva` - The new RVA for the CLR runtime header
    /// * `size` - The new size of the CLR runtime header (typically 72 bytes)
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::DataDirectories;
    ///
    /// # let mut data_directories = DataDirectories::new();
    /// // Update CLR header to point to new location
    /// data_directories.update_clr_entry(0x2000, 72);
    /// ```
    pub fn update_clr_entry(&mut self, rva: u32, size: u32) {
        self.update_entry(DataDirectoryType::ClrRuntimeHeader, rva, size);
    }

    fn from_goblin(goblin_dd: &goblin::pe::data_directories::DataDirectories) -> Self {
        let mut directories = HashMap::new();

        // Convert goblin data directories to our owned format
        // Note: We avoid using goblin_dd.dirs() because it can panic on malformed files
        // with invalid data directory indices. Instead, we manually iterate through
        // the valid range and handle errors gracefully.
        for (i, opt_entry) in goblin_dd.data_directories.iter().enumerate() {
            if let Some((_, dir_entry)) = opt_entry {
                let dir_type = match i {
                    0 => DataDirectoryType::ExportTable,
                    1 => DataDirectoryType::ImportTable,
                    2 => DataDirectoryType::ResourceTable,
                    3 => DataDirectoryType::ExceptionTable,
                    4 => DataDirectoryType::CertificateTable,
                    5 => DataDirectoryType::BaseRelocationTable,
                    6 => DataDirectoryType::Debug,
                    7 => DataDirectoryType::Architecture,
                    8 => DataDirectoryType::GlobalPtr,
                    9 => DataDirectoryType::TlsTable,
                    10 => DataDirectoryType::LoadConfigTable,
                    11 => DataDirectoryType::BoundImport,
                    12 => DataDirectoryType::ImportAddressTable,
                    13 => DataDirectoryType::DelayImportDescriptor,
                    14 => DataDirectoryType::ClrRuntimeHeader,
                    15 => DataDirectoryType::Reserved,
                    _ => {
                        continue;
                    }
                };

                if dir_entry.virtual_address != 0 || dir_entry.size != 0 {
                    directories.insert(
                        dir_type,
                        DataDirectory {
                            virtual_address: dir_entry.virtual_address,
                            size: dir_entry.size,
                        },
                    );
                }
            }
        }

        Self { directories }
    }

    fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write all 16 data directory entries in order
        for i in 0..16 {
            let dir_type = match i {
                0 => DataDirectoryType::ExportTable,
                1 => DataDirectoryType::ImportTable,
                2 => DataDirectoryType::ResourceTable,
                3 => DataDirectoryType::ExceptionTable,
                4 => DataDirectoryType::CertificateTable,
                5 => DataDirectoryType::BaseRelocationTable,
                6 => DataDirectoryType::Debug,
                7 => DataDirectoryType::Architecture,
                8 => DataDirectoryType::GlobalPtr,
                9 => DataDirectoryType::TlsTable,
                10 => DataDirectoryType::LoadConfigTable,
                11 => DataDirectoryType::BoundImport,
                12 => DataDirectoryType::ImportAddressTable,
                13 => DataDirectoryType::DelayImportDescriptor,
                14 => DataDirectoryType::ClrRuntimeHeader,
                15 => DataDirectoryType::Reserved,
                _ => unreachable!(),
            };

            if let Some(entry) = self.directories.get(&dir_type) {
                writer.write_all(&entry.virtual_address.to_le_bytes())?;
                writer.write_all(&entry.size.to_le_bytes())?;
            } else {
                // Empty entry
                writer.write_all(&0u32.to_le_bytes())?; // virtual_address
                writer.write_all(&0u32.to_le_bytes())?; // size
            }
        }

        Ok(())
    }
}

impl SectionTable {
    /// Size of a section table entry in bytes (40 bytes per section).
    pub const SIZE: usize = 40;

    fn from_goblin(goblin_section: &goblin::pe::section_table::SectionTable) -> Result<Self> {
        let name = std::str::from_utf8(&goblin_section.name)
            .map_err(|_| ParseFailure::InvalidField {
                stage: ParseStage::SectionTable,
                field: "section_name",
                reason: "invalid UTF-8 in section name".into(),
            })?
            .trim_end_matches('\0')
            .to_string();

        Ok(Self {
            name,
            virtual_size: goblin_section.virtual_size,
            virtual_address: goblin_section.virtual_address,
            size_of_raw_data: goblin_section.size_of_raw_data,
            pointer_to_raw_data: goblin_section.pointer_to_raw_data,
            pointer_to_relocations: goblin_section.pointer_to_relocations,
            pointer_to_line_numbers: goblin_section.pointer_to_linenumbers,
            number_of_relocations: goblin_section.number_of_relocations,
            number_of_line_numbers: goblin_section.number_of_linenumbers,
            characteristics: goblin_section.characteristics,
        })
    }

    /// Calculates the total size required for a section table with the given number of sections.
    ///
    /// # Arguments
    /// * `section_count` - Number of sections in the table
    ///
    /// # Returns
    /// Total size in bytes for the section table
    #[must_use]
    pub fn calculate_table_size(section_count: usize) -> u64 {
        section_count.saturating_mul(Self::SIZE) as u64
    }

    /// Creates a SectionTable from layout information.
    ///
    /// This converts from the layout planning structures used during write operations
    /// back to the PE section table format.
    ///
    /// # Arguments
    /// * `name` - Section name
    /// * `virtual_address` - RVA where section is mapped
    /// * `virtual_size` - Virtual size of section in memory
    /// * `file_offset` - File offset where section data is stored
    /// * `file_size` - Size of section data in file
    /// * `characteristics` - Section characteristics flags
    ///
    /// # Returns
    /// A new SectionTable instance
    ///
    /// # Errors
    /// Returns an error if the file offset or size exceed u32 range
    pub fn from_layout_info(
        name: String,
        virtual_address: u32,
        virtual_size: u32,
        file_offset: u64,
        file_size: u64,
        characteristics: u32,
    ) -> Result<Self> {
        let size_of_raw_data = u32::try_from(file_size)
            .map_err(|_| pe_invalid("file_size", format!("exceeds u32 range: {file_size}")))?;
        let pointer_to_raw_data = u32::try_from(file_offset)
            .map_err(|_| pe_invalid("file_offset", format!("exceeds u32 range: {file_offset}")))?;

        Ok(Self {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations: 0,  // 0 for .NET assemblies
            pointer_to_line_numbers: 0, // 0 for .NET assemblies
            number_of_relocations: 0,   // 0 for .NET assemblies
            number_of_line_numbers: 0,  // 0 for .NET assemblies
            characteristics,
        })
    }

    /// Updates the virtual address and size of this section.
    ///
    /// # Arguments
    /// * `virtual_address` - New RVA where section is mapped
    /// * `virtual_size` - New virtual size of section in memory
    pub fn update_virtual_location(&mut self, virtual_address: u32, virtual_size: u32) {
        self.virtual_address = virtual_address;
        self.virtual_size = virtual_size;
    }

    /// Updates the file location and size of this section.
    ///
    /// # Arguments
    /// * `file_offset` - New file offset where section data is stored
    /// * `file_size` - New size of section data in file
    ///
    /// # Errors
    /// Returns an error if the file offset or size exceed u32 range
    pub fn update_file_location(&mut self, file_offset: u64, file_size: u64) -> Result<()> {
        self.pointer_to_raw_data = u32::try_from(file_offset)
            .map_err(|_| pe_invalid("file_offset", format!("exceeds u32 range: {file_offset}")))?;
        self.size_of_raw_data = u32::try_from(file_size)
            .map_err(|_| pe_invalid("file_size", format!("exceeds u32 range: {file_size}")))?;
        Ok(())
    }

    /// Updates the section characteristics flags.
    ///
    /// # Arguments
    /// * `characteristics` - New section characteristics flags
    pub fn update_characteristics(&mut self, characteristics: u32) {
        self.characteristics = characteristics;
    }

    /// Sets the section name.
    ///
    /// PE section names are limited to 8 bytes per the PE specification.
    /// This method validates the name length before setting it.
    ///
    /// # Arguments
    /// * `name` - New section name (must be 8 bytes or less)
    ///
    /// # Errors
    /// Returns an error if the name exceeds 8 bytes.
    pub fn set_name(&mut self, name: String) -> Result<()> {
        if name.len() > 8 {
            return Err(ParseFailure::InvalidField {
                stage: ParseStage::SectionTable,
                field: "section_name",
                reason: format!(
                    "section name '{name}' exceeds 8-byte PE limit ({} bytes)",
                    name.len()
                ),
            }
            .into());
        }
        self.name = name;
        Ok(())
    }

    /// Writes this section header to the writer.
    ///
    /// Each section header is 40 bytes and describes a section's location in both
    /// the file and virtual memory, along with its characteristics (readable,
    /// writable, executable, etc.).
    ///
    /// # Arguments
    ///
    /// * `writer` - The writer to output the section header to
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        // Write name (8 bytes, null-padded)
        let mut name_bytes = [0u8; 8];
        let name_str = self.name.as_bytes();
        let copy_len = std::cmp::min(name_str.len(), 8);
        if let (Some(dst), Some(src)) = (name_bytes.get_mut(..copy_len), name_str.get(..copy_len)) {
            dst.copy_from_slice(src);
        }
        writer.write_all(&name_bytes)?;

        writer.write_all(&self.virtual_size.to_le_bytes())?;
        writer.write_all(&self.virtual_address.to_le_bytes())?;
        writer.write_all(&self.size_of_raw_data.to_le_bytes())?;
        writer.write_all(&self.pointer_to_raw_data.to_le_bytes())?;
        writer.write_all(&self.pointer_to_relocations.to_le_bytes())?;
        writer.write_all(&self.pointer_to_line_numbers.to_le_bytes())?;
        writer.write_all(&self.number_of_relocations.to_le_bytes())?;
        writer.write_all(&self.number_of_line_numbers.to_le_bytes())?;
        writer.write_all(&self.characteristics.to_le_bytes())?;

        Ok(())
    }
}

impl Import {
    /// Get the function identifier for this import (name or ordinal)
    #[must_use]
    pub fn function_identifier(&self) -> String {
        if let Some(ref name) = self.name {
            name.clone()
        } else if let Some(ordinal) = self.ordinal {
            format!("#{ordinal}")
        } else {
            "unknown".to_string()
        }
    }
}

/// Represents an image resource directory header in the PE format.
///
/// This is the header structure at each level of the resource directory tree.
/// The resource directory is organized as a tree with up to 3 levels:
/// Type -> Name -> Language.
///
/// # Structure (16 bytes)
///
/// | Offset | Size | Field                    |
/// |--------|------|--------------------------|
/// | 0      | 4    | characteristics          |
/// | 4      | 4    | time_date_stamp          |
/// | 8      | 2    | major_version            |
/// | 10     | 2    | minor_version            |
/// | 12     | 2    | number_of_named_entries  |
/// | 14     | 2    | number_of_id_entries     |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageResourceDirectory {
    /// Resource flags (reserved, typically 0).
    pub characteristics: u32,
    /// Time/date stamp of resource creation.
    pub time_date_stamp: u32,
    /// Major version number.
    pub major_version: u16,
    /// Minor version number.
    pub minor_version: u16,
    /// Number of entries that use string names.
    pub number_of_named_entries: u16,
    /// Number of entries that use integer IDs.
    pub number_of_id_entries: u16,
}

impl ImageResourceDirectory {
    /// Reads an `ImageResourceDirectory` from a byte slice at the given offset.
    pub fn read_from(data: &[u8], offset: usize) -> Result<Self> {
        let mut pos = offset;
        Ok(Self {
            characteristics: read_le_at::<u32>(data, &mut pos)?,
            time_date_stamp: read_le_at::<u32>(data, &mut pos)?,
            major_version: read_le_at::<u16>(data, &mut pos)?,
            minor_version: read_le_at::<u16>(data, &mut pos)?,
            number_of_named_entries: read_le_at::<u16>(data, &mut pos)?,
            number_of_id_entries: read_le_at::<u16>(data, &mut pos)?,
        })
    }

    /// Returns the total number of entries (named + ID).
    #[inline]
    pub fn entry_count(&self) -> usize {
        (self.number_of_named_entries as usize).saturating_add(self.number_of_id_entries as usize)
    }

    /// Writes this `ImageResourceDirectory` to a byte slice at the given offset.
    pub fn write_to(&self, data: &mut [u8], offset: usize) -> Result<()> {
        let mut pos = offset;
        write_le_at::<u32>(data, &mut pos, self.characteristics)?;
        write_le_at::<u32>(data, &mut pos, self.time_date_stamp)?;
        write_le_at::<u16>(data, &mut pos, self.major_version)?;
        write_le_at::<u16>(data, &mut pos, self.minor_version)?;
        write_le_at::<u16>(data, &mut pos, self.number_of_named_entries)?;
        write_le_at::<u16>(data, &mut pos, self.number_of_id_entries)?;
        Ok(())
    }
}

/// Represents a resource directory entry in the PE format.
///
/// Each entry can point to either a subdirectory or a data entry.
///
/// # Structure (8 bytes)
///
/// | Offset | Size | Field                        |
/// |--------|------|------------------------------|
/// | 0      | 4    | name_or_id                   |
/// | 4      | 4    | offset_to_data_or_directory  |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceEntry {
    /// Either a string name offset (if high bit set) or an integer ID.
    pub name_or_id: u32,
    /// Offset to either a subdirectory (if high bit set) or a data entry.
    pub offset_to_data_or_directory: u32,
}

impl ResourceEntry {
    /// Reads a `ResourceEntry` from a byte slice at the given offset.
    pub fn read_from(data: &[u8], offset: usize) -> Result<Self> {
        let mut pos = offset;
        Ok(Self {
            name_or_id: read_le_at::<u32>(data, &mut pos)?,
            offset_to_data_or_directory: read_le_at::<u32>(data, &mut pos)?,
        })
    }

    /// Returns true if this entry points to a subdirectory.
    #[inline]
    #[must_use]
    pub fn is_directory(self) -> bool {
        self.offset_to_data_or_directory & constants::IMAGE_RESOURCE_DATA_IS_DIRECTORY != 0
    }

    /// Returns the offset to the target (directory or data entry).
    #[inline]
    #[must_use]
    pub fn target_offset(self) -> usize {
        (self.offset_to_data_or_directory & constants::IMAGE_RESOURCE_MASK) as usize
    }

    /// Writes this `ResourceEntry` to a byte slice at the given offset.
    pub fn write_to(self, data: &mut [u8], offset: usize) -> Result<()> {
        let mut pos = offset;
        write_le_at::<u32>(data, &mut pos, self.name_or_id)?;
        write_le_at::<u32>(data, &mut pos, self.offset_to_data_or_directory)?;
        Ok(())
    }
}

/// Represents a resource data entry (leaf node) in the PE format.
///
/// This structure contains the RVA pointing to actual resource data.
///
/// # Structure (16 bytes)
///
/// | Offset | Size | Field          |
/// |--------|------|----------------|
/// | 0      | 4    | offset_to_data | (RVA - needs relocation!)
/// | 4      | 4    | size           |
/// | 8      | 4    | code_page      |
/// | 12     | 4    | reserved       |
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceDataEntry {
    /// RVA to the actual resource data. This field needs relocation when the section moves.
    pub offset_to_data: u32,
    /// Size of the resource data in bytes.
    pub size: u32,
    /// Code page for character encoding.
    pub code_page: u32,
    /// Reserved (must be 0).
    pub reserved: u32,
}

impl ResourceDataEntry {
    /// Reads a `ResourceDataEntry` from a byte slice at the given offset.
    pub fn read_from(data: &[u8], offset: usize) -> Result<Self> {
        let mut pos = offset;
        Ok(Self {
            offset_to_data: read_le_at::<u32>(data, &mut pos)?,
            size: read_le_at::<u32>(data, &mut pos)?,
            code_page: read_le_at::<u32>(data, &mut pos)?,
            reserved: read_le_at::<u32>(data, &mut pos)?,
        })
    }

    /// Writes this `ResourceDataEntry` to a byte slice at the given offset.
    pub fn write_to(&self, data: &mut [u8], offset: usize) -> Result<()> {
        let mut pos = offset;
        write_le_at::<u32>(data, &mut pos, self.offset_to_data)?;
        write_le_at::<u32>(data, &mut pos, self.size)?;
        write_le_at::<u32>(data, &mut pos, self.code_page)?;
        write_le_at::<u32>(data, &mut pos, self.reserved)?;
        Ok(())
    }
}

/// Relocates resource section data when the section moves to a new virtual address.
///
/// The PE resource directory contains a tree structure where leaf nodes (`ResourceDataEntry`)
/// contain RVAs pointing to the actual resource data. When the resource section is moved
/// to a new location, these RVAs must be adjusted by the delta between the old and new
/// section virtual addresses.
///
/// # Arguments
///
/// * `data` - Mutable slice containing the resource section data
/// * `old_rva` - The original virtual address of the resource section
/// * `new_rva` - The new virtual address where the section will be placed
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if the resource directory is malformed.
///
/// # Resource Directory Structure
///
/// The resource directory is a tree with up to 3 levels (Type -> Name -> Language).
/// Each level consists of:
/// - `ImageResourceDirectory` header (16 bytes)
/// - Array of `ResourceEntry` structures (8 bytes each)
///
/// `ResourceEntry` can point to either:
/// - Another `ImageResourceDirectory` (if high bit of offset is set)
/// - A `ResourceDataEntry` leaf node (if high bit is clear)
///
/// Only `ResourceDataEntry::offset_to_data` contains an absolute RVA that needs relocation.
/// All other offsets in the directory are relative to the start of the resource section.
///
/// Entries can share a subdirectory or a data entry, or name a directory above them, as the
/// loader allows: each directory is walked and each data entry relocated once, however many
/// entries name it. Directories that overlap can name more entries than the section holds,
/// so the walk reads entries, counted per directory, up to the section's size.
pub fn relocate_resource_section(data: &mut [u8], old_rva: u32, new_rva: u32) -> Result<()> {
    if old_rva == new_rva || data.is_empty() {
        return Ok(()); // No relocation needed
    }

    // i64 has plenty of headroom for u32 - u32; checked_sub is overkill but
    // satisfies clippy's arithmetic_side_effects lint.
    let delta = i64::from(new_rva)
        .checked_sub(i64::from(old_rva))
        .ok_or_else(|| ParseFailure::InvalidField {
            stage: ParseStage::Resources,
            field: "rva_delta",
            reason: "resource RVA delta overflow".into(),
        })?;
    let res_invalid = |field: &'static str, reason: String| ParseFailure::InvalidField {
        stage: ParseStage::Resources,
        field,
        reason,
    };

    // The root directory is at offset 0
    let mut directories = HashSet::from([0usize]);
    let mut data_entries = HashSet::new();
    let mut pending = vec![0usize];
    let mut budget = data.len();
    while let Some(offset) = pending.pop() {
        let dir = ImageResourceDirectory::read_from(data, offset)?;
        let size = dir
            .entry_count()
            .checked_mul(RESOURCE_ENTRY_SIZE)
            .and_then(|entries| entries.checked_add(IMAGE_RESOURCE_DIRECTORY_SIZE))
            .ok_or_else(|| res_invalid("entry_count", "directory size overflow".into()))?;
        budget = budget.checked_sub(size).ok_or_else(|| {
            res_invalid(
                "entry_count",
                format!(
                    "the directories' entries, counted per directory, are more than the \
                     section's {} bytes",
                    data.len()
                ),
            )
        })?;
        let entries_offset = offset
            .checked_add(IMAGE_RESOURCE_DIRECTORY_SIZE)
            .ok_or_else(|| {
                res_invalid("entries_offset", "directory entries offset overflow".into())
            })?;

        for i in 0..dir.entry_count() {
            let scaled = i
                .checked_mul(RESOURCE_ENTRY_SIZE)
                .ok_or_else(|| res_invalid("entry_index", "entry index overflow".into()))?;
            let entry_offset = entries_offset
                .checked_add(scaled)
                .ok_or_else(|| res_invalid("entry_offset", "entry offset overflow".into()))?;
            let entry = ResourceEntry::read_from(data, entry_offset)?;
            let target = entry.target_offset();

            if entry.is_directory() {
                if directories.insert(target) {
                    pending.push(target);
                }
            } else if data_entries.insert(target) {
                // A ResourceDataEntry: its RVA is its first 4 bytes
                let mut pos = target;
                let old_data_rva: u32 = read_le_at(data, &mut pos)?;
                let new_data_rva = u32::try_from(i64::from(old_data_rva).saturating_add(delta))
                    .map_err(|_| {
                        res_invalid(
                            "rva",
                            format!(
                                "RVA relocation overflow: old_rva={old_data_rva:#x}, delta={delta}",
                            ),
                        )
                    })?;
                let mut pos = target;
                write_le_at::<u32>(data, &mut pos, new_data_rva)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u32(data: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
    }

    /// A directory at `offset` whose id entries name `targets`, each a subdirectory when
    /// its flag is set.
    fn directory(data: &mut [u8], offset: usize, targets: &[(usize, bool)]) {
        put_u16(data, offset + 14, u16::try_from(targets.len()).unwrap());
        for (index, &(target, is_directory)) in targets.iter().enumerate() {
            let entry = offset + 16 + index * 8;
            put_u32(data, entry, u32::try_from(index).unwrap() + 1);
            let flag = if is_directory { 0x8000_0000 } else { 0 };
            put_u32(data, entry + 4, flag | u32::try_from(target).unwrap());
        }
    }

    /// Two entries naming one data entry move it once, not by twice the delta.
    #[test]
    fn a_shared_data_entry_is_relocated_once() {
        let mut data = vec![0u8; 0x100];
        directory(&mut data, 0, &[(0x40, false), (0x40, false)]);
        put_u32(&mut data, 0x40, 0x2010);
        relocate_resource_section(&mut data, 0x2000, 0x5000).unwrap();
        assert_eq!(get_u32(&data, 0x40), 0x5010);
    }

    /// Two entries naming one subdirectory walk it once: its data entries move once.
    #[test]
    fn a_shared_subdirectory_is_walked_once() {
        let mut data = vec![0u8; 0x100];
        directory(&mut data, 0, &[(0x40, true), (0x40, true)]);
        directory(&mut data, 0x40, &[(0x80, false)]);
        put_u32(&mut data, 0x80, 0x2010);
        relocate_resource_section(&mut data, 0x2000, 0x5000).unwrap();
        assert_eq!(get_u32(&data, 0x80), 0x5010);
    }

    /// An entry naming a directory above it ends the walk there.
    #[test]
    fn a_directory_cycle_ends() {
        let mut data = vec![0u8; 0x100];
        directory(&mut data, 0, &[(0x40, true)]);
        directory(&mut data, 0x40, &[(0, true), (0x80, false)]);
        put_u32(&mut data, 0x80, 0x2010);
        relocate_resource_section(&mut data, 0x2000, 0x5000).unwrap();
        assert_eq!(get_u32(&data, 0x80), 0x5010);
    }

    /// A chain of directories whose two entries both name the next one is 2^depth paths to
    /// its leaf: walked once per directory, the leaf moves once, deeper than any depth cap.
    #[test]
    fn a_doubling_chain_is_walked_once_per_directory() {
        let depth = 40;
        let mut data = vec![0u8; 0x20 * (depth + 2)];
        let leaf = 0x20 * (depth + 1);
        for level in 0..depth {
            let next = 0x20 * (level + 1);
            if level + 1 == depth {
                directory(&mut data, 0x20 * level, &[(leaf, false), (leaf, false)]);
            } else {
                directory(&mut data, 0x20 * level, &[(next, true), (next, true)]);
            }
        }
        put_u32(&mut data, leaf, 0x2010);
        relocate_resource_section(&mut data, 0x2000, 0x5000).unwrap();
        assert_eq!(get_u32(&data, leaf), 0x5010);
    }

    /// Directories that overlap one another name more entries than the section holds: the
    /// walk stops at the section's size and says so, rather than reading each in full.
    #[test]
    fn overlapping_directories_are_bounded_by_the_section() {
        let count = 1000;
        let start = 0x3000;
        // From `start`, every 8 bytes read as a directory header of 0x2000 named entries,
        // each a data entry at 0x2000
        let len = start + 8 * count + 16 + 8 * 0x2000;
        let mut data = vec![0u8; len];
        let mut offset = start;
        while offset + 8 <= len {
            put_u32(&mut data, offset + 4, 0x2000);
            offset += 8;
        }
        let targets: Vec<_> = (0..count).map(|j| (start + 8 * j, true)).collect();
        directory(&mut data, 0, &targets);

        let error = relocate_resource_section(&mut data, 0x2000, 0x5000).unwrap_err();
        assert!(
            error.to_string().contains("more than the section's"),
            "{error}"
        );
    }
}
