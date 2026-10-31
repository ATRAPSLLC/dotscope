//! PE file abstraction and .NET binary parsing.
//!
//! This module provides comprehensive support for parsing and analyzing Portable Executable (PE)
//! files containing .NET assemblies. It abstracts over different data sources (files, memory)
//! and provides ergonomic access to PE structures, .NET metadata, and binary data.
//!
//! # Architecture
//!
//! The module is built around several key components that work together to provide
//! comprehensive PE file analysis capabilities:
//!
//! - **File abstraction layer** - Unified interface for PE file access backed by CowFile
//! - **PE format parsing** - Complete PE/COFF structure analysis
//! - **Address translation** - RVA to file offset conversion
//! - **Data directory access** - Direct access to PE data directories
//! - **Transparent PE repair** - Automatic fix of corrupted PE headers during loading
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::file::File`] - Main PE file abstraction with .NET-specific functionality
//!
//! ## Parsing Infrastructure
//! - [`crate::file::parser::Parser`] - High-level parsing interface for metadata extraction
//! - [`crate::file::io`] - Low-level I/O utilities for reading PE structures
//!
//! # Data Sources
//!
//! The module supports multiple data sources via `CowFile` (copy-on-write):
//! - **Physical files** - Memory-mapped files for zero-copy disk access
//! - **Memory buffers** - In-memory PE data for dynamic analysis
//!
//! # PE Format Support
//!
//! Supports both PE32 and PE32+ formats with:
//! - DOS header and PE signature parsing
//! - COFF header and optional header extraction
//! - Section table parsing and virtual address resolution
//! - Data directory access (Import, Export, .NET metadata, etc.)
//! - RVA to file offset translation
//!
//! # Examples
//!
//! ## Loading from File
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::{borrow::Cow, path::Path};
//!
//! // Load a .NET assembly from disk
//! let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//! println!("Loaded PE file with {} bytes", file.len());
//!
//! // Access PE headers
//! println!("Image base: 0x{:x}", file.imagebase());
//! println!("Number of sections: {}", file.sections().len());
//!
//! // Access .NET metadata location
//! let Some((clr_rva, clr_size)) = file.clr() else {
//!     panic!("No CLR header found");
//! };
//! println!("CLR header at RVA 0x{:x}, size: {} bytes", clr_rva, clr_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Loading from Memory
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::fs;
//!
//! // Load assembly data into memory
//! let data = fs::read("tests/samples/WindowsBase.dll")?;
//! let file = File::from_mem(data)?;
//!
//! // Same API as file-based loading
//! println!("Assembly size: {} bytes", file.len());
//!
//! // Find specific sections
//! for section in file.sections() {
//!     let name = section.name.trim_end_matches('\0');
//!     if name == ".text" {
//!         println!("Code section at RVA 0x{:x}", section.virtual_address);
//!         break;
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Address Translation
//!
//! ```rust,no_run
//! use dotscope::File;
//! use std::path::Path;
//!
//! let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//!
//! // Convert CLR header RVA to file offset
//! let Some((clr_rva, _)) = file.clr() else {
//!     panic!("No CLR header found");
//! };
//! let clr_offset = file.rva_to_offset(clr_rva)?;
//!
//! // Read CLR header data
//! let clr_data = file.data_slice(clr_offset, 72)?; // CLR header is 72 bytes
//! println!("CLR header starts with: {:02x?}", &clr_data[0..8]);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//!
//! # Thread Safety
//!
//! All components are designed to be thread-safe and can be shared across threads
//! for concurrent analysis of the same PE file.
//!
//! # References
//!
//! - Microsoft PE/COFF Specification
//! - ECMA-335 6th Edition, Partition II - PE File Format

pub mod debug;
mod native;
pub mod parser;
pub mod pe;
pub mod repair;
pub mod sectionmap;

use std::{borrow::Cow, path::Path};

use cowfile::CowFile;
use goblin::pe::{
    options::{ParseMode, ParseOptions},
    PE,
};
use pe::{DataDirectory, DataDirectoryType, Pe};

use crate::{
    file::{
        pe::constants::COR20_HEADER_SIZE,
        repair::{repair_pe_cow, RepairAction},
        sectionmap::{RvaMapping, SectionMap},
    },
    utils::align_to,
    Error::{self, LayoutFailed, Other},
    ParseFailure, ParseStage, Result,
};

/// Represents a loaded PE file.
///
/// This struct can load both .NET assemblies and native PE files. Use [`File::is_clr()`]
/// to check if the file contains .NET metadata.
///
/// This struct contains the parsed PE information and provides methods for accessing headers,
/// sections, data directories, and for converting between address spaces. It supports loading
/// from both files and memory buffers.
///
/// The `File` struct is the main entry point for working with PE files. It can load both
/// .NET assemblies and native PE executables/DLLs. Use [`File::is_clr()`] or [`File::clr()`]
/// to determine if the loaded file contains .NET metadata.
///
/// # Examples
///
/// ## Loading and checking for .NET metadata
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::path::Path;
///
/// let file = File::from_path(Path::new("example.exe"))?;
/// println!("Loaded PE with {} sections", file.sections().len());
///
/// // Check if it's a .NET assembly
/// if file.is_clr() {
///     let (clr_rva, clr_size) = file.clr().unwrap();
///     println!(".NET assembly - CLR at RVA 0x{:x}, size={}", clr_rva, clr_size);
/// } else {
///     println!("Native PE executable (no .NET metadata)");
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Loading from memory
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::fs;
///
/// let data = fs::read("assembly.dll")?;
/// let file = File::from_mem(data)?;
///
/// // Access CLR metadata if present
/// if let Some((clr_rva, clr_size)) = file.clr() {
///     println!("CLR header at RVA 0x{:x}, {} bytes", clr_rva, clr_size);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Working with addresses
///
/// ```rust,no_run
/// use dotscope::File;
/// use std::path::Path;
///
/// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
///
/// // Convert between address spaces
/// let entry_rva = file.header_optional().as_ref().unwrap()
///     .standard_fields.address_of_entry_point as usize;
/// let entry_offset = file.rva_to_offset(entry_rva)?;
///
/// // Read entry point code
/// let entry_code = file.data_slice(entry_offset, 16)?;
/// println!("Entry point bytes: {:02x?}", entry_code);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct File {
    /// The underlying data via CowFile (mmap or CoW mmap), committed and read-only.
    data: CowFile,
    /// The parsed PE structure as owned data.
    pe: Pe,
    /// PE repairs applied during loading (empty if none needed).
    repairs: Vec<RepairAction>,
}

impl File {
    /// Loads a PE file from the given path.
    ///
    /// This method opens a file from disk and parses it as a PE file.
    /// The file is memory-mapped for efficient access. Works with both .NET assemblies
    /// and native PE executables/DLLs.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PE file on disk. Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read or opened
    /// - The file is not a valid PE format
    /// - The file is empty
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// // With Path
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // With string slice
    /// let file = File::from_path("tests/samples/WindowsBase.dll")?;
    ///
    /// println!("Loaded {} bytes with {} sections",
    ///          file.len(), file.sections().len());
    ///
    /// // Check if it's a .NET assembly
    /// if let Some((clr_rva, clr_size)) = file.clr() {
    ///     println!("CLR runtime header: RVA=0x{:x}, size={}", clr_rva, clr_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_path(path: impl AsRef<Path>) -> Result<File> {
        let cowfile = CowFile::open(path)?;
        Self::load(cowfile)
    }

    /// Loads a PE file from a memory buffer.
    ///
    /// This method parses a PE file that's already loaded into memory.
    /// Useful when working with embedded resources or downloaded files.
    /// Works with both .NET assemblies and native PE executables/DLLs.
    ///
    /// # Arguments
    ///
    /// * `data` - The bytes of the PE file.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The buffer is empty
    /// - The data is not a valid PE format
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::fs;
    ///
    /// // Load from downloaded or embedded data
    /// let data = fs::read("tests/samples/WindowsBase.dll")?;
    /// let file = File::from_mem(data)?;
    ///
    /// // Inspect the assembly
    /// println!("Assembly size: {} bytes", file.len());
    /// println!("Image base: 0x{:x}", file.imagebase());
    ///
    /// // Find specific sections
    /// for section in file.sections() {
    ///     let name = section.name.trim_end_matches('\0');
    ///     if name == ".text" {
    ///         println!("Code section at RVA 0x{:x}", section.virtual_address);
    ///         break;
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_mem(data: Vec<u8>) -> Result<File> {
        let cowfile = CowFile::from_vec(data);
        Self::load(cowfile)
    }

    /// Creates a File from an opened std::fs::File.
    ///
    /// The file is memory-mapped for efficient access. This is useful when you already have
    /// a file handle open with specific permissions or from a special location.
    ///
    /// # Arguments
    /// * `file` - An opened file handle
    ///
    /// # Errors
    /// Returns an error if:
    /// - The file cannot be memory-mapped
    /// - The data is not a valid PE format
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::fs::File as StdFile;
    ///
    /// let std_file = StdFile::open("assembly.dll")?;
    /// let pe_file = File::from_std_file(std_file)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_std_file(file: std::fs::File) -> Result<File> {
        let cowfile = CowFile::from_file(file)?;
        Self::load(cowfile)
    }

    /// Creates a File from any type implementing Read.
    ///
    /// This is the most flexible constructor, allowing Files to be created from
    /// network streams, archives, cursors, or any custom reader.
    ///
    /// # Arguments
    /// * `reader` - Any type implementing Read
    ///
    /// # Errors
    /// Returns an error if:
    /// - The reader cannot be read
    /// - The data is not a valid PE format
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::io::Cursor;
    ///
    /// let data = vec![/* PE bytes */];
    /// let cursor = Cursor::new(data);
    /// let file = File::from_reader(cursor)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_reader<R: std::io::Read>(mut reader: R) -> Result<File> {
        let mut data = Vec::new();
        reader
            .read_to_end(&mut data)
            .map_err(|e| Other(format!("Failed to read from reader: {e}")))?;
        Self::from_mem(data)
    }

    /// Internal loader with transparent PE repair.
    ///
    /// Attempts to parse the PE file. If parsing fails, applies known PE
    /// repairs (BitMono, BitDotNet, etc.) via the CowFile pending log, commits
    /// the pending writes to the buffer, and retries.
    ///
    /// # Arguments
    ///
    /// * `cowfile` - The CowFile providing the PE data.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is empty or not a valid PE format
    /// (even after repair attempts).
    fn load(mut cowfile: CowFile) -> Result<File> {
        if cowfile.is_empty() {
            return Err(Error::NotSupported);
        }

        // ToDo: For MONO, the .NET CIL part is embedded into an ELF as an actual valid PE file.
        //       To support MONO, we'll need to parse the ELF file here, and extract the PE structure that this `File`
        //       is then pointing to

        // Always attempt PE repair proactively. Some obfuscators (e.g., BitMono's
        // BitDecompiler) corrupt CLR headers that goblin's PE::parse() does not
        // validate, so we must repair before parsing - not just on failure.
        let repair_result = repair_pe_cow(&cowfile);
        if !repair_result.repairs.is_empty() {
            cowfile.commit()?;
        }

        // Resources are parsed off. Nothing here reads them: `Pe::from_goblin_pe`
        // takes the headers, sections and data directories, and a .NET assembly's
        // own resources live in the managed metadata (`ManifestResource` / the
        // `.resources` streams), not in the PE resource directory. What the directory does hold for an assembly is
        // `VS_VERSIONINFO`, dialogs and string tables - and goblin walks that
        // tree in `ParseMode::Strict` by default, so one malformed
        // `ResourceString` in any of it aborts the whole parse and takes every
        // bit of CIL metadata with it. The relocation-side directory walk this
        // crate needs is its own, in `file::pe`. Imports are parsed off too: the
        // import table is read entry by entry in `file::native`, which records what
        // it cannot read instead of failing the load over it.
        //
        // And the rest of goblin's walk is permissive: this crate takes only the
        // headers, the sections and the data directories from it
        // (`Pe::from_goblin_pe`), so a malformed part it does not read - a base
        // relocation table that runs past the end of the file, a debug directory,
        // TLS data, a certificate table - is dropped by goblin instead of
        // failing the load, where strict parsing took the whole of the CIL
        // metadata with it. The headers and sections still parse strictly.
        let opts = ParseOptions::default()
            .with_parse_resources(false)
            .with_parse_imports(false)
            .with_parse_mode(ParseMode::Permissive);
        let goblin_pe = PE::parse_with_opts(cowfile.data(), &opts).map_err(Error::from)?;
        let pe = Pe::from_goblin_pe(&goblin_pe, cowfile.data())?;

        Ok(File {
            data: cowfile,
            pe,
            repairs: repair_result.repairs,
        })
    }

    /// Returns the total size of the loaded file in bytes.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// println!("File size: {} bytes", file.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the file has a length of zero.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// assert!(!file.is_empty()); // Valid PE files are never empty
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the original file path if the CowFile was opened from disk.
    ///
    /// Returns `None` for memory-backed assemblies or those loaded via [`from_mem`](File::from_mem).
    #[must_use]
    pub fn source_path(&self) -> Option<&Path> {
        self.data.source_path()
    }

    /// Creates an independent fork of the underlying CowFile.
    ///
    /// For file-backed assemblies, this re-opens the original file via a new
    /// `MAP_PRIVATE` mmap - zero-copy, OS shares physical read pages.
    /// For memory-backed assemblies, this clones the data.
    ///
    /// Pending writes (PE repairs) are **not** carried over.
    pub fn fork_cowfile(&self) -> Result<CowFile> {
        self.data.fork().map_err(|e| Error::Other(e.to_string()))
    }

    /// Returns the image base address of the loaded PE file.
    ///
    /// The image base is the preferred virtual address where the PE file
    /// should be loaded in memory. This is used for calculating virtual addresses.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let base = file.imagebase();
    /// println!("Image base: 0x{:x}", base);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn imagebase(&self) -> u64 {
        self.pe.image_base
    }

    /// Returns a reference to the COFF header.
    ///
    /// The COFF header contains essential metadata about the executable,
    /// including the machine type, number of sections, and timestamp.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let header = file.header();
    /// println!("Machine type: 0x{:x}", header.machine);
    /// println!("Number of sections: {}", header.number_of_sections);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header(&self) -> &pe::CoffHeader {
        &self.pe.coff_header
    }

    /// Returns a reference to the DOS header.
    ///
    /// The DOS header is the first part of a PE file and contains the DOS stub
    /// that displays the "This program cannot be run in DOS mode" message.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let dos_header = file.header_dos();
    /// println!("DOS signature: 0x{:x}", dos_header.signature);
    /// println!("Number of bytes on last page: {}", dos_header.bytes_on_last_page);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header_dos(&self) -> &pe::DosHeader {
        &self.pe.dos_header
    }

    /// Returns a reference to the optional header, if present.
    ///
    /// This is always `Some` for valid .NET assemblies since they require
    /// an optional header to define data directories and other metadata.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let optional_header = file.header_optional().as_ref().unwrap();
    /// println!("Entry point: 0x{:x}", optional_header.standard_fields.address_of_entry_point);
    /// println!("Subsystem: {:?}", optional_header.windows_fields.subsystem);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn header_optional(&self) -> &Option<pe::OptionalHeader> {
        // We have verified the existence of the optional_header during the initial load.
        &self.pe.optional_header
    }

    /// Returns the RVA and size of the CLR runtime header, if present.
    ///
    /// The CLR runtime header contains metadata about the .NET runtime,
    /// including pointers to metadata tables and other runtime structures.
    ///
    /// # Returns
    ///
    /// - `Some((rva, size))` if this PE file contains a CLR runtime header (.NET assembly)
    /// - `None` if this is a native PE file without .NET metadata
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.exe"))?;
    /// match file.clr() {
    ///     Some((rva, size)) => println!(".NET assembly: CLR at RVA 0x{:x}", rva),
    ///     None => println!("Native PE file (no .NET metadata)"),
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn clr(&self) -> Option<(usize, usize)> {
        self.pe
            .get_clr_runtime_header()
            .map(|clr_dir| (clr_dir.virtual_address as usize, clr_dir.size as usize))
    }

    /// Returns true if this PE file contains a CLR runtime header (.NET assembly).
    ///
    /// This is a convenience method equivalent to `file.clr().is_some()`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.exe"))?;
    /// if file.is_clr() {
    ///     println!("This is a .NET assembly");
    /// } else {
    ///     println!("This is a native PE file");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_clr(&self) -> bool {
        self.clr().is_some()
    }

    /// Returns a slice of the section headers of the PE file.
    ///
    /// Sections contain the actual code and data of the PE file, such as
    /// `.text` (executable code), `.data` (initialized data), and `.rsrc` (resources).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for section in file.sections() {
    ///     println!("Section: {} at RVA 0x{:x}, size: {} bytes",
    ///              section.name, section.virtual_address, section.virtual_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn sections(&self) -> &[pe::SectionTable] {
        &self.pe.sections
    }

    /// Returns the data directories of the PE file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// for (dir_type, directory) in file.directories() {
    ///     println!("Directory: {:?}, RVA: 0x{:x}", dir_type, directory.virtual_address);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn directories(&self) -> Vec<(DataDirectoryType, DataDirectory)> {
        // We have verified the existence of the optional_header during the initial load.
        self.pe
            .data_directories
            .iter()
            .map(|(&dir_type, &dir)| (dir_type, dir))
            .collect()
    }

    /// Returns the RVA and size of a specific data directory entry.
    ///
    /// This method provides unified access to PE data directory entries by type.
    /// It returns the virtual address and size if the directory exists and is valid,
    /// or `None` if the directory doesn't exist or has zero address/size.
    ///
    /// # Arguments
    /// * `dir_type` - The type of data directory to retrieve
    ///
    /// # Returns
    /// - `Some((rva, size))` if the directory exists with non-zero address and size
    /// - `None` if the directory doesn't exist or has zero address/size
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use dotscope::DataDirectoryType;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.dll"))?;
    ///
    /// // Check for import table
    /// if let Some((import_rva, import_size)) = file.get_data_directory(DataDirectoryType::ImportTable) {
    ///     println!("Import table at RVA 0x{:x}, size: {} bytes", import_rva, import_size);
    /// }
    ///
    /// // Check for export table
    /// if let Some((export_rva, export_size)) = file.get_data_directory(DataDirectoryType::ExportTable) {
    ///     println!("Export table at RVA 0x{:x}, size: {} bytes", export_rva, export_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_data_directory(&self, dir_type: DataDirectoryType) -> Option<(u32, u32)> {
        self.pe
            .get_data_directory(dir_type)
            .filter(|directory| directory.virtual_address != 0 && directory.size != 0)
            .map(|directory| (directory.virtual_address, directory.size))
    }

    /// Returns the parsed import data from the PE file.
    ///
    /// Uses goblin's PE parsing to extract import table information including
    /// DLL dependencies and imported functions. Returns the parsed import data
    /// if an import directory exists.
    ///
    /// # Returns
    /// - `Some(imports)` if import directory exists and was successfully parsed
    /// - `None` if no import directory exists or parsing failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.dll"))?;
    /// if let Some(imports) = file.imports() {
    ///     for import in imports {
    ///         println!("DLL: {}", import.dll);
    ///         if let Some(ref name) = import.name {
    ///             if !name.is_empty() {
    ///                 println!("  Function: {}", name);
    ///             }
    ///         } else if let Some(ordinal) = import.ordinal {
    ///             println!("  Ordinal: {}", ordinal);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn imports(&self) -> Option<&Vec<pe::Import>> {
        if self.pe.imports.is_empty() {
            None
        } else {
            Some(&self.pe.imports)
        }
    }

    /// Returns the parsed export data from the PE file.
    ///
    /// Uses goblin's PE parsing to extract export table information including
    /// exported functions and their addresses. Returns the parsed export data
    /// if an export directory exists.
    ///
    /// # Returns
    /// - `Some(exports)` if export directory exists and was successfully parsed
    /// - `None` if no export directory exists or parsing failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.dll"))?;
    /// if let Some(exports) = file.exports() {
    ///     for export in exports {
    ///         if let Some(name) = &export.name {
    ///             println!("Export: {} -> 0x{:X}", name, export.rva);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn exports(&self) -> Option<&Vec<pe::Export>> {
        if self.pe.exports.is_empty() {
            None
        } else {
            Some(&self.pe.exports)
        }
    }

    /// Returns the raw data of the loaded file.
    ///
    /// This provides access to the entire PE file contents as a byte slice.
    /// Useful for reading specific offsets or when you need direct access
    /// to the binary data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let data = file.data();
    ///
    /// // Check DOS signature (MZ)
    /// assert_eq!(&data[0..2], b"MZ");
    ///
    /// // Access PE signature offset
    /// let pe_offset = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    /// assert_eq!(&data[pe_offset..pe_offset + 4], b"PE\0\0");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.data.data()
    }

    /// Consumes the `File` and returns the underlying `CowFile`.
    #[must_use]
    pub fn into_cowfile(self) -> CowFile {
        self.data
    }

    /// Queues a byte patch at the given file offset.
    ///
    /// Uses the underlying `CowFile`'s interior-mutable pending-write log.
    /// Patches are not visible via `data()` until `commit_pending()` is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset + data length exceeds the file size.
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<()> {
        self.data.write(offset, data).map_err(Into::into)
    }

    /// Queues a little-endian primitive patch at the given file offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset is out of bounds.
    pub fn write_le<T: cowfile::Primitive>(&self, offset: usize, value: T) -> Result<()> {
        self.data.write_le(offset, value).map_err(Into::into)
    }

    /// Reads a little-endian primitive from the committed file data.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset is out of bounds.
    pub fn read_le<T: cowfile::Primitive>(&self, offset: usize) -> Result<T> {
        self.data.read_le(offset).map_err(Into::into)
    }

    /// Returns `true` if there are uncommitted pending byte patches.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.data.has_pending()
    }

    /// Applies all pending byte patches in-place to the committed data.
    ///
    /// After this call, `data()` reflects the patched bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if a patch is out of bounds.
    pub fn commit_pending(&mut self) -> Result<()> {
        self.data.commit().map_err(Into::into)
    }

    /// Returns a slice of the file data at the given offset and length.
    ///
    /// This is a safe way to access specific portions of the PE file data
    /// with bounds checking to prevent buffer overflows.
    ///
    /// # Arguments
    ///
    /// * `offset` - The offset to start the slice from.
    /// * `len` - The length of the slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the requested range is out of bounds.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Read the DOS header (first 64 bytes)
    /// let dos_header = file.data_slice(0, 64)?;
    /// assert_eq!(&dos_header[0..2], b"MZ");
    ///
    /// // Read PE signature
    /// let pe_offset = u32::from_le_bytes([dos_header[60], dos_header[61],
    ///                                     dos_header[62], dos_header[63]]) as usize;
    /// let pe_sig = file.data_slice(pe_offset, 4)?;
    /// assert_eq!(pe_sig, b"PE\0\0");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn data_slice(&self, offset: usize, len: usize) -> Result<&[u8]> {
        let base = self.data.data();
        let oob = || ParseFailure::OutOfBounds {
            stage: ParseStage::DataDirectory,
        };
        let end = offset.checked_add(len).ok_or_else(|| Error::from(oob()))?;
        base.get(offset..end).ok_or_else(|| Error::from(oob()))
    }

    /// Converts a virtual address (VA) to a file offset.
    ///
    /// Virtual addresses are absolute addresses where the PE file would be
    /// loaded in memory. This method converts them to file offsets for
    /// reading data from the actual file.
    ///
    /// # Arguments
    ///
    /// * `va` - The virtual address to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA is out of bounds or cannot be mapped.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Convert entry point VA to file offset
    /// let entry_point_va = file.header_optional().as_ref().unwrap().standard_fields.address_of_entry_point as usize;
    /// let image_base = file.imagebase() as usize;
    /// let full_va = image_base + entry_point_va;
    ///
    /// let offset = file.va_to_offset(full_va)?;
    /// println!("Entry point at file offset: 0x{:x}", offset);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn va_to_offset(&self, va: usize) -> Result<usize> {
        let ib = self.imagebase();
        let rva_u64 = (va as u64).checked_sub(ib).ok_or_else(|| {
            Error::from(ParseFailure::OutOfBounds {
                stage: ParseStage::DataDirectory,
            })
        })?;
        let rva = usize::try_from(rva_u64).map_err(|_| ParseFailure::InvalidField {
            stage: ParseStage::DataDirectory,
            field: "rva",
            reason: format!("RVA too large to fit in usize: {rva_u64}"),
        })?;
        self.rva_to_offset(rva)
    }

    /// Converts a relative virtual address (RVA) to a file offset.
    ///
    /// RVAs are addresses relative to the image base. This is the most common
    /// address format used within PE files for referencing data and code. An RVA has a file
    /// offset when it lies in a section's raw data within the section's `VirtualSize` (see
    /// [`SectionMap`]); to read bytes at an RVA, use [`File::rva_slice`] or
    /// [`File::section_bounded`], which keep the read inside the section and give the zeros
    /// of its zero-filled part.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the RVA has no file offset: it lies past its section's
    /// `VirtualSize`, in its zero-filled part, or in no section.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Convert CLR header RVA to file offset
    /// let Some((clr_rva, _)) = file.clr() else {
    ///     panic!("No CLR header found");
    /// };
    /// let clr_offset = file.rva_to_offset(clr_rva)?;
    ///
    /// // Read CLR header data
    /// let clr_data = file.data_slice(clr_offset, 72)?; // CLR header is 72 bytes
    /// println!("CLR header starts with: {:02x?}", &clr_data[0..8]);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn rva_to_offset(&self, rva: usize) -> Result<usize> {
        let invalid = |reason: String| ParseFailure::InvalidField {
            stage: ParseStage::SectionTable,
            field: "rva",
            reason,
        };
        let rva_u32 = u32::try_from(rva)
            .map_err(|_| invalid(format!("RVA too large to fit in u32: {rva}")))?;
        match self.section_map().map(rva_u32) {
            RvaMapping::File(offset) => Ok(offset),
            RvaMapping::ZeroFill => Err(invalid(format!(
                "RVA {rva:#x} is in a section's zero-filled part, which the file does not hold"
            ))
            .into()),
            RvaMapping::Unmapped => {
                Err(invalid(format!("RVA {rva:#x} is not a byte the image defines")).into())
            }
        }
    }

    /// The image's RVA mapping: each section's `VirtualSize` bytes, its raw data then zeros
    /// (see [`SectionMap`]).
    #[must_use]
    pub fn section_map(&self) -> SectionMap<'_> {
        SectionMap::new(&self.pe.sections, self.data().len())
    }

    /// The `len` bytes the loaded image holds at `rva`, within one section:
    /// borrowed from the file, or with the zeros of a section's zero-filled part.
    ///
    /// # Errors
    ///
    /// When a byte of the range is not the image's: past its section's `VirtualSize`, or
    /// raw data the file lacks.
    pub fn rva_slice(&self, rva: usize, len: usize) -> Result<Cow<'_, [u8]>> {
        let rva = u32::try_from(rva).map_err(|_| ParseFailure::InvalidField {
            stage: ParseStage::SectionTable,
            field: "rva",
            reason: format!("RVA too large to fit in u32: {rva}"),
        })?;
        self.section_map().read(self.data(), rva, len)
    }

    /// The file bytes from `rva` to the end of what the file holds of its section, within the
    /// section's `VirtualSize`: where a structure of unknown length, such as a method body, is
    /// read from.
    ///
    /// # Errors
    ///
    /// When `rva` is not a byte of the image.
    pub fn section_bounded(&self, rva: usize) -> Result<&[u8]> {
        let rva = u32::try_from(rva).map_err(|_| ParseFailure::InvalidField {
            stage: ParseStage::SectionTable,
            field: "rva",
            reason: format!("RVA too large to fit in u32: {rva}"),
        })?;
        self.section_map().section_bounded(self.data(), rva)
    }

    /// Converts a file offset to a relative virtual address (RVA).
    ///
    /// This is the inverse of `rva_to_offset()`. Given a file offset,
    /// it calculates what RVA that offset corresponds to when the
    /// PE file is loaded in memory.
    ///
    /// # Arguments
    ///
    /// * `offset` - The file offset to convert.
    ///
    /// # Errors
    ///
    /// Returns an error if the offset is not loaded: it is in no section's raw data within
    /// the section's `VirtualSize`.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    ///
    /// // Find what RVA corresponds to file offset 0x1000
    /// let rva = file.offset_to_rva(0x1000)?;
    /// println!("File offset 0x1000 maps to RVA 0x{:x}", rva);
    ///
    /// // Verify round-trip conversion
    /// let back_to_offset = file.rva_to_offset(rva)?;
    /// assert_eq!(back_to_offset, 0x1000);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn offset_to_rva(&self, offset: usize) -> Result<usize> {
        self.section_map()
            .offset_to_rva(offset)
            .map(|rva| rva as usize)
            .ok_or_else(|| {
                ParseFailure::InvalidField {
                    stage: ParseStage::SectionTable,
                    field: "offset",
                    reason: format!(
                        "file offset {offset:#x} is not loaded: it is in no section's data within \
                         its VirtualSize"
                    ),
                }
                .into()
            })
    }

    /// Determines if a section contains .NET metadata by checking the actual metadata RVA.
    ///
    /// This method reads the CLR runtime header to get the metadata RVA and checks
    /// if it falls within the specified section's address range. This is more accurate
    /// than name-based heuristics since metadata can technically be located in any section.
    ///
    /// # Arguments
    /// * `section_name` - The name of the section to check (e.g., ".text")
    ///
    /// # Returns
    /// Returns `true` if the section contains .NET metadata, `false` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("example.dll"))?;
    ///
    /// if file.section_contains_metadata(".text") {
    ///     println!("The .text section contains .NET metadata");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn section_contains_metadata(&self, section_name: &str) -> bool {
        let clr_rva = match self.clr() {
            Some((rva, size)) if rva > 0 && size >= COR20_HEADER_SIZE as usize => {
                let Ok(rva_u32) = u32::try_from(rva) else {
                    return false; // RVA too large for valid PE
                };
                rva_u32
            }
            _ => return false, // No CLR header means no .NET metadata
        };

        let Ok(clr_data) = self.rva_slice(clr_rva as usize, COR20_HEADER_SIZE as usize) else {
            return false;
        };

        let Some(rva_bytes) = clr_data
            .get(8..12)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
        else {
            return false;
        };
        let meta_data_rva = u32::from_le_bytes(rva_bytes);

        if meta_data_rva == 0 {
            return false; // No metadata
        }

        for section in self.sections() {
            let current_section_name = section.name.as_str();

            if current_section_name == section_name {
                let section_start = section.virtual_address;
                let Some(section_end) = section.virtual_address.checked_add(section.virtual_size)
                else {
                    return false;
                };
                return meta_data_rva >= section_start && meta_data_rva < section_end;
            }
        }

        false // Section not found
    }

    /// Gets the file alignment value from the PE header.
    ///
    /// This method extracts the file alignment value from the PE optional header.
    /// This is typically 512 bytes for most .NET assemblies.
    ///
    /// # Returns
    /// Returns the file alignment value in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the PE header cannot be accessed.
    pub fn file_alignment(&self) -> Result<u32> {
        let optional_header = self.header_optional().as_ref().ok_or_else(|| {
            LayoutFailed("Missing optional header for file alignment".to_string())
        })?;

        Ok(optional_header.windows_fields.file_alignment)
    }

    /// Gets the section alignment value from the PE header.
    ///
    /// This method extracts the section alignment value from the PE optional header.
    /// This is typically 4096 bytes (page size) for most .NET assemblies.
    ///
    /// # Returns
    /// Returns the section alignment value in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the PE header cannot be accessed.
    pub fn section_alignment(&self) -> Result<u32> {
        let optional_header = self.header_optional().as_ref().ok_or_else(|| {
            LayoutFailed("Missing optional header for section alignment".to_string())
        })?;

        Ok(optional_header.windows_fields.section_alignment)
    }

    /// Determines if this is a PE32+ format file.
    ///
    /// Returns `true` for PE32+ (64-bit) format, `false` for PE32 (32-bit) format.
    /// This affects the size of ILT/IAT entries and ordinal import bit positions.
    ///
    /// # Returns
    /// Returns `true` if PE32+ format, `false` if PE32 format.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the PE format cannot be determined.
    pub fn is_pe32_plus_format(&self) -> Result<bool> {
        let optional_header = self.header_optional().as_ref().ok_or_else(|| {
            LayoutFailed("Missing optional header for PE format detection".to_string())
        })?;

        // PE32 magic is 0x10b, PE32+ magic is 0x20b
        Ok(optional_header.standard_fields.magic != 0x10b)
    }

    /// Finds the .text section in the PE file.
    ///
    /// Locates the .text section (or .text-prefixed section) which typically
    /// contains .NET metadata and executable code.
    ///
    /// # Returns
    /// Returns a reference to the .text section table entry.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if no .text section is found.
    fn find_text_section(&self) -> Result<&pe::SectionTable> {
        self.sections()
            .iter()
            .find(|s| s.name.as_str() == ".text" || s.name.starts_with(".text"))
            .ok_or_else(|| LayoutFailed("Could not find .text section".to_string()))
    }

    /// Gets the RVA of the .text section.
    ///
    /// Locates the .text section (or .text-prefixed section) which typically
    /// contains .NET metadata and executable code.
    ///
    /// # Returns
    /// Returns the RVA (Relative Virtual Address) of the .text section.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if no .text section is found.
    pub fn text_section_rva(&self) -> Result<u32> {
        Ok(self.find_text_section()?.virtual_address)
    }

    /// Gets the file offset of the .text section.
    ///
    /// This method finds the .text section in the PE file and returns its file offset.
    /// This is needed for calculating absolute file offsets for metadata components.
    ///
    /// # Returns
    /// Returns the file offset of the .text section.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if no .text section is found.
    pub fn text_section_file_offset(&self) -> Result<u64> {
        Ok(u64::from(self.find_text_section()?.pointer_to_raw_data))
    }

    /// Gets the raw size of the .text section.
    ///
    /// This method finds the .text section and returns its raw data size.
    /// This is needed for calculating metadata expansion requirements.
    ///
    /// # Returns
    /// Returns the raw size of the .text section in bytes.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if no .text section is found.
    pub fn text_section_raw_size(&self) -> Result<u32> {
        Ok(self.find_text_section()?.size_of_raw_data)
    }

    /// Gets the total size of the file.
    ///
    /// Returns the size of the underlying file data in bytes.
    ///
    /// # Returns
    /// Returns the file size in bytes.
    #[must_use]
    pub fn file_size(&self) -> u64 {
        u64::try_from(self.data().len()).unwrap_or(u64::MAX)
    }

    /// Gets the PE signature offset from the DOS header.
    ///
    /// Reads the PE offset from the DOS header at offset 0x3C to locate
    /// the PE signature ("PE\0\0") within the file.
    ///
    /// # Returns
    /// Returns the file offset where the PE signature is located.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the file is too small to contain
    /// a valid DOS header.
    pub fn pe_signature_offset(&self) -> Result<u64> {
        let data = self.data();

        if data.len() < 64 {
            return Err(LayoutFailed(
                "File too small to contain DOS header".to_string(),
            ));
        }

        // PE offset is at offset 0x3C in DOS header
        let bytes = data
            .get(60..64)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or_else(|| LayoutFailed("DOS header truncated".to_string()))?;
        let pe_offset = u32::from_le_bytes(bytes);
        Ok(u64::from(pe_offset))
    }

    /// Calculates the size of PE headers (including optional header).
    ///
    /// Computes the total size of PE signature, COFF header, and optional header
    /// by reading the optional header size from the COFF header.
    ///
    /// # Returns
    /// Returns the total size in bytes of all PE headers.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the file is too small or
    /// headers are malformed.
    pub fn pe_headers_size(&self) -> Result<u64> {
        // PE signature (4) + COFF header (20) + Optional header size
        // We need to read the optional header size from the COFF header
        let pe_sig_offset = self.pe_signature_offset()?;
        let data = self.data();

        let coff_header_offset = pe_sig_offset
            .checked_add(4)
            .ok_or_else(|| LayoutFailed("COFF header offset overflow".to_string()))?; // Skip PE signature

        let coff_end = coff_header_offset
            .checked_add(20)
            .ok_or_else(|| LayoutFailed("COFF header end overflow".to_string()))?;
        let coff_end_usize = usize::try_from(coff_end)
            .map_err(|_| LayoutFailed("COFF header end exceeds usize".to_string()))?;
        if data.len() < coff_end_usize {
            return Err(LayoutFailed(
                "File too small to contain COFF header".to_string(),
            ));
        }

        // Optional header size is at offset 16 in COFF header
        let opt_header_size_offset = coff_header_offset
            .checked_add(16)
            .ok_or_else(|| LayoutFailed("Optional header size offset overflow".to_string()))?;
        let opt_offset_usize = usize::try_from(opt_header_size_offset)
            .map_err(|_| LayoutFailed("Optional header offset exceeds usize".to_string()))?;
        let opt_end_usize = opt_offset_usize
            .checked_add(2)
            .ok_or_else(|| LayoutFailed("Optional header offset+2 overflow".to_string()))?;
        let opt_bytes = data
            .get(opt_offset_usize..opt_end_usize)
            .and_then(|s| <[u8; 2]>::try_from(s).ok())
            .ok_or_else(|| LayoutFailed("Optional header size truncated".to_string()))?;
        let opt_header_size = u16::from_le_bytes(opt_bytes);

        // PE sig + COFF + Optional header
        24u64
            .checked_add(u64::from(opt_header_size))
            .ok_or_else(|| LayoutFailed("PE headers size overflow".to_string()))
    }

    /// Aligns an offset to this file's PE file alignment boundary.
    ///
    /// PE files require data to be aligned to specific boundaries for optimal loading.
    /// This method uses the actual file alignment value from the PE header rather than
    /// assuming a hardcoded value.
    ///
    /// # Arguments
    /// * `offset` - The offset to align
    ///
    /// # Returns
    /// Returns the offset rounded up to the next file alignment boundary.
    ///
    /// # Errors
    /// Returns [`crate::Error::LayoutFailed`] if the PE header cannot be accessed.
    pub fn align_to_file_alignment(&self, offset: u64) -> Result<u64> {
        let file_alignment = u64::from(self.file_alignment()?);
        Ok(align_to(offset, file_alignment))
    }

    /// Returns a reference to the internal Pe structure.
    ///
    /// This provides access to the owned PE data structures for operations
    /// that need to work directly with PE components, such as size calculations
    /// and header updates during write operations.
    ///
    /// # Returns
    /// Reference to the internal Pe structure
    #[must_use]
    pub fn pe(&self) -> &Pe {
        &self.pe
    }

    /// Returns a mutable reference to the internal Pe structure.
    ///
    /// This provides mutable access to the owned PE data structures, enabling
    /// direct modifications to PE headers, sections, and data directories.
    /// Use this when you need to modify the PE structure in-place rather than
    /// creating copies.
    ///
    /// # Returns
    /// Mutable reference to the internal Pe structure
    ///
    /// # Examples
    /// ```rust,no_run
    /// use dotscope::{File, SectionTable};
    ///
    /// // Add a new section to the PE file
    /// let mut file = File::from_path("assembly.dll")?;
    /// let new_section = SectionTable::from_layout_info(
    ///     ".meta".to_string(),
    ///     0x4000,
    ///     0x1000,
    ///     0x2000,
    ///     0x1000,
    ///     0x40000040,
    /// )?;
    /// file.pe_mut().add_section(new_section);
    ///
    /// // Update CLR data directory
    /// file.pe_mut().update_clr_data_directory(0x4000, 72)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn pe_mut(&mut self) -> &mut Pe {
        &mut self.pe
    }

    /// Consumes the File and returns the underlying data as an owned `Vec<u8>`.
    ///
    /// For files loaded via `from_mem()`, this transfers ownership without copying.
    /// For files loaded via `from_file()`, this makes a complete copy of the memory-mapped data.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal lock was poisoned by a panicking thread.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::File;
    /// use std::path::Path;
    ///
    /// // From memory - no copy
    /// let original_data = vec![/* PE bytes */];
    /// let file = File::from_mem(original_data)?;
    /// let recovered_data = file.into_data()?;
    ///
    /// // From file - copies the data
    /// let file = File::from_path(Path::new("assembly.dll"))?;
    /// let data_copy = file.into_data()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn into_data(self) -> Result<Vec<u8>> {
        Ok(self.data.into_vec()?)
    }

    /// Returns any PE repairs that were applied during loading.
    ///
    /// If the PE file was corrupted (e.g., by BitMono or BitDotNet packers),
    /// the repair actions describe what was fixed.
    #[must_use]
    pub fn repairs(&self) -> &[RepairAction] {
        &self.repairs
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        file::pe::DataDirectoryType,
        testkit::{factories::general::file::verify_file, fixture},
        File,
    };

    /// Tests loading a PE file from disk.
    #[test]
    fn load_file() {
        let path = fixture("WindowsBase.dll");
        let file = File::from_path(&path).unwrap();

        verify_file(&file);
    }

    /// Tests loading a PE file from a memory buffer.
    #[test]
    fn load_buffer() {
        let path = fixture("WindowsBase.dll");
        let data = fs::read(&path).unwrap();
        let file = File::from_mem(data).unwrap();

        verify_file(&file);
    }

    /// **A malformed part the load does not read does not refuse the file.**
    /// A base relocation directory that runs past the end of the file (a .NET
    /// sample on a release corpus: offset 0x1f1200 and size 0xc in a 0x1efe6f
    /// byte file) failed the whole load in goblin's strict mode, and with it
    /// every table of the CIL metadata; the file now loads with its metadata.
    #[test]
    fn a_relocation_directory_past_the_end_does_not_refuse_the_file() {
        let path = fixture("WindowsBase.dll");
        let mut data = fs::read(&path).unwrap();
        let pe = goblin::pe::PE::parse(&data).unwrap();
        let optional = pe.header.coff_header.size_of_optional_header as usize;
        let header_end = pe.header.dos_header.pe_pointer as usize + 4 + 20 + optional;
        // The base relocation entry (index 5) of the data directories, which
        // close the optional header: 16 entries of 8 bytes.
        let entry = header_end - 16 * 8 + 5 * 8;
        let past_the_end = u32::try_from(data.len()).unwrap();
        data[entry + 4..entry + 8].copy_from_slice(&past_the_end.to_le_bytes());
        assert!(
            goblin::pe::PE::parse(&data).is_err(),
            "strict goblin refuses the corrupted directory"
        );

        let file = File::from_mem(data).unwrap();
        verify_file(&file);
    }

    /// Tests loading an invalid PE file.
    #[test]
    fn load_invalid() {
        let data = include_bytes!("../../tests/samples/WB_ROOT.bin");
        if File::from_mem(data.to_vec()).is_ok() {
            panic!("This should not load!")
        }
    }

    /// Tests the unified get_data_directory method.
    #[test]
    fn test_get_data_directory() {
        let path = fixture("WindowsBase.dll");
        let file = File::from_path(&path).unwrap();

        // Test CLR runtime header (should exist for .NET assemblies)
        let clr_dir = file.get_data_directory(DataDirectoryType::ClrRuntimeHeader);
        assert!(clr_dir.is_some(), "CLR runtime header should exist");
        let (clr_rva, clr_size) = clr_dir.unwrap();
        assert!(clr_rva > 0, "CLR RVA should be non-zero");
        assert!(clr_size > 0, "CLR size should be non-zero");

        // Verify it matches the existing clr() method
        let (expected_rva, expected_size) = file.clr().expect("Should have CLR header");
        assert_eq!(
            clr_rva as usize, expected_rva,
            "CLR RVA should match clr() method"
        );
        assert_eq!(
            clr_size as usize, expected_size,
            "CLR size should match clr() method"
        );

        // Test non-existent directory (should return None)
        let _base_reloc_dir = file.get_data_directory(DataDirectoryType::BaseRelocationTable);
        // For a typical .NET assembly, base relocation table might not exist
        // We don't assert anything specific here as it depends on the assembly

        // The method should handle any directory type gracefully
        let tls_dir = file.get_data_directory(DataDirectoryType::TlsTable);
        // TLS table typically doesn't exist in .NET assemblies, but method should not panic
        if let Some((tls_rva, tls_size)) = tls_dir {
            assert!(
                tls_rva > 0 && tls_size > 0,
                "If TLS directory exists, it should have valid values"
            );
        }
    }

    /// Tests the pe_signature_offset method.
    #[test]
    fn test_pe_signature_offset() {
        let path = fixture("crafted_2.exe");
        let file = File::from_path(&path).expect("Failed to load test assembly");

        let pe_offset = file
            .pe_signature_offset()
            .expect("Should get PE signature offset");
        assert!(pe_offset > 0, "PE signature offset should be positive");
        assert!(pe_offset < 1024, "PE signature offset should be reasonable");
    }

    /// Tests the pe_headers_size method.
    #[test]
    fn test_pe_headers_size() {
        let path = fixture("crafted_2.exe");
        let file = File::from_path(&path).expect("Failed to load test assembly");

        let headers_size = file
            .pe_headers_size()
            .expect("Should calculate headers size");
        assert!(headers_size >= 24, "Headers should be at least 24 bytes");
        assert!(headers_size <= 1024, "Headers size should be reasonable");
    }

    /// Tests the align_to_file_alignment method.
    #[test]
    fn test_align_to_file_alignment() {
        let path = fixture("crafted_2.exe");
        let file = File::from_path(&path).expect("Failed to load test assembly");

        // Test alignment with actual file alignment from PE header
        let alignment = file.file_alignment().expect("Should get file alignment");

        // Test various offsets
        assert_eq!(file.align_to_file_alignment(0).unwrap(), 0);
        assert_eq!(file.align_to_file_alignment(1).unwrap(), alignment as u64);
        assert_eq!(
            file.align_to_file_alignment(alignment as u64).unwrap(),
            alignment as u64
        );
        assert_eq!(
            file.align_to_file_alignment(alignment as u64 + 1).unwrap(),
            (alignment * 2) as u64
        );
    }
}
