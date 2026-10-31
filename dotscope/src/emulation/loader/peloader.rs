//! PE image loader for emulation.
//!
//! This module provides [`PeLoader`] which loads Portable Executable (PE) images
//! into the emulation address space with proper section mapping, alignment, and
//! memory protection.
//!
//! # Overview
//!
//! The PE loader handles the complexity of mapping Windows executable files
//! (.exe, .dll) into a virtual address space suitable for emulation or analysis.
//! It supports both 32-bit (PE32) and 64-bit (PE32+) formats, including .NET
//! assemblies.
//!
//! # Features
//!
//! - **Section Mapping**: Properly maps each PE section at its virtual address
//! - **Memory Protection**: Applies appropriate read/write/execute permissions
//! - **Base Relocations**: Fixes up absolute addresses when loading at non-preferred base
//! - **CLR Detection**: Identifies .NET assemblies via CLR header presence
//! - **Configurable Loading**: Supports custom base addresses and permission overrides
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::emulation::PeLoader;
//! use dotscope::emulation::PeLoaderConfig;
//! use dotscope::emulation::AddressSpace;
//! use std::path::Path;
//!
//! // Load with default settings (uses PE's preferred base address)
//! let loader = PeLoader::new();
//! let image = loader.load_file(Path::new("target.exe"), &address_space)?;
//!
//! // Load with custom configuration
//! let config = PeLoaderConfig::new()
//!     .with_base_address(0x10000000)
//!     .without_permissions();
//! let loader = PeLoader::with_config(config);
//! let image = loader.load_file(Path::new("target.dll"), &address_space)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # PE Format Support
//!
//! The loader uses the `goblin` crate for PE parsing and supports:
//!
//! - PE32 (32-bit executables)
//! - PE32+ (64-bit executables)
//! - DLL files
//! - .NET assemblies (with CLR header detection)
//!
//! # Limitations
//!
//! - Import resolution is not yet fully implemented (placeholder support)
//! - TLS callbacks are not processed
//! - Delay-load imports are not handled

use goblin::pe::options::{ParseMode, ParseOptions};

use crate::{
    emulation::memory::{AddressSpace, MemoryProtection, MemoryRegion, SectionInfo},
    Error, Result,
};

/// Base relocation types from the PE format specification.
///
/// These constants define how addresses should be fixed up when an image
/// is loaded at a different base address than its preferred location.
mod reloc_type {
    /// No-op relocation, used for padding to maintain alignment.
    pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
    /// 32-bit address fixup (add delta to DWORD at offset).
    pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
    /// 64-bit address fixup (add delta to QWORD at offset).
    pub const IMAGE_REL_BASED_DIR64: u16 = 10;
}

/// Configuration options for PE image loading.
///
/// This struct controls how the [`PeLoader`] processes and maps PE images into
/// the address space. It uses the builder pattern for convenient configuration.
///
/// # Default Configuration
///
/// The default configuration:
/// - Uses the PE's preferred base address (from the optional header)
/// - Applies section memory permissions
/// - Zero-fills BSS (uninitialized data) sections
/// - Does not resolve imports
/// - Applies relocations when loading at a non-preferred base
///
/// # Example
///
/// ```no_run
/// use dotscope::emulation::PeLoaderConfig;
///
/// // Custom configuration for debugging
/// let config = PeLoaderConfig::new()
///     .with_base_address(0x10000000)  // Force specific base
///     .without_permissions();          // Allow all access
/// ```
#[derive(Clone, Debug)]
pub struct PeLoaderConfig {
    /// Base address override for loading the PE image.
    ///
    /// When `None`, the loader uses the preferred base address from the PE's
    /// optional header. When `Some(address)`, the image is loaded at the
    /// specified address, and relocations are applied if necessary.
    pub base_address: Option<u64>,

    /// Whether to apply section memory protection flags.
    ///
    /// When `true` (default), each section receives the appropriate read/write/execute
    /// permissions based on its characteristics. When `false`, all sections are
    /// mapped with full RWX access, which can be useful for debugging or analysis.
    pub apply_permissions: bool,

    /// Whether to apply base relocations when loading at a non-preferred address.
    ///
    /// When `true` (default) and the image is loaded at an address different from
    /// its preferred base, the loader applies relocations to fix up absolute
    /// addresses in the code and data sections.
    pub apply_relocations: bool,

    /// Ceiling on the image buffer this loader will materialise, in bytes.
    ///
    /// `SizeOfImage` is a `u32` taken verbatim from the optional header of an
    /// attacker-supplied file, and it alone sizes the zero-initialised image buffer. A few
    /// hundred bytes of input can therefore ask for 4 GiB. `alloc_zeroed` makes that cheap in
    /// resident memory but not free: a hard cgroup limit, `vm.overcommit_memory=2`, Windows
    /// commit charge, a 32-bit build, or enough concurrent loads all turn it into a real
    /// failure.
    pub max_image_size: u64,
}

impl Default for PeLoaderConfig {
    fn default() -> Self {
        Self {
            base_address: None,
            apply_permissions: true,
            apply_relocations: true,
            max_image_size: 512 * 1024 * 1024,
        }
    }
}

impl PeLoaderConfig {
    /// Creates a new configuration with default settings.
    ///
    /// This is equivalent to calling [`Default::default()`] but provides a more
    /// explicit entry point for the builder pattern.
    ///
    /// # Returns
    ///
    /// A new `PeLoaderConfig` with all default settings applied.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets a custom base address for loading the PE image.
    ///
    /// When specified, the image will be loaded at this address instead of its
    /// preferred base address. If the PE contains relocations and
    /// [`apply_relocations`](Self::apply_relocations) is `true`, the loader will
    /// fix up absolute addresses accordingly.
    ///
    /// # Arguments
    ///
    /// * `base` - The virtual address where the image should be loaded
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let config = PeLoaderConfig::new().with_base_address(0x10000000);
    /// assert_eq!(config.base_address, Some(0x10000000));
    /// ```
    #[must_use]
    pub fn with_base_address(mut self, base: u64) -> Self {
        self.base_address = Some(base);
        self
    }

    /// Disables section memory protection enforcement.
    ///
    /// When called, all sections will be mapped with full read-write-execute
    /// permissions, regardless of their declared characteristics. This is useful
    /// for debugging or when analyzing self-modifying code.
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    ///
    /// # Security Note
    ///
    /// Disabling permissions removes a layer of memory safety. Use with caution.
    #[must_use]
    pub fn without_permissions(mut self) -> Self {
        self.apply_permissions = false;
        self
    }

    /// Disables base relocation processing.
    ///
    /// When called, the loader will NOT apply relocations even when loading
    /// at a non-preferred base address. This can be useful for analysis tools
    /// that need to examine the original unrelocated addresses.
    ///
    /// # Returns
    ///
    /// The modified configuration for method chaining.
    ///
    /// # Warning
    ///
    /// Disabling relocations while loading at a non-preferred base address
    /// will result in incorrect absolute addresses throughout the image.
    /// Code execution will likely fail or produce incorrect results.
    #[must_use]
    pub fn without_relocations(mut self) -> Self {
        self.apply_relocations = false;
        self
    }
}

/// Metadata about a PE image that has been loaded into the address space.
///
/// This struct is returned by [`PeLoader::load`] and [`PeLoader::load_file`] after
/// successfully mapping a PE image. It contains comprehensive information about
/// the loaded image including its location, structure, and sections.
///
/// # Fields Overview
///
/// - **Address Information**: `base_address`, `size_of_image`
/// - **Execution Details**: `entry_point`, `is_64_bit`
/// - **Structure**: `sections`, `file_size`
/// - **.NET Metadata**: `clr_header_rva`, `clr_header_size`
///
/// # Example
///
/// ```no_run
/// let image = loader.load_file(path, &address_space)?;
///
/// println!("Image: {} loaded at 0x{:X}", image.name, image.base_address);
/// println!("Entry point: 0x{:X?}", image.entry_point_va());
/// println!("Is .NET: {}", image.is_dotnet());
///
/// for section in &image.sections {
///     println!("  Section: {} at RVA 0x{:X}", section.name, section.virtual_address);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct LoadedImage {
    /// Base address where the image was loaded in virtual memory.
    ///
    /// This may differ from the PE's preferred base address if a custom base
    /// was specified in the loader configuration or if the preferred address
    /// was unavailable.
    pub base_address: u64,

    /// Total size of the image in memory (from the PE optional header).
    ///
    /// This is the `SizeOfImage` field from the PE header, representing the
    /// total virtual size of all sections plus headers, rounded up to the
    /// section alignment.
    pub size_of_image: u64,

    /// Entry point as a Relative Virtual Address (RVA), if present.
    ///
    /// For executables, this points to the start of execution. For DLLs,
    /// this is the `DllMain` function. Use [`entry_point_va`](Self::entry_point_va)
    /// to get the absolute virtual address.
    ///
    /// This is `None` for resource-only DLLs or other special PE files.
    pub entry_point: Option<u64>,

    /// Whether this is a 64-bit (PE32+) image.
    ///
    /// When `true`, the image uses 64-bit addressing (PE32+ format).
    /// When `false`, the image uses 32-bit addressing (PE32 format).
    pub is_64_bit: bool,

    /// Information about each section that was loaded.
    ///
    /// Contains detailed metadata for each PE section including name,
    /// addresses, sizes, and protection flags.
    pub sections: Vec<LoadedSection>,

    /// Name or label identifying this image.
    ///
    /// Typically the filename of the PE file, or a custom label if loaded
    /// from bytes. Used for debugging and logging purposes.
    pub name: String,

    /// Size of the original PE file in bytes.
    ///
    /// This is the on-disk file size, which may be significantly smaller than
    /// [`size_of_image`](Self::size_of_image) due to section alignment and
    /// zero-filled BSS regions.
    pub file_size: usize,

    /// CLR runtime header RVA for .NET assemblies.
    ///
    /// When present (non-`None`), indicates this PE contains managed (.NET) code.
    /// The value is the RVA of the CLR header (also known as the COR20 header).
    pub clr_header_rva: Option<u32>,

    /// Size of the CLR runtime header in bytes.
    ///
    /// Only meaningful when [`clr_header_rva`](Self::clr_header_rva) is `Some`.
    /// Typically 0x48 (72 bytes) for the standard COR20 header.
    pub clr_header_size: Option<u32>,
}

impl LoadedImage {
    /// Computes the absolute virtual address of the entry point.
    ///
    /// Converts the entry point RVA to an absolute virtual address by adding
    /// the base address. Returns `None` if the image has no entry point.
    ///
    /// # Returns
    ///
    /// The virtual address of the entry point, or `None` if no entry point exists.
    ///
    /// # Example
    ///
    /// ```no_run
    /// if let Some(entry) = image.entry_point_va() {
    ///     println!("Start execution at: 0x{:X}", entry);
    /// }
    /// ```
    #[must_use]
    pub fn entry_point_va(&self) -> Option<u64> {
        self.entry_point
            .map(|rva| self.base_address.saturating_add(rva))
    }

    /// Converts a Relative Virtual Address (RVA) to an absolute virtual address.
    ///
    /// This is a simple calculation: `base_address + rva`. Use this to translate
    /// addresses from PE headers and data directories to their actual location
    /// in the mapped address space.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to convert
    ///
    /// # Returns
    ///
    /// The absolute virtual address in the loaded image.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let import_table_va = image.rva_to_va(import_table_rva);
    /// let data = address_space.read(import_table_va, size)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn rva_to_va(&self, rva: u32) -> u64 {
        self.base_address.saturating_add(u64::from(rva))
    }

    /// Checks whether an RVA falls within the bounds of this image.
    ///
    /// Returns `true` if the RVA is less than the image's total size, meaning
    /// it refers to a valid offset within the loaded image.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to check
    ///
    /// # Returns
    ///
    /// `true` if the RVA is within the image bounds, `false` otherwise.
    #[must_use]
    pub fn contains_rva(&self, rva: u32) -> bool {
        u64::from(rva) < self.size_of_image
    }

    /// Finds the section that contains a given RVA.
    ///
    /// Searches through all loaded sections to find the one that contains the
    /// specified RVA. This is useful for determining which section a particular
    /// address belongs to (e.g., whether it's in `.text`, `.data`, etc.).
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to look up
    ///
    /// # Returns
    ///
    /// A reference to the [`LoadedSection`] containing the RVA, or `None` if
    /// the RVA falls outside all sections (e.g., in the PE headers).
    ///
    /// # Example
    ///
    /// ```no_run
    /// if let Some(section) = image.section_for_rva(0x1000) {
    ///     println!("RVA 0x1000 is in section: {}", section.name);
    ///     if section.is_code {
    ///         println!("  This is a code section");
    ///     }
    /// }
    /// ```
    #[must_use]
    pub fn section_for_rva(&self, rva: u32) -> Option<&LoadedSection> {
        self.sections.iter().find(|s| {
            rva >= s.virtual_address
                && rva
                    < s.virtual_address
                        .saturating_add(s.virtual_size.max(s.raw_size))
        })
    }

    /// Checks whether this image is a .NET (managed) assembly.
    ///
    /// Returns `true` if the PE contains a CLR runtime header, indicating it
    /// requires the .NET runtime to execute. This is determined by the presence
    /// of data directory entry 14 (COM Descriptor/CLR Header).
    ///
    /// # Returns
    ///
    /// `true` if this is a .NET assembly, `false` for native executables.
    ///
    /// # Example
    ///
    /// ```no_run
    /// if image.is_dotnet() {
    ///     println!("{} is a .NET assembly", image.name);
    ///     println!("CLR header at RVA: 0x{:X}", image.clr_header_rva.unwrap());
    /// }
    /// ```
    #[must_use]
    pub fn is_dotnet(&self) -> bool {
        self.clr_header_rva.is_some()
    }
}

/// Metadata about an individual PE section that was loaded into memory.
///
/// Each PE image contains one or more sections, each with a specific purpose
/// (code, data, resources, etc.). This struct captures the properties of a
/// section after it has been mapped into the address space.
///
/// # Common Section Names
///
/// | Name | Typical Content |
/// |------|-----------------|
/// | `.text` | Executable code |
/// | `.data` | Initialized read-write data |
/// | `.rdata` | Read-only data (constants, import tables) |
/// | `.bss` | Uninitialized data (zero-filled) |
/// | `.rsrc` | Resources (icons, strings, etc.) |
/// | `.reloc` | Base relocation data |
///
/// # Example
///
/// ```no_run
/// for section in &image.sections {
///     println!("{}: RVA=0x{:X}, Size=0x{:X}",
///         section.name,
///         section.virtual_address,
///         section.virtual_size
///     );
///
///     if section.is_code {
///         println!("  Contains executable code");
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct LoadedSection {
    /// Name of the section (e.g., ".text", ".data", ".rsrc").
    ///
    /// Section names are limited to 8 characters in the PE format. Longer names
    /// may be truncated or stored in the string table.
    pub name: String,

    /// Relative Virtual Address (RVA) where the section starts.
    ///
    /// This is the offset from the image base address. To get the absolute
    /// virtual address, add this to [`LoadedImage::base_address`].
    pub virtual_address: u32,

    /// Size of the section in memory when loaded.
    ///
    /// This may be larger than [`raw_size`](Self::raw_size) if the section
    /// contains uninitialized data that is zero-filled during loading.
    pub virtual_size: u32,

    /// Size of the section's data on disk.
    ///
    /// This is the amount of data actually stored in the PE file. May be
    /// smaller than [`virtual_size`](Self::virtual_size) for BSS sections
    /// or larger due to file alignment padding.
    pub raw_size: u32,

    /// Memory protection flags applied to this section.
    ///
    /// Derived from the section's characteristics flags. Common combinations:
    /// - Code: `READ | EXECUTE`
    /// - Data: `READ | WRITE`
    /// - Constants: `READ` only
    pub protection: MemoryProtection,

    /// Indicates this section contains executable code.
    ///
    /// Corresponds to the `IMAGE_SCN_CNT_CODE` characteristic flag.
    pub is_code: bool,

    /// Indicates this section contains initialized data.
    ///
    /// Corresponds to the `IMAGE_SCN_CNT_INITIALIZED_DATA` characteristic flag.
    /// The data is copied from the PE file into memory during loading.
    pub is_initialized_data: bool,

    /// Indicates this section contains uninitialized (BSS) data.
    ///
    /// Corresponds to the `IMAGE_SCN_CNT_UNINITIALIZED_DATA` characteristic flag.
    /// The section is zero-filled during loading rather than copied from disk.
    pub is_uninitialized_data: bool,
}

/// PE image loader for mapping Windows executables into the emulation address space.
///
/// `PeLoader` parses Portable Executable (PE) files and maps them into an
/// [`AddressSpace`](crate::emulation::memory::AddressSpace) with proper section
/// alignment, memory protection, and optional relocation support.
///
/// # Features
///
/// - Parses both PE32 (32-bit) and PE32+ (64-bit) formats
/// - Maps sections at their correct virtual addresses
/// - Applies section-specific memory protection flags
/// - Handles BSS (uninitialized data) sections
/// - Detects .NET assemblies via CLR header
///
/// # Configuration
///
/// Loading behavior can be customized via [`PeLoaderConfig`]:
///
/// - Override the base address
/// - Disable memory protection enforcement
/// - Enable/disable import resolution
/// - Control relocation application
///
/// # Thread Safety
///
/// `PeLoader` instances are not `Sync` due to internal state, but multiple
/// loaders can operate on the same address space concurrently.
///
/// # Example
///
/// ```no_run
/// use dotscope::emulation::PeLoader;
/// use std::path::Path;
///
/// let loader = PeLoader::new();
/// let image = loader.load_file(
///     Path::new("program.exe"),
///     &address_space,
/// )?;
///
/// println!("Loaded {} ({} sections)", image.name, image.sections.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct PeLoader {
    /// Configuration controlling loading behavior.
    config: PeLoaderConfig,
}

impl PeLoader {
    /// Creates a new PE loader with default configuration.
    ///
    /// The default configuration uses the PE's preferred base address, applies
    /// section permissions, and handles relocations automatically.
    ///
    /// # Returns
    ///
    /// A new `PeLoader` instance with default settings.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let loader = PeLoader::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: PeLoaderConfig::default(),
        }
    }

    /// Creates a new PE loader with the specified configuration.
    ///
    /// Use this constructor when you need to customize loading behavior,
    /// such as specifying a base address or disabling permissions.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to use for loading
    ///
    /// # Returns
    ///
    /// A new `PeLoader` instance with the specified configuration.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let config = PeLoaderConfig::new()
    ///     .with_base_address(0x10000000)
    ///     .without_permissions();
    /// let loader = PeLoader::with_config(config);
    /// ```
    #[must_use]
    pub fn with_config(config: PeLoaderConfig) -> Self {
        Self { config }
    }

    /// Loads a PE image from a byte slice into the address space.
    ///
    /// Parses the PE headers from the provided bytes, allocates space in the
    /// address space, and maps each section to its virtual address. The image
    /// is loaded according to the loader's configuration.
    ///
    /// # Arguments
    ///
    /// * `pe_bytes` - The raw bytes of the PE file
    /// * `address_space` - The address space to map the image into
    /// * `name` - A name/label for the loaded image (used for debugging)
    ///
    /// # Returns
    ///
    /// Returns `Ok(LoadedImage)` containing metadata about the loaded image,
    /// or an error if parsing or mapping fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The bytes are not a valid PE file
    /// - The PE headers are malformed or unsupported
    /// - The target address range is already mapped
    /// - Memory allocation fails
    ///
    /// # Example
    ///
    /// ```no_run
    /// let pe_data = std::fs::read("program.exe")?;
    /// let image = loader.load(&pe_data, &address_space, "program.exe")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn load(
        &self,
        pe_bytes: &[u8],
        address_space: &AddressSpace,
        name: impl Into<String>,
    ) -> Result<LoadedImage> {
        let name = name.into();

        // The headers and sections, from goblin, permissively: the loader reads
        // nothing else of goblin's walk (relocations are applied from the data
        // directory below), so a malformed optional part does not refuse the
        // image a process would still map.
        let pe = goblin::pe::PE::parse_with_opts(
            pe_bytes,
            &ParseOptions::default().with_parse_mode(ParseMode::Permissive),
        )?;

        // Determine base address
        let preferred_base = pe.image_base;
        let base_address = self.config.base_address.unwrap_or(preferred_base);

        // Get image size from optional header
        let size_of_image = pe
            .header
            .optional_header
            .map_or(0, |oh| u64::from(oh.windows_fields.size_of_image));

        // Get entry point
        let entry_point = pe
            .header
            .optional_header
            .map(|oh| u64::from(oh.standard_fields.address_of_entry_point));

        // Check if 64-bit
        let is_64_bit = pe.is_64;

        // Get CLR header info (data directory index 14)
        let (clr_header_rva, clr_header_size) = if let Some(oh) = pe.header.optional_header.as_ref()
        {
            if let Some(dd) = oh.data_directories.get_clr_runtime_header() {
                if dd.size > 0 {
                    (Some(dd.virtual_address), Some(dd.size))
                } else {
                    (None, None)
                }
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        // Build section list and map data
        let mut sections = Vec::new();
        let mut section_infos = Vec::new();

        // Validate the declared image size before committing an allocation to it.
        //
        // Two independent bounds, because either alone is too permissive: the configured
        // ceiling caps the absolute cost, and the section extents catch a header that claims
        // far more than its own sections describe. Sections are the authority on what the
        // image actually needs — anything past the highest section end is memory no section
        // maps into.
        if size_of_image > self.config.max_image_size {
            return Err(malformed_error!(
                "SizeOfImage {} exceeds the {} byte loader limit",
                size_of_image,
                self.config.max_image_size
            ));
        }

        let section_extent = pe
            .sections
            .iter()
            .map(|section| {
                u64::from(section.virtual_address).saturating_add(u64::from(
                    section.virtual_size.max(section.size_of_raw_data),
                ))
            })
            .max()
            .unwrap_or(0);
        // Rounded up generously: SizeOfImage is SectionAlignment-aligned and may legitimately
        // exceed the last section's end by up to one alignment unit, plus the headers.
        let plausible = section_extent.saturating_add(0x100_0000);
        if section_extent > 0 && size_of_image > plausible {
            return Err(malformed_error!(
                "SizeOfImage {} is not plausible for sections ending at {}",
                size_of_image,
                section_extent
            ));
        }

        // Create the full image data buffer
        // ToDo: Switch this and the emulator to use mmap for having a disk-backed file if it is very large
        let image_size = usize::try_from(size_of_image).map_err(|_| {
            malformed_error!("SizeOfImage {} exceeds the address width", size_of_image)
        })?;
        let mut image_data = vec![0u8; image_size];

        // Copy headers
        let headers_size = pe
            .header
            .optional_header
            .map_or(0x200, |oh| oh.windows_fields.size_of_headers as usize);
        if headers_size <= pe_bytes.len() && headers_size <= image_data.len() {
            let dst = image_data
                .get_mut(..headers_size)
                .ok_or(out_of_bounds_error!())?;
            let src = pe_bytes.get(..headers_size).ok_or(out_of_bounds_error!())?;
            dst.copy_from_slice(src);
        }

        // Map each section
        for section in &pe.sections {
            let section_name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();
            let virtual_address = section.virtual_address;
            let virtual_size = section.virtual_size;
            let raw_size = section.size_of_raw_data;
            let raw_offset = section.pointer_to_raw_data as usize;
            let characteristics = section.characteristics;

            // Determine protection
            let mut protection = MemoryProtection::ZERO;
            if characteristics & 0x2000_0000 != 0 {
                // IMAGE_SCN_MEM_EXECUTE
                protection |= MemoryProtection::EXECUTE;
            }
            if characteristics & 0x4000_0000 != 0 {
                // IMAGE_SCN_MEM_READ
                protection |= MemoryProtection::READ;
            }
            if characteristics & 0x8000_0000 != 0 {
                // IMAGE_SCN_MEM_WRITE
                protection |= MemoryProtection::WRITE;
            }

            // Determine section type
            let is_code = characteristics & 0x20 != 0; // IMAGE_SCN_CNT_CODE
            let is_initialized_data = characteristics & 0x40 != 0; // IMAGE_SCN_CNT_INITIALIZED_DATA
            let is_uninitialized_data = characteristics & 0x80 != 0; // IMAGE_SCN_CNT_UNINITIALIZED_DATA

            // Copy section data to image as the loader does (`file::sectionmap`): the raw data
            // within the section's VirtualSize (its raw size when that is 0), as much of it as
            // the file holds, and zeros after. Past VirtualSize the image holds zeros, as
            // CoreCLR leaves them.
            let dest_offset = virtual_address as usize;
            let extent = if virtual_size == 0 {
                raw_size
            } else {
                virtual_size
            };
            let copy_size =
                (raw_size.min(extent) as usize).min(pe_bytes.len().saturating_sub(raw_offset));

            let raw_end = raw_offset
                .checked_add(copy_size)
                .ok_or_else(|| malformed_error!("PE section raw range overflow"))?;
            let dest_end = dest_offset
                .checked_add(copy_size)
                .ok_or_else(|| malformed_error!("PE section virtual range overflow"))?;

            if raw_end <= pe_bytes.len() && dest_end <= image_data.len() {
                let dst = image_data
                    .get_mut(dest_offset..dest_end)
                    .ok_or(out_of_bounds_error!())?;
                let src = pe_bytes
                    .get(raw_offset..raw_end)
                    .ok_or(out_of_bounds_error!())?;
                dst.copy_from_slice(src);
            }

            let section_protection = if self.config.apply_permissions {
                protection
            } else {
                MemoryProtection::READ | MemoryProtection::WRITE | MemoryProtection::EXECUTE
            };

            sections.push(LoadedSection {
                name: section_name.clone(),
                virtual_address,
                virtual_size,
                raw_size,
                protection: section_protection,
                is_code,
                is_initialized_data,
                is_uninitialized_data,
            });

            #[allow(clippy::cast_possible_truncation)]
            section_infos.push(SectionInfo {
                name: section_name,
                virtual_address,
                virtual_size,
                raw_data_offset: raw_offset as u32,
                raw_data_size: raw_size,
                characteristics,
                protection: section_protection,
            });
        }

        // Apply relocations if loading at a non-preferred base
        let delta = base_address
            .cast_signed()
            .checked_sub(preferred_base.cast_signed())
            .ok_or_else(|| malformed_error!("PE relocation delta overflow"))?;
        if delta != 0 && self.config.apply_relocations {
            Self::apply_relocations(&pe, &mut image_data, delta, is_64_bit)?;
        }

        // Create the memory region
        let region = MemoryRegion::pe_image(base_address, &image_data, section_infos, name.clone());

        // Map into address space
        address_space.map_at(base_address, region)?;

        Ok(LoadedImage {
            base_address,
            size_of_image,
            entry_point,
            is_64_bit,
            sections,
            name,
            file_size: pe_bytes.len(),
            clr_header_rva,
            clr_header_size,
        })
    }

    /// Loads a PE image from a file path into the address space.
    ///
    /// Convenience method that reads the file from disk and then calls
    /// [`load`](Self::load). The filename (without directory path) is used
    /// as the image name.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PE file to load
    /// * `address_space` - The address space to map the image into
    ///
    /// # Returns
    ///
    /// Returns `Ok(LoadedImage)` containing metadata about the loaded image,
    /// or an error if reading or loading fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read (permission denied, not found, I/O error)
    /// - The file is not a valid PE (see [`load`](Self::load) for parsing errors)
    /// - The address space cannot accommodate the image
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::path::Path;
    ///
    /// let loader = PeLoader::new();
    /// let image = loader.load_file(
    ///     Path::new("C:\\Windows\\System32\\kernel32.dll"),
    ///     &address_space,
    /// )?;
    ///
    /// println!("Loaded: {}", image.name);
    /// println!("Base: 0x{:X}", image.base_address);
    /// println!("Size: 0x{:X} bytes", image.size_of_image);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn load_file(
        &self,
        path: &std::path::Path,
        address_space: &AddressSpace,
    ) -> Result<LoadedImage> {
        let pe_bytes = std::fs::read(path)
            .map_err(|e| Error::Other(format!("Failed to read PE file: {e}")))?;

        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        self.load(&pe_bytes, address_space, name)
    }

    /// Applies base relocations to fix up absolute addresses in the image.
    ///
    /// When a PE image is loaded at a different address than its preferred base,
    /// absolute addresses embedded in the code and data sections need to be adjusted.
    /// This method parses the relocation directory and applies the necessary fixups.
    ///
    /// # PE Relocation Format
    ///
    /// The base relocation table consists of blocks, each covering a 4KB page:
    /// - Block header: 4-byte page RVA + 4-byte block size
    /// - Block entries: Array of 16-bit values (type in high 4 bits, offset in low 12 bits)
    ///
    /// # Arguments
    ///
    /// * `pe` - Parsed PE structure containing relocation directory info
    /// * `image_data` - Mutable image buffer to apply fixups to
    /// * `delta` - Difference between actual and preferred base address
    /// * `is_64_bit` - Whether the image is PE32+ (affects relocation types)
    ///
    /// # Errors
    ///
    /// Returns an error if relocations are required but the relocation directory
    /// is missing or malformed.
    fn apply_relocations(
        pe: &goblin::pe::PE,
        image_data: &mut [u8],
        delta: i64,
        is_64_bit: bool,
    ) -> Result<()> {
        // Get the base relocation directory (index 5)
        let reloc_dir = pe
            .header
            .optional_header
            .as_ref()
            .and_then(|oh| oh.data_directories.get_base_relocation_table());

        let Some(reloc_dir) = reloc_dir else {
            // No relocation directory - image cannot be relocated
            // This is only an error if we actually need to relocate
            if delta != 0 {
                return Err(Error::Other(
                    "Image requires relocation but has no relocation directory".to_string(),
                ));
            }
            return Ok(());
        };

        if reloc_dir.size == 0 {
            if delta != 0 {
                return Err(Error::Other(
                    "Image requires relocation but has empty relocation directory".to_string(),
                ));
            }
            return Ok(());
        }

        let reloc_rva = reloc_dir.virtual_address as usize;
        let reloc_size = reloc_dir.size as usize;

        // Ensure relocation data is within bounds
        let end = reloc_rva
            .checked_add(reloc_size)
            .ok_or_else(|| malformed_error!("PE relocation directory range overflow"))?;
        if end > image_data.len() {
            return Err(Error::Other(
                "Relocation directory extends beyond image bounds".to_string(),
            ));
        }

        // Process relocation blocks
        let mut offset = reloc_rva;

        while offset.checked_add(8).is_some_and(|next| next <= end) {
            // Read block header
            let header_end = offset
                .checked_add(8)
                .ok_or_else(|| malformed_error!("PE relocation block header overflow"))?;
            let header_slice = image_data
                .get(offset..header_end)
                .ok_or(out_of_bounds_error!())?;
            let page_rva_bytes = header_slice.get(0..4).ok_or(out_of_bounds_error!())?;
            let block_size_bytes = header_slice.get(4..8).ok_or(out_of_bounds_error!())?;
            let page_rva = u32::from_le_bytes(
                page_rva_bytes
                    .try_into()
                    .map_err(|_| out_of_bounds_error!())?,
            ) as usize;
            let block_size = u32::from_le_bytes(
                block_size_bytes
                    .try_into()
                    .map_err(|_| out_of_bounds_error!())?,
            ) as usize;

            // Validate block size
            let block_end = match offset.checked_add(block_size) {
                Some(v) => v,
                None => break,
            };
            if block_size < 8 || block_end > end {
                break;
            }

            // Process entries in this block
            let entry_count = (block_size.saturating_sub(8)) / 2;
            for i in 0..entry_count {
                let entry_offset = match offset
                    .checked_add(8)
                    .and_then(|base| i.checked_mul(2).and_then(|delta| base.checked_add(delta)))
                {
                    Some(v) => v,
                    None => break,
                };
                let entry_end = match entry_offset.checked_add(2) {
                    Some(v) => v,
                    None => break,
                };
                if entry_end > image_data.len() {
                    break;
                }

                let entry_bytes = image_data
                    .get(entry_offset..entry_end)
                    .ok_or(out_of_bounds_error!())?;
                let entry =
                    u16::from_le_bytes(entry_bytes.try_into().map_err(|_| out_of_bounds_error!())?);

                let reloc_type = entry >> 12;
                let reloc_offset = (entry & 0x0FFF) as usize;
                let target_offset = match page_rva.checked_add(reloc_offset) {
                    Some(v) => v,
                    None => break,
                };

                match reloc_type {
                    // 32-bit fixup
                    reloc_type::IMAGE_REL_BASED_HIGHLOW
                        if target_offset
                            .checked_add(4)
                            .is_some_and(|t| t <= image_data.len()) =>
                    {
                        let target_end = target_offset
                            .checked_add(4)
                            .ok_or_else(|| malformed_error!("PE reloc target overflow"))?;
                        let val_slice = image_data
                            .get(target_offset..target_end)
                            .ok_or(out_of_bounds_error!())?;
                        let value = u32::from_le_bytes(
                            val_slice.try_into().map_err(|_| out_of_bounds_error!())?,
                        );
                        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                        let new_value = i64::from(value).wrapping_add(delta) as u32;
                        let dst = image_data
                            .get_mut(target_offset..target_end)
                            .ok_or(out_of_bounds_error!())?;
                        dst.copy_from_slice(&new_value.to_le_bytes());
                    }
                    // 64-bit fixup
                    reloc_type::IMAGE_REL_BASED_DIR64
                        if is_64_bit
                            && target_offset
                                .checked_add(8)
                                .is_some_and(|t| t <= image_data.len()) =>
                    {
                        let target_end = target_offset
                            .checked_add(8)
                            .ok_or_else(|| malformed_error!("PE reloc target overflow"))?;
                        let val_slice = image_data
                            .get(target_offset..target_end)
                            .ok_or(out_of_bounds_error!())?;
                        let value = u64::from_le_bytes(
                            val_slice.try_into().map_err(|_| out_of_bounds_error!())?,
                        );
                        let new_value = value.cast_signed().wrapping_add(delta).cast_unsigned();
                        let dst = image_data
                            .get_mut(target_offset..target_end)
                            .ok_or(out_of_bounds_error!())?;
                        dst.copy_from_slice(&new_value.to_le_bytes());
                    }
                    _ => {
                        // ABSOLUTE (padding), out-of-bounds, or unsupported relocation type - skip
                    }
                }
            }

            offset = match offset.checked_add(block_size) {
                Some(v) => v,
                None => break,
            };
        }

        Ok(())
    }
}

impl Default for PeLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_loader_config() {
        let config = PeLoaderConfig::new()
            .with_base_address(0x10000000)
            .without_permissions();

        assert_eq!(config.base_address, Some(0x10000000));
        assert!(!config.apply_permissions);
    }

    #[test]
    fn test_loaded_image_methods() {
        let image = LoadedImage {
            base_address: 0x400000,
            size_of_image: 0x10000,
            entry_point: Some(0x1000),
            is_64_bit: false,
            sections: vec![LoadedSection {
                name: ".text".to_string(),
                virtual_address: 0x1000,
                virtual_size: 0x5000,
                raw_size: 0x4800,
                protection: MemoryProtection::READ | MemoryProtection::EXECUTE,
                is_code: true,
                is_initialized_data: false,
                is_uninitialized_data: false,
            }],
            name: "test.exe".to_string(),
            file_size: 0x8000,
            clr_header_rva: Some(0x2000),
            clr_header_size: Some(0x48),
        };

        assert_eq!(image.entry_point_va(), Some(0x401000));
        assert_eq!(image.rva_to_va(0x2000), 0x402000);
        assert!(image.contains_rva(0x5000));
        assert!(!image.contains_rva(0x20000));
        assert!(image.is_dotnet());

        let section = image.section_for_rva(0x2000);
        assert!(section.is_some());
        assert_eq!(section.unwrap().name, ".text");
    }

    #[test]
    fn test_loaded_section_protection() {
        let section = LoadedSection {
            name: ".text".to_string(),
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_size: 0x800,
            protection: MemoryProtection::READ | MemoryProtection::EXECUTE,
            is_code: true,
            is_initialized_data: false,
            is_uninitialized_data: false,
        };

        assert!(section.protection.contains(MemoryProtection::READ));
        assert!(section.protection.contains(MemoryProtection::EXECUTE));
        assert!(!section.protection.contains(MemoryProtection::WRITE));
        assert!(section.is_code);
    }

    #[test]
    fn test_pe_loader_config_without_relocations() {
        let config = PeLoaderConfig::new().without_relocations();

        assert!(!config.apply_relocations);
        // Defaults should still be intact
        assert!(config.apply_permissions);
        assert!(config.base_address.is_none());
    }

    #[test]
    fn test_pe_loader_config_defaults() {
        let config = PeLoaderConfig::default();

        assert!(config.apply_relocations);
        assert!(config.apply_permissions);
        assert!(config.base_address.is_none());
    }

    #[test]
    fn test_relocation_type_constants() {
        // Verify relocation type constants match PE specification
        assert_eq!(reloc_type::IMAGE_REL_BASED_ABSOLUTE, 0);
        assert_eq!(reloc_type::IMAGE_REL_BASED_HIGHLOW, 3);
        assert_eq!(reloc_type::IMAGE_REL_BASED_DIR64, 10);
    }

    /// Helper to create a minimal valid PE header for testing
    fn create_test_pe_bytes(image_base: u64, with_relocations: bool) -> Vec<u8> {
        // Create minimal 32-bit PE with optional relocation section
        let mut pe = Vec::new();

        // DOS Header
        pe.extend_from_slice(b"MZ"); // e_magic
        pe.resize(0x3C, 0); // Fill to e_lfanew offset
        pe.extend_from_slice(&0x80u32.to_le_bytes()); // e_lfanew points to PE header

        // DOS stub (fill to 0x80)
        pe.resize(0x80, 0);

        // PE Signature
        pe.extend_from_slice(b"PE\0\0");

        // COFF Header (20 bytes)
        pe.extend_from_slice(&0x014Cu16.to_le_bytes()); // Machine: i386
        pe.extend_from_slice(&0x0002u16.to_le_bytes()); // NumberOfSections: 2 (.text, .reloc)
        pe.extend_from_slice(&0u32.to_le_bytes()); // TimeDateStamp
        pe.extend_from_slice(&0u32.to_le_bytes()); // PointerToSymbolTable
        pe.extend_from_slice(&0u32.to_le_bytes()); // NumberOfSymbols
        pe.extend_from_slice(&0x00E0u16.to_le_bytes()); // SizeOfOptionalHeader (224 for PE32)
        pe.extend_from_slice(&0x0103u16.to_le_bytes()); // Characteristics: executable, no relocs stripped, 32-bit

        // Optional Header (PE32)
        pe.extend_from_slice(&0x010Bu16.to_le_bytes()); // Magic: PE32
        pe.extend_from_slice(&[0u8; 2]); // Linker version
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        pe.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // AddressOfEntryPoint
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        pe.extend_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData

        // Windows-specific fields
        pe.extend_from_slice(&(image_base as u32).to_le_bytes()); // ImageBase
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
        pe.extend_from_slice(&0x0006u16.to_le_bytes()); // MajorOperatingSystemVersion
        pe.extend_from_slice(&0x0000u16.to_le_bytes()); // MinorOperatingSystemVersion
        pe.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
        pe.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
        pe.extend_from_slice(&0x0006u16.to_le_bytes()); // MajorSubsystemVersion
        pe.extend_from_slice(&0x0000u16.to_le_bytes()); // MinorSubsystemVersion
        pe.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        pe.extend_from_slice(&0x4000u32.to_le_bytes()); // SizeOfImage
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        pe.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        pe.extend_from_slice(&0x0003u16.to_le_bytes()); // Subsystem: Console
        pe.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
        pe.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfStackReserve
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfStackCommit
        pe.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfHeapReserve
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeapCommit
        pe.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

        // Data Directories (16 entries, 8 bytes each)
        // 0: Export
        pe.extend_from_slice(&[0u8; 8]);
        // 1: Import
        pe.extend_from_slice(&[0u8; 8]);
        // 2: Resource
        pe.extend_from_slice(&[0u8; 8]);
        // 3: Exception
        pe.extend_from_slice(&[0u8; 8]);
        // 4: Security
        pe.extend_from_slice(&[0u8; 8]);
        // 5: Base Relocation
        if with_relocations {
            pe.extend_from_slice(&0x3000u32.to_le_bytes()); // VirtualAddress of .reloc
            pe.extend_from_slice(&0x10u32.to_le_bytes()); // Size of relocation data
        } else {
            pe.extend_from_slice(&[0u8; 8]);
        }
        // 6-15: Other directories
        pe.extend_from_slice(&[0u8; 80]);

        // Section Headers (40 bytes each)
        // .text section
        pe.extend_from_slice(b".text\0\0\0"); // Name
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
        pe.extend_from_slice(&[0u8; 12]); // PointerToRelocations, PointerToLinenumbers, etc.
        pe.extend_from_slice(&0x60000020u32.to_le_bytes()); // Characteristics: CODE | EXECUTE | READ

        // .reloc section
        pe.extend_from_slice(b".reloc\0\0"); // Name
        pe.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualSize
        pe.extend_from_slice(&0x3000u32.to_le_bytes()); // VirtualAddress
        pe.extend_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe.extend_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
        pe.extend_from_slice(&[0u8; 12]); // PointerToRelocations, etc.
        pe.extend_from_slice(&0x42000040u32.to_le_bytes()); // Characteristics: INITIALIZED_DATA | DISCARDABLE | READ

        // Pad to file offset 0x200 (section alignment)
        pe.resize(0x200, 0);

        // .text section data (at offset 0x200)
        // Write a 32-bit absolute address that should be relocated
        // At file offset 0x200 + 0x10 = 0x210, which maps to RVA 0x1000 + 0x10 = 0x1010
        // Store absolute address image_base + 0x2000
        pe.resize(0x400, 0); // Allocate space for .text section
        let abs_addr = (image_base as u32) + 0x2000;
        pe[0x210..0x214].copy_from_slice(&abs_addr.to_le_bytes());

        // .reloc section data (at offset 0x400)
        if with_relocations {
            // Relocation block for page at RVA 0x1000
            pe.extend_from_slice(&0x1000u32.to_le_bytes()); // PageRVA
            pe.extend_from_slice(&0x10u32.to_le_bytes()); // BlockSize (8 header + 2*4 entries)
                                                          // Entry 1: HIGHLOW relocation at offset 0x10
            let entry1: u16 = (3 << 12) | 0x10; // Type 3 (HIGHLOW), offset 0x10
            pe.extend_from_slice(&entry1.to_le_bytes());
            // Entry 2: ABSOLUTE (padding)
            pe.extend_from_slice(&0u16.to_le_bytes());
            // Entry 3: ABSOLUTE (padding)
            pe.extend_from_slice(&0u16.to_le_bytes());
            // Entry 4: ABSOLUTE (padding)
            pe.extend_from_slice(&0u16.to_le_bytes());
        }

        pe.resize(0x600, 0);
        pe
    }

    #[test]
    fn test_load_pe_at_preferred_base() {
        let pe_bytes = create_test_pe_bytes(0x400000, true);
        let address_space = AddressSpace::new();
        let loader = PeLoader::new();

        let image = loader.load(&pe_bytes, &address_space, "test.exe").unwrap();

        assert_eq!(image.base_address, 0x400000);
        assert!(!image.is_64_bit);

        // Verify the absolute address was NOT modified (no relocation needed)
        let data = address_space.read(0x400000 + 0x1010, 4).unwrap();
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(value, 0x400000 + 0x2000);
    }

    #[test]
    fn test_load_pe_with_relocation() {
        let pe_bytes = create_test_pe_bytes(0x400000, true);
        let address_space = AddressSpace::new();
        let config = PeLoaderConfig::new().with_base_address(0x10000000);
        let loader = PeLoader::with_config(config);

        let image = loader.load(&pe_bytes, &address_space, "test.exe").unwrap();

        assert_eq!(image.base_address, 0x10000000);

        // Verify the absolute address WAS relocated
        // Original: 0x400000 + 0x2000 = 0x402000
        // Delta: 0x10000000 - 0x400000 = 0x0FC00000
        // New: 0x402000 + 0x0FC00000 = 0x10002000
        let data = address_space.read(0x10000000 + 0x1010, 4).unwrap();
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(value, 0x10000000 + 0x2000);
    }

    #[test]
    fn test_load_pe_without_relocation_disabled() {
        let pe_bytes = create_test_pe_bytes(0x400000, true);
        let address_space = AddressSpace::new();
        let config = PeLoaderConfig::new()
            .with_base_address(0x10000000)
            .without_relocations();
        let loader = PeLoader::with_config(config);

        let image = loader.load(&pe_bytes, &address_space, "test.exe").unwrap();

        assert_eq!(image.base_address, 0x10000000);

        // Verify the absolute address was NOT modified (relocations disabled)
        let data = address_space.read(0x10000000 + 0x1010, 4).unwrap();
        let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        // Original value should be preserved
        assert_eq!(value, 0x400000 + 0x2000);
    }

    #[test]
    fn test_load_pe_no_reloc_section_at_preferred_base() {
        // PE without relocation section, loaded at preferred base - should work
        let pe_bytes = create_test_pe_bytes(0x400000, false);
        let address_space = AddressSpace::new();
        let loader = PeLoader::new();

        let result = loader.load(&pe_bytes, &address_space, "test.exe");
        assert!(result.is_ok());
    }
}
