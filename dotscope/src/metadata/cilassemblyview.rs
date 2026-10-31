//! Raw assembly view for editing and modification operations.
//!
//! This module provides the [`crate::metadata::cilassemblyview::CilAssemblyView`] struct, which offers a read-only
//! representation of .NET assemblies that maintains a 1:1 mapping with the underlying
//! file structure. Unlike [`crate::CilObject`] which provides a fully processed and
//! resolved view optimized for analysis, [`crate::metadata::cilassemblyview::CilAssemblyView`] preserves the raw metadata
//! structure to enable future editing and modification operations.
//!
//! # Architecture
//!
//! The module is built around a self-referencing pattern that enables efficient access to
//! file data while maintaining memory safety. The architecture provides:
//!
//! - **Raw Structure Access**: Direct access to metadata tables and streams without resolution
//! - **Immutable View**: Read-only operations to ensure data integrity during analysis
//! - **Editing Foundation**: Structured to support future writable operations
//! - **Memory Efficient**: Self-referencing pattern avoids data duplication
//! - **No Validation**: Pure parsing without format validation or compliance checks
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::metadata::cilassemblyview::CilAssemblyView`] - Main assembly view struct with file-mapped data
//! - [`crate::metadata::cilassemblyview::CilAssemblyViewData`] - Internal data structure holding raw metadata
//!
//! ## Access Methods
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::tables`] - Raw metadata tables without semantic resolution
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::strings`] - Direct access to strings heap (#Strings)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::userstrings`] - Direct access to user strings heap (#US)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::guids`] - Direct access to GUID heap (#GUID)
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::blobs`] - Direct access to blob heap (#Blob)
//!
//! ## Conversion Methods
//! - [`crate::metadata::cilassemblyview::CilAssemblyView::to_owned`] - Convert to mutable [`crate::CilAssembly`] for editing
//!
//! # Usage Examples
//!
//! ## Basic Raw Metadata Access
//!
//! ```rust,no_run
//! use dotscope::CilAssemblyView;
//! use std::path::Path;
//!
//! // Load assembly for potential editing operations
//! let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
//!
//! // Access raw metadata structures
//! if let Some(tables) = view.tables() {
//!     println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
//! }
//!
//! // Access string heaps directly
//! if let Some(strings) = view.strings() {
//!     if let Ok(name) = strings.get(0x123) {
//!         println!("Raw string: {}", name);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Converting to Mutable Assembly
//!
//! ```rust,no_run
//! use dotscope::{CilAssemblyView, CilAssembly};
//! use std::path::Path;
//!
//! // Load raw view
//! let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
//!
//! // Convert to mutable assembly for editing
//! let mut assembly = view.to_owned();
//!
//! // Now you can perform editing operations
//! let string_index = assembly.string_add("New String")?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Analyzing Raw Structures
//!
//! ```rust,no_run
//! use dotscope::CilAssemblyView;
//! use std::path::Path;
//!
//! let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
//!
//! // Direct access to CLR header
//! let cor20 = view.cor20header();
//! println!("Runtime version: {}.{}", cor20.major_runtime_version, cor20.minor_runtime_version);
//!
//! // Raw metadata root access
//! let root = view.metadata_root();
//! println!("Metadata signature: {:?}", root.signature);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`crate::metadata::cilassemblyview::CilAssemblyView`] is [`std::marker::Send`] and [`std::marker::Sync`] as it provides read-only access
//! to immutable file data. Multiple threads can safely access the same view concurrently
//! without additional synchronization.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::CilAssembly`] - Provides conversion to mutable assembly for editing operations
//! - [`crate::metadata::streams`] - Uses stream types for direct heap access
//! - [`crate::metadata::cor20header`] - Provides CLR header information
//! - File I/O abstraction for memory-mapped or in-memory access

use std::{path::Path, sync::Arc};

use log::debug;
use ouroboros::self_referencing;

use crate::{
    cilassembly::CilAssembly,
    file::File,
    metadata::{
        cor20header::Cor20Header,
        diagnostics::{DiagnosticCategory, Diagnostics},
        identity::{AssemblyIdentity, AssemblyVersion, Identity, ProcessorArchitecture},
        root::Root,
        streams::{Blob, Guid, StreamHeader, Strings, TablesHeader, UserStrings},
        tables::{skip_unreadable, AssemblyProcessorRaw, AssemblyRaw, AssemblyRefRaw, ModuleRaw},
        validation::ValidationEngine,
    },
    Error, Result, ValidationConfig,
};

/// Raw assembly view data holding references to file structures.
///
/// `CilAssemblyViewData` manages the parsed metadata structures while maintaining
/// direct references to the underlying file data. This structure is designed to
/// preserve the raw layout of metadata streams and tables as they appear in the
/// PE file, enabling future editing operations.
///
/// # Layout Preservation
///
/// Unlike `CilObjectData` which creates resolved and cross-referenced structures,
/// `CilAssemblyViewData` maintains:
/// - Raw metadata table data without resolution
/// - Direct stream references without semantic processing
/// - Original file offsets and layout information
/// - Unprocessed blob and signature data
pub struct CilAssemblyViewData<'a> {
    /// Reference to the owning File structure
    pub file: Arc<File>,

    /// Raw file data slice
    pub data: &'a [u8],

    /// COR20 header containing .NET-specific PE information
    pub cor20header: Cor20Header,

    /// Metadata root header with stream directory
    pub metadata_root: Root,

    /// Raw metadata tables header from #~ or #- stream
    pub metadata_tables: Option<TablesHeader<'a>>,

    /// Strings heap from #Strings stream
    pub strings: Option<Strings<'a>>,

    /// User strings heap from #US stream
    pub userstrings: Option<UserStrings<'a>>,

    /// GUID heap from #GUID stream
    pub guids: Option<Guid<'a>>,

    /// Blob heap from #Blob stream
    pub blobs: Option<Blob<'a>>,

    /// Diagnostics collected during loading (duplicate heaps, structural issues, etc.)
    pub diagnostics: Arc<Diagnostics>,
}

impl<'a> CilAssemblyViewData<'a> {
    /// Creates a new `CilAssemblyViewData` from file data.
    ///
    /// This method parses the essential .NET metadata structures while preserving
    /// their raw form. Unlike `CilObjectData::from_file`, this method:
    /// - Does not resolve cross-references between tables
    /// - Does not create semantic object representations
    /// - Preserves original file layout information
    /// - Focuses on structural metadata access
    /// - Performs no validation or compliance checking
    ///
    /// # Arguments
    ///
    /// * `file` - The File containing PE data
    /// * `data` - Raw file data slice
    ///
    /// # Returns
    ///
    /// Returns the parsed `CilAssemblyViewData` structure or an error if
    /// essential structures cannot be located (e.g., missing CLR header).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly (missing CLR header).
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the file data is truncated or corrupted.
    pub fn from_dotscope_file(file: Arc<File>, data: &'a [u8]) -> Result<Self> {
        let (clr_rva, clr_size) = file.clr().ok_or(Error::NotSupported)?;

        if clr_rva == 0 || clr_size == 0 {
            return Err(Error::NotSupported);
        }

        // Each structure lies within its section's data, where the runtime reads it
        let clr_offset = file.rva_to_offset(clr_rva)?;
        if clr_size > file.section_bounded(clr_rva)?.len() {
            return Err(out_of_bounds_error!());
        }
        let clr_end = clr_offset
            .checked_add(clr_size)
            .ok_or(out_of_bounds_error!())?;

        let cor20_header = Cor20Header::read(
            data.get(clr_offset..clr_end)
                .ok_or(out_of_bounds_error!())?,
        )?;
        debug!(
            "PE header: CLR {}.{}, metadata at RVA 0x{:X}",
            cor20_header.major_runtime_version,
            cor20_header.minor_runtime_version,
            cor20_header.meta_data_rva
        );

        let metadata_offset = file.rva_to_offset(cor20_header.meta_data_rva as usize)?;
        if cor20_header.meta_data_size as usize
            > file
                .section_bounded(cor20_header.meta_data_rva as usize)?
                .len()
        {
            return Err(out_of_bounds_error!());
        }
        let metadata_end = metadata_offset
            .checked_add(cor20_header.meta_data_size as usize)
            .ok_or(out_of_bounds_error!())?;

        let metadata_slice = data
            .get(metadata_offset..metadata_end)
            .ok_or(out_of_bounds_error!())?;
        let metadata_root = Root::read(metadata_slice)?;
        let stream_names: Vec<&str> = metadata_root
            .stream_headers
            .iter()
            .map(|s| s.name.as_str())
            .collect();
        debug!("Metadata streams: {}", stream_names.join(", "));

        let diagnostics = Arc::new(Diagnostics::new());

        // Each stream is read from the header the runtime reads (`Root::stream`); a header
        // it does not read, a repeat or a name it gives no stream, is only recorded.
        let stream_data = |header: &StreamHeader| -> Result<&[u8]> {
            let start = header.offset as usize;
            let end = start
                .checked_add(header.size as usize)
                .ok_or(out_of_bounds_error!())?;
            metadata_slice.get(start..end).ok_or(out_of_bounds_error!())
        };
        for unread in metadata_root.unread_streams() {
            diagnostics.info(
                DiagnosticCategory::Heap,
                format!(
                    "metadata stream '{}' at offset {} is not read: the runtime reads another header of that name, or gives the name no stream",
                    unread.name, unread.offset
                ),
            );
        }

        // `#JTD` beside uncompressed tables is the CLR's "minimal delta" marker: it then reads
        // every index column as four bytes, whatever the row counts and heap sizes say.
        let minimal_delta = metadata_root
            .stream_headers
            .iter()
            .any(|s| s.name == "#JTD");
        let metadata_tables = metadata_root
            .tables_stream()
            .map(|header| {
                stream_data(header)
                    .and_then(|data| TablesHeader::from(data, minimal_delta && header.name == "#-"))
            })
            .transpose()?;
        let strings_heap = metadata_root
            .stream("#Strings")
            .map(|header| stream_data(header).and_then(Strings::from))
            .transpose()?;
        let userstrings_heap = metadata_root
            .stream("#US")
            .map(|header| stream_data(header).and_then(UserStrings::from))
            .transpose()?;
        let guid_heap = metadata_root
            .stream("#GUID")
            .map(|header| stream_data(header).and_then(Guid::from))
            .transpose()?;
        let blob_heap = metadata_root
            .stream("#Blob")
            .map(|header| stream_data(header).and_then(Blob::from))
            .transpose()?;

        Ok(CilAssemblyViewData {
            file,
            data,
            cor20header: cor20_header,
            metadata_root,
            metadata_tables,
            strings: strings_heap,
            userstrings: userstrings_heap,
            guids: guid_heap,
            blobs: blob_heap,
            diagnostics,
        })
    }
}

#[self_referencing]
/// A read-only view of a .NET assembly optimized for editing operations.
///
/// `CilAssemblyView` provides raw access to .NET assembly metadata structures
/// while maintaining a 1:1 mapping with the underlying file format. This design
/// preserves the original file layout and structure to enable future editing
/// and modification capabilities.
///
/// # Key Differences from CilObject
///
/// - **Raw Access**: Direct access to metadata tables without semantic resolution
/// - **Structure Preservation**: Maintains original file layout and offsets
/// - **Editing Foundation**: Designed as the base for modification operations
/// - **Minimal Processing**: No cross-reference resolution or object construction
/// - **No Validation**: Pure parsing without format validation or compliance checks
///
/// # Architecture
///
/// The view uses a self-referencing pattern to maintain efficient access to
/// file data while ensuring memory safety. The structure provides:
/// - Direct access to all metadata streams (#~, #Strings, #US, #GUID, #Blob)
/// - Raw metadata table data without semantic interpretation
/// - Original stream headers and layout information
/// - File-level operations for RVA resolution and section access
///
/// # Thread Safety
///
/// `CilAssemblyView` is designed for concurrent read access and implements
/// `Send` and `Sync` for safe use across threads. All operations are read-only
/// and do not modify the underlying file data.
pub struct CilAssemblyView {
    /// Holds the input data, either as memory buffer or memory-mapped file
    file: Arc<File>,

    #[borrows(file)]
    #[not_covariant]
    /// Holds direct references to metadata structures in the file
    data: CilAssemblyViewData<'this>,
}

impl CilAssemblyView {
    /// Creates a new `CilAssemblyView` by loading a .NET assembly from a path.
    ///
    /// This method loads the assembly and parses essential metadata structures
    /// while preserving their raw format. The file is memory-mapped for
    /// efficient access to large assemblies.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .NET assembly file (.dll, .exe, or .netmodule).
    ///   Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the file cannot be loaded or essential structures are missing.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the file cannot be read.
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly.
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the file data is corrupted.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// // With Path
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    ///
    /// // With string slice
    /// let view = CilAssemblyView::from_path("assembly.dll")?;
    ///
    /// // Access raw metadata
    /// let root = view.metadata_root();
    /// println!("Metadata root loaded");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_path_with_validation(path, ValidationConfig::production())
    }

    /// Creates a new `CilAssemblyView` by loading a .NET assembly from a path with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Raw validation (stage 1) is performed if enabled in the configuration.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .NET assembly file (.dll, .exe, or .netmodule).
    ///   Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the file cannot be loaded, essential structures are missing,
    /// or validation checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the file cannot be read.
    /// Returns [`crate::Error::NotSupported`] if the file is not a .NET assembly.
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the file data is corrupted.
    /// Returns validation errors if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::path::Path;
    ///
    /// // Load with minimal validation for maximum performance
    /// let view = CilAssemblyView::from_path_with_validation(
    ///     "assembly.dll",
    ///     ValidationConfig::minimal()
    /// )?;
    ///
    /// // Load with comprehensive validation for maximum safety
    /// let view = CilAssemblyView::from_path_with_validation(
    ///     Path::new("assembly.dll"),
    ///     ValidationConfig::comprehensive()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_path_with_validation(
        path: impl AsRef<Path>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let input = Arc::new(File::from_path(path)?);
        Self::load_with_validation(input, validation_config)
    }

    /// Creates a new `CilAssemblyView` by parsing a .NET assembly from a memory buffer.
    ///
    /// This method is useful for analyzing assemblies that are already loaded
    /// in memory or obtained from external sources. The data is managed
    /// internally to ensure proper lifetime handling.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the data is not a .NET assembly.
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the data is corrupted or truncated.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    ///
    /// let file_data = std::fs::read("assembly.dll")?;
    /// let view = CilAssemblyView::from_mem(file_data)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_mem(data: Vec<u8>) -> Result<Self> {
        Self::from_mem_with_validation(data, ValidationConfig::production())
    }

    /// Creates a new `CilAssemblyView` by parsing a .NET assembly from a memory buffer with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Raw validation (stage 1) is performed if enabled in the configuration.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a `CilAssemblyView` providing raw access to assembly metadata
    /// or an error if the data cannot be parsed or validation checks fail.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] if the data is not a .NET assembly.
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the data is corrupted or truncated.
    /// Returns validation errors if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    ///
    /// let file_data = std::fs::read("assembly.dll")?;
    ///
    /// // Load with production validation settings
    /// let view = CilAssemblyView::from_mem_with_validation(
    ///     file_data,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_mem_with_validation(
        data: Vec<u8>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let input = Arc::new(File::from_mem(data)?);
        Self::load_with_validation(input, validation_config)
    }

    /// Creates a CilAssemblyView from a dotscope::file::File.
    ///
    /// This allows you to inspect the PE file before deciding to parse the .NET metadata,
    /// or to reuse an existing File instance.
    ///
    /// # Arguments
    /// * `file` - A File instance containing a .NET assembly
    ///
    /// # Errors
    /// Returns an error if:
    /// - The File doesn't contain a CLR runtime header
    /// - The .NET metadata is corrupted or invalid
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{File, CilAssemblyView};
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("assembly.dll"))?;
    /// if file.is_clr() {
    ///     let view = CilAssemblyView::from_dotscope_file(file)?;
    ///     println!("Loaded .NET assembly view");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_dotscope_file(file: File) -> Result<Self> {
        Self::from_dotscope_file_with_validation(file, ValidationConfig::production())
    }

    /// Creates a CilAssemblyView from a dotscope::file::File with validation.
    ///
    /// # Arguments
    /// * `file` - A File instance containing a .NET assembly
    /// * `validation_config` - Validation configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - The File doesn't contain a CLR runtime header
    /// - The .NET metadata is corrupted or invalid
    /// - Validation checks fail
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{File, CilAssemblyView, ValidationConfig};
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("assembly.dll"))?;
    /// let view = CilAssemblyView::from_dotscope_file_with_validation(
    ///     file,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_dotscope_file_with_validation(
        file: File,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let file_arc = Arc::new(file);
        Self::load_with_validation(file_arc, validation_config)
    }

    /// Creates a CilAssemblyView from an opened std::fs::File.
    ///
    /// The file is memory-mapped for efficient access.
    ///
    /// # Arguments
    /// * `file` - An opened file handle to a .NET assembly
    ///
    /// # Errors
    /// Returns an error if the file is not a valid .NET assembly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::fs::File;
    ///
    /// let std_file = File::open("assembly.dll")?;
    /// let view = CilAssemblyView::from_std_file(std_file)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_std_file(file: std::fs::File) -> Result<Self> {
        Self::from_std_file_with_validation(file, ValidationConfig::production())
    }

    /// Creates a CilAssemblyView from an opened std::fs::File with validation.
    ///
    /// The file is memory-mapped for efficient access.
    ///
    /// # Arguments
    /// * `file` - An opened file handle to a .NET assembly
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Errors
    /// Returns an error if the file is not a valid .NET assembly or if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::fs::File;
    ///
    /// let std_file = File::open("assembly.dll")?;
    /// let view = CilAssemblyView::from_std_file_with_validation(
    ///     std_file,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_std_file_with_validation(
        file: std::fs::File,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let pe_file = File::from_std_file(file)?;
        Self::from_dotscope_file_with_validation(pe_file, validation_config)
    }

    /// Creates a CilAssemblyView from any reader.
    ///
    /// # Arguments
    /// * `reader` - Any type implementing Read
    ///
    /// # Errors
    /// Returns an error if the data is not a valid .NET assembly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::io::Cursor;
    ///
    /// let data = vec![/* PE bytes */];
    /// let cursor = Cursor::new(data);
    /// let view = CilAssemblyView::from_reader(cursor)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Self::from_reader_with_validation(reader, ValidationConfig::production())
    }

    /// Creates a CilAssemblyView from any reader with validation.
    ///
    /// # Arguments
    /// * `reader` - Any type implementing Read
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Errors
    /// Returns an error if the data is not a valid .NET assembly or if validation checks fail.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::io::Cursor;
    ///
    /// let data = vec![/* PE bytes */];
    /// let cursor = Cursor::new(data);
    /// let view = CilAssemblyView::from_reader_with_validation(
    ///     cursor,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_reader_with_validation<R: std::io::Read>(
        reader: R,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let pe_file = File::from_reader(reader)?;
        Self::from_dotscope_file_with_validation(pe_file, validation_config)
    }

    /// Creates a `CilAssemblyView` from an owned [`File`] with custom validation.
    ///
    /// The `File` is wrapped in an `Arc` internally. Used when rebuilding a
    /// view after byte-level patches have been committed in-place (e.g. from
    /// `WorkingAssembly::commit`).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be parsed as a .NET assembly.
    pub fn from_file_with_validation(
        file: File,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        Self::load_with_validation(Arc::new(file), validation_config)
    }

    /// Consumes this view and returns the underlying owned [`File`].
    ///
    /// Drops the borrowing metadata structures first, which reduces the
    /// `Arc<File>` reference count to 1, then unwraps the `Arc` to obtain
    /// exclusive ownership of the `File`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `Arc<File>` still has multiple owners at the
    /// time of unwrapping, which indicates a bug in the caller.
    pub fn into_file(self) -> Result<File> {
        // into_heads() is ouroboros-generated and accessible within this module.
        // It drops the borrowing CilAssemblyViewData (which holds one Arc clone)
        // before returning the owned `file: Arc<File>` - leaving count = 1.
        let heads = self.into_heads();
        Arc::try_unwrap(heads.file).map_err(|_| {
            Error::Other(
                "CilAssemblyView::into_file: Arc<File> has unexpected extra owners".to_string(),
            )
        })
    }

    /// Internal method for loading a CilAssemblyView from a File structure with validation.
    ///
    /// This method serves as the common implementation for validation-enabled loading operations.
    /// It first loads the assembly normally, then performs raw validation (stage 1) if enabled
    /// in the configuration.
    ///
    /// # Arguments
    ///
    /// * `file` - Arc-wrapped File containing the PE assembly data
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a fully constructed `CilAssemblyView` with parsed metadata structures
    /// or an error if parsing or validation fails.
    pub(crate) fn load_with_validation(
        file: Arc<File>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        let view = CilAssemblyView::try_new(file, |file| {
            CilAssemblyViewData::from_dotscope_file(file.clone(), file.data())
        })?;

        if validation_config.should_validate_raw() {
            view.validate(validation_config)?;
        }

        Ok(view)
    }

    /// Returns the COR20 header containing .NET-specific PE information.
    ///
    /// The COR20 header provides essential information about the .NET assembly
    /// including metadata location, entry point, and runtime flags.
    ///
    /// # Returns
    ///
    /// Reference to the [`Cor20Header`] structure.
    #[must_use]
    pub fn cor20header(&self) -> &Cor20Header {
        self.with_data(|data| &data.cor20header)
    }

    /// Returns the metadata root header containing stream directory information.
    ///
    /// The metadata root is the entry point to .NET metadata, containing
    /// version information and the directory of all metadata streams.
    ///
    /// # Returns
    ///
    /// Reference to the [`Root`] structure.
    #[must_use]
    pub fn metadata_root(&self) -> &Root {
        self.with_data(|data| &data.metadata_root)
    }

    /// Returns raw access to the metadata tables from the #~ or #- stream.
    ///
    /// Provides direct access to the metadata tables structure without
    /// semantic interpretation or cross-reference resolution.
    ///
    /// # Returns
    ///
    /// - `Some(&TablesHeader)` if metadata tables are present
    /// - `None` if no tables stream exists
    #[must_use]
    pub fn tables(&self) -> Option<&TablesHeader<'_>> {
        self.with_data(|data| data.metadata_tables.as_ref())
    }

    /// Returns direct access to the strings heap from the #Strings stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Strings)` if the strings heap is present
    /// - `None` if no #Strings stream exists
    #[must_use]
    pub fn strings(&self) -> Option<&Strings<'_>> {
        self.with_data(|data| data.strings.as_ref())
    }

    /// Returns direct access to the user strings heap from the #US stream.
    ///
    /// # Returns
    ///
    /// - `Some(&UserStrings)` if the user strings heap is present
    /// - `None` if no #US stream exists
    #[must_use]
    pub fn userstrings(&self) -> Option<&UserStrings<'_>> {
        self.with_data(|data| data.userstrings.as_ref())
    }

    /// Returns direct access to the GUID heap from the #GUID stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Guid)` if the GUID heap is present
    /// - `None` if no #GUID stream exists
    #[must_use]
    pub fn guids(&self) -> Option<&Guid<'_>> {
        self.with_data(|data| data.guids.as_ref())
    }

    /// Returns direct access to the blob heap from the #Blob stream.
    ///
    /// # Returns
    ///
    /// - `Some(&Blob)` if the blob heap is present
    /// - `None` if no #Blob stream exists
    #[must_use]
    pub fn blobs(&self) -> Option<&Blob<'_>> {
        self.with_data(|data| data.blobs.as_ref())
    }

    /// Returns all stream headers from the metadata root.
    ///
    /// Stream headers contain location and size information for all
    /// metadata streams in the assembly.
    ///
    /// # Returns
    ///
    /// Reference to the vector of [`StreamHeader`] structures.
    #[must_use]
    pub fn streams(&self) -> &[StreamHeader] {
        self.with_data(|data| &data.metadata_root.stream_headers)
    }

    /// Returns the underlying file representation of this assembly.
    ///
    /// Provides access to PE file operations, RVA resolution, and
    /// low-level file structure access.
    ///
    /// # Returns
    ///
    /// Reference to the `Arc<File>` containing the PE file representation.
    #[must_use]
    pub fn file(&self) -> &Arc<File> {
        self.borrow_file()
    }

    /// Returns the raw file data as a byte slice.
    ///
    /// # Returns
    ///
    /// Reference to the complete file data.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        self.with_data(|data| data.data)
    }

    /// Returns the diagnostics collected during loading.
    ///
    /// Diagnostics include warnings about structural issues like duplicate heap
    /// streams that were encountered during loading. These don't prevent loading
    /// but may indicate obfuscation or malformed metadata.
    ///
    /// # Returns
    ///
    /// Reference to the shared [`crate::metadata::diagnostics::Diagnostics`] container.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    ///
    /// if view.diagnostics().has_any() {
    ///     println!("Loading issues found:");
    ///     for diag in view.diagnostics().iter() {
    ///         println!("  {}", diag);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn diagnostics(&self) -> &Arc<Diagnostics> {
        self.with_data(|data| &data.diagnostics)
    }

    /// Converts this read-only view into a mutable assembly.
    ///
    /// This method consumes the `CilAssemblyView` and creates a `CilAssembly`
    /// that can be modified. The original data remains unchanged until
    /// modifications are made.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// let mut assembly = view.to_owned();
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn to_owned(self) -> CilAssembly {
        CilAssembly::new(self)
    }

    /// Performs raw validation (stage 1) on the loaded assembly view.
    ///
    /// This method validates the raw assembly data using the unified validation engine
    /// without any modifications (changes = None). It performs basic structural
    /// validation and integrity checks on the raw metadata.
    ///
    /// # Arguments
    ///
    /// * `config` - Validation configuration specifying which validations to perform
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if validation passes, or an error describing validation failures.
    ///
    /// # Errors
    ///
    /// Returns validation errors if any validation checks fail, including schema violations,
    /// RID consistency issues, or referential integrity problems.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilAssemblyView, ValidationConfig};
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// view.validate(ValidationConfig::production())?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn validate(&self, config: ValidationConfig) -> Result<()> {
        if config == ValidationConfig::disabled() {
            return Ok(());
        }

        let engine = ValidationEngine::new(self, config)?;
        let result = engine.execute_stage1_validation(self, None)?;
        result.into_result()
    }

    /// Extract assembly dependencies from the AssemblyRef metadata table.
    ///
    /// This method reads the AssemblyRef table (0x23) from the metadata to extract
    /// all referenced assemblies as `AssemblyIdentity` instances. These represent
    /// the external assemblies that this assembly depends on.
    ///
    /// # Returns
    ///
    /// A vector of `AssemblyIdentity` for each referenced assembly. Returns an empty
    /// vector if the metadata tables are unavailable or the AssemblyRef table is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// let deps = view.dependencies();
    ///
    /// for dep in deps {
    ///     println!("Depends on: {} v{}", dep.name, dep.version);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn dependencies(&self) -> Vec<AssemblyIdentity> {
        let (Some(tables), Some(strings), Some(blobs)) =
            (self.tables(), self.strings(), self.blobs())
        else {
            return Vec::new();
        };

        let Some(assembly_ref_table) = tables.table::<AssemblyRefRaw>() else {
            return Vec::new();
        };

        assembly_ref_table
            .into_iter()
            .filter_map(skip_unreadable)
            .filter_map(|row| row.to_owned(strings, blobs).ok())
            .map(|assembly_ref| AssemblyIdentity::from_assembly_ref(&assembly_ref))
            .collect()
    }

    /// Extract assembly identity from the Assembly metadata table.
    ///
    /// This method reads the Assembly table (0x20) from the metadata to construct
    /// the complete AssemblyIdentity including name, version, culture, and strong name.
    /// This is the proper way to get assembly identity information rather than relying
    /// on file names or heuristics.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(AssemblyIdentity))` - Complete assembly identity extracted from metadata
    /// * `Ok(None)` - Assembly table is missing or empty (this is a netmodule)
    /// * `Err(_)` - If metadata is malformed or cannot be parsed
    ///
    /// # Netmodules
    ///
    /// .NET netmodules (.netmodule files) are modules without their own assembly manifest.
    /// They contain types and code but are designed to be linked into a multi-file assembly.
    /// For these modules, this method returns `Ok(None)` instead of an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the metadata tables or strings heap are missing, or if the assembly
    /// has a public key reference but the blob heap is unavailable.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    /// if let Some(identity) = view.identity()? {
    ///     println!("Assembly: {} v{}", identity.name, identity.version.major);
    /// } else {
    ///     println!("This is a netmodule without assembly identity");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn identity(&self) -> Result<Option<AssemblyIdentity>> {
        let (Some(tables), Some(strings)) = (self.tables(), self.strings()) else {
            return Err(malformed_error!(
                "Metadata tables or strings heap are missing"
            ));
        };

        let Some(assembly_table) = tables.table::<AssemblyRaw>() else {
            // No Assembly table - this is a netmodule
            return Ok(None);
        };

        // The Assembly table holds at most one row, at RID 1 (ECMA-335 II.22.2), so it is
        // fetched by RID. Taking the first row that *parses* would silently promote a later
        // row when RID 1 is malformed, and report another row's identity as the assembly's.
        let Some(assembly_row) = assembly_table.get(1).ok().flatten() else {
            // Empty Assembly table - also a netmodule
            return Ok(None);
        };

        // For identity extraction, we can work without the blob heap if there's no public key
        let blobs = self.blobs();

        // Get assembly name and version directly from raw row (doesn't need blob heap)
        let name = strings.get(assembly_row.name as usize)?.to_string();

        let culture = if assembly_row.culture == 0 {
            None
        } else {
            Some(strings.get(assembly_row.culture as usize)?.to_string())
        };

        // Public key requires blob heap - only fail if we need it but don't have it
        let strong_name = if assembly_row.public_key == 0 {
            None
        } else if let Some(blobs) = blobs {
            Some(Identity::PubKey(
                blobs.get(assembly_row.public_key as usize)?.to_vec(),
            ))
        } else {
            // Has public key index but no blob heap - this is malformed
            return Err(malformed_error!(
                "Assembly has public key reference but no blob heap"
            ));
        };

        let processor_architecture = tables
            .table::<AssemblyProcessorRaw>()
            .and_then(|proc_table| proc_table.get(1).ok().flatten())
            .and_then(|proc| ProcessorArchitecture::try_from(proc.processor).ok());

        #[allow(clippy::cast_possible_truncation)]
        Ok(Some(AssemblyIdentity {
            name,
            version: AssemblyVersion {
                major: assembly_row.major_version as u16,
                minor: assembly_row.minor_version as u16,
                build: assembly_row.build_number as u16,
                revision: assembly_row.revision_number as u16,
            },
            culture,
            strong_name,
            processor_architecture,
        }))
    }

    /// Get the module name from the Module metadata table.
    ///
    /// The Module table always contains exactly one row with the module name.
    /// This is useful for netmodules which don't have an Assembly table.
    ///
    /// # Returns
    ///
    /// * `Some(String)` - The module name (e.g., "MyModule.dll" or "Helper.netmodule")
    /// * `None` - If the Module table is missing or name cannot be resolved
    pub fn module_name(&self) -> Option<String> {
        let tables = self.tables()?;
        let strings = self.strings()?;

        let module_table = tables.table::<ModuleRaw>()?;
        // Module is RID 1 by definition (ECMA-335 II.22.30).
        let module_row = module_table.get(1).ok().flatten()?;

        strings.get(module_row.name as usize).ok().map(String::from)
    }

    /// Check if this is a netmodule (module without assembly manifest).
    ///
    /// A netmodule is a .NET module that lacks its own assembly identity.
    /// It contains types and code but is designed to be linked into a
    /// multi-file assembly. Netmodules have a Module table but no Assembly table.
    ///
    /// # Returns
    ///
    /// * `true` - This is a netmodule (no Assembly table)
    /// * `false` - This is a full assembly with its own identity
    #[must_use]
    pub fn is_netmodule(&self) -> bool {
        let Some(tables) = self.tables() else {
            return false;
        };

        // A netmodule has a Module table but no Assembly table
        let has_module = tables.table::<ModuleRaw>().is_some();
        let has_assembly = tables
            .table::<AssemblyRaw>()
            .is_some_and(|t| t.iter().next().is_some());

        has_module && !has_assembly
    }

    /// Get assembly identity, or create a fallback identity from module name for netmodules.
    ///
    /// This method is useful for cases where an identity is required even for netmodules,
    /// such as type registry initialization. For netmodules, a synthetic identity is
    /// created with version 0.0.0.0 and the module name (without extension).
    ///
    /// # Returns
    ///
    /// * `Ok(AssemblyIdentity)` - Either from Assembly table or synthesized from module name
    /// * `Err(_)` - If neither Assembly nor Module table can provide identity
    ///
    /// # Errors
    ///
    /// Returns an error if neither the Assembly nor Module table are available for identity
    /// extraction, or if the underlying `identity()` call fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilAssemblyView;
    /// use std::path::Path;
    ///
    /// let view = CilAssemblyView::from_path(Path::new("helper.netmodule"))?;
    /// let identity = view.identity_or_fallback()?;
    /// // Returns identity with name "helper" and version 0.0.0.0
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn identity_or_fallback(&self) -> Result<AssemblyIdentity> {
        // Try to get real assembly identity first
        if let Some(identity) = self.identity()? {
            return Ok(identity);
        }

        // Fallback to module name for netmodules
        let module_name = self.module_name().ok_or_else(|| {
            malformed_error!("Neither Assembly nor Module table available for identity")
        })?;

        // Strip extension from module name (e.g., "helper.netmodule" -> "helper")
        let name = module_name
            .rsplit_once('.')
            .map(|(base, _)| base.to_string())
            .unwrap_or(module_name);

        Ok(AssemblyIdentity {
            name,
            version: AssemblyVersion {
                major: 0,
                minor: 0,
                build: 0,
                revision: 0,
            },
            culture: None,
            strong_name: None,
            processor_architecture: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testkit::{
        factories::metadata::cilassemblyview::verify_assembly_view_complete, fixture,
    };

    #[test]
    fn from_file() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).unwrap();

        verify_assembly_view_complete(&view);
    }

    #[test]
    fn from_buffer() {
        let path = fixture("WindowsBase.dll");
        let data = fs::read(path).unwrap();
        let view = CilAssemblyView::from_mem(data.clone()).unwrap();

        assert_eq!(view.data(), data.as_slice());
        verify_assembly_view_complete(&view);
    }

    #[test]
    fn test_error_handling() {
        // Test with non-existent file
        let result = CilAssemblyView::from_path(Path::new("non_existent_file.dll"));
        assert!(result.is_err());

        // Test with invalid data
        let invalid_data = vec![0u8; 100];
        let result = CilAssemblyView::from_mem(invalid_data);
        assert!(result.is_err());

        // Test with empty data
        let empty_data = Vec::new();
        let result = CilAssemblyView::from_mem(empty_data);
        assert!(result.is_err());
    }
}
