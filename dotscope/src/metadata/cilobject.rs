//! High-level .NET assembly abstraction and metadata access.
//!
//! This module provides the main entry point for analyzing .NET assemblies through the
//! [`crate::CilObject`] struct. It offers comprehensive access to all ECMA-335 metadata
//! tables, streams, type system, resources, and assembly information with efficient
//! memory management and thread-safe access patterns.
//!
//! # Architecture
//!
//! The module is built around a self-referencing pattern that ensures parsed metadata
//! structures maintain valid references to the underlying file data without expensive
//! copying. Key architectural components include:
//!
//! - **File Layer**: Memory-mapped file access for efficient I/O
//! - **Metadata Layer**: Structured access to ECMA-335 metadata tables and streams
//! - **Validation Layer**: Configurable validation during loading
//! - **Caching Layer**: Thread-safe caching of parsed structures
//! - **Analysis Layer**: High-level access to types, methods, fields, and metadata
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::CilObject`] - Main entry point for .NET assembly analysis
//! - Internal data structure holding parsed metadata and type registry
//!
//! ## Loading Methods
//! - [`crate::CilObject::from_path`] - Load assembly from disk with default validation
//! - [`crate::CilObject::from_path_with_validation`] - Load from path with custom validation settings
//! - [`crate::CilObject::from_mem`] - Load assembly from memory buffer
//! - [`crate::CilObject::from_mem_with_validation`] - Load from memory with custom validation
//! - [`crate::CilObject::from_dotscope_file`] - Load from a dotscope File instance
//! - [`crate::CilObject::from_dotscope_file_with_validation`] - Load from File with custom validation
//! - [`crate::CilObject::from_std_file`] - Load from a std::fs::File handle
//! - [`crate::CilObject::from_std_file_with_validation`] - Load from std::fs::File with custom validation
//! - [`crate::CilObject::from_reader`] - Load from any Read implementation
//! - [`crate::CilObject::from_reader_with_validation`] - Load from Read with custom validation
//! - [`crate::CilObject::from_view`] - Load from a CilAssemblyView instance
//! - [`crate::CilObject::from_view_with_validation`] - Load from CilAssemblyView with custom validation
//!
//! ## Metadata Access Methods
//! - [`crate::CilObject::module`] - Get module information
//! - [`crate::CilObject::assembly`] - Get assembly metadata
//! - [`crate::CilObject::strings`] - Access strings heap
//! - [`crate::CilObject::userstrings`] - Access user strings heap
//! - [`crate::CilObject::guids`] - Access GUID heap
//! - [`crate::CilObject::blob`] - Access blob heap
//! - [`crate::CilObject::tables`] - Access raw metadata tables
//!
//! ## High-level Analysis Methods
//! - [`crate::CilObject::types`] - Get all type definitions
//! - [`crate::CilObject::methods`] - Get all method definitions
//! - [`crate::CilObject::imports`] - Get imported types and methods
//! - [`crate::CilObject::exports`] - Get exported types and methods
//! - [`crate::CilObject::resources`] - Get embedded resources
//!
//! # Usage Examples
//!
//! ## Basic Assembly Loading and Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! // Load an assembly from file
//! let assembly = CilObject::from_path(Path::new("tests/samples/mono_4.8/mscorlib.dll"))?;
//!
//! // Access basic assembly information
//! if let Some(module) = assembly.module() {
//!     println!("Module: {}", module.name);
//! }
//!
//! if let Some(assembly_info) = assembly.assembly() {
//!     println!("Assembly: {}", assembly_info.name);
//! }
//!
//! // Analyze types and methods
//! let types = assembly.types();
//! let methods = assembly.methods();
//! println!("Found {} types and {} methods", types.len(), methods.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Memory-based Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//!
//! // Load from memory buffer (e.g., downloaded or embedded)
//! let file_data = std::fs::read("assembly.dll")?;
//! let assembly = CilObject::from_mem(file_data)?;
//!
//! // Access metadata streams with iteration
//! if let Some(strings) = assembly.strings() {
//!     // Indexed access
//!     if let Ok(name) = strings.get(1) {
//!         println!("String at index 1: {}", name);
//!     }
//!     
//!     // Iterate through all strings
//!     for (offset, string) in strings.iter() {
//!         println!("String at {}: '{}'", offset, string);
//!     }
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Custom Validation Settings
//!
//! ```rust,no_run
//! use dotscope::{CilObject, ValidationConfig};
//! use std::path::Path;
//!
//! // Use minimal validation for best performance
//! let assembly = CilObject::from_path_with_validation(
//!     Path::new("tests/samples/mono_4.8/mscorlib.dll"),
//!     ValidationConfig::minimal()
//! )?;
//!
//! // Use strict validation for maximum verification
//! let assembly = CilObject::from_path_with_validation(
//!     Path::new("tests/samples/mono_4.8/mscorlib.dll"),
//!     ValidationConfig::strict()
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Comprehensive Metadata Analysis
//!
//! ```rust,no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/mono_4.8/mscorlib.dll"))?;
//!
//! // Analyze imports and exports
//! let imports = assembly.imports();
//! let exports = assembly.exports();
//! println!("Imports: {} items", imports.total_count());
//! println!("Exports: {} items", exports.total_count());
//!
//! // Access embedded resources
//! let resources = assembly.resources();
//! println!("Resources: {} items", resources.len());
//!
//! // Access raw metadata tables for low-level analysis
//! if let Some(tables) = assembly.tables() {
//!     println!("Metadata schema version: {}.{}",
//!              tables.major_version, tables.minor_version);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Error Handling
//!
//! All operations return [`crate::Result<T>`] with comprehensive error information:
//! - **File I/O errors**: When files cannot be read or accessed
//! - **Format errors**: When PE or metadata format is invalid
//! - **Validation errors**: When validation checks fail during loading
//! - **Memory errors**: When insufficient memory is available
//!
//! # Thread Safety
//!
//! [`crate::CilObject`] is designed for thread-safe concurrent read access. Internal
//! caching and lazy loading use appropriate synchronization primitives to ensure
//! correctness in multi-threaded scenarios. All public APIs are [`std::marker::Send`] and [`std::marker::Sync`].
//!
use std::{path::Path, sync::Arc};

use log::debug;

use crate::{
    analysis::CallGraph,
    cilassembly::CilAssembly,
    file::File,
    metadata::{
        cilassemblyview::CilAssemblyView,
        cor20header::Cor20Header,
        diagnostics::Diagnostics,
        exports::UnifiedExportContainer,
        identity::AssemblyIdentity,
        imports::UnifiedImportContainer,
        loader::CilObjectData,
        method::{method_name_by_token, MethodMap, MethodRc},
        pdb::PortablePdb,
        query::{MethodQuery, TypeQuery},
        resolver::TokenResolver,
        resources::Resources,
        root::Root,
        streams::{Blob, Guid, Strings, TablesHeader, UserStrings},
        tables::{
            member_ref_name_by_token, method_spec_name_by_token, AssemblyOsRc, AssemblyProcessorRc,
            AssemblyRc, AssemblyRefMap, CustomAttributeMap, DeclSecurityMap, FieldMap, FileMap,
            MemberRefMap, MemberRefRc, MethodSpecMap, MethodSpecRc, ModuleRc, ModuleRefMap,
        },
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
        validation::{ValidationConfig, ValidationEngine},
    },
    project::ProjectContext,
    Error, MethodLookupError, Result,
};

/// A fully parsed and loaded .NET assembly representation.
///
/// `CilObject` is the main entry point for analyzing .NET PE files, providing
/// access to all metadata tables, streams, and assembly information. It uses
/// efficient memory access techniques to handle large assemblies while
/// maintaining memory safety through self-referencing data structures.
///
/// The object automatically handles the complex .NET metadata format including:
/// - CLI header parsing and validation
/// - Metadata root and stream directory processing  
/// - All metadata tables (Type, Method, Field, Assembly, etc.)
/// - String heaps, user string heaps, GUID heaps, and blob heaps
/// - Cross-references between assemblies and modules
/// - Type system construction and method disassembly integration
///
/// # Architecture
///
/// The implementation uses a self-referencing pattern to ensure that parsed
/// metadata structures maintain valid references to the underlying file data
/// without requiring expensive data copying. This enables efficient analysis
/// of large assemblies while maintaining Rust's memory safety guarantees.
///
/// # Usage Examples
///
/// ```rust,no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// // Load an assembly from file
/// let assembly = CilObject::from_path(Path::new("tests/samples/mono_4.8/mscorlib.dll"))?;
///
/// // Access assembly metadata
/// if let Some(assembly_info) = assembly.assembly() {
///     println!("Assembly name: {}", assembly_info.name);
/// }
/// println!("Number of types: {}", assembly.types().len());
///
/// // Examine methods
/// for entry in assembly.methods().iter() {
///     let method = entry.value();
///     println!("Method: {} (RVA: {:X})", method.name, method.rva.unwrap_or(0));
/// }
///
/// // Load from memory buffer
/// let file_data = std::fs::read("tests/samples/mono_4.8/mscorlib.dll")?;
/// let assembly = CilObject::from_mem(file_data)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Thread Safety
///
/// [`CilObject`] is [`std::marker::Send`] and [`std::marker::Sync`] for thread-safe concurrent read access.
/// Internal caching and lazy loading use appropriate synchronization primitives
/// to ensure correctness in multi-threaded scenarios. All accessor methods can be
/// safely called concurrently from multiple threads.
pub struct CilObject {
    /// Handles file lifetime management and provides raw metadata access
    assembly_view: CilAssemblyView,
    /// Contains resolved metadata structures (types, methods, etc.)
    data: CilObjectData,
    /// The validation the assembly was loaded with, which a reload with a PDB attached
    /// ([`CilObject::with_pdb`]) repeats
    validation_config: ValidationConfig,
}

impl CilObject {
    /// Creates a new `CilObject` by loading and parsing a .NET assembly from a path.
    ///
    /// This method handles the complete loading process including file I/O,
    /// PE header validation, and metadata parsing. The file is memory-mapped
    /// for efficient access to large assemblies.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .NET assembly file (.dll, .exe, or .netmodule).
    ///   Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    ///
    /// # Returns
    ///
    /// Returns a fully parsed `CilObject` or an error if:
    /// - The file cannot be opened or read
    /// - The file is not a valid PE format
    /// - The PE file is not a valid .NET assembly
    /// - Metadata streams are corrupted or invalid
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// // With Path
    /// let assembly = CilObject::from_path(Path::new("tests/samples/mono_4.8/mscorlib.dll"))?;
    ///
    /// // With string slice
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(assembly_info) = assembly.assembly() {
    ///     println!("Loaded assembly: {}", assembly_info.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the file cannot be read or parsed as a valid .NET assembly.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        Self::from_path_with_validation(path, ValidationConfig::production())
    }

    /// Creates a new `CilObject` by parsing a .NET assembly from a path with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Use this when you need to balance security requirements vs. loading speed.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the .NET assembly file. Accepts `&Path`, `&str`, `String`, or `PathBuf`.
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilObject, ValidationConfig};
    /// use std::path::Path;
    ///
    /// // Load with minimal validation for maximum speed
    /// let assembly = CilObject::from_path_with_validation(
    ///     "tests/samples/mono_4.8/mscorlib.dll",
    ///     ValidationConfig::minimal()
    /// )?;
    ///
    /// // Load with production validation for balance of safety and speed
    /// let assembly = CilObject::from_path_with_validation(
    ///     Path::new("tests/samples/mono_4.8/mscorlib.dll"),
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the file cannot be read, parsed as a valid .NET assembly,
    /// or if validation checks fail.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from_path_with_validation(
        path: impl AsRef<Path>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        debug!("Loading assembly: {}", path.as_ref().display());
        let assembly_view =
            CilAssemblyView::from_path_with_validation(path, ValidationConfig::disabled())?;
        Self::load_validated(assembly_view, validation_config, None)
    }

    /// Creates a new `CilObject` by parsing a .NET assembly from a memory buffer.
    ///
    /// This method is useful for analyzing assemblies that are already loaded
    /// in memory, downloaded from network sources, or embedded as resources.
    /// The data is copied internally to ensure proper lifetime management.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    ///
    /// # Returns
    ///
    /// Returns a fully parsed `CilObject` or an error if:
    /// - The data is not a valid PE format
    /// - The PE data is not a valid .NET assembly  
    /// - Metadata streams are corrupted or invalid
    /// - Memory allocation fails during processing
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// // Load assembly from file into memory then parse
    /// let file_data = std::fs::read("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let assembly = CilObject::from_mem(file_data)?;
    ///
    /// // Access the loaded assembly
    /// if let Some(module) = assembly.module() {
    ///     println!("Module name: {}", module.name);
    /// }
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the memory buffer cannot be parsed as a valid .NET assembly.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from_mem(data: Vec<u8>) -> Result<Self> {
        Self::from_mem_with_validation(data, ValidationConfig::production())
    }

    /// Creates a new `CilObject` by parsing a .NET assembly from a memory buffer with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during loading.
    /// Use this when you need to balance security requirements vs. loading speed.
    ///
    /// # Arguments
    ///
    /// * `data` - Raw bytes of the .NET assembly in PE format
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilObject, ValidationConfig};
    ///
    /// let file_data = std::fs::read("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// // Load with production validation settings
    /// let assembly = CilObject::from_mem_with_validation(
    ///     file_data.clone(),
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if the memory buffer cannot be parsed as a valid .NET assembly
    /// or if validation checks fail.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from_mem_with_validation(
        data: Vec<u8>,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        debug!("Loading assembly from memory buffer ({} bytes)", data.len());
        let assembly_view =
            CilAssemblyView::from_mem_with_validation(data, ValidationConfig::disabled())?;
        Self::load_validated(assembly_view, validation_config, None)
    }

    /// Creates a CilObject from a dotscope::file::File.
    ///
    /// This allows you to inspect the PE file before parsing .NET metadata,
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
    /// use dotscope::{File, CilObject};
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("assembly.dll"))?;
    /// if file.is_clr() {
    ///     let cil_obj = CilObject::from_dotscope_file(file)?;
    ///     println!("Loaded {} methods", cil_obj.methods().len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_dotscope_file(file: File) -> Result<Self> {
        Self::from_dotscope_file_with_validation(file, ValidationConfig::production())
    }

    /// Creates a CilObject from a dotscope::file::File with validation.
    ///
    /// # Arguments
    /// * `file` - A File instance containing a .NET assembly
    /// * `validation_config` - Configuration specifying which validation checks to perform
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
    /// use dotscope::{File, CilObject, ValidationConfig};
    /// use std::path::Path;
    ///
    /// let file = File::from_path(Path::new("assembly.dll"))?;
    /// let cil_obj = CilObject::from_dotscope_file_with_validation(
    ///     file,
    ///     ValidationConfig::production()
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_dotscope_file_with_validation(
        file: File,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        if !file.is_clr() {
            return Err(Error::NotSupported);
        }

        let assembly_view = CilAssemblyView::from_dotscope_file_with_validation(
            file,
            ValidationConfig::disabled(),
        )?;
        Self::load_validated(assembly_view, validation_config, None)
    }

    /// Creates a CilObject from an opened std::fs::File.
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
    /// use dotscope::CilObject;
    /// use std::fs::File;
    ///
    /// let std_file = File::open("assembly.dll")?;
    /// let cil_obj = CilObject::from_std_file(std_file)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn from_std_file(file: std::fs::File) -> Result<Self> {
        Self::from_std_file_with_validation(file, ValidationConfig::production())
    }

    /// Creates a CilObject from an opened std::fs::File with validation.
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
    /// use dotscope::{CilObject, ValidationConfig};
    /// use std::fs::File;
    ///
    /// let std_file = File::open("assembly.dll")?;
    /// let cil_obj = CilObject::from_std_file_with_validation(
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

    /// Creates a CilObject from any reader.
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
    /// use dotscope::CilObject;
    /// use std::io::Cursor;
    ///
    /// let data = vec![/* PE bytes */];
    /// let cursor = Cursor::new(data);
    /// let cil_obj = CilObject::from_reader(cursor)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_reader<R: std::io::Read>(reader: R) -> Result<Self> {
        Self::from_reader_with_validation(reader, ValidationConfig::production())
    }

    /// Creates a CilObject from any reader with validation.
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
    /// use dotscope::{CilObject, ValidationConfig};
    /// use std::io::Cursor;
    ///
    /// let data = vec![/* PE bytes */];
    /// let cursor = Cursor::new(data);
    /// let cil_obj = CilObject::from_reader_with_validation(
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

    /// Creates a new `CilObject` from an existing `CilAssemblyView`.
    ///
    /// This method is designed for the CilProject workflow where CilAssemblyView instances
    /// are used for lightweight dependency discovery before being converted to full CilObjects.
    /// It bypasses file I/O since the CilAssemblyView already contains the parsed metadata.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Pre-loaded CilAssemblyView with parsed metadata
    ///
    /// # Returns
    ///
    /// Returns a fully parsed `CilObject` or an error if:
    /// - Metadata processing fails during CilObjectData creation
    /// - Memory allocation fails during processing
    /// - Cross-references cannot be resolved
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{CilObject, CilAssemblyView};
    /// use std::path::Path;
    ///
    /// // Load assembly view for dependency discovery
    /// let view = CilAssemblyView::from_path(Path::new("assembly.dll"))?;
    ///
    /// // Convert to full CilObject (single assembly mode)
    /// let assembly = CilObject::from_view(view)?;
    ///
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Integration with CilProject
    ///
    /// For multi-assembly projects with circular dependencies, use `from_project` instead
    /// which provides proper barrier synchronization for parallel loading.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly cannot be processed or validated.
    pub fn from_view(assembly_view: CilAssemblyView) -> Result<Self> {
        Self::from_view_with_validation(assembly_view, ValidationConfig::production())
    }

    /// Creates a new `CilObject` from an existing `CilAssemblyView` with custom validation configuration.
    ///
    /// This method allows you to control which validation checks are performed during processing.
    /// Use this when you need to balance security requirements vs. loading speed.
    ///
    /// For multi-assembly projects with cross-references, use `from_project` instead which
    /// provides proper registry coordination.
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Pre-loaded CilAssemblyView with parsed metadata
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a fully parsed `CilObject` or an error if validation checks fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the assembly cannot be processed or if validation checks fail.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn from_view_with_validation(
        assembly_view: CilAssemblyView,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        Self::load_validated(assembly_view, validation_config, None)
    }

    /// Builds the object for `assembly_view` and validates it with one engine, so one
    /// reference scan: the raw stage before the owned data is built, so a raw failure ends
    /// the load before it, and the owned stage after. `standalone_pdb` is a Portable PDB to
    /// read the debug information from instead of the image's own.
    fn load_validated(
        assembly_view: CilAssemblyView,
        validation_config: ValidationConfig,
        standalone_pdb: Option<&[u8]>,
    ) -> Result<Self> {
        let engine = if validation_config == ValidationConfig::disabled() {
            None
        } else {
            Some(ValidationEngine::new(&assembly_view, validation_config)?)
        };
        if let Some(engine) = engine
            .as_ref()
            .filter(|_| validation_config.should_validate_raw())
        {
            engine
                .execute_stage1_validation(&assembly_view, None)?
                .into_result()?;
        }

        let data = CilObjectData::from_assembly_view(
            &assembly_view,
            None,
            validation_config.lenient,
            standalone_pdb,
        )?;
        let object = CilObject {
            assembly_view,
            data,
            validation_config,
        };

        if let Some(engine) = engine.filter(|_| validation_config.should_validate_owned()) {
            engine.execute_stage2_validation(&object)?.into_result()?;
        }
        debug!(
            "Assembly loaded: {} types, {} methods",
            object.types().len(),
            object.methods().len()
        );
        Ok(object)
    }

    /// Creates a new `CilObject` from an existing `CilAssemblyView` with project coordination.
    ///
    /// This method is designed for multi-assembly project loading where circular dependencies
    /// require barrier synchronization. The `ProjectContext` coordinates the parallel loading
    /// of multiple assemblies, ensuring proper TypeRegistry linking at the right stages.
    ///
    /// # Loading Pipeline
    ///
    /// The loading process is split into two phases to handle cross-assembly dependencies:
    ///
    /// 1. **Loading Phase**: All metadata loaders execute with barrier synchronization
    ///    - Stage 1-4 barriers ensure proper ordering of cross-assembly operations
    ///    - All assemblies must complete loading before any proceeds to validation
    ///
    /// 2. **Validation Phase**: After stage 4 barrier, validation runs on fully loaded data
    ///    - Nested type relationships are fully populated across all assemblies
    ///    - Cross-assembly type references can be safely traversed
    ///
    /// # Arguments
    ///
    /// * `assembly_view` - Pre-loaded CilAssemblyView with parsed metadata
    /// * `project_context` - Coordination context for multi-assembly parallel loading
    /// * `validation_config` - Configuration specifying which validation checks to perform
    ///
    /// # Returns
    ///
    /// Returns a fully parsed `CilObject` or an error if loading or validation fails.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and designed to be called concurrently from multiple threads
    /// with the same `ProjectContext`. The `ProjectContext` handles barrier synchronization.
    pub(crate) fn from_project(
        assembly_view: CilAssemblyView,
        project_context: &ProjectContext,
        validation_config: ValidationConfig,
    ) -> Result<Self> {
        // Phase 1: Load all metadata with barrier synchronization.
        // The stage 4 barrier inside from_assembly_view ensures all assemblies complete
        // their metadata loaders before any assembly proceeds past this point.
        let lenient = validation_config.lenient;
        let object_data = CilObjectData::from_assembly_view(
            &assembly_view,
            Some(project_context),
            lenient,
            None,
        )?;

        let object = CilObject {
            assembly_view,
            data: object_data,
            validation_config,
        };

        // Phase 2: Validate after all assemblies have completed loading.
        // This ensures cross-assembly nested type references are fully populated
        // before validation attempts to traverse them. The raw stage ran when the
        // project loader read the view, which lets it leave out an assembly that fails it.
        if validation_config != ValidationConfig::disabled()
            && validation_config.should_validate_owned()
        {
            ValidationEngine::new(&object.assembly_view, validation_config)?
                .execute_stage2_validation(&object)?
                .into_result()?;
        }
        Ok(object)
    }

    /// Returns the COR20 header containing .NET-specific PE information.
    ///
    /// The COR20 header (also known as CLI header) contains essential information
    /// about the .NET assembly including metadata directory location, entry point,
    /// and runtime flags. This header is always present in valid .NET assemblies.
    ///
    /// # Returns
    ///
    /// Reference to the parsed [`crate::metadata::cor20header::Cor20Header`] structure containing:
    /// - Metadata directory RVA and size
    /// - Entry point token (for executables)
    /// - Runtime flags (`IL_ONLY`, `32BIT_REQUIRED`, etc.)
    /// - Resources and strong name signature locations
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let header = assembly.cor20header();
    ///
    /// println!("Metadata RVA: 0x{:X}", header.meta_data_rva);
    /// println!("Runtime flags: {:?}", header.flags);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn cor20header(&self) -> &Cor20Header {
        self.assembly_view.cor20header()
    }

    /// Returns the metadata root header containing stream directory information.
    ///
    /// The metadata root is the entry point to the .NET metadata system, containing
    /// the version signature, stream count, and directory of all metadata streams
    /// (#~, #Strings, #US, #GUID, #Blob). This structure is always present and
    /// provides the foundation for accessing all assembly metadata.
    ///
    /// # Returns
    ///
    /// Reference to the parsed [`crate::metadata::root::Root`] structure containing:
    /// - Metadata format version and signature  
    /// - Stream directory with names, offsets, and sizes
    /// - Framework version string
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let root = assembly.metadata_root();
    ///
    /// println!("Metadata version: {}", root.version);
    /// println!("Number of streams: {}", root.stream_headers.len());
    /// for stream in &root.stream_headers {
    ///     println!("Stream: {} at offset 0x{:X}", stream.name, stream.offset);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn metadata_root(&self) -> &Root {
        self.assembly_view.metadata_root()
    }

    /// Returns the metadata tables header from the #~ or #- stream.
    ///
    /// The tables header contains all metadata tables defined by ECMA-335,
    /// including Type definitions, Method definitions, Field definitions,
    /// Assembly references, and many others. This is the core of .NET metadata
    /// and provides structured access to all assembly information.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::streams::TablesHeader`]`)` if the #~ stream is present (compressed metadata)
    /// - `None` if no tables stream is found (invalid or malformed assembly)
    ///
    /// The [`crate::metadata::streams::TablesHeader`] provides access to:
    /// - All metadata table row counts and data
    /// - String, GUID, and Blob heap indices
    /// - Schema version and heap size information
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::{CilObject, metadata::tables::{TypeDefRaw, TableId}};
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(tables) = assembly.tables() {
    ///     println!("Schema version: {}.{}", tables.major_version, tables.minor_version);
    ///
    ///     // Access individual tables
    ///     if let Some(typedef_table) = &tables.table::<TypeDefRaw>() {
    ///         println!("Number of types: {}", typedef_table.row_count);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn tables(&self) -> Option<&TablesHeader<'_>> {
        self.assembly_view.tables()
    }

    /// Returns the strings heap from the #Strings stream.
    ///
    /// The strings heap contains null-terminated UTF-8 strings used throughout
    /// the metadata tables for names of types, members, parameters, and other
    /// identifiers. String references in tables are indices into this heap.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::streams::Strings`]`)` if the #Strings stream is present
    /// - `None` if the stream is missing (malformed assembly)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(strings) = assembly.strings() {
    ///     // Look up string by index (from metadata table)
    ///     if let Ok(name) = strings.get(0x123) {
    ///         println!("String at index 0x123: {}", name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn strings(&self) -> Option<&Strings<'_>> {
        self.assembly_view.strings()
    }

    /// Returns the user strings heap from the #US stream.
    ///
    /// The user strings heap contains length-prefixed Unicode strings that appear
    /// as string literals in CIL code (e.g., from C# string literals). These are
    /// accessed via the `ldstr` instruction and are distinct from metadata strings.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::streams::UserStrings`]`)` if the #US stream is present
    /// - `None` if the stream is missing (assembly has no string literals)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(user_strings) = assembly.userstrings() {
    ///     // Look up user string by token (from ldstr instruction)
    ///     if let Ok(literal) = user_strings.get(0x70000001) {
    ///         println!("String literal: {}", literal.to_string().unwrap());
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn userstrings(&self) -> Option<&UserStrings<'_>> {
        self.assembly_view.userstrings()
    }

    /// Returns the GUID heap from the #GUID stream.
    ///
    /// The GUID heap contains 16-byte GUIDs referenced by metadata tables,
    /// typically used for type library IDs, interface IDs, and other unique
    /// identifiers in COM interop scenarios.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::streams::Guid`]`)` if the #GUID stream is present
    /// - `None` if the stream is missing (assembly has no GUID references)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(guids) = assembly.guids() {
    ///     // Look up GUID by index (from metadata table)
    ///     if let Ok(guid) = guids.get(1) {
    ///         println!("GUID: {}", guid);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn guids(&self) -> Option<&Guid<'_>> {
        self.assembly_view.guids()
    }

    /// Returns the blob heap from the #Blob stream.
    ///
    /// The blob heap contains variable-length binary data referenced by metadata
    /// tables, including type signatures, method signatures, field signatures,
    /// custom attribute values, and marshalling information.
    ///
    /// # Returns
    ///
    /// - `Some(&`[`crate::metadata::streams::Blob`]`)` if the #Blob stream is present
    /// - `None` if the stream is missing (malformed assembly)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(blob) = assembly.blob() {
    ///     // Look up blob by index (from metadata table)
    ///     if let Ok(signature) = blob.get(0x456) {
    ///         println!("Signature bytes: {:02X?}", signature);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn blob(&self) -> Option<&Blob<'_>> {
        self.assembly_view.blobs()
    }

    /// Returns the diagnostics collected during loading.
    ///
    /// Diagnostics include warnings about structural issues, parsing failures,
    /// and other anomalies encountered during loading. These don't necessarily
    /// prevent loading but may indicate obfuscation or malformed metadata.
    ///
    /// # Returns
    ///
    /// Reference to the shared [`crate::metadata::diagnostics::Diagnostics`] container.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if assembly.diagnostics().has_any() {
    ///     println!("Loading issues found:");
    ///     for diag in assembly.diagnostics().iter() {
    ///         println!("  {}", diag);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn diagnostics(&self) -> &Arc<Diagnostics> {
        self.assembly_view.diagnostics()
    }

    /// Returns all assembly references used by this assembly.
    ///
    /// Assembly references represent external .NET assemblies that this assembly
    /// depends on, including version information, public key tokens, and culture
    /// settings. These correspond to entries in the `AssemblyRef` metadata table.
    ///
    /// # Returns
    ///
    /// Reference to the `AssemblyRefMap` containing all external assembly dependencies.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let refs = assembly.refs_assembly();
    ///
    /// for entry in refs.iter() {
    ///     let (token, assembly_ref) = (entry.key(), entry.value());
    ///     println!("Dependency: {} v{}.{}.{}.{}",
    ///         assembly_ref.name,
    ///         assembly_ref.major_version,
    ///         assembly_ref.minor_version,
    ///         assembly_ref.build_number,
    ///         assembly_ref.revision_number
    ///     );
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn refs_assembly(&self) -> &AssemblyRefMap {
        &self.data.refs_assembly
    }

    /// Returns all module references used by this assembly.
    ///
    /// Module references represent external unmanaged modules (native DLLs)
    /// that this assembly imports functions from via P/Invoke declarations.
    /// These correspond to entries in the `ModuleRef` metadata table.
    ///
    /// # Returns
    ///
    /// Reference to the `ModuleRefMap` containing all external module dependencies.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let refs = assembly.refs_module();
    ///
    /// for entry in refs.iter() {
    ///     let (token, module_ref) = (entry.key(), entry.value());
    ///     println!("Native module: {}", module_ref.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn refs_module(&self) -> &ModuleRefMap {
        &self.data.refs_module
    }

    /// Returns all member references used by this assembly.
    ///
    /// Member references represent external type members (methods, fields, properties)
    /// from other assemblies that are referenced by this assembly's code.
    /// These correspond to entries in the `MemberRef` metadata table.
    ///
    /// # Returns
    ///
    /// Reference to the `MemberRefMap` containing all external member references.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let refs = assembly.refs_members();
    ///
    /// for entry in refs.iter() {
    ///     let (token, member_ref) = (entry.key(), entry.value());
    ///     println!("External member: {}", member_ref.name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn refs_members(&self) -> &MemberRefMap {
        &self.data.refs_member
    }

    /// Returns all file references for multi-file assemblies.
    ///
    /// File references correspond to entries in the `File` metadata table and
    /// describe additional files that belong to this assembly (netmodules,
    /// resource files). Each entry contains the file name, hash value, and
    /// flags indicating whether the file contains metadata.
    ///
    /// # Returns
    ///
    /// Reference to the `FileMap` containing all file references.
    pub fn refs_file(&self) -> &FileMap {
        &self.data.refs_file
    }

    /// Returns all security declarations and permission sets defined in this assembly.
    ///
    /// Security declarations include Code Access Security (CAS) permissions, security
    /// transparency attributes, and other declarative security constraints. Each entry
    /// maps a token to its corresponding security declaration containing permission sets,
    /// security actions, and validation rules.
    ///
    /// # Returns
    ///
    /// A reference to the [`crate::metadata::tables::DeclSecurityMap`] containing all security declarations.
    /// The map uses tokens as keys and [`crate::metadata::tables::DeclSecurityRc`] (reference-counted security
    /// declarations) as values for efficient memory management.
    ///
    /// # Usage
    ///
    /// ```rust,no_run
    /// # use dotscope::CilObject;
    /// # fn security_example() -> dotscope::Result<()> {
    /// let assembly = CilObject::from_path("example.dll")?;
    /// let security_decls = assembly.security_declarations();
    ///
    /// for entry in security_decls.iter() {
    ///     let (token, decl) = (entry.key(), entry.value());
    ///     println!("Security declaration for token {}: {:?}",
    ///              token.value(), decl.action);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn security_declarations(&self) -> &DeclSecurityMap {
        &self.data.decl_security
    }

    /// Returns the primary module information for this assembly.
    ///
    /// The module represents the main file of the assembly, containing the
    /// module's name, MVID (Module Version Identifier), and generation ID.
    /// Multi-file assemblies can have additional modules, but there's always
    /// one primary module.
    ///
    /// # Returns
    ///
    /// - `Some(&ModuleRc)` if module information is present
    /// - `None` if no module table entry exists (malformed assembly)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(module) = assembly.module() {
    ///     println!("Module name: {}", module.name);
    ///     println!("Module GUID: {}", module.mvid);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn module(&self) -> Option<&ModuleRc> {
        self.data.module.get()
    }

    /// Returns the assembly metadata for this .NET assembly.
    ///
    /// The assembly metadata contains the assembly's identity including name,
    /// version, culture, public key information, and security attributes.
    /// This corresponds to the Assembly metadata table entry.
    ///
    /// # Returns
    ///
    /// - `Some(&AssemblyRc)` if assembly metadata is present
    /// - `None` if this is a module-only file (no Assembly table entry)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    ///
    /// if let Some(assembly_info) = assembly.assembly() {
    ///     println!("Assembly: {}", assembly_info.name);
    ///     println!("Version: {}.{}.{}.{}",
    ///         assembly_info.major_version,
    ///         assembly_info.minor_version,
    ///         assembly_info.build_number,
    ///         assembly_info.revision_number
    ///     );
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn assembly(&self) -> Option<&AssemblyRc> {
        self.data.assembly.get()
    }

    /// Returns assembly OS information if present.
    ///
    /// The `AssemblyOS` table contains operating system identification information
    /// for the assembly. This table is rarely used in modern .NET assemblies
    /// and is primarily for legacy compatibility.
    ///
    /// # Returns
    ///
    /// - `Some(&AssemblyOsRc)` if OS information is present
    /// - `None` if no `AssemblyOS` table entry exists (typical for most assemblies)
    pub fn assembly_os(&self) -> Option<&AssemblyOsRc> {
        self.data.assembly_os.get()
    }

    /// Returns assembly processor information if present.
    ///
    /// The `AssemblyProcessor` table contains processor architecture identification
    /// information for the assembly. This table is rarely used in modern .NET
    /// assemblies and is primarily for legacy compatibility.
    ///
    /// # Returns
    ///
    /// - `Some(&AssemblyProcessorRc)` if processor information is present  
    /// - `None` if no `AssemblyProcessor` table entry exists (typical for most assemblies)
    pub fn assembly_processor(&self) -> Option<&AssemblyProcessorRc> {
        self.data.assembly_processor.get()
    }

    /// Returns the complete assembly identity for this loaded assembly.
    ///
    /// The assembly identity provides comprehensive identification information including
    /// name, version, culture, strong name, and processor architecture. This serves as
    /// the primary identifier for assemblies in multi-assembly analysis scenarios and
    /// cross-assembly resolution.
    ///
    /// # Returns
    ///
    /// - `Some(AssemblyIdentity)` if assembly metadata is present
    /// - `None` if no `Assembly` table entry exists (rare, but possible in malformed assemblies)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("example.dll"))?;
    ///
    /// if let Some(identity) = assembly.identity() {
    ///     println!("Assembly: {}", identity.display_name());
    ///     println!("Version: {}", identity.version);
    ///     println!("Strong named: {}", identity.is_strong_named());
    ///     println!("Culture neutral: {}", identity.is_culture_neutral());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Multi-Assembly Usage
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use std::collections::HashMap;
    /// use std::path::PathBuf;
    ///
    /// let mut assemblies = HashMap::new();
    /// let assembly_paths = vec![
    ///     PathBuf::from("tests/samples/mono_4.8/mscorlib.dll"),
    ///     PathBuf::from("tests/samples/mono_4.8/System.dll"),
    /// ];
    ///
    /// for path in assembly_paths {
    ///     let assembly = CilObject::from_path(&path)?;
    ///     if let Some(identity) = assembly.identity() {
    ///         assemblies.insert(identity, assembly);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn identity(&self) -> Option<AssemblyIdentity> {
        self.assembly()
            .map(|asm| AssemblyIdentity::from_assembly(asm))
    }

    /// Checks if this is a netmodule (module without assembly manifest).
    ///
    /// A netmodule is a .NET module that lacks its own assembly identity.
    /// It contains types and code but is designed to be linked into a
    /// multi-file assembly. Netmodules have a Module table but no Assembly table.
    ///
    /// # Returns
    ///
    /// * `true` - This is a netmodule (no Assembly table)
    /// * `false` - This is a full assembly with its own identity
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let module = CilObject::from_path("helper.netmodule")?;
    /// if module.is_netmodule() {
    ///     println!("This is a netmodule - part of a multi-file assembly");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_netmodule(&self) -> bool {
        // A netmodule has a module but no assembly identity
        self.module().is_some() && self.assembly().is_none()
    }

    /// Returns the imports container with all P/Invoke and COM import information.
    ///
    /// The imports container provides access to all external function imports
    /// including P/Invoke declarations, COM method imports, and related
    /// marshalling information. This data comes from `ImplMap` and related tables.
    ///
    /// # Returns
    ///
    /// Reference to the `Imports` container with all import declarations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let imports = assembly.imports();
    ///
    /// for entry in imports.cil().iter() {
    ///     let (token, import) = (entry.key(), entry.value());
    ///     println!("Import: {}.{} from {:?}", import.namespace, import.name, import.source_id);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn imports(&self) -> &UnifiedImportContainer {
        &self.data.import_container
    }

    /// Returns the exports container with all exported function information.
    ///
    /// The exports container provides access to all functions that this assembly
    /// exports for use by other assemblies or native code. This includes both
    /// managed exports and any native exports in mixed-mode assemblies.
    ///
    /// # Returns
    ///
    /// Reference to the `UnifiedExportContainer` with both CIL and native export declarations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let exports = assembly.exports();
    ///
    /// // Access CIL exports (existing functionality)
    /// for entry in exports.cil().iter() {
    ///     let (token, export) = (entry.key(), entry.value());
    ///     println!("CIL Export: {} at offset 0x{:X} - Token 0x{:X}", export.name, export.offset, token.value());
    /// }
    ///
    /// // Access native function exports
    /// let native_functions = exports.get_native_function_names();
    /// for function_name in native_functions {
    ///     println!("Native Export: {}", function_name);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn exports(&self) -> &UnifiedExportContainer {
        &self.data.export_container
    }

    /// Returns the methods container with all method definitions and metadata.
    ///
    /// The methods container provides access to all methods defined in this assembly,
    /// including their signatures, IL code, exception handlers, and related metadata.
    /// This integrates data from `MethodDef`, `Param`, and other method-related tables.
    ///
    /// # Returns
    ///
    /// Reference to the `MethodMap` containing all method definitions.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let methods = assembly.methods();
    ///
    /// for entry in methods.iter() {
    ///     let (token, method) = (entry.key(), entry.value());
    ///     println!("Method: {} (Token: 0x{:08X})", method.name, token.value());
    ///     if let Some(rva) = method.rva {
    ///         println!("  RVA: 0x{:X}", rva);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn methods(&self) -> &MethodMap {
        &self.data.methods
    }

    /// Returns the method specifications container with all generic method instantiations.
    ///
    /// The method specifications container provides access to all generic method instantiations
    /// defined in this assembly. `MethodSpec` entries represent calls to generic methods with
    /// specific type arguments, enabling IL instructions to reference these instantiations.
    ///
    /// # Returns
    ///
    /// Reference to the `MethodSpecMap` containing all method specifications.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let method_specs = assembly.method_specs();
    ///
    /// for entry in method_specs.iter() {
    ///     let (token, method_spec) = (entry.key(), entry.value());
    ///     println!("MethodSpec: Token 0x{:08X}", token.value());
    ///     println!("  Generic args count: {}", method_spec.generic_args.count());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn method_specs(&self) -> &MethodSpecMap {
        &self.data.method_specs
    }

    /// Returns the field definitions container, keyed by Field token (table 0x04).
    ///
    /// The same fields are reachable through their owning types' field lists; this map
    /// finds one by token without searching the types.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// for entry in assembly.fields().iter().take(3) {
    ///     println!("{}: {:?}", entry.value().name, entry.value().signature.base);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn fields(&self) -> &FieldMap {
        &self.data.fields
    }

    /// Returns every custom attribute, keyed by CustomAttribute token (table 0x0C).
    ///
    /// The same attributes are reachable through their owners' attribute lists; this map
    /// holds them all, with their parent and constructor, without walking every owner.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// for entry in assembly.custom_attributes().iter().take(3) {
    ///     println!("{:?}: {} fixed arguments", entry.key(), entry.value().value.fixed_args.len());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn custom_attributes(&self) -> &CustomAttributeMap {
        &self.data.custom_attributes
    }

    /// Returns the method definition for the given token.
    ///
    /// Convenience accessor over [`methods()`](Self::methods) - looks up a
    /// method by its metadata token and returns a cloned reference-counted
    /// pointer to the [`Method`](crate::metadata::method::Method) object,
    /// eliminating the boilerplate of unwrapping the `Entry` guard manually.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token (table 0x06) identifying the method definition.
    ///
    /// # Returns
    ///
    /// `Ok(`[`Method`](crate::metadata::method::Method)`)` reference-counted
    /// if the token resolves; `Err(`[`MethodLookupError::NotFound`]`)` if the
    /// token is not present in the `MethodDef` table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LookupMethod`]`(`[`MethodLookupError::NotFound`]`)`
    /// when `token` does not match any row in the `MethodDef` table. **This
    /// is distinct from RVA = 0.** A method that exists but has no IL body
    /// (abstract, P/Invoke, runtime-managed) still resolves to `Ok(method)`;
    /// inspect [`Method::rva_kind`](crate::metadata::method::Method::rva_kind)
    /// to see why the body is absent. Match on `Error::LookupMethod(_)` to
    /// recover the structured [`MethodLookupError`] variant.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let token = Token::new(0x06000001);
    ///
    /// match assembly.method(&token) {
    ///     Ok(method) => {
    ///         println!("Method: {} (static: {})", method.name, method.is_static());
    ///     }
    ///     Err(e) => eprintln!("lookup failed: {e}"),
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn method(&self, token: &Token) -> Result<MethodRc> {
        self.data
            .methods
            .get(token)
            .map(|e| e.value().clone())
            .ok_or_else(|| MethodLookupError::NotFound(*token).into())
    }

    /// Returns the member reference for the given token, if it exists.
    ///
    /// This is a convenience accessor that looks up a member reference (external method
    /// or field reference) by its metadata token and returns a cloned reference-counted
    /// pointer to the [`MemberRef`](crate::metadata::tables::MemberRef) object.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token (table 0x0A) identifying the member reference.
    ///
    /// # Returns
    ///
    /// - `Some(`[`MemberRef`](crate::metadata::tables::MemberRef)`)` reference-counted
    ///   if `token` resolves to a row in the `MemberRef` table.
    /// - `None` only when `token` is not present in the `MemberRef` table.
    ///   This is a lookup miss, not a malformed-input signal - the assembly
    ///   may simply not reference the requested member.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let token = Token::new(0x0A000001);
    ///
    /// if let Some(member_ref) = assembly.member_ref(&token) {
    ///     println!("Member: {} (declared by: {:?})", member_ref.name, member_ref.declaredby.token());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn member_ref(&self, token: &Token) -> Option<MemberRefRc> {
        self.data.refs_member.get(token).map(|e| e.value().clone())
    }

    /// Returns the method specification for the given token.
    ///
    /// A method specification represents a generic method instantiation with
    /// concrete type arguments. Convenience accessor that looks up a
    /// `MethodSpec` by its metadata token and returns a cloned
    /// reference-counted pointer.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token (table 0x2B) identifying the method specification.
    ///
    /// # Returns
    ///
    /// `Ok(`[`MethodSpec`](crate::metadata::tables::MethodSpec)`)` reference-counted
    /// if the token resolves; `Err(`[`MethodLookupError::SpecNotFound`]`)` if the
    /// token is not present in the `MethodSpec` table.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LookupMethod`]`(`[`MethodLookupError::SpecNotFound`]`)`
    /// when `token` does not match any row in the `MethodSpec` table. Match
    /// on `Error::LookupMethod(_)` to recover the structured
    /// [`MethodLookupError`] variant.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let token = Token::new(0x2B000001);
    ///
    /// if let Ok(spec) = assembly.method_spec(&token) {
    ///     println!("MethodSpec: {:?} with {} generic args",
    ///              spec.method.token(), spec.generic_args.count());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn method_spec(&self, token: &Token) -> Result<MethodSpecRc> {
        self.data
            .method_specs
            .get(token)
            .map(|e| e.value().clone())
            .ok_or_else(|| MethodLookupError::SpecNotFound(*token).into())
    }

    /// Resolves a method-like token to its simple method name.
    ///
    /// This method handles the three token types that can refer to a method:
    ///
    /// - **MethodDef** (table 0x06): Returns the method definition name.
    /// - **MemberRef** (table 0x0A): Returns the member reference name.
    /// - **MethodSpec** (table 0x2B): Follows the generic instantiation to the
    ///   underlying method and returns its name.
    ///
    /// This is useful for pattern matching on call targets where only the method
    /// name is needed (e.g., checking if a call targets `"get_IsAttached"` or
    /// `"Decompress"`), regardless of whether the call uses a direct definition,
    /// an external reference, or a generic instantiation.
    ///
    /// # Arguments
    ///
    /// * `token` - A metadata token from a call-like instruction operand.
    ///
    /// # Returns
    ///
    /// - `Some(name)` if `token` resolves to a row in the `MethodDef`,
    ///   `MemberRef`, or `MethodSpec` table.
    /// - `None` in two distinct cases that this accessor does **not**
    ///   distinguish:
    ///   - `token` belongs to one of the three supported tables but the row
    ///     is missing (lookup miss).
    ///   - `token`'s table is not one of the three supported types (caller
    ///     bug - the helper is intended for call-site operands only).
    ///
    /// If you need to distinguish those cases, dispatch on
    /// [`Token::table`](crate::metadata::token::Token::table) yourself and
    /// call [`method`](Self::method) / [`member_ref`](Self::member_ref) /
    /// [`method_spec`](Self::method_spec) directly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    ///
    /// // Resolve a MethodDef token
    /// let token = Token::new(0x06000001);
    /// if let Some(name) = assembly.resolve_method_name(token) {
    ///     println!("Method name: {name}");
    /// }
    ///
    /// // Resolve a MemberRef token
    /// let token = Token::new(0x0A000001);
    /// if let Some(name) = assembly.resolve_method_name(token) {
    ///     println!("Member ref name: {name}");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn resolve_method_name(&self, token: Token) -> Option<String> {
        match token.table() {
            0x06 => method_name_by_token(&self.data.methods, &token),
            0x0A => member_ref_name_by_token(&self.data.refs_member, &token),
            0x2B => method_spec_name_by_token(&self.data.method_specs, &token),
            _ => None,
        }
    }

    /// Resolves a method token to the full name of the type that declares the
    /// method.
    ///
    /// The counterpart of [`Self::resolve_method_name`], over the same three
    /// tables: a `MethodDef`'s declaring type, a `MemberRef`'s parent, and the
    /// method a `MethodSpec` instantiates. Matching a call target needs both:
    /// `Concat` alone names a user's `StringHelper.Concat` as readily as
    /// `System.String.Concat`.
    ///
    /// # Arguments
    ///
    /// * `token` - A metadata token from a call-like instruction operand.
    ///
    /// # Returns
    ///
    /// The declaring type's full name (`System.String`), or `None` when the
    /// token is not a method token, its row is missing, or its declaring type
    /// cannot be resolved.
    pub fn resolve_method_declaring_type(&self, token: Token) -> Option<String> {
        let method_def = |method: Option<MethodRc>| {
            method
                .and_then(|method| method.declaring_type_rc())
                .map(|ty| ty.fullname().to_string())
        };
        let parent = |member: &MemberRefRc| member.declaredby.fullname();
        match token.table() {
            0x06 => method_def(self.data.methods.get(&token).map(|e| e.value().clone())),
            0x0A => self
                .data
                .refs_member
                .get(&token)
                .and_then(|e| parent(e.value())),
            0x2B => {
                let spec = self.data.method_specs.get(&token)?;
                match &spec.value().method {
                    CilTypeReference::MethodDef(method) => method_def(method.upgrade()),
                    CilTypeReference::MemberRef(member) => parent(member),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Returns the resources container with all embedded and linked resources.
    ///
    /// The resources container provides access to all resources associated with
    /// this assembly, including embedded resources, linked files, and resource
    /// metadata. This includes both .NET resources and Win32 resources.
    ///
    /// # Returns
    ///
    /// Reference to the `Resources` container with all resource information.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let resources = assembly.resources();
    ///
    /// for entry in resources.iter() {
    ///     let resource = entry.value();
    ///     println!("Resource: {} (Size: {}, Offset: 0x{:X})", resource.name, resource.data_size, resource.data_offset);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn resources(&self) -> &Resources {
        &self.data.resources
    }

    /// Returns the assembly's Portable PDB: its debug information.
    ///
    /// Every load reads the PDB the assembly carries: the one the image embeds in its debug
    /// directory, or else the debug tables in the image's own metadata. A standalone `.pdb`
    /// file is never looked for on disk; [`CilObject::with_pdb`] attaches one.
    ///
    /// The PDB the image carries is read leniently whatever the load's mode, since the runtime
    /// never reads it to load the assembly: a malformed row, or an embedded PDB that does not
    /// inflate or was written for another image, is a [diagnostic](Self::diagnostics) rather
    /// than a failed load.
    ///
    /// # Returns
    ///
    /// The [`PortablePdb`], with its documents, method debug information (sequence points),
    /// local scopes, variables and constants, import scopes, state machine methods and custom
    /// debug information; `None` when the assembly has no debug information.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/pdb/embedded/PdbProbe.dll")?;
    /// if let Some(pdb) = assembly.pdb() {
    ///     println!("{} PDB with {} documents", pdb.origin(), pdb.documents().len());
    ///     for entry in pdb.documents().iter() {
    ///         let document = entry.value();
    ///         println!("  {} ({})", document.name, document.hash_algorithm_name());
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn pdb(&self) -> Option<&PortablePdb> {
        self.data.pdb.as_ref()
    }

    /// Reloads the assembly with the standalone Portable PDB at `path` attached.
    ///
    /// See [`CilObject::with_pdb_bytes`], which this reads the file for.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, and as [`CilObject::with_pdb_bytes`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/pdb/portable/PdbProbe.dll")?
    ///     .with_pdb("tests/samples/pdb/portable/PdbProbe.pdb")?;
    /// let pdb = assembly.pdb().expect("the PDB is attached");
    /// println!("entry point: {:?}", pdb.entry_point());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn with_pdb(self, path: impl AsRef<Path>) -> Result<Self> {
        let pdb = std::fs::read(path)?;
        self.with_pdb_bytes(&pdb)
    }

    /// Reloads the assembly with the standalone Portable PDB `pdb` attached.
    ///
    /// The assembly is loaded again from the same file, with the same validation, and its
    /// debug information read from `pdb` rather than the PDB the image carries. The result
    /// is the object a load with that PDB gives: its diagnostics are the new load's.
    ///
    /// A standalone PDB is read in the load's mode. In strict mode it fails the reload when
    /// it does not read, a row of it is malformed, or its `#Pdb` stream records row counts
    /// other than the image's (it was written for another image, so its columns cannot be
    /// read against this one); in lenient mode each of these is a diagnostic. A PDB whose id
    /// is not the one the image's CodeView entry names (another build of the same source)
    /// is read, with a diagnostic, since its rows are still well-formed.
    ///
    /// # Arguments
    ///
    /// * `pdb` - The standalone PDB's bytes
    ///
    /// # Errors
    ///
    /// Returns an error when the assembly no longer loads or validates, or, in strict mode,
    /// when `pdb` is malformed or written for another image. The object is consumed either
    /// way: on an error, load the assembly again to keep working without the PDB.
    pub fn with_pdb_bytes(self, pdb: &[u8]) -> Result<Self> {
        let file = self.assembly_view.file().clone();
        let validation_config = self.validation_config;
        drop(self);
        let assembly_view =
            CilAssemblyView::load_with_validation(file, ValidationConfig::disabled())?;
        Self::load_validated(assembly_view, validation_config, Some(pdb))
    }

    /// Returns the type registry containing all type definitions and references.
    ///
    /// The type registry provides centralized access to all types defined in and
    /// referenced by this assembly. This includes `TypeDef` entries (types defined
    /// in this assembly), `TypeRef` entries (types referenced from other assemblies),
    /// `TypeSpec` entries (instantiated generic types), and primitive types.
    ///
    /// # Returns
    ///
    /// Reference to the `TypeRegistry` containing all type information.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let types = assembly.types();
    ///
    /// println!("Total types: {}", types.len());
    ///
    /// // Get all types
    /// for type_info in types.all_types() {
    ///     println!("Type: {}.{} (Token: 0x{:08X})",
    ///         type_info.namespace, type_info.name, type_info.token.value());
    /// }
    ///
    /// // Look up specific types
    /// let string_types = types.get_by_name("String");
    /// for string_type in string_types {
    ///     println!("Found String type in namespace: {}", string_type.namespace);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn types(&self) -> Arc<TypeRegistry> {
        self.data.types.clone()
    }

    /// Returns a composable query over types in this assembly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    ///
    /// // Find all public, defined types
    /// let public_types = assembly.query_types()
    ///     .defined()
    ///     .public()
    ///     .find_all();
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn query_types(&self) -> TypeQuery<'_> {
        TypeQuery::new(&self.data.types)
    }

    /// Returns a composable query over all methods in this assembly.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    ///
    /// // Find all static constructors
    /// let cctors = assembly.query_methods()
    ///     .static_constructors()
    ///     .find_all();
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn query_methods(&self) -> MethodQuery<'_> {
        MethodQuery::from_assembly(&self.data.methods)
    }

    /// Returns a cross-table token resolver for this assembly.
    ///
    /// The [`TokenResolver`] normalizes metadata token references across tables,
    /// resolving indirections that arise from the .NET metadata table design:
    ///
    /// - **TypeRef → TypeDef**: Finds the local type definition for an external
    ///   type reference, giving access to the type's methods and fields.
    /// - **MemberRef → MethodDef**: Resolves a member reference to the locally
    ///   defined method, enabling emulation of calls that use MemberRef tokens.
    /// - **MemberRef → FieldDef**: Resolves a member reference to the locally
    ///   defined field for field access instructions.
    /// - **MethodSpec → MethodDef**: Unwraps generic method instantiations to
    ///   their base method definition.
    ///
    /// This complements [`query_types()`](Self::query_types) and
    /// [`query_methods()`](Self::query_methods) (which filter existing collections)
    /// and [`TypeResolver`](crate::metadata::typesystem::TypeResolver) (which
    /// resolves type *signatures* from blob heaps into [`CilType`](crate::metadata::typesystem::CilType)
    /// instances).
    ///
    /// The resolver is a zero-cost borrowing wrapper - it holds only a reference
    /// to this `CilObject` and performs no allocations or caching.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resolver = assembly.resolver();
    ///
    /// // Resolve a MemberRef to its local MethodDef
    /// let member_ref = Token::new(0x0A000001);
    /// if let Some(method_def) = resolver.resolve_method(member_ref) {
    ///     println!("Resolved to MethodDef: 0x{:08X}", method_def.value());
    /// }
    ///
    /// // Find which type declares a method
    /// let method = Token::new(0x06000001);
    /// if let Some(declaring_type) = resolver.declaring_type(method) {
    ///     println!("Declared in: {}", declaring_type.fullname());
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn resolver(&self) -> TokenResolver<'_> {
        TokenResolver::new(self)
    }

    /// Builds and returns the call graph for this assembly.
    ///
    /// The call graph represents the calling relationships between methods in the
    /// assembly, including direct calls, virtual dispatch, and interface calls.
    /// This is useful for understanding code structure, finding entry points,
    /// and performing inter-procedural analysis.
    ///
    /// Note: Building the call graph requires analyzing all methods in the assembly,
    /// which may be expensive for large assemblies. Consider caching the result if
    /// you need to access it multiple times.
    ///
    /// # Returns
    ///
    /// A [`CallGraph`] for this assembly, or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if call graph construction fails (e.g., due to corrupted
    /// method metadata).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let callgraph = assembly.callgraph()?;
    ///
    /// let stats = callgraph.stats();
    /// println!("Call graph: {} methods, {} edges", stats.method_count, stats.edge_count);
    ///
    /// // Export as DOT for visualization
    /// let dot = callgraph.to_dot(Some("MyAssembly"));
    /// std::fs::write("callgraph.dot", dot)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn callgraph(&self) -> Result<CallGraph> {
        CallGraph::build(self)
    }

    /// Returns the underlying file representation of this assembly.
    ///
    /// The file object provides access to the raw PE file data, headers, and
    /// file-level operations such as RVA-to-offset conversion, section access,
    /// and memory-mapped or buffered file I/O. This is useful for low-level
    /// analysis or when you need direct access to the PE file structure.
    ///
    /// # Returns
    ///
    /// Reference to the `Arc<File>` containing the PE file representation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/mono_4.8/mscorlib.dll")?;
    /// let file = assembly.file();
    ///
    /// // Access file-level information
    /// println!("File size: {} bytes", file.data().len());
    ///
    /// // Access PE headers
    /// let dos_header = file.header_dos();
    /// let nt_headers = file.header();
    /// println!("Machine type: 0x{:X}", nt_headers.machine);
    ///
    /// // Convert RVA to file offset
    /// let Some((clr_rva, _)) = file.clr() else {
    ///     panic!("No CLR header found");
    /// };
    /// let offset = file.rva_to_offset(clr_rva)?;
    /// println!("CLR header at file offset: 0x{:X}", offset);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn file(&self) -> &Arc<File> {
        self.assembly_view.file()
    }

    /// Converts this `CilObject` into a [`CilAssembly`] for modification.
    ///
    /// This method efficiently transfers ownership of the internal assembly view
    /// to create a mutable assembly, avoiding unnecessary data copying. The resolved
    /// metadata (types, methods, etc.) is dropped since modifications work on the
    /// raw assembly view level.
    ///
    /// # Returns
    ///
    /// A [`CilAssembly`] ready for modification operations.
    ///
    /// # Usage Examples
    ///
    /// ```rust,no_run
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("input.dll")?;
    ///
    /// // Convert to mutable assembly for modifications
    /// let mut mutable = assembly.into_assembly();
    ///
    /// // Perform modifications
    /// mutable.string_add("NewString")?;
    ///
    /// // Write back and convert to CilObject
    /// let modified = mutable.into_cilobject()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Performance
    ///
    /// This operation is O(1) - it transfers ownership of the internal view
    /// without copying the underlying assembly data.
    #[must_use]
    pub fn into_assembly(self) -> CilAssembly {
        CilAssembly::new(self.assembly_view)
    }

    /// Validates the loaded assembly metadata using the specified configuration.
    ///
    /// This method runs comprehensive validation checks on the assembly metadata
    /// to ensure structural integrity, semantic correctness, and compliance with
    /// .NET metadata format requirements. This is separate from loading validation
    /// and can be used when you need to perform more comprehensive checks,
    /// additional validation after loading, or when you loaded with minimal
    /// validation initially.
    ///
    /// # Arguments
    ///
    /// * `config` - Validation configuration specifying which validations to perform
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all validations pass, or an error describing
    /// any validation failures found.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::{CilObject, ValidationConfig};
    /// use std::path::Path;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// // Load assembly with minimal validation for speed
    /// let assembly = CilObject::from_path_with_validation(
    ///     Path::new("tests/samples/mono_4.8/mscorlib.dll"),
    ///     ValidationConfig::minimal()
    /// )?;
    ///
    /// // Later, perform comprehensive validation
    /// assembly.validate(ValidationConfig::comprehensive())?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns validation errors found during analysis, such as:
    /// - Circular type nesting
    /// - Field layout overlaps
    /// - Invalid generic constraints
    /// - Type system inconsistencies
    pub fn validate(&self, config: ValidationConfig) -> Result<()> {
        if config == ValidationConfig::disabled() {
            return Ok(());
        }

        let engine = ValidationEngine::new(&self.assembly_view, config)?;
        let result = engine.execute_two_stage_validation(&self.assembly_view, None, Some(self))?;

        result.into_result()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{metadata::tables::TableId, testkit::get_testfile_crafted2};

    /// Every Field row is in [`CilObject::fields`], and it is the same field its owning type
    /// lists.
    #[test]
    fn every_field_is_found_by_its_token() {
        let assembly = CilObject::from_path(get_testfile_crafted2()).unwrap();
        let rows = assembly.tables().unwrap().table_row_count(TableId::Field);
        assert!(rows > 0);
        assert_eq!(assembly.fields().len(), rows as usize);

        let mut owned = 0;
        for entry in assembly.types().iter() {
            for (_, field) in entry.value().fields.iter() {
                let found = assembly.fields().get(&field.token).unwrap();
                assert!(Arc::ptr_eq(found.value(), field), "{}", field.name);
                owned += 1;
            }
        }
        assert_eq!(owned, rows as usize);
    }
}
