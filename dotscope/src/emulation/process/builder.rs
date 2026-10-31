//! Process builder for configuring emulation processes.
//!
//! This module provides [`ProcessBuilder`] for fluent configuration of
//! emulation processes. The builder pattern allows for flexible setup of
//! all aspects of .NET emulation including:
//!
//! - Assembly loading and PE image mapping
//! - Memory configuration and data mapping
//! - Execution limits and resource constraints
//! - Stub registration for BCL method emulation
//! - Capture configuration for extracting runtime data
//!
//! # Overview
//!
//! The [`ProcessBuilder`] is the primary entry point for creating [`EmulationProcess`]
//! instances. It provides a fluent API that supports both simple and complex
//! configuration scenarios through method chaining.
//!
//! # Usage Patterns
//!
//! ## Simple Configuration
//!
//! For basic emulation, load an assembly and use preset configurations:
//!
//! ```rust,no_run
//! use dotscope::emulation::ProcessBuilder;
//! use dotscope::CilObject;
//!
//! # fn main() -> Result<(), dotscope::Error> {
//! let assembly = CilObject::from_path("sample.exe")?;
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .for_extraction()
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Advanced Configuration
//!
//! For detailed control, configure individual components:
//!
//! ```rust,no_run
//! use dotscope::emulation::{ProcessBuilder, EmulationConfig, CaptureConfig};
//! use dotscope::CilObject;
//!
//! # fn main() -> Result<(), dotscope::Error> {
//! # let assembly = CilObject::from_path("sample.exe")?;
//! # let pe_bytes = std::fs::read("sample.exe").unwrap();
//! # let encrypted_data = vec![0u8; 16];
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .config(EmulationConfig::extraction())
//!     .with_max_instructions(100_000_000)
//!     .with_max_heap_bytes(512 * 1024 * 1024)
//!     .map_pe_image(&pe_bytes, "main.exe")
//!     .map_data(0x400000, encrypted_data, "encrypted_section")
//!     .capture_assemblies()
//!     .capture_strings()
//!     .build()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Custom Stubs
//!
//! Register custom method stubs for BCL methods:
//!
//! ```no_run
//! # use dotscope::emulation::ProcessBuilder;
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .stub(signature, my_custom_stub)
//!     .no_default_stubs() // Optionally disable built-in stubs
//!     .build()?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{path::Path, sync::Arc};

use cowfile::CowFile;
use log::debug;

use crate::{
    emulation::{
        capture::CaptureContext,
        fakeobjects::SharedFakeObjects,
        filesystem::VirtualFs,
        loader::{DataLoader, PeLoader, PeLoaderConfig},
        memory::{AddressSpace, MemoryProtection, SharedHeap},
        process::{CaptureConfig, EmulationConfig, EmulationProcess, TracingConfig},
        runtime::{Hook, RuntimeState},
        thread::ThreadContext,
        tracer::{TraceListener, TraceWriter},
        EmValue,
    },
    metadata::{
        tables::{FieldRvaRaw, ModuleRaw},
        token::Token,
        typesystem::PointerSize,
    },
    CilObject, Error, Result,
};

/// Pre-populates static fields with data from the FieldRVA table.
///
/// This function reads the FieldRVA metadata table and initializes static fields
/// that have embedded data in the PE file. This is essential for deobfuscation
/// where static initializers may reference this data.
///
/// # What Gets Initialized
///
/// - Primitive value types (I1, I2, I4, I8, U1, U2, U4, U8, R4, R8, Boolean, Char)
/// - Value types with known sizes from the ClassLayout table
///
/// # What Is NOT Initialized
///
/// - Arrays (handled by `RuntimeHelpers.InitializeArray` during execution)
/// - Reference types
/// - Complex value types without explicit size information
///
/// # Arguments
///
/// * `assembly` - The assembly to read FieldRVA data from
/// * `address_space` - The address space containing static field storage
fn populate_fieldrva_statics(assembly: &CilObject, address_space: &AddressSpace) -> Result<()> {
    let Some(tables) = assembly.tables() else {
        return Ok(());
    };

    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return Ok(());
    };

    let types = assembly.types();
    let file = assembly.file();
    let ptr_size = PointerSize::from_is_64bit(file.pe().is_64bit);

    for row in fieldrva_table {
        let row = row?;
        if row.rva == 0 {
            continue;
        }

        // Convert field index to full token (table 0x04 = Field)
        let field_token = Token::new(row.field | 0x0400_0000);

        // Look up the field to get its byte size from TypeRegistry
        let Some(field_type_size) = types.get_field_byte_size(&field_token, ptr_size) else {
            continue;
        };

        // The field's bytes as the loaded image holds them
        let Ok(data) = file.rva_slice(row.rva as usize, field_type_size) else {
            continue;
        };
        let data = data.as_ref();

        // Convert to EmValue based on size
        let value = match field_type_size {
            1 => {
                let Some(b) = data.first() else { continue };
                EmValue::I32(i32::from(b.cast_signed()))
            }
            2 => {
                let Ok(bytes) = <[u8; 2]>::try_from(data) else {
                    continue;
                };
                EmValue::I32(i32::from(i16::from_le_bytes(bytes)))
            }
            4 => {
                let Ok(bytes) = <[u8; 4]>::try_from(data) else {
                    continue;
                };
                EmValue::I32(i32::from_le_bytes(bytes))
            }
            8 => {
                let Ok(bytes) = <[u8; 8]>::try_from(data) else {
                    continue;
                };
                EmValue::I64(i64::from_le_bytes(bytes))
            }
            _ => continue,
        };

        // Store in static field storage
        address_space.statics().set(field_token, value)?;
    }
    Ok(())
}

/// Deferred mapping operation for [`ProcessBuilder`].
///
/// Represents a memory mapping operation that will be executed when
/// [`ProcessBuilder::build`] is called. Operations are stored in order
/// and executed sequentially during process construction.
///
/// This enum is internal to the builder and not exposed publicly.
#[derive(Clone)]
enum MappingOperation {
    /// Map a PE image from raw bytes into the address space.
    ///
    /// The PE loader will parse headers, map sections, and apply relocations.
    PeImage {
        /// Raw PE file bytes.
        data: Vec<u8>,
        /// Display name for the loaded image.
        name: String,
        /// Configuration for the PE loader.
        config: PeLoaderConfig,
    },

    /// Map a PE image from a file path.
    ///
    /// The file will be read and loaded using the PE loader.
    PeFile {
        /// Path to the PE file.
        path: std::path::PathBuf,
        /// Configuration for the PE loader.
        config: PeLoaderConfig,
    },

    /// Map raw data at a specific virtual address.
    ///
    /// Used for mapping decrypted sections, unpacked data, or other
    /// raw memory regions at known addresses.
    DataAt {
        /// Target virtual address for the mapping.
        address: u64,
        /// Raw data bytes to map.
        data: Vec<u8>,
        /// Descriptive label for the region.
        label: String,
        /// Memory protection flags.
        protection: MemoryProtection,
    },

    /// Map raw data at the next available address.
    ///
    /// The address space allocator will choose an appropriate location.
    Data {
        /// Raw data bytes to map.
        data: Vec<u8>,
        /// Descriptive label for the region.
        label: String,
        /// Memory protection flags.
        protection: MemoryProtection,
    },

    /// Map file contents at a specific address.
    ///
    /// Reads a file and maps its contents into the address space.
    File {
        /// Path to the file to map.
        path: std::path::PathBuf,
        /// Target virtual address for the mapping.
        address: u64,
        /// Memory protection flags.
        protection: MemoryProtection,
    },

    /// Map zeroed memory at a specific address.
    ///
    /// Allocates a region of zero-initialized memory, useful for
    /// creating stack space, heap regions, or uninitialized data sections.
    Zeroed {
        /// Target virtual address for the mapping.
        address: u64,
        /// Size of the region in bytes.
        size: usize,
        /// Descriptive label for the region.
        label: String,
        /// Memory protection flags.
        protection: MemoryProtection,
    },
}

/// Builder for creating and configuring emulation processes.
///
/// `ProcessBuilder` provides a fluent API for setting up .NET emulation with
/// assemblies, PE images, mapped data, and custom stubs. It is the recommended
/// way to create [`EmulationProcess`] instances.
///
/// # Builder Pattern
///
/// The builder follows a fluent interface pattern where all configuration methods
/// return `self`, allowing method chaining. Configuration is accumulated and
/// applied when [`build()`](ProcessBuilder::build) is called.
///
/// # Configuration Categories
///
/// The builder supports several categories of configuration:
///
/// - **Assembly**: Set the primary .NET assembly to emulate
/// - **Memory Mapping**: Map PE images, raw data, or files into the address space
/// - **Limits**: Configure instruction counts, call depth, and memory limits
/// - **Stubs**: Register custom method implementations for BCL methods
/// - **Capture**: Configure what data to capture during emulation
/// - **Presets**: Use predefined configurations for common use cases
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::emulation::{ProcessBuilder, EmulationConfig};
/// use dotscope::CilObject;
///
/// # fn main() -> Result<(), dotscope::Error> {
/// let assembly = CilObject::from_path("sample.exe")?;
/// # let pe_bytes = std::fs::read("sample.exe").unwrap();
///
/// let process = ProcessBuilder::new()
///     .assembly(assembly)
///     .config(EmulationConfig::extraction())
///     .map_pe_image(&pe_bytes, "main.exe")
///     .capture_assemblies()
///     .build()?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// The builder itself is not thread-safe, but the resulting [`EmulationProcess`]
/// can be safely shared across threads via `Arc`.
pub struct ProcessBuilder {
    /// Primary .NET assembly to emulate.
    ///
    /// When set, the assembly's PE image is automatically mapped as the
    /// primary image during build.
    assembly: Option<Arc<CilObject>>,

    /// Emulation configuration controlling execution behavior.
    ///
    /// Includes limits, stub settings, threading options, and more.
    config: EmulationConfig,

    /// Configuration for capturing runtime data.
    ///
    /// Controls what information (assemblies, strings, buffers) is
    /// captured during emulation.
    capture_config: CaptureConfig,

    /// Hooks for method interception.
    ///
    /// These are registered with the runtime's hook manager before execution.
    hooks: Vec<Hook>,

    /// Deferred memory mapping operations.
    ///
    /// These are executed in order during build to set up the address space.
    mappings: Vec<MappingOperation>,

    /// Whether to register default BCL stubs.
    ///
    /// When true (default), standard library stubs for String, Array,
    /// Math, etc. are automatically registered.
    register_defaults: bool,

    /// Optional process name for identification.
    ///
    /// If not set, defaults to the assembly name or "emulation".
    name: Option<String>,

    /// Optional PE bytes to use instead of the assembly's own PE data.
    ///
    /// When set, these bytes are mapped into the address space instead of
    /// `assembly.file().data()`. This is used to bypass anti-tamper integrity
    /// checks: the emulator uses the patched assembly for metadata resolution
    /// but maps the original (pre-deobfuscation) PE bytes so that in-memory
    /// hash/checksum verification by the target code sees unmodified data.
    pe_override: Option<Vec<u8>>,

    /// Virtual filesystem entries to populate during build.
    virtual_fs_entries: Vec<VirtualFsEntry>,

    /// Trace listeners to attach to the trace writer.
    trace_listeners: Vec<Box<dyn TraceListener>>,
}

/// A deferred virtual filesystem entry for the builder.
enum VirtualFsEntry {
    /// Map from in-memory data.
    Data { vfs_path: String, data: Vec<u8> },
    /// Map from an existing CowFile (takes ownership).
    CowFile { vfs_path: String, cow: CowFile },
}

impl ProcessBuilder {
    /// Creates a new process builder with default settings.
    ///
    /// The builder is initialized with:
    /// - No assembly loaded
    /// - Default emulation configuration
    /// - Default capture configuration (nothing captured)
    /// - No custom hooks
    /// - Default BCL hooks enabled
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    ///
    /// let builder = ProcessBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            assembly: None,
            config: EmulationConfig::default(),
            capture_config: CaptureConfig::default(),
            hooks: Vec::new(),
            mappings: Vec::new(),
            register_defaults: true,
            name: None,
            pe_override: None,
            virtual_fs_entries: Vec::new(),
            trace_listeners: Vec::new(),
        }
    }

    /// Sets the primary .NET assembly for emulation.
    ///
    /// The assembly provides metadata for type resolution, method lookup,
    /// and instruction decoding. Its PE image is automatically mapped
    /// into the address space during build.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The loaded [`CilObject`] to use as the primary assembly
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    /// use dotscope::CilObject;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// let assembly = CilObject::from_path("sample.exe")?;
    /// let builder = ProcessBuilder::new().assembly(assembly);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn assembly(mut self, assembly: CilObject) -> Self {
        self.assembly = Some(Arc::new(assembly));
        self
    }

    /// Sets the primary assembly using an existing `Arc<CilObject>`.
    ///
    /// This variant is useful when the assembly is already wrapped in an
    /// `Arc`, avoiding an extra allocation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Arc-wrapped [`CilObject`] to use as the primary assembly
    #[must_use]
    pub fn assembly_arc(mut self, assembly: Arc<CilObject>) -> Self {
        self.assembly = Some(assembly);
        self
    }

    /// Sets the emulation configuration.
    ///
    /// The configuration controls execution limits, stub behavior,
    /// threading options, and tracing settings.
    ///
    /// # Arguments
    ///
    /// * `config` - The [`EmulationConfig`] to use
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{ProcessBuilder, EmulationConfig};
    ///
    /// let builder = ProcessBuilder::new()
    ///     .config(EmulationConfig::extraction());
    /// ```
    ///
    /// # See Also
    ///
    /// - [`for_extraction`](Self::for_extraction) - Preset for assembly extraction
    /// - [`for_analysis`](Self::for_analysis) - Preset for static analysis
    /// - [`for_full_emulation`](Self::for_full_emulation) - Preset for complete emulation
    #[must_use]
    pub fn config(mut self, config: EmulationConfig) -> Self {
        self.config = config;
        self
    }

    /// Overrides the target pointer size for native int/uint types.
    ///
    /// By default, pointer size is auto-detected from the PE header during
    /// [`build()`](Self::build). Use this method to override it manually.
    ///
    /// # Arguments
    ///
    /// * `ptr_size` - The [`PointerSize`] to use
    #[must_use]
    pub fn pointer_size(mut self, ptr_size: PointerSize) -> Self {
        self.config.pointer_size = ptr_size;
        self
    }

    /// Sets the capture configuration.
    ///
    /// The capture configuration determines what runtime data is collected
    /// during emulation, such as loaded assemblies, decrypted strings,
    /// and memory buffers.
    ///
    /// # Arguments
    ///
    /// * `config` - The [`CaptureConfig`] to use
    ///
    /// # See Also
    ///
    /// For individual capture settings, see:
    /// - [`capture_assemblies`](Self::capture_assemblies)
    /// - [`capture_strings`](Self::capture_strings)
    /// - [`capture_memory_region`](Self::capture_memory_region)
    #[must_use]
    pub fn capture(mut self, config: CaptureConfig) -> Self {
        self.capture_config = config;
        self
    }

    /// Sets the process name for identification.
    ///
    /// The name is used for logging and debugging. If not set, defaults
    /// to the assembly name or "emulation".
    ///
    /// # Arguments
    ///
    /// * `name` - Display name for the process
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Applies the extraction preset configuration.
    ///
    /// This preset is optimized for extracting packed or encrypted assemblies:
    /// - High instruction limit (50 million)
    /// - Unknown methods return default values
    /// - Assembly capture enabled automatically
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    /// use dotscope::CilObject;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// # let assembly = CilObject::from_path("sample.exe")?;
    /// let process = ProcessBuilder::new()
    ///     .assembly(assembly)
    ///     .for_extraction()
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn for_extraction(mut self) -> Self {
        self.config = EmulationConfig::extraction();
        self.capture_config.assemblies = true;
        self
    }

    /// Applies the analysis preset configuration.
    ///
    /// This preset is optimized for static analysis and constant propagation:
    /// - Moderate instruction limit (1 million)
    /// - Symbolic tracking enabled
    /// - Threading disabled for determinism
    /// - Unknown methods return symbolic values
    #[must_use]
    pub fn for_analysis(mut self) -> Self {
        self.config = EmulationConfig::analysis();
        self
    }

    /// Applies the full emulation preset configuration.
    ///
    /// This preset enables all emulation features:
    /// - Very high instruction limit (100 million)
    /// - 5 minute timeout
    /// - Strict mode (fail on missing stubs)
    /// - Full threading and exception handling
    #[must_use]
    pub fn for_full_emulation(mut self) -> Self {
        self.config = EmulationConfig::full();
        self
    }

    /// Applies the minimal preset configuration.
    ///
    /// This preset is optimized for simple constant folding:
    /// - Low instruction limit (10,000)
    /// - Shallow call depth (10)
    /// - Only BCL stubs enabled
    /// - Threading and exceptions disabled
    #[must_use]
    pub fn for_minimal(mut self) -> Self {
        self.config = EmulationConfig::minimal();
        self
    }

    /// Sets the maximum number of instructions to execute.
    ///
    /// When this limit is reached, emulation stops with a
    /// [`LimitReached`](crate::emulation::engine::EmulationOutcome::LimitReached) outcome.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum instruction count (0 for unlimited)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// let process = ProcessBuilder::new()
    ///     .with_max_instructions(1_000_000)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_max_instructions(mut self, max: u64) -> Self {
        self.config.limits.max_instructions = max;
        self
    }

    /// Sets the maximum call stack depth.
    ///
    /// Prevents runaway recursion by limiting nested method calls.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum call depth
    #[must_use]
    pub fn with_max_call_depth(mut self, max: usize) -> Self {
        self.config.limits.max_call_depth = max;
        self
    }

    /// Sets the maximum heap memory in bytes.
    ///
    /// Limits total memory that can be allocated on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum heap size in bytes
    #[must_use]
    pub fn with_max_heap_bytes(mut self, max: usize) -> Self {
        self.config.limits.max_heap_bytes = max;
        self.config.memory.max_heap_size = max;
        self
    }

    /// Sets the execution timeout in milliseconds.
    ///
    /// When exceeded, emulation stops with a timeout error.
    ///
    /// # Arguments
    ///
    /// * `ms` - Timeout in milliseconds (0 for no timeout)
    #[must_use]
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.config.limits.timeout_ms = ms;
        self
    }

    /// Sets the tracing configuration.
    ///
    /// Controls what events are logged during emulation. Use the preset
    /// methods on [`TracingConfig`] for common scenarios.
    ///
    /// # Arguments
    ///
    /// * `tracing` - The [`TracingConfig`] to use
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{ProcessBuilder, TracingConfig};
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// let process = ProcessBuilder::new()
    ///     .with_tracing(TracingConfig::full_trace("trace.log"))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_tracing(mut self, tracing: TracingConfig) -> Self {
        self.config.tracing = tracing;
        self
    }

    /// Maps a PE image from raw bytes into the address space.
    ///
    /// The PE loader will:
    /// - Parse PE headers
    /// - Map sections at their virtual addresses
    /// - Apply base relocations if needed
    /// - Set appropriate memory protections
    ///
    /// # Arguments
    ///
    /// * `pe_bytes` - Raw PE file bytes
    /// * `name` - Display name for the loaded image
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let pe_data = std::fs::read("sample.exe")?;
    /// let process = ProcessBuilder::new()
    ///     .map_pe_image(&pe_data, "sample.exe")
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn map_pe_image(mut self, pe_bytes: &[u8], name: impl Into<String>) -> Self {
        self.mappings.push(MappingOperation::PeImage {
            data: pe_bytes.to_vec(),
            name: name.into(),
            config: PeLoaderConfig::default(),
        });
        self
    }

    /// Maps a PE image from bytes with custom loader configuration.
    ///
    /// Allows fine-grained control over how the PE is loaded, such as
    /// forcing a specific base address or skipping relocations.
    ///
    /// # Arguments
    ///
    /// * `pe_bytes` - Raw PE file bytes
    /// * `name` - Display name for the loaded image
    /// * `config` - Custom [`PeLoaderConfig`] settings
    #[must_use]
    pub fn map_pe_image_with_config(
        mut self,
        pe_bytes: &[u8],
        name: impl Into<String>,
        config: PeLoaderConfig,
    ) -> Self {
        self.mappings.push(MappingOperation::PeImage {
            data: pe_bytes.to_vec(),
            name: name.into(),
            config,
        });
        self
    }

    /// Maps a PE image from a file path.
    ///
    /// Reads the file and loads it as a PE image during build.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the PE file
    #[must_use]
    pub fn map_pe_file(mut self, path: impl AsRef<Path>) -> Self {
        self.mappings.push(MappingOperation::PeFile {
            path: path.as_ref().to_path_buf(),
            config: PeLoaderConfig::default(),
        });
        self
    }

    /// Maps raw data at a specific virtual address.
    ///
    /// The data is mapped with read/write protection by default. This is
    /// useful for mapping decrypted sections, unpacked code, or test data.
    ///
    /// # Arguments
    ///
    /// * `address` - Target virtual address
    /// * `data` - Raw bytes to map
    /// * `label` - Descriptive label for the region
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// let decrypted = vec![0x90; 0x1000];
    /// let process = ProcessBuilder::new()
    ///     .map_data(0x00400000, decrypted, "decrypted_code")
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn map_data(mut self, address: u64, data: Vec<u8>, label: impl Into<String>) -> Self {
        self.mappings.push(MappingOperation::DataAt {
            address,
            data,
            label: label.into(),
            protection: MemoryProtection::READ | MemoryProtection::WRITE,
        });
        self
    }

    /// Maps raw data at a specific address with custom protection.
    ///
    /// # Arguments
    ///
    /// * `address` - Target virtual address
    /// * `data` - Raw bytes to map
    /// * `label` - Descriptive label for the region
    /// * `protection` - Memory protection flags
    #[must_use]
    pub fn map_data_with_protection(
        mut self,
        address: u64,
        data: Vec<u8>,
        label: impl Into<String>,
        protection: MemoryProtection,
    ) -> Self {
        self.mappings.push(MappingOperation::DataAt {
            address,
            data,
            label: label.into(),
            protection,
        });
        self
    }

    /// Maps a file's contents at a specific address.
    ///
    /// The file is read during build and mapped with read-only protection.
    ///
    /// # Arguments
    ///
    /// * `address` - Target virtual address
    /// * `path` - Path to the file to map
    #[must_use]
    pub fn map_file(mut self, address: u64, path: impl AsRef<Path>) -> Self {
        self.mappings.push(MappingOperation::File {
            path: path.as_ref().to_path_buf(),
            address,
            protection: MemoryProtection::READ,
        });
        self
    }

    /// Maps zeroed memory at a specific address.
    ///
    /// Creates a region of zero-initialized memory with read/write protection.
    /// Useful for allocating stack space, heap regions, or BSS sections.
    ///
    /// # Arguments
    ///
    /// * `address` - Target virtual address
    /// * `size` - Size of the region in bytes
    /// * `label` - Descriptive label for the region
    #[must_use]
    pub fn map_zeroed(mut self, address: u64, size: usize, label: impl Into<String>) -> Self {
        self.mappings.push(MappingOperation::Zeroed {
            address,
            size,
            label: label.into(),
            protection: MemoryProtection::READ | MemoryProtection::WRITE,
        });
        self
    }

    /// Enables capture of dynamically loaded assemblies.
    ///
    /// When enabled, assemblies loaded via `Assembly.Load` during emulation
    /// are captured and can be retrieved after execution.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// # let packed_assembly = CilObject::from_path("sample.exe")?;
    /// # let entry_point = Token::new(0x06000001);
    /// let process = ProcessBuilder::new()
    ///     .assembly(packed_assembly)
    ///     .capture_assemblies()
    ///     .build()?;
    ///
    /// process.execute_method(entry_point, vec![])?;
    ///
    /// for asm in process.captured_assemblies() {
    ///     println!("Captured: {} bytes", asm.data.len());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn capture_assemblies(mut self) -> Self {
        self.capture_config.assemblies = true;
        self
    }

    /// Enables capture of decrypted/constructed strings.
    ///
    /// Captures strings that are created or decrypted during emulation,
    /// useful for extracting obfuscated string literals.
    #[must_use]
    pub fn capture_strings(mut self) -> Self {
        self.capture_config.strings = true;
        self
    }

    /// Enables capture of file system operations.
    ///
    /// Records file reads, writes, and other I/O operations performed
    /// during emulation.
    #[must_use]
    pub fn capture_file_operations(mut self) -> Self {
        self.capture_config.file_operations = true;
        self
    }

    /// Enables capture of network operations.
    ///
    /// Records network connections, sends, and receives performed
    /// during emulation.
    #[must_use]
    pub fn capture_network_operations(mut self) -> Self {
        self.capture_config.network_operations = true;
        self
    }

    /// Adds a memory region to capture.
    ///
    /// Monitors writes to the specified address range and captures
    /// the data. Useful for extracting decrypted code or data.
    ///
    /// # Arguments
    ///
    /// * `start` - Start address of the region (inclusive)
    /// * `end` - End address of the region (exclusive)
    #[must_use]
    pub fn capture_memory_region(mut self, start: u64, end: u64) -> Self {
        self.capture_config.memory_regions.push(start..end);
        self
    }

    /// Registers a method hook for interception.
    ///
    /// Hooks provide flexible method interception with support for:
    /// - Multiple matching criteria (name, signature types, runtime data)
    /// - Pre/post execution handlers
    /// - Bypassing the original method execution
    ///
    /// Hooks can intercept any method call that matches their matchers.
    ///
    /// # Arguments
    ///
    /// * `hook` - The hook to register
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{ProcessBuilder, Hook, PreHookResult};
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// let process = ProcessBuilder::new()
    ///     .hook(Hook::new("log-calls")
    ///         .match_method_name("Decrypt")
    ///         .pre(|ctx, thread| {
    ///             println!("Decrypt called!");
    ///             PreHookResult::Continue
    ///         }))
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn hook(mut self, hook: Hook) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Overrides the PE bytes mapped into the emulator's address space.
    ///
    /// When the assembly is set via [`assembly`](Self::assembly) or
    /// [`assembly_arc`](Self::assembly_arc), its PE data is normally mapped
    /// automatically. This method substitutes different bytes for that mapping
    /// while still using the assembly for metadata resolution.
    ///
    /// This is useful for anti-tamper bypass: deobfuscation may patch the PE
    /// (decrypting method bodies, updating RVAs), but the target code's integrity
    /// checks read the in-memory PE image. Mapping the original, unpatched bytes
    /// lets those checks pass while the emulator uses the patched metadata.
    #[must_use]
    pub fn with_pe_override(mut self, pe_bytes: Vec<u8>) -> Self {
        self.pe_override = Some(pe_bytes);
        self
    }

    /// Maps a virtual file from in-memory data.
    ///
    /// The data will be accessible to emulated code via FileStream/File hooks.
    #[must_use]
    pub fn with_virtual_file(mut self, vfs_path: &str, data: Vec<u8>) -> Self {
        self.virtual_fs_entries.push(VirtualFsEntry::Data {
            vfs_path: vfs_path.to_string(),
            data,
        });
        self
    }

    /// Maps a virtual file from an existing CowFile (takes ownership).
    ///
    /// For mmap-backed CowFiles, this is zero-copy. The CowFile's pending
    /// writes are not carried over.
    #[must_use]
    pub fn with_virtual_file_cow(mut self, vfs_path: &str, cow: CowFile) -> Self {
        self.virtual_fs_entries.push(VirtualFsEntry::CowFile {
            vfs_path: vfs_path.to_string(),
            cow,
        });
        self
    }

    /// Disables registration of default BCL stubs.
    ///
    /// By default, the builder registers stubs for common BCL methods
    /// (String, Array, Math, etc.). Call this to start with no stubs
    /// and only use explicitly registered ones.
    ///
    /// # Warning
    ///
    /// Disabling default stubs may cause emulation to fail if the
    /// target code calls any BCL methods.
    #[must_use]
    pub fn no_default_stubs(mut self) -> Self {
        self.register_defaults = false;
        self
    }

    /// Adds a trace listener that will receive all trace events.
    ///
    /// Listeners are attached to the [`TraceWriter`] during build. They
    /// receive events synchronously during emulation, so keep processing
    /// lightweight.
    ///
    /// Tracing must be enabled (via [`TracingConfig`]) for listeners to
    /// receive events.
    ///
    /// # Arguments
    ///
    /// * `listener` - A boxed [`TraceListener`](crate::emulation::TraceListener) implementation
    #[must_use]
    pub fn with_trace_listener(mut self, listener: Box<dyn TraceListener>) -> Self {
        self.trace_listeners.push(listener);
        self
    }

    /// Builds the emulation process from the configured settings.
    ///
    /// This method consumes the builder and creates an [`EmulationProcess`]
    /// ready for method execution. The build process:
    ///
    /// 1. Creates the address space with configured heap size
    /// 2. Initializes the runtime state with stubs
    /// 3. Sets up the capture context
    /// 4. Maps the primary assembly's PE image (if set)
    /// 5. Executes all deferred mapping operations in order
    /// 6. Determines the process name
    ///
    /// # Returns
    ///
    /// Returns `Ok(EmulationProcess)` on success, or an error if:
    /// - A PE image fails to load or parse
    /// - A mapping operation fails (invalid address, file not found, etc.)
    /// - Memory allocation fails
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] if any mapping operation fails. The error
    /// type depends on the specific failure (I/O error, PE parse error, etc.).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::ProcessBuilder;
    /// use dotscope::CilObject;
    /// use dotscope::metadata::token::Token;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// # let assembly = CilObject::from_path("sample.exe")?;
    /// # let entry_point = Token::new(0x06000001);
    /// let process = ProcessBuilder::new()
    ///     .assembly(assembly)
    ///     .for_extraction()
    ///     .build()?;
    ///
    /// // Process is now ready for execution
    /// let outcome = process.execute_method(entry_point, vec![])?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self) -> Result<EmulationProcess> {
        debug!(
            "Creating emulation process: instruction_limit={}, call_depth={}",
            self.config.limits.max_instructions, self.config.limits.max_call_depth
        );
        // Two fields describe the same ceiling: `limits.max_heap_bytes` and
        // `memory.max_heap_size`. Only `ProcessBuilder::with_max_heap_bytes` keeps them in sync,
        // so a caller who builds `EmulationConfig` as a struct literal — the pattern the config
        // module's own docs demonstrate — sets `max_heap_bytes` and silently gets the default.
        // Honour the stricter of the two rather than picking one and ignoring the other.
        let heap_size = self
            .config
            .memory
            .max_heap_size
            .min(self.config.limits.max_heap_bytes);
        let heap = SharedHeap::new(heap_size);
        heap.heap()
            .set_max_objects(self.config.limits.max_heap_objects);

        // Initialize fake BCL objects before anything else uses the heap
        let fake_objects = SharedFakeObjects::new(heap.heap());

        let address_space = Arc::new(AddressSpace::with_heap(heap));
        // Apply the configured unmanaged ceiling. Unmanaged allocations bypass the managed
        // heap budget entirely, so without this the `max_unmanaged_bytes` setting has no
        // effect on anything.
        address_space.set_max_unmanaged_bytes(self.config.limits.max_unmanaged_bytes);

        let mut config = self.config.clone();
        if !self.register_defaults {
            config.stubs.bcl_stubs = false;
            config.stubs.pinvoke_stubs = false;
        }

        // Auto-detect pointer size from PE header
        if let Some(ref assembly) = self.assembly {
            config.pointer_size = if assembly.file().pe().is_64bit {
                PointerSize::Bit64
            } else {
                PointerSize::Bit32
            };
        }

        let config_arc = Arc::new(config);
        let runtime = RuntimeState::with_config(config_arc.clone());

        for hook in self.hooks {
            runtime.hooks().register(hook)?;
        }

        let capture = Arc::new(CaptureContext::with_config(self.capture_config));
        let mut loaded_images = Vec::new();
        let mut mapped_regions = Vec::new();

        if let Some(ref assembly) = self.assembly {
            let loader = PeLoader::default();
            let pe_bytes = self
                .pe_override
                .as_deref()
                .unwrap_or(assembly.file().data());
            let name = assembly
                .assembly()
                .map_or_else(|| "primary".to_string(), |a| a.name.clone());
            if let Ok(image) = loader.load(pe_bytes, &address_space, name) {
                loaded_images.push(image);
            }

            populate_fieldrva_statics(assembly, &address_space)?;
        }

        for mapping in self.mappings {
            match mapping {
                MappingOperation::PeImage { data, name, config } => {
                    let loader = PeLoader::with_config(config);
                    let image = loader.load(&data, &address_space, name)?;
                    loaded_images.push(image);
                }
                MappingOperation::PeFile { path, config } => {
                    let loader = PeLoader::with_config(config);
                    let image = loader.load_file(&path, &address_space)?;
                    loaded_images.push(image);
                }
                MappingOperation::DataAt {
                    address,
                    data,
                    label,
                    protection,
                } => {
                    let info =
                        DataLoader::map_at(&address_space, address, &data, label, protection)?;
                    mapped_regions.push(info);
                }
                MappingOperation::Data {
                    data,
                    label,
                    protection,
                } => {
                    let info = DataLoader::map(&address_space, &data, label, protection)?;
                    mapped_regions.push(info);
                }
                MappingOperation::File {
                    path,
                    address,
                    protection,
                } => {
                    let info = DataLoader::map_file(&address_space, &path, address, protection)?;
                    mapped_regions.push(info);
                }
                MappingOperation::Zeroed {
                    address,
                    size,
                    label,
                    protection,
                } => {
                    let info =
                        DataLoader::map_zeroed(&address_space, address, size, label, protection)?;
                    mapped_regions.push(info);
                }
            }
        }

        let name = self.name.unwrap_or_else(|| {
            self.assembly
                .as_ref()
                .and_then(|a| a.assembly())
                .map_or_else(|| "emulation".to_string(), |asm| asm.name.clone())
        });

        // Create trace writer if tracing is enabled or listeners are registered
        let has_listeners = !self.trace_listeners.is_empty();
        let trace_writer = if config_arc.tracing.is_enabled() || has_listeners {
            let context = config_arc.tracing.context_prefix.clone();
            let mut writer = if let Some(ref path) = config_arc.tracing.output_path {
                // File-based tracing - propagate errors to caller
                TraceWriter::new_file(path, context).map_err(|e| {
                    Error::TracingError(format!(
                        "Failed to create trace file {}: {e}",
                        path.display()
                    ))
                })?
            } else {
                // Memory-based tracing
                TraceWriter::new_memory(config_arc.tracing.max_trace_entries, context)
            };
            for listener in self.trace_listeners {
                writer.add_listener(listener);
            }
            Some(Arc::new(writer))
        } else {
            None
        };

        // Build virtual filesystem from accumulated entries
        let mut virtual_fs = VirtualFs::new();
        for entry in self.virtual_fs_entries {
            match entry {
                VirtualFsEntry::Data { vfs_path, data } => {
                    virtual_fs.map_data(&vfs_path, data);
                }
                VirtualFsEntry::CowFile { vfs_path, cow } => {
                    virtual_fs.map_cow(&vfs_path, cow);
                }
            }
        }

        // Auto-map the assembly's PE under its .NET module name.
        // Anti-tamper checks use Assembly.Location (which returns a path ending
        // in the module name) to open and verify the PE. The VirtualFs filename
        // fallback matches the filename component regardless of the full path.
        //
        // Try owned module metadata first, then fall back to raw Module table
        // (same approach as Assembly.get_Location hook) for obfuscated binaries
        // where owned metadata may not be populated.
        if let Some(ref assembly) = self.assembly {
            let module_name = assembly.module().map(|m| m.name.clone()).or_else(|| {
                let tables = assembly.tables()?;
                let strings = assembly.strings()?;
                let module_table = tables.table::<ModuleRaw>()?;
                // Module is RID 1 by definition (ECMA-335 II.22.30).
                let module_row = module_table.get(1).ok().flatten()?;
                strings.get(module_row.name as usize).ok().map(String::from)
            });

            if let Some(name) = module_name {
                if !virtual_fs.exists(&name) {
                    match assembly.file().fork_cowfile() {
                        Ok(cow) => {
                            debug!("Auto-mapped assembly PE as virtual file: {}", name);
                            virtual_fs.map_cow(&name, cow);
                        }
                        Err(e) => {
                            debug!("Auto-map: fork_cowfile failed for module '{}': {}", name, e);
                        }
                    }
                }
            }
        }

        let hook_count = runtime.hooks().len();

        let context = Arc::new(ThreadContext::new(
            address_space,
            Arc::new(std::sync::RwLock::new(runtime)),
            capture,
            config_arc,
            self.assembly,
            fake_objects,
            Arc::new(virtual_fs),
        ));

        let process = EmulationProcess {
            name,
            context,
            loaded_images,
            mapped_regions,
            instruction_count: std::sync::atomic::AtomicU64::new(0),
            trace_writer,
        };
        debug!("Emulation process ready: {} hooks registered", hook_count);
        Ok(process)
    }
}

impl Default for ProcessBuilder {
    /// Creates a default process builder.
    ///
    /// Equivalent to calling [`ProcessBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_defaults() {
        let builder = ProcessBuilder::new();
        let process = builder.build().unwrap();

        assert!(!process.has_assembly());
        assert_eq!(process.loaded_image_count(), 0);
    }

    #[test]
    fn test_builder_config_presets() {
        let process = ProcessBuilder::new().for_extraction().build().unwrap();

        assert!(process.capture().config().assemblies);
    }

    #[test]
    fn test_builder_capture_config() {
        let process = ProcessBuilder::new()
            .capture_assemblies()
            .capture_strings()
            .capture_memory_region(0x400000, 0x410000)
            .build()
            .unwrap();

        let config = process.capture().config();
        assert!(config.assemblies);
        assert!(config.strings);
        assert_eq!(config.memory_regions.len(), 1);
    }

    #[test]
    fn test_builder_map_data() {
        let process = ProcessBuilder::new()
            .map_data(0x10000, vec![0x01, 0x02, 0x03, 0x04], "test_data")
            .build()
            .unwrap();

        assert_eq!(process.mapped_region_count(), 1);

        let data = process.address_space().read(0x10000, 4).unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_builder_name() {
        let process = ProcessBuilder::new().name("test_process").build().unwrap();

        assert_eq!(process.name(), "test_process");
    }

    #[test]
    fn test_builder_no_default_hooks() {
        // With default hooks enabled (default behavior)
        let process_with_hooks = ProcessBuilder::new().build().unwrap();
        let runtime_with = process_with_hooks.runtime().read().unwrap();
        let count_with = runtime_with.hooks().len();

        // With default hooks disabled
        let process_no_hooks = ProcessBuilder::new().no_default_stubs().build().unwrap();
        let runtime_no = process_no_hooks.runtime().read().unwrap();
        let count_no = runtime_no.hooks().len();

        // Default hooks should have many registered (BCL + native)
        assert!(count_with > 0, "Expected default hooks to be registered");

        // No default hooks should have zero registered
        assert_eq!(
            count_no, 0,
            "Expected no hooks when no_default_stubs() is called"
        );
    }
}
