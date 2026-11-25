//! Native PE export table support for .NET assemblies.
//!
//! This module provides comprehensive functionality for parsing, analyzing, and generating
//! native PE export tables. It enables dotscope to handle mixed-mode assemblies that export
//! native functions alongside managed (.NET) types, supporting COM interop, native libraries,
//! and other scenarios requiring PE export table functionality.
//!
//! # Architecture
//!
//! The native export system implements the PE/COFF export table format with support for:
//!
//! - **Export Directory**: Main export table with metadata and function table references
//! - **Export Address Table (EAT)**: Function addresses indexed by ordinal number
//! - **Export Name Table**: Function names for name-based exports
//! - **Export Ordinal Table**: Ordinal mappings for name-to-ordinal resolution
//! - **Export Forwarders**: Function forwarding to other DLLs
//!
//! # Key Components
//!
//! - [`NativeExports`] - Main container for PE export table data
//! - [`ExportFunction`] - Individual function export with address/ordinal information
//! - [`ExportForwarder`] - Export forwarding to external DLL functions
//! - [`ExportDirectory`] - PE export directory structure metadata
//!
//! # Export Table Structure
//!
//! The PE export table follows this layout:
//! ```text
//! Export Directory Table
//! ├── DLL Name RVA
//! ├── Base Ordinal
//! ├── Number of Functions
//! ├── Number of Names
//! ├── Export Address Table RVA
//! ├── Export Name Table RVA
//! └── Export Ordinal Table RVA
//!
//! Export Address Table (EAT)
//! ├── Function 1 Address/Forwarder RVA
//! ├── Function 2 Address/Forwarder RVA
//! └── ...
//!
//! Export Name Table
//! ├── Function Name 1 RVA
//! ├── Function Name 2 RVA
//! └── ...
//!
//! Export Ordinal Table
//! ├── Function 1 Ordinal
//! ├── Function 2 Ordinal
//! └── ...
//!
//! Name Strings
//! ├── DLL Name + Null
//! ├── Function Name 1 + Null
//! ├── Function Name 2 + Null
//! └── Forwarder Strings + Null
//! ```
//!
//! # Usage Examples
//!
//! ## Read an Assembly's Export Table
//!
//! ```no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("library.dll")?;
//! let native_exports = assembly.exports().native();
//!
//! // Analyze exported functions
//! for function in native_exports.functions() {
//!     match &function.name {
//!         Some(name) => println!("Export: {} @ ordinal {}", name, function.ordinal),
//!         None => println!("Export: ordinal {} only", function.ordinal),
//!     }
//!     println!("  Address: 0x{:X}", function.address);
//! }
//!
//! // Exports forwarded to another library
//! for forwarder in native_exports.forwarders() {
//!     println!("Ordinal {} forwards to {}", forwarder.ordinal, forwarder.target);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Create Export Table
//!
//! ```rust,no_run
//! use dotscope::metadata::exports::NativeExports;
//!
//! let mut exports = NativeExports::new("MyLibrary.dll");
//!
//! // Add a regular function export
//! exports.add_function("MyFunction", 1, 0x1000)?;
//!
//! // Add an ordinal-only export
//! exports.add_function_by_ordinal(2, 0x2000)?;
//!
//! // Add a forwarded export
//! exports.add_forwarder("ForwardedFunc", 3, "Other.dll.TargetFunc")?;
//!
//! // Generate export table data
//! let export_data = exports.get_export_table_data()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All operations on [`NativeExports`] are thread-safe when accessed through shared references.
//! Mutable operations require exclusive access but can be performed concurrently with
//! immutable operations on different instances.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::exports::UnifiedExportContainer`] - Unified export container combining CIL and native
//! - [`crate::cilassembly::CilAssembly`] - PE writing pipeline for export table generation
//! - [`goblin`] - PE parsing library for export directory analysis

use std::collections::HashMap;

use crate::{
    file::pe::{Export, ExportHeader},
    utils::{to_u32, write_le_at, write_string_at},
    Result,
};

/// Container for native PE export table data.
///
/// Manages export directory metadata, function exports, and forwarder entries for
/// native DLL exports. Provides functionality for parsing existing export tables
/// from PE files and generating new export table data.
///
/// # Storage Strategy
/// - **Export Directory**: Core metadata including DLL name and table parameters
/// - **Function Exports**: Indexed by ordinal with optional name mapping
/// - **Forwarder Entries**: Export forwarding to external DLL functions
/// - **Name Mapping**: Efficient name-to-ordinal lookup
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::exports::NativeExports;
///
/// let mut exports = NativeExports::new("MyLibrary.dll");
///
/// // Add a function export
/// exports.add_function("MyFunction", 1, 0x1000)?;
///
/// // Generate export table
/// let table_data = exports.get_export_table_data()?;
/// println!("Export table size: {} bytes", table_data.len());
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct NativeExports {
    /// Export directory metadata
    directory: ExportDirectory,

    /// Function exports indexed by ordinal
    functions: HashMap<u16, ExportFunction>,

    /// Export forwarders indexed by ordinal
    forwarders: HashMap<u16, ExportForwarder>,

    /// Name-to-ordinal mapping for efficient lookups
    name_to_ordinal: HashMap<String, u16>,

    /// Next available ordinal for automatic assignment
    next_ordinal: u16,

    /// Base RVA where the export table will be placed
    export_table_base_rva: u32,
}

/// PE export directory structure.
///
/// Contains the core metadata for the export table, including DLL identification,
/// table sizes, and RVA references to the various export tables.
///
/// # PE Format Mapping
/// This structure corresponds to the PE IMAGE_EXPORT_DIRECTORY:
/// - `dll_name`: Name of the DLL containing the exports
/// - `base_ordinal`: Starting ordinal number (usually 1)
/// - `function_count`: Number of entries in Export Address Table
/// - `name_count`: Number of entries in Export Name Table
#[derive(Debug, Clone)]
pub struct ExportDirectory {
    /// Name of the DLL (e.g., "MyLibrary.dll")
    pub dll_name: String,

    /// Base ordinal number (typically 1)
    pub base_ordinal: u16,

    /// Number of functions in Export Address Table
    pub function_count: u32,

    /// Number of names in Export Name Table
    pub name_count: u32,

    /// Timestamp for the export table (usually 0)
    pub timestamp: u32,

    /// Major version number
    pub major_version: u16,

    /// Minor version number
    pub minor_version: u16,
}

/// Individual function export within the export table.
///
/// Represents a single exported function with its ordinal, optional name,
/// and either a function address or forwarder target. Functions can be
/// exported by ordinal only or by both name and ordinal.
///
/// # Export Methods
/// - **By Name**: Uses function name for symbolic resolution
/// - **By Ordinal**: Uses ordinal number for direct address lookup
/// - **Forwarded**: Redirects to function in another DLL
#[derive(Debug, Clone)]
pub struct ExportFunction {
    /// Ordinal number for this export
    pub ordinal: u16,

    /// Function name if exported by name
    pub name: Option<String>,

    /// Function address (RVA) if not forwarded
    pub address: u32,

    /// Whether this export is a forwarder
    pub is_forwarder: bool,
}

/// Export forwarder to another DLL.
///
/// Represents an export that forwards calls to a function in another DLL.
/// The Windows loader resolves forwarders at runtime by loading the target
/// DLL and finding the specified function.
#[derive(Debug, Clone)]
pub struct ExportForwarder {
    /// Ordinal number for this forwarder
    pub ordinal: u16,

    /// Function name if exported by name
    pub name: Option<String>,

    /// Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    pub target: String,
}

impl NativeExports {
    /// Create a new native exports container.
    ///
    /// Initializes an empty container with the specified DLL name and default
    /// export directory settings. The container starts with base ordinal 1.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL (e.g., "MyLibrary.dll")
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// assert!(exports.is_empty());
    /// assert_eq!(exports.dll_name(), "MyLibrary.dll");
    /// assert_eq!(exports.function_count(), 0);
    /// ```
    #[must_use]
    pub fn new(dll_name: &str) -> Self {
        Self {
            directory: ExportDirectory {
                dll_name: dll_name.to_owned(),
                base_ordinal: 1,
                function_count: 0,
                name_count: 0,
                timestamp: 0,
                major_version: 0,
                minor_version: 0,
            },
            functions: HashMap::new(),
            forwarders: HashMap::new(),
            name_to_ordinal: HashMap::new(),
            next_ordinal: 1,
            export_table_base_rva: 0,
        }
    }

    /// Creates native exports from an export directory as read: its header, and each export
    /// with its ordinal, its name and its address or forwarder.
    ///
    /// The directory keeps its name, ordinal base, time stamp and version, every ordinal its
    /// own (base 0 makes ordinal 0 one), and every name of an ordinal with several.
    ///
    /// # Arguments
    /// * `header` - The export directory's own fields
    /// * `pe_exports` - Its exports, an entry per name of each ordinal
    ///
    /// # Errors
    /// When the ordinal base does not fit 16 bits while there are exports, when a name is
    /// exported twice, or when one ordinal is both a function and a forwarder.
    ///
    /// # Examples
    /// ```no_run
    /// use dotscope::{metadata::exports::NativeExports, PeExport, PeExportHeader};
    ///
    /// let header = PeExportHeader {
    ///     name: "MyLibrary.dll".to_string(),
    ///     base: 1,
    ///     timestamp: 0,
    ///     major_version: 0,
    ///     minor_version: 0,
    /// };
    /// let pe_exports = vec![PeExport {
    ///     name: Some("MyFunction".to_string()),
    ///     ordinal: 1,
    ///     rva: 0x1000,
    ///     offset: None,
    ///     forwarder: None,
    /// }];
    ///
    /// let native_exports = NativeExports::from_pe_exports(&header, &pe_exports).unwrap();
    /// assert_eq!(native_exports.dll_name(), "MyLibrary.dll");
    /// ```
    pub fn from_pe_exports(header: &ExportHeader, pe_exports: &[Export]) -> Result<Self> {
        let mut exports = Self::new(&header.name);
        exports.directory.base_ordinal = match u16::try_from(header.base) {
            Ok(base) => base,
            Err(_) if pe_exports.is_empty() => exports.directory.base_ordinal,
            Err(_) => {
                return Err(malformed_error!(
                    "Export ordinal base {} exceeds u16 range",
                    header.base
                ))
            }
        };
        exports.directory.timestamp = header.timestamp;
        exports.directory.major_version = header.major_version;
        exports.directory.minor_version = header.minor_version;

        for export in pe_exports {
            let ordinal = export.ordinal;
            if let Some(target) = &export.forwarder {
                if exports.functions.contains_key(&ordinal) {
                    return Err(malformed_error!(
                        "Ordinal {ordinal} is both a function and a forwarder"
                    ));
                }
                exports
                    .forwarders
                    .entry(ordinal)
                    .or_insert_with(|| ExportForwarder {
                        ordinal,
                        name: export.name.clone(),
                        target: target.clone(),
                    });
            } else {
                if exports.forwarders.contains_key(&ordinal) {
                    return Err(malformed_error!(
                        "Ordinal {ordinal} is both a function and a forwarder"
                    ));
                }
                exports
                    .functions
                    .entry(ordinal)
                    .or_insert_with(|| ExportFunction {
                        ordinal,
                        name: export.name.clone(),
                        address: export.rva,
                        is_forwarder: false,
                    });
            }
            if let Some(name) = &export.name {
                if exports
                    .name_to_ordinal
                    .insert(name.clone(), ordinal)
                    .is_some()
                {
                    return Err(malformed_error!("Function name '{name}' is exported twice"));
                }
            }
            if ordinal >= exports.next_ordinal {
                exports.next_ordinal = ordinal.saturating_add(1);
            }
        }

        exports.directory.function_count = to_u32(
            exports
                .functions
                .len()
                .saturating_add(exports.forwarders.len()),
        )?;
        exports.directory.name_count = to_u32(exports.name_to_ordinal.len())?;
        Ok(exports)
    }

    /// Add a function export with name and ordinal.
    ///
    /// Adds a named function export to the export table with the specified
    /// ordinal and function address. The function will be accessible by both
    /// name and ordinal.
    ///
    /// # Arguments
    /// * `name` - Name of the exported function
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address (RVA)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("MyFunction", 1, 0x1000)?;
    /// exports.add_function("AnotherFunc", 2, 0x2000)?;
    ///
    /// assert_eq!(exports.function_count(), 2);
    /// assert!(exports.has_function("MyFunction"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The function name is empty
    /// - The ordinal is already in use
    /// - The function name is already exported
    /// - The ordinal is 0 (invalid)
    pub fn add_function(&mut self, name: &str, ordinal: u16, address: u32) -> Result<()> {
        if name.is_empty() {
            return Err(malformed_error!("Function name cannot be empty"));
        }

        if ordinal == 0 {
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        // Check for conflicts
        if self.functions.contains_key(&ordinal) || self.forwarders.contains_key(&ordinal) {
            return Err(malformed_error!("Ordinal {ordinal} is already in use"));
        }

        if self.name_to_ordinal.contains_key(name) {
            return Err(malformed_error!(
                "Function name '{name}' is already exported"
            ));
        }

        // Create function export
        let function = ExportFunction {
            ordinal,
            name: Some(name.to_owned()),
            address,
            is_forwarder: false,
        };

        // Update mappings
        self.functions.insert(ordinal, function);
        self.name_to_ordinal.insert(name.to_owned(), ordinal);

        // Update directory metadata
        self.directory.function_count = to_u32(self.functions.len())?;
        self.directory.name_count = to_u32(self.name_to_ordinal.len())?;

        // Update next ordinal
        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Ordinal counter overflow"))?;
        }

        Ok(())
    }

    /// Add a function export by ordinal only.
    ///
    /// Adds a function export that is accessible by ordinal number only,
    /// without a symbolic name. This can be more efficient but is less
    /// portable across DLL versions.
    ///
    /// # Arguments
    /// * `ordinal` - Ordinal number for the export
    /// * `address` - Function address (RVA)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function_by_ordinal(1, 0x1000)?;
    /// exports.add_function_by_ordinal(2, 0x2000)?;
    ///
    /// assert_eq!(exports.function_count(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ordinal is already in use
    /// - The ordinal is 0 (invalid)
    pub fn add_function_by_ordinal(&mut self, ordinal: u16, address: u32) -> Result<()> {
        if ordinal == 0 {
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        // Check for conflicts
        if self.functions.contains_key(&ordinal) || self.forwarders.contains_key(&ordinal) {
            return Err(malformed_error!("Ordinal {ordinal} is already in use"));
        }

        // Create function export
        let function = ExportFunction {
            ordinal,
            name: None,
            address,
            is_forwarder: false,
        };

        // Update mappings
        self.functions.insert(ordinal, function);

        // Update directory metadata
        self.directory.function_count = to_u32(self.functions.len())?;

        // Update next ordinal
        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Ordinal counter overflow"))?;
        }

        Ok(())
    }

    /// Add an export forwarder.
    ///
    /// Adds a function export that forwards calls to a function in another DLL.
    /// The target specification can be either "DllName.FunctionName" or
    /// "DllName.#Ordinal" for ordinal-based forwarding.
    ///
    /// # Arguments
    /// * `name` - Name of the exported function (can be empty for ordinal-only)
    /// * `ordinal` - Ordinal number for the export
    /// * `target` - Target specification: "DllName.FunctionName" or "DllName.#Ordinal"
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    ///
    /// // Forward by name
    /// exports.add_forwarder("ForwardedFunc", 1, "kernel32.dll.GetCurrentProcessId")?;
    ///
    /// // Forward by ordinal
    /// exports.add_forwarder("AnotherForward", 2, "user32.dll.#120")?;
    ///
    /// assert_eq!(exports.forwarder_count(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The ordinal is already in use
    /// - The function name is already exported (if name is provided)
    /// - The target specification is empty
    /// - The ordinal is 0 (invalid)
    pub fn add_forwarder(&mut self, name: &str, ordinal: u16, target: &str) -> Result<()> {
        if ordinal == 0 {
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        if target.is_empty() {
            return Err(malformed_error!("Forwarder target cannot be empty"));
        }

        if !target.contains('.') {
            return Err(malformed_error!(
                "Forwarder target '{}' must be in format 'DllName.FunctionName' or 'DllName.#Ordinal'",
                target
            ));
        }

        if target.contains('\0') {
            return Err(malformed_error!(
                "Forwarder target cannot contain null bytes"
            ));
        }

        if self.functions.contains_key(&ordinal) || self.forwarders.contains_key(&ordinal) {
            return Err(malformed_error!("Ordinal {ordinal} is already in use"));
        }

        if !name.is_empty() && self.name_to_ordinal.contains_key(name) {
            return Err(malformed_error!(
                "Function name '{name}' is already exported"
            ));
        }

        let forwarder = ExportForwarder {
            ordinal,
            name: if name.is_empty() {
                None
            } else {
                Some(name.to_owned())
            },
            target: target.to_owned(),
        };

        self.forwarders.insert(ordinal, forwarder);

        if !name.is_empty() {
            self.name_to_ordinal.insert(name.to_owned(), ordinal);
        }

        self.directory.function_count = to_u32(
            self.functions
                .len()
                .checked_add(self.forwarders.len())
                .ok_or_else(|| malformed_error!("Function/forwarder count overflow"))?,
        )?;
        self.directory.name_count = to_u32(self.name_to_ordinal.len())?;

        if ordinal >= self.next_ordinal {
            self.next_ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Ordinal counter overflow"))?;
        }

        Ok(())
    }

    /// Get the DLL name.
    ///
    /// Returns the name of the DLL that contains these exports.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// assert_eq!(exports.dll_name(), "MyLibrary.dll");
    /// ```
    #[must_use]
    pub fn dll_name(&self) -> &str {
        &self.directory.dll_name
    }

    /// Get the number of function exports.
    ///
    /// Returns the total count of function exports, including both regular
    /// functions and forwarders.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// assert_eq!(exports.function_count(), 0);
    /// ```
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len().saturating_add(self.forwarders.len())
    }

    /// Get the number of forwarder exports.
    ///
    /// Returns the count of export forwarders to other DLLs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// assert_eq!(exports.forwarder_count(), 0);
    /// ```
    #[must_use]
    pub fn forwarder_count(&self) -> usize {
        self.forwarders.len()
    }

    /// Check if the export table is empty.
    ///
    /// Returns `true` if no functions or forwarders have been added.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// assert!(exports.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.functions.is_empty() && self.forwarders.is_empty()
    }

    /// Check if a function is exported.
    ///
    /// Returns `true` if the specified function name is exported.
    ///
    /// # Arguments
    /// * `name` - Name of the function to check
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("MyFunction", 1, 0x1000)?;
    ///
    /// assert!(exports.has_function("MyFunction"));
    /// assert!(!exports.has_function("MissingFunction"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn has_function(&self, name: &str) -> bool {
        self.name_to_ordinal.contains_key(name)
    }

    /// Get a function export by ordinal.
    ///
    /// Returns a reference to the function export with the specified ordinal,
    /// or `None` if no function exists with that ordinal.
    ///
    /// # Arguments
    /// * `ordinal` - Ordinal number to find
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("MyFunction", 1, 0x1000)?;
    ///
    /// let function = exports.get_function_by_ordinal(1);
    /// assert!(function.is_some());
    /// assert_eq!(function.unwrap().ordinal, 1);
    ///
    /// let missing = exports.get_function_by_ordinal(99);
    /// assert!(missing.is_none());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_function_by_ordinal(&self, ordinal: u16) -> Option<&ExportFunction> {
        self.functions.get(&ordinal)
    }

    /// Get a forwarder export by ordinal.
    ///
    /// Returns a reference to the forwarder export with the specified ordinal,
    /// or `None` if no forwarder exists with that ordinal.
    ///
    /// # Arguments
    /// * `ordinal` - Ordinal number to find
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_forwarder("ForwardedFunc", 1, "kernel32.dll.GetCurrentProcessId")?;
    ///
    /// let forwarder = exports.get_forwarder_by_ordinal(1);
    /// assert!(forwarder.is_some());
    /// assert_eq!(forwarder.unwrap().target, "kernel32.dll.GetCurrentProcessId");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_forwarder_by_ordinal(&self, ordinal: u16) -> Option<&ExportForwarder> {
        self.forwarders.get(&ordinal)
    }

    /// Get an ordinal by function name.
    ///
    /// Returns the ordinal number for the specified function name,
    /// or `None` if the function is not exported.
    ///
    /// # Arguments
    /// * `name` - Name of the function to find
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("MyFunction", 5, 0x1000)?;
    ///
    /// let ordinal = exports.get_ordinal_by_name("MyFunction");
    /// assert_eq!(ordinal, Some(5));
    ///
    /// let missing = exports.get_ordinal_by_name("MissingFunction");
    /// assert_eq!(missing, None);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_ordinal_by_name(&self, name: &str) -> Option<u16> {
        self.name_to_ordinal.get(name).copied()
    }

    /// Get all function exports.
    ///
    /// Returns an iterator over all function exports in the table.
    /// The order is not guaranteed to be consistent.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::{NativeExports, ExportFunction};
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("Function1", 1, 0x1000)?;
    /// exports.add_function("Function2", 2, 0x2000)?;
    ///
    /// let functions: Vec<&ExportFunction> = exports.functions().collect();
    /// assert_eq!(functions.len(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn functions(&self) -> impl Iterator<Item = &ExportFunction> {
        self.functions.values()
    }

    /// Get all forwarder exports.
    ///
    /// Returns an iterator over all forwarder exports in the table.
    /// The order is not guaranteed to be consistent.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::exports::NativeExports;
    /// use dotscope::metadata::exports::ExportForwarder;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_forwarder("Forwarder1", 1, "kernel32.dll.Function1")?;
    /// exports.add_forwarder("Forwarder2", 2, "user32.dll.Function2")?;
    ///
    /// let forwarders: Vec<&ExportForwarder> = exports.forwarders().collect();
    /// assert_eq!(forwarders.len(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn forwarders(&self) -> impl Iterator<Item = &ExportForwarder> {
        self.forwarders.values()
    }

    /// Get all exported function names.
    ///
    /// Returns a vector of all function names that are exported.
    /// The order is not guaranteed to be consistent.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("Function1", 1, 0x1000)?;
    /// exports.add_function("Function2", 2, 0x2000)?;
    ///
    /// let names = exports.get_exported_function_names();
    /// assert_eq!(names.len(), 2);
    /// assert!(names.contains(&"Function1".to_string()));
    /// assert!(names.contains(&"Function2".to_string()));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_exported_function_names(&self) -> Vec<String> {
        self.name_to_ordinal.keys().cloned().collect()
    }

    /// Generate export table data for PE writing.
    ///
    /// Creates the complete export table structure including export directory,
    /// Export Address Table (EAT), Export Name Table, Export Ordinal Table,
    /// and name strings. The returned data can be written directly to a PE
    /// file's export section.
    ///
    /// # Returns
    ///
    /// A vector containing the complete export table data in PE format, or an
    /// empty vector if no exports are present.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("MyLibrary.dll");
    /// exports.add_function("MyFunction", 1, 0x1000)?;
    ///
    /// let table_data = exports.get_export_table_data()?;
    /// assert!(!table_data.is_empty());
    /// println!("Export table size: {} bytes", table_data.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Table Layout
    ///
    /// The generated data follows this structure:
    /// 1. Export Directory (40 bytes)
    /// 2. Export Address Table (4 bytes per function)
    /// 3. Export Name Table (4 bytes per named export)
    /// 4. Export Ordinal Table (2 bytes per named export)
    /// 5. DLL name string
    /// 6. Function name strings
    /// 7. Forwarder target strings
    ///
    /// # Errors
    ///
    /// Returns an error if the export table base RVA has not been set or if
    /// data encoding fails during table generation.
    pub fn get_export_table_data(&self) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let base_rva = self.export_table_base_rva;
        if base_rva == 0 {
            return Err(malformed_error!("Export table base RVA not set"));
        }
        self.get_export_table_data_with_base_rva(base_rva)
    }

    /// Generate export table data for PE writing with a specified base RVA.
    ///
    /// This is the same as [`get_export_table_data`](Self::get_export_table_data)
    /// but allows specifying the base RVA for all internal RVA calculations.
    /// This is useful when the export table location is calculated dynamically
    /// during PE file layout.
    ///
    /// # Arguments
    /// * `base_rva` - The RVA where the export table will be placed in the final PE file
    ///
    /// # Returns
    ///
    /// A vector containing the complete export table data in PE format: with no exports,
    /// the directory and the DLL's name, as an image whose export directory lists none
    /// holds them.
    ///
    /// # Errors
    ///
    /// Returns an error if the export table data cannot be serialized due to
    /// invalid ordinal ranges or buffer allocation failures.
    pub fn get_export_table_data_with_base_rva(&self, base_rva: u32) -> Result<Vec<u8>> {
        // Calculate table sizes and offsets
        let export_dir_size = 40u32; // sizeof(IMAGE_EXPORT_DIRECTORY)

        // Calculate the ordinal range we need to cover
        let mut min_ordinal = u16::MAX;
        let mut max_ordinal = 0u16;
        for &ordinal in self.functions.keys().chain(self.forwarders.keys()) {
            if ordinal < min_ordinal {
                min_ordinal = ordinal;
            }
            if ordinal > max_ordinal {
                max_ordinal = ordinal;
            }
        }

        // EAT must cover from base_ordinal to highest ordinal
        let eat_entry_count = if max_ordinal >= self.directory.base_ordinal {
            let span = max_ordinal
                .checked_sub(self.directory.base_ordinal)
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| malformed_error!("EAT entry count overflow"))?;
            u32::from(span)
        } else {
            0
        };

        let eat_size = eat_entry_count
            .checked_mul(4)
            .ok_or_else(|| malformed_error!("EAT size overflow"))?;
        let name_table_size = self
            .directory
            .name_count
            .checked_mul(4)
            .ok_or_else(|| malformed_error!("Name table size overflow"))?;
        let ordinal_table_size = self
            .directory
            .name_count
            .checked_mul(2)
            .ok_or_else(|| malformed_error!("Ordinal table size overflow"))?;

        let eat_rva = base_rva
            .checked_add(export_dir_size)
            .ok_or_else(|| malformed_error!("EAT RVA overflow"))?;
        let name_table_rva = eat_rva
            .checked_add(eat_size)
            .ok_or_else(|| malformed_error!("Name table RVA overflow"))?;
        let ordinal_table_rva = name_table_rva
            .checked_add(name_table_size)
            .ok_or_else(|| malformed_error!("Ordinal table RVA overflow"))?;
        let strings_rva = ordinal_table_rva
            .checked_add(ordinal_table_size)
            .ok_or_else(|| malformed_error!("Strings RVA overflow"))?;

        // Calculate total size needed for strings
        let mut total_strings_size: usize = self
            .directory
            .dll_name
            .len()
            .checked_add(1)
            .ok_or_else(|| malformed_error!("DLL name size overflow"))?;
        for name in self.name_to_ordinal.keys() {
            let name_size = name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Name size overflow"))?;
            total_strings_size = total_strings_size
                .checked_add(name_size)
                .ok_or_else(|| malformed_error!("Strings size overflow"))?;
        }
        for forwarder in self.forwarders.values() {
            let target_size = forwarder
                .target
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Forwarder target size overflow"))?;
            total_strings_size = total_strings_size
                .checked_add(target_size)
                .ok_or_else(|| malformed_error!("Strings size overflow"))?;
        }

        let total_strings_size_u32 = to_u32(total_strings_size)?;
        let total_size = export_dir_size
            .checked_add(eat_size)
            .and_then(|s| s.checked_add(name_table_size))
            .and_then(|s| s.checked_add(ordinal_table_size))
            .and_then(|s| s.checked_add(total_strings_size_u32))
            .ok_or_else(|| malformed_error!("Export table total size overflow"))?;
        let mut data = vec![0u8; total_size as usize];
        let mut offset = 0;

        // Write Export Directory (IMAGE_EXPORT_DIRECTORY structure)
        write_le_at(&mut data, &mut offset, 0u32)?; // Characteristics (reserved)
        write_le_at(&mut data, &mut offset, self.directory.timestamp)?; // TimeDateStamp
        write_le_at(&mut data, &mut offset, self.directory.major_version)?; // MajorVersion
        write_le_at(&mut data, &mut offset, self.directory.minor_version)?; // MinorVersion
        write_le_at(&mut data, &mut offset, strings_rva)?; // Name RVA (DLL name)
        write_le_at(
            &mut data,
            &mut offset,
            u32::from(self.directory.base_ordinal),
        )?; // Base ordinal
        write_le_at(&mut data, &mut offset, eat_entry_count)?; // NumberOfFunctions
        write_le_at(&mut data, &mut offset, self.directory.name_count)?; // NumberOfNames
        write_le_at(&mut data, &mut offset, eat_rva)?; // AddressOfFunctions (EAT RVA)
        write_le_at(&mut data, &mut offset, name_table_rva)?; // AddressOfNames (Export Name Table RVA)
        write_le_at(&mut data, &mut offset, ordinal_table_rva)?; // AddressOfNameOrdinals (Export Ordinal Table RVA)

        // Build sorted lists for consistent output
        let mut named_exports: Vec<(&String, u16)> = self
            .name_to_ordinal
            .iter()
            .map(|(name, &ordinal)| (name, ordinal))
            .collect();
        named_exports.sort_by_key(|(name, _)| name.as_str());
        // Forwarder strings follow the names in ordinal order: the same exports always
        // write the same bytes
        let mut forwarders: Vec<&ExportForwarder> = self.forwarders.values().collect();
        forwarders.sort_by_key(|forwarder| forwarder.ordinal);

        // Calculate string offsets for forwarders
        let mut forwarder_string_offsets = HashMap::new();
        let mut current_forwarder_offset = self
            .directory
            .dll_name
            .len()
            .checked_add(1)
            .ok_or_else(|| malformed_error!("DLL name size overflow"))?; // After DLL name
        for (name, _) in &named_exports {
            let name_size = name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Name size overflow"))?;
            current_forwarder_offset = current_forwarder_offset
                .checked_add(name_size)
                .ok_or_else(|| malformed_error!("Forwarder offset overflow"))?;
        }
        for forwarder in &forwarders {
            forwarder_string_offsets.insert(forwarder.ordinal, current_forwarder_offset);
            let target_size = forwarder
                .target
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Forwarder target size overflow"))?;
            current_forwarder_offset = current_forwarder_offset
                .checked_add(target_size)
                .ok_or_else(|| malformed_error!("Forwarder offset overflow"))?;
        }

        // Write Export Address Table (EAT)
        // Fill with zeros first, then populate known entries
        let eat_start_offset = offset;
        for _ in 0..eat_entry_count {
            write_le_at(&mut data, &mut offset, 0u32)?;
        }

        // Go back and populate known entries
        let mut temp_offset = eat_start_offset;
        for ordinal_index in 0..eat_entry_count {
            let ordinal_index_u16 = u16::try_from(ordinal_index)
                .map_err(|_| malformed_error!("Ordinal index exceeds u16 range"))?;
            let ordinal = self
                .directory
                .base_ordinal
                .checked_add(ordinal_index_u16)
                .ok_or_else(|| malformed_error!("Ordinal computation overflow"))?;

            let temp_end = temp_offset
                .checked_add(4)
                .ok_or_else(|| malformed_error!("EAT entry offset overflow"))?;

            if let Some(function) = self.functions.get(&ordinal) {
                // Regular function - write address
                data.get_mut(temp_offset..temp_end)
                    .ok_or(out_of_bounds_error!())?
                    .copy_from_slice(&function.address.to_le_bytes());
            } else if let Some(_forwarder) = self.forwarders.get(&ordinal) {
                // Forwarder - write RVA to forwarder string
                if let Some(&string_offset) = forwarder_string_offsets.get(&ordinal) {
                    let forwarder_rva = strings_rva
                        .checked_add(to_u32(string_offset)?)
                        .ok_or_else(|| malformed_error!("Forwarder RVA overflow"))?;
                    data.get_mut(temp_offset..temp_end)
                        .ok_or(out_of_bounds_error!())?
                        .copy_from_slice(&forwarder_rva.to_le_bytes());
                }
            }
            // Otherwise leave as 0 (no function at this ordinal)

            temp_offset = temp_end;
        }

        // Write Export Name Table
        let mut name_string_offset = self
            .directory
            .dll_name
            .len()
            .checked_add(1)
            .ok_or_else(|| malformed_error!("DLL name size overflow"))?; // After DLL name
        for (name, _) in &named_exports {
            let name_rva = strings_rva
                .checked_add(to_u32(name_string_offset)?)
                .ok_or_else(|| malformed_error!("Name RVA overflow"))?;
            write_le_at(&mut data, &mut offset, name_rva)?;
            let name_size = name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Name size overflow"))?;
            name_string_offset = name_string_offset
                .checked_add(name_size)
                .ok_or_else(|| malformed_error!("Name offset overflow"))?;
        }

        // Write Export Ordinal Table
        for (_, ordinal) in &named_exports {
            let adjusted_ordinal = ordinal
                .checked_sub(self.directory.base_ordinal)
                .ok_or_else(|| malformed_error!("Ordinal adjustment underflow"))?;
            write_le_at(&mut data, &mut offset, adjusted_ordinal)?;
        }

        // Write strings
        // DLL name
        write_string_at(&mut data, &mut offset, &self.directory.dll_name)?;

        // Function names (in alphabetical order)
        for (name, _ordinal) in &named_exports {
            write_string_at(&mut data, &mut offset, name)?;
        }

        // Forwarder strings
        for forwarder in &forwarders {
            write_string_at(&mut data, &mut offset, &forwarder.target)?;
        }

        Ok(data)
    }

    /// Set the base RVA for the export table.
    ///
    /// Sets the RVA where the export table will be placed in the final PE file.
    /// This is used to calculate proper RVAs for all export table components.
    ///
    /// # Arguments
    /// * `base_rva` - The RVA where the export table will be placed in the final PE file
    pub fn set_export_table_base_rva(&mut self, base_rva: u32) {
        self.export_table_base_rva = base_rva;
    }

    /// Set the DLL name for the export directory.
    ///
    /// Updates the DLL name used in the PE export directory. This is the name
    /// that will appear in the export table when the PE file is written.
    ///
    /// # Arguments
    /// * `dll_name` - New DLL name to use (e.g., "MyLibrary.dll")
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let mut exports = NativeExports::new("OldName.dll");
    /// assert_eq!(exports.dll_name(), "OldName.dll");
    ///
    /// exports.set_dll_name("NewName.dll").unwrap();
    /// assert_eq!(exports.dll_name(), "NewName.dll");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    pub fn set_dll_name(&mut self, dll_name: &str) -> Result<()> {
        if dll_name.is_empty() {
            return Err(malformed_error!("DLL name cannot be empty"));
        }

        if dll_name.contains('\0') {
            return Err(malformed_error!("DLL name cannot contain null bytes"));
        }

        dll_name.clone_into(&mut self.directory.dll_name);
        Ok(())
    }

    /// Get the export directory.
    ///
    /// Returns a reference to the export directory metadata.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::NativeExports;
    ///
    /// let exports = NativeExports::new("MyLibrary.dll");
    /// let directory = exports.directory();
    /// assert_eq!(directory.dll_name, "MyLibrary.dll");
    /// assert_eq!(directory.base_ordinal, 1);
    /// ```
    #[must_use]
    pub fn directory(&self) -> &ExportDirectory {
        &self.directory
    }
}

impl ExportFunction {
    /// Check if this export is a forwarder.
    ///
    /// Returns `true` if this function export forwards calls to another DLL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::exports::ExportFunction;
    ///
    /// let function = ExportFunction {
    ///     ordinal: 1,
    ///     name: Some("MyFunction".to_string()),
    ///     address: 0x1000,
    ///     is_forwarder: false,
    /// };
    ///
    /// assert!(!function.is_forwarder());
    /// ```
    #[must_use]
    pub fn is_forwarder(&self) -> bool {
        self.is_forwarder
    }
}

impl Default for NativeExports {
    fn default() -> Self {
        Self::new("Unknown.dll")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_native_exports_is_empty() {
        let exports = NativeExports::new("Test.dll");
        assert!(exports.is_empty());
        assert_eq!(exports.function_count(), 0);
        assert_eq!(exports.forwarder_count(), 0);
        assert_eq!(exports.dll_name(), "Test.dll");
    }

    #[test]
    fn add_function_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("MyFunction", 1, 0x1000).unwrap();
        assert!(!exports.is_empty());
        assert_eq!(exports.function_count(), 1);
        assert!(exports.has_function("MyFunction"));

        let function = exports.get_function_by_ordinal(1).unwrap();
        assert_eq!(function.name, Some("MyFunction".to_string()));
        assert_eq!(function.address, 0x1000);
        assert!(!function.is_forwarder());
    }

    #[test]
    fn add_function_with_empty_name_fails() {
        let mut exports = NativeExports::new("Test.dll");

        let result = exports.add_function("", 1, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn add_function_with_zero_ordinal_fails() {
        let mut exports = NativeExports::new("Test.dll");

        let result = exports.add_function("MyFunction", 0, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn add_duplicate_function_name_fails() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("MyFunction", 1, 0x1000).unwrap();
        let result = exports.add_function("MyFunction", 2, 0x2000);
        assert!(result.is_err());
    }

    #[test]
    fn add_duplicate_ordinal_fails() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("Function1", 1, 0x1000).unwrap();
        let result = exports.add_function("Function2", 1, 0x2000);
        assert!(result.is_err());
    }

    #[test]
    fn add_function_by_ordinal_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function_by_ordinal(1, 0x1000).unwrap();
        assert_eq!(exports.function_count(), 1);

        let function = exports.get_function_by_ordinal(1).unwrap();
        assert_eq!(function.name, None);
        assert_eq!(function.address, 0x1000);
    }

    #[test]
    fn add_forwarder_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports
            .add_forwarder("ForwardedFunc", 1, "kernel32.dll.GetCurrentProcessId")
            .unwrap();
        assert_eq!(exports.function_count(), 1);
        assert_eq!(exports.forwarder_count(), 1);
        assert!(exports.has_function("ForwardedFunc"));

        let forwarder = exports.get_forwarder_by_ordinal(1).unwrap();
        assert_eq!(forwarder.name, Some("ForwardedFunc".to_string()));
        assert_eq!(forwarder.target, "kernel32.dll.GetCurrentProcessId");
    }

    #[test]
    fn add_forwarder_with_empty_target_fails() {
        let mut exports = NativeExports::new("Test.dll");

        let result = exports.add_forwarder("ForwardedFunc", 1, "");
        assert!(result.is_err());
    }

    #[test]
    fn get_ordinal_by_name_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("Function1", 5, 0x1000).unwrap();
        exports
            .add_forwarder("Function2", 10, "kernel32.dll.SomeFunc")
            .unwrap();

        assert_eq!(exports.get_ordinal_by_name("Function1"), Some(5));
        assert_eq!(exports.get_ordinal_by_name("Function2"), Some(10));
        assert_eq!(exports.get_ordinal_by_name("MissingFunction"), None);
    }

    #[test]
    fn get_exported_function_names_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("Function1", 1, 0x1000).unwrap();
        exports.add_function("Function2", 2, 0x2000).unwrap();
        exports.add_function_by_ordinal(3, 0x3000).unwrap(); // No name

        let names = exports.get_exported_function_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"Function1".to_string()));
        assert!(names.contains(&"Function2".to_string()));
    }

    #[test]
    fn get_export_table_data_empty_returns_empty() {
        let exports = NativeExports::new("Test.dll");
        let data = exports.get_export_table_data().unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn get_export_table_data_without_base_rva_fails() {
        let mut exports = NativeExports::new("Test.dll");
        exports.add_function("MyFunction", 1, 0x1000).unwrap();

        let result = exports.get_export_table_data();
        assert!(result.is_err());
    }

    #[test]
    fn get_export_table_data_with_exports_returns_data() {
        let mut exports = NativeExports::new("Test.dll");
        exports.set_export_table_base_rva(0x3000);

        exports.add_function("MyFunction", 1, 0x1000).unwrap();

        let data = exports.get_export_table_data().unwrap();
        assert!(!data.is_empty());
        assert!(data.len() >= 40); // At least export directory size
    }

    #[test]
    fn function_iteration_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("Function1", 1, 0x1000).unwrap();
        exports.add_function("Function2", 2, 0x2000).unwrap();

        let functions: Vec<&ExportFunction> = exports.functions().collect();
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn forwarder_iteration_works() {
        let mut exports = NativeExports::new("Test.dll");

        exports
            .add_forwarder("Forwarder1", 1, "kernel32.dll.Func1")
            .unwrap();
        exports
            .add_forwarder("Forwarder2", 2, "user32.dll.Func2")
            .unwrap();

        let forwarders: Vec<&ExportForwarder> = exports.forwarders().collect();
        assert_eq!(forwarders.len(), 2);
    }

    #[test]
    fn mixed_functions_and_forwarders() {
        let mut exports = NativeExports::new("Test.dll");

        exports.add_function("RegularFunc", 1, 0x1000).unwrap();
        exports
            .add_forwarder("ForwardedFunc", 2, "kernel32.dll.GetTick")
            .unwrap();
        exports.add_function_by_ordinal(3, 0x3000).unwrap();

        assert_eq!(exports.function_count(), 3); // Total including forwarders
        assert_eq!(exports.forwarders().count(), 1); // Just forwarders
        assert_eq!(exports.functions().count(), 2); // Just regular functions

        let names = exports.get_exported_function_names();
        assert_eq!(names.len(), 2); // Only named exports
    }

    #[test]
    fn set_dll_name_works() {
        let mut exports = NativeExports::new("OldName.dll");
        assert_eq!(exports.dll_name(), "OldName.dll");

        exports.set_dll_name("NewName.dll").unwrap();
        assert_eq!(exports.dll_name(), "NewName.dll");

        // Check that directory is also updated
        assert_eq!(exports.directory().dll_name, "NewName.dll");
    }

    #[test]
    fn set_dll_name_empty_fails() {
        let mut exports = NativeExports::new("Original.dll");
        let result = exports.set_dll_name("");
        assert!(result.is_err());

        // Original name should be unchanged
        assert_eq!(exports.dll_name(), "Original.dll");
    }

    #[test]
    fn set_dll_name_with_null_byte_fails() {
        let mut exports = NativeExports::new("Original.dll");
        let result = exports.set_dll_name("Invalid\0Name.dll");
        assert!(result.is_err());

        // Original name should be unchanged
        assert_eq!(exports.dll_name(), "Original.dll");
    }

    #[test]
    fn add_forwarder_invalid_format_fails() {
        let mut exports = NativeExports::new("Test.dll");

        // Missing dot separator
        let result = exports.add_forwarder("BadForward", 1, "kernel32GetTick");
        assert!(result.is_err());

        // Should have no forwarders
        assert_eq!(exports.forwarder_count(), 0);
    }

    #[test]
    fn add_forwarder_with_null_byte_fails() {
        let mut exports = NativeExports::new("Test.dll");

        let result = exports.add_forwarder("BadForward", 1, "kernel32\0.dll.GetTick");
        assert!(result.is_err());

        // Should have no forwarders
        assert_eq!(exports.forwarder_count(), 0);
    }

    #[test]
    fn add_forwarder_valid_formats() {
        let mut exports = NativeExports::new("Test.dll");

        // Valid format: DllName.FunctionName
        exports
            .add_forwarder("Forward1", 1, "kernel32.dll.GetCurrentProcessId")
            .unwrap();

        // Valid format: DllName.#Ordinal
        exports
            .add_forwarder("Forward2", 2, "user32.dll.#120")
            .unwrap();

        // Valid format: Simple name.function
        exports.add_forwarder("Forward3", 3, "api.Func").unwrap();

        assert_eq!(exports.forwarder_count(), 3);
    }

    /// Forwarder strings are written in ordinal order: the same exports always give the same
    /// table, where they were written in hash order.
    #[test]
    fn forwarder_strings_are_written_in_ordinal_order() {
        let mut exports = NativeExports::new("a.dll");
        for ordinal in [5u16, 3, 9, 1, 7, 2, 8, 4, 6] {
            exports
                .add_forwarder(
                    &format!("F{ordinal}"),
                    ordinal,
                    &format!("t.Target{ordinal}"),
                )
                .unwrap();
        }
        let data = exports.get_export_table_data_with_base_rva(0x1000).unwrap();

        let at = |ordinal: u16| {
            let target = format!("t.Target{ordinal}\0");
            data.windows(target.len())
                .position(|window| window == target.as_bytes())
                .unwrap()
        };
        let offsets: Vec<usize> = (1..=9).map(at).collect();
        assert!(
            offsets.windows(2).all(|pair| pair[0] < pair[1]),
            "{offsets:?}"
        );
    }
}
