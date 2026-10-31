//! Native PE import table support for .NET assemblies.
//!
//! This module provides comprehensive functionality for parsing, analyzing, and generating
//! native PE import tables. It enables dotscope to handle mixed-mode assemblies that contain
//! both managed (.NET) code and native import dependencies from Windows DLLs.
//!
//! # Architecture
//!
//! The native import system implements the PE/COFF import table format with support for:
//!
//! - **Import Descriptors**: Per-DLL import information with lookup table references
//! - **Import Address Table (IAT)**: Runtime-patchable function address storage
//! - **Import Lookup Table (ILT)**: Template for loader processing
//! - **Name Tables**: Function name and hint information for symbol resolution
//!
//! # Key Components
//!
//! - [`NativeImports`] - Main container for PE import table data
//! - [`ImportDescriptor`] - Per-DLL import descriptor with function lists
//! - [`Import`] - Individual function import with name/ordinal information
//! - [`ImportAddressEntry`] - IAT entry with RVA and patching information
//!
//! # Import Table Structure
//!
//! The PE import table follows this layout:
//! ```text
//! Import Directory Table
//! ├── Import Descriptor 1 (DLL A)
//! │   ├── Original First Thunk (ILT RVA)
//! │   ├── First Thunk (IAT RVA)
//! │   └── DLL Name RVA
//! ├── Import Descriptor 2 (DLL B)
//! └── Null Terminator
//!
//! Import Lookup Table (ILT)
//! ├── Function 1 Name RVA/Ordinal
//! ├── Function 2 Name RVA/Ordinal
//! └── Null Terminator
//!
//! Import Address Table (IAT)
//! ├── Function 1 Address (patched by loader)
//! ├── Function 2 Address (patched by loader)
//! └── Null Terminator
//!
//! Name Table
//! ├── Function 1: Hint + Name + Null
//! ├── Function 2: Hint + Name + Null
//! └── DLL Names + Null terminators
//! ```
//!
//! # Usage Examples
//!
//! ## Read an Assembly's Import Table
//!
//! ```no_run
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("application.exe")?;
//! let native_imports = assembly.imports().native();
//!
//! // Analyze DLL dependencies
//! for descriptor in native_imports.descriptors() {
//!     println!("DLL: {}", descriptor.dll_name);
//!     for function in &descriptor.functions {
//!         match &function.name {
//!             Some(name) => println!("  Function: {}", name),
//!             None => println!("  Ordinal: {}", function.ordinal.unwrap()),
//!         }
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Create Import Table
//!
//! ```rust,no_run
//! use dotscope::metadata::imports::NativeImports;
//!
//! # fn main() -> dotscope::Result<()> {
//! let mut imports = NativeImports::new();
//!
//! // Add DLL and functions
//! imports.add_dll("kernel32.dll")?;
//! imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
//! imports.add_function("kernel32.dll", "ExitProcess")?;
//!
//! imports.add_dll("user32.dll")?;
//! imports.add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
//! # Ok(())
//! # }
//! ```
//!
//! # Thread Safety
//!
//! All operations on [`NativeImports`] are thread-safe when accessed through shared references.
//! Mutable operations require exclusive access but can be performed concurrently with
//! immutable operations on different instances.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::imports::UnifiedImportContainer`] - Unified import container combining CIL and native
//! - [`crate::cilassembly::CilAssembly`] - PE writing pipeline for import table generation
//! - [`goblin`] - PE parsing library for import directory analysis

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use crate::{
    file::pe::Import,
    utils::{to_u32, write_le_at, write_string_at},
    Result,
};

/// Container for native PE import table data.
///
/// Manages import descriptors, Import Address Table (IAT) entries, and associated
/// metadata for native DLL dependencies. Provides functionality for parsing existing
/// import tables from PE files and generating new import table data.
///
/// # Storage Strategy
/// - **Import Descriptors**: Per-DLL import information with function lists
/// - **IAT Management**: Address tracking for loader patching
/// - **Name Resolution**: Function name and ordinal mapping
/// - **RVA Tracking**: Relative Virtual Address management for relocations
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::imports::NativeImports;
///
/// # fn main() -> dotscope::Result<()> {
/// let mut imports = NativeImports::new();
///
/// // Add a DLL dependency
/// imports.add_dll("kernel32.dll")?;
/// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
///
/// println!("DLL count: {}", imports.dll_count());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct NativeImports {
    /// Import descriptors indexed by DLL name for fast lookup
    descriptors: HashMap<String, Dll>,

    /// Next available RVA for IAT allocation
    next_iat_rva: u32,

    /// Whether this is a PE32+ (64-bit) image.
    /// Affects IAT entry size: 4 bytes for PE32, 8 bytes for PE32+.
    is_pe32_plus: bool,
}

/// Import descriptor for a single DLL.
///
/// Contains all import information for functions from a specific DLL, including
/// Import Lookup Table (ILT) and Import Address Table (IAT) references.
///
/// # PE Format Mapping
/// This structure directly corresponds to the PE IMAGE_IMPORT_DESCRIPTOR:
/// - `original_first_thunk`: RVA of Import Lookup Table (ILT)
/// - `first_thunk`: RVA of Import Address Table (IAT)
/// - `dll_name`: Name of the DLL containing the imported functions
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// Name of the DLL (e.g., "kernel32.dll"), the string its functions share
    pub dll_name: Arc<str>,

    /// RVA of Import Lookup Table (ILT) - template for IAT
    pub original_first_thunk: u32,

    /// RVA of Import Address Table (IAT) - patched by loader
    pub first_thunk: u32,

    /// Functions imported from this DLL  
    pub functions: Vec<Import>,

    /// Timestamp for bound imports (usually 0)
    pub timestamp: u32,

    /// Forwarder chain for bound imports (usually 0)
    pub forwarder_chain: u32,
}

/// A DLL's descriptor, with the names and ordinals it imports: a function imported twice is
/// found without scanning the descriptor's functions.
#[derive(Debug, Clone)]
struct Dll {
    descriptor: ImportDescriptor,
    names: HashSet<String>,
    ordinals: HashSet<u16>,
}

impl Dll {
    fn new(dll_name: Arc<str>) -> Self {
        Dll {
            descriptor: ImportDescriptor {
                dll_name,
                original_first_thunk: 0, // Will be set during table generation
                first_thunk: 0,          // Will be set during table generation
                functions: Vec::new(),
                timestamp: 0,
                forwarder_chain: 0,
            },
            names: HashSet::new(),
            ordinals: HashSet::new(),
        }
    }

    /// Adds `function`, with its name or ordinal, to the descriptor.
    fn push(&mut self, function: Import) {
        if let Some(name) = &function.name {
            self.names.insert(name.clone());
        }
        if let Some(ordinal) = function.ordinal {
            self.ordinals.insert(ordinal);
        }
        self.descriptor.functions.push(function);
    }
}

/// Entry in the Import Address Table (IAT).
///
/// Represents a single IAT slot that gets patched by the Windows loader with
/// the actual function address at runtime. Essential for RVA tracking and
/// relocation processing.
#[derive(Debug, Clone)]
pub struct ImportAddressEntry {
    /// RVA of this IAT entry
    pub rva: u32,

    /// DLL containing the imported function
    pub dll_name: String,

    /// Function name or ordinal identifier
    pub function_identifier: String,

    /// Original ILT value before loader patching
    pub original_value: u64,
}

impl NativeImports {
    /// Create a new empty native imports container.
    ///
    /// Initializes an empty container ready for import descriptor creation.
    /// The container starts with default RVA allocation starting at 0x1000.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert!(imports.is_empty());
    /// assert_eq!(imports.dll_count(), 0);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: HashMap::new(),
            next_iat_rva: 0x1000, // Default IAT base address
            is_pe32_plus: false,  // Default to PE32 (32-bit)
        }
    }

    /// Sets whether this is a PE32+ (64-bit) image.
    ///
    /// This affects the IAT entry size:
    /// - PE32 (32-bit): 4 bytes per entry
    /// - PE32+ (64-bit): 8 bytes per entry
    ///
    /// # Arguments
    /// * `is_pe32_plus` - `true` for 64-bit PE32+, `false` for 32-bit PE32
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.set_pe_format(true); // Configure for 64-bit
    /// assert!(imports.is_pe32_plus());
    /// ```
    pub fn set_pe_format(&mut self, is_pe32_plus: bool) {
        self.is_pe32_plus = is_pe32_plus;
    }

    /// Returns whether this is configured for PE32+ (64-bit) format.
    ///
    /// # Returns
    /// `true` if configured for PE32+ (64-bit), `false` for PE32 (32-bit).
    #[must_use]
    pub fn is_pe32_plus(&self) -> bool {
        self.is_pe32_plus
    }

    /// Returns the IAT entry size in bytes based on the PE format.
    ///
    /// # Returns
    /// - 4 bytes for PE32 (32-bit)
    /// - 8 bytes for PE32+ (64-bit)
    #[must_use]
    pub fn iat_entry_size(&self) -> u32 {
        if self.is_pe32_plus {
            8
        } else {
            4
        }
    }

    /// Creates native imports directly from PE import data.
    ///
    /// # Arguments
    /// * `pe_imports` - Slice of PE import entries to process
    /// * `is_pe32_plus` - `true` for PE32+ (64-bit), `false` for PE32 (32-bit)
    ///
    /// # Returns
    /// Returns a configured NativeImports instance with all import descriptors,
    /// IAT entries, and internal structures properly initialized.
    ///
    /// # Errors
    /// Returns error if:
    /// - Memory allocation fails during structure creation
    /// - Import data contains invalid or inconsistent information
    ///
    /// # Examples
    /// ```no_run
    /// use dotscope::metadata::imports::NativeImports;
    /// use dotscope::PeImport;
    ///
    /// let pe_imports = vec![PeImport {
    ///     dll: "kernel32.dll".into(),
    ///     name: Some("GetCurrentProcessId".to_string()),
    ///     ordinal: None,
    ///     rva: 0x2000,
    ///     hint: 0,
    ///     ilt_value: 0,
    /// }];
    ///
    /// // For 32-bit PE files
    /// let native_imports = NativeImports::from_pe_imports(&pe_imports, false)?;
    /// assert_eq!(native_imports.dll_count(), 1);
    ///
    /// // For 64-bit PE files
    /// let native_imports_64 = NativeImports::from_pe_imports(&pe_imports, true)?;
    /// assert!(native_imports_64.is_pe32_plus());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn from_pe_imports(pe_imports: &[Import], is_pe32_plus: bool) -> Result<Self> {
        let mut native = Self::new();
        native.is_pe32_plus = is_pe32_plus;

        let mut imports_by_dll: HashMap<&str, Vec<&Import>> = HashMap::new();
        for import in pe_imports {
            imports_by_dll.entry(&import.dll).or_default().push(import);
        }

        for (dll_name, dll_imports) in imports_by_dll {
            let mut dll = Dll::new(Arc::from(dll_name));
            dll.descriptor.functions.reserve(dll_imports.len());
            for pe_import in dll_imports {
                dll.push(Import {
                    dll: Arc::clone(&dll.descriptor.dll_name),
                    ..pe_import.clone()
                });
            }
            native.descriptors.insert(dll_name.to_owned(), dll);
        }

        Ok(native)
    }

    /// Add a DLL to the import table.
    ///
    /// Creates a new import descriptor for the specified DLL if it doesn't already exist.
    /// Multiple calls with the same DLL name will reuse the existing descriptor.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL (e.g., "kernel32.dll", "user32.dll")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// assert_eq!(imports.dll_count(), 2);
    /// assert!(imports.has_dll("kernel32.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the DLL name is empty or contains invalid characters.
    pub fn add_dll(&mut self, dll_name: &str) -> Result<()> {
        if dll_name.is_empty() {
            return Err(malformed_error!("DLL name cannot be empty"));
        }

        if !self.descriptors.contains_key(dll_name) {
            self.descriptors
                .insert(dll_name.to_owned(), Dll::new(Arc::from(dll_name)));
        }

        Ok(())
    }

    /// Add a function import from a specific DLL.
    ///
    /// Adds a named function import to the specified DLL's import descriptor.
    /// The DLL must be added first using [`add_dll`](Self::add_dll).
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL containing the function
    /// * `function_name` - Name of the function to import
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
    /// imports.add_function("kernel32.dll", "ExitProcess")?;
    ///
    /// let descriptor = imports.get_descriptor("kernel32.dll").unwrap();
    /// assert_eq!(descriptor.functions.len(), 2);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL has not been added to the import table
    /// - The function name is empty
    /// - The function is already imported from this DLL
    ///
    /// # Panics
    ///
    /// Panics if the DLL has not been added to the import table first.
    /// Use [`Self::add_dll`] before calling this method.
    pub fn add_function(&mut self, dll_name: &str, function_name: &str) -> Result<()> {
        if function_name.is_empty() {
            return Err(malformed_error!("Function name cannot be empty"));
        }

        match self.descriptors.get(dll_name) {
            Some(dll) if dll.names.contains(function_name) => {
                return Err(malformed_error!(
                    "Function '{function_name}' already imported from '{dll_name}'"
                ));
            }
            Some(_) => {}
            None => {
                return Err(malformed_error!(
                    "DLL '{dll_name}' not found in import table"
                ))
            }
        }

        let iat_rva = self.allocate_iat_rva()?;
        let dll = self
            .descriptors
            .get_mut(dll_name)
            .ok_or_else(|| malformed_error!("DLL '{dll_name}' disappeared from import table"))?;
        dll.push(Import {
            dll: Arc::clone(&dll.descriptor.dll_name),
            name: Some(function_name.to_owned()),
            ordinal: None,
            rva: iat_rva,
            hint: 0,
            ilt_value: 0,
        });

        Ok(())
    }

    /// Add an ordinal-based function import.
    ///
    /// Adds a function import that uses ordinal-based lookup instead of name-based.
    /// This can be more efficient but is less portable across DLL versions.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL containing the function
    /// * `ordinal` - Ordinal number of the function in the DLL's export table
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("user32.dll")?;
    /// imports.add_function_by_ordinal("user32.dll", 120)?; // MessageBoxW
    ///
    /// let descriptor = imports.get_descriptor("user32.dll").unwrap();
    /// assert_eq!(descriptor.functions[0].ordinal, Some(120));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The DLL has not been added to the import table
    /// - The ordinal is 0 (invalid)
    /// - A function with the same ordinal is already imported
    ///
    /// # Panics
    ///
    /// Panics if the DLL has not been added to the import table first.
    /// Use [`Self::add_dll`] before calling this method.
    pub fn add_function_by_ordinal(&mut self, dll_name: &str, ordinal: u16) -> Result<()> {
        if ordinal == 0 {
            return Err(malformed_error!("Ordinal cannot be 0"));
        }

        match self.descriptors.get(dll_name) {
            Some(dll) if dll.ordinals.contains(&ordinal) => {
                return Err(malformed_error!(
                    "Ordinal {ordinal} already imported from '{dll_name}'"
                ));
            }
            Some(_) => {}
            None => {
                return Err(malformed_error!(
                    "DLL '{dll_name}' not found in import table"
                ))
            }
        }

        let iat_rva = self.allocate_iat_rva()?;
        let dll = self
            .descriptors
            .get_mut(dll_name)
            .ok_or_else(|| malformed_error!("DLL '{dll_name}' disappeared from import table"))?;
        dll.push(Import {
            dll: Arc::clone(&dll.descriptor.dll_name),
            name: None,
            ordinal: Some(ordinal),
            rva: iat_rva,
            hint: 0,
            ilt_value: 0x8000_0000_0000_0000u64 | u64::from(ordinal),
        });

        Ok(())
    }

    /// Get an import descriptor by DLL name.
    ///
    /// Returns a reference to the import descriptor for the specified DLL,
    /// or `None` if the DLL is not in the import table.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to find
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    ///
    /// let descriptor = imports.get_descriptor("kernel32.dll");
    /// assert!(descriptor.is_some());
    /// assert_eq!(descriptor.unwrap().dll_name, "kernel32.dll");
    ///
    /// let missing = imports.get_descriptor("missing.dll");
    /// assert!(missing.is_none());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_descriptor(&self, dll_name: &str) -> Option<&ImportDescriptor> {
        self.descriptors.get(dll_name).map(|dll| &dll.descriptor)
    }

    /// Get all import descriptors.
    ///
    /// Returns an iterator over all import descriptors in the container.
    /// The order is not guaranteed to be consistent across calls.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// let dll_names: Vec<&str> = imports.descriptors()
    ///     .map(|desc| desc.dll_name.as_str())
    ///     .collect();
    ///
    /// assert_eq!(dll_names.len(), 2);
    /// assert!(dll_names.contains(&"kernel32.dll"));
    /// assert!(dll_names.contains(&"user32.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn descriptors(&self) -> impl Iterator<Item = &ImportDescriptor> {
        self.descriptors.values().map(|dll| &dll.descriptor)
    }

    /// Check if a DLL is in the import table.
    ///
    /// Returns `true` if the specified DLL has been added to the import table.
    ///
    /// # Arguments
    /// * `dll_name` - Name of the DLL to check
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    ///
    /// assert!(imports.has_dll("kernel32.dll"));
    /// assert!(!imports.has_dll("missing.dll"));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn has_dll(&self, dll_name: &str) -> bool {
        self.descriptors.contains_key(dll_name)
    }

    /// Get the number of DLLs in the import table.
    ///
    /// Returns the count of unique DLLs that have import descriptors.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert_eq!(imports.dll_count(), 0);
    /// ```
    #[must_use]
    pub fn dll_count(&self) -> usize {
        self.descriptors.len()
    }

    /// Get the total count of all imported functions across all DLLs.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// println!("Total imported functions: {}", imports.total_function_count());
    /// ```
    #[must_use]
    pub fn total_function_count(&self) -> usize {
        self.descriptors
            .values()
            .map(|dll| dll.descriptor.functions.len())
            .sum()
    }

    /// Check if the import table is empty.
    ///
    /// Returns `true` if no DLLs have been added to the import table.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let imports = NativeImports::new();
    /// assert!(imports.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.descriptors.is_empty()
    }

    /// Get all DLL names in the import table.
    ///
    /// Returns a vector of all DLL names that have import descriptors.
    /// The order is not guaranteed to be consistent.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_dll("user32.dll")?;
    ///
    /// let dll_names = imports.get_dll_names();
    /// assert_eq!(dll_names.len(), 2);
    /// assert!(dll_names.contains(&"kernel32.dll".to_string()));
    /// assert!(dll_names.contains(&"user32.dll".to_string()));
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_dll_names(&self) -> Vec<String> {
        self.descriptors.keys().cloned().collect()
    }

    /// Update Import Address Table RVAs after section moves.
    ///
    /// Adjusts all IAT RVAs by the specified delta when sections are moved
    /// during PE layout changes. Essential for maintaining valid references
    /// after assembly modifications.
    ///
    /// # Arguments
    /// * `rva_delta` - The signed offset to apply to all RVAs
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::NativeImports;
    ///
    /// let mut imports = NativeImports::new();
    /// imports.add_dll("kernel32.dll")?;
    /// imports.add_function("kernel32.dll", "GetCurrentProcessId")?;
    ///
    /// // Section moved up by 0x1000 bytes
    /// imports.update_iat_rvas(0x1000)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the RVA delta would cause integer overflow or
    /// result in invalid RVA values.
    pub fn update_iat_rvas(&mut self, rva_delta: i64) -> Result<()> {
        for dll in self.descriptors.values_mut() {
            for function in &mut dll.descriptor.functions {
                function.rva = adjust_rva(function.rva, rva_delta)?;
            }
        }

        self.next_iat_rva = adjust_rva(self.next_iat_rva, rva_delta)?;

        Ok(())
    }

    /// Allocate a new IAT RVA.
    ///
    /// Returns the next available RVA for IAT allocation and increments
    /// the internal counter by the appropriate entry size (4 bytes for PE32,
    /// 8 bytes for PE32+). Used internally when adding new function imports.
    ///
    /// # Errors
    /// Returns an error if the IAT RVA counter would overflow.
    fn allocate_iat_rva(&mut self) -> Result<u32> {
        let rva = self.next_iat_rva;
        self.next_iat_rva = self
            .next_iat_rva
            .checked_add(self.iat_entry_size())
            .ok_or_else(|| malformed_error!("IAT RVA counter overflow"))?;
        Ok(rva)
    }

    /// Calculate the total size of the Import Address Table (IAT) in bytes.
    ///
    /// For .NET PE files, the IAT is placed at the start of the .text section.
    /// Each DLL's imports require (function_count + 1) entries for the null terminator.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    ///
    /// # Returns
    /// Total IAT size in bytes.
    ///
    /// # Errors
    /// Returns an error if the computed size would overflow `usize`.
    pub fn iat_byte_size(&self, is_pe32_plus: bool) -> Result<usize> {
        let entry_size: usize = if is_pe32_plus { 8 } else { 4 };
        let mut total_entries: usize = 0;

        for descriptor in self.descriptors() {
            // Each DLL needs: function entries + 1 null terminator
            let dll_entries = descriptor
                .functions
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("IAT entry count overflow"))?;
            total_entries = total_entries
                .checked_add(dll_entries)
                .ok_or_else(|| malformed_error!("IAT entry count overflow"))?;
        }

        total_entries
            .checked_mul(entry_size)
            .ok_or_else(|| malformed_error!("IAT byte size overflow"))
    }

    /// Build the IAT (Import Address Table) bytes for .NET PE generation.
    ///
    /// Generates the IAT content that should be written at the start of the .text section.
    /// Each entry contains an RVA pointing to the hint/name table entry for that function.
    /// The RVAs are calculated based on the provided `import_table_rva` parameter which
    /// indicates where the import table (containing the strings) will be located.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    /// * `import_table_rva` - RVA where the import table will be written (used to calculate string RVAs)
    ///
    /// # Returns
    /// IAT bytes to write at the start of .text section.
    ///
    /// # Errors
    /// Returns an error if writing IAT entries exceeds the allocated buffer bounds.
    pub fn build_iat_bytes(&self, is_pe32_plus: bool, import_table_rva: u32) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let entry_size: usize = if is_pe32_plus { 8 } else { 4 };
        let mut iat_bytes = Vec::with_capacity(self.iat_byte_size(is_pe32_plus)?);

        // Sort descriptors for deterministic ordering (mscoree.dll should be first when building import list)
        let mut descriptors_sorted: Vec<_> = self.descriptors().collect();
        descriptors_sorted.sort_by_key(|d| d.dll_name.to_lowercase());

        // Calculate where strings will be in the import table
        // Layout: descriptors + null descriptor + ILT entries + strings
        let descriptor_count_with_null = self
            .descriptors
            .len()
            .checked_add(1)
            .ok_or_else(|| malformed_error!("Descriptor count overflow"))?;
        let descriptor_size = descriptor_count_with_null
            .checked_mul(20)
            .ok_or_else(|| malformed_error!("Descriptor table size overflow"))?;

        let mut total_ilt_entries: usize = 0;
        for desc in &descriptors_sorted {
            let dll_entries = desc
                .functions
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("ILT entry count overflow"))?;
            total_ilt_entries = total_ilt_entries
                .checked_add(dll_entries)
                .ok_or_else(|| malformed_error!("ILT entry count overflow"))?;
        }
        let ilt_size = total_ilt_entries
            .checked_mul(entry_size)
            .ok_or_else(|| malformed_error!("ILT byte size overflow"))?;

        // Strings start after descriptors and ILT
        let header_size = descriptor_size
            .checked_add(ilt_size)
            .ok_or_else(|| malformed_error!("Import table header size overflow"))?;
        let strings_start_rva = import_table_rva
            .checked_add(to_u32(header_size)?)
            .ok_or_else(|| malformed_error!("Strings start RVA overflow"))?;

        // Calculate hint/name RVAs for each function
        let mut current_string_rva = strings_start_rva;

        // First pass: calculate DLL name RVAs (they come first in strings)
        let mut dll_name_end_rva = current_string_rva;
        for desc in &descriptors_sorted {
            let dll_name_size = desc
                .dll_name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("DLL name size overflow"))?;
            dll_name_end_rva = dll_name_end_rva
                .checked_add(to_u32(dll_name_size)?)
                .ok_or_else(|| malformed_error!("DLL name RVA overflow"))?;
        }

        // Function hint/names come after DLL names
        current_string_rva = dll_name_end_rva;

        // Build IAT entries for each DLL
        for descriptor in &descriptors_sorted {
            for function in &descriptor.functions {
                let thunk_value = if let Some(ordinal) = function.ordinal {
                    // Ordinal import: high bit set + ordinal
                    if function.name.is_none() {
                        if is_pe32_plus {
                            0x8000_0000_0000_0000u64 | u64::from(ordinal)
                        } else {
                            0x8000_0000u64 | u64::from(ordinal)
                        }
                    } else {
                        // Named import with hint
                        u64::from(current_string_rva)
                    }
                } else {
                    // Named import
                    u64::from(current_string_rva)
                };

                // Write IAT entry
                if is_pe32_plus {
                    iat_bytes.extend_from_slice(&thunk_value.to_le_bytes());
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    iat_bytes.extend_from_slice(&(thunk_value as u32).to_le_bytes());
                }

                // Advance string RVA for named imports
                if let Some(function_name) = function.name.as_ref() {
                    // hint (2 bytes) + name + null
                    let name_size = function_name
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| malformed_error!("Function name size overflow"))?;
                    let advance = name_size
                        .checked_add(2)
                        .ok_or_else(|| malformed_error!("Hint/name advance overflow"))?;
                    current_string_rva = current_string_rva
                        .checked_add(to_u32(advance)?)
                        .ok_or_else(|| malformed_error!("String RVA overflow"))?;
                }
            }

            // Null terminator for this DLL's IAT
            if is_pe32_plus {
                iat_bytes.extend_from_slice(&0u64.to_le_bytes());
            } else {
                iat_bytes.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        Ok(iat_bytes)
    }

    /// Build the import table data (descriptors + ILT + strings) for .NET PE generation.
    ///
    /// Generates import table data where FirstThunk fields point to the external IAT
    /// at `iat_rva` (typically at the start of .text section). This method does NOT
    /// generate an embedded IAT - only descriptors, ILT, and strings.
    ///
    /// # Arguments
    /// * `is_pe32_plus` - Whether this is PE32+ (64-bit) or PE32 (32-bit) format
    /// * `iat_rva` - RVA where the IAT is located (start of .text section)
    /// * `table_rva` - RVA where this import table will be written
    ///
    /// # Returns
    /// Import table bytes (descriptors + ILT + strings) to write after metadata.
    ///
    /// # Errors
    /// Returns an error if writing import descriptors, ILT entries, or string data
    /// exceeds the allocated buffer bounds.
    pub fn build_import_table(
        &self,
        is_pe32_plus: bool,
        iat_rva: u32,
        table_rva: u32,
    ) -> Result<Vec<u8>> {
        if self.is_empty() {
            return Ok(Vec::new());
        }

        let entry_size: usize = if is_pe32_plus { 8 } else { 4 };

        // Sort descriptors for deterministic ordering
        let mut descriptors_sorted: Vec<_> = self.descriptors().collect();
        descriptors_sorted.sort_by_key(|d| d.dll_name.to_lowercase());

        // Calculate layout sizes
        let descriptor_count_with_null = descriptors_sorted
            .len()
            .checked_add(1)
            .ok_or_else(|| malformed_error!("Descriptor count overflow"))?;
        let descriptor_table_size = descriptor_count_with_null
            .checked_mul(20)
            .ok_or_else(|| malformed_error!("Descriptor table size overflow"))?;

        // Calculate total ILT size
        let mut total_ilt_entries: usize = 0;
        for desc in &descriptors_sorted {
            let dll_entries = desc
                .functions
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("ILT entry count overflow"))?;
            total_ilt_entries = total_ilt_entries
                .checked_add(dll_entries)
                .ok_or_else(|| malformed_error!("ILT entry count overflow"))?;
        }
        let ilt_size = total_ilt_entries
            .checked_mul(entry_size)
            .ok_or_else(|| malformed_error!("ILT byte size overflow"))?;

        // Calculate total string size
        let mut total_string_size: usize = 0;
        for desc in &descriptors_sorted {
            // DLL name + null
            let dll_size = desc
                .dll_name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("DLL name size overflow"))?;
            total_string_size = total_string_size
                .checked_add(dll_size)
                .ok_or_else(|| malformed_error!("String table size overflow"))?;
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    // hint + name + null
                    let name_size = name
                        .len()
                        .checked_add(3)
                        .ok_or_else(|| malformed_error!("Function name size overflow"))?;
                    total_string_size = total_string_size
                        .checked_add(name_size)
                        .ok_or_else(|| malformed_error!("String table size overflow"))?;
                }
            }
        }

        // Allocate buffer (+16 for alignment padding)
        let total_size = descriptor_table_size
            .checked_add(ilt_size)
            .and_then(|s| s.checked_add(total_string_size))
            .and_then(|s| s.checked_add(16))
            .ok_or_else(|| malformed_error!("Import table total size overflow"))?;
        let mut data = vec![0u8; total_size];
        let mut offset = 0;

        // Calculate RVAs
        let ilt_start_rva = table_rva
            .checked_add(to_u32(descriptor_table_size)?)
            .ok_or_else(|| malformed_error!("ILT start RVA overflow"))?;
        let strings_start_rva = ilt_start_rva
            .checked_add(to_u32(ilt_size)?)
            .ok_or_else(|| malformed_error!("Strings start RVA overflow"))?;

        // Build ILT offset map and string RVAs
        let mut ilt_rva = ilt_start_rva;
        let mut iat_offset: u32 = 0; // Offset within IAT for each DLL

        // Pre-calculate DLL name RVAs
        let mut dll_name_rvas = Vec::with_capacity(descriptors_sorted.len());
        let mut current_dll_name_rva = strings_start_rva;
        for desc in &descriptors_sorted {
            dll_name_rvas.push(current_dll_name_rva);
            let dll_size = desc
                .dll_name
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("DLL name size overflow"))?;
            current_dll_name_rva = current_dll_name_rva
                .checked_add(to_u32(dll_size)?)
                .ok_or_else(|| malformed_error!("DLL name RVA overflow"))?;
        }

        // Pre-calculate function name RVAs
        let mut current_func_name_rva = current_dll_name_rva;
        let mut func_name_rvas: Vec<Vec<u64>> = Vec::with_capacity(descriptors_sorted.len());

        for desc in &descriptors_sorted {
            let mut rvas = Vec::with_capacity(desc.functions.len());
            for func in &desc.functions {
                if let Some(function_name) = func.name.as_ref() {
                    rvas.push(u64::from(current_func_name_rva));
                    // hint (2 bytes) + name + null
                    let name_size = function_name
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| malformed_error!("Function name size overflow"))?;
                    let advance = name_size
                        .checked_add(2)
                        .ok_or_else(|| malformed_error!("Hint/name advance overflow"))?;
                    current_func_name_rva = current_func_name_rva
                        .checked_add(to_u32(advance)?)
                        .ok_or_else(|| malformed_error!("Function name RVA overflow"))?;
                } else {
                    rvas.push(0); // Will use ordinal
                }
            }
            func_name_rvas.push(rvas);
        }

        // Write import descriptors
        for (i, desc) in descriptors_sorted.iter().enumerate() {
            let desc_ilt_rva = ilt_rva;
            let desc_iat_rva = iat_rva
                .checked_add(iat_offset)
                .ok_or_else(|| malformed_error!("IAT RVA overflow"))?;

            let dll_name_rva = *dll_name_rvas.get(i).ok_or(out_of_bounds_error!())?;

            // OriginalFirstThunk (ILT RVA)
            write_le_at::<u32>(&mut data, &mut offset, desc_ilt_rva)?;
            // TimeDateStamp
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
            // ForwarderChain
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
            // Name (DLL name RVA)
            write_le_at::<u32>(&mut data, &mut offset, dll_name_rva)?;
            // FirstThunk (IAT RVA - points to external IAT)
            write_le_at::<u32>(&mut data, &mut offset, desc_iat_rva)?;

            // Update offsets for next descriptor (+1 for null terminator)
            let entries_for_dll = desc
                .functions
                .len()
                .checked_add(1)
                .ok_or_else(|| malformed_error!("ILT entry count overflow"))?;
            let dll_size = entries_for_dll
                .checked_mul(entry_size)
                .ok_or_else(|| malformed_error!("ILT DLL size overflow"))?;
            let dll_size_u32 = to_u32(dll_size)?;
            ilt_rva = ilt_rva
                .checked_add(dll_size_u32)
                .ok_or_else(|| malformed_error!("ILT RVA overflow"))?;
            iat_offset = iat_offset
                .checked_add(dll_size_u32)
                .ok_or_else(|| malformed_error!("IAT offset overflow"))?;
        }

        // Write null terminator descriptor
        for _ in 0..5 {
            write_le_at::<u32>(&mut data, &mut offset, 0)?;
        }

        // Write ILT entries
        for (i, desc) in descriptors_sorted.iter().enumerate() {
            let dll_func_rvas = func_name_rvas.get(i).ok_or(out_of_bounds_error!())?;
            for (j, func) in desc.functions.iter().enumerate() {
                let ilt_value = if func.name.is_none() {
                    // Ordinal import
                    if let Some(ordinal) = func.ordinal {
                        if is_pe32_plus {
                            0x8000_0000_0000_0000u64 | u64::from(ordinal)
                        } else {
                            0x8000_0000u64 | u64::from(ordinal)
                        }
                    } else {
                        0
                    }
                } else {
                    // Named import - use pre-calculated RVA
                    *dll_func_rvas.get(j).ok_or(out_of_bounds_error!())?
                };

                if is_pe32_plus {
                    write_le_at::<u64>(&mut data, &mut offset, ilt_value)?;
                } else {
                    #[allow(clippy::cast_possible_truncation)]
                    write_le_at::<u32>(&mut data, &mut offset, ilt_value as u32)?;
                }
            }

            // Null terminator for this DLL's ILT
            if is_pe32_plus {
                write_le_at::<u64>(&mut data, &mut offset, 0)?;
            } else {
                write_le_at::<u32>(&mut data, &mut offset, 0)?;
            }
        }

        // Write strings: DLL names first, then function names
        for desc in &descriptors_sorted {
            write_string_at(&mut data, &mut offset, &desc.dll_name)?;
        }

        for desc in &descriptors_sorted {
            for func in &desc.functions {
                if let Some(ref name) = func.name {
                    // Write hint (2 bytes)
                    write_le_at::<u16>(&mut data, &mut offset, func.hint)?;
                    // Write function name
                    write_string_at(&mut data, &mut offset, name)?;
                }
            }
        }

        // Align to 4 bytes
        while offset % 4 != 0 {
            if let Some(slot) = data.get_mut(offset) {
                *slot = 0;
            }
            offset = offset
                .checked_add(1)
                .ok_or_else(|| malformed_error!("Alignment offset overflow"))?;
        }

        // Truncate to actual size
        data.truncate(offset);

        Ok(data)
    }
}

impl Default for NativeImports {
    fn default() -> Self {
        Self::new()
    }
}

/// Apply a signed delta to a u32 RVA, returning an error on overflow.
fn adjust_rva(rva: u32, delta: i64) -> Result<u32> {
    if delta >= 0 {
        let abs_delta =
            u32::try_from(delta).map_err(|_| malformed_error!("RVA delta exceeds u32 range"))?;
        rva.checked_add(abs_delta)
            .ok_or_else(|| malformed_error!("RVA delta would cause overflow"))
    } else {
        // Negate without overflow even when delta == i64::MIN
        let abs_delta_i64 = delta
            .checked_neg()
            .ok_or_else(|| malformed_error!("RVA delta magnitude overflow"))?;
        let abs_delta = u32::try_from(abs_delta_i64)
            .map_err(|_| malformed_error!("RVA delta exceeds u32 range"))?;
        rva.checked_sub(abs_delta)
            .ok_or_else(|| malformed_error!("RVA delta would cause overflow"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_native_imports_is_empty() {
        let imports = NativeImports::new();
        assert!(imports.is_empty());
        assert_eq!(imports.dll_count(), 0);
    }

    #[test]
    fn add_dll_works() {
        let mut imports = NativeImports::new();

        imports.add_dll("kernel32.dll").unwrap();
        assert!(!imports.is_empty());
        assert_eq!(imports.dll_count(), 1);
        assert!(imports.has_dll("kernel32.dll"));

        // Adding same DLL again should not increase count
        imports.add_dll("kernel32.dll").unwrap();
        assert_eq!(imports.dll_count(), 1);
    }

    /// A function the read table imports is found without scanning: adding it again is
    /// refused, by name and by ordinal, as for one added through the builder.
    #[test]
    fn a_read_import_is_not_imported_twice() {
        let read = |name: Option<&str>, ordinal: Option<u16>| Import {
            dll: "kernel32.dll".into(),
            name: name.map(str::to_string),
            ordinal,
            rva: 0x2000,
            hint: 0,
            ilt_value: 0,
        };
        let mut imports = NativeImports::from_pe_imports(
            &[read(Some("Sleep"), None), read(None, Some(5))],
            false,
        )
        .unwrap();

        assert!(imports.add_function("kernel32.dll", "Sleep").is_err());
        assert!(imports.add_function_by_ordinal("kernel32.dll", 5).is_err());
        imports.add_function("kernel32.dll", "Beep").unwrap();
        imports.add_function_by_ordinal("kernel32.dll", 6).unwrap();
        assert!(imports.add_function("kernel32.dll", "Beep").is_err());
        assert_eq!(imports.total_function_count(), 4);
    }

    /// A descriptor's functions share its DLL's name rather than a copy each.
    #[test]
    fn functions_share_their_dll_name() {
        let mut imports = NativeImports::new();
        imports.add_dll("kernel32.dll").unwrap();
        imports.add_function("kernel32.dll", "Sleep").unwrap();
        imports.add_function_by_ordinal("kernel32.dll", 5).unwrap();

        let descriptor = imports.get_descriptor("kernel32.dll").unwrap();
        assert!(descriptor
            .functions
            .iter()
            .all(|function| Arc::ptr_eq(&function.dll, &descriptor.dll_name)));
    }
}
