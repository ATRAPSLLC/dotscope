//! Analysis and representation of imported types and methods in .NET assemblies.
//!
//! This module provides comprehensive functionality for tracking and analyzing all external
//! dependencies (imports) of a .NET assembly, including methods and types imported from other
//! assemblies, modules, native DLLs, or file resources. Essential for dependency analysis,
//! interoperability scenarios, and assembly resolution workflows.
//!
//! # Architecture
//!
//! The imports system uses a multi-index approach built on concurrent data structures for
//! thread-safe access patterns. The architecture separates import classification, source
//! tracking, and lookup optimization into distinct but integrated components.
//!
//! ## Core Design Principles
//!
//! - **Reference Cycle Prevention**: Token-based source identification avoids circular dependencies
//! - **Multi-Index Strategy**: Separate indices for name, namespace, and source-based lookups
//! - **Concurrent Safety**: Lock-free data structures for high-performance multi-threaded access
//! - **Memory Efficiency**: Reference counting and weak references minimize memory overhead
//!
//! # Key Components
//!
//! ## Primary Types
//!
//! - [`crate::metadata::imports::Import`] - Individual imported entity with complete metadata
//! - [`crate::metadata::imports::Imports`] - Main container with multi-index lookup capabilities
//! - [`crate::metadata::imports::ImportType`] - Classification as method or type import
//! - [`crate::metadata::imports::ImportSourceId`] - Token-based source identification
//! - [`crate::metadata::imports::ImportContainer`] - Trait for source aggregation patterns
//!
//! ## Import Categories
//!
//! - **Type Imports**: External types from other .NET assemblies
//! - **Method Imports**: Platform Invoke (P/Invoke) methods from native DLLs
//! - **Module References**: Types and methods from separate compilation units
//! - **File References**: Resources and embedded types from external files
//!
//! # Usage Examples
//!
//! ## Basic Import Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::imports::{Imports, ImportType};
//!
//! let imports = Imports::new();
//!
//! // Find all imports from System namespace
//! let system_imports = imports.by_namespace("System");
//! for import in system_imports {
//!     println!("System import: {}", import.fullname());
//!     match &import.import {
//!         ImportType::Type(cil_type) => println!("  Type: {}", cil_type.name),
//!         ImportType::Method(method) => println!("  Method: {}", method.name),
//!     }
//! }
//!
//! // Find specific imported type
//! if let Some(string_import) = imports.by_fullname("System.String") {
//!     println!("Found String type from: {:?}", string_import.source_id);
//! }
//! ```
//!
//! ## Source-Based Analysis
//!
//! ```rust,no_run
//! use dotscope::metadata::imports::{Imports, ImportContainer};
//!
//! let imports = Imports::new();
//!
//! # fn get_assembly_ref() -> std::sync::Arc<dotscope::metadata::tables::AssemblyRef> { todo!() }
//! # fn get_module_ref() -> std::sync::Arc<dotscope::metadata::tables::ModuleRef> { todo!() }
//! let system_core = get_assembly_ref(); // System.Core assembly reference
//! let kernel32 = get_module_ref(); // kernel32.dll module reference
//!
//! // Get all imports from specific sources
//! let core_imports = imports.from_assembly_ref(&system_core);
//! let native_imports = imports.from_module_ref(&kernel32);
//!
//! println!("Imports from System.Core: {}", core_imports.len());
//! println!("Native imports from kernel32: {}", native_imports.len());
//! ```
//!
//! ## Comprehensive Import Enumeration
//!
//! ```rust,no_run
//! use dotscope::metadata::imports::{Imports, ImportType};
//!
//! let imports = Imports::new();
//!
//! // Analyze all imports in the assembly
//! for entry in &imports {
//!     let import = entry.value();
//!     println!("Import {} from {:?}", import.fullname(), import.source_id);
//!     
//!     match &import.import {
//!         ImportType::Type(cil_type) => {
//!             println!("  Type: {}.{}", cil_type.namespace, cil_type.name);
//!         }
//!         ImportType::Method(method) => {
//!             println!("  P/Invoke Method: {}", method.name);
//!         }
//!     }
//! }
//! ```
//!
//! # Integration
//!
//! The imports system integrates with other dotscope components:
//! - [`crate::metadata::typesystem`] - Type resolution and external references
//! - [`crate::metadata::method`] - Method body analysis and P/Invoke declarations
//! - [`crate::metadata::tables`] - Metadata table navigation and token resolution
//! - [`crate::CilObject`] - High-level assembly analysis and dependency tracking
//!
//! # Interoperability Support
//!
//! Special handling for Platform Invoke (P/Invoke) scenarios:
//! - Native DLL method imports via [`crate::metadata::tables::ModuleRef`]
//! - COM interop type imports from external assemblies  
//! - Mixed-mode assembly dependencies and marshalling requirements
//!
//! # Thread Safety
//!
//! All operations are thread-safe using lock-free concurrent data structures:
//! - [`crossbeam_skiplist::SkipMap`] for ordered token-based primary storage
//! - [`dashmap::DashMap`] for high-performance index lookups
//! - Reference counting enables safe sharing across threads without contention

use std::sync::Arc;

use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;

use crate::{
    metadata::{
        method::MethodRc,
        streams::SharedStr,
        tables::{AssemblyRef, AssemblyRefRc, File, FileRc, Module, ModuleRef, ModuleRefRc},
        texthash::TextHash,
        token::Token,
        typesystem::{CilTypeRc, CilTypeReference},
    },
    Result,
};

/// A reference to an `Import`
pub type ImportRc = Arc<Import>;

/// Classification of what is being imported from external sources.
///
/// Distinguishes between the two primary categories of imports in .NET assemblies:
/// methods (typically from native DLLs via P/Invoke) and types (from other assemblies).
/// This classification affects how the import is resolved and used at runtime.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::imports::ImportType;
///
/// # fn process_import(import_type: &ImportType) {
/// match import_type {
///     ImportType::Method(method) => {
///         println!("Native method import: {}", method.name);
///         // Handle P/Invoke or COM method
///     }
///     ImportType::Type(cil_type) => {
///         println!("Type import: {}.{}", cil_type.namespace, cil_type.name);
///         // Handle cross-assembly type reference
///     }
/// }
/// # }
/// ```
///
/// # Thread Safety
///
/// [`ImportType`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only reference-counted data.
/// Instances can be safely shared across threads and accessed concurrently.
pub enum ImportType {
    /// Importing a method from external source (typically native DLL via P/Invoke).
    ///
    /// Represents a method import, most commonly used for Platform Invoke (P/Invoke)
    /// scenarios where managed code calls into native libraries. The method reference
    /// contains signature information, calling conventions, and marshalling details.
    Method(MethodRc),

    /// Importing a type from external assembly or module.
    ///
    /// Represents a type import from another .NET assembly, module, or file. This
    /// includes classes, interfaces, value types, and enums that are defined externally
    /// but referenced by the current assembly. Used for cross-assembly type resolution.
    Type(CilTypeRc),
}

/// Import source identifier for tracking origins without reference cycles.
///
/// Provides a lightweight way to identify where imports originate from without
/// creating strong references that could lead to reference cycles. Each variant
/// stores only the token of the source entity, allowing the import system to
/// group and query imports by source while maintaining clean memory management.
///
/// # Design Rationale
///
/// Using token-based identification instead of direct references:
/// - **Prevents Reference Cycles**: Avoids circular dependencies between imports and sources
/// - **Memory Efficient**: Stores only 4-byte tokens instead of full object references
/// - **Enables Grouping**: Efficient queries for all imports from specific sources
/// - **Thread Safe**: Tokens are copyable and don't require synchronization
///
/// # Source Categories
///
/// - **Module/ModuleRef**: Types and methods from separate compilation units
/// - **`AssemblyRef`**: Types from external .NET assemblies
/// - **File**: Resources and types from external files
/// - **`TypeRef`**: Nested types under other type references
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::imports::ImportSourceId;
/// use dotscope::metadata::token::Token;
///
/// // Create source identifiers
/// let module_source = ImportSourceId::Module(Token::new(0x00000001));
/// let assembly_source = ImportSourceId::AssemblyRef(Token::new(0x23000001));
/// let file_source = ImportSourceId::File(Token::new(0x26000001));
///
/// // Use in grouping operations
/// let sources = vec![module_source, assembly_source, file_source];
/// for source in sources {
///     println!("Processing imports from: {:?}", source);
/// }
/// ```
///
/// # Thread Safety
///
/// [`ImportSourceId`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only primitive data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Debug)]
pub enum ImportSourceId {
    /// Import from a module within the same assembly.
    ///
    /// Used for types and members defined in the current assembly's modules.
    /// The token refers to a `Module` table entry. This variant is relatively
    /// rare since most imports come from external assemblies.
    ///
    /// # Example Use Cases
    /// - Multi-module assemblies where types are defined across modules
    /// - Internal cross-module references within a single assembly
    Module(Token),

    /// Import from an external module reference (P/Invoke target).
    ///
    /// Used for P/Invoke method imports that call into native DLLs.
    /// The token refers to a `ModuleRef` table entry which contains the
    /// DLL name (e.g., "kernel32.dll", "user32.dll").
    ///
    /// # Example Use Cases
    /// - `[DllImport("kernel32.dll")] extern GetCurrentProcessId()`
    /// - Native interop calls to Windows API functions
    /// - Calls to custom native libraries
    ///
    /// # Retrieving the DLL Name
    /// Use [`Imports::get_module_ref`] with the contained token to retrieve
    /// the `ModuleRef` entry and access its `name` field for the DLL name.
    ModuleRef(Token),

    /// Import from an external assembly reference.
    ///
    /// The most common import source. Used for types imported from other
    /// .NET assemblies. The token refers to an `AssemblyRef` table entry.
    ///
    /// # Example Use Cases
    /// - Types from `mscorlib` / `System.Runtime` (e.g., `System.String`)
    /// - Types from `System.Collections.Generic` (e.g., `List<T>`)
    /// - Types from third-party NuGet packages
    AssemblyRef(Token),

    /// Import from an external file reference.
    ///
    /// Used for resources and types embedded in external files associated
    /// with the assembly. The token refers to a `File` table entry.
    /// This is uncommon in modern .NET assemblies.
    ///
    /// # Example Use Cases
    /// - Satellite assemblies for localization
    /// - Resource files bundled with the assembly
    File(Token),

    /// Import reference through a parent type (nested types).
    ///
    /// Used when the import's resolution scope is another `TypeRef`, indicating
    /// a nested type. The token refers to a `TypeRef` table entry representing
    /// the enclosing type.
    ///
    /// # Example Use Cases
    /// - Nested classes: `OuterClass.InnerClass`
    /// - Nested interfaces: `IContainer.IEnumerator`
    /// - Private implementation types: `Dictionary<K,V>.Enumerator`
    TypeRef(Token),

    /// No specific source identified.
    ///
    /// Used internally when the import's source cannot be determined or is
    /// not applicable. This typically indicates:
    /// - An error during metadata parsing
    /// - A malformed or incomplete import entry
    /// - Synthetic imports created programmatically
    ///
    /// Code handling imports should treat this variant as an edge case that
    /// may require special handling or error reporting.
    None,
}

/// A method or type imported from external .NET assembly or native DLL.
///
/// Represents a single import entity with complete metadata about its origin, type,
/// and naming information. This structure provides all necessary information for
/// resolving dependencies, performing interop operations, and analyzing assembly
/// relationships.
///
/// # Structure
///
/// Each import contains:
/// - **Identity**: Token and name information for resolution
/// - **Classification**: Whether it's a method or type import
/// - **Source Tracking**: Where the import originates from
/// - **Namespace**: For organized lookup and grouping
///
/// # Use Cases
///
/// - **Dependency Analysis**: Understanding external dependencies
/// - **P/Invoke Resolution**: Mapping managed calls to native methods
/// - **Type Loading**: Resolving external type references
/// - **Assembly Binding**: Determining required assemblies at runtime
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::imports::{Import, ImportType};
///
/// # fn process_import(import: &Import) {
/// // Examine the import details
/// println!("Import: {} (Token: {})", import.fullname(), import.token);
/// println!("Source: {:?}", import.source_id);
///
/// match &import.import {
///     ImportType::Type(cil_type) => {
///         println!("Type import: {}", cil_type.name);
///         // Handle cross-assembly type reference
///     }
///     ImportType::Method(method) => {
///         println!("Method import: {}", method.name);
///         // Handle P/Invoke or COM method
///     }
/// }
/// # }
/// ```
///
/// # Thread Safety
///
/// [`Import`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data and reference-counted imports.
/// Instances can be safely shared across threads and accessed concurrently.
pub struct Import {
    /// The metadata token identifying this import in the assembly.
    pub token: Token,
    /// The name of the imported entity (may differ from original export name).
    pub name: SharedStr,
    /// The namespace of the imported entity (empty for global namespace).
    pub namespace: SharedStr,
    /// The specific method or type being imported.
    pub import: ImportType,
    /// Identifier for the source of this import (avoids reference cycles).
    pub source_id: ImportSourceId,
}

impl Import {
    /// Return the entity's fully qualified name (namespace.name).
    ///
    /// Constructs the full name by combining namespace and name components.
    /// For entities in the global namespace (empty namespace), returns only the name.
    /// This format matches the standard .NET type naming conventions.
    ///
    /// # Returns
    /// - `"namespace.name"` if namespace is non-empty
    /// - `"name"` if namespace is empty or global
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::imports::Import;
    /// # use dotscope::metadata::token::Token;
    /// # use dotscope::metadata::imports::{ImportType, ImportSourceId};
    /// # fn example() {
    /// // Example: System.String type import
    /// // let import = ...;  // constructed from metadata
    /// // assert_eq!(import.fullname(), "System.String");
    ///
    /// // Example: Global namespace method
    /// // let global_import = ...;  // constructed from metadata
    /// // assert_eq!(global_import.fullname(), "GlobalFunction");
    /// # }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn fullname(&self) -> SharedStr {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            SharedStr::from(format!("{}.{}", self.namespace, self.name))
        }
    }

    /// The [`TextHash`] of [`Self::fullname`], from the shared names without joining them.
    fn fullname_hash(&self) -> TextHash {
        if self.namespace.is_empty() {
            self.name.text_hash()
        } else {
            self.namespace
                .text_hash()
                .then(TextHash::of(b"."))
                .then(self.name.text_hash())
        }
    }
}

/// Container for all imported types and methods in a .NET assembly.
///
/// The `Imports` container provides efficient storage, lookup, and analysis capabilities for
/// all external dependencies imported by a .NET assembly. It maintains multiple concurrent
/// indices to support different query patterns while ensuring thread-safe access for
/// multi-threaded metadata processing scenarios.
///
/// # Architecture
///
/// ## Multi-Index Strategy
/// - **Primary Storage**: Token-based ordering using [`crossbeam_skiplist::SkipMap`]
/// - **Name Indices**: Fast lookup by simple name and fully-qualified name
/// - **Namespace Index**: Efficient grouping of imports by namespace
/// - **Source Index**: Imports grouped by originating assembly, module, or file
///
/// ## Concurrent Design
/// All operations are lock-free using concurrent data structures:
/// - Primary storage supports concurrent reads and writes
/// - Index updates are atomic and consistent
/// - Reference counting enables safe sharing across threads
///
/// # Import Categories
///
/// The container handles multiple types of imports:
/// - **Type Imports**: Classes, interfaces, value types from external assemblies
/// - **Method Imports**: P/Invoke methods from native DLLs
/// - **Module Imports**: Types and methods from separate modules
/// - **File Imports**: Resources and types from external files
///
/// # Usage Examples
///
/// ## Basic Container Operations
///
/// ```rust,no_run
/// use dotscope::metadata::imports::Imports;
///
/// let imports = Imports::new();
/// println!("Empty container has {} imports", imports.len());
/// assert!(imports.is_empty());
///
/// // Container will be populated during assembly parsing
/// // ...parsing logic adds imports...
///
/// if !imports.is_empty() {
///     println!("Found {} total imports", imports.len());
/// }
/// ```
///
/// ## Name-Based Lookups
///
/// ```rust,no_run
/// use dotscope::metadata::imports::Imports;
///
/// let imports = Imports::new();
///
/// // Find first import with specific name
/// if let Some(string_import) = imports.by_name("String") {
///     println!("Found String import: {}", string_import.fullname());
/// }
///
/// // Find all imports with same name (handles conflicts)
/// let list_imports = imports.all_by_name("List");
/// for import in list_imports {
///     println!("List import: {} from {:?}", import.fullname(), import.source_id);
/// }
///
/// // Find by fully-qualified name
/// if let Some(specific_import) = imports.by_fullname("System.Collections.Generic.List") {
///     println!("Found specific List type");
/// }
/// ```
///
/// ## Namespace and Source Analysis
///
/// ```rust,no_run
/// use dotscope::metadata::imports::{Imports, ImportContainer};
///
/// let imports = Imports::new();
///
/// // Analyze imports by namespace
/// let system_imports = imports.by_namespace("System");
/// println!("System namespace has {} imports", system_imports.len());
///
/// # fn get_assembly_ref() -> std::sync::Arc<dotscope::metadata::tables::AssemblyRef> { todo!() }
/// let mscorlib = get_assembly_ref(); // mscorlib assembly reference
/// let mscorlib_imports = imports.from_assembly_ref(&mscorlib);
/// println!("mscorlib provides {} imports", mscorlib_imports.len());
/// ```
///
/// ## Comprehensive Analysis
///
/// ```rust,no_run
/// use dotscope::metadata::imports::{Imports, ImportType};
///
/// let imports = Imports::new();
///
/// // Analyze all imports with detailed classification
/// for entry in &imports {
///     let import = entry.value();
///     match &import.import {
///         ImportType::Type(cil_type) => {
///             println!("Type Import: {}.{} from {:?}",
///                      cil_type.namespace, cil_type.name, import.source_id);
///         }
///         ImportType::Method(method) => {
///             println!("Method Import: {} from {:?}",
///                      method.name, import.source_id);
///         }
///     }
/// }
/// ```
///
/// # Source Registration
///
/// The container tracks import sources to enable efficient source-based queries:
/// - Assembly references are automatically registered when types are added
/// - Module references are registered when methods are imported
/// - File references are tracked for resource-based imports
/// - Source tracking uses weak references to prevent circular dependencies
///
/// # Thread Safety
///
/// All operations are thread-safe and lock-free:
/// - Multiple threads can add imports concurrently
/// - Lookups can proceed while additions are in progress
/// - Iterator consistency is maintained across concurrent modifications
/// - Reference counting ensures safe access to imported entities
pub struct Imports {
    /// Primary storage - token to import mapping
    data: SkipMap<Token, ImportRc>,

    /// Index for lookup by simple name
    by_name: DashMap<SharedStr, Vec<Token>>,
    /// Index for lookup by full qualified name
    by_fullname: DashMap<TextHash, Vec<Token>>,
    /// Index for lookup by namespace
    by_namespace: DashMap<SharedStr, Vec<Token>>,

    /// Group imports by their source assembly/module
    by_source: DashMap<ImportSourceId, Vec<Token>>,

    /// Module instances indexed by token
    modules: DashMap<Token, Arc<Module>>,
    /// Module reference instances indexed by token
    module_refs: DashMap<Token, Arc<ModuleRef>>,
    /// Assembly reference instances indexed by token
    assembly_refs: DashMap<Token, Arc<AssemblyRef>>,
    /// File instances indexed by token
    files: DashMap<Token, Arc<File>>,
}

impl Imports {
    /// Create a new empty imports container.
    ///
    /// Initializes all internal data structures for efficient concurrent access.
    /// The container is immediately ready for import registration and lookup operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    /// assert!(imports.is_empty());
    /// assert_eq!(imports.len(), 0);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new() -> Self {
        Imports {
            data: SkipMap::new(),
            by_name: DashMap::new(),
            by_fullname: DashMap::new(),
            by_namespace: DashMap::new(),
            by_source: DashMap::new(),
            modules: DashMap::new(),
            module_refs: DashMap::new(),
            assembly_refs: DashMap::new(),
            files: DashMap::new(),
        }
    }

    /// Register a source entity for import tracking.
    ///
    /// Creates internal tracking for entities that can provide imports, enabling
    /// efficient source-based queries. This registration uses weak references to
    /// prevent circular dependencies between imports and their sources.
    ///
    /// # Arguments
    /// * `source` - The source entity to register for import tracking
    ///
    /// # Supported Sources
    /// - [`crate::metadata::typesystem::CilTypeReference::Module`] - Internal modules
    /// - [`crate::metadata::typesystem::CilTypeReference::ModuleRef`] - External module references
    /// - [`crate::metadata::typesystem::CilTypeReference::AssemblyRef`] - External assembly references
    /// - [`crate::metadata::typesystem::CilTypeReference::File`] - External file references
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    /// use dotscope::metadata::typesystem::CilTypeReference;
    ///
    /// let imports = Imports::new();
    ///
    /// # fn get_assembly_ref() -> CilTypeReference { todo!() }
    /// let assembly_ref = get_assembly_ref();
    /// imports.register_source(&assembly_ref);
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn register_source(&self, source: &CilTypeReference) {
        match source {
            CilTypeReference::Module(module) => {
                let token = module.token;
                self.modules.insert(token, module.clone());
            }
            CilTypeReference::ModuleRef(module_ref) => {
                let token = module_ref.token;
                self.module_refs.insert(token, module_ref.clone());
            }
            CilTypeReference::AssemblyRef(assembly_ref) => {
                let token = assembly_ref.token;
                self.assembly_refs.insert(token, assembly_ref.clone());
            }
            CilTypeReference::File(file) => {
                let token = file.token;
                self.files.insert(token, file.clone());
            }
            _ => {}
        }
    }

    /// Add a type as an import from external source.
    ///
    /// Registers a [`crate::metadata::typesystem::CilType`] as an imported type, creating all
    /// necessary index entries for efficient lookup. The type must have an external reference
    /// to be considered an import; internal types are ignored.
    ///
    /// # Arguments
    /// * `cil_type` - The type to register as an import
    ///
    /// # Import Processing
    /// 1. Validates the type has an external reference
    /// 2. Creates appropriate source identifier
    /// 3. Registers the source entity if needed
    /// 4. Updates all lookup indices
    /// 5. Handles special cases (`TypeRef` nesting)
    ///
    /// # Special Handling
    /// - **`TypeRef`**: Nested types are added to parent's nested collection, not tracked as imports
    /// - **Source Registration**: External sources are automatically registered for tracking
    /// - **Index Updates**: All name, namespace, and source indices are updated atomically
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    ///
    /// # fn get_external_type() -> std::sync::Arc<dotscope::metadata::typesystem::CilType> { todo!() }
    /// let external_type = get_external_type(); // Type with external reference
    /// imports.add_type(&external_type)?;
    ///
    /// println!("Added import: {}", external_type.name);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns [`crate::Error`] if:
    /// - External reference type is invalid or unrecognized
    /// - Source registration fails
    /// - Internal data structure operations fail
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn add_type(&self, cil_type: &CilTypeRc) -> Result<()> {
        if let Some(external) = cil_type.external() {
            // Create the source ID from the external reference
            let source_id = match external {
                CilTypeReference::Module(module) => ImportSourceId::Module(module.token),
                CilTypeReference::ModuleRef(module_ref) => {
                    ImportSourceId::ModuleRef(module_ref.token)
                }
                CilTypeReference::AssemblyRef(assembly_ref) => {
                    ImportSourceId::AssemblyRef(assembly_ref.token)
                }
                CilTypeReference::File(file) => ImportSourceId::File(file.token),
                CilTypeReference::TypeRef(type_ref) => {
                    // For TypeRef, add to the parent's nested_types and establish
                    // the enclosing_type link so fullname() produces nested paths.
                    if let Some(nested_types) = type_ref.nested_types() {
                        nested_types.push(cil_type.clone().into());
                    }
                    let _ = cil_type.set_enclosing_type(type_ref);
                    return Ok(());
                }
                _ => return Err(malformed_error!("Invalid source id for Import")),
            };

            // Register the source entity for later reference
            self.register_source(external);

            // Create the import
            let import_rc = Arc::new(Import {
                token: cil_type.token,
                name: cil_type.name.clone(),
                namespace: cil_type.namespace.clone(),
                import: ImportType::Type(cil_type.clone()),
                source_id,
            });

            // Store the import with all appropriate indices
            self.add_import_entry(import_rc, source_id);

            Ok(())
        } else {
            Ok(())
        }
    }

    /// Add a method as an import from external module.
    ///
    /// Registers a Platform Invoke (P/Invoke) method or other external method as an import.
    /// This is typically used for native DLL methods that are called from managed code
    /// through P/Invoke declarations.
    ///
    /// # Arguments
    /// * `name` - The imported name of the method (may differ from original export name)
    /// * `token` - The metadata token identifying this import in the assembly
    /// * `method` - The method definition containing signature and attributes
    /// * `module` - The external module reference providing the method
    ///
    /// # Import Processing
    /// 1. Creates module reference-based source identifier
    /// 2. Registers the module for source tracking
    /// 3. Creates import entry with method classification
    /// 4. Updates all relevant lookup indices
    ///
    /// # Use Cases
    /// - **P/Invoke Methods**: Native library functions called from managed code
    /// - **COM Interop**: Methods from COM objects and interfaces
    /// - **Mixed Mode**: Methods from C++/CLI assemblies
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    /// use dotscope::metadata::token::Token;
    ///
    /// let imports = Imports::new();
    ///
    /// # fn get_method() -> std::sync::Arc<dotscope::metadata::method::Method> { todo!() }
    /// # fn get_module_ref() -> std::sync::Arc<dotscope::metadata::tables::ModuleRef> { todo!() }
    /// let method = get_method();
    /// let kernel32 = get_module_ref(); // kernel32.dll module reference
    /// let token = Token::new(0x0A000001);
    ///
    /// imports.add_method(
    ///     "GetProcessId".into(),
    ///     &token,
    ///     method,
    ///     &kernel32
    /// )?;
    ///
    /// println!("Added P/Invoke import: GetProcessId");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    /// Returns [`crate::Error`] if internal data structure operations fail.
    /// Currently does not validate method signatures or module compatibility.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn add_method(
        &self,
        name: SharedStr,
        token: &Token,
        method: MethodRc,
        module: &ModuleRefRc,
    ) -> Result<()> {
        let source_id = ImportSourceId::ModuleRef(module.token);

        // Register the source module
        self.module_refs.insert(module.token, module.clone());

        // Create the import
        let import_rc = Arc::new(Import {
            token: *token,
            name,
            namespace: SharedStr::default(),
            import: ImportType::Method(method),
            source_id,
        });

        // Store the import with all appropriate indices
        self.add_import_entry(import_rc, source_id);

        Ok(())
    }

    /// Helper method to add an import entry to all indices
    fn add_import_entry(&self, import_rc: ImportRc, source_id: ImportSourceId) {
        // Add to lookup indices
        self.by_name
            .entry(import_rc.name.clone())
            .or_default()
            .push(import_rc.token);

        self.by_fullname
            .entry(import_rc.fullname_hash())
            .or_default()
            .push(import_rc.token);

        if !import_rc.namespace.is_empty() {
            self.by_namespace
                .entry(import_rc.namespace.clone())
                .or_default()
                .push(import_rc.token);
        }

        // Add to source grouping
        self.by_source
            .entry(source_id)
            .or_default()
            .push(import_rc.token);

        // Add to primary storage
        self.data.insert(import_rc.token, import_rc);
    }

    /// Get the total number of imports in the container.
    ///
    /// Returns the count of all registered imports, including both type and method imports.
    /// This operation is O(1) as the underlying skip map maintains an internal count.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    /// assert_eq!(imports.len(), 0);
    ///
    /// // After adding imports...
    /// # fn add_some_imports(imports: &Imports) {}
    /// add_some_imports(&imports);
    /// println!("Container now has {} imports", imports.len());
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the container has no imports.
    ///
    /// Returns `true` if no imports have been registered, `false` otherwise.
    /// Equivalent to `self.len() == 0` but may be more semantically clear.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    /// assert!(imports.is_empty());
    ///
    /// # fn add_import(imports: &Imports) -> dotscope::Result<()> { Ok(()) }
    /// add_import(&imports)?;
    /// assert!(!imports.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over all imports in the container.
    ///
    /// Returns an iterator that yields [`crossbeam_skiplist::map::Entry`] instances,
    /// each containing a ([`Token`], [`crate::metadata::imports::ImportRc`]) pair.
    /// The iteration order is sorted by token value due to the skip map's ordering properties.
    ///
    /// # Iterator Properties
    /// - **Ordering**: Imports are yielded in ascending token order
    /// - **Consistency**: Safe to use during concurrent modifications
    /// - **Performance**: Efficient traversal with minimal overhead
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::{Imports, ImportType};
    ///
    /// let imports = Imports::new();
    ///
    /// // Analyze all imports with classification
    /// for entry in imports.iter() {
    ///     let token = entry.key();
    ///     let import = entry.value();
    ///     
    ///     match &import.import {
    ///         ImportType::Type(cil_type) => {
    ///             println!("Type Import {}: {}.{}", token, cil_type.namespace, cil_type.name);
    ///         }
    ///         ImportType::Method(method) => {
    ///             println!("Method Import {}: {}", token, method.name);
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn iter(&self) -> crossbeam_skiplist::map::Iter<'_, Token, ImportRc> {
        self.data.iter()
    }

    /// Find an import with the specified name.
    ///
    /// Performs efficient lookup for imports by their simple name (without namespace).
    /// If multiple imports have the same name (e.g., from different assemblies or
    /// namespaces), returns one of them arbitrarily.
    ///
    /// # Ordering Behavior
    ///
    /// **Important**: When multiple imports share the same name, this method returns
    /// the one with the lowest metadata token value. The ordering is determined by
    /// the internal token-indexed storage, not by insertion order. This ordering
    /// is consistent within a single session but should not be relied upon for
    /// deterministic selection across different runs.
    ///
    /// Use [`Self::all_by_name`] when you need all imports with a given name, or
    /// when deterministic selection among duplicates is required.
    ///
    /// # Arguments
    /// * `name` - The simple name to search for (case-sensitive)
    ///
    /// # Returns
    /// An [`ImportRc`] with matching name, or `None` if not found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    ///
    /// // Find any import named "String"
    /// if let Some(string_import) = imports.by_name("String") {
    ///     println!("Found String import: {}", string_import.fullname());
    /// }
    ///
    /// // When duplicates exist, use all_by_name for full control
    /// let all_strings = imports.all_by_name("String");
    /// if all_strings.len() > 1 {
    ///     println!("Found {} imports named String", all_strings.len());
    ///     for import in all_strings {
    ///         println!("  - {} from {:?}", import.fullname(), import.source_id);
    ///     }
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn by_name(&self, name: &str) -> Option<ImportRc> {
        if let Some(tokens) = self.by_name.get(name) {
            if let Some(first) = tokens.first() {
                if let Some(token) = self.data.get(first) {
                    return Some(token.value().clone());
                }
            }
        }
        None
    }

    /// Find all imports with the specified name.
    ///
    /// Returns all imports that have the given simple name, regardless of namespace.
    /// This is useful when there are name collisions between imports from different
    /// sources or namespaces.
    ///
    /// # Arguments
    /// * `name` - The simple name to search for (case-sensitive)
    ///
    /// # Returns
    /// A [`Vec`] of [`crate::metadata::imports::ImportRc`] containing all matching imports.
    /// Empty vector if no matches are found.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    ///
    /// // Find all imports named "Point" (might be from different namespaces)
    /// let point_imports = imports.all_by_name("Point");
    /// for import in point_imports {
    ///     println!("Point import: {} from {:?}", import.fullname(), import.source_id);
    /// }
    ///
    /// // Handle empty results
    /// let missing_imports = imports.all_by_name("NonExistent");
    /// assert!(missing_imports.is_empty());
    /// ```
    pub fn all_by_name(&self, name: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_name.get(name) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Find import by fully-qualified name.
    ///
    /// Performs efficient lookup using the complete namespace-qualified name.
    /// This provides precise matching when you know the exact full name of the import.
    ///
    /// # Arguments
    /// * `name` - The fully-qualified name (e.g., "System.Collections.Generic.List")
    ///
    /// # Returns
    /// The first [`crate::metadata::imports::ImportRc`] with matching full name, or `None` if not found.
    ///
    /// # Name Format
    /// - **With Namespace**: "Namespace.TypeName" or "Namespace.Subnamespace.TypeName"
    /// - **Global Namespace**: Just "`TypeName`" for imports in the global namespace
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    ///
    /// // Find specific type by full name
    /// if let Some(list_import) = imports.by_fullname("System.Collections.Generic.List") {
    ///     println!("Found List import from: {:?}", list_import.source_id);
    /// }
    ///
    /// // Find global namespace import
    /// if let Some(global_import) = imports.by_fullname("GlobalFunction") {
    ///     println!("Found global import: {}", global_import.name);
    /// }
    /// ```
    pub fn by_fullname(&self, name: &str) -> Option<ImportRc> {
        if let Some(tokens) = self.by_fullname.get(&TextHash::of(name.as_bytes())) {
            if let Some(first) = tokens.first() {
                if let Some(token) = self.data.get(first) {
                    return Some(token.value().clone());
                }
            }
        }
        None
    }

    /// Get all `Import`s by full name (namespace.name)
    ///
    /// ## Arguments
    /// * 'name' - The imported name to look for
    pub fn all_by_fullname(&self, name: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_fullname.get(&TextHash::of(name.as_bytes())) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Find all imports in the specified namespace.
    ///
    /// Returns all imports that belong to the given namespace, enabling analysis
    /// of imports organized by their namespace hierarchy. Useful for understanding
    /// dependencies on specific namespaces or libraries.
    ///
    /// # Arguments
    /// * `namespace` - The namespace to search in (case-sensitive)
    ///
    /// # Returns
    /// A [`Vec`] of [`crate::metadata::imports::ImportRc`] containing all imports in the namespace.
    /// Empty vector if the namespace contains no imports.
    ///
    /// # Namespace Matching
    /// - **Exact Match**: Only imports with exactly matching namespace are returned
    /// - **Case Sensitive**: Namespace comparison is case-sensitive
    /// - **No Hierarchy**: Subnamespaces are not included (e.g., "System" won't include "System.IO")
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    ///
    /// let imports = Imports::new();
    ///
    /// // Find all System namespace imports
    /// let system_imports = imports.by_namespace("System");
    /// println!("System namespace has {} imports", system_imports.len());
    /// for import in system_imports {
    ///     println!("  {}", import.name);
    /// }
    ///
    /// // Find specific sub-namespace imports
    /// let collections_imports = imports.by_namespace("System.Collections.Generic");
    /// for import in collections_imports {
    ///     println!("Collections import: {}", import.fullname());
    /// }
    /// ```
    pub fn by_namespace(&self, namespace: &str) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_namespace.get(namespace) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Get all `Import`s from a specific module
    ///
    /// ## Arguments
    /// * `module_ref` - The module reference to get imports from
    pub fn from_module_ref(&self, module_ref: &ModuleRefRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::ModuleRef(module_ref.token);
        self.imports_from_source(source_id)
    }

    /// Get all `Import`s from a specific assembly reference
    ///
    /// ## Arguments
    /// * `assembly_ref` - The assembly reference to get imports from
    pub fn from_assembly_ref(&self, assembly_ref: &AssemblyRefRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::AssemblyRef(assembly_ref.token);
        self.imports_from_source(source_id)
    }

    /// Get all `Import`s from a specific file
    ///
    /// ## Arguments
    /// * 'file' - The file to get imports from
    pub fn from_file(&self, file: &FileRc) -> Vec<ImportRc> {
        let source_id = ImportSourceId::File(file.token);
        self.imports_from_source(source_id)
    }

    /// Helper method to get all imports from a specific source ID
    fn imports_from_source(&self, source_id: ImportSourceId) -> Vec<ImportRc> {
        if let Some(tokens) = self.by_source.get(&source_id) {
            return tokens
                .iter()
                .filter_map(|token| self.data.get(token).map(|entry| entry.value().clone()))
                .collect();
        }
        Vec::new()
    }

    /// Get an import by its token.
    ///
    /// Direct lookup of an import using its metadata token. This is the most
    /// efficient lookup method when you already know the token of the import
    /// you're looking for.
    ///
    /// # Arguments
    /// * `token` - The metadata token identifying the import
    ///
    /// # Returns
    /// - `Some(ImportRc)` if an import with the token exists
    /// - `None` if no import with the token is found
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    /// use dotscope::metadata::token::Token;
    ///
    /// let imports = Imports::new();
    /// let token = Token::new(0x0A000001);
    ///
    /// if let Some(import) = imports.get(token) {
    ///     println!("Found import: {}", import.fullname());
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn get(&self, token: Token) -> Option<ImportRc> {
        self.data.get(&token).map(|entry| entry.value().clone())
    }

    /// Get a module reference by its token.
    ///
    /// Retrieves the [`ModuleRef`] associated with the given token, if it has been
    /// registered as a source for P/Invoke method imports. This is useful for
    /// looking up the DLL name associated with a P/Invoke import.
    ///
    /// # Arguments
    /// * `token` - The metadata token identifying the module reference
    ///
    /// # Returns
    /// - `Some(ModuleRefRc)` if a module reference with the token exists
    /// - `None` if no module reference with the token is found
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::imports::Imports;
    /// use dotscope::metadata::token::Token;
    ///
    /// let imports = Imports::new();
    ///
    /// // Look up a module reference by token
    /// let token = Token::new(0x1A000001);
    /// if let Some(module_ref) = imports.get_module_ref(token) {
    ///     println!("DLL name: {}", module_ref.name);
    /// }
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn get_module_ref(&self, token: Token) -> Option<ModuleRefRc> {
        self.module_refs.get(&token).map(|entry| entry.clone())
    }
}

impl Default for Imports {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Imports {
    fn clone(&self) -> Self {
        // Create a new Imports container and copy all entries
        let new_imports = Self::new();
        for entry in &self.data {
            let token = *entry.key();
            let import = entry.value().clone();
            new_imports.data.insert(token, import.clone());

            // Rebuild the indices
            new_imports
                .by_name
                .entry(import.name.clone())
                .or_default()
                .push(token);

            new_imports
                .by_fullname
                .entry(import.fullname_hash())
                .or_default()
                .push(token);

            if !import.namespace.is_empty() {
                new_imports
                    .by_namespace
                    .entry(import.namespace.clone())
                    .or_default()
                    .push(token);
            }
        }
        new_imports
    }
}

impl<'a> IntoIterator for &'a Imports {
    type Item = crossbeam_skiplist::map::Entry<'a, Token, ImportRc>;
    type IntoIter = crossbeam_skiplist::map::Iter<'a, Token, ImportRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Trait for entities that can provide or aggregate imports.
///
/// This trait enables different types of import sources (assemblies, modules, files)
/// to provide a unified interface for retrieving their associated imports. It supports
/// the source-based analysis patterns common in dependency analysis and interop scenarios.
///
/// # Design Purpose
///
/// The trait serves multiple purposes:
/// - **Unified Interface**: Different source types can be queried uniformly
/// - **Source Analysis**: Easy aggregation of imports by their originating entity
/// - **Dependency Tracking**: Understanding what each source contributes to the assembly
/// - **Modularity**: New source types can implement the trait without changing core logic
///
/// # Implementation Strategy
///
/// Implementors typically:
/// 1. Create an appropriate [`crate::metadata::imports::ImportSourceId`] from their token
/// 2. Query the imports container using the source ID
/// 3. Return the filtered collection of imports
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::imports::{Imports, ImportContainer};
///
/// let imports = Imports::new();
///
/// # fn get_assembly_ref() -> std::sync::Arc<dotscope::metadata::tables::AssemblyRef> { todo!() }
/// let mscorlib = get_assembly_ref(); // Assembly reference
///
/// // Use the trait to get imports from this source
/// let mscorlib_imports = mscorlib.get_imports(&imports);
/// println!("mscorlib provides {} imports", mscorlib_imports.len());
///
/// for import in mscorlib_imports {
///     println!("  {}", import.fullname());
/// }
/// ```
///
/// # Implementing the Trait
///
/// ```rust,no_run
/// use dotscope::metadata::imports::{ImportContainer, Imports, ImportRc, ImportSourceId};
/// use dotscope::metadata::token::Token;
///
/// struct CustomSource {
///     token: Token,
/// }
///
/// impl ImportContainer for CustomSource {
///     fn get_imports(&self, imports: &Imports) -> Vec<ImportRc> {
///         // Implementation would use appropriate public methods
///         // to find imports from this source
///         Vec::new() // placeholder
///     }
/// }
/// ```
pub trait ImportContainer {
    /// Get all imports provided by this source entity.
    ///
    /// Returns a collection of all imports that originate from this specific source.
    /// The implementation should query the imports container using an appropriate
    /// source identifier derived from the entity's metadata token.
    ///
    /// # Arguments
    /// * `imports` - The imports container to query
    ///
    /// # Returns
    /// A [`Vec`] of [`crate::metadata::imports::ImportRc`] containing all imports from this source.
    /// Empty vector if this source provides no imports.
    fn get_imports(&self, imports: &Imports) -> Vec<ImportRc>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{
        create_assembly_ref, create_cil_type, create_file, create_method, create_module_ref,
    };

    #[test]
    fn test_add_method_import() {
        let imports = Imports::new();
        let module_ref = create_module_ref(1, "kernel32.dll");
        let method = create_method("GetProcessId");
        let token = Token::new(0x0A000001);

        imports
            .add_method("GetProcessId".into(), &token, method.clone(), &module_ref)
            .unwrap();

        assert_eq!(imports.len(), 1);

        // Test by_name lookup
        let found = imports.by_name("GetProcessId").unwrap();
        assert_eq!(found.token, token);
        assert_eq!(found.name, "GetProcessId");

        match &found.import {
            ImportType::Method(m) => {
                assert_eq!(m.name, "GetProcessId");
                assert_eq!(m.rva.unwrap(), 0x1000);
            }
            _ => panic!("Expected Method import type"),
        }

        // Test by_fullname lookup
        let found = imports.by_fullname("GetProcessId").unwrap();
        assert_eq!(found.token, token);

        // Test ImportContainer trait
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 1);
        assert_eq!(module_imports[0].token, token);
        assert_eq!(module_imports[0].name, "GetProcessId");
    }

    #[test]
    fn test_add_type_import() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");
        let token = Token::new(0x01000001);

        let cil_type = create_cil_type(
            token,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        imports.add_type(&cil_type).unwrap();

        assert_eq!(imports.len(), 1);

        // Test by_name lookup
        let found = imports.by_name("List").unwrap();
        assert_eq!(found.token, token);
        assert_eq!(found.namespace, "System.Collections.Generic");

        // Test by_fullname lookup
        let found = imports
            .by_fullname("System.Collections.Generic.List")
            .unwrap();
        assert_eq!(found.token, token);

        // Test by_namespace lookup
        let found_by_ns = imports.by_namespace("System.Collections.Generic");
        assert_eq!(found_by_ns.len(), 1);
        assert_eq!(found_by_ns[0].token, token);

        // Test ImportContainer trait
        let assembly_imports = assembly_ref.get_imports(&imports);
        assert_eq!(assembly_imports.len(), 1);
        assert_eq!(assembly_imports[0].token, token);
    }

    #[test]
    fn test_multiple_imports_same_source() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");

        // Add multiple types from same assembly
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);
        let token3 = Token::new(0x01000003);

        let type1 = create_cil_type(
            token1,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.Collections.Generic",
            "Dictionary",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        let type3 = create_cil_type(
            token3,
            "System.Linq",
            "Enumerable",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();
        imports.add_type(&type3).unwrap();

        assert_eq!(imports.len(), 3);

        // Test all_by_namespace
        let generic_types = imports.by_namespace("System.Collections.Generic");
        assert_eq!(generic_types.len(), 2);

        // Test ImportContainer trait
        let assembly_imports = assembly_ref.get_imports(&imports);
        assert_eq!(assembly_imports.len(), 3);
    }

    #[test]
    fn test_multiple_imports_different_sources() {
        let imports = Imports::new();

        let assembly_ref1 = create_assembly_ref(1, "System.Core");
        let assembly_ref2 = create_assembly_ref(2, "System.IO");
        let module_ref = create_module_ref(1, "kernel32.dll");
        let file_ref = create_file(1, "Resources.dll");

        // Types from different sources
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);
        let token3 = Token::new(0x01000003);
        let token4 = Token::new(0x01000004);

        let type1 = create_cil_type(
            token1,
            "System.Collections",
            "ArrayList",
            Some(CilTypeReference::AssemblyRef(assembly_ref1.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.IO",
            "Stream",
            Some(CilTypeReference::AssemblyRef(assembly_ref2.clone())),
        );

        let type3 = create_cil_type(
            token3,
            "NativeTypes",
            "ProcessInfo",
            Some(CilTypeReference::ModuleRef(module_ref.clone())),
        );

        let type4 = create_cil_type(
            token4,
            "Resources",
            "ImageData",
            Some(CilTypeReference::File(file_ref.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();
        imports.add_type(&type3).unwrap();
        imports.add_type(&type4).unwrap();

        assert_eq!(imports.len(), 4);

        // Test imports by different sources
        let asm1_imports = assembly_ref1.get_imports(&imports);
        assert_eq!(asm1_imports.len(), 1);
        assert_eq!(asm1_imports[0].fullname(), "System.Collections.ArrayList");

        let asm2_imports = assembly_ref2.get_imports(&imports);
        assert_eq!(asm2_imports.len(), 1);
        assert_eq!(asm2_imports[0].fullname(), "System.IO.Stream");

        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 1);
        assert_eq!(module_imports[0].fullname(), "NativeTypes.ProcessInfo");

        let file_imports = file_ref.get_imports(&imports);
        assert_eq!(file_imports.len(), 1);
        assert_eq!(file_imports[0].fullname(), "Resources.ImageData");
    }

    #[test]
    fn test_name_collision() {
        let imports = Imports::new();

        let assembly_ref1 = create_assembly_ref(1, "System.Core");
        let assembly_ref2 = create_assembly_ref(2, "System.Drawing");

        // Two types with the same name but different namespaces
        let token1 = Token::new(0x01000001);
        let token2 = Token::new(0x01000002);

        let type1 = create_cil_type(
            token1,
            "System.Drawing",
            "Point",
            Some(CilTypeReference::AssemblyRef(assembly_ref1.clone())),
        );

        let type2 = create_cil_type(
            token2,
            "System.Windows",
            "Point",
            Some(CilTypeReference::AssemblyRef(assembly_ref2.clone())),
        );

        imports.add_type(&type1).unwrap();
        imports.add_type(&type2).unwrap();

        assert_eq!(imports.len(), 2);

        // Test all_by_name to get multiple matches
        let points = imports.all_by_name("Point");
        assert_eq!(points.len(), 2);

        // Make sure fullname lookups work correctly
        let drawing_point = imports.by_fullname("System.Drawing.Point").unwrap();
        assert_eq!(drawing_point.token, token1);

        let windows_point = imports.by_fullname("System.Windows.Point").unwrap();
        assert_eq!(windows_point.token, token2);
    }

    #[test]
    fn test_type_ref_handling() {
        let imports = Imports::new();

        // Create a TypeRef
        let type_ref_token = Token::new(0x01000001);
        let type_ref = create_cil_type(type_ref_token, "System", "Object", None);

        // Create a type that will be nested under the TypeRef
        let nested_token = Token::new(0x01000002);
        let nested_type = create_cil_type(
            nested_token,
            "System.Collections",
            "Nested",
            Some(CilTypeReference::TypeRef(type_ref.clone().into())),
        );

        // Adding a type with TypeRef external should add it to nested_types
        // but not track it as an import
        imports.add_type(&nested_type).unwrap();

        // Verify it wasn't added as an import
        assert_eq!(imports.len(), 0);

        // Verify it was added as a nested type
        assert_eq!(type_ref.nested_types.count(), 1);
        assert_eq!(
            type_ref
                .nested_types
                .get(0)
                .and_then(|nested| nested.token()),
            Some(nested_token)
        );
    }

    #[test]
    fn test_module_method_imports() {
        let imports = Imports::new();
        let module_ref = create_module_ref(1, "kernel32.dll");

        // Add multiple methods from same module
        let method1 = create_method("GetProcessId");
        let method2 = create_method("GetCurrentProcess");
        let method3 = create_method("ExitProcess");

        let token1 = Token::new(0x0A000001);
        let token2 = Token::new(0x0A000002);
        let token3 = Token::new(0x0A000003);

        imports
            .add_method("GetProcessId".into(), &token1, method1, &module_ref)
            .unwrap();

        imports
            .add_method("GetCurrentProcess".into(), &token2, method2, &module_ref)
            .unwrap();

        imports
            .add_method("ExitProcess".into(), &token3, method3, &module_ref)
            .unwrap();

        assert_eq!(imports.len(), 3);

        // Test method imports via ImportContainer
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 3);

        // Verify we can find all methods
        assert!(imports.by_name("GetProcessId").is_some());
        assert!(imports.by_name("GetCurrentProcess").is_some());
        assert!(imports.by_name("ExitProcess").is_some());
    }

    #[test]
    fn test_empty_lookups() {
        let imports = Imports::new();

        // Test various empty lookups
        assert!(imports.by_name("NonExistent").is_none());
        assert!(imports.by_fullname("NonExistent.Type").is_none());
        assert_eq!(imports.by_namespace("NonExistent").len(), 0);
        assert_eq!(imports.all_by_name("NonExistent").len(), 0);

        // Create a source but don't add any imports from it
        let module_ref = create_module_ref(1, "kernel32.dll");
        let module_imports = module_ref.get_imports(&imports);
        assert_eq!(module_imports.len(), 0);
    }

    #[test]
    fn test_iter_works() {
        let imports = Imports::new();
        let assembly_ref = create_assembly_ref(1, "System.Core");
        let module_ref = create_module_ref(1, "kernel32.dll");

        // Add a type import
        let type_token = Token::new(0x01000001);
        let cil_type = create_cil_type(
            type_token,
            "System.Collections.Generic",
            "List",
            Some(CilTypeReference::AssemblyRef(assembly_ref.clone())),
        );
        imports.add_type(&cil_type).unwrap();

        // Add a method import
        let method_token = Token::new(0x0A000001);
        let method = create_method("GetProcessId");
        imports
            .add_method("GetProcessId".into(), &method_token, method, &module_ref)
            .unwrap();

        // Test that we can iterate over all imports
        let mut count = 0;
        let mut tokens = Vec::new();

        for entry in imports.iter() {
            count += 1;
            tokens.push(*entry.key());
        }

        assert_eq!(count, 2);
        assert!(tokens.contains(&type_token));
        assert!(tokens.contains(&method_token));

        // Verify we can access the imports through the iterator
        for entry in imports.iter() {
            let import = entry.value();
            match import.token {
                t if t == type_token => {
                    assert_eq!(import.name, "List");
                    assert_eq!(import.namespace, "System.Collections.Generic");
                    assert!(matches!(import.import, ImportType::Type(_)));
                }
                t if t == method_token => {
                    assert_eq!(import.name, "GetProcessId");
                    assert_eq!(import.namespace, "");
                    assert!(matches!(import.import, ImportType::Method(_)));
                }
                _ => panic!("Unexpected import token: {:?}", import.token),
            }
        }
    }
}
