//! Embedded resources and manifest resource management for .NET assemblies.
//!
//! This module provides comprehensive support for parsing, storing, and accessing embedded resources
//! in .NET assemblies, including manifest resources, resource streams, and resource data management.
//! It handles the three primary resource storage mechanisms in .NET: embedded resources, linked files,
//! and assembly references.
//!
//! # Resource Types in .NET
//!
//! .NET assemblies can contain resources in several forms:
//! - **Embedded Resources**: Binary data directly embedded within the assembly
//! - **Linked Files**: References to external files that should be included during deployment
//! - **Assembly References**: Resources located in other .NET assemblies
//!
//! This module currently focuses on embedded resources, which are the most common type.
//!
//! # Architecture Overview
//!
//! The resource management system uses a multi-layered approach:
//! - **Storage Layer**: [`crate::metadata::resources::Resources`] provides thread-safe resource collection management
//! - **Parsing Layer**: Internal parser handles resource data extraction and parsing
//! - **Type Layer**: Resource-related data structures accessible via public re-exports
//! - **Metadata Integration**: Seamless integration with .NET metadata table system
//!
//! # Key Components
//!
//! ## Core Types
//! - [`crate::metadata::resources::Resources`] - Thread-safe container for all resources in an assembly
//! - [`crate::metadata::resources::Resource`] - Parsed resource entry with metadata
//! - [`crate::metadata::tables::ManifestResourceRc`] - Reference-counted manifest resource from metadata tables
//!
//! ## Resource Access Patterns
//! - **By Name**: Direct lookup using resource names from manifest
//! - **Iteration**: Efficient traversal of all available resources
//! - **Data Access**: Safe data slice extraction with bounds checking
//!
//! # Usage Patterns
//!
//! ## Basic Resource Enumeration
//!
//! ```
//! use dotscope::metadata::tables::ManifestResourceAttributes;
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! println!("Assembly contains {} resources", resources.len());
//!
//! for resource_entry in resources.iter() {
//!     let resource = resource_entry.value();
//!     println!("Resource: {} (Size: {} bytes, Offset: 0x{:X})",
//!              resource.name, resource.data_size, resource.data_offset);
//!     
//!     // Check resource visibility using flags
//!     if resource.flags.contains(ManifestResourceAttributes::PUBLIC) {
//!         println!("  - Public resource");
//!     } else {
//!         println!("  - Private resource");
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Resource Data Access
//!
//! ```no_run
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! // Access specific resource by name
//! if let Some(resource) = resources.get("MyResource.xml") {
//!     if let Some(data) = resources.get_data(&resource) {
//!         println!("Resource data: {} bytes", data.len());
//!
//!         // Process the resource data
//!         match std::str::from_utf8(data) {
//!             Ok(text) => println!("Text resource content: {}", text),
//!             Err(_) => println!("Binary resource data"),
//!         }
//!     } else {
//!         println!("Resource data not available (may be external)");
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Comprehensive Resource Analysis
//!
//! ```
//! use dotscope::CilObject;
//! use std::path::Path;
//!
//! let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
//! let resources = assembly.resources();
//!
//! let mut total_size = 0u64;
//! let mut embedded_count = 0;
//! let mut external_count = 0;
//!
//! for resource_entry in resources.iter() {
//!     let resource = resource_entry.value();
//!     total_size += resource.data_size as u64;
//!     
//!     match resource.source {
//!         None => {
//!             embedded_count += 1;
//!             println!("Embedded: {} ({} bytes)", resource.name, resource.data_size);
//!         }
//!         Some(ref source) => {
//!             external_count += 1;
//!             println!("External: {} -> {:?}", resource.name, source.name());
//!         }
//!     }
//! }
//!
//! println!("Total: {} resources, {} embedded, {} external, {} total bytes",
//!          resources.len(), embedded_count, external_count, total_size);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Resource Storage Mechanisms
//!
//! ## Embedded Resources (Currently Supported)
//! - Stored directly in the assembly's data section
//! - Accessible via RVA (Relative Virtual Address) and size
//! - Most common type for application resources
//! - Fully supported by this implementation
//!
//! ## Linked Files (Future Enhancement)
//! - References to external files in the same directory
//! - Metadata contains filename and hash information
//! - Requires file system access during resource loading
//! - Currently returns `None` for data access
//!
//! ## Assembly References (Future Enhancement)
//! - Resources located in other .NET assemblies
//! - Requires loading and parsing additional assemblies
//! - Cross-assembly resource resolution
//! - Currently returns `None` for data access
//!
//! # Thread Safety
//!
//! All resource operations are thread-safe:
//! - **Concurrent Access**: Multiple threads can safely read resources
//! - **Atomic Operations**: Resource insertion and lookup are atomic
//! - **Reference Counting**: `Arc`-based sharing prevents data races
//! - **Iterator Safety**: Iteration can happen concurrently with reads
//!
//! # Error Handling
//!
//! Resource access is designed to be robust:
//! - **Graceful Degradation**: Invalid resources return `None` rather than panicking
//! - **Bounds Checking**: All data access is bounds-checked for safety
//! - **Format Validation**: Resource headers validated during parsing
//! - **Memory Safety**: No unsafe code in resource data access paths
pub mod baml;
mod encoder;
pub mod nrbf;
mod parser;
mod types;

use std::{collections::BTreeMap, sync::Arc};

use crossbeam_skiplist::{
    map::{Entry, Iter},
    SkipMap,
};
pub use encoder::*;
pub use parser::{parse_dotnet_resource, parse_dotnet_resource_ref, Resource};
pub use types::*;

use crate::{
    file::File,
    metadata::{tables::ManifestResourceRc, token::Token},
};

/// Container for all resources in an assembly with thread-safe access and efficient lookup.
///
/// `Resources` provides a comprehensive resource management system for .NET assemblies,
/// supporting concurrent access, efficient lookup by name, and safe data access with
/// proper bounds checking. It serves as the central hub for all resource operations
/// within an assembly.
///
/// # Architecture
///
/// The container uses a two-layer architecture:
/// - **Storage Layer**: Thread-safe hash map for O(1) resource lookup
/// - **Data Layer**: Direct file access for zero-copy resource data retrieval
///
/// # Resource Lifecycle
///
/// 1. **Loading**: Resources are discovered during metadata table parsing
/// 2. **Registration**: [`insert()`](Resources::insert) adds resources to the collection
/// 3. **Access**: Resources accessed by name or through iteration
/// 4. **Data Retrieval**: [`get_data()`](Resources::get_data) provides access to actual resource bytes
///
/// # Thread Safety
///
/// All operations are thread-safe and can be performed concurrently:
/// - Multiple threads can safely read resources simultaneously
/// - Resource insertion is atomic and doesn't block readers
/// - Iteration can happen concurrently with other operations
///
/// # Examples
///
/// ## Basic Resource Management
///
/// ```no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
/// let resources = assembly.resources();
///
/// // Check if assembly has resources
/// if !resources.is_empty() {
///     println!("Assembly has {} resources", resources.len());
///
///     // Access specific resource
///     if let Some(resource) = resources.get("MyResource") {
///         println!("Found resource: {} ({} bytes)",
///                  resource.name, resource.data_size);
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Resource Data Processing
///
/// ```no_run
/// use dotscope::CilObject;
/// use std::path::Path;
///
/// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
/// let resources = assembly.resources();
///
/// for resource_entry in resources.iter() {
///     let resource = resource_entry.value();
///
///     if let Some(data) = resources.get_data(&resource) {
///         println!("Processing resource: {} ({} bytes)",
///                  resource.name, data.len());
///
///         // Determine resource type based on content
///         if data.starts_with(b"<?xml") {
///             println!("  - XML resource");
///         } else if data.starts_with(b"\x89PNG") {
///             println!("  - PNG image resource");
///         } else {
///             println!("  - Binary resource");
///         }
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct Resources {
    /// Reference to the originally loaded file
    file: Arc<File>,
    /// Every resource, keyed by its `ManifestResource` token so the map
    /// iterates in table order however the loader's threads inserted them
    data: SkipMap<Token, ManifestResourceRc>,
}

impl Resources {
    /// Creates a new empty Resources container.
    ///
    /// Initializes an empty resource collection that will be populated during
    /// the metadata loading process. The container maintains a reference to the
    /// source file for efficient data access.
    ///
    /// # Arguments
    ///
    /// * `file` - Arc-wrapped reference to the originally loaded PE file,
    ///   used for accessing embedded resource data
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::Resources;
    /// use dotscope::File;
    /// use std::sync::Arc;
    ///
    /// let file = Arc::new(File::from_path("tests/samples/crafted_2.exe")?);
    /// let resources = Resources::new(file);
    /// assert!(resources.is_empty());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new(file: Arc<File>) -> Self {
        Resources {
            file,
            data: SkipMap::new(),
        }
    }

    /// Gets a resource by name.
    ///
    /// Returns the first resource in table order with the specified name, as a
    /// cloned reference-counted pointer. The collection is keyed by row, so
    /// this walks it; an assembly declares few resources.
    ///
    /// # Arguments
    ///
    /// * `name` - The exact name of the resource to look for (case-sensitive)
    ///
    /// # Returns
    ///
    /// - `Some(ManifestResourceRc)` if a resource with the given name exists
    /// - `None` if no resource with the given name is found
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Look for specific resources
    /// if let Some(config) = resources.get("app.config") {
    ///     println!("Found configuration resource: {}", config.name);
    /// }
    ///
    /// if let Some(icon) = resources.get("app.ico") {
    ///     println!("Found icon resource: {} ({} bytes)",
    ///              icon.name, icon.data_size);
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ManifestResourceRc> {
        self.data
            .iter()
            .find(|entry| entry.value().name == name)
            .map(|entry| entry.value().clone())
    }

    /// Gets a reference to all resources for advanced iteration patterns.
    ///
    /// Returns a direct reference to the internal map for advanced use cases
    /// that require direct map operations. For simple iteration, prefer using the
    /// [`iter()`](Resources::iter) method or the `IntoIterator` implementation.
    ///
    /// # Returns
    ///
    /// A reference to the internal `SkipMap<Token, ManifestResourceRc>`, keyed
    /// by `ManifestResource` token
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Advanced map operations
    /// let all_resources = resources.all();
    /// let resource_names: Vec<String> = all_resources.iter()
    ///     .map(|entry| entry.value().name.clone())
    ///     .collect();
    ///
    /// println!("All resource names: {:?}", resource_names);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn all(&self) -> &SkipMap<Token, ManifestResourceRc> {
        &self.data
    }

    /// Get a slice to the data of a resource with bounds checking and safety guarantees.
    ///
    /// Attempts to access the actual data bytes of a resource. Currently supports
    /// embedded resources only; linked files and assembly references will return
    /// `None` until future implementation.
    ///
    /// The method performs comprehensive bounds checking to ensure safe access to
    /// the resource data without buffer overruns.
    ///
    /// # Arguments
    ///
    /// * `resource` - The manifest resource to read data from
    ///
    /// # Returns
    ///
    /// - `Some(&[u8])` containing the resource data for embedded resources
    /// - `None` for linked files, assembly references, or if bounds checking fails
    ///
    /// # Resource Types
    ///
    /// - **Embedded (Supported)**: Data stored directly in the assembly
    /// - **Linked Files (Future)**: External files referenced by the assembly
    /// - **Assembly References (Future)**: Resources in other .NET assemblies
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// for resource_entry in resources.iter() {
    ///     let resource = resource_entry.value();
    ///
    ///     match resources.get_data(&resource) {
    ///         Some(data) => {
    ///             println!("Resource '{}': {} bytes of data available",
    ///                      resource.name, data.len());
    ///
    ///             // Analyze resource content
    ///             if let Ok(text) = std::str::from_utf8(data) {
    ///                 if text.len() <= 100 {
    ///                     println!("  Content preview: {}", text);
    ///                 }
    ///             }
    ///         }
    ///         None => {
    ///             println!("Resource '{}': data not accessible (external resource)",
    ///                      resource.name);
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn get_data(&self, resource: &ManifestResourceRc) -> Option<&[u8]> {
        match resource.source {
            // ToDo: The only case we currently handle, is if the resource is embedded in the current file.
            //       Other cases, like File or AssemblyRef, will require us to implement loading multiple binaries
            //       and reading the data from there
            None => self
                .file
                .data_slice(resource.data_offset, resource.data_size)
                .ok(),
            _ => None,
        }
    }

    /// Parse a .NET resource file with zero-copy semantics.
    ///
    /// Parses a .NET `.resources` file, returning a map of resource names to their entries.
    /// String and byte array data are borrowed directly from the source buffer without
    /// allocation, enabling efficient handling of large embedded resources.
    ///
    /// # Arguments
    ///
    /// * `resource` - The manifest resource to parse (must be a .resources file)
    ///
    /// # Returns
    ///
    /// A `BTreeMap` containing all parsed resources with borrowed data, or `None` if
    /// the resource data is not accessible or parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::metadata::resources::ResourceTypeRef;
    /// use dotscope::CilObject;
    ///
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resources = assembly.resources();
    ///
    /// // Find .resources files
    /// for entry in resources.iter() {
    ///     let resource = entry.value();
    ///
    ///     if resource.name.ends_with(".resources") {
    ///         // Zero-copy parsing!
    ///         if let Some(parsed) = resources.parse_dotnet_resource(&resource) {
    ///             println!("Found {} embedded items in {}", parsed.len(), resource.name);
    ///
    ///             for (name, item) in &parsed {
    ///                 match &item.data {
    ///                     ResourceTypeRef::ByteArray(bytes) => {
    ///                         if bytes.starts_with(b"PK\x03\x04") {
    ///                             println!("  ZIP archive '{}': {} bytes (no copy!)",
    ///                                      name, bytes.len());
    ///                         }
    ///                     }
    ///                     ResourceTypeRef::String(s) => {
    ///                         println!("  String '{}': {}", name, s);
    ///                     }
    ///                     _ => {}
    ///                 }
    ///             }
    ///         }
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn parse_dotnet_resource<'a>(
        &'a self,
        resource: &ManifestResourceRc,
    ) -> Option<BTreeMap<String, ResourceEntryRef<'a>>> {
        let raw_data = self.get_data(resource)?;
        parse_dotnet_resource_ref(raw_data).ok()
    }

    /// Inserts a manifest resource into the collection.
    ///
    /// This method is typically called by the `ManifestResource` table loader during
    /// the metadata parsing process. It performs an atomic insertion that doesn't
    /// block concurrent readers.
    ///
    /// # Arguments
    ///
    /// * `resource` - The manifest resource to insert into the collection
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple
    /// threads without synchronization. The insertion is atomic and won't interfere
    /// with ongoing read operations.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::sync::Arc;
    /// use dotscope::metadata::resources::Resources;
    /// use dotscope::{CilObject, File};
    ///
    /// // This is typically called internally during metadata loading: here a
    /// // resource the loaded assembly holds goes into a fresh collection
    /// let assembly = CilObject::from_path("tests/samples/WindowsBase.dll")?;
    /// let resource = assembly.resources().iter().next().expect("a resource").value().clone();
    /// let resources = Resources::new(Arc::new(File::from_path("tests/samples/WindowsBase.dll")?));
    /// resources.insert(resource);
    /// assert_eq!(resources.len(), 1);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn insert(&self, resource: ManifestResourceRc) {
        self.data.insert(resource.token, resource);
    }

    /// Returns the number of resources in the collection.
    ///
    /// This operation is thread-safe and provides an exact count of resources
    /// currently stored in the collection.
    ///
    /// # Returns
    ///
    /// The total number of resources in the collection
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// let count = resources.len();
    /// if count > 0 {
    ///     println!("Assembly contains {} resources", count);
    /// } else {
    ///     println!("Assembly contains no embedded resources");
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns true if there are no resources in the collection.
    ///
    /// This is equivalent to checking if `len() == 0` but may be more efficient
    /// and provides better semantic clarity for emptiness checks.
    ///
    /// # Returns
    ///
    /// `true` if the collection contains no resources, `false` otherwise
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// if resources.is_empty() {
    ///     println!("This assembly has no embedded resources");
    /// } else {
    ///     println!("This assembly has {} resources", resources.len());
    ///
    ///     // Process resources...
    ///     for resource_entry in resources.iter() {
    ///         let resource = resource_entry.value();
    ///         println!("  - {}", resource.name);
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over all resources, in `ManifestResource` table order.
    ///
    /// The order is the one the assembly declares them in, which is the order
    /// `Assembly.GetManifestResourceNames` reports and the order a rewritten
    /// assembly keeps. The iterator is thread-safe and can run concurrently
    /// with other operations on the same `Resources` instance.
    ///
    /// # Returns
    ///
    /// An iterator over entries whose [`key`](Entry::key) is the resource's
    /// `ManifestResource` token and whose [`value`](Entry::value) is its row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("tests/samples/WindowsBase.dll"))?;
    /// let resources = assembly.resources();
    ///
    /// // Iterate over all resources
    /// for resource_entry in resources.iter() {
    ///     let resource = resource_entry.value();
    ///
    ///     println!("Resource: {} (Offset: 0x{:X}, Size: {} bytes)",
    ///              resource.name, resource.data_offset, resource.data_size);
    ///     
    ///     // Check resource properties
    ///     if resource.flags.contains(dotscope::metadata::tables::ManifestResourceAttributes::PUBLIC) {
    ///         println!("  - Public resource");
    ///     }
    /// }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn iter(&self) -> Iter<'_, Token, ManifestResourceRc> {
        self.data.iter()
    }
}

impl<'a> IntoIterator for &'a Resources {
    type Item = Entry<'a, Token, ManifestResourceRc>;
    type IntoIter = Iter<'a, Token, ManifestResourceRc>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{
            resources::parser::{parse_dotnet_resource, parse_dotnet_resource_ref},
            tables::{ManifestResource, ManifestResourceAttributes},
        },
        testkit::helpers::test_assembly_arc,
    };

    #[test]
    fn resources_come_back_in_table_order() {
        let resources = Resources::new(test_assembly_arc().file().clone());
        // Inserted last row first, the way parallel loading can deliver them.
        for rid in (1..=32u32).rev() {
            resources.insert(Arc::new(ManifestResource {
                rid,
                token: Token::new(0x2800_0000 | rid),
                offset: 0,
                data_offset: 0,
                data_size: 0,
                flags: ManifestResourceAttributes::PUBLIC,
                name: format!("resource{rid}"),
                source: None,
            }));
        }

        let rids: Vec<u32> = resources.iter().map(|entry| entry.value().rid).collect();
        assert_eq!(rids, (1..=32).collect::<Vec<_>>());
        assert_eq!(
            resources.get("resource7").map(|resource| resource.rid),
            Some(7)
        );
    }

    /// Helper trait to abstract over owned (ResourceType) and borrowed (ResourceTypeRef) variants.
    /// This allows writing generic test code that works with both.
    trait ResourceData {
        fn as_string(&self) -> Option<&str>;
        fn as_bool(&self) -> Option<bool>;
        fn as_byte(&self) -> Option<u8>;
        fn as_sbyte(&self) -> Option<i8>;
        fn as_char(&self) -> Option<char>;
        fn as_int16(&self) -> Option<i16>;
        fn as_uint16(&self) -> Option<u16>;
        fn as_int32(&self) -> Option<i32>;
        fn as_uint32(&self) -> Option<u32>;
        fn as_int64(&self) -> Option<i64>;
        fn as_uint64(&self) -> Option<u64>;
        fn as_single(&self) -> Option<f32>;
        fn as_double(&self) -> Option<f64>;
        fn as_bytes(&self) -> Option<&[u8]>;
        fn as_stream(&self) -> Option<&[u8]>;
        fn as_decimal(&self) -> Option<(i32, i32, i32, i32)>;
        fn as_datetime(&self) -> Option<i64>;
        fn as_timespan(&self) -> Option<i64>;
    }

    impl ResourceData for ResourceType {
        fn as_string(&self) -> Option<&str> {
            match self {
                ResourceType::String(s) => Some(s),
                _ => None,
            }
        }
        fn as_bool(&self) -> Option<bool> {
            match self {
                ResourceType::Boolean(b) => Some(*b),
                _ => None,
            }
        }
        fn as_byte(&self) -> Option<u8> {
            match self {
                ResourceType::Byte(b) => Some(*b),
                _ => None,
            }
        }
        fn as_sbyte(&self) -> Option<i8> {
            match self {
                ResourceType::SByte(b) => Some(*b),
                _ => None,
            }
        }
        fn as_char(&self) -> Option<char> {
            match self {
                ResourceType::Char(c) => Some(*c),
                _ => None,
            }
        }
        fn as_int16(&self) -> Option<i16> {
            match self {
                ResourceType::Int16(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint16(&self) -> Option<u16> {
            match self {
                ResourceType::UInt16(i) => Some(*i),
                _ => None,
            }
        }
        fn as_int32(&self) -> Option<i32> {
            match self {
                ResourceType::Int32(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint32(&self) -> Option<u32> {
            match self {
                ResourceType::UInt32(i) => Some(*i),
                _ => None,
            }
        }
        fn as_int64(&self) -> Option<i64> {
            match self {
                ResourceType::Int64(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint64(&self) -> Option<u64> {
            match self {
                ResourceType::UInt64(i) => Some(*i),
                _ => None,
            }
        }
        fn as_single(&self) -> Option<f32> {
            match self {
                ResourceType::Single(f) => Some(*f),
                _ => None,
            }
        }
        fn as_double(&self) -> Option<f64> {
            match self {
                ResourceType::Double(f) => Some(*f),
                _ => None,
            }
        }
        fn as_bytes(&self) -> Option<&[u8]> {
            match self {
                ResourceType::ByteArray(b) => Some(b),
                _ => None,
            }
        }
        fn as_stream(&self) -> Option<&[u8]> {
            match self {
                ResourceType::Stream(b) => Some(b),
                _ => None,
            }
        }
        fn as_decimal(&self) -> Option<(i32, i32, i32, i32)> {
            match self {
                ResourceType::Decimal { lo, mid, hi, flags } => Some((*lo, *mid, *hi, *flags)),
                _ => None,
            }
        }
        fn as_datetime(&self) -> Option<i64> {
            match self {
                ResourceType::DateTime(dt) => Some(*dt),
                _ => None,
            }
        }
        fn as_timespan(&self) -> Option<i64> {
            match self {
                ResourceType::TimeSpan(ts) => Some(*ts),
                _ => None,
            }
        }
    }

    impl ResourceData for ResourceTypeRef<'_> {
        fn as_string(&self) -> Option<&str> {
            match self {
                ResourceTypeRef::String(s) => Some(s),
                _ => None,
            }
        }
        fn as_bool(&self) -> Option<bool> {
            match self {
                ResourceTypeRef::Boolean(b) => Some(*b),
                _ => None,
            }
        }
        fn as_byte(&self) -> Option<u8> {
            match self {
                ResourceTypeRef::Byte(b) => Some(*b),
                _ => None,
            }
        }
        fn as_sbyte(&self) -> Option<i8> {
            match self {
                ResourceTypeRef::SByte(b) => Some(*b),
                _ => None,
            }
        }
        fn as_char(&self) -> Option<char> {
            match self {
                ResourceTypeRef::Char(c) => Some(*c),
                _ => None,
            }
        }
        fn as_int16(&self) -> Option<i16> {
            match self {
                ResourceTypeRef::Int16(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint16(&self) -> Option<u16> {
            match self {
                ResourceTypeRef::UInt16(i) => Some(*i),
                _ => None,
            }
        }
        fn as_int32(&self) -> Option<i32> {
            match self {
                ResourceTypeRef::Int32(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint32(&self) -> Option<u32> {
            match self {
                ResourceTypeRef::UInt32(i) => Some(*i),
                _ => None,
            }
        }
        fn as_int64(&self) -> Option<i64> {
            match self {
                ResourceTypeRef::Int64(i) => Some(*i),
                _ => None,
            }
        }
        fn as_uint64(&self) -> Option<u64> {
            match self {
                ResourceTypeRef::UInt64(i) => Some(*i),
                _ => None,
            }
        }
        fn as_single(&self) -> Option<f32> {
            match self {
                ResourceTypeRef::Single(f) => Some(*f),
                _ => None,
            }
        }
        fn as_double(&self) -> Option<f64> {
            match self {
                ResourceTypeRef::Double(f) => Some(*f),
                _ => None,
            }
        }
        fn as_bytes(&self) -> Option<&[u8]> {
            match self {
                ResourceTypeRef::ByteArray(b) => Some(b),
                _ => None,
            }
        }
        fn as_stream(&self) -> Option<&[u8]> {
            match self {
                ResourceTypeRef::Stream(b) => Some(b),
                _ => None,
            }
        }
        fn as_decimal(&self) -> Option<(i32, i32, i32, i32)> {
            match self {
                ResourceTypeRef::Decimal { lo, mid, hi, flags } => Some((*lo, *mid, *hi, *flags)),
                _ => None,
            }
        }
        fn as_datetime(&self) -> Option<i64> {
            match self {
                ResourceTypeRef::DateTime(dt) => Some(*dt),
                _ => None,
            }
        }
        fn as_timespan(&self) -> Option<i64> {
            match self {
                ResourceTypeRef::TimeSpan(ts) => Some(*ts),
                _ => None,
            }
        }
    }

    /// Macro to generate a test that runs both owned and ref variants
    macro_rules! test_both_variants {
        ($test_name:ident, $body:expr) => {
            #[test]
            fn $test_name() {
                let test_fn = $body;
                test_fn(false); // owned variant
                test_fn(true); // ref variant
            }
        };
    }

    /// Return type for parse_resources helper
    type ParsedResources<'a> = (
        Option<BTreeMap<String, ResourceEntry>>,
        Option<BTreeMap<String, ResourceEntryRef<'a>>>,
    );

    /// Helper to parse resources in either owned or ref mode
    fn parse_resources<'a>(data: &'a [u8], use_ref: bool) -> ParsedResources<'a> {
        if use_ref {
            (None, Some(parse_dotnet_resource_ref(data).unwrap()))
        } else {
            (Some(parse_dotnet_resource(data).unwrap()), None)
        }
    }

    /// Helper macro to get resource data from either owned or ref map
    macro_rules! get_resource_data {
        ($owned:expr, $borrowed:expr, $key:expr) => {
            if let Some(ref map) = $owned {
                &map[$key].data as &dyn ResourceData
            } else if let Some(ref map) = $borrowed {
                &map[$key].data as &dyn ResourceData
            } else {
                panic!("No resource map available")
            }
        };
    }

    /// Helper macro to get resource count from either owned or ref map
    macro_rules! get_resource_count {
        ($owned:expr, $borrowed:expr) => {
            if let Some(ref map) = $owned {
                map.len()
            } else if let Some(ref map) = $borrowed {
                map.len()
            } else {
                panic!("No resource map available")
            }
        };
    }

    test_both_variants!(test_string_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("TestString", "Hello, World!").unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 1);

        let data = get_resource_data!(owned, borrowed, "TestString");
        assert_eq!(data.as_string().unwrap(), "Hello, World!");
    });

    test_both_variants!(test_multiple_types_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("StringRes", "Test").unwrap();
        encoder.add_int32("IntRes", 42).unwrap();
        encoder.add_boolean("BoolRes", true).unwrap();
        encoder.add_byte_array("ByteRes", &[1, 2, 3, 4]).unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 4);

        assert_eq!(
            get_resource_data!(owned, borrowed, "StringRes")
                .as_string()
                .unwrap(),
            "Test"
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "IntRes")
                .as_int32()
                .unwrap(),
            42
        );
        assert!(get_resource_data!(owned, borrowed, "BoolRes")
            .as_bool()
            .unwrap());
        assert_eq!(
            get_resource_data!(owned, borrowed, "ByteRes")
                .as_bytes()
                .unwrap(),
            &[1, 2, 3, 4]
        );
    });

    test_both_variants!(test_all_primitive_types_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        encoder.add_boolean("bool_true", true).unwrap();
        encoder.add_boolean("bool_false", false).unwrap();
        encoder.add_byte("byte_val", 255).unwrap();
        encoder.add_sbyte("sbyte_val", -128).unwrap();
        encoder.add_char("char_val", 'A').unwrap();
        encoder.add_int16("int16_val", -32768).unwrap();
        encoder.add_uint16("uint16_val", 65535).unwrap();
        encoder.add_int32("int32_val", -2147483648).unwrap();
        encoder.add_uint32("uint32_val", 4294967295).unwrap();
        encoder
            .add_int64("int64_val", -9223372036854775808i64)
            .unwrap();
        encoder
            .add_uint64("uint64_val", 18446744073709551615u64)
            .unwrap();
        encoder
            .add_single("single_val", std::f32::consts::PI)
            .unwrap();
        encoder
            .add_double("double_val", std::f64::consts::E)
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 13);

        assert!(get_resource_data!(owned, borrowed, "bool_true")
            .as_bool()
            .unwrap());
        assert!(!get_resource_data!(owned, borrowed, "bool_false")
            .as_bool()
            .unwrap());
        assert_eq!(
            get_resource_data!(owned, borrowed, "byte_val")
                .as_byte()
                .unwrap(),
            255
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "sbyte_val")
                .as_sbyte()
                .unwrap(),
            -128
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "char_val")
                .as_char()
                .unwrap(),
            'A'
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "int16_val")
                .as_int16()
                .unwrap(),
            -32768
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "uint16_val")
                .as_uint16()
                .unwrap(),
            65535
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "int32_val")
                .as_int32()
                .unwrap(),
            -2147483648
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "uint32_val")
                .as_uint32()
                .unwrap(),
            4294967295
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "int64_val")
                .as_int64()
                .unwrap(),
            -9223372036854775808i64
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "uint64_val")
                .as_uint64()
                .unwrap(),
            18446744073709551615u64
        );
        assert!(
            (get_resource_data!(owned, borrowed, "single_val")
                .as_single()
                .unwrap()
                - std::f32::consts::PI)
                .abs()
                < 1e-5
        );
        assert!(
            (get_resource_data!(owned, borrowed, "double_val")
                .as_double()
                .unwrap()
                - std::f64::consts::E)
                .abs()
                < 1e-14
        );
    });

    test_both_variants!(test_string_edge_cases_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        encoder.add_string("empty", "").unwrap();
        encoder.add_string("single_char", "X").unwrap();
        encoder.add_string("basic_ascii", "Hello World").unwrap();
        encoder
            .add_string("medium_string", &"A".repeat(100))
            .unwrap();
        encoder.add_string("special_chars", "\n\r\t\\\"'").unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 5);

        assert_eq!(
            get_resource_data!(owned, borrowed, "empty")
                .as_string()
                .unwrap(),
            ""
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "single_char")
                .as_string()
                .unwrap(),
            "X"
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "basic_ascii")
                .as_string()
                .unwrap(),
            "Hello World"
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "medium_string")
                .as_string()
                .unwrap(),
            &"A".repeat(100)
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "special_chars")
                .as_string()
                .unwrap(),
            "\n\r\t\\\"'"
        );
    });

    test_both_variants!(test_byte_array_edge_cases_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        encoder.add_byte_array("empty", &[]).unwrap();
        encoder.add_byte_array("single_byte", &[42]).unwrap();
        encoder.add_byte_array("all_zeros", &[0; 100]).unwrap();
        encoder.add_byte_array("all_ones", &[255; 50]).unwrap();
        encoder
            .add_byte_array("pattern", &(0u8..=255).collect::<Vec<_>>())
            .unwrap();
        encoder
            .add_byte_array("large", &vec![123u8; 10000])
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 6);

        assert_eq!(
            get_resource_data!(owned, borrowed, "empty")
                .as_bytes()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "single_byte")
                .as_bytes()
                .unwrap(),
            &[42]
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "all_zeros")
                .as_bytes()
                .unwrap(),
            &[0; 100]
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "all_ones")
                .as_bytes()
                .unwrap(),
            &[255; 50]
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "pattern")
                .as_bytes()
                .unwrap(),
            &(0u8..=255).collect::<Vec<_>>()[..]
        );

        let large_bytes = get_resource_data!(owned, borrowed, "large")
            .as_bytes()
            .unwrap();
        assert_eq!(large_bytes.len(), 10000);
        assert!(large_bytes.iter().all(|&b| b == 123));
    });

    test_both_variants!(test_stream_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        encoder.add_stream("empty_stream", &[]).unwrap();
        encoder
            .add_stream("image_data", &[0x89, 0x50, 0x4E, 0x47])
            .unwrap();
        encoder
            .add_stream("large_stream", &vec![0xAB; 5000])
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 3);

        assert_eq!(
            get_resource_data!(owned, borrowed, "empty_stream")
                .as_stream()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "image_data")
                .as_stream()
                .unwrap(),
            &[0x89, 0x50, 0x4E, 0x47]
        );

        let large_stream = get_resource_data!(owned, borrowed, "large_stream")
            .as_stream()
            .unwrap();
        assert_eq!(large_stream.len(), 5000);
        assert!(large_stream.iter().all(|&b| b == 0xAB));
    });

    test_both_variants!(test_decimal_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        encoder
            .add_decimal("positive", 3261, 0, 0, 0x0003_0000)
            .unwrap();
        #[allow(clippy::cast_possible_wrap)]
        encoder
            .add_decimal("negative", 12345, 0, 0, 0x8002_0000_u32 as i32)
            .unwrap();
        encoder
            .add_decimal("large", i32::MAX, i32::MAX, 100, 0x0000_0000)
            .unwrap();
        encoder.add_decimal("zero", 0, 0, 0, 0).unwrap();
        encoder
            .add_decimal("max_scale", 1, 0, 0, 0x001C_0000)
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 5);

        assert_eq!(
            get_resource_data!(owned, borrowed, "positive")
                .as_decimal()
                .unwrap(),
            (3261, 0, 0, 0x0003_0000)
        );
        #[allow(clippy::cast_possible_wrap)]
        let expected_neg_flags = 0x8002_0000_u32 as i32;
        assert_eq!(
            get_resource_data!(owned, borrowed, "negative")
                .as_decimal()
                .unwrap(),
            (12345, 0, 0, expected_neg_flags)
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "large")
                .as_decimal()
                .unwrap(),
            (i32::MAX, i32::MAX, 100, 0)
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "zero")
                .as_decimal()
                .unwrap(),
            (0, 0, 0, 0)
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "max_scale")
                .as_decimal()
                .unwrap(),
            (1, 0, 0, 0x001C_0000)
        );
    });

    test_both_variants!(test_datetime_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        let ticks_2024: i64 = 638_396_736_000_000_000;
        let utc_kind: i64 = 1 << 62;
        let local_kind: i64 = 2 << 62;
        let large_ticks: i64 = 3_155_378_975_999_999_999;

        encoder
            .add_datetime("utc_date", ticks_2024 | utc_kind)
            .unwrap();
        encoder
            .add_datetime("local_date", ticks_2024 | local_kind)
            .unwrap();
        encoder
            .add_datetime("unspecified_date", ticks_2024)
            .unwrap();
        encoder.add_datetime("min_date", 0).unwrap();
        encoder.add_datetime("large_date", large_ticks).unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 5);

        let utc_binary = get_resource_data!(owned, borrowed, "utc_date")
            .as_datetime()
            .unwrap();
        assert_eq!(utc_binary, ticks_2024 | utc_kind);
        assert_eq!((utc_binary >> 62) & 0x3, 1); // UTC kind

        let local_binary = get_resource_data!(owned, borrowed, "local_date")
            .as_datetime()
            .unwrap();
        assert_eq!((local_binary >> 62) & 0x3, 2); // Local kind

        let unspec_binary = get_resource_data!(owned, borrowed, "unspecified_date")
            .as_datetime()
            .unwrap();
        assert_eq!((unspec_binary >> 62) & 0x3, 0); // Unspecified kind

        assert_eq!(
            get_resource_data!(owned, borrowed, "min_date")
                .as_datetime()
                .unwrap(),
            0
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "large_date")
                .as_datetime()
                .unwrap(),
            large_ticks
        );
    });

    test_both_variants!(test_timespan_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        const TICKS_PER_MILLISECOND: i64 = 10_000;
        const TICKS_PER_SECOND: i64 = 10_000_000;
        const TICKS_PER_MINUTE: i64 = 600_000_000;
        const TICKS_PER_HOUR: i64 = 36_000_000_000;
        const TICKS_PER_DAY: i64 = 864_000_000_000;

        encoder.add_timespan("one_hour", TICKS_PER_HOUR).unwrap();
        encoder
            .add_timespan("thirty_seconds", 30 * TICKS_PER_SECOND)
            .unwrap();
        encoder
            .add_timespan("negative_5min", -5 * TICKS_PER_MINUTE)
            .unwrap();
        encoder.add_timespan("zero", 0).unwrap();

        let complex_span = TICKS_PER_DAY
            + 2 * TICKS_PER_HOUR
            + 3 * TICKS_PER_MINUTE
            + 4 * TICKS_PER_SECOND
            + 5 * TICKS_PER_MILLISECOND;
        encoder.add_timespan("complex", complex_span).unwrap();
        encoder.add_timespan("max", i64::MAX).unwrap();
        encoder.add_timespan("min", i64::MIN).unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 7);

        assert_eq!(
            get_resource_data!(owned, borrowed, "one_hour")
                .as_timespan()
                .unwrap(),
            TICKS_PER_HOUR
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "thirty_seconds")
                .as_timespan()
                .unwrap(),
            30 * TICKS_PER_SECOND
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "negative_5min")
                .as_timespan()
                .unwrap(),
            -5 * TICKS_PER_MINUTE
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "zero")
                .as_timespan()
                .unwrap(),
            0
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "complex")
                .as_timespan()
                .unwrap(),
            complex_span
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "max")
                .as_timespan()
                .unwrap(),
            i64::MAX
        );
        assert_eq!(
            get_resource_data!(owned, borrowed, "min")
                .as_timespan()
                .unwrap(),
            i64::MIN
        );
    });

    test_both_variants!(test_mixed_large_resource_set_roundtrip, |use_ref: bool| {
        let mut encoder = DotNetResourceEncoder::new();

        for i in 0..100 {
            match i % 13 {
                0 => encoder
                    .add_string(&format!("str_{i}"), &format!("String value {i}"))
                    .unwrap(),
                1 => encoder
                    .add_boolean(&format!("bool_{i}"), i % 2 == 0)
                    .unwrap(),
                2 => encoder
                    .add_byte(&format!("byte_{i}"), (i % 256) as u8)
                    .unwrap(),
                3 => encoder
                    .add_sbyte(
                        &format!("sbyte_{i}"),
                        ((i % 256) as u8).wrapping_sub(128) as i8,
                    )
                    .unwrap(),
                4 => encoder
                    .add_char(
                        &format!("char_{i}"),
                        char::from_u32((65 + (i % 26)) as u32).unwrap(),
                    )
                    .unwrap(),
                5 => encoder
                    .add_int16(&format!("int16_{i}"), ((i % 32768) as i16) - 16384)
                    .unwrap(),
                6 => encoder
                    .add_uint16(&format!("uint16_{i}"), (i % 65536) as u16)
                    .unwrap(),
                7 => encoder
                    .add_int32(&format!("int32_{i}"), i as i32 - 50)
                    .unwrap(),
                8 => encoder
                    .add_uint32(&format!("uint32_{i}"), i as u32 * 1000)
                    .unwrap(),
                9 => encoder
                    .add_int64(&format!("int64_{i}"), (i as i64) * 1000000)
                    .unwrap(),
                10 => encoder
                    .add_uint64(&format!("uint64_{i}"), (i as u64) * 2000000)
                    .unwrap(),
                11 => encoder
                    .add_single(&format!("single_{i}"), i as f32 * 0.1)
                    .unwrap(),
                12 => encoder
                    .add_byte_array(&format!("bytes_{i}"), &vec![i as u8; i % 20 + 1])
                    .unwrap(),
                _ => unreachable!(),
            }
        }

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let (owned, borrowed) = parse_resources(&encoded_data, use_ref);

        assert_eq!(get_resource_count!(owned, borrowed), 100);

        assert_eq!(
            get_resource_data!(owned, borrowed, "str_0")
                .as_string()
                .unwrap(),
            "String value 0"
        );
        assert!(!get_resource_data!(owned, borrowed, "bool_1")
            .as_bool()
            .unwrap());

        let bytes_64 = get_resource_data!(owned, borrowed, "bytes_64")
            .as_bytes()
            .unwrap();
        assert_eq!(bytes_64.len(), 64 % 20 + 1);
        assert!(bytes_64.iter().all(|&b| b == 64));
    });

    #[test]
    fn test_large_byte_array_zero_copy() {
        let mut encoder = DotNetResourceEncoder::new();
        let large_data = vec![0xAB; 10 * 1024 * 1024];
        encoder
            .add_byte_array("LargeResource", &large_data)
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource_ref(&encoded_data).unwrap();

        assert_eq!(parsed_resources.len(), 1);

        match &parsed_resources["LargeResource"].data {
            ResourceTypeRef::ByteArray(bytes) => {
                assert_eq!(bytes.len(), 10 * 1024 * 1024);

                // Verify zero-copy: bytes should point into encoded_data buffer
                let encoded_ptr = encoded_data.as_ptr() as usize;
                let bytes_ptr = bytes.as_ptr() as usize;
                assert!(
                    bytes_ptr >= encoded_ptr && bytes_ptr < encoded_ptr + encoded_data.len(),
                    "Bytes should be borrowed from encoded_data buffer (zero-copy)"
                );

                assert_eq!(bytes[0], 0xAB);
                assert_eq!(bytes[bytes.len() - 1], 0xAB);
            }
            _ => panic!("Expected byte array resource"),
        }
    }

    #[test]
    fn test_string_zero_copy_verification() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder
            .add_string(
                "TestString",
                "This is a test string for zero-copy verification",
            )
            .unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();
        let parsed_resources = parse_dotnet_resource_ref(&encoded_data).unwrap();

        match &parsed_resources["TestString"].data {
            ResourceTypeRef::String(s) => {
                // Verify zero-copy: string should point into encoded_data buffer
                let encoded_ptr = encoded_data.as_ptr() as usize;
                let str_ptr = s.as_ptr() as usize;
                assert!(
                    str_ptr >= encoded_ptr && str_ptr < encoded_ptr + encoded_data.len(),
                    "String should be borrowed from encoded_data buffer (zero-copy)"
                );

                assert_eq!(*s, "This is a test string for zero-copy verification");
            }
            _ => panic!("Expected string resource"),
        }
    }

    #[test]
    fn test_owned_vs_ref_equivalence() {
        let mut encoder = DotNetResourceEncoder::new();
        encoder.add_string("str", "Hello").unwrap();
        encoder.add_int32("int", 42).unwrap();
        encoder.add_byte_array("bytes", &[1, 2, 3, 4, 5]).unwrap();

        let encoded_data = encoder.encode_dotnet_format().unwrap();

        let owned = parse_dotnet_resource(&encoded_data).unwrap();
        let borrowed = parse_dotnet_resource_ref(&encoded_data).unwrap();

        assert_eq!(owned.len(), borrowed.len());

        // String comparison
        match (&owned["str"].data, &borrowed["str"].data) {
            (ResourceType::String(s1), ResourceTypeRef::String(s2)) => {
                assert_eq!(s1, s2);
            }
            _ => panic!("Type mismatch"),
        }

        // Int comparison
        match (&owned["int"].data, &borrowed["int"].data) {
            (ResourceType::Int32(i1), ResourceTypeRef::Int32(i2)) => {
                assert_eq!(i1, i2);
            }
            _ => panic!("Type mismatch"),
        }

        // Bytes comparison
        match (&owned["bytes"].data, &borrowed["bytes"].data) {
            (ResourceType::ByteArray(b1), ResourceTypeRef::ByteArray(b2)) => {
                assert_eq!(b1.as_slice(), *b2);
            }
            _ => panic!("Type mismatch"),
        }
    }
}
