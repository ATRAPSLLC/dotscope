//! # ManifestResource Builder
//!
//! Provides a fluent API for building ManifestResource table entries that describe resources in .NET assemblies.
//! The ManifestResource table contains information about resources embedded in or linked to assemblies,
//! supporting multiple resource storage models including embedded resources, file-based resources, and
//! resources in external assemblies.
//!
//! ## Overview
//!
//! The `ManifestResourceBuilder` enables creation of resource entries with:
//! - Resource name specification (required)
//! - Resource visibility configuration (public/private)
//! - Resource location setup (embedded, file-based, or external assembly)
//! - Offset management for embedded resources
//! - Automatic heap management and token generation
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create an embedded resource
//! let embedded_token = ManifestResourceBuilder::new()
//!     .name("MyApp.Resources.strings.resources")
//!     .public()
//!     .offset(0x1000)
//!     .build(&mut assembly)?;
//!
//! // Create a file-based resource
//! let file_ref = FileBuilder::new()
//!     .name("Resources.resources")
//!     .contains_no_metadata()
//!     .build(&mut assembly)?;
//!
//! let file_resource_token = ManifestResourceBuilder::new()
//!     .name("MyApp.FileResources")
//!     .private()
//!     .implementation_file(file_ref.placeholder())
//!     .build(&mut assembly)?;
//!
//! // Create an external assembly resource
//! let assembly_ref = AssemblyRefBuilder::new()
//!     .name("MyApp.Resources")
//!     .version(1, 0, 0, 0)
//!     .build(&mut assembly)?;
//!
//! let external_resource_token = ManifestResourceBuilder::new()
//!     .name("MyApp.ExternalResources")
//!     .public()
//!     .implementation_assembly_ref(assembly_ref.placeholder())
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Resource name is required
//! - **Heap Management**: Strings are automatically added to heaps
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Implementation Support**: Methods for embedded, file-based, and external resources

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        resources::DotNetResourceEncoder,
        tables::{
            CodedIndex, CodedIndexType, ManifestResourceAttributes, ManifestResourceRaw,
            TableDataOwned, TableId,
        },
        token::Token,
    },
    Error, Result,
};

/// Represents the implementation target for a ManifestResource entry.
///
/// This enum captures both the row index (which can be a placeholder or actual row ID)
/// and the target table type. The `CodedIndex` is constructed at write time, not at
/// builder time, to ensure proper placeholder resolution.
#[derive(Debug, Clone, Copy)]
enum ResourceImplementationTarget {
    /// Resource is embedded in the assembly (null implementation)
    Embedded,
    /// Reference to a File table entry (file-based resource)
    File(u32),
    /// Reference to an AssemblyRef table entry (external assembly resource)
    AssemblyRef(u32),
}

/// Builder for creating ManifestResource table entries.
///
/// `ManifestResourceBuilder` provides a fluent API for creating entries in the ManifestResource
/// metadata table, which contains information about resources embedded in or linked to assemblies.
///
/// # Purpose
///
/// The ManifestResource table serves several key functions:
/// - **Resource Management**: Defines resources available in the assembly
/// - **Location Tracking**: Specifies where resource data is stored
/// - **Access Control**: Controls resource visibility and accessibility
/// - **Globalization Support**: Enables localized resource access
/// - **Multi-assembly Resources**: Supports resources in external assemblies
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing ManifestResource entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// let resource_token = ManifestResourceBuilder::new()
///     .name("MyApp.Resources.strings")
///     .public()
///     .offset(0x1000)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Name Required**: A resource name must be provided
/// - **Name Not Empty**: Resource names cannot be empty strings
/// - **Implementation Consistency**: Only one implementation type can be set
///
/// # Integration
///
/// ManifestResource entries integrate with other metadata structures:
/// - **File**: External file-based resources reference File table entries
/// - **AssemblyRef**: External assembly resources reference AssemblyRef entries
/// - **Resource Data**: Embedded resources reference assembly resource sections
#[derive(Debug, Clone)]
pub struct ManifestResourceBuilder {
    /// The name of the resource
    name: Option<String>,
    /// Resource visibility and access flags
    flags: ManifestResourceAttributes,
    /// Offset for embedded resources
    offset: u32,
    /// Implementation target capturing the row index and target table type.
    /// The `CodedIndex` is constructed at write time.
    implementation: Option<ResourceImplementationTarget>,
    /// Optional resource data for embedded resources
    resource_data: Option<Vec<u8>>,
    /// Optional resource data encoder for generating resource data
    resource_encoder: Option<DotNetResourceEncoder>,
}

impl Default for ManifestResourceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ManifestResourceBuilder {
    /// Creates a new `ManifestResourceBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods. Resource visibility defaults to
    /// `PUBLIC` (0x0001) and implementation defaults to embedded (null).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: ManifestResourceAttributes::PUBLIC,
            offset: 0,
            implementation: None, // Default to embedded (null implementation)
            resource_data: None,
            resource_encoder: None,
        }
    }

    /// Sets the name of the resource.
    ///
    /// Resource names are typically hierarchical and follow naming conventions
    /// like "Namespace.Type.ResourceType" (e.g., "MyApp.Forms.strings.resources").
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the resource
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.Resources.strings.resources");
    /// ```
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets resource attributes.
    ///
    /// Resource attributes control visibility and accessibility of the resource.
    /// Use the `ManifestResourceAttributes` constants for standard values.
    ///
    /// # Arguments
    ///
    /// * `flags` - Resource attributes
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::tables::ManifestResourceAttributes;
    /// let builder = ManifestResourceBuilder::new()
    ///     .flags(ManifestResourceAttributes::PRIVATE);
    /// ```
    #[must_use]
    pub fn flags(mut self, flags: ManifestResourceAttributes) -> Self {
        self.flags = flags;
        self
    }

    /// Marks the resource as public (accessible from external assemblies).
    ///
    /// Public resources can be accessed by other assemblies and runtime systems,
    /// enabling cross-assembly resource sharing and component integration.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.PublicResources")
    ///     .public();
    /// ```
    #[must_use]
    pub fn public(mut self) -> Self {
        self.flags |= ManifestResourceAttributes::PUBLIC;
        self.flags &= !ManifestResourceAttributes::PRIVATE;
        self
    }

    /// Marks the resource as private (restricted to the declaring assembly).
    ///
    /// Private resources are only accessible within the declaring assembly,
    /// providing encapsulation and preventing external access to sensitive data.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("MyApp.InternalResources")
    ///     .private();
    /// ```
    #[must_use]
    pub fn private(mut self) -> Self {
        self.flags |= ManifestResourceAttributes::PRIVATE;
        self.flags &= !ManifestResourceAttributes::PUBLIC;
        self
    }

    /// Sets the offset for embedded resources.
    ///
    /// For embedded resources (implementation.row == 0), this specifies the offset
    /// within the assembly's resource section where the resource data begins.
    ///
    /// # Arguments
    ///
    /// * `offset` - The byte offset within the resource section
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("EmbeddedResource")
    ///     .offset(0x1000);
    /// ```
    #[must_use]
    pub fn offset(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }

    /// Sets the implementation to reference a File table entry.
    ///
    /// Use this for file-based resources that are stored in external files
    /// referenced through the File table.
    /// The `CodedIndex` is NOT created at builder time to ensure proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `file_row` - Row index or placeholder of the File table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let file_ref = FileBuilder::new()
    ///     .name("Resources.resources")
    ///     .build(&mut assembly)?;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("FileBasedResource")
    ///     .implementation_file(file_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_file(mut self, file_row: u32) -> Self {
        self.implementation = Some(ResourceImplementationTarget::File(file_row));
        self
    }

    /// Sets the implementation to reference an AssemblyRef table entry.
    ///
    /// Use this for resources that are stored in external assemblies
    /// referenced through the AssemblyRef table.
    /// The `CodedIndex` is NOT created at builder time to ensure proper placeholder resolution.
    ///
    /// # Arguments
    ///
    /// * `assembly_ref_row` - Row index or placeholder of the AssemblyRef table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let assembly_ref = AssemblyRefBuilder::new()
    ///     .name("MyApp.Resources")
    ///     .version(1, 0, 0, 0)
    ///     .build(&mut assembly)?;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("ExternalResource")
    ///     .implementation_assembly_ref(assembly_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn implementation_assembly_ref(mut self, assembly_ref_row: u32) -> Self {
        self.implementation = Some(ResourceImplementationTarget::AssemblyRef(assembly_ref_row));
        self
    }

    /// Sets the implementation to embedded (null implementation).
    ///
    /// This is the default for embedded resources stored directly in the assembly.
    /// The resource data is located at the specified offset within the assembly's
    /// resource section.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("EmbeddedResource")
    ///     .implementation_embedded()
    ///     .offset(0x1000);
    /// ```
    #[must_use]
    pub fn implementation_embedded(mut self) -> Self {
        self.implementation = Some(ResourceImplementationTarget::Embedded);
        self
    }

    /// Sets the resource data for embedded resources.
    ///
    /// Specifies the actual data content for embedded resources. When resource data
    /// is provided, the resource will be stored directly in the assembly's resource
    /// section and the offset will be calculated automatically during assembly generation.
    ///
    /// # Arguments
    ///
    /// * `data` - The resource data as raw bytes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let resource_data = b"Hello, World!";
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("TextResource")
    ///     .resource_data(resource_data);
    /// ```
    #[must_use]
    pub fn resource_data(mut self, data: &[u8]) -> Self {
        self.resource_data = Some(data.to_vec());
        self.implementation = Some(ResourceImplementationTarget::Embedded); // Force embedded implementation
        self
    }

    /// Sets the resource data from a string for text-based embedded resources.
    ///
    /// Convenience method for setting string content as resource data. The string
    /// is encoded as UTF-8 bytes and stored as embedded resource data.
    ///
    /// # Arguments
    ///
    /// * `content` - The string content to store as resource data
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("ConfigResource")
    ///     .resource_string("key=value\nsetting=option");
    /// ```
    #[must_use]
    pub fn resource_string(mut self, content: &str) -> Self {
        self.resource_data = Some(content.as_bytes().to_vec());
        self.implementation = Some(ResourceImplementationTarget::Embedded); // Force embedded implementation
        self
    }

    /// Adds a string resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a string resource
    /// with the specified name and content. Multiple resources can be added to the
    /// same encoder for efficient bundling.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `content` - String content of the resource
    ///
    /// # Examples
    ///
    /// ```
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppResources")
    ///     .add_string_resource("AppTitle", "My Application")?
    ///     .add_string_resource("Version", "1.0.0")?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the string resource.
    pub fn add_string_resource(mut self, resource_name: &str, content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, content)?;
        self.implementation = Some(ResourceImplementationTarget::Embedded); // Force embedded implementation
        Ok(self)
    }

    /// Adds a binary resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a binary resource
    /// with the specified name and data.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `data` - Binary data of the resource
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let icon_data = std::fs::read("icon.png")?;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppResources")
    ///     .add_binary_resource("AppIcon", &icon_data)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the binary resource.
    pub fn add_binary_resource(mut self, resource_name: &str, data: &[u8]) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_byte_array(resource_name, data)?;
        self.implementation = Some(ResourceImplementationTarget::Embedded); // Force embedded implementation
        Ok(self)
    }

    /// Adds an XML resource using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include an XML resource
    /// with the specified name and content. XML resources are treated as structured
    /// data and may receive optimized encoding.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `xml_content` - XML content as a string
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let config_xml = r#"<?xml version="1.0"?>
    /// <configuration>
    ///     <setting name="timeout" value="30" />
    /// </configuration>"#;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppConfig")
    ///     .add_xml_resource("config.xml", config_xml)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the XML resource.
    pub fn add_xml_resource(mut self, resource_name: &str, xml_content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, xml_content)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Adds a text resource with explicit type specification using the resource encoder.
    ///
    /// Creates or updates the internal resource encoder to include a text resource
    /// with a specific resource type for encoding optimization.
    ///
    /// # Arguments
    ///
    /// * `resource_name` - Name of the individual resource within the encoder
    /// * `content` - Text content of the resource
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let json_config = r#"{"timeout": 30, "retries": 3}"#;
    ///
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("AppConfig")
    ///     .add_text_resource("config.json", json_config)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if the resource encoder fails to add the text resource.
    pub fn add_text_resource(mut self, resource_name: &str, content: &str) -> Result<Self> {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        encoder.add_string(resource_name, content)?;
        self.implementation = None; // Force embedded implementation
        Ok(self)
    }

    /// Configures the resource encoder with specific settings.
    ///
    /// Allows customization of the resource encoding process, including alignment,
    /// compression, and deduplication settings. This method provides access to
    /// advanced encoding options for performance optimization.
    ///
    /// # Arguments
    ///
    /// * `configure_fn` - Closure that configures the resource encoder
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// let builder = ManifestResourceBuilder::new()
    ///     .name("OptimizedResources")
    ///     .configure_encoder(|encoder| {
    ///         // DotNetResourceEncoder configuration can be added here
    ///         // when additional configuration options are implemented
    ///     });
    /// ```
    #[must_use]
    pub fn configure_encoder<F>(mut self, configure_fn: F) -> Self
    where
        F: FnOnce(&mut DotNetResourceEncoder),
    {
        let encoder = self
            .resource_encoder
            .get_or_insert_with(DotNetResourceEncoder::new);
        configure_fn(encoder);
        self.implementation = None; // Force embedded implementation
        self
    }

    /// Builds the ManifestResource entry and adds it to the assembly.
    ///
    /// This method validates all required fields, adds any strings to the appropriate heaps,
    /// creates the ManifestResource table entry, and returns the metadata token for the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created ManifestResource entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The resource name is not set
    /// - The resource name is empty
    /// - The implementation reference uses an invalid table type (must be File, AssemblyRef, or ExportedType)
    /// - The implementation reference has a row index of 0 for non-embedded resources
    /// - There are issues adding strings to heaps
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    ///
    /// let resource_token = ManifestResourceBuilder::new()
    ///     .name("MyApp.Resources")
    ///     .public()
    ///     .offset(0x1000)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created ManifestResource with token: {:?}", resource_token.placeholder_token());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid("Resource name is required for ManifestResource".to_string())
        })?;

        if name.is_empty() {
            return Err(Error::ModificationInvalid(
                "Resource name cannot be empty for ManifestResource".to_string(),
            ));
        }

        let name_index = assembly.string_get_or_add(&name)?.placeholder();

        // Construct the CodedIndex from the stored target information.
        // The row value may be a placeholder that will be resolved at write time
        // by the ResolvePlaceholders implementation.
        let implementation = match self.implementation {
            Some(ResourceImplementationTarget::File(row)) => {
                // Validate that row is not 0 (unless it's a placeholder with bit 31 set)
                if row == 0 {
                    return Err(Error::ModificationInvalid(
                        "Implementation reference row cannot be 0 for File table".to_string(),
                    ));
                }
                CodedIndex::new(TableId::File, row, CodedIndexType::Implementation)
            }
            Some(ResourceImplementationTarget::AssemblyRef(row)) => {
                if row == 0 {
                    return Err(Error::ModificationInvalid(
                        "Implementation reference row cannot be 0 for AssemblyRef table"
                            .to_string(),
                    ));
                }
                CodedIndex::new(TableId::AssemblyRef, row, CodedIndexType::Implementation)
            }
            Some(ResourceImplementationTarget::Embedded) | None => {
                // For embedded resources, create a null coded index (row 0)
                CodedIndex::new(TableId::File, 0, CodedIndexType::Implementation)
            }
        };

        // Handle resource data if provided
        let mut final_offset = self.offset;
        if let Some(encoder) = self.resource_encoder {
            let encoded_data = encoder.encode_dotnet_format()?;
            final_offset = assembly.resource_data_add(&encoded_data);
        } else if let Some(data) = self.resource_data {
            final_offset = assembly.resource_data_add(&data);
        }

        let manifest_resource = ManifestResourceRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            offset_field: final_offset,
            flags: self.flags.bits(),
            name: name_index,
            implementation,
        };

        assembly.table_row_add(
            TableId::ManifestResource,
            TableDataOwned::ManifestResource(manifest_resource),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind,
        metadata::tables::{ManifestResourceAttributes, TableId},
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_manifest_resource_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("MyApp.Resources")
            .build(&mut assembly)?;

        // Verify the ref has the correct kind
        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_default() -> Result<()> {
        let builder = ManifestResourceBuilder::default();
        assert!(builder.name.is_none());
        assert_eq!(builder.flags, ManifestResourceAttributes::PUBLIC);
        assert_eq!(builder.offset, 0);
        assert!(builder.resource_data.is_none());
        assert!(builder.resource_encoder.is_none());
        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = ManifestResourceBuilder::new().public().build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name is required"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_empty_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = ManifestResourceBuilder::new().name("").build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Resource name cannot be empty"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_public() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("PublicResource")
            .public()
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_private() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("PrivateResource")
            .private()
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_offset() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("EmbeddedResource")
            .offset(0x1000)
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_flags() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("CustomResource")
            .flags(ManifestResourceAttributes::PRIVATE)
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_embedded() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("EmbeddedResource")
            .implementation_embedded()
            .offset(0x2000)
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_multiple_resources() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref1 = ManifestResourceBuilder::new()
            .name("Resource1")
            .public()
            .build(&mut assembly)?;

        let ref2 = ManifestResourceBuilder::new()
            .name("Resource2")
            .private()
            .build(&mut assembly)?;

        // Verify refs are different
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert_eq!(
            ref1.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );
        assert_eq!(
            ref2.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_comprehensive() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("MyApp.Comprehensive.Resources")
            .public()
            .offset(0x4000)
            .implementation_embedded()
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test fluent API chaining
        let resource_ref = ManifestResourceBuilder::new()
            .name("FluentResource")
            .private()
            .offset(0x8000)
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_clone() {
        let builder1 = ManifestResourceBuilder::new().name("CloneTest").public();
        let builder2 = builder1.clone();

        assert_eq!(builder1.name, builder2.name);
        assert_eq!(builder1.flags, builder2.flags);
        assert_eq!(builder1.offset, builder2.offset);
    }

    #[test]
    fn test_manifest_resource_builder_debug() {
        let builder = ManifestResourceBuilder::new().name("DebugResource");
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("ManifestResourceBuilder"));
        assert!(debug_str.contains("DebugResource"));
    }

    #[test]
    fn test_manifest_resource_builder_zero_row_file_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a builder with a zero row implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ZeroRowImplementation");

        // Manually set an implementation with row 0 (invalid for File)
        builder.implementation = Some(ResourceImplementationTarget::File(0));

        let result = builder.build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_zero_row_assemblyref_implementation() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a builder with a zero row implementation reference
        let mut builder = ManifestResourceBuilder::new().name("ZeroRowImplementation");

        // Manually set an implementation with row 0 (invalid for AssemblyRef)
        builder.implementation = Some(ResourceImplementationTarget::AssemblyRef(0));

        let result = builder.build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Implementation reference row cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_resource_data() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_data = b"Hello, World!";
        let resource_ref = ManifestResourceBuilder::new()
            .name("TextResource")
            .resource_data(resource_data)
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_resource_string() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("ConfigResource")
            .resource_string("key=value\nsetting=option")
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_with_encoder() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("EncodedResources")
            .add_string_resource("AppTitle", "My Application")?
            .add_string_resource("Version", "1.0.0")?
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_configure_encoder() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let resource_ref = ManifestResourceBuilder::new()
            .name("OptimizedResources")
            .configure_encoder(|_encoder| {
                // DotNetResourceEncoder doesn't need deduplication setup
            })
            .add_string_resource("Test", "Content")?
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }

    #[test]
    fn test_manifest_resource_builder_mixed_resources() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let binary_data = vec![0x01, 0x02, 0x03, 0x04];
        let xml_content = r#"<?xml version="1.0"?><config><setting value="test"/></config>"#;

        let resource_ref = ManifestResourceBuilder::new()
            .name("MixedResources")
            .add_string_resource("title", "My App")?
            .add_binary_resource("data", &binary_data)?
            .add_xml_resource("config.xml", xml_content)?
            .build(&mut assembly)?;

        assert_eq!(
            resource_ref.kind(),
            ChangeRefKind::TableRow(TableId::ManifestResource)
        );

        Ok(())
    }
}
