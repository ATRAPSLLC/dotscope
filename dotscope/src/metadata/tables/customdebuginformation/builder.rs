//! Builder for constructing `CustomDebugInformation` table entries
//!
//! This module provides the [`crate::metadata::tables::customdebuginformation::CustomDebugInformationBuilder`] which enables fluent construction
//! of `CustomDebugInformation` metadata table entries. The builder follows the established
//! pattern used across all table builders in the library.
//!
//! # Usage Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//!
//! # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
//! let mut assembly = CilAssembly::new(view);
//!
//! let parent = CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::HasCustomDebugInformation);  // Method with debug info
//! let debug_token = CustomDebugInformationBuilder::new()
//!     .parent(parent)                    // Element being debugged
//!     .kind(42)                          // GUID heap index for debug type
//!     .value(&[0x01, 0x02, 0x03])        // Raw debug blob data
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        customdebuginformation::{encode_custom_debug_blob, CustomDebugInfo},
        tables::{CodedIndex, CodedIndexType, CustomDebugInformationRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `CustomDebugInformation` table entries
///
/// Provides a fluent interface for building `CustomDebugInformation` metadata table entries.
/// These entries store custom debugging information that extends beyond the standard Portable PDB
/// tables, allowing compilers and tools to embed specialized debugging metadata.
///
/// # Required Fields
/// - `parent`: HasCustomDebugInformation coded index to the metadata element
/// - `kind`: GUID heap index identifying the type of custom debug information
/// - `value`: Raw debug information blob data
///
/// # Custom Debug Information Types
///
/// Common Kind GUIDs include:
/// - State Machine Hoisted Local Scopes
/// - Dynamic Local Variables  
/// - Default Namespace (VB)
/// - Edit and Continue Local Slot Map
/// - Edit and Continue Lambda and Closure Map
/// - Embedded Source
/// - Source Link
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// # let source_bytes = vec![0x01, 0x02, 0x03];
/// // Source link debug information for a method
/// let method_parent = CodedIndex::new(TableId::MethodDef, 5, CodedIndexType::HasCustomDebugInformation);
/// let source_link = CustomDebugInformationBuilder::new()
///     .parent(method_parent)
///     .kind(1)  // GUID heap index for Source Link type
///     .value(b"{\"documents\": {\"*\": \"https://github.com/...\"}}")
///     .build(&mut assembly)?;
///
/// // Embedded source for a document
/// let document_parent = CodedIndex::new(TableId::Document, 2, CodedIndexType::HasCustomDebugInformation);
/// let embedded_source = CustomDebugInformationBuilder::new()
///     .parent(document_parent)
///     .kind(2)  // GUID heap index for Embedded Source type
///     .value(&source_bytes)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct CustomDebugInformationBuilder {
    /// HasCustomDebugInformation coded index to the metadata element
    parent: Option<CodedIndex>,
    /// GUID heap index for the debug information type identifier
    kind: Option<u32>,
    /// Raw debug information blob data
    value: Option<Vec<u8>>,
    /// The value, decoded: encoded when the entry is built
    parsed: Option<CustomDebugInfo>,
}

impl CustomDebugInformationBuilder {
    /// Creates a new `CustomDebugInformationBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide all required fields before calling build().
    ///
    /// # Returns
    /// A new `CustomDebugInformationBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CustomDebugInformationBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            kind: None,
            value: None,
            parsed: None,
        }
    }

    /// Sets the parent metadata element
    ///
    /// Specifies the metadata element that this custom debug information
    /// is associated with using a HasCustomDebugInformation coded index.
    ///
    /// # Parameters
    /// - `parent`: HasCustomDebugInformation coded index to the target element
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Valid Parent Types
    /// - MethodDef, Field, TypeRef, TypeDef, Param, InterfaceImpl, MemberRef, Module
    /// - DeclSecurity, Property, Event, StandAloneSig, ModuleRef, TypeSpec, Assembly
    /// - AssemblyRef, File, ExportedType, ManifestResource, GenericParam, GenericParamConstraint
    /// - MethodSpec, Document, LocalScope, LocalVariable, LocalConstant, ImportScope
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Debug info for a method
    /// let method_parent = CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::HasCustomDebugInformation);
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .parent(method_parent);
    ///
    /// // Debug info for a document
    /// let document_parent = CodedIndex::new(TableId::Document, 3, CodedIndexType::HasCustomDebugInformation);
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .parent(document_parent);
    /// ```
    #[must_use]
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the debug information type GUID index
    ///
    /// Specifies the GUID heap index that identifies the specific type of
    /// custom debug information, which determines how to interpret the value blob.
    ///
    /// # Parameters
    /// - `kind`: GUID heap index for the debug information type
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .kind(1);  // Points to Source Link GUID in heap
    /// ```
    #[must_use]
    pub fn kind(mut self, kind: u32) -> Self {
        self.kind = Some(kind);
        self
    }

    /// Sets the debug information value blob
    ///
    /// Specifies the raw blob data containing the custom debug information.
    /// The format of this data is determined by the Kind GUID.
    ///
    /// # Parameters
    /// - `value`: Raw debug information blob data
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // JSON data for Source Link
    /// let json_data = b"{\"documents\": {\"*\": \"https://github.com/...\"}}";
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .value(json_data);
    ///
    /// // Binary data for custom debug info
    /// let binary_data = vec![0x01, 0x02, 0x03, 0x04];
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .value(&binary_data);
    ///
    /// // Empty value for some debug info types
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .value(&[]);
    /// ```
    #[must_use]
    pub fn value(mut self, value: &[u8]) -> Self {
        self.value = Some(value.to_vec());
        self.parsed = None;
        self
    }

    /// Sets the custom debug information, decoded: its blob is encoded now, and its kind's
    /// GUID is added to the `#GUID` heap when [`build`](Self::build) runs, unless
    /// [`kind`](Self::kind) set one.
    ///
    /// The rows the value names (a type's documents, the method of an async method's awaits)
    /// are rows of the input, or rows a change adds, named by their placeholders; the writer
    /// renumbers them as it renumbers the rows.
    ///
    /// # Arguments
    ///
    /// * `info` - The value
    ///
    /// # Errors
    ///
    /// [`build`](Self::build) fails when the value cannot be encoded
    /// ([`encode_custom_debug_blob`]).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{metadata::customdebuginformation::CustomDebugInfo, prelude::*};
    ///
    /// let builder = CustomDebugInformationBuilder::new()
    ///     .value_parsed(CustomDebugInfo::DefaultNamespace("Root".to_string()));
    /// ```
    #[must_use]
    pub fn value_parsed(mut self, info: CustomDebugInfo) -> Self {
        self.parsed = Some(info);
        self.value = None;
        self
    }

    /// Builds and adds the `CustomDebugInformation` entry to the metadata
    ///
    /// Validates all required fields, creates the `CustomDebugInformation` table entry,
    /// and adds it to the CilAssembly. Returns a token that can be used
    /// to reference this custom debug information.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CilAssembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created custom debug information
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (parent, kind, or value)
    /// - Invalid coded index for parent
    /// - Table operations fail due to metadata constraints
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let parent = CodedIndex::new(TableId::MethodDef, 1, CodedIndexType::HasCustomDebugInformation);
    /// let debug_data = vec![0x01, 0x02, 0x03];
    /// let token = CustomDebugInformationBuilder::new()
    ///     .parent(parent)
    ///     .kind(42)
    ///     .value(&debug_data)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let parent = self.parent.ok_or_else(|| {
            Error::ModificationInvalid(
                "Parent coded index is required for CustomDebugInformation".to_string(),
            )
        })?;

        let kind = match (self.kind, &self.parsed) {
            (Some(kind), _) => kind,
            (None, Some(info)) => assembly
                .guid_add(&info.kind().guid().to_bytes())?
                .placeholder(),
            (None, None) => {
                return Err(Error::ModificationInvalid(
                    "Kind GUID index is required for CustomDebugInformation".to_string(),
                ))
            }
        };

        let value = match (self.value, &self.parsed) {
            (Some(value), _) => value,
            (None, Some(info)) => encode_custom_debug_blob(info)?,
            (None, None) => {
                return Err(Error::ModificationInvalid(
                    "Value blob data is required for CustomDebugInformation".to_string(),
                ))
            }
        };

        // Validate that the parent uses a valid coded index type
        let valid_tables = CodedIndexType::HasCustomDebugInformation.tables();
        if !valid_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Invalid parent table {:?} for CustomDebugInformation. Must be a HasCustomDebugInformation coded index.",
                parent.tag
            )));
        }

        let value_index = if value.is_empty() {
            0
        } else {
            assembly.blob_add(&value)?.placeholder()
        };

        let custom_debug_info = CustomDebugInformationRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            parent,
            kind,
            value: value_index,
        };

        assembly.table_row_add(
            TableId::CustomDebugInformation,
            TableDataOwned::CustomDebugInformation(custom_debug_info),
        )
    }
}

impl Default for CustomDebugInformationBuilder {
    /// Creates a default `CustomDebugInformationBuilder`
    ///
    /// Equivalent to calling [`CustomDebugInformationBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_customdebuginformation_builder_new() {
        let builder = CustomDebugInformationBuilder::new();

        assert!(builder.parent.is_none());
        assert!(builder.kind.is_none());
        assert!(builder.value.is_none());
    }

    #[test]
    fn test_customdebuginformation_builder_default() {
        let builder = CustomDebugInformationBuilder::default();

        assert!(builder.parent.is_none());
        assert!(builder.kind.is_none());
        assert!(builder.value.is_none());
    }

    #[test]
    fn test_customdebuginformation_builder_method_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let debug_data = vec![0x01, 0x02, 0x03];
        let ref_ = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(42)
            .value(&debug_data)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_document_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(
            TableId::Document,
            2,
            CodedIndexType::HasCustomDebugInformation,
        );
        let source_link_json = b"{\"documents\": {\"*\": \"https://github.com/repo/\"}}";
        let ref_ = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(1) // Source Link GUID index
            .value(source_link_json)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_empty_value() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(
            TableId::TypeDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let ref_ = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(5)
            .value(&[]) // Empty value
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_missing_parent() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let debug_data = vec![0x01, 0x02];
        let result = CustomDebugInformationBuilder::new()
            .kind(1)
            .value(&debug_data)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Parent coded index is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_missing_kind() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let debug_data = vec![0x01, 0x02];
        let result = CustomDebugInformationBuilder::new()
            .parent(parent)
            .value(&debug_data)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Kind GUID index is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_missing_value() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let result = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(1)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Value blob data is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_clone() {
        let parent = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let debug_data = vec![0x01, 0x02, 0x03];
        let builder = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(42)
            .value(&debug_data);

        let cloned = builder.clone();
        assert_eq!(builder.parent, cloned.parent);
        assert_eq!(builder.kind, cloned.kind);
        assert_eq!(builder.value, cloned.value);
    }

    #[test]
    fn test_customdebuginformation_builder_debug() {
        let parent = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let debug_data = vec![0x01, 0x02, 0x03];
        let builder = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(42)
            .value(&debug_data);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("CustomDebugInformationBuilder"));
        assert!(debug_str.contains("parent"));
        assert!(debug_str.contains("kind"));
        assert!(debug_str.contains("value"));
    }

    #[test]
    fn test_customdebuginformation_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent = CodedIndex::new(TableId::Field, 3, CodedIndexType::HasCustomDebugInformation);
        let debug_data = vec![0xFF, 0xEE, 0xDD];

        // Test method chaining
        let ref_ = CustomDebugInformationBuilder::new()
            .parent(parent)
            .kind(99)
            .value(&debug_data)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        Ok(())
    }

    #[test]
    fn test_customdebuginformation_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let parent1 = CodedIndex::new(
            TableId::MethodDef,
            1,
            CodedIndexType::HasCustomDebugInformation,
        );
        let parent2 = CodedIndex::new(
            TableId::MethodDef,
            2,
            CodedIndexType::HasCustomDebugInformation,
        );
        let data1 = vec![0x01, 0x02];
        let data2 = vec![0x03, 0x04];

        // Build first debug info
        let ref1 = CustomDebugInformationBuilder::new()
            .parent(parent1)
            .kind(1)
            .value(&data1)
            .build(&mut assembly)
            .expect("Should build first debug info");

        // Build second debug info
        let ref2 = CustomDebugInformationBuilder::new()
            .parent(parent2)
            .kind(2)
            .value(&data2)
            .build(&mut assembly)
            .expect("Should build second debug info");

        assert_eq!(
            ref1.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        assert_eq!(
            ref2.kind(),
            ChangeRefKind::TableRow(TableId::CustomDebugInformation)
        );
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }
}
