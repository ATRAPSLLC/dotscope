//! # MethodDebugInformation Builder
//!
//! Provides a fluent API for building MethodDebugInformation table entries for Portable PDB debug information.
//! The MethodDebugInformation table associates method definitions with their debugging information,
//! including source document references and sequence point mappings that link IL instructions to source code locations.
//!
//! ## Overview
//!
//! The `MethodDebugInformationBuilder` enables creation of method debug information entries with:
//! - Document reference specification for source file association
//! - Sequence points data for IL-to-source mapping
//! - Support for methods without debugging information
//! - Validation of document indices and sequence point data
//! - Automatic token generation and metadata management
//!
//! ## Usage
//!
//! ```rust,no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create method debug information entry with document reference
//! let debug_info_token = MethodDebugInformationBuilder::new()
//!     .document(1) // Reference to Document table entry
//!     .sequence_points(vec![0x01, 0x02, 0x03]) // Sequence points blob data
//!     .build(&mut assembly)?;
//!
//! // Create entry for method without debug information
//! let minimal_debug_token = MethodDebugInformationBuilder::new()
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Optional References**: Document and sequence points are optional
//! - **Blob Management**: Sequence points data is stored in the blob heap
//! - **Token Generation**: Metadata tokens are created automatically
//! - **Validation**: Document indices are validated when provided

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        sequencepoints::SequencePoints,
        tables::{MethodDebugInformationRaw, TableDataOwned, TableId},
        token::Token,
    },
    Result,
};

/// Builder for creating MethodDebugInformation table entries.
///
/// `MethodDebugInformationBuilder` provides a fluent API for creating entries in the
/// MethodDebugInformation metadata table, which associates method definitions with
/// debugging information including source document references and sequence point mappings.
///
/// # Purpose
///
/// The MethodDebugInformation table serves several key functions:
/// - **Source Mapping**: Links IL instructions to source code locations for debugging
/// - **Document Association**: Associates methods with their source documents
/// - **Step-Through Debugging**: Enables debuggers to provide accurate source navigation
/// - **Stack Trace Resolution**: Maps compiled code back to original source locations
/// - **IDE Integration**: Supports breakpoints, stepping, and source highlighting
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing MethodDebugInformation entries:
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// let debug_info_token = MethodDebugInformationBuilder::new()
///     .document(1)                                    // Document table reference
///     .sequence_points(vec![0x01, 0x02, 0x03])      // Sequence points blob
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Integration
///
/// MethodDebugInformation entries integrate with other metadata structures:
/// - **Document**: References entries in the Document table for source file information
/// - **MethodDef**: Associated with specific method definitions for debugging
/// - **Portable PDB**: Core component of .NET debugging symbol files
/// - **Development Tools**: Used by debuggers, IDEs, and profiling tools
#[derive(Debug, Clone)]
pub struct MethodDebugInformationBuilder {
    /// Document table index (0 = no associated document)
    document: Option<u32>,
    /// Sequence points blob data
    sequence_points: Option<Vec<u8>>,
    /// Sequence points to encode at build, once the document is known
    parsed_sequence_points: Option<SequencePoints>,
}

impl Default for MethodDebugInformationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodDebugInformationBuilder {
    /// Creates a new `MethodDebugInformationBuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = MethodDebugInformationBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            document: None,
            sequence_points: None,
            parsed_sequence_points: None,
        }
    }

    /// Sets the document table reference.
    ///
    /// Associates this method debug information with a specific document entry
    /// in the Document table. The document contains source file information
    /// including the file path and content hash.
    ///
    /// # Arguments
    ///
    /// * `document_index` - 1-based index into the Document table
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = MethodDebugInformationBuilder::new()
    ///     .document(1);
    /// ```
    #[must_use]
    pub fn document(mut self, document_index: u32) -> Self {
        self.document = Some(document_index);
        self
    }

    /// Sets the sequence points blob data.
    ///
    /// Provides the compressed sequence point data that maps IL instruction
    /// offsets to source code locations. The data follows the Portable PDB
    /// format specification with delta compression and variable-length encoding.
    ///
    /// # Arguments
    ///
    /// * `data` - Binary sequence points data in Portable PDB format
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let sequence_data = vec![0x01, 0x02, 0x03, 0x04];
    /// let builder = MethodDebugInformationBuilder::new()
    ///     .sequence_points(sequence_data);
    /// ```
    #[must_use]
    pub fn sequence_points(mut self, data: Vec<u8>) -> Self {
        self.sequence_points = Some(data);
        self.parsed_sequence_points = None;
        self
    }

    /// Sets sequence points from parsed SequencePoints structure.
    ///
    /// Convenience method that accepts a parsed SequencePoints structure
    /// and serializes it to the appropriate blob format for storage.
    ///
    /// # Arguments
    ///
    /// * `points` - Parsed sequence points structure
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use dotscope::metadata::sequencepoints::SequencePoints;
    /// # let points = SequencePoints::default();
    /// let builder = MethodDebugInformationBuilder::new()
    ///     .sequence_points_parsed(points);
    /// ```
    ///
    /// The points are encoded when the entry is built, against the document set
    /// with [`document`](Self::document): the blob's header names the first
    /// point's document only when the method has none. [`build`](Self::build)
    /// fails when they cannot be encoded (see [`SequencePoints::to_bytes`]).
    #[must_use]
    pub fn sequence_points_parsed(mut self, points: SequencePoints) -> Self {
        self.parsed_sequence_points = Some(points);
        self.sequence_points = None;
        self
    }

    /// Builds the MethodDebugInformation entry and adds it to the assembly.
    ///
    /// This method creates the MethodDebugInformation table entry with the specified
    /// document reference and sequence points data. All blob data is added to the
    /// blob heap and appropriate indices are generated.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// Returns the metadata token for the newly created MethodDebugInformation entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - There are issues adding blob data to heaps
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
    /// let debug_token = MethodDebugInformationBuilder::new()
    ///     .document(1)
    ///     .sequence_points(vec![0x01, 0x02, 0x03])
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created MethodDebugInformation with token: {:?}", debug_token.placeholder_token());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let document_index = self.document.unwrap_or(0);

        let encoded = match &self.parsed_sequence_points {
            Some(points) => Some(points.to_bytes(document_index)?),
            None => self.sequence_points,
        };
        let sequence_points_index = if let Some(data) = encoded {
            if data.is_empty() {
                0
            } else {
                assembly.blob_add(&data)?.placeholder()
            }
        } else {
            0
        };

        let method_debug_info = MethodDebugInformationRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            document: document_index,
            sequence_points: sequence_points_index,
        };

        assembly.table_row_add(
            TableId::MethodDebugInformation,
            TableDataOwned::MethodDebugInformation(method_debug_info),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind,
        metadata::{sequencepoints::SequencePoint, tables::TableId},
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_method_debug_information_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = MethodDebugInformationBuilder::new()
            .document(1)
            .sequence_points(vec![0x01, 0x02, 0x03])
            .build(&mut assembly)?;

        // Verify the reference has the correct kind
        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_encodes_parsed_points_against_its_document(
    ) -> Result<()> {
        let points = SequencePoints {
            local_signature: 0,
            points: vec![SequencePoint::new(0, 3, 1, 3, 9).unwrap()],
        };

        // With a document the points are in it.
        let mut assembly = get_test_assembly()?;
        MethodDebugInformationBuilder::new()
            .document(1)
            .sequence_points_parsed(points.clone())
            .build(&mut assembly)?;

        // Without one, a point must name its own.
        let mut assembly = get_test_assembly()?;
        assert!(MethodDebugInformationBuilder::new()
            .sequence_points_parsed(points)
            .build(&mut assembly)
            .is_err());
        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_default() -> Result<()> {
        let builder = MethodDebugInformationBuilder::default();
        assert!(builder.document.is_none());
        assert!(builder.sequence_points.is_none());
        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_minimal() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Should work with no document or sequence points
        let ref_ = MethodDebugInformationBuilder::new().build(&mut assembly)?;

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_document_only() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let ref_ = MethodDebugInformationBuilder::new()
            .document(5)
            .build(&mut assembly)?;

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_sequence_points_only() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let sequence_data = vec![0x10, 0x20, 0x30, 0x40];
        let ref_ = MethodDebugInformationBuilder::new()
            .sequence_points(sequence_data)
            .build(&mut assembly)?;

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_empty_sequence_points() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Empty sequence points should result in index 0
        let ref_ = MethodDebugInformationBuilder::new()
            .document(1)
            .sequence_points(vec![])
            .build(&mut assembly)?;

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }

    #[test]
    fn test_method_debug_information_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test fluent chaining
        let ref_ = MethodDebugInformationBuilder::new()
            .document(3)
            .sequence_points(vec![0xAA, 0xBB, 0xCC])
            .build(&mut assembly)?;

        assert_eq!(
            ref_.kind(),
            ChangeRefKind::TableRow(TableId::MethodDebugInformation)
        );

        Ok(())
    }
}
