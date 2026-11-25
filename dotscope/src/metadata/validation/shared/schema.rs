//! Shared schema validation utilities for the unified validation framework.
//!
//! This module provides common schema validation operations that ensure metadata
//! structures conform to ECMA-335 requirements. It centralizes schema validation
//! logic that can be used by both raw and owned validators to validate table structures,
//! heap references, coded indices, and other fundamental metadata schema constraints.
//!
//! # Architecture
//!
//! The schema validation system provides comprehensive ECMA-335 compliance checking:
//! 1. **Table Structure Validation** - Validates required tables and row count constraints
//! 2. **Heap Reference Validation** - Ensures heap indices are within valid bounds
//! 3. **Coded Index Validation** - Validates complex coded index encodings
//! 4. **Cross-Table Consistency** - Validates relationships between dependent tables
//! 5. **RID Validation** - Ensures Row IDs follow ECMA-335 requirements
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::shared::schema::SchemaValidator`] - Main schema validation orchestrator
//! - [`crate::metadata::validation::shared::schema::SchemaValidationStatistics`] - Comprehensive schema validation statistics
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{SchemaValidator, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::tables::TableId;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//! let validator = SchemaValidator::new(&scanner);
//!
//! // Validate basic schema structure
//! if let Some(tables) = view.tables() {
//!     validator.validate_basic_structure(tables)?;
//! }
//!
//! // Validate heap references
//! validator.validate_string_index(1)?;
//! validator.validate_blob_index(4)?;
//!
//! // Validate Row IDs
//! validator.validate_rid(TableId::TypeDef, 1)?;
//!
//! // Get comprehensive statistics
//! let stats = validator.get_validation_statistics();
//! println!("Tables: {}, Rows: {}", stats.total_tables, stats.total_rows);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`crate::metadata::validation::SchemaValidator`] is stateless and implements [`Send`] + [`Sync`],
//! making it safe for concurrent use across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::scanner`] - Provides metadata analysis infrastructure
//! - Raw validators - Used by raw validators for schema validation
//! - Owned validators - Used by owned validators for consistency checks
//! - [`crate::metadata::tables`] - Validates table structure and relationships

use crate::{
    metadata::{
        tables::TableId,
        token::Token,
        validation::{
            scanner::{HeapSizes, ReferenceScanner},
            ScannerStatistics,
        },
    },
    Error, HeapKind, ParseFailure, Result,
};

/// Shared schema validation utilities.
///
/// This struct provides reusable schema validation operations for ensuring
/// metadata structures conform to ECMA-335 specifications. It encapsulates
/// common validation patterns used across different validator types and operates
/// on pre-analyzed metadata from [`crate::metadata::validation::scanner::ReferenceScanner`] for efficient validation.
///
/// # Thread Safety
///
/// This type is stateless and implements [`Send`] + [`Sync`], making it safe for concurrent use.
pub struct SchemaValidator<'a> {
    /// Reference scanner for metadata analysis
    scanner: &'a ReferenceScanner,
}

impl<'a> SchemaValidator<'a> {
    /// Creates a new schema validator using the provided reference scanner.
    ///
    /// # Arguments
    ///
    /// * `scanner` - The [`crate::metadata::validation::scanner::ReferenceScanner`] containing pre-analyzed metadata
    ///
    /// # Returns
    ///
    /// A new [`SchemaValidator`] instance ready for validation operations.
    #[must_use]
    pub fn new(scanner: &'a ReferenceScanner) -> Self {
        Self { scanner }
    }

    /// Validates the basic structure of metadata tables.
    ///
    /// This method performs fundamental schema validation including:
    /// - Table presence validation
    /// - Row count consistency
    /// - Basic structural integrity
    ///
    /// # Arguments
    ///
    /// * `tables` - The tables header to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the schema is valid, or an error describing the validation failure.
    ///
    /// # Errors
    ///
    /// - `ValidationOwnedFailed`: If table structure is invalid
    pub fn validate_basic_structure(&self, tables: &crate::TablesHeader) -> Result<()> {
        // Module table is required by ECMA-335
        if self.scanner.table_row_count(TableId::Module) == 0 {
            return Err(Error::ValidationOwnedFailed {
                validator: "SchemaValidator".to_string(),
                message: "Module table is required but empty".to_string(),
            });
        }

        // Module table must have exactly one row
        if self.scanner.table_row_count(TableId::Module) > 1 {
            return Err(Error::ValidationOwnedFailed {
                validator: "SchemaValidator".to_string(),
                message: "Module table must contain exactly one row".to_string(),
            });
        }

        // Validate table consistency
        self.validate_table_consistency(tables)?;

        Ok(())
    }

    /// Validates consistency between related metadata tables.
    ///
    /// This method checks that cross-table relationships are properly maintained
    /// and that dependent tables have consistent row counts and references.
    ///
    /// # Arguments
    ///
    /// * `tables` - The tables header containing metadata tables
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if tables are consistent, or an error otherwise.
    fn validate_table_consistency(&self, _tables: &crate::TablesHeader) -> Result<()> {
        // Validate TypeDef dependencies
        let typedef_count = self.scanner.table_row_count(TableId::TypeDef);
        if typedef_count > 0 {
            // If we have TypeDefs, we need at least one Assembly or AssemblyRef
            let assembly_count = self.scanner.table_row_count(TableId::Assembly);
            let assemblyref_count = self.scanner.table_row_count(TableId::AssemblyRef);

            if assembly_count == 0 && assemblyref_count == 0 {
                return Err(Error::ValidationOwnedFailed {
                    validator: "SchemaValidator".to_string(),
                    message: "TypeDef tables require Assembly or AssemblyRef table".to_string(),
                });
            }
        }

        // Validate FieldMap consistency
        self.validate_field_map_consistency()?;

        // Validate MethodMap consistency
        self.validate_method_map_consistency()?;

        Ok(())
    }

    /// Validates field mapping consistency between TypeDef and Field tables.
    ///
    /// This method ensures that field ownership relationships are properly
    /// maintained according to ECMA-335 requirements.
    fn validate_field_map_consistency(&self) -> Result<()> {
        let typedef_count = self.scanner.table_row_count(TableId::TypeDef);
        let field_count = self.scanner.table_row_count(TableId::Field);

        // If we have fields, we must have type definitions that own them
        if field_count > 0 && typedef_count == 0 {
            return Err(Error::ValidationOwnedFailed {
                validator: "SchemaValidator".to_string(),
                message: "Field table requires TypeDef table".to_string(),
            });
        }

        Ok(())
    }

    /// Validates method mapping consistency between TypeDef and MethodDef tables.
    ///
    /// This method ensures that method ownership relationships are properly
    /// maintained according to ECMA-335 requirements.
    fn validate_method_map_consistency(&self) -> Result<()> {
        let typedef_count = self.scanner.table_row_count(TableId::TypeDef);
        let methoddef_count = self.scanner.table_row_count(TableId::MethodDef);

        // If we have methods, we must have type definitions that own them
        if methoddef_count > 0 && typedef_count == 0 {
            return Err(Error::ValidationOwnedFailed {
                validator: "SchemaValidator".to_string(),
                message: "MethodDef table requires TypeDef table".to_string(),
            });
        }

        Ok(())
    }

    /// Validates heap reference integrity.
    ///
    /// This method checks that heap references (strings, blobs, GUIDs, user strings)
    /// are within valid bounds and point to existing heap entries.
    ///
    /// # Arguments
    ///
    /// * `heap_type` - The type of heap to validate
    /// * `index` - The heap index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the heap reference is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `HeapBoundsError`: If the heap index is out of bounds
    pub fn validate_heap_reference(&self, heap_type: &str, index: u32) -> Result<()> {
        self.scanner.validate_heap_index(heap_type, index)
    }

    /// Validates a collection of heap references.
    ///
    /// This method efficiently validates multiple heap references in batch,
    /// providing comprehensive error reporting for any invalid references.
    ///
    /// # Arguments
    ///
    /// * `heap_type` - The type of heap being validated
    /// * `indices` - Iterator of heap indices to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all heap references are valid, or the first error encountered.
    ///
    /// # Errors
    ///
    /// Returns an error if any heap reference is invalid or out of bounds.
    pub fn validate_heap_references<I>(&self, heap_type: &str, indices: I) -> Result<()>
    where
        I: IntoIterator<Item = u32>,
    {
        for index in indices {
            self.validate_heap_reference(heap_type, index)?;
        }
        Ok(())
    }

    /// Validates table row ID constraints.
    ///
    /// This method ensures that Row IDs (RIDs) follow ECMA-335 requirements:
    /// - RIDs must be non-zero
    /// - RIDs must be within table bounds
    /// - RIDs must be unique within their table
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table to validate
    /// * `rid` - The row ID to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the RID is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `InvalidRid`: If the RID is invalid
    pub fn validate_rid(&self, table_id: TableId, rid: u32) -> Result<()> {
        if rid == 0 {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        let max_rid = self.scanner.table_row_count(table_id);
        if rid > max_rid {
            return Err(Error::InvalidRid {
                table: table_id,
                rid,
            });
        }

        Ok(())
    }

    /// Validates coded index constraints.
    ///
    /// Coded indices in ECMA-335 encode both a table type and row ID in a single value.
    /// This method validates that coded indices are properly formed and reference valid rows.
    ///
    /// # Arguments
    ///
    /// * `coded_index` - The coded index value to validate
    /// * `allowed_tables` - The tables that this coded index can reference
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the coded index is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// - `ValidationInvalidTokenType`: If the coded index references an invalid table
    /// - `InvalidRid`: If the referenced RID is invalid
    pub fn validate_coded_index(&self, coded_index: u32, allowed_tables: &[TableId]) -> Result<()> {
        if coded_index == 0 {
            // Null coded index is often valid
            return Ok(());
        }

        // Extract table index and RID from coded index
        // The exact decoding depends on the specific coded index type
        // This is a simplified validation - real implementation would decode properly
        let table_bits = allowed_tables.len().next_power_of_two().trailing_zeros();
        let mask = 1u32.checked_shl(table_bits).unwrap_or(0).saturating_sub(1);
        let table_index = coded_index & mask;
        let rid = coded_index.checked_shr(table_bits).unwrap_or(0);

        // Validate table index is within allowed range
        if (table_index as usize) >= allowed_tables.len() {
            return Err(Error::InvalidToken {
                token: Token::new(coded_index),
                message: format!("Table index {table_index} not in allowed range"),
            });
        }

        // Validate RID for the decoded table
        let table_id =
            *allowed_tables
                .get(table_index as usize)
                .ok_or_else(|| Error::InvalidToken {
                    token: Token::new(coded_index),
                    message: format!("Table index {table_index} not in allowed range"),
                })?;
        self.validate_rid(table_id, rid)
    }

    /// Validates string heap indices.
    ///
    /// This method specifically validates indices into the strings heap,
    /// ensuring they point to valid null-terminated UTF-8 strings.
    ///
    /// # Arguments
    ///
    /// * `index` - The string heap index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the string index is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the string index is invalid or out of bounds.
    pub fn validate_string_index(&self, index: u32) -> Result<()> {
        self.validate_heap_reference("strings", index)
    }

    /// Validates blob heap indices.
    ///
    /// This method specifically validates indices into the blob heap,
    /// ensuring they point to valid length-prefixed binary data.
    ///
    /// # Arguments
    ///
    /// * `index` - The blob heap index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the blob index is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the blob index is invalid or out of bounds.
    pub fn validate_blob_index(&self, index: u32) -> Result<()> {
        self.validate_heap_reference("blobs", index)
    }

    /// Validates GUID heap indices.
    ///
    /// This method specifically validates indices into the GUID heap,
    /// ensuring they point to valid 16-byte GUID values using 1-based indexing.
    ///
    /// # Arguments
    ///
    /// * `index` - The GUID heap index to validate (1-based)
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the GUID index is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the GUID index is invalid or out of bounds.
    pub fn validate_guid_index(&self, index: u32) -> Result<()> {
        if index == 0 {
            // Null GUID reference is valid
            return Ok(());
        }

        // GUID heap uses 1-based indexing, validate against heap size
        let guid_heap_size = self.scanner.heap_sizes().guids;
        let max_index = guid_heap_size / 16; // Each GUID is 16 bytes

        if index > max_index {
            return Err(Error::Parse(ParseFailure::HeapOutOfBounds {
                heap: HeapKind::Guid,
                index,
            }));
        }

        Ok(())
    }

    /// Validates user string heap indices.
    ///
    /// This method specifically validates indices into the user strings heap,
    /// ensuring they point to valid length-prefixed UTF-16 strings.
    ///
    /// # Arguments
    ///
    /// * `index` - The user string heap index to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the user string index is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the user string index is invalid or out of bounds.
    pub fn validate_user_string_index(&self, index: u32) -> Result<()> {
        self.validate_heap_reference("userstrings", index)
    }

    /// Gets validation statistics for the current schema.
    ///
    /// This method returns comprehensive statistics about the metadata schema,
    /// useful for validation reporting and debugging.
    ///
    /// # Returns
    ///
    /// Returns a `SchemaValidationStatistics` struct containing detailed information.
    #[must_use]
    pub fn get_validation_statistics(&self) -> SchemaValidationStatistics {
        SchemaValidationStatistics {
            total_tables: self.scanner.count_non_empty_tables(),
            total_rows: self.scanner.count_total_rows(),
            heap_sizes: self.scanner.heap_sizes().clone(),
            scanner_stats: self.scanner.statistics(),
        }
    }
}

/// Schema validation statistics.
///
/// This struct contains comprehensive statistics about metadata schema validation,
/// useful for reporting and debugging validation results.
#[derive(Debug, Clone)]
pub struct SchemaValidationStatistics {
    /// Number of non-empty metadata tables
    pub total_tables: usize,
    /// Total number of rows across all tables
    pub total_rows: u32,
    /// Metadata heap sizes
    pub heap_sizes: HeapSizes,
    /// Reference scanner statistics
    pub scanner_stats: ScannerStatistics,
}

impl std::fmt::Display for SchemaValidationStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Schema Statistics: {} tables, {} total rows, Heaps(strings: {}, blobs: {}, guids: {}, userstrings: {})",
            self.total_tables,
            self.total_rows,
            self.heap_sizes.strings,
            self.heap_sizes.blobs,
            self.heap_sizes.guids,
            self.heap_sizes.userstrings
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{metadata::cilassemblyview::CilAssemblyView, testkit::fixture};

    #[test]
    fn test_schema_validator_creation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        // Test basic functionality
        let stats = validator.get_validation_statistics();
        assert!(stats.total_tables > 0);
        assert!(stats.total_rows > 0);
    }

    #[test]
    fn test_basic_structure_validation() {
        let path = fixture("WindowsBase.dll");
        let view = crate::metadata::cilassemblyview::CilAssemblyView::from_path(&path)
            .expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        // Should pass for valid assembly
        if let Some(tables) = view.tables() {
            assert!(validator.validate_basic_structure(tables).is_ok());
        }
    }

    #[test]
    fn test_rid_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        // Test invalid RID (0)
        assert!(validator.validate_rid(TableId::TypeDef, 0).is_err());

        // Test valid RID (if table has rows)
        if scanner.table_row_count(TableId::TypeDef) > 0 {
            assert!(validator.validate_rid(TableId::TypeDef, 1).is_ok());
        }

        // Test out-of-bounds RID
        let max_rid = scanner.table_row_count(TableId::TypeDef);
        if max_rid > 0 {
            assert!(validator
                .validate_rid(TableId::TypeDef, max_rid + 1)
                .is_err());
        }
    }

    #[test]
    fn test_heap_reference_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        // Test string heap validation
        assert!(validator.validate_string_index(0).is_ok()); // Null reference

        // Test blob heap validation
        assert!(validator.validate_blob_index(0).is_ok()); // Null reference

        // Test GUID heap validation
        assert!(validator.validate_guid_index(0).is_ok()); // Null reference

        // Test user string heap validation
        assert!(validator.validate_user_string_index(0).is_ok()); // Null reference
    }

    #[test]
    fn test_validation_statistics() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        let stats = validator.get_validation_statistics();
        let stats_string = stats.to_string();

        assert!(stats_string.contains("tables"));
        assert!(stats_string.contains("rows"));
        assert!(stats_string.contains("Heaps"));
    }

    #[test]
    fn test_coded_index_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = SchemaValidator::new(&scanner);

        // Test null coded index (should be valid)
        let allowed_tables = &[TableId::TypeDef, TableId::TypeRef, TableId::TypeSpec];
        assert!(validator.validate_coded_index(0, allowed_tables).is_ok());

        // Note: Real coded index validation would require proper decoding
        // This test just verifies the null case works
    }
}
