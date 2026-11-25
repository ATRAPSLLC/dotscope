//! # FieldRVA Builder
//!
//! Provides a fluent API for building FieldRVA table entries that define Relative Virtual Addresses (RVAs)
//! for fields with initial data stored in the PE file. The FieldRVA table enables static field initialization,
//! constant data embedding, and global variable setup with pre-computed values.
//!
//! ## Overview
//!
//! The `FieldRVABuilder` enables creation of field RVA entries with:
//! - Field row index specification (required)
//! - RVA location for initial data (required)
//! - Validation of field row indices and RVA values
//! - Automatic metadata management
//!
//! ## Usage
//!
//! ```no_run
//! # use dotscope::prelude::*;
//! # use std::path::Path;
//! # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
//! # let mut assembly = CilAssembly::new(view);
//!
//! // Create a field signature for static data
//! let field_sig = vec![0x06, 0x08]; // FIELD, ELEMENT_TYPE_I4
//!
//! // Create a field first
//! let field_ref = FieldBuilder::new()
//!     .name("StaticData")
//!     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
//!     .signature(&field_sig)
//!     .build(&mut assembly)?;
//!
//! // Create a field RVA entry for static field initialization
//! let field_rva_ref = FieldRVABuilder::new()
//!     .field(field_ref.placeholder())
//!     .rva(0x2000) // RVA pointing to initial data
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Design
//!
//! The builder follows the established pattern with:
//! - **Validation**: Field row index and RVA are required and validated
//! - **Field Verification**: Ensures field row index is valid and non-zero
//! - **Automatic Management**: Metadata entries are created automatically
//! - **RVA Validation**: Ensures RVA values are non-zero and valid

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{FieldRvaRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldRVA table entries.
///
/// `FieldRVABuilder` provides a fluent API for creating entries in the FieldRVA
/// metadata table, which specifies Relative Virtual Addresses for fields that have
/// initial data stored in the PE file.
///
/// # Purpose
///
/// The FieldRVA table serves several key functions:
/// - **Static Field Initialization**: Pre-computed values for static fields
/// - **Constant Data**: Read-only data embedded directly in the PE file
/// - **Global Variables**: Module-level data with specific initial states
/// - **Interop Data**: Native data structures for P/Invoke and COM scenarios
/// - **Resource Embedding**: Binary resources accessible through field references
///
/// # Builder Pattern
///
/// The builder provides a fluent interface for constructing FieldRVA entries:
///
/// ```no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
/// # let field_ref = FieldBuilder::new()
/// #     .name("StaticData")
/// #     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
/// #     .signature(&[0x06, 0x08])
/// #     .build(&mut assembly)?;
///
/// let field_rva_ref = FieldRVABuilder::new()
///     .field(field_ref.placeholder())
///     .rva(0x2000)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Validation
///
/// The builder enforces the following constraints:
/// - **Field Required**: A field row index must be provided
/// - **Field Validation**: Field row index must be non-zero
/// - **RVA Required**: An RVA value must be provided
/// - **RVA Validation**: RVA values must be greater than 0
///
/// # Integration
///
/// FieldRVA entries integrate with other metadata structures:
/// - **Field**: References specific fields in the Field table
/// - **PE Sections**: RVAs point to data in specific PE file sections
/// - **Static Data**: Enables runtime access to pre-initialized field values
#[derive(Debug, Clone)]
pub struct FieldRVABuilder {
    /// The row index of the field with initial data
    field: Option<u32>,
    /// The RVA pointing to the field's initial data
    rva: Option<u32>,
}

impl Default for FieldRVABuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldRVABuilder {
    /// Creates a new `FieldRVABuilder` instance.
    ///
    /// Returns a builder with all fields unset, ready for configuration
    /// through the fluent API methods.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FieldRVABuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            field: None,
            rva: None,
        }
    }

    /// Sets the field row index for the field with initial data.
    ///
    /// The field must be a valid Field table row index or placeholder that represents
    /// the field that has initial data stored at the specified RVA location.
    ///
    /// # Arguments
    ///
    /// * `field` - Row index or placeholder of the Field table entry
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let field_sig = vec![0x06]; // Simple type signature
    /// let field_ref = FieldBuilder::new()
    ///     .name("StaticArray")
    ///     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
    ///     .signature(&field_sig)
    ///     .build(&mut assembly)?;
    ///
    /// let builder = FieldRVABuilder::new()
    ///     .field(field_ref.placeholder());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn field(mut self, field: u32) -> Self {
        self.field = Some(field);
        self
    }

    /// Sets the RVA pointing to the field's initial data.
    ///
    /// The RVA (Relative Virtual Address) specifies the location within the PE file
    /// where the field's initial data is stored. This address is relative to the
    /// image base and must point to valid data.
    ///
    /// # Arguments
    ///
    /// * `rva` - The RVA value pointing to initial data
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use dotscope::prelude::*;
    /// let builder = FieldRVABuilder::new()
    ///     .rva(0x2000); // RVA pointing to initial data
    /// ```
    #[must_use]
    pub fn rva(mut self, rva: u32) -> Self {
        self.rva = Some(rva);
        self
    }

    /// Builds the FieldRVA entry and adds it to the assembly.
    ///
    /// This method validates all required fields, verifies the field row index is valid,
    /// validates the RVA value, creates the FieldRVA table entry, and returns a
    /// reference to the new entry.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly being modified
    ///
    /// # Returns
    ///
    /// Returns a reference to the newly created FieldRVA entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The field row index is not set
    /// - The field row index is 0
    /// - The RVA is not set
    /// - The RVA value is 0
    /// - There are issues adding the table row
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// # let field_ref = FieldBuilder::new()
    /// #     .name("StaticData")
    /// #     .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
    /// #     .signature(&[0x06, 0x08])
    /// #     .build(&mut assembly)?;
    ///
    /// let field_rva_ref = FieldRVABuilder::new()
    ///     .field(field_ref.placeholder())
    ///     .rva(0x2000)
    ///     .build(&mut assembly)?;
    ///
    /// println!("Created FieldRVA entry");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let field = self.field.ok_or_else(|| {
            Error::ModificationInvalid("Field row index is required for FieldRVA".to_string())
        })?;

        let rva = self.rva.ok_or_else(|| {
            Error::ModificationInvalid("RVA is required for FieldRVA".to_string())
        })?;

        if field == 0 {
            return Err(Error::ModificationInvalid(
                "Field row index cannot be 0".to_string(),
            ));
        }

        if rva == 0 {
            return Err(Error::ModificationInvalid("RVA cannot be 0".to_string()));
        }

        let field_rva = FieldRvaRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            rva,
            field,
        };

        assembly.table_row_add(TableId::FieldRVA, TableDataOwned::FieldRVA(field_rva))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind,
        metadata::tables::{FieldAttributes, TableId},
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_field_rva_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a Field for testing
        let field_ref = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06]) // Simple signature
            .build(&mut assembly)?;

        let rva_ref = FieldRVABuilder::new()
            .field(field_ref.placeholder())
            .rva(0x2000)
            .build(&mut assembly)?;

        // Verify the ref has the correct kind
        assert_eq!(rva_ref.kind(), ChangeRefKind::TableRow(TableId::FieldRVA));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_default() -> Result<()> {
        let builder = FieldRVABuilder::default();
        assert!(builder.field.is_none());
        assert!(builder.rva.is_none());
        Ok(())
    }

    #[test]
    fn test_field_rva_builder_missing_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let result = FieldRVABuilder::new().rva(0x2000).build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Field row index is required"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_missing_rva() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a Field for testing
        let field_ref = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut assembly)?;

        let result = FieldRVABuilder::new()
            .field(field_ref.placeholder())
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("RVA is required"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_zero_field() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Use a zero field row index (invalid)
        let result = FieldRVABuilder::new()
            .field(0)
            .rva(0x2000)
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Field row index cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_zero_rva() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a Field for testing
        let field_ref = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut assembly)?;

        let result = FieldRVABuilder::new()
            .field(field_ref.placeholder())
            .rva(0) // Zero RVA is invalid
            .build(&mut assembly);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("RVA cannot be 0"));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_multiple_entries() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create Fields for testing
        let field1_ref = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData1")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut assembly)?;

        let field2_ref = crate::metadata::tables::FieldBuilder::new()
            .name("StaticData2")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut assembly)?;

        let rva1_ref = FieldRVABuilder::new()
            .field(field1_ref.placeholder())
            .rva(0x2000)
            .build(&mut assembly)?;

        let rva2_ref = FieldRVABuilder::new()
            .field(field2_ref.placeholder())
            .rva(0x3000)
            .build(&mut assembly)?;

        // Verify refs are different
        assert!(!std::sync::Arc::ptr_eq(&rva1_ref, &rva2_ref));
        assert_eq!(rva1_ref.kind(), ChangeRefKind::TableRow(TableId::FieldRVA));
        assert_eq!(rva2_ref.kind(), ChangeRefKind::TableRow(TableId::FieldRVA));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_various_rva_values() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test with different RVA values
        let test_rvas = [0x1000, 0x2000, 0x4000, 0x8000, 0x10000];

        for (i, &rva) in test_rvas.iter().enumerate() {
            let field_ref = crate::metadata::tables::FieldBuilder::new()
                .name(format!("StaticData{i}"))
                .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
                .signature(&[0x06])
                .build(&mut assembly)?;

            let rva_ref = FieldRVABuilder::new()
                .field(field_ref.placeholder())
                .rva(rva)
                .build(&mut assembly)?;

            assert_eq!(rva_ref.kind(), ChangeRefKind::TableRow(TableId::FieldRVA));
        }

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_fluent_api() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a Field for testing
        let field_ref = crate::metadata::tables::FieldBuilder::new()
            .name("FluentTestField")
            .flags(FieldAttributes::STATIC | FieldAttributes::PRIVATE)
            .signature(&[0x06])
            .build(&mut assembly)?;

        // Test fluent API chaining
        let rva_ref = FieldRVABuilder::new()
            .field(field_ref.placeholder())
            .rva(0x5000)
            .build(&mut assembly)?;

        assert_eq!(rva_ref.kind(), ChangeRefKind::TableRow(TableId::FieldRVA));

        Ok(())
    }

    #[test]
    fn test_field_rva_builder_clone() {
        let builder1 = FieldRVABuilder::new().field(1).rva(0x2000);
        let builder2 = builder1.clone();

        assert_eq!(builder1.field, builder2.field);
        assert_eq!(builder1.rva, builder2.rva);
    }

    #[test]
    fn test_field_rva_builder_debug() {
        let builder = FieldRVABuilder::new().field(1).rva(0x2000);
        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("FieldRVABuilder"));
    }
}
