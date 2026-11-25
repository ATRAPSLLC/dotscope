//! StandAloneSigBuilder for creating standalone signature specifications.
//!
//! This module provides [`crate::metadata::tables::standalonesig::StandAloneSigBuilder`] for creating StandAloneSig table entries
//! with a fluent API. Standalone signatures provide metadata signatures that are not
//! directly associated with specific methods, fields, or properties, supporting complex
//! scenarios like method pointers, local variables, and dynamic signature generation.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{StandAloneSigRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating StandAloneSig metadata entries.
///
/// `StandAloneSigBuilder` provides a fluent API for creating StandAloneSig table entries
/// with validation and automatic blob management. Standalone signatures are used for
/// various metadata scenarios including method pointers, local variable declarations,
/// and CIL instruction operands that require signature information.
///
/// # Standalone Signature Model
///
/// .NET standalone signatures follow a flexible architecture:
/// - **Signature Blob**: Binary representation of type and calling convention information
/// - **Multiple Uses**: Same signature can be referenced from multiple contexts
/// - **Type Resolution**: Signatures contain encoded type references and specifications
/// - **Calling Conventions**: Method signatures include calling convention information
/// - **Local Variables**: Method local variable type declarations
/// - **Generic Support**: Generic type parameters and constraints
///
/// # Signature Types and Scenarios
///
/// Different signature patterns serve various metadata scenarios:
/// - **Method Signatures**: Function pointer signatures with calling conventions and parameters
/// - **Local Variable Signatures**: Method local variable type declarations for proper runtime allocation
/// - **Field Signatures**: Standalone field type specifications for dynamic scenarios
/// - **Generic Signatures**: Generic type and method instantiation signatures with type constraints
/// - **Delegate Signatures**: Delegate type definitions with invoke method signatures
/// - **CIL Instruction Support**: Signatures referenced by CIL instructions like `calli` and `ldftn`
///
/// # Signature Blob Format
///
/// Signatures are stored as binary blobs containing:
/// - **Calling Convention**: Method calling convention flags and type
/// - **Parameter Count**: Number of parameters for method signatures
/// - **Return Type**: Return type specification for method signatures
/// - **Parameter Types**: Type specifications for each parameter
/// - **Generic Information**: Generic parameter count and constraints
/// - **Local Variables**: Local variable types and initialization information
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Create a method signature for a function pointer
/// let method_signature = vec![
///     0x00, // Calling convention: DEFAULT
///     0x02, // Parameter count: 2
///     0x01, // Return type: ELEMENT_TYPE_VOID
///     0x08, // Parameter 1: ELEMENT_TYPE_I4 (int32)
///     0x0E, // Parameter 2: ELEMENT_TYPE_STRING
/// ];
///
/// let method_sig_token = StandAloneSigBuilder::new()
///     .signature(&method_signature)
///     .build(&mut assembly)?;
///
/// // Create a local variable signature
/// let locals_signature = vec![
///     0x07, // ELEMENT_TYPE_LOCALVAR signature
///     0x03, // Local variable count: 3
///     0x08, // Local 0: ELEMENT_TYPE_I4 (int32)
///     0x0E, // Local 1: ELEMENT_TYPE_STRING
///     0x1C, // Local 2: ELEMENT_TYPE_OBJECT
/// ];
///
/// let locals_sig_token = StandAloneSigBuilder::new()
///     .signature(&locals_signature)
///     .build(&mut assembly)?;
///
/// // Create a complex generic method signature
/// let generic_method_signature = vec![
///     0x10, // Calling convention: GENERIC
///     0x01, // Generic parameter count: 1
///     0x02, // Parameter count: 2
///     0x13, // Return type: ELEMENT_TYPE_VAR (generic parameter 0)
///     0x00, // Generic parameter index: 0
///     0x13, // Parameter 1: ELEMENT_TYPE_VAR (generic parameter 0)
///     0x00, // Generic parameter index: 0
///     0x08, // Parameter 2: ELEMENT_TYPE_I4 (int32)
/// ];
///
/// let generic_sig_token = StandAloneSigBuilder::new()
///     .signature(&generic_method_signature)
///     .build(&mut assembly)?;
///
/// // Create a delegate signature with multiple parameters
/// let delegate_signature = vec![
///     0x00, // Calling convention: DEFAULT
///     0x04, // Parameter count: 4
///     0x08, // Return type: ELEMENT_TYPE_I4 (int32)
///     0x0E, // Parameter 1: ELEMENT_TYPE_STRING
///     0x08, // Parameter 2: ELEMENT_TYPE_I4 (int32)
///     0x1C, // Parameter 3: ELEMENT_TYPE_OBJECT
///     0x01, // Parameter 4: ELEMENT_TYPE_VOID pointer
/// ];
///
/// let delegate_sig_token = StandAloneSigBuilder::new()
///     .signature(&delegate_signature)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct StandAloneSigBuilder {
    signature: Option<Vec<u8>>,
}

impl Default for StandAloneSigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl StandAloneSigBuilder {
    /// Creates a new StandAloneSigBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::standalonesig::StandAloneSigBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self { signature: None }
    }

    /// Sets the signature blob data.
    ///
    /// Specifies the binary signature data that defines the type information,
    /// calling conventions, and parameter details for this standalone signature.
    /// The signature blob format follows the ECMA-335 specification for
    /// signature encoding.
    ///
    /// # Arguments
    ///
    /// * `data` - The signature blob data as a byte slice
    ///
    /// # Returns
    ///
    /// The builder instance for method chaining.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::metadata::tables::StandAloneSigBuilder;
    /// let builder = StandAloneSigBuilder::new()
    ///     .signature(&[0x00, 0x01, 0x01]); // Simple void method signature
    /// ```
    #[must_use]
    pub fn signature(mut self, data: &[u8]) -> Self {
        self.signature = Some(data.to_vec());
        self
    }

    /// Builds the StandAloneSig entry and adds it to the assembly.
    ///
    /// Validates all required fields, adds the signature to the blob heap,
    /// creates the StandAloneSigRaw structure, and adds it to the assembly's
    /// StandAloneSig table. Returns a token that can be used to reference
    /// this standalone signature.
    ///
    /// # Arguments
    ///
    /// * `assembly` - CilAssembly for heap and table management
    ///
    /// # Returns
    ///
    /// Returns a `Result<Token>` containing the token for the new StandAloneSig entry,
    /// or an error if validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// This method returns an error if:
    /// - `signature` is not specified (required field)
    /// - The signature blob is empty or invalid
    /// - Blob heap operations fail
    /// - Table operations fail
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # use dotscope::prelude::*;
    /// # use std::path::Path;
    /// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
    /// # let mut assembly = CilAssembly::new(view);
    /// let signature_data = vec![0x00, 0x01, 0x01]; // Simple method signature
    /// let token = StandAloneSigBuilder::new()
    ///     .signature(&signature_data)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let signature_data = self
            .signature
            .ok_or_else(|| Error::ModificationInvalid("signature field is required".to_string()))?;

        if signature_data.is_empty() {
            return Err(Error::ModificationInvalid(
                "signature cannot be empty".to_string(),
            ));
        }

        let signature_index = assembly.blob_add(&signature_data)?.placeholder();

        let standalonesig_raw = StandAloneSigRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            signature: signature_index,
        };

        assembly.table_row_add(
            TableId::StandAloneSig,
            TableDataOwned::StandAloneSig(standalonesig_raw),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::testkit::factories::table::assemblyref::get_test_assembly;

    #[test]
    fn test_standalonesig_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        let signature = vec![0x00, 0x01, 0x01]; // Simple method signature: DEFAULT, 1 param, VOID
        let _change_ref = StandAloneSigBuilder::new()
            .signature(&signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_method_signature() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Method signature: DEFAULT calling convention, 2 params, returns I4, params: I4, STRING
        let method_signature = vec![
            0x00, // Calling convention: DEFAULT
            0x02, // Parameter count: 2
            0x08, // Return type: ELEMENT_TYPE_I4 (int32)
            0x08, // Parameter 1: ELEMENT_TYPE_I4 (int32)
            0x0E, // Parameter 2: ELEMENT_TYPE_STRING
        ];

        let _change_ref = StandAloneSigBuilder::new()
            .signature(&method_signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_locals_signature() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Local variable signature: 3 locals of types I4, STRING, OBJECT
        let locals_signature = vec![
            0x07, // ELEMENT_TYPE_LOCALVAR signature
            0x03, // Local variable count: 3
            0x08, // Local 0: ELEMENT_TYPE_I4 (int32)
            0x0E, // Local 1: ELEMENT_TYPE_STRING
            0x1C, // Local 2: ELEMENT_TYPE_OBJECT
        ];

        let _change_ref = StandAloneSigBuilder::new()
            .signature(&locals_signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_generic_signature() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Generic method signature: GENERIC calling convention, 1 generic param, 2 params
        let generic_signature = vec![
            0x10, // Calling convention: GENERIC
            0x01, // Generic parameter count: 1
            0x02, // Parameter count: 2
            0x13, // Return type: ELEMENT_TYPE_VAR (generic parameter 0)
            0x00, // Generic parameter index: 0
            0x13, // Parameter 1: ELEMENT_TYPE_VAR (generic parameter 0)
            0x00, // Generic parameter index: 0
            0x08, // Parameter 2: ELEMENT_TYPE_I4 (int32)
        ];

        let _change_ref = StandAloneSigBuilder::new()
            .signature(&generic_signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_complex_signature() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Complex signature with arrays and pointers
        let complex_signature = vec![
            0x00, // Calling convention: DEFAULT
            0x03, // Parameter count: 3
            0x01, // Return type: ELEMENT_TYPE_VOID
            0x1D, // Parameter 1: ELEMENT_TYPE_SZARRAY (single-dimensional array)
            0x08, // Array element type: ELEMENT_TYPE_I4 (int32[])
            0x0F, // Parameter 2: ELEMENT_TYPE_PTR (pointer)
            0x01, // Pointer target: ELEMENT_TYPE_VOID (void*)
            0x1C, // Parameter 3: ELEMENT_TYPE_OBJECT
        ];

        let _change_ref = StandAloneSigBuilder::new()
            .signature(&complex_signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_missing_signature() {
        let mut assembly = get_test_assembly().unwrap();

        let result = StandAloneSigBuilder::new().build(&mut assembly);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("signature"));
    }

    #[test]
    fn test_standalonesig_builder_empty_signature() {
        let mut assembly = get_test_assembly().unwrap();

        let result = StandAloneSigBuilder::new()
            .signature(&[])
            .build(&mut assembly);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("signature cannot be empty"));
    }

    #[test]
    fn test_standalonesig_builder_default() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Test Default trait implementation
        let signature = vec![0x00, 0x00, 0x01]; // No-param void method
        let _change_ref = StandAloneSigBuilder::default()
            .signature(&signature)
            .build(&mut assembly)?;

        Ok(())
    }

    #[test]
    fn test_standalonesig_builder_multiple_signatures() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create multiple different signatures
        let sig1 = vec![0x00, 0x00, 0x01]; // No-param void method
        let sig2 = vec![0x00, 0x01, 0x08, 0x08]; // One I4 param, returns I4
        let sig3 = vec![0x07, 0x02, 0x08, 0x0E]; // Two locals: I4, STRING

        let ref1 = StandAloneSigBuilder::new()
            .signature(&sig1)
            .build(&mut assembly)?;

        let ref2 = StandAloneSigBuilder::new()
            .signature(&sig2)
            .build(&mut assembly)?;

        let ref3 = StandAloneSigBuilder::new()
            .signature(&sig3)
            .build(&mut assembly)?;

        // All change refs should be different
        assert!(!Arc::ptr_eq(&ref1, &ref2));
        assert!(!Arc::ptr_eq(&ref2, &ref3));
        assert!(!Arc::ptr_eq(&ref1, &ref3));

        Ok(())
    }
}
