//! Builder for constructing `LocalConstant` table entries
//!
//! This module provides the [`crate::metadata::tables::localconstant::LocalConstantBuilder`] which enables fluent construction
//! of `LocalConstant` metadata table entries. The builder follows the established
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
//! let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4 signature
//!
//! let constant_token = LocalConstantBuilder::new()
//!     .name("PI")                    // Constant name
//!     .signature(&signature_bytes)   // Raw signature bytes
//!     .build(&mut assembly)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        pdb::LocalConstantSig,
        tables::{LocalConstantRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for constructing `LocalConstant` table entries
///
/// Provides a fluent interface for building `LocalConstant` metadata table entries.
/// The builder validates all required fields are provided and handles proper
/// integration with the metadata system.
///
/// # Required Fields
/// - `name`: Constant name (can be empty for anonymous constants, but must be explicitly set)
/// - `signature`: Raw signature bytes (must be provided)
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::prelude::*;
///
/// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
/// # let mut assembly = CilAssembly::new(view);
/// // Named local constant with I4 signature
/// let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
/// let constant_token = LocalConstantBuilder::new()
///     .name("MAX_VALUE")
///     .signature(&signature_bytes)
///     .build(&mut assembly)?;
///
/// // Anonymous constant (compiler-generated)
/// let anon_token = LocalConstantBuilder::new()
///     .name("")  // Empty name for anonymous constant
///     .signature(&signature_bytes)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug, Clone)]
pub struct LocalConstantBuilder {
    /// Constant name (empty string for anonymous constants)
    name: Option<String>,
    /// Raw signature bytes for the constant type
    signature: Option<Vec<u8>>,
    /// The signature, decoded: encoded when the entry is built
    parsed: Option<LocalConstantSig>,
}

impl LocalConstantBuilder {
    /// Creates a new `LocalConstantBuilder` with default values
    ///
    /// Initializes a new builder instance with all fields unset. The caller
    /// must provide the required fields (name and signature) before calling build().
    ///
    /// # Returns
    /// A new `LocalConstantBuilder` instance ready for configuration
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// let builder = LocalConstantBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            signature: None,
            parsed: None,
        }
    }

    /// Sets the constant name
    ///
    /// Specifies the name for this local constant. The name can be empty
    /// for anonymous or compiler-generated constants.
    ///
    /// # Parameters
    /// - `name`: The constant name (can be empty string)
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // Named constant
    /// let builder = LocalConstantBuilder::new()
    ///     .name("PI");
    ///
    /// // Anonymous constant
    /// let anon_builder = LocalConstantBuilder::new()
    ///     .name("");
    /// ```
    #[must_use]
    pub fn name<T: Into<String>>(mut self, name: T) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the constant signature bytes
    ///
    /// Specifies the raw signature bytes for this local constant. These bytes
    /// represent the field signature format as defined in ECMA-335.
    ///
    /// # Parameters
    /// - `signature`: The raw signature bytes
    ///
    /// # Returns
    /// Self for method chaining
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// // I4 (int32) constant signature
    /// let i4_signature = vec![0x08]; // ELEMENT_TYPE_I4
    /// let builder = LocalConstantBuilder::new()
    ///     .signature(&i4_signature);
    ///
    /// // String constant signature  
    /// let string_signature = vec![0x0E]; // ELEMENT_TYPE_STRING
    /// let builder = LocalConstantBuilder::new()
    ///     .signature(&string_signature);
    /// ```
    #[must_use]
    pub fn signature(mut self, signature: &[u8]) -> Self {
        self.signature = Some(signature.to_vec());
        self.parsed = None;
        self
    }

    /// Sets the constant's type and value, decoded: the LocalConstantSig blob is encoded when
    /// [`build`](Self::build) runs.
    ///
    /// The types it names are TypeDef, TypeRef or TypeSpec tokens of the input, or of rows a
    /// change adds, named by their placeholders; the writer renumbers them with the rows.
    ///
    /// # Arguments
    ///
    /// * `signature` - The constant's custom modifiers, type and value
    ///
    /// # Errors
    ///
    /// [`build`](Self::build) fails when the signature cannot be encoded
    /// ([`LocalConstantSig::encode`]).
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::{
    ///     metadata::pdb::{LocalConstantSig, LocalConstantValue, PrimitiveConstant},
    ///     prelude::*,
    /// };
    ///
    /// let builder = LocalConstantBuilder::new()
    ///     .name("answer")
    ///     .signature_parsed(LocalConstantSig {
    ///         modifiers: Vec::new(),
    ///         value: LocalConstantValue::Primitive(PrimitiveConstant::I4(42)),
    ///     });
    /// ```
    #[must_use]
    pub fn signature_parsed(mut self, signature: LocalConstantSig) -> Self {
        self.parsed = Some(signature);
        self.signature = None;
        self
    }

    /// Builds and adds the `LocalConstant` entry to the metadata
    ///
    /// Validates all required fields, creates the `LocalConstant` table entry,
    /// and adds it to the CIL assembly. Returns a token that can be used
    /// to reference this local constant.
    ///
    /// # Parameters
    /// - `assembly`: Mutable reference to the CIL assembly
    ///
    /// # Returns
    /// - `Ok(Token)`: Token referencing the created local constant
    /// - `Err(Error)`: If validation fails or table operations fail
    ///
    /// # Errors
    /// - Missing required field (name or signature)
    /// - Table operations fail due to metadata constraints
    /// - Local constant validation failed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::prelude::*;
    ///
    /// # let view = CilAssemblyView::from_path(std::path::Path::new("a.dll")).unwrap();
    /// let mut assembly = CilAssembly::new(view);
    /// let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
    /// let token = LocalConstantBuilder::new()
    ///     .name("myConstant")
    ///     .signature(&signature_bytes)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let name = self.name.ok_or_else(|| {
            Error::ModificationInvalid(
                "Constant name is required for LocalConstant (use empty string for anonymous)"
                    .to_string(),
            )
        })?;

        let signature = match (self.signature, &self.parsed) {
            (Some(signature), _) => signature,
            (None, Some(parsed)) => parsed.encode()?,
            (None, None) => {
                return Err(Error::ModificationInvalid(
                    "Constant signature is required for LocalConstant".to_string(),
                ))
            }
        };

        let name_index = if name.is_empty() {
            0
        } else {
            assembly.string_add(&name)?.placeholder()
        };

        let signature_index = if signature.is_empty() {
            0
        } else {
            assembly.blob_add(&signature)?.placeholder()
        };

        let local_constant = LocalConstantRaw {
            rid: 0,
            token: Token::new(0),
            offset: 0,
            name: name_index,
            signature: signature_index,
        };

        assembly.table_row_add(
            TableId::LocalConstant,
            TableDataOwned::LocalConstant(local_constant),
        )
    }
}

impl Default for LocalConstantBuilder {
    /// Creates a default `LocalConstantBuilder`
    ///
    /// Equivalent to calling [`LocalConstantBuilder::new()`].
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cilassembly::ChangeRefKind, metadata::tables::TableId,
        testkit::factories::table::assemblyref::get_test_assembly,
    };

    #[test]
    fn test_localconstant_builder_new() {
        let builder = LocalConstantBuilder::new();

        assert!(builder.name.is_none());
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_localconstant_builder_default() {
        let builder = LocalConstantBuilder::default();

        assert!(builder.name.is_none());
        assert!(builder.signature.is_none());
    }

    #[test]
    fn test_localconstant_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let ref_ = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalConstant));
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_anonymous_constant() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let signature_bytes = vec![0x0E]; // ELEMENT_TYPE_STRING
        let ref_ = LocalConstantBuilder::new()
            .name("") // Empty name for anonymous constant
            .signature(&signature_bytes)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalConstant));
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_missing_name() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let result = LocalConstantBuilder::new()
            .signature(&signature_bytes)
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Constant name is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_missing_signature() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let result = LocalConstantBuilder::new()
            .name("testConstant")
            .build(&mut assembly);

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ModificationInvalid(details) => {
                assert!(details.contains("Constant signature is required"));
            }
            _ => panic!("Expected ModificationInvalid error"),
        }
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_clone() {
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let builder = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes);

        let cloned = builder.clone();
        assert_eq!(builder.name, cloned.name);
        assert_eq!(builder.signature, cloned.signature);
    }

    #[test]
    fn test_localconstant_builder_debug() {
        let signature_bytes = vec![0x08]; // ELEMENT_TYPE_I4
        let builder = LocalConstantBuilder::new()
            .name("testConstant")
            .signature(&signature_bytes);

        let debug_str = format!("{builder:?}");
        assert!(debug_str.contains("LocalConstantBuilder"));
        assert!(debug_str.contains("name"));
        assert!(debug_str.contains("signature"));
    }

    #[test]
    fn test_localconstant_builder_fluent_interface() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let signature_bytes = vec![0x02]; // ELEMENT_TYPE_BOOLEAN

        // Test method chaining
        let ref_ = LocalConstantBuilder::new()
            .name("chainedConstant")
            .signature(&signature_bytes)
            .build(&mut assembly)
            .expect("Should build successfully");

        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::LocalConstant));
        Ok(())
    }

    #[test]
    fn test_localconstant_builder_multiple_builds() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let signature1 = vec![0x08]; // ELEMENT_TYPE_I4
        let signature2 = vec![0x0E]; // ELEMENT_TYPE_STRING

        // Build first constant
        let ref1 = LocalConstantBuilder::new()
            .name("constant1")
            .signature(&signature1)
            .build(&mut assembly)
            .expect("Should build first constant");

        // Build second constant
        let ref2 = LocalConstantBuilder::new()
            .name("constant2")
            .signature(&signature2)
            .build(&mut assembly)
            .expect("Should build second constant");

        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::LocalConstant));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::LocalConstant));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        Ok(())
    }
}
