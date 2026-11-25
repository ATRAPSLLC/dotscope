//! ParamBuilder for creating parameter definitions.
//!
//! This module provides [`crate::metadata::tables::param::ParamBuilder`] for creating Param table entries
//! with a fluent API. Parameters define method parameter information including
//! names, attributes, sequence numbers, and characteristics for proper method
//! signature construction and parameter binding.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        tables::{ParamAttributes, ParamRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating Param metadata entries.
///
/// `ParamBuilder` provides a fluent API for creating Param table entries
/// with validation and automatic heap management. Param entries define
/// method parameter information including names, attributes, sequence numbers,
/// and marshalling information for proper method invocation.
///
/// # Parameter Sequencing
///
/// The sequence field determines parameter ordering:
/// - **0**: Reserved for return type information
/// - **1+**: Method parameters in declaration order
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use dotscope::metadata::tables::ParamBuilder;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// # let mut assembly = CilAssembly::new(view);
///
/// // Create a method parameter
/// let param = ParamBuilder::new()
///     .name("value")
///     .flags(ParamAttributes::IN)
///     .sequence(1)   // First parameter
///     .build(&mut assembly)?;
///
/// // Create a return type parameter (no name, sequence 0)
/// let return_param = ParamBuilder::new()
///     .flags(ParamAttributes::ZERO)
///     .sequence(0)   // Return type
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct ParamBuilder {
    name: Option<String>,
    flags: Option<ParamAttributes>,
    sequence: Option<u32>,
}

impl Default for ParamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ParamBuilder {
    /// Creates a new ParamBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::param::ParamBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: None,
            flags: None,
            sequence: None,
        }
    }

    /// Sets the parameter name.
    ///
    /// Parameter names are used for debugging, reflection, and IDE support.
    /// Return type parameters (sequence 0) typically don't have names.
    ///
    /// # Arguments
    ///
    /// * `name` - The parameter name (must be a valid identifier)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the parameter flags (attributes).
    ///
    /// Parameter flags control direction, optional status, and special behaviors.
    /// Common flag values from [`crate::metadata::tables::ParamAttributes`]:
    /// - `0x0001`: IN - Parameter is input (default for most parameters)
    /// - `0x0002`: OUT - Parameter is output (for ref/out parameters)
    /// - `0x0010`: OPTIONAL - Parameter is optional (COM interop)
    /// - `0x1000`: HAS_DEFAULT - Parameter has default value in Constant table
    /// - `0x2000`: HAS_FIELD_MARSHAL - Parameter has marshalling information
    ///
    /// # Arguments
    ///
    /// * `flags` - The parameter attribute flags bitmask
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn flags(mut self, flags: ParamAttributes) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the parameter sequence number.
    ///
    /// The sequence number determines parameter ordering in method signatures:
    /// - **0**: Return type parameter (usually unnamed)
    /// - **1**: First method parameter
    /// - **2**: Second method parameter
    /// - **N**: Nth method parameter
    ///
    /// # Arguments
    ///
    /// * `sequence` - The parameter sequence number (0 for return type, 1+ for parameters)
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn sequence(mut self, sequence: u32) -> Self {
        self.sequence = Some(sequence);
        self
    }

    /// Builds the parameter and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the name to
    /// the string heap (if provided), creates the raw parameter structure,
    /// and adds it to the Param table.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The CilAssembly being modified
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created parameter, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if flags are not set
    /// - Returns error if sequence is not set
    /// - Returns error if heap operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        let flags = self.flags.ok_or_else(|| {
            Error::ModificationInvalid("Parameter flags are required".to_string())
        })?;

        let sequence = self.sequence.ok_or_else(|| {
            Error::ModificationInvalid("Parameter sequence is required".to_string())
        })?;

        let name_index = if let Some(name) = self.name {
            assembly.string_get_or_add(&name)?.placeholder()
        } else {
            0 // No name (common for return type parameters)
        };

        let rid = assembly.next_rid(TableId::Param)?;

        let token = Token::from_parts(TableId::Param, rid);

        let param_raw = ParamRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            flags: flags.bits(),
            sequence,
            name: name_index,
        };

        assembly.table_row_add(TableId::Param, TableDataOwned::Param(param_raw))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::{cilassemblyview::CilAssemblyView, tables::ParamAttributes},
        testkit::fixture,
    };

    #[test]
    fn test_param_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let ref_ = ParamBuilder::new()
            .name("testParam")
            .flags(ParamAttributes::IN)
            .sequence(1)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Param));
    }

    #[test]
    fn test_param_builder_return_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a return type parameter (no name, sequence 0)
        let ref_ = ParamBuilder::new()
            .flags(ParamAttributes::ZERO) // No special flags for return type
            .sequence(0) // Return type
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Param));
    }

    #[test]
    fn test_param_builder_with_attributes() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create an OUT parameter with optional flag
        let ref_ = ParamBuilder::new()
            .name("outParam")
            .flags(ParamAttributes::OUT | ParamAttributes::OPTIONAL)
            .sequence(2)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Param));
    }

    #[test]
    fn test_param_builder_default_value() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a parameter with default value
        let ref_ = ParamBuilder::new()
            .name("defaultParam")
            .flags(ParamAttributes::IN | ParamAttributes::HAS_DEFAULT)
            .sequence(3)
            .build(&mut assembly)
            .unwrap();

        // Verify reference is created correctly
        assert_eq!(ref_.kind(), ChangeRefKind::TableRow(TableId::Param));
    }

    #[test]
    fn test_param_builder_missing_flags() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = ParamBuilder::new()
            .name("testParam")
            .sequence(1)
            .build(&mut assembly);

        // Should fail because flags are required
        assert!(result.is_err());
    }

    #[test]
    fn test_param_builder_missing_sequence() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let result = ParamBuilder::new()
            .name("testParam")
            .flags(ParamAttributes::IN)
            .build(&mut assembly);

        // Should fail because sequence is required
        assert!(result.is_err());
    }

    #[test]
    fn test_param_builder_multiple_params() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create multiple parameters with different sequences
        let ref1 = ParamBuilder::new()
            .name("param1")
            .flags(ParamAttributes::IN)
            .sequence(1)
            .build(&mut assembly)
            .unwrap();

        let ref2 = ParamBuilder::new()
            .name("param2")
            .flags(ParamAttributes::OUT)
            .sequence(2)
            .build(&mut assembly)
            .unwrap();

        let ref3 = ParamBuilder::new()
            .flags(ParamAttributes::ZERO)
            .sequence(0) // Return type
            .build(&mut assembly)
            .unwrap();

        // All should succeed and have different references
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref2));
        assert!(!std::sync::Arc::ptr_eq(&ref1, &ref3));
        assert!(!std::sync::Arc::ptr_eq(&ref2, &ref3));

        // All should have Param table kind
        assert_eq!(ref1.kind(), ChangeRefKind::TableRow(TableId::Param));
        assert_eq!(ref2.kind(), ChangeRefKind::TableRow(TableId::Param));
        assert_eq!(ref3.kind(), ChangeRefKind::TableRow(TableId::Param));
    }
}
