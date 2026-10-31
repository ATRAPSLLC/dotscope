//! FieldMarshalBuilder for creating P/Invoke marshaling specifications.
//!
//! This module provides [`crate::metadata::tables::fieldmarshal::FieldMarshalBuilder`] for creating FieldMarshal table entries
//! with a fluent API. Field marshaling defines how managed types are converted to and
//! from native types during P/Invoke calls, COM interop, and platform invoke scenarios,
//! enabling seamless interoperability between managed and unmanaged code.

use crate::{
    cilassembly::{ChangeRefRc, CilAssembly},
    metadata::{
        marshalling::{encode_marshalling_descriptor, MarshallingInfo, NativeType, NATIVE_TYPE},
        tables::{CodedIndex, CodedIndexType, FieldMarshalRaw, TableDataOwned, TableId},
        token::Token,
    },
    Error, Result,
};

/// Builder for creating FieldMarshal metadata entries.
///
/// `FieldMarshalBuilder` provides a fluent API for creating FieldMarshal table entries
/// with validation and automatic blob management. Field marshaling defines the conversion
/// rules between managed and native types for fields and parameters during interop
/// scenarios including P/Invoke calls, COM interop, and platform invoke operations.
///
/// # Marshaling Model
///
/// .NET marshaling follows a structured pattern:
/// - **Parent Entity**: The field or parameter that requires marshaling
/// - **Native Type**: How the managed type appears in native code
/// - **Conversion Rules**: Automatic conversion behavior during calls
/// - **Memory Management**: Responsibility for allocation and cleanup
///
/// # Coded Index Types
///
/// Field marshaling uses the `HasFieldMarshal` coded index to specify targets:
/// - **Field**: Marshaling for struct fields and class fields
/// - **Param**: Marshaling for method parameters and return values
///
/// # Marshaling Scenarios and Types
///
/// Different native types serve various interop scenarios:
/// - **Primitive Types**: Direct mapping for integers, floats, and booleans
/// - **String Types**: Character encoding and memory management (ANSI, Unicode)
/// - **Array Types**: Element type specification and size management
/// - **Pointer Types**: Memory layout and dereferencing behavior
/// - **Interface Types**: COM interface marshaling and reference counting
/// - **Custom Types**: User-defined marshaling with custom marshalers
///
/// # Marshaling Descriptors
///
/// Marshaling information is stored as binary descriptors in the blob heap:
/// - **Simple Types**: Single byte indicating native type (e.g., NATIVE_TYPE_I4)
/// - **Complex Types**: Multi-byte descriptors with parameters (arrays, strings)
/// - **Custom Marshalers**: Full type name and initialization parameters
/// - **Array Descriptors**: Element type, dimensions, and size specifications
///
/// # Examples
///
/// ```rust,no_run
/// # use dotscope::prelude::*;
/// # use std::path::Path;
/// # let view = CilAssemblyView::from_path(Path::new("test.dll"))?;
/// let mut assembly = CilAssembly::new(view);
///
/// // Marshal a parameter as a null-terminated Unicode string
/// let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal); // String parameter
/// let unicode_string_descriptor = vec![NATIVE_TYPE::LPWSTR]; // Simple descriptor
///
/// let string_marshal = FieldMarshalBuilder::new()
///     .parent(param_ref)
///     .native_type(&unicode_string_descriptor)
///     .build(&mut assembly)?;
///
/// // Marshal a field as a fixed-size ANSI character array
/// let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal); // Character array field
/// let fixed_array_descriptor = vec![
///     NATIVE_TYPE::FIXEDARRAY,
///     0x20,           // 32 elements (a compressed integer)
///     NATIVE_TYPE::I1, // of signed bytes
/// ];
///
/// let array_marshal = FieldMarshalBuilder::new()
///     .parent(field_ref)
///     .native_type(&fixed_array_descriptor)
///     .build(&mut assembly)?;
///
/// // Marshal a parameter as a COM interface pointer
/// let interface_param = CodedIndex::new(TableId::Param, 2, CodedIndexType::HasFieldMarshal); // Interface parameter
/// let interface_descriptor = vec![NATIVE_TYPE::INTERFACE]; // COM interface
///
/// let interface_marshal = FieldMarshalBuilder::new()
///     .parent(interface_param)
///     .native_type(&interface_descriptor)
///     .build(&mut assembly)?;
///
/// // Marshal a return value as a platform-dependent integer
/// let return_param = CodedIndex::new(TableId::Param, 0, CodedIndexType::HasFieldMarshal); // Return value (sequence 0)
/// let platform_int_descriptor = vec![NATIVE_TYPE::INT]; // Platform IntPtr
///
/// let return_marshal = FieldMarshalBuilder::new()
///     .parent(return_param)
///     .native_type(&platform_int_descriptor)
///     .build(&mut assembly)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct FieldMarshalBuilder {
    parent: Option<CodedIndex>,
    native_type: Option<Vec<u8>>,
    /// Stores encoding errors from `native_type_spec` or `marshalling_info` methods
    /// to be surfaced at `build()` time.
    encoding_error: Option<Error>,
}

impl Default for FieldMarshalBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldMarshalBuilder {
    /// Creates a new FieldMarshalBuilder.
    ///
    /// # Returns
    ///
    /// A new [`crate::metadata::tables::fieldmarshal::FieldMarshalBuilder`] instance ready for configuration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            parent: None,
            native_type: None,
            encoding_error: None,
        }
    }

    /// Sets the parent field or parameter that requires marshaling.
    ///
    /// The parent must be a valid `HasFieldMarshal` coded index that references
    /// either a field definition or parameter definition. This establishes which
    /// entity will have marshaling behavior applied during interop operations.
    ///
    /// Valid parent types include:
    /// - `Field` - Marshaling for struct fields in P/Invoke scenarios
    /// - `Param` - Marshaling for method parameters and return values
    ///
    /// Marshaling scope considerations:
    /// - **Field marshaling**: Applied when the containing struct crosses managed/native boundary
    /// - **Parameter marshaling**: Applied during each method call that crosses boundaries
    /// - **Return marshaling**: Applied to return values from native methods
    /// - **Array marshaling**: Applied to array elements and overall array structure
    ///
    /// # Arguments
    ///
    /// * `parent` - A `HasFieldMarshal` coded index pointing to the target field or parameter
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn parent(mut self, parent: CodedIndex) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Sets the native type marshaling descriptor.
    ///
    /// The native type descriptor defines how the managed type should be represented
    /// and converted in native code. This binary descriptor is stored in the blob heap
    /// and follows .NET's marshaling specification format.
    ///
    /// Descriptor format varies by complexity:
    /// - **Simple types**: Single byte (e.g., `[NATIVE_TYPE::I4]` for 32-bit integer)
    /// - **String types**: May include encoding and length parameters
    /// - **Array types**: Include element type, dimensions, and size information
    /// - **Custom types**: Include full type names and initialization parameters
    ///
    /// Common descriptor patterns:
    /// - **Primitive**: `[NATIVE_TYPE::I4]` - 32-bit signed integer
    /// - **Unicode String**: `[NATIVE_TYPE_LPWSTR]` - Null-terminated wide string
    /// - **ANSI String**: `[NATIVE_TYPE_LPSTR]` - Null-terminated ANSI string
    /// - **Fixed Array**: `[NATIVE_TYPE_BYVALARRAY, element_type, size...]` - In-place array
    /// - **Interface**: `[NATIVE_TYPE_INTERFACE]` - COM interface pointer
    ///
    /// # Arguments
    ///
    /// * `native_type` - The binary marshaling descriptor specifying conversion behavior
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn native_type(mut self, native_type: &[u8]) -> Self {
        self.native_type = Some(native_type.to_vec());
        self
    }

    /// Sets a simple native type marshaling descriptor.
    ///
    /// This is a convenience method for common marshaling scenarios that require
    /// only a single native type identifier without additional parameters.
    ///
    /// # Arguments
    ///
    /// * `type_id` - The native type identifier from the NativeType constants
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn simple_native_type(mut self, type_id: u8) -> Self {
        self.native_type = Some(vec![type_id]);
        self
    }

    /// Sets Unicode string marshaling (LPWSTR).
    ///
    /// This convenience method configures marshaling for Unicode string parameters
    /// and fields, using null-terminated wide character representation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn unicode_string(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::LPWSTR)
    }

    /// Sets ANSI string marshaling (LPSTR).
    ///
    /// This convenience method configures marshaling for ANSI string parameters
    /// and fields, using null-terminated single-byte character representation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn ansi_string(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::LPSTR)
    }

    /// Sets fixed-size array marshaling (`ByValArray`): `size` elements of the native type
    /// `element_type` (a [`NATIVE_TYPE`] byte), marshaled in place within the containing
    /// structure.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn fixed_array(self, element_type: u8, size: u32) -> Self {
        self.fixed_array_typed(Some(element_type), size)
    }

    /// Sets COM interface marshaling.
    ///
    /// This convenience method configures marshaling for COM interface pointers,
    /// enabling proper reference counting and interface negotiation.
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn com_interface(self) -> Self {
        self.simple_native_type(NATIVE_TYPE::INTERFACE)
    }

    /// Sets marshaling using a high-level NativeType specification.
    ///
    /// This method provides a type-safe way to configure marshaling using the
    /// structured `NativeType` enum rather than raw binary descriptors. It automatically
    /// encodes the native type specification to the correct binary format.
    ///
    /// # Arguments
    ///
    /// * `native_type` - The native type specification to marshal to
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Note
    ///
    /// If encoding fails, the error is stored and will be returned when `build()` is called.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::marshalling::NativeType;
    /// use dotscope::metadata::tables::FieldMarshalBuilder;
    ///
    /// // Unicode string with size parameter
    /// let marshal = FieldMarshalBuilder::new()
    ///     .parent(param_ref)
    ///     .native_type_spec(NativeType::LPWStr { size_param_index: Some(2) })
    ///     .build(&mut assembly)?;
    ///
    /// // Array of 32-bit integers
    /// let array_marshal = FieldMarshalBuilder::new()
    ///     .parent(field_ref)
    ///     .native_type_spec(NativeType::Array {
    ///         element_type: Box::new(NativeType::I4),
    ///         num_param: Some(1),
    ///         num_element: Some(10),
    ///         flags: None,
    ///     })
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn native_type_spec(mut self, native_type: NativeType) -> Self {
        let info = MarshallingInfo {
            primary_type: native_type,
        };

        match encode_marshalling_descriptor(&info) {
            Ok(descriptor) => self.native_type = Some(descriptor),
            Err(e) => self.encoding_error = Some(e),
        }

        self
    }

    /// Sets marshaling using a complete marshalling descriptor.
    ///
    /// This method allows specifying complex marshalling scenarios with primary
    /// and additional types. This is useful for advanced marshalling cases that
    /// require multiple type specifications.
    ///
    /// # Arguments
    ///
    /// * `info` - The complete marshalling descriptor with primary and additional types
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    ///
    /// # Note
    ///
    /// If encoding fails, the error is stored and will be returned when `build()` is called.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use dotscope::metadata::marshalling::{NativeType, MarshallingInfo};
    /// use dotscope::metadata::tables::FieldMarshalBuilder;
    ///
    /// let complex_info = MarshallingInfo {
    ///     primary_type: NativeType::CustomMarshaler {
    ///         guid: "12345678-1234-5678-9ABC-DEF012345678".to_string(),
    ///         native_type_name: "NativeArray".to_string(),
    ///         cookie: "size=dynamic".to_string(),
    ///         type_reference: "MyAssembly.ArrayMarshaler".to_string(),
    ///     },
    /// };
    ///
    /// let marshal = FieldMarshalBuilder::new()
    ///     .parent(param_ref)
    ///     .marshalling_info(complex_info)
    ///     .build(&mut assembly)?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn marshalling_info(mut self, info: &MarshallingInfo) -> Self {
        match encode_marshalling_descriptor(info) {
            Ok(descriptor) => self.native_type = Some(descriptor),
            Err(e) => self.encoding_error = Some(e),
        }

        self
    }

    /// Sets marshaling for a pointer to a specific native type.
    ///
    /// This convenience method configures marshaling for pointer types with
    /// optional target type specification.
    ///
    /// # Arguments
    ///
    /// * `ref_type` - The native type the pointer references, when given: a [`NATIVE_TYPE`]
    ///   byte
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn pointer(self, ref_type: Option<u8>) -> Self {
        self.native_type_spec(NativeType::Ptr { ref_type })
    }

    /// Sets marshaling for a variable-length array.
    ///
    /// This convenience method configures marshaling for arrays with runtime
    /// size determination through parameter references.
    ///
    /// # Arguments
    ///
    /// * `element_type` - The native type of the elements: a [`NATIVE_TYPE`] byte
    /// * `size_param` - Optional parameter index for array size
    /// * `element_count` - Optional fixed element count
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn variable_array(
        self,
        element_type: u8,
        size_param: Option<u32>,
        element_count: Option<u32>,
    ) -> Self {
        let array_type = NativeType::Array {
            element_type,
            num_param: size_param,
            num_element: element_count,
            flags: None,
        };
        self.native_type_spec(array_type)
    }

    /// Sets marshaling for a fixed-size array.
    ///
    /// This convenience method configures marshaling for arrays with compile-time
    /// known size embedded directly in structures.
    ///
    /// # Arguments
    ///
    /// * `element_type` - The native type of the elements, when given: a [`NATIVE_TYPE`] byte
    /// * `size` - Number of elements in the array
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn fixed_array_typed(self, element_type: Option<u8>, size: u32) -> Self {
        self.native_type_spec(NativeType::FixedArray { size, element_type })
    }

    /// Sets marshaling for a native structure.
    ///
    /// This convenience method configures marshaling for native structures with
    /// optional packing and size specifications.
    ///
    /// # Arguments
    ///
    /// * `packing_size` - Optional structure packing alignment in bytes
    /// * `class_size` - Optional total structure size in bytes
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn native_struct(self, packing_size: Option<u8>, class_size: Option<u32>) -> Self {
        let struct_type = NativeType::Struct {
            packing_size,
            class_size,
        };
        self.native_type_spec(struct_type)
    }

    /// Sets marshaling for a COM safe array.
    ///
    /// This convenience method configures marshaling for COM safe arrays with
    /// variant type specification for element types.
    ///
    /// # Arguments
    ///
    /// * `variant_type` - VARIANT type constant for array elements
    /// * `user_defined_name` - Optional user-defined type name
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn safe_array(self, variant_type: u16, user_defined_name: Option<String>) -> Self {
        let array_type = NativeType::SafeArray {
            variant_type: Some(variant_type),
            user_defined_name,
        };
        self.native_type_spec(array_type)
    }

    /// Sets marshaling for a custom marshaler.
    ///
    /// This convenience method configures marshaling using a user-defined custom
    /// marshaler with GUID identification and initialization parameters.
    ///
    /// # Arguments
    ///
    /// * `guid` - GUID identifying the custom marshaler
    /// * `native_type_name` - Native type name for the marshaler
    /// * `cookie` - Cookie string passed to the marshaler for initialization
    /// * `type_reference` - Full type name of the custom marshaler class
    ///
    /// # Returns
    ///
    /// Self for method chaining.
    #[must_use]
    pub fn custom_marshaler(
        self,
        guid: &str,
        native_type_name: &str,
        cookie: &str,
        type_reference: &str,
    ) -> Self {
        let marshaler_type = NativeType::CustomMarshaler {
            guid: guid.to_string(),
            native_type_name: native_type_name.to_string(),
            cookie: cookie.to_string(),
            type_reference: type_reference.to_string(),
        };
        self.native_type_spec(marshaler_type)
    }

    /// Builds the field marshal entry and adds it to the assembly.
    ///
    /// This method validates all required fields are set, adds the marshaling
    /// descriptor to the blob heap, creates the raw field marshal structure,
    /// and adds it to the FieldMarshal table with proper token generation.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly being modified
    ///
    /// # Returns
    ///
    /// A [`crate::metadata::token::Token`] representing the newly created field marshal entry, or an error if
    /// validation fails or required fields are missing.
    ///
    /// # Errors
    ///
    /// - Returns error if encoding failed during `native_type_spec` or `marshalling_info`
    /// - Returns error if parent is not set
    /// - Returns error if native_type is not set or empty
    /// - Returns error if parent is not a valid HasFieldMarshal coded index
    /// - Returns error if blob operations fail
    /// - Returns error if table operations fail
    pub fn build(self, assembly: &mut CilAssembly) -> Result<ChangeRefRc> {
        if let Some(encoding_error) = self.encoding_error {
            return Err(encoding_error);
        }

        let parent = self
            .parent
            .ok_or_else(|| Error::ModificationInvalid("Marshal parent is required".to_string()))?;

        let native_type = self.native_type.ok_or_else(|| {
            Error::ModificationInvalid("Native type descriptor is required".to_string())
        })?;

        if native_type.is_empty() {
            return Err(Error::ModificationInvalid(
                "Native type descriptor cannot be empty".to_string(),
            ));
        }

        let valid_parent_tables = CodedIndexType::HasFieldMarshal.tables();
        if !valid_parent_tables.contains(&parent.tag) {
            return Err(Error::ModificationInvalid(format!(
                "Parent must be a HasFieldMarshal coded index (Field/Param), got {:?}",
                parent.tag
            )));
        }

        // Add native type descriptor to blob heap
        let native_type_index = assembly.blob_add(&native_type)?.placeholder();

        let rid = assembly.next_rid(TableId::FieldMarshal)?;

        let token = Token::from_parts(TableId::FieldMarshal, rid);

        let field_marshal_raw = FieldMarshalRaw {
            rid,
            token,
            offset: 0, // Will be set during binary generation
            parent,
            native_type: native_type_index,
        };

        assembly.table_row_add(
            TableId::FieldMarshal,
            TableDataOwned::FieldMarshal(field_marshal_raw),
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::{ChangeRefKind, CilAssembly},
        metadata::cilassemblyview::CilAssemblyView,
        testkit::fixture,
    };

    #[test]
    fn test_field_marshal_builder_basic() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Create a basic field marshal entry
        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal); // Parameter target
        let marshal_descriptor = vec![NATIVE_TYPE::I4]; // Simple integer marshaling

        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .native_type(&marshal_descriptor)
            .build(&mut assembly)
            .unwrap();

        // Verify ref is created correctly
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_different_parents() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let marshal_descriptor = vec![NATIVE_TYPE::I4];

        // Test Field parent
        let field_parent = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);
        let field_marshal_ref = FieldMarshalBuilder::new()
            .parent(field_parent)
            .native_type(&marshal_descriptor)
            .build(&mut assembly)
            .unwrap();

        // Test Param parent
        let param_parent = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);
        let param_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_parent)
            .native_type(&marshal_descriptor)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed with correct kind
        assert_eq!(
            field_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            param_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert!(!std::sync::Arc::ptr_eq(
            &field_marshal_ref,
            &param_marshal_ref
        ));
    }

    #[test]
    fn test_field_marshal_builder_different_native_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Test various native types
        let param_refs: Vec<_> = (1..=8)
            .map(|i| CodedIndex::new(TableId::Param, i, CodedIndexType::HasFieldMarshal))
            .collect();

        // Simple integer types
        let int_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_refs[0].clone())
            .simple_native_type(NATIVE_TYPE::I4)
            .build(&mut assembly)
            .unwrap();

        // Unicode string
        let unicode_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_refs[1].clone())
            .unicode_string()
            .build(&mut assembly)
            .unwrap();

        // ANSI string
        let ansi_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_refs[2].clone())
            .ansi_string()
            .build(&mut assembly)
            .unwrap();

        // Fixed array
        let array_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_refs[3].clone())
            .fixed_array(NATIVE_TYPE::I1, 32) // 32-byte array
            .build(&mut assembly)
            .unwrap();

        // COM interface
        let interface_marshal_ref = FieldMarshalBuilder::new()
            .parent(param_refs[4].clone())
            .com_interface()
            .build(&mut assembly)
            .unwrap();

        // All should succeed with FieldMarshal table kind
        assert_eq!(
            int_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            unicode_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            ansi_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            array_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            interface_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );

        // All should be different references
        let refs = [
            &int_marshal_ref,
            &unicode_marshal_ref,
            &ansi_marshal_ref,
            &array_marshal_ref,
            &interface_marshal_ref,
        ];
        for i in 0..refs.len() {
            for j in i + 1..refs.len() {
                assert!(!std::sync::Arc::ptr_eq(refs[i], refs[j]));
            }
        }
    }

    #[test]
    fn test_field_marshal_builder_complex_descriptors() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);

        // Complex array descriptor with multiple parameters
        let complex_array_descriptor = vec![
            NATIVE_TYPE::ARRAY,
            NATIVE_TYPE::I4, // Element type
            0x02,            // Array rank
            0x10,
            0x00,
            0x00,
            0x00, // Size parameter (16 elements)
            0x00,
            0x00,
            0x00,
            0x00, // Lower bound
        ];

        let marshal_ref = FieldMarshalBuilder::new()
            .parent(field_ref)
            .native_type(&complex_array_descriptor)
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_missing_parent() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let marshal_descriptor = vec![NATIVE_TYPE::I4];

        let result = FieldMarshalBuilder::new()
            .native_type(&marshal_descriptor)
            // Missing parent
            .build(&mut assembly);

        // Should fail because parent is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_marshal_builder_missing_native_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        let result = FieldMarshalBuilder::new()
            .parent(param_ref)
            // Missing native_type
            .build(&mut assembly);

        // Should fail because native type is required
        assert!(result.is_err());
    }

    #[test]
    fn test_field_marshal_builder_empty_native_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);
        let empty_descriptor = vec![]; // Empty descriptor

        let result = FieldMarshalBuilder::new()
            .parent(param_ref)
            .native_type(&empty_descriptor)
            .build(&mut assembly);

        // Should fail because native type cannot be empty
        assert!(result.is_err());
    }

    #[test]
    fn test_field_marshal_builder_invalid_parent_type() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Use a table type that's not valid for HasFieldMarshal
        let invalid_parent = CodedIndex::new(TableId::TypeDef, 1, CodedIndexType::HasFieldMarshal); // TypeDef not in HasFieldMarshal
        let marshal_descriptor = vec![NATIVE_TYPE::I4];

        let result = FieldMarshalBuilder::new()
            .parent(invalid_parent)
            .native_type(&marshal_descriptor)
            .build(&mut assembly);

        // Should fail because parent type is not valid for HasFieldMarshal
        assert!(result.is_err());
    }

    #[test]
    fn test_field_marshal_builder_all_primitive_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Test all primitive native types
        let primitive_types = [
            NATIVE_TYPE::BOOLEAN,
            NATIVE_TYPE::I1,
            NATIVE_TYPE::U1,
            NATIVE_TYPE::I2,
            NATIVE_TYPE::U2,
            NATIVE_TYPE::I4,
            NATIVE_TYPE::U4,
            NATIVE_TYPE::I8,
            NATIVE_TYPE::U8,
            NATIVE_TYPE::R4,
            NATIVE_TYPE::R8,
            NATIVE_TYPE::INT,
            NATIVE_TYPE::UINT,
        ];

        for (i, &native_type) in primitive_types.iter().enumerate() {
            let param_ref = CodedIndex::new(
                TableId::Param,
                (i + 1) as u32,
                CodedIndexType::HasFieldMarshal,
            );

            let marshal_ref = FieldMarshalBuilder::new()
                .parent(param_ref)
                .simple_native_type(native_type)
                .build(&mut assembly)
                .unwrap();

            // All should succeed
            assert_eq!(
                marshal_ref.kind(),
                ChangeRefKind::TableRow(TableId::FieldMarshal)
            );
        }
    }

    #[test]
    fn test_field_marshal_builder_string_types() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Test string marshaling types
        let param1 = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);
        let param2 = CodedIndex::new(TableId::Param, 2, CodedIndexType::HasFieldMarshal);
        let param3 = CodedIndex::new(TableId::Param, 3, CodedIndexType::HasFieldMarshal);
        let param4 = CodedIndex::new(TableId::Param, 4, CodedIndexType::HasFieldMarshal);

        // LPSTR (ANSI string)
        let ansi_marshal_ref = FieldMarshalBuilder::new()
            .parent(param1)
            .simple_native_type(NATIVE_TYPE::LPSTR)
            .build(&mut assembly)
            .unwrap();

        // LPWSTR (Unicode string)
        let unicode_marshal_ref = FieldMarshalBuilder::new()
            .parent(param2)
            .simple_native_type(NATIVE_TYPE::LPWSTR)
            .build(&mut assembly)
            .unwrap();

        // BSTR (COM string)
        let bstr_marshal_ref = FieldMarshalBuilder::new()
            .parent(param3)
            .simple_native_type(NATIVE_TYPE::BSTR)
            .build(&mut assembly)
            .unwrap();

        // BYVALSTR (fixed-length string)
        let byval_marshal_ref = FieldMarshalBuilder::new()
            .parent(param4)
            .simple_native_type(NATIVE_TYPE::BYVALSTR)
            .build(&mut assembly)
            .unwrap();

        // All should succeed
        assert_eq!(
            ansi_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            unicode_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            bstr_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            byval_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_realistic_pinvoke() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Realistic P/Invoke scenario: Win32 API function
        // BOOL CreateDirectory(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);

        // Parameter 1: LPCWSTR (Unicode string path)
        let path_param = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);
        let path_marshal_ref = FieldMarshalBuilder::new()
            .parent(path_param)
            .unicode_string() // LPCWSTR
            .build(&mut assembly)
            .unwrap();

        // Parameter 2: LPSECURITY_ATTRIBUTES (structure pointer)
        let security_param = CodedIndex::new(TableId::Param, 2, CodedIndexType::HasFieldMarshal);
        let security_marshal_ref = FieldMarshalBuilder::new()
            .parent(security_param)
            .simple_native_type(NATIVE_TYPE::PTR) // Pointer to struct
            .build(&mut assembly)
            .unwrap();

        // Return value: BOOL (32-bit integer)
        let return_param = CodedIndex::new(TableId::Param, 0, CodedIndexType::HasFieldMarshal); // Return value
        let return_marshal_ref = FieldMarshalBuilder::new()
            .parent(return_param)
            .simple_native_type(NATIVE_TYPE::I4) // 32-bit bool
            .build(&mut assembly)
            .unwrap();

        // All should succeed
        assert_eq!(
            path_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            security_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            return_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );

        // All should be different references
        assert!(!std::sync::Arc::ptr_eq(
            &path_marshal_ref,
            &security_marshal_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &path_marshal_ref,
            &return_marshal_ref
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &security_marshal_ref,
            &return_marshal_ref
        ));
    }

    #[test]
    fn test_field_marshal_builder_struct_fields() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        // Realistic struct marshaling: POINT structure
        // struct POINT { LONG x; LONG y; };

        let x_field = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);
        let y_field = CodedIndex::new(TableId::Field, 2, CodedIndexType::HasFieldMarshal);

        // X coordinate as 32-bit signed integer
        let x_marshal_ref = FieldMarshalBuilder::new()
            .parent(x_field)
            .simple_native_type(NATIVE_TYPE::I4)
            .build(&mut assembly)
            .unwrap();

        // Y coordinate as 32-bit signed integer
        let y_marshal_ref = FieldMarshalBuilder::new()
            .parent(y_field)
            .simple_native_type(NATIVE_TYPE::I4)
            .build(&mut assembly)
            .unwrap();

        // Both should succeed
        assert_eq!(
            x_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert_eq!(
            y_marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
        assert!(!std::sync::Arc::ptr_eq(&x_marshal_ref, &y_marshal_ref));
    }

    #[test]
    fn test_field_marshal_builder_high_level_native_type_spec() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        // Test high-level NativeType specification
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .native_type_spec(NativeType::LPWStr {
                size_param_index: Some(2),
            })
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_variable_array() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);

        // Test variable array marshaling
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(field_ref)
            .variable_array(NATIVE_TYPE::I4, Some(1), Some(10))
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_fixed_array_typed() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);

        // Test fixed array marshaling with type specification
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(field_ref)
            .fixed_array_typed(Some(NATIVE_TYPE::BOOLEAN), 64)
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_native_struct() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let field_ref = CodedIndex::new(TableId::Field, 1, CodedIndexType::HasFieldMarshal);

        // Test native struct marshaling
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(field_ref)
            .native_struct(Some(4), Some(128))
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_pointer() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        // Test pointer marshaling
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .pointer(Some(NATIVE_TYPE::I4))
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_custom_marshaler() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        // Test custom marshaler
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .custom_marshaler(
                "12345678-1234-5678-9ABC-DEF012345678",
                "NativeType",
                "cookie_data",
                "MyAssembly.CustomMarshaler",
            )
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_safe_array() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        // Test safe array marshaling
        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .safe_array(crate::metadata::marshalling::VARIANT_TYPE::I4, None)
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }

    #[test]
    fn test_field_marshal_builder_marshalling_info() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let mut assembly = CilAssembly::new(view);

        let param_ref = CodedIndex::new(TableId::Param, 1, CodedIndexType::HasFieldMarshal);

        // Test complex marshalling info
        let info = MarshallingInfo {
            primary_type: NativeType::LPStr {
                size_param_index: Some(1),
            },
        };

        let marshal_ref = FieldMarshalBuilder::new()
            .parent(param_ref)
            .marshalling_info(&info)
            .build(&mut assembly)
            .unwrap();

        // Should succeed
        assert_eq!(
            marshal_ref.kind(),
            ChangeRefKind::TableRow(TableId::FieldMarshal)
        );
    }
}
