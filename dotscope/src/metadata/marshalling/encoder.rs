//! Encoder for .NET marshalling descriptors.
//!
//! This module provides encoding functionality for converting structured `MarshallingInfo` and
//! `NativeType` representations into binary marshalling descriptors as defined in ECMA-335 II.23.2.9.

use crate::{
    metadata::marshalling::types::{MarshallingInfo, NativeType, MAX_RECURSION_DEPTH, NATIVE_TYPE},
    utils::write_compressed_uint,
    Error::RecursionLimit,
    Result,
};

/// Encodes a marshaling descriptor to bytes.
///
/// This is a convenience function that creates a [`MarshallingEncoder`] and encodes a complete
/// marshalling descriptor to a byte vector. The function handles the full encoding process
/// including primary type encoding, parameter encoding, and additional type processing.
///
/// # Arguments
///
/// * `info` - The marshalling descriptor to encode. This includes the primary native type
///   and any additional types required for complex marshalling scenarios.
///
/// # Returns
///
/// * [`Ok`]([`Vec<u8>`]) - Successfully encoded marshalling descriptor as bytes
/// * [`Err`]([`crate::Error`]) - Encoding failed due to unsupported types or invalid data
///
/// # Errors
///
/// This function returns an error in the following cases:
/// - **Unsupported Type**: Attempt to encode an unsupported or invalid native type
/// - **Invalid Parameters**: Type parameters are inconsistent or out of range
/// - **Recursion Limit**: Nested types exceed the maximum recursion depth for safety
/// - **String Encoding**: Issues encoding UTF-8 strings for custom marshalers
///
/// # Examples
///
/// ## Simple Type Encoding
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo, NATIVE_TYPE};
///
/// // Encode a simple boolean type
/// let info = MarshallingInfo {
///     primary_type: NativeType::Boolean,
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::BOOLEAN]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## String Type with Parameters
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo, NATIVE_TYPE};
///
/// // Encode LPSTR with size parameter index 5
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// assert_eq!(bytes, vec![NATIVE_TYPE::LPSTR, 0x05]);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Complex Array Type
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{encode_marshalling_descriptor, NativeType, MarshallingInfo};
///
/// // Encode array of I4 with parameter and size info
/// let info = MarshallingInfo {
///     primary_type: NativeType::Array {
///         element_type: NATIVE_TYPE::I4,
///         num_param: Some(3),
///         num_element: Some(10),
///         flags: None,
///     },
/// };
/// let bytes = encode_marshalling_descriptor(&info)?;
/// // Result will be [NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x0A]
/// # Ok::<(), dotscope::Error>(())
/// ```
///
pub fn encode_marshalling_descriptor(info: &MarshallingInfo) -> Result<Vec<u8>> {
    let mut encoder = MarshallingEncoder::new();
    encoder.encode_descriptor(info)
}

/// Encoder for marshaling descriptors.
///
/// The `MarshallingEncoder` provides stateful encoding of marshalling descriptors from
/// `MarshallingInfo` structures to binary format as defined in ECMA-335 II.23.2.9.
/// It maintains recursion depth tracking to safely encode complex nested type structures.
///
/// # Design
///
/// The encoder converts `NativeType` enum variants to their binary representation with:
/// - **Type Constants**: Maps enum variants to NATIVE_TYPE byte constants
/// - **Parameter Encoding**: Handles size, index, and other type-specific parameters
/// - **Recursion Control**: Prevents stack overflow from deeply nested types
/// - **Binary Format**: Produces ECMA-335 compliant binary descriptors
///
/// # Usage Pattern
///
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{MarshallingEncoder, NativeType, MarshallingInfo};
///
/// let info = MarshallingInfo {
///     primary_type: NativeType::LPStr { size_param_index: Some(5) },
/// };
///
/// let mut encoder = MarshallingEncoder::new();
/// let bytes = encoder.encode_descriptor(&info)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Safety
///
/// The encoder includes several safety mechanisms:
/// - **Recursion Limits**: Prevents stack overflow from nested types
/// - **Parameter Validation**: Ensures parameters are within valid ranges
/// - **Format Compliance**: Produces only valid binary descriptors
/// - **Type Validation**: Ensures all types can be properly encoded
///
pub struct MarshallingEncoder {
    /// Buffer for building the encoded descriptor
    buffer: Vec<u8>,
    /// Current recursion depth for stack overflow prevention
    depth: usize,
}

impl MarshallingEncoder {
    /// Creates a new encoder.
    ///
    /// Initializes a fresh encoder state with zero recursion depth and an empty buffer.
    ///
    /// # Returns
    ///
    /// A new [`MarshallingEncoder`] ready to encode marshalling descriptors.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::marshalling::MarshallingEncoder;
    ///
    /// let mut encoder = MarshallingEncoder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        MarshallingEncoder {
            buffer: Vec::new(),
            depth: 0,
        }
    }

    /// Writes an optional compressed uint to the buffer if value is Some.
    ///
    /// This helper method reduces code duplication for writing optional
    /// size parameters, indices, and counts.
    /// Writes a length-prefixed UTF-8 string.
    fn write_string(&mut self, text: &str) -> Result<()> {
        let length = u32::try_from(text.len()).map_err(|_| {
            malformed_error!("Marshalling string of {} bytes is too long", text.len())
        })?;
        write_compressed_uint(length, &mut self.buffer)?;
        self.buffer.extend_from_slice(text.as_bytes());
        Ok(())
    }

    fn write_optional_compressed_uint(&mut self, value: Option<u32>) -> Result<()> {
        if let Some(v) = value {
            write_compressed_uint(v, &mut self.buffer)?;
        }
        Ok(())
    }

    /// Encodes a single native type to the internal buffer.
    ///
    /// This method encodes a single `NativeType` variant to its binary representation
    /// according to ECMA-335 II.23.2.9. For nested types (arrays, pointers), this method
    /// is called recursively with depth tracking to prevent stack overflow.
    ///
    /// # Arguments
    ///
    /// * `native_type` - The native type to encode
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The recursion depth exceeds [`MAX_RECURSION_DEPTH`]
    /// - A nested type fails to encode
    pub fn encode_native_type(&mut self, native_type: &NativeType) -> Result<()> {
        self.depth = self.depth.saturating_add(1);
        if self.depth >= MAX_RECURSION_DEPTH {
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        match native_type {
            NativeType::End => self.buffer.push(NATIVE_TYPE::END),
            NativeType::Unspecified => self.buffer.push(NATIVE_TYPE::MAX),
            NativeType::Void => self.buffer.push(NATIVE_TYPE::VOID),
            NativeType::Boolean => self.buffer.push(NATIVE_TYPE::BOOLEAN),
            NativeType::I1 => self.buffer.push(NATIVE_TYPE::I1),
            NativeType::U1 => self.buffer.push(NATIVE_TYPE::U1),
            NativeType::I2 => self.buffer.push(NATIVE_TYPE::I2),
            NativeType::U2 => self.buffer.push(NATIVE_TYPE::U2),
            NativeType::I4 => self.buffer.push(NATIVE_TYPE::I4),
            NativeType::U4 => self.buffer.push(NATIVE_TYPE::U4),
            NativeType::I8 => self.buffer.push(NATIVE_TYPE::I8),
            NativeType::U8 => self.buffer.push(NATIVE_TYPE::U8),
            NativeType::R4 => self.buffer.push(NATIVE_TYPE::R4),
            NativeType::R8 => self.buffer.push(NATIVE_TYPE::R8),
            NativeType::SysChar => self.buffer.push(NATIVE_TYPE::SYSCHAR),
            NativeType::Variant => self.buffer.push(NATIVE_TYPE::VARIANT),
            NativeType::Currency => self.buffer.push(NATIVE_TYPE::CURRENCY),
            NativeType::Decimal => self.buffer.push(NATIVE_TYPE::DECIMAL),
            NativeType::Date => self.buffer.push(NATIVE_TYPE::DATE),
            NativeType::Int => self.buffer.push(NATIVE_TYPE::INT),
            NativeType::UInt => self.buffer.push(NATIVE_TYPE::UINT),
            NativeType::Error => self.buffer.push(NATIVE_TYPE::ERROR),
            NativeType::BStr => self.buffer.push(NATIVE_TYPE::BSTR),
            NativeType::LPStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPSTR);
                self.write_optional_compressed_uint(*size_param_index)?;
            }
            NativeType::LPWStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPWSTR);
                self.write_optional_compressed_uint(*size_param_index)?;
            }
            NativeType::LPTStr { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPTSTR);
                self.write_optional_compressed_uint(*size_param_index)?;
            }
            NativeType::LPUtf8Str { size_param_index } => {
                self.buffer.push(NATIVE_TYPE::LPUTF8STR);
                self.write_optional_compressed_uint(*size_param_index)?;
            }
            NativeType::FixedSysString { size } => {
                self.buffer.push(NATIVE_TYPE::FIXEDSYSSTRING);
                write_compressed_uint(*size, &mut self.buffer)?;
            }
            NativeType::ObjectRef => self.buffer.push(NATIVE_TYPE::OBJECTREF),
            NativeType::IUnknown => self.buffer.push(NATIVE_TYPE::IUNKNOWN),
            NativeType::IDispatch => self.buffer.push(NATIVE_TYPE::IDISPATCH),
            NativeType::IInspectable => self.buffer.push(NATIVE_TYPE::IINSPECTABLE),
            NativeType::Struct {
                packing_size,
                class_size,
            } => {
                self.buffer.push(NATIVE_TYPE::STRUCT);
                if let Some(packing) = packing_size {
                    self.buffer.push(*packing);
                }
                self.write_optional_compressed_uint(*class_size)?;
            }
            NativeType::Interface { iid_param_index } => {
                self.buffer.push(NATIVE_TYPE::INTERFACE);
                self.write_optional_compressed_uint(*iid_param_index)?;
            }
            NativeType::SafeArray {
                variant_type,
                user_defined_name,
            } => {
                self.buffer.push(NATIVE_TYPE::SAFEARRAY);
                if let Some(variant_type) = variant_type {
                    write_compressed_uint(u32::from(*variant_type), &mut self.buffer)?;
                }
                if let Some(user_defined_name) = user_defined_name {
                    self.write_string(user_defined_name)?;
                }
            }
            NativeType::FixedArray { size, element_type } => {
                self.buffer.push(NATIVE_TYPE::FIXEDARRAY);
                write_compressed_uint(*size, &mut self.buffer)?;
                if let Some(element_type) = element_type {
                    self.buffer.push(*element_type);
                }
            }
            NativeType::Array {
                element_type,
                num_param,
                num_element,
                flags,
            } => {
                self.buffer.push(NATIVE_TYPE::ARRAY);
                self.buffer.push(*element_type);
                self.write_optional_compressed_uint(*num_param)?;
                self.write_optional_compressed_uint(*num_element)?;
                self.write_optional_compressed_uint(*flags)?;
            }
            NativeType::NestedStruct => self.buffer.push(NATIVE_TYPE::NESTEDSTRUCT),
            NativeType::ByValStr { size } => {
                self.buffer.push(NATIVE_TYPE::BYVALSTR);
                write_compressed_uint(*size, &mut self.buffer)?;
            }
            NativeType::AnsiBStr => self.buffer.push(NATIVE_TYPE::ANSIBSTR),
            NativeType::TBStr => self.buffer.push(NATIVE_TYPE::TBSTR),
            NativeType::VariantBool => self.buffer.push(NATIVE_TYPE::VARIANTBOOL),
            NativeType::Func => self.buffer.push(NATIVE_TYPE::FUNC),
            NativeType::AsAny => self.buffer.push(NATIVE_TYPE::ASANY),
            NativeType::LPStruct => self.buffer.push(NATIVE_TYPE::LPSTRUCT),
            NativeType::CustomMarshaler {
                guid,
                native_type_name,
                cookie,
                type_reference,
            } => {
                self.buffer.push(NATIVE_TYPE::CUSTOMMARSHALER);
                // Four length-prefixed strings, in the order ECMA-335 II.23.4 gives them
                for text in [guid, native_type_name, type_reference, cookie] {
                    self.write_string(text)?;
                }
            }
            NativeType::HString => self.buffer.push(NATIVE_TYPE::HSTRING),
            NativeType::Ptr { ref_type } => {
                self.buffer.push(NATIVE_TYPE::PTR);
                if let Some(ref_type) = ref_type {
                    self.buffer.push(*ref_type);
                }
            }
        }

        self.depth = self.depth.saturating_sub(1);
        Ok(())
    }

    /// Encodes a complete marshaling descriptor to a new byte vector.
    ///
    /// This method encodes the primary type and any additional types from the
    /// `MarshallingInfo` structure into a binary marshalling descriptor. The descriptor
    /// is validated before encoding to catch invalid type combinations early.
    ///
    /// # Arguments
    ///
    /// * `info` - The marshalling descriptor containing the primary type and optional
    ///   additional types to encode
    ///
    /// # Returns
    ///
    /// A new `Vec<u8>` containing the encoded marshalling descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The marshalling descriptor fails validation (invalid type combinations)
    /// - A type cannot be encoded
    /// - The recursion depth exceeds [`MAX_RECURSION_DEPTH`]
    pub fn encode_descriptor(&mut self, info: &MarshallingInfo) -> Result<Vec<u8>> {
        info.validate()?;

        self.buffer.clear();
        self.depth = 0;

        self.encode_native_type(&info.primary_type)?;

        Ok(self.buffer.clone())
    }

    /// Encodes a marshaling descriptor into the provided output buffer.
    ///
    /// This is an optimization method for high-frequency encoding scenarios where
    /// buffer reuse is important. Instead of allocating a new `Vec<u8>`, this method
    /// appends the encoded data to the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `info` - The marshalling descriptor to encode
    /// * `output` - The buffer to append encoded data to
    ///
    /// # Errors
    ///
    /// Returns an error if the marshalling descriptor is invalid or cannot be encoded.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::marshalling::{MarshallingEncoder, MarshallingInfo, NativeType};
    ///
    /// let mut encoder = MarshallingEncoder::new();
    /// let mut buffer = Vec::with_capacity(1024);
    ///
    /// let info = MarshallingInfo {
    ///     primary_type: NativeType::I4,
    /// };
    ///
    /// encoder.encode_descriptor_into(&info, &mut buffer)?;
    /// // buffer now contains the encoded marshalling descriptor
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode_descriptor_into(
        &mut self,
        info: &MarshallingInfo,
        output: &mut Vec<u8>,
    ) -> Result<()> {
        info.validate()?;

        self.buffer.clear();
        self.depth = 0;

        self.encode_native_type(&info.primary_type)?;

        output.extend_from_slice(&self.buffer);
        Ok(())
    }
}

impl Default for MarshallingEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{
        metadata::marshalling::{parse_marshalling_descriptor, VARIANT_TYPE},
        testkit::{arb, arb::check},
    };

    #[test]
    fn test_roundtrip_simple_types() {
        let test_cases = vec![
            NativeType::Void,
            NativeType::Boolean,
            NativeType::I1,
            NativeType::U1,
            NativeType::I2,
            NativeType::U2,
            NativeType::I4,
            NativeType::U4,
            NativeType::I8,
            NativeType::U8,
            NativeType::R4,
            NativeType::R8,
            NativeType::Int,
            NativeType::UInt,
            NativeType::VariantBool,
            NativeType::IInspectable,
            NativeType::HString,
            NativeType::BStr,
            NativeType::AnsiBStr,
            NativeType::TBStr,
            NativeType::IUnknown,
            NativeType::IDispatch,
            NativeType::NestedStruct,
            NativeType::LPStruct,
            NativeType::ObjectRef,
            NativeType::Func,
            NativeType::AsAny,
            NativeType::SysChar,
            NativeType::Variant,
            NativeType::Currency,
            NativeType::Decimal,
            NativeType::Date,
            NativeType::Error,
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_string_types_with_parameters() {
        let test_cases = vec![
            NativeType::LPStr {
                size_param_index: None,
            },
            NativeType::LPStr {
                size_param_index: Some(5),
            },
            NativeType::LPWStr {
                size_param_index: None,
            },
            NativeType::LPWStr {
                size_param_index: Some(10),
            },
            NativeType::LPTStr {
                size_param_index: None,
            },
            NativeType::LPTStr {
                size_param_index: Some(3),
            },
            NativeType::LPUtf8Str {
                size_param_index: None,
            },
            NativeType::LPUtf8Str {
                size_param_index: Some(16),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_fixed_types_with_size() {
        let test_cases = vec![
            NativeType::FixedSysString { size: 32 },
            NativeType::FixedSysString { size: 128 },
            NativeType::ByValStr { size: 64 },
            NativeType::ByValStr { size: 256 },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_struct_types() {
        let test_cases = vec![
            NativeType::Struct {
                packing_size: None,
                class_size: None,
            },
            NativeType::Struct {
                packing_size: Some(4),
                class_size: None,
            },
            NativeType::Struct {
                packing_size: Some(8),
                class_size: Some(128),
            },
            NativeType::Struct {
                packing_size: Some(1),
                class_size: Some(64),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_interface_types() {
        let test_cases = vec![
            NativeType::Interface {
                iid_param_index: None,
            },
            NativeType::Interface {
                iid_param_index: Some(1),
            },
            NativeType::Interface {
                iid_param_index: Some(5),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_safe_array_encoding_debug() {
        // Test parsing a simple case first
        let simple_case = NativeType::SafeArray {
            variant_type: Some(VARIANT_TYPE::I4),
            user_defined_name: None,
        };

        let info = MarshallingInfo {
            primary_type: simple_case.clone(),
        };

        let encoded = encode_marshalling_descriptor(&info).unwrap();
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();
        assert_eq!(parsed.primary_type, simple_case);

        // Now test the complex case with user-defined name
        let complex_case = NativeType::SafeArray {
            variant_type: Some(VARIANT_TYPE::EMPTY),
            user_defined_name: Some("CustomStruct".to_string()),
        };

        let info = MarshallingInfo {
            primary_type: complex_case.clone(),
        };

        let encoded = encode_marshalling_descriptor(&info).unwrap();
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();
        assert_eq!(parsed.primary_type, complex_case);
    }

    #[test]
    fn test_roundtrip_safe_array_types() {
        let test_cases = vec![
            // SafeArray with no variant type and no user-defined name
            NativeType::SafeArray {
                variant_type: None,
                user_defined_name: None,
            },
            // SafeArray with variant type but no user-defined name
            NativeType::SafeArray {
                variant_type: Some(VARIANT_TYPE::I4),
                user_defined_name: None,
            },
            NativeType::SafeArray {
                variant_type: Some(VARIANT_TYPE::BSTR),
                user_defined_name: None,
            },
            // SafeArray with both variant type and user-defined name
            NativeType::SafeArray {
                variant_type: Some(VARIANT_TYPE::I4),
                user_defined_name: Some("MyCustomType".to_string()),
            },
            NativeType::SafeArray {
                variant_type: Some(VARIANT_TYPE::BSTR),
                user_defined_name: Some("System.String".to_string()),
            },
            // SafeArray with only user-defined name (no variant type)
            NativeType::SafeArray {
                variant_type: Some(VARIANT_TYPE::EMPTY),
                user_defined_name: Some("CustomStruct".to_string()),
            },
        ];

        for (i, original_type) in test_cases.into_iter().enumerate() {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify - Now we can do full verification
            assert_eq!(parsed.primary_type, original_type, "Test case {i} failed");
        }
    }

    #[test]
    fn test_roundtrip_fixed_array_types() {
        let test_cases = vec![
            NativeType::FixedArray {
                size: 10,
                element_type: None,
            },
            NativeType::FixedArray {
                size: 32,
                element_type: Some(NATIVE_TYPE::I4),
            },
            NativeType::FixedArray {
                size: 64,
                element_type: Some(NATIVE_TYPE::BOOLEAN),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_variable_array_types() {
        let test_cases = vec![
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_param: None,
                num_element: None,
                flags: None,
            },
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_param: Some(3),
                num_element: None,
                flags: None,
            },
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_param: Some(3),
                num_element: Some(10),
                flags: None,
            },
            NativeType::Array {
                element_type: NATIVE_TYPE::BOOLEAN,
                num_param: Some(5),
                num_element: None,
                flags: None,
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_pointer_types() {
        let test_cases = vec![
            NativeType::Ptr { ref_type: None },
            NativeType::Ptr {
                ref_type: Some(NATIVE_TYPE::I4),
            },
            NativeType::Ptr {
                ref_type: Some(NATIVE_TYPE::VOID),
            },
        ];

        for original_type in test_cases {
            let info = MarshallingInfo {
                primary_type: original_type.clone(),
            };

            // Encode
            let encoded = encode_marshalling_descriptor(&info).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed.primary_type, original_type);
        }
    }

    #[test]
    fn test_roundtrip_custom_marshaler() {
        let original_type = NativeType::CustomMarshaler {
            guid: "ABCD1234-5678-90EF".to_string(),
            native_type_name: "MyNativeType".to_string(),
            cookie: "cookie_data".to_string(),
            type_reference: "MyAssembly.MyMarshaler".to_string(),
        };

        let info = MarshallingInfo {
            primary_type: original_type.clone(),
        };

        // Encode
        let encoded = encode_marshalling_descriptor(&info).unwrap();

        // Parse back
        let parsed = parse_marshalling_descriptor(&encoded).unwrap();

        // Verify
        assert_eq!(parsed.primary_type, original_type);
    }

    /// An array's element is its type's tag alone (ECMA-335 II.23.4, and as CoreCLR reads it):
    /// `[MarshalAs(LPArray, ArraySubType = LPWStr, SizeParamIndex = 5)]` is followed by the
    /// array's parameter index, not a size parameter of the strings'.
    #[test]
    fn an_array_element_is_a_tag_and_the_fields_after_it_are_the_arrays() {
        let bytes = [NATIVE_TYPE::ARRAY, NATIVE_TYPE::LPWSTR, 0x05, 0x0A];
        let parsed = parse_marshalling_descriptor(&bytes).unwrap();
        assert_eq!(
            parsed.primary_type,
            NativeType::Array {
                element_type: NATIVE_TYPE::LPWSTR,
                num_param: Some(5),
                num_element: Some(10),
                flags: None,
            }
        );
        assert_eq!(encode_marshalling_descriptor(&parsed).unwrap(), bytes);
        assert_eq!(
            NativeType::from_tag(NATIVE_TYPE::LPWSTR),
            Some(NativeType::LPWStr {
                size_param_index: None
            })
        );

        // A pointer to a struct, and a ByValArray of bytes
        for bytes in [
            vec![NATIVE_TYPE::PTR, NATIVE_TYPE::STRUCT],
            vec![NATIVE_TYPE::FIXEDARRAY, 0x20, NATIVE_TYPE::I1],
        ] {
            let parsed = parse_marshalling_descriptor(&bytes).unwrap();
            assert_eq!(encode_marshalling_descriptor(&parsed).unwrap(), bytes);
        }
    }

    #[test]
    fn test_roundtrip_comprehensive_scenarios() {
        // Test realistic P/Invoke scenarios
        let pinvoke_scenarios = vec![
            // Win32 API: BOOL CreateDirectory(LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)
            MarshallingInfo {
                primary_type: NativeType::I4, // BOOL return
            },
            // Parameter 1: LPCWSTR
            MarshallingInfo {
                primary_type: NativeType::LPWStr {
                    size_param_index: None,
                },
            },
            // Parameter 2: LPSECURITY_ATTRIBUTES
            MarshallingInfo {
                primary_type: NativeType::Ptr {
                    ref_type: Some(NATIVE_TYPE::STRUCT),
                },
            },
        ];

        for scenario in pinvoke_scenarios {
            // Encode
            let encoded = encode_marshalling_descriptor(&scenario).unwrap();

            // Parse back
            let parsed = parse_marshalling_descriptor(&encoded).unwrap();

            // Verify
            assert_eq!(parsed, scenario);
        }
    }

    #[test]
    fn test_validation_struct_class_size_without_packing() {
        // Invalid: class_size without packing_size
        let invalid = MarshallingInfo {
            primary_type: NativeType::Struct {
                packing_size: None,
                class_size: Some(128),
            },
        };

        let result = encode_marshalling_descriptor(&invalid);
        assert!(result.is_err());
    }

    #[test]
    fn test_validation_array_num_element_without_num_param() {
        // Invalid: num_element without num_param
        let invalid = MarshallingInfo {
            primary_type: NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_param: None,
                num_element: Some(10),
                flags: None,
            },
        };

        let result = encode_marshalling_descriptor(&invalid);
        assert!(result.is_err());
    }

    /// An optional field is present when bytes remain, so one cannot be given without those
    /// before it: the encoder refuses what it would write as something else.
    #[test]
    fn optional_fields_out_of_order_are_refused() {
        for primary_type in [
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_param: Some(1),
                num_element: None,
                flags: Some(1),
            },
            NativeType::SafeArray {
                variant_type: None,
                user_defined_name: Some("Name".to_string()),
            },
        ] {
            let info = MarshallingInfo { primary_type };
            assert!(encode_marshalling_descriptor(&info).is_err(), "{info:?}");
        }
    }

    #[test]
    fn test_encode_descriptor_into() {
        let mut encoder = MarshallingEncoder::new();
        let mut buffer = Vec::with_capacity(64);

        let info = MarshallingInfo {
            primary_type: NativeType::I4,
        };

        encoder.encode_descriptor_into(&info, &mut buffer).unwrap();
        assert_eq!(buffer, vec![NATIVE_TYPE::I4]);

        // Encode another one into the same buffer
        let info2 = MarshallingInfo {
            primary_type: NativeType::Boolean,
        };

        encoder.encode_descriptor_into(&info2, &mut buffer).unwrap();
        assert_eq!(buffer, vec![NATIVE_TYPE::I4, NATIVE_TYPE::BOOLEAN]);
    }

    /// Descriptors as compilers write them encode back to their own bytes: an array with no
    /// element type given (`NATIVE_TYPE_MAX`), a parameter index of 0 and the flags after it, a custom marshaler's
    /// four length-prefixed strings, and a safe array whose element type is `VT_EMPTY`.
    #[test]
    fn descriptors_round_trip_to_their_bytes() {
        let mut custom = vec![NATIVE_TYPE::CUSTOMMARSHALER, 0x00, 0x00, 0x05];
        custom.extend_from_slice(b"M.Rsh");
        custom.push(0x00);
        for bytes in [
            vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::MAX],
            vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::MAX, 0x00],
            vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::MAX, 0x01, 0x00],
            // parameter index 0, one element, and the flag that the index was given
            vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::MAX, 0x00, 0x01, 0x00],
            vec![NATIVE_TYPE::LPSTR, 0x00],
            vec![NATIVE_TYPE::SAFEARRAY, 0x00],
            custom,
        ] {
            let parsed = parse_marshalling_descriptor(&bytes).unwrap();
            assert_eq!(
                encode_marshalling_descriptor(&parsed).unwrap(),
                bytes,
                "{parsed:?}"
            );
        }
    }

    /// Every descriptor the encoder accepts decodes back to itself: one it would write as
    /// something else must be refused.
    #[test]
    fn every_descriptor_the_encoder_accepts_decodes_to_itself() {
        check(arb::native_type(), |primary_type| {
            let info = MarshallingInfo { primary_type };
            let Ok(bytes) = encode_marshalling_descriptor(&info) else {
                return Ok(());
            };
            let decoded = parse_marshalling_descriptor(&bytes).map_err(|error| {
                TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
            })?;
            prop_assert_eq!(&decoded, &info, "encoded as {:02x?}", bytes);
            Ok(())
        });
    }
}
