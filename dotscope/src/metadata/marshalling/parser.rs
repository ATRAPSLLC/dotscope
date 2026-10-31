//! Parser for .NET marshalling descriptors.
//!
//! This module provides parsing functionality for binary marshalling descriptors as defined
//! in ECMA-335 II.23.2.9. It converts raw byte data into structured `MarshallingInfo` and
//! `NativeType` representations.

use crate::{
    file::parser::Parser,
    metadata::marshalling::types::{MarshallingInfo, NativeType, MAX_RECURSION_DEPTH, NATIVE_TYPE},
    Error::RecursionLimit,
    Result,
};

/// Parses a marshaling descriptor from bytes.
///
/// This is a convenience function that creates a [`MarshallingParser`] and parses a complete
/// marshalling descriptor from the provided byte slice. The function handles the full parsing
/// process including primary type extraction, parameter parsing, and additional type processing.
///
/// # Arguments
///
/// * `data` - The byte slice containing the marshalling descriptor to parse. The format follows
///   ECMA-335 II.23.2.9 with the first byte(s) indicating the native type followed by optional
///   type-specific parameters.
///
/// # Returns
///
/// * [`Ok`]([`MarshallingInfo`]) - Successfully parsed marshalling descriptor
/// * [`Err`]([`crate::Error`]) - Parsing failed due to malformed data, unsupported types, or I/O errors
///
/// # Errors
///
/// This function returns an error in the following cases:
/// - **Invalid Format**: Malformed or truncated marshalling descriptor
/// - **Unknown Type**: Unrecognized native type constant
/// - **Recursion Limit**: Nested types exceed the maximum recursion depth for safety
/// - **Data Corruption**: Inconsistent or invalid parameter data
///
/// # Examples
///
/// ## Simple Type Parsing
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{parse_marshalling_descriptor, NativeType, NATIVE_TYPE};
///
/// // Parse a simple boolean type
/// let bytes = &[NATIVE_TYPE::BOOLEAN];
/// let info = parse_marshalling_descriptor(bytes)?;
/// assert_eq!(info.primary_type, NativeType::Boolean);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## String Type with Parameters
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{parse_marshalling_descriptor, NativeType, NATIVE_TYPE};
///
/// // Parse LPSTR with size parameter index 5
/// let bytes = &[NATIVE_TYPE::LPSTR, 0x05];
/// let info = parse_marshalling_descriptor(bytes)?;
///
/// match info.primary_type {
///     NativeType::LPStr { size_param_index: Some(5) } => {
///         println!("LPSTR with size from parameter 5");
///     }
///     _ => unreachable!(),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// ## Complex Array Type
/// ```rust,no_run
/// use dotscope::metadata::marshalling::{parse_marshalling_descriptor, NativeType, NATIVE_TYPE};
///
/// // Parse array of I4 with parameter and size info
/// let bytes = &[NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x0A];
/// let info = parse_marshalling_descriptor(bytes)?;
///
/// match info.primary_type {
///     NativeType::Array { element_type, num_param, num_element } => {
///         println!("Array of {:?}, param: {:?}, size: {:?}",
///                  element_type, num_param, num_element);
///     }
///     _ => unreachable!(),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
pub fn parse_marshalling_descriptor(data: &[u8]) -> Result<MarshallingInfo> {
    let mut parser = MarshallingParser::new(data);
    parser.parse_descriptor()
}

/// Parser for marshaling descriptors.
///
/// The `MarshallingParser` provides stateful parsing of binary marshalling descriptors as defined
/// in ECMA-335 II.23.2.9. It maintains position state and recursion depth tracking to safely
/// parse complex nested type structures.
///
/// # Design
///
/// The parser is built on top of [`crate::file::parser::Parser`] for low-level byte operations
/// and adds marshalling-specific logic for:
/// - **Type Recognition**: Identifying native type constants and their formats
/// - **Parameter Parsing**: Extracting size, index, and other type-specific parameters
/// - **Recursion Control**: Preventing stack overflow from deeply nested types
/// - **Validation**: Ensuring descriptor format compliance and data integrity
///
/// # Usage Pattern
///
/// ```no_run
/// use dotscope::metadata::marshalling::MarshallingParser;
///
/// let descriptor_bytes = &[/* marshalling descriptor data */];
/// let mut parser = MarshallingParser::new(descriptor_bytes);
///
/// // Parse individual types
/// let native_type = parser.parse_native_type()?;
///
/// // Or parse complete descriptor
/// let descriptor = parser.parse_descriptor()?;
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Safety
///
/// The parser includes several safety mechanisms:
/// - **Recursion Limits**: Prevents stack overflow from nested types
/// - **Bounds Checking**: Validates all memory accesses
/// - **Format Validation**: Rejects malformed descriptors
/// - **Type Validation**: Ensures only valid native type constants
///
/// # Note on Default Trait
///
/// `MarshallingParser` does not implement `Default` because it requires input data
/// (a byte slice) to function. Use [`MarshallingParser::new`] to create instances.
/// For encoding-focused workflows, use [`super::MarshallingEncoder`] which does implement `Default`.
///
pub struct MarshallingParser<'a> {
    /// Underlying byte parser for low-level operations
    parser: Parser<'a>,
    /// Current recursion depth for stack overflow prevention
    depth: usize,
}

impl<'a> MarshallingParser<'a> {
    /// Creates a new parser for the given data.
    ///
    /// Initializes a fresh parser state with zero recursion depth and positions
    /// the parser at the beginning of the provided data slice.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice containing the marshalling descriptor to parse
    ///
    /// # Returns
    ///
    /// A new [`MarshallingParser`] ready to parse the provided data.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::metadata::marshalling::MarshallingParser;
    ///
    /// let descriptor_bytes = &[0x14, 0x05]; // LPSTR with size param 5
    /// let mut parser = MarshallingParser::new(descriptor_bytes);
    /// let native_type = parser.parse_native_type()?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        MarshallingParser {
            parser: Parser::new(data),
            depth: 0,
        }
    }

    /// Parses an optional compressed uint if more data is available and the next byte is not END.
    ///
    /// This is a helper method to avoid code duplication for parsing optional parameters
    /// that are common across many native types (size parameters, indices, etc.).
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - If more data was available and not END marker
    /// * `Ok(None)` - If no more data or next byte is END marker
    /// * `Err(...)` - If reading fails
    fn parse_optional_compressed_uint(&mut self) -> Result<Option<u32>> {
        // The descriptor is a blob of its own length: an optional field is present when
        // bytes remain, a 0 among them (a parameter index of 0) too
        if self.parser.has_more_data() {
            Ok(Some(self.parser.read_compressed_uint()?))
        } else {
            Ok(None)
        }
    }

    /// Parses an optional raw byte if more data is available and the next byte is not END.
    ///
    /// # Returns
    ///
    /// * `Ok(Some(value))` - If more data was available and not END marker
    /// * `Ok(None)` - If no more data or next byte is END marker
    /// * `Err(...)` - If reading fails
    fn parse_optional_byte(&mut self) -> Result<Option<u8>> {
        if self.parser.has_more_data() {
            Ok(Some(self.parser.read_le::<u8>()?))
        } else {
            Ok(None)
        }
    }

    /// Checks if more optional data is available (not at END and has more bytes).
    fn has_optional_data(&mut self) -> Result<bool> {
        Ok(self.parser.has_more_data())
    }

    /// Parses a single native type from the current position
    ///
    /// # Errors
    /// Returns an error if the native type cannot be parsed or recursion limit is exceeded
    pub fn parse_native_type(&mut self) -> Result<NativeType> {
        self.depth = self.depth.saturating_add(1);
        if self.depth >= MAX_RECURSION_DEPTH {
            self.depth = self.depth.saturating_sub(1);
            return Err(RecursionLimit(MAX_RECURSION_DEPTH));
        }

        let result = self.parse_native_type_inner();
        self.depth = self.depth.saturating_sub(1);
        result
    }

    /// Inner implementation of parse_native_type (depth tracking handled by caller)
    fn parse_native_type_inner(&mut self) -> Result<NativeType> {
        let head_byte = self.parser.read_le::<u8>()?;
        match head_byte {
            NATIVE_TYPE::END => Ok(NativeType::End),
            NATIVE_TYPE::MAX => Ok(NativeType::Unspecified),
            NATIVE_TYPE::VOID => Ok(NativeType::Void),
            NATIVE_TYPE::BOOLEAN => Ok(NativeType::Boolean),
            NATIVE_TYPE::I1 => Ok(NativeType::I1),
            NATIVE_TYPE::U1 => Ok(NativeType::U1),
            NATIVE_TYPE::I2 => Ok(NativeType::I2),
            NATIVE_TYPE::U2 => Ok(NativeType::U2),
            NATIVE_TYPE::I4 => Ok(NativeType::I4),
            NATIVE_TYPE::U4 => Ok(NativeType::U4),
            NATIVE_TYPE::I8 => Ok(NativeType::I8),
            NATIVE_TYPE::U8 => Ok(NativeType::U8),
            NATIVE_TYPE::R4 => Ok(NativeType::R4),
            NATIVE_TYPE::R8 => Ok(NativeType::R8),
            NATIVE_TYPE::SYSCHAR => Ok(NativeType::SysChar),
            NATIVE_TYPE::VARIANT => Ok(NativeType::Variant),
            NATIVE_TYPE::CURRENCY => Ok(NativeType::Currency),
            NATIVE_TYPE::DECIMAL => Ok(NativeType::Decimal),
            NATIVE_TYPE::DATE => Ok(NativeType::Date),
            NATIVE_TYPE::INT => Ok(NativeType::Int),
            NATIVE_TYPE::UINT => Ok(NativeType::UInt),
            NATIVE_TYPE::ERROR => Ok(NativeType::Error),
            NATIVE_TYPE::BSTR => Ok(NativeType::BStr),
            NATIVE_TYPE::LPSTR => {
                let size_param_index = self.parse_optional_compressed_uint()?;
                Ok(NativeType::LPStr { size_param_index })
            }
            NATIVE_TYPE::LPWSTR => {
                let size_param_index = self.parse_optional_compressed_uint()?;
                Ok(NativeType::LPWStr { size_param_index })
            }
            NATIVE_TYPE::LPTSTR => {
                let size_param_index = self.parse_optional_compressed_uint()?;
                Ok(NativeType::LPTStr { size_param_index })
            }
            NATIVE_TYPE::LPUTF8STR => {
                let size_param_index = self.parse_optional_compressed_uint()?;
                Ok(NativeType::LPUtf8Str { size_param_index })
            }
            NATIVE_TYPE::FIXEDSYSSTRING => {
                let size = self.parser.read_compressed_uint()?;
                Ok(NativeType::FixedSysString { size })
            }
            NATIVE_TYPE::OBJECTREF => Ok(NativeType::ObjectRef),
            NATIVE_TYPE::IUNKNOWN => Ok(NativeType::IUnknown),
            NATIVE_TYPE::IDISPATCH => Ok(NativeType::IDispatch),
            NATIVE_TYPE::IINSPECTABLE => Ok(NativeType::IInspectable),
            NATIVE_TYPE::STRUCT => {
                let packing_size = self.parse_optional_byte()?;
                let class_size = self.parse_optional_compressed_uint()?;
                Ok(NativeType::Struct {
                    packing_size,
                    class_size,
                })
            }
            NATIVE_TYPE::INTERFACE => {
                let iid_param_index = self.parse_optional_compressed_uint()?;
                Ok(NativeType::Interface { iid_param_index })
            }
            NATIVE_TYPE::SAFEARRAY => {
                // SAFEARRAY Opt<VARTYPE> Opt<user-defined type name>: a compressed VARTYPE
                // and a length-prefixed name, each present when bytes remain
                let variant_type = if self.parser.has_more_data() {
                    let value = self.parser.read_compressed_uint()?;
                    Some(u16::try_from(value).map_err(|_| {
                        malformed_error!("SAFEARRAY element VARTYPE 0x{:X} exceeds 16 bits", value)
                    })?)
                } else {
                    None
                };
                let user_defined_name = if self.parser.has_more_data() {
                    Some(self.parser.read_compressed_string_utf8()?)
                } else {
                    None
                };

                Ok(NativeType::SafeArray {
                    variant_type,
                    user_defined_name,
                })
            }
            NATIVE_TYPE::FIXEDARRAY => {
                let size = self.parser.read_compressed_uint()?;
                // Optional element type
                // The element is its type's tag alone, as CoreCLR reads it
                let element_type = if self.has_optional_data()? {
                    Some(self.parser.read_le::<u8>()?)
                } else {
                    None
                };
                Ok(NativeType::FixedArray { size, element_type })
            }
            NATIVE_TYPE::ARRAY => {
                // ARRAY Type Opt<ParamNumber> Opt<NumElement> Opt<Flags>
                // The element is its type's tag alone (ECMA-335 II.23.4): an array of LPSTR
                // is followed by the array's parameter index, not the string's
                let array_type = self.parser.read_le::<u8>()?;
                let num_param = self.parse_optional_compressed_uint()?;
                let num_element = self.parse_optional_compressed_uint()?;
                let flags = self.parse_optional_compressed_uint()?;

                Ok(NativeType::Array {
                    element_type: array_type,
                    num_param,
                    num_element,
                    flags,
                })
            }
            NATIVE_TYPE::NESTEDSTRUCT => Ok(NativeType::NestedStruct),
            NATIVE_TYPE::BYVALSTR => {
                let size = self.parser.read_compressed_uint()?;
                Ok(NativeType::ByValStr { size })
            }
            NATIVE_TYPE::ANSIBSTR => Ok(NativeType::AnsiBStr),
            NATIVE_TYPE::TBSTR => Ok(NativeType::TBStr),
            NATIVE_TYPE::VARIANTBOOL => Ok(NativeType::VariantBool),
            NATIVE_TYPE::FUNC => Ok(NativeType::Func),
            NATIVE_TYPE::ASANY => Ok(NativeType::AsAny),
            NATIVE_TYPE::LPSTRUCT => Ok(NativeType::LPStruct),
            NATIVE_TYPE::CUSTOMMARSHALER => {
                // Four length-prefixed strings: the GUID, the unmanaged type name, the
                // managed type of the marshaler, and the cookie (ECMA-335 II.23.4)
                let guid = self.parser.read_compressed_string_utf8()?;
                let native_type_name = self.parser.read_compressed_string_utf8()?;
                let type_reference = self.parser.read_compressed_string_utf8()?;
                let cookie = self.parser.read_compressed_string_utf8()?;

                Ok(NativeType::CustomMarshaler {
                    guid,
                    native_type_name,
                    cookie,
                    type_reference,
                })
            }
            NATIVE_TYPE::HSTRING => Ok(NativeType::HString),
            NATIVE_TYPE::PTR => {
                // Optional referenced type
                let ref_type = if self.has_optional_data()? {
                    Some(self.parser.read_le::<u8>()?)
                } else {
                    None
                };
                Ok(NativeType::Ptr { ref_type })
            }
            _ => Err(malformed_error!("Invalid NATIVE_TYPE byte - {}", head_byte)),
        }
    }

    /// Parses a complete marshaling descriptor
    ///
    /// # Errors
    /// Returns an error if the marshalling descriptor is malformed or cannot be parsed
    pub fn parse_descriptor(&mut self) -> Result<MarshallingInfo> {
        // A descriptor is one native type (ECMA-335 II.23.4). Its optional fields take the bytes
        // that remain, so only a type without them can leave any, which the runtime ignores.
        Ok(MarshallingInfo {
            primary_type: self.parse_native_type()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Error, ParseFailure};

    #[test]
    fn test_parse_simple_types() {
        let test_cases = vec![
            (vec![NATIVE_TYPE::VOID], NativeType::Void),
            (vec![NATIVE_TYPE::BOOLEAN], NativeType::Boolean),
            (vec![NATIVE_TYPE::I1], NativeType::I1),
            (vec![NATIVE_TYPE::U1], NativeType::U1),
            (vec![NATIVE_TYPE::I2], NativeType::I2),
            (vec![NATIVE_TYPE::U2], NativeType::U2),
            (vec![NATIVE_TYPE::I4], NativeType::I4),
            (vec![NATIVE_TYPE::U4], NativeType::U4),
            (vec![NATIVE_TYPE::I8], NativeType::I8),
            (vec![NATIVE_TYPE::U8], NativeType::U8),
            (vec![NATIVE_TYPE::R4], NativeType::R4),
            (vec![NATIVE_TYPE::R8], NativeType::R8),
            (vec![NATIVE_TYPE::INT], NativeType::Int),
            (vec![NATIVE_TYPE::UINT], NativeType::UInt),
            (vec![NATIVE_TYPE::VARIANTBOOL], NativeType::VariantBool),
            (vec![NATIVE_TYPE::IINSPECTABLE], NativeType::IInspectable),
            (vec![NATIVE_TYPE::HSTRING], NativeType::HString),
        ];

        for (input, expected) in test_cases {
            let mut parser = MarshallingParser::new(&input);
            let result = parser.parse_native_type().unwrap();
            assert_eq!(result, expected);
        }
    }

    #[test]
    fn test_parse_lpstr() {
        // LPSTR with size parameter
        let input = vec![NATIVE_TYPE::LPSTR, 0x05];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPStr {
                size_param_index: Some(5)
            }
        );

        // LPSTR without size parameter
        let input = vec![NATIVE_TYPE::LPSTR];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPStr {
                size_param_index: None
            }
        );
    }

    #[test]
    fn test_parse_lputf8str() {
        // LPUTF8STR with size parameter
        let input = vec![NATIVE_TYPE::LPUTF8STR, 0x10];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPUtf8Str {
                size_param_index: Some(16)
            }
        );

        // LPUTF8STR without size parameter
        let input = vec![NATIVE_TYPE::LPUTF8STR];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::LPUtf8Str {
                size_param_index: None
            }
        );
    }

    #[test]
    fn test_parse_array() {
        // Array with Type, Opt<num_param>, Opt<num_element>
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03, 0x01];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_element: Some(1),
                num_param: Some(3),
                flags: None
            }
        );

        // Array with Type, Opt<num_param>, NONE
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4, 0x03];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_element: None,
                num_param: Some(3),
                flags: None
            }
        );

        // Array with Type, None , None
        let input = vec![NATIVE_TYPE::ARRAY, NATIVE_TYPE::I4];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Array {
                element_type: NATIVE_TYPE::I4,
                num_element: None,
                num_param: None,
                flags: None
            }
        );
    }

    #[test]
    fn test_parse_fixed_array() {
        // Fixed array with size and element type
        let input = vec![NATIVE_TYPE::FIXEDARRAY, 0x0A, NATIVE_TYPE::I4];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::FixedArray {
                size: 10,
                element_type: Some(NATIVE_TYPE::I4)
            }
        );

        // Fixed array with size but no element type
        let input = vec![NATIVE_TYPE::FIXEDARRAY, 0x0A];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::FixedArray {
                size: 10,
                element_type: None
            }
        );
    }

    #[test]
    fn test_parse_complete_descriptor() {
        // Simple descriptor with just one type
        let input = vec![NATIVE_TYPE::I4];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(descriptor.primary_type, NativeType::I4);

        // Bytes after a type without optional fields are not part of the descriptor
        let input = vec![NATIVE_TYPE::BOOLEAN, NATIVE_TYPE::I4, NATIVE_TYPE::END];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(descriptor.primary_type, NativeType::Boolean);

        // Descriptor with only END marker
        let input = vec![NATIVE_TYPE::END];
        let descriptor = parse_marshalling_descriptor(&input).unwrap();
        assert_eq!(descriptor.primary_type, NativeType::End);
    }

    #[test]
    fn test_error_conditions() {
        // Test unexpected end of data
        let input: Vec<u8> = vec![];
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::Parse(ParseFailure::OutOfBounds { .. })
        ));

        // Test unknown native type
        let input = vec![0xFF];
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());

        // Test invalid compressed integer
        let input = vec![NATIVE_TYPE::LPSTR, 0xC0]; // 4-byte format but only one byte available
        let result = parse_marshalling_descriptor(&input);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::Parse(ParseFailure::OutOfBounds { .. })
        ));
    }

    #[test]
    fn test_parse_struct() {
        // Struct with packing size and class size
        let input = vec![NATIVE_TYPE::STRUCT, 0x04, 0x20];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: Some(4),
                class_size: Some(32)
            }
        );

        // Struct with packing size but no class size
        let input = vec![NATIVE_TYPE::STRUCT, 0x04];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: Some(4),
                class_size: None
            }
        );

        // Struct with no packing size or class size
        let input = vec![NATIVE_TYPE::STRUCT];
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::Struct {
                packing_size: None,
                class_size: None
            }
        );
    }

    #[test]
    fn test_parse_custom_marshaler() {
        // CUSTOMMARSHALER, then four length-prefixed strings: GUID, unmanaged type name,
        // the marshaler's managed type, and the cookie (ECMA-335 II.23.4)
        let mut input = vec![NATIVE_TYPE::CUSTOMMARSHALER];
        for text in ["ABCD", "Native", "Type", "Cookie"] {
            input.push(u8::try_from(text.len()).unwrap());
            input.extend_from_slice(text.as_bytes());
        }
        let mut parser = MarshallingParser::new(&input);
        let result = parser.parse_native_type().unwrap();
        assert_eq!(
            result,
            NativeType::CustomMarshaler {
                guid: "ABCD".to_string(),
                native_type_name: "Native".to_string(),
                cookie: "Cookie".to_string(),
                type_reference: "Type".to_string(),
            }
        );
    }
}
