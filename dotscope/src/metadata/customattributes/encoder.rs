//! Custom attribute blob encoding implementation for .NET metadata generation.
//!
//! This module provides comprehensive encoding of custom attribute data according to the
//! ECMA-335 II.23.3 `CustomAttribute` signature specification. It implements the inverse
//! functionality of the parsing implementation, enabling complete round-trip support for
//! all .NET custom attribute types and structures.
//!
//! # Architecture
//!
//! The encoding architecture mirrors the parsing implementation, providing:
//!
//! ## Core Components
//!
//! - **Fixed Arguments**: Encode constructor arguments using type-specific binary formats
//! - **Named Arguments**: Encode field/property assignments with embedded type tags
//! - **Type System**: Complete coverage of all .NET primitive and complex types
//! - **Binary Format**: Strict ECMA-335 compliance with proper prolog and structure
//!
//! ## Design Principles
//!
//! - **Round-Trip Accuracy**: Encoded data must parse back to identical structures
//! - **ECMA-335 Compliance**: Strict adherence to official binary format specification
//! - **Type Safety**: Leverages existing type system for accurate encoding
//! - **Error Handling**: Comprehensive validation with detailed error messages
//!
//! # Key Functions
//!
//! - [`encode_custom_attribute_value`] - Main encoding function for complete custom attributes
//! - [`encode_custom_attribute_argument`] - Individual argument value encoding
//! - [`encode_field_or_prop_type`] - A named argument's or boxed value's type
//!
//! # Usage Examples
//!
//! ## Encoding Complete Custom Attribute
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{
//!     CustomAttributeValue, CustomAttributeArgument, encode_custom_attribute_value
//! };
//! use dotscope::metadata::typesystem::CilTypeReference;
//!
//! let custom_attr = CustomAttributeValue {
//!     fixed_args: vec![
//!         CustomAttributeArgument::String("Debug".to_string()),
//!         CustomAttributeArgument::Bool(true),
//!     ],
//!     named_args: vec![],
//!     constructor: CilTypeReference::None,
//!     blob_index: 0,
//! };
//!
//! let encoded_blob = encode_custom_attribute_value(&custom_attr)?;
//! println!("Encoded {} bytes", encoded_blob.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Encoding Individual Arguments
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{CustomAttributeArgument, encode_custom_attribute_argument};
//!
//! let string_arg = CustomAttributeArgument::String("Hello".to_string());
//! let mut encoded_string = Vec::new();
//! encode_custom_attribute_argument(&string_arg, &mut encoded_string)?;
//!
//! let int_arg = CustomAttributeArgument::I4(42);
//! let mut encoded_int = Vec::new();
//! encode_custom_attribute_argument(&int_arg, &mut encoded_int)?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Binary Format
//!
//! The encoder produces binary data in the exact format specified by ECMA-335:
//!
//! ```text
//! CustomAttribute ::= Prolog FixedArgs NumNamed NamedArgs
//! Prolog          ::= 0x0001
//! FixedArgs       ::= Argument*
//! NumNamed        ::= PackedLen
//! NamedArgs       ::= NamedArg*
//! NamedArg        ::= FIELD | PROPERTY FieldOrPropType FieldOrPropName FixedArg
//! ```
//!
//! # Thread Safety
//!
//! All functions in this module are thread-safe and stateless. The encoder can be called
//! concurrently from multiple threads as it operates only on immutable input data.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::types`] - Type definitions for encoding
//! - [`crate::metadata::customattributes::parser`] - Round-trip validation with parsing
//! - [`crate::cilassembly::CilAssembly`] - Assembly modification and blob heap integration
//! - [`crate::metadata::typesystem`] - Type system for accurate encoding

use crate::{
    metadata::customattributes::{
        CustomAttributeArgument, CustomAttributeNamedArgument, CustomAttributeValue,
        FieldOrPropType, NAMED_ARG_TYPE, SERIALIZATION_TYPE,
    },
    utils::write_compressed_uint,
    Result,
};

/// Encodes a complete custom attribute value into binary blob format according to ECMA-335.
///
/// This is the main entry point for custom attribute encoding. It produces a binary blob
/// that is compatible with the .NET custom attribute format and can be stored in the
/// blob heap of a .NET assembly.
///
/// # Binary Format
///
/// The output follows ECMA-335 II.23.3:
/// 1. Prolog: 0x0001 (little-endian)
/// 2. Fixed arguments: Constructor parameters in order
/// 3. Named argument count: unsigned int16
/// 4. Named arguments: FIELD or PROPERTY, the `FieldOrPropType`, the name, the value
///
/// # Arguments
///
/// * `value` - The custom attribute value to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded custom attribute blob.
///
/// # Errors
///
/// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] in the following cases:
/// - Too many named arguments (exceeds u16 maximum of 65535)
/// - An array of more than `u32::MAX - 1` elements
/// - A string longer than a compressed uint can state (0x1FFFFFFF bytes)
/// - A boxed value holding a boxed value, which the grammar has no type for
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{
///     CustomAttributeValue, CustomAttributeArgument, encode_custom_attribute_value,
/// };
/// use dotscope::metadata::typesystem::CilTypeReference;
///
/// let custom_attr = CustomAttributeValue {
///     fixed_args: vec![CustomAttributeArgument::String(Some("Test".to_string()))],
///     named_args: vec![],
///     constructor: CilTypeReference::None,
///     blob_index: 0,
/// };
///
/// let blob = encode_custom_attribute_value(&custom_attr)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_custom_attribute_value(value: &CustomAttributeValue) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    // Write prolog (0x0001 in little-endian)
    buffer.extend_from_slice(&[0x01, 0x00]);

    for arg in &value.fixed_args {
        encode_custom_attribute_argument(arg, &mut buffer)?;
    }

    // ECMA-335 §II.23.3: NumNamed is encoded as unsigned int16
    let named_count = u16::try_from(value.named_args.len()).map_err(|_| {
        malformed_error!(
            "Too many named arguments: {} exceeds u16 maximum (65535)",
            value.named_args.len()
        )
    })?;
    buffer.extend_from_slice(&named_count.to_le_bytes());

    encode_named_arguments(&value.named_args, &mut buffer)?;

    Ok(buffer)
}

/// Encodes named arguments (field/property assignments) into binary format.
///
/// According to ECMA-335 II.23.3, named arguments are encoded as:
/// ```text
/// NamedArg ::= FIELD | PROPERTY FieldOrPropType FieldOrPropName FixedArg
/// FIELD    ::= NAMED_ARG_TYPE::FIELD (0x53)
/// PROPERTY ::= NAMED_ARG_TYPE::PROPERTY (0x54)
/// ```
pub(crate) fn encode_named_arguments(
    args: &[CustomAttributeNamedArgument],
    buffer: &mut Vec<u8>,
) -> Result<()> {
    for arg in args {
        buffer.push(if arg.is_field {
            NAMED_ARG_TYPE::FIELD
        } else {
            NAMED_ARG_TYPE::PROPERTY
        });
        encode_field_or_prop_type(&arg.arg_type, buffer)?;
        write_string(buffer, Some(&arg.name))?;
        encode_custom_attribute_argument(&arg.value, buffer)?;
    }
    Ok(())
}

/// Encodes a `FieldOrPropType`: its serialization tag, with an enum's type name or an
/// array's element type after it (ECMA-335 II.23.3).
///
/// # Errors
///
/// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] when an enum's
/// type name is too long to encode.
pub fn encode_field_or_prop_type(
    argument_type: &FieldOrPropType,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    match argument_type {
        FieldOrPropType::Bool => buffer.push(SERIALIZATION_TYPE::BOOLEAN),
        FieldOrPropType::Char => buffer.push(SERIALIZATION_TYPE::CHAR),
        FieldOrPropType::I1 => buffer.push(SERIALIZATION_TYPE::I1),
        FieldOrPropType::U1 => buffer.push(SERIALIZATION_TYPE::U1),
        FieldOrPropType::I2 => buffer.push(SERIALIZATION_TYPE::I2),
        FieldOrPropType::U2 => buffer.push(SERIALIZATION_TYPE::U2),
        FieldOrPropType::I4 => buffer.push(SERIALIZATION_TYPE::I4),
        FieldOrPropType::U4 => buffer.push(SERIALIZATION_TYPE::U4),
        FieldOrPropType::I8 => buffer.push(SERIALIZATION_TYPE::I8),
        FieldOrPropType::U8 => buffer.push(SERIALIZATION_TYPE::U8),
        FieldOrPropType::R4 => buffer.push(SERIALIZATION_TYPE::R4),
        FieldOrPropType::R8 => buffer.push(SERIALIZATION_TYPE::R8),
        FieldOrPropType::String => buffer.push(SERIALIZATION_TYPE::STRING),
        FieldOrPropType::Type => buffer.push(SERIALIZATION_TYPE::TYPE),
        FieldOrPropType::Boxed => buffer.push(SERIALIZATION_TYPE::TAGGED_OBJECT),
        FieldOrPropType::Enum(name) => {
            buffer.push(SERIALIZATION_TYPE::ENUM);
            write_string(buffer, Some(name))?;
        }
        FieldOrPropType::SzArray(element) => {
            buffer.push(SERIALIZATION_TYPE::SZARRAY);
            encode_field_or_prop_type(element, buffer)?;
        }
    }
    Ok(())
}

/// Encodes a single custom attribute argument value into binary format (ECMA-335 II.23.3
/// `Elem`, or for a boxed value its type and then its value).
///
/// # Arguments
///
/// * `arg` - The argument to encode
/// * `buffer` - The output buffer to write encoded data to
///
/// # Errors
///
/// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`] in the following cases:
/// - `String` or `Type`: longer than a compressed uint can state (0x1FFFFFFF bytes)
/// - `Array`: `u32::MAX` elements or more (`u32::MAX` is the null array)
/// - `Boxed`: holding a boxed value
pub fn encode_custom_attribute_argument(
    arg: &CustomAttributeArgument,
    buffer: &mut Vec<u8>,
) -> Result<()> {
    match arg {
        CustomAttributeArgument::Bool(value) => buffer.push(u8::from(*value)),
        CustomAttributeArgument::Char(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::I1(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::U1(value) => buffer.push(*value),
        CustomAttributeArgument::I2(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::U2(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::I4(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::U4(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::I8(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::U8(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::R4(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::R8(value) => buffer.extend_from_slice(&value.to_le_bytes()),
        CustomAttributeArgument::String(value) | CustomAttributeArgument::Type(value) => {
            write_string(buffer, value.as_deref())?;
        }
        CustomAttributeArgument::Array(_, None) => {
            buffer.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        CustomAttributeArgument::Array(_, Some(elements)) => {
            // NumElem: a little-endian uint32, with u32::MAX standing for the null array
            let len = u32::try_from(elements.len())
                .ok()
                .filter(|len| *len != u32::MAX)
                .ok_or_else(|| malformed_error!("Array too large: {} elements", elements.len()))?;
            buffer.extend_from_slice(&len.to_le_bytes());
            for element in elements {
                encode_custom_attribute_argument(element, buffer)?;
            }
        }
        CustomAttributeArgument::Enum(_, underlying_value) => {
            encode_custom_attribute_argument(underlying_value, buffer)?;
        }
        CustomAttributeArgument::Boxed(value) => {
            let Some(held) = value.field_or_prop_type() else {
                return Err(malformed_error!("A boxed value cannot hold a boxed value"));
            };
            encode_field_or_prop_type(&held, buffer)?;
            encode_custom_attribute_argument(value, buffer)?;
        }
    }
    Ok(())
}

/// Writes a `SerString`: 0xFF for the null string, otherwise a compressed length and the
/// UTF-8 bytes.
fn write_string(buffer: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        buffer.push(0xFF);
        return Ok(());
    };
    let utf8_bytes = value.as_bytes();
    let len = u32::try_from(utf8_bytes.len()).map_err(|_| {
        malformed_error!(
            "String too long: {} bytes exceeds a compressed length",
            utf8_bytes.len()
        )
    })?;
    write_compressed_uint(len, buffer)?;
    buffer.extend_from_slice(utf8_bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use proptest::{collection::vec, prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{
        metadata::{
            customattributes::{
                parse_custom_attribute_data, CustomAttributeNamedArgument, CustomAttributeValue,
            },
            tables::ParamList,
            typesystem::CilTypeReference,
        },
        testkit::{arb, arb::check},
    };

    #[test]
    fn test_encode_simple_custom_attribute() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(Some("Test".to_string()))],
            named_args: vec![],
            constructor: CilTypeReference::None,
            blob_index: 0,
        };

        let result = encode_custom_attribute_value(&custom_attr);
        assert!(
            result.is_ok(),
            "Simple custom attribute encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded data should not be empty");

        // Check prolog (0x0001)
        assert_eq!(encoded[0], 0x01, "First byte should be 0x01");
        assert_eq!(encoded[1], 0x00, "Second byte should be 0x00");

        // Should have named argument count (0)
        let last_byte = encoded[encoded.len() - 1];
        assert_eq!(last_byte, 0x00, "Named argument count should be 0");
    }

    #[test]
    fn test_encode_boolean_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::Bool(true);

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Boolean encoding should succeed");
        assert_eq!(buffer, vec![1], "True should encode as 1");

        buffer.clear();
        let arg = CustomAttributeArgument::Bool(false);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Boolean encoding should succeed");
        assert_eq!(buffer, vec![0], "False should encode as 0");
    }

    #[test]
    fn test_encode_integer_arguments() {
        let mut buffer = Vec::new();

        // Test I4
        let arg = CustomAttributeArgument::I4(0x12345678);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "I4 encoding should succeed");
        assert_eq!(
            buffer,
            vec![0x78, 0x56, 0x34, 0x12],
            "I4 should be little-endian"
        );

        // Test U2
        buffer.clear();
        let arg = CustomAttributeArgument::U2(0x1234);
        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "U2 encoding should succeed");
        assert_eq!(buffer, vec![0x34, 0x12], "U2 should be little-endian");
    }

    #[test]
    fn test_encode_string_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::String(Some("Hello".to_string()));

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "String encoding should succeed");

        // Should be: length (5) + "Hello" UTF-8
        let expected = vec![5, b'H', b'e', b'l', b'l', b'o'];
        assert_eq!(buffer, expected, "String should encode with length prefix");
    }

    #[test]
    fn test_encode_array_argument() {
        let mut buffer = Vec::new();
        let arg = CustomAttributeArgument::Array(
            FieldOrPropType::I4,
            Some(vec![
                CustomAttributeArgument::I4(1),
                CustomAttributeArgument::I4(2),
            ]),
        );

        let result = encode_custom_attribute_argument(&arg, &mut buffer);
        assert!(result.is_ok(), "Array encoding should succeed");

        // NumElem as a little-endian uint32, then the two I4 values
        let expected = vec![
            2, 0, 0, 0, // NumElem
            1, 0, 0, 0, // I4(1) little-endian
            2, 0, 0, 0, // I4(2) little-endian
        ];
        assert_eq!(
            buffer, expected,
            "Array should encode with length and elements"
        );
    }

    #[test]
    fn test_encode_named_argument() {
        let named_args = vec![CustomAttributeNamedArgument {
            is_field: false, // property
            name: "Value".to_string(),
            arg_type: FieldOrPropType::String,
            value: CustomAttributeArgument::String(Some("Test".to_string())),
        }];

        let mut buffer = Vec::new();
        let result = encode_named_arguments(&named_args, &mut buffer);
        assert!(result.is_ok(), "Named argument encoding should succeed");

        assert!(!buffer.is_empty(), "Named argument should produce data");
        assert_eq!(buffer[0], 0x54, "Should start with PROPERTY marker");
        assert_eq!(
            buffer[1],
            SERIALIZATION_TYPE::STRING,
            "Should have STRING type tag"
        );
    }

    #[test]
    fn test_encode_compressed_uint() {
        let mut buffer = Vec::new();

        // Test single byte encoding
        write_compressed_uint(42, &mut buffer).unwrap();
        assert_eq!(buffer, vec![42], "Small values should use single byte");

        // Test two byte encoding
        buffer.clear();
        write_compressed_uint(0x1234, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            vec![0x80 | 0x12, 0x34],
            "Medium values should use two bytes"
        );

        // Test four byte encoding
        buffer.clear();
        write_compressed_uint(0x12345678, &mut buffer).unwrap();
        assert_eq!(
            buffer,
            vec![0xC0 | 0x12, 0x34, 0x56, 0x78],
            "Large values should use four bytes"
        );
    }

    /// A type the blob names: an enum by its name, an array by its element type.
    #[test]
    fn a_field_or_prop_type_encodes_as_the_grammar_writes_it() {
        let mut buffer = Vec::new();
        encode_field_or_prop_type(
            &FieldOrPropType::SzArray(Box::new(FieldOrPropType::Enum("E.Ty".to_string()))),
            &mut buffer,
        )
        .unwrap();
        assert_eq!(buffer, [0x1D, 0x55, 4, b'E', b'.', b'T', b'y']);
    }

    /// A boxed value names its type before it, and null strings and arrays have markers of
    /// their own.
    #[test]
    fn boxed_values_and_nulls_encode_as_the_grammar_writes_them() {
        let cases: [(CustomAttributeArgument, &[u8]); 4] = [
            (
                CustomAttributeArgument::Boxed(Box::new(CustomAttributeArgument::I4(7))),
                &[0x08, 7, 0, 0, 0],
            ),
            (
                CustomAttributeArgument::Boxed(Box::new(CustomAttributeArgument::Enum(
                    "E".to_string(),
                    Box::new(CustomAttributeArgument::U1(3)),
                ))),
                &[0x55, 1, b'E', 3],
            ),
            (CustomAttributeArgument::String(None), &[0xFF]),
            (
                CustomAttributeArgument::Array(FieldOrPropType::I4, None),
                &[0xFF, 0xFF, 0xFF, 0xFF],
            ),
        ];
        for (argument, bytes) in cases {
            let mut buffer = Vec::new();
            encode_custom_attribute_argument(&argument, &mut buffer).unwrap();
            assert_eq!(buffer, bytes, "{argument:?}");
        }
        let nested = CustomAttributeArgument::Boxed(Box::new(CustomAttributeArgument::Boxed(
            Box::new(CustomAttributeArgument::I4(1)),
        )));
        assert!(encode_custom_attribute_argument(&nested, &mut Vec::new()).is_err());
    }

    #[test]
    fn test_encode_complete_custom_attribute_with_named_args() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::String(Some("Debug".to_string()))],
            named_args: vec![CustomAttributeNamedArgument {
                is_field: false,
                name: "Name".to_string(),
                arg_type: FieldOrPropType::String,
                value: CustomAttributeArgument::String(Some("TestName".to_string())),
            }],
            constructor: CilTypeReference::None,
            blob_index: 0,
        };

        let result = encode_custom_attribute_value(&custom_attr);
        assert!(
            result.is_ok(),
            "Complete custom attribute encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(
            encoded.len() > 10,
            "Complete attribute should be substantial"
        );

        // Check prolog
        assert_eq!(encoded[0], 0x01, "Should start with prolog");
        assert_eq!(encoded[1], 0x00, "Should start with prolog");
    }

    #[test]
    fn test_debug_named_args_encoding() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![],
            named_args: vec![CustomAttributeNamedArgument {
                is_field: true,
                name: "FieldValue".to_string(),
                arg_type: FieldOrPropType::I4,
                value: CustomAttributeArgument::I4(42),
            }],
            constructor: CilTypeReference::None,
            blob_index: 0,
        };

        let encoded = encode_custom_attribute_value(&custom_attr).unwrap();

        // Expected format:
        // 0x01, 0x00 - Prolog
        // (no fixed args)
        // 0x01, 0x00 - Named args count (1, little-endian u16)
        // 0x53 - Field indicator
        // 0x08 - I4 type tag
        // field name length + "FieldValue"
        // 42 as I4

        // Check actual structure
        if encoded.len() >= 6 {
            // Verify structure: prolog, named count, field indicator, type tag
            assert_eq!(encoded[0], 0x01);
            assert_eq!(encoded[1], 0x00);
            assert_eq!(encoded[2], 0x01);
            assert_eq!(encoded[3], 0x00);
            assert_eq!(encoded[4], 0x53);
            assert_eq!(encoded[5], 0x08);
        }
    }

    #[test]
    fn test_debug_type_args_encoding() {
        let custom_attr = CustomAttributeValue {
            fixed_args: vec![CustomAttributeArgument::Type(Some(
                "System.String".to_string(),
            ))],
            named_args: vec![],
            constructor: CilTypeReference::None,
            blob_index: 0,
        };

        let encoded = encode_custom_attribute_value(&custom_attr).unwrap();

        // Expected format:
        // 0x01, 0x00 - Prolog
        // Type string: compressed length + "System.String"
        // 0x00, 0x00 - Named args count (0, little-endian u16)

        // Verify byte structure
        let mut pos = 0;
        assert_eq!(encoded[pos], 0x01);
        assert_eq!(encoded[pos + 1], 0x00);
        pos += 2;

        // String encoding: first read compressed length
        if pos < encoded.len() {
            let str_len = encoded[pos];
            pos += 1;

            if pos + str_len as usize <= encoded.len() {
                let string_bytes = &encoded[pos..pos + str_len as usize];
                let string_str = String::from_utf8_lossy(string_bytes);
                assert_eq!(string_str, "System.String");
                pos += str_len as usize;
            }
        }

        if pos + 1 < encoded.len() {
            // Verify named count is 0
            assert_eq!(encoded[pos], 0x00);
            assert_eq!(encoded[pos + 1], 0x00);
        }
    }

    /// Every value the encoder writes decodes back to itself: the arguments are compared by
    /// what they print, which tells every value apart but a NaN's payload, and by their bytes
    /// written again, which tells that apart too.
    #[test]
    fn every_attribute_value_decodes_to_what_was_encoded() {
        check(vec(arb::named_argument(), 0..5), |named_args| {
            let value = CustomAttributeValue {
                fixed_args: Vec::new(),
                named_args,
                constructor: CilTypeReference::None,
                blob_index: 0,
            };
            let bytes = encode_custom_attribute_value(&value)
                .map_err(|error| TestCaseError::fail(format!("does not encode: {error}")))?;
            let decoded =
                parse_custom_attribute_data(&bytes, &ParamList::new()).map_err(|error| {
                    TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
                })?;
            prop_assert_eq!(
                format!("{:?}", decoded.named_args),
                format!("{:?}", value.named_args),
                "encoded as {:02x?}",
                bytes
            );
            prop_assert_eq!(encode_custom_attribute_value(&decoded).ok(), Some(bytes));
            Ok(())
        });
    }
}
