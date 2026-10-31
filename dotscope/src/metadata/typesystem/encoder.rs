//! Binary encoding for .NET type signatures according to ECMA-335.
//!
//! This module provides functionality to encode [`crate::metadata::signatures::TypeSignature`] instances into their
//! binary representation as defined by the ECMA-335 standard. The encoding process
//! converts structured type information into compact binary signatures suitable for
//! storage in metadata blob heaps.
//!
//! # Encoding Format
//!
//! Type signatures are encoded using ECMA-335 element type constants and compressed
//! integer encoding for optimal space efficiency. The encoding supports all .NET
//! type system features including:
//!
//! - **Primitive Types**: Direct element type encoding (I4, String, Boolean, etc.)
//! - **Reference Types**: Element type + TypeDefOrRef coded index
//! - **Generic Types**: GENERICINST + base type + argument count + type arguments
//! - **Array Types**: ARRAY/SZARRAY + element type + dimension information
//! - **Pointer Types**: PTR/BYREF + custom modifiers + pointed-to type
//! - **Function Types**: FNPTR + method signature encoding
//!
//! # Usage
//!
//! ```rust
//! use dotscope::prelude::*;
//!
//! // Encode a simple primitive type
//! let signature = TypeSignature::I4;
//! let encoded = TypeSignatureEncoder::encode(&signature)?;
//! assert_eq!(encoded, vec![0x08]); // ELEMENT_TYPE_I4
//!
//! // Encode a single-dimensional array
//! let array_sig = TypeSignature::SzArray(SignatureSzArray {
//!     base: Box::new(TypeSignature::String),
//!     modifiers: vec![],
//! });
//! let encoded = TypeSignatureEncoder::encode(&array_sig)?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use crate::{
    metadata::{
        signatures::{CustomModifier, SignatureMethod, SignatureParameter, TypeSignature},
        token::Token,
        typesystem::ELEMENT_TYPE,
    },
    utils::{write_compressed_int, write_compressed_uint},
    Error, Result,
};

/// Maximum recursion depth for type signature encoding.
///
/// This limit prevents stack overflow from deeply nested or circular type signatures.
/// The value is set to match the type resolver's limit for consistency since they work together.
const MAX_RECURSION_DEPTH: usize = 100;

/// Encoder for converting type signatures into binary format.
///
/// `TypeSignatureEncoder` provides methods to convert structured [`crate::metadata::signatures::TypeSignature`]
/// instances into their binary representation according to ECMA-335 standards.
/// The encoder handles all type signature variants and their specific encoding
/// requirements.
///
/// # Encoding Features
///
/// - **Element Type Constants**: Uses standard ECMA-335 element type values
/// - **Compressed Integers**: Variable-length encoding for counts and indices
/// - **Coded Indices**: TypeDefOrRef and other coded index formats
/// - **Custom Modifiers**: Required and optional modifier encoding
/// - **Recursive Encoding**: Proper handling of nested type structures
///
/// # Thread Safety
///
/// All methods are stateless and thread-safe. Multiple threads can safely
/// use the encoder simultaneously without synchronization.
pub struct TypeSignatureEncoder;

impl TypeSignatureEncoder {
    /// Encodes a type signature into binary format.
    ///
    /// Converts a [`crate::metadata::signatures::TypeSignature`] into its binary representation according
    /// to ECMA-335 standards. The encoding process handles all type signature
    /// variants and their specific encoding requirements.
    ///
    /// # Recursion Protection
    ///
    /// This method enforces a maximum recursion depth limit
    /// to prevent stack overflow from deeply nested or circular type signatures.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    ///
    /// # Returns
    ///
    /// A vector of bytes representing the encoded signature.
    ///
    /// # Errors
    ///
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Encoding format errors
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::prelude::*;
    ///
    /// // Encode primitive types
    /// let int_sig = TypeSignature::I4;
    /// let encoded = TypeSignatureEncoder::encode(&int_sig)?;
    /// assert_eq!(encoded, vec![0x08]); // ELEMENT_TYPE_I4
    ///
    /// let string_sig = TypeSignature::String;
    /// let encoded = TypeSignatureEncoder::encode(&string_sig)?;
    /// assert_eq!(encoded, vec![0x0E]); // ELEMENT_TYPE_STRING
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode(signature: &TypeSignature) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();
        Self::encode_type_signature_internal(signature, &mut buffer, 0)?;
        Ok(buffer)
    }

    /// Encodes a type signature into an existing buffer.
    ///
    /// Public wrapper method that calls the internal recursive implementation
    /// with initial depth tracking. This provides a clean public API while
    /// maintaining recursion protection.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Recursive encoding errors
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    pub fn encode_type_signature(signature: &TypeSignature, buffer: &mut Vec<u8>) -> Result<()> {
        Self::encode_type_signature_internal(signature, buffer, 0)
    }

    /// Internal recursive implementation of type signature encoding.
    ///
    /// Recursively encodes a [`crate::metadata::signatures::TypeSignature`] and all its components into
    /// the provided buffer with depth tracking for recursion protection.
    /// This method handles all type signature variants and their specific
    /// encoding requirements.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    /// * `depth` - Current recursion depth for overflow protection
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - [`crate::Error::RecursionLimit`]: Maximum recursion depth exceeded
    /// - Unsupported signature type
    /// - Invalid token references
    /// - Recursive encoding errors
    fn encode_type_signature_internal(
        signature: &TypeSignature,
        buffer: &mut Vec<u8>,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_RECURSION_DEPTH {
            return Err(Error::RecursionLimit(MAX_RECURSION_DEPTH));
        }

        match signature {
            // Primitive types - direct element type encoding
            TypeSignature::Void => buffer.push(ELEMENT_TYPE::VOID),
            TypeSignature::Boolean => buffer.push(ELEMENT_TYPE::BOOLEAN),
            TypeSignature::Char => buffer.push(ELEMENT_TYPE::CHAR),
            TypeSignature::I1 => buffer.push(ELEMENT_TYPE::I1),
            TypeSignature::U1 => buffer.push(ELEMENT_TYPE::U1),
            TypeSignature::I2 => buffer.push(ELEMENT_TYPE::I2),
            TypeSignature::U2 => buffer.push(ELEMENT_TYPE::U2),
            TypeSignature::I4 => buffer.push(ELEMENT_TYPE::I4),
            TypeSignature::U4 => buffer.push(ELEMENT_TYPE::U4),
            TypeSignature::I8 => buffer.push(ELEMENT_TYPE::I8),
            TypeSignature::U8 => buffer.push(ELEMENT_TYPE::U8),
            TypeSignature::R4 => buffer.push(ELEMENT_TYPE::R4),
            TypeSignature::R8 => buffer.push(ELEMENT_TYPE::R8),
            TypeSignature::String => buffer.push(ELEMENT_TYPE::STRING),
            TypeSignature::Object => buffer.push(ELEMENT_TYPE::OBJECT),
            TypeSignature::I => buffer.push(ELEMENT_TYPE::I),
            TypeSignature::U => buffer.push(ELEMENT_TYPE::U),
            TypeSignature::TypedByRef => buffer.push(ELEMENT_TYPE::TYPEDBYREF),

            // Reference types with token encoding
            TypeSignature::ValueType(token) => {
                buffer.push(ELEMENT_TYPE::VALUETYPE);
                Self::encode_typedefref_token(*token, buffer)?;
            }

            TypeSignature::Class(token) => {
                buffer.push(ELEMENT_TYPE::CLASS);
                Self::encode_typedefref_token(*token, buffer)?;
            }

            // Generic parameters
            TypeSignature::GenericParamType(index) => {
                buffer.push(ELEMENT_TYPE::VAR);
                write_compressed_uint(*index, buffer)?;
            }

            TypeSignature::GenericParamMethod(index) => {
                buffer.push(ELEMENT_TYPE::MVAR);
                write_compressed_uint(*index, buffer)?;
            }

            // Reference and pointer types
            TypeSignature::ByRef(inner) => {
                buffer.push(ELEMENT_TYPE::BYREF);
                Self::encode_type_signature_internal(inner, buffer, depth.saturating_add(1))?;
            }

            TypeSignature::Ptr(pointer) => {
                buffer.push(ELEMENT_TYPE::PTR);
                // Encode custom modifiers
                Self::encode_custom_modifiers(&pointer.modifiers, buffer)?;
                Self::encode_type_signature_internal(
                    &pointer.base,
                    buffer,
                    depth.saturating_add(1),
                )?;
            }

            TypeSignature::Pinned(inner) => {
                buffer.push(ELEMENT_TYPE::PINNED);
                Self::encode_type_signature_internal(inner, buffer, depth.saturating_add(1))?;
            }

            // Array types
            TypeSignature::SzArray(array) => {
                buffer.push(ELEMENT_TYPE::SZARRAY);
                // Encode custom modifiers
                Self::encode_custom_modifiers(&array.modifiers, buffer)?;
                Self::encode_type_signature_internal(&array.base, buffer, depth.saturating_add(1))?;
            }

            TypeSignature::Array(array) => {
                buffer.push(ELEMENT_TYPE::ARRAY);
                Self::encode_type_signature_internal(&array.base, buffer, depth.saturating_add(1))?;
                write_compressed_uint(array.rank, buffer)?;

                // Collect sizes and lower bounds from dimensions
                let mut sizes = Vec::new();
                let mut lower_bounds = Vec::new();

                for dimension in &array.dimensions {
                    if let Some(size) = dimension.size {
                        sizes.push(size);
                    }
                    if let Some(lower_bound) = dimension.lower_bound {
                        lower_bounds.push(lower_bound);
                    }
                }

                // Encode NumSizes and Sizes
                write_compressed_uint(
                    u32::try_from(sizes.len()).map_err(|_| {
                        malformed_error!("Array sizes length out of range: {}", sizes.len())
                    })?,
                    buffer,
                )?;
                for size in sizes {
                    write_compressed_uint(size, buffer)?;
                }

                // Encode NumLoBounds and LoBounds
                write_compressed_uint(
                    u32::try_from(lower_bounds.len()).map_err(|_| {
                        malformed_error!(
                            "Array lower bounds length out of range: {}",
                            lower_bounds.len()
                        )
                    })?,
                    buffer,
                )?;
                for lower_bound in lower_bounds {
                    write_compressed_int(lower_bound, buffer)?;
                }
            }

            // Generic type instantiation
            TypeSignature::GenericInst(base_type, type_args) => {
                buffer.push(ELEMENT_TYPE::GENERICINST);
                Self::encode_type_signature_internal(base_type, buffer, depth.saturating_add(1))?;
                write_compressed_uint(
                    u32::try_from(type_args.len()).map_err(|_| {
                        malformed_error!(
                            "Generic type arguments length out of range: {}",
                            type_args.len()
                        )
                    })?,
                    buffer,
                )?;
                for type_arg in type_args {
                    Self::encode_type_signature_internal(
                        type_arg,
                        buffer,
                        depth.saturating_add(1),
                    )?;
                }
            }

            // Function pointer
            TypeSignature::FnPtr(method_sig) => {
                buffer.push(ELEMENT_TYPE::FNPTR);
                Self::encode_method_signature(
                    method_sig.as_ref(),
                    buffer,
                    depth.saturating_add(1),
                )?;
            }

            // Custom modifiers
            TypeSignature::ModifiedRequired(modifiers)
            | TypeSignature::ModifiedOptional(modifiers) => {
                for modifier in modifiers {
                    let modifier_type = if modifier.is_required {
                        0x1F // ELEMENT_TYPE_CMOD_REQD
                    } else {
                        0x20 // ELEMENT_TYPE_CMOD_OPT
                    };
                    buffer.push(modifier_type);
                    Self::encode_typedefref_token(modifier.modifier_type, buffer)?;
                }
            }

            // Special types for custom attributes and internal use
            TypeSignature::Type => buffer.push(0x50), // Custom attribute type marker
            TypeSignature::Boxed => buffer.push(0x51), // Custom attribute boxed marker
            TypeSignature::Field => {
                return Err(Error::ModificationInvalid(
                    "Field signatures should not appear in type specifications".to_string(),
                ));
            }
            TypeSignature::Internal => {
                return Err(Error::ModificationInvalid(
                    "Cannot encode internal type signature".to_string(),
                ));
            }
            TypeSignature::Modifier => buffer.push(ELEMENT_TYPE::MODIFIER),
            TypeSignature::Sentinel => buffer.push(ELEMENT_TYPE::SENTINEL),
            TypeSignature::Reserved => {
                return Err(Error::ModificationInvalid(
                    "Cannot encode reserved type signature".to_string(),
                ));
            }

            // Unknown or unsupported types
            TypeSignature::Unknown => {
                return Err(Error::ModificationInvalid(
                    "Cannot encode unknown type signature".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Encodes a method signature (ECMA-335 II.23.2.1, II.23.2.2): the one implementation,
    /// for a function pointer's signature and for a method's own, carrying `depth` so a
    /// signature nesting through function pointers stays bounded.
    ///
    /// Writes the calling convention (its kind, and the `HASTHIS`, `EXPLICITTHIS` and
    /// `GENERIC` flags), the generic parameter count, the parameter count (a vararg call
    /// site's extra arguments included), the return type, the parameters, and for a vararg
    /// call site a `SENTINEL` and its extra arguments.
    ///
    /// # Errors
    ///
    /// [`crate::Error::RecursionLimit`] past the nesting limit, and any error encoding a
    /// parameter's type.
    pub(crate) fn encode_method_signature(
        method_sig: &SignatureMethod,
        buffer: &mut Vec<u8>,
        depth: usize,
    ) -> Result<()> {
        if depth >= MAX_RECURSION_DEPTH {
            return Err(crate::Error::RecursionLimit(MAX_RECURSION_DEPTH));
        }

        buffer.push(method_sig.calling_convention());
        if method_sig.param_count_generic > 0 {
            write_compressed_uint(method_sig.param_count_generic, buffer)?;
        }

        let total = method_sig
            .params
            .len()
            .saturating_add(method_sig.varargs.len());
        write_compressed_uint(
            u32::try_from(total).map_err(|_| {
                malformed_error!("Method parameters length out of range: {}", total)
            })?,
            buffer,
        )?;

        let depth = depth.saturating_add(1);
        Self::encode_parameter(&method_sig.return_type, buffer, depth)?;
        for param in &method_sig.params {
            Self::encode_parameter(param, buffer, depth)?;
        }
        if !method_sig.varargs.is_empty() {
            buffer.push(ELEMENT_TYPE::SENTINEL);
            for param in &method_sig.varargs {
                Self::encode_parameter(param, buffer, depth)?;
            }
        }

        Ok(())
    }

    /// Encodes a parameter or return type: its custom modifiers, `BYREF` for a by-reference
    /// one, then its type.
    ///
    /// # Errors
    ///
    /// Any error encoding a modifier or the type.
    pub(crate) fn encode_parameter(
        parameter: &SignatureParameter,
        buffer: &mut Vec<u8>,
        depth: usize,
    ) -> Result<()> {
        Self::encode_custom_modifiers(&parameter.modifiers, buffer)?;
        if parameter.by_ref {
            buffer.push(ELEMENT_TYPE::BYREF);
        }
        Self::encode_type_signature_internal(&parameter.base, buffer, depth)
    }

    /// Encodes custom modifiers.
    ///
    /// Encodes a list of custom modifier tokens according to ECMA-335
    /// custom modifier format. Each modifier is encoded with its appropriate
    /// element type (required or optional) followed by the token reference.
    ///
    /// # Arguments
    ///
    /// * `modifiers` - List of modifier tokens to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    fn encode_custom_modifiers(modifiers: &[CustomModifier], buffer: &mut Vec<u8>) -> Result<()> {
        for modifier in modifiers {
            let modifier_type = if modifier.is_required {
                0x1F // ELEMENT_TYPE_CMOD_REQD
            } else {
                0x20 // ELEMENT_TYPE_CMOD_OPT
            };
            buffer.push(modifier_type);
            Self::encode_typedefref_token(modifier.modifier_type, buffer)?;
        }
        Ok(())
    }

    /// Encodes a token as a TypeDefOrRef coded index.
    ///
    /// Converts a metadata token into its compressed coded index representation
    /// according to ECMA-335 TypeDefOrRef coded index format. The encoding
    /// depends on the token's table type and row identifier.
    ///
    /// # TypeDefOrRef Coding
    ///
    /// - TypeDef (0x02): `(rid << 2) | 0`
    /// - TypeRef (0x01): `(rid << 2) | 1`
    /// - TypeSpec (0x1B): `(rid << 2) | 2`
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token to encode
    /// * `buffer` - The output buffer to write encoded bytes to
    ///
    /// # Returns
    ///
    /// Success or error result from encoding.
    ///
    /// # Errors
    ///
    /// - Invalid token format
    /// - Unsupported table type for TypeDefOrRef
    fn encode_typedefref_token(token: Token, buffer: &mut Vec<u8>) -> Result<()> {
        let table_id = (token.value() >> 24) & 0xFF;
        let rid = token.value() & 0x00FF_FFFF;

        let coded_index = match table_id {
            0x02 => rid << 2,       // TypeDef
            0x01 => (rid << 2) | 1, // TypeRef
            0x1B => (rid << 2) | 2, // TypeSpec
            _ => {
                return Err(Error::ModificationInvalid(format!(
                    "Invalid token for TypeDefOrRef coded index: {:08x}",
                    token.value()
                )));
            }
        };

        write_compressed_uint(coded_index, buffer)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::{
        signatures::{
            parse_type_spec_signature, SignatureArray, SignaturePointer, SignatureSzArray,
        },
        typesystem::ArrayDimensions,
    };

    #[test]
    fn test_encode_primitive_types() {
        // Test all primitive types
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Void).unwrap(),
            vec![0x01]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Boolean).unwrap(),
            vec![0x02]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Char).unwrap(),
            vec![0x03]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I1).unwrap(),
            vec![0x04]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U1).unwrap(),
            vec![0x05]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I2).unwrap(),
            vec![0x06]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U2).unwrap(),
            vec![0x07]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I4).unwrap(),
            vec![0x08]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U4).unwrap(),
            vec![0x09]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I8).unwrap(),
            vec![0x0A]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U8).unwrap(),
            vec![0x0B]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::R4).unwrap(),
            vec![0x0C]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::R8).unwrap(),
            vec![0x0D]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::String).unwrap(),
            vec![0x0E]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Object).unwrap(),
            vec![0x1C]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::I).unwrap(),
            vec![0x18]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::U).unwrap(),
            vec![0x19]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::TypedByRef).unwrap(),
            vec![0x16]
        );
    }

    #[test]
    fn test_encode_reference_types() {
        // Test ValueType with token
        let valuetype_token = Token::new(0x02000001); // TypeDef RID 1
        let valuetype_sig = TypeSignature::ValueType(valuetype_token);
        let encoded = TypeSignatureEncoder::encode(&valuetype_sig).unwrap();
        assert_eq!(encoded, vec![0x11, 0x04]); // ELEMENT_TYPE_VALUETYPE + coded index (1 << 2 | 0)

        // Test Class with token
        let class_token = Token::new(0x01000001); // TypeRef RID 1
        let class_sig = TypeSignature::Class(class_token);
        let encoded = TypeSignatureEncoder::encode(&class_sig).unwrap();
        assert_eq!(encoded, vec![0x12, 0x05]); // ELEMENT_TYPE_CLASS + coded index (1 << 2 | 1)
    }

    #[test]
    fn test_encode_generic_parameters() {
        // Test type generic parameter
        let type_param = TypeSignature::GenericParamType(0);
        let encoded = TypeSignatureEncoder::encode(&type_param).unwrap();
        assert_eq!(encoded, vec![0x13, 0x00]); // ELEMENT_TYPE_VAR + index 0

        // Test method generic parameter
        let method_param = TypeSignature::GenericParamMethod(1);
        let encoded = TypeSignatureEncoder::encode(&method_param).unwrap();
        assert_eq!(encoded, vec![0x1E, 0x01]); // ELEMENT_TYPE_MVAR + index 1
    }

    #[test]
    fn test_encode_byref() {
        // Test managed reference
        let byref_sig = TypeSignature::ByRef(Box::new(TypeSignature::I4));
        let encoded = TypeSignatureEncoder::encode(&byref_sig).unwrap();
        assert_eq!(encoded, vec![0x10, 0x08]); // ELEMENT_TYPE_BYREF + ELEMENT_TYPE_I4
    }

    #[test]
    fn test_encode_pointer() {
        // Test unmanaged pointer
        let pointer_sig = TypeSignature::Ptr(SignaturePointer {
            modifiers: vec![],
            base: Box::new(TypeSignature::I4),
        });
        let encoded = TypeSignatureEncoder::encode(&pointer_sig).unwrap();
        assert_eq!(encoded, vec![0x0F, 0x08]); // ELEMENT_TYPE_PTR + ELEMENT_TYPE_I4
    }

    #[test]
    fn test_encode_szarray() {
        // Test single-dimensional array
        let array_sig = TypeSignature::SzArray(SignatureSzArray {
            modifiers: vec![],
            base: Box::new(TypeSignature::String),
        });
        let encoded = TypeSignatureEncoder::encode(&array_sig).unwrap();
        assert_eq!(encoded, vec![0x1D, 0x0E]); // ELEMENT_TYPE_SZARRAY + ELEMENT_TYPE_STRING
    }

    #[test]
    fn test_encode_array() {
        // Test multi-dimensional array
        let array_sig = TypeSignature::Array(SignatureArray {
            base: Box::new(TypeSignature::I4),
            rank: 2,
            dimensions: vec![
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: None,
                },
            ],
        });
        let encoded = TypeSignatureEncoder::encode(&array_sig).unwrap();
        assert_eq!(encoded, vec![0x14, 0x08, 0x02, 0x00, 0x00]); // ELEMENT_TYPE_ARRAY + I4 + rank=2 + no sizes/bounds
    }

    #[test]
    fn test_encode_array_with_signed_lower_bounds() {
        // int32[-3..., 64...]: lower bounds are compressed signed integers.
        let array_sig = TypeSignature::Array(SignatureArray {
            base: Box::new(TypeSignature::I4),
            rank: 2,
            dimensions: vec![
                ArrayDimensions {
                    size: None,
                    lower_bound: Some(-3),
                },
                ArrayDimensions {
                    size: None,
                    lower_bound: Some(64),
                },
            ],
        });
        let encoded = TypeSignatureEncoder::encode(&array_sig).unwrap();
        assert_eq!(
            encoded,
            vec![0x14, 0x08, 0x02, 0x00, 0x02, 0x7B, 0x80, 0x80]
        );
    }

    #[test]
    fn test_encode_generic_instantiation() {
        // Test generic instantiation: List<int>
        let list_token = Token::new(0x02000001);
        let generic_sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(list_token)),
            vec![TypeSignature::I4],
        );
        let encoded = TypeSignatureEncoder::encode(&generic_sig).unwrap();
        assert_eq!(encoded, vec![0x15, 0x12, 0x04, 0x01, 0x08]); // GENERICINST + CLASS + token + count=1 + I4
    }

    #[test]
    fn test_encode_complex_nested_generic() {
        // Test Dictionary<string, List<int>>
        let dict_token = Token::new(0x02000001);
        let list_token = Token::new(0x02000002);

        let nested_list = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(list_token)),
            vec![TypeSignature::I4],
        );

        let complex_sig = TypeSignature::GenericInst(
            Box::new(TypeSignature::Class(dict_token)),
            vec![TypeSignature::String, nested_list],
        );

        let encoded = TypeSignatureEncoder::encode(&complex_sig).unwrap();
        // Should start with GENERICINST + CLASS + dict_token + count=2 + STRING + nested generic...
        assert_eq!(encoded[0], 0x15); // ELEMENT_TYPE_GENERICINST
        assert_eq!(encoded[1], 0x12); // ELEMENT_TYPE_CLASS
        assert_eq!(encoded[2], 0x04); // dict_token coded index
        assert_eq!(encoded[3], 0x02); // argument count = 2
        assert_eq!(encoded[4], 0x0E); // ELEMENT_TYPE_STRING
        assert_eq!(encoded[5], 0x15); // Start of nested GENERICINST
    }

    #[test]
    fn test_encode_typedefref_tokens() {
        let mut buffer = Vec::new();

        // Test TypeDef token
        let typedef_token = Token::new(0x02000001);
        TypeSignatureEncoder::encode_typedefref_token(typedef_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x04]); // (1 << 2) | 0
        buffer.clear();

        // Test TypeRef token
        let typeref_token = Token::new(0x01000001);
        TypeSignatureEncoder::encode_typedefref_token(typeref_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x05]); // (1 << 2) | 1
        buffer.clear();

        // Test TypeSpec token
        let typespec_token = Token::new(0x1B000001);
        TypeSignatureEncoder::encode_typedefref_token(typespec_token, &mut buffer).unwrap();
        assert_eq!(buffer, vec![0x06]); // (1 << 2) | 2
    }

    #[test]
    fn test_encode_invalid_token() {
        let mut buffer = Vec::new();
        let invalid_token = Token::new(0x03000001); // FieldDef - not valid for TypeDefOrRef

        let result = TypeSignatureEncoder::encode_typedefref_token(invalid_token, &mut buffer);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid token for TypeDefOrRef"));
    }

    #[test]
    fn test_encode_unknown_signature() {
        let unknown_sig = TypeSignature::Unknown;
        let result = TypeSignatureEncoder::encode(&unknown_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode unknown type signature"));
    }

    #[test]
    fn test_recursion_protection() {
        // Create a deeply nested type signature that would exceed the recursion limit
        let mut nested_sig = TypeSignature::I4;
        for _ in 0..MAX_RECURSION_DEPTH + 10 {
            nested_sig = TypeSignature::ByRef(Box::new(nested_sig));
        }

        let result = TypeSignatureEncoder::encode(&nested_sig);
        assert!(result.is_err());
        if let Err(err) = result {
            if let Error::RecursionLimit(depth) = err {
                assert_eq!(depth, MAX_RECURSION_DEPTH);
            } else {
                panic!("Expected RecursionLimit error, got: {err:?}");
            }
        }
    }

    #[test]
    fn test_encode_pinned_type() {
        let pinned_sig = TypeSignature::Pinned(Box::new(TypeSignature::I4));
        let encoded = TypeSignatureEncoder::encode(&pinned_sig).unwrap();
        assert_eq!(encoded, vec![0x45, 0x08]); // ELEMENT_TYPE_PINNED + ELEMENT_TYPE_I4
    }

    /// Every element type the parser reads on its own encodes back to its own byte: the
    /// encoder wrote `ELEMENT_TYPE_MODIFIER` (0x40) as 0x22, which nothing reads.
    #[test]
    fn every_element_type_encodes_to_the_byte_it_is_read_from() {
        for byte in [
            ELEMENT_TYPE::VOID,
            ELEMENT_TYPE::BOOLEAN,
            ELEMENT_TYPE::CHAR,
            ELEMENT_TYPE::I1,
            ELEMENT_TYPE::U1,
            ELEMENT_TYPE::I2,
            ELEMENT_TYPE::U2,
            ELEMENT_TYPE::I4,
            ELEMENT_TYPE::U4,
            ELEMENT_TYPE::I8,
            ELEMENT_TYPE::U8,
            ELEMENT_TYPE::R4,
            ELEMENT_TYPE::R8,
            ELEMENT_TYPE::STRING,
            ELEMENT_TYPE::TYPEDBYREF,
            ELEMENT_TYPE::I,
            ELEMENT_TYPE::U,
            ELEMENT_TYPE::OBJECT,
            ELEMENT_TYPE::MODIFIER,
            ELEMENT_TYPE::SENTINEL,
        ] {
            let read = parse_type_spec_signature(&[ELEMENT_TYPE::BYREF, byte]).unwrap();
            let encoded = TypeSignatureEncoder::encode(&read.base).unwrap();
            assert_eq!(encoded, [ELEMENT_TYPE::BYREF, byte], "{:?}", read.base);
        }
    }

    #[test]
    fn test_encode_special_types() {
        // Test custom attribute special types
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Type).unwrap(),
            vec![0x50]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Boxed).unwrap(),
            vec![0x51]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Modifier).unwrap(),
            vec![0x40]
        );
        assert_eq!(
            TypeSignatureEncoder::encode(&TypeSignature::Sentinel).unwrap(),
            vec![0x41]
        );
    }

    #[test]
    fn test_encode_invalid_types() {
        // Test types that should fail to encode
        let internal_sig = TypeSignature::Internal;
        let result = TypeSignatureEncoder::encode(&internal_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode internal type signature"));

        let reserved_sig = TypeSignature::Reserved;
        let result = TypeSignatureEncoder::encode(&reserved_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot encode reserved type signature"));

        let field_sig = TypeSignature::Field;
        let result = TypeSignatureEncoder::encode(&field_sig);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Field signatures should not appear"));
    }
}
