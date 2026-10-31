//! Dedicated signature encoders for .NET metadata blob encoding.
//!
//! This module provides specialized encoders for each signature type, built on top
//! of the existing TypeSignatureEncoder foundation. Each encoder implements the
//! specific ECMA-335 binary format for its signature type.
//!
//! # Available Encoders
//!
//! - [`encode_method_signature`] - Method signatures for MethodDef, MemberRef, MethodSpec
//! - [`encode_field_signature`] - Field signatures for Field and MemberRef tables
//! - [`encode_property_signature`] - Property signatures for Property table
//! - [`encode_local_var_signature`] - Local variable signatures for StandAloneSig table
//! - [`encode_typespec_signature`] - Type specification signatures for TypeSpec table
//!
//! # Design Principles
//!
//! - **Separation of Concerns**: Encoding logic is separated from CilAssembly coordination
//! - **Reusable Components**: Encoders can be used independently or through CilAssembly
//! - **ECMA-335 Compliance**: All encoders follow the official binary format specifications
//! - **TypeSignatureEncoder Foundation**: Built on the proven TypeSignatureEncoder base

use crate::{
    metadata::{
        signatures::{
            CustomModifier, SignatureField, SignatureLocalVariables, SignatureMethod,
            SignatureMethodSpec, SignatureProperty, SignatureTypeSpec, CALLING_CONVENTION,
            SIGNATURE_HEADER,
        },
        token::Token,
        typesystem::{TypeSignatureEncoder, ELEMENT_TYPE},
    },
    utils::write_compressed_uint,
    Error, Result,
};

/// Encodes a custom modifier token into binary format according to ECMA-335.
///
/// Custom modifiers are encoded as:
/// - Required modifiers: 0x1F (ELEMENT_TYPE_CMOD_REQD) + TypeDefOrRef coded index
/// - Optional modifiers: 0x20 (ELEMENT_TYPE_CMOD_OPT) + TypeDefOrRef coded index
///
/// # Arguments
///
/// * `modifier` - The modifier: its type token and whether it is required
/// * `buffer` - The output buffer to write the encoded modifier to
///
/// # TypeDefOrRef Coded Index Encoding
///
/// The modifier token is encoded using the TypeDefOrRef coded index format:
/// - TypeDef: `(rid << 2) | 0`
/// - TypeRef: `(rid << 2) | 1`
/// - TypeSpec: `(rid << 2) | 2`
///
/// # Errors
///
/// When the modifier's token is not a TypeDef, TypeRef or TypeSpec token, or its row does
/// not fit a compressed integer.
pub fn encode_custom_modifier(modifier: &CustomModifier, buffer: &mut Vec<u8>) -> Result<()> {
    let modifier_type = if modifier.is_required {
        ELEMENT_TYPE::CMOD_REQD
    } else {
        ELEMENT_TYPE::CMOD_OPT
    };
    buffer.push(modifier_type);

    let coded_index = encode_type_def_or_ref_coded_index(modifier.modifier_type)?;
    write_compressed_uint(coded_index, buffer)?;
    Ok(())
}

/// Encodes a token as a TypeDefOrRef coded index according to ECMA-335 §II.24.2.6.
///
/// The TypeDefOrRef coded index encodes tokens from three possible tables:
/// - TypeDef (0x02): `(rid << 2) | 0`
/// - TypeRef (0x01): `(rid << 2) | 1`
/// - TypeSpec (0x1B): `(rid << 2) | 2`
///
/// # Arguments
///
/// * `token` - The metadata token to encode
///
/// # Returns
///
/// Returns `Ok` with the TypeDefOrRef coded index value ready for compressed integer encoding,
/// or `Err` if the token is not from a valid table for TypeDefOrRef encoding.
///
/// # Errors
///
/// Returns [`crate::Error::ModificationInvalid`] if the token's table is not
/// TypeDef (0x02), TypeRef (0x01), or TypeSpec (0x1B).
pub fn encode_type_def_or_ref_coded_index(token: Token) -> Result<u32> {
    let table_id = token.table();
    let rid = token.row();

    match table_id {
        0x02 => Ok(rid << 2),       // TypeDef
        0x01 => Ok((rid << 2) | 1), // TypeRef
        0x1B => Ok((rid << 2) | 2), // TypeSpec
        _ => Err(Error::ModificationInvalid(format!(
            "Invalid token table 0x{:02X} for TypeDefOrRef coded index. \
            Expected TypeDef (0x02), TypeRef (0x01), or TypeSpec (0x1B). Token: 0x{:08X}",
            table_id,
            token.value()
        ))),
    }
}

/// Encodes a method signature into binary format according to ECMA-335.
///
/// Method signatures encode:
/// - The calling convention byte: its kind, and the `HASTHIS`, `EXPLICITTHIS` and `GENERIC`
///   flags
/// - The generic parameter count, for a generic method
/// - The parameter count (compressed integer), a vararg call site's extra arguments included
/// - The return type and the parameters, each with its custom modifiers and `BYREF`
/// - For a vararg call site, a `SENTINEL` and the extra arguments
///
/// # Arguments
///
/// * `signature` - The method signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded method signature.
///
/// # Errors
///
/// Returns an error if encoding any parameter or return type fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::signatures::*;
///
/// let signature = MethodSignatureBuilder::new()
///     .calling_convention_default()
///     .returns(TypeSignature::Void)
///     .param(TypeSignature::I4)
///     .build()?;
///
/// let encoded = encode_method_signature(&signature)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_method_signature(signature: &SignatureMethod) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    TypeSignatureEncoder::encode_method_signature(signature, &mut buffer, 0)?;
    Ok(buffer)
}

/// Encodes a field signature into binary format according to ECMA-335.
///
/// Field signatures encode:
/// - Field signature prolog (0x06)
/// - Custom modifiers (if any)
/// - Field type (using TypeSignatureEncoder)
///
/// # Arguments
///
/// * `signature` - The field signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded field signature.
///
/// # Errors
///
/// Returns an error if encoding the field type fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
pub fn encode_field_signature(signature: &SignatureField) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    buffer.push(SIGNATURE_HEADER::FIELD);

    // Encode custom modifiers before the field type
    // Custom modifiers are applied in sequence and evaluated right-to-left
    for modifier in &signature.modifiers {
        encode_custom_modifier(modifier, &mut buffer)?;
    }

    TypeSignatureEncoder::encode_type_signature(&signature.base, &mut buffer)?;

    Ok(buffer)
}

/// Encodes a property signature into binary format according to ECMA-335.
///
/// Property signatures encode:
/// - Property signature prolog (0x08 | HASTHIS if instance property)
/// - Parameter count (compressed integer)
/// - Property type (using TypeSignatureEncoder)
/// - Index parameter types (for indexers)
///
/// # Arguments
///
/// * `signature` - The property signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded property signature.
///
/// # Errors
///
/// Returns an error if encoding the property type or any parameter fails, typically due to:
/// - Invalid type signature structures
/// - Unsupported type encodings
/// - Issues with type reference tokens
/// - Too many parameters (exceeds u32 range)
pub fn encode_property_signature(signature: &SignatureProperty) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    let mut prolog = SIGNATURE_HEADER::PROPERTY;
    if signature.has_this {
        prolog |= CALLING_CONVENTION::HASTHIS;
    }
    buffer.push(prolog);

    let param_count = u32::try_from(signature.params.len()).map_err(|_| {
        Error::ModificationInvalid(format!(
            "Too many parameters in property signature: {}",
            signature.params.len()
        ))
    })?;
    write_compressed_uint(param_count, &mut buffer)?;

    // Encode custom modifiers before the property type
    // Property signatures can have custom modifiers on the property type itself
    // (similar to field signatures). The encoding follows the same ECMA-335 rules.
    for modifier in &signature.modifiers {
        encode_custom_modifier(modifier, &mut buffer)?;
    }

    TypeSignatureEncoder::encode_type_signature(&signature.base, &mut buffer)?;

    for param in &signature.params {
        TypeSignatureEncoder::encode_parameter(param, &mut buffer, 0)?;
    }

    Ok(buffer)
}

/// Encodes a local variable signature into binary format according to ECMA-335.
///
/// Local variable signatures encode:
/// - Local variable signature prolog (0x07)
/// - Local variable count (compressed integer)
/// - Local variable types with modifiers
///
/// # Arguments
///
/// * `signature` - The local variable signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded local variable signature.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - Local variable count exceeds u32 range
/// - Type signature encoding fails
pub fn encode_local_var_signature(signature: &SignatureLocalVariables) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();

    buffer.push(SIGNATURE_HEADER::LOCAL_SIG);

    write_compressed_uint(
        u32::try_from(signature.locals.len()).map_err(|_| {
            malformed_error!(
                "LocalVar signature has too many locals: {}",
                signature.locals.len()
            )
        })?,
        &mut buffer,
    )?;

    for local in &signature.locals {
        // CustomMod* Constraint* [BYREF] Type (ECMA-335 II.23.2.6)
        for modifier in &local.modifiers {
            encode_custom_modifier(modifier, &mut buffer)?;
        }
        if local.is_pinned {
            buffer.push(ELEMENT_TYPE::PINNED);
        }

        if local.is_byref {
            buffer.push(ELEMENT_TYPE::BYREF);
        }

        TypeSignatureEncoder::encode_type_signature(&local.base, &mut buffer)?;
    }

    Ok(buffer)
}

/// Encodes a type specification signature into binary format according to ECMA-335.
///
/// Type specification signatures directly encode complex type signatures using
/// the existing TypeSignatureEncoder foundation.
///
/// # Arguments
///
/// * `signature` - The type specification signature to encode
///
/// # Returns
///
/// A vector of bytes representing the encoded type specification signature.
///
/// # Errors
///
/// Returns [`crate::Error`] if type signature encoding fails.
pub fn encode_typespec_signature(signature: &SignatureTypeSpec) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    for modifier in &signature.modifiers {
        encode_custom_modifier(modifier, &mut buffer)?;
    }
    TypeSignatureEncoder::encode_type_signature(&signature.base, &mut buffer)?;
    Ok(buffer)
}

/// Encodes a generic method instantiation (ECMA-335 II.23.2.15): `GENRICINST`, the number of
/// type arguments, then each type argument.
///
/// # Errors
///
/// Returns [`crate::Error`] if there are more type arguments than a compressed integer holds,
/// or a type argument cannot be encoded.
pub fn encode_method_spec_signature(signature: &SignatureMethodSpec) -> Result<Vec<u8>> {
    let mut buffer = vec![SIGNATURE_HEADER::GENRICINST];
    let count = u32::try_from(signature.generic_args.len())
        .map_err(|_| Error::LayoutFailed("too many generic arguments".to_string()))?;
    write_compressed_uint(count, &mut buffer)?;
    for argument in &signature.generic_args {
        buffer.extend(TypeSignatureEncoder::encode(argument)?);
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use proptest::{prop_assert_eq, test_runner::TestCaseError};

    use super::*;
    use crate::{
        metadata::{
            signatures::{
                parse_field_signature, parse_local_var_signature, parse_method_signature,
                parse_method_spec_signature, parse_property_signature, parse_type_spec_signature,
                CustomModifier, FieldSignatureBuilder, LocalVariableSignatureBuilder,
                MethodSignatureBuilder, PropertySignatureBuilder, SignatureSzArray, TypeSignature,
                TypeSpecSignatureBuilder, SIGNATURE_HEADER,
            },
            token::Token,
            typesystem::ELEMENT_TYPE,
        },
        testkit::{arb, arb::check},
    };

    /// Every shape of method signature encodes back to the bytes it was read from: each
    /// calling convention, the instance and generic flags, by-reference parameters, custom
    /// modifiers, a vararg call site's extra arguments, and all of these inside a function
    /// pointer.
    #[test]
    fn every_method_signature_shape_round_trips() {
        let shapes: &[&[u8]] = &[
            &[0x00, 0x00, 0x01],                   // void()
            &[0x01, 0x00, 0x01],                   // unmanaged cdecl
            &[0x02, 0x00, 0x01],                   // unmanaged stdcall
            &[0x03, 0x00, 0x01],                   // unmanaged thiscall
            &[0x04, 0x00, 0x01],                   // unmanaged fastcall
            &[0x20, 0x01, 0x01, 0x08],             // instance void(int)
            &[0x60, 0x01, 0x01, 0x08],             // explicit this
            &[0x30, 0x01, 0x01, 0x01, 0x1E, 0x00], // instance void M<T>(!!0)
            &[0x00, 0x01, 0x01, 0x10, 0x08],       // void(int&)
            &[0x00, 0x01, 0x01, 0x20, 0x15, 0x08], // void(modopt(TypeRef 5) int)
            &[0x05, 0x02, 0x01, 0x08, 0x41, 0x0E], // vararg void(int, ..., string)
            // void(method vararg void *(int&, ..., string))
            &[
                0x00, 0x01, 0x01, 0x1B, 0x05, 0x02, 0x01, 0x10, 0x08, 0x41, 0x0E,
            ],
            // method void *(modreq(TypeRef 5) int&) returning a generic method's !!0
            &[
                0x10, 0x01, 0x01, 0x1E, 0x00, 0x1B, 0x00, 0x01, 0x01, 0x1F, 0x15, 0x10, 0x08,
            ],
        ];
        for shape in shapes {
            let parsed = parse_method_signature(shape).unwrap();
            assert_eq!(
                encode_method_signature(&parsed).unwrap(),
                *shape,
                "{shape:02x?}: {parsed:?}"
            );
        }
    }

    /// Every other kind of signature encodes back to the bytes it was read from, custom
    /// modifiers included: fields, properties, local variable lists (pinned, by-reference
    /// and typed-reference locals) and type specifications.
    #[test]
    fn every_other_signature_kind_round_trips() {
        let fields: &[&[u8]] = &[&[0x06, 0x08], &[0x06, 0x1F, 0x15, 0x12, 0x0D]];
        for shape in fields {
            let parsed = parse_field_signature(shape).unwrap();
            assert_eq!(
                encode_field_signature(&parsed).unwrap(),
                *shape,
                "{shape:02x?}"
            );
        }
        let properties: &[&[u8]] = &[
            &[0x28, 0x00, 0x08],
            &[0x08, 0x01, 0x20, 0x15, 0x0E, 0x10, 0x08],
        ];
        for shape in properties {
            let parsed = parse_property_signature(shape).unwrap();
            assert_eq!(
                encode_property_signature(&parsed).unwrap(),
                *shape,
                "{shape:02x?}"
            );
        }
        let locals: &[&[u8]] = &[
            &[0x07, 0x02, 0x08, 0x16],
            &[0x07, 0x01, 0x1F, 0x15, 0x08],
            &[0x07, 0x01, 0x45, 0x10, 0x08],
            &[0x07, 0x01, 0x20, 0x15, 0x45, 0x10, 0x12, 0x0D],
        ];
        for shape in locals {
            let parsed = parse_local_var_signature(shape).unwrap();
            assert_eq!(
                encode_local_var_signature(&parsed).unwrap(),
                *shape,
                "{shape:02x?}"
            );
        }
        let type_specs: &[&[u8]] = &[
            &[0x15, 0x12, 0x10, 0x01, 0x08],
            &[0x20, 0x15, 0x08],
            &[0x1D, 0x1F, 0x15, 0x08],
        ];
        for shape in type_specs {
            let parsed = parse_type_spec_signature(shape).unwrap();
            assert_eq!(
                encode_typespec_signature(&parsed).unwrap(),
                *shape,
                "{shape:02x?}"
            );
        }
    }

    /// A method instantiation reads back as it was written, class arguments included.
    #[test]
    fn a_method_spec_signature_round_trips() {
        let signature = SignatureMethodSpec {
            generic_args: vec![
                TypeSignature::I4,
                TypeSignature::Class(Token::new(0x0100_0090)),
                TypeSignature::SzArray(SignatureSzArray {
                    modifiers: Vec::new(),
                    base: Box::new(TypeSignature::String),
                }),
            ],
        };
        let encoded = encode_method_spec_signature(&signature).unwrap();
        assert_eq!(encoded.first(), Some(&SIGNATURE_HEADER::GENRICINST));
        assert_eq!(parse_method_spec_signature(&encoded).unwrap(), signature);
    }

    #[test]
    fn test_encode_method_signature() {
        let signature = MethodSignatureBuilder::new()
            .calling_convention_default()
            .returns(TypeSignature::Void)
            .param(TypeSignature::I4)
            .build()
            .unwrap();

        let result = encode_method_signature(&signature);
        assert!(result.is_ok(), "Method signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Basic structure check: should have calling convention + param count + return type + param type
        assert!(
            encoded.len() >= 3,
            "Encoded signature should have minimum structure"
        );
    }

    #[test]
    fn test_encode_field_signature() {
        let signature = FieldSignatureBuilder::new()
            .field_type(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_field_signature(&signature);
        assert!(result.is_ok(), "Field signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with field signature marker
        assert_eq!(
            encoded[0],
            SIGNATURE_HEADER::FIELD,
            "Field signature should start with SIGNATURE_HEADER::FIELD"
        );
    }

    #[test]
    fn test_encode_property_signature() {
        let signature = PropertySignatureBuilder::new()
            .property_type(TypeSignature::I4)
            .build()
            .unwrap();

        let result = encode_property_signature(&signature);
        assert!(result.is_ok(), "Property signature encoding should succeed");

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with property signature marker
        assert_eq!(
            encoded[0],
            SIGNATURE_HEADER::PROPERTY,
            "Property signature should start with SIGNATURE_HEADER::PROPERTY"
        );
    }

    #[test]
    fn test_encode_local_var_signature() {
        let signature = LocalVariableSignatureBuilder::new()
            .add_local(TypeSignature::I4)
            .add_pinned_local(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_local_var_signature(&signature);
        assert!(
            result.is_ok(),
            "Local variable signature encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");

        // Should start with local signature marker
        assert_eq!(
            encoded[0],
            SIGNATURE_HEADER::LOCAL_SIG,
            "Local variable signature should start with SIGNATURE_HEADER::LOCAL_SIG"
        );
    }

    #[test]
    fn test_encode_typespec_signature() {
        let signature = TypeSpecSignatureBuilder::new()
            .type_signature(TypeSignature::String)
            .build()
            .unwrap();

        let result = encode_typespec_signature(&signature);
        assert!(
            result.is_ok(),
            "Type specification signature encoding should succeed"
        );

        let encoded = result.unwrap();
        assert!(!encoded.is_empty(), "Encoded signature should not be empty");
    }

    #[test]
    fn test_encode_custom_modifier() {
        let mut buffer = Vec::new();

        // Test optional modifier encoding
        let optional_modifier = CustomModifier {
            is_required: false,
            modifier_type: Token::new(0x01000001), // TypeRef token (table 0x01, RID 1)
        };
        encode_custom_modifier(&optional_modifier, &mut buffer).unwrap();

        // Should encode as: ELEMENT_TYPE_CMOD_OPT + TypeDefOrRef coded index
        assert_eq!(
            buffer[0],
            ELEMENT_TYPE::CMOD_OPT,
            "Optional modifier should start with ELEMENT_TYPE_CMOD_OPT"
        );
        assert!(buffer.len() > 1, "Modifier should include coded index");

        // Test required modifier encoding
        buffer.clear();
        let required_modifier = CustomModifier {
            is_required: true,
            modifier_type: Token::new(0x01000001),
        };
        encode_custom_modifier(&required_modifier, &mut buffer).unwrap();

        // Should encode as: ELEMENT_TYPE_CMOD_REQD + TypeDefOrRef coded index
        assert_eq!(
            buffer[0],
            ELEMENT_TYPE::CMOD_REQD,
            "Required modifier should start with ELEMENT_TYPE_CMOD_REQD"
        );
        assert!(buffer.len() > 1, "Modifier should include coded index");
    }

    #[test]
    fn test_encode_type_def_or_ref_coded_index_error() {
        // Test invalid token table (e.g., MethodDef table 0x06)
        let invalid_token = Token::new(0x06000001);
        let result = encode_type_def_or_ref_coded_index(invalid_token);
        assert!(
            result.is_err(),
            "Should return error for invalid token table"
        );

        // Valid tokens should succeed
        let typedef_token = Token::new(0x02000001);
        assert!(encode_type_def_or_ref_coded_index(typedef_token).is_ok());

        let typeref_token = Token::new(0x01000001);
        assert!(encode_type_def_or_ref_coded_index(typeref_token).is_ok());

        let typespec_token = Token::new(0x1B000001);
        assert!(encode_type_def_or_ref_coded_index(typespec_token).is_ok());
    }

    #[test]
    fn test_encode_type_def_or_ref_coded_index() {
        // Test TypeDef token (table 0x02)
        let typedef_token = Token::new(0x02000001); // TypeDef table, RID 1
        let coded_index = encode_type_def_or_ref_coded_index(typedef_token).unwrap();
        assert_eq!(coded_index, 1 << 2, "TypeDef should encode as (rid << 2)");

        // Test TypeRef token (table 0x01)
        let typeref_token = Token::new(0x01000005); // TypeRef table, RID 5
        let coded_index = encode_type_def_or_ref_coded_index(typeref_token).unwrap();
        assert_eq!(
            coded_index,
            (5 << 2) | 1,
            "TypeRef should encode as (rid << 2) | 1"
        );

        // Test TypeSpec token (table 0x1B)
        let typespec_token = Token::new(0x1B000003); // TypeSpec table, RID 3
        let coded_index = encode_type_def_or_ref_coded_index(typespec_token).unwrap();
        assert_eq!(
            coded_index,
            (3 << 2) | 2,
            "TypeSpec should encode as (rid << 2) | 2"
        );
    }

    /// `value` encodes, and its encoding decodes back to it.
    fn round_trips<T: PartialEq + std::fmt::Debug>(
        value: &T,
        encode: fn(&T) -> Result<Vec<u8>>,
        decode: fn(&[u8]) -> Result<T>,
    ) -> std::result::Result<(), TestCaseError> {
        let bytes = encode(value)
            .map_err(|error| TestCaseError::fail(format!("does not encode: {error}")))?;
        let decoded = decode(&bytes).map_err(|error| {
            TestCaseError::fail(format!("{bytes:02x?} does not decode: {error}"))
        })?;
        prop_assert_eq!(&decoded, value, "encoded as {:02x?}", bytes);
        Ok(())
    }

    #[test]
    fn every_signature_decodes_to_what_was_encoded() {
        check(arb::method_signature(), |signature| {
            round_trips(&signature, encode_method_signature, parse_method_signature)
        });
        check(arb::field_signature(), |signature| {
            round_trips(&signature, encode_field_signature, parse_field_signature)
        });
        check(arb::property_signature(), |signature| {
            round_trips(
                &signature,
                encode_property_signature,
                parse_property_signature,
            )
        });
        check(arb::local_var_signature(), |signature| {
            round_trips(
                &signature,
                encode_local_var_signature,
                parse_local_var_signature,
            )
        });
        check(arb::type_spec_signature(), |signature| {
            round_trips(
                &signature,
                encode_typespec_signature,
                parse_type_spec_signature,
            )
        });
        check(arb::method_spec_signature(), |signature| {
            round_trips(
                &signature,
                encode_method_spec_signature,
                parse_method_spec_signature,
            )
        });
    }
}
