//! The LocalConstantSig blob: a constant local's type and value.
//!
//! ```text
//! Blob             ::= CustomMod* (PrimitiveConstant | EnumConstant | GeneralConstant)
//! PrimitiveConstant ::= PrimitiveTypeCode PrimitiveValue
//! PrimitiveTypeCode ::= BOOLEAN | CHAR | I1 | U1 | I2 | U2 | I4 | U4 | I8 | U8 | R4 | R8 | STRING
//! EnumConstant     ::= EnumTypeCode EnumValue EnumType
//! EnumTypeCode     ::= BOOLEAN | CHAR | I1 | U1 | I2 | U2 | I4 | U4 | I8 | U8
//! EnumType         ::= TypeDefOrRefOrSpecEncoded
//! GeneralConstant  ::= (CLASS | VALUETYPE) TypeDefOrRefOrSpecEncoded GeneralValue? | OBJECT
//! ```
//!
//! A string's value is its UTF-16 code units to the end of the blob, or the single byte `0xFF`
//! for null. A general constant's value is a `System.Decimal` (a sign and scale byte, then three
//! 32-bit words) or a `System.DateTime` (its 64-bit ticks), or nothing for null. C# writes a
//! `nint` or `nuint` constant as I4 or U4.
//!
//! # Reference
//!
//! The Portable PDB v1.0 format specification, "LocalConstantSig Blob".

use crate::{
    file::parser::Parser,
    metadata::{
        signatures::{encode_custom_modifier, encode_type_def_or_ref_coded_index, CustomModifier},
        token::Token,
    },
    utils::write_compressed_uint,
    Result,
};

/// `ELEMENT_TYPE_*` codes the blob uses.
mod code {
    pub const BOOLEAN: u8 = 0x02;
    pub const CHAR: u8 = 0x03;
    pub const I1: u8 = 0x04;
    pub const U1: u8 = 0x05;
    pub const I2: u8 = 0x06;
    pub const U2: u8 = 0x07;
    pub const I4: u8 = 0x08;
    pub const U4: u8 = 0x09;
    pub const I8: u8 = 0x0A;
    pub const U8: u8 = 0x0B;
    pub const R4: u8 = 0x0C;
    pub const R8: u8 = 0x0D;
    pub const STRING: u8 = 0x0E;
    pub const VALUETYPE: u8 = 0x11;
    pub const CLASS: u8 = 0x12;
    pub const OBJECT: u8 = 0x1C;
    pub const CMOD_REQD: u8 = 0x1F;
    pub const CMOD_OPT: u8 = 0x20;
}

/// The byte a null string's value is.
const NULL_STRING: u8 = 0xFF;

/// A primitive constant's value: what PrimitiveTypeCode and EnumTypeCode name.
#[derive(Debug, Clone, PartialEq)]
pub enum PrimitiveConstant {
    /// `bool`
    Boolean(bool),
    /// `char`: a UTF-16 code unit
    Char(u16),
    /// `sbyte`
    I1(i8),
    /// `byte`
    U1(u8),
    /// `short`
    I2(i16),
    /// `ushort`
    U2(u16),
    /// `int` (and C#'s `nint`)
    I4(i32),
    /// `uint` (and C#'s `nuint`)
    U4(u32),
    /// `long`
    I8(i64),
    /// `ulong`
    U8(u64),
    /// `float`
    R4(f32),
    /// `double`
    R8(f64),
    /// `string`: its UTF-16 code units, `None` for null
    String(Option<Vec<u16>>),
}

/// A general constant's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneralValue {
    /// No value: a null reference, or a default value type
    None,
    /// A `System.Decimal`: negative when the sign bit is set, `scale` digits after the point,
    /// the 96-bit integer as three 32-bit words, low first
    Decimal {
        /// Whether the value is negative
        negative: bool,
        /// The number of digits after the decimal point
        scale: u8,
        /// The integer's low, middle and high 32 bits
        words: [u32; 3],
    },
    /// A `System.DateTime`: its ticks
    DateTime(i64),
}

/// A constant local's value, as the LocalConstantSig blob gives it.
#[derive(Debug, Clone, PartialEq)]
pub enum LocalConstantValue {
    /// A primitive constant
    Primitive(PrimitiveConstant),
    /// An enum constant: its underlying value, and the enum type
    Enum {
        /// The value, of the enum's underlying type
        value: PrimitiveConstant,
        /// The enum type (TypeDef, TypeRef or TypeSpec)
        enum_type: Token,
    },
    /// A constant of a class or value type: its type, and a decimal or date and time value
    General {
        /// Whether the type is a value type (VALUETYPE) rather than a class (CLASS)
        value_type: bool,
        /// The type (TypeDef, TypeRef or TypeSpec)
        type_token: Token,
        /// The value, `GeneralValue::None` for null
        value: GeneralValue,
    },
    /// A null `object` (and C#'s `dynamic`)
    NullObject,
}

/// A decoded LocalConstantSig blob.
#[derive(Debug, Clone, PartialEq)]
pub struct LocalConstantSig {
    /// The custom modifiers before the type
    pub modifiers: Vec<CustomModifier>,
    /// The constant's type and value
    pub value: LocalConstantValue,
}

impl LocalConstantSig {
    /// Decodes a LocalConstantSig blob.
    ///
    /// # Arguments
    ///
    /// * `blob` - The blob a LocalConstant row's Signature column names
    ///
    /// # Returns
    ///
    /// The constant's custom modifiers, type and value.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::pdb::{LocalConstantSig, LocalConstantValue, PrimitiveConstant};
    ///
    /// // `const string greeting = "hi";`
    /// let constant = LocalConstantSig::parse(&[0x0E, b'h', 0, b'i', 0])?;
    /// let LocalConstantValue::Primitive(PrimitiveConstant::String(Some(units))) = constant.value
    /// else {
    ///     unreachable!()
    /// };
    /// assert_eq!(String::from_utf16(&units).unwrap(), "hi");
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Errors
    ///
    /// When the blob ends early, names a type code the format has no place for, or has
    /// bytes after its value that are no enum type.
    pub fn parse(blob: &[u8]) -> Result<Self> {
        let mut parser = Parser::new(blob);
        let mut modifiers = Vec::new();
        loop {
            let code = parser.peek_byte()?;
            if code != code::CMOD_REQD && code != code::CMOD_OPT {
                break;
            }
            parser.advance()?;
            modifiers.push(CustomModifier {
                is_required: code == code::CMOD_REQD,
                modifier_type: parser.read_compressed_token()?,
            });
        }

        let code = parser.read_le::<u8>()?;
        let value = match code {
            code::STRING => {
                let rest = blob.get(parser.pos()..).unwrap_or_default();
                // The value runs to the blob's end
                parser.seek(blob.len())?;
                LocalConstantValue::Primitive(PrimitiveConstant::String(if rest == [NULL_STRING] {
                    None
                } else {
                    if !rest.len().is_multiple_of(2) {
                        return Err(malformed_error!(
                            "a string constant's value is {} bytes, not UTF-16",
                            rest.len()
                        ));
                    }
                    Some(
                        rest.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|&unit| u16::from_le_bytes(unit))
                            .collect(),
                    )
                }))
            }
            code::CLASS | code::VALUETYPE => {
                let type_token = parser.read_compressed_token()?;
                let rest = blob.get(parser.pos()..).unwrap_or_default();
                let value = match rest.len() {
                    0 => GeneralValue::None,
                    8 => GeneralValue::DateTime(parser.read_le::<i64>()?),
                    13 => {
                        let sign_scale = parser.read_le::<u8>()?;
                        GeneralValue::Decimal {
                            negative: sign_scale & 0x80 != 0,
                            scale: sign_scale & 0x7F,
                            words: [
                                parser.read_le::<u32>()?,
                                parser.read_le::<u32>()?,
                                parser.read_le::<u32>()?,
                            ],
                        }
                    }
                    other => {
                        return Err(malformed_error!(
                            "a general constant's value is {other} bytes: neither a decimal \
                             (13) nor a date and time (8)"
                        ))
                    }
                };
                LocalConstantValue::General {
                    value_type: code == code::VALUETYPE,
                    type_token,
                    value,
                }
            }
            code::OBJECT => LocalConstantValue::NullObject,
            primitive => {
                let value = read_primitive(&mut parser, primitive)?;
                if parser.has_more_data() {
                    LocalConstantValue::Enum {
                        value,
                        enum_type: parser.read_compressed_token()?,
                    }
                } else {
                    LocalConstantValue::Primitive(value)
                }
            }
        };
        if parser.has_more_data() {
            return Err(malformed_error!(
                "a local constant's signature has {} bytes after its value",
                blob.len().saturating_sub(parser.pos())
            ));
        }
        Ok(LocalConstantSig { modifiers, value })
    }

    /// Encodes the blob.
    ///
    /// The inverse of [`LocalConstantSig::parse`]: the bytes are the ones the C# and Visual
    /// Basic compilers write for the constant, so a blob they wrote decodes and encodes back
    /// to itself.
    ///
    /// # Returns
    ///
    /// The LocalConstantSig blob.
    ///
    /// # Errors
    ///
    /// Returns an error when a modifier, enum or general type is not a TypeDef, TypeRef or
    /// TypeSpec token.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::pdb::{LocalConstantSig, LocalConstantValue, PrimitiveConstant};
    ///
    /// let constant = LocalConstantSig {
    ///     modifiers: Vec::new(),
    ///     value: LocalConstantValue::Primitive(PrimitiveConstant::I4(42)),
    /// };
    /// let blob = constant.encode()?;
    /// assert_eq!(blob, [0x08, 42, 0, 0, 0]);
    /// assert_eq!(LocalConstantSig::parse(&blob)?, constant);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut blob = Vec::new();
        for modifier in &self.modifiers {
            encode_custom_modifier(modifier, &mut blob)?;
        }
        match &self.value {
            LocalConstantValue::Primitive(value) => write_primitive(value, &mut blob),
            LocalConstantValue::Enum { value, enum_type } => {
                write_primitive(value, &mut blob);
                write_compressed_uint(encode_type_def_or_ref_coded_index(*enum_type)?, &mut blob)?;
            }
            LocalConstantValue::General {
                value_type,
                type_token,
                value,
            } => {
                blob.push(if *value_type {
                    code::VALUETYPE
                } else {
                    code::CLASS
                });
                write_compressed_uint(encode_type_def_or_ref_coded_index(*type_token)?, &mut blob)?;
                match value {
                    GeneralValue::None => {}
                    GeneralValue::DateTime(ticks) => blob.extend_from_slice(&ticks.to_le_bytes()),
                    GeneralValue::Decimal {
                        negative,
                        scale,
                        words,
                    } => {
                        blob.push(u8::from(*negative) << 7 | (scale & 0x7F));
                        for word in words {
                            blob.extend_from_slice(&word.to_le_bytes());
                        }
                    }
                }
            }
            LocalConstantValue::NullObject => blob.push(code::OBJECT),
        }
        Ok(blob)
    }
}

/// Reads the value of a primitive type code (not STRING, which reads to the blob's end).
fn read_primitive(parser: &mut Parser<'_>, code: u8) -> Result<PrimitiveConstant> {
    Ok(match code {
        code::BOOLEAN => PrimitiveConstant::Boolean(parser.read_le::<u8>()? != 0),
        code::CHAR => PrimitiveConstant::Char(parser.read_le::<u16>()?),
        code::I1 => PrimitiveConstant::I1(parser.read_le::<i8>()?),
        code::U1 => PrimitiveConstant::U1(parser.read_le::<u8>()?),
        code::I2 => PrimitiveConstant::I2(parser.read_le::<i16>()?),
        code::U2 => PrimitiveConstant::U2(parser.read_le::<u16>()?),
        code::I4 => PrimitiveConstant::I4(parser.read_le::<i32>()?),
        code::U4 => PrimitiveConstant::U4(parser.read_le::<u32>()?),
        code::I8 => PrimitiveConstant::I8(parser.read_le::<i64>()?),
        code::U8 => PrimitiveConstant::U8(parser.read_le::<u64>()?),
        code::R4 => PrimitiveConstant::R4(parser.read_le::<f32>()?),
        code::R8 => PrimitiveConstant::R8(parser.read_le::<f64>()?),
        other => {
            return Err(malformed_error!(
                "type code 0x{other:02X} is no local constant's type"
            ))
        }
    })
}

/// Writes a primitive's type code and value.
fn write_primitive(value: &PrimitiveConstant, blob: &mut Vec<u8>) {
    match value {
        PrimitiveConstant::Boolean(value) => blob.extend([code::BOOLEAN, u8::from(*value)]),
        PrimitiveConstant::Char(value) => {
            blob.push(code::CHAR);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::I1(value) => blob.extend([code::I1, value.to_le_bytes()[0]]),
        PrimitiveConstant::U1(value) => blob.extend([code::U1, *value]),
        PrimitiveConstant::I2(value) => {
            blob.push(code::I2);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::U2(value) => {
            blob.push(code::U2);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::I4(value) => {
            blob.push(code::I4);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::U4(value) => {
            blob.push(code::U4);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::I8(value) => {
            blob.push(code::I8);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::U8(value) => {
            blob.push(code::U8);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::R4(value) => {
            blob.push(code::R4);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::R8(value) => {
            blob.push(code::R8);
            blob.extend_from_slice(&value.to_le_bytes());
        }
        PrimitiveConstant::String(value) => {
            blob.push(code::STRING);
            match value {
                Some(units) => {
                    for unit in units {
                        blob.extend_from_slice(&unit.to_le_bytes());
                    }
                }
                None => blob.push(NULL_STRING),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.split('-')
            .map(|byte| u8::from_str_radix(byte, 16).unwrap())
            .collect()
    }

    fn utf16(text: &str) -> Option<Vec<u16>> {
        Some(text.encode_utf16().collect())
    }

    /// The blobs the C# compiler wrote for the probe's constants (`Constants.cs`, `Locals.cs`
    /// of `tests/samples/factory/generators/PdbProbe`), as SRM read them, decode to the values
    /// the source declares, and encode back to the same bytes.
    #[test]
    fn the_probes_constants_decode_to_their_source_values() {
        use LocalConstantValue::{Enum, General, NullObject, Primitive};
        use PrimitiveConstant as P;
        let cases: Vec<(&str, LocalConstantValue)> =
            vec![
            ("02-01", Primitive(P::Boolean(true))),
            ("03-5A-00", Primitive(P::Char(u16::from(b'Z')))),
            ("04-F8", Primitive(P::I1(-8))),
            ("05-C8", Primitive(P::U1(200))),
            ("06-D4-FE", Primitive(P::I2(-300))),
            ("07-60-EA", Primitive(P::U2(60000))),
            ("08-C0-1D-FE-FF", Primitive(P::I4(-123_456))),
            ("09-00-28-6B-EE", Primitive(P::U4(4_000_000_000))),
            ("0A-00-E6-8E-E7-FD-FF-FF-FF", Primitive(P::I8(-9_000_000_000))),
            ("0B-00-00-08-C5-A1-D8-CC-F9", Primitive(P::U8(18_000_000_000_000_000_000))),
            ("0C-00-00-C0-3F", Primitive(P::R4(1.5))),
            ("0D-00-00-00-00-00-00-02-C0", Primitive(P::R8(-2.25))),
            (
                "11-80-C9-04-15-CD-5B-07-00-00-00-00-00-00-00-00",
                General {
                    value_type: true,
                    type_token: Token::new(0x0100_0032),
                    value: GeneralValue::Decimal {
                        negative: false,
                        scale: 4,
                        words: [123_456_789, 0, 0],
                    },
                },
            ),
            (
                "11-80-C9-83-01-00-00-00-00-00-00-00-00-00-00-00",
                General {
                    value_type: true,
                    type_token: Token::new(0x0100_0032),
                    value: GeneralValue::Decimal {
                        negative: true,
                        scale: 3,
                        words: [1, 0, 0],
                    },
                },
            ),
            (
                "0E-63-00-6F-00-6E-00-73-00-74-00-61-00-6E-00-74-00-20-00-74-00-65-00-78-00-74-00",
                Primitive(P::String(utf16("constant text"))),
            ),
            ("0E-FF", Primitive(P::String(None))),
            ("1C", NullObject),
            (
                "06-07-00-0C",
                Enum {
                    value: P::I2(7),
                    enum_type: Token::new(0x0200_0003),
                },
            ),
            ("08-FB-FF-FF-FF", Primitive(P::I4(-5))),
            ("09-05-00-00-00", Primitive(P::U4(5))),
            (
                "08-04-00-00-00-80-CD",
                Enum {
                    value: P::I4(4),
                    enum_type: Token::new(0x0100_0033),
                },
            ),
        ];
        for (blob, expected) in cases {
            let bytes = hex(blob);
            let sig = LocalConstantSig::parse(&bytes).unwrap();
            assert_eq!(sig.value, expected, "{blob}");
            assert!(sig.modifiers.is_empty());
            assert_eq!(sig.encode().unwrap(), bytes, "{blob}");
        }
    }

    /// Modifiers before the type are kept, and survive encoding.
    #[test]
    fn modifiers_are_kept() {
        let bytes = hex("1F-05-20-0C-08-01-00-00-00");
        let sig = LocalConstantSig::parse(&bytes).unwrap();
        assert_eq!(
            sig.modifiers,
            [
                CustomModifier {
                    is_required: true,
                    modifier_type: Token::new(0x0100_0001),
                },
                CustomModifier {
                    is_required: false,
                    modifier_type: Token::new(0x0200_0003),
                },
            ]
        );
        assert_eq!(
            sig.value,
            LocalConstantValue::Primitive(PrimitiveConstant::I4(1))
        );
        assert_eq!(sig.encode().unwrap(), bytes);
    }

    /// A date and time, and a null class constant, are general constants.
    #[test]
    fn general_constants_round_trip() {
        for value in [
            LocalConstantValue::General {
                value_type: true,
                type_token: Token::new(0x0100_0007),
                value: GeneralValue::DateTime(637_500_000_000_000_000),
            },
            LocalConstantValue::General {
                value_type: false,
                type_token: Token::new(0x1B00_0002),
                value: GeneralValue::None,
            },
        ] {
            let sig = LocalConstantSig {
                modifiers: Vec::new(),
                value,
            };
            assert_eq!(
                LocalConstantSig::parse(&sig.encode().unwrap()).unwrap(),
                sig
            );
        }
    }

    /// What the format has no place for is refused, not read as something else.
    #[test]
    fn malformed_blobs_are_refused() {
        for blob in [
            "",            // no type
            "08-01-00",    // an int cut short
            "0E-41",       // a string of an odd byte count
            "11-0C-00",    // a general value neither decimal nor date and time
            "13-00",       // a type code no constant has
            "1C-00",       // bytes after a null object
            "02-01-0C-00", // bytes after an enum type
        ] {
            let bytes = if blob.is_empty() {
                Vec::new()
            } else {
                hex(blob)
            };
            assert!(LocalConstantSig::parse(&bytes).is_err(), "{blob}");
        }
    }
}
