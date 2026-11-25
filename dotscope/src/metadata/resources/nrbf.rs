//! A reader of the root object a `BinaryFormatter` stream holds (MS-NRBF).
//!
//! A .NET Framework resource set stores a value of a user type (type code
//! `0x40` and above, [`ResourceType::Serialized`](crate::metadata::resources::ResourceType::Serialized))
//! as the stream `BinaryFormatter` writes for it: a header, the library the
//! type is in, the object's class with its members' names and types, and the
//! members' values. A WinForms form's localized layout is such values:
//! `System.Drawing.Point` (`x`, `y`), `System.Drawing.Size` (`width`,
//! `height`), an enumeration (`value__`).
//!
//! [`read_object`] reads the root object: its class's name and each member's
//! value where the stream states it in place (a primitive, a string, `null`).
//! A member that is another object of the stream is a reference to its
//! record, which this reader does not follow: it reads one object, never
//! recursing, every count checked against the bytes left.
//!
//! # Reference
//!
//! [MS-NRBF]: .NET Remoting: Binary Format Data Structure, sections 2.1 to 2.6.

use std::str;

use crate::{file::parser::Parser, Result};

/// The root object of a `BinaryFormatter` stream.
#[derive(Debug, Clone, PartialEq)]
pub struct NrbfObject {
    /// The class's full name (`System.Drawing.Point`).
    pub class_name: String,
    /// Each member's name and value, in the order the class lists them.
    pub members: Vec<(String, NrbfValue)>,
}

impl NrbfObject {
    /// The value of the member `name`, when the object has one.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&NrbfValue> {
        self.members
            .iter()
            .find(|(member, _)| member == name)
            .map(|(_, value)| value)
    }
}

/// A member's value as the stream states it.
#[derive(Debug, Clone, PartialEq)]
pub enum NrbfValue {
    /// A `Boolean`.
    Boolean(bool),
    /// A `Byte`.
    Byte(u8),
    /// An `SByte`.
    SByte(i8),
    /// A `Char`.
    Char(char),
    /// An `Int16`.
    Int16(i16),
    /// A `UInt16`.
    UInt16(u16),
    /// An `Int32`.
    Int32(i32),
    /// A `UInt32`.
    UInt32(u32),
    /// An `Int64`, or a `TimeSpan` or `DateTime` as its ticks.
    Int64(i64),
    /// A `UInt64`.
    UInt64(u64),
    /// A `Single`.
    Single(f32),
    /// A `Double`.
    Double(f64),
    /// A `Decimal`, as the string the stream spells it as.
    Decimal(String),
    /// A string.
    String(String),
    /// `null`.
    Null,
    /// Another object of the stream, by the id of its record.
    Reference(i32),
    /// A value this reader does not read in place (an inline object or
    /// array); the members after it are not read either.
    Unread,
}

impl NrbfValue {
    /// The value as an integer, for an integral member.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        Some(match self {
            Self::Byte(v) => i64::from(*v),
            Self::SByte(v) => i64::from(*v),
            Self::Int16(v) => i64::from(*v),
            Self::UInt16(v) => i64::from(*v),
            Self::Int32(v) => i64::from(*v),
            Self::UInt32(v) => i64::from(*v),
            Self::Int64(v) => *v,
            Self::UInt64(v) => i64::try_from(*v).ok()?,
            _ => return None,
        })
    }
}

/// `RecordTypeEnumeration` values (MS-NRBF 2.1.2.1) this reader reads.
mod record {
    /// `SerializedStreamHeader`.
    pub const HEADER: u8 = 0;
    /// `ClassWithId`: an object of a class an earlier record declared.
    pub const CLASS_WITH_ID: u8 = 1;
    /// `SystemClassWithMembers`.
    pub const SYSTEM_CLASS_WITH_MEMBERS: u8 = 2;
    /// `ClassWithMembers`.
    pub const CLASS_WITH_MEMBERS: u8 = 3;
    /// `SystemClassWithMembersAndTypes`.
    pub const SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES: u8 = 4;
    /// `ClassWithMembersAndTypes`.
    pub const CLASS_WITH_MEMBERS_AND_TYPES: u8 = 5;
    /// `BinaryObjectString`.
    pub const OBJECT_STRING: u8 = 6;
    /// `MemberPrimitiveTyped`.
    pub const MEMBER_PRIMITIVE_TYPED: u8 = 8;
    /// `MemberReference`.
    pub const MEMBER_REFERENCE: u8 = 9;
    /// `ObjectNull`.
    pub const OBJECT_NULL: u8 = 10;
    /// `BinaryLibrary`.
    pub const LIBRARY: u8 = 12;
}

/// `BinaryTypeEnumeration` values (MS-NRBF 2.1.2.2): how a member's type is
/// stated, and so what its additional information is.
mod binary_type {
    /// A primitive, its `PrimitiveTypeEnumeration` following.
    pub const PRIMITIVE: u8 = 0;
    /// A `SystemClass`, its class name following.
    pub const SYSTEM_CLASS: u8 = 3;
    /// A `Class`, its class name and library id following.
    pub const CLASS: u8 = 4;
    /// A `PrimitiveArray`, its element's `PrimitiveTypeEnumeration` following.
    pub const PRIMITIVE_ARRAY: u8 = 7;
}

/// Reads the root object of the `BinaryFormatter` stream `data`.
///
/// # Errors
///
/// A malformed-input error when the stream does not start with its header,
/// holds no class record before its first value, or a record or count runs
/// past the data.
pub fn read_object(data: &[u8]) -> Result<NrbfObject> {
    let mut parser = Parser::new(data);
    if parser.read_le::<u8>()? != record::HEADER {
        return Err(malformed_error!(
            "NRBF stream does not start with its header"
        ));
    }
    // Root id, header id, major and minor version.
    for _ in 0..4 {
        parser.read_le::<i32>()?;
    }
    loop {
        match parser.read_le::<u8>()? {
            record::LIBRARY => {
                parser.read_le::<i32>()?;
                parser.read_prefixed_string_utf8()?;
            }
            record::CLASS_WITH_MEMBERS_AND_TYPES => return read_class(&mut parser, true, true),
            record::SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES => {
                return read_class(&mut parser, true, false)
            }
            record::CLASS_WITH_MEMBERS => return read_class(&mut parser, false, true),
            record::SYSTEM_CLASS_WITH_MEMBERS => return read_class(&mut parser, false, false),
            other => {
                return Err(malformed_error!(
                    "NRBF record {other} before the root object's class"
                ))
            }
        }
    }
}

/// How one member's value is stated: in place as a primitive of its type, or
/// as a record of its own.
#[derive(Clone, Copy)]
enum MemberType {
    /// A primitive of this `PrimitiveTypeEnumeration`.
    Primitive(u8),
    /// A record of its own (a string, an object, an array, `null`).
    Record,
}

/// Reads a class record and its members' values: with its members' types
/// when `typed`, followed by its library's id when `library`.
fn read_class(parser: &mut Parser<'_>, typed: bool, library: bool) -> Result<NrbfObject> {
    parser.read_le::<i32>()?; // the object's id
    let class_name = parser.read_prefixed_string_utf8()?;
    let count = parser.read_le::<i32>()?;
    let count = usize::try_from(count)
        .ok()
        .filter(|count| *count <= parser.remaining())
        .ok_or_else(|| malformed_error!("NRBF class {class_name} has {count} members"))?;
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(parser.read_prefixed_string_utf8()?);
    }
    let types = if typed {
        read_member_types(parser, count)?
    } else {
        vec![MemberType::Record; count]
    };
    if library {
        parser.read_le::<i32>()?;
    }
    let mut members = Vec::with_capacity(count);
    let mut unread = false;
    for (name, ty) in names.into_iter().zip(types) {
        let value = if unread {
            NrbfValue::Unread
        } else {
            match ty {
                MemberType::Primitive(primitive) => read_primitive(parser, primitive)?,
                MemberType::Record => read_member_record(parser)?,
            }
        };
        unread |= value == NrbfValue::Unread;
        members.push((name, value));
    }
    Ok(NrbfObject {
        class_name,
        members,
    })
}

/// Reads a class's `MemberTypeInfo`: each member's `BinaryTypeEnumeration`,
/// then the additional information each states.
fn read_member_types(parser: &mut Parser<'_>, count: usize) -> Result<Vec<MemberType>> {
    let mut kinds = Vec::with_capacity(count);
    for _ in 0..count {
        kinds.push(parser.read_le::<u8>()?);
    }
    let mut types = Vec::with_capacity(count);
    for kind in kinds {
        types.push(match kind {
            binary_type::PRIMITIVE => MemberType::Primitive(parser.read_le::<u8>()?),
            binary_type::PRIMITIVE_ARRAY => {
                parser.read_le::<u8>()?;
                MemberType::Record
            }
            binary_type::SYSTEM_CLASS => {
                parser.read_prefixed_string_utf8()?;
                MemberType::Record
            }
            binary_type::CLASS => {
                parser.read_prefixed_string_utf8()?;
                parser.read_le::<i32>()?;
                MemberType::Record
            }
            _ => MemberType::Record,
        });
    }
    Ok(types)
}

/// Reads a member stated as a record of its own: a string, `null`, a
/// reference, or a typed primitive; any other record (an inline object or
/// array) is [`NrbfValue::Unread`].
fn read_member_record(parser: &mut Parser<'_>) -> Result<NrbfValue> {
    Ok(match parser.read_le::<u8>()? {
        record::OBJECT_STRING => {
            parser.read_le::<i32>()?;
            NrbfValue::String(parser.read_prefixed_string_utf8()?)
        }
        record::OBJECT_NULL => NrbfValue::Null,
        record::MEMBER_REFERENCE => NrbfValue::Reference(parser.read_le::<i32>()?),
        record::MEMBER_PRIMITIVE_TYPED => {
            let primitive = parser.read_le::<u8>()?;
            read_primitive(parser, primitive)?
        }
        record::CLASS_WITH_ID
        | record::SYSTEM_CLASS_WITH_MEMBERS
        | record::CLASS_WITH_MEMBERS
        | record::SYSTEM_CLASS_WITH_MEMBERS_AND_TYPES
        | record::CLASS_WITH_MEMBERS_AND_TYPES => NrbfValue::Unread,
        _ => NrbfValue::Unread,
    })
}

/// Reads a primitive of `PrimitiveTypeEnumeration` `primitive` (MS-NRBF
/// 2.1.2.3).
fn read_primitive(parser: &mut Parser<'_>, primitive: u8) -> Result<NrbfValue> {
    Ok(match primitive {
        1 => NrbfValue::Boolean(parser.read_le::<u8>()? != 0),
        2 => NrbfValue::Byte(parser.read_le::<u8>()?),
        3 => NrbfValue::Char(read_char(parser)?),
        5 => NrbfValue::Decimal(parser.read_prefixed_string_utf8()?),
        6 => NrbfValue::Double(parser.read_le::<f64>()?),
        7 => NrbfValue::Int16(parser.read_le::<i16>()?),
        8 => NrbfValue::Int32(parser.read_le::<i32>()?),
        9 | 12 | 13 => NrbfValue::Int64(parser.read_le::<i64>()?),
        10 => NrbfValue::SByte(parser.read_le::<i8>()?),
        11 => NrbfValue::Single(parser.read_le::<f32>()?),
        14 => NrbfValue::UInt16(parser.read_le::<u16>()?),
        15 => NrbfValue::UInt32(parser.read_le::<u32>()?),
        16 => NrbfValue::UInt64(parser.read_le::<u64>()?),
        17 => NrbfValue::Null,
        18 => NrbfValue::String(parser.read_prefixed_string_utf8()?),
        other => return Err(malformed_error!("NRBF primitive type {other}")),
    })
}

/// Reads a `Char`: one character, UTF-8 encoded in one to four bytes.
fn read_char(parser: &mut Parser<'_>) -> Result<char> {
    let lead = parser.read_le::<u8>()?;
    // The continuation bytes the lead byte says follow it.
    let continuation = match lead {
        0x00..=0x7f => 0,
        0xc0..=0xdf => 1,
        0xe0..=0xef => 2,
        0xf0..=0xf7 => 3,
        _ => return Err(malformed_error!("NRBF char lead byte {lead:#x}")),
    };
    let mut bytes = vec![lead];
    bytes.extend_from_slice(parser.read_bytes(continuation)?);
    str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.chars().next())
        .ok_or_else(|| malformed_error!("NRBF char is not UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The stream `resgen` writes for `System.Drawing.Size` 284 x 161.
    const SIZE: &[u8] = &[
        0x00, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x0e, b'S', b'y', b's', b't', b'e', b'm', b'.',
        b'D', b'r', b'a', b'w', b'i', b'n', b'g', 0x05, 0x01, 0x00, 0x00, 0x00, 0x13, b'S', b'y',
        b's', b't', b'e', b'm', b'.', b'D', b'r', b'a', b'w', b'i', b'n', b'g', b'.', b'S', b'i',
        b'z', b'e', 0x02, 0x00, 0x00, 0x00, 0x05, b'w', b'i', b'd', b't', b'h', 0x06, b'h', b'e',
        b'i', b'g', b'h', b't', 0x00, 0x00, 0x08, 0x08, 0x02, 0x00, 0x00, 0x00, 0x1c, 0x01, 0x00,
        0x00, 0xa1, 0x00, 0x00, 0x00, 0x0b,
    ];

    /// **A serialized value reads as its class and its members.** `resgen`'s
    /// stream for a `Size` names its class, its two `Int32` members and their
    /// values.
    #[test]
    fn a_serialized_value_reads_as_its_class_and_members() {
        let object = read_object(SIZE).expect("the stream reads");
        assert_eq!(object.class_name, "System.Drawing.Size");
        assert_eq!(
            object.members,
            [
                ("width".to_owned(), NrbfValue::Int32(284)),
                ("height".to_owned(), NrbfValue::Int32(161)),
            ]
        );
        assert_eq!(
            object.member("height").and_then(NrbfValue::as_i64),
            Some(161)
        );
    }

    /// **A stream cut short, or claiming more members than its bytes hold, is
    /// refused.** Every prefix of the stream before its last value fails to
    /// read, and a member count past the data is refused before anything is
    /// allocated for it.
    #[test]
    fn a_short_or_overclaiming_stream_is_refused() {
        for end in 0..SIZE.len() - 1 {
            assert!(
                read_object(&SIZE[..end]).is_err(),
                "a prefix of {end} bytes"
            );
        }
        let mut overclaiming = SIZE.to_vec();
        // The member count, after the class name.
        let at = 62;
        assert_eq!(overclaiming[at..at + 4], [0x02, 0x00, 0x00, 0x00]);
        overclaiming[at..at + 4].copy_from_slice(&0x7fff_ffff_i32.to_le_bytes());
        assert!(read_object(&overclaiming).is_err());
    }
}
