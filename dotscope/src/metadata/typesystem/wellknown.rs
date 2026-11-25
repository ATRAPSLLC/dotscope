//! Well-known .NET type names, member names, and primitive mappings.
//!
//! Centralizes the string constants and mappings that are repeated across the codebase.
//! Using these constants instead of raw string literals enables compile-time typo detection
//! and makes refactoring easier.

use crate::metadata::{token::Token, typesystem::CilPrimitiveKind};

/// Well-known fully qualified type names from the .NET base class library.
pub mod names {
    /// `System.Object` - root of the .NET type hierarchy.
    pub const OBJECT: &str = "System.Object";
    /// `System.ValueType` - base class for all value types.
    pub const VALUE_TYPE: &str = "System.ValueType";
    /// `System.Enum` - base class for all enumerations.
    pub const ENUM: &str = "System.Enum";
    /// `System.Delegate` - base class for delegates.
    pub const DELEGATE: &str = "System.Delegate";
    /// `System.MulticastDelegate` - base class for multicast delegates.
    pub const MULTICAST_DELEGATE: &str = "System.MulticastDelegate";
    /// `System.String` - the .NET string type.
    pub const STRING: &str = "System.String";
    /// `System.Void` - represents the void return type.
    pub const VOID: &str = "System.Void";
    /// `System.Exception` - base class for all exceptions.
    pub const EXCEPTION: &str = "System.Exception";
    /// `System.Type` - runtime type representation.
    pub const TYPE: &str = "System.Type";
    /// `System.Array` - base class for all array types.
    pub const ARRAY: &str = "System.Array";
    /// `System.Attribute` - base class for custom attributes.
    pub const ATTRIBUTE: &str = "System.Attribute";
}

/// Well-known member names in the .NET type system.
pub mod members {
    /// `.cctor` - static class constructor (type initializer).
    pub const CCTOR: &str = ".cctor";
    /// `.ctor` - instance constructor.
    pub const CTOR: &str = ".ctor";
    /// `<Module>` - the global module type that holds module-level methods and fields.
    pub const MODULE_TYPE: &str = "<Module>";
    /// `<PrivateImplementationDetails>` - compiler-generated type for array initializers etc.
    pub const PRIVATE_IMPL: &str = "<PrivateImplementationDetails>";
}

/// Maps a [`CilPrimitiveKind`] synthetic token (`0xF000_xxxx`) to a .NET `TypeCode` integer.
///
/// Extracts the [`CilPrimitiveKind`] from the token's encoded element type byte
/// and delegates to [`CilPrimitiveKind::typecode`]. Non-primitive tokens return `None`.
#[must_use]
pub fn primitive_token_to_typecode(token: Token) -> Option<i32> {
    // Synthetic primitive tokens use format 0xF000_00xx where xx is the ELEMENT_TYPE byte
    if token.value() & 0xFFFF_FF00 != 0xF000_0000 {
        return None;
    }
    let element_byte = (token.value() & 0xFF) as u8;
    CilPrimitiveKind::from_byte(element_byte).ok()?.typecode()
}

/// Maps a type fullname to a .NET `TypeCode` integer.
///
/// Returns the `System.TypeCode` enum value matching the given fully qualified
/// type name. Unknown types return `TypeCode.Object` (1).
#[must_use]
pub fn fullname_to_typecode(fullname: &str) -> i32 {
    match fullname {
        "System.Boolean" => 3,
        "System.Char" => 4,
        "System.SByte" => 5,
        "System.Byte" => 6,
        "System.Int16" => 7,
        "System.UInt16" => 8,
        "System.Int32" => 9,
        "System.UInt32" => 10,
        "System.Int64" => 11,
        "System.UInt64" => 12,
        "System.Single" => 13,
        "System.Double" => 14,
        "System.DateTime" => 16,
        "System.String" => 18,
        _ => 1, // TypeCode.Object
    }
}

/// Checks whether a fullname corresponds to a well-known .NET value type.
///
/// Covers all primitive value types, `System.Decimal`, `System.DateTime`,
/// `System.Guid`, `System.TimeSpan`, `System.DateTimeOffset`, and
/// `System.IntPtr`/`System.UIntPtr`. Useful as a fallback when the base
/// chain walk and flavor check both fail (common for TypeRef entries of
/// external BCL types).
#[must_use]
pub fn is_known_value_type(fullname: &str) -> bool {
    matches!(
        fullname,
        "System.Boolean"
            | "System.Char"
            | "System.SByte"
            | "System.Byte"
            | "System.Int16"
            | "System.UInt16"
            | "System.Int32"
            | "System.UInt32"
            | "System.Int64"
            | "System.UInt64"
            | "System.Single"
            | "System.Double"
            | "System.IntPtr"
            | "System.UIntPtr"
            | "System.Decimal"
            | "System.DateTime"
            | "System.DateTimeOffset"
            | "System.TimeSpan"
            | "System.Guid"
            | "System.TypedReference"
    )
}

/// Maps a System namespace short name (e.g. `"Int32"`) to its [`CilPrimitiveKind`].
///
/// This covers all ECMA-335 primitive types. Returns `None` for non-primitive
/// System types like `Exception`, `Type`, etc.
#[must_use]
pub fn system_name_to_primitive(name: &str) -> Option<CilPrimitiveKind> {
    match name {
        "Void" => Some(CilPrimitiveKind::Void),
        "Boolean" => Some(CilPrimitiveKind::Boolean),
        "Char" => Some(CilPrimitiveKind::Char),
        "SByte" => Some(CilPrimitiveKind::I1),
        "Byte" => Some(CilPrimitiveKind::U1),
        "Int16" => Some(CilPrimitiveKind::I2),
        "UInt16" => Some(CilPrimitiveKind::U2),
        "Int32" => Some(CilPrimitiveKind::I4),
        "UInt32" => Some(CilPrimitiveKind::U4),
        "Int64" => Some(CilPrimitiveKind::I8),
        "UInt64" => Some(CilPrimitiveKind::U8),
        "Single" => Some(CilPrimitiveKind::R4),
        "Double" => Some(CilPrimitiveKind::R8),
        "IntPtr" => Some(CilPrimitiveKind::I),
        "UIntPtr" => Some(CilPrimitiveKind::U),
        "String" => Some(CilPrimitiveKind::String),
        "Object" => Some(CilPrimitiveKind::Object),
        _ => None,
    }
}
