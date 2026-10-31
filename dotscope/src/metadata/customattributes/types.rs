//! Custom attribute types and data structures for .NET metadata parsing.
//!
//! This module provides the complete type system for representing parsed custom attribute data
//! according to ECMA-335 II.23.3 specification. It includes argument values, named arguments,
//! and serialization type constants used throughout the custom attribute parsing pipeline.
//!
//! # Architecture
//!
//! The module implements a hierarchical type system that mirrors the .NET custom attribute
//! specification, providing complete coverage of all supported argument types and structures.
//!
//! ## Core Data Structures
//!
//! - **Value Container**: [`crate::metadata::customattributes::types::CustomAttributeValue`] - Complete attribute representation
//! - **Argument Types**: [`crate::metadata::customattributes::types::CustomAttributeArgument`] - Type-safe value storage
//! - **Named Arguments**: [`crate::metadata::customattributes::types::CustomAttributeNamedArgument`] - Field/property assignments
//! - **Type Constants**: [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] - Binary format constants
//!
//! ## Memory Management
//!
//! Uses efficient reference counting and concurrent collections:
//! - [`crate::metadata::customattributes::types::CustomAttributeValueRc`] - Shared ownership
//! - [`crate::metadata::customattributes::types::CustomAttributeValueList`] - Thread-safe collections
//!
//! # Key Components
//!
//! ## Type Hierarchy Overview
//!
//! ```text
//! CustomAttributeValue
//! ├── fixed_args: Vec<CustomAttributeArgument>
//! └── named_args: Vec<CustomAttributeNamedArgument>
//!     ├── name: String
//!     ├── arg_type: String  
//!     └── value: CustomAttributeArgument
//! ```
//!
//! ## Supported Argument Types
//!
//! - **Primitive Types**: All .NET primitive types (bool, integers, floats, char)
//! - **Reference Types**: String, Type references, multi-dimensional arrays
//! - **Complex Types**: Enum values with type names and underlying values
//! - **Platform Types**: Native integers with platform-dependent sizing
//!
//! # Usage Examples
//!
//! ## Creating Custom Attribute Values
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::{
//!     CustomAttributeValue, CustomAttributeArgument, CustomAttributeNamedArgument
//! };
//! use dotscope::metadata::typesystem::CilTypeReference;
//!
//! // Example: Create a custom attribute value programmatically
//! let custom_attr = CustomAttributeValue {
//!     fixed_args: vec![
//!         CustomAttributeArgument::String("Hello".to_string()),
//!         CustomAttributeArgument::I4(42),
//!     ],
//!     named_args: vec![
//!         CustomAttributeNamedArgument {
//!             is_field: false,  // property
//!             name: "Name".to_string(),
//!             arg_type: "String".to_string(),
//!             value: CustomAttributeArgument::String("Value".to_string()),
//!         }
//!     ],
//!     constructor: CilTypeReference::None,
//!     blob_index: 0,
//! };
//!
//! println!("Custom attribute has {} fixed args", custom_attr.fixed_args.len());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Working with Different Argument Types
//!
//! ```rust,no_run
//! use dotscope::metadata::customattributes::CustomAttributeArgument;
//!
//! // Different argument types
//! let bool_arg = CustomAttributeArgument::Bool(true);
//! let string_arg = CustomAttributeArgument::String("Hello".to_string());
//! let int_arg = CustomAttributeArgument::I4(42);
//! let array_arg = CustomAttributeArgument::Array(vec![
//!     CustomAttributeArgument::I4(1),
//!     CustomAttributeArgument::I4(2),
//! ]);
//!
//! // Enum with underlying value
//! let enum_arg = CustomAttributeArgument::Enum(
//!     "System.AttributeTargets".to_string(),
//!     Box::new(CustomAttributeArgument::I4(1)),
//! );
//!
//! // Pattern matching on argument types
//! match &string_arg {
//!     CustomAttributeArgument::String(s) => println!("String value: {}", s),
//!     CustomAttributeArgument::I4(i) => println!("Integer value: {}", i),
//!     _ => println!("Other argument type"),
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! All types in this module are thread-safe and implement [`std::marker::Send`] and [`std::marker::Sync`].
//! The custom attribute value types contain only owned data, and the reference-counted types
//! ([`crate::metadata::customattributes::types::CustomAttributeValueRc`] and
//! [`crate::metadata::customattributes::types::CustomAttributeValueList`]) provide safe concurrent access.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::customattributes::parser`] - Parsing implementation using these types
//! - [`crate::metadata::typesystem`] - Type system integration for `CilFlavor` mapping
//! - [`crate::metadata::tables`] - Metadata table storage and retrieval
//! - [`crate::metadata::streams`] - Blob and string heap access
//!
//! # Binary Format Compatibility
//!
//! The types directly correspond to the .NET runtime's internal representation:
//! - **Fixed arguments** parsed using constructor parameter types
//! - **Named arguments** parsed using embedded [`crate::metadata::customattributes::types::SERIALIZATION_TYPE`] tags
//! - **Values** stored in little-endian binary format as per ECMA-335
//!
//! # Standards Compliance
//!
//! - **ECMA-335**: Full compliance with custom attribute specification (II.23.3)
//! - **Type Safety**: Strongly typed argument values prevent runtime errors
//! - **Memory Efficiency**: Reference counting and concurrent collections minimize overhead
//! - **.NET Compatibility**: Direct mapping to runtime `CorSerializationType` enumeration

use std::{fmt, sync::Arc};

use crate::{metadata::typesystem::CilTypeReference, utils::RowList};

/// A reference-counted pointer to a [`CustomAttributeValue`] for efficient sharing.
///
/// Enables safe sharing of custom attribute data across multiple metadata consumers
/// without copying or blocking. Used throughout the metadata subsystem for
/// attaching custom attributes to types, methods, fields, and other metadata elements.
pub type CustomAttributeValueRc = Arc<CustomAttributeValue>;

/// A concurrent vector storing multiple [`CustomAttributeValueRc`] instances.
///
/// Provides thread-safe storage for custom attribute collections on metadata objects.
/// Uses [`boxcar::Vec`] for lock-free concurrent access and [`Arc`] for reference counting,
/// enabling efficient metadata processing in multi-threaded scenarios.
pub type CustomAttributeValueList = RowList<CustomAttributeValueRc>;

/// Represents a complete parsed custom attribute with fixed and named arguments.
///
/// This is the top-level structure for custom attribute data parsed from .NET metadata.
/// It contains both constructor arguments (`fixed_args`) and field/property assignments
/// (`named_args`) as specified in ECMA-335 II.23.3.
///
/// # Structure
/// - **Fixed Arguments**: Parsed using constructor method parameter types, appear in declaration order
/// - **Named Arguments**: Field/property assignments with embedded type information
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{CustomAttributeValue, CustomAttributeArgument};
/// use dotscope::metadata::typesystem::CilTypeReference;
///
/// let custom_attr = CustomAttributeValue {
///     fixed_args: vec![
///         CustomAttributeArgument::String("Debug".to_string()),
///         CustomAttributeArgument::Bool(true),
///     ],
///     named_args: vec![], // No named arguments in this example
///     constructor: CilTypeReference::None,
///     blob_index: 0,
/// };
///
/// // Access constructor arguments
/// if let CustomAttributeArgument::String(name) = &custom_attr.fixed_args[0] {
///     println!("Attribute name: {}", name);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeValue`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
/// Instances can be safely shared across threads and accessed concurrently.
#[derive(Debug, Clone)]
pub struct CustomAttributeValue {
    /// Fixed arguments from the constructor signature, parsed using parameter type information
    pub fixed_args: Vec<CustomAttributeArgument>,
    /// Named arguments (fields and properties) with embedded type tags
    pub named_args: Vec<CustomAttributeNamedArgument>,
    /// Resolved constructor method reference (MethodDef or MemberRef)
    pub constructor: CilTypeReference,
    /// Blob heap index for on-demand raw byte access during formatting
    pub blob_index: usize,
}

/// The type of a custom attribute argument, as the blob names it: ECMA-335 II.23.3's
/// `FieldOrPropType`, which a named argument and a boxed value carry before their value.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::FieldOrPropType;
///
/// // `int[]`, and an enum named by its type
/// let numbers = FieldOrPropType::SzArray(Box::new(FieldOrPropType::I4));
/// let targets = FieldOrPropType::Enum("System.AttributeTargets".to_string());
/// # let _ = (numbers, targets);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldOrPropType {
    /// `bool`
    Bool,
    /// `char`
    Char,
    /// `sbyte`
    I1,
    /// `byte`
    U1,
    /// `short`
    I2,
    /// `ushort`
    U2,
    /// `int`
    I4,
    /// `uint`
    U4,
    /// `long`
    I8,
    /// `ulong`
    U8,
    /// `float`
    R4,
    /// `double`
    R8,
    /// `string`
    String,
    /// `System.Type`, stored as a type name
    Type,
    /// `object`: the value names its own type before it ([`CustomAttributeArgument::Boxed`])
    Boxed,
    /// An enum, by its type name; its value has the size of the enum's underlying type
    Enum(String),
    /// A single-dimensional array of the element type
    SzArray(Box<FieldOrPropType>),
}

impl fmt::Display for FieldOrPropType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldOrPropType::Bool => write!(f, "bool"),
            FieldOrPropType::Char => write!(f, "char"),
            FieldOrPropType::I1 => write!(f, "int8"),
            FieldOrPropType::U1 => write!(f, "uint8"),
            FieldOrPropType::I2 => write!(f, "int16"),
            FieldOrPropType::U2 => write!(f, "uint16"),
            FieldOrPropType::I4 => write!(f, "int32"),
            FieldOrPropType::U4 => write!(f, "uint32"),
            FieldOrPropType::I8 => write!(f, "int64"),
            FieldOrPropType::U8 => write!(f, "uint64"),
            FieldOrPropType::R4 => write!(f, "float32"),
            FieldOrPropType::R8 => write!(f, "float64"),
            FieldOrPropType::String => write!(f, "string"),
            FieldOrPropType::Type => write!(f, "type"),
            FieldOrPropType::Boxed => write!(f, "object"),
            FieldOrPropType::Enum(name) => write!(f, "enum {name}"),
            FieldOrPropType::SzArray(element) => write!(f, "{element}[]"),
        }
    }
}

/// A custom attribute argument's value, as ECMA-335 II.23.3 encodes one.
///
/// A fixed argument's type is its constructor parameter's, a named argument's is its
/// [`CustomAttributeNamedArgument::arg_type`]; the value says the rest: whether a string, a
/// type or an array is null, an array's element type, and for a boxed (`object`) value the
/// type it holds.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{CustomAttributeArgument, FieldOrPropType};
///
/// let text = CustomAttributeArgument::String(Some("Hello".to_string()));
/// let nothing = CustomAttributeArgument::String(None);
/// let numbers = CustomAttributeArgument::Array(
///     FieldOrPropType::I4,
///     Some(vec![CustomAttributeArgument::I4(1), CustomAttributeArgument::I4(2)]),
/// );
/// let target = CustomAttributeArgument::Enum(
///     "System.AttributeTargets".to_string(),
///     Box::new(CustomAttributeArgument::I4(1)),
/// );
/// let boxed = CustomAttributeArgument::Boxed(Box::new(CustomAttributeArgument::I4(7)));
/// # let _ = (text, nothing, numbers, target, boxed);
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeArgument`] is [`std::marker::Send`] and [`std::marker::Sync`] as all variants contain only owned data.
#[derive(Debug, Clone, PartialEq)]
pub enum CustomAttributeArgument {
    /// Boolean value
    Bool(bool),
    /// A UTF-16 code unit, as stored: an unpaired surrogate too
    Char(u16),
    /// Signed 8-bit integer
    I1(i8),
    /// Unsigned 8-bit integer
    U1(u8),
    /// Signed 16-bit integer
    I2(i16),
    /// Unsigned 16-bit integer
    U2(u16),
    /// Signed 32-bit integer
    I4(i32),
    /// Unsigned 32-bit integer
    U4(u32),
    /// Signed 64-bit integer
    I8(i64),
    /// Unsigned 64-bit integer
    U8(u64),
    /// 32-bit floating point
    R4(f32),
    /// 64-bit floating point
    R8(f64),
    /// A string; `None` is the null string
    String(Option<String>),
    /// A `System.Type`, by its type name; `None` is a null type
    Type(Option<String>),
    /// A single-dimensional array of the element type; `None` is the null array
    Array(FieldOrPropType, Option<Vec<CustomAttributeArgument>>),
    /// An enum value: the enum's type name and its value in the enum's underlying type
    Enum(String, Box<CustomAttributeArgument>),
    /// An `object` argument: the value it holds, whose type the blob names before it
    Boxed(Box<CustomAttributeArgument>),
}

impl CustomAttributeArgument {
    /// The type the blob names before this value when it is boxed or a named argument:
    /// `None` for a boxed value, which cannot itself be boxed.
    #[must_use]
    pub fn field_or_prop_type(&self) -> Option<FieldOrPropType> {
        Some(match self {
            CustomAttributeArgument::Bool(_) => FieldOrPropType::Bool,
            CustomAttributeArgument::Char(_) => FieldOrPropType::Char,
            CustomAttributeArgument::I1(_) => FieldOrPropType::I1,
            CustomAttributeArgument::U1(_) => FieldOrPropType::U1,
            CustomAttributeArgument::I2(_) => FieldOrPropType::I2,
            CustomAttributeArgument::U2(_) => FieldOrPropType::U2,
            CustomAttributeArgument::I4(_) => FieldOrPropType::I4,
            CustomAttributeArgument::U4(_) => FieldOrPropType::U4,
            CustomAttributeArgument::I8(_) => FieldOrPropType::I8,
            CustomAttributeArgument::U8(_) => FieldOrPropType::U8,
            CustomAttributeArgument::R4(_) => FieldOrPropType::R4,
            CustomAttributeArgument::R8(_) => FieldOrPropType::R8,
            CustomAttributeArgument::String(_) => FieldOrPropType::String,
            CustomAttributeArgument::Type(_) => FieldOrPropType::Type,
            CustomAttributeArgument::Array(element, _) => {
                FieldOrPropType::SzArray(Box::new(element.clone()))
            }
            CustomAttributeArgument::Enum(name, _) => FieldOrPropType::Enum(name.clone()),
            CustomAttributeArgument::Boxed(_) => return None,
        })
    }
}

impl fmt::Display for CustomAttributeArgument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CustomAttributeArgument::Bool(v) => write!(f, "bool({v})"),
            CustomAttributeArgument::Char(v) => write!(f, "char(0x{v:04X})"),
            CustomAttributeArgument::I1(v) => write!(f, "int8({v})"),
            CustomAttributeArgument::U1(v) => write!(f, "uint8({v})"),
            CustomAttributeArgument::I2(v) => write!(f, "int16({v})"),
            CustomAttributeArgument::U2(v) => write!(f, "uint16({v})"),
            CustomAttributeArgument::I4(v) => write!(f, "int32({v})"),
            CustomAttributeArgument::U4(v) => write!(f, "uint32({v})"),
            CustomAttributeArgument::I8(v) => write!(f, "int64({v})"),
            CustomAttributeArgument::U8(v) => write!(f, "uint64({v})"),
            CustomAttributeArgument::R4(v) => write!(f, "float32({v})"),
            CustomAttributeArgument::R8(v) => write!(f, "float64({v})"),
            CustomAttributeArgument::String(Some(s)) => write!(f, "\"{s}\""),
            CustomAttributeArgument::String(None) => write!(f, "null"),
            CustomAttributeArgument::Type(Some(s)) => write!(f, "type({s})"),
            CustomAttributeArgument::Type(None) => write!(f, "type(null)"),
            CustomAttributeArgument::Array(_, None) => write!(f, "null"),
            CustomAttributeArgument::Array(_, Some(items)) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            CustomAttributeArgument::Enum(name, val) => write!(f, "enum {name}({val})"),
            CustomAttributeArgument::Boxed(value) => write!(f, "object({value})"),
        }
    }
}

/// A named argument (a field or property set) of a custom attribute: ECMA-335 II.23.3's
/// `NamedArg`, its type as the blob names it, then its value.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::{
///     CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType,
/// };
///
/// let named_arg = CustomAttributeNamedArgument {
///     is_field: false,
///     name: "Name".to_string(),
///     arg_type: FieldOrPropType::String,
///     value: CustomAttributeArgument::String(Some("MyName".to_string())),
/// };
/// # let _ = named_arg;
/// ```
///
/// # Thread Safety
///
/// [`CustomAttributeNamedArgument`] is [`std::marker::Send`] and [`std::marker::Sync`] as it contains only owned data.
#[derive(Debug, Clone, PartialEq)]
pub struct CustomAttributeNamedArgument {
    /// Whether this is a field (true) or property (false)
    pub is_field: bool,
    /// Name of the field or property
    pub name: String,
    /// The type the blob names for it
    pub arg_type: FieldOrPropType,
    /// Value of the argument
    pub value: CustomAttributeArgument,
}

/// .NET `CorSerializationType` enumeration constants from the runtime.
///
/// These constants define the binary format for custom attribute argument types
/// as specified in ECMA-335 and implemented in the .NET runtime. They are used
/// in named argument type tags to enable self-describing argument parsing.
///
/// # Usage
///
/// Used by the custom attribute parser to parse named arguments that contain
/// explicit type information in their binary representation.
///
/// # References
///
/// - ECMA-335 II.23.3 `CustomAttribute` specification
/// - .NET Runtime corhdr.h `CorSerializationType` enumeration
/// - CLI Standard Partition II Metadata definition
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::SERIALIZATION_TYPE;
///
/// // Check type tags during parsing
/// let type_tag = SERIALIZATION_TYPE::STRING;
/// match type_tag {
///     SERIALIZATION_TYPE::STRING => println!("String type"),
///     SERIALIZATION_TYPE::I4 => println!("I4 type"),
///     SERIALIZATION_TYPE::ENUM => println!("Enum type"),
///     _ => println!("Other type"),
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[allow(non_snake_case)]
pub mod SERIALIZATION_TYPE {
    /// Boolean type (System.Boolean) - stored as single byte (0 = false, non-zero = true)
    pub const BOOLEAN: u8 = 0x02;
    /// Character type (System.Char) - stored as 16-bit Unicode value
    pub const CHAR: u8 = 0x03;
    /// Signed 8-bit integer (System.SByte)
    pub const I1: u8 = 0x04;
    /// Unsigned 8-bit integer (System.Byte)
    pub const U1: u8 = 0x05;
    /// Signed 16-bit integer (System.Int16)
    pub const I2: u8 = 0x06;
    /// Unsigned 16-bit integer (System.UInt16)
    pub const U2: u8 = 0x07;
    /// Signed 32-bit integer (System.Int32)
    pub const I4: u8 = 0x08;
    /// Unsigned 32-bit integer (System.UInt32)
    pub const U4: u8 = 0x09;
    /// Signed 64-bit integer (System.Int64)
    pub const I8: u8 = 0x0A;
    /// Unsigned 64-bit integer (System.UInt64)
    pub const U8: u8 = 0x0B;
    /// 32-bit floating point (System.Single)
    pub const R4: u8 = 0x0C;
    /// 64-bit floating point (System.Double)
    pub const R8: u8 = 0x0D;
    /// String type (System.String) - compressed length + UTF-8 data
    pub const STRING: u8 = 0x0E;
    /// Type reference (System.Type) - stored as string containing type name
    pub const TYPE: u8 = 0x50;
    /// Tagged object - followed by another type tag for the actual value
    pub const TAGGED_OBJECT: u8 = 0x51;
    /// Enum type - type name string followed by underlying value (usually I4)
    pub const ENUM: u8 = 0x55;
    /// Single-dimensional array - element type tag + length + elements
    pub const SZARRAY: u8 = 0x1D;
}

/// Constants for named argument field/property indicators per ECMA-335 §II.23.3.
///
/// These bytes appear at the start of each named argument to indicate whether
/// the target is a field or a property.
///
/// # Usage
///
/// ```rust,no_run
/// use dotscope::metadata::customattributes::NAMED_ARG_TYPE;
///
/// let indicator = 0x53;
/// match indicator {
///     NAMED_ARG_TYPE::FIELD => println!("This is a field"),
///     NAMED_ARG_TYPE::PROPERTY => println!("This is a property"),
///     _ => println!("Unknown indicator"),
/// }
/// ```
#[allow(non_snake_case)]
pub mod NAMED_ARG_TYPE {
    /// Field indicator - named argument targets a public field
    pub const FIELD: u8 = 0x53;
    /// Property indicator - named argument targets a public property
    pub const PROPERTY: u8 = 0x54;
}
