//! Core runtime value representation for CIL emulation.

use std::fmt;

use crate::{
    analysis::{ConstValue, FloatFormat},
    emulation::{value::symbolic::SymbolicValue, EmulationError},
    metadata::{
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    utils::LeBytes,
};

/// Runtime value during CIL emulation.
///
/// `EmValue` represents all possible values that can exist on the CIL evaluation
/// stack or in local variables during emulation. It covers the full range of
/// .NET value types, reference types, and special emulation-specific values.
///
/// # CIL Type Mapping
///
/// | CIL Type | EmValue Variant |
/// |----------|-----------------|
/// | `int8`, `int16`, `int32` | [`EmValue::I32`] |
/// | `uint8`, `uint16`, `uint32` | [`EmValue::I32`] (bit pattern preserved) |
/// | `int64` | [`EmValue::I64`] |
/// | `uint64` | [`EmValue::I64`] (bit pattern preserved) |
/// | `float32` | [`EmValue::F32`] |
/// | `float64` | [`EmValue::F64`] |
/// | `native int` | [`EmValue::NativeInt`] |
/// | `native uint` | [`EmValue::NativeUInt`] |
/// | `bool` | [`EmValue::Bool`] |
/// | `char` | [`EmValue::Char`] |
/// | Object reference | [`EmValue::ObjectRef`] |
/// | `null` | [`EmValue::Null`] |
/// | Managed pointer | [`EmValue::ManagedPtr`] |
/// | Unmanaged pointer | [`EmValue::UnmanagedPtr`] |
/// | Value type (struct) | [`EmValue::ValueType`] |
///
/// # Stack Behavior
///
/// When values are pushed onto the CIL evaluation stack, they are widened to
/// one of the stack types defined in ECMA-335. Use [`EmValue::cil_flavor()`]
/// to determine the type flavor of a value.
///
/// # Symbolic Values
///
/// For partial emulation where some values cannot be determined, the
/// [`EmValue::Symbolic`] variant tracks unknown values and their origins.
/// This enables taint tracking and constraint collection for more advanced
/// analysis.
#[derive(Clone, Debug)]
pub enum EmValue {
    /// No value (void return, uninitialized).
    ///
    /// Used for methods that return `void` or for representing the absence
    /// of a value. Should not appear on the evaluation stack.
    Void,

    /// 32-bit signed integer.
    ///
    /// Also used for `int8`, `int16`, `uint8`, `uint16`, `uint32`, and `bool`
    /// when they appear on the stack (they are widened to 32 bits).
    I32(i32),

    /// 64-bit signed integer.
    ///
    /// Also used for `uint64` (bit pattern preserved).
    I64(i64),

    /// 32-bit floating point.
    F32(f32),

    /// 64-bit floating point.
    F64(f64),

    /// Native-sized signed integer.
    ///
    /// Size depends on platform (32 or 64 bits). For emulation purposes,
    /// we use 64 bits to support both platforms.
    NativeInt(i64),

    /// Native-sized unsigned integer.
    ///
    /// Size depends on platform (32 or 64 bits). For emulation purposes,
    /// we use 64 bits to support both platforms.
    NativeUInt(u64),

    /// Boolean value.
    ///
    /// Note: On the CIL stack, booleans are represented as `int32` (0 = false,
    /// non-zero = true). This variant preserves the boolean semantics for
    /// clearer analysis.
    Bool(bool),

    /// Unicode character.
    ///
    /// Note: On the CIL stack, characters are represented as `int32`.
    /// This variant preserves the character semantics.
    Char(char),

    /// Managed reference to heap object.
    ///
    /// Points to an object allocated on the managed heap. The [`HeapRef`]
    /// can reference strings, arrays, or object instances.
    ObjectRef(HeapRef),

    /// Null reference.
    ///
    /// Represents the `null` value for reference types. Distinguished from
    /// [`EmValue::Void`] which represents the absence of any value.
    Null,

    /// Managed pointer (ref/out parameter, address of local).
    ///
    /// Used for `ldloca`, `ldarga`, `ldelema`, `ldflda` operations.
    /// Points to a storage location that can be read from or written to.
    ManagedPtr(ManagedPointer),

    /// Unmanaged pointer.
    ///
    /// Used for P/Invoke and unsafe code. The value is the raw memory address.
    UnmanagedPtr(u64),

    /// Value type (struct) stored inline.
    ///
    /// Contains the type token and field values. Unlike reference types,
    /// value types are copied by value and stored inline.
    ValueType {
        /// Metadata token identifying the value type.
        type_token: Token,
        /// Field values in declaration order.
        fields: Vec<EmValue>,
    },

    /// Typed reference (TypedReference).
    ///
    /// A typed reference contains both a managed pointer and the type
    /// of the referenced value. Used with `mkrefany` and `refanyval`.
    TypedRef {
        /// The managed pointer component.
        ptr: Box<ManagedPointer>,
        /// Token of the referenced type.
        type_token: Token,
    },

    /// Unknown/symbolic value for partial emulation.
    ///
    /// When a value cannot be determined during emulation (e.g., method
    /// parameter, return value from unstubbed method), it is represented
    /// as symbolic. This enables:
    ///
    /// - Taint tracking to identify value origins
    /// - Constraint collection for symbolic execution
    /// - Partial emulation that doesn't fail on unknown values
    Symbolic(SymbolicValue),
}

/// `EmValue` is the unit of currency in the interpreter: every `push`/`pop`, every local slot,
/// argument slot, array element and inline field is one of these, and `EvaluationStack::new`
/// preallocates up to 256 per thread. Its width is therefore a whole-interpreter cost, and it
/// is set by whichever variant is widest — `Symbolic`, through the `CilFlavor` it carries.
/// `CilFlavor::FnPtr` boxes its `SignatureMethod` for exactly this reason: embedding one by
/// value costs every `EmValue` in the process 96 further bytes.
///
/// The bound below is the measured width, not a round number with slack in it: nothing else in
/// the build would catch a newly added fat variant, and a loose bound would let one land
/// silently.
///
/// If this assertion fails, box the offending variant rather than raising the bound.
const _: () = assert!(std::mem::size_of::<EmValue>() <= 104);

impl EmValue {
    /// Returns the type token for this value, if available.
    ///
    /// For value types and typed references, returns the associated type token.
    /// For object references, the type token must be obtained from the heap.
    /// Returns `None` for primitive types and null.
    #[must_use]
    pub fn type_token(&self) -> Option<Token> {
        match self {
            EmValue::ValueType { type_token, .. } | EmValue::TypedRef { type_token, .. } => {
                Some(*type_token)
            }
            _ => None,
        }
    }

    /// Returns `true` if this value is concrete (fully known).
    ///
    /// A concrete value has a specific, known value at emulation time.
    /// Symbolic values are not concrete.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!(EmValue::I32(42).is_concrete());
    /// assert!(EmValue::Null.is_concrete());
    /// ```
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        !matches!(self, EmValue::Symbolic(_))
    }

    /// Returns `true` if this value is symbolic (unknown/partial).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!(!EmValue::I32(42).is_symbolic());
    /// ```
    #[must_use]
    pub fn is_symbolic(&self) -> bool {
        matches!(self, EmValue::Symbolic(_))
    }

    /// Returns `true` if this value is null.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!(EmValue::Null.is_null());
    /// assert!(!EmValue::I32(0).is_null());
    /// ```
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, EmValue::Null)
    }

    /// Returns `true` if this value is void.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!(EmValue::Void.is_void());
    /// assert!(!EmValue::Null.is_void());
    /// ```
    #[must_use]
    pub fn is_void(&self) -> bool {
        matches!(self, EmValue::Void)
    }

    /// Returns `true` if this value is a reference type (object reference or null).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, HeapRef};
    ///
    /// assert!(EmValue::Null.is_reference());
    /// assert!(EmValue::ObjectRef(HeapRef::new(1)).is_reference());
    /// assert!(!EmValue::I32(42).is_reference());
    /// ```
    #[must_use]
    pub fn is_reference(&self) -> bool {
        matches!(self, EmValue::ObjectRef(_) | EmValue::Null)
    }

    /// Attempts to extract an `i32` value.
    ///
    /// Returns `Some(i32)` if this value can be interpreted as a 32-bit
    /// signed integer, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(42).as_i32(), Some(42));
    /// assert_eq!(EmValue::Bool(true).as_i32(), Some(1));
    /// assert_eq!(EmValue::Bool(false).as_i32(), Some(0));
    /// assert_eq!(EmValue::Char('A').as_i32(), Some(65));
    /// assert_eq!(EmValue::I64(100).as_i32(), None);
    /// ```
    #[must_use]
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            EmValue::I32(v) => Some(*v),
            EmValue::Bool(v) => Some(i32::from(*v)),
            EmValue::Char(v) => Some(*v as i32),
            _ => None,
        }
    }

    /// Attempts to extract an `i64` value.
    ///
    /// Returns `Some(i64)` if this value can be interpreted as a 64-bit
    /// signed integer, `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I64(42).as_i64(), Some(42));
    /// assert_eq!(EmValue::I32(42).as_i64(), None); // Use convert for widening
    /// ```
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            EmValue::I64(v) | EmValue::NativeInt(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract an `f32` value.
    ///
    /// Returns `Some(f32)` only if this value is [`EmValue::F32`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::F32(3.14).as_f32(), Some(3.14));
    /// assert_eq!(EmValue::F64(3.14).as_f32(), None);
    /// ```
    #[must_use]
    pub fn as_f32(&self) -> Option<f32> {
        match self {
            EmValue::F32(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract an `f64` value.
    ///
    /// Returns `Some(f64)` if this value is [`EmValue::F64`] or [`EmValue::F32`]
    /// (with automatic widening conversion).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::F64(3.14).as_f64(), Some(3.14));
    /// // F32 is automatically widened to F64
    /// assert!(EmValue::F32(3.14).as_f64().is_some());
    /// assert_eq!(EmValue::I32(42).as_f64(), None);
    /// ```
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            EmValue::F64(v) => Some(*v),
            EmValue::F32(v) => Some(f64::from(*v)),
            _ => None,
        }
    }

    /// Attempts to extract a `bool` value.
    ///
    /// Returns `Some(bool)` if this value can be interpreted as a boolean.
    /// For `I32`, any non-zero value is considered `true`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::Bool(true).as_bool(), Some(true));
    /// assert_eq!(EmValue::I32(1).as_bool(), Some(true));
    /// assert_eq!(EmValue::I32(0).as_bool(), Some(false));
    /// assert_eq!(EmValue::I32(-1).as_bool(), Some(true));
    /// ```
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            EmValue::Bool(v) => Some(*v),
            EmValue::I32(v) => Some(*v != 0),
            _ => None,
        }
    }

    /// Attempts to extract a `char` value.
    ///
    /// Returns `Some(char)` if this value is [`EmValue::Char`] or an [`EmValue::I32`]
    /// containing a valid Unicode code point.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::Char('A').as_char(), Some('A'));
    /// assert_eq!(EmValue::I32(65).as_char(), Some('A'));
    /// // Invalid Unicode code point returns None
    /// assert_eq!(EmValue::I32(-1).as_char(), None);
    /// ```
    #[must_use]
    #[allow(clippy::cast_sign_loss)] // Intentional: i32 bit pattern reinterprets as Unicode code point
    pub fn as_char(&self) -> Option<char> {
        match self {
            EmValue::Char(v) => Some(*v),
            EmValue::I32(v) => {
                let code = *v as u32;
                char::from_u32(code)
            }
            _ => None,
        }
    }

    /// Attempts to extract a heap reference.
    ///
    /// Returns `Some(HeapRef)` if this value is an [`EmValue::ObjectRef`].
    /// Returns `None` for [`EmValue::Null`] and all other variants.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, HeapRef};
    ///
    /// let heap_ref = HeapRef::new(42);
    /// assert_eq!(EmValue::ObjectRef(heap_ref).as_object_ref(), Some(heap_ref));
    /// assert_eq!(EmValue::Null.as_object_ref(), None);
    /// ```
    #[must_use]
    pub fn as_object_ref(&self) -> Option<HeapRef> {
        match self {
            EmValue::ObjectRef(r) => Some(*r),
            _ => None,
        }
    }

    /// Attempts to extract a managed pointer.
    ///
    /// Returns a reference to the [`ManagedPointer`] if this value is an
    /// [`EmValue::ManagedPtr`], `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::{EmValue, ManagedPointer};
    ///
    /// let ptr = ManagedPointer::to_local(0, 0);
    /// let value = EmValue::ManagedPtr(ptr.clone());
    /// assert!(value.as_managed_ptr().is_some());
    /// assert_eq!(EmValue::Null.as_managed_ptr(), None);
    /// ```
    #[must_use]
    pub fn as_managed_ptr(&self) -> Option<&ManagedPointer> {
        match self {
            EmValue::ManagedPtr(p) => Some(p),
            _ => None,
        }
    }

    /// Attempts to extract an unmanaged pointer value.
    ///
    /// Returns the raw pointer address if this value is an [`EmValue::UnmanagedPtr`],
    /// `None` otherwise.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::UnmanagedPtr(0x1000).as_unmanaged_ptr(), Some(0x1000));
    /// assert_eq!(EmValue::Null.as_unmanaged_ptr(), None);
    /// ```
    #[must_use]
    pub fn as_unmanaged_ptr(&self) -> Option<u64> {
        match self {
            EmValue::UnmanagedPtr(v) => Some(*v),
            _ => None,
        }
    }

    /// Attempts to extract the native int value.
    ///
    /// Returns the value as `i64` if this is a [`EmValue::NativeInt`] or
    /// [`EmValue::NativeUInt`] (with bit pattern reinterpretation).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::NativeInt(42).as_native_int(), Some(42));
    /// assert_eq!(EmValue::NativeUInt(100).as_native_int(), Some(100));
    /// assert_eq!(EmValue::I32(42).as_native_int(), None);
    /// ```
    #[must_use]
    pub fn as_native_int(&self) -> Option<i64> {
        match self {
            EmValue::NativeInt(v) => Some(*v),
            // Intentional: native uint bit pattern reinterprets as signed
            EmValue::NativeUInt(v) => Some((*v).cast_signed()),
            _ => None,
        }
    }

    /// Converts this value to a [`ConstValue`] if possible.
    ///
    /// This converts primitive emulation values to their constant representation
    /// for use in SSA analysis. Object references and complex types cannot be
    /// converted and return `None`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    /// use dotscope::analysis::ConstValue;
    ///
    /// assert_eq!(EmValue::I32(42).to_const_value(), Some(ConstValue::I32(42)));
    /// assert_eq!(EmValue::F64(3.14).to_const_value(), Some(ConstValue::from(3.14)));
    /// assert_eq!(EmValue::Null.to_const_value(), Some(ConstValue::Null));
    /// assert_eq!(EmValue::Void.to_const_value(), None);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_wrap)] // Intentional: NativeUInt reinterprets as i64
    pub fn to_const_value(&self) -> Option<ConstValue> {
        match self {
            EmValue::I32(v) => Some(ConstValue::I32(*v)),
            EmValue::I64(v) => Some(ConstValue::I64(*v)),
            EmValue::F32(v) => Some(ConstValue::from(*v)),
            EmValue::F64(v) => Some(ConstValue::from(*v)),
            EmValue::Bool(v) => Some(ConstValue::from_bool(*v)),
            EmValue::NativeInt(v) => Some(ConstValue::NativeInt(*v)),
            EmValue::NativeUInt(v) => Some(ConstValue::NativeUInt(*v)),
            EmValue::Null => Some(ConstValue::Null),
            // Object references, value types, pointers, etc. can't be
            // represented as constants without additional context (heap access)
            _ => None,
        }
    }

    /// Returns the default value for a given CIL type flavor.
    ///
    /// Used to initialize local variables and fields with proper type awareness.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    /// use dotscope::metadata::typesystem::CilFlavor;
    ///
    /// assert_eq!(EmValue::default_for_flavor(&CilFlavor::I4), EmValue::I32(0));
    /// assert_eq!(EmValue::default_for_flavor(&CilFlavor::Boolean), EmValue::Bool(false));
    /// assert_eq!(EmValue::default_for_flavor(&CilFlavor::Object), EmValue::Null);
    /// ```
    #[must_use]
    pub fn default_for_flavor(flavor: &CilFlavor) -> Self {
        match flavor {
            // Boolean preserves its type
            CilFlavor::Boolean => EmValue::Bool(false),

            // Char preserves its type
            CilFlavor::Char => EmValue::Char('\0'),

            // Integer types - all represented as I32 on the stack
            CilFlavor::I1
            | CilFlavor::U1
            | CilFlavor::I2
            | CilFlavor::U2
            | CilFlavor::I4
            | CilFlavor::U4 => EmValue::I32(0),

            // 64-bit integers
            CilFlavor::I8 | CilFlavor::U8 => EmValue::I64(0),

            // Floating point
            CilFlavor::R4 => EmValue::F32(0.0),
            CilFlavor::R8 => EmValue::F64(0.0),

            // Native integers
            CilFlavor::I => EmValue::NativeInt(0),
            CilFlavor::U => EmValue::NativeUInt(0),

            // Reference types - all default to null
            // Managed pointer defaults to null
            CilFlavor::Object
            | CilFlavor::String
            | CilFlavor::Class
            | CilFlavor::Interface
            | CilFlavor::Array { .. }
            | CilFlavor::GenericInstance
            | CilFlavor::ByRef => EmValue::Null,

            // Pointers
            CilFlavor::Pointer | CilFlavor::FnPtr { .. } => EmValue::UnmanagedPtr(0),

            // Void
            // Value types need more info for proper initialization
            // Generic parameters - need runtime resolution
            // Pinned is a modifier, shouldn't appear as a standalone type
            // TypedReference is a special struct containing pointer and type info
            // Unknown types
            CilFlavor::Void
            | CilFlavor::ValueType
            | CilFlavor::GenericParameter { .. }
            | CilFlavor::Pinned
            | CilFlavor::TypedRef { .. }
            | CilFlavor::Unknown => EmValue::Void,
        }
    }

    /// Returns the CIL type flavor that best represents this value.
    ///
    /// This provides more precise type information than `stack_type()`.
    /// Note that some precision is lost for values that don't preserve
    /// their original type (e.g., I1/U1/I2/U2 values stored as I32).
    #[must_use]
    pub fn cil_flavor(&self) -> CilFlavor {
        match self {
            EmValue::Void => CilFlavor::Void,
            EmValue::Bool(_) => CilFlavor::Boolean,
            EmValue::Char(_) => CilFlavor::Char,
            EmValue::I32(_) => CilFlavor::I4,
            EmValue::I64(_) => CilFlavor::I8,
            EmValue::F32(_) => CilFlavor::R4,
            EmValue::F64(_) => CilFlavor::R8,
            EmValue::NativeInt(_) => CilFlavor::I,
            EmValue::NativeUInt(_) => CilFlavor::U,
            EmValue::ObjectRef(_) | EmValue::Null => CilFlavor::Object,
            EmValue::ManagedPtr(_) => CilFlavor::ByRef,
            EmValue::UnmanagedPtr(_) => CilFlavor::Pointer,
            // TypedRef is a value type
            EmValue::ValueType { .. } | EmValue::TypedRef { .. } => CilFlavor::ValueType,
            EmValue::Symbolic(s) => s.cil_flavor.clone(),
        }
    }
}

impl PartialEq for EmValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (EmValue::Void, EmValue::Void) | (EmValue::Null, EmValue::Null) => true,
            (EmValue::I32(a), EmValue::I32(b)) => a == b,
            (EmValue::I64(a), EmValue::I64(b)) | (EmValue::NativeInt(a), EmValue::NativeInt(b)) => {
                a == b
            }
            (EmValue::F32(a), EmValue::F32(b)) => a.to_bits() == b.to_bits(),
            (EmValue::F64(a), EmValue::F64(b)) => a.to_bits() == b.to_bits(),
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b))
            | (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => a == b,
            (EmValue::Bool(a), EmValue::Bool(b)) => a == b,
            (EmValue::Char(a), EmValue::Char(b)) => a == b,
            (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => a == b,
            (
                EmValue::ValueType {
                    type_token: t1,
                    fields: f1,
                },
                EmValue::ValueType {
                    type_token: t2,
                    fields: f2,
                },
            ) => t1 == t2 && f1 == f2,
            // Managed pointers compare by target
            (EmValue::ManagedPtr(a), EmValue::ManagedPtr(b)) => a == b,
            // Symbolic values are never equal (each is unique), and mismatched types are not equal
            _ => false,
        }
    }
}

impl fmt::Display for EmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmValue::Void => write!(f, "void"),
            EmValue::I32(v) => write!(f, "{v}"),
            EmValue::I64(v) => write!(f, "{v}L"),
            EmValue::F32(v) => write!(f, "{v}f"),
            EmValue::F64(v) => write!(f, "{v}"),
            EmValue::NativeInt(v) => write!(f, "nint({v})"),
            EmValue::NativeUInt(v) => write!(f, "nuint({v})"),
            EmValue::Bool(v) => write!(f, "{v}"),
            EmValue::Char(v) => write!(f, "'{v}'"),
            EmValue::ObjectRef(r) => write!(f, "ref@{}", r.0),
            EmValue::Null => write!(f, "null"),
            EmValue::ManagedPtr(p) => write!(f, "&{p:?}"),
            EmValue::UnmanagedPtr(v) => write!(f, "ptr(0x{v:016X})"),
            EmValue::ValueType { type_token, .. } => write!(f, "valuetype({type_token})"),
            EmValue::TypedRef { type_token, .. } => write!(f, "typedref({type_token})"),
            EmValue::Symbolic(s) => write!(f, "symbolic({})", s.id),
        }
    }
}

impl From<i32> for EmValue {
    fn from(value: i32) -> Self {
        EmValue::I32(value)
    }
}

impl From<i64> for EmValue {
    fn from(value: i64) -> Self {
        EmValue::I64(value)
    }
}

impl From<f32> for EmValue {
    fn from(value: f32) -> Self {
        EmValue::F32(value)
    }
}

impl From<f64> for EmValue {
    fn from(value: f64) -> Self {
        EmValue::F64(value)
    }
}

impl From<bool> for EmValue {
    fn from(value: bool) -> Self {
        EmValue::Bool(value)
    }
}

impl From<char> for EmValue {
    fn from(value: char) -> Self {
        EmValue::Char(value)
    }
}

impl From<u8> for EmValue {
    fn from(value: u8) -> Self {
        EmValue::I32(i32::from(value))
    }
}

impl From<i8> for EmValue {
    fn from(value: i8) -> Self {
        EmValue::I32(i32::from(value))
    }
}

impl From<u16> for EmValue {
    fn from(value: u16) -> Self {
        EmValue::I32(i32::from(value))
    }
}

impl From<i16> for EmValue {
    fn from(value: i16) -> Self {
        EmValue::I32(i32::from(value))
    }
}

impl From<HeapRef> for EmValue {
    fn from(value: HeapRef) -> Self {
        EmValue::ObjectRef(value)
    }
}

impl From<ManagedPointer> for EmValue {
    fn from(value: ManagedPointer) -> Self {
        EmValue::ManagedPtr(value)
    }
}

impl TryFrom<&ConstValue> for EmValue {
    type Error = EmulationError;

    /// Converts an SSA constant value to the emulation value the evaluation stack holds,
    /// following CIL's widening rules (smaller integers are widened to `int32`). A runtime
    /// handle is its token as a native int, as `ldtoken` pushes it.
    ///
    /// # Errors
    ///
    /// [`EmulationError::ValueConversion`] for a constant that is an object of the heap
    /// (a user string, a decrypted string or array), which only a process can allocate, and
    /// for a SIMD vector or a float format other than binary32 and binary64, which CIL has no
    /// value for.
    #[allow(clippy::cast_possible_wrap)] // U32->I32 and U64->I64 are intentional bit-preserving casts
    fn try_from(value: &ConstValue) -> Result<Self, Self::Error> {
        let refused = |source_type: &'static str| EmulationError::ValueConversion {
            source_type,
            target_type: "an evaluation stack value",
        };
        Ok(match value {
            // Uninhabited for this target: CIL has no symbol space.
            ConstValue::Symbol(symbol) => match *symbol {},
            // Signed integers - promote small types to I32 using infallible From
            ConstValue::I8(v) => EmValue::I32(i32::from(*v)),
            ConstValue::I16(v) => EmValue::I32(i32::from(*v)),
            ConstValue::I32(v) => EmValue::I32(*v),
            ConstValue::I64(v) => EmValue::I64(*v),
            // Unsigned integers - promote small types to I32 using infallible From
            ConstValue::U8(v) => EmValue::I32(i32::from(*v)),
            ConstValue::U16(v) => EmValue::I32(i32::from(*v)),
            // U32->I32 is intentional bit-preserving cast for CIL semantics
            ConstValue::U32(v) => EmValue::I32(*v as i32),
            // U64->I64 is intentional bit-preserving cast for CIL semantics
            ConstValue::U64(v) => EmValue::I64(*v as i64),
            // Native integers - stored as i64/u64 internally in EmValue
            ConstValue::NativeInt(v) => EmValue::NativeInt(*v),
            ConstValue::NativeUInt(v) => EmValue::NativeUInt(*v),
            ConstValue::Null => EmValue::Null,
            ConstValue::True => EmValue::I32(1),
            ConstValue::False => EmValue::I32(0),
            ConstValue::Type(type_ref) => EmValue::NativeInt(i64::from(type_ref.token().value())),
            ConstValue::MethodHandle(method_ref) => {
                EmValue::NativeInt(i64::from(method_ref.token().value()))
            }
            ConstValue::FieldHandle(field_ref) => {
                EmValue::NativeInt(i64::from(field_ref.token().value()))
            }
            ConstValue::String(_) => return Err(refused("a user string")),
            ConstValue::DecryptedString(_) => return Err(refused("a decrypted string")),
            ConstValue::DecryptedArray(_) => return Err(refused("a decrypted array")),
            ConstValue::Vector(_) => return Err(refused("a vector constant")),
            // binary32 and binary64 are CIL's floats; the other formats have no CIL value
            ConstValue::Float(bits) => match bits.format() {
                FloatFormat::Single => f32::try_from(*bits).map(EmValue::F32),
                FloatFormat::Double => f64::try_from(*bits).map(EmValue::F64),
                _ => Err(*bits),
            }
            .map_err(|_| refused("a float format CIL has no value for"))?,
        })
    }
}

impl TryFrom<&EmValue> for i32 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::I32(v) => Ok(*v),
            EmValue::Bool(v) => Ok(i32::from(*v)),
            EmValue::Char(v) => Ok(*v as i32),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "i32",
            }),
        }
    }
}

impl TryFrom<EmValue> for i32 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        i32::try_from(&value)
    }
}

impl TryFrom<&EmValue> for i64 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v),
            EmValue::I32(v) => Ok(i64::from(*v)),
            EmValue::Bool(v) => Ok(i64::from(*v)),
            EmValue::Char(v) => Ok(i64::from(*v as u32)),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "i64",
            }),
        }
    }
}

impl TryFrom<EmValue> for i64 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        i64::try_from(&value)
    }
}

impl TryFrom<&EmValue> for u64 {
    type Error = crate::emulation::EmulationError;

    #[allow(clippy::cast_sign_loss)] // Intentional bit reinterpretation from signed to unsigned
    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::NativeUInt(v) | EmValue::UnmanagedPtr(v) => Ok(*v),
            // Allow conversion from signed types with bit reinterpretation
            EmValue::I64(v) | EmValue::NativeInt(v) => Ok(*v as u64),
            EmValue::I32(v) => Ok(*v as u64),
            EmValue::Bool(v) => Ok(u64::from(*v)),
            EmValue::Char(v) => Ok(u64::from(*v as u32)),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "u64",
            }),
        }
    }
}

impl TryFrom<EmValue> for u64 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        u64::try_from(&value)
    }
}

impl TryFrom<&EmValue> for f32 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::F32(v) => Ok(*v),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "f32",
            }),
        }
    }
}

impl TryFrom<EmValue> for f32 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        f32::try_from(&value)
    }
}

impl TryFrom<&EmValue> for f64 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::F64(v) => Ok(*v),
            EmValue::F32(v) => Ok(f64::from(*v)),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "f64",
            }),
        }
    }
}

impl TryFrom<EmValue> for f64 {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        f64::try_from(&value)
    }
}

impl TryFrom<&EmValue> for bool {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::Bool(v) => Ok(*v),
            EmValue::I32(v) => Ok(*v != 0),
            EmValue::I64(v) => Ok(*v != 0),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "bool",
            }),
        }
    }
}

impl TryFrom<EmValue> for bool {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        bool::try_from(&value)
    }
}

impl TryFrom<&EmValue> for char {
    type Error = crate::emulation::EmulationError;

    #[allow(clippy::cast_sign_loss)] // Intentional: i32 bit pattern reinterprets as Unicode code point
    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::Char(v) => Ok(*v),
            EmValue::I32(v) => {
                char::from_u32(*v as u32).ok_or(crate::emulation::EmulationError::ValueConversion {
                    source_type: "I32",
                    target_type: "char",
                })
            }
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "char",
            }),
        }
    }
}

impl TryFrom<EmValue> for char {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        char::try_from(&value)
    }
}

impl TryFrom<&EmValue> for HeapRef {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::ObjectRef(r) => Ok(*r),
            _ => Err(crate::emulation::EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "HeapRef",
            }),
        }
    }
}

impl TryFrom<EmValue> for HeapRef {
    type Error = crate::emulation::EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        HeapRef::try_from(&value)
    }
}

impl TryFrom<&EmValue> for usize {
    type Error = crate::emulation::EmulationError;

    /// Converts an `EmValue` to a `usize` for array indexing.
    ///
    /// This conversion validates that the value is non-negative and within the
    /// range of `usize`. This is critical for safe array access - malformed
    /// bytecode or malicious input could provide negative indices that would
    /// wrap to large positive values without this check.
    ///
    /// # Supported Conversions
    ///
    /// - `I32` - Succeeds if value is non-negative
    /// - `I64` - Succeeds if value is non-negative and fits in `usize`
    /// - `NativeInt` - Succeeds if value is non-negative and fits in `usize`
    /// - `Bool` - Converts `false` to 0, `true` to 1
    /// - `Char` - Converts to Unicode code point value
    ///
    /// # Errors
    ///
    /// Returns `ValueConversion` error if:
    /// - The value is a negative integer
    /// - The value exceeds `usize::MAX`
    /// - The value type is not convertible to an index (e.g., float, null)
    fn try_from(value: &EmValue) -> Result<Self, Self::Error> {
        match value {
            EmValue::I32(v) => usize::try_from(*v).map_err(|_| EmulationError::ValueConversion {
                source_type: "I32 (negative)",
                target_type: "usize",
            }),
            EmValue::I64(v) | EmValue::NativeInt(v) => {
                usize::try_from(*v).map_err(|_| EmulationError::ValueConversion {
                    source_type: "I64 (negative or overflow)",
                    target_type: "usize",
                })
            }
            EmValue::Bool(v) => Ok(usize::from(*v)),
            EmValue::Char(v) => Ok(*v as usize),
            _ => Err(EmulationError::ValueConversion {
                source_type: value.type_name(),
                target_type: "usize",
            }),
        }
    }
}

impl TryFrom<EmValue> for usize {
    type Error = EmulationError;

    fn try_from(value: EmValue) -> Result<Self, Self::Error> {
        usize::try_from(&value)
    }
}

impl EmValue {
    /// Returns a static string name for this value's type variant.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self {
            EmValue::Void => "Void",
            EmValue::I32(_) => "I32",
            EmValue::I64(_) => "I64",
            EmValue::F32(_) => "F32",
            EmValue::F64(_) => "F64",
            EmValue::NativeInt(_) => "NativeInt",
            EmValue::NativeUInt(_) => "NativeUInt",
            EmValue::Bool(_) => "Bool",
            EmValue::Char(_) => "Char",
            EmValue::ObjectRef(_) => "ObjectRef",
            EmValue::Null => "Null",
            EmValue::ManagedPtr(_) => "ManagedPtr",
            EmValue::UnmanagedPtr(_) => "UnmanagedPtr",
            EmValue::ValueType { .. } => "ValueType",
            EmValue::TypedRef { .. } => "TypedRef",
            EmValue::Symbolic(_) => "Symbolic",
        }
    }

    /// Converts to `i8` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 8 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.i1` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(300).to_i8_cil(), 44); // 300 & 0xFF = 44
    /// assert_eq!(EmValue::I32(-1).to_i8_cil(), -1);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_i8_cil(&self) -> i8 {
        self.to_i64_cil() as i8
    }

    /// Converts to `u8` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 8 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.u1` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(300).to_u8_cil(), 44);
    /// assert_eq!(EmValue::I32(-1).to_u8_cil(), 255);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn to_u8_cil(&self) -> u8 {
        self.to_i64_cil() as u8
    }

    /// Converts to `i16` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 16 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.i2` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(70000).to_i16_cil(), 4464);
    /// assert_eq!(EmValue::I32(-1).to_i16_cil(), -1);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_i16_cil(&self) -> i16 {
        self.to_i64_cil() as i16
    }

    /// Converts to `u16` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 16 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.u2` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(70000).to_u16_cil(), 4464);
    /// assert_eq!(EmValue::I32(-1).to_u16_cil(), 65535);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn to_u16_cil(&self) -> u16 {
        self.to_i64_cil() as u16
    }

    /// Converts to `i32` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 32 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.i4` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I64(0x1_0000_0001).to_i32_cil(), 1);
    /// assert_eq!(EmValue::F64(3.7).to_i32_cil(), 3);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_i32_cil(&self) -> i32 {
        self.to_i64_cil() as i32
    }

    /// Converts to `u32` using CIL conversion semantics (with truncation).
    ///
    /// Truncates the value to 32 bits. For non-numeric types, returns 0.
    /// This corresponds to the CIL `conv.u4` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(-1).to_u32_cil(), 0xFFFFFFFF);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn to_u32_cil(&self) -> u32 {
        self.to_i64_cil() as u32
    }

    /// Converts to `i64` using CIL conversion semantics (with truncation).
    ///
    /// This follows the behavior of CIL `conv.i8` - it will truncate
    /// floating point values and return 0 for non-numeric types.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I32(42).to_i64_cil(), 42);
    /// assert_eq!(EmValue::F64(3.9).to_i64_cil(), 3);
    /// assert_eq!(EmValue::Bool(true).to_i64_cil(), 1);
    /// assert_eq!(EmValue::Null.to_i64_cil(), 0);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    pub fn to_i64_cil(&self) -> i64 {
        match self {
            EmValue::I32(n) => i64::from(*n),
            EmValue::I64(n) | EmValue::NativeInt(n) => *n,
            EmValue::NativeUInt(n) | EmValue::UnmanagedPtr(n) => *n as i64,
            EmValue::F32(f) => *f as i64,
            EmValue::F64(f) => *f as i64,
            EmValue::Bool(b) => i64::from(*b),
            EmValue::Char(c) => i64::from(*c as u32),
            _ => 0,
        }
    }

    /// Tries to convert to `i64`, returning `None` for non-integer types.
    ///
    /// Unlike [`Self::to_i64_cil`], this returns `None` for types that cannot be
    /// meaningfully converted to an integer (objects, null, void, etc.).
    /// Unlike [`Self::as_i64`], this accepts all integer-like types including I32.
    #[must_use]
    pub fn try_to_i64(&self) -> Option<i64> {
        match self {
            EmValue::I32(n) => Some(i64::from(*n)),
            EmValue::I64(n) | EmValue::NativeInt(n) => Some(*n),
            // Intentional: native uint bit pattern reinterprets as signed
            EmValue::NativeUInt(n) => Some((*n).cast_signed()),
            EmValue::Bool(b) => Some(i64::from(*b)),
            EmValue::Char(c) => Some(i64::from(*c as u32)),
            _ => None,
        }
    }

    /// Converts to `u64` using CIL conversion semantics (with truncation).
    ///
    /// Reinterprets the value's bit pattern as unsigned. For non-numeric types,
    /// returns 0. This corresponds to the CIL `conv.u8` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert_eq!(EmValue::I64(-1).to_u64_cil(), u64::MAX);
    /// assert_eq!(EmValue::I32(42).to_u64_cil(), 42);
    /// ```
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn to_u64_cil(&self) -> u64 {
        self.to_i64_cil() as u64
    }

    /// Converts to `f32` using CIL conversion semantics.
    ///
    /// Converts numeric values to single-precision floating point.
    /// This corresponds to the CIL `conv.r4` instruction behavior.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!((EmValue::I32(42).to_f32_cil() - 42.0).abs() < f32::EPSILON);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn to_f32_cil(&self) -> f32 {
        self.to_f64_cil() as f32
    }

    /// Converts to `f64` using CIL conversion semantics.
    ///
    /// This follows the behavior of CIL `conv.r8`. Converts any numeric value
    /// to double-precision floating point. Non-numeric types return 0.0.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!((EmValue::I32(42).to_f64_cil() - 42.0).abs() < f64::EPSILON);
    /// assert!((EmValue::F32(3.5).to_f64_cil() - 3.5).abs() < 0.001);
    /// ```
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn to_f64_cil(&self) -> f64 {
        match self {
            EmValue::F64(f) => *f,
            EmValue::F32(f) => f64::from(*f),
            EmValue::I32(n) => f64::from(*n),
            EmValue::I64(n) | EmValue::NativeInt(n) => *n as f64,
            EmValue::NativeUInt(n) | EmValue::UnmanagedPtr(n) => *n as f64,
            EmValue::Bool(b) => f64::from(u8::from(*b)),
            EmValue::Char(c) => f64::from(*c as u32),
            _ => 0.0,
        }
    }

    /// Converts to `bool` using CIL conversion semantics.
    ///
    /// Returns `true` for any non-zero numeric value, `false` otherwise.
    /// This follows CIL boolean semantics where any non-zero value is truthy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    ///
    /// assert!(EmValue::I32(1).to_bool_cil());
    /// assert!(EmValue::I32(-1).to_bool_cil());
    /// assert!(!EmValue::I32(0).to_bool_cil());
    /// assert!(!EmValue::Null.to_bool_cil());
    /// ```
    #[must_use]
    pub fn to_bool_cil(&self) -> bool {
        match self {
            EmValue::Bool(b) => *b,
            EmValue::I32(n) => *n != 0,
            EmValue::I64(n) | EmValue::NativeInt(n) => *n != 0,
            EmValue::NativeUInt(n) | EmValue::UnmanagedPtr(n) => *n != 0,
            EmValue::F32(f) => *f != 0.0,
            EmValue::F64(f) => *f != 0.0,
            _ => false,
        }
    }

    /// Implements CLR `Object.Equals` semantics for emulated values.
    ///
    /// This matches the behavior of `System.Object.Equals`:
    /// - **Reference types** (`ObjectRef`): reference equality (same identity)
    /// - **Value types** (`ValueType`): structural field-by-field comparison
    /// - **Primitives** (`I32`, `I64`, etc.): value equality, including
    ///   cross-type widening (e.g., `I32(1)` equals `I64(1)`)
    /// - **Null**: `null.Equals(null)` is `true`; `null.Equals(x)` is `false`
    /// - **Symbolic**: always `false` (unknown values cannot be compared)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    /// use dotscope::emulation::HeapRef;
    ///
    /// // Primitive value equality
    /// assert!(EmValue::I32(42).clr_equals(&EmValue::I32(42)));
    /// assert!(!EmValue::I32(1).clr_equals(&EmValue::I32(2)));
    ///
    /// // Cross-type widening
    /// assert!(EmValue::I32(10).clr_equals(&EmValue::I64(10)));
    ///
    /// // Reference equality for objects
    /// let r1 = EmValue::ObjectRef(HeapRef::new(1));
    /// let r2 = EmValue::ObjectRef(HeapRef::new(1));
    /// let r3 = EmValue::ObjectRef(HeapRef::new(2));
    /// assert!(r1.clr_equals(&r2)); // same identity
    /// assert!(!r1.clr_equals(&r3)); // different identity
    ///
    /// // Null semantics
    /// assert!(EmValue::Null.clr_equals(&EmValue::Null));
    /// assert!(!EmValue::I32(0).clr_equals(&EmValue::Null));
    /// ```
    #[must_use]
    pub fn clr_equals(&self, other: &EmValue) -> bool {
        match (self, other) {
            // Null equality
            (EmValue::Null, EmValue::Null) => true,

            // Reference types: identity comparison
            (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => a.id() == b.id(),

            // Same-type primitive equality
            (EmValue::I32(a), EmValue::I32(b)) => a == b,
            (EmValue::I64(a), EmValue::I64(b)) => a == b,
            (EmValue::F32(a), EmValue::F32(b)) => a.to_bits() == b.to_bits(),
            (EmValue::F64(a), EmValue::F64(b)) => a.to_bits() == b.to_bits(),
            (EmValue::NativeInt(a), EmValue::NativeInt(b)) => a == b,
            (EmValue::NativeUInt(a), EmValue::NativeUInt(b)) => a == b,
            (EmValue::Bool(a), EmValue::Bool(b)) => a == b,
            (EmValue::Char(a), EmValue::Char(b)) => a == b,
            (EmValue::UnmanagedPtr(a), EmValue::UnmanagedPtr(b)) => a == b,

            // Cross-type integer widening (boxed value types may compare across widths)
            (EmValue::I32(a), EmValue::I64(b)) | (EmValue::I32(a), EmValue::NativeInt(b)) => {
                i64::from(*a) == *b
            }
            (EmValue::I64(a), EmValue::I32(b)) | (EmValue::NativeInt(a), EmValue::I32(b)) => {
                *a == i64::from(*b)
            }
            (EmValue::I64(a), EmValue::NativeInt(b)) | (EmValue::NativeInt(a), EmValue::I64(b)) => {
                a == b
            }

            // Value type: structural field comparison
            (
                EmValue::ValueType {
                    type_token: t1,
                    fields: f1,
                },
                EmValue::ValueType {
                    type_token: t2,
                    fields: f2,
                },
            ) => {
                t1 == t2 && f1.len() == f2.len() && f1.iter().zip(f2).all(|(a, b)| a.clr_equals(b))
            }

            // Managed pointer comparison
            (EmValue::ManagedPtr(a), EmValue::ManagedPtr(b)) => a == b,

            // Everything else (including Symbolic, Void, mismatched types)
            _ => false,
        }
    }

    /// Extracts a size value (non-negative integer) from this value.
    ///
    /// Used for memory allocation and copy operations where a size is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The value is a negative signed integer
    /// - The value is not an integer type
    #[allow(clippy::match_same_arms)]
    pub fn as_size(&self) -> Result<usize, EmulationError> {
        match self {
            EmValue::I32(n) => {
                if *n < 0 {
                    return Err(EmulationError::InvalidOperand {
                        instruction: "memory operation",
                        expected: "non-negative size",
                    });
                }
                // Intentional: converting validated non-negative i32 to usize
                #[allow(clippy::cast_sign_loss)]
                let result = *n as usize;
                Ok(result)
            }
            EmValue::I64(n) => {
                if *n < 0 {
                    return Err(EmulationError::InvalidOperand {
                        instruction: "memory operation",
                        expected: "non-negative size",
                    });
                }
                // Intentional: converting validated non-negative i64 to usize (may truncate on 32-bit)
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let result = *n as usize;
                Ok(result)
            }
            EmValue::NativeInt(n) => {
                if *n < 0 {
                    return Err(EmulationError::InvalidOperand {
                        instruction: "memory operation",
                        expected: "non-negative size",
                    });
                }
                // Intentional: converting validated non-negative i64 to usize (may truncate on 32-bit)
                #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                let result = *n as usize;
                Ok(result)
            }
            // Intentional: u64 to usize (may truncate on 32-bit platforms)
            #[allow(clippy::cast_possible_truncation)]
            EmValue::NativeUInt(n) => Ok(*n as usize),
            _ => Err(EmulationError::TypeMismatch {
                operation: "size extraction",
                expected: "integer",
                found: self.type_name(),
            }),
        }
    }

    /// Extracts a pointer address (u64) from this value.
    ///
    /// Used for unmanaged memory operations that require a raw address.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is a managed pointer (which cannot
    /// be used for unmanaged memory operations) or is not a pointer/integer type.
    pub fn as_pointer_address(&self) -> Result<u64, EmulationError> {
        match self {
            EmValue::UnmanagedPtr(addr) => Ok(*addr),
            // Intentional: reinterpret signed native int and i64 as unsigned address
            EmValue::NativeInt(n) | EmValue::I64(n) => Ok((*n).cast_unsigned()),
            EmValue::NativeUInt(n) => Ok(*n),
            // Intentional: reinterpret signed i32 as unsigned address (with sign extension)
            EmValue::I32(n) => Ok(u64::from((*n).cast_unsigned())),
            EmValue::ManagedPtr(_) => Err(EmulationError::TypeMismatch {
                operation: "unmanaged memory access",
                expected: "unmanaged pointer",
                found: "managed pointer",
            }),
            _ => Err(EmulationError::TypeMismatch {
                operation: "pointer extraction",
                expected: "pointer or integer",
                found: self.type_name(),
            }),
        }
    }

    /// Converts this value to its little-endian byte representation.
    ///
    /// The output size is determined by the `flavor` parameter, which specifies
    /// the target CIL type. This is used for operations like `Buffer.BlockCopy`
    /// that work at the byte level.
    ///
    /// For `NativeInt`/`NativeUInt`, serializes to 4 or 8 bytes based on `ptr_size`.
    ///
    /// # Arguments
    ///
    /// * `flavor` - The CIL type flavor determining the byte width
    /// * `ptr_size` - The pointer size for native integer serialization
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    /// use dotscope::metadata::typesystem::{CilFlavor, PointerSize};
    ///
    /// let value = EmValue::I32(0x12345678);
    /// assert_eq!(&*value.to_le_bytes(&CilFlavor::I4, PointerSize::Bit64), &[0x78, 0x56, 0x34, 0x12]);
    /// assert_eq!(&*value.to_le_bytes(&CilFlavor::I2, PointerSize::Bit64), &[0x78, 0x56]);
    /// assert_eq!(&*value.to_le_bytes(&CilFlavor::I1, PointerSize::Bit64), &[0x78]);
    /// ```
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn to_le_bytes(&self, flavor: &CilFlavor, ptr_size: PointerSize) -> LeBytes {
        match (self, flavor) {
            (EmValue::I32(v), CilFlavor::I1 | CilFlavor::U1 | CilFlavor::Boolean) => {
                LeBytes::from_byte(*v as u8)
            }
            (EmValue::I32(v), CilFlavor::I2 | CilFlavor::U2 | CilFlavor::Char) => {
                LeBytes::from_2((*v as i16).to_le_bytes())
            }
            (EmValue::I32(v), _) => LeBytes::from_4(v.to_le_bytes()),
            (EmValue::I64(v), _) => LeBytes::from_8(v.to_le_bytes()),
            (EmValue::F32(v), _) => LeBytes::from_4(v.to_le_bytes()),
            (EmValue::F64(v), _) => LeBytes::from_8(v.to_le_bytes()),
            (EmValue::NativeInt(v), _) => match ptr_size {
                PointerSize::Bit32 => LeBytes::from_4((*v as i32).to_le_bytes()),
                PointerSize::Bit64 => LeBytes::from_8(v.to_le_bytes()),
                PointerSize::Bit8 => LeBytes::from_byte((*v as i8).to_le_bytes()[0]),
                PointerSize::Bit16 => LeBytes::from_2((*v as i16).to_le_bytes()),
                PointerSize::Bit128 => LeBytes::zeroed(8),
            },
            (EmValue::NativeUInt(v), _) => match ptr_size {
                PointerSize::Bit32 => LeBytes::from_4((*v as u32).to_le_bytes()),
                PointerSize::Bit64 => LeBytes::from_8(v.to_le_bytes()),
                PointerSize::Bit8 => LeBytes::from_byte((*v as u8).to_le_bytes()[0]),
                PointerSize::Bit16 => LeBytes::from_2((*v as u16).to_le_bytes()),
                PointerSize::Bit128 => LeBytes::zeroed(8),
            },
            (EmValue::Bool(v), _) => LeBytes::from_byte(u8::from(*v)),
            (EmValue::Char(v), _) => LeBytes::from_2((*v as u16).to_le_bytes()),
            _ => LeBytes::zeroed(flavor.element_size(ptr_size).unwrap_or(ptr_size.bytes())),
        }
    }

    /// Creates an `EmValue` from little-endian bytes according to the given flavor.
    ///
    /// This is the inverse of [`to_le_bytes`](Self::to_le_bytes). The number of bytes
    /// consumed depends on the `flavor` parameter.
    ///
    /// For `CilFlavor::I` / `CilFlavor::U`, reads 4 or 8 bytes based on `ptr_size`.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The source bytes in little-endian order
    /// * `flavor` - The CIL type flavor determining how to interpret the bytes
    /// * `ptr_size` - The pointer size for native integer deserialization
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::emulation::EmValue;
    /// use dotscope::metadata::typesystem::{CilFlavor, PointerSize};
    ///
    /// let bytes = [0x78, 0x56, 0x34, 0x12];
    /// assert_eq!(EmValue::from_le_bytes(&bytes, &CilFlavor::I4, PointerSize::Bit64), EmValue::I32(0x12345678));
    /// assert_eq!(EmValue::from_le_bytes(&bytes, &CilFlavor::I2, PointerSize::Bit64), EmValue::I32(0x5678));
    /// assert_eq!(EmValue::from_le_bytes(&bytes, &CilFlavor::I1, PointerSize::Bit64), EmValue::I32(0x78));
    /// ```
    #[must_use]
    pub fn from_le_bytes(bytes: &[u8], flavor: &CilFlavor, ptr_size: PointerSize) -> EmValue {
        match flavor {
            CilFlavor::I1 | CilFlavor::U1 | CilFlavor::Boolean => {
                EmValue::I32(i32::from(bytes.first().copied().unwrap_or(0)))
            }
            CilFlavor::I2 | CilFlavor::U2 | CilFlavor::Char => {
                let arr: [u8; 2] = bytes
                    .get(..2.min(bytes.len()))
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0, 0]);
                EmValue::I32(i32::from(i16::from_le_bytes(arr)))
            }
            CilFlavor::I4 | CilFlavor::U4 | CilFlavor::R4 => {
                let arr: [u8; 4] = bytes
                    .get(..4.min(bytes.len()))
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0, 0, 0, 0]);
                if matches!(flavor, CilFlavor::R4) {
                    EmValue::F32(f32::from_le_bytes(arr))
                } else {
                    EmValue::I32(i32::from_le_bytes(arr))
                }
            }
            CilFlavor::I8 | CilFlavor::U8 | CilFlavor::R8 => {
                let arr: [u8; 8] = bytes
                    .get(..8.min(bytes.len()))
                    .and_then(|s| s.try_into().ok())
                    .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]);
                if matches!(flavor, CilFlavor::R8) {
                    EmValue::F64(f64::from_le_bytes(arr))
                } else {
                    EmValue::I64(i64::from_le_bytes(arr))
                }
            }
            CilFlavor::I | CilFlavor::U => match ptr_size {
                PointerSize::Bit32 => {
                    let arr: [u8; 4] = bytes
                        .get(..4.min(bytes.len()))
                        .and_then(|s| s.try_into().ok())
                        .unwrap_or([0, 0, 0, 0]);
                    if matches!(flavor, CilFlavor::I) {
                        EmValue::NativeInt(i64::from(i32::from_le_bytes(arr)))
                    } else {
                        EmValue::NativeUInt(u64::from(u32::from_le_bytes(arr)))
                    }
                }
                PointerSize::Bit64 => {
                    let arr: [u8; 8] = bytes
                        .get(..8.min(bytes.len()))
                        .and_then(|s| s.try_into().ok())
                        .unwrap_or([0, 0, 0, 0, 0, 0, 0, 0]);
                    if matches!(flavor, CilFlavor::I) {
                        EmValue::NativeInt(i64::from_le_bytes(arr))
                    } else {
                        EmValue::NativeUInt(u64::from_le_bytes(arr))
                    }
                }
                PointerSize::Bit8 => {
                    let byte = bytes.first().copied().unwrap_or(0);
                    if matches!(flavor, CilFlavor::I) {
                        EmValue::NativeInt(i64::from(byte as i8))
                    } else {
                        EmValue::NativeUInt(u64::from(byte))
                    }
                }
                PointerSize::Bit16 => {
                    let arr: [u8; 2] = bytes
                        .get(..2.min(bytes.len()))
                        .and_then(|s| s.try_into().ok())
                        .unwrap_or([0, 0]);
                    if matches!(flavor, CilFlavor::I) {
                        EmValue::NativeInt(i64::from(i16::from_le_bytes(arr)))
                    } else {
                        EmValue::NativeUInt(u64::from(u16::from_le_bytes(arr)))
                    }
                }
                PointerSize::Bit128 => {
                    let arr: [u8; 16] = bytes
                        .get(..16.min(bytes.len()))
                        .and_then(|s| s.try_into().ok())
                        .unwrap_or([0; 16]);
                    if matches!(flavor, CilFlavor::I) {
                        EmValue::NativeInt(i128::from_le_bytes(arr) as i64)
                    } else {
                        EmValue::NativeUInt(u128::from_le_bytes(arr) as u64)
                    }
                }
            },
            _ => EmValue::I32(0),
        }
    }
}

/// Reference to a heap-allocated object.
///
/// `HeapRef` is an opaque handle that identifies an object on the managed heap.
/// It is used with [`ManagedHeap`](super::super::memory::ManagedHeap) to access
/// strings, arrays, and object instances.
///
/// # Equality
///
/// Two `HeapRef` values are equal if they point to the same heap object.
/// This implements reference equality semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeapRef(pub(crate) u64);

impl HeapRef {
    /// Creates a new heap reference with the given ID.
    ///
    /// This is typically called by [`ManagedHeap`](super::super::memory::ManagedHeap)
    /// when allocating new objects.
    #[must_use]
    pub fn new(id: u64) -> Self {
        HeapRef(id)
    }

    /// Returns the internal ID of this heap reference.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for HeapRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HeapRef({})", self.0)
    }
}

/// Managed pointer for ref/out parameters and address-of operations.
///
/// A managed pointer points to a storage location (local variable, argument,
/// field, or array element) that can be read from or written to. Unlike
/// object references, managed pointers can point to value types.
///
/// # CIL Operations
///
/// Managed pointers are created by:
/// - `ldloca` - Address of local variable
/// - `ldarga` - Address of argument
/// - `ldflda` - Address of instance field
/// - `ldsflda` - Address of static field
/// - `ldelema` - Address of array element
///
/// And used by:
/// - `ldind.*` - Load indirect
/// - `stind.*` - Store indirect
/// - `ldobj` - Load object
/// - `stobj` - Store object
/// - `cpobj` - Copy object
#[derive(Clone, Debug, PartialEq)]
pub struct ManagedPointer {
    /// What this pointer points to.
    pub target: PointerTarget,
    /// Byte offset within the target for field access.
    pub offset: u32,
    /// Call stack index (0-based) of the frame that owns this pointer.
    /// Only meaningful for Local and Argument targets; set to 0 for others.
    pub frame_depth: usize,
}

impl ManagedPointer {
    /// Creates a new managed pointer to a local variable.
    #[must_use]
    pub fn to_local(index: u16, frame_depth: usize) -> Self {
        ManagedPointer {
            target: PointerTarget::Local(index),
            offset: 0,
            frame_depth,
        }
    }

    /// Creates a new managed pointer to an argument.
    #[must_use]
    pub fn to_argument(index: u16, frame_depth: usize) -> Self {
        ManagedPointer {
            target: PointerTarget::Argument(index),
            offset: 0,
            frame_depth,
        }
    }

    /// Creates a new managed pointer to an array element.
    #[must_use]
    pub fn to_array_element(array: HeapRef, index: usize) -> Self {
        ManagedPointer {
            target: PointerTarget::ArrayElement { array, index },
            offset: 0,
            frame_depth: 0,
        }
    }

    /// Creates a new managed pointer to an object field.
    #[must_use]
    pub fn to_object_field(object: HeapRef, field: Token) -> Self {
        ManagedPointer {
            target: PointerTarget::ObjectField { object, field },
            offset: 0,
            frame_depth: 0,
        }
    }

    /// Creates a new managed pointer to a static field.
    #[must_use]
    pub fn to_static_field(field: Token) -> Self {
        ManagedPointer {
            target: PointerTarget::StaticField(field),
            offset: 0,
            frame_depth: 0,
        }
    }

    /// Returns a new pointer with an added offset.
    #[must_use]
    pub fn with_offset(mut self, additional_offset: u32) -> Self {
        self.offset = self.offset.saturating_add(additional_offset);
        self
    }

    /// Synthesizes a deterministic address for this managed pointer.
    ///
    /// ECMA-335 §III.3.19 permits converting managed pointers to native int
    /// via `conv.i` / `conv.u`. The resulting value is implementation-defined
    /// but must be consistent: the same pointer must always produce the same
    /// address.
    ///
    /// Since managed pointers in the emulator do not have real memory
    /// addresses, we synthesize a unique value from the pointer's components.
    /// The address space is partitioned by target kind to avoid collisions:
    ///
    /// | Target | Base address |
    /// |--------|-------------|
    /// | Local | `0x7FFE_0000_0000` + frame * 0x1_0000 + index * 8 |
    /// | Argument | `0x7FFD_0000_0000` + frame * 0x1_0000 + index * 8 |
    /// | ArrayElement | `0x7FFC_0000_0000` + array_id * 0x1_0000 + index * 8 |
    /// | ObjectField | `0x7FFB_0000_0000` + object_id * 0x1_0000 + field |
    /// | StaticField | `0x7FFA_0000_0000` + field_token |
    #[must_use]
    pub fn synthesize_address(&self) -> u64 {
        let base = match &self.target {
            PointerTarget::Local(index) => 0x7FFE_0000_0000_u64
                .wrapping_add((self.frame_depth as u64).wrapping_mul(0x1_0000))
                .wrapping_add(u64::from(*index).wrapping_mul(8)),
            PointerTarget::Argument(index) => 0x7FFD_0000_0000_u64
                .wrapping_add((self.frame_depth as u64).wrapping_mul(0x1_0000))
                .wrapping_add(u64::from(*index).wrapping_mul(8)),
            PointerTarget::ArrayElement { array, index } => 0x7FFC_0000_0000_u64
                .wrapping_add(array.id().wrapping_mul(0x1_0000))
                .wrapping_add((*index as u64).wrapping_mul(8)),
            PointerTarget::ObjectField { object, field } => 0x7FFB_0000_0000_u64
                .wrapping_add(object.id().wrapping_mul(0x1_0000))
                .wrapping_add(u64::from(field.value())),
            PointerTarget::StaticField(token) => {
                0x7FFA_0000_0000_u64.wrapping_add(u64::from(token.value()))
            }
        };
        base.wrapping_add(u64::from(self.offset))
    }
}

/// Target of a managed pointer.
///
/// Describes what storage location a managed pointer references.
#[derive(Clone, Debug, PartialEq)]
pub enum PointerTarget {
    /// Local variable by index.
    Local(u16),
    /// Method argument by index.
    Argument(u16),
    /// Array element by array reference and index.
    ArrayElement {
        /// Reference to the array.
        array: HeapRef,
        /// Index within the array.
        index: usize,
    },
    /// Instance field by object reference and field token.
    ObjectField {
        /// Reference to the object.
        object: HeapRef,
        /// Field metadata token.
        field: Token,
    },
    /// Static field by token.
    StaticField(Token),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emvalue_cil_flavors() {
        assert_eq!(EmValue::I32(0).cil_flavor(), CilFlavor::I4);
        assert_eq!(EmValue::Bool(true).cil_flavor(), CilFlavor::Boolean);
        assert_eq!(EmValue::Char('A').cil_flavor(), CilFlavor::Char);
        assert_eq!(EmValue::I64(0).cil_flavor(), CilFlavor::I8);
        assert_eq!(EmValue::F32(0.0).cil_flavor(), CilFlavor::R4);
        assert_eq!(EmValue::F64(0.0).cil_flavor(), CilFlavor::R8);
        assert_eq!(EmValue::NativeInt(0).cil_flavor(), CilFlavor::I);
        assert_eq!(EmValue::NativeUInt(0).cil_flavor(), CilFlavor::U);
        assert_eq!(
            EmValue::ObjectRef(HeapRef::new(1)).cil_flavor(),
            CilFlavor::Object
        );
        assert_eq!(EmValue::Null.cil_flavor(), CilFlavor::Object);
        assert_eq!(EmValue::UnmanagedPtr(0).cil_flavor(), CilFlavor::Pointer);
    }

    #[test]
    fn test_emvalue_as_i32() {
        assert_eq!(EmValue::I32(42).as_i32(), Some(42));
        assert_eq!(EmValue::I32(-1).as_i32(), Some(-1));
        assert_eq!(EmValue::Bool(true).as_i32(), Some(1));
        assert_eq!(EmValue::Bool(false).as_i32(), Some(0));
        assert_eq!(EmValue::Char('A').as_i32(), Some(65));
        assert_eq!(EmValue::I64(100).as_i32(), None);
        assert_eq!(EmValue::Null.as_i32(), None);
    }

    #[test]
    fn test_emvalue_as_bool() {
        assert_eq!(EmValue::Bool(true).as_bool(), Some(true));
        assert_eq!(EmValue::Bool(false).as_bool(), Some(false));
        assert_eq!(EmValue::I32(1).as_bool(), Some(true));
        assert_eq!(EmValue::I32(0).as_bool(), Some(false));
        assert_eq!(EmValue::I32(-1).as_bool(), Some(true));
        assert_eq!(EmValue::I32(42).as_bool(), Some(true));
    }

    #[test]
    fn test_emvalue_equality() {
        assert_eq!(EmValue::I32(42), EmValue::I32(42));
        assert_ne!(EmValue::I32(42), EmValue::I32(43));
        assert_eq!(EmValue::Null, EmValue::Null);
        assert_eq!(EmValue::Void, EmValue::Void);
        assert_ne!(EmValue::Null, EmValue::Void);

        // Float equality uses bit comparison for deterministic behavior
        assert_eq!(EmValue::F64(0.0), EmValue::F64(0.0));
        // NaN equality: using bit comparison means identical NaN representations are equal
        // This is intentional - for emulation we want deterministic comparison
        assert_eq!(EmValue::F64(f64::NAN), EmValue::F64(f64::NAN));

        // Positive and negative zero are different by bits
        assert_ne!(EmValue::F64(0.0), EmValue::F64(-0.0));
    }

    #[test]
    fn test_emvalue_is_predicates() {
        assert!(EmValue::Void.is_void());
        assert!(!EmValue::Null.is_void());

        assert!(EmValue::Null.is_null());
        assert!(!EmValue::I32(0).is_null());

        assert!(EmValue::I32(42).is_concrete());
        assert!(EmValue::Null.is_concrete());

        assert!(EmValue::Null.is_reference());
        assert!(EmValue::ObjectRef(HeapRef::new(1)).is_reference());
        assert!(!EmValue::I32(0).is_reference());
    }

    #[test]
    fn test_emvalue_default_for_flavor() {
        assert_eq!(EmValue::default_for_flavor(&CilFlavor::I4), EmValue::I32(0));
        assert_eq!(EmValue::default_for_flavor(&CilFlavor::I8), EmValue::I64(0));
        assert_eq!(
            EmValue::default_for_flavor(&CilFlavor::R4),
            EmValue::F32(0.0)
        );
        assert_eq!(
            EmValue::default_for_flavor(&CilFlavor::R8),
            EmValue::F64(0.0)
        );
        assert_eq!(
            EmValue::default_for_flavor(&CilFlavor::Object),
            EmValue::Null
        );
        assert_eq!(
            EmValue::default_for_flavor(&CilFlavor::Boolean),
            EmValue::Bool(false)
        );
        assert_eq!(
            EmValue::default_for_flavor(&CilFlavor::Char),
            EmValue::Char('\0')
        );
    }

    #[test]
    fn test_heap_ref() {
        let r1 = HeapRef::new(42);
        let r2 = HeapRef::new(42);
        let r3 = HeapRef::new(43);

        assert_eq!(r1, r2);
        assert_ne!(r1, r3);
        assert_eq!(r1.id(), 42);
    }

    #[test]
    fn test_managed_pointer_creation() {
        let p1 = ManagedPointer::to_local(0, 0);
        assert_eq!(p1.target, PointerTarget::Local(0));
        assert_eq!(p1.offset, 0);
        assert_eq!(p1.frame_depth, 0);

        let p2 = ManagedPointer::to_argument(1, 0);
        assert_eq!(p2.target, PointerTarget::Argument(1));

        let p3 = ManagedPointer::to_array_element(HeapRef::new(1), 5);
        assert!(matches!(
            p3.target,
            PointerTarget::ArrayElement { index: 5, .. }
        ));

        let p4 = p1.with_offset(8);
        assert_eq!(p4.offset, 8);
    }

    #[test]
    fn test_emvalue_display() {
        assert_eq!(format!("{}", EmValue::I32(42)), "42");
        assert_eq!(format!("{}", EmValue::I64(42)), "42L");
        assert_eq!(format!("{}", EmValue::Bool(true)), "true");
        assert_eq!(format!("{}", EmValue::Null), "null");
        assert_eq!(format!("{}", EmValue::Void), "void");
        assert_eq!(format!("{}", EmValue::Char('A')), "'A'");
    }

    #[test]
    fn test_from_primitives() {
        assert_eq!(EmValue::from(42_i32), EmValue::I32(42));
        assert_eq!(EmValue::from(42_i64), EmValue::I64(42));
        assert_eq!(
            EmValue::from(std::f32::consts::PI),
            EmValue::F32(std::f32::consts::PI)
        );
        assert_eq!(
            EmValue::from(std::f64::consts::PI),
            EmValue::F64(std::f64::consts::PI)
        );
        assert_eq!(EmValue::from(true), EmValue::Bool(true));
        assert_eq!(EmValue::from('A'), EmValue::Char('A'));
        assert_eq!(EmValue::from(255_u8), EmValue::I32(255));
        assert_eq!(EmValue::from(-128_i8), EmValue::I32(-128));
        assert_eq!(EmValue::from(1000_u16), EmValue::I32(1000));
        assert_eq!(EmValue::from(-1000_i16), EmValue::I32(-1000));
    }

    #[test]
    fn test_try_from_emvalue_i32() {
        assert_eq!(i32::try_from(&EmValue::I32(42)), Ok(42));
        assert_eq!(i32::try_from(&EmValue::Bool(true)), Ok(1));
        assert_eq!(i32::try_from(&EmValue::Bool(false)), Ok(0));
        assert_eq!(i32::try_from(&EmValue::Char('A')), Ok(65));
        assert!(i32::try_from(&EmValue::I64(100)).is_err());
        assert!(i32::try_from(&EmValue::Null).is_err());
    }

    #[test]
    fn test_try_from_emvalue_i64() {
        assert_eq!(i64::try_from(&EmValue::I64(42)), Ok(42));
        assert_eq!(i64::try_from(&EmValue::I32(42)), Ok(42));
        assert_eq!(i64::try_from(&EmValue::Bool(true)), Ok(1));
        assert_eq!(i64::try_from(&EmValue::Char('A')), Ok(65));
        assert_eq!(i64::try_from(&EmValue::NativeInt(100)), Ok(100));
        assert!(i64::try_from(&EmValue::Null).is_err());
    }

    #[test]
    fn test_try_from_emvalue_bool() {
        assert_eq!(bool::try_from(&EmValue::Bool(true)), Ok(true));
        assert_eq!(bool::try_from(&EmValue::Bool(false)), Ok(false));
        assert_eq!(bool::try_from(&EmValue::I32(0)), Ok(false));
        assert_eq!(bool::try_from(&EmValue::I32(1)), Ok(true));
        assert_eq!(bool::try_from(&EmValue::I32(-1)), Ok(true));
        assert_eq!(bool::try_from(&EmValue::I64(0)), Ok(false));
        assert!(bool::try_from(&EmValue::Null).is_err());
    }

    #[test]
    fn test_try_from_emvalue_char() {
        assert_eq!(char::try_from(&EmValue::Char('A')), Ok('A'));
        assert_eq!(char::try_from(&EmValue::I32(65)), Ok('A'));
        // Invalid Unicode code point
        assert!(char::try_from(&EmValue::I32(-1)).is_err());
        assert!(char::try_from(&EmValue::Null).is_err());
    }

    #[test]
    fn test_try_from_emvalue_heapref() {
        let r = HeapRef::new(42);
        assert_eq!(HeapRef::try_from(&EmValue::ObjectRef(r)), Ok(r));
        assert!(HeapRef::try_from(&EmValue::Null).is_err());
        assert!(HeapRef::try_from(&EmValue::I32(42)).is_err());
    }

    #[test]
    fn test_to_i64_cil() {
        assert_eq!(EmValue::I32(42).to_i64_cil(), 42);
        assert_eq!(EmValue::I64(100).to_i64_cil(), 100);
        assert_eq!(EmValue::F32(3.9).to_i64_cil(), 3);
        assert_eq!(EmValue::F64(3.9).to_i64_cil(), 3);
        assert_eq!(EmValue::Bool(true).to_i64_cil(), 1);
        assert_eq!(EmValue::Bool(false).to_i64_cil(), 0);
        assert_eq!(EmValue::Null.to_i64_cil(), 0);
    }

    #[test]
    fn test_to_f64_cil() {
        assert!((EmValue::I32(42).to_f64_cil() - 42.0).abs() < f64::EPSILON);
        assert!((EmValue::F32(3.5).to_f64_cil() - 3.5).abs() < 0.001);
        assert!(
            (EmValue::F64(std::f64::consts::PI).to_f64_cil() - std::f64::consts::PI).abs()
                < f64::EPSILON
        );
        assert!((EmValue::Bool(true).to_f64_cil() - 1.0).abs() < f64::EPSILON);
        assert!((EmValue::Null.to_f64_cil() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_type_name() {
        assert_eq!(EmValue::I32(0).type_name(), "I32");
        assert_eq!(EmValue::I64(0).type_name(), "I64");
        assert_eq!(EmValue::F32(0.0).type_name(), "F32");
        assert_eq!(EmValue::F64(0.0).type_name(), "F64");
        assert_eq!(EmValue::Bool(false).type_name(), "Bool");
        assert_eq!(EmValue::Char('a').type_name(), "Char");
        assert_eq!(EmValue::Null.type_name(), "Null");
        assert_eq!(EmValue::Void.type_name(), "Void");
    }

    #[test]
    fn test_as_size_i32() {
        assert_eq!(EmValue::I32(100).as_size().unwrap(), 100);
        assert_eq!(EmValue::I32(0).as_size().unwrap(), 0);
    }

    #[test]
    fn test_as_size_i64() {
        assert_eq!(EmValue::I64(200).as_size().unwrap(), 200);
    }

    #[test]
    fn test_as_size_native() {
        assert_eq!(EmValue::NativeInt(300).as_size().unwrap(), 300);
        assert_eq!(EmValue::NativeUInt(400).as_size().unwrap(), 400);
    }

    #[test]
    fn test_as_size_negative_fails() {
        assert!(EmValue::I32(-1).as_size().is_err());
        assert!(EmValue::I64(-100).as_size().is_err());
        assert!(EmValue::NativeInt(-50).as_size().is_err());
    }

    #[test]
    fn test_as_size_wrong_type_fails() {
        assert!(EmValue::Null.as_size().is_err());
        assert!(EmValue::F64(1.0).as_size().is_err());
    }

    #[test]
    fn test_as_pointer_address_unmanaged() {
        assert_eq!(
            EmValue::UnmanagedPtr(0x1000).as_pointer_address().unwrap(),
            0x1000
        );
    }

    #[test]
    fn test_as_pointer_address_native_int() {
        assert_eq!(
            EmValue::NativeInt(0x2000).as_pointer_address().unwrap(),
            0x2000
        );
        assert_eq!(
            EmValue::NativeUInt(0x3000).as_pointer_address().unwrap(),
            0x3000
        );
    }

    #[test]
    fn test_as_pointer_address_i32_i64() {
        assert_eq!(EmValue::I32(0x100).as_pointer_address().unwrap(), 0x100);
        assert_eq!(EmValue::I64(0x200).as_pointer_address().unwrap(), 0x200);
    }

    #[test]
    fn test_as_pointer_address_managed_fails() {
        let ptr = ManagedPointer::to_local(0, 0);
        assert!(EmValue::ManagedPtr(ptr).as_pointer_address().is_err());
    }

    #[test]
    fn test_as_pointer_address_wrong_type_fails() {
        assert!(EmValue::Null.as_pointer_address().is_err());
        assert!(EmValue::F64(1.0).as_pointer_address().is_err());
    }
}
