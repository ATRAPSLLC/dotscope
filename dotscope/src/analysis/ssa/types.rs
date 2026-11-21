//! SSA type system for .NET CIL types.
//!
//! This module provides a type representation for SSA variables that captures
//! the essential type information needed for analysis and optimization without
//! requiring full metadata resolution.
//!
//! # Design Rationale
//!
//! The `SsaType` enum is designed to be:
//! - **Fast to compare**: Enum variants are faster than token resolution
//! - **Self-contained**: No metadata context needed for basic operations
//! - **Analysis-friendly**: Includes special types like `Unknown` and `Null`
//!
//! # Type Categories
//!
//! - **Primitives**: Fixed-size numeric and boolean types
//! - **References**: Object references, arrays, and pointers
//! - **Special**: Generic parameters and analysis-only types

use std::{fmt, sync::OnceLock};

use crate::{
    metadata::{
        cilobject::CilObject,
        method::{ExceptionHandlerFlags, Method},
        signatures::{
            parse_local_var_signature, CustomModifiers, SignatureArray, SignatureLocalVariable,
            SignatureMethod, SignatureParameter, SignaturePointer, SignatureSzArray, TypeSignature,
        },
        tables::{MemberRefSignature, StandAloneSigRaw, StandAloneSignature, TableId, TypeSpecRaw},
        token::Token,
        typesystem::{wellknown, ArrayDimensions, CilFlavor},
    },
    utils::EnumUtils,
};

/// How deeply a type may nest before it is treated as unknown.
///
/// A TypeSpec is typed from its own signature, which can name further
/// TypeSpecs. Well-formed metadata stays far below this; malformed metadata
/// whose TypeSpec names itself would otherwise recurse without end.
const MAX_TYPE_DEPTH: usize = 64;

/// Reference to a type in metadata.
///
/// This is a lightweight handle that can be resolved to full type information
/// when needed. Used for class types, value types, and generic instantiations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TypeRef(pub Token);

impl TypeRef {
    /// Creates a new type reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TypeRef({})", self.0)
    }
}

/// Reference to a method in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MethodRef(pub Token);

impl MethodRef {
    /// Creates a new method reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl From<Token> for MethodRef {
    fn from(token: Token) -> Self {
        Self(token)
    }
}

impl fmt::Display for MethodRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MethodRef({})", self.0)
    }
}

/// Reference to a field in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FieldRef(pub Token);

impl FieldRef {
    /// Creates a new field reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for FieldRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldRef({})", self.0)
    }
}

/// Reference to a standalone signature in metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SigRef(pub Token);

impl SigRef {
    /// Creates a new signature reference from a metadata token.
    #[must_use]
    pub const fn new(token: Token) -> Self {
        Self(token)
    }

    /// Returns the underlying metadata token.
    #[must_use]
    pub const fn token(&self) -> Token {
        self.0
    }
}

impl fmt::Display for SigRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigRef({})", self.0)
    }
}

/// SSA type representation for CIL types.
///
/// This enum provides a simplified view of .NET types suitable for SSA analysis.
/// It captures the essential type information without requiring full metadata
/// resolution for common operations.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::analysis::SsaType;
///
/// let int_type = SsaType::I32;
/// let string_type = SsaType::String;
/// let array_type = SsaType::Array(Box::new(SsaType::I32), 1);
///
/// assert!(int_type.is_primitive());
/// assert!(string_type.is_reference());
/// assert!(array_type.is_array());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SsaType {
    /// No return value (void).
    Void,

    /// Boolean type (System.Boolean).
    Bool,

    /// Signed 8-bit integer (System.SByte).
    I8,

    /// Unsigned 8-bit integer (System.Byte).
    U8,

    /// Signed 16-bit integer (System.Int16).
    I16,

    /// Unsigned 16-bit integer (System.UInt16).
    U16,

    /// Signed 32-bit integer (System.Int32).
    I32,

    /// Unsigned 32-bit integer (System.UInt32).
    U32,

    /// Signed 64-bit integer (System.Int64).
    I64,

    /// Unsigned 64-bit integer (System.UInt64).
    U64,

    /// Native-sized signed integer (System.IntPtr).
    NativeInt,

    /// Native-sized unsigned integer (System.UIntPtr).
    NativeUInt,

    /// 32-bit floating point (System.Single).
    F32,

    /// 64-bit floating point (System.Double).
    F64,

    /// Unicode character (System.Char).
    Char,

    /// System.Object reference.
    Object,

    /// System.String reference.
    String,

    /// Reference to a specific class type.
    Class(TypeRef),

    /// Value type (struct) - stored inline, not by reference.
    ValueType(TypeRef),

    /// Generic instantiation of a type with concrete type arguments.
    ///
    /// For example, `List<int>` is `GenericInst(Class(List), [I32])`.
    GenericInst(Box<SsaType>, Vec<SsaType>),

    /// Single-dimensional or multi-dimensional array.
    ///
    /// The `u32` is the rank (number of dimensions). Rank 1 is a vector (SZ array).
    Array(Box<SsaType>, u32),

    /// Unmanaged pointer to a type.
    Pointer(Box<SsaType>),

    /// Managed reference (byref) to a type.
    ByRef(Box<SsaType>),

    /// Typed reference (System.TypedReference).
    TypedReference,

    /// Generic type parameter (e.g., `!0`, `!1`).
    ///
    /// The `u32` is the parameter index.
    GenericParam(u32),

    /// Generic method parameter (e.g., `!!0`, `!!1`).
    ///
    /// The `u32` is the parameter index.
    MethodGenericParam(u32),

    /// Function pointer type.
    FnPtr(Box<FnPtrSig>),

    /// Known null constant (more precise than Object).
    Null,

    /// Type not yet inferred or unknown.
    ///
    /// This is used during type inference before a type is determined.
    Unknown,

    /// Type that varies depending on control flow (for incomplete inference).
    Varying,
}

/// Function pointer signature.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FnPtrSig {
    /// Return type.
    pub ret: SsaType,
    /// Parameter types.
    pub params: Vec<SsaType>,
    /// The signature's first byte: calling convention kind and flags, as
    /// [`SignatureMethod::calling_convention`] gives it.
    pub call_conv: u8,
    /// The return type's custom modifiers. An unmanaged pointer's platform convention
    /// (`delegate* unmanaged[Cdecl]`) is one of them.
    pub ret_modifiers: CustomModifiers,
    /// Each parameter's custom modifiers, in parameter order.
    pub param_modifiers: Vec<CustomModifiers>,
}

impl FnPtrSig {
    /// The function pointer type a method signature describes.
    fn from_signature(signature: &SignatureMethod, assembly: &CilObject, depth: usize) -> Self {
        let parameter = |param: &SignatureParameter| {
            let base = SsaType::from_signature_at(&param.base, assembly, depth);
            if param.by_ref {
                SsaType::ByRef(Box::new(base))
            } else {
                base
            }
        };
        Self {
            ret: parameter(&signature.return_type),
            params: signature.params.iter().map(parameter).collect(),
            call_conv: signature.calling_convention(),
            ret_modifiers: signature.return_type.modifiers.clone(),
            param_modifiers: signature
                .params
                .iter()
                .map(|param| param.modifiers.clone())
                .collect(),
        }
    }
}

/// Classification of types by their storage requirements.
///
/// Used for local variable coalescing to determine which types can share
/// the same storage slot. Types in the same class can be coalesced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TypeClass {
    /// 32-bit integer types (I32, U32, Bool, Char, I16, U16, I8, U8).
    ///
    /// All these types are stored as 4 bytes on the CLR evaluation stack.
    Int32,
    /// 64-bit integer types (I64, U64).
    Int64,
    /// 32-bit floating point (F32).
    Float32,
    /// 64-bit floating point (F64).
    Float64,
    /// Reference types (Object, String, Class, Array, etc.).
    ///
    /// All reference types are pointer-sized.
    Reference,
    /// Native-sized integers (IntPtr, UIntPtr).
    ///
    /// Platform-dependent size (4 or 8 bytes).
    NativeInt,
    /// Other/unknown types that cannot be coalesced.
    Other,
}

impl SsaType {
    /// Calls `visit` with every metadata token the type names, however deep:
    /// a class or value type, the base and arguments of an instantiation, the
    /// element or pointee of an array, pointer or reference, and a function
    /// pointer's return and parameter types and custom modifiers. A load or
    /// store of the type, or the TypeSpec interned for it, writes them.
    pub fn visit_tokens(&self, visit: &mut impl FnMut(Token)) {
        match self {
            Self::Class(type_ref) | Self::ValueType(type_ref) => visit(type_ref.token()),
            Self::GenericInst(base, args) => {
                base.visit_tokens(visit);
                for arg in args {
                    arg.visit_tokens(visit);
                }
            }
            Self::Array(element, _) | Self::Pointer(element) | Self::ByRef(element) => {
                element.visit_tokens(visit);
            }
            Self::FnPtr(signature) => {
                signature.ret.visit_tokens(visit);
                for param in &signature.params {
                    param.visit_tokens(visit);
                }
                for modifier in signature
                    .ret_modifiers
                    .iter()
                    .chain(signature.param_modifiers.iter().flatten())
                {
                    visit(modifier.modifier_type);
                }
            }
            Self::Void
            | Self::Bool
            | Self::I8
            | Self::U8
            | Self::I16
            | Self::U16
            | Self::I32
            | Self::U32
            | Self::I64
            | Self::U64
            | Self::NativeInt
            | Self::NativeUInt
            | Self::F32
            | Self::F64
            | Self::Char
            | Self::Object
            | Self::String
            | Self::TypedReference
            | Self::GenericParam(_)
            | Self::MethodGenericParam(_)
            | Self::Null
            | Self::Unknown
            | Self::Varying => {}
        }
    }

    /// This type with its generic parameters replaced by the arguments of the
    /// instantiation it was read through: `!n` by `type_args[n]` and `!!n` by
    /// `method_args[n]`.
    ///
    /// A member's signature is written in its declaring type's own terms, so a
    /// field declared `class Node<!0>` read through `Node<!!0>` holds a
    /// `Node<!!0>`. Both kinds are replaced in one pass, since the arguments
    /// belong to the reader's context: the `!!0` a class argument brings in
    /// is the reader's own, not the called method's. `None` leaves that kind
    /// of parameter as it is; a parameter the instantiation does not supply
    /// becomes `Unknown`.
    #[must_use]
    pub fn substitute_generic_params(
        self,
        type_args: Option<&[SsaType]>,
        method_args: Option<&[SsaType]>,
    ) -> SsaType {
        let substitute = |ty: SsaType| ty.substitute_generic_params(type_args, method_args);
        match self {
            Self::GenericParam(idx) => match type_args {
                Some(args) => args.get(idx as usize).cloned().unwrap_or(Self::Unknown),
                None => Self::GenericParam(idx),
            },
            Self::MethodGenericParam(idx) => match method_args {
                Some(args) => args.get(idx as usize).cloned().unwrap_or(Self::Unknown),
                None => Self::MethodGenericParam(idx),
            },
            Self::Array(elem, rank) => Self::Array(Box::new(substitute(*elem)), rank),
            Self::ByRef(inner) => Self::ByRef(Box::new(substitute(*inner))),
            Self::Pointer(inner) => Self::Pointer(Box::new(substitute(*inner))),
            Self::GenericInst(base, args) => Self::GenericInst(
                Box::new(substitute(*base)),
                args.into_iter().map(substitute).collect(),
            ),
            Self::FnPtr(sig) => {
                let FnPtrSig {
                    ret,
                    params,
                    call_conv,
                    ret_modifiers,
                    param_modifiers,
                } = *sig;
                Self::FnPtr(Box::new(FnPtrSig {
                    ret: substitute(ret),
                    params: params.into_iter().map(substitute).collect(),
                    call_conv,
                    ret_modifiers,
                    param_modifiers,
                }))
            }
            other => other,
        }
    }

    /// Returns `true` if this is a primitive numeric or boolean type.
    #[must_use]
    pub const fn is_primitive(&self) -> bool {
        matches!(
            self,
            Self::Bool
                | Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::NativeInt
                | Self::NativeUInt
                | Self::F32
                | Self::F64
                | Self::Char
        )
    }

    /// Returns `true` if this is an integer type (signed or unsigned).
    #[must_use]
    pub const fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::I8
                | Self::U8
                | Self::I16
                | Self::U16
                | Self::I32
                | Self::U32
                | Self::I64
                | Self::U64
                | Self::NativeInt
                | Self::NativeUInt
        )
    }

    /// Returns `true` if this is a floating-point type.
    #[must_use]
    pub const fn is_float(&self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    /// Returns `true` if this is a reference type (can be null).
    #[must_use]
    pub fn is_reference(&self) -> bool {
        match self {
            Self::Object | Self::String | Self::Class(_) | Self::Array(_, _) | Self::Null => true,
            Self::GenericInst(base, _) => base.is_reference(),
            _ => false,
        }
    }

    /// Returns `true` if this is a value type (struct).
    #[must_use]
    pub const fn is_value_type(&self) -> bool {
        matches!(self, Self::ValueType(_)) || self.is_primitive()
    }

    /// Returns `true` if this is an array type.
    #[must_use]
    pub const fn is_array(&self) -> bool {
        matches!(self, Self::Array(_, _))
    }

    /// Returns `true` if this is a pointer type (managed or unmanaged).
    #[must_use]
    pub const fn is_pointer(&self) -> bool {
        matches!(self, Self::Pointer(_) | Self::ByRef(_))
    }

    /// Returns `true` if this is the void type.
    #[must_use]
    pub const fn is_void(&self) -> bool {
        matches!(self, Self::Void)
    }

    /// Returns `true` if this type is unknown or not yet inferred.
    #[must_use]
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown | Self::Varying)
    }

    /// Returns `true` if this is the null type.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Returns `true` if this is a generic parameter.
    #[must_use]
    pub const fn is_generic_param(&self) -> bool {
        matches!(self, Self::GenericParam(_) | Self::MethodGenericParam(_))
    }

    /// Returns the element type if this is an array.
    #[must_use]
    pub fn array_element_type(&self) -> Option<&SsaType> {
        match self {
            Self::Array(elem, _) => Some(elem),
            _ => None,
        }
    }

    /// Returns the array rank (number of dimensions) if this is an array.
    #[must_use]
    pub const fn array_rank(&self) -> Option<u32> {
        match self {
            Self::Array(_, rank) => Some(*rank),
            _ => None,
        }
    }

    /// Returns the pointed-to type if this is a pointer or byref.
    #[must_use]
    pub fn pointee_type(&self) -> Option<&SsaType> {
        match self {
            Self::Pointer(inner) | Self::ByRef(inner) => Some(inner),
            _ => None,
        }
    }

    /// Returns the size in bytes for primitive types, if known.
    ///
    /// Returns `None` for reference types and types with platform-dependent sizes.
    #[must_use]
    pub const fn size_bytes(&self) -> Option<u32> {
        match self {
            Self::Bool | Self::I8 | Self::U8 => Some(1),
            Self::I16 | Self::U16 | Self::Char => Some(2),
            Self::I32 | Self::U32 | Self::F32 => Some(4),
            Self::I64 | Self::U64 | Self::F64 => Some(8),
            // NativeInt/NativeUInt and pointers are platform-dependent
            _ => None,
        }
    }

    /// The class this type computes in as an operand of arithmetic, when it
    /// can be one: `int32` for every integer up to 32 bits, `int64`,
    /// `native int`, the float it is, or the pointer it is.
    #[must_use]
    pub fn arithmetic_class(&self) -> Option<Self> {
        match self {
            Self::Bool
            | Self::I8
            | Self::U8
            | Self::I16
            | Self::U16
            | Self::Char
            | Self::I32
            | Self::U32 => Some(Self::I32),
            Self::I64 | Self::U64 => Some(Self::I64),
            Self::NativeInt | Self::NativeUInt => Some(Self::NativeInt),
            Self::F32 | Self::F64 | Self::Pointer(_) | Self::ByRef(_) => Some(self.clone()),
            _ => None,
        }
    }

    /// The value type a value of this type is, plain or instantiated: an enum
    /// nested in a generic type (`Outer<T>.Flags`) is an instantiation of it.
    /// An enum's integer is stated only by its definition, which this names.
    #[must_use]
    pub fn value_type_ref(&self) -> Option<TypeRef> {
        match self {
            Self::ValueType(type_ref) => Some(*type_ref),
            Self::GenericInst(base, _) => match **base {
                Self::ValueType(type_ref) => Some(type_ref),
                _ => None,
            },
            _ => None,
        }
    }

    /// Whether a value of this type computes as a number the type does not
    /// state: an enum ([`Self::value_type_ref`]), or a generic parameter,
    /// whose instantiation says. Two values of one such type compute as a
    /// value of it.
    fn computes_unstated(&self) -> bool {
        self.value_type_ref().is_some()
            || matches!(self, Self::GenericParam(_) | Self::MethodGenericParam(_))
    }

    /// The result type of a unary numeric operation on an operand of this
    /// type (a negation, a complement or a shift of the value, ECMA-335
    /// III.1.5): the operand's class, and a value of its own type for an enum
    /// or a generic parameter, whose number is the one its values are. `None`
    /// for a type that is no number.
    #[must_use]
    pub fn unary_numeric(&self) -> Option<Self> {
        if self.computes_unstated() {
            return Some(self.clone());
        }
        self.arithmetic_class()
    }

    /// The result type of a binary numeric operation on operands of types
    /// `left` and `right`, by ECMA-335's binary numeric table (III.1.5).
    ///
    /// Equal integer classes keep their class, `int32` with `native int` is
    /// `native int`, floats are the wider float, and - for `add` and `sub`
    /// (`additive`) - a pointer moved by an integer stays that pointer while
    /// the distance between two pointers is a `native int`. A value type -
    /// an enum - with an integer computes in that integer's class; two values
    /// of one enum or generic parameter are a value of it, and of two enums a
    /// value of the first, whose integer a valid program shares with the
    /// second. `None` for a combination the table does not allow.
    #[must_use]
    pub fn binary_numeric(left: &Self, right: &Self, additive: bool) -> Option<Self> {
        // An enum is its underlying integer on the stack, which its type here
        // does not say; computing with an integer, it is that integer's class
        // (`flags & 0x...L` is a `long`).
        let integer = |ty: &Self| matches!(ty, Self::I32 | Self::I64 | Self::NativeInt);
        let (a, b) = match (left.arithmetic_class(), right.arithmetic_class()) {
            (Some(a), Some(b)) => (a, b),
            // Two values of one enum, or of one generic parameter, compute as
            // its number, whichever that is, and the result is a value of it.
            // Two enums' values compute as the one integer a valid program
            // gives both, which the first names as well as the second.
            (None, None)
                if left.computes_unstated() && left == right
                    || left.value_type_ref().is_some() && right.value_type_ref().is_some() =>
            {
                return Some(left.clone());
            }
            (Some(a), None) if right.value_type_ref().is_some() && integer(&a) => (a.clone(), a),
            (None, Some(b)) if left.value_type_ref().is_some() && integer(&b) => (b.clone(), b),
            _ => return None,
        };
        let pointer = |ty: &Self| matches!(ty, Self::Pointer(_) | Self::ByRef(_));
        let integer = |ty: &Self| matches!(ty, Self::I32 | Self::NativeInt);
        match (&a, &b) {
            (Self::F32 | Self::F64, Self::F32 | Self::F64) => {
                if a == Self::F64 || b == Self::F64 {
                    Some(Self::F64)
                } else {
                    Some(Self::F32)
                }
            }
            _ if a == b && !pointer(&a) => Some(a),
            (Self::I32, Self::NativeInt) | (Self::NativeInt, Self::I32) => Some(Self::NativeInt),
            _ if additive && pointer(&a) && integer(&b) => Some(a),
            _ if additive && integer(&a) && pointer(&b) => Some(b),
            _ if additive && pointer(&a) && pointer(&b) => Some(Self::NativeInt),
            _ => None,
        }
    }

    /// Returns the stack slot type for this SSA type.
    ///
    /// CIL uses a normalized set of types on the evaluation stack:
    /// - All integer types smaller than 32 bits become I32
    /// - Float types stay as-is (F32 becomes F64 in some contexts)
    /// - References stay as references
    #[must_use]
    pub fn stack_type(&self) -> SsaType {
        match self {
            // Small integers promote to I32 on the stack
            Self::Bool | Self::I8 | Self::U8 | Self::I16 | Self::U16 | Self::Char | Self::I32 => {
                Self::I32
            }
            Self::U32 => Self::I32, // Treated as I32 on stack
            Self::I64 | Self::U64 => Self::I64,
            Self::NativeInt | Self::NativeUInt => Self::NativeInt,
            Self::F32 | Self::F64 => Self::F64, // F is typically F64 on stack
            // Reference types stay as-is
            _ => self.clone(),
        }
    }

    /// Returns the storage class of this type.
    ///
    /// Used for local variable coalescing to determine which types can share
    /// the same storage slot without requiring conversion.
    #[must_use]
    pub fn storage_class(&self) -> TypeClass {
        match self {
            // 32-bit integers (all stored as 4 bytes on the CLR stack)
            Self::I32
            | Self::U32
            | Self::Bool
            | Self::Char
            | Self::I16
            | Self::U16
            | Self::I8
            | Self::U8 => TypeClass::Int32,

            // 64-bit integers
            Self::I64 | Self::U64 => TypeClass::Int64,

            // Floating point
            Self::F32 => TypeClass::Float32,
            Self::F64 => TypeClass::Float64,

            // Native integers
            Self::NativeInt | Self::NativeUInt => TypeClass::NativeInt,

            // Reference types and value types (all pointer-sized on stack).
            // Note that value-types share this class with reference-types
            // only for the purposes of local-slot coalescing — CIL still
            // forbids `stloc` of a value-type into a slot declared as a
            // reference-type. `is_compatible_for_storage` enforces the
            // exact-match rule within this class to keep the two apart.
            Self::Object
            | Self::String
            | Self::Class(_)
            | Self::ValueType(_)
            | Self::Array(_, _)
            | Self::ByRef(_)
            | Self::Pointer(_)
            | Self::TypedReference => TypeClass::Reference,

            // Generic instantiation delegates to its base type
            Self::GenericInst(base, _) => base.storage_class(),

            // Other types
            Self::Void
            | Self::Unknown
            | Self::Varying
            | Self::Null
            | Self::GenericParam(_)
            | Self::MethodGenericParam(_)
            | Self::FnPtr(_) => TypeClass::Other,
        }
    }

    /// Checks if this type can share a local slot with another type.
    ///
    /// Two types are compatible for storage if they have the same size and
    /// alignment requirements, meaning they can be stored in the same local
    /// variable slot without data corruption.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::SsaType;
    ///
    /// // Same types are compatible
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::I32));
    ///
    /// // 32-bit integers can share slots
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::U32));
    /// assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Bool));
    ///
    /// // Reference types can share slots
    /// assert!(SsaType::Object.is_compatible_for_storage(&SsaType::String));
    ///
    /// // Different sizes are incompatible
    /// assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::I64));
    /// ```
    #[must_use]
    pub fn is_compatible_for_storage(&self, other: &SsaType) -> bool {
        if self == other {
            return true;
        }

        // Unknown types are conservatively compatible
        if matches!(self, Self::Unknown) || matches!(other, Self::Unknown) {
            return true;
        }

        if self.storage_class() != other.storage_class() {
            return false;
        }

        // Reference types require exact type match for CIL local sharing.
        // The CIL verifier checks assignment compatibility on stloc (the value
        // must be assignable to the declared type) and the declared type is what
        // ldloc pushes. Different reference types (e.g., string vs char[]) in
        // the same local would require the LUB (object) as declared type, but
        // then ldloc pushes object and downstream code expecting the specific
        // type would fail verification. Requiring exact match avoids this.
        if self.storage_class() == TypeClass::Reference {
            return false; // self != other was already checked above
        }

        // For value-type classes (Int32, Int64, Float, NativeInt), same-class
        // types can share slots. The CIL evaluation stack widens all sub-int32
        // types to int32, so stloc/ldloc of any Int32-class type is compatible.
        true
    }

    /// Merges two types at a control flow join point.
    ///
    /// Returns the common type if compatible, or `Varying` if incompatible.
    #[must_use]
    pub fn merge(&self, other: &SsaType) -> SsaType {
        if self == other {
            return self.clone();
        }

        // Unknown can be refined
        if matches!(self, Self::Unknown) {
            return other.clone();
        }
        if matches!(other, Self::Unknown) {
            return self.clone();
        }

        // Null can merge with any reference type
        if matches!(self, Self::Null) && other.is_reference() {
            return other.clone();
        }
        if matches!(other, Self::Null) && self.is_reference() {
            return self.clone();
        }

        // If types are incompatible, return Varying
        Self::Varying
    }

    /// Converts this SSA type to a `TypeSignature` for signature encoding.
    ///
    /// This enables generating local variable signatures from SSA type information.
    /// Analysis-only types (`Unknown`, `Null`, `Varying`) are converted to `Object`
    /// as a safe fallback.
    ///
    /// # Returns
    ///
    /// The corresponding `TypeSignature` that can be used for signature encoding.
    #[must_use]
    pub fn to_type_signature(&self) -> TypeSignature {
        match self {
            Self::Void => TypeSignature::Void,
            Self::Bool => TypeSignature::Boolean,
            Self::I8 => TypeSignature::I1,
            Self::U8 => TypeSignature::U1,
            Self::I16 => TypeSignature::I2,
            Self::U16 => TypeSignature::U2,
            Self::I32 => TypeSignature::I4,
            Self::U32 => TypeSignature::U4,
            Self::I64 => TypeSignature::I8,
            Self::U64 => TypeSignature::U8,
            Self::NativeInt => TypeSignature::I,
            Self::NativeUInt => TypeSignature::U,
            Self::F32 => TypeSignature::R4,
            Self::F64 => TypeSignature::R8,
            Self::Char => TypeSignature::Char,
            Self::String => TypeSignature::String,
            Self::Class(type_ref) => TypeSignature::Class(type_ref.token()),
            Self::ValueType(type_ref) => TypeSignature::ValueType(type_ref.token()),
            Self::GenericInst(base, type_args) => TypeSignature::GenericInst(
                Box::new(base.to_type_signature()),
                type_args.iter().map(SsaType::to_type_signature).collect(),
            ),
            Self::Array(elem, 1) => TypeSignature::SzArray(SignatureSzArray {
                modifiers: CustomModifiers::default(),
                base: Box::new(elem.to_type_signature()),
            }),
            Self::Array(elem, rank) => TypeSignature::Array(SignatureArray {
                base: Box::new(elem.to_type_signature()),
                rank: *rank,
                dimensions: (0..*rank)
                    .map(|_| ArrayDimensions {
                        size: None,
                        lower_bound: None,
                    })
                    .collect(),
            }),
            Self::Pointer(inner) => TypeSignature::Ptr(SignaturePointer {
                modifiers: CustomModifiers::default(),
                base: Box::new(inner.to_type_signature()),
            }),
            Self::ByRef(inner) => TypeSignature::ByRef(Box::new(inner.to_type_signature())),
            Self::TypedReference => TypeSignature::TypedByRef,
            Self::GenericParam(idx) => TypeSignature::GenericParamType(*idx),
            Self::MethodGenericParam(idx) => TypeSignature::GenericParamMethod(*idx),
            Self::FnPtr(sig) => {
                let mut signature = SignatureMethod::default();
                // The byte came from a signature, so it names a method signature kind.
                if signature.set_calling_convention(sig.call_conv).is_err() {
                    signature.default = true;
                }
                // Safe: .NET methods have at most ~65535 parameters
                #[allow(clippy::cast_possible_truncation)]
                let param_count = sig.params.len() as u32;
                signature.param_count = param_count;
                signature.return_type = SignatureParameter {
                    modifiers: sig.ret_modifiers.clone(),
                    by_ref: false,
                    base: sig.ret.to_type_signature(),
                };
                signature.params = sig
                    .params
                    .iter()
                    .enumerate()
                    .map(|(index, param)| SignatureParameter {
                        modifiers: sig.param_modifiers.get(index).cloned().unwrap_or_default(),
                        by_ref: false,
                        base: param.to_type_signature(),
                    })
                    .collect();
                TypeSignature::FnPtr(Box::new(signature))
            }
            // Object and analysis-only types. Runtime-handle variants have
            // been removed from `SsaType` — construction sites now always
            // produce `ValueType(token)` for them via
            // [`resolve_runtime_handle_type`], so they never land here.
            Self::Object | Self::Null | Self::Unknown | Self::Varying => TypeSignature::Object,
        }
    }

    /// Creates an `SsaType` from a `CilFlavor`.
    ///
    /// This converts the metadata type flavor to the SSA type representation.
    /// For complex types (arrays, pointers, generic instances), a token is needed
    /// to create a proper type reference.
    ///
    /// # Arguments
    ///
    /// * `flavor` - The CIL type flavor to convert
    /// * `token` - The metadata token for creating type references
    #[must_use]
    pub fn from_cil_flavor(flavor: &CilFlavor, token: Token) -> Self {
        match flavor {
            // Primitive types
            CilFlavor::Void => Self::Void,
            CilFlavor::Boolean => Self::Bool,
            CilFlavor::Char => Self::Char,
            CilFlavor::I1 => Self::I8,
            CilFlavor::U1 => Self::U8,
            CilFlavor::I2 => Self::I16,
            CilFlavor::U2 => Self::U16,
            CilFlavor::I4 => Self::I32,
            CilFlavor::U4 => Self::U32,
            CilFlavor::I8 => Self::I64,
            CilFlavor::U8 => Self::U64,
            CilFlavor::R4 => Self::F32,
            CilFlavor::R8 => Self::F64,
            CilFlavor::I => Self::NativeInt,
            CilFlavor::U => Self::NativeUInt,
            CilFlavor::Object => Self::Object,
            CilFlavor::String => Self::String,

            // Complex types
            CilFlavor::Array { rank, .. } => Self::Array(Box::new(Self::Unknown), *rank),
            CilFlavor::Pointer => Self::Pointer(Box::new(Self::Unknown)),
            CilFlavor::ByRef => Self::ByRef(Box::new(Self::Unknown)),
            CilFlavor::GenericParameter { index, method } => {
                if *method {
                    Self::MethodGenericParam(*index)
                } else {
                    Self::GenericParam(*index)
                }
            }

            // Type categories
            CilFlavor::GenericInstance | CilFlavor::Class | CilFlavor::Interface => {
                Self::Class(TypeRef::new(token))
            }
            // ValueType and TypedReference (which is a value type)
            CilFlavor::ValueType | CilFlavor::TypedRef { .. } => {
                Self::ValueType(TypeRef::new(token))
            }

            CilFlavor::Pinned | CilFlavor::FnPtr { .. } | CilFlavor::Unknown => Self::Unknown,
        }
    }

    /// Creates an `SsaType` from a `TypeSignature`.
    ///
    /// This converts a metadata type signature to the SSA type representation.
    /// For class and value types, the assembly context is used to resolve
    /// type tokens to determine if they are primitives.
    ///
    /// # Arguments
    ///
    /// * `signature` - The type signature to convert
    /// * `assembly` - Assembly context for resolving type tokens
    #[must_use]
    pub fn from_type_signature(signature: &TypeSignature, assembly: &CilObject) -> Self {
        Self::from_signature_at(signature, assembly, 0)
    }

    /// The type of a local variable: its type, behind a managed pointer for a `ref` local.
    #[must_use]
    pub fn from_local(local: &SignatureLocalVariable, assembly: &CilObject) -> Self {
        let base = Self::from_type_signature(&local.base, assembly);
        if local.is_byref {
            Self::ByRef(Box::new(base))
        } else {
            base
        }
    }

    /// The type of a parameter or return value: its type, behind a managed pointer when the
    /// signature passes it by reference (`ref T`, ECMA-335 II.23.2.10).
    #[must_use]
    pub fn from_parameter(param: &SignatureParameter, assembly: &CilObject) -> Self {
        let base = Self::from_type_signature(&param.base, assembly);
        if param.by_ref {
            Self::ByRef(Box::new(base))
        } else {
            base
        }
    }

    /// [`from_type_signature`](Self::from_type_signature) for a type `depth`
    /// levels down.
    fn from_signature_at(signature: &TypeSignature, assembly: &CilObject, depth: usize) -> Self {
        if depth > MAX_TYPE_DEPTH {
            return Self::Unknown;
        }
        let nested = depth.saturating_add(1);
        match signature {
            // Primitive types
            TypeSignature::Void => Self::Void,
            TypeSignature::Boolean => Self::Bool,
            TypeSignature::Char => Self::Char,
            TypeSignature::I1 => Self::I8,
            TypeSignature::U1 => Self::U8,
            TypeSignature::I2 => Self::I16,
            TypeSignature::U2 => Self::U16,
            TypeSignature::I4 => Self::I32,
            TypeSignature::U4 => Self::U32,
            TypeSignature::I8 => Self::I64,
            TypeSignature::U8 => Self::U64,
            TypeSignature::R4 => Self::F32,
            TypeSignature::R8 => Self::F64,
            TypeSignature::I => Self::NativeInt,
            TypeSignature::U => Self::NativeUInt,

            // Reference types
            TypeSignature::String => Self::String,
            TypeSignature::Object | TypeSignature::Type | TypeSignature::Boxed => Self::Object,
            TypeSignature::TypedByRef => Self::TypedReference,

            // Class/ValueType with token. The element type says which of the
            // two the type is, and it is the only thing that does for a type
            // imported from another assembly: the registry has no definition
            // to read the kind from and guesses, so a `System.DateTime` it
            // cannot see comes back a class. Primitives are still recognised
            // by name, since `valuetype System.Int32` is an `int32`.
            TypeSignature::Class(token) => match Self::from_token_at(*token, assembly, nested) {
                Self::ValueType(type_ref) => Self::Class(type_ref),
                other => other,
            },
            TypeSignature::ValueType(token) => {
                match Self::from_token_at(*token, assembly, nested) {
                    Self::Class(type_ref) => Self::ValueType(type_ref),
                    other => other,
                }
            }

            // Arrays
            TypeSignature::SzArray(sz_array) => {
                let elem_type = Self::from_signature_at(&sz_array.base, assembly, nested);
                Self::Array(Box::new(elem_type), 1)
            }
            TypeSignature::Array(array) => {
                let elem_type = Self::from_signature_at(&array.base, assembly, nested);
                Self::Array(Box::new(elem_type), array.rank)
            }

            // Pointers and references
            TypeSignature::Ptr(ptr) => {
                let inner = Self::from_signature_at(&ptr.base, assembly, nested);
                Self::Pointer(Box::new(inner))
            }
            TypeSignature::ByRef(inner) => {
                let inner_type = Self::from_signature_at(inner, assembly, nested);
                Self::ByRef(Box::new(inner_type))
            }

            // Generic parameters
            TypeSignature::GenericParamType(index) => Self::GenericParam(*index),
            TypeSignature::GenericParamMethod(index) => Self::MethodGenericParam(*index),

            // Generic instantiation - preserve both base type and type arguments
            TypeSignature::GenericInst(base_type, type_args) => {
                let base = Self::from_signature_at(base_type, assembly, nested);
                let args = type_args
                    .iter()
                    .map(|a| Self::from_signature_at(a, assembly, nested))
                    .collect();
                Self::GenericInst(Box::new(base), args)
            }

            // Pinned - unwrap to inner type
            TypeSignature::Pinned(inner) => Self::from_signature_at(inner, assembly, nested),

            TypeSignature::FnPtr(signature) => Self::FnPtr(Box::new(FnPtrSig::from_signature(
                signature, assembly, nested,
            ))),

            // A modifier does not change the value's representation
            TypeSignature::ModifiedRequired(_, base) | TypeSignature::ModifiedOptional(_, base) => {
                Self::from_signature_at(base, assembly, nested)
            }

            // Special types - not representable
            TypeSignature::Sentinel
            | TypeSignature::Unknown
            | TypeSignature::Internal
            | TypeSignature::Modifier
            | TypeSignature::Reserved
            | TypeSignature::Field => Self::Unknown,
        }
    }

    /// Creates an `SsaType` from a type token by resolving it in the assembly.
    ///
    /// Handles TypeDef (0x02), TypeRef (0x01), and TypeSpec (0x1B) tokens.
    #[must_use]
    pub fn from_type_token(token: Token, assembly: &CilObject) -> Self {
        Self::from_token_at(token, assembly, 0)
    }

    /// [`from_type_token`](Self::from_type_token) for a type `depth` levels
    /// down.
    fn from_token_at(token: Token, assembly: &CilObject, depth: usize) -> Self {
        let table_id = token.table();

        match table_id {
            // TypeDef or TypeRef - look up in type registry
            0x02 | 0x01 => {
                let Some(cil_type) = assembly.types().get(&token) else {
                    return Self::Unknown;
                };

                let name = &cil_type.name;
                let namespace = &cil_type.namespace;

                // Check for well-known primitive types in System namespace
                if namespace == "System" {
                    if let Some(primitive) = Self::match_system_type(name) {
                        return primitive;
                    }
                }

                // Return Class or ValueType based on flavor
                if cil_type.flavor().is_value_type() {
                    Self::ValueType(TypeRef::new(token))
                } else {
                    Self::Class(TypeRef::new(token))
                }
            }

            // TypeSpec - generic instantiation or complex type, typed from its
            // own signature. The registry's entry for it carries a flavor
            // alone, and `GenericInstance` reads as a class whatever is being
            // instantiated: `Nullable<T>` and `List<T>.Enumerator` are structs.
            0x1B if depth <= MAX_TYPE_DEPTH => match Self::typespec_signature(token, assembly) {
                Some(signature) => {
                    Self::from_signature_at(&signature, assembly, depth.saturating_add(1))
                }
                None => assembly
                    .types()
                    .get(&token)
                    .map_or(Self::Unknown, |cil_type| {
                        Self::from_cil_flavor(cil_type.flavor(), token)
                    }),
            },

            // 0xF0 - artificial types created by TypeResolver for constructed types
            //         (generic instances, arrays, pointers, etc.)
            0xF0 => {
                let Some(cil_type) = assembly.types().get(&token) else {
                    return Self::Unknown;
                };
                match cil_type.flavor() {
                    CilFlavor::FnPtr { signature } => Self::FnPtr(Box::new(
                        FnPtrSig::from_signature(signature, assembly, depth.saturating_add(1)),
                    )),
                    flavor => Self::from_cil_flavor(flavor, token),
                }
            }

            // Unknown table, or nesting too deep to be well-formed
            _ => Self::Unknown,
        }
    }

    /// The signature a TypeSpec token stands for, read from its row.
    fn typespec_signature(token: Token, assembly: &CilObject) -> Option<TypeSignature> {
        let table = assembly.tables()?.table::<TypeSpecRaw>()?;
        let raw = table.get(token.row()).ok().flatten()?;
        let owned = raw.to_owned(assembly.blob()?).ok()?;
        Some(owned.signature.base.clone())
    }

    /// Matches a System namespace type name to its SSA primitive type.
    fn match_system_type(name: &str) -> Option<Self> {
        // Handle types that map through CilPrimitiveKind
        if let Some(kind) = wellknown::system_name_to_primitive(name) {
            return Some(Self::from_cil_flavor(&CilFlavor::from(kind), Token::new(0)));
        }
        // Non-primitive System types
        match name {
            "TypedReference" => Some(Self::TypedReference),
            _ => None,
        }
    }
}

impl fmt::Display for SsaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Bool => write!(f, "bool"),
            Self::I8 => write!(f, "i8"),
            Self::U8 => write!(f, "u8"),
            Self::I16 => write!(f, "i16"),
            Self::U16 => write!(f, "u16"),
            Self::I32 => write!(f, "i32"),
            Self::U32 => write!(f, "u32"),
            Self::I64 => write!(f, "i64"),
            Self::U64 => write!(f, "u64"),
            Self::NativeInt => write!(f, "nint"),
            Self::NativeUInt => write!(f, "nuint"),
            Self::F32 => write!(f, "f32"),
            Self::F64 => write!(f, "f64"),
            Self::Char => write!(f, "char"),
            Self::Object => write!(f, "object"),
            Self::String => write!(f, "string"),
            Self::Class(t) => write!(f, "class {t}"),
            Self::ValueType(t) => write!(f, "valuetype {t}"),
            Self::GenericInst(base, args) => {
                write!(f, "{base}<")?;
                for (i, arg) in args.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                write!(f, ">")
            }
            Self::Array(elem, 1) => write!(f, "{elem}[]"),
            Self::Array(elem, rank) => write!(f, "{elem}[{rank}d]"),
            Self::Pointer(inner) => write!(f, "{inner}*"),
            Self::ByRef(inner) => write!(f, "{inner}&"),
            Self::TypedReference => write!(f, "typedref"),
            Self::GenericParam(idx) => write!(f, "!{idx}"),
            Self::MethodGenericParam(idx) => write!(f, "!!{idx}"),
            Self::FnPtr(_) => write!(f, "fnptr"),
            Self::Null => write!(f, "null"),
            Self::Unknown => write!(f, "?"),
            Self::Varying => write!(f, "varying"),
        }
    }
}

/// Resolves a corelib fully-qualified type name (e.g.
/// `"System.RuntimeFieldHandle"`) to [`SsaType::ValueType`] with a real
/// TypeRef / TypeDef token.
///
/// Prefers the TypeRef importing the type from the module's core library
/// (see [`TypeRegistry::get_corelib_typeref`](crate::metadata::typesystem::TypeRegistry::get_corelib_typeref)):
/// that's the import the rest of the assembly already references, and it
/// keeps the signatures we emit pointing at the row that survives cleanup.
/// Falls back to `TypeRegistry::get_by_fullname` (which filters TypeRefs
/// out but returns any TypeDef / external match of the same fullname).
/// Returns [`SsaType::Unknown`] only when no row matches; callers log a
/// warning in that case since it indicates missing corelib references.
///
/// Used at SSA construction time so every `ldtoken` / handle-producing
/// op gets a `valuetype [mscorlib]System.Runtime*Handle` token baked
/// into the variable's type — replacing the old tokenless
/// `RuntimeFieldHandle` / `RuntimeMethodHandle` / `RuntimeTypeHandle`
/// variants that could not round-trip through
/// [`SsaType::to_type_signature`].
#[must_use]
pub fn resolve_corelib_valuetype(assembly: &CilObject, fullname: &str) -> SsaType {
    let registry = assembly.types();
    if let Some(ty) = registry
        .get_corelib_typeref(fullname)
        .or_else(|| registry.get_by_fullname(fullname, true))
    {
        return SsaType::ValueType(TypeRef::new(ty.token));
    }
    log::warn!(
        "resolve_corelib_valuetype: no TypeRef or TypeDef for {fullname:?}; \
         SSA type falls back to Unknown — the assembly appears to be missing \
         corelib imports for this type"
    );
    SsaType::Unknown
}

/// Trait for providing type information during SSA construction.
///
/// This abstracts the type resolution API so that the SSA converter can work
/// with different sources of type information:
/// - `TypeContext` for real assembly metadata
/// - `TestTypeProvider` for synthetic CIL in tests
pub trait TypeProvider {
    /// Returns the type of a method argument by index.
    fn arg_type(&self, idx: u16) -> SsaType;

    /// Returns the type of a local variable by index.
    fn local_type(&self, idx: u16) -> SsaType;

    /// Returns the return type of a called method.
    fn call_return_type(&self, token: Token) -> SsaType;

    /// Returns the type of a newly constructed object (for newobj instruction).
    fn newobj_type(&self, ctor_token: Token) -> SsaType;

    /// Returns the type of a field.
    fn field_type(&self, field_token: Token) -> SsaType;

    /// Returns the return type of a `calli` (indirect call) from its `StandAloneSig` token.
    fn call_indirect_return_type(&self, sig_token: Token) -> SsaType;

    /// Returns the assembly reference, if available.
    fn assembly(&self) -> Option<&CilObject>;

    /// Returns the integer an enum value type is on the evaluation stack: its
    /// underlying type (ECMA-335 II.14.3, I.8.5.2), or `None` for a value type
    /// that is no enum or whose definition is not known.
    ///
    /// An enum's values compute as that integer, so `flags1 & flags2` of a
    /// `ulong` enum is a `long`; the value type alone does not say which
    /// integer it is. `None` by default, for a provider with no metadata.
    fn enum_underlying(&self, _value_type: &TypeRef) -> Option<SsaType> {
        None
    }

    /// Returns the original local variable type signatures for code generation.
    fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        None
    }

    /// Returns `true` when the runtime zeroes the method's locals before it
    /// runs (the body's `.locals init` flag), so a local read before any write
    /// holds zero or null.
    ///
    /// Without the flag a local's initial contents are unspecified, and nothing
    /// may be assumed about a read of one.
    fn locals_zero_initialized(&self) -> bool {
        true
    }

    /// Returns the exception type for a catch handler, identified by its handler index.
    ///
    /// This is used during SSA construction to type the exception object that the
    /// CLR pushes onto the stack at catch handler entry (ECMA-335 §I.12.4.2.5).
    ///
    /// Returns `SsaType::Object` by default (all .NET exceptions are reference types).
    /// Implementations may return a more specific type (e.g., `SsaType::Class`) if
    /// the catch clause's type token can be resolved.
    fn handler_catch_type(&self, _handler_index: usize) -> SsaType {
        SsaType::Object
    }
}

/// Provides type information during SSA construction.
///
/// This struct holds references to the method being converted and the containing
/// assembly, allowing type lookups for arguments, locals, and call return types
/// without duplicating type information.
///
/// # Usage
///
/// ```
/// use dotscope::{analysis::TypeContext, CilObject};
///
/// let assembly = CilObject::from_path("tests/samples/crafted_2.exe")?;
/// # let entry = assembly.methods().iter().next().expect("the sample has methods");
/// # let method = entry.value();
/// let ctx = TypeContext::new(method, &assembly);
/// let arg0_type = ctx.arg_type(0);
/// let local2_type = ctx.local_type(2);
/// let ret_type = ctx.call_return_type(method.token);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct TypeContext<'a> {
    /// The method being converted to SSA form.
    method: &'a Method,
    /// The assembly containing the method.
    assembly: &'a CilObject,
    /// The method's local variable signatures, read from its LocalVarSig blob the first time
    /// they are asked for: the lift asks for a local's type at every load and store of it.
    local_signatures: OnceLock<Option<Vec<SignatureLocalVariable>>>,
    /// Each local's type, resolved from those signatures once.
    local_types: OnceLock<Box<[SsaType]>>,
}

impl<'a> TypeContext<'a> {
    /// Creates a new type context for SSA construction.
    #[must_use]
    pub fn new(method: &'a Method, assembly: &'a CilObject) -> Self {
        Self {
            method,
            assembly,
            local_signatures: OnceLock::new(),
            local_types: OnceLock::new(),
        }
    }

    /// Returns the assembly reference.
    #[must_use]
    pub fn assembly(&self) -> &'a CilObject {
        self.assembly
    }

    /// Returns the type of a method argument by index.
    ///
    /// For instance methods, argument 0 is `this`. Parameter indices are offset
    /// by 1 for instance methods.
    #[must_use]
    pub fn arg_type(&self, idx: u16) -> SsaType {
        let idx = idx as usize;

        // For instance methods, arg 0 is 'this'
        if self.method.signature.has_this {
            if idx == 0 {
                // 'this' is the declaring type's instance, or a managed pointer to it
                // when the type is a value type (ECMA-335 II.13.3)
                return self
                    .method
                    .declaring_type_rc()
                    .map_or(SsaType::Object, |dt| {
                        let declaring = SsaType::from_type_token(dt.token, self.assembly);
                        if dt.flavor().is_value_type() {
                            SsaType::ByRef(Box::new(declaring))
                        } else {
                            declaring
                        }
                    });
            }
            // Adjust for 'this' offset
            if let Some(param) = self.method.signature.params.get(idx.saturating_sub(1)) {
                let ty = SsaType::from_parameter(param, self.assembly);
                return self.validate_generic_params(ty);
            }
        } else if let Some(param) = self.method.signature.params.get(idx) {
            let ty = SsaType::from_parameter(param, self.assembly);
            return self.validate_generic_params(ty);
        }

        SsaType::Unknown
    }

    /// Returns the type of a local variable by index.
    ///
    /// Prefers raw blob signatures from `local_type_signatures()` to avoid the
    /// lossy round-trip through `to_signature_local()` → `type_ref_to_signature()`,
    /// which produces artificial 0xF0 tokens for constructed types (generic
    /// instances, arrays, pointers).
    ///
    /// Every local's type is resolved the first time one is asked for, and kept.
    #[must_use]
    pub fn local_type(&self, idx: u16) -> SsaType {
        self.local_types
            .get_or_init(|| {
                let resolve = |sig: &SignatureLocalVariable| {
                    self.validate_generic_params(SsaType::from_local(sig, self.assembly))
                };
                // Prefer raw blob signatures which preserve original metadata tokens.
                // Fall back to Method::get_local_type_signatures() only when the raw
                // blob path is unavailable (e.g., missing body or local_var_sig_token).
                match self.parsed_local_signatures() {
                    Some(signatures) => signatures.iter().map(resolve).collect(),
                    None => self
                        .method
                        .get_local_type_signatures()
                        .map(|signatures| signatures.iter().map(resolve).collect())
                        .unwrap_or_default(),
                }
            })
            .get(usize::from(idx))
            .cloned()
            .unwrap_or(SsaType::Unknown)
    }

    /// Returns the return type of a called method.
    ///
    /// Handles MethodDef (0x06), MemberRef (0x0A), and MethodSpec (0x2B) tokens.
    #[must_use]
    pub fn call_return_type(&self, token: Token) -> SsaType {
        let table_id = token.table();

        match table_id {
            // MethodDef - look up in methods
            0x06 => self
                .assembly
                .methods()
                .get(&token)
                .map_or(SsaType::Unknown, |entry| {
                    let method = entry.value();
                    SsaType::from_parameter(&method.signature.return_type, self.assembly)
                }),

            // MemberRef - the signature's return type, in the terms of the
            // instantiation the method is called through
            0x0A => self
                .member_ref_return(token)
                .map_or(SsaType::Unknown, |(ret, type_args)| {
                    ret.substitute_generic_params(type_args.as_deref(), None)
                }),

            // MethodSpec - the underlying method's return type with the class
            // and method arguments substituted together
            0x2B => {
                let Some(entry) = self.assembly.method_specs().get(&token) else {
                    return SsaType::Unknown;
                };
                let spec = entry.value();
                let Some(method_token) = spec.method.token() else {
                    return SsaType::Unknown;
                };
                let method_args: Vec<SsaType> = spec
                    .instantiation
                    .generic_args
                    .iter()
                    .map(|arg| SsaType::from_type_signature(arg, self.assembly))
                    .collect();
                let (ret, type_args) = if method_token.table() == 0x0A {
                    match self.member_ref_return(method_token) {
                        Some(found) => found,
                        None => return SsaType::Unknown,
                    }
                } else {
                    (self.call_return_type(method_token), None)
                };
                ret.substitute_generic_params(type_args.as_deref(), Some(&method_args))
            }

            _ => SsaType::Unknown,
        }
    }

    /// Returns the type of a newly constructed object (for newobj instruction).
    ///
    /// Extracts the declaring type from the constructor method token.
    #[must_use]
    pub fn newobj_type(&self, ctor_token: Token) -> SsaType {
        let table_id = ctor_token.table();

        match table_id {
            // MethodDef - get declaring type
            0x06 => self
                .assembly
                .methods()
                .get(&ctor_token)
                .and_then(|entry| entry.value().declaring_type_rc().map(|dt| dt.token))
                .map_or(SsaType::Object, |type_token| {
                    SsaType::from_type_token(type_token, self.assembly)
                }),

            // MemberRef - get declaring type from member ref
            0x0A => self
                .assembly
                .refs_members()
                .get(&ctor_token)
                .and_then(|entry| entry.value().declaredby.token())
                .map_or(SsaType::Object, |class_token| {
                    SsaType::from_type_token(class_token, self.assembly)
                }),

            // MethodSpec - resolve to underlying constructor
            0x2B => self
                .assembly
                .method_specs()
                .get(&ctor_token)
                .and_then(|entry| entry.value().method.token())
                .map_or(SsaType::Object, |method_token| {
                    self.newobj_type(method_token)
                }),

            _ => SsaType::Object,
        }
    }

    /// Returns the type of a field.
    ///
    /// Looks up the field's type signature from the assembly metadata.
    #[must_use]
    pub fn field_type(&self, field_token: Token) -> SsaType {
        let table_id = field_token.table();

        match table_id {
            // Field table (0x04) - look up through type registry
            0x04 => self
                .assembly
                .fields()
                .get(&field_token)
                .map_or(SsaType::Unknown, |entry| {
                    SsaType::from_type_signature(&entry.value().signature.base, self.assembly)
                }),

            // MemberRef table (0x0A) - a field reached through a reference,
            // typed in the terms of the instantiation it is read through
            0x0A => self
                .assembly
                .refs_members()
                .get(&field_token)
                .and_then(|entry| {
                    let member_ref = entry.value();
                    let MemberRefSignature::Field(field_sig) = &member_ref.signature else {
                        return None;
                    };
                    let type_args = self.instantiation_args(member_ref.declaredby.token());
                    Some(
                        SsaType::from_type_signature(&field_sig.base, self.assembly)
                            .substitute_generic_params(type_args.as_deref(), None),
                    )
                })
                .unwrap_or(SsaType::Unknown),

            _ => SsaType::Unknown,
        }
    }

    /// Returns the return type of a `calli` (indirect call) from its `StandAloneSig` token.
    ///
    /// Resolves the standalone method signature referenced by the token and extracts
    /// the return type. Returns `SsaType::Unknown` on any resolution failure.
    #[must_use]
    pub fn call_indirect_return_type(&self, sig_token: Token) -> SsaType {
        // StandAloneSig table is 0x11
        if sig_token.table() != 0x11 {
            return SsaType::Unknown;
        }
        let Some(tables) = self.assembly.tables() else {
            return SsaType::Unknown;
        };
        let Some(table) = tables.table::<StandAloneSigRaw>() else {
            return SsaType::Unknown;
        };
        let Some(raw) = table.get(sig_token.row()).ok().flatten() else {
            return SsaType::Unknown;
        };
        let Some(blob) = self.assembly.blob() else {
            return SsaType::Unknown;
        };
        let Ok(owned) = raw.to_owned(blob) else {
            return SsaType::Unknown;
        };
        match &owned.parsed_signature {
            StandAloneSignature::Method(sig) => {
                SsaType::from_parameter(&sig.return_type, self.assembly)
            }
            _ => SsaType::Unknown,
        }
    }

    /// A method MemberRef's declared return type, unsubstituted, and the type
    /// arguments of the instantiation it names the method through (`None`
    /// when its parent is not a generic instance).
    fn member_ref_return(&self, token: Token) -> Option<(SsaType, Option<Vec<SsaType>>)> {
        let entry = self.assembly.refs_members().get(&token)?;
        let member_ref = entry.value();
        let MemberRefSignature::Method(sig) = &member_ref.signature else {
            return None;
        };
        let ret = SsaType::from_parameter(&sig.return_type, self.assembly);
        Some((ret, self.instantiation_args(member_ref.declaredby.token())))
    }

    /// The type arguments of a generic instantiation TypeSpec, or `None` for
    /// any other parent (a plain type supplies no arguments to substitute).
    fn instantiation_args(&self, parent: Option<Token>) -> Option<Vec<SsaType>> {
        let parent = parent.filter(|token| token.table() == 0x1B)?;
        match SsaType::from_type_token(parent, self.assembly) {
            SsaType::GenericInst(_, args) => Some(args),
            _ => None,
        }
    }

    /// Validates generic parameter references against the method's actual generic params.
    ///
    /// ConfuserEx-corrupted metadata can contain `!!0` references in non-generic methods.
    /// This replaces out-of-range generic parameter references with `Unknown` to prevent
    /// invalid types from propagating through the pipeline.
    fn validate_generic_params(&self, ty: SsaType) -> SsaType {
        match ty {
            SsaType::MethodGenericParam(idx) => {
                if (idx as usize) < self.method.generic_params.count() {
                    SsaType::MethodGenericParam(idx)
                } else {
                    SsaType::Unknown
                }
            }
            SsaType::GenericParam(idx) => {
                let valid = self
                    .method
                    .declaring_type_rc()
                    .is_some_and(|dt| (idx as usize) < dt.generic_params.count());
                if valid {
                    SsaType::GenericParam(idx)
                } else {
                    SsaType::Unknown
                }
            }
            SsaType::Array(elem, rank) => {
                SsaType::Array(Box::new(self.validate_generic_params(*elem)), rank)
            }
            SsaType::ByRef(inner) => SsaType::ByRef(Box::new(self.validate_generic_params(*inner))),
            SsaType::Pointer(inner) => {
                SsaType::Pointer(Box::new(self.validate_generic_params(*inner)))
            }
            SsaType::GenericInst(base, args) => {
                let validated_base = self.validate_generic_params(*base);
                let validated_args = args
                    .into_iter()
                    .map(|a| self.validate_generic_params(a))
                    .collect();
                SsaType::GenericInst(Box::new(validated_base), validated_args)
            }
            other => other,
        }
    }

    /// Returns the original local variable type signatures for code generation.
    ///
    /// This reads the raw `StandAloneSig` blob directly from metadata, bypassing
    /// the resolved `CilType` weak references. This ensures we always get the original
    /// `TypeSignature` tokens (TypeDef/TypeRef/TypeSpec) that can be correctly encoded
    /// back to metadata, rather than artificial tokens created by the `TypeResolver`.
    #[must_use]
    pub fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        self.parsed_local_signatures().cloned()
    }

    /// The local signatures [`Self::local_type_signatures`] returns, parsed from the
    /// LocalVarSig blob once.
    fn parsed_local_signatures(&self) -> Option<&Vec<SignatureLocalVariable>> {
        self.local_signatures
            .get_or_init(|| {
                let sig_rid = self.method.body.get()?.local_var_sig_rid()?;
                let tables = self.assembly.tables()?;
                let table = tables.table::<StandAloneSigRaw>()?;
                let raw = table.get(sig_rid).ok().flatten()?;
                let blob = self.assembly.blob()?;
                let sig_data = blob.get(raw.signature as usize).ok()?;
                let locals_sig = parse_local_var_signature(sig_data).ok()?;
                Some(locals_sig.locals)
            })
            .as_ref()
    }

    /// Returns the catch handler's exception type as an `SsaType`.
    ///
    /// Resolves the catch clause's type token from the method's exception handler
    /// table. Falls back to `SsaType::Object` if the handler index is out of
    /// range or the type cannot be resolved.
    #[must_use]
    pub fn handler_catch_type(&self, handler_index: usize) -> SsaType {
        let Some(body) = self.method.body.get() else {
            return SsaType::Object;
        };

        let Some(handler) = body.exception_handlers.get(handler_index) else {
            return SsaType::Object;
        };

        // For catch handlers, resolve the type token from the handler's type reference
        if handler.flags == ExceptionHandlerFlags::EXCEPTION {
            if let Some(type_ref) = &handler.handler {
                return SsaType::from_type_token(type_ref.token, self.assembly);
            }
        }

        // Filter handlers and fallback: exception type is System.Object
        SsaType::Object
    }
}

impl TypeProvider for TypeContext<'_> {
    fn arg_type(&self, idx: u16) -> SsaType {
        self.arg_type(idx)
    }

    fn local_type(&self, idx: u16) -> SsaType {
        self.local_type(idx)
    }

    fn call_return_type(&self, token: Token) -> SsaType {
        self.call_return_type(token)
    }

    fn newobj_type(&self, ctor_token: Token) -> SsaType {
        self.newobj_type(ctor_token)
    }

    fn field_type(&self, field_token: Token) -> SsaType {
        self.field_type(field_token)
    }

    fn call_indirect_return_type(&self, sig_token: Token) -> SsaType {
        self.call_indirect_return_type(sig_token)
    }

    fn assembly(&self) -> Option<&CilObject> {
        Some(self.assembly)
    }

    /// Read through the loader: a reference resolves to its definition in
    /// this assembly, or else in an external registry the loader holds.
    fn enum_underlying(&self, value_type: &TypeRef) -> Option<SsaType> {
        let types = self.assembly.types();
        let named = types.resolve(&value_type.token())?;
        let definition = if named.token.is_table(TableId::TypeRef) {
            types
                .get_by_fullname(&named.fullname(), true)
                .unwrap_or(named)
        } else {
            named
        };
        if !EnumUtils::is_enum_type(&definition, Some(&types)) {
            return None;
        }
        let underlying = SsaType::from_type_signature(definition.enum_underlying()?, self.assembly);
        (underlying.is_integer() || matches!(underlying, SsaType::Bool | SsaType::Char))
            .then_some(underlying)
    }

    fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        TypeContext::local_type_signatures(self)
    }

    fn locals_zero_initialized(&self) -> bool {
        self.method
            .body
            .get()
            .is_some_and(|body| body.is_init_local)
    }

    fn handler_catch_type(&self, handler_index: usize) -> SsaType {
        self.handler_catch_type(handler_index)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::ssa::types::{SsaType, TypeClass, TypeContext, TypeRef},
        metadata::{
            signatures::TypeSignature,
            tables::{MemberRefSignature, TableAccess, TypeSpecRaw},
            token::Token,
        },
        testkit::helpers::test_assembly_arc,
    };

    /// ECMA-335's binary numeric table: equal classes keep their class,
    /// `int32` with `native int` widens, floats take the wider, a pointer
    /// moved by an integer stays a pointer and two pointers differ by a
    /// `native int`; an enum, plain or instantiated, takes the integer it is
    /// computed with, two values of one enum or one generic parameter compute
    /// as it, and of two enums as the first; the rest combine to nothing. A
    /// unary operation keeps its operand's class, an enum's or a parameter's
    /// value its type.
    #[test]
    fn binary_numeric_follows_the_ecma_table() {
        let pointer = SsaType::Pointer(Box::new(SsaType::I32));
        let flags = SsaType::ValueType(TypeRef::new(Token::new(0x0200_0001)));
        let other_flags = SsaType::ValueType(TypeRef::new(Token::new(0x0200_0002)));
        let nested = SsaType::GenericInst(Box::new(flags.clone()), vec![SsaType::GenericParam(0)]);
        let parameter = SsaType::MethodGenericParam(0);
        let cases = [
            (SsaType::I32, SsaType::U16, false, Some(SsaType::I32)),
            (SsaType::U64, SsaType::I64, false, Some(SsaType::I64)),
            (
                SsaType::I32,
                SsaType::NativeInt,
                false,
                Some(SsaType::NativeInt),
            ),
            (SsaType::F32, SsaType::F32, false, Some(SsaType::F32)),
            (SsaType::F32, SsaType::F64, false, Some(SsaType::F64)),
            (pointer.clone(), SsaType::I32, true, Some(pointer.clone())),
            (
                pointer.clone(),
                pointer.clone(),
                true,
                Some(SsaType::NativeInt),
            ),
            (pointer.clone(), SsaType::I32, false, None),
            (flags.clone(), SsaType::I64, false, Some(SsaType::I64)),
            (flags.clone(), flags.clone(), false, Some(flags.clone())),
            (
                flags.clone(),
                other_flags.clone(),
                false,
                Some(flags.clone()),
            ),
            (nested.clone(), SsaType::I32, false, Some(SsaType::I32)),
            (nested.clone(), nested.clone(), false, Some(nested.clone())),
            (
                parameter.clone(),
                parameter.clone(),
                true,
                Some(parameter.clone()),
            ),
            (parameter.clone(), SsaType::I32, true, None),
            (SsaType::I32, SsaType::I64, false, None),
            (SsaType::I32, SsaType::F64, false, None),
        ];
        for (left, right, additive, expected) in cases {
            assert_eq!(
                SsaType::binary_numeric(&left, &right, additive),
                expected,
                "{left:?} with {right:?}"
            );
        }
        assert_eq!(SsaType::U16.unary_numeric(), Some(SsaType::I32));
        assert_eq!(flags.unary_numeric(), Some(flags.clone()));
        assert_eq!(nested.unary_numeric(), Some(nested.clone()));
        assert_eq!(parameter.unary_numeric(), Some(parameter.clone()));
        assert_eq!(SsaType::String.unary_numeric(), None);
    }

    #[test]
    fn a_member_of_an_instantiation_is_typed_in_its_terms() {
        let assembly = test_assembly_arc();
        let method = assembly
            .methods()
            .iter()
            .next()
            .map(|entry| entry.value().clone())
            .expect("the sample has methods");
        let ctx = TypeContext::new(&method, &assembly);

        let mut checked = 0;
        for entry in assembly.refs_members().iter() {
            let member_ref = entry.value();
            let MemberRefSignature::Method(sig) = &member_ref.signature else {
                continue;
            };
            // A method returning its class's own parameter, like `List<T>.get_Item`.
            let TypeSignature::GenericParamType(idx) = sig.return_type.base else {
                continue;
            };
            let Some(parent) = member_ref.declaredby.token().filter(|t| t.table() == 0x1B) else {
                continue;
            };
            let SsaType::GenericInst(_, args) = SsaType::from_type_token(parent, &assembly) else {
                continue;
            };
            let expected = args[idx as usize].clone();
            if matches!(
                expected,
                SsaType::GenericParam(_) | SsaType::MethodGenericParam(_)
            ) {
                continue;
            }
            assert_eq!(
                ctx.call_return_type(member_ref.token),
                expected,
                "{:?} returns !{idx} of {args:?}",
                member_ref.token,
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "the sample calls a member of a concrete instantiation"
        );
    }

    #[test]
    fn class_and_method_arguments_are_substituted_together() {
        // `Foo<!!0>::Bar<int32>` returning `Pair<!0, !!0>`: the class argument
        // is the caller's `!!0`, which the method's `int32` must not replace.
        let ret = SsaType::GenericInst(
            Box::new(SsaType::Class(TypeRef::new(Token::new(0x0100_0001)))),
            vec![SsaType::GenericParam(0), SsaType::MethodGenericParam(0)],
        );
        let substituted = ret.substitute_generic_params(
            Some(&[SsaType::MethodGenericParam(0)]),
            Some(&[SsaType::I32]),
        );
        assert_eq!(
            substituted,
            SsaType::GenericInst(
                Box::new(SsaType::Class(TypeRef::new(Token::new(0x0100_0001)))),
                vec![SsaType::MethodGenericParam(0), SsaType::I32],
            )
        );
    }

    #[test]
    fn an_instantiated_struct_is_a_value_type() {
        let assembly = test_assembly_arc();
        let tables = assembly.tables().expect("tables");
        let blob = assembly.blob().expect("blob heap");
        let table = <_ as TableAccess<TypeSpecRaw>>::table(tables).expect("TypeSpec table");
        let struct_instances: Vec<Token> = table
            .into_iter()
            .flatten()
            .filter(|row| {
                row.to_owned(blob).is_ok_and(|spec| {
                    matches!(
                        &spec.signature.base,
                        TypeSignature::GenericInst(base, _)
                            if matches!(**base, TypeSignature::ValueType(_))
                    )
                })
            })
            .map(|row| row.token)
            .collect();
        assert!(
            !struct_instances.is_empty(),
            "the sample instantiates a struct"
        );

        for token in struct_instances {
            let ty = SsaType::from_type_token(token, &assembly);
            assert!(
                matches!(&ty, SsaType::GenericInst(base, _) if matches!(**base, SsaType::ValueType(_))),
                "{token:?} typed as {ty:?}",
            );
        }
    }

    #[test]
    fn a_signature_says_whether_an_imported_type_is_a_struct() {
        let assembly = test_assembly_arc();
        let imported = |name: &str| {
            assembly
                .types()
                .iter()
                .map(|entry| entry.value().clone())
                .find(|ty| ty.token.table() == 0x01 && ty.fullname() == name)
                .map(|ty| ty.token)
                .unwrap_or_else(|| panic!("{name} is imported"))
        };
        let date_time = imported("System.DateTime");
        let enum_base = imported("System.Enum");

        assert_eq!(
            SsaType::from_type_signature(&TypeSignature::ValueType(date_time), &assembly),
            SsaType::ValueType(TypeRef::new(date_time)),
        );
        // `System.Enum` is the reference type every enum derives from, whatever
        // its name suggests.
        assert_eq!(
            SsaType::from_type_signature(&TypeSignature::Class(enum_base), &assembly),
            SsaType::Class(TypeRef::new(enum_base)),
        );
    }

    #[test]
    fn test_primitive_types() {
        assert!(SsaType::I32.is_primitive());
        assert!(SsaType::F64.is_primitive());
        assert!(SsaType::Bool.is_primitive());
        assert!(!SsaType::Object.is_primitive());
        assert!(!SsaType::String.is_primitive());
    }

    #[test]
    fn test_integer_types() {
        assert!(SsaType::I32.is_integer());
        assert!(SsaType::U64.is_integer());
        assert!(SsaType::NativeInt.is_integer());
        assert!(!SsaType::F32.is_integer());
        assert!(!SsaType::Bool.is_integer());
    }

    #[test]
    fn test_float_types() {
        assert!(SsaType::F32.is_float());
        assert!(SsaType::F64.is_float());
        assert!(!SsaType::I32.is_float());
    }

    #[test]
    fn test_reference_types() {
        assert!(SsaType::Object.is_reference());
        assert!(SsaType::String.is_reference());
        assert!(SsaType::Null.is_reference());
        let array_type = SsaType::Array(Box::new(SsaType::I32), 1);
        assert!(array_type.is_reference());
        assert!(!SsaType::I32.is_reference());
    }

    #[test]
    fn test_array_type() {
        let array = SsaType::Array(Box::new(SsaType::I32), 1);
        assert!(array.is_array());
        assert_eq!(array.array_element_type(), Some(&SsaType::I32));
        assert_eq!(array.array_rank(), Some(1));

        let multi_dim = SsaType::Array(Box::new(SsaType::F64), 3);
        assert_eq!(multi_dim.array_rank(), Some(3));
    }

    #[test]
    fn test_pointer_types() {
        let ptr = SsaType::Pointer(Box::new(SsaType::I32));
        assert!(ptr.is_pointer());
        assert_eq!(ptr.pointee_type(), Some(&SsaType::I32));

        let byref = SsaType::ByRef(Box::new(SsaType::Object));
        assert!(byref.is_pointer());
        assert_eq!(byref.pointee_type(), Some(&SsaType::Object));
    }

    #[test]
    fn test_size_bytes() {
        assert_eq!(SsaType::I8.size_bytes(), Some(1));
        assert_eq!(SsaType::I16.size_bytes(), Some(2));
        assert_eq!(SsaType::I32.size_bytes(), Some(4));
        assert_eq!(SsaType::I64.size_bytes(), Some(8));
        assert_eq!(SsaType::F32.size_bytes(), Some(4));
        assert_eq!(SsaType::F64.size_bytes(), Some(8));
        assert_eq!(SsaType::NativeInt.size_bytes(), None); // Platform-dependent
        assert_eq!(SsaType::Object.size_bytes(), None);
    }

    #[test]
    fn test_stack_type() {
        assert_eq!(SsaType::I8.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I16.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I32.stack_type(), SsaType::I32);
        assert_eq!(SsaType::I64.stack_type(), SsaType::I64);
        assert_eq!(SsaType::F32.stack_type(), SsaType::F64);
    }

    #[test]
    fn test_type_merge() {
        // Same types merge to themselves
        assert_eq!(SsaType::I32.merge(&SsaType::I32), SsaType::I32);

        // Unknown merges with anything
        assert_eq!(SsaType::Unknown.merge(&SsaType::I32), SsaType::I32);
        assert_eq!(SsaType::I32.merge(&SsaType::Unknown), SsaType::I32);

        // Null merges with reference types
        assert_eq!(SsaType::Null.merge(&SsaType::Object), SsaType::Object);
        assert_eq!(SsaType::Object.merge(&SsaType::Null), SsaType::Object);

        // Incompatible types become Varying
        assert_eq!(SsaType::I32.merge(&SsaType::I64), SsaType::Varying);
        assert_eq!(SsaType::Object.merge(&SsaType::I32), SsaType::Varying);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", SsaType::I32), "i32");
        assert_eq!(format!("{}", SsaType::Object), "object");
        assert_eq!(
            format!("{}", SsaType::Array(Box::new(SsaType::I32), 1)),
            "i32[]"
        );
        assert_eq!(
            format!("{}", SsaType::Pointer(Box::new(SsaType::I32))),
            "i32*"
        );
        assert_eq!(
            format!("{}", SsaType::ByRef(Box::new(SsaType::I32))),
            "i32&"
        );
        assert_eq!(format!("{}", SsaType::GenericParam(0)), "!0");
        assert_eq!(format!("{}", SsaType::MethodGenericParam(1)), "!!1");
    }

    #[test]
    fn test_storage_class() {
        // 32-bit integers
        assert_eq!(SsaType::I32.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::U32.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::Bool.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::Char.storage_class(), TypeClass::Int32);
        assert_eq!(SsaType::I8.storage_class(), TypeClass::Int32);

        // 64-bit integers
        assert_eq!(SsaType::I64.storage_class(), TypeClass::Int64);
        assert_eq!(SsaType::U64.storage_class(), TypeClass::Int64);

        // Floats
        assert_eq!(SsaType::F32.storage_class(), TypeClass::Float32);
        assert_eq!(SsaType::F64.storage_class(), TypeClass::Float64);

        // Native integers
        assert_eq!(SsaType::NativeInt.storage_class(), TypeClass::NativeInt);
        assert_eq!(SsaType::NativeUInt.storage_class(), TypeClass::NativeInt);

        // Reference types
        assert_eq!(SsaType::Object.storage_class(), TypeClass::Reference);
        assert_eq!(SsaType::String.storage_class(), TypeClass::Reference);
        assert_eq!(
            SsaType::Array(Box::new(SsaType::I32), 1).storage_class(),
            TypeClass::Reference
        );

        // Other
        assert_eq!(SsaType::Void.storage_class(), TypeClass::Other);
        assert_eq!(SsaType::Unknown.storage_class(), TypeClass::Other);
    }

    #[test]
    fn test_is_compatible_for_storage() {
        // Same types are compatible
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::I32));

        // 32-bit integers are compatible with each other
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::U32));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Bool));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Char));

        // 64-bit integers are compatible
        assert!(SsaType::I64.is_compatible_for_storage(&SsaType::U64));

        // Reference types require exact match (CIL verifier constraint)
        assert!(!SsaType::Object.is_compatible_for_storage(&SsaType::String));
        assert!(SsaType::String.is_compatible_for_storage(&SsaType::String));

        // Unknown is compatible with anything
        assert!(SsaType::Unknown.is_compatible_for_storage(&SsaType::I32));
        assert!(SsaType::I32.is_compatible_for_storage(&SsaType::Unknown));

        // Different classes are not compatible
        assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::I64));
        assert!(!SsaType::I32.is_compatible_for_storage(&SsaType::Object));
        assert!(!SsaType::F32.is_compatible_for_storage(&SsaType::F64));
    }

    fn make_generic_inst_class(args: Vec<SsaType>) -> SsaType {
        SsaType::GenericInst(
            Box::new(SsaType::Class(TypeRef::new(Token::new(0x0200_0001)))),
            args,
        )
    }

    #[test]
    fn test_generic_inst_is_reference() {
        // GenericInst with Class base is a reference type
        let list_int = make_generic_inst_class(vec![SsaType::I32]);
        assert!(list_int.is_reference());

        // GenericInst with ValueType base is NOT a reference type
        let valuetype_inst = SsaType::GenericInst(
            Box::new(SsaType::ValueType(TypeRef::new(Token::new(0x0200_0002)))),
            vec![SsaType::I32],
        );
        assert!(!valuetype_inst.is_reference());
    }

    #[test]
    fn test_generic_inst_storage_class() {
        // GenericInst with Class base has Reference storage class
        let list_int = make_generic_inst_class(vec![SsaType::I32]);
        assert_eq!(list_int.storage_class(), TypeClass::Reference);

        // GenericInst with ValueType base has Reference storage class (value types are Reference in storage)
        let valuetype_inst = SsaType::GenericInst(
            Box::new(SsaType::ValueType(TypeRef::new(Token::new(0x0200_0002)))),
            vec![SsaType::I32],
        );
        assert_eq!(valuetype_inst.storage_class(), TypeClass::Reference);
    }

    #[test]
    fn test_generic_inst_display() {
        let list_int = make_generic_inst_class(vec![SsaType::I32]);
        assert_eq!(format!("{list_int}"), "class TypeRef(0x02000001)<i32>");

        let dict = SsaType::GenericInst(
            Box::new(SsaType::Class(TypeRef::new(Token::new(0x0200_0003)))),
            vec![SsaType::String, SsaType::I32],
        );
        assert_eq!(format!("{dict}"), "class TypeRef(0x02000003)<string, i32>");
    }

    #[test]
    fn test_generic_inst_to_type_signature_roundtrip() {
        let list_int = make_generic_inst_class(vec![SsaType::I32]);
        let sig = list_int.to_type_signature();

        // Should produce GenericInst with Class base and I4 arg
        match &sig {
            TypeSignature::GenericInst(base, args) => {
                assert!(matches!(base.as_ref(), TypeSignature::Class(_)));
                assert_eq!(args.len(), 1);
                assert!(matches!(args[0], TypeSignature::I4));
            }
            other => panic!("Expected GenericInst, got {other:?}"),
        }
    }

    #[test]
    fn test_generic_inst_merge() {
        let list_int = make_generic_inst_class(vec![SsaType::I32]);
        let list_int2 = make_generic_inst_class(vec![SsaType::I32]);

        // Same GenericInst merges to itself
        assert_eq!(list_int.merge(&list_int2), list_int);

        // Different type args produce Varying
        let list_str = make_generic_inst_class(vec![SsaType::String]);
        assert_eq!(list_int.merge(&list_str), SsaType::Varying);

        // Null merges with GenericInst (reference type)
        assert_eq!(SsaType::Null.merge(&list_int), list_int);
        assert_eq!(list_int.merge(&SsaType::Null), list_int);

        // Unknown merges with GenericInst
        assert_eq!(SsaType::Unknown.merge(&list_int), list_int);
        assert_eq!(list_int.merge(&SsaType::Unknown), list_int);
    }

    #[test]
    fn test_generic_inst_storage_compatibility() {
        let list_int = make_generic_inst_class(vec![SsaType::I32]);

        // GenericInst(Class) is NOT compatible with Object or String (different reference types
        // require exact match for CIL local sharing)
        assert!(!list_int.is_compatible_for_storage(&SsaType::Object));
        assert!(!list_int.is_compatible_for_storage(&SsaType::String));

        // Same GenericInst IS compatible with itself
        let list_int2 = make_generic_inst_class(vec![SsaType::I32]);
        assert!(list_int.is_compatible_for_storage(&list_int2));

        // Not compatible with Int32
        assert!(!list_int.is_compatible_for_storage(&SsaType::I32));
    }
}
