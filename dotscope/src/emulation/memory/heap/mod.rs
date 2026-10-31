//! Managed heap implementation for CIL emulation.
//!
//! This module provides [`ManagedHeap`], which simulates the .NET runtime's
//! garbage-collected heap. It supports allocation of:
//!
//! - **Strings** - Immutable .NET strings stored as `Arc<str>`
//! - **Arrays** - Single and multi-dimensional arrays with element type tracking
//! - **Objects** - Class instances with field storage by token
//! - **Boxed values** - Value types wrapped as reference types
//! - **Delegates** - Method references with optional target objects
//! - **Special types** - Encoding and cryptographic algorithm instances for stubs
//!
//! # Interior Mutability
//!
//! The heap uses interior mutability via `RwLock` to allow shared access
//! during emulation. This enables multiple concurrent reads and exclusive
//! writes without requiring `&mut self` on accessor methods.
//!
//! # Copy-on-Write Semantics
//!
//! The heap uses `imbl::HashMap` for O(1) fork operations. When you call `fork()`,
//! both the original and the fork share the same underlying data structure via
//! structural sharing. Only modified entries are copied (true copy-on-write at
//! the data structure level).
//!
//! # Memory Limits
//!
//! The heap enforces a configurable maximum size. Allocation attempts that
//! would exceed this limit return [`EmulationError::HeapMemoryLimitExceeded`](crate::emulation::EmulationError::HeapMemoryLimitExceeded).
//!
//! # Object References
//!
//! Objects are referenced via [`HeapRef`](crate::emulation::HeapRef), an opaque handle
//! that contains an internal ID. References remain valid for the lifetime of the
//! heap (no garbage collection is simulated).

mod arrays;
mod collections;
mod crypto;
mod reflection;
mod streams;

use std::{
    collections::{HashMap, HashSet as StdHashSet, VecDeque},
    fmt,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
};

use imbl::HashMap as ImHashMap;

use crate::{
    assembly::InstructionAssembler,
    emulation::{engine::EmulationError, tokens, EmValue, HeapRef},
    metadata::{signatures::TypeSignature, token::Token, typesystem::CilFlavor},
    utils::truncate_chars,
    Result,
};

/// Host cost of one element in an emulated array or list.
///
/// Derived from the type rather than hard-coded, so the budget stays honest if [`EmValue`]
/// changes width. A fixed per-element figure is easy to get badly wrong: `EmValue` is
/// currently on the order of a couple of hundred bytes, so under-charging it would let an
/// array sit nominally inside a 256 MB cap while really costing gigabytes.
pub(crate) const EMVALUE_SIZE: usize = std::mem::size_of::<EmValue>();

/// Object-header overhead charged for a single-dimensional array.
const ARRAY_HEADER_BYTES: usize = 24;

/// Object-header overhead charged for a multi-dimensional array.
const MULTI_ARRAY_HEADER_BYTES: usize = 32;

/// Object-header overhead charged for a `List<T>`.
const LIST_HEADER_BYTES: usize = 32;

/// Object-header overhead charged for a delegate.
const DELEGATE_HEADER_BYTES: usize = 48;

/// Host cost of one entry in a delegate's invocation list.
///
/// Derived from the type so it tracks [`DelegateEntry`] rather than drifting from it.
const DELEGATE_ENTRY_BYTES: usize = std::mem::size_of::<DelegateEntry>();

/// Maximum number of entries in a single delegate's invocation list.
///
/// `Delegate.Combine` concatenates two invocation lists and nothing stops both arguments from
/// being the same delegate, so each call can double the length — exponential growth in a linear
/// number of emulated instructions. Charging the list against the heap budget (see
/// [`HeapObject::estimated_size`]) bounds the total, but a dedicated cap fails the operation at
/// the point of the defect with a message that names it, instead of surfacing as a generic
/// out-of-memory once the doubling happens to cross the budget.
///
/// Real multicast delegates hold a handful of entries; .NET itself has no fixed limit.
const MAX_DELEGATE_INVOCATION_LIST: usize = 65_536;

/// Info about a symmetric algorithm: (algorithm_type, key, iv, mode, padding).
pub type SymmetricAlgorithmInfo = (Arc<str>, Option<Vec<u8>>, Option<Vec<u8>>, u8, u8);

/// Info about a crypto transform: (algorithm, key, iv, is_encryptor, mode, padding).
pub type CryptoTransformInfo = (Arc<str>, Vec<u8>, Vec<u8>, bool, u8, u8);

/// Info about key derivation: (password, salt, iterations, hash_algorithm).
pub type KeyDerivationInfo = (Vec<u8>, Vec<u8>, u32, Arc<str>);

/// Info about a reflection property: (property_name, declaring_type_token, getter_token, setter_token).
pub type ReflectionPropertyInfo = (Arc<str>, Token, Option<Token>, Option<Token>);

/// Iterator over heap objects.
///
/// This iterator holds a pre-collected snapshot of all heap objects taken
/// at the time [`ManagedHeap::iter()`] was called. No further lock
/// acquisition is needed during iteration.
///
/// # Example
///
/// ```no_run
/// for (heap_ref, object) in heap.iter()? {
///     println!("{}: {}", heap_ref, object);
/// }
/// ```
pub struct HeapIter {
    items: std::vec::IntoIter<(HeapRef, HeapObject)>,
}

impl Iterator for HeapIter {
    type Item = (HeapRef, HeapObject);

    fn next(&mut self) -> Option<Self::Item> {
        self.items.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.items.size_hint()
    }
}

impl ExactSizeIterator for HeapIter {}

/// Text encoding type for `System.Text.Encoding` stubs.
///
/// This enum tracks the encoding type for encoding objects allocated on
/// the heap, enabling the emulator to correctly handle string encoding
/// and decoding operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodingType {
    /// UTF-8 encoding (variable-width, 1-4 bytes per character).
    Utf8,
    /// ASCII encoding (7-bit, single byte per character).
    Ascii,
    /// UTF-16 Little Endian (Windows Unicode, 2 bytes per character).
    Utf16Le,
    /// UTF-16 Big Endian (2 bytes per character).
    Utf16Be,
    /// UTF-32 encoding (4 bytes per character).
    Utf32,
}

/// Key type for Dictionary and HashSet storage.
///
/// Supports the common .NET key types used in obfuscator lookup tables:
/// integers, strings, booleans, chars, and object references.
#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub enum DictionaryKey {
    /// Integer key (covers i32, i64, NativeInt, NativeUInt).
    Integer(i64),
    /// String key.
    String(Arc<str>),
    /// Boolean key.
    Bool(bool),
    /// Character key.
    Char(char),
    /// Object reference key (identity-based equality).
    ObjectRef(HeapRef),
    /// Null key.
    Null,
}

impl DictionaryKey {
    /// Converts an `EmValue` to a `DictionaryKey`.
    ///
    /// Returns `None` for value types that cannot be used as dictionary keys
    /// (e.g., floats, void, pointers, value types).
    #[must_use]
    pub fn from_emvalue(value: &EmValue, heap: &ManagedHeap) -> Option<Self> {
        match value {
            EmValue::I32(v) => Some(DictionaryKey::Integer(i64::from(*v))),
            EmValue::I64(v) => Some(DictionaryKey::Integer(*v)),
            EmValue::NativeInt(v) => Some(DictionaryKey::Integer(*v)),
            EmValue::NativeUInt(v) => Some(DictionaryKey::Integer(*v as i64)),
            EmValue::Bool(v) => Some(DictionaryKey::Bool(*v)),
            EmValue::Char(v) => Some(DictionaryKey::Char(*v)),
            EmValue::Null => Some(DictionaryKey::Null),
            EmValue::ObjectRef(href) => {
                // For string references, use string value equality
                if let Ok(s) = heap.get_string(*href) {
                    Some(DictionaryKey::String(s))
                } else {
                    Some(DictionaryKey::ObjectRef(*href))
                }
            }
            _ => None,
        }
    }

    /// Converts this key back to an `EmValue`.
    #[must_use]
    pub fn to_emvalue(&self, heap: &ManagedHeap) -> EmValue {
        match self {
            DictionaryKey::Integer(v) => EmValue::I32(*v as i32),
            DictionaryKey::String(s) => {
                if let Ok(href) = heap.alloc_string(s) {
                    EmValue::ObjectRef(href)
                } else {
                    EmValue::Null
                }
            }
            DictionaryKey::Bool(v) => EmValue::Bool(*v),
            DictionaryKey::Char(v) => EmValue::Char(*v),
            DictionaryKey::ObjectRef(href) => EmValue::ObjectRef(*href),
            DictionaryKey::Null => EmValue::Null,
        }
    }
}

/// Wrapper type information for reflection types created by
/// `Type.MakeByRefType()`, `Type.MakeArrayType()`, `Type.MakeGenericType()`.
#[derive(Debug, Clone, PartialEq)]
pub enum TypeWrapper {
    /// Created by `Type.MakeByRefType()`
    ByRef,
    /// Created by `Type.MakeArrayType()`
    SzArray,
    /// Created by `Type.MakePointerType()`
    Pointer,
    /// Created by `Type.MakeGenericType()`
    GenericInst(Vec<Token>),
}

/// Object stored on the managed heap.
///
/// A single entry in a delegate's invocation list.
///
/// Each entry represents one (target, method) pair. For instance methods,
/// `target` holds the bound `this` reference; for static methods it is `None`.
#[derive(Clone, Debug)]
pub struct DelegateEntry {
    /// Target object for instance methods, `None` for static methods.
    pub target: Option<HeapRef>,
    /// The method being referenced.
    pub method_token: Token,
}

/// This enum represents all types of objects that can be allocated on the
/// simulated managed heap. Each variant corresponds to a different .NET
/// reference type or special emulator type.
///
/// # Cloning
///
/// Most variants use `Arc` for their string/byte data, making cloning cheap.
/// The [`ManagedHeap`] methods that return objects (like [`get`](ManagedHeap::get))
/// return cloned copies to avoid borrow conflicts.
// ToDo:  Migrate all storage to be Arc rather than having to clone / create expensive copies
#[derive(Clone, Debug)]
pub enum HeapObject {
    /// A .NET string (immutable sequence of UTF-16 chars).
    ///
    /// Stored internally as `Arc<str>` (UTF-8) for efficient, borrow-free access.
    /// Conversion to/from UTF-16 is handled at the API boundary.
    String(Arc<str>),

    /// A single-dimensional array (SZArray).
    ///
    /// Elements are stored as [`EmValue`] instances with the declared element type
    /// tracked separately for type checking.
    Array {
        /// The declared element type.
        element_type: CilFlavor,
        /// The array elements.
        elements: Vec<EmValue>,
    },

    /// A multi-dimensional array.
    ///
    /// Elements are stored in row-major order (C-style) in a flattened vector.
    MultiArray {
        /// The declared element type.
        element_type: CilFlavor,
        /// Dimension lengths (e.g., `[3, 4]` for a 3x4 array).
        dimensions: Vec<usize>,
        /// Flattened elements in row-major order.
        elements: Vec<EmValue>,
    },

    /// A class instance.
    ///
    /// Fields are stored by their metadata token, allowing dynamic field access
    /// without requiring full type resolution.
    Object {
        /// The type token (TypeDef or TypeRef) of the object.
        type_token: Token,
        /// Field values indexed by field token.
        fields: HashMap<Token, EmValue>,
    },

    /// A boxed value type.
    ///
    /// Created by the `box` instruction to convert a value type to a reference type.
    BoxedValue {
        /// The original value type token.
        type_token: Token,
        /// The boxed value.
        value: Box<EmValue>,
    },

    /// A delegate instance (supports multicast).
    ///
    /// Represents one or more method references, optionally bound to target objects.
    /// For single-cast delegates, `invocation_list` has exactly one entry.
    /// For multicast delegates (Delegate.Combine), it has multiple entries.
    Delegate {
        /// The delegate type token.
        type_token: Token,
        /// Ordered list of (target, method) pairs for invocation.
        invocation_list: Vec<DelegateEntry>,
    },

    /// A `System.TypedReference` — a (type, pointer) pair created by `mkrefany`.
    ///
    /// ECMA-335 §III.4.14: `mkrefany` packages an address and a type token into
    /// a typed reference.  `refanyval` extracts the address (with a type check)
    /// and `refanytype` extracts the type token.
    TypedReference {
        /// The type token supplied to `mkrefany`.
        type_token: Token,
        /// The address value that was on the stack when `mkrefany` executed.
        address: EmValue,
    },

    /// A `System.Text.Encoding` instance (for encoding stubs).
    Encoding {
        /// The encoding type.
        encoding_type: EncodingType,
    },

    /// A cryptographic hash/asymmetric algorithm instance (for crypto stubs).
    ///
    /// Used to stub `MD5`, `SHA1`, `SHA256`, `HMACSHA256`, `HMACSHA512`,
    /// `RSACryptoServiceProvider`, etc.
    /// Supports incremental hashing via `accumulated_data` / `hash_result`,
    /// HMAC keyed hashing via `hmac_key`, and RSA key import via `rsa_public_key`.
    CryptoAlgorithm {
        /// The algorithm name (e.g., "MD5", "SHA1", "SHA256", "HMACSHA256", "HMACSHA512", "RSA").
        algorithm_type: Arc<str>,
        /// Data accumulated via `TransformBlock` for incremental hashing.
        accumulated_data: Vec<u8>,
        /// Computed hash after `TransformFinalBlock` / `finalize_hash`.
        hash_result: Option<Vec<u8>>,
        /// Imported RSA public key as (modulus, exponent) from `FromXmlString`.
        rsa_public_key: Option<(Vec<u8>, Vec<u8>)>,
        /// HMAC key for keyed hash algorithms (`HMACSHA256`, `HMACSHA512`).
        hmac_key: Option<Vec<u8>>,
    },

    /// A symmetric encryption algorithm instance (for crypto stubs).
    ///
    /// Used to stub `Aes`, `DES`, `TripleDES`, etc.
    SymmetricAlgorithm {
        /// The algorithm name (e.g., "AES", "DES", "TripleDES").
        algorithm_type: Arc<str>,
        /// The encryption key, if set.
        key: Option<Vec<u8>>,
        /// The initialization vector, if set.
        iv: Option<Vec<u8>>,
        /// Cipher mode: 1=CBC (default), 2=ECB, 4=CFB — matches .NET CipherMode enum.
        mode: u8,
        /// Padding mode: 1=None, 2=PKCS7 (default), 3=Zeros — matches .NET PaddingMode enum.
        padding: u8,
    },

    /// A crypto transform instance (encryptor/decryptor).
    ///
    /// Represents an `ICryptoTransform` implementation with all parameters
    /// needed to perform actual encryption/decryption.
    CryptoTransform {
        /// The algorithm name (e.g., "AES", "DES", "TripleDES", "Rijndael").
        algorithm: Arc<str>,
        /// The encryption key.
        key: Vec<u8>,
        /// The initialization vector.
        iv: Vec<u8>,
        /// Whether this is an encryptor (true) or decryptor (false).
        is_encryptor: bool,
        /// Cipher mode: 1=CBC (default), 2=ECB, 4=CFB.
        mode: u8,
        /// Padding mode: 1=None, 2=PKCS7 (default), 3=Zeros.
        padding: u8,
    },

    /// A reflection method info object.
    ///
    /// Created by `Module.ResolveMethod()` to track the resolved method token.
    /// Used by `MethodBase.Invoke()` to determine which method to call.
    ReflectionMethod {
        /// The method token that was resolved.
        method_token: Token,
        /// Method-level generic type arguments (from `MakeGenericMethod`).
        /// `None` for non-generic or open method references.
        method_type_args: Option<Vec<Token>>,
    },

    /// A reflection type object carrying the actual metadata type token.
    ///
    /// Created by `Type.GetTypeFromHandle()` to track which type was resolved.
    /// Used by `Type.GetFields()` to look up fields from the assembly metadata.
    ReflectionType {
        /// The TypeDef/TypeRef/TypeSpec metadata token.
        type_token: Token,
        /// Optional wrapper type override for types created by
        /// `MakeByRefType`, `MakeArrayType`, `MakeGenericType`.
        /// When set, this takes precedence over the type registry lookup
        /// for `IsByRef`/`IsArray`/`IsPointer`/`IsGenericType` checks.
        wrapper: Option<TypeWrapper>,
    },

    /// A reflection field info object carrying field and declaring type tokens.
    ///
    /// Created by `Type.GetFields()` to track which field was resolved.
    /// Used by `FieldInfo.SetValue()` and `FieldInfo.GetValue()` to read/write field values.
    ReflectionField {
        /// The FieldDef metadata token (0x04 table).
        field_token: Token,
        /// The TypeDef token of the type that declares this field.
        declaring_type_token: Token,
        /// Whether this is a static field.
        is_static: bool,
    },

    /// A reflection property info object carrying property metadata.
    ///
    /// Created by `Type.GetProperty()` to track which property was resolved.
    /// Used by `PropertyInfo.GetValue()` and `PropertyInfo.SetValue()` to invoke
    /// the getter/setter methods via `ReflectionInvokeRequest`.
    ReflectionProperty {
        /// The property name.
        property_name: Arc<str>,
        /// The TypeDef token of the type that declares this property.
        declaring_type_token: Token,
        /// The method token for the getter, if any.
        getter_token: Option<Token>,
        /// The method token for the setter, if any.
        setter_token: Option<Token>,
    },

    /// A reflection parameter info object carrying parameter metadata.
    ///
    /// Created by `MethodBase.GetParameters()` to provide real parameter type
    /// information. Used by `ParameterInfo.get_ParameterType` to return the
    /// actual parameter type.
    ReflectionParameter {
        /// The method token that owns this parameter.
        method_token: Token,
        /// The zero-based position of this parameter in the method signature.
        position: u32,
        /// The type signature of this parameter.
        parameter_type: TypeSignature,
    },

    /// A `System.Reflection.Emit.DynamicMethod` instance.
    ///
    /// The `il_generator` holds the complete IL bytecode via
    /// `InstructionAssembler`, which is finalized into a synthetic method
    /// body on `CreateDelegate`.
    DynamicMethod {
        /// The ILGenerator associated with this DynamicMethod, if created.
        il_generator: Option<HeapRef>,
        /// Whether this DynamicMethod is a static method.
        is_static: bool,
        /// Parameter type tokens for the method signature.
        param_types: Vec<Token>,
        /// Return type token (None = void).
        return_type: Option<Token>,
    },

    /// A `System.Reflection.Emit.ILGenerator` instance.
    ///
    /// Uses the existing `InstructionAssembler` to accumulate CIL instructions
    /// so that `DynamicMethod.CreateDelegate()` can finalize the IL into a
    /// synthetic method body that the emulator's interpreter can execute.
    ILGenerator {
        /// Reference to the DynamicMethod this generator belongs to.
        dynamic_method: HeapRef,
        /// The instruction assembler that accumulates IL instructions.
        assembler: Arc<Mutex<InstructionAssembler>>,
        /// Label names: maps label index (from `DefineLabel`) to the label name
        /// string used in the assembler's label system.
        label_names: Box<boxcar::Vec<String>>,
        /// Token map: maps synthetic token IDs emitted in IL to real metadata tokens.
        token_map: Box<boxcar::Vec<(u32, Token)>>,
        /// Declared local variable type tokens.
        local_types: Box<boxcar::Vec<Token>>,
    },

    /// A key derivation function instance (PBKDF2, PasswordDeriveBytes).
    ///
    /// Stores the parameters needed to derive cryptographic keys from passwords.
    /// Used by `Rfc2898DeriveBytes` and `PasswordDeriveBytes` stubs.
    KeyDerivation {
        /// The password bytes (UTF-8 encoded).
        password: Vec<u8>,
        /// The salt bytes.
        salt: Vec<u8>,
        /// The iteration count for PBKDF2.
        iterations: u32,
        /// The hash algorithm ("SHA1", "SHA256", "SHA384", "SHA512").
        hash_algorithm: Arc<str>,
    },

    /// A generic dictionary (key-value store).
    ///
    /// Used to emulate `System.Collections.Generic.Dictionary<TKey, TValue>`.
    /// Keys are stored as [`DictionaryKey`] supporting integers, strings, booleans,
    /// chars, and object references.
    Dictionary {
        /// The stored entries: key → value.
        entries: HashMap<DictionaryKey, EmValue>,
    },

    /// A generic list (`System.Collections.Generic.List<T>`).
    ///
    /// Stores elements in insertion order with indexed access.
    /// Used by obfuscator initialization routines that build collections
    /// of delegate proxies, field references, and other runtime data.
    List {
        /// The stored elements in insertion order.
        elements: Vec<EmValue>,
    },

    /// A stream instance (MemoryStream, resource stream, etc.).
    ///
    /// Stores the stream data buffer and current read/write position.
    /// Used by `GetManifestResourceStream`, `MemoryStream`, etc.
    Stream {
        /// The stream data buffer (mutable for write support).
        data: Vec<u8>,
        /// Current position in the stream.
        position: usize,
    },

    /// A `System.Text.StringBuilder` instance.
    ///
    /// Stores a mutable string buffer for efficient string building operations.
    StringBuilder {
        /// The current string buffer contents.
        buffer: String,
        /// The capacity hint (informational only).
        capacity: usize,
    },

    /// A `System.Collections.Generic.Stack<T>` instance (LIFO).
    Stack {
        /// Elements stored with the top of the stack at the end.
        elements: Vec<EmValue>,
    },

    /// A `System.Collections.Generic.Queue<T>` instance (FIFO).
    Queue {
        /// Elements stored with the front at index 0.
        elements: VecDeque<EmValue>,
    },

    /// A `System.Collections.Generic.HashSet<T>` instance.
    HashSet {
        /// The stored elements using [`DictionaryKey`] for hashing.
        elements: StdHashSet<DictionaryKey>,
    },

    /// A CryptoStream instance wrapping another stream with encryption/decryption.
    ///
    /// Uses "transform-all-at-once" approach: on first read/flush, the entire
    /// underlying data is transformed and cached. This is simpler than true
    /// streaming but sufficient for deobfuscation purposes.
    CryptoStream {
        /// The underlying stream to read from or write to.
        underlying_stream: HeapRef,
        /// The crypto transform (encryptor/decryptor).
        transform: HeapRef,
        /// The mode: 0 = Read (decrypt from underlying), 1 = Write (encrypt to underlying).
        mode: u8,
        /// Cached transformed data (decrypted for Read mode, encrypted for Write mode).
        /// `None` until the first read or flush triggers transformation.
        transformed_data: Option<Vec<u8>>,
        /// Current read position in the transformed data.
        transformed_pos: usize,
        /// Write buffer accumulating data before transformation (Write mode only).
        write_buffer: Vec<u8>,
    },

    /// A compressed stream (DeflateStream or GZipStream).
    ///
    /// Stores a reference to the underlying stream and caches the decompressed
    /// data on first read. Uses "decompress-all-at-once" approach: on first
    /// read, the entire underlying stream is decompressed and cached.
    CompressedStream {
        /// The underlying stream containing compressed data.
        underlying_stream: HeapRef,
        /// Compression type: 0=Deflate, 1=GZip.
        compression_type: u8,
        /// Mode: 0=Decompress, 1=Compress.
        mode: u8,
        /// Cached decompressed data (populated on first read).
        decompressed_data: Option<Vec<u8>>,
        /// Current read position in the decompressed data.
        read_position: usize,
    },
}

impl HeapObject {
    /// Returns a human-readable description of the object kind.
    ///
    /// This is useful for error messages and debugging output.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            HeapObject::String(_) => "string",
            HeapObject::Array { .. } => "array",
            HeapObject::MultiArray { .. } => "multi-dimensional array",
            HeapObject::Object { .. } => "object",
            HeapObject::BoxedValue { .. } => "boxed value",
            HeapObject::Delegate { .. } => "delegate",
            HeapObject::TypedReference { .. } => "typed reference",
            HeapObject::Encoding { .. } => "encoding",
            HeapObject::CryptoAlgorithm { .. } => "crypto algorithm",
            HeapObject::SymmetricAlgorithm { .. } => "symmetric algorithm",
            HeapObject::CryptoTransform { .. } => "crypto transform",
            HeapObject::ReflectionMethod { .. } => "reflection method",
            HeapObject::ReflectionType { .. } => "reflection type",
            HeapObject::ReflectionField { .. } => "reflection field",
            HeapObject::ReflectionProperty { .. } => "reflection property",
            HeapObject::ReflectionParameter { .. } => "reflection parameter",
            HeapObject::DynamicMethod { .. } => "dynamic method",
            HeapObject::ILGenerator { .. } => "IL generator",
            HeapObject::Dictionary { .. } => "dictionary",
            HeapObject::List { .. } => "list",
            HeapObject::StringBuilder { .. } => "string builder",
            HeapObject::Stack { .. } => "stack",
            HeapObject::Queue { .. } => "queue",
            HeapObject::HashSet { .. } => "hash set",
            HeapObject::KeyDerivation { .. } => "key derivation",
            HeapObject::Stream { .. } => "stream",
            HeapObject::CryptoStream { .. } => "crypto stream",
            HeapObject::CompressedStream { .. } => "compressed stream",
        }
    }

    /// Returns the estimated size of this object in bytes.
    ///
    /// This is used for heap memory limit tracking. The estimate includes
    /// object header overhead and data storage, but is not exact.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        // All sizes are estimates for in-memory tracking; saturating arithmetic
        // is correct here — overflow only matters for pathological inputs and
        // saturated `usize::MAX` correctly signals "huge" for limit checks.
        match self {
            HeapObject::String(s) => s.len().saturating_mul(2).saturating_add(24), // Object header + UTF-16
            HeapObject::Array { elements, .. } => elements
                .len()
                .saturating_mul(EMVALUE_SIZE)
                .saturating_add(ARRAY_HEADER_BYTES),
            HeapObject::MultiArray { elements, .. } => elements
                .len()
                .saturating_mul(EMVALUE_SIZE)
                .saturating_add(MULTI_ARRAY_HEADER_BYTES),
            HeapObject::Object { fields, .. } => fields.len().saturating_mul(16).saturating_add(24),
            HeapObject::TypedReference { .. }
            | HeapObject::BoxedValue { .. }
            | HeapObject::CryptoAlgorithm { .. }
            | HeapObject::ReflectionMethod { .. }
            | HeapObject::ReflectionType { .. }
            | HeapObject::ReflectionField { .. }
            | HeapObject::ReflectionProperty { .. }
            | HeapObject::ReflectionParameter { .. }
            | HeapObject::DynamicMethod { .. } => 32,
            HeapObject::ILGenerator { .. } => 128,
            HeapObject::CryptoTransform { key, iv, .. } => {
                48usize.saturating_add(key.len()).saturating_add(iv.len())
            }
            // Charged by content, like every other variadic variant. A flat constant here was a
            // hole in the memory limit rather than an inaccuracy: `Delegate.Combine(d, d)` is
            // legal and doubles the invocation list, so ~30 emulated calls reach a billion
            // entries while the heap accounts each result at the same 48 bytes.
            HeapObject::Delegate {
                invocation_list, ..
            } => invocation_list
                .len()
                .saturating_mul(DELEGATE_ENTRY_BYTES)
                .saturating_add(DELEGATE_HEADER_BYTES),
            HeapObject::Encoding { .. } => 24,
            HeapObject::SymmetricAlgorithm { key, iv, .. } => 32usize
                .saturating_add(key.as_ref().map_or(0, Vec::len))
                .saturating_add(iv.as_ref().map_or(0, Vec::len)),
            HeapObject::Dictionary { entries } => {
                entries.len().saturating_mul(32).saturating_add(48)
            }
            HeapObject::List { elements } => elements
                .len()
                .saturating_mul(EMVALUE_SIZE)
                .saturating_add(LIST_HEADER_BYTES),
            HeapObject::StringBuilder { buffer, .. } => 32usize.saturating_add(buffer.len()),
            HeapObject::Stack { elements } => elements.len().saturating_mul(8).saturating_add(32),
            HeapObject::Queue { elements } => elements.len().saturating_mul(8).saturating_add(32),
            HeapObject::HashSet { elements } => {
                elements.len().saturating_mul(16).saturating_add(48)
            }
            HeapObject::KeyDerivation { password, salt, .. } => 48usize
                .saturating_add(password.len())
                .saturating_add(salt.len()),
            HeapObject::Stream { data, .. } => 32usize.saturating_add(data.len()),
            HeapObject::CryptoStream {
                transformed_data,
                write_buffer,
                ..
            } => 64usize
                .saturating_add(transformed_data.as_ref().map_or(0, Vec::len))
                .saturating_add(write_buffer.len()),
            HeapObject::CompressedStream {
                decompressed_data, ..
            } => 48usize.saturating_add(decompressed_data.as_ref().map_or(0, Vec::len)),
        }
    }
}

impl fmt::Display for HeapObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeapObject::String(s) => {
                if s.chars().count() > 50 {
                    write!(f, "\"{}...\"", truncate_chars(s, 47))
                } else {
                    write!(f, "\"{s}\"")
                }
            }
            HeapObject::Array {
                element_type,
                elements,
            } => {
                write!(f, "{:?}[{}]", element_type, elements.len())
            }
            HeapObject::MultiArray {
                element_type,
                dimensions,
                ..
            } => {
                write!(f, "{element_type:?}[")?;
                for (i, dim) in dimensions.iter().enumerate() {
                    if i > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{dim}")?;
                }
                write!(f, "]")
            }
            HeapObject::Object { type_token, .. } => {
                write!(f, "object({type_token})")
            }
            HeapObject::BoxedValue { type_token, value } => {
                write!(f, "boxed({type_token}, {value})")
            }
            HeapObject::Delegate {
                type_token,
                invocation_list,
            } => {
                if let Some(entry) = invocation_list.last() {
                    write!(f, "delegate({type_token}, {})", entry.method_token)
                } else {
                    write!(f, "delegate({type_token}, empty)")
                }
            }
            HeapObject::TypedReference {
                type_token,
                address,
            } => {
                write!(
                    f,
                    "typed_reference(type=0x{:08x}, addr={address:?})",
                    type_token.value()
                )
            }
            HeapObject::Encoding { encoding_type } => {
                write!(f, "encoding({encoding_type:?})")
            }
            HeapObject::CryptoAlgorithm { algorithm_type, .. } => {
                write!(f, "crypto_algorithm({algorithm_type})")
            }
            HeapObject::SymmetricAlgorithm { algorithm_type, .. } => {
                write!(f, "symmetric_algorithm({algorithm_type})")
            }
            HeapObject::CryptoTransform {
                algorithm,
                is_encryptor,
                key,
                ..
            } => {
                let mode = if *is_encryptor { "encrypt" } else { "decrypt" };
                write!(
                    f,
                    "crypto_transform({} {} key={}B)",
                    algorithm,
                    mode,
                    key.len()
                )
            }
            HeapObject::ReflectionMethod { method_token, .. } => {
                write!(f, "reflection_method(0x{:08x})", method_token.value())
            }
            HeapObject::ReflectionType { type_token, .. } => {
                write!(f, "reflection_type(0x{:08x})", type_token.value())
            }
            HeapObject::ReflectionField {
                field_token,
                declaring_type_token,
                is_static,
            } => {
                let kind = if *is_static { "static" } else { "instance" };
                write!(
                    f,
                    "reflection_field({kind}, 0x{:08x}, declaring=0x{:08x})",
                    field_token.value(),
                    declaring_type_token.value()
                )
            }
            HeapObject::ReflectionProperty {
                property_name,
                declaring_type_token,
                ..
            } => {
                write!(
                    f,
                    "reflection_property({property_name}, declaring=0x{:08x})",
                    declaring_type_token.value()
                )
            }
            HeapObject::ReflectionParameter {
                method_token,
                position,
                ..
            } => {
                write!(
                    f,
                    "reflection_parameter(pos={position}, method=0x{:08x})",
                    method_token.value()
                )
            }
            HeapObject::DynamicMethod { .. } => {
                write!(f, "dynamic_method")
            }
            HeapObject::ILGenerator { dynamic_method, .. } => {
                write!(f, "il_generator(dm={:?})", dynamic_method)
            }
            HeapObject::Dictionary { entries } => {
                write!(f, "dictionary({} entries)", entries.len())
            }
            HeapObject::List { elements } => {
                write!(f, "list({} elements)", elements.len())
            }
            HeapObject::StringBuilder { buffer, .. } => {
                if buffer.chars().count() > 50 {
                    write!(
                        f,
                        "stringbuilder({}... len={})",
                        truncate_chars(buffer, 47),
                        buffer.len()
                    )
                } else {
                    write!(f, "stringbuilder(\"{buffer}\")")
                }
            }
            HeapObject::Stack { elements } => {
                write!(f, "stack({} elements)", elements.len())
            }
            HeapObject::Queue { elements } => {
                write!(f, "queue({} elements)", elements.len())
            }
            HeapObject::HashSet { elements } => {
                write!(f, "hashset({} elements)", elements.len())
            }
            HeapObject::KeyDerivation {
                hash_algorithm,
                iterations,
                ..
            } => {
                write!(
                    f,
                    "key_derivation({hash_algorithm}, {iterations} iterations)"
                )
            }
            HeapObject::Stream { data, position } => {
                write!(f, "stream({} bytes, pos={})", data.len(), position)
            }
            HeapObject::CryptoStream {
                mode,
                transformed_data,
                write_buffer,
                ..
            } => {
                let mode_str = if *mode == 0 { "Read" } else { "Write" };
                let cached = transformed_data.as_ref().map_or(0, Vec::len);
                let buffered = write_buffer.len();
                write!(
                    f,
                    "crypto_stream(mode={mode_str}, cached={cached}, buffered={buffered})"
                )
            }
            HeapObject::CompressedStream {
                compression_type,
                mode,
                decompressed_data,
                read_position,
                ..
            } => {
                let kind = if *compression_type == 0 {
                    "Deflate"
                } else {
                    "GZip"
                };
                let mode_str = if *mode == 0 { "Decompress" } else { "Compress" };
                let cached = decompressed_data.as_ref().map_or(0, Vec::len);
                write!(
                    f,
                    "compressed_stream({kind}, mode={mode_str}, cached={cached}, pos={read_position})"
                )
            }
        }
    }
}

/// Internal state of the managed heap, protected by `RwLock`.
///
/// This struct holds the mutable state that is shared across all heap
/// operations. It is wrapped in `RwLock` to enable concurrent reads
/// and exclusive writes.
///
/// Uses `imbl::HashMap` for O(1) fork via structural sharing.
#[derive(Clone, Debug)]
pub(crate) struct HeapState {
    /// Object storage indexed by reference ID.
    ///
    /// Uses `imbl::HashMap` for O(1) cloning via structural sharing.
    /// This enables efficient `fork()` operations where parent and child
    /// share unmodified entries.
    pub(crate) objects: ImHashMap<u64, HeapObject>,

    /// Preserves the original .NET type token when a heap object is replaced
    /// by a BCL wrapper type (e.g., `Object` → `KeyDerivation`).
    ///
    /// Without this, virtual dispatch fails for replaced objects because the
    /// synthetic BCL type tokens (0x7F00_xxxx) have no metadata type hierarchy.
    pub(crate) original_types: ImHashMap<u64, Token>,
}

/// Simulated managed heap for CIL emulation.
///
/// The managed heap allocates and tracks objects, arrays, and strings.
/// It enforces memory limits to prevent runaway allocation.
///
/// # Interior Mutability
///
/// This struct uses interior mutability via `RwLock`, allowing methods to
/// take `&self` instead of `&mut self`. This enables concurrent access patterns
/// and avoids borrow checker conflicts when accessing multiple heap objects.
///
/// # Copy-on-Write Semantics
///
/// The heap uses `imbl::HashMap` internally, which provides O(1) `clone()`
/// through structural sharing. The `fork()` method creates an independent
/// copy of the heap that shares unmodified data with the original.
///
/// # Memory Limits
///
/// The heap has a configurable maximum size. Exceeding this limit returns
/// an error.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::ManagedHeap;
///
/// let heap = ManagedHeap::new(1024 * 1024); // 1MB limit
///
/// // Allocate a string
/// let string_ref = heap.alloc_string("Hello, World!").unwrap();
///
/// // Read the string (returns Arc<str> for borrow-free access)
/// let value = heap.get_string(string_ref).unwrap();
/// assert_eq!(&*value, "Hello, World!");
///
/// // Fork creates an independent copy (O(1) operation!)
/// let forked = heap.fork().unwrap();
/// // Both heaps share unmodified data via structural sharing
/// ```
#[derive(Debug)]
pub struct ManagedHeap {
    /// Internal state protected by RwLock.
    /// Contains the imbl::HashMap for O(1) fork.
    pub(crate) state: RwLock<HeapState>,
    /// Next reference ID to allocate (atomic for lock-free allocation IDs).
    pub(crate) next_id: AtomicU64,
    /// Current estimated heap size in bytes (atomic for lock-free reads).
    pub(crate) current_size: AtomicUsize,
    /// Maximum allowed heap size in bytes.
    pub(crate) max_size: usize,
    /// Maximum number of live heap objects, independent of their total size.
    ///
    /// A byte ceiling alone does not bound object *count*: a flood of tiny objects is charged
    /// only its header estimate each while really costing an `imbl::HashMap` node plus an
    /// `original_types` entry per object. Set from `EmulationLimits::max_heap_objects`;
    /// `usize::MAX` means unlimited.
    pub(crate) max_objects: AtomicUsize,
}

impl ManagedHeap {
    /// Creates a new managed heap with the given size limit.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum heap size in bytes
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        ManagedHeap {
            state: RwLock::new(HeapState {
                objects: ImHashMap::new(),
                original_types: ImHashMap::new(),
            }),
            next_id: AtomicU64::new(1),
            current_size: AtomicUsize::new(0),
            max_size,
            // Unlimited until a builder applies the configured ceiling, so constructing a heap
            // directly keeps its previous behaviour.
            max_objects: AtomicUsize::new(usize::MAX),
        }
    }

    /// Sets the maximum number of live heap objects.
    ///
    /// See `max_objects` for why a byte ceiling alone is insufficient.
    pub fn set_max_objects(&self, max: usize) {
        self.max_objects.store(max, Ordering::Relaxed);
    }

    /// Creates a managed heap with default size (64MB).
    #[must_use]
    pub fn default_size() -> Self {
        // 64 * 1024 * 1024 = 64 MiB
        Self::new(64usize.saturating_mul(1024).saturating_mul(1024))
    }

    /// Checks if allocation would exceed memory limit.
    ///
    /// Returns `Ok(())` if the allocation can proceed, or an error if the
    /// allocation would exceed [`max_size`](Self::max_size).
    pub(crate) fn check_allocation(&self, size: usize) -> Result<()> {
        let current = self.current_size.load(Ordering::Relaxed);
        if current.saturating_add(size) > self.max_size {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current,
                limit: self.max_size,
            }
            .into());
        }
        Ok(())
    }

    /// Reserves budget for `size` bytes *before* the caller commits any host memory.
    ///
    /// Hook and allocator code that builds a payload whose size is derived from emulated,
    /// attacker-controlled values must call this first. Checking after the payload exists is
    /// useless: the host allocator has already been asked for the memory, so the budget cannot
    /// prevent the very exhaustion it exists to prevent.
    ///
    /// This performs no accounting of its own — the eventual
    /// `alloc_object_internal` records the real size. It is a
    /// gate, not a reservation ledger, so a caller that reserves and then does not allocate
    /// leaks nothing.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if `size` would exceed the budget.
    pub fn reserve(&self, size: usize) -> Result<()> {
        self.check_allocation(size)
    }

    /// Reserves budget for an array of `count` [`EmValue`] elements.
    ///
    /// Charges the same per-element cost that [`HeapObject::estimated_size`] charges, so the
    /// pre-flight gate and the post-allocation accounting cannot disagree.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if the array would exceed the budget.
    pub(crate) fn reserve_elements(&self, count: usize) -> Result<()> {
        self.check_allocation(
            count
                .saturating_mul(EMVALUE_SIZE)
                .saturating_add(ARRAY_HEADER_BYTES),
        )
    }

    /// Internal helper to allocate an object on the heap.
    ///
    /// This consolidates the common allocation pattern: check size limits,
    /// generate ID, insert object, update size tracking. When `type_token`
    /// is `Some`, the token is recorded in `original_types` so that
    /// [`get_type_token`] returns the real .NET type instead of a synthetic
    /// placeholder. This enables virtual dispatch on BCL wrapper objects
    /// created via factory methods (not just the `replace_with_*` path).
    pub(crate) fn alloc_object_internal(
        &self,
        obj: HeapObject,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        let size = obj.estimated_size();
        self.check_allocation(size)?;

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let heap_ref = HeapRef::new(id);

        // Record the original .NET type token at allocation time so it survives
        // BCL wrapper replacements (e.g., Object → Stream/KeyDerivation).
        let original_type = type_token.or(match &obj {
            HeapObject::Object { type_token, .. }
            | HeapObject::BoxedValue { type_token, .. }
            | HeapObject::Delegate { type_token, .. } => Some(*type_token),
            _ => None,
        });

        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;

        // Object-count ceiling, checked under the same lock that performs the insert so the
        // count cannot drift. The byte budget above does not bound count: many small objects
        // pay only their header estimate while each costs a map node plus an entry in
        // `original_types`.
        let max_objects = self.max_objects.load(Ordering::Relaxed);
        if state.objects.len() >= max_objects {
            return Err(EmulationError::ResourceLimitExceeded(format!(
                "heap object count limit reached ({max_objects} objects)"
            ))
            .into());
        }

        state.objects.insert(heap_ref.id(), obj);
        if let Some(token) = original_type {
            state.original_types.insert(heap_ref.id(), token);
        }
        self.current_size.fetch_add(size, Ordering::Relaxed);

        Ok(heap_ref)
    }

    /// Associates a .NET type token with an existing heap object.
    ///
    /// This enables virtual dispatch and type checks on BCL wrapper objects
    /// that were allocated via factory methods. The token is stored in
    /// `original_types` and takes priority in [`Self::get_type_token`].
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn set_type_token(&self, heap_ref: HeapRef, type_token: Token) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        state.original_types.insert(heap_ref.id(), type_token);
        Ok(())
    }

    /// Forks this heap, creating an independent copy with CoW semantics.
    ///
    /// The forked heap shares its data structure with the original via
    /// structural sharing. Both heaps can be modified independently -
    /// only the modified entries are copied (true copy-on-write).
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl::HashMap`'s structural sharing.
    /// The actual data is only copied when either heap modifies an entry.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    ///
    /// # Example
    ///
    /// ```no_run
    /// let heap = ManagedHeap::new(1024 * 1024);
    /// let string_ref = heap.alloc_string("Hello").unwrap();
    ///
    /// let forked = heap.fork().unwrap();
    ///
    /// // Both heaps see the same string
    /// assert_eq!(heap.get_string(string_ref).unwrap().as_ref(), "Hello");
    /// assert_eq!(forked.get_string(string_ref).unwrap().as_ref(), "Hello");
    ///
    /// // Modifications to forked don't affect original
    /// let new_ref = forked.alloc_string("World").unwrap();
    /// assert!(forked.contains(new_ref).unwrap());
    /// assert!(!heap.contains(new_ref).unwrap());
    /// ```
    pub fn fork(&self) -> Result<Self> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(ManagedHeap {
            // imbl::HashMap::clone() is O(1) - structural sharing!
            state: RwLock::new(HeapState {
                objects: state.objects.clone(),
                original_types: state.original_types.clone(),
            }),
            next_id: AtomicU64::new(self.next_id.load(Ordering::SeqCst)),
            current_size: AtomicUsize::new(self.current_size.load(Ordering::Relaxed)),
            max_size: self.max_size,
            // The fork must inherit the ceiling; otherwise forking would itself be an escape
            // from it.
            max_objects: AtomicUsize::new(self.max_objects.load(Ordering::Relaxed)),
        })
    }

    /// Allocates a string on the heap.
    ///
    /// # Arguments
    ///
    /// * `value` - The string value
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_string(&self, value: &str) -> Result<HeapRef> {
        let arc_str: Arc<str> = value.into();
        self.alloc_object_internal(HeapObject::String(arc_str), None)
    }

    /// Allocates an object instance on the heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token of the object
    /// * `field_types` - Field tokens and their types for initialization
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_object_with_fields(
        &self,
        type_token: Token,
        field_types: &[(Token, CilFlavor)],
    ) -> Result<HeapRef> {
        let mut fields = HashMap::new();
        for (token, cil_flavor) in field_types {
            fields.insert(*token, EmValue::default_for_flavor(cil_flavor));
        }
        self.alloc_object_internal(HeapObject::Object { type_token, fields }, None)
    }

    /// Allocates an empty object instance on the heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token of the object
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_object(&self, type_token: Token) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::Object {
                type_token,
                fields: HashMap::new(),
            },
            None,
        )
    }

    /// Allocates a boxed value on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_boxed(&self, type_token: Token, value: EmValue) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::BoxedValue {
                type_token,
                value: Box::new(value),
            },
            None,
        )
    }

    /// Allocates a `TypedReference` on the heap.
    ///
    /// ECMA-335 §III.4.14: packages an address and a type token into
    /// a typed reference that can later be unpacked by `refanyval` or
    /// `refanytype`.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_typed_reference(&self, type_token: Token, address: EmValue) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::TypedReference {
                type_token,
                address,
            },
            None,
        )
    }

    /// Returns the type token stored in a `TypedReference` heap object.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or not a `TypedReference`.
    pub fn typed_reference_type(&self, heap_ref: HeapRef) -> Result<Token> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::TypedReference { type_token, .. }) => Ok(*type_token),
            Some(other) => Err(EmulationError::TypeMismatch {
                operation: "refanytype",
                expected: "TypedReference",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Returns the address stored in a `TypedReference` heap object.
    ///
    /// If `expected_type` is `Some(token)`, verifies that the stored type token
    /// matches, returning `InvalidCast` if it does not (ECMA-335 §III.4.22).
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid, not a `TypedReference`,
    /// or the type check fails.
    pub fn typed_reference_value(
        &self,
        heap_ref: HeapRef,
        expected_type: Option<Token>,
    ) -> Result<EmValue> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::TypedReference {
                type_token,
                address,
            }) => {
                if let Some(expected) = expected_type {
                    if *type_token != expected {
                        return Err(EmulationError::InvalidCast {
                            from_type: format!("TypedReference(0x{:08X})", type_token.value()),
                            to_type: format!("0x{:08X}", expected.value()),
                        }
                        .into());
                    }
                }
                Ok(address.clone())
            }
            Some(other) => Err(EmulationError::TypeMismatch {
                operation: "refanyval",
                expected: "TypedReference",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Allocates a delegate on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_delegate(
        &self,
        type_token: Token,
        target: Option<HeapRef>,
        method_token: Token,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(
            HeapObject::Delegate {
                type_token,
                invocation_list: vec![DelegateEntry {
                    target,
                    method_token,
                }],
            },
            None,
        )
    }

    /// Allocates a multicast delegate on the heap.
    ///
    /// The invocation list is capped at `MAX_DELEGATE_INVOCATION_LIST`; see that constant for
    /// why an unbounded list is reachable in a few dozen emulated instructions.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory, or
    /// [`EmulationError::ResourceLimitExceeded`] if the invocation list is too long.
    pub fn alloc_multicast_delegate(
        &self,
        type_token: Token,
        entries: Vec<DelegateEntry>,
    ) -> Result<HeapRef> {
        if entries.len() > MAX_DELEGATE_INVOCATION_LIST {
            return Err(EmulationError::ResourceLimitExceeded(format!(
                "delegate invocation list of {} entries exceeds maximum {}",
                entries.len(),
                MAX_DELEGATE_INVOCATION_LIST
            ))
            .into());
        }

        self.alloc_object_internal(
            HeapObject::Delegate {
                type_token,
                invocation_list: entries,
            },
            None,
        )
    }

    /// Gets a clone of an object from the heap.
    ///
    /// Returns a cloned `HeapObject` to avoid borrow conflicts. For strings
    /// and other Arc-backed data, cloning is cheap (just incrementing a
    /// reference count).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::InvalidHeapReference`] if the reference is invalid.
    pub fn get(&self, heap_ref: HeapRef) -> Result<HeapObject> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        state.objects.get(&heap_ref.id()).cloned().ok_or(
            EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into(),
        )
    }

    /// Reads an object on the heap in place: `f` sees it under the heap's read lock, without
    /// the copy [`get`](Self::get) makes, which for an array is every element. `f` must not
    /// touch the heap itself.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::InvalidHeapReference`] if the reference is invalid.
    pub fn with_object<F, R>(&self, heap_ref: HeapRef, f: F) -> Result<R>
    where
        F: FnOnce(&HeapObject) -> Result<R>,
    {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let obj =
            state
                .objects
                .get(&heap_ref.id())
                .ok_or(EmulationError::InvalidHeapReference {
                    reference_id: heap_ref.id(),
                })?;
        f(obj)
    }

    /// Applies a mutation function to an object on the heap.
    ///
    /// This method provides controlled mutable access while maintaining
    /// interior mutability semantics.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::InvalidHeapReference`] if the reference is invalid.
    pub fn with_object_mut<F, R>(&self, heap_ref: HeapRef, f: F) -> Result<R>
    where
        F: FnOnce(&mut HeapObject) -> Result<R>,
    {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let obj =
            state
                .objects
                .get_mut(&heap_ref.id())
                .ok_or(EmulationError::InvalidHeapReference {
                    reference_id: heap_ref.id(),
                })?;
        f(obj)
    }

    /// Gets a string from the heap.
    ///
    /// Returns an `Arc<str>` for efficient, borrow-free access. This allows
    /// holding onto the string while performing other heap operations.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or doesn't point to a string.
    pub fn get_string(&self, heap_ref: HeapRef) -> Result<Arc<str>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::String(s)) => Ok(Arc::clone(s)),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "string",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets an object field value (cloned).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid, not an object, or field not found.
    pub fn get_field(&self, heap_ref: HeapRef, field_token: Token) -> Result<EmValue> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Object { fields, .. }) => fields
                .get(&field_token)
                .cloned()
                .ok_or(EmulationError::FieldNotFound { token: field_token }.into()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "object",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Sets an object field value.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not an object.
    pub fn set_field(&self, heap_ref: HeapRef, field_token: Token, value: EmValue) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get_mut(&heap_ref.id()) {
            Some(HeapObject::Object { fields, .. }) => {
                fields.insert(field_token, value);
                Ok(())
            }
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "object",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the type token of an object.
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid.
    pub fn get_type_token(&self, heap_ref: HeapRef) -> Result<Token> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;

        // For BCL wrapper types, check if the original .NET type was preserved
        // from before the object was replaced. This enables virtual dispatch to
        // work correctly even after an Object is converted to a BCL wrapper.
        if let Some(original_token) = state.original_types.get(&heap_ref.id()) {
            return Ok(*original_token);
        }

        match state.objects.get(&heap_ref.id()) {
            Some(
                HeapObject::Object { type_token, .. }
                | HeapObject::BoxedValue { type_token, .. }
                | HeapObject::Delegate { type_token, .. },
            ) => Ok(*type_token),
            Some(HeapObject::String(_)) => Ok(tokens::system::STRING),
            Some(HeapObject::Array { .. } | HeapObject::MultiArray { .. }) => {
                Ok(tokens::system::ARRAY)
            }
            Some(HeapObject::TypedReference { .. }) => Ok(tokens::system::TYPED_REFERENCE),
            Some(HeapObject::Encoding { .. }) => Ok(tokens::system::ENCODING),
            Some(HeapObject::CryptoAlgorithm { .. }) => Ok(tokens::crypto::CRYPTO_ALGORITHM),
            Some(HeapObject::SymmetricAlgorithm { .. }) => Ok(tokens::crypto::SYMMETRIC_ALGORITHM),
            Some(HeapObject::CryptoTransform { .. }) => Ok(tokens::crypto::CRYPTO_TRANSFORM),
            Some(HeapObject::ReflectionMethod { .. }) => Ok(tokens::reflection::METHOD),
            Some(HeapObject::ReflectionType { .. }) => Ok(tokens::reflection::TYPE),
            Some(HeapObject::ReflectionField { .. }) => Ok(tokens::reflection::FIELD),
            Some(HeapObject::ReflectionProperty { .. }) => Ok(tokens::reflection::PROPERTY),
            Some(HeapObject::ReflectionParameter { .. }) => Ok(tokens::reflection::PARAMETER),
            Some(HeapObject::Dictionary { .. }) => Ok(tokens::collections::DICTIONARY),
            Some(HeapObject::List { .. }) => Ok(tokens::collections::LIST),
            Some(HeapObject::StringBuilder { .. }) => Ok(tokens::system::STRING_BUILDER),
            Some(HeapObject::Stack { .. }) => Ok(tokens::collections::STACK),
            Some(HeapObject::Queue { .. }) => Ok(tokens::collections::QUEUE),
            Some(HeapObject::HashSet { .. }) => Ok(tokens::collections::HASH_SET),
            Some(HeapObject::DynamicMethod { .. }) => Ok(tokens::codegen::DYNAMIC_METHOD),
            Some(HeapObject::ILGenerator { .. }) => Ok(tokens::codegen::IL_GENERATOR),
            Some(HeapObject::KeyDerivation { .. }) => Ok(tokens::crypto::KEY_DERIVATION),
            Some(HeapObject::Stream { .. }) => Ok(tokens::io::STREAM),
            Some(HeapObject::CryptoStream { .. }) => Ok(tokens::io::CRYPTO_STREAM),
            Some(HeapObject::CompressedStream { .. }) => Ok(tokens::io::COMPRESSED_STREAM),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Unboxes a value from the heap (cloned).
    ///
    /// # Panics
    ///
    /// Panics if the internal `RwLock` is poisoned.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not a boxed value.
    pub fn unbox(&self, heap_ref: HeapRef) -> Result<EmValue> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::BoxedValue { value, .. }) => Ok((**value).clone()),
            Some(other) => Err(EmulationError::HeapTypeMismatch {
                expected: "boxed value",
                found: other.kind(),
            }
            .into()),
            None => Err(EmulationError::InvalidHeapReference {
                reference_id: heap_ref.id(),
            }
            .into()),
        }
    }

    /// Gets the boxed value (cloned) from the heap.
    ///
    /// # Errors
    ///
    /// Returns error if the reference is invalid or not a boxed value.
    pub fn get_boxed_value(&self, heap_ref: HeapRef) -> Result<EmValue> {
        self.unbox(heap_ref)
    }

    /// Returns `true` if the reference exists on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn contains(&self, heap_ref: HeapRef) -> Result<bool> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(state.objects.contains_key(&heap_ref.id()))
    }

    /// Returns the current estimated heap size in bytes.
    #[must_use]
    pub fn current_size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Returns the maximum heap size in bytes.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Returns the number of allocated objects.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn object_count(&self) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(state.objects.len())
    }

    /// Clears all objects from the heap.
    ///
    /// Note: This doesn't simulate GC, it just empties the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn clear(&self) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        state.objects.clear();
        self.current_size.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Returns all heap objects as a vector of (HeapRef, HeapObject) pairs.
    ///
    /// This clones all objects, which may be expensive for large heaps.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn to_vec(&self) -> Result<Vec<(HeapRef, HeapObject)>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(state
            .objects
            .iter()
            .map(|(&id, obj)| (HeapRef::new(id), obj.clone()))
            .collect())
    }

    /// Returns an iterator over all heap objects.
    ///
    /// Snapshots all objects upfront so no lock is held during iteration.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn iter(&self) -> Result<HeapIter> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let items: Vec<_> = state
            .objects
            .iter()
            .map(|(&id, obj)| (HeapRef::new(id), obj.clone()))
            .collect();
        Ok(HeapIter {
            items: items.into_iter(),
        })
    }

    /// Returns the number of modified entries since fork (for diagnostics).
    ///
    /// Note: This is an approximation based on imbl's internal structure.
    /// After fork, unmodified entries are shared, so this helps understand
    /// memory usage.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn object_count_estimate(&self) -> Result<usize> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(state.objects.len())
    }

    /// Gets a string from the heap (convenience returning Option).
    #[must_use]
    pub fn get_string_opt(&self, heap_ref: HeapRef) -> Option<Arc<str>> {
        self.get_string(heap_ref).ok()
    }

    /// Allocates an encoding object on the heap.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if heap is out of memory.
    pub fn alloc_encoding(
        &self,
        encoding_type: EncodingType,
        type_token: Option<Token>,
    ) -> Result<HeapRef> {
        self.alloc_object_internal(HeapObject::Encoding { encoding_type }, type_token)
    }

    /// Gets the encoding type from an encoding object.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned.
    pub fn get_encoding_type(&self, heap_ref: HeapRef) -> Result<Option<EncodingType>> {
        let state = self
            .state
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        Ok(match state.objects.get(&heap_ref.id()) {
            Some(HeapObject::Encoding { encoding_type }) => Some(*encoding_type),
            _ => None,
        })
    }

    /// Preserves the original .NET type token when a heap object is about to be
    /// replaced by a BCL wrapper. Must be called while holding `state` write lock.
    pub(crate) fn preserve_original_type(state: &mut HeapState, id: u64) {
        if state.original_types.contains_key(&id) {
            return;
        }
        if let Some(
            HeapObject::Object { type_token, .. } | HeapObject::BoxedValue { type_token, .. },
        ) = state.objects.get(&id)
        {
            state.original_types.insert(id, *type_token);
        }
    }

    /// Replaces any heap object at the given reference with a new object.
    ///
    /// Used by collection constructors and StringBuilder mutations.
    ///
    /// The size difference between the outgoing and incoming object is charged against the heap
    /// budget. This is the write-back path for `StringBuilder`, `List`, `Dictionary` and
    /// `HashSet`, so without it every one of those could grow without bound after allocation:
    /// the budget was consulted only when an object was first created, leaving in-place growth
    /// both unchecked and invisible to `current_size`.
    ///
    /// A replacement that would exceed the budget is refused and the existing object is left
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the internal `RwLock` is poisoned, or
    /// [`EmulationError::HeapMemoryLimitExceeded`] if the growth would exceed the budget.
    pub fn replace_object(&self, heap_ref: HeapRef, obj: HeapObject) -> Result<()> {
        let mut state = self
            .state
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "managed heap",
            })?;
        let id = heap_ref.id();
        Self::preserve_original_type(&mut state, id);

        let Some(existing) = state.objects.get(&id) else {
            return Ok(());
        };

        let old_size = existing.estimated_size();
        let new_size = obj.estimated_size();

        // Charge before mutating, so a refused replacement leaves the heap as it was.
        let growth = new_size.saturating_sub(old_size);
        if growth > 0 {
            self.check_allocation(growth)?;
            self.current_size.fetch_add(growth, Ordering::Relaxed);
        } else {
            self.current_size
                .fetch_sub(old_size.saturating_sub(new_size), Ordering::Relaxed);
        }

        state.objects.insert(id, obj);
        Ok(())
    }
}

impl Default for ManagedHeap {
    fn default() -> Self {
        Self::default_size()
    }
}

impl fmt::Display for ManagedHeap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.read().map_err(|_| fmt::Error)?;
        write!(
            f,
            "Heap({} objects, {}/{} bytes)",
            state.objects.len(),
            self.current_size.load(Ordering::Relaxed),
            self.max_size
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    /// A delegate's accounted size must scale with its invocation list.
    ///
    /// While this was a flat constant, `Delegate.Combine(d, d)` — which is legal, since nothing
    /// stops both arguments being the same handle — doubled the list on every call while the
    /// heap charged the same 48 bytes each time. Roughly thirty calls reach a billion entries
    /// with the memory limit offering no resistance at all.
    #[test]
    fn delegate_size_scales_with_invocation_list() {
        let type_token = Token::new(0x0200_0001);
        let entry = || DelegateEntry {
            target: None,
            method_token: Token::new(0x0600_0001),
        };

        let one = HeapObject::Delegate {
            type_token,
            invocation_list: vec![entry()],
        };
        let many = HeapObject::Delegate {
            type_token,
            invocation_list: (0..1000).map(|_| entry()).collect(),
        };

        assert!(
            many.estimated_size() > one.estimated_size(),
            "a longer invocation list must cost more"
        );
        assert!(
            many.estimated_size() >= 1000usize.saturating_mul(DELEGATE_ENTRY_BYTES),
            "every entry must be charged"
        );
    }

    /// The invocation-list cap fails the doubling at its source.
    #[test]
    fn multicast_delegate_invocation_list_is_capped() {
        let heap = ManagedHeap::new(usize::MAX);
        let entries: Vec<DelegateEntry> = (0..MAX_DELEGATE_INVOCATION_LIST.saturating_add(1))
            .map(|_| DelegateEntry {
                target: None,
                method_token: Token::new(0x0600_0001),
            })
            .collect();

        assert!(heap
            .alloc_multicast_delegate(Token::new(0x0200_0001), entries)
            .is_err());
    }

    /// Growing an object in place must be charged, and refused when it does not fit.
    ///
    /// `replace_object` is the write-back path for `StringBuilder`, `List`, `Dictionary` and
    /// `HashSet`. A budget consulted only at creation cannot see growth after allocation.
    #[test]
    fn replace_object_charges_growth_and_refuses_overflow() {
        let heap = ManagedHeap::new(4096);
        let heap_ref = heap.alloc_string("small").unwrap();
        let before = heap.current_size.load(Ordering::Relaxed);

        // A modest growth is charged.
        heap.replace_object(heap_ref, HeapObject::String("a".repeat(100).into()))
            .unwrap();
        let after = heap.current_size.load(Ordering::Relaxed);
        assert!(
            after > before,
            "in-place growth must increase the accounted size"
        );

        // A growth past the budget is refused, and leaves the object untouched.
        let err = heap.replace_object(heap_ref, HeapObject::String("b".repeat(100_000).into()));
        assert!(err.is_err(), "growth past the budget must be refused");
        assert_eq!(
            heap.get_string(heap_ref).unwrap().len(),
            100,
            "a refused replacement must not mutate the object"
        );
    }

    /// Shrinking must give the budget back, or a long-lived object would ratchet the heap up.
    #[test]
    fn replace_object_credits_shrinkage() {
        let heap = ManagedHeap::new(1024 * 1024);
        let heap_ref = heap.alloc_string(&"a".repeat(1000)).unwrap();
        let before = heap.current_size.load(Ordering::Relaxed);

        heap.replace_object(heap_ref, HeapObject::String("x".into()))
            .unwrap();

        assert!(
            heap.current_size.load(Ordering::Relaxed) < before,
            "shrinking must return budget"
        );
    }

    /// The object-count ceiling bounds a flood of tiny objects, which the byte budget does not:
    /// each pays only its header estimate while costing a map node plus an `original_types` entry.
    #[test]
    fn heap_object_count_is_capped() {
        let heap = ManagedHeap::new(usize::MAX);
        heap.set_max_objects(8);

        for _ in 0..8 {
            heap.alloc_string("x").unwrap();
        }

        assert!(
            heap.alloc_string("x").is_err(),
            "allocation past the object ceiling must fail"
        );
    }

    /// A fork must inherit the object ceiling, or forking would itself escape it.
    #[test]
    fn fork_inherits_object_ceiling() {
        let heap = ManagedHeap::new(usize::MAX);
        heap.set_max_objects(4);
        heap.alloc_string("x").unwrap();

        let forked = heap.fork().unwrap();
        assert_eq!(forked.max_objects.load(Ordering::Relaxed), 4);

        for _ in 0..3 {
            forked.alloc_string("y").unwrap();
        }
        assert!(forked.alloc_string("z").is_err());
    }

    #[test]
    fn test_heap_alloc_string() {
        let heap = ManagedHeap::new(1024 * 1024);

        let string_ref = heap.alloc_string("Hello, World!").unwrap();
        assert!(heap.contains(string_ref).unwrap());

        let value = heap.get_string(string_ref).unwrap();
        assert_eq!(&*value, "Hello, World!");
    }

    #[test]
    fn test_heap_alloc_object() {
        let heap = ManagedHeap::new(1024 * 1024);

        let type_token = Token::new(0x0200_0001);
        let field_token = Token::new(0x0400_0001);
        let obj_ref = heap
            .alloc_object_with_fields(type_token, &[(field_token, CilFlavor::I4)])
            .unwrap();

        // Field should be default initialized
        let field = heap.get_field(obj_ref, field_token).unwrap();
        assert_eq!(field, EmValue::I32(0));

        // Set field
        heap.set_field(obj_ref, field_token, EmValue::I32(42))
            .unwrap();
        let field = heap.get_field(obj_ref, field_token).unwrap();
        assert_eq!(field, EmValue::I32(42));
    }

    #[test]
    fn test_heap_boxing() {
        let heap = ManagedHeap::new(1024 * 1024);

        let type_token = Token::new(0x0200_0001);
        let boxed_ref = heap.alloc_boxed(type_token, EmValue::I32(42)).unwrap();

        let value = heap.unbox(boxed_ref).unwrap();
        assert_eq!(value, EmValue::I32(42));
    }

    #[test]
    fn test_heap_out_of_memory() {
        let heap = ManagedHeap::new(100); // Very small

        // Try to allocate large string
        let large_string = "A".repeat(1000);
        let result = heap.alloc_string(&large_string);
        assert!(matches!(
            result,
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::HeapMemoryLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_heap_invalid_reference() {
        let heap = ManagedHeap::new(1024 * 1024);

        let fake_ref = HeapRef::new(9999);
        assert!(heap.get(fake_ref).is_err());
        assert!(!heap.contains(fake_ref).unwrap());
    }

    #[test]
    fn test_heap_type_mismatch() {
        let heap = ManagedHeap::new(1024 * 1024);

        let string_ref = heap.alloc_string("test").unwrap();

        // Try to get array element from string
        assert!(matches!(
            heap.get_array_element(string_ref, 0),
            Err(Error::Emulation(ref e)) if matches!(e.as_ref(), EmulationError::HeapTypeMismatch { .. })
        ));
    }

    #[test]
    fn test_heap_clear() {
        let heap = ManagedHeap::new(1024 * 1024);

        heap.alloc_string("test").unwrap();
        heap.alloc_array(CilFlavor::I4, 10).unwrap();

        assert!(heap.object_count().unwrap() > 0);

        heap.clear().unwrap();
        assert_eq!(heap.object_count().unwrap(), 0);
        assert_eq!(heap.current_size(), 0);
    }

    #[test]
    fn test_heap_display() {
        let heap = ManagedHeap::new(1024 * 1024);
        heap.alloc_string("test").unwrap();

        let display = format!("{heap}");
        assert!(display.contains("1 objects"));
    }

    #[test]
    fn test_heap_object_display() {
        let obj = HeapObject::String("test".into());
        assert!(format!("{obj}").contains("test"));

        let obj = HeapObject::Array {
            element_type: CilFlavor::I4,
            elements: vec![EmValue::I32(0); 5],
        };
        assert!(format!("{obj}").contains("5"));
    }

    #[test]
    fn test_heap_concurrent_access() {
        // Test that we can access the heap without borrow conflicts
        let heap = ManagedHeap::new(1024 * 1024);

        let s1 = heap.alloc_string("first").unwrap();
        let s2 = heap.alloc_string("second").unwrap();

        // Get both strings without borrow conflicts
        let str1 = heap.get_string(s1).unwrap();
        let str2 = heap.get_string(s2).unwrap();

        assert_eq!(&*str1, "first");
        assert_eq!(&*str2, "second");

        // Can still allocate while holding references
        let s3 = heap.alloc_string("third").unwrap();
        let str3 = heap.get_string(s3).unwrap();

        assert_eq!(&*str3, "third");
        // Original Arc references still valid
        assert_eq!(&*str1, "first");
    }

    #[test]
    fn test_heap_fork() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate some objects
        let s1 = heap.alloc_string("original").unwrap();
        let arr1 = heap.alloc_array(CilFlavor::I4, 5).unwrap();
        heap.set_array_element(arr1, 0, EmValue::I32(42)).unwrap();

        // Fork the heap
        let forked = heap.fork().unwrap();

        // Both heaps should see the same data
        assert_eq!(heap.get_string(s1).unwrap().as_ref(), "original");
        assert_eq!(forked.get_string(s1).unwrap().as_ref(), "original");
        assert_eq!(heap.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));
        assert_eq!(forked.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));

        // Modify the forked heap
        forked
            .set_array_element(arr1, 0, EmValue::I32(100))
            .unwrap();
        let s2 = forked.alloc_string("forked").unwrap();

        // Original heap should be unchanged
        assert_eq!(heap.get_array_element(arr1, 0).unwrap(), EmValue::I32(42));
        assert!(!heap.contains(s2).unwrap());

        // Forked heap should have the new values
        assert_eq!(
            forked.get_array_element(arr1, 0).unwrap(),
            EmValue::I32(100)
        );
        assert!(forked.contains(s2).unwrap());
        assert_eq!(forked.get_string(s2).unwrap().as_ref(), "forked");
    }

    #[test]
    fn test_heap_fork_isolation() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate in original
        let s1 = heap.alloc_string("hello").unwrap();

        // Create multiple forks
        let fork1 = heap.fork().unwrap();
        let fork2 = heap.fork().unwrap();

        // Allocate in each fork - they will get the same IDs since they
        // started from the same next_id, but the objects are independent
        let f1_str = fork1.alloc_string("fork1").unwrap();
        let f2_str = fork2.alloc_string("fork2").unwrap();

        // Both forks see the original string
        assert!(fork1.contains(s1).unwrap());
        assert!(fork2.contains(s1).unwrap());
        assert_eq!(fork1.get_string(s1).unwrap().as_ref(), "hello");
        assert_eq!(fork2.get_string(s1).unwrap().as_ref(), "hello");

        // Each fork sees its own allocation (with the same ID, but different content)
        assert_eq!(fork1.get_string(f1_str).unwrap().as_ref(), "fork1");
        assert_eq!(fork2.get_string(f2_str).unwrap().as_ref(), "fork2");

        // Original should not see any fork allocations
        // (the IDs are the same, but original doesn't have those objects)
        assert!(heap.contains(s1).unwrap());
        assert!(!heap.contains(f1_str).unwrap()); // ID 2 doesn't exist in original
    }

    #[test]
    fn test_heap_fork_cow_semantics() {
        let heap = ManagedHeap::new(1024 * 1024);

        // Allocate an array
        let arr = heap.alloc_array(CilFlavor::I4, 3).unwrap();
        heap.set_array_element(arr, 0, EmValue::I32(1)).unwrap();
        heap.set_array_element(arr, 1, EmValue::I32(2)).unwrap();
        heap.set_array_element(arr, 2, EmValue::I32(3)).unwrap();

        // Fork
        let forked = heap.fork().unwrap();

        // Both see the same initial values
        assert_eq!(heap.get_array_element(arr, 0).unwrap(), EmValue::I32(1));
        assert_eq!(forked.get_array_element(arr, 0).unwrap(), EmValue::I32(1));

        // Modify in forked - this triggers CoW at the data structure level
        forked.set_array_element(arr, 0, EmValue::I32(100)).unwrap();

        // Original is unchanged (CoW worked!)
        assert_eq!(heap.get_array_element(arr, 0).unwrap(), EmValue::I32(1));
        assert_eq!(heap.get_array_element(arr, 1).unwrap(), EmValue::I32(2));
        assert_eq!(heap.get_array_element(arr, 2).unwrap(), EmValue::I32(3));

        // Forked has the new value
        assert_eq!(forked.get_array_element(arr, 0).unwrap(), EmValue::I32(100));
        // But other elements are still shared (at the object level, not imbl level)
        assert_eq!(forked.get_array_element(arr, 1).unwrap(), EmValue::I32(2));
        assert_eq!(forked.get_array_element(arr, 2).unwrap(), EmValue::I32(3));
    }
}
