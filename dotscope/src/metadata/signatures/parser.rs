//! Binary signature parser implementation for .NET metadata signatures.
//!
//! This module provides the core parsing engine for all .NET signature types according to
//! the ECMA-335 specification. The parser handles the binary blob format used to encode
//! type information, method signatures, and other metadata elements in .NET assemblies.
//!
//! # Parser Architecture
//!
//! The signature parser is built around a single [`SignatureParser`] struct that maintains
//! parsing state and provides methods for extracting different signature types from binary
//! data. The parser uses an iterative stack-based approach to handle complex nested types while
//! maintaining protection against malformed data and excessive nesting depth.
//!
//! ## Core Components
//!
//! - **Binary Reader**: Low-level byte stream processing with compressed integer support
//! - **Type Parser**: Iterative type signature parsing with nesting depth limiting
//! - **Custom Modifier Handler**: Support for modreq/modopt type annotations
//! - **Token Resolution**: Compressed metadata token decoding
//! - **Error Recovery**: Comprehensive error reporting with context information
//!
//! # Supported Signature Types
//!
//! ## Method Signatures (`MethodDefSig`, `MethodRefSig`, `StandAloneMethodSig`)
//! - Standard managed calling conventions (DEFAULT, HASTHIS, `EXPLICIT_THIS`)
//! - Platform invoke calling conventions (C, STDCALL, THISCALL, FASTCALL)
//! - Variable argument signatures (VARARG with sentinel markers)
//! - Generic method signatures with type parameter counts
//! - Parameter lists with byref and custom modifiers
//!
//! ## Field Signatures
//! - Simple field type declarations
//! - Custom modifiers (modreq/modopt) for interop scenarios
//! - Complex field types including arrays, pointers, and generic instantiations
//!
//! ## Property Signatures  
//! - Instance and static property declarations
//! - Indexed properties with parameter lists
//! - Custom modifiers on property types and parameters
//!
//! ## Local Variable Signatures
//! - Method local variable type lists
//! - Pinned variables for unsafe code and interop
//! - `ByRef` locals for reference semantics
//! - `TypedByRef` for reflection scenarios
//!
//! ## Type Specification Signatures
//! - Generic type instantiations (List&lt;T&gt;, Dictionary&lt;K,V&gt;)
//! - Complex array types with bounds and dimensions
//! - Pointer and managed reference types
//! - Function pointer signatures
//!
//! ## Method Specification Signatures
//! - Generic method instantiation type arguments
//! - Type argument lists for method calls
//! - Constraint validation support
//!
//! # Binary Format Details
//!
//! ## Element Type Encoding
//! Primitive types are encoded as single bytes according to ECMA-335:
//! ```text
//! 0x01: VOID       0x08: I4         0x0E: STRING
//! 0x02: BOOLEAN    0x09: U4         0x0F: PTR
//! 0x03: CHAR       0x0A: I8         0x10: BYREF
//! 0x04: I1         0x0B: U8         0x11: VALUETYPE
//! 0x05: U1         0x0C: R4         0x12: CLASS
//! 0x06: I2         0x0D: R8         0x13: VAR
//! 0x07: U2         0x1C: OBJECT     0x1E: MVAR
//! ```
//!
//! ## Calling Convention Flags
//! Method signatures start with calling convention bytes:
//! ```text
//! 0x00: DEFAULT      0x20: HASTHIS
//! 0x01: C            0x40: EXPLICITTHIS  
//! 0x02: STDCALL      0x10: GENERIC
//! 0x03: THISCALL     0x05: VARARG
//! 0x04: FASTCALL
//! ```
//!
//! ## Compressed Integer Encoding
//! Counts and indices use variable-length encoding:
//! - 0x00-0x7F: Single byte (0-127)
//! - 0x80-0xBF: Two bytes (128-16383)
//! - 0xC0-0xFF: Four bytes (16384+)
//!
//! # Security and Safety
//!
//! ## Nesting Depth Protection
//! The parser includes protection against stack overflow from malformed signatures:
//! - Bounded nesting: 1000 levels per parse plus a 10,000-node budget across the whole
//!   signature, using iterative parsing
//! - Explicit stack-based processing prevents call stack exhaustion
//! - Early termination on depth limit exceeded
//! - Clear error reporting for nesting depth limits
//!
//! ## Buffer Boundary Checking
//! All data access includes bounds checking:
//! - No unchecked array access or pointer arithmetic
//! - Graceful handling of truncated signature data
//! - Clear error messages for malformed input
//!
//! ## Error Handling
//! Comprehensive error reporting for analysis scenarios:
//! - Specific error types for different failure modes
//! - Context information including byte positions
//! - Recovery suggestions for common issues
//!
//! # References
//!
//! - **ECMA-335, Partition II, Section 23.2**: Blobs and signature formats
//! - **ECMA-335, Partition II, Section 23.1**: Metadata validation rules
//! - **`CoreCLR` sigparse.cpp**: Reference implementation patterns
//! - **.NET Runtime Documentation**: Implementation notes and edge cases

use crate::{
    file::parser::Parser,
    metadata::{
        signatures::{
            CustomModifier, SignatureArray, SignatureField, SignatureLocalVariable,
            SignatureLocalVariables, SignatureMethod, SignatureMethodSpec, SignatureParameter,
            SignaturePointer, SignatureProperty, SignatureSzArray, SignatureTypeSpec,
            TypeSignature,
        },
        typesystem::{ArrayDimensions, ELEMENT_TYPE},
    },
    Error::DepthLimitExceeded,
    Result,
};

/// Signature marker bytes as defined in ECMA-335 II.23.2.
///
/// These constants identify the signature type at the start of a signature blob.
/// Note: These overlap numerically with ELEMENT_TYPE but have different semantic meaning
/// in the context of signature headers vs type encoding.
#[allow(non_snake_case)]
pub mod SIGNATURE_HEADER {
    /// Field signature header (ECMA-335 II.23.2.4)
    pub const FIELD: u8 = 0x06;
    /// Local variable signature header (ECMA-335 II.23.2.6)
    pub const LOCAL_SIG: u8 = 0x07;
    /// Property signature header flag (ECMA-335 II.23.2.5)
    pub const PROPERTY: u8 = 0x08;
    /// Method specification signature header (ECMA-335 II.23.2.15)
    pub const GENRICINST: u8 = 0x0A;
}

/// Calling convention flags as defined in ECMA-335 II.23.2.1 for **method signature encoding**.
///
/// These constants are used to decode the calling convention byte in method signatures
/// stored in the blob heap. The low 4 bits (0x0F mask) encode the calling convention kind,
/// while the high bits encode flags like HASTHIS, EXPLICITTHIS, and GENERIC.
///
/// **Important**: These are distinct from [`crate::metadata::tables::PInvokeAttributes`] constants,
/// which use a different encoding (0x0100-0x0500 range) for P/Invoke calling conventions in the
/// ImplMap metadata table. This module is for signature parsing, not P/Invoke metadata.
#[allow(non_snake_case)]
pub mod CALLING_CONVENTION {
    /// Default managed calling convention
    pub const DEFAULT: u8 = 0x00;
    /// C-style calling convention (cdecl)
    pub const C: u8 = 0x01;
    /// Standard calling convention (stdcall)
    pub const STDCALL: u8 = 0x02;
    /// This calling convention (thiscall)
    pub const THISCALL: u8 = 0x03;
    /// Fast calling convention (fastcall)
    pub const FASTCALL: u8 = 0x04;
    /// Variable argument calling convention
    pub const VARARG: u8 = 0x05;
    /// Unmanaged calling convention (C# 9+ function pointers with unmanaged convention)
    pub const UNMANAGED: u8 = 0x09;

    /// Mask for extracting the calling convention kind from the convention byte
    pub const KIND_MASK: u8 = 0x0F;
    /// Flag indicating method has generic parameters
    pub const GENERIC: u8 = 0x10;
    /// Flag indicating method has implicit 'this' parameter
    pub const HASTHIS: u8 = 0x20;
    /// Flag indicating 'this' parameter is explicitly in the signature
    pub const EXPLICITTHIS: u8 = 0x40;
}

/// The deepest a parsed type may nest: the height of the tree it builds, counted across the
/// function pointers it holds. Each level is a `Box` the consumers (drop, `Display`,
/// equality, the reference scanners) walk recursively, so the bound keeps them on a worker's
/// stack. A type's breadth (its generic arguments, a method's parameters) is bounded by the
/// bytes that state it, not by this.
const MAX_NESTING_DEPTH: usize = 1000;

/// Maximum depth of **native** (call-stack) recursion in this parser.
///
/// Tighter than [`MAX_NESTING_DEPTH`], because the two bound different resources: that one
/// the height of the tree built on the heap, this one real stack frames. A function pointer's
/// signature is parsed by re-entering the parser (`parse_type` → `parse_method_signature` →
/// `parse_param` → `parse_type`), and at debug frame sizes a thousand of those cycles exhaust
/// a worker's stack.
const MAX_NATIVE_RECURSION_DEPTH: usize = 64;

/// Maximum number of array dimensions allowed in a signature.
///
/// .NET supports multi-dimensional arrays, but reasonable limits prevent memory exhaustion
/// attacks. 32 dimensions is far beyond any practical use case.
const MAX_ARRAY_DIMENSIONS: u32 = 32;

/// Maximum number of local variables in a method: locals are numbered by an unsigned 16-bit
/// index (ECMA-335 III.3.43). The declared count is refused past it before anything is
/// allocated against it.
const MAX_LOCAL_VARIABLES: u32 = 65536;

/// Binary signature parser for all .NET metadata signature types according to ECMA-335.
///
/// `SignatureParser` provides a stateful parser for extracting type information from the
/// binary blob format used in .NET assembly metadata. The parser handles all signature
/// types defined in ECMA-335 and includes protection against malformed data, infinite
/// recursion, and buffer overruns.
///
/// # Parser State
///
/// The parser maintains internal state during parsing operations:
/// - **Binary Position**: Current read position in the signature blob
/// - **Recursion Depth**: Current nesting level for recursive type parsing
/// - **Error Context**: Information for meaningful error reporting
///
/// # Thread Safety
///
/// `SignatureParser` is not thread-safe and should not be shared across threads.
/// Create separate parser instances for concurrent signature parsing operations.
///
/// # Usage Pattern
///
/// The parser is designed for single-use parsing of individual signatures. Do not
/// reuse parser instances for multiple signatures as this may lead to incorrect
/// results due to retained internal state.
///
/// # Examples
///
/// ## Basic Method Signature Parsing
///
/// ```rust
/// use dotscope::metadata::signatures::SignatureParser;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a simple instance method: void Method(int param)
/// let signature_data = &[
///     0x20, // HASTHIS calling convention
///     0x01, // 1 parameter
///     0x01, // VOID return type  
///     0x08, // I4 (int) parameter type
/// ];
///
/// let mut parser = SignatureParser::new(signature_data);
/// let method_sig = parser.parse_method_signature()?;
///
/// assert!(method_sig.has_this);
/// assert_eq!(method_sig.params.len(), 1);
/// println!("Method has {} parameters", method_sig.params.len());
/// # Ok(())
/// # }
/// ```
///
/// ## Complex Type Parsing
///
/// ```rust
/// use dotscope::metadata::signatures::{SignatureParser, TypeSignature};
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a generic type instantiation: List<string>
/// let type_data = &[
///     0x15, // GENERICINST  
///     0x12, 0x42, // CLASS token reference
///     0x01, // 1 type argument
///     0x0E, // STRING type argument
/// ];
///
/// let mut parser = SignatureParser::new(type_data);
/// let type_sig = parser.parse_type_spec_signature()?;
///
/// if let TypeSignature::GenericInst(_, args) = &type_sig.base {
///     println!("Generic type with {} arguments", args.len());
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Field Signature with Custom Modifiers
///
/// ```rust
/// use dotscope::metadata::signatures::SignatureParser;
///
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Parse a field with modifiers: modreq(IsConst) int field
/// let field_data = &[
///     0x06, // FIELD signature marker
///     0x1F, 0x42, // CMOD_REQD with token
///     0x08, // I4 (int) field type
/// ];
///
/// let mut parser = SignatureParser::new(field_data);
/// let field_sig = parser.parse_field_signature()?;
///
/// println!("Field has {} custom modifiers", field_sig.modifiers.len());
/// # Ok(())
/// # }
/// ```
///
/// # Error Handling
///
/// The parser provides detailed error information for various failure scenarios:
///
/// ## Malformed Signature Data
/// - Invalid signature headers or magic bytes
/// - Truncated signature data or unexpected end of stream
/// - Unknown element types or calling conventions
///
/// ## Recursion Limits
/// - Protection against stack overflow from circular references
/// - Clear error messages indicating recursion depth exceeded
/// - Safe termination of parsing operations
///
/// ## Format Violations
/// - ECMA-335 compliance validation
/// - Type consistency checking
/// - Proper error context for debugging
///
/// # Performance Considerations
///
/// - **Linear Parsing**: O(n) time complexity where n is signature length
/// - **Memory Efficiency**: Minimal heap allocation during parsing
/// - **Error Recovery**: Fast failure with detailed error information
/// - **Caching**: Consider caching parsed results for frequently accessed signatures
///
/// # ECMA-335 Compliance
///
/// The parser implements the complete ECMA-335 signature specification:
/// - **Partition II, Section 23.2**: Binary blob and signature formats
/// - **Partition II, Section 7**: Type system fundamentals
/// - **Partition I, Section 8**: Common Type System (CTS) integration
/// - **All signature types**: Method, Field, Property, `LocalVar`, `TypeSpec`, `MethodSpec`
pub struct SignatureParser<'a> {
    /// Binary data parser for reading signature bytes
    parser: Parser<'a>,
    /// Native recursion depth: [`parse_type`](Self::parse_type) re-enters itself through a
    /// function pointer's method signature, bounded by [`MAX_NATIVE_RECURSION_DEPTH`].
    depth: usize,

    /// How deep in the tree the type being parsed sits: the levels of the types and function
    /// pointers around it. A function pointer's signature parses its types from here, so
    /// [`MAX_NESTING_DEPTH`] bounds the whole tree's height, not each signature's.
    base_depth: usize,
}

impl<'a> SignatureParser<'a> {
    /// Create a new signature parser for the given binary signature data.
    ///
    /// Initializes a new parser instance with the provided signature blob data.
    /// The parser starts at the beginning of the data and maintains internal
    /// state for tracking parsing progress and recursion depth.
    ///
    /// # Parameters
    /// - `data`: Binary signature data from a .NET assembly's blob heap
    ///
    /// # Returns
    /// A new `SignatureParser` instance ready for parsing operations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::signatures::SignatureParser;
    ///
    /// // Create parser for a simple method signature
    /// let signature_data = &[0x00, 0x00, 0x01]; // DEFAULT, 0 params, VOID
    /// let parser = SignatureParser::new(signature_data);
    /// ```
    ///
    /// # Important Notes
    ///
    /// - **Single Use**: Do not reuse parser instances for multiple signatures
    /// - **Thread Safety**: Not thread-safe, create separate instances for concurrent use
    /// - **Data Lifetime**: Parser borrows the input data, ensure it remains valid
    /// - **State Management**: Parser maintains internal state, reset not supported
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        SignatureParser {
            parser: Parser::new(data),
            depth: 0,
            base_depth: 0,
        }
    }

    /// Reads the compressed count of a list that follows. Each element takes at least a byte,
    /// so a count the bytes that remain cannot hold is refused before anything is allocated
    /// for it.
    ///
    /// # Errors
    ///
    /// [`crate::ParseFailure::OutOfBounds`] when the count exceeds the bytes that remain: the
    /// data ends before the list does.
    fn element_count(&mut self) -> Result<u32> {
        let count = self.parser.read_compressed_uint()?;
        if count as usize > self.parser.len().saturating_sub(self.parser.pos()) {
            return Err(out_of_bounds_error!());
        }
        Ok(count)
    }

    /// Parse a single type signature from the current position in the signature blob, in one
    /// pass in stream order (ECMA-335 II.23.2.12): an array's shape follows its element, a
    /// generic instantiation's arguments its base type.
    ///
    /// # Errors
    /// - [`crate::error::Error::DepthLimitExceeded`]: the type nests deeper than
    ///   [`MAX_NESTING_DEPTH`], or its function pointers deeper than
    ///   [`MAX_NATIVE_RECURSION_DEPTH`]
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid element type or malformed signature data
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated signature data
    fn parse_type(&mut self) -> Result<TypeSignature> {
        self.enter()?;
        let result = self.parse_type_inner();
        self.exit();
        result
    }

    /// Inner implementation of [`parse_type`]; native depth is handled by the caller.
    fn parse_type_inner(&mut self) -> Result<TypeSignature> {
        /// Work items for the iterative parsing stack
        enum WorkItem {
            /// Parse a type signature and push result
            ParseType,
            /// Build PTR from modifiers and the type on the stack
            BuildPtr(Vec<CustomModifier>),
            /// Build BYREF from the type on the stack
            BuildByRef,
            /// Read the array shape that follows the element, then build ARRAY from the
            /// element on the stack
            BuildArray,
            /// Build GENERICINST from the base type and `arg_count` arguments on the stack
            BuildGenericInst { arg_count: u32 },
            /// Build SZARRAY from modifiers and the element on the stack
            BuildSzArray(Vec<CustomModifier>),
            /// Build PINNED from the type on the stack
            BuildPinned,
        }

        let mut work_stack: Vec<WorkItem> = vec![WorkItem::ParseType];
        let mut result_stack: Vec<TypeSignature> = Vec::new();
        // The types under construction around the next one parsed: its ancestors in the tree
        let mut open = 0usize;

        while let Some(work) = work_stack.pop() {
            if !matches!(work, WorkItem::ParseType) {
                open = open.saturating_sub(1);
            }
            match work {
                WorkItem::ParseType => {
                    if self.base_depth.saturating_add(open) >= MAX_NESTING_DEPTH {
                        return Err(DepthLimitExceeded(MAX_NESTING_DEPTH));
                    }
                    let current_byte = self.parser.read_le::<u8>()?;
                    let mut wrap = |item: WorkItem, work_stack: &mut Vec<WorkItem>| {
                        work_stack.push(item);
                        open = open.saturating_add(1);
                        work_stack.push(WorkItem::ParseType);
                    };
                    match current_byte {
                        ELEMENT_TYPE::VOID => result_stack.push(TypeSignature::Void),
                        ELEMENT_TYPE::BOOLEAN => result_stack.push(TypeSignature::Boolean),
                        ELEMENT_TYPE::CHAR => result_stack.push(TypeSignature::Char),
                        ELEMENT_TYPE::I1 => result_stack.push(TypeSignature::I1),
                        ELEMENT_TYPE::U1 => result_stack.push(TypeSignature::U1),
                        ELEMENT_TYPE::I2 => result_stack.push(TypeSignature::I2),
                        ELEMENT_TYPE::U2 => result_stack.push(TypeSignature::U2),
                        ELEMENT_TYPE::I4 => result_stack.push(TypeSignature::I4),
                        ELEMENT_TYPE::U4 => result_stack.push(TypeSignature::U4),
                        ELEMENT_TYPE::I8 => result_stack.push(TypeSignature::I8),
                        ELEMENT_TYPE::U8 => result_stack.push(TypeSignature::U8),
                        ELEMENT_TYPE::R4 => result_stack.push(TypeSignature::R4),
                        ELEMENT_TYPE::R8 => result_stack.push(TypeSignature::R8),
                        ELEMENT_TYPE::STRING => result_stack.push(TypeSignature::String),
                        ELEMENT_TYPE::VALUETYPE => {
                            let token = self.parser.read_compressed_token()?;
                            result_stack.push(TypeSignature::ValueType(token));
                        }
                        ELEMENT_TYPE::CLASS => {
                            let token = self.parser.read_compressed_token()?;
                            result_stack.push(TypeSignature::Class(token));
                        }
                        ELEMENT_TYPE::VAR => {
                            let index = self.parser.read_compressed_uint()?;
                            result_stack.push(TypeSignature::GenericParamType(index));
                        }
                        ELEMENT_TYPE::TYPEDBYREF => result_stack.push(TypeSignature::TypedByRef),
                        ELEMENT_TYPE::I => result_stack.push(TypeSignature::I),
                        ELEMENT_TYPE::U => result_stack.push(TypeSignature::U),
                        ELEMENT_TYPE::FNPTR => {
                            // The signature's types sit below this one in the tree
                            let enclosing = self.base_depth;
                            self.base_depth = enclosing.saturating_add(open).saturating_add(1);
                            let method_sig = self.parse_method_signature();
                            self.base_depth = enclosing;
                            result_stack.push(TypeSignature::FnPtr(Box::new(method_sig?)));
                        }
                        ELEMENT_TYPE::OBJECT => result_stack.push(TypeSignature::Object),
                        ELEMENT_TYPE::MVAR => {
                            let index = self.parser.read_compressed_uint()?;
                            result_stack.push(TypeSignature::GenericParamMethod(index));
                        }
                        ELEMENT_TYPE::INTERNAL => result_stack.push(TypeSignature::Internal),
                        ELEMENT_TYPE::MODIFIER => result_stack.push(TypeSignature::Modifier),
                        ELEMENT_TYPE::SENTINEL => result_stack.push(TypeSignature::Sentinel),
                        ELEMENT_TYPE::PTR => {
                            let modifiers = self.parse_custom_mods()?;
                            wrap(WorkItem::BuildPtr(modifiers), &mut work_stack);
                        }
                        ELEMENT_TYPE::BYREF => wrap(WorkItem::BuildByRef, &mut work_stack),
                        ELEMENT_TYPE::ARRAY => wrap(WorkItem::BuildArray, &mut work_stack),
                        ELEMENT_TYPE::GENERICINST => {
                            // The base type is a class or value type's token, read inline
                            let base = match self.parser.read_le::<u8>()? {
                                ELEMENT_TYPE::CLASS => {
                                    TypeSignature::Class(self.parser.read_compressed_token()?)
                                }
                                ELEMENT_TYPE::VALUETYPE => {
                                    TypeSignature::ValueType(self.parser.read_compressed_token()?)
                                }
                                other => {
                                    return Err(malformed_error!(
                                    "GENERICINST - Next byte is not TYPE_CLASS or TYPE_VALUE - {}",
                                    other
                                ))
                                }
                            };
                            result_stack.push(base);
                            let arg_count = self.element_count()?;
                            work_stack.push(WorkItem::BuildGenericInst { arg_count });
                            open = open.saturating_add(1);
                            work_stack.extend((0..arg_count).map(|_| WorkItem::ParseType));
                        }
                        ELEMENT_TYPE::SZARRAY => {
                            let modifiers = self.parse_custom_mods()?;
                            wrap(WorkItem::BuildSzArray(modifiers), &mut work_stack);
                        }
                        ELEMENT_TYPE::CMOD_REQD => {
                            // We consumed the CMOD_REQD byte, go back so parse_custom_mods can handle it
                            let prev_pos = self
                                .parser
                                .pos()
                                .checked_sub(1)
                                .ok_or_else(|| malformed_error!("Parser position underflow"))?;
                            self.parser.seek(prev_pos)?;
                            let modifiers = self.parse_custom_mods()?;
                            result_stack.push(TypeSignature::ModifiedRequired(modifiers));
                        }
                        ELEMENT_TYPE::CMOD_OPT => {
                            // We consumed the CMOD_OPT byte, go back so parse_custom_mods can handle it
                            let prev_pos = self
                                .parser
                                .pos()
                                .checked_sub(1)
                                .ok_or_else(|| malformed_error!("Parser position underflow"))?;
                            self.parser.seek(prev_pos)?;
                            let modifiers = self.parse_custom_mods()?;
                            result_stack.push(TypeSignature::ModifiedOptional(modifiers));
                        }
                        ELEMENT_TYPE::PINNED => wrap(WorkItem::BuildPinned, &mut work_stack),
                        _ => {
                            return Err(malformed_error!(
                                "Unsupported ELEMENT_TYPE - {}",
                                current_byte
                            ));
                        }
                    }
                }
                WorkItem::BuildPtr(modifiers) => {
                    let base_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing base type for PTR"))?;
                    result_stack.push(TypeSignature::Ptr(SignaturePointer {
                        modifiers,
                        base: Box::new(base_type),
                    }));
                }
                WorkItem::BuildByRef => {
                    let base_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing base type for BYREF"))?;
                    result_stack.push(TypeSignature::ByRef(Box::new(base_type)));
                }
                WorkItem::BuildArray => {
                    let elem_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing element type for ARRAY"))?;
                    let (rank, dimensions) = self.parse_array_shape()?;
                    result_stack.push(TypeSignature::Array(SignatureArray {
                        base: Box::new(elem_type),
                        rank,
                        dimensions,
                    }));
                }
                WorkItem::BuildGenericInst { arg_count } => {
                    // The stack holds the base type, then the arguments, the last on top
                    let first_argument = result_stack
                        .len()
                        .checked_sub(arg_count as usize)
                        .filter(|start| *start > 0)
                        .ok_or_else(|| {
                            malformed_error!("Insufficient types on stack for GENERICINST")
                        })?;
                    let type_args = result_stack.split_off(first_argument);
                    let base_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing base type for GENERICINST"))?;
                    result_stack.push(TypeSignature::GenericInst(Box::new(base_type), type_args));
                }
                WorkItem::BuildSzArray(modifiers) => {
                    let base_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing base type for SZARRAY"))?;
                    result_stack.push(TypeSignature::SzArray(SignatureSzArray {
                        modifiers,
                        base: Box::new(base_type),
                    }));
                }
                WorkItem::BuildPinned => {
                    let base_type = result_stack
                        .pop()
                        .ok_or_else(|| malformed_error!("Missing base type for PINNED"))?;
                    result_stack.push(TypeSignature::Pinned(Box::new(base_type)));
                }
            }
        }

        if result_stack.len() != 1 {
            return Err(malformed_error!(
                "Internal error: expected 1 type on stack, got {}",
                result_stack.len()
            ));
        }

        result_stack
            .pop()
            .ok_or_else(|| malformed_error!("internal: result stack empty after validation"))
    }

    /// Reads an array shape (ECMA-335 II.23.2.13): the rank, the sizes of leading dimensions,
    /// then their lower bounds, which are signed.
    ///
    /// # Errors
    ///
    /// When the shape is truncated, the rank exceeds [`MAX_ARRAY_DIMENSIONS`] (the runtime's
    /// largest), or more sizes or lower bounds are given than the rank has dimensions.
    fn parse_array_shape(&mut self) -> Result<(u32, Vec<ArrayDimensions>)> {
        // `rank` is bounded here and not merely stored: it bounds the size and lower-bound
        // counts below, before anything is allocated against them
        let rank = self.parser.read_compressed_uint()?;
        if rank > MAX_ARRAY_DIMENSIONS {
            return Err(malformed_error!(
                "Array signature has too many dimensions: rank {} (max: {})",
                rank,
                MAX_ARRAY_DIMENSIONS
            ));
        }
        let num_sizes = self.parser.read_compressed_uint()?;
        if num_sizes > MAX_ARRAY_DIMENSIONS {
            return Err(malformed_error!(
                "Array signature has too many dimensions: {} (max: {})",
                num_sizes,
                MAX_ARRAY_DIMENSIONS
            ));
        }
        let mut dimensions: Vec<ArrayDimensions> = Vec::with_capacity(num_sizes as usize);
        for _ in 0..num_sizes {
            dimensions.push(ArrayDimensions {
                size: Some(self.parser.read_compressed_uint()?),
                lower_bound: None,
            });
        }
        let num_lo_bounds = self.parser.read_compressed_uint()?;
        if num_lo_bounds > rank {
            return Err(malformed_error!(
                "Array signature has more lower bounds ({}) than dimensions (rank {})",
                num_lo_bounds,
                rank
            ));
        }
        while dimensions.len() < num_lo_bounds as usize {
            dimensions.push(ArrayDimensions {
                size: None,
                lower_bound: None,
            });
        }
        for i in 0..num_lo_bounds {
            if let Some(dimension) = dimensions.get_mut(i as usize) {
                dimension.lower_bound = Some(self.parser.read_compressed_int()?);
            }
        }
        Ok((rank, dimensions))
    }

    /// Enters one level of native recursion, refusing to go past
    /// [`MAX_NATIVE_RECURSION_DEPTH`].
    ///
    /// Paired with [`exit`](Self::exit) - every early return between the two
    /// would leak a level, so callers use it around a single recursive call.
    fn enter(&mut self) -> Result<()> {
        self.depth = self.depth.saturating_add(1);
        if self.depth >= MAX_NATIVE_RECURSION_DEPTH {
            self.depth = self.depth.saturating_sub(1);
            return Err(DepthLimitExceeded(MAX_NATIVE_RECURSION_DEPTH));
        }
        Ok(())
    }

    /// Leaves one level of nesting.
    fn exit(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Parse custom modifiers (modreq/modopt) from the current signature position.
    ///
    /// Custom modifiers provide additional type information for advanced scenarios such as
    /// C++/CLI interop, const/volatile semantics, and platform-specific type constraints.
    /// This method parses a sequence of modifier tokens that appear before type information.
    ///
    /// # Modifier Types
    ///
    /// ## Required Modifiers (modreq)
    /// - **`CMOD_REQD` (0x1F)**: Required for type identity and compatibility
    /// - **Usage**: Platform interop, const fields, security annotations
    /// - **Impact**: Affects type identity for assignment and method resolution
    ///
    /// ## Optional Modifiers (modopt)  
    /// - **`CMOD_OPT` (0x20)**: Optional hints that don't affect type identity
    /// - **Usage**: Optimization hints, debugging information, tool annotations
    /// - **Impact**: Preserved for metadata consumers but don't affect runtime behavior
    ///
    /// # Binary Format
    ///
    /// Custom modifiers are encoded as:
    /// ```text
    /// [ModifierType] [CompressedToken]
    /// ```
    /// Where `ModifierType` is 0x1F (required) or 0x20 (optional), followed by
    /// a compressed metadata token referencing the modifier type.
    ///
    /// # Examples
    ///
    /// ```text
    /// 0x1F 0x42      // modreq(TypeRef:0x1B000010)  
    /// 0x20 0x35      // modopt(TypeRef:0x100000D)
    /// 0x1F 0x15      // modreq(TypeRef:0x1B000005)
    /// 0x08           // I4 (base type follows modifiers)
    /// ```
    ///
    /// # Returns
    /// A vector of [`crate::metadata::token::Token`] references to the modifier types.
    /// The vector is empty if no custom modifiers are present.
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid compressed token encoding
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated modifier data
    ///
    /// # Performance Notes
    /// - Modifiers are relatively uncommon in most .NET code
    /// - Vector allocation is avoided when no modifiers are present
    /// - Parsing cost is linear in the number of modifiers
    fn parse_custom_mods(&mut self) -> Result<Vec<CustomModifier>> {
        let mut mods = Vec::new();

        while self.parser.has_more_data() {
            let is_required = match self.parser.peek_byte()? {
                0x20 => false,
                0x1F => true,
                _ => break,
            };

            self.parser.advance()?;

            let modifier_token = self.parser.read_compressed_token()?;
            mods.push(CustomModifier {
                is_required,
                modifier_type: modifier_token,
            });
        }

        Ok(mods)
    }

    /// Parse a method parameter or return type with custom modifiers and byref semantics.
    ///
    /// This method parses a single parameter specification that includes optional custom
    /// modifiers, byref semantics, and the parameter type. Parameters and return types
    /// share the same binary format in .NET signatures.
    ///
    /// # Parameter Format
    ///
    /// Parameters are encoded as:
    /// ```text
    /// [CustomModifier*] [BYREF?] [Type]
    /// ```
    ///
    /// ## Custom Modifiers
    /// Zero or more custom modifiers (modreq/modopt) that apply to the parameter type.
    /// These provide additional type information for interop and advanced scenarios.
    ///
    /// ## `ByRef` Semantics
    /// - **BYREF (0x10)**: Indicates reference parameter semantics (`ref`, `out`, `in`)
    /// - **Reference Types**: Creates a reference to the reference (double indirection)
    /// - **Value Types**: Passes by reference instead of by value
    /// - **Null References**: `ByRef` parameters cannot be null references
    ///
    /// ## Parameter Types
    /// Any valid .NET type including primitives, classes, value types, arrays,
    /// generic instantiations, and complex nested types.
    ///
    /// # Examples
    ///
    /// ## Simple Value Parameter
    /// ```text
    /// 0x08           // I4 (int parameter)
    /// ```
    ///
    /// ## Reference Parameter
    /// ```text
    /// 0x10 0x08      // BYREF I4 (ref int parameter)
    /// ```
    ///
    /// ## Parameter with Custom Modifiers
    /// ```text
    /// 0x1F 0x42      // modreq(IsConst)
    /// 0x20 0x35      // modopt(Hint)  
    /// 0x10           // BYREF
    /// 0x0E           // STRING (ref string with modifiers)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureParameter`] containing:
    /// - Custom modifier tokens
    /// - `ByRef` flag for reference semantics
    /// - Complete type signature information
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid parameter encoding
    /// - [`crate::Error::DepthLimitExceeded`]: Parameter type parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated parameter data
    ///
    /// # Usage Notes
    ///
    /// This method is used for both method parameters and return types since they
    /// share the same binary encoding format. The calling context determines the
    /// semantic interpretation of the parsed parameter information.
    fn parse_param(&mut self) -> Result<SignatureParameter> {
        let custom_mods = self.parse_custom_mods()?;

        let mut by_ref = false;
        if self.parser.peek_byte()? == 0x10 {
            self.parser.advance()?;
            by_ref = true;
        }

        Ok(SignatureParameter {
            modifiers: custom_mods,
            by_ref,
            base: self.parse_type()?,
        })
    }

    /// Parse a complete method signature from the signature blob.
    ///
    /// Parses method signatures for method definitions, method references, and standalone
    /// method signatures according to ECMA-335 specification. Method signatures encode
    /// calling conventions, parameter types, return types, and generic information.
    ///
    /// # Method Signature Format
    ///
    /// Method signatures follow this binary structure:
    /// ```text
    /// [CallingConvention] [GenericParamCount?] [ParamCount] [ReturnType] [Param1] [Param2] ...
    /// ```
    ///
    /// ## Calling Convention Byte
    /// The first byte encodes calling convention and method flags:
    /// ```text
    /// Bit 0-3: Calling convention
    ///   0x00: DEFAULT (standard managed)
    ///   0x01: C (cdecl for P/Invoke)
    ///   0x02: STDCALL (stdcall for P/Invoke)  
    ///   0x03: THISCALL (thiscall for P/Invoke)
    ///   0x04: FASTCALL (fastcall for P/Invoke)
    ///   0x05: VARARG (variable arguments)
    ///
    /// Bit 4: GENERIC (0x10) - method has generic parameters
    /// Bit 5: HASTHIS (0x20) - method has implicit 'this' parameter
    /// Bit 6: EXPLICITTHIS (0x40) - 'this' parameter is explicit
    /// ```
    ///
    /// ## Generic Parameter Count
    /// If GENERIC flag is set, the next compressed integer specifies the number
    /// of generic type parameters for the method.
    ///
    /// ## Parameter Processing
    /// Parameters are parsed sequentially, with special handling for:
    /// - **Return Type**: Always the first parameter parsed
    /// - **Regular Parameters**: Method parameters in declaration order  
    /// - **SENTINEL (0x41)**: Marks transition to variable arguments
    /// - **Variable Arguments**: Additional parameters for VARARG methods
    ///
    /// # Supported Method Types
    ///
    /// ## Instance Methods
    /// ```csharp
    /// public int Method(string param)  // HASTHIS, 1 param, I4 return, STRING param
    /// ```
    ///
    /// ## Static Methods
    /// ```csharp
    /// public static void Method()      // DEFAULT, 0 params, VOID return
    /// ```
    ///
    /// ## Generic Methods
    /// ```csharp
    /// public T Method<T>(T item)       // HASTHIS | GENERIC, 1 generic param, 1 param
    /// ```
    ///
    /// ## Variable Argument Methods
    /// ```csharp
    /// public void Method(int a, __arglist)  // VARARG with sentinel
    /// ```
    ///
    /// ## Platform Invoke Methods
    /// ```csharp
    /// [DllImport("kernel32")]
    /// public static extern int GetLastError();  // Various calling conventions
    /// ```
    ///
    /// # Examples
    ///
    /// ## Simple Static Method
    /// ```text
    /// 0x00           // DEFAULT calling convention
    /// 0x00           // 0 parameters
    /// 0x01           // VOID return type
    /// ```
    ///
    /// ## Instance Method with Parameters
    /// ```text
    /// 0x20           // HASTHIS calling convention
    /// 0x02           // 2 parameters
    /// 0x08           // I4 (int) return type
    /// 0x0E           // STRING first parameter
    /// 0x10 0x08      // BYREF I4 second parameter (ref int)
    /// ```
    ///
    /// ## Generic Method
    /// ```text
    /// 0x30           // HASTHIS | GENERIC
    /// 0x01           // 1 generic parameter (T)
    /// 0x01           // 1 method parameter
    /// 0x13 0x00      // VAR 0 return type (T)
    /// 0x13 0x00      // VAR 0 parameter type (T)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureMethod`] containing:
    /// - Calling convention flags and generic parameter count
    /// - Return type information with custom modifiers
    /// - Parameter list with types and modifiers
    /// - Variable argument list (if applicable)
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid calling convention or parameter encoding
    /// - [`crate::Error::DepthLimitExceeded`]: Parameter type parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated signature data
    ///
    /// # Performance Notes
    /// - Parameter vectors are pre-allocated based on parameter count
    /// - Calling convention flags are decoded using bitwise operations
    /// - Generic parameter count is only parsed when GENERIC flag is set
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.1**: `MethodDefSig`
    /// - **Partition II, Section 23.2.2**: `MethodRefSig`
    /// - **Partition II, Section 23.2.3**: `StandAloneMethodSig`
    /// - **Partition I, Section 14.3**: Calling conventions
    ///
    /// # Implementation Notes
    /// This method uses `parse_method_parameters` internally to handle the complex
    /// logic of parsing fixed parameters and optional varargs separated by SENTINEL.
    pub fn parse_method_signature(&mut self) -> Result<SignatureMethod> {
        let convention_byte = self.parser.read_le::<u8>()?;
        let mut convention = SignatureMethod::default();
        convention.set_calling_convention(convention_byte)?;

        let mut method = SignatureMethod {
            param_count_generic: if convention_byte & CALLING_CONVENTION::GENERIC != 0 {
                self.parser.read_compressed_uint()?
            } else {
                0
            },
            param_count: self.element_count()?,
            return_type: self.parse_param()?,
            params: Vec::new(),
            varargs: Vec::new(),
            ..convention
        };

        // Parse fixed parameters and varargs using the helper method
        let (params, varargs) = self.parse_method_parameters(method.param_count)?;
        method.params = params;
        method.varargs = varargs;

        Ok(method)
    }

    /// Parse a method signature's `param_count` parameters: the fixed ones, then, after a
    /// SENTINEL, the varargs of a call site (ECMA-335 II.23.2.2). `ParamCount` counts both, so
    /// what the sentinel leaves of it is the vararg count; the sentinel needs at least one.
    ///
    /// # Returns
    /// The fixed parameters and the varargs (empty without a sentinel).
    fn parse_method_parameters(
        &mut self,
        param_count: u32,
    ) -> Result<(Vec<SignatureParameter>, Vec<SignatureParameter>)> {
        let mut params = Vec::with_capacity(param_count as usize);
        let mut varargs = Vec::new();
        for _ in 0..param_count {
            if self.parser.peek_byte()? == ELEMENT_TYPE::SENTINEL {
                self.parser.advance()?;
                let remaining = (param_count as usize).saturating_sub(params.len());
                if remaining == 0 {
                    return Err(malformed_error!(
                        "A method signature's sentinel is followed by no parameter"
                    ));
                }
                varargs.reserve(remaining);
                for _ in 0..remaining {
                    varargs.push(self.parse_param()?);
                }
                break;
            }
            params.push(self.parse_param()?);
        }
        Ok((params, varargs))
    }

    /// Parse a field signature from the signature blob according to ECMA-335 II.23.2.4.
    ///
    /// Field signatures define the type information for fields in .NET types, including
    /// custom modifiers for advanced scenarios like interop, const semantics, and
    /// platform-specific type constraints.
    ///
    /// # Field Signature Format
    ///
    /// Field signatures follow this binary structure:
    /// ```text
    /// [FIELD] [CustomModifier*] [Type]
    /// ```
    ///
    /// ## Field Signature Header
    /// - **FIELD (0x06)**: Required signature type marker
    /// - **Validation**: Parser verifies the signature starts with 0x06
    /// - **Purpose**: Distinguishes field signatures from other signature types
    ///
    /// ## Custom Modifiers
    /// Zero or more custom modifiers that provide additional type information:
    /// - **modreq**: Required modifiers that affect type identity
    /// - **modopt**: Optional modifiers that provide hints
    /// - **Common Uses**: `volatile`, `const`, interop constraints
    ///
    /// ## Field Types
    /// Any valid .NET type including:
    /// - **Primitive Types**: `int`, `string`, `bool`, etc.
    /// - **Reference Types**: Classes and interfaces  
    /// - **Value Types**: Structs and enums
    /// - **Array Types**: Single and multi-dimensional arrays
    /// - **Generic Types**: Open and closed generic instantiations
    /// - **Pointer Types**: Unmanaged pointers for unsafe scenarios
    ///
    /// # Common Field Scenarios
    ///
    /// ## Simple Field Types
    /// ```csharp
    /// public int counter;           // I4 field
    /// public string name;           // STRING field  
    /// public List<int> items;       // Generic instantiation field
    /// ```
    ///
    /// ## Array Fields
    /// ```csharp
    /// public int[] numbers;         // SZARRAY I4 field
    /// public string[,] matrix;      // ARRAY STRING field with rank 2
    /// ```
    ///
    /// ## Fields with Custom Modifiers
    /// ```csharp
    /// public volatile int flag;     // modreq(IsVolatile) I4 field
    /// public const string Name;     // modreq(IsConst) STRING field
    /// ```
    ///
    /// ## Unsafe Pointer Fields
    /// ```csharp
    /// public unsafe int* ptr;       // PTR I4 field
    /// public unsafe void* handle;   // PTR VOID field
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Integer Field
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x08           // I4 (int) field type
    /// ```
    ///
    /// ## String Array Field
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x1D           // SZARRAY (single-dimensional array)
    /// 0x0E           // STRING element type
    /// ```
    ///
    /// ## Field with Required Modifier
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x1F 0x42      // modreq(TypeRef token)
    /// 0x08           // I4 field type with modifier
    /// ```
    ///
    /// ## Generic Field Type
    /// ```text
    /// 0x06           // FIELD signature marker
    /// 0x15           // GENERICINST
    /// 0x12 0x35      // CLASS List<T> token
    /// 0x01           // 1 type argument
    /// 0x08           // I4 type argument (List<int>)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureField`] containing:
    /// - Custom modifier token list
    /// - Complete field type information
    /// - Type constraints and annotations
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid field signature header (not 0x06)
    /// - [`crate::Error::DepthLimitExceeded`]: Field type parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated field signature data
    ///
    /// # Custom Modifier Applications
    ///
    /// Custom modifiers on fields are commonly used for:
    /// - **volatile**: Memory barrier semantics for multithreading
    /// - **const**: Compile-time constant field values
    /// - **Interop**: C++/CLI and platform-specific type constraints
    /// - **Security**: Type-based security and access control annotations
    ///
    /// # Performance Notes
    /// - Field signatures are typically simple and parse quickly
    /// - Custom modifiers add minimal overhead when present
    /// - Complex generic field types may require recursive parsing
    /// - Caching of parsed field signatures is recommended for hot paths
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.4
    /// for field signature encoding and supports all standard field type scenarios.
    pub fn parse_field_signature(&mut self) -> Result<SignatureField> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != SIGNATURE_HEADER::FIELD {
            return Err(malformed_error!(
                "SignatureField - invalid start - {} (expected {})",
                head_byte,
                SIGNATURE_HEADER::FIELD
            ));
        }

        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        Ok(SignatureField {
            modifiers: custom_mods,
            base: type_sig,
        })
    }

    /// Parse a property signature from the signature blob according to ECMA-335 II.23.2.5.
    ///
    /// Property signatures define the type and parameter information for properties,
    /// including simple properties, indexed properties (indexers), and properties
    /// with custom modifiers. Properties in .NET are implemented as methods but
    /// have their own signature format for metadata storage.
    ///
    /// # Property Signature Format
    ///
    /// Property signatures follow this binary structure:
    /// ```text
    /// [PropertyFlags] [ParamCount] [CustomModifier*] [PropertyType] [Param1] [Param2] ...
    /// ```
    ///
    /// ## Property Flags Byte
    /// The first byte encodes property characteristics:
    /// ```text
    /// Bit 3: PROPERTY (0x08) - Required property signature marker
    /// Bit 5: HASTHIS (0x20) - Property belongs to an instance (not static)
    /// Other bits: Reserved and should be zero
    /// ```
    ///
    /// ## Parameter Count
    /// Compressed integer indicating the number of indexer parameters:
    /// - **0**: Simple property (no indexer parameters)
    /// - **N > 0**: Indexed property with N indexer parameters
    ///
    /// ## Property Type
    /// The type of the property value, which can be any valid .NET type.
    /// Custom modifiers may precede the property type for advanced scenarios.
    ///
    /// ## Indexer Parameters
    /// For indexed properties, parameter specifications define the indexer signature.
    /// Each parameter includes type information and optional custom modifiers.
    ///
    /// # Property Categories
    ///
    /// ## Simple Properties
    /// Standard properties with getter and/or setter methods:
    /// ```csharp
    /// public int Count { get; set; }                    // Instance property
    /// public static string DefaultName { get; set; }   // Static property
    /// ```
    ///
    /// ## Indexed Properties (Indexers)
    /// Properties that accept parameters for indexed access:
    /// ```csharp
    /// public string this[int index] { get; set; }       // Single parameter indexer
    /// public T this[int x, int y] { get; set; }         // Multi-parameter indexer
    /// ```
    ///
    /// ## Properties with Custom Modifiers
    /// Properties with additional type constraints or annotations:
    /// ```csharp
    /// public volatile int Flag { get; set; }            // modreq(IsVolatile) property
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Instance Property
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x00           // 0 parameters (not indexed)
    /// 0x08           // I4 (int) property type
    /// ```
    ///
    /// ## Static String Property
    /// ```text
    /// 0x08           // PROPERTY (static, no HASTHIS)
    /// 0x00           // 0 parameters
    /// 0x0E           // STRING property type
    /// ```
    ///
    /// ## Single-Parameter Indexer
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x01           // 1 indexer parameter
    /// 0x0E           // STRING property type
    /// 0x08           // I4 indexer parameter type
    /// ```
    ///
    /// ## Multi-Parameter Indexer
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x02           // 2 indexer parameters
    /// 0x1C           // OBJECT property type
    /// 0x08           // I4 first parameter (int x)
    /// 0x08           // I4 second parameter (int y)
    /// ```
    ///
    /// ## Generic Property Type
    /// ```text
    /// 0x28           // PROPERTY | HASTHIS
    /// 0x00           // 0 parameters
    /// 0x15           // GENERICINST
    /// 0x12 0x42      // CLASS List<T> token
    /// 0x01           // 1 type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureProperty`] containing:
    /// - Instance vs. static property indication
    /// - Property type with custom modifiers
    /// - Indexer parameter list (empty for simple properties)
    /// - Complete type and modifier information
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid property signature header (missing PROPERTY bit)
    /// - [`crate::Error::DepthLimitExceeded`]: Property or parameter type parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated property signature data
    ///
    /// # Indexer Design Patterns
    ///
    /// ## Collection Indexers
    /// ```csharp
    /// public T this[int index] => items[index];         // Array-style access
    /// ```
    ///
    /// ## Dictionary-Style Indexers
    /// ```csharp
    /// public TValue this[TKey key] => dict[key];        // Key-value access
    /// ```
    ///
    /// ## Multi-Dimensional Indexers
    /// ```csharp
    /// public T this[int row, int col] => matrix[row, col];  // Matrix access
    /// ```
    ///
    /// # Performance Notes
    /// - Simple properties parse very quickly with minimal allocations
    /// - Indexed properties require parameter parsing which scales with parameter count
    /// - Generic property types may require recursive type parsing
    /// - Consider caching parsed property signatures for frequently accessed properties
    ///
    /// # Implementation Relationship
    /// Properties are implemented as methods in IL, but property signatures provide
    /// the high-level abstraction for metadata consumers. The actual getter/setter
    /// methods have their own method signatures that reference this property signature.
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.5
    /// for property signature encoding and supports all standard property scenarios.
    pub fn parse_property_signature(&mut self) -> Result<SignatureProperty> {
        let head_byte = self.parser.read_le::<u8>()?;
        if (head_byte & SIGNATURE_HEADER::PROPERTY) == 0 {
            return Err(malformed_error!(
                "SignatureProperty - invalid start - {} (expected PROPERTY bit {})",
                head_byte,
                SIGNATURE_HEADER::PROPERTY
            ));
        }

        let has_this = (head_byte & CALLING_CONVENTION::HASTHIS) != 0;

        let param_count = self.element_count()?;

        let custom_mods = self.parse_custom_mods()?;
        let type_sig = self.parse_type()?;

        let mut params = Vec::with_capacity(param_count as usize);
        for _ in 0..param_count {
            params.push(self.parse_param()?);
        }

        Ok(SignatureProperty {
            has_this,
            modifiers: custom_mods,
            base: type_sig,
            params,
        })
    }

    /// Parse a local variable signature from the signature blob according to ECMA-335 II.23.2.6.
    ///
    /// Local variable signatures define the types and constraints for all local variables
    /// within a method body. These signatures are used by the JIT compiler for type
    /// checking, memory management, and garbage collection root tracking.
    ///
    /// # Local Variable Signature Format
    ///
    /// Local variable signatures follow this binary structure:
    /// ```text
    /// [LOCAL_SIG] [Count] [LocalVar1] [LocalVar2] ...
    /// ```
    ///
    /// Each local variable specification can include:
    /// ```text
    /// [CustomModifier*] [PINNED?] [BYREF?] [Type]
    /// ```
    ///
    /// ## Local Variable Signature Header
    /// - **`LOCAL_SIG` (0x07)**: Required signature type marker
    /// - **Count**: Compressed integer specifying number of local variables
    /// - **Validation**: Parser verifies signature starts with 0x07
    ///
    /// ## Local Variable Constraints
    ///
    /// ### PINNED Constraint (0x45)
    /// - **Purpose**: Fixes variable location in memory for interop scenarios
    /// - **Usage**: P/Invoke calls, unsafe code, COM interop
    /// - **GC Impact**: Prevents garbage collector from moving the object
    /// - **Syntax**: `fixed` statement in C#, `pin_ptr` in C++/CLI
    ///
    /// ### BYREF Constraint (0x10)
    /// - **Purpose**: Creates reference semantics for local variables
    /// - **Usage**: `ref` locals, `out` parameters stored in locals
    /// - **Memory**: Variable stores address rather than value
    /// - **Restrictions**: Cannot be null, must point to valid memory
    ///
    /// ### TYPEDBYREF Special Type (0x16)
    /// - **Purpose**: Runtime type information for reflection scenarios
    /// - **Usage**: Advanced reflection, method argument handling
    /// - **Contents**: Type information and object reference pair
    /// - **Restrictions**: Cannot be used with other constraints
    ///
    /// # Local Variable Categories
    ///
    /// ## Simple Local Variables
    /// Standard local variables with primitive or reference types:
    /// ```csharp
    /// int counter;              // I4 local
    /// string message;           // STRING local  
    /// List<int> items;          // Generic instantiation local
    /// ```
    ///
    /// ## Reference Local Variables
    /// Local variables that store references to other variables:
    /// ```csharp
    /// ref int refValue = ref someField;     // BYREF I4 local
    /// ref readonly string refText;          // BYREF STRING local
    /// ```
    ///
    /// ## Pinned Local Variables  
    /// Local variables with fixed memory locations for unsafe scenarios:
    /// ```csharp
    /// fixed (byte* ptr = &array[0]) {       // PINNED PTR local
    ///     // ptr location is fixed during this scope
    /// }
    /// ```
    ///
    /// ## `TypedByRef` Locals
    /// Special locals for advanced reflection scenarios:
    /// ```csharp
    /// __makeref(variable);                  // TYPEDBYREF local
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Simple Local Variables
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x02           // 2 local variables
    /// 0x08           // I4 (int) first local
    /// 0x0E           // STRING second local
    /// ```
    ///
    /// ## Reference and Pinned Locals
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x03           // 3 local variables
    /// 0x10 0x08      // BYREF I4 (ref int)
    /// 0x45 0x0F      // PINNED PTR (pinned pointer)
    /// 0x16           // TYPEDBYREF
    /// ```
    ///
    /// ## Locals with Custom Modifiers
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x01           // 1 local variable
    /// 0x1F 0x42      // modreq(IsVolatile)
    /// 0x45           // PINNED constraint
    /// 0x08           // I4 (volatile pinned int)
    /// ```
    ///
    /// ## Complex Generic Local
    /// ```text
    /// 0x07           // LOCAL_SIG marker
    /// 0x01           // 1 local variable
    /// 0x15           // GENERICINST
    /// 0x12 0x35      // CLASS Dictionary<,> token
    /// 0x02           // 2 type arguments
    /// 0x0E           // STRING (TKey)
    /// 0x1C           // OBJECT (TValue)
    /// ```
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureLocalVariables`] containing:
    /// - Array of local variable specifications
    /// - Type information for each local
    /// - Constraint flags (pinned, byref) for each local
    /// - Custom modifier information
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid local variable signature header (not 0x07)
    /// - [`crate::Error::DepthLimitExceeded`]: Local variable type parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated local variable signature data
    ///
    /// # Memory Management Implications
    ///
    /// ## Garbage Collection Roots
    /// Local variables containing reference types serve as GC roots:
    /// - **Reference Locals**: Prevent referenced objects from collection
    /// - **Pinned Locals**: Create fixed memory regions that GC cannot move
    /// - **Lifetime Tracking**: GC tracks local variable lifetimes for collection
    ///
    /// ## Interop Scenarios
    /// Pinned locals are essential for safe interop:
    /// - **P/Invoke**: Passing managed array pointers to native code
    /// - **COM Interop**: Fixed memory for COM interface calls
    /// - **Unsafe Code**: Direct memory manipulation with fixed addresses
    ///
    /// # Performance Considerations
    /// - **Pinned Locals**: Can impact GC performance due to memory fragmentation
    /// - **`ByRef` Locals**: Minimal overhead, similar to pointer operations
    /// - **Parsing Speed**: Linear in the number of local variables
    /// - **Memory Usage**: Efficient parsing with pre-allocated vectors
    ///
    /// # JIT Compiler Usage
    /// The JIT compiler uses local variable signatures for:
    /// - **Stack Frame Layout**: Determining local variable stack positions
    /// - **Type Safety**: Verifying type-safe access to local variables
    /// - **Optimization**: Register allocation and lifetime analysis
    /// - **Debugging Info**: Mapping IL locals to native debug information
    ///
    /// # ECMA-335 Compliance
    /// This implementation follows ECMA-335 6th Edition, Partition II, Section 23.2.6
    /// for local variable signature encoding and supports all standard local variable scenarios.
    pub fn parse_local_var_signature(&mut self) -> Result<SignatureLocalVariables> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != SIGNATURE_HEADER::LOCAL_SIG {
            return Err(malformed_error!(
                "SignatureLocalVar - invalid start - {} (expected {})",
                head_byte,
                SIGNATURE_HEADER::LOCAL_SIG
            ));
        }

        let count = self.parser.read_compressed_uint()?;
        if count > MAX_LOCAL_VARIABLES {
            return Err(malformed_error!(
                "Local variable signature has too many locals: {} (max: {})",
                count,
                MAX_LOCAL_VARIABLES
            ));
        }

        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            locals.push(self.parse_single_local_variable()?);
        }

        Ok(SignatureLocalVariables { locals })
    }

    /// Parse a single local variable with its constraints and modifiers.
    ///
    /// This helper method handles the parsing of individual local variables according to
    /// ECMA-335 II.23.2.6. Local variables can have custom modifiers, PINNED constraints,
    /// and BYREF modifiers in a specific order.
    ///
    /// # Local Variable Grammar
    /// ```text
    /// LocalVarSig ::= LOCAL_SIG Count (TYPEDBYREF | ([CustomMod]* [Constraint]* [BYREF] Type))
    /// Constraint  ::= ELEMENT_TYPE_PINNED
    /// ```
    ///
    /// Note that unlike method parameters, local variable modifiers and constraints can be
    /// interleaved: custom_mod -> constraint -> custom_mod -> ...
    ///
    /// # Returns
    /// A `SignatureLocalVariable` containing:
    /// - Custom modifiers (modreq/modopt)
    /// - Whether the variable is pinned
    /// - Whether the variable is byref
    /// - The variable's type signature
    fn parse_single_local_variable(&mut self) -> Result<SignatureLocalVariable> {
        // TYPEDBYREF special case - no modifiers or constraints allowed
        if self.parser.peek_byte()? == ELEMENT_TYPE::TYPEDBYREF {
            self.parser.advance()?;
            return Ok(SignatureLocalVariable {
                modifiers: Vec::new(),
                is_byref: false,
                is_pinned: false,
                base: TypeSignature::TypedByRef,
            });
        }

        // Parse interleaved custom modifiers and constraints
        let (custom_mods, pinned) = self.parse_local_var_constraints()?;

        // Parse optional BYREF
        let by_ref = if self.parser.peek_byte()? == ELEMENT_TYPE::BYREF {
            self.parser.advance()?;
            true
        } else {
            false
        };

        // Parse the type
        let type_sig = self.parse_type()?;

        Ok(SignatureLocalVariable {
            modifiers: custom_mods,
            is_byref: by_ref,
            is_pinned: pinned,
            base: type_sig,
        })
    }

    /// Parse local variable constraints and custom modifiers.
    ///
    /// This helper method separates the concern of parsing the interleaved sequence of
    /// custom modifiers (CMOD_REQD/CMOD_OPT) and constraints (PINNED) that can appear
    /// before a local variable's type.
    ///
    /// # Returns
    /// A tuple containing:
    /// - `Vec<CustomModifier>`: The custom modifiers found
    /// - `bool`: Whether the PINNED constraint was present
    fn parse_local_var_constraints(&mut self) -> Result<(Vec<CustomModifier>, bool)> {
        let mut custom_mods = Vec::new();
        let mut pinned = false;

        while self.parser.has_more_data() {
            match self.parser.peek_byte()? {
                ELEMENT_TYPE::CMOD_REQD | ELEMENT_TYPE::CMOD_OPT => {
                    let is_required = self.parser.peek_byte()? == ELEMENT_TYPE::CMOD_REQD;
                    self.parser.advance()?;
                    let modifier_token = self.parser.read_compressed_token()?;
                    custom_mods.push(CustomModifier {
                        is_required,
                        modifier_type: modifier_token,
                    });
                }
                ELEMENT_TYPE::PINNED => {
                    // PINNED constraint (ELEMENT_TYPE_PINNED) - II.23.2.9
                    // This constraint applies to the entire local variable,
                    // not to individual custom modifiers.
                    self.parser.advance()?;
                    pinned = true;
                }
                _ => break,
            }
        }

        Ok((custom_mods, pinned))
    }

    /// Parse a type specification signature from the signature blob according to ECMA-335 II.23.2.14.
    ///
    /// Type specification signatures define complex type instantiations that cannot be represented
    /// directly in metadata tables. They are used for generic type instantiations, array types
    /// with complex bounds, function pointer types, and other constructed types.
    ///
    /// # Type Specification Format
    ///
    /// Type specifications contain a single type signature:
    /// ```text
    /// [Type]
    /// ```
    ///
    /// Unlike other signature types, type specifications do not have a signature header byte.
    /// They directly encode the type information using the standard type signature format.
    ///
    /// # Common Type Specification Uses
    ///
    /// ## Generic Type Instantiations
    /// ```csharp
    /// List<string>              // GENERICINST CLASS List<T> with STRING argument
    /// Dictionary<int, object>   // GENERICINST CLASS Dictionary<K,V> with I4, OBJECT arguments
    /// Nullable<DateTime>        // GENERICINST VALUETYPE Nullable<T> with DateTime argument
    /// ```
    ///
    /// ## Complex Array Types
    /// ```csharp
    /// int[,]                    // ARRAY I4 with rank 2
    /// string[,,]                // ARRAY STRING with rank 3  
    /// float[0..10, 0..5]        // ARRAY R4 with bounds and dimensions
    /// ```
    ///
    /// ## Function Pointer Types
    /// ```csharp
    /// delegate*<int, string>    // FNPTR with method signature
    /// delegate* unmanaged<void> // FNPTR with unmanaged calling convention
    /// ```
    ///
    /// ## Constructed Reference Types
    /// ```csharp
    /// string[]                  // SZARRAY STRING (single-dimensional array)
    /// int*                      // PTR I4 (unmanaged pointer)
    /// ref readonly DateTime     // BYREF with custom modifiers
    /// ```
    ///
    /// # Binary Examples
    ///
    /// ## Generic List of Strings
    /// ```text
    /// 0x15           // GENERICINST
    /// 0x12 0x42      // CLASS token (List<T>)
    /// 0x01           // 1 type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// ## Two-Dimensional Array
    /// ```text
    /// 0x14           // ARRAY
    /// 0x08           // I4 element type
    /// 0x02           // rank = 2
    /// 0x00           // 0 size specifications
    /// 0x00           // 0 lower bound specifications
    /// ```
    ///
    /// ## Function Pointer
    /// ```text
    /// 0x1B           // FNPTR
    /// 0x00           // DEFAULT calling convention
    /// 0x01           // 1 parameter
    /// 0x01           // VOID return type
    /// 0x08           // I4 parameter type
    /// ```
    ///
    /// # Usage Context
    ///
    /// Type specifications are referenced from:
    /// - **`TypeSpec` Table**: Metadata table entries for constructed types
    /// - **Signature Blobs**: Complex type references in other signatures
    /// - **Custom Attributes**: Type arguments in attribute instantiations
    /// - **Generic Constraints**: Where clauses and type parameter bounds
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureTypeSpec`] containing the complete
    /// type specification information ready for type system operations.
    ///
    /// # Errors
    /// - [`crate::Error::DepthLimitExceeded`]: Type parsing exceeds maximum nesting depth
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid type encoding or format
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated type specification data
    ///
    /// # Performance Notes
    /// - Type specifications often involve complex recursive parsing
    /// - Generic instantiations with many type arguments require more processing
    /// - Consider caching parsed type specifications for frequently accessed types
    /// - Simple types (primitives, single classes) parse very quickly
    ///
    /// # Thread Safety
    /// This method is not thread-safe. Use separate parser instances for concurrent operations.
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.14**: `TypeSpec` signature format
    /// - **Partition II, Section 22.39**: `TypeSpec` metadata table
    /// - **Partition I, Section 8**: Type system and constructed types
    /// - **Partition II, Section 23.1.16**: Generic type instantiation validation
    pub fn parse_type_spec_signature(&mut self) -> Result<SignatureTypeSpec> {
        // First, parse any custom modifiers at the beginning
        let modifiers = self.parse_custom_mods()?;

        // Then parse the base type signature
        let base_type_sig = self.parse_type()?;

        // If we got a ModifiedRequired/Optional from parse_type, we need to handle it specially.
        //
        // Matched by reference and drained rather than moved out: `TypeSignature` implements
        // `Drop` (for iterative teardown), which makes moving a field out of it illegal.
        let mut base_type_sig = base_type_sig;
        match &mut base_type_sig {
            TypeSignature::ModifiedRequired(mod_modifiers)
            | TypeSignature::ModifiedOptional(mod_modifiers) => {
                // Combine the modifiers from parse_custom_mods() and from the ModifiedRequired
                let mut all_modifiers = modifiers;
                all_modifiers.append(mod_modifiers);

                // Parse the base type that follows the modifiers
                let base_type = self.parse_type()?;

                Ok(SignatureTypeSpec {
                    modifiers: all_modifiers,
                    base: base_type,
                })
            }
            _ => {
                // No additional modifiers, just use what we found
                Ok(SignatureTypeSpec {
                    modifiers,
                    base: base_type_sig,
                })
            }
        }
    }

    /// Parse a method specification signature from the signature blob according to ECMA-335 II.23.2.15.
    ///
    /// Method specification signatures provide type arguments for generic method instantiations.
    /// They are used when calling generic methods with specific type parameters, allowing the
    /// runtime to create concrete method instances from generic method definitions.
    ///
    /// # Method Specification Format
    ///
    /// Method specifications follow this binary structure:
    /// ```text
    /// [GENRICINST] [GenericArgCount] [GenericArg1] [GenericArg2] ...
    /// ```
    ///
    /// ## Method Specification Header
    /// - **GENRICINST (0x0A)**: Required signature type marker for method specifications
    /// - **Validation**: Parser verifies the signature starts with 0x0A
    /// - **Purpose**: Distinguishes method specifications from other signature types
    ///
    /// ## Generic Argument Count
    /// A compressed integer specifying the number of type arguments provided for the
    /// generic method instantiation. This count must match the number of generic
    /// type parameters defined on the target generic method.
    ///
    /// ## Generic Type Arguments
    /// A sequence of complete type signatures, one for each generic type parameter.
    /// Each type argument can be any valid .NET type including:
    /// - **Primitive Types**: `int`, `string`, `bool`, etc.
    /// - **Reference Types**: Classes and interfaces
    /// - **Value Types**: Structs and enums  
    /// - **Constructed Types**: Arrays, generic instantiations, pointers
    /// - **Generic Parameters**: Other generic type or method parameters
    ///
    /// # Generic Method Instantiation Examples
    ///
    /// ## Simple Generic Method Call
    /// ```csharp
    /// // Generic method definition:
    /// public static T Create<T>() where T : new() => new T();
    ///
    /// // Method call with type argument:
    /// var instance = Create<string>();  // T = string
    /// ```
    ///
    /// ## Multiple Type Parameters
    /// ```csharp
    /// // Generic method definition:
    /// public static Dictionary<TKey, TValue> CreateDictionary<TKey, TValue>()
    ///     => new Dictionary<TKey, TValue>();
    ///
    /// // Method call with multiple type arguments:
    /// var dict = CreateDictionary<int, string>();  // TKey = int, TValue = string
    /// ```
    ///
    /// ## Complex Type Arguments
    /// ```csharp
    /// // Generic method definition:
    /// public static List<T[]> CreateArrayList<T>() => new List<T[]>();
    ///
    /// // Method call with array type argument:
    /// var arrays = CreateArrayList<DateTime>();  // T = DateTime, result = List<DateTime[]>
    /// ```
    ///
    /// ## Nested Generic Instantiations
    /// ```csharp
    /// // Generic method definition:
    /// public static T Process<T>(T input) => input;
    ///
    /// // Method call with generic type argument:
    /// var result = Process<List<int>>(myList);  // T = List<int>
    /// ```
    ///
    /// # Binary Format Examples
    ///
    /// ## Single Type Argument (string)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument
    /// 0x0E           // STRING type argument
    /// ```
    ///
    /// ## Multiple Type Arguments (int, string)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker  
    /// 0x02           // 2 generic type arguments
    /// 0x08           // I4 (int) first type argument
    /// 0x0E           // STRING second type argument
    /// ```
    ///
    /// ## Complex Type Argument (`List<DateTime>`)
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument
    /// 0x15           // GENERICINST (generic instantiation)
    /// 0x12 0x42      // CLASS token (List<T>)
    /// 0x01           // 1 type argument for List<T>
    /// 0x12 0x35      // CLASS token (DateTime)
    /// ```
    ///
    /// ## Generic Method Parameter as Argument
    /// ```text
    /// 0x0A           // GENRICINST method specification marker
    /// 0x01           // 1 generic type argument  
    /// 0x1E 0x00      // MVAR 0 (method generic parameter M0)
    /// ```
    ///
    /// # Usage Context
    ///
    /// Method specifications are used in:
    /// - **Method References**: Calls to generic methods from other assemblies
    /// - **Reflection Emit**: Dynamic method generation with generic type arguments
    /// - **Runtime Instantiation**: JIT compilation of generic method instances
    /// - **Metadata Analysis**: Type flow analysis and generic constraint validation
    ///
    /// # Type Argument Validation
    ///
    /// The runtime validates that provided type arguments satisfy the generic constraints
    /// defined on the target method:
    /// - **where T : class**: Reference type constraints
    /// - **where T : struct**: Value type constraints  
    /// - **where T : `new()`**: Default constructor constraints
    /// - **where T : `BaseClass`**: Base class constraints
    /// - **where T : `IInterface`**: Interface implementation constraints
    ///
    /// # Returns
    /// A [`crate::metadata::signatures::SignatureMethodSpec`] containing:
    /// - Complete list of type arguments for the generic method
    /// - Type signature information for each argument
    /// - Ready for runtime method instantiation
    ///
    /// # Errors
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Invalid method specification header (not 0x0A)
    /// - [`crate::Error::DepthLimitExceeded`]: Type argument parsing exceeds nesting depth limit
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`]: Truncated method specification data
    /// - [`crate::Error::Parse`] carrying [`crate::ParseFailure::Other`]: Mismatched type argument count
    ///
    /// # Performance Notes
    /// - Type argument parsing cost is linear in the number of arguments
    /// - Complex constructed type arguments require recursive parsing
    /// - Simple primitive type arguments parse very quickly
    /// - Consider caching method specifications for frequently called generic methods
    ///
    /// # Thread Safety
    /// This method is not thread-safe. Use separate parser instances for concurrent operations.
    ///
    /// # ECMA-335 References
    /// - **Partition II, Section 23.2.15**: `MethodSpec` signature format
    /// - **Partition II, Section 22.26**: `MethodSpec` metadata table
    /// - **Partition II, Section 9.4**: Generic method instantiation
    /// - **Partition I, Section 9.5.1**: Generic method constraints and validation
    pub fn parse_method_spec_signature(&mut self) -> Result<SignatureMethodSpec> {
        let head_byte = self.parser.read_le::<u8>()?;
        if head_byte != 0x0A {
            return Err(malformed_error!(
                "SignatureMethodSpec - invalid start - {}",
                head_byte
            ));
        }

        let arg_count = self.element_count()?;

        let mut generic_args = Vec::with_capacity(arg_count as usize);
        for _ in 0..arg_count {
            generic_args.push(self.parse_type()?);
        }

        Ok(SignatureMethodSpec { generic_args })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::signatures::encode_field_signature, prelude::Token, Error, ParseFailure,
    };

    #[test]
    fn test_parse_primitive_types() {
        let test_cases = [
            (vec![0x01], TypeSignature::Void),
            (vec![0x02], TypeSignature::Boolean),
            (vec![0x03], TypeSignature::Char),
            (vec![0x04], TypeSignature::I1),
            (vec![0x05], TypeSignature::U1),
            (vec![0x06], TypeSignature::I2),
            (vec![0x07], TypeSignature::U2),
            (vec![0x08], TypeSignature::I4),
            (vec![0x09], TypeSignature::U4),
            (vec![0x0A], TypeSignature::I8),
            (vec![0x0B], TypeSignature::U8),
            (vec![0x0C], TypeSignature::R4),
            (vec![0x0D], TypeSignature::R8),
            (vec![0x0E], TypeSignature::String),
            (vec![0x1C], TypeSignature::Object),
            (vec![0x18], TypeSignature::I),
            (vec![0x19], TypeSignature::U),
        ];

        for (bytes, expected_type) in test_cases {
            let mut parser = SignatureParser::new(&bytes);
            let result = parser.parse_type().unwrap();
            assert_eq!(result, expected_type);
        }
    }

    #[test]
    fn test_parse_class_and_valuetype() {
        // Class type: Class token 0x10 in TypeRef
        let mut parser = SignatureParser::new(&[0x12, 0x42]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::Class(Token::new(0x1B000010))
        );

        // Value type: Token 0xD in TypeRef
        let mut parser = SignatureParser::new(&[0x11, 0x35]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::ValueType(Token::new(0x100000D))
        );

        // Generic parameter: Index 3
        let mut parser = SignatureParser::new(&[0x13, 0x03]);
        assert_eq!(
            parser.parse_type().unwrap(),
            TypeSignature::GenericParamType(0x03)
        );
    }

    #[test]
    fn test_parse_arrays() {
        // SzArray of Int32 (int[])
        let mut parser = SignatureParser::new(&[0x1D, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::SzArray(_)));
        if let TypeSignature::SzArray(inner) = &result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // Multi-dimensional array int[,] with rank 2, no sizes, no bounds
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x00, // num_sizes 0
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = &result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 0)
        }

        // An overlarge rank is rejected on the declared value, before anything is sized from
        // it. `rank` is the only ceiling on `num_lo_bounds`, and the lower-bound extension
        // loop grows `dimensions` to that count before any read can run out of input -- so an
        // unbounded rank is an allocation bomb, not just an implausible array.
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0xC0, 0x40, 0x00, 0x00, // rank 0x400000, a 4-byte compressed uint
            0x00, // num_sizes 0
            0x00, // num_lo_bounds 0
        ]);
        assert!(
            parser.parse_type().is_err(),
            "an array rank above MAX_ARRAY_DIMENSIONS must be rejected"
        );

        // Multi-dimensional array int[2,3] with rank 2, with sizes
        let mut parser = SignatureParser::new(&[
            0x14, // ARRAY
            0x08, // I4 (element type)
            0x02, // rank 2
            0x02, // num_sizes 2
            0x02, // size 2
            0x03, // size 3
            0x00, // num_lo_bounds 0
        ]);

        let result = parser.parse_type().unwrap();
        assert!(matches!(result, TypeSignature::Array(_)));
        if let TypeSignature::Array(array) = &result {
            assert_eq!(*array.base, TypeSignature::I4);
            assert_eq!(array.rank, 2);
            assert_eq!(array.dimensions.len(), 2);
            assert_eq!(array.dimensions[0].lower_bound, None);
            assert_eq!(array.dimensions[0].size, Some(2));
            assert_eq!(array.dimensions[1].lower_bound, None);
            assert_eq!(array.dimensions[1].size, Some(3));
        }
    }

    #[test]
    fn an_array_shape_is_read_once_and_parsing_continues_after_it() {
        // `ReadOnlyCollection<T>[0..., 0...]` followed by `ReadOnlyCollection<T>`
        // and three `int32`, as System.Data.Entity declares them: the shape
        // bytes after the element type belong to the array, not to the next
        // locals.
        let blob = [
            0x07, 0x05, // LOCAL_SIG, 5 locals
            0x14, // ARRAY
            0x15, 0x12, 0x6D, 0x01, 0x12, 0x88, 0x4C, // GENERICINST class 1 arg
            0x02, // rank 2
            0x00, // no sizes
            0x02, 0x00, 0x00, // two lower bounds, both 0
            0x15, 0x12, 0x6D, 0x01, 0x12, 0x88, 0x4C, // GENERICINST class 1 arg
            0x08, 0x08, 0x08, // three I4
        ];
        let locals = SignatureParser::new(&blob)
            .parse_local_var_signature()
            .unwrap()
            .locals;
        assert_eq!(locals.len(), 5);
        let TypeSignature::Array(array) = &locals[0].base else {
            panic!("local 0 is {:?}", locals[0].base);
        };
        assert!(matches!(*array.base, TypeSignature::GenericInst(_, _)));
        assert_eq!(array.rank, 2);
        assert_eq!(
            array
                .dimensions
                .iter()
                .map(|dimension| dimension.lower_bound)
                .collect::<Vec<_>>(),
            [Some(0), Some(0)]
        );
        assert!(matches!(locals[1].base, TypeSignature::GenericInst(_, _)));
        for local in &locals[2..] {
            assert_eq!(local.base, TypeSignature::I4);
        }
    }

    #[test]
    fn array_lower_bounds_are_signed() {
        // int32[-3..., 64...]: the bounds are compressed signed integers
        // (ECMA-335 II.23.2.13), -3 as 0x7B and 64 as 0x80 0x80.
        let mut parser =
            SignatureParser::new(&[0x14, 0x08, 0x02, 0x00, 0x02, 0x7B, 0x80, 0x80, 0x08]);
        let TypeSignature::Array(ref array) = parser.parse_type().unwrap() else {
            panic!("not an array");
        };
        assert_eq!(array.dimensions[0].lower_bound, Some(-3));
        assert_eq!(array.dimensions[1].lower_bound, Some(64));
        assert_eq!(parser.parse_type().unwrap(), TypeSignature::I4);
    }

    #[test]
    fn deeply_nested_signature_is_refused_not_built() {
        // A long run of ELEMENT_TYPE_PTR (0x0F) terminated by I4. Each byte is one nesting
        // level and consumes no other input, which is what makes this cheap to weaponise: a
        // ~60 KB blob describes a ~61 000-level structure, deep enough that recursive drop
        // glue overflows a 2 MiB rayon worker stack.
        let mut blob = vec![0x0F_u8; MAX_NESTING_DEPTH.saturating_mul(2)];
        blob.push(0x08); // I4

        let mut parser = SignatureParser::new(&blob);
        assert!(matches!(
            parser.parse_type(),
            Err(DepthLimitExceeded(MAX_NESTING_DEPTH))
        ));
    }

    /// The tree's height is bounded across function pointers: runs of PTR each short of the
    /// limit, separated by FNPTR headers, add up to a structure past it.
    #[test]
    fn nesting_through_function_pointers_counts_toward_one_height() {
        let mut blob = Vec::new();
        for _ in 0..4 {
            blob.extend(std::iter::repeat_n(0x0F, MAX_NESTING_DEPTH / 2));
            blob.extend_from_slice(&[0x1B, 0x00, 0x00]); // FNPTR, DEFAULT, no parameters
        }
        blob.push(0x08); // I4 return
        assert!(matches!(
            SignatureParser::new(&blob).parse_type(),
            Err(DepthLimitExceeded(MAX_NESTING_DEPTH))
        ));
    }

    /// Breadth is bounded by the bytes, not by a budget: thousands of locals, and generic
    /// arguments, parse.
    #[test]
    fn wide_signatures_parse() {
        // 5000 locals, each GENERICINST CLASS TypeRef[1] <int32>
        let mut locals = vec![0x07, 0x80 | 0x13, 0x88];
        for _ in 0..5000 {
            locals.extend_from_slice(&[0x15, 0x12, 0x05, 0x01, 0x08]);
        }
        assert_eq!(
            SignatureParser::new(&locals)
                .parse_local_var_signature()
                .unwrap()
                .locals
                .len(),
            5000
        );

        // A local of a generic instantiation with 2000 arguments
        let mut arguments = vec![0x07, 0x01, 0x15, 0x12, 0x05, 0x80 | 0x07, 0xD0];
        arguments.extend(std::iter::repeat_n(0x08, 2000));
        let local = SignatureParser::new(&arguments)
            .parse_local_var_signature()
            .unwrap();
        let TypeSignature::GenericInst(_, args) = &local.locals[0].base else {
            panic!("{:?}", local.locals[0].base);
        };
        assert_eq!(args.len(), 2000);
    }

    /// ARRAY and FNPTR alternating parse in one pass: the element is parsed once, before the
    /// shape that follows it, where a lookahead parsed it twice at every level.
    #[test]
    fn alternating_arrays_and_function_pointers_parse_once() {
        let levels = 30;
        let mut blob = Vec::new();
        for _ in 0..levels {
            blob.extend_from_slice(&[0x14, 0x1B, 0x00, 0x00]); // ARRAY of FNPTR() returning
        }
        blob.push(0x08); // int32
        for _ in 0..levels {
            blob.extend_from_slice(&[0x01, 0x00, 0x00]); // rank 1, no sizes, no bounds
        }
        let parsed = SignatureParser::new(&blob).parse_type().unwrap();
        let mut node = &parsed;
        for _ in 0..levels {
            let TypeSignature::Array(array) = node else {
                panic!("{node:?}");
            };
            let TypeSignature::FnPtr(method) = &*array.base else {
                panic!("{:?}", array.base);
            };
            node = &method.return_type.base;
        }
        assert_eq!(node, &TypeSignature::I4);
    }

    /// An END byte is not a type: it is refused, not read as `void`.
    #[test]
    fn an_end_byte_is_not_a_type() {
        assert!(SignatureParser::new(&[0x00]).parse_type().is_err());
    }

    /// Signatures of ordinary depth must still parse - the budget must not be so tight that it
    /// rejects real assemblies.
    #[test]
    fn moderately_nested_signature_still_parses() {
        // int**...* nested 100 levels: far beyond anything a real compiler emits, well inside
        // the budget.
        let mut blob = vec![0x0F_u8; 100];
        blob.push(0x08); // I4

        let mut parser = SignatureParser::new(&blob);
        assert!(parser.parse_type().is_ok());
    }

    /// Dropping a deep signature must not recurse.
    ///
    /// Built by hand rather than parsed, because the parser now refuses to construct one this
    /// deep; the `Drop` impl has to hold for any `TypeSignature` however it was produced.
    #[test]
    fn deep_signature_drops_without_recursing() {
        let mut sig = TypeSignature::I4;
        for _ in 0..200_000 {
            sig = TypeSignature::Pinned(Box::new(sig));
        }

        // The assertion is simply that this returns: with drop glue recursing, 200 000 levels
        // overflows the stack and takes the process down with SIGSEGV.
        drop(sig);
    }

    #[test]
    fn test_parse_pointers_and_byrefs() {
        // Pointer to Int32 (int*)
        let mut parser = SignatureParser::new(&[0x0F, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::Ptr(_)));
        if let TypeSignature::Ptr(inner) = &result {
            assert_eq!(*inner.base, TypeSignature::I4);
        }

        // ByRef to Int32 (ref int)
        let mut parser = SignatureParser::new(&[0x10, 0x08]);
        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::ByRef(_)));
        if let TypeSignature::ByRef(inner) = &result {
            assert_eq!(**inner, TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_generic_instance() {
        // Generic instance List<int>
        // Assume List is token 0x1B
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = &result {
            assert!(matches!(**class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 1);
            assert_eq!(args[0], TypeSignature::I4);
        }

        // Generic instance Dictionary<string, int>
        // Assume Dictionary is token 0x2A
        let mut parser = SignatureParser::new(&[
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // 2 type args
            0x0E, // String type arg
            0x08, // I4 type arg
        ]);

        let result = parser.parse_type().unwrap();

        assert!(matches!(result, TypeSignature::GenericInst(_, _)));
        if let TypeSignature::GenericInst(class, args) = &result {
            assert!(matches!(**class, TypeSignature::Class(_)));
            assert_eq!(args.len(), 2);
            assert_eq!(args[0], TypeSignature::String);
            assert_eq!(args[1], TypeSignature::I4);
        }
    }

    #[test]
    fn test_parse_custom_mods() {
        // Optional modifier (modopt) followed by required modifier (modreq)
        let mut parser = SignatureParser::new(&[
            0x20, 0x42, // CMOD_OPT, token 0x42
            0x1F, 0x49, // CMOD_REQD, token 0x49
            0x08, // I4 (to test we can still parse after the modifiers)
        ]);

        let mods = parser.parse_custom_mods().unwrap();
        assert_eq!(
            mods,
            vec![
                CustomModifier {
                    is_required: false,
                    modifier_type: Token::new(0x1B000010)
                },
                CustomModifier {
                    is_required: true,
                    modifier_type: Token::new(0x01000012)
                }
            ]
        );

        // Verify we can still parse the type after the modifiers
        let type_sig = parser.parse_type().unwrap();
        assert_eq!(type_sig, TypeSignature::I4);

        // Test empty modifiers
        let mut parser = SignatureParser::new(&[0x08]); // Just I4, no mods
        let mods = parser.parse_custom_mods().unwrap();
        assert!(mods.is_empty());
    }

    #[test]
    fn test_complex_signature() {
        // A complex method signature:
        // Dictionary<List<int>, string[]> Method<T>(ref T arg1, List<int>[] arg2)
        let mut parser = SignatureParser::new(&[
            0x30, // HASTHIS | GENERIC
            0x01, // 1 generic parameter
            0x02, // 2 parameters
            // Return type: Dictionary<List<int>, string[]>
            0x15, // GENERICINST
            0x12, 0x2A, // Class token for Dictionary
            0x02, // arg count
            // First type arg: List<int>
            0x15, // GENERICINST
            0x12, 0x49, // Class token for List
            0x01, // arg count
            0x08, // I4
            // Second type arg: string[]
            0x1D, // SZARRAY
            0x0E, // String
            // First parameter: ref T
            0x10, // BYREF
            0x13, 0x00, // GenericParam(0)
            // Second parameter: List<int>[]
            0x1D, // SZARRAY
            0x15, // GENERICINST
            0x12, 0x42, // Class token for List
            0x01, // arg count
            0x08, // I4
        ]);

        let result = parser.parse_method_signature().unwrap();

        // Test method general properties
        assert!(result.has_this);
        assert_eq!(result.param_count_generic, 1);
        assert_eq!(result.params.len(), 2);

        // Test return type (Dictionary<List<int>, string[]>)
        assert!(matches!(
            result.return_type.base,
            TypeSignature::GenericInst(_, _)
        ));

        // Test first parameter (ref T)
        assert!(result.params[0].by_ref);
        assert_eq!(result.params[0].base, TypeSignature::GenericParamType(0));

        // Test second parameter (List<int>[])
        assert!(!result.params[1].by_ref);
        assert!(matches!(result.params[1].base, TypeSignature::SzArray(_)));
    }

    #[test]
    fn test_error_handling() {
        // Test invalid method signature format: kind 0x0F is no method signature kind
        let mut parser = SignatureParser::new(&[0xFF, 0x01]);
        let error = parser.parse_method_signature().unwrap_err();
        assert!(
            error.to_string().contains("calling convention 0xFF"),
            "{error}"
        );

        // Test truncated method signature: a parameter count with no return type after it
        let mut parser = SignatureParser::new(&[0x00, 0x01]);
        assert!(matches!(
            parser.parse_method_signature(),
            Err(Error::Parse(ParseFailure::OutOfBounds { .. }))
        ));

        // Test invalid field signature format
        let mut parser = SignatureParser::new(&[0x07, 0x08]); // Should be 0x06 for FIELD
        assert!(parser.parse_field_signature().is_err());
    }

    #[test]
    fn an_unmanaged_function_pointer_keeps_its_calling_convention() {
        // FIELD, FNPTR of `delegate* unmanaged[Cdecl]<int, void>`: UNMANAGED, one
        // parameter, a void return with modopt(CallConvCdecl), then int.
        let blob = [0x06, 0x1B, 0x09, 0x01, 0x20, 0x09, 0x01, 0x08];
        let field = SignatureParser::new(&blob).parse_field_signature().unwrap();
        let TypeSignature::FnPtr(method) = &field.base else {
            panic!("expected a function pointer, got {:?}", field.base);
        };
        assert!(method.unmanaged && !method.default);
        assert_eq!(method.calling_convention(), CALLING_CONVENTION::UNMANAGED);
        assert_eq!(encode_field_signature(&field).unwrap(), blob);
    }

    #[test]
    fn a_method_signature_kind_no_method_has_is_refused() {
        for kind in [0x06, 0x07, 0x08, 0x0A, 0x0B, 0x0F] {
            let blob = [kind, 0x00, 0x01];
            let mut parser = SignatureParser::new(&blob);
            assert!(parser.parse_method_signature().is_err(), "kind {kind:#04x}");
        }
        for kind in [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x09] {
            let blob = [kind, 0x00, 0x01];
            let mut parser = SignatureParser::new(&blob);
            let method = parser.parse_method_signature().unwrap();
            assert_eq!(method.calling_convention(), kind);
        }
    }

    /// A long run of `PTR` bytes inside an array's element is refused, not recursed: a
    /// lookahead over the element used to recurse natively, one stack frame per byte.
    #[test]
    fn a_deep_pointer_run_is_refused_rather_than_overflowing() {
        // FIELD, ARRAY, then a long run of PTR, terminated by I4.
        let mut blob = vec![0x06, 0x14];
        blob.extend(std::iter::repeat_n(0x0F, 8192));
        blob.push(0x08);

        let mut parser = SignatureParser::new(&blob);
        // Reaching a verdict at all is the assertion - this used to abort the
        // process rather than return.
        assert!(
            parser.parse_field_signature().is_err(),
            "a signature nested past the cap must be refused"
        );
    }

    /// The nesting cap survives re-entry through `FNPTR`.
    ///
    /// `parse_type` bounds itself with a heap work stack, but allocated a fresh
    /// one per invocation - so `parse_type` → `parse_method_signature` →
    /// `parse_param` → `parse_type` re-armed the cap on every hop. Before the
    /// fix, 1000 nested FNPTRs parsed successfully and the cap never fired.
    #[test]
    fn the_nesting_cap_survives_fnptr_reentry() {
        // FIELD, then N × (FNPTR, DEFAULT calling convention, 0 params),
        // bottoming out in I4.
        let mut blob = vec![0x06];
        for _ in 0..2000 {
            blob.push(0x1B); // FNPTR
            blob.push(0x00); // DEFAULT
            blob.push(0x00); // param count 0
        }
        blob.push(0x08); // I4 return

        let mut parser = SignatureParser::new(&blob);
        assert!(
            parser.parse_field_signature().is_err(),
            "nesting through FNPTR must count toward the same cap"
        );
    }

    /// A vararg call site's `ParamCount` counts its varargs: inside a local signature, the
    /// function pointer's varargs end where that count does, and the next local follows.
    #[test]
    fn a_vararg_function_pointer_reads_the_varargs_its_count_states() {
        let blob = [
            0x07, 0x02, // LOCAL_SIG, two locals
            0x1B, 0x05, 0x02, 0x01, // FNPTR, VARARG, ParamCount 2, returns void
            0x08, 0x41, 0x0A, // int32, SENTINEL, int64
            0x08, // the second local: int32
        ];
        let locals = SignatureParser::new(&blob)
            .parse_local_var_signature()
            .unwrap()
            .locals;
        assert_eq!(locals.len(), 2);
        let TypeSignature::FnPtr(method) = &locals[0].base else {
            panic!("{:?}", locals[0].base);
        };
        assert_eq!(method.param_count, 2);
        assert_eq!(method.params.len(), 1);
        assert_eq!(method.varargs.len(), 1);
        assert_eq!(method.varargs[0].base, TypeSignature::I8);
        assert_eq!(locals[1].base, TypeSignature::I4);

        // A sentinel with no parameter after it
        assert!(SignatureParser::new(&[0x05, 0x01, 0x01, 0x41])
            .parse_method_signature()
            .is_err());
    }
}
