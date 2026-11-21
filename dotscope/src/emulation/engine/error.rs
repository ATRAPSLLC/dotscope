//! Emulation error types and result handling.
//!
//! This module defines comprehensive error types for all failure modes
//! that can occur during CIL bytecode emulation.

use std::{fmt, time::Duration};

use crate::metadata::{token::Token, typesystem::CilFlavor};

/// Synthetic exception type tokens for CLR exceptions.
///
/// These tokens represent BCL exception types when converting emulation errors
/// to CLR exceptions that can be caught by exception handlers. They use table
/// `0x7F` (which does not exist in ECMA-335) to avoid collisions with real
/// metadata tokens. The second byte `0x01` distinguishes exception tokens from
/// heap type tokens (`0x7F00_xxxx`).
///
/// | Token        | CLR Type                                          |
/// |--------------|---------------------------------------------------|
/// | 0x7F01_0000  | System.Exception (base)                           |
/// | 0x7F01_0001  | System.IndexOutOfRangeException                   |
/// | 0x7F01_0002  | System.NullReferenceException                     |
/// | 0x7F01_0003  | System.DivideByZeroException                      |
/// | 0x7F01_0004  | System.OverflowException                          |
/// | 0x7F01_0005  | System.InvalidCastException                       |
/// | 0x7F01_0006  | System.IO.EndOfStreamException                    |
/// | 0x7F01_0007  | System.ObjectDisposedException                    |
/// | 0x7F01_0008  | System.InvalidOperationException                  |
/// | 0x7F01_0009  | System.FormatException                            |
/// | 0x7F01_000A  | System.ArgumentException                          |
/// | 0x7F01_000B  | System.ArgumentNullException                      |
/// | 0x7F01_000C  | System.NotSupportedException                      |
/// | 0x7F01_000D  | System.Collections.Generic.KeyNotFoundException   |
/// | 0x7F01_000E  | System.IO.FileNotFoundException                   |
/// | 0x7F01_000F  | System.IO.DirectoryNotFoundException              |
/// | 0x7F01_0010  | System.Reflection.TargetInvocationException        |
/// | 0x7F01_0011  | System.ArithmeticException                        |
/// | 0x7F01_0012  | System.IO.IOException                             |
/// | 0x7F01_0013  | System.TypeInitializationException                |
/// | 0x7F01_0014  | System.SystemException                            |
/// | 0x7F01_0015  | System.TypeLoadException                          |
/// | 0x7F01_0016  | System.MissingMethodException                     |
/// | 0x7F01_0017  | System.MissingFieldException                      |
/// | 0x7F01_0018  | System.NotImplementedException                    |
/// | 0x7F01_001B  | System.AccessViolationException                   |
/// | 0x7F01_001C  | System.Security.Cryptography.CryptographicException |
/// | 0x7F01_001D  | System.IO.InvalidDataException                    |
pub mod synthetic_exception {
    use crate::metadata::token::Token;

    /// System.Exception (generic base — root of the hierarchy).
    pub const BASE_EXCEPTION: Token = Token::new(0x7F01_0000);
    /// System.IndexOutOfRangeException
    pub const INDEX_OUT_OF_RANGE: Token = Token::new(0x7F01_0001);
    /// System.NullReferenceException
    pub const NULL_REFERENCE: Token = Token::new(0x7F01_0002);
    /// System.DivideByZeroException
    pub const DIVIDE_BY_ZERO: Token = Token::new(0x7F01_0003);
    /// System.OverflowException
    pub const OVERFLOW: Token = Token::new(0x7F01_0004);
    /// System.InvalidCastException
    pub const INVALID_CAST: Token = Token::new(0x7F01_0005);
    /// System.IO.EndOfStreamException
    pub const END_OF_STREAM: Token = Token::new(0x7F01_0006);
    /// System.ObjectDisposedException
    pub const OBJECT_DISPOSED: Token = Token::new(0x7F01_0007);
    /// System.InvalidOperationException
    pub const INVALID_OPERATION: Token = Token::new(0x7F01_0008);
    /// System.FormatException
    pub const FORMAT_EXCEPTION: Token = Token::new(0x7F01_0009);
    /// System.ArgumentException
    pub const ARGUMENT_EXCEPTION: Token = Token::new(0x7F01_000A);
    /// System.ArgumentNullException
    pub const ARGUMENT_NULL: Token = Token::new(0x7F01_000B);
    /// System.NotSupportedException
    pub const NOT_SUPPORTED: Token = Token::new(0x7F01_000C);
    /// System.Collections.Generic.KeyNotFoundException
    pub const KEY_NOT_FOUND: Token = Token::new(0x7F01_000D);
    /// System.IO.FileNotFoundException
    pub const FILE_NOT_FOUND: Token = Token::new(0x7F01_000E);
    /// System.IO.DirectoryNotFoundException
    pub const DIRECTORY_NOT_FOUND: Token = Token::new(0x7F01_000F);
    /// System.Reflection.TargetInvocationException
    pub const TARGET_INVOCATION: Token = Token::new(0x7F01_0010);
    /// System.ArithmeticException — parent of DivideByZero, Overflow.
    pub const ARITHMETIC: Token = Token::new(0x7F01_0011);
    /// System.IO.IOException — parent of EndOfStream, FileNotFound, DirectoryNotFound.
    pub const IO_EXCEPTION: Token = Token::new(0x7F01_0012);
    /// System.TypeInitializationException — wraps .cctor failures.
    pub const TYPE_INITIALIZATION: Token = Token::new(0x7F01_0013);
    /// System.SystemException — intermediate base for most runtime exceptions.
    pub const SYSTEM_EXCEPTION: Token = Token::new(0x7F01_0014);
    /// System.TypeLoadException
    pub const TYPE_LOAD: Token = Token::new(0x7F01_0015);
    /// System.MissingMethodException
    pub const MISSING_METHOD: Token = Token::new(0x7F01_0016);
    /// System.MissingFieldException
    pub const MISSING_FIELD: Token = Token::new(0x7F01_0017);
    /// System.NotImplementedException
    pub const NOT_IMPLEMENTED: Token = Token::new(0x7F01_0018);
    /// System.ArgumentOutOfRangeException — subtype of `ARGUMENT_EXCEPTION`.
    ///
    /// Thrown by BCL hooks that receive a negative or oversized count, index or length from
    /// emulated code, so that the emulated program observes the same failure the real runtime
    /// would produce and can catch it, instead of the emulator allocating on the bad value.
    pub const ARGUMENT_OUT_OF_RANGE: Token = Token::new(0x7F01_0019);
    /// System.OutOfMemoryException
    ///
    /// Thrown when a request would exceed the emulator's heap budget. This is deliberately a
    /// catchable CLR exception rather than a hard emulation error: real .NET code that probes
    /// allocation limits expects to catch it, and surfacing it as a Rust error instead would
    /// abandon the emulation of samples that handle it.
    pub const OUT_OF_MEMORY: Token = Token::new(0x7F01_001A);
    /// System.AccessViolationException
    ///
    /// Thrown when emulated code reads or writes memory its protection does not permit, or
    /// touches a guard page. Obfuscators probe for an emulator by writing where a real
    /// process would fault, so silently permitting the access is itself a detection signal.
    pub const ACCESS_VIOLATION: Token = Token::new(0x7F01_001B);
    /// System.Security.Cryptography.CryptographicException
    ///
    /// Thrown by the cryptography hooks where the runtime throws it: a key or IV of a size the
    /// algorithm does not take, input that is not whole blocks, padding that does not check
    /// out, a malformed key. Decrypting with the wrong key is the case obfuscated code relies
    /// on: it catches the exception rather than reading garbage.
    pub const CRYPTOGRAPHIC: Token = Token::new(0x7F01_001C);
    /// System.IO.InvalidDataException
    ///
    /// Thrown by `DeflateStream`/`GZipStream` reads whose compressed data does not inflate,
    /// as the runtime throws it.
    pub const INVALID_DATA: Token = Token::new(0x7F01_001D);
}

/// Errors that can occur during CIL emulation.
///
/// This enum covers all failure modes during bytecode execution,
/// from stack underflows to unsupported opcodes.
#[derive(Debug, Clone, PartialEq)]
pub enum EmulationError {
    /// Evaluation stack overflow.
    StackOverflow,
    /// Evaluation stack underflow (pop from empty stack).
    StackUnderflow,
    /// Stack type mismatch during operation.
    StackTypeMismatch {
        /// Expected type.
        expected: &'static str,
        /// Actual type found.
        found: &'static str,
    },
    /// Local variable index out of bounds.
    LocalIndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// Number of locals available.
        count: usize,
    },
    /// Argument index out of bounds.
    ArgumentIndexOutOfBounds {
        /// The requested index.
        index: usize,
        /// Number of arguments available.
        count: usize,
    },
    /// Local variable CIL type flavor mismatch.
    LocalFlavorMismatch {
        /// The local index.
        index: usize,
        /// Expected CIL type flavor (boxed to reduce enum size).
        expected: Box<CilFlavor>,
        /// Actual CIL type flavor found (boxed to reduce enum size).
        found: Box<CilFlavor>,
    },
    /// Argument CIL type flavor mismatch.
    ArgumentFlavorMismatch {
        /// The argument index.
        index: usize,
        /// Expected CIL type flavor (boxed to reduce enum size).
        expected: Box<CilFlavor>,
        /// Actual CIL type flavor found (boxed to reduce enum size).
        found: Box<CilFlavor>,
    },
    /// Invalid heap reference.
    InvalidHeapReference {
        /// The invalid reference ID.
        reference_id: u64,
    },
    /// Heap memory limit exceeded.
    HeapMemoryLimitExceeded {
        /// Current heap size.
        current: usize,
        /// Maximum allowed size.
        limit: usize,
    },
    /// Invalid pointer access (unmanaged memory).
    InvalidPointer {
        /// The invalid address.
        address: u64,
        /// Reason for invalidity.
        reason: &'static str,
    },
    /// Null reference access.
    NullReference,
    /// Division by zero.
    DivisionByZero,
    /// Arithmetic overflow.
    ArithmeticOverflow,
    /// Invalid conversion (e.g., NaN to integer).
    InvalidConversion {
        /// Source type.
        from: &'static str,
        /// Target type.
        to: &'static str,
    },
    /// Type mismatch in operation.
    TypeMismatch {
        /// Operation being performed.
        operation: &'static str,
        /// Expected type.
        expected: &'static str,
        /// Actual type found.
        found: &'static str,
    },
    /// Invalid cast operation.
    InvalidCast {
        /// Source type.
        from_type: String,
        /// Target type.
        to_type: String,
    },
    /// Invalid branch target.
    InvalidBranchTarget {
        /// The invalid target address.
        target: u64,
    },
    /// Invalid instruction pointer.
    InvalidInstructionPointer {
        /// The invalid offset.
        offset: u32,
    },
    /// Method not found.
    MethodNotFound {
        /// Token of the missing method.
        token: Token,
    },
    /// Call depth limit exceeded.
    CallDepthExceeded {
        /// Current call depth.
        depth: usize,
        /// Maximum allowed depth.
        limit: usize,
    },
    /// Instruction count limit exceeded.
    InstructionLimitExceeded {
        /// Number of instructions executed.
        executed: u64,
        /// Maximum allowed.
        limit: u64,
    },
    /// A configured resource ceiling other than memory, call depth or instruction count was
    /// reached — for example the heap object count or a delegate's invocation-list length.
    ///
    /// Carries a description naming the limit and the value that breached it, because these
    /// ceilings are varied enough that a shared structured shape would fit none of them well.
    ResourceLimitExceeded(String),
    /// Execution timeout.
    Timeout {
        /// Time elapsed.
        elapsed: Duration,
        /// Timeout limit.
        limit: Duration,
    },
    /// Unsupported opcode.
    UnsupportedOpcode {
        /// The unsupported opcode.
        opcode: u8,
        /// Optional prefix byte.
        prefix: Option<u8>,
        /// Instruction mnemonic if known.
        mnemonic: Option<&'static str>,
    },
    /// Invalid operand for instruction.
    InvalidOperand {
        /// Instruction mnemonic.
        instruction: &'static str,
        /// Description of what was expected.
        expected: &'static str,
    },
    /// Missing method body.
    MissingMethodBody {
        /// Token of the method.
        token: Token,
    },
    /// Invalid method metadata.
    InvalidMethodMetadata {
        /// Token of the method.
        token: Token,
        /// Description of what was invalid.
        reason: &'static str,
    },
    /// Field not found.
    FieldNotFound {
        /// Token of the field.
        token: Token,
    },
    /// Array index out of bounds.
    ArrayIndexOutOfBounds {
        /// The invalid index.
        index: i64,
        /// Array length.
        length: usize,
    },
    /// Invalid array element type.
    ArrayElementTypeMismatch {
        /// Expected element type.
        expected: &'static str,
        /// Actual element type.
        found: &'static str,
    },
    /// User string not found.
    UserStringNotFound {
        /// The string index.
        index: u32,
    },
    /// Invalid string operation.
    InvalidStringOperation {
        /// Description of the error.
        description: String,
    },
    /// Unhandled exception during emulation.
    UnhandledException {
        /// Description of the exception.
        description: String,
    },
    /// Invalid exception handler.
    InvalidExceptionHandler {
        /// Description of the problem.
        description: String,
    },
    /// Internal emulation error (bug in emulator).
    InternalError {
        /// Description of the error.
        description: String,
    },
    /// Symbolic value encountered where concrete required.
    SymbolicValueRequired {
        /// The operation requiring a concrete value.
        operation: &'static str,
    },
    /// Invalid types for operation.
    InvalidOperationTypes {
        /// The operation that was attempted.
        operation: String,
        /// Description of the operand type(s).
        operand_types: String,
    },
    /// Invalid stack state for operation.
    InvalidStackState {
        /// Description of the invalid state.
        message: String,
    },
    /// Heap object type mismatch.
    HeapTypeMismatch {
        /// Expected object kind.
        expected: &'static str,
        /// Actual object kind.
        found: &'static str,
    },

    /// Unsupported method call.
    UnsupportedMethod {
        /// Token of the method.
        token: Token,
        /// Reason why the method is unsupported.
        reason: &'static str,
    },

    /// Type not found or reference is dead.
    TypeNotFound {
        /// Token of the method containing the problematic type.
        method_token: Token,
        /// Index of the local variable with the dead type reference.
        local_index: u16,
    },

    /// Value conversion error.
    ///
    /// This error occurs when converting an `EmValue` to a primitive type fails
    /// because the value type is not compatible with the target type.
    ValueConversion {
        /// The source type that couldn't be converted.
        source_type: &'static str,
        /// The target type that was requested.
        target_type: &'static str,
    },

    /// Access rejected by the memory protection of the target page.
    ///
    /// Distinct from [`InvalidAddress`](Self::InvalidAddress): the address *is* mapped, but
    /// the access is not permitted — a write to a read-only PE section, a read of a
    /// PAGE_NOACCESS page, or any touch of a guard page.
    AccessViolation {
        /// The address whose page rejected the access.
        address: u64,
        /// Which protection rejected it.
        reason: String,
    },

    /// Invalid memory address.
    ///
    /// This error occurs when accessing an unmapped or invalid memory address
    /// in the emulated address space.
    InvalidAddress {
        /// The invalid address.
        address: u64,
        /// Reason why the address is invalid.
        reason: String,
    },

    /// Type token could not be resolved.
    ///
    /// This error occurs when a type token does not correspond to a known
    /// TypeDef, TypeRef, or TypeSpec table entry.
    UnresolvedTypeToken {
        /// The unresolved token.
        token: Token,
    },

    /// Hook execution error.
    ///
    /// This error occurs when a hook returns an error during pre-hook or
    /// post-hook execution.
    HookError(String),

    /// Memory page out of bounds access.
    ///
    /// This error occurs when attempting to read or write memory at an offset
    /// that exceeds the page boundaries.
    PageOutOfBounds {
        /// The requested offset.
        offset: usize,
        /// The size of the operation (1 for byte, or buffer length).
        size: usize,
        /// The maximum valid offset (PAGE_SIZE).
        page_size: usize,
    },

    /// Lock poisoned error.
    ///
    /// This error occurs when a synchronization lock (RwLock/Mutex) has been
    /// poisoned due to a panic in another thread while holding the lock.
    LockPoisoned {
        /// Description of which lock was poisoned.
        description: &'static str,
    },
}

impl fmt::Display for EmulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmulationError::StackOverflow => write!(f, "evaluation stack overflow"),
            EmulationError::StackUnderflow => write!(f, "evaluation stack underflow"),
            EmulationError::StackTypeMismatch { expected, found } => {
                write!(f, "stack type mismatch: expected {expected}, found {found}")
            }
            EmulationError::LocalIndexOutOfBounds { index, count } => {
                write!(
                    f,
                    "local variable index {index} out of bounds (count: {count})"
                )
            }
            EmulationError::ArgumentIndexOutOfBounds { index, count } => {
                write!(f, "argument index {index} out of bounds (count: {count})")
            }
            EmulationError::LocalFlavorMismatch {
                index,
                expected,
                found,
            } => {
                write!(
                    f,
                    "local variable {index} type mismatch: expected {expected:?}, found {found:?}"
                )
            }
            EmulationError::ArgumentFlavorMismatch {
                index,
                expected,
                found,
            } => {
                write!(
                    f,
                    "argument {index} type mismatch: expected {expected:?}, found {found:?}"
                )
            }
            EmulationError::InvalidHeapReference { reference_id } => {
                write!(f, "invalid heap reference: {reference_id}")
            }
            EmulationError::HeapMemoryLimitExceeded { current, limit } => {
                write!(
                    f,
                    "heap memory limit exceeded: {current} bytes (limit: {limit})"
                )
            }
            EmulationError::InvalidPointer { address, reason } => {
                write!(f, "invalid pointer 0x{address:016X}: {reason}")
            }
            EmulationError::NullReference => write!(f, "null reference"),
            EmulationError::DivisionByZero => write!(f, "division by zero"),
            EmulationError::ArithmeticOverflow => write!(f, "arithmetic overflow"),
            EmulationError::InvalidConversion { from, to } => {
                write!(f, "invalid conversion from {from} to {to}")
            }
            EmulationError::TypeMismatch {
                operation,
                expected,
                found,
            } => {
                write!(
                    f,
                    "type mismatch in {operation}: expected {expected}, found {found}"
                )
            }
            EmulationError::InvalidCast { from_type, to_type } => {
                write!(f, "invalid cast from {from_type} to {to_type}")
            }
            EmulationError::InvalidBranchTarget { target } => {
                write!(f, "invalid branch target: 0x{target:08X}")
            }
            EmulationError::InvalidInstructionPointer { offset } => {
                write!(f, "invalid instruction pointer: 0x{offset:08X}")
            }
            EmulationError::MethodNotFound { token } => {
                write!(f, "method not found: 0x{:08X}", token.value())
            }
            EmulationError::CallDepthExceeded { depth, limit } => {
                write!(f, "call depth exceeded: {depth} (limit: {limit})")
            }
            EmulationError::InstructionLimitExceeded { executed, limit } => {
                write!(f, "instruction limit exceeded: {executed} (limit: {limit})")
            }
            EmulationError::ResourceLimitExceeded(description) => {
                write!(f, "resource limit exceeded: {description}")
            }
            EmulationError::Timeout { elapsed, limit } => {
                write!(
                    f,
                    "execution timeout: {}ms (limit: {}ms)",
                    elapsed.as_millis(),
                    limit.as_millis()
                )
            }
            EmulationError::UnsupportedOpcode {
                opcode,
                prefix,
                mnemonic,
            } => {
                let mnemonic_str = mnemonic.unwrap_or("unknown");
                if let Some(p) = prefix {
                    write!(
                        f,
                        "unsupported opcode: 0x{p:02X}:0x{opcode:02X} ({mnemonic_str})"
                    )
                } else {
                    write!(f, "unsupported opcode: 0x{opcode:02X} ({mnemonic_str})")
                }
            }
            EmulationError::InvalidOperand {
                instruction,
                expected,
            } => {
                write!(f, "invalid operand for {instruction}: expected {expected}")
            }
            EmulationError::MissingMethodBody { token } => {
                write!(f, "missing method body: 0x{:08X}", token.value())
            }
            EmulationError::InvalidMethodMetadata { token, reason } => {
                write!(
                    f,
                    "invalid method metadata for 0x{:08X}: {reason}",
                    token.value()
                )
            }
            EmulationError::FieldNotFound { token } => {
                write!(f, "field not found: 0x{:08X}", token.value())
            }
            EmulationError::ArrayIndexOutOfBounds { index, length } => {
                write!(f, "array index {index} out of bounds (length: {length})")
            }
            EmulationError::ArrayElementTypeMismatch { expected, found } => {
                write!(
                    f,
                    "array element type mismatch: expected {expected}, found {found}"
                )
            }
            EmulationError::UserStringNotFound { index } => {
                write!(f, "user string not found: 0x{index:08X}")
            }
            EmulationError::InvalidStringOperation { description } => {
                write!(f, "invalid string operation: {description}")
            }
            EmulationError::UnhandledException { description } => {
                write!(f, "unhandled exception: {description}")
            }
            EmulationError::InvalidExceptionHandler { description } => {
                write!(f, "invalid exception handler: {description}")
            }
            EmulationError::InternalError { description } => {
                write!(f, "internal emulation error: {description}")
            }
            EmulationError::SymbolicValueRequired { operation } => {
                write!(
                    f,
                    "symbolic value encountered in {operation} (concrete value required)"
                )
            }
            EmulationError::InvalidOperationTypes {
                operation,
                operand_types,
            } => {
                write!(f, "invalid types for {operation}: {operand_types}")
            }
            EmulationError::InvalidStackState { message } => {
                write!(f, "invalid stack state: {message}")
            }
            EmulationError::HeapTypeMismatch { expected, found } => {
                write!(f, "heap type mismatch: expected {expected}, found {found}")
            }
            EmulationError::UnsupportedMethod { token, reason } => {
                write!(f, "unsupported method 0x{:08X}: {reason}", token.value())
            }
            EmulationError::TypeNotFound {
                method_token,
                local_index,
            } => {
                write!(
                    f,
                    "type not found for local variable {local_index} in method 0x{:08X}",
                    method_token.value()
                )
            }
            EmulationError::ValueConversion {
                source_type,
                target_type,
            } => {
                write!(f, "cannot convert {source_type} to {target_type}")
            }
            EmulationError::AccessViolation { address, reason } => {
                write!(f, "access violation at 0x{address:08X}: {reason}")
            }
            EmulationError::InvalidAddress { address, reason } => {
                write!(f, "invalid address 0x{address:08X}: {reason}")
            }
            EmulationError::UnresolvedTypeToken { token } => {
                write!(
                    f,
                    "unresolved type token 0x{:08X} (table: 0x{:02X})",
                    token.value(),
                    token.table()
                )
            }
            EmulationError::HookError(msg) => {
                write!(f, "hook error: {msg}")
            }
            EmulationError::PageOutOfBounds {
                offset,
                size,
                page_size,
            } => {
                write!(
                    f,
                    "page out of bounds: offset {offset} + size {size} exceeds page size {page_size}"
                )
            }
            EmulationError::LockPoisoned { description } => {
                write!(f, "lock poisoned: {description}")
            }
        }
    }
}

impl std::error::Error for EmulationError {}

impl EmulationError {
    /// Checks if this error should be treated as a CLR exception.
    ///
    /// Certain emulation errors correspond to CLR runtime exceptions:
    /// - `ArrayIndexOutOfBounds` -> `IndexOutOfRangeException`
    /// - `NullReference` -> `NullReferenceException`
    /// - `DivisionByZero` -> `DivideByZeroException`
    /// - `ArithmeticOverflow` -> `OverflowException`
    /// - `InvalidCast` -> `InvalidCastException`
    ///
    /// These errors, in a real CLR, could be caught by exception handlers.
    #[must_use]
    pub fn is_clr_exception(&self) -> bool {
        matches!(
            self,
            EmulationError::ArrayIndexOutOfBounds { .. }
                | EmulationError::NullReference
                | EmulationError::DivisionByZero
                | EmulationError::ArithmeticOverflow
                | EmulationError::InvalidCast { .. }
        )
    }

    /// Maps this error to a synthetic CLR exception type token.
    ///
    /// Returns a synthetic token that represents the corresponding BCL exception type.
    /// Use [`synthetic_exception`] constants to compare tokens.
    ///
    /// # Returns
    ///
    /// The synthetic exception token, or `BASE_EXCEPTION` for unrecognized errors.
    #[must_use]
    pub fn to_exception_token(&self) -> Token {
        match self {
            EmulationError::ArrayIndexOutOfBounds { .. } => synthetic_exception::INDEX_OUT_OF_RANGE,
            EmulationError::NullReference => synthetic_exception::NULL_REFERENCE,
            EmulationError::DivisionByZero => synthetic_exception::DIVIDE_BY_ZERO,
            EmulationError::ArithmeticOverflow => synthetic_exception::OVERFLOW,
            EmulationError::InvalidCast { .. } => synthetic_exception::INVALID_CAST,
            EmulationError::AccessViolation { .. } => synthetic_exception::ACCESS_VIOLATION,
            _ => synthetic_exception::BASE_EXCEPTION,
        }
    }

    /// Returns a description suitable for tracing/logging.
    #[must_use]
    pub fn description(&self) -> String {
        format!("{self}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let errors = vec![
            EmulationError::StackOverflow,
            EmulationError::StackUnderflow,
            EmulationError::DivisionByZero,
            EmulationError::NullReference,
            EmulationError::LocalIndexOutOfBounds { index: 5, count: 3 },
            EmulationError::UnsupportedOpcode {
                opcode: 0xFF,
                prefix: None,
                mnemonic: Some("invalid"),
            },
        ];

        for err in errors {
            let display = format!("{err}");
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_local_errors() {
        let err = EmulationError::LocalIndexOutOfBounds {
            index: 10,
            count: 5,
        };
        assert!(format!("{err}").contains("10"));
        assert!(format!("{err}").contains("5"));

        let err = EmulationError::LocalFlavorMismatch {
            index: 3,
            expected: Box::new(CilFlavor::I4),
            found: Box::new(CilFlavor::I8),
        };
        assert!(format!("{err}").contains("3"));
    }

    #[test]
    fn test_new_variants() {
        let err = EmulationError::InvalidOperationTypes {
            operation: "add".to_string(),
            operand_types: "i32, string".to_string(),
        };
        assert!(format!("{err}").contains("add"));

        let err = EmulationError::InvalidStackState {
            message: "corrupted".to_string(),
        };
        assert!(format!("{err}").contains("corrupted"));

        let err = EmulationError::HeapTypeMismatch {
            expected: "String",
            found: "Array",
        };
        assert!(format!("{err}").contains("String"));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<EmulationError>();
    }
}
