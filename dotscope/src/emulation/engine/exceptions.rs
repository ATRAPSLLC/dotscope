//! Synthetic exception type hierarchy for CLR exception handling.
//!
//! The CIL emulator uses synthetic tokens (in the `0x7F01_00xx` range, using
//! table `0x7F` which does not exist in ECMA-335) to represent BCL exception
//! types that don't exist in the loaded assembly's metadata. All token constants
//! are defined in [`synthetic_exception`].
//! This module defines the parent-child
//! hierarchy so that `catch` clauses correctly discriminate between exception
//! types per ECMA-335 §III.4.27: "an exception is caught if the thrown type is
//! the handler type or a subclass of it."
//!
//! # Hierarchy
//!
//! ```text
//! System.Exception (BASE_EXCEPTION)
//! ├── System.SystemException
//! │   ├── System.ArithmeticException (ARITHMETIC)
//! │   │   ├── System.DivideByZeroException
//! │   │   └── System.OverflowException
//! │   ├── System.InvalidCastException
//! │   ├── System.IndexOutOfRangeException
//! │   ├── System.NullReferenceException
//! │   ├── System.FormatException
//! │   ├── System.NotSupportedException
//! │   ├── System.InvalidOperationException
//! │   │   └── System.ObjectDisposedException
//! │   ├── System.ArgumentException
//! │   │   └── System.ArgumentNullException
//! │   ├── System.Collections.Generic.KeyNotFoundException
//! │   ├── System.Reflection.TargetInvocationException
//! │   ├── System.TypeInitializationException
//! │   ├── System.TypeLoadException
//! │   ├── System.MissingMethodException
//! │   ├── System.MissingFieldException
//! │   └── System.NotImplementedException
//! └── System.IO.IOException (IO_EXCEPTION)
//!     ├── System.IO.EndOfStreamException
//!     ├── System.IO.FileNotFoundException
//!     └── System.IO.DirectoryNotFoundException
//! ```

use crate::{emulation::engine::error::synthetic_exception, metadata::token::Token};

/// Returns the parent exception token in the synthetic hierarchy.
///
/// # Arguments
///
/// * `token` — A synthetic exception token (in the `0x7F01_00xx` range).
///
/// # Returns
///
/// - `Some(parent_token)` for any exception type that has a parent
///   (e.g., `DIVIDE_BY_ZERO → ARITHMETIC`).
/// - `None` for `BASE_EXCEPTION` (the root of the hierarchy).
/// - `Some(BASE_EXCEPTION)` for unknown synthetic tokens as a safe default.
#[must_use]
pub fn parent(token: Token) -> Option<Token> {
    match token {
        // ArithmeticException subtypes
        t if t == synthetic_exception::DIVIDE_BY_ZERO => Some(synthetic_exception::ARITHMETIC),
        t if t == synthetic_exception::OVERFLOW => Some(synthetic_exception::ARITHMETIC),

        // IOException subtypes
        t if t == synthetic_exception::END_OF_STREAM => Some(synthetic_exception::IO_EXCEPTION),
        t if t == synthetic_exception::FILE_NOT_FOUND => Some(synthetic_exception::IO_EXCEPTION),
        t if t == synthetic_exception::DIRECTORY_NOT_FOUND => {
            Some(synthetic_exception::IO_EXCEPTION)
        }

        // InvalidOperationException subtypes
        t if t == synthetic_exception::OBJECT_DISPOSED => {
            Some(synthetic_exception::INVALID_OPERATION)
        }

        // ArgumentException subtypes
        t if t == synthetic_exception::ARGUMENT_NULL => {
            Some(synthetic_exception::ARGUMENT_EXCEPTION)
        }
        t if t == synthetic_exception::ARGUMENT_OUT_OF_RANGE => {
            Some(synthetic_exception::ARGUMENT_EXCEPTION)
        }

        // Intermediate types → SystemException
        t if t == synthetic_exception::ARITHMETIC => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::IO_EXCEPTION => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::INVALID_OPERATION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::ARGUMENT_EXCEPTION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::INDEX_OUT_OF_RANGE => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::NULL_REFERENCE => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::INVALID_CAST => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::FORMAT_EXCEPTION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::NOT_SUPPORTED => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::KEY_NOT_FOUND => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::TARGET_INVOCATION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::TYPE_INITIALIZATION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::TYPE_LOAD => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::MISSING_METHOD => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::MISSING_FIELD => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::NOT_IMPLEMENTED => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::OUT_OF_MEMORY => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::ACCESS_VIOLATION => {
            Some(synthetic_exception::SYSTEM_EXCEPTION)
        }
        t if t == synthetic_exception::CRYPTOGRAPHIC => Some(synthetic_exception::SYSTEM_EXCEPTION),
        t if t == synthetic_exception::INVALID_DATA => Some(synthetic_exception::SYSTEM_EXCEPTION),

        // SystemException → Exception
        t if t == synthetic_exception::SYSTEM_EXCEPTION => {
            Some(synthetic_exception::BASE_EXCEPTION)
        }

        // Everything else at the top → Exception (root)
        t if t == synthetic_exception::BASE_EXCEPTION => None,

        // Unknown synthetic token — default to BASE_EXCEPTION as parent
        _ => Some(synthetic_exception::BASE_EXCEPTION),
    }
}

/// Checks if a token is a synthetic exception token (in the `0x7F01_00xx` range).
///
/// Synthetic exception tokens use table ID `0x7F` (which does not exist in
/// ECMA-335) to avoid collisions with real metadata tokens.
#[must_use]
pub fn is_synthetic(token: Token) -> bool {
    token.value() & 0xFFFF_FF00 == 0x7F01_0000
}

/// Checks if `source` is the same type as, or a subtype of, `target`
/// within the synthetic exception hierarchy.
///
/// Walks the parent chain from `source` upward, returning `true` if
/// `target` is encountered at any level (including `source == target`).
/// The walk is bounded to 5 levels (the deepest hierarchy path is 4:
/// `DivideByZero → Arithmetic → SystemException → Exception`).
///
/// # Arguments
///
/// * `source` — Token of the thrown exception type.
/// * `target` — Token of the handler's catch type.
///
/// # Returns
///
/// `true` if `source == target` or `source` inherits from `target`.
#[must_use]
pub fn is_subtype_of(source: Token, target: Token) -> bool {
    if source == target {
        return true;
    }

    let mut current = source;
    // Walk at most 5 levels (deepest hierarchy is 4: DivideByZero → Arithmetic → System → Exception)
    for _ in 0..5 {
        match parent(current) {
            Some(p) if p == target => return true,
            Some(p) => current = p,
            None => return false,
        }
    }
    false
}

/// Maps a well-known exception type's fully-qualified name to its synthetic token.
///
/// # Arguments
///
/// * `fullname` — The full .NET type name (e.g., `"System.DivideByZeroException"`).
///
/// # Returns
///
/// `Some(token)` for the 21 well-known exception types in the synthetic
/// hierarchy, `None` for all other type names.
#[must_use]
pub fn token_from_fullname(fullname: &str) -> Option<Token> {
    match fullname {
        "System.Exception" => Some(synthetic_exception::BASE_EXCEPTION),
        "System.SystemException" => Some(synthetic_exception::SYSTEM_EXCEPTION),
        "System.IndexOutOfRangeException" => Some(synthetic_exception::INDEX_OUT_OF_RANGE),
        "System.NullReferenceException" => Some(synthetic_exception::NULL_REFERENCE),
        "System.DivideByZeroException" => Some(synthetic_exception::DIVIDE_BY_ZERO),
        "System.OverflowException" => Some(synthetic_exception::OVERFLOW),
        "System.InvalidCastException" => Some(synthetic_exception::INVALID_CAST),
        "System.IO.EndOfStreamException" => Some(synthetic_exception::END_OF_STREAM),
        "System.ObjectDisposedException" => Some(synthetic_exception::OBJECT_DISPOSED),
        "System.InvalidOperationException" => Some(synthetic_exception::INVALID_OPERATION),
        "System.FormatException" => Some(synthetic_exception::FORMAT_EXCEPTION),
        "System.ArgumentException" => Some(synthetic_exception::ARGUMENT_EXCEPTION),
        "System.ArgumentNullException" => Some(synthetic_exception::ARGUMENT_NULL),
        "System.ArgumentOutOfRangeException" => Some(synthetic_exception::ARGUMENT_OUT_OF_RANGE),
        "System.OutOfMemoryException" => Some(synthetic_exception::OUT_OF_MEMORY),
        "System.NotSupportedException" => Some(synthetic_exception::NOT_SUPPORTED),
        "System.Collections.Generic.KeyNotFoundException" => {
            Some(synthetic_exception::KEY_NOT_FOUND)
        }
        "System.IO.FileNotFoundException" => Some(synthetic_exception::FILE_NOT_FOUND),
        "System.IO.DirectoryNotFoundException" => Some(synthetic_exception::DIRECTORY_NOT_FOUND),
        "System.Reflection.TargetInvocationException" => {
            Some(synthetic_exception::TARGET_INVOCATION)
        }
        "System.ArithmeticException" => Some(synthetic_exception::ARITHMETIC),
        "System.IO.IOException" => Some(synthetic_exception::IO_EXCEPTION),
        "System.TypeInitializationException" => Some(synthetic_exception::TYPE_INITIALIZATION),
        "System.TypeLoadException" => Some(synthetic_exception::TYPE_LOAD),
        "System.MissingMethodException" => Some(synthetic_exception::MISSING_METHOD),
        "System.MissingFieldException" => Some(synthetic_exception::MISSING_FIELD),
        "System.NotImplementedException" => Some(synthetic_exception::NOT_IMPLEMENTED),
        "System.AccessViolationException" => Some(synthetic_exception::ACCESS_VIOLATION),
        "System.Security.Cryptography.CryptographicException" => {
            Some(synthetic_exception::CRYPTOGRAPHIC)
        }
        "System.IO.InvalidDataException" => Some(synthetic_exception::INVALID_DATA),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::engine::{
            error::synthetic_exception,
            exceptions::{is_subtype_of, is_synthetic, token_from_fullname},
        },
        metadata::token::Token,
    };

    #[test]
    fn test_is_synthetic() {
        assert!(is_synthetic(synthetic_exception::BASE_EXCEPTION));
        assert!(is_synthetic(synthetic_exception::DIVIDE_BY_ZERO));
        assert!(is_synthetic(synthetic_exception::ARITHMETIC));
        assert!(is_synthetic(synthetic_exception::IO_EXCEPTION));
        assert!(!is_synthetic(Token::new(0x0200_0001))); // TypeRef
        assert!(!is_synthetic(Token::new(0x0600_0001))); // MethodDef
    }

    #[test]
    fn test_divide_by_zero_hierarchy() {
        // DivideByZero → Arithmetic → SystemException → Exception
        assert!(is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::DIVIDE_BY_ZERO
        ));
        assert!(is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::ARITHMETIC
        ));
        assert!(is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::SYSTEM_EXCEPTION
        ));
        assert!(is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::BASE_EXCEPTION
        ));

        // Not caught by unrelated types
        assert!(!is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::IO_EXCEPTION
        ));
        assert!(!is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::NULL_REFERENCE
        ));
    }

    #[test]
    fn test_argument_null_hierarchy() {
        // ArgumentNull → Argument → SystemException → Exception
        assert!(is_subtype_of(
            synthetic_exception::ARGUMENT_NULL,
            synthetic_exception::ARGUMENT_EXCEPTION
        ));
        assert!(is_subtype_of(
            synthetic_exception::ARGUMENT_NULL,
            synthetic_exception::SYSTEM_EXCEPTION
        ));
        assert!(is_subtype_of(
            synthetic_exception::ARGUMENT_NULL,
            synthetic_exception::BASE_EXCEPTION
        ));

        assert!(!is_subtype_of(
            synthetic_exception::ARGUMENT_NULL,
            synthetic_exception::FORMAT_EXCEPTION
        ));
    }

    #[test]
    fn test_object_disposed_hierarchy() {
        // ObjectDisposed → InvalidOperation → SystemException → Exception
        assert!(is_subtype_of(
            synthetic_exception::OBJECT_DISPOSED,
            synthetic_exception::INVALID_OPERATION
        ));
        assert!(is_subtype_of(
            synthetic_exception::OBJECT_DISPOSED,
            synthetic_exception::BASE_EXCEPTION
        ));
    }

    #[test]
    fn test_io_exception_hierarchy() {
        // EndOfStream → IOException → SystemException → Exception
        assert!(is_subtype_of(
            synthetic_exception::END_OF_STREAM,
            synthetic_exception::IO_EXCEPTION
        ));
        assert!(is_subtype_of(
            synthetic_exception::END_OF_STREAM,
            synthetic_exception::BASE_EXCEPTION
        ));

        // FileNotFound → IOException
        assert!(is_subtype_of(
            synthetic_exception::FILE_NOT_FOUND,
            synthetic_exception::IO_EXCEPTION
        ));
        // DirectoryNotFound → IOException
        assert!(is_subtype_of(
            synthetic_exception::DIRECTORY_NOT_FOUND,
            synthetic_exception::IO_EXCEPTION
        ));

        // IOException does NOT catch ArithmeticException
        assert!(!is_subtype_of(
            synthetic_exception::ARITHMETIC,
            synthetic_exception::IO_EXCEPTION
        ));
    }

    #[test]
    fn test_base_exception_catches_all_synthetic() {
        let all_exceptions = [
            synthetic_exception::INDEX_OUT_OF_RANGE,
            synthetic_exception::NULL_REFERENCE,
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::OVERFLOW,
            synthetic_exception::INVALID_CAST,
            synthetic_exception::END_OF_STREAM,
            synthetic_exception::OBJECT_DISPOSED,
            synthetic_exception::INVALID_OPERATION,
            synthetic_exception::FORMAT_EXCEPTION,
            synthetic_exception::ARGUMENT_EXCEPTION,
            synthetic_exception::ARGUMENT_NULL,
            synthetic_exception::NOT_SUPPORTED,
            synthetic_exception::KEY_NOT_FOUND,
            synthetic_exception::FILE_NOT_FOUND,
            synthetic_exception::DIRECTORY_NOT_FOUND,
            synthetic_exception::TARGET_INVOCATION,
            synthetic_exception::ARITHMETIC,
            synthetic_exception::IO_EXCEPTION,
            synthetic_exception::TYPE_INITIALIZATION,
            synthetic_exception::SYSTEM_EXCEPTION,
            synthetic_exception::TYPE_LOAD,
            synthetic_exception::MISSING_METHOD,
            synthetic_exception::MISSING_FIELD,
            synthetic_exception::NOT_IMPLEMENTED,
            synthetic_exception::ACCESS_VIOLATION,
            synthetic_exception::CRYPTOGRAPHIC,
            synthetic_exception::INVALID_DATA,
        ];

        for exc in &all_exceptions {
            assert!(
                is_subtype_of(*exc, synthetic_exception::BASE_EXCEPTION),
                "Expected {:08X} to be subtype of BASE_EXCEPTION",
                exc.value()
            );
        }
    }

    #[test]
    fn test_not_cross_hierarchy() {
        // Arithmetic does not catch IO and vice versa
        assert!(!is_subtype_of(
            synthetic_exception::DIVIDE_BY_ZERO,
            synthetic_exception::IO_EXCEPTION
        ));
        assert!(!is_subtype_of(
            synthetic_exception::END_OF_STREAM,
            synthetic_exception::ARITHMETIC
        ));

        // IndexOutOfRange does not catch NullReference
        assert!(!is_subtype_of(
            synthetic_exception::INDEX_OUT_OF_RANGE,
            synthetic_exception::NULL_REFERENCE
        ));
    }

    #[test]
    fn test_token_from_fullname() {
        assert_eq!(
            token_from_fullname("System.DivideByZeroException"),
            Some(synthetic_exception::DIVIDE_BY_ZERO)
        );
        assert_eq!(
            token_from_fullname("System.ArithmeticException"),
            Some(synthetic_exception::ARITHMETIC)
        );
        assert_eq!(
            token_from_fullname("System.IO.IOException"),
            Some(synthetic_exception::IO_EXCEPTION)
        );
        assert_eq!(token_from_fullname("SomeOther.Type"), None);
    }
}
