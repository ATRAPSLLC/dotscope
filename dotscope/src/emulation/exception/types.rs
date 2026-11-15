//! Exception clause types for .NET exception handling.
//!
//! This module defines the different types of exception clauses that can appear
//! in .NET method metadata. Exception clauses define protected regions (try blocks)
//! and their associated handlers as specified in ECMA-335.
//!
//! # Exception Clause Types
//!
//! .NET supports four types of exception handlers:
//!
//! - **Catch** (`try { } catch (Type) { }`) - Handles exceptions of a specific type
//! - **Filter** (`try { } catch when (expr) { }`) - Handles exceptions based on runtime
//!   evaluation of a filter expression
//! - **Finally** (`try { } finally { }`) - Cleanup code that runs regardless of whether
//!   an exception occurred
//! - **Fault** - Similar to finally, but only runs when an exception is thrown (not
//!   commonly used in C#)
//!
//! # Metadata Representation
//!
//! In .NET metadata, exception clauses are stored in the method body header and define:
//! - The try block's offset and length
//! - The handler block's offset and length
//! - Additional data depending on type (catch type token, filter offset)
//!
//! # Handler Matching
//!
//! When an exception is thrown, clauses are searched in order (innermost first) to find
//! a matching handler. The [`HandlerMatch`] enum represents a found handler ready for
//! execution.

use crate::metadata::{
    method::{ExceptionHandler as MetadataExceptionHandler, ExceptionHandlerFlags},
    token::Token,
};

/// An exception handling clause from .NET method metadata.
///
/// Exception clauses define protected regions (try blocks) and their associated
/// handlers within a method. Each clause specifies the IL offset ranges for
/// both the try block and the handler block.
///
/// # Clause Types
///
/// - [`Catch`](ExceptionClause::Catch) - Type-based exception handling
/// - [`Filter`](ExceptionClause::Filter) - Condition-based exception handling
/// - [`Finally`](ExceptionClause::Finally) - Guaranteed cleanup code
/// - [`Fault`](ExceptionClause::Fault) - Exception-only cleanup code
///
/// # IL Offset Ranges
///
/// All offsets are relative to the start of the method body's IL code:
/// - `try_offset` to `try_offset + try_length` defines the protected region
/// - `handler_offset` to `handler_offset + handler_length` defines the handler
///
/// # Example
///
/// ```
/// use dotscope::emulation::ExceptionClause;
/// use dotscope::metadata::token::Token;
///
/// // `System.Exception`, as the module's TypeRef names it
/// let exception_type_token = Token::new(0x0100_0002);
///
/// // For C# code:
/// // try { /* IL 0x00-0x10 */ }
/// // catch (Exception) { /* IL 0x10-0x20 */ }
///
/// let clause = ExceptionClause::Catch {
///     try_offset: 0x00,
///     try_length: 0x10,
///     handler_offset: 0x10,
///     handler_length: 0x10,
///     catch_type: exception_type_token,
/// };
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExceptionClause {
    /// A catch clause that handles exceptions of a specific type.
    ///
    /// Corresponds to `try { } catch (ExceptionType) { }` in C#.
    /// The handler is entered if the thrown exception's type is assignable
    /// to `catch_type`.
    Catch {
        /// IL offset where the try block begins.
        try_offset: u32,
        /// Length in bytes of the try block.
        try_length: u32,
        /// IL offset where the catch handler begins.
        handler_offset: u32,
        /// Length in bytes of the catch handler.
        handler_length: u32,
        /// Metadata token of the exception type to catch.
        ///
        /// The exception is caught if its type is this type or a derived type.
        catch_type: Token,
    },

    /// A filter clause that handles exceptions based on a runtime condition.
    ///
    /// Corresponds to `try { } catch (Exception e) when (condition) { }` in C#.
    /// The filter code is evaluated first; if it returns true (non-zero on
    /// the evaluation stack), the handler is entered.
    Filter {
        /// IL offset where the try block begins.
        try_offset: u32,
        /// Length in bytes of the try block.
        try_length: u32,
        /// IL offset where the catch handler begins (entered if filter passes).
        handler_offset: u32,
        /// Length in bytes of the catch handler.
        handler_length: u32,
        /// IL offset where the filter code begins.
        ///
        /// The filter code must push an integer onto the stack:
        /// - Non-zero (typically 1): Enter the handler
        /// - Zero: Continue searching for other handlers
        filter_offset: u32,
    },

    /// A finally clause that runs regardless of whether an exception occurred.
    ///
    /// Corresponds to `try { } finally { }` in C#.
    /// The handler runs on both normal exit (via `leave` instruction) and
    /// exception exit (during unwinding).
    Finally {
        /// IL offset where the try block begins.
        try_offset: u32,
        /// Length in bytes of the try block.
        try_length: u32,
        /// IL offset where the finally handler begins.
        handler_offset: u32,
        /// Length in bytes of the finally handler.
        handler_length: u32,
    },

    /// A fault clause that runs only when an exception is thrown.
    ///
    /// Similar to finally, but only executes on the exception path.
    /// Not commonly used in C# but supported by the CLR.
    Fault {
        /// IL offset where the try block begins.
        try_offset: u32,
        /// Length in bytes of the try block.
        try_length: u32,
        /// IL offset where the fault handler begins.
        handler_offset: u32,
        /// Length in bytes of the fault handler.
        handler_length: u32,
    },
}

impl ExceptionClause {
    /// Gets the IL offset where the try block begins.
    ///
    /// # Returns
    ///
    /// The starting IL offset of the protected region.
    #[must_use]
    pub fn try_offset(&self) -> u32 {
        match self {
            Self::Catch { try_offset, .. }
            | Self::Filter { try_offset, .. }
            | Self::Finally { try_offset, .. }
            | Self::Fault { try_offset, .. } => *try_offset,
        }
    }

    /// Gets the length of the try block in bytes.
    ///
    /// # Returns
    ///
    /// The length of the protected region.
    #[must_use]
    pub fn try_length(&self) -> u32 {
        match self {
            Self::Catch { try_length, .. }
            | Self::Filter { try_length, .. }
            | Self::Finally { try_length, .. }
            | Self::Fault { try_length, .. } => *try_length,
        }
    }

    /// Gets the IL offset where the try block ends.
    ///
    /// This is the first offset *after* the try block (exclusive end).
    ///
    /// # Returns
    ///
    /// The ending IL offset of the protected region.
    #[must_use]
    pub fn try_end(&self) -> u32 {
        self.try_offset().saturating_add(self.try_length())
    }

    /// Gets the IL offset where the handler block begins.
    ///
    /// # Returns
    ///
    /// The starting IL offset of the handler code.
    #[must_use]
    pub fn handler_offset(&self) -> u32 {
        match self {
            Self::Catch { handler_offset, .. }
            | Self::Filter { handler_offset, .. }
            | Self::Finally { handler_offset, .. }
            | Self::Fault { handler_offset, .. } => *handler_offset,
        }
    }

    /// Gets the length of the handler block in bytes.
    ///
    /// # Returns
    ///
    /// The length of the handler code.
    #[must_use]
    pub fn handler_length(&self) -> u32 {
        match self {
            Self::Catch { handler_length, .. }
            | Self::Filter { handler_length, .. }
            | Self::Finally { handler_length, .. }
            | Self::Fault { handler_length, .. } => *handler_length,
        }
    }

    /// Gets the IL offset where the handler block ends.
    ///
    /// This is the first offset *after* the handler block (exclusive end).
    ///
    /// # Returns
    ///
    /// The ending IL offset of the handler code.
    #[must_use]
    pub fn handler_end(&self) -> u32 {
        self.handler_offset().saturating_add(self.handler_length())
    }

    /// Checks if an IL offset is within the try block.
    ///
    /// An offset is considered "in the try block" if it is greater than or
    /// equal to the try offset and less than the try end (half-open range).
    ///
    /// # Arguments
    ///
    /// * `offset` - The IL offset to check
    ///
    /// # Returns
    ///
    /// `true` if the offset is within the protected region.
    #[must_use]
    pub fn is_in_try(&self, offset: u32) -> bool {
        offset >= self.try_offset() && offset < self.try_end()
    }

    /// Checks if an IL offset is within the handler block.
    ///
    /// An offset is considered "in the handler" if it is greater than or
    /// equal to the handler offset and less than the handler end.
    ///
    /// # Arguments
    ///
    /// * `offset` - The IL offset to check
    ///
    /// # Returns
    ///
    /// `true` if the offset is within the handler code.
    #[must_use]
    pub fn is_in_handler(&self, offset: u32) -> bool {
        offset >= self.handler_offset() && offset < self.handler_end()
    }

    /// Checks if this is a catch clause.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`Catch`](ExceptionClause::Catch) variant.
    #[must_use]
    pub fn is_catch(&self) -> bool {
        matches!(self, Self::Catch { .. })
    }

    /// Checks if this is a filter clause.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`Filter`](ExceptionClause::Filter) variant.
    #[must_use]
    pub fn is_filter(&self) -> bool {
        matches!(self, Self::Filter { .. })
    }

    /// Checks if this is a finally clause.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`Finally`](ExceptionClause::Finally) variant.
    #[must_use]
    pub fn is_finally(&self) -> bool {
        matches!(self, Self::Finally { .. })
    }

    /// Checks if this is a fault clause.
    ///
    /// # Returns
    ///
    /// `true` if this is a [`Fault`](ExceptionClause::Fault) variant.
    #[must_use]
    pub fn is_fault(&self) -> bool {
        matches!(self, Self::Fault { .. })
    }

    /// Gets the catch type token for catch clauses.
    ///
    /// # Returns
    ///
    /// - `Some(token)` if this is a [`Catch`](ExceptionClause::Catch) clause
    /// - `None` for other clause types
    #[must_use]
    pub fn catch_type(&self) -> Option<Token> {
        match self {
            Self::Catch { catch_type, .. } => Some(*catch_type),
            _ => None,
        }
    }

    /// Gets the filter offset for filter clauses.
    ///
    /// # Returns
    ///
    /// - `Some(offset)` if this is a [`Filter`](ExceptionClause::Filter) clause
    /// - `None` for other clause types
    #[must_use]
    pub fn filter_offset(&self) -> Option<u32> {
        match self {
            Self::Filter { filter_offset, .. } => Some(*filter_offset),
            _ => None,
        }
    }
}

/// A location within a method's IL instruction stream.
///
/// This structure uniquely identifies a point in the IL code of a method,
/// combining the method's token with an offset into its IL body. It is used
/// for stack traces, exception throw locations, and handler entry points.
///
/// # Display Format
///
/// When formatted for display, uses the format `{method_token}+0x{offset:04X}`,
/// for example: `0x06000001+0x0042`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstructionLocation {
    /// The metadata token of the method containing this location.
    ///
    /// This is typically a MethodDef token (table 0x06) from the assembly's
    /// metadata tables.
    pub method: Token,

    /// The IL offset within the method body.
    ///
    /// This is the byte offset from the start of the method's IL code where
    /// this location points.
    pub offset: u32,
}

impl InstructionLocation {
    /// Creates a new instruction location.
    ///
    /// # Arguments
    ///
    /// * `method` - The metadata token of the containing method
    /// * `offset` - The IL byte offset within the method
    ///
    /// # Returns
    ///
    /// A new `InstructionLocation` pointing to the specified position.
    #[must_use]
    pub fn new(method: Token, offset: u32) -> Self {
        Self { method, offset }
    }
}

impl std::fmt::Display for InstructionLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}+0x{:04X}", self.method, self.offset)
    }
}

/// Result of searching for an exception handler.
///
/// This enum represents a handler that was found during exception handler search.
/// It contains all the information needed to execute the handler or continue
/// the search after cleanup handlers complete.
///
/// # Handler Types
///
/// - [`Catch`](HandlerMatch::Catch) - A type-matched catch handler ready to enter
/// - [`Filter`](HandlerMatch::Filter) - A filter handler requiring evaluation
/// - [`Finally`](HandlerMatch::Finally) - A finally block to execute during unwind
/// - [`Fault`](HandlerMatch::Fault) - A fault block to execute on exception path
///
/// # Execution Order
///
/// When multiple handlers match, they execute in this order:
/// 1. Finally/fault blocks (cleanup)
/// 2. Filter evaluation (if applicable)
/// 3. Catch handler entry (if filter passes or type matches)
#[derive(Clone, Debug)]
pub enum HandlerMatch {
    /// A catch handler that matches the exception type.
    ///
    /// The handler is ready to be entered; the exception type has already
    /// been verified as compatible with the catch clause's type.
    Catch {
        /// The method containing the catch handler.
        method: Token,
        /// IL offset where the catch handler code begins.
        handler_offset: u32,
    },

    /// A filter handler that requires runtime evaluation.
    ///
    /// The filter code must be executed first. If it returns non-zero
    /// (true), control transfers to the handler; otherwise, the search
    /// continues.
    Filter {
        /// The method containing the filter and handler.
        method: Token,
        /// IL offset where the filter evaluation code begins.
        filter_offset: u32,
        /// IL offset where the handler begins (entered if filter passes).
        handler_offset: u32,
    },

    /// A finally block that must execute during unwinding.
    ///
    /// Finally blocks run on both exception and normal exit paths.
    /// They must complete before the search can continue.
    Finally {
        /// The method containing the finally block.
        method: Token,
        /// IL offset where the finally handler code begins.
        handler_offset: u32,
        /// Length of the finally handler in bytes.
        handler_length: u32,
        /// Whether to continue searching for a catch handler after this finally.
        ///
        /// - `true` - This finally is part of exception unwinding
        /// - `false` - This finally is for a `leave` instruction (normal exit)
        continue_search_after: bool,
    },

    /// A fault block that runs only on the exception path.
    ///
    /// Similar to finally, but only executes when an exception is active.
    Fault {
        /// The method containing the fault block.
        method: Token,
        /// IL offset where the fault handler code begins.
        handler_offset: u32,
        /// Length of the fault handler in bytes.
        handler_length: u32,
    },
}

impl ExceptionClause {
    /// Converts a metadata exception handler to an exception clause.
    ///
    /// This method bridges the metadata representation ([`MetadataExceptionHandler`])
    /// used during assembly loading with the emulation representation ([`ExceptionClause`])
    /// used during runtime exception handling.
    ///
    /// # Arguments
    ///
    /// * `handler` - The metadata exception handler to convert
    ///
    /// # Returns
    ///
    /// An `ExceptionClause` with the appropriate variant based on the handler's flags:
    /// - `FILTER` flag -> [`Filter`](ExceptionClause::Filter)
    /// - `FINALLY` flag -> [`Finally`](ExceptionClause::Finally)
    /// - `FAULT` flag -> [`Fault`](ExceptionClause::Fault)
    /// - No flags (default) -> [`Catch`](ExceptionClause::Catch)
    ///
    /// [`MetadataExceptionHandler`]: crate::metadata::method::ExceptionHandler
    #[must_use]
    pub fn from_metadata_handler(handler: &MetadataExceptionHandler) -> Self {
        if handler.flags.contains(ExceptionHandlerFlags::FILTER) {
            ExceptionClause::Filter {
                try_offset: handler.try_offset,
                try_length: handler.try_length,
                handler_offset: handler.handler_offset,
                handler_length: handler.handler_length,
                filter_offset: handler.filter_offset,
            }
        } else if handler.flags.contains(ExceptionHandlerFlags::FINALLY) {
            ExceptionClause::Finally {
                try_offset: handler.try_offset,
                try_length: handler.try_length,
                handler_offset: handler.handler_offset,
                handler_length: handler.handler_length,
            }
        } else if handler.flags.contains(ExceptionHandlerFlags::FAULT) {
            ExceptionClause::Fault {
                try_offset: handler.try_offset,
                try_length: handler.try_length,
                handler_offset: handler.handler_offset,
                handler_length: handler.handler_length,
            }
        } else {
            // EXCEPTION (catch) handler
            let catch_type = handler
                .handler
                .as_ref()
                .map_or_else(|| Token::new(0), |t| t.token);
            ExceptionClause::Catch {
                try_offset: handler.try_offset,
                try_length: handler.try_length,
                handler_offset: handler.handler_offset,
                handler_length: handler.handler_length,
                catch_type,
            }
        }
    }

    /// Converts a slice of metadata exception handlers to exception clauses.
    ///
    /// Convenience method for converting all exception handlers from a method's
    /// metadata into the emulation representation.
    ///
    /// # Arguments
    ///
    /// * `handlers` - Slice of metadata exception handlers from a method body
    ///
    /// # Returns
    ///
    /// A vector of exception clauses in the same order as the input handlers.
    /// The order is significant: clauses are processed innermost-first during
    /// handler search.
    #[must_use]
    pub fn from_metadata_handlers(handlers: &[MetadataExceptionHandler]) -> Vec<Self> {
        handlers.iter().map(Self::from_metadata_handler).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_clause_catch() {
        let clause = ExceptionClause::Catch {
            try_offset: 0x10,
            try_length: 0x20,
            handler_offset: 0x30,
            handler_length: 0x10,
            catch_type: Token::new(0x01000001),
        };

        assert!(clause.is_catch());
        assert!(!clause.is_finally());
        assert_eq!(clause.try_offset(), 0x10);
        assert_eq!(clause.try_end(), 0x30);
        assert_eq!(clause.handler_offset(), 0x30);
        assert!(clause.is_in_try(0x15));
        assert!(!clause.is_in_try(0x30));
        assert!(clause.is_in_handler(0x35));
    }

    #[test]
    fn test_exception_clause_finally() {
        let clause = ExceptionClause::Finally {
            try_offset: 0x00,
            try_length: 0x50,
            handler_offset: 0x50,
            handler_length: 0x10,
        };

        assert!(clause.is_finally());
        assert!(!clause.is_catch());
        assert!(clause.catch_type().is_none());
    }

    #[test]
    fn test_instruction_location() {
        let loc = InstructionLocation::new(Token::new(0x06000001), 0x0042);
        assert_eq!(loc.method, Token::new(0x06000001));
        assert_eq!(loc.offset, 0x0042);
    }
}
