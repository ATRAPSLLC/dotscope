//! .NET CIL method exception handler representation and analysis.
//!
//! This module provides comprehensive support for analyzing exception handling structures
//! in Common Intermediate Language (CIL) method bodies. Exception handlers define
//! try/catch/finally/fault regions that control program flow during exception processing,
//! as specified by ECMA-335.
//!
//! # Exception Handling in .NET
//!
//! The .NET runtime uses structured exception handling (SEH) with four types of handlers:
//!
//! 1. **Exception Handlers**: Catch specific exception types using type matching
//! 2. **Filter Handlers**: Use custom filter expressions to determine exception handling
//! 3. **Finally Handlers**: Execute cleanup code regardless of exception occurrence
//! 4. **Fault Handlers**: Execute cleanup code only when exceptions are thrown
//!
//! ## Exception Handler Layout
//!
//! Exception handlers are defined by two regions in the IL code:
//! ```text
//! try {
//!     // Protected region: [try_offset, try_offset + try_length)
//!     // Code that may throw exceptions
//! }
//! catch (SpecificException) {
//!     // Handler region: [handler_offset, handler_offset + handler_length)
//!     // Exception handling code
//! }
//! ```
//!
//! # Common Use Cases
//!
//! ## Exception Handler Analysis
//!
//! ```rust
//! use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//!
//! # fn analyze_method_body() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! for handler in &exception_handlers {
//!     match handler.flags {
//!         ExceptionHandlerFlags::EXCEPTION => {
//!             println!("Catch block for try region [{}, {})",
//!                 handler.try_offset,
//!                 handler.try_offset + handler.try_length);
//!             
//!             if let Some(exception_type) = &handler.handler {
//!                 println!("  Catches: {}", exception_type.name);
//!             }
//!         },
//!         ExceptionHandlerFlags::FINALLY => {
//!             println!("Finally block at offset 0x{:04X}", handler.handler_offset);
//!         },
//!         ExceptionHandlerFlags::FILTER => {
//!             println!("Filter handler at offset 0x{:04X}", handler.filter_offset);
//!         },
//!         ExceptionHandlerFlags::FAULT => {
//!             println!("Fault handler at offset 0x{:04X}", handler.handler_offset);
//!         },
//!         _ => println!("Unknown handler type: {:?}", handler.flags),
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Control Flow Graph Construction
//!
//! ```rust
//! # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//! # fn build_control_flow_graph() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! // Exception handlers create additional control flow edges
//! for handler in &exception_handlers {
//!     // Entry point for protected region
//!     let protected_start = handler.try_offset;
//!     let protected_end = handler.try_offset + handler.try_length;
//!     
//!     // Handler entry point
//!     let handler_start = handler.handler_offset;
//!     
//!     // Any instruction in protected region can transfer to handler
//!     println!("Protected region: [0x{:04X}, 0x{:04X}) -> Handler: 0x{:04X}",
//!         protected_start, protected_end, handler_start);
//!         
//!     if handler.flags == ExceptionHandlerFlags::FILTER {
//!         println!("  Filter expression at: 0x{:04X}", handler.filter_offset);
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Security Analysis
//!
//! ```rust
//! # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
//! # fn security_analysis() -> Result<(), Box<dyn std::error::Error>> {
//! # let exception_handlers: Vec<ExceptionHandler> = vec![];
//! // Analyze exception handling patterns for security implications
//! let mut has_generic_catch = false;
//! let mut has_empty_catch = false;
//!
//! for handler in &exception_handlers {
//!     if handler.flags == ExceptionHandlerFlags::EXCEPTION {
//!         if let Some(exception_type) = &handler.handler {
//!             if exception_type.name == "System.Exception" {
//!                 has_generic_catch = true;
//!             }
//!         }
//!         
//!         if handler.handler_length == 0 {
//!             has_empty_catch = true;
//!         }
//!     }
//! }
//!
//! if has_generic_catch {
//!     println!("WARNING: Catches all exceptions (potential information hiding)");
//! }
//! if has_empty_catch {
//!     println!("WARNING: Empty exception handler (swallows exceptions)");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Binary Format
//!
//! Exception handlers are stored in method body headers using two formats:
//!
//! ## Small Format (12 bytes per handler)
//! ```text
//! - Flags: u16
//! - TryOffset: u16  
//! - TryLength: u8
//! - HandlerOffset: u16
//! - HandlerLength: u8
//! - ClassToken/FilterOffset: u32
//! ```
//!
//! ## Fat Format (24 bytes per handler)
//! ```text
//! - Flags: u32
//! - TryOffset: u32
//! - TryLength: u32  
//! - HandlerOffset: u32
//! - HandlerLength: u32
//! - ClassToken/FilterOffset: u32
//! ```
//!
//! # ECMA-335 Compliance
//!
//! This implementation follows ECMA-335 6th Edition specifications:
//! - **Partition I, Section 12.4**: Exception handling model
//! - **Partition II, Section 25.4.6**: Exception handling clauses format
//! - **Partition III, Section 1.7.5**: Exception handling instruction semantics
//!
//! # Thread Safety
//!
//! [`ExceptionHandler`] instances are immutable and safe to share across threads.
//! Exception type references use reference-counted smart pointers for efficient sharing.

use std::collections::{BTreeSet, HashSet};

use crate::{
    assembly::{FlowType, Instruction},
    metadata::typesystem::CilTypeRc,
    Error, Result,
};

metadata_flags! {
    /// Exception handler type flags defining the kind of exception handling clause.
    ///
    /// These flags determine how the exception handler processes exceptions and controls
    /// program flow within structured exception handling blocks. Each flag represents
    /// a different exception handling strategy as defined by ECMA-335.
    ///
    /// # Handler Types
    ///
    /// The four fundamental exception handler types each serve different purposes:
    ///
    /// - **Exception Handlers**: Type-based exception catching with class token matching
    /// - **Filter Handlers**: Custom filter expressions for complex exception logic
    /// - **Finally Handlers**: Guaranteed cleanup code execution
    /// - **Fault Handlers**: Exception-only cleanup code execution
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::method::ExceptionHandlerFlags;
    ///
    /// // Check handler type
    /// let flags = ExceptionHandlerFlags::EXCEPTION;
    /// assert!(flags == ExceptionHandlerFlags::EXCEPTION);
    /// assert!(!flags.contains(ExceptionHandlerFlags::FINALLY));
    ///
    /// // Multiple flags are mutually exclusive for exception handlers
    /// assert!(ExceptionHandlerFlags::EXCEPTION.bits() == 0x0000);
    /// assert!(ExceptionHandlerFlags::FILTER.bits() == 0x0001);
    /// ```
    ///
    /// # Binary Representation
    ///
    /// The flags are stored as a 16-bit or 32-bit value in the exception handler
    /// table, depending on whether the small or fat format is used.
    pub struct ExceptionHandlerFlags(u16);
}

impl ExceptionHandlerFlags {
    /// A typed exception clause that catches specific exception types.
    ///
    /// The handler catches exceptions that are assignment-compatible with the
    /// exception type specified by the `class_token` field. This includes the
    /// exact type and all derived types.
    ///
    /// # Usage
    ///
    /// ```csharp
    /// try {
    ///     // Protected code
    /// }
    /// catch (ArgumentException ex) {
    ///     // Handler code - class_token points to ArgumentException
    /// }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - The `class_token` field contains the metadata token of the exception type
    /// - Type matching follows .NET inheritance rules (catches derived types)
    /// - Most common exception handler type in .NET assemblies
    pub const EXCEPTION: Self = Self(0x0000);

    /// An exception filter and handler clause with custom filter logic.
    ///
    /// The filter expression is executed first to determine whether this handler
    /// should process the exception. The filter can examine the exception object
    /// and execution context to make complex decisions.
    ///
    /// # Usage
    ///
    /// ```csharp
    /// try {
    ///     // Protected code
    /// }
    /// catch (Exception ex) when (ex.Message.Contains("specific")) {
    ///     // Handler code - filter_offset points to filter expression
    /// }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - The `filter_offset` field points to the filter expression code
    /// - Filter must leave a boolean value on the evaluation stack
    /// - Provides fine-grained control over exception handling logic
    /// - Less common than typed exception handlers
    pub const FILTER: Self = Self(0x0001);

    /// A finally clause that executes regardless of exception occurrence.
    ///
    /// Finally blocks provide guaranteed cleanup code execution during both
    /// normal control flow and exception unwinding. The runtime ensures
    /// finally blocks execute even when exceptions are thrown.
    ///
    /// # Usage
    ///
    /// ```csharp
    /// try {
    ///     // Protected code
    /// }
    /// finally {
    ///     // Cleanup code - always executes
    /// }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - Executes during normal method exit and exception unwinding
    /// - Cannot catch exceptions, only perform cleanup
    /// - Essential for resource management (using statements compile to finally)
    /// - The `class_token`/`filter_offset` field is unused for finally handlers
    pub const FINALLY: Self = Self(0x0002);

    /// A fault clause that executes only when exceptions are thrown.
    ///
    /// Fault handlers are similar to finally blocks but only execute during
    /// exception unwinding, not during normal control flow. They provide
    /// exception-specific cleanup without catching the exception.
    ///
    /// # Usage
    ///
    /// ```csharp
    /// try {
    ///     // Protected code
    /// }
    /// fault {
    ///     // Cleanup code - executes only on exceptions
    /// }
    /// ```
    ///
    /// # Implementation Notes
    ///
    /// - Only executes during exception unwinding, not normal exit
    /// - Cannot catch exceptions, only perform fault-specific cleanup
    /// - Less common than finally handlers in typical .NET code
    /// - The `class_token`/`filter_offset` field is unused for fault handlers
    pub const FAULT: Self = Self(0x0004);

    /// Returns the discrete handler kind for this flag value.
    ///
    /// Performs the bitwise classification described by ECMA-335 §II.25.4.6 and
    /// returns a typed enum, removing the need for callers to match against the
    /// individual `EXCEPTION`/`FILTER`/`FINALLY`/`FAULT` constants. Unrecognized
    /// flag values fall back to [`ExceptionHandlerKind::Catch`] because
    /// `EXCEPTION` is the zero pattern.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::method::{ExceptionHandlerFlags, ExceptionHandlerKind};
    ///
    /// assert_eq!(ExceptionHandlerFlags::EXCEPTION.kind(), ExceptionHandlerKind::Catch);
    /// assert_eq!(ExceptionHandlerFlags::FILTER.kind(),    ExceptionHandlerKind::Filter);
    /// assert_eq!(ExceptionHandlerFlags::FINALLY.kind(),   ExceptionHandlerKind::Finally);
    /// assert_eq!(ExceptionHandlerFlags::FAULT.kind(),     ExceptionHandlerKind::Fault);
    /// ```
    #[must_use]
    pub const fn kind(&self) -> ExceptionHandlerKind {
        // ECMA-335 §II.25.4.6: handler-kind bits are mutually exclusive.
        // FILTER/FINALLY/FAULT are 0x0001/0x0002/0x0004; EXCEPTION (catch) is 0x0000.
        if self.0 & ExceptionHandlerFlags::FILTER.0 != 0 {
            ExceptionHandlerKind::Filter
        } else if self.0 & ExceptionHandlerFlags::FINALLY.0 != 0 {
            ExceptionHandlerKind::Finally
        } else if self.0 & ExceptionHandlerFlags::FAULT.0 != 0 {
            ExceptionHandlerKind::Fault
        } else {
            ExceptionHandlerKind::Catch
        }
    }
}

/// Discrete classification of an exception handler clause.
///
/// Returned by [`ExceptionHandlerFlags::kind`]. Each variant corresponds to one
/// of the four handler kinds defined by ECMA-335 §II.25.4.6.
///
/// # Stability
///
/// The string returned by [`ExceptionHandlerKind::as_str`] and by the [`Display`]
/// impl is part of the stable public API. It is safe to persist (file, database,
/// log line) and to parse.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionHandlerKind {
    /// Typed exception clause - the protected region's exceptions are matched
    /// against the type referenced by the handler's class token.
    Catch,
    /// Filtered exception clause - IL at `filter_offset` decides whether the
    /// handler runs.
    Filter,
    /// Finally clause - runs unconditionally on protected-region exit.
    Finally,
    /// Fault clause - runs only when the protected region exits via exception.
    Fault,
}

impl ExceptionHandlerKind {
    /// Returns a stable `&'static str` identifier for this kind.
    ///
    /// Identifiers are lowercase (`"catch"`, `"filter"`, `"finally"`, `"fault"`).
    /// They are part of the stable public API and safe to persist.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            ExceptionHandlerKind::Catch => "catch",
            ExceptionHandlerKind::Filter => "filter",
            ExceptionHandlerKind::Finally => "finally",
            ExceptionHandlerKind::Fault => "fault",
        }
    }
}

impl std::fmt::Display for ExceptionHandlerKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Represents a single exception handler within a .NET method body.
///
/// An `ExceptionHandler` defines a structured exception handling region that consists
/// of a protected try block and associated handler code. Exception handlers implement
/// the .NET runtime's structured exception handling (SEH) model as specified by ECMA-335.
///
/// # Structure
///
/// Each exception handler defines two key regions:
///
/// 1. **Protected Region**: The try block where exceptions may be thrown
/// 2. **Handler Region**: The catch/finally/fault code that processes exceptions
///
/// # Handler Types and Field Usage
///
/// Different handler types use the fields differently:
///
/// ## Exception Handlers (`EXCEPTION` flag)
/// - `handler`: Contains the exception type that this handler catches
/// - `filter_offset`: Unused (contains class token value for historical reasons)
/// - Catches exceptions assignable to the specified type
///
/// ## Filter Handlers (`FILTER` flag)  
/// - `handler`: Contains the exception type (typically `System.Exception`)
/// - `filter_offset`: Points to the filter expression code within the method
/// - Filter code determines whether to handle the exception
///
/// ## Finally Handlers (`FINALLY` flag)
/// - `handler`: Unused (None)
/// - `filter_offset`: Unused  
/// - Always executes during normal and exceptional control flow
///
/// ## Fault Handlers (`FAULT` flag)
/// - `handler`: Unused (None)
/// - `filter_offset`: Unused
/// - Executes only during exception unwinding
///
/// # Memory Layout
///
/// ```text
/// Try Block:     [try_offset, try_offset + try_length)
/// Handler Block: [handler_offset, handler_offset + handler_length)
/// Filter Block:  [filter_offset, ...]  (FILTER handlers only)
/// ```
///
/// # Examples
///
/// ## Basic Exception Handler Analysis
///
/// ```rust
/// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
///
/// # fn analyze_handler(handler: &ExceptionHandler) -> Result<(), Box<dyn std::error::Error>> {
/// match handler.flags {
///     ExceptionHandlerFlags::EXCEPTION => {
///         println!("Exception handler:");
///         println!("  Protected: [0x{:04X}, 0x{:04X})",
///             handler.try_offset,
///             handler.try_offset + handler.try_length);
///         println!("  Handler: [0x{:04X}, 0x{:04X})",
///             handler.handler_offset,
///             handler.handler_offset + handler.handler_length);
///             
///         if let Some(exception_type) = &handler.handler {
///             println!("  Catches: {}", exception_type.name);
///         }
///     },
///     ExceptionHandlerFlags::FINALLY => {
///         println!("Finally handler at 0x{:04X} (length: {})",
///             handler.handler_offset, handler.handler_length);
///     },
///     _ => println!("Other handler type: {:?}", handler.flags),
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Control Flow Edge Detection
///
/// ```rust
/// # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
/// # fn detect_control_flow_edges(handlers: &[ExceptionHandler]) -> Result<(), Box<dyn std::error::Error>> {
/// for handler in handlers {
///     // Any instruction in the protected region can transfer to the handler
///     for offset in handler.try_offset..(handler.try_offset + handler.try_length) {
///         println!("IL_{:04X} -> Handler_{:04X} (exception edge)",
///             offset, handler.handler_offset);
///     }
///     
///     // Filter handlers have additional control flow
///     if handler.flags == ExceptionHandlerFlags::FILTER {
///         println!("IL_{:04X} -> Filter_{:04X} (filter evaluation)",
///             handler.try_offset, handler.filter_offset);
///         println!("Filter_{:04X} -> Handler_{:04X} (filter success)",
///             handler.filter_offset, handler.handler_offset);
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// ## Exception Handler Overlap Detection
///
/// ```rust
/// # use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
/// # fn check_handler_overlap(handlers: &[ExceptionHandler]) -> Result<(), Box<dyn std::error::Error>> {
/// for (i, handler1) in handlers.iter().enumerate() {
///     for (j, handler2) in handlers.iter().enumerate() {
///         if i != j {
///             let h1_start = handler1.try_offset;
///             let h1_end = handler1.try_offset + handler1.try_length;
///             let h2_start = handler2.try_offset;
///             let h2_end = handler2.try_offset + handler2.try_length;
///             
///             // Check for nested or overlapping handlers
///             if h1_start < h2_end && h2_start < h1_end {
///                 println!("Overlapping handlers: [{}, {}) and [{}, {})",
///                     h1_start, h1_end, h2_start, h2_end);
///             }
///         }
///     }
/// }
/// # Ok(())
/// # }
/// ```
///
/// # Binary Format Compatibility
///
/// Exception handlers support both small (12-byte) and fat (24-byte) binary formats.
/// The format choice depends on the size of offsets and lengths in the method body.
/// This struct normalizes both formats to 32-bit fields for consistent processing.
///
/// # ECMA-335 References
///
/// - **Partition I, Section 12.4**: Exception handling model and semantics  
/// - **Partition II, Section 25.4.6**: Exception handling clause binary format
/// - **Partition III, Section 1.7.5**: Exception handling instruction behavior
///
/// # Thread Safety
///
/// `ExceptionHandler` instances are immutable and safe to share across threads.
/// The optional exception type reference uses a reference-counted smart pointer.
#[derive(Clone)]
pub struct ExceptionHandler {
    /// Exception handler type flags (EXCEPTION, FILTER, FINALLY, or FAULT).
    ///
    /// Determines the behavior and semantics of this exception handler. Each flag
    /// corresponds to a different exception handling strategy defined by ECMA-335.
    /// The flags are mutually exclusive - each handler has exactly one type.
    pub flags: ExceptionHandlerFlags,

    /// Byte offset of the protected try block from the start of the method body.
    ///
    /// This offset points to the first IL instruction that is protected by this
    /// exception handler. All instructions in the range [`try_offset`, `try_offset` + `try_length`)
    /// are covered by this handler and can potentially transfer control to the handler code.
    pub try_offset: u32,

    /// Length of the protected try block in bytes.
    ///
    /// Combined with `try_offset`, this defines the complete protected region.
    /// The protected region spans [`try_offset`, `try_offset` + `try_length`) and includes
    /// all IL instructions that may throw exceptions handled by this handler.
    pub try_length: u32,

    /// Byte offset of the exception handler code from the start of the method body.
    ///
    /// Points to the first IL instruction of the handler code (catch, finally, or fault block).
    /// For FILTER handlers, this points to the actual handler code, not the filter expression.
    /// The handler code spans [`handler_offset`, `handler_offset` + `handler_length`).
    pub handler_offset: u32,

    /// Length of the exception handler code in bytes.
    ///
    /// Defines the size of the handler code block. Combined with `handler_offset`,
    /// this specifies the complete range of IL instructions that comprise the
    /// exception handling logic for this handler.
    pub handler_length: u32,

    /// The exception type that this handler catches (for EXCEPTION handlers only).
    ///
    /// Contains a reference to the .NET type that this handler catches. For EXCEPTION
    /// handlers, this specifies the exact type and all derived types that will be
    /// caught. For other handler types (FILTER, FINALLY, FAULT), this field is None.
    ///
    /// # Type Matching
    ///
    /// Exception catching follows .NET's type system rules:
    /// - Exact type matches are caught
    /// - Derived types (subclasses) are caught  
    /// - Interface implementations are caught if the exception type is an interface
    /// - System.Object catches all exceptions
    pub handler: Option<CilTypeRc>,

    /// Byte offset of the filter expression code (for FILTER handlers only).
    ///
    /// For FILTER handlers, this points to the IL code that evaluates whether
    /// this handler should process the exception. The filter code must leave
    /// a boolean value on the evaluation stack. For non-FILTER handlers, this
    /// field may contain legacy data and should be ignored.
    ///
    /// # Filter Execution
    ///
    /// The filter expression:
    /// 1. Receives the exception object and execution context
    /// 2. Executes custom logic to test the exception
    /// 3. Returns true (1) to handle or false (0) to continue unwinding
    ///
    /// # Dual Purpose (ECMA-335 II.25.4.6)
    ///
    /// This field has different meanings depending on the handler type:
    /// - **FILTER handlers**: Contains the IL byte offset where the filter expression begins
    /// - **EXCEPTION handlers**: Initially contains the TypeDef/TypeRef/TypeSpec token for the
    ///   caught exception type (before resolution). After type resolution via
    ///   [`Method::parse()`][crate::metadata::method::Method::parse], this is cleared to 0
    ///   and the resolved type is stored in the [`handler`][Self::handler] field.
    /// - **FINALLY/FAULT handlers**: Should be 0 (unused)
    ///
    /// For type-safe access, use the [`get_filter_offset()`][Self::get_filter_offset] and
    /// [`get_class_token()`][Self::get_class_token] accessor methods.
    pub filter_offset: u32,
}

impl std::fmt::Debug for ExceptionHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExceptionHandler")
            .field("flags", &self.flags)
            .field("try_offset", &self.try_offset)
            .field("try_length", &self.try_length)
            .field("handler_offset", &self.handler_offset)
            .field("handler_length", &self.handler_length)
            .field("handler", &self.handler.as_ref().map(|t| t.token))
            .field("filter_offset", &self.filter_offset)
            .finish()
    }
}

impl ExceptionHandler {
    /// Returns the filter expression offset for FILTER handlers.
    ///
    /// For FILTER exception handlers, this returns the IL byte offset where the
    /// filter expression code begins. The filter expression evaluates whether
    /// this handler should process the current exception.
    ///
    /// # Returns
    ///
    /// - `Some(offset)` if this is a FILTER handler
    /// - `None` for all other handler types (EXCEPTION, FINALLY, FAULT)
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
    ///
    /// let handler = ExceptionHandler {
    ///     flags: ExceptionHandlerFlags::FILTER,
    ///     try_offset: 0,
    ///     try_length: 10,
    ///     handler_offset: 20,
    ///     handler_length: 5,
    ///     handler: None,
    ///     filter_offset: 15,
    /// };
    ///
    /// assert_eq!(handler.get_filter_offset(), Some(15));
    /// ```
    #[must_use]
    pub fn get_filter_offset(&self) -> Option<u32> {
        if self.flags.contains(ExceptionHandlerFlags::FILTER) {
            Some(self.filter_offset)
        } else {
            None
        }
    }

    /// Returns the class token for unresolved EXCEPTION handlers.
    ///
    /// For EXCEPTION (catch) handlers that have not yet been resolved, this returns
    /// the raw TypeDef/TypeRef/TypeSpec token that identifies the exception type
    /// to catch.
    ///
    /// # Returns
    ///
    /// - `Some(token)` if this is an EXCEPTION handler with a non-zero token
    ///   (i.e., before type resolution)
    /// - `None` if this is not an EXCEPTION handler, or if the type has already
    ///   been resolved (token cleared to 0)
    ///
    /// # Note
    ///
    /// After [`Method::parse()`][crate::metadata::method::Method::parse] is called,
    /// the class token is resolved to an actual type reference stored in the
    /// [`handler`][Self::handler] field, and this method will return `None`.
    /// Use the `handler` field to access the resolved type.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
    ///
    /// // Before type resolution
    /// let handler = ExceptionHandler {
    ///     flags: ExceptionHandlerFlags::EXCEPTION,
    ///     try_offset: 0,
    ///     try_length: 10,
    ///     handler_offset: 10,
    ///     handler_length: 5,
    ///     handler: None,
    ///     filter_offset: 0x01000001, // TypeRef token
    /// };
    ///
    /// assert_eq!(handler.get_class_token(), Some(0x01000001));
    /// ```
    #[must_use]
    pub fn get_class_token(&self) -> Option<u32> {
        // EXCEPTION is 0x0000, so we check that this is a catch handler and has a non-zero token
        if self.is_catch() && self.filter_offset != 0 {
            Some(self.filter_offset)
        } else {
            None
        }
    }

    /// Returns true if this handler catches a specific exception type.
    ///
    /// This is a convenience method to check if the handler is an EXCEPTION
    /// handler (catch block) as opposed to FILTER, FINALLY, or FAULT.
    ///
    /// Since `EXCEPTION = 0x0000`, this checks that none of the other handler
    /// type flags (FILTER, FINALLY, FAULT) are set.
    #[must_use]
    pub fn is_catch(&self) -> bool {
        // EXCEPTION is 0x0000, so we check that no other flags are set
        !self.flags.contains(ExceptionHandlerFlags::FILTER)
            && !self.flags.contains(ExceptionHandlerFlags::FINALLY)
            && !self.flags.contains(ExceptionHandlerFlags::FAULT)
    }

    /// Returns true if this handler is a finally block.
    #[must_use]
    pub fn is_finally(&self) -> bool {
        self.flags.contains(ExceptionHandlerFlags::FINALLY)
    }

    /// Returns true if this handler is a fault block.
    #[must_use]
    pub fn is_fault(&self) -> bool {
        self.flags.contains(ExceptionHandlerFlags::FAULT)
    }

    /// Returns true if this handler uses a filter expression.
    #[must_use]
    pub fn is_filter(&self) -> bool {
        self.flags.contains(ExceptionHandlerFlags::FILTER)
    }
}

/// How a method body's exception handling section was written, beyond the clauses it holds:
/// the section's format and its `DataSize` (ECMA-335 II.25.4.5).
///
/// Either format holds any clause the small one can, and the runtime reads the clause count
/// as `DataSize` divided by the clause size, so a `DataSize` that leaves out the section's
/// 4-byte header (as AsmResolver writes it) reads as the same clauses. Encoding with the
/// format a body was read with writes its section back as it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionSectionFormat {
    /// The fat format: 24-byte clauses and a 3-byte `DataSize`, where the small format has
    /// 12-byte clauses and a 1-byte one
    pub fat: bool,
    /// The section's `DataSize` as written
    pub data_size: u32,
}

/// Orders exception clauses as ECMA-335 II.19 requires: a nested clause before the clauses
/// that enclose it.
///
/// A clause is nested in another when its protected region lies inside the other's protected
/// or handler region. Clauses move only as far as that requires: an order that already
/// satisfies it, as a compiler's does, comes back unchanged, and the handlers of one protected
/// region stay in the order they are tried.
///
/// # Arguments
///
/// * `handlers` - The clauses, in any order.
///
/// # Returns
///
/// The same clauses, each after every clause nested in it.
#[must_use]
pub fn order_nested_first(handlers: Vec<ExceptionHandler>) -> Vec<ExceptionHandler> {
    let span = |offset: u32, length: u32| (offset, offset.saturating_add(length));
    let within = |inner: (u32, u32), outer: (u32, u32)| {
        outer.0 <= inner.0 && inner.1 <= outer.1 && inner != outer
    };
    let nested_in = |inner: &ExceptionHandler, outer: &ExceptionHandler| {
        let protected = span(inner.try_offset, inner.try_length);
        within(protected, span(outer.try_offset, outer.try_length))
            || within(protected, span(outer.handler_offset, outer.handler_length))
    };

    // Each clause waits for the clauses nested in it; of the clauses free to go, the first in
    // the given order goes next
    let count = handlers.len();
    let mut waiting_for = vec![0usize; count];
    let mut enclosing: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (inner, inner_clause) in handlers.iter().enumerate() {
        for (outer, outer_clause) in handlers.iter().enumerate() {
            if inner != outer && nested_in(inner_clause, outer_clause) {
                if let (Some(waits), Some(encloses)) =
                    (waiting_for.get_mut(outer), enclosing.get_mut(inner))
                {
                    *waits = waits.saturating_add(1);
                    encloses.push(outer);
                }
            }
        }
    }
    let mut free: BTreeSet<usize> = (0..count)
        .filter(|&index| waiting_for.get(index) == Some(&0))
        .collect();
    let mut order = Vec::with_capacity(count);
    while let Some(next) = free.pop_first() {
        order.push(next);
        for &outer in enclosing.get(next).map(Vec::as_slice).unwrap_or_default() {
            if let Some(waits) = waiting_for.get_mut(outer) {
                *waits = waits.saturating_sub(1);
                if *waits == 0 {
                    free.insert(outer);
                }
            }
        }
    }

    let mut slots: Vec<Option<ExceptionHandler>> = handlers.into_iter().map(Some).collect();
    let mut ordered: Vec<ExceptionHandler> = order
        .into_iter()
        .filter_map(|index| slots.get_mut(index).and_then(Option::take))
        .collect();
    // Containment is a strict order, so every clause is placed; any left would keep its place
    ordered.extend(slots.into_iter().flatten());
    ordered
}

/// Encodes exception handlers as a method body's exception handling section (ECMA-335
/// II.25.4.5-6), padded to 4 bytes; empty when there are none.
///
/// With `format`, the section has that format if it can hold the clauses, and its
/// `DataSize` when that still states as many clauses; otherwise, and without `format`, the
/// small format when it can hold them and a `DataSize` that counts the section header.
///
/// A catch clause's class token is its resolved type's token, or its raw `filter_offset`
/// field when unresolved; a filter's is its filter offset; and a finally or fault clause
/// writes its raw field back.
///
/// # Errors
///
/// When a clause cannot be encoded: more clauses than a fat section's 24-bit `DataSize`
/// states.
///
/// # Examples
///
/// ```rust
/// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags, encode_exception_handlers};
///
/// let handlers = vec![ExceptionHandler {
///     flags: ExceptionHandlerFlags::FINALLY,
///     try_offset: 0,
///     try_length: 10,
///     handler_offset: 10,
///     handler_length: 5,
///     handler: None,
///     filter_offset: 0,
/// }];
///
/// let section = encode_exception_handlers(&handlers, None)?;
/// assert_eq!(&section[..4], &[0x01, 0x10, 0x00, 0x00]); // small EH table, 16 bytes
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn encode_exception_handlers(
    handlers: &[ExceptionHandler],
    format: Option<ExceptionSectionFormat>,
) -> Result<Vec<u8>> {
    if handlers.is_empty() {
        return Ok(Vec::new());
    }

    // The small format holds 16-bit offsets, 8-bit lengths, and as many clauses as its 1-byte
    // DataSize can state after the 4-byte header: (0xFF - 4) / 12 = 20.
    const SMALL_FORMAT_MAX_CLAUSES: usize = (0xFF - 4) / 12;
    let small_fits = handlers.len() <= SMALL_FORMAT_MAX_CLAUSES
        && handlers.iter().all(|eh| {
            eh.try_offset <= 0xFFFF
                && eh.try_length <= 0xFF
                && eh.handler_offset <= 0xFFFF
                && eh.handler_length <= 0xFF
        });
    let fat = !small_fits || format.is_some_and(|format| format.fat);
    let clause_size: usize = if fat { 24 } else { 12 };
    let data_size = format
        .filter(|format| format.fat == fat)
        .map(|format| format.data_size)
        .filter(|size| (*size as usize).checked_div(clause_size) == Some(handlers.len()))
        .map_or_else(
            || {
                handlers
                    .len()
                    .checked_mul(clause_size)
                    .and_then(|size| size.checked_add(4))
                    .and_then(|size| u32::try_from(size).ok())
                    .filter(|size| *size <= 0x00FF_FFFF)
                    .ok_or_else(|| {
                        malformed_error!(
                            "{} exception handlers exceed a section's DataSize",
                            handlers.len()
                        )
                    })
            },
            Ok,
        )?;

    let mut section =
        Vec::with_capacity(handlers.len().saturating_mul(clause_size).saturating_add(4));
    if fat {
        section.push(0x41); // Kind = EHTable | FatFormat
        section.extend_from_slice(&data_size.to_le_bytes()[..3]);
    } else {
        // Small: Kind = EHTable, a 1-byte DataSize and two reserved bytes
        let data_size = u8::try_from(data_size).map_err(|_| {
            malformed_error!(
                "Small exception section DataSize {} exceeds a byte",
                data_size
            )
        })?;
        section.extend_from_slice(&[0x01, data_size, 0x00, 0x00]);
    }

    for eh in handlers {
        // ClassToken or FilterOffset
        let token_or_offset = match &eh.handler {
            Some(handler_type) if !eh.flags.contains(ExceptionHandlerFlags::FILTER) => {
                handler_type.token.value()
            }
            _ => eh.filter_offset,
        };
        if fat {
            section.extend_from_slice(&u32::from(eh.flags.bits()).to_le_bytes());
            section.extend_from_slice(&eh.try_offset.to_le_bytes());
            section.extend_from_slice(&eh.try_length.to_le_bytes());
            section.extend_from_slice(&eh.handler_offset.to_le_bytes());
            section.extend_from_slice(&eh.handler_length.to_le_bytes());
        } else {
            let narrow = |value: u32, bits: u32| {
                if value >> bits == 0 {
                    Ok(value)
                } else {
                    Err(malformed_error!(
                        "Exception handler field {} exceeds the small format",
                        value
                    ))
                }
            };
            section.extend_from_slice(&eh.flags.bits().to_le_bytes());
            section.extend_from_slice(&narrow(eh.try_offset, 16)?.to_le_bytes()[..2]);
            section.push(narrow(eh.try_length, 8)?.to_le_bytes()[0]);
            section.extend_from_slice(&narrow(eh.handler_offset, 16)?.to_le_bytes()[..2]);
            section.push(narrow(eh.handler_length, 8)?.to_le_bytes()[0]);
        }
        section.extend_from_slice(&token_or_offset.to_le_bytes());
    }

    // Align to 4-byte boundary
    while !section.len().is_multiple_of(4) {
        section.push(0);
    }

    Ok(section)
}

/// What a range an exception clause names is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    /// A protected (`try`) range.
    Try,
    /// A catch handler.
    Catch,
    /// A finally or fault handler, which `endfinally` ends.
    Finally,
    /// A filter, which `endfilter` ends.
    Filter,
}

/// One range an exception clause names: `start..end` in IL offsets.
#[derive(Debug, Clone, Copy)]
struct Block {
    start: u64,
    end: u64,
    kind: BlockKind,
    clause: usize,
}

impl Block {
    fn contains(self, offset: u64) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Whether control enters the block only by an exception: a handler or a filter.
    fn entered_by_exception(self) -> bool {
        self.kind != BlockKind::Try
    }

    fn describe(self) -> String {
        let kind = match self.kind {
            BlockKind::Try => "try",
            BlockKind::Catch => "catch handler",
            BlockKind::Finally => "finally or fault handler",
            BlockKind::Filter => "filter",
        };
        format!(
            "{kind} {:#x}..{:#x} of clause {}",
            self.start, self.end, self.clause
        )
    }
}

/// The defects in how a method body's exception clauses structure its code (ECMA-335
/// Partition I, 12.4.2.5-8, and Partition II, 19), each stated with the offsets it is at.
///
/// - No clause boundary falls inside an instruction, and every branch target is one's start.
/// - Clause ranges nest or are disjoint; several clauses may protect the same `try`, but a
///   clause's handler or filter does not overlap its own `try`.
/// - A handler or filter is entered only by an exception: no branch or fall-through from
///   outside lands in one, and a `try` is entered only at its first instruction.
/// - A range is left only by `leave`, `throw`, `rethrow`, `endfinally` or `endfilter`: no
///   branch or fall-through crosses its end, no `ret` is inside one, and a `leave` does not
///   leave a filter, finally or fault handler.
/// - `endfinally` is only in a finally or fault handler, and `endfilter` only ends a filter.
///
/// The stack is not checked: a call's effect on it is its signature's, which the
/// instructions do not state.
///
/// # Arguments
///
/// * `instructions` - The method's instructions, decoded; the one at the lowest RVA starts
///   the code, and an instruction's IL offset is its RVA less that one's
/// * `handlers` - Its exception clauses
#[must_use]
pub fn exception_structure_defects(
    instructions: &[Instruction],
    handlers: &[ExceptionHandler],
) -> Vec<String> {
    let mut defects = Vec::new();
    let mut blocks: Vec<Block> = Vec::new();
    for (clause, handler) in handlers.iter().enumerate() {
        let range = |start: u32, length: u32| {
            (
                u64::from(start),
                u64::from(start).saturating_add(u64::from(length)),
            )
        };
        let (start, end) = range(handler.try_offset, handler.try_length);
        blocks.push(Block {
            start,
            end,
            kind: BlockKind::Try,
            clause,
        });
        let (start, end) = range(handler.handler_offset, handler.handler_length);
        let kind = if handler.flags.contains(ExceptionHandlerFlags::FINALLY)
            || handler.flags.contains(ExceptionHandlerFlags::FAULT)
        {
            BlockKind::Finally
        } else {
            BlockKind::Catch
        };
        blocks.push(Block {
            start,
            end,
            kind,
            clause,
        });
        if handler.flags.contains(ExceptionHandlerFlags::FILTER) {
            blocks.push(Block {
                start: u64::from(handler.filter_offset),
                end: u64::from(handler.handler_offset),
                kind: BlockKind::Filter,
                clause,
            });
        }
    }
    if blocks.is_empty() {
        return defects;
    }

    let base = instructions
        .iter()
        .map(|instruction| instruction.rva)
        .min()
        .unwrap_or_default();
    let offset_of = |rva: u64| rva.saturating_sub(base);
    let code_end = instructions
        .iter()
        .map(|instruction| offset_of(instruction.rva).saturating_add(instruction.size))
        .max()
        .unwrap_or_default();
    let boundaries: HashSet<u64> = instructions
        .iter()
        .map(|instruction| offset_of(instruction.rva))
        .chain([code_end])
        .collect();

    // Clause boundaries are instruction boundaries. Code no path reaches need not be decoded,
    // so a boundary there is only wrong inside an instruction that is.
    for block in &blocks {
        for at in [block.start, block.end] {
            if let Some(instruction) = instructions.iter().find(|instruction| {
                let start = offset_of(instruction.rva);
                start < at && at < start.saturating_add(instruction.size)
            }) {
                defects.push(format!(
                    "{} has a boundary at {at:#x}, inside {} at {:#x}",
                    block.describe(),
                    instruction.mnemonic,
                    offset_of(instruction.rva)
                ));
            }
        }
    }

    // Ranges nest or are disjoint; a clause's handler and filter lie outside its try
    for (index, one) in blocks.iter().enumerate() {
        for other in blocks.iter().skip(index.saturating_add(1)) {
            let overlap = one.start < other.end && other.start < one.end;
            if !overlap {
                continue;
            }
            let same = one.start == other.start && one.end == other.end;
            let nested = (one.start <= other.start && other.end <= one.end)
                || (other.start <= one.start && one.end <= other.end);
            let own_try = one.clause == other.clause
                && (one.kind == BlockKind::Try || other.kind == BlockKind::Try);
            if own_try {
                defects.push(format!("{} overlaps {}", one.describe(), other.describe()));
            } else if same {
                if one.kind != BlockKind::Try || other.kind != BlockKind::Try {
                    defects.push(format!("{} is also {}", one.describe(), other.describe()));
                }
            } else if !nested {
                defects.push(format!(
                    "{} and {} overlap without nesting",
                    one.describe(),
                    other.describe()
                ));
            }
        }
    }

    // The innermost range around an offset
    let innermost = |offset: u64| {
        blocks
            .iter()
            .filter(|block| block.contains(offset))
            .min_by_key(|block| block.end.saturating_sub(block.start))
            .copied()
    };

    for instruction in instructions {
        let from = offset_of(instruction.rva);
        let next = from.saturating_add(instruction.size);
        let mnemonic = instruction.mnemonic;

        match mnemonic {
            "endfinally" if innermost(from).map(|block| block.kind) != Some(BlockKind::Finally) => {
                defects.push(format!(
                    "endfinally at {from:#x} is outside a finally or fault handler"
                ));
            }
            "endfilter"
                if !innermost(from)
                    .is_some_and(|block| block.kind == BlockKind::Filter && block.end == next) =>
            {
                defects.push(format!("endfilter at {from:#x} does not end a filter"));
            }
            _ => {}
        }

        if instruction.flow_type == FlowType::Return {
            if let Some(block) = blocks.iter().find(|block| block.contains(from)) {
                defects.push(format!("ret at {from:#x} inside {}", block.describe()));
            }
            continue;
        }

        let leaves = instruction.flow_type == FlowType::Leave;
        let falls_through = matches!(
            instruction.flow_type,
            FlowType::Sequential | FlowType::Call | FlowType::ConditionalBranch | FlowType::Switch
        );
        let mut successors: Vec<u64> = instruction
            .branch_targets
            .iter()
            .map(|target| offset_of(*target))
            .collect();
        for target in &successors {
            if !boundaries.contains(target) || *target >= code_end {
                defects.push(format!(
                    "{mnemonic} at {from:#x} branches to {target:#x}, which no instruction starts"
                ));
            }
        }
        if falls_through && next < code_end {
            successors.push(next);
        }

        for target in successors {
            for block in &blocks {
                let (inside_from, inside_to) = (block.contains(from), block.contains(target));
                if !inside_from && inside_to {
                    if block.entered_by_exception() {
                        defects.push(format!(
                            "{mnemonic} at {from:#x} enters {} at {target:#x}",
                            block.describe()
                        ));
                    } else if target != block.start {
                        defects.push(format!(
                            "{mnemonic} at {from:#x} enters {} at {target:#x}, not its start",
                            block.describe()
                        ));
                    }
                }
                if inside_from && !inside_to {
                    if !leaves {
                        defects.push(format!(
                            "{mnemonic} at {from:#x} leaves {} for {target:#x} without leave",
                            block.describe()
                        ));
                    } else if block.entered_by_exception() && block.kind != BlockKind::Catch {
                        defects.push(format!(
                            "leave at {from:#x} leaves {} for {target:#x}",
                            block.describe()
                        ));
                    }
                }
            }
        }
    }
    defects
}

/// Checks that control enters and leaves every protected range the way ECMA-335 allows, and
/// that the clauses structure the code as it requires: the first of
/// [`exception_structure_defects`], as an error.
///
/// Clause ranges that are merely in bounds can still break these rules - a region that
/// covers code the method falls into from outside is in bounds and invalid - and the
/// runtime rejects such a body when it is first called.
///
/// # Arguments
///
/// * `instructions` - The method body, decoded.
/// * `handlers` - Its exception clauses.
///
/// # Errors
///
/// Returns an error naming the first defect.
pub fn validate_protected_region_flow(
    instructions: &[Instruction],
    handlers: &[ExceptionHandler],
) -> Result<()> {
    match exception_structure_defects(instructions, handlers)
        .into_iter()
        .next()
    {
        Some(defect) => Err(Error::CodegenFailed(defect)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assembly::{decode_stream, InstructionAssembler},
        Parser,
    };

    /// `try { nop; leave end } finally { endfinally } end: nop; ret`, decoded,
    /// with its clause.
    fn try_finally_body() -> (Vec<Instruction>, Vec<ExceptionHandler>) {
        let mut asm = InstructionAssembler::new();
        asm.try_start("t")
            .unwrap()
            .nop()
            .unwrap()
            .leave_s("end")
            .unwrap()
            .try_end("t")
            .unwrap()
            .finally_start("t")
            .unwrap()
            .endfinally()
            .unwrap()
            .finally_end("t")
            .unwrap()
            .label("end")
            .unwrap()
            .nop()
            .unwrap()
            .ret()
            .unwrap();
        let (bytecode, _, handlers) = asm.finish().unwrap();
        let instructions = decode_stream(&mut Parser::new(&bytecode), 0).unwrap();
        (instructions, handlers)
    }

    #[test]
    fn a_well_formed_try_finally_passes_the_flow_check() {
        let (instructions, handlers) = try_finally_body();
        assert!(validate_protected_region_flow(&instructions, &handlers).is_ok());
    }

    #[test]
    fn a_handler_range_covering_code_reached_by_normal_flow_is_rejected() {
        // Stretch the finally over the `nop` after it: that `nop` is where the
        // leave lands, so normal flow would enter the handler.
        let (instructions, mut handlers) = try_finally_body();
        handlers[0].handler_length += 1;
        let err = validate_protected_region_flow(&instructions, &handlers)
            .expect_err("a leave into a handler range is invalid");
        assert!(
            format!("{err}").contains("enters finally or fault handler"),
            "{err}"
        );
    }

    #[test]
    fn test_encode_exception_handlers_empty() {
        let handlers = vec![];
        let result = encode_exception_handlers(&handlers, None).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_encode_exception_handlers_small_format() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        }];

        let result = encode_exception_handlers(&handlers, None).unwrap();

        // Should use small format: 4-byte header + 12 bytes per handler = 16 bytes
        assert_eq!(result.len(), 16);

        // First byte should be 0x01 (EHTable, small format)
        assert_eq!(result[0], 0x01);

        // Second byte should be section size (16)
        assert_eq!(result[1], 16);
    }

    #[test]
    fn test_encode_exception_handlers_fat_format() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0x10000, // Forces fat format (> 16 bits)
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        }];

        let result = encode_exception_handlers(&handlers, None).unwrap();

        // Should use fat format: 4-byte header + 24 bytes per handler = 28 bytes,
        // already 4-byte aligned.
        assert_eq!(result.len(), 28);

        // First byte should be 0x41 (EHTable | FatFormat)
        assert_eq!(result[0], 0x41);

        // DataSize (bytes 1..4, little-endian) must equal the section size (28),
        // and must be readable directly after the single Kind byte.
        let data_size = u32::from_le_bytes([result[1], result[2], result[3], 0]);
        assert_eq!(data_size, 28);
    }

    #[test]
    fn test_encode_exception_handlers_filter() {
        let handlers = vec![ExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 15,
        }];

        let result = encode_exception_handlers(&handlers, None).unwrap();

        // Should successfully encode filter handler
        assert_eq!(result.len(), 16); // Small format
        assert_eq!(result[0], 0x01); // Small format flag
    }

    // Tests for ExceptionHandler accessor methods (MTH-L008)

    #[test]
    fn test_exception_handler_get_filter_offset() {
        // FILTER handler should return Some
        let filter_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 15,
        };
        assert_eq!(filter_handler.get_filter_offset(), Some(15));

        // Non-FILTER handlers should return None
        let finally_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        };
        assert_eq!(finally_handler.get_filter_offset(), None);

        let exception_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0x01000001, // Type token
        };
        assert_eq!(exception_handler.get_filter_offset(), None);
    }

    #[test]
    fn test_exception_handler_get_class_token() {
        // EXCEPTION handler with non-zero token should return Some
        let unresolved_catch = ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0x01000001, // TypeRef token
        };
        assert_eq!(unresolved_catch.get_class_token(), Some(0x01000001));

        // EXCEPTION handler with zero token (resolved) should return None
        let resolved_catch = ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None, // Would have resolved type in real scenario
            filter_offset: 0,
        };
        assert_eq!(resolved_catch.get_class_token(), None);

        // Non-EXCEPTION handlers should return None
        let filter_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 15,
        };
        assert_eq!(filter_handler.get_class_token(), None);
    }

    #[test]
    fn test_exception_handler_type_checks() {
        let catch_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        };
        assert!(catch_handler.is_catch());
        assert!(!catch_handler.is_finally());
        assert!(!catch_handler.is_fault());
        assert!(!catch_handler.is_filter());

        let finally_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        };
        assert!(!finally_handler.is_catch());
        assert!(finally_handler.is_finally());
        assert!(!finally_handler.is_fault());
        assert!(!finally_handler.is_filter());

        let fault_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FAULT,
            try_offset: 0,
            try_length: 10,
            handler_offset: 10,
            handler_length: 5,
            handler: None,
            filter_offset: 0,
        };
        assert!(!fault_handler.is_catch());
        assert!(!fault_handler.is_finally());
        assert!(fault_handler.is_fault());
        assert!(!fault_handler.is_filter());

        let filter_handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_offset: 0,
            try_length: 10,
            handler_offset: 20,
            handler_length: 5,
            handler: None,
            filter_offset: 15,
        };
        assert!(!filter_handler.is_catch());
        assert!(!filter_handler.is_finally());
        assert!(!filter_handler.is_fault());
        assert!(filter_handler.is_filter());
    }

    #[test]
    fn test_exception_handler_flags_kind() {
        assert_eq!(
            ExceptionHandlerFlags::EXCEPTION.kind(),
            ExceptionHandlerKind::Catch
        );
        assert_eq!(
            ExceptionHandlerFlags::FILTER.kind(),
            ExceptionHandlerKind::Filter
        );
        assert_eq!(
            ExceptionHandlerFlags::FINALLY.kind(),
            ExceptionHandlerKind::Finally
        );
        assert_eq!(
            ExceptionHandlerFlags::FAULT.kind(),
            ExceptionHandlerKind::Fault
        );
    }

    #[test]
    fn test_exception_handler_kind_stable_strings() {
        // The strings here are part of the stable public API. Changing them is
        // a breaking change for downstream consumers that persist these values.
        assert_eq!(ExceptionHandlerKind::Catch.as_str(), "catch");
        assert_eq!(ExceptionHandlerKind::Filter.as_str(), "filter");
        assert_eq!(ExceptionHandlerKind::Finally.as_str(), "finally");
        assert_eq!(ExceptionHandlerKind::Fault.as_str(), "fault");

        assert_eq!(format!("{}", ExceptionHandlerKind::Catch), "catch");
        assert_eq!(format!("{}", ExceptionHandlerKind::Filter), "filter");
        assert_eq!(format!("{}", ExceptionHandlerKind::Finally), "finally");
        assert_eq!(format!("{}", ExceptionHandlerKind::Fault), "fault");
    }

    /// A clause over `code` decoded from offset 0.
    fn clause(
        flags: ExceptionHandlerFlags,
        try_range: (u32, u32),
        handler_range: (u32, u32),
        filter_offset: u32,
    ) -> ExceptionHandler {
        ExceptionHandler {
            flags,
            try_offset: try_range.0,
            try_length: try_range.1 - try_range.0,
            handler_offset: handler_range.0,
            handler_length: handler_range.1 - handler_range.0,
            filter_offset,
            handler: None,
        }
    }

    fn defects(code: &[u8], clauses: &[ExceptionHandler]) -> Vec<String> {
        let instructions = decode_stream(&mut Parser::new(code), 0).unwrap();
        exception_structure_defects(&instructions, clauses)
    }

    /// `try { nop; leave 6 } catch { pop; leave 6 } 6: ret`: the valid shape the rules below
    /// break, with the try at 0..3 and the catch at 3..6.
    const TRY_CATCH: [u8; 7] = [0x00, 0xDE, 0x03, 0x26, 0xDE, 0x00, 0x2A];

    #[test]
    fn a_valid_try_catch_has_no_defects() {
        let catch = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 6),
            0x0100_0001,
        );
        assert_eq!(defects(&TRY_CATCH, &[catch]), Vec::<String>::new());
    }

    #[test]
    fn ranges_that_overlap_without_nesting_are_defects() {
        // A second clause whose try straddles the first's try and handler
        let first = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 6),
            0x0100_0001,
        );
        let straddling = clause(ExceptionHandlerFlags::FAULT, (1, 4), (4, 6), 0);
        let found = defects(&TRY_CATCH, &[first, straddling]);
        assert!(
            found.iter().any(|d| d.contains("overlap without nesting")),
            "{found:?}"
        );

        // A handler inside its own try
        let own = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 6),
            (3, 6),
            0x0100_0001,
        );
        assert!(defects(&TRY_CATCH, &[own])
            .iter()
            .any(|d| d.contains("overlaps")));

        // Two clauses with one handler range
        let one = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 6),
            0x0100_0001,
        );
        let shared = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 6),
            0x0100_0002,
        );
        assert!(defects(&TRY_CATCH, &[one, shared])
            .iter()
            .any(|d| d.contains("is also")));
    }

    #[test]
    fn several_clauses_may_protect_one_try() {
        // try { nop; leave } catch { pop; leave } catch { pop; leave } ret
        let code = [0x00, 0xDE, 0x06, 0x26, 0xDE, 0x03, 0x26, 0xDE, 0x00, 0x2A];
        let first = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 6),
            0x0100_0001,
        );
        let second = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (6, 9),
            0x0100_0002,
        );
        assert_eq!(defects(&code, &[first, second]), Vec::<String>::new());
    }

    #[test]
    fn endfinally_outside_a_finally_and_endfilter_not_ending_a_filter_are_defects() {
        // endfinally in a catch handler
        let code = [0x00, 0xDE, 0x01, 0xDC, 0x2A];
        let catch = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 3),
            (3, 4),
            0x0100_0001,
        );
        assert!(defects(&code, &[catch])
            .iter()
            .any(|d| d.contains("endfinally at 0x3")));

        // endfilter in the middle of a filter: filter 3..7 is endfilter, nop, ...
        let code = [0x00, 0xDE, 0x06, 0xFE, 0x11, 0x00, 0x26, 0xDE, 0x00, 0x2A];
        let filter = clause(ExceptionHandlerFlags::FILTER, (0, 3), (6, 9), 3);
        assert!(defects(&code, &[filter])
            .iter()
            .any(|d| d.contains("endfilter at 0x3 does not end a filter")));
    }

    #[test]
    fn a_leave_out_of_a_finally_is_a_defect() {
        // try { nop; leave 6 } finally { leave 6 } 6: ret
        let code = [0x00, 0xDE, 0x03, 0xDE, 0x01, 0xDC, 0x2A];
        let finally = clause(ExceptionHandlerFlags::FINALLY, (0, 3), (3, 6), 0);
        assert!(defects(&code, &[finally])
            .iter()
            .any(|d| d.contains("leave at 0x3 leaves finally")));
    }

    #[test]
    fn a_boundary_or_branch_inside_an_instruction_is_a_defect() {
        // A try ending inside the leave
        let catch = clause(
            ExceptionHandlerFlags::EXCEPTION,
            (0, 2),
            (3, 6),
            0x0100_0001,
        );
        assert!(defects(&TRY_CATCH, &[catch])
            .iter()
            .any(|d| d.contains("boundary at 0x2, inside leave.s")));

        // br.s into the middle of a ldc.i4 (offset 3 of 2..7)
        let code = [0x2B, 0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x2A];
        let instructions = decode_stream(&mut Parser::new(&code[..2]), 0)
            .unwrap()
            .into_iter()
            .chain(decode_stream(&mut Parser::new(&code[2..]), 2).unwrap())
            .collect::<Vec<_>>();
        let fault = clause(ExceptionHandlerFlags::FAULT, (2, 7), (7, 8), 0);
        let found = exception_structure_defects(&instructions, &[fault]);
        assert!(
            found
                .iter()
                .any(|d| d.contains("which no instruction starts")),
            "{found:?}"
        );
    }

    /// A finally clause `(try offset, try length, handler offset, handler length)`.
    fn finally(
        try_offset: u32,
        try_length: u32,
        handler: u32,
        handler_length: u32,
    ) -> ExceptionHandler {
        ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset,
            try_length,
            handler_offset: handler,
            handler_length,
            handler: None,
            filter_offset: 0,
        }
    }

    fn spans(clauses: &[ExceptionHandler]) -> Vec<(u32, u32)> {
        clauses
            .iter()
            .map(|c| (c.try_offset, c.try_length))
            .collect()
    }

    /// An order that already puts every nested clause first comes back unchanged: Roslyn's
    /// clauses of WindowsBase's `Dispose`, which nest at different depths, came back reordered
    /// by depth, valid but not what the method holds.
    #[test]
    fn a_valid_order_comes_back_unchanged() {
        let clauses = vec![
            finally(246, 23, 269, 8),
            finally(199, 40, 239, 39),
            finally(152, 40, 192, 87),
            finally(30, 25, 55, 14),
            finally(76, 69, 145, 135),
            finally(4, 65, 69, 212),
        ];
        assert_eq!(spans(&order_nested_first(clauses.clone())), spans(&clauses));
    }

    /// A clause listed before one nested in it moves after it, by protected and by handler
    /// region; the clauses of one protected region keep their order.
    #[test]
    fn an_enclosing_clause_moves_after_the_clauses_nested_in_it() {
        let outer = finally(0, 10, 10, 30);
        let in_handler = finally(12, 20, 32, 4);
        let in_try = finally(2, 4, 6, 2);
        let ordered = order_nested_first(vec![outer.clone(), in_handler.clone(), in_try.clone()]);
        assert_eq!(spans(&ordered), spans(&[in_handler, in_try, outer]));

        let first = finally(0, 4, 4, 2);
        let second = finally(0, 4, 6, 2);
        let same_try = order_nested_first(vec![first.clone(), second.clone()]);
        assert_eq!(
            same_try
                .iter()
                .map(|c| c.handler_offset)
                .collect::<Vec<_>>(),
            [first.handler_offset, second.handler_offset]
        );
    }
}
