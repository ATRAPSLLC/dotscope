//! Method body builder for creating CIL method implementations.
//!
//! This module provides [`MethodBodyBuilder`] for creating method body implementations
//! with automatic stack management, local variables, and exception handling support.
//! It integrates the existing [`crate::assembly::InstructionAssembler`] with ECMA-335
//! method body format encoding.

use std::collections::HashMap;

use crate::{
    assembly::{decode_stream, InstructionAssembler},
    cilassembly::CilAssembly,
    file::parser::Parser,
    metadata::{
        method::{
            encode_exception_handlers, encode_method_body_header, order_nested_first,
            ExceptionHandler, ExceptionHandlerFlags,
        },
        signatures::{
            encode_local_var_signature, SignatureLocalVariable, SignatureLocalVariables,
            TypeSignature,
        },
        tables::StandAloneSigBuilder,
        token::Token,
        typesystem::CilTypeRc,
    },
    Error, Result,
};

/// Exception handler defined with labels for automatic offset calculation.
#[derive(Clone)]
struct LabeledExceptionHandler {
    /// Exception handler flags (finally, catch, fault, filter)
    flags: ExceptionHandlerFlags,
    /// Label marking the start of the protected try block
    try_start_label: String,
    /// Label marking the end of the protected try block
    try_end_label: String,
    /// Label marking the start of the handler block
    handler_start_label: String,
    /// Label marking the end of the handler block
    handler_end_label: String,
    /// The exception type for typed handlers
    handler_type: Option<CilTypeRc>,
    /// Label marking the start of the filter expression (for FILTER handlers only)
    filter_start_label: Option<String>,
}

/// Type alias for method body implementation closures
type ImplementationFn = Box<dyn FnOnce(&mut InstructionAssembler) -> Result<()>>;

/// Resolve a labeled exception handler to a regular exception handler with calculated byte offsets.
///
/// This function takes the final label offsets of an assembled body and a labeled exception
/// handler, and converts it to a regular exception handler by looking up the label positions
/// and calculating the byte offsets and lengths. The offsets are the finalized ones: finalizing
/// shortens branches, which moves the code after them.
///
/// # Parameters
///
/// * `labels` - Every label's final offset, from [`InstructionAssembler::finish_with_labels`]
/// * `labeled_handler` - The labeled exception handler to resolve
///
/// # Returns
///
/// A regular [`ExceptionHandler`] with calculated byte offsets.
///
/// # Errors
///
/// Returns an error if any of the referenced labels are not defined in the assembler.
fn resolve_labeled_exception_handler(
    labels: &HashMap<String, u32>,
    labeled_handler: &LabeledExceptionHandler,
) -> Result<ExceptionHandler> {
    let position = |label: &str| labels.get(label).copied();
    // Look up all label positions
    let try_start_offset = position(&labeled_handler.try_start_label)
        .ok_or_else(|| Error::UndefinedLabel(labeled_handler.try_start_label.clone()))?;

    let try_end_offset = position(&labeled_handler.try_end_label)
        .ok_or_else(|| Error::UndefinedLabel(labeled_handler.try_end_label.clone()))?;

    let handler_start_offset = position(&labeled_handler.handler_start_label)
        .ok_or_else(|| Error::UndefinedLabel(labeled_handler.handler_start_label.clone()))?;

    let handler_end_offset = position(&labeled_handler.handler_end_label)
        .ok_or_else(|| Error::UndefinedLabel(labeled_handler.handler_end_label.clone()))?;

    // Calculate lengths
    if try_end_offset < try_start_offset {
        return Err(Error::ModificationInvalid(format!(
            "Try end label '{}' (at {}) is before try start label '{}' (at {})",
            labeled_handler.try_end_label,
            try_end_offset,
            labeled_handler.try_start_label,
            try_start_offset
        )));
    }

    if handler_end_offset < handler_start_offset {
        return Err(Error::ModificationInvalid(format!(
            "Handler end label '{}' (at {}) is before handler start label '{}' (at {})",
            labeled_handler.handler_end_label,
            handler_end_offset,
            labeled_handler.handler_start_label,
            handler_start_offset
        )));
    }

    let try_length = try_end_offset
        .checked_sub(try_start_offset)
        .ok_or_else(|| Error::ModificationInvalid("try region length underflow".into()))?;
    let handler_length = handler_end_offset
        .checked_sub(handler_start_offset)
        .ok_or_else(|| Error::ModificationInvalid("handler region length underflow".into()))?;

    // Resolve filter offset for FILTER handlers
    let filter_offset = if let Some(filter_label) = &labeled_handler.filter_start_label {
        position(filter_label).ok_or_else(|| Error::UndefinedLabel(filter_label.clone()))?
    } else {
        0
    };

    // Create the regular exception handler
    Ok(ExceptionHandler {
        flags: labeled_handler.flags,
        try_offset: try_start_offset,
        try_length,
        handler_offset: handler_start_offset,
        handler_length,
        handler: labeled_handler.handler_type.clone(),
        filter_offset,
    })
}

/// Validates exception handler ranges against the method body code size.
///
/// This function ensures that all exception handlers have valid byte ranges that fit
/// within the method body according to ECMA-335 requirements:
///
/// 1. Try block range must be within the code: `try_offset + try_length <= code_size`
/// 2. Handler block range must be within the code: `handler_offset + handler_length <= code_size`
/// 3. For FILTER handlers: `filter_offset < code_size` (filter must start within code)
///
/// # Parameters
///
/// * `handlers` - The exception handlers to validate
/// * `code_size` - The total size of the method body IL code in bytes
///
/// # Returns
///
/// `Ok(())` if all handlers have valid ranges.
///
/// # Errors
///
/// Returns an error if any handler has an invalid range that would exceed the code size.
fn validate_exception_handler_ranges(handlers: &[ExceptionHandler], code_size: u32) -> Result<()> {
    for (index, handler) in handlers.iter().enumerate() {
        // Validate try block range
        let try_end = handler
            .try_offset
            .checked_add(handler.try_length)
            .ok_or_else(|| {
                Error::ModificationInvalid(format!(
                    "Exception handler {}: try block range overflow (offset {} + length {})",
                    index, handler.try_offset, handler.try_length
                ))
            })?;

        if try_end > code_size {
            return Err(Error::ModificationInvalid(format!(
                "Exception handler {}: try block exceeds code size (offset {} + length {} = {}, code size = {})",
                index, handler.try_offset, handler.try_length, try_end, code_size
            )));
        }

        // Validate handler block range
        let handler_end = handler
            .handler_offset
            .checked_add(handler.handler_length)
            .ok_or_else(|| {
                Error::ModificationInvalid(format!(
                    "Exception handler {}: handler block range overflow (offset {} + length {})",
                    index, handler.handler_offset, handler.handler_length
                ))
            })?;

        if handler_end > code_size {
            return Err(Error::ModificationInvalid(format!(
                "Exception handler {}: handler block exceeds code size (offset {} + length {} = {}, code size = {})",
                index, handler.handler_offset, handler.handler_length, handler_end, code_size
            )));
        }

        // Validate filter offset for FILTER handlers
        if handler.flags.contains(ExceptionHandlerFlags::FILTER)
            && handler.filter_offset >= code_size
        {
            return Err(Error::ModificationInvalid(format!(
                "Exception handler {}: filter offset {} exceeds code size {}",
                index, handler.filter_offset, code_size
            )));
        }
    }

    Ok(())
}

/// Builder for creating method body implementations.
///
/// `MethodBodyBuilder` focuses specifically on creating method body bytes according
/// to the ECMA-335 specification (II.25.4.5). It wraps the existing
/// [`crate::assembly::InstructionAssembler`] and adds:
///
/// - Precise stack depth calculation using real-time instruction analysis
/// - Local variable management with automatic signature generation
/// - Method body format encoding (tiny vs fat) based on actual requirements
/// - Exception handler support
///
/// # Examples
///
/// ## Simple Method Body
///
/// ```rust,no_run
/// use dotscope::MethodBodyBuilder;
/// use dotscope::assembly::InstructionAssembler;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let (body_bytes, _token) = MethodBodyBuilder::new()
///     .max_stack(2)
///     .implementation(|asm| {
///         asm.ldarg_0()?
///            .ldarg_1()?
///            .add()?
///            .ret()?;
///         Ok(())
///     })
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
///
/// ## Method with Local Variables
///
/// ```rust,no_run
/// use dotscope::MethodBodyBuilder;
/// use dotscope::metadata::signatures::TypeSignature;
///
/// # fn example() -> dotscope::Result<()> {
/// # let view = dotscope::CilAssemblyView::from_path("test.dll")?;
/// # let mut assembly = dotscope::CilAssembly::new(view);
/// let (body_bytes, _token) = MethodBodyBuilder::new()
///     .local("temp", TypeSignature::I4)
///     .local("result", TypeSignature::I4)
///     .implementation(|asm| {
///         asm.ldarg_0()?
///            .stloc_0()?  // Store to first local (temp)
///            .ldloc_0()?  // Load from temp
///            .stloc_1()?  // Store to second local (result)
///            .ldloc_1()?  // Load result
///            .ret()?;
///         Ok(())
///     })
///     .build(&mut assembly)?;
/// # Ok(())
/// # }
/// ```
pub struct MethodBodyBuilder {
    /// Maximum stack depth (None = auto-calculate)
    max_stack: Option<u16>,

    /// Initialize locals to zero
    init_locals: bool,

    /// Local variable definitions
    locals: Vec<(String, TypeSignature)>,

    /// The implementation closure
    implementation: Option<ImplementationFn>,

    /// Exception handlers for try/catch/finally blocks (manual byte offsets)
    exception_handlers: Vec<ExceptionHandler>,

    /// Exception handlers defined with labels (automatic offset calculation)
    labeled_exception_handlers: Vec<LabeledExceptionHandler>,

    /// Pre-built bytecode (from `SsaCodeGenerator`). When set, no implementation closure needed.
    prebuilt_bytecode: Option<Vec<u8>>,

    /// Pre-built local variable signatures. When set, used instead of `locals`.
    prebuilt_local_sig: Option<SignatureLocalVariables>,
}

impl MethodBodyBuilder {
    /// Create a new method body builder.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_stack: None,
            init_locals: true,
            locals: Vec::new(),
            implementation: None,
            exception_handlers: Vec::new(),
            labeled_exception_handlers: Vec::new(),
            prebuilt_bytecode: None,
            prebuilt_local_sig: None,
        }
    }

    /// Create a method body builder from pre-built compilation output.
    ///
    /// This constructor accepts pre-built bytecode, local variable signatures, and
    /// exception handlers — typically produced by [`crate::compiler::SsaCodeGenerator::compile`].
    /// No implementation closure is needed; the bytecode is used directly.
    ///
    /// The builder can still be customized with [`init_locals`](Self::init_locals) before
    /// calling [`build`](Self::build).
    ///
    /// # Arguments
    ///
    /// * `bytecode` - Pre-built CIL bytecode
    /// * `max_stack` - Maximum evaluation stack depth
    /// * `locals` - Local variable signatures
    /// * `exception_handlers` - Exception handlers with bytecode offsets
    #[must_use]
    pub fn from_compilation(
        bytecode: Vec<u8>,
        max_stack: u16,
        locals: Vec<SignatureLocalVariable>,
        exception_handlers: Vec<ExceptionHandler>,
    ) -> Self {
        let prebuilt_local_sig = if locals.is_empty() {
            None
        } else {
            Some(SignatureLocalVariables { locals })
        };
        Self {
            max_stack: Some(max_stack),
            init_locals: true,
            locals: Vec::new(),
            implementation: None,
            exception_handlers,
            labeled_exception_handlers: Vec::new(),
            prebuilt_bytecode: Some(bytecode),
            prebuilt_local_sig,
        }
    }

    /// Set the maximum stack depth explicitly.
    ///
    /// If not set, the stack depth will be calculated automatically with precise
    /// real-time tracking of stack effects during instruction assembly. Explicit
    /// setting is useful for optimization or special cases where manual control is needed.
    ///
    /// # Arguments
    ///
    /// * `stack_size` - Maximum number of stack slots needed
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new().max_stack(4);
    /// ```
    #[must_use]
    pub fn max_stack(mut self, stack_size: u16) -> Self {
        self.max_stack = Some(stack_size);
        self
    }

    /// Add a local variable to the method.
    ///
    /// Local variables are indexed in the order they are added, starting from 0.
    /// The name is used for documentation purposes but is not encoded in the
    /// final method body (use debugging information for that).
    ///
    /// # Arguments
    ///
    /// * `name` - Variable name (for documentation)
    /// * `local_type` - Type signature of the local variable
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// let builder = MethodBodyBuilder::new()
    ///     .local("counter", TypeSignature::I4)
    ///     .local("result", TypeSignature::String);
    /// ```
    #[must_use]
    pub fn local(mut self, name: &str, local_type: TypeSignature) -> Self {
        self.locals.push((name.to_string(), local_type));
        self
    }

    /// Set whether to initialize local variables to zero.
    ///
    /// By default, locals are initialized to zero/null. Setting this to false
    /// can improve performance but requires careful initialization in the method body.
    ///
    /// # Arguments
    ///
    /// * `init` - Whether to initialize locals to zero
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let builder = MethodBodyBuilder::new().init_locals(false);
    /// ```
    #[must_use]
    pub fn init_locals(mut self, init: bool) -> Self {
        self.init_locals = init;
        self
    }

    /// Add an exception handler to the method body.
    ///
    /// Exception handlers define protected try regions and their corresponding
    /// catch, finally, or fault handlers. This method provides a high-level
    /// interface for adding exception handling to method bodies.
    ///
    /// # Arguments
    ///
    /// * `handler` - The exception handler specification
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::method::{ExceptionHandler, ExceptionHandlerFlags};
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .exception_handler(ExceptionHandler {
    ///         flags: ExceptionHandlerFlags::EXCEPTION,
    ///         try_offset: 0,
    ///         try_length: 10,
    ///         handler_offset: 10,
    ///         handler_length: 5,
    ///         handler: None, // Would be set to exception type
    ///         filter_offset: 0,
    ///     });
    /// ```
    #[must_use]
    pub fn exception_handler(mut self, handler: ExceptionHandler) -> Self {
        self.exception_handlers.push(handler);
        self
    }

    /// Add a simple catch handler for a specific exception type.
    ///
    /// This is a convenience method for adding typed exception handlers without
    /// manually constructing the ExceptionHandler structure.
    ///
    /// # Arguments
    ///
    /// * `try_offset` - Byte offset of the protected try block
    /// * `try_length` - Length of the protected try block in bytes
    /// * `handler_offset` - Byte offset of the catch handler code
    /// * `handler_length` - Length of the catch handler code in bytes
    /// * `exception_type` - The exception type to catch (optional)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .catch_handler(0, 10, 10, 5, None); // Catch any exception
    /// ```
    #[must_use]
    pub fn catch_handler(
        mut self,
        try_offset: u32,
        try_length: u32,
        handler_offset: u32,
        handler_length: u32,
        exception_type: Option<CilTypeRc>,
    ) -> Self {
        let handler = ExceptionHandler {
            // A catch-all is a catch of System.Object, resolved when the body is built: a fault
            // handler would let the exception go on
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            handler: exception_type,
            filter_offset: 0,
        };
        self.exception_handlers.push(handler);
        self
    }

    /// Add a finally handler.
    ///
    /// Finally handlers execute regardless of whether an exception is thrown
    /// in the protected try region, providing guaranteed cleanup functionality.
    ///
    /// # Arguments
    ///
    /// * `try_offset` - Byte offset of the protected try block
    /// * `try_length` - Length of the protected try block in bytes
    /// * `handler_offset` - Byte offset of the finally handler code
    /// * `handler_length` - Length of the finally handler code in bytes
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .finally_handler(0, 10, 15, 8);
    /// ```
    #[must_use]
    pub fn finally_handler(
        mut self,
        try_offset: u32,
        try_length: u32,
        handler_offset: u32,
        handler_length: u32,
    ) -> Self {
        let handler = ExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_offset,
            try_length,
            handler_offset,
            handler_length,
            handler: None,
            filter_offset: 0,
        };
        self.exception_handlers.push(handler);
        self
    }

    /// Add a finally handler using labels for automatic offset calculation.
    ///
    /// This is a higher-level API that calculates byte offsets automatically from labels
    /// placed in the instruction sequence. The labels are resolved during method body
    /// compilation to determine the exact byte positions.
    ///
    /// # Arguments
    ///
    /// * `try_start_label` - Label marking the start of the protected try block
    /// * `try_end_label` - Label marking the end of the protected try block
    /// * `handler_start_label` - Label marking the start of the finally handler
    /// * `handler_end_label` - Label marking the end of the finally handler
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .finally_handler_with_labels("try_start", "try_end", "finally_start", "finally_end");
    /// ```
    #[must_use]
    pub fn finally_handler_with_labels(
        mut self,
        try_start_label: &str,
        try_end_label: &str,
        handler_start_label: &str,
        handler_end_label: &str,
    ) -> Self {
        // Store label names - they will be resolved during build()
        let handler = LabeledExceptionHandler {
            flags: ExceptionHandlerFlags::FINALLY,
            try_start_label: try_start_label.to_string(),
            try_end_label: try_end_label.to_string(),
            handler_start_label: handler_start_label.to_string(),
            handler_end_label: handler_end_label.to_string(),
            handler_type: None,
            filter_start_label: None,
        };
        self.labeled_exception_handlers.push(handler);
        self
    }

    /// Add a catch handler using labels for automatic offset calculation.
    ///
    /// This is a higher-level API that calculates byte offsets automatically from labels
    /// placed in the instruction sequence.
    ///
    /// # Arguments
    ///
    /// * `try_start_label` - Label marking the start of the protected try block
    /// * `try_end_label` - Label marking the end of the protected try block
    /// * `handler_start_label` - Label marking the start of the catch handler
    /// * `handler_end_label` - Label marking the end of the catch handler
    /// * `exception_type` - The exception type to catch (optional for catch-all)
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .catch_handler_with_labels("try_start", "try_end", "catch_start", "catch_end", None);
    /// ```
    #[must_use]
    pub fn catch_handler_with_labels(
        mut self,
        try_start_label: &str,
        try_end_label: &str,
        handler_start_label: &str,
        handler_end_label: &str,
        exception_type: Option<CilTypeRc>,
    ) -> Self {
        let handler = LabeledExceptionHandler {
            // A catch-all is a catch of System.Object, resolved when the body is built
            flags: ExceptionHandlerFlags::EXCEPTION,
            try_start_label: try_start_label.to_string(),
            try_end_label: try_end_label.to_string(),
            handler_start_label: handler_start_label.to_string(),
            handler_end_label: handler_end_label.to_string(),
            handler_type: exception_type,
            filter_start_label: None,
        };
        self.labeled_exception_handlers.push(handler);
        self
    }

    /// Add a filter handler using labels for automatic offset calculation.
    ///
    /// Filter handlers use a custom filter expression to determine whether to handle
    /// an exception. The filter expression must leave a boolean value on the stack:
    /// - Non-zero (true): The handler will process the exception
    /// - Zero (false): The exception continues to propagate
    ///
    /// # Arguments
    ///
    /// * `try_start_label` - Label marking the start of the protected try block
    /// * `try_end_label` - Label marking the end of the protected try block
    /// * `filter_start_label` - Label marking the start of the filter expression
    /// * `handler_start_label` - Label marking the start of the handler block
    /// * `handler_end_label` - Label marking the end of the handler block
    ///
    /// # Filter Expression
    ///
    /// The filter expression code (between `filter_start_label` and `handler_start_label`)
    /// receives the exception object on the stack and must evaluate to a boolean.
    /// Use `endfilter` instruction to complete the filter evaluation.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// let body_builder = MethodBodyBuilder::new()
    ///     .filter_handler_with_labels(
    ///         "try_start", "try_end",
    ///         "filter_start",
    ///         "handler_start", "handler_end"
    ///     );
    /// ```
    #[must_use]
    pub fn filter_handler_with_labels(
        mut self,
        try_start_label: &str,
        try_end_label: &str,
        filter_start_label: &str,
        handler_start_label: &str,
        handler_end_label: &str,
    ) -> Self {
        let handler = LabeledExceptionHandler {
            flags: ExceptionHandlerFlags::FILTER,
            try_start_label: try_start_label.to_string(),
            try_end_label: try_end_label.to_string(),
            handler_start_label: handler_start_label.to_string(),
            handler_end_label: handler_end_label.to_string(),
            handler_type: None,
            filter_start_label: Some(filter_start_label.to_string()),
        };
        self.labeled_exception_handlers.push(handler);
        self
    }

    /// Set the method implementation using the instruction assembler.
    ///
    /// This is where you define what the method actually does using the fluent
    /// instruction assembler API. The closure receives a mutable reference to
    /// an [`crate::assembly::InstructionAssembler`] that can be used to emit CIL instructions.
    ///
    /// # Arguments
    ///
    /// * `f` - Closure that implements the method body
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    ///
    /// # fn example() -> dotscope::Result<()> {
    /// # let view = dotscope::CilAssemblyView::from_path("test.dll")?;
    /// # let mut assembly = dotscope::CilAssembly::new(view);
    /// let (body_bytes, _token) = MethodBodyBuilder::new()
    ///     .implementation(|asm| {
    ///         asm.ldc_i4_const(42)?
    ///            .ret()?;
    ///         Ok(())
    ///     })
    ///     .build(&mut assembly)?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn implementation<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut InstructionAssembler) -> Result<()> + 'static,
    {
        self.implementation = Some(Box::new(f));
        self
    }

    /// Build the method body and return the encoded bytes with local variable signature token.
    ///
    /// This method integrates with [`crate::cilassembly::CilAssembly`] to properly
    /// handle local variable signatures and heap management. It performs the following steps:
    /// 1. Execute the implementation closure to generate CIL bytecode
    /// 2. Calculate max stack depth if not explicitly set
    /// 3. Generate proper local variable signature tokens using CilAssembly
    /// 4. Choose between tiny and fat method body format
    /// 5. Encode the complete method body according to ECMA-335
    ///
    /// # Arguments
    ///
    /// * `assembly` - CIL assembly for heap and table management
    ///
    /// # Returns
    ///
    /// A tuple of (method_body_bytes, local_var_sig_token) where the token
    /// can be used when creating the MethodDef entry.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No implementation was provided
    /// - The implementation closure returns an error
    /// - Method body encoding fails
    /// - Local variable signature creation fails
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::MethodBodyBuilder;
    /// use dotscope::metadata::signatures::TypeSignature;
    ///
    /// # fn example(assembly: &mut dotscope::CilAssembly) -> dotscope::Result<()> {
    /// let (body_bytes, local_sig_token) = MethodBodyBuilder::new()
    ///     .local("temp", TypeSignature::I4)
    ///     .implementation(|asm| {
    ///         asm.ldc_i4_1()?
    ///            .stloc_0()?
    ///            .ldloc_0()?
    ///            .ret()?;
    ///         Ok(())
    ///     })
    ///     .build(assembly)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build(self, assembly: &mut CilAssembly) -> Result<(Vec<u8>, Token)> {
        // Extract values from self to avoid borrow issues
        let MethodBodyBuilder {
            max_stack,
            init_locals,
            locals,
            implementation,
            exception_handlers,
            labeled_exception_handlers,
            prebuilt_bytecode,
            prebuilt_local_sig,
        } = self;

        // Resolve bytecode and max_stack based on path (prebuilt vs assembler)
        let (code_bytes, all_exception_handlers, max_stack) =
            if let Some(bytecode) = prebuilt_bytecode {
                // Prebuilt path: bytecode and exception handlers are already resolved
                let max_stack = max_stack.unwrap_or(8);
                (bytecode, exception_handlers, max_stack)
            } else {
                // Assembler path: run the implementation closure
                let implementation = implementation.ok_or_else(|| {
                    Error::ModificationInvalid("Method body implementation is required".to_string())
                })?;

                let mut assembler = InstructionAssembler::new();
                implementation(&mut assembler)?;

                // The clauses the assembler built, and the labeled handlers resolved at the
                // offsets the finished code has
                let (code_bytes, calculated_max_stack, assembled, labels) =
                    assembler.finish_with_labels()?;
                let mut all_exception_handlers = exception_handlers;
                for labeled_handler in labeled_exception_handlers {
                    all_exception_handlers.push(resolve_labeled_exception_handler(
                        &labels,
                        &labeled_handler,
                    )?);
                }
                all_exception_handlers.extend(assembled);
                let max_stack = max_stack.unwrap_or(calculated_max_stack);
                (code_bytes, all_exception_handlers, max_stack)
            };

        // A catch-all catches System.Object (ECMA-335 II.19); a clause with no class names
        // the core library's, which the assembly has to reference
        let mut all_exception_handlers = all_exception_handlers;
        for clause in &mut all_exception_handlers {
            if clause.flags == ExceptionHandlerFlags::EXCEPTION
                && clause.handler.is_none()
                && clause.filter_offset == 0
            {
                let object = assembly
                    .find_corelib_type("System", "Object")
                    .ok_or_else(|| {
                        Error::ModificationInvalid(
                            "a catch-all handler catches System.Object, which the assembly \
                             neither references nor defines"
                                .to_string(),
                        )
                    })?;
                clause.filter_offset = object.token.value();
            }
        }
        let all_exception_handlers = order_nested_first(all_exception_handlers);

        // Generate local variable signature token
        let local_var_sig_token_value = if let Some(local_sig) = prebuilt_local_sig {
            // Prebuilt path: encode the provided local signatures
            let sig_bytes = encode_local_var_signature(&local_sig)?;
            let local_sig_ref = StandAloneSigBuilder::new()
                .signature(&sig_bytes)
                .build(assembly)?;
            local_sig_ref.placeholder_token().map_or(0, |t| t.value())
        } else if locals.is_empty() {
            0u32
        } else {
            // Assembler path: convert simple type pairs to signatures
            let signature_locals: Vec<SignatureLocalVariable> = locals
                .iter()
                .map(|(_, sig)| SignatureLocalVariable {
                    modifiers: Vec::new(),
                    is_byref: false,
                    is_pinned: false,
                    base: sig.clone(),
                })
                .collect();

            let local_sig = SignatureLocalVariables {
                locals: signature_locals,
            };

            let sig_bytes = encode_local_var_signature(&local_sig)?;

            let local_sig_ref = StandAloneSigBuilder::new()
                .signature(&sig_bytes)
                .build(assembly)?;

            local_sig_ref.placeholder_token().map_or(0, |t| t.value())
        };

        // Determine if we have exception handlers
        let has_exceptions = !all_exception_handlers.is_empty();

        // Generate method body header
        let code_size = u32::try_from(code_bytes.len())
            .map_err(|_| malformed_error!("Method body size exceeds u32 range"))?;
        // InitLocals zeroes the locals and `localloc` memory: a body with neither has nothing
        // for it to do, and leaving it off lets a small body take the tiny header
        let init_locals = init_locals
            && (local_var_sig_token_value != 0
                || decode_stream(&mut Parser::new(&code_bytes), 0)?
                    .iter()
                    .any(|instruction| instruction.mnemonic == "localloc"));
        let header = encode_method_body_header(
            code_size,
            max_stack,
            local_var_sig_token_value,
            has_exceptions,
            init_locals,
        )?;

        // Combine header + code
        let mut body = header;
        body.extend_from_slice(&code_bytes);

        // Add exception handler section if needed
        if has_exceptions {
            // Validate exception handler ranges before encoding
            validate_exception_handler_ranges(&all_exception_handlers, code_size)?;

            // Align to 4-byte boundary before exception handler section (ECMA-335 requirement)
            while body.len() % 4 != 0 {
                body.push(0x00);
            }

            // Exception handlers are encoded after the method body according to ECMA-335
            let eh_section = encode_exception_handlers(&all_exception_handlers, None)?;
            body.extend_from_slice(&eh_section);
        }

        Ok((body, Token::new(local_var_sig_token_value)))
    }
}

impl Default for MethodBodyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{
        cilassembly::CilAssembly,
        metadata::{cilassemblyview::CilAssemblyView, method::MethodBody},
        testkit::fixture,
    };

    fn get_test_assembly() -> Result<CilAssembly> {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path)?;
        Ok(CilAssembly::new(view))
    }

    /// The exception clauses of a built body, as the body is read back.
    fn clauses(body: &[u8]) -> Vec<ExceptionHandler> {
        MethodBody::from(body).unwrap().exception_handlers
    }

    /// The clauses the assembler builds from `try_start`/`catch_start` are part of the body:
    /// they were dropped.
    #[test]
    fn the_assembler_s_own_clauses_are_kept() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let exception = assembly
            .find_corelib_typeref("System", "Exception")
            .expect("WindowsBase references System.Exception")
            .token;
        let (body, _) = MethodBodyBuilder::new()
            .implementation(move |asm| {
                asm.try_start("t")?
                    .nop()?
                    .leave_s("end")?
                    .try_end("t")?
                    .catch_start("t", exception)?
                    .pop()?
                    .leave_s("end")?
                    .catch_end("t")?
                    .label("end")?
                    .ret()?;
                Ok(())
            })
            .build(&mut assembly)?;
        let clauses = clauses(&body);
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].flags, ExceptionHandlerFlags::EXCEPTION);
        assert_eq!(clauses[0].filter_offset, exception.value());
        Ok(())
    }

    /// A catch-all is a catch of System.Object (ECMA-335 II.19): it was a fault handler, which
    /// lets the exception go on.
    #[test]
    fn a_catch_all_catches_system_object() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let object = assembly
            .find_corelib_typeref("System", "Object")
            .expect("WindowsBase references System.Object")
            .token;
        let (body, _) = MethodBodyBuilder::new()
            .catch_handler_with_labels("try", "try_end", "handler", "handler_end", None)
            .implementation(|asm| {
                asm.label("try")?
                    .nop()?
                    .leave_s("end")?
                    .label("try_end")?
                    .label("handler")?
                    .leave_s("end")?
                    .label("handler_end")?
                    .label("end")?
                    .ret()?;
                Ok(())
            })
            .build(&mut assembly)?;
        let clauses = clauses(&body);
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].flags, ExceptionHandlerFlags::EXCEPTION);
        assert_eq!(clauses[0].filter_offset, object.value());
        Ok(())
    }

    /// A labeled handler sits where its labels are in the finished code: finishing shortens
    /// branches, and the labels after one moved, which the handler was resolved before.
    #[test]
    fn a_labeled_handler_is_resolved_after_branches_shorten() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body, _) = MethodBodyBuilder::new()
            .finally_handler_with_labels("try", "try_end", "handler", "handler_end")
            .implementation(|asm| {
                asm.br("try")?
                    .label("try")?
                    .nop()?
                    .leave_s("end")?
                    .label("try_end")?
                    .label("handler")?
                    .endfinally()?
                    .label("handler_end")?
                    .label("end")?
                    .ret()?;
                Ok(())
            })
            .build(&mut assembly)?;
        let parsed = MethodBody::from(&body).unwrap();
        let code = &body[parsed.size_header..parsed.size_header + parsed.size_code];
        // The leading branch comes out short (br.s, two bytes): the try region starts after it
        assert_eq!(code[0], 0x2B, "the branch is shortened");
        let clauses = parsed.exception_handlers;
        assert_eq!(clauses.len(), 1);
        assert_eq!(clauses[0].try_offset, 2);
        assert_eq!(code[clauses[0].handler_offset as usize], 0xDC, "endfinally");
        Ok(())
    }

    #[test]
    fn test_method_body_builder_basic() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .implementation(|asm| {
                asm.ldc_i4_1()?.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;

        // Should have at least header + 2 instruction bytes
        assert!(body_bytes.len() >= 3);

        // For tiny format with 2 bytes of code: header should be (2 << 2) | 0x02 = 0x0A
        assert_eq!(body_bytes[0], 0x0A);

        // Should contain ldc.i4.1 (0x17) and ret (0x2A)
        assert_eq!(body_bytes[1], 0x17); // ldc.i4.1
        assert_eq!(body_bytes[2], 0x2A); // ret

        Ok(())
    }

    #[test]
    fn test_method_body_builder_with_max_stack() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .max_stack(10)
            .implementation(|asm| {
                asm.nop()?.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;

        // With max_stack > 8, should use fat format (12 byte header + code)
        assert!(body_bytes.len() >= 14); // 12 byte header + 2 instruction bytes

        // Fat format should start with flags
        let flags = u16::from_le_bytes([body_bytes[0], body_bytes[1]]);
        assert_eq!(flags & 0x0003, 0x0003); // Fat format flags

        Ok(())
    }

    #[test]
    fn test_method_body_builder_with_locals() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body_bytes, local_sig_token) = MethodBodyBuilder::new()
            .local("temp", TypeSignature::I4)
            .local("result", TypeSignature::String)
            .implementation(|asm| {
                asm.ldarg_0()?.stloc_0()?.ldloc_0()?.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;

        // Should have created a local variable signature token
        assert_ne!(local_sig_token.value(), 0);

        // Should create method body
        assert!(!body_bytes.is_empty());

        Ok(())
    }

    #[test]
    fn test_method_body_builder_complex_method() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .local("counter", TypeSignature::I4)
            .implementation(|asm| {
                asm.ldc_i4_0()? // Initialize counter to 0
                    .stloc_0()? // Store to local 0
                    .label("loop")? // Loop label
                    .ldloc_0()? // Load counter
                    .ldc_i4_const(10)? // Load 10
                    .blt_s("continue")? // Branch if counter < 10
                    .ldloc_0()? // Load final counter value
                    .ret()? // Return counter
                    .label("continue")?
                    .ldloc_0()? // Load counter
                    .ldc_i4_1()? // Load 1
                    .add()? // Increment counter
                    .stloc_0()? // Store back to local
                    .br_s("loop")?; // Continue loop
                Ok(())
            })
            .build(&mut assembly)?;

        // Should successfully create a method body with branching
        assert!(body_bytes.len() > 10);

        Ok(())
    }

    #[test]
    fn test_method_body_builder_no_implementation_fails() {
        let mut assembly = get_test_assembly().unwrap();
        let result = MethodBodyBuilder::new().build(&mut assembly);

        assert!(result.is_err());
    }

    #[test]
    fn test_method_body_with_exception_handlers() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        // Create a method with enough code to accommodate exception handlers
        // Try block: offset 0, length 5 (covers nop, nop, nop, nop, nop)
        // Handler block: offset 5, length 3 (covers nop, nop, nop for finally)
        // Total code: 9 bytes
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .finally_handler(0, 5, 5, 3) // Finally block - try covers 5 bytes, handler is 3 bytes
            .implementation(|asm| {
                // Try block: 5 bytes of nops
                asm.nop()?; // offset 0
                asm.nop()?; // offset 1
                asm.nop()?; // offset 2
                asm.nop()?; // offset 3
                asm.nop()?; // offset 4
                            // Finally handler block: 3 bytes
                asm.nop()?; // offset 5 - finally code
                asm.nop()?; // offset 6
                asm.endfinally()?; // offset 7 - end finally
                                   // After the protected region
                asm.ret()?; // offset 8 - return point
                Ok(())
            })
            .build(&mut assembly)?;

        // Should create method body with fat format due to exception handlers
        assert!(!body_bytes.is_empty());
        // Fat format should be used when exception handlers are present
        assert!(body_bytes.len() >= 12); // Fat header is larger than tiny header

        Ok(())
    }

    #[test]
    fn test_filter_handler_with_labels() -> Result<()> {
        let mut assembly = get_test_assembly()?;

        // Create a method with a filter exception handler
        // Note: This test verifies the filter handler structure is built correctly.
        // The CLR pushes exception objects at filter/handler entry points, but our
        // stack tracking doesn't model this. We use nop instead of pop to avoid
        // stack underflow errors in testing.
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .filter_handler_with_labels(
                "try_start",
                "try_end",
                "filter_start",
                "handler_start",
                "handler_end",
            )
            .implementation(|asm| {
                // Try block
                asm.label("try_start")?;
                asm.nop()?;
                asm.nop()?;
                asm.leave_s("try_end")?;

                // Filter expression - must evaluate to int32 for endfilter
                // In real code: pop exception, evaluate, push result
                // Here we just push 1 (accept) to test structure
                asm.label("filter_start")?;
                asm.ldc_i4_1()?; // Return true (handle this exception)
                asm.endfilter()?;

                // Handler block
                asm.label("handler_start")?;
                asm.nop()?; // Handler code would go here
                asm.leave_s("handler_end")?;

                // End labels and return
                asm.label("handler_end")?;
                asm.label("try_end")?;
                asm.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;

        // Should create method body with fat format due to exception handlers
        assert!(!body_bytes.is_empty());
        assert!(body_bytes.len() >= 12); // Fat header required for exception handlers

        Ok(())
    }

    #[test]
    fn test_accurate_stack_tracking() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (body_bytes, _local_sig_token) = MethodBodyBuilder::new()
            .implementation(|asm| {
                // This sequence has a known stack pattern:
                // ldc.i4.1: +1 (stack=1, max=1)
                // ldc.i4.2: +1 (stack=2, max=2)
                // add: -2+1 (stack=1, max=2)
                // dup: +1 (stack=2, max=2)
                // ret: -1 (stack=1, max=2)
                asm.ldc_i4_1()?.ldc_i4_2()?.add()?.dup()?.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;

        // Should have created method body successfully
        assert!(!body_bytes.is_empty());

        // The method should use tiny format since max stack (2) <= 8 and no locals/exceptions
        // Tiny format: first byte = (code_size << 2) | 0x02
        // Code size is 5 bytes: ldc.i4.1(1) + ldc.i4.2(1) + add(1) + dup(1) + ret(1)
        assert_eq!(body_bytes[0], (5 << 2) | 0x02); // 0x16 = tiny format with 5-byte code

        Ok(())
    }

    /// InitLocals also zeroes `localloc` memory: a body that allocates keeps it without locals,
    /// and one with neither takes the tiny header, which cannot say it.
    #[test]
    fn init_locals_is_kept_where_it_zeroes_something() -> Result<()> {
        let mut assembly = get_test_assembly()?;
        let (allocating, _) = MethodBodyBuilder::new()
            .implementation(|asm| {
                // localloc
                asm.ldc_i4_s(16)?.emit_opcode(0xFE0F, None)?.pop()?.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;
        let body = MethodBody::from(&allocating)?;
        assert!(body.is_fat);
        assert!(body.is_init_local);

        let (plain, _) = MethodBodyBuilder::new()
            .implementation(|asm| {
                asm.ret()?;
                Ok(())
            })
            .build(&mut assembly)?;
        assert!(!MethodBody::from(&plain)?.is_fat);
        Ok(())
    }
}
