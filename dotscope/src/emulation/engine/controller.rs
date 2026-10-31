//! High-level emulation controller.
//!
//! The [`EmulationController`] orchestrates method emulation, managing the
//! execution loop, call stack, and coordination between sub-modules.
//!
//! # Architecture
//!
//! The controller sits between the low-level [`Interpreter`] and the high-level
//! [`EmulationProcess`](crate::emulation::process::EmulationProcess). It
//! delegates to focused sub-modules for specific concerns:
//!
//! - **[`callresolver`](super::callresolver)** — Hook dispatch, virtual dispatch,
//!   delegate dispatch, P/Invoke, frame management, and type initialization
//! - **[`exhandler`](super::exhandler)** — Exception handler search, finally
//!   scheduling, and stack unwinding
//! - **[`typeops`](super::typeops)** — Type operations (box, unbox, cast, sizeof,
//!   static fields, newarr, newobj, ldstr)
//!
//! The controller itself handles the step-based execution loop: fetching
//! instructions, dispatching to the interpreter, and routing the resulting
//! [`StepResult`] to the appropriate sub-module.
//!
//! # Execution Model
//!
//! 1. Fetch the instruction at the current IP
//! 2. Execute via the interpreter, producing a [`StepResult`]
//! 3. Handle the result (branch, call, return, exception, etc.)
//! 4. Repeat until completion or limit reached
//!
//! [`Interpreter`]: crate::emulation::engine::Interpreter
//! [`StepResult`]: crate::emulation::engine::StepResult

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};

use dashmap::DashMap;
use log::{debug, trace};

use crate::{
    emulation::{
        capture::CaptureContext,
        engine::{
            callresolver::{self, CallResolver},
            cctors::CctorTracker,
            context::EmulationContext,
            exhandler,
            generics::GenericRegistry,
            interpreter::Interpreter,
            resolution::{CallResolution, NewObjResolution, MAX_REDIRECT_DEPTH},
            result::{EmulationOutcome, StepResult},
            typeops, EmulationError,
        },
        exception::{ExceptionInfo, InstructionLocation},
        fakeobjects::SharedFakeObjects,
        filesystem::VirtualFs,
        memory::AddressSpace,
        process::{EmulationConfig, EmulationLimits},
        runtime::RuntimeState,
        thread::{EmulationThread, ThreadCallFrame, ThreadContext},
        tracer::{TraceEvent, TraceWriter},
        EmValue, SymbolicValue, TaintSource, ThreadId,
    },
    metadata::{
        signatures::TypeSignature,
        tables::{StandAloneSignature, TableId, TypeSpecRaw},
        token::Token,
        typesystem::CilFlavor,
    },
    CilObject, Error, Result,
};

/// Control flow directive returned by extracted handler methods.
///
/// Each handler in the execution loop returns a `LoopAction` to tell the main
/// loop what to do next:
/// - [`Continue`](LoopAction::Continue) — re-fetch and execute the next instruction
/// - [`Return`](LoopAction::Return) — exit the execution loop with an outcome
enum LoopAction {
    /// Re-fetch and execute the next instruction.
    Continue,
    /// Exit the execution loop, returning the given outcome to the caller.
    Return(Box<EmulationOutcome>),
}

/// High-level controller for CIL method emulation.
///
/// The `EmulationController` provides the main entry point for emulating .NET
/// methods. It manages:
/// - Method execution with proper call stack handling
/// - Method hook resolution for framework methods
/// - Exception handling
/// - Execution limits and timeouts
///
/// All memory operations go through the shared `AddressSpace`, which manages:
/// - Managed heap (shared across all executions)
/// - Static field storage
/// - Mapped memory regions (PE images, raw data)
///
/// # Example
///
/// ```no_run
/// use dotscope::emulation::{EmulationController, EmValue, ProcessBuilder};
/// use dotscope::CilObject;
/// use std::sync::Arc;
///
/// let assembly = Arc::new(CilObject::from_path("test.dll")?);
/// let process = ProcessBuilder::new()
///     .assembly_arc(assembly.clone())
///     .build()?;
///
/// // Use process.execute_method() instead of controller directly
/// let result = process.execute_method(method_token, vec![EmValue::I32(42)])?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct EmulationController {
    /// Shared process environment (address space, runtime, capture, config, etc.).
    context: Arc<ThreadContext>,

    /// Call resolution pipeline: hook dispatch, virtual dispatch, delegate
    /// dispatch, P/Invoke, and method resolution caching.
    call_resolver: CallResolver,

    /// Optional trace writer for debugging execution.
    trace_writer: Option<Arc<TraceWriter>>,

    /// Tracks types whose .cctor has failed, so subsequent accesses
    /// re-throw the same `TypeInitializationException`.
    cctor_tracker: CctorTracker,

    /// Generic type and method instantiation tracking.
    generics: Arc<GenericRegistry>,

    /// Monotonically increasing call ID for correlating call/return trace events.
    next_call_id: AtomicU64,

    /// Memoized per-assembly emulation contexts, keyed by loaded assembly index.
    ///
    /// Keeps each assembly's decoded-method cache alive across the execution
    /// loop instead of rebuilding it on every instruction.
    assembly_contexts: DashMap<u32, Arc<EmulationContext>>,
}

impl EmulationController {
    /// Creates a new emulation controller with shared infrastructure.
    ///
    /// # Arguments
    ///
    /// - `context` - Shared process environment (address space, runtime, config, etc.)
    /// - `trace_writer` - Optional trace writer for debugging
    pub fn new(
        context: Arc<ThreadContext>,
        trace_writer: Option<Arc<TraceWriter>>,
    ) -> Result<Self> {
        let generics = Arc::new(GenericRegistry::new());
        let call_resolver = CallResolver::new(
            Arc::clone(&context.runtime),
            Arc::clone(&context.config),
            trace_writer.clone(),
            Arc::clone(&generics),
        )?;

        Ok(EmulationController {
            context,
            call_resolver,
            trace_writer,
            cctor_tracker: CctorTracker::new(),
            generics,
            next_call_id: AtomicU64::new(1),
            assembly_contexts: DashMap::new(),
        })
    }

    /// Returns a reference to the shared thread context.
    #[must_use]
    pub fn context(&self) -> &Arc<ThreadContext> {
        &self.context
    }

    /// Returns a reference to the shared fake objects.
    #[must_use]
    pub fn fake_objects(&self) -> &SharedFakeObjects {
        &self.context.fake_objects
    }

    /// Returns a reference to the address space.
    #[must_use]
    pub fn address_space(&self) -> &Arc<AddressSpace> {
        &self.context.address_space
    }

    /// Returns a reference to the runtime state.
    #[must_use]
    pub fn runtime(&self) -> &Arc<RwLock<RuntimeState>> {
        &self.context.runtime
    }

    /// Returns a reference to the capture context.
    #[must_use]
    pub fn capture(&self) -> &Arc<CaptureContext> {
        &self.context.capture
    }

    /// Returns a reference to the emulation config.
    #[must_use]
    pub fn config(&self) -> &Arc<EmulationConfig> {
        &self.context.config
    }

    /// Returns a reference to the assembly being emulated.
    ///
    /// This provides stubs access to metadata, type information, and PE data.
    #[must_use]
    pub fn assembly(&self) -> Option<&Arc<CilObject>> {
        self.context.assembly.as_ref()
    }

    /// Resolves generic type parameters in `ldtoken` tokens.
    ///
    /// When `ldtoken !!0` is encountered inside a generic method instantiation
    /// (e.g., `Get<byte[]>(int)`), the operand is a TypeSpec encoding
    /// `ELEMENT_TYPE_MVAR` with a parameter index. This method resolves it to
    /// the actual type argument from the current call frame's MethodSpec.
    ///
    /// Returns `Some(resolved_token)` if the token was a generic parameter that
    /// was successfully resolved, `None` if no resolution was needed or possible.
    fn resolve_ldtoken_generic(
        token: Token,
        thread: &EmulationThread,
        context: &EmulationContext,
    ) -> Option<Token> {
        // Only TypeSpec tokens can encode generic parameters
        if !token.is_table(TableId::TypeSpec) {
            return None;
        }

        // Parse the TypeSpec signature using the existing signature parser
        let assembly = context.assembly();
        let typespec_row = assembly
            .tables()
            .and_then(|t| t.table::<TypeSpecRaw>())
            .and_then(|table| table.get(token.row()).ok().flatten())?;

        let blob = assembly.blob()?;
        let parsed = typespec_row.to_owned(blob).ok()?;

        match &parsed.signature.base {
            TypeSignature::GenericParamMethod(index) => {
                let frame = thread.current_frame()?;
                let type_args = frame.method_type_args()?;
                type_args.get(*index as usize).copied()
            }
            TypeSignature::GenericParamType(index) => {
                let frame = thread.current_frame()?;
                let type_args = frame.type_type_args()?;
                type_args.get(*index as usize).copied()
            }
            _ => None,
        }
    }

    /// Returns the execution limits.
    #[must_use]
    pub fn limits(&self) -> &EmulationLimits {
        &self.context.config.limits
    }

    /// Writes a trace event if tracing is enabled.
    #[inline]
    fn trace(&self, event: TraceEvent) {
        if let Some(ref writer) = self.trace_writer {
            writer.write(event);
        }
    }

    /// Checks if instruction tracing is enabled.
    #[inline]
    fn trace_instructions_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.context.config.tracing.trace_instructions
    }

    /// Checks if call tracing is enabled.
    #[inline]
    fn trace_calls_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.context.config.tracing.trace_calls
    }

    /// Checks if a specific method at a given call depth passes the trace filter.
    #[inline]
    fn trace_filter_passes(&self, method_token: Token, call_depth: u32) -> bool {
        self.context
            .config
            .tracing
            .filter
            .should_trace(method_token, call_depth)
    }

    /// Checks if exception tracing is enabled.
    #[inline]
    fn trace_exceptions_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.context.config.tracing.trace_exceptions
    }

    /// Checks if array operation tracing is enabled.
    #[inline]
    fn trace_array_ops_enabled(&self) -> bool {
        self.trace_writer.is_some() && self.context.config.tracing.trace_array_ops
    }

    /// Creates an [`EmulationContext`] for a dynamically loaded assembly.
    ///
    /// Returns `None` if the assembly index doesn't exist in the `RuntimeState`.
    /// This is called per-iteration when executing a frame from a loaded assembly,
    /// but `EmulationContext::new` is trivial (wraps an `Arc`), so the cost is negligible.
    fn loaded_assembly_context(&self, index: u32) -> Result<Option<Arc<EmulationContext>>> {
        // The execution loop resolves the frame's context on every instruction.
        // Rebuilding the context each time meant taking the runtime lock and
        // discarding the assembly's decoded-method cache per step, so memoize it.
        if let Some(cached) = self.assembly_contexts.get(&index) {
            return Ok(Some(Arc::clone(cached.value())));
        }

        let state = self
            .context
            .runtime
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "runtime state",
            })?;
        let Some(asm) = usize::try_from(index)
            .ok()
            .and_then(|index| state.app_domain().get_parsed_assembly(index))
        else {
            return Ok(None);
        };

        let context = Arc::new(EmulationContext::new(
            Arc::clone(asm),
            Arc::clone(&self.context.synthetic_methods),
        ));
        self.assembly_contexts.insert(index, Arc::clone(&context));
        Ok(Some(context))
    }

    /// Emulates a method with the given arguments.
    ///
    /// This is the main entry point for method emulation. It sets up the
    /// execution context and runs the method to completion.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method to emulate
    /// * `args` - Arguments to pass to the method
    /// * `assembly` - The loaded assembly containing the method
    ///
    /// # Errors
    ///
    /// Returns an error if method setup fails, an unrecoverable error occurs,
    /// or an internal invariant is violated (e.g., empty call stack).
    pub fn emulate_method(
        &self,
        method_token: Token,
        args: Vec<EmValue>,
        assembly: Arc<CilObject>,
    ) -> Result<EmulationOutcome> {
        let context = EmulationContext::new(assembly, Arc::clone(&self.context.synthetic_methods));

        // Create interpreter
        let mut interpreter = Interpreter::new(
            self.context.config.limits.clone(),
            Arc::clone(&self.context.address_space),
            self.context.config.pointer_size,
        );
        interpreter.start();

        // Create emulation thread with initial call frame
        let mut thread = self.create_thread_for_method(&context, method_token, args)?;

        // Set interpreter to the method
        interpreter.set_method(method_token);

        // Run the execution loop
        self.run_execution_loop(&mut interpreter, &mut thread, &context)
    }

    /// Emulates a method until a specific condition is met.
    ///
    /// Useful for patterns like "emulate until ldstr" for string decryption.
    ///
    /// # Arguments
    ///
    /// * `method_token` - The token of the method to emulate
    /// * `args` - Arguments to pass to the method
    /// * `assembly` - The loaded assembly containing the method
    /// * `condition` - A closure that returns `true` when emulation should stop
    ///
    /// # Errors
    ///
    /// Returns an error if method setup fails, an unrecoverable error occurs,
    /// or an internal invariant is violated (e.g., empty call stack).
    pub fn emulate_until<F>(
        &self,
        method_token: Token,
        args: Vec<EmValue>,
        assembly: Arc<CilObject>,
        condition: F,
    ) -> Result<EmulationOutcome>
    where
        F: Fn(&StepResult, &EmulationThread) -> bool,
    {
        let context = EmulationContext::new(assembly, Arc::clone(&self.context.synthetic_methods));

        // Create interpreter
        let mut interpreter = Interpreter::new(
            self.context.config.limits.clone(),
            Arc::clone(&self.context.address_space),
            self.context.config.pointer_size,
        );
        interpreter.start();

        // Create emulation thread with initial call frame
        let mut thread = self.create_thread_for_method(&context, method_token, args)?;

        // Set interpreter to the method
        interpreter.set_method(method_token);

        // Run with condition check
        self.run_execution_loop_with_condition(&mut interpreter, &mut thread, &context, condition)
    }

    /// Creates an emulation thread for a method.
    ///
    /// This creates a thread with the initial call frame set up based on the method's
    /// local variables and the provided arguments. The thread shares the controller's
    /// address space.
    ///
    /// # Arguments
    ///
    /// * `context` - The emulation context providing method metadata
    /// * `method_token` - Token of the method to create a thread for
    /// * `args` - Arguments to pass to the method
    ///
    /// # Returns
    ///
    /// A new [`EmulationThread`] configured to execute the specified method.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method metadata lookup fails
    /// - Local variable type resolution fails
    fn create_thread_for_method(
        &self,
        context: &EmulationContext,
        method_token: Token,
        args: Vec<EmValue>,
    ) -> Result<EmulationThread> {
        // Resolve MethodSpec tokens to their underlying MethodDef for metadata lookup,
        // while preserving the generic type arguments for ldtoken resolution.
        let (effective_token, method_type_args) = if method_token.is_table(TableId::MethodSpec) {
            if let Some(method_spec) = context.get_method_spec(method_token) {
                let underlying = EmulationContext::resolve_method_spec_to_token(&method_spec);
                let type_args: Vec<Token> = method_spec
                    .instantiation
                    .generic_args
                    .iter()
                    .filter_map(|sig| {
                        context.type_signature_to_token(sig, None, None, &self.generics)
                    })
                    .collect();
                let args_opt = if type_args.is_empty() {
                    None
                } else {
                    Some(type_args)
                };
                (underlying.unwrap_or(method_token), args_opt)
            } else {
                (method_token, None)
            }
        } else {
            (method_token, None)
        };

        // Get method info using the resolved MethodDef token
        let is_instance = !context.is_static_method(effective_token)?;
        let local_types = context.get_local_types(effective_token)?;
        let local_cil_flavors = local_types;

        let param_types = context.get_parameter_types(effective_token)?;
        let arg_types: Vec<CilFlavor> = if is_instance {
            let mut types = vec![CilFlavor::Object];
            types.extend(param_types);
            types
        } else {
            param_types
        };

        let mut thread = EmulationThread::new(ThreadId::MAIN, Arc::clone(&self.context));

        let args_with_types: Vec<(EmValue, CilFlavor)> = args.into_iter().zip(arg_types).collect();

        // Start the method using the resolved MethodDef token
        thread.start_method(effective_token, local_cil_flavors, args_with_types, false);

        // Set generic type arguments on the frame so ldtoken !!0 can resolve them
        if let Some(type_args) = method_type_args {
            if let Some(frame) = thread.current_frame_mut() {
                frame.set_method_type_args(type_args);
            }
        }

        Ok(thread)
    }

    /// Runs the main execution loop until completion or limit reached.
    ///
    /// This is a convenience wrapper around [`run_execution_loop_with_condition`](Self::run_execution_loop_with_condition)
    /// that runs without any early stopping condition.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter for executing instructions
    /// * `thread` - The emulation thread with call stack and evaluation stack
    /// * `context` - The emulation context providing method metadata
    ///
    /// # Returns
    ///
    /// The outcome of execution - completion, limit reached, or error.
    ///
    /// # Errors
    ///
    /// Returns an error if instruction fetch or execution fails.
    fn run_execution_loop(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
    ) -> Result<EmulationOutcome> {
        self.run_execution_loop_with_condition(
            interpreter,
            thread,
            context,
            |_, _| false, // Never stop early
        )
    }

    /// Runs the execution loop with an optional early stopping condition.
    ///
    /// This is the core execution loop that fetches and executes instructions,
    /// handles branching, method calls, returns, and exception handling.
    ///
    /// # Arguments
    ///
    /// * `interpreter` - The CIL interpreter for executing instructions
    /// * `thread` - The emulation thread with call stack and evaluation stack
    /// * `context` - The emulation context providing method metadata
    /// * `condition` - A closure that returns `true` to stop execution early.
    ///   Called after each step with the result and thread state.
    ///
    /// # Returns
    ///
    /// The outcome of execution:
    /// - [`EmulationOutcome::Completed`] - Method finished normally
    /// - [`EmulationOutcome::Stopped`] - Condition triggered early stop
    /// - [`EmulationOutcome::LimitReached`] - Execution limit hit
    /// - [`EmulationOutcome::Faulted`] - Unhandled exception
    ///
    /// # Errors
    ///
    /// Returns an error if instruction fetch or execution fails.
    fn run_execution_loop_with_condition<F>(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        condition: F,
    ) -> Result<EmulationOutcome>
    where
        F: Fn(&StepResult, &EmulationThread) -> bool,
    {
        // Clear any previous exception state at the start of the execution loop
        thread.exception_state_mut().clear();

        loop {
            // Native work the last step's hooks did counts as instructions
            let stats = interpreter.stats_mut();
            stats.instructions_executed = stats
                .instructions_executed
                .saturating_add(thread.take_work());

            // Check all limits (instruction count, call depth, timeout)
            if let Some(limit_exceeded) = interpreter
                .stats()
                .check_limits(&self.context.config.limits, thread.call_depth())
            {
                return Ok(EmulationOutcome::LimitReached {
                    limit: limit_exceeded,
                    partial_state: None,
                });
            }
            thread.begin_work(
                interpreter.stats().instructions_executed,
                self.context.config.limits.max_instructions,
            );

            // Get current method and assembly index from the active frame.
            let (current_method, asm_index) = match thread.current_frame() {
                Some(frame) => (frame.method(), frame.assembly_index()),
                None => {
                    return Ok(EmulationOutcome::Completed {
                        return_value: None,
                        instructions: interpreter.stats().instructions_executed,
                    });
                }
            };

            // Resolve the correct emulation context for this frame's assembly.
            let loaded_context;
            let context = if let Some(idx) = asm_index {
                loaded_context = self.loaded_assembly_context(idx)?;
                loaded_context.as_deref().unwrap_or(context)
            } else {
                context
            };

            // Get the instruction at current offset. The decoded body is cached
            // and shared, so this borrows the instruction rather than cloning it.
            let method_code = context.get_method_code(current_method)?;
            let offset = interpreter.ip().offset();
            let instruction = method_code
                .instruction_at(offset)
                .ok_or(EmulationError::InvalidInstructionPointer { offset })?;

            // Capture pre-execution instruction info for tracing
            let trace_info = if self.trace_instructions_enabled() {
                let offset = interpreter.ip().offset();
                let opcode = if instruction.prefix == 0xFE {
                    u16::from(instruction.prefix) << 8 | u16::from(instruction.opcode)
                } else {
                    u16::from(instruction.opcode)
                };
                Some((
                    offset,
                    opcode,
                    instruction.mnemonic.to_string(),
                    instruction.operand.as_string(),
                    thread.stack().depth(),
                ))
            } else {
                None
            };

            // Capture array store info before execution if tracing
            let array_store_info = if self.trace_array_ops_enabled() {
                let is_stelem = matches!(instruction.opcode, 0x9B..=0xA2)
                    || (instruction.prefix == 0xFE && instruction.opcode == 0xA4);
                if is_stelem && thread.stack().depth() >= 3 {
                    let value = thread.stack().peek_at(0).ok().cloned();
                    let index = thread.stack().peek_at(1).ok().cloned();
                    let array_ref = thread.stack().peek_at(2).ok().cloned();
                    Some((array_ref, index, value, interpreter.ip().offset()))
                } else {
                    None
                }
            } else {
                None
            };

            // Execute the instruction
            let step_result = match interpreter.step(thread, instruction) {
                Ok(result) => result,
                Err(err) => {
                    match self.handle_step_error(
                        interpreter,
                        thread,
                        context,
                        current_method,
                        err,
                    )? {
                        LoopAction::Continue => continue,
                        LoopAction::Return(outcome) => return Ok(*outcome),
                    }
                }
            };

            // Emit instruction trace AFTER execution (captures post-execution stack values)
            if let Some((offset, opcode, mnemonic, operand, pre_depth)) = trace_info {
                let stack_values = if self.context.config.tracing.trace_stack_values {
                    let depth = thread.stack().depth();
                    let count = depth.min(3);
                    let mut vals = Vec::with_capacity(count);
                    for i in 0..count {
                        if let Ok(v) = thread.stack().peek_at(i) {
                            vals.push(format!("{v:?}"));
                        }
                    }
                    Some(vals)
                } else {
                    None
                };

                self.trace(TraceEvent::Instruction {
                    method: current_method,
                    offset,
                    opcode,
                    mnemonic,
                    operand,
                    stack_depth: pre_depth,
                    stack_values,
                });
            }

            // Check condition before handling result
            if condition(&step_result, thread) {
                return Ok(EmulationOutcome::Stopped {
                    reason: "Condition met".to_string(),
                    instructions: interpreter.stats().instructions_executed,
                });
            }

            // Emit array store trace event if we captured one
            if let Some((Some(EmValue::ObjectRef(href)), Some(index), Some(value), offset)) =
                array_store_info
            {
                let idx = match index {
                    EmValue::I32(i) => Some(i.cast_unsigned() as usize),
                    #[allow(clippy::cast_possible_truncation)]
                    EmValue::NativeInt(i) => Some(i.cast_unsigned() as usize),
                    _ => None,
                };
                if let Some(idx) = idx {
                    self.trace(TraceEvent::ArrayStore {
                        method: current_method,
                        offset,
                        heap_ref: href.id(),
                        index: idx,
                        value: format!("{value:?}"),
                    });
                }
            }

            // Handle the step result — dispatch to extracted handler methods
            // for complex cases, keep simple ones inline.
            let action = match step_result {
                StepResult::Continue => LoopAction::Continue,

                StepResult::Branch { target } => {
                    let method_offset = context.rva_to_method_offset(current_method, target)?;
                    if self.trace_instructions_enabled() {
                        self.trace(TraceEvent::Branch {
                            method: current_method,
                            from_offset: interpreter.ip().offset(),
                            to_offset: method_offset,
                            conditional: true,
                        });
                    }
                    interpreter.set_offset(method_offset);
                    LoopAction::Continue
                }

                StepResult::Return { value: _ } => {
                    self.handle_return(interpreter, thread, context, current_method)?
                }

                StepResult::Call {
                    method,
                    args: _,
                    is_virtual,
                    constrained_type,
                } => self.handle_call(
                    interpreter,
                    thread,
                    context,
                    current_method,
                    method,
                    is_virtual,
                    constrained_type,
                )?,

                StepResult::CallIndirect {
                    signature,
                    function_pointer,
                } => self.handle_call_indirect(
                    interpreter,
                    thread,
                    context,
                    current_method,
                    signature,
                    function_pointer,
                )?,

                StepResult::NewObj {
                    constructor,
                    args: _,
                } => {
                    self.handle_newobj(interpreter, thread, context, current_method, constructor)?
                }

                StepResult::NewArray {
                    element_type,
                    length,
                } => {
                    typeops::handle_newarr(thread, context, element_type, length)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LoadString { token } => {
                    typeops::handle_ldstr(thread, context, token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LoadStaticField { field } => {
                    if callresolver::maybe_run_type_cctor(
                        &self.context.address_space,
                        &self.cctor_tracker,
                        interpreter,
                        thread,
                        context,
                        field,
                    )? {
                        LoopAction::Continue
                    } else {
                        typeops::handle_ldsfld(
                            &self.context.address_space,
                            thread,
                            context,
                            field,
                        )?;
                        if self.trace_writer.is_some() {
                            let value_str = thread
                                .stack()
                                .peek()
                                .map(|v| format!("{v:?}"))
                                .unwrap_or_default();
                            self.trace(TraceEvent::StaticFieldValue {
                                method: current_method,
                                offset: interpreter.ip().offset(),
                                field,
                                is_load: true,
                                value: value_str,
                            });
                        }
                        interpreter.ip_mut().advance_current();
                        LoopAction::Continue
                    }
                }

                StepResult::StoreStaticField { field, value } => {
                    if self.trace_writer.is_some() {
                        self.trace(TraceEvent::StaticFieldValue {
                            method: current_method,
                            offset: interpreter.ip().offset(),
                            field,
                            is_load: false,
                            value: format!("{value:?}"),
                        });
                    }
                    thread.push(value.clone())?;
                    if callresolver::maybe_run_type_cctor(
                        &self.context.address_space,
                        &self.cctor_tracker,
                        interpreter,
                        thread,
                        context,
                        field,
                    )? {
                        LoopAction::Continue
                    } else {
                        let _ = thread.pop()?;
                        self.context.address_space.set_static(field, value)?;
                        interpreter.ip_mut().advance_current();
                        LoopAction::Continue
                    }
                }

                StepResult::Throw { exception } => {
                    self.handle_throw(interpreter, thread, context, current_method, exception)?
                }

                StepResult::Leave { target } => {
                    self.handle_leave(interpreter, thread, context, current_method, target)?
                }

                StepResult::EndFinally => {
                    self.handle_end_finally(interpreter, thread, context, current_method)?
                }

                StepResult::EndFilter { value } => {
                    // ECMA-335 §12.4.2.5: `endfilter` takes an int32. 0 means "continue the
                    // search", 1 means "this handler runs". Anything else is not a filter
                    // result — treating a non-int32 as rejection silently mis-routes the
                    // exception, so it is a program error.
                    let EmValue::I32(filter_result) = value else {
                        return Err(EmulationError::InternalError {
                            description: format!(
                                "endfilter expects an int32 result, found {}",
                                value.type_name()
                            ),
                        }
                        .into());
                    };
                    let should_handle = filter_result != 0;

                    thread
                        .exception_state_mut()
                        .set_filter_result(Some(should_handle));

                    if should_handle {
                        // Read the filter state *before* clearing it. `set_in_filter(false)`
                        // also nulls `filter_handler_offset` (see
                        // `ThreadExceptionState::set_in_filter`), so reading the offset
                        // afterwards always yields `None` — and the resulting fall-through
                        // returns `Continue` without advancing the IP, re-executing this same
                        // `endfilter` forever. The rejecting path below has the same
                        // constraint: it needs the offset as its skip key.
                        let handler_offset = thread.exception_state_mut().filter_handler_offset();
                        let origin_offset = self.exception_origin(thread, interpreter);
                        thread.exception_state_mut().set_in_filter(false);

                        let Some(handler_offset) = handler_offset else {
                            // `enter_filter` records the offset on every path that dispatches a
                            // filter, so its absence here means the filter body was entered
                            // without going through exception dispatch. Continuing would spin.
                            return Err(EmulationError::InternalError {
                                description:
                                    "endfilter accepted but no filter handler offset was recorded"
                                        .to_string(),
                            }
                            .into());
                        };

                        {
                            // `endfilter` consumed the exception object that
                            // `apply_handler_match` pushed before entering the filter, so the
                            // handler would otherwise start on whatever the filter left behind
                            // — typically an underflow on its first `stloc`. Re-push it, as the
                            // catch path does.
                            if let Some(exception) =
                                thread.exception_state_mut().get_exception_value()
                            {
                                thread.stack_mut().clear();
                                thread.push(exception)?;
                            }

                            thread.exception_state_mut().enter_catch_handler(
                                current_method,
                                origin_offset,
                                handler_offset,
                            );
                            interpreter.set_offset(handler_offset);
                            LoopAction::Continue
                        }
                    } else {
                        // Rejection means "keep searching", not "unhandled". Resume the scan
                        // after the rejected Filter clause and fall into the normal unwind path
                        // if nothing else matches; returning `UnhandledException` here reports a
                        // genuinely-caught exception as unhandled and stops the run, which an
                        // obfuscator can use to hide everything past a rejecting filter.
                        self.resume_search_after_filter(
                            interpreter,
                            thread,
                            context,
                            current_method,
                        )?
                    }
                }

                StepResult::Rethrow => {
                    self.handle_rethrow(interpreter, thread, context, current_method)?
                }

                StepResult::Breakpoint => {
                    LoopAction::Return(Box::new(EmulationOutcome::Breakpoint {
                        offset: interpreter.ip().offset(),
                        instructions: interpreter.stats().instructions_executed,
                    }))
                }

                StepResult::Jmp { method } => {
                    self.handle_jmp(interpreter, thread, context, method)?
                }

                StepResult::TailCall {
                    method,
                    is_virtual,
                    constrained_type,
                } => self.handle_tail_call(
                    interpreter,
                    thread,
                    context,
                    current_method,
                    method,
                    is_virtual,
                    constrained_type,
                )?,

                StepResult::Box { type_token } => {
                    typeops::handle_box(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::Unbox { type_token } | StepResult::UnboxAny { type_token } => {
                    typeops::handle_unbox(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::CastClass { type_token } => {
                    typeops::handle_castclass(thread, context, type_token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::IsInst { type_token } => {
                    typeops::handle_isinst(thread, context, type_token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::SizeOf { type_token } => {
                    typeops::handle_sizeof(
                        thread,
                        context,
                        type_token,
                        self.context.config.pointer_size,
                    )?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LoadToken { token } => {
                    // Resolve generic type parameters (!!0, !!1, etc.) in ldtoken.
                    // TypeSpec tokens encoding ELEMENT_TYPE_MVAR need to be resolved
                    // to the actual type argument from the current MethodSpec.
                    let resolved =
                        Self::resolve_ldtoken_generic(token, thread, context).unwrap_or(token);
                    thread.push(EmValue::NativeInt(i64::from(resolved.value())))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LoadFunctionPointer { method } => {
                    thread.push(EmValue::UnmanagedPtr(u64::from(method.value())))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LoadVirtualFunctionPointer { method } => {
                    thread.push(EmValue::UnmanagedPtr(u64::from(method.value())))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::InitObj { type_token } => {
                    typeops::handle_initobj(thread, Some(context), type_token)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::CopyObject { type_token } => {
                    typeops::handle_cpobj(
                        &self.context.address_space,
                        thread,
                        Some(context),
                        type_token,
                    )?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::LocalAlloc { size } => {
                    let size_bytes = size.as_size()?;
                    let ptr = thread.address_space().alloc_unmanaged(size_bytes)?;
                    thread.push(EmValue::UnmanagedPtr(ptr))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::CopyBlock { dest, src, size } => {
                    typeops::handle_cpblk(thread, &dest, &src, &size)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::InitBlock { addr, value, size } => {
                    typeops::handle_initblk(thread, &addr, &value, &size)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::RefAnyVal { type_token } => {
                    // ECMA-335 §III.4.22: extract address from typed reference,
                    // verifying the type matches. Throws InvalidCastException on
                    // mismatch.
                    let typed_ref = thread.pop()?;
                    let address = match typed_ref.as_object_ref() {
                        Some(href) => self
                            .context
                            .address_space
                            .managed_heap()
                            .typed_reference_value(href, Some(type_token))?,
                        None => {
                            return Err(EmulationError::TypeMismatch {
                                operation: "refanyval",
                                expected: "TypedReference (object ref)",
                                found: "non-reference value",
                            }
                            .into());
                        }
                    };
                    thread.push(address)?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::MkRefAny { type_token } => {
                    // ECMA-335 §III.4.14: package an address and type into a
                    // TypedReference.
                    let addr = thread.pop()?;
                    let href = self
                        .context
                        .address_space
                        .managed_heap()
                        .alloc_typed_reference(type_token, addr)?;
                    thread.push(EmValue::ObjectRef(href))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::RefAnyType => {
                    // ECMA-335 §III.4.23: extract the type token from a typed
                    // reference and push it as a RuntimeTypeHandle (NativeInt).
                    let typed_ref = thread.pop()?;
                    let type_value = match typed_ref.as_object_ref() {
                        Some(href) => {
                            let token = self
                                .context
                                .address_space
                                .managed_heap()
                                .typed_reference_type(href)?;
                            i64::from(token.value())
                        }
                        None => 0,
                    };
                    thread.push(EmValue::NativeInt(type_value))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }

                StepResult::ArgList => {
                    thread.push(EmValue::NativeInt(0))?;
                    interpreter.ip_mut().advance_current();
                    LoopAction::Continue
                }
            };

            match action {
                LoopAction::Continue => {}
                LoopAction::Return(outcome) => return Ok(*outcome),
            }
        }
    }

    /// Unwinds the call stack after a CLR exception originating from an
    /// interpreter error, with TargetInvocationException wrapping at
    /// reflection-invoke boundaries.
    ///
    /// Searches for exception handlers in caller frames, scheduling finally
    /// blocks along the way. If a reflection-invoke frame is encountered,
    /// the exception is wrapped in a `TargetInvocationException` per CLR
    /// semantics.
    ///
    /// Returns `LoopAction::Continue` when a handler or finally is found,
    /// or `LoopAction::Return(UnhandledException)` when the stack is exhausted.
    fn unwind_after_error(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        exception: &EmValue,
        mut exception_type: Token,
    ) -> Result<LoopAction> {
        loop {
            // Check for pending finally blocks
            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                thread.exception_state_mut().set_in_unwind_finally(true);
                interpreter.set_method(pending.method);
                interpreter.set_offset(pending.handler_offset);
                thread
                    .exception_state_mut()
                    .set_leave_target(pending.leave_target);
                return Ok(LoopAction::Continue);
            }

            // Capture return_offset before popping — this is the
            // call site in the CALLER where the exception escaped.
            // Also check if the frame was entered via reflection invoke
            // — if so, wrap in TargetInvocationException as real .NET does.
            let (fr_offset, fr_is_refl, fr_method) = thread
                .current_frame()
                .map_or((0, false, Token::new(0)), |f| {
                    (f.return_offset(), f.is_reflection_invoke(), f.method())
                });
            if fr_is_refl {
                let inner = thread
                    .exception_state_mut()
                    .take_exception_as_value()
                    .unwrap_or_else(|| exception.clone());
                if let Ok((tie_val, tie_type)) = exhandler::wrap_in_target_invocation_exception(
                    &self.context.address_space,
                    &inner,
                ) {
                    exception_type = tie_type;
                    if let Some(tie_ref) = tie_val.as_object_ref() {
                        let throw_loc = InstructionLocation::new(fr_method, fr_offset);
                        thread
                            .exception_state_mut()
                            .set_exception(ExceptionInfo::new(tie_ref, tie_type, throw_loc));
                    }
                }
            }

            // Pop call frame
            thread.pop_frame();

            if thread.call_depth() == 0 {
                return Ok(LoopAction::Return(Box::new(
                    EmulationOutcome::UnhandledException {
                        exception: thread
                            .exception_state_mut()
                            .take_exception_as_value()
                            .unwrap_or_else(|| exception.clone()),
                        instructions: interpreter.stats().instructions_executed,
                    },
                )));
            }

            // Search for handler in caller
            let caller_frame = thread
                .current_frame()
                .ok_or(EmulationError::InternalError {
                    description: "call stack empty during exception unwinding".to_string(),
                })?;
            let caller_method = caller_frame.method();

            if let Some(handler_match) = exhandler::find_exception_handler(
                context,
                caller_method,
                fr_offset,
                Some(exception_type),
                thread.exception_state_mut(),
                None,
            )? {
                let exc = thread
                    .exception_state_mut()
                    .take_exception_as_value()
                    .unwrap_or_else(|| {
                        trace!("No pending exception for extraction");
                        EmValue::Null
                    });
                thread.stack_mut().clear();
                let target_offset = exhandler::apply_handler_match(
                    &handler_match,
                    exc,
                    fr_offset,
                    caller_method,
                    thread,
                )?;
                interpreter.set_method(caller_method);
                interpreter.set_offset(target_offset);
                return Ok(LoopAction::Continue);
            }
        }
    }

    /// Unwinds the call stack for a propagating exception (throw or endfinally).
    ///
    /// Unlike [`unwind_after_error`](Self::unwind_after_error), this does NOT
    /// perform TargetInvocationException wrapping. When `track_cctor_failure`
    /// is `true`, records .cctor failures before popping frames (used by the
    /// endfinally path per ECMA-335 §II.10.5.3.3).
    ///
    /// Returns `LoopAction::Continue` when a handler or finally is found,
    /// or `LoopAction::Return(UnhandledException)` when the stack is exhausted.
    fn unwind_propagating_exception(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        track_cctor_failure: bool,
    ) -> Result<LoopAction> {
        let mut call_site_in_caller = 0u32;
        loop {
            // Track .cctor failure before popping the frame (endfinally path)
            if track_cctor_failure {
                if let Some(exc) = thread.exception_state_mut().get_exception_value() {
                    exhandler::track_cctor_failure_if_needed(
                        &self.cctor_tracker,
                        thread,
                        &exc,
                        context,
                    )?;
                }
            }

            // Run any finally scheduled for the frame we are about to leave, *before* leaving
            // it.
            //
            // `find_exception_handler` queues finallys against the frame it searched, and the
            // handler's IL reads locals, arguments and the evaluation stack from
            // `thread.current_frame()`. Popping first and then jumping to the handler — without
            // pushing a frame — executes that IL against the grandparent's frame instead. It
            // also skips the popped frame's own catch clauses, because the handler search below
            // only examines the frame that survives the pop.
            //
            // Every other unwind path in the engine (`unwind_after_error`, `handle_throw`,
            // `exhandler::route_clr_exception`) already drains the queue before popping; this
            // one was the outlier.
            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                thread.exception_state_mut().set_in_unwind_finally(true);
                interpreter.set_method(pending.method);
                interpreter.set_offset(pending.handler_offset);
                thread
                    .exception_state_mut()
                    .set_leave_target(pending.leave_target);
                return Ok(LoopAction::Continue);
            }

            // Capture the return_offset from the frame being popped
            if let Some(frame) = thread.current_frame() {
                call_site_in_caller = frame.return_offset();
            }

            thread.pop_frame();

            if thread.call_depth() == 0 {
                return Ok(LoopAction::Return(Box::new(
                    EmulationOutcome::UnhandledException {
                        exception: thread
                            .exception_state_mut()
                            .take_exception_as_value()
                            .unwrap_or_else(|| {
                                trace!("No pending exception for extraction");
                                EmValue::Null
                            }),
                        instructions: interpreter.stats().instructions_executed,
                    },
                )));
            }

            // Search for handlers in the caller
            let caller_frame = thread
                .current_frame()
                .ok_or(EmulationError::InternalError {
                    description: "call stack empty during exception unwinding".to_string(),
                })?;
            let caller_method = caller_frame.method();

            let exc_clone = thread.exception_state_mut().get_exception_value().ok_or(
                EmulationError::InternalError {
                    description: "exception state empty during exception unwinding".to_string(),
                },
            )?;
            let exc_type = exhandler::resolve_exception_type(&exc_clone, thread);

            if let Some(handler_match) = exhandler::find_exception_handler(
                context,
                caller_method,
                call_site_in_caller,
                exc_type,
                thread.exception_state_mut(),
                None,
            )? {
                let exc = thread
                    .exception_state_mut()
                    .take_exception_as_value()
                    .unwrap_or_else(|| {
                        trace!("No pending exception for extraction");
                        EmValue::Null
                    });
                thread.stack_mut().clear();
                let target_offset = exhandler::apply_handler_match(
                    &handler_match,
                    exc,
                    call_site_in_caller,
                    caller_method,
                    thread,
                )?;
                interpreter.set_method(caller_method);
                interpreter.set_offset(target_offset);
                return Ok(LoopAction::Continue);
            }
        }
    }

    /// Handles an interpreter step error by converting CLR-representable errors
    /// to managed exceptions and searching for handlers.
    ///
    /// Non-CLR errors are returned as `Err(...)` for the caller to propagate.
    /// CLR errors create a managed exception object, search for a handler in
    /// the current method, and if none is found, unwind the call stack via
    /// [`unwind_after_error`](Self::unwind_after_error).
    fn handle_step_error(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        err: crate::Error,
    ) -> Result<LoopAction> {
        let Error::Emulation(ref emu_err) = err else {
            return Err(err);
        };
        if !emu_err.is_clr_exception() {
            return Err(err);
        }

        // Trace the runtime exception if enabled
        if self.trace_exceptions_enabled() {
            let offset = interpreter.ip().offset();
            let error_type = match &**emu_err {
                EmulationError::ArrayIndexOutOfBounds { .. } => "ArrayIndexOutOfBounds",
                EmulationError::NullReference => "NullReference",
                EmulationError::DivisionByZero => "DivisionByZero",
                EmulationError::ArithmeticOverflow => "ArithmeticOverflow",
                EmulationError::InvalidCast { .. } => "InvalidCast",
                _ => "RuntimeException",
            };
            self.trace(TraceEvent::RuntimeException {
                method: current_method,
                offset,
                error_type: error_type.to_string(),
                description: emu_err.description(),
            });
        }

        // Convert emulation error to a CLR exception and search for handlers
        let exception = exhandler::create_clr_exception(&self.context.address_space, emu_err)?;
        let exception_type = emu_err.to_exception_token();

        let current_offset = interpreter.ip().offset();
        let throw_location = InstructionLocation::new(current_method, current_offset);

        // Set up exception state
        if let Some(heap_ref) = exception.as_object_ref() {
            let exception_info = ExceptionInfo::new(heap_ref, exception_type, throw_location);
            if thread.exception_state_mut().in_unwind_finally() {
                thread
                    .exception_state_mut()
                    .replace_exception_in_unwind_finally(exception_info);
            } else {
                thread.exception_state_mut().set_exception(exception_info);
            }
        }

        // Search for exception handler in current method
        if let Some(handler_match) = exhandler::find_exception_handler(
            context,
            current_method,
            current_offset,
            Some(exception_type),
            thread.exception_state_mut(),
            None,
        )? {
            thread.stack_mut().clear();
            let target_offset = exhandler::apply_handler_match(
                &handler_match,
                exception,
                current_offset,
                current_method,
                thread,
            )?;
            interpreter.set_offset(target_offset);
            return Ok(LoopAction::Continue);
        }

        // No handler in current method — unwind call stack
        self.unwind_after_error(interpreter, thread, context, &exception, exception_type)
    }

    /// Handles a `StepResult::Throw` — sets up exception state, searches for a
    /// handler in the current method, and unwinds the call stack if needed.
    fn handle_throw(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        exception: EmValue,
    ) -> Result<LoopAction> {
        let current_offset = interpreter.ip().offset();

        // Resolve exception type and create exception info
        let exception_type = exhandler::resolve_exception_type(&exception, thread);
        let throw_location = InstructionLocation::new(current_method, current_offset);

        // Trace exception throw if enabled
        if self.trace_exceptions_enabled() {
            self.trace(TraceEvent::ExceptionThrow {
                method: current_method,
                offset: current_offset,
                exception_type,
                description: format!("{exception:?}"),
            });
        }

        // In valid CIL, only object references can be thrown
        match (exception.as_object_ref(), exception_type) {
            (Some(heap_ref), Some(type_token)) => {
                let exception_info = ExceptionInfo::new(heap_ref, type_token, throw_location);
                if thread.exception_state_mut().in_unwind_finally() {
                    thread
                        .exception_state_mut()
                        .replace_exception_in_unwind_finally(exception_info);
                } else {
                    thread.exception_state_mut().set_exception(exception_info);
                }
            }
            (None, _) => {
                return Err(EmulationError::InvalidOperand {
                    instruction: "throw",
                    expected: "object reference",
                }
                .into());
            }
            (Some(_), None) => {
                return Err(EmulationError::TypeMismatch {
                    operation: "throw",
                    expected: "resolvable exception type",
                    found: "unresolved type",
                }
                .into());
            }
        }

        // Try to find an exception handler in the current method
        if let Some(handler_match) = exhandler::find_exception_handler(
            context,
            current_method,
            current_offset,
            exception_type,
            thread.exception_state_mut(),
            None,
        )? {
            thread.stack_mut().clear();
            let target_offset = exhandler::apply_handler_match(
                &handler_match,
                exception,
                current_offset,
                current_method,
                thread,
            )?;
            interpreter.set_offset(target_offset);
            return Ok(LoopAction::Continue);
        }

        // No handler found — unwind the call stack
        let mut call_site_in_caller = current_offset;
        loop {
            // Check for pending finally blocks
            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                thread.exception_state_mut().set_in_unwind_finally(true);
                interpreter.set_method(pending.method);
                interpreter.set_offset(pending.handler_offset);
                thread
                    .exception_state_mut()
                    .set_leave_target(pending.leave_target);
                return Ok(LoopAction::Continue);
            }

            if let Some(frame) = thread.current_frame() {
                call_site_in_caller = frame.return_offset();
            }

            thread.pop_frame();

            if thread.call_depth() == 0 {
                return Ok(LoopAction::Return(Box::new(
                    EmulationOutcome::UnhandledException {
                        exception: thread
                            .exception_state_mut()
                            .take_exception_as_value()
                            .unwrap_or_else(|| {
                                trace!("No pending exception for extraction");
                                EmValue::Null
                            }),
                        instructions: interpreter.stats().instructions_executed,
                    },
                )));
            }

            let caller_frame = thread
                .current_frame()
                .ok_or(EmulationError::InternalError {
                    description: "call stack empty during exception unwinding".to_string(),
                })?;
            let caller_method = caller_frame.method();

            // Get exception to avoid borrow conflict
            let exc_clone = thread.exception_state_mut().get_exception_value().ok_or(
                EmulationError::InternalError {
                    description: "exception state empty during exception handling".to_string(),
                },
            )?;
            let exc_type = exhandler::resolve_exception_type(&exc_clone, thread);

            if let Some(handler_match) = exhandler::find_exception_handler(
                context,
                caller_method,
                call_site_in_caller,
                exc_type,
                thread.exception_state_mut(),
                None,
            )? {
                let exc = thread
                    .exception_state_mut()
                    .take_exception_as_value()
                    .unwrap_or_else(|| {
                        trace!("No pending exception for extraction");
                        EmValue::Null
                    });
                thread.stack_mut().clear();
                let target_offset = exhandler::apply_handler_match(
                    &handler_match,
                    exc,
                    call_site_in_caller,
                    caller_method,
                    thread,
                )?;
                interpreter.set_method(caller_method);
                interpreter.set_offset(target_offset);
                return Ok(LoopAction::Continue);
            }
        }
    }

    /// Handles a `StepResult::Rethrow` — re-raises the current exception from
    /// within a catch handler, searching for another handler or unwinding.
    /// Resumes the handler search after a filter returned zero.
    ///
    /// ECMA-335 §12.4.2.5: a filter returning 0 means "continue the search" — the method's
    /// remaining clauses are examined, then the caller frames. It does **not** mean the
    /// exception is unhandled.
    ///
    /// Mirrors [`handle_rethrow`](Self::handle_rethrow), differing only in what it skips: the
    /// scan resumes past the rejected filter's own handler rather than past an enclosing catch.
    ///
    /// # Errors
    ///
    /// Propagates handler-search failures, and returns an error if the call stack is empty
    /// while a frame is expected.
    /// The IL offset a handler search should resume from.
    ///
    /// `exception_origin_offset` is only ever written by
    /// [`ThreadExceptionState::enter_catch_handler`], so it is `None` for an exception that has
    /// not yet entered a catch — which is precisely the case on the filter paths. Reading it
    /// alone made the post-filter rescan skip the current method's remaining clauses entirely
    /// and jump straight to unwinding the caller.
    ///
    /// The throw site is already recorded on the in-flight exception itself
    /// ([`ExceptionInfo::throw_location`], set by `handle_throw`), so it serves as the fallback.
    /// The interpreter's current offset is the last resort, for a filter evaluated with no
    /// exception state at all.
    fn exception_origin(&self, thread: &EmulationThread, interpreter: &Interpreter) -> u32 {
        thread
            .exception_state()
            .exception_origin_offset()
            .or_else(|| {
                thread
                    .exception_state()
                    .exception()
                    .map(|info| info.throw_location.offset)
            })
            .unwrap_or_else(|| interpreter.ip().offset())
    }

    fn resume_search_after_filter(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
    ) -> Result<LoopAction> {
        let Some(exception) = thread.exception_state_mut().get_exception_value() else {
            // No exception in flight: a filter evaluated outside exception dispatch. Nothing to
            // route, so just carry on.
            return Ok(LoopAction::Continue);
        };

        let exception_type = exhandler::resolve_exception_type(&exception, thread);
        // Both reads must precede `set_in_filter(false)`, which nulls the handler offset.
        // Without the skip key the rescan below re-matches the filter clause that just
        // rejected, re-enters its body, and loops.
        let skip_handler = thread.exception_state_mut().filter_handler_offset();
        let origin = self.exception_origin(thread, interpreter);
        thread.exception_state_mut().set_in_filter(false);

        // Remaining clauses of the current method, past the rejected filter.
        if let Some(handler_match) = exhandler::find_exception_handler(
            context,
            current_method,
            origin,
            exception_type,
            thread.exception_state_mut(),
            skip_handler,
        )? {
            thread.stack_mut().clear();
            let target_offset = exhandler::apply_handler_match(
                &handler_match,
                exception,
                origin,
                current_method,
                thread,
            )?;
            interpreter.set_offset(target_offset);
            return Ok(LoopAction::Continue);
        }

        // Nothing left in this method — hand over to the normal unwind path, which drains
        // pending finallys and searches each caller in turn.
        self.unwind_propagating_exception(interpreter, thread, context, false)
    }

    fn handle_rethrow(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
    ) -> Result<LoopAction> {
        // ECMA-335 III.4.24: rethrow only valid in catch handler, not filter
        if thread.exception_state().in_filter() {
            return Err(EmulationError::InternalError {
                description: "rethrow inside filter clause (ECMA-335 III.4.24)".into(),
            }
            .into());
        }

        let Some(exception) = thread.exception_state_mut().get_exception_value() else {
            return Err(EmulationError::InternalError {
                description: "rethrow outside catch handler (no current exception)".to_string(),
            }
            .into());
        };

        let origin_offset = thread.exception_state_mut().exception_origin_offset();
        let skip_handler = thread.exception_state_mut().current_handler_offset();
        let exception_type = exhandler::resolve_exception_type(&exception, thread);

        // First, try to find another handler in the current method
        if let Some(origin) = origin_offset {
            if let Some(handler_match) = exhandler::find_exception_handler(
                context,
                current_method,
                origin,
                exception_type,
                thread.exception_state_mut(),
                skip_handler,
            )? {
                thread.stack_mut().clear();
                let target_offset = exhandler::apply_handler_match(
                    &handler_match,
                    exception,
                    origin,
                    current_method,
                    thread,
                )?;
                interpreter.set_offset(target_offset);
                return Ok(LoopAction::Continue);
            }
        }

        // No handler in current method — unwind to caller
        let call_site_in_caller = thread
            .current_frame()
            .map(|f| f.return_offset())
            .unwrap_or(0);

        thread.pop_frame();
        if thread.call_depth() == 0 {
            return Ok(LoopAction::Return(Box::new(
                EmulationOutcome::UnhandledException {
                    exception,
                    instructions: interpreter.stats().instructions_executed,
                },
            )));
        }

        let caller_frame = thread
            .current_frame()
            .ok_or(EmulationError::InternalError {
                description: "call stack empty during rethrow".to_string(),
            })?;
        let caller_method = caller_frame.method();
        let exc_type = exhandler::resolve_exception_type(&exception, thread);

        if let Some(handler_match) = exhandler::find_exception_handler(
            context,
            caller_method,
            call_site_in_caller,
            exc_type,
            thread.exception_state_mut(),
            None,
        )? {
            thread.stack_mut().clear();
            let target_offset = exhandler::apply_handler_match(
                &handler_match,
                exception,
                call_site_in_caller,
                caller_method,
                thread,
            )?;
            interpreter.set_method(caller_method);
            interpreter.set_offset(target_offset);
            return Ok(LoopAction::Continue);
        }

        Ok(LoopAction::Return(Box::new(
            EmulationOutcome::UnhandledException {
                exception: thread
                    .exception_state_mut()
                    .take_exception_as_value()
                    .unwrap_or_else(|| {
                        trace!("No pending exception for extraction");
                        EmValue::Null
                    }),
                instructions: interpreter.stats().instructions_executed,
            },
        )))
    }

    /// Handles `StepResult::EndFinally` — processes the end of a finally/fault
    /// handler by chaining to the next finally, resuming at the leave target,
    /// or continuing exception unwinding.
    fn handle_end_finally(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
    ) -> Result<LoopAction> {
        let from_offset = interpreter.ip().offset();
        // Finally completed normally — clear unwind-finally flag
        thread.exception_state_mut().set_in_unwind_finally(false);

        if let Some(target) = thread.exception_state_mut().take_leave_target() {
            // Normal leave — continue to leave target or next finally
            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                if self.trace_instructions_enabled() {
                    self.trace(TraceEvent::FinallyEnter {
                        method: pending.method,
                        handler_offset: pending.handler_offset,
                    });
                }
                interpreter.set_method(pending.method);
                interpreter.set_offset(pending.handler_offset);
                thread
                    .exception_state_mut()
                    .set_leave_target(pending.leave_target);
            } else {
                if self.trace_instructions_enabled() {
                    self.trace(TraceEvent::Branch {
                        method: current_method,
                        from_offset,
                        to_offset: target,
                        conditional: false,
                    });
                }
                interpreter.set_offset(target);
            }
            return Ok(LoopAction::Continue);
        }

        if thread.exception_state_mut().has_exception() {
            // Exception is propagating — continue unwinding
            if let Some(pending) = thread.exception_state_mut().pop_finally() {
                thread.exception_state_mut().set_in_unwind_finally(true);
                if self.trace_instructions_enabled() {
                    self.trace(TraceEvent::FinallyEnter {
                        method: pending.method,
                        handler_offset: pending.handler_offset,
                    });
                }
                interpreter.set_method(pending.method);
                interpreter.set_offset(pending.handler_offset);
                thread
                    .exception_state_mut()
                    .set_leave_target(pending.leave_target);
            } else {
                // No more finally blocks — unwind the call stack
                return self.unwind_propagating_exception(
                    interpreter,
                    thread,
                    context,
                    true, // track_cctor_failure
                );
            }
        }

        // If neither exception nor leave, just continue (shouldn't happen)
        Ok(LoopAction::Continue)
    }

    /// Handles `StepResult::Leave` — clears the stack, schedules finally blocks,
    /// and transfers control to the leave target or the first finally handler.
    fn handle_leave(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        target: u64,
    ) -> Result<LoopAction> {
        thread.stack_mut().clear();

        // If leaving a catch handler normally, clear exception tracking
        if thread.exception_state_mut().current_handler_method() == Some(current_method) {
            thread.exception_state_mut().leave_catch_handler();
        }

        let method_target = context.rva_to_method_offset(current_method, target)?;
        let current_offset = interpreter.ip().offset();

        exhandler::schedule_finally_blocks(
            context,
            current_method,
            current_offset,
            method_target,
            thread.exception_state_mut(),
        )?;

        if let Some(pending) = thread.exception_state_mut().pop_finally() {
            if self.trace_instructions_enabled() {
                self.trace(TraceEvent::FinallyEnter {
                    method: pending.method,
                    handler_offset: pending.handler_offset,
                });
            }
            interpreter.set_method(pending.method);
            interpreter.set_offset(pending.handler_offset);
            thread
                .exception_state_mut()
                .set_leave_target(pending.leave_target);
        } else {
            if self.trace_instructions_enabled() {
                self.trace(TraceEvent::Branch {
                    method: current_method,
                    from_offset: current_offset,
                    to_offset: method_target,
                    conditional: false,
                });
            }
            interpreter.set_offset(method_target);
        }

        Ok(LoopAction::Continue)
    }

    /// Resolves a call through the redirect chain and enters the target method
    /// or applies a hook result.
    ///
    /// This is the shared redirect loop used by both `Call` and `CallIndirect`
    /// handlers. The `initial_virtual` and `initial_constraint` parameters
    /// control the first resolution; redirects may change these.
    ///
    /// When `is_tail_call` is `true`, the current frame is replaced instead of
    /// pushing a new one. This implements `tail.` prefix semantics per ECMA-335
    /// §III.2.4: the called method returns directly to the current method's caller.
    #[allow(clippy::too_many_arguments)]
    fn resolve_and_enter_call(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        initial_token: Token,
        initial_virtual: bool,
        initial_constraint: Option<Token>,
        is_tail_call: bool,
    ) -> Result<LoopAction> {
        let mut token = initial_token;
        let mut virt = initial_virtual;
        let constraint = initial_constraint;
        let mut pending_pre_push: Option<EmValue> = None;
        let mut pending_reflection_invoke = false;
        let mut pending_assembly_index: Option<u32> = None;
        let mut pending_method_type_args: Option<Vec<Token>> = None;

        for _ in 0..MAX_REDIRECT_DEPTH {
            match self.call_resolver.resolve_call(
                context,
                token,
                thread,
                virt,
                constraint,
                &self.context.address_space,
            )? {
                CallResolution::HookedBypass { return_value } => {
                    if is_tail_call {
                        return self.complete_tail_as_return(interpreter, thread, return_value);
                    }
                    if let Some(v) = return_value {
                        thread.push(v)?;
                    }
                    interpreter.ip_mut().advance_current();
                    return Ok(LoopAction::Continue);
                }
                CallResolution::ReturnSynthetic { value } => {
                    if is_tail_call {
                        return self.complete_tail_as_return(interpreter, thread, value);
                    }
                    if let Some(v) = value {
                        thread.push(v)?;
                    }
                    interpreter.ip_mut().advance_current();
                    return Ok(LoopAction::Continue);
                }
                CallResolution::EnterMethod {
                    token: t,
                    arguments,
                    expects_return,
                    assembly_index,
                    method_type_args,
                } => {
                    if let Some(v) = pending_pre_push.take() {
                        thread.push(v)?;
                    }
                    let arg_count = arguments.len();
                    let effective_method_type_args =
                        method_type_args.or(pending_method_type_args.take());

                    // For tail calls, capture caller info and trace before replacing
                    // the frame; for normal calls, capture before pushing the new frame.
                    let caller;
                    let caller_offset;
                    if is_tail_call {
                        // The "caller" for tracing is None — tail calls have no
                        // return point in the current method.
                        caller = None;
                        caller_offset = None;
                        self.enter_tail_call_target(
                            interpreter,
                            thread,
                            context,
                            t,
                            arguments,
                            expects_return,
                        )?;
                    } else {
                        caller = thread.current_frame().map(ThreadCallFrame::method);
                        caller_offset = Some(interpreter.ip().next_offset());
                        callresolver::push_method_frame(
                            interpreter,
                            thread,
                            context,
                            t,
                            arguments,
                            expects_return,
                        )?;
                    }

                    if let Some(args) = effective_method_type_args {
                        if let Some(frame) = thread.current_frame_mut() {
                            frame.set_method_type_args(args);
                        }
                    }

                    let asm_idx = assembly_index.or(pending_assembly_index);
                    if let Some(idx) = asm_idx {
                        if let Some(frame) = thread.current_frame_mut() {
                            frame.set_assembly_index(Some(idx));
                        }
                    }

                    if pending_reflection_invoke {
                        if let Some(frame) = thread.current_frame_mut() {
                            frame.set_reflection_invoke();
                            debug!("  Marked frame 0x{:08X} as reflection_invoke", t.value());
                        }
                    }

                    let cid = self.next_call_id.fetch_add(1, Ordering::Relaxed);
                    if let Some(frame) = thread.current_frame_mut() {
                        frame.set_call_id(cid);
                    }

                    if self.trace_calls_enabled()
                        && self.trace_filter_passes(t, thread.call_depth() as u32)
                    {
                        self.trace(TraceEvent::MethodCall {
                            target: t,
                            is_virtual: virt,
                            arg_count,
                            call_depth: thread.call_depth(),
                            caller,
                            caller_offset,
                            call_id: cid,
                        });
                    }
                    return Ok(LoopAction::Continue);
                }
                CallResolution::ThrowException {
                    exception_type,
                    message,
                } => {
                    if self.trace_exceptions_enabled() {
                        self.trace(TraceEvent::RuntimeException {
                            method: current_method,
                            offset: interpreter.ip().offset(),
                            error_type: message,
                            description: format!(
                                "Hook threw CLR exception at 0x{:04X}",
                                interpreter.ip().offset()
                            ),
                        });
                    }
                    let exception = exhandler::create_exception_from_type(
                        &self.context.address_space,
                        exception_type,
                    )?;
                    if !exhandler::route_clr_exception(
                        &self.context.address_space,
                        context,
                        interpreter,
                        thread,
                        current_method,
                        exception_type,
                        exception.clone(),
                    )? {
                        return Ok(LoopAction::Return(Box::new(
                            EmulationOutcome::UnhandledException {
                                exception,
                                instructions: interpreter.stats().instructions_executed,
                            },
                        )));
                    }
                    return Ok(LoopAction::Continue);
                }
                CallResolution::Redirect {
                    target_token,
                    arguments,
                    is_virtual: rv,
                    pre_push_value,
                    is_reflection_invoke,
                    assembly_index: redirect_asm,
                    method_type_args,
                } => {
                    for arg in arguments {
                        thread.push(arg)?;
                    }
                    if let Some(v) = pre_push_value {
                        pending_pre_push = Some(v);
                    }
                    if is_reflection_invoke {
                        pending_reflection_invoke = true;
                        debug!(
                            "  Reflection invoke redirect to 0x{:08X}",
                            target_token.value()
                        );
                    }
                    if redirect_asm.is_some() {
                        pending_assembly_index = redirect_asm;
                    }
                    if method_type_args.is_some() {
                        pending_method_type_args = method_type_args;
                    }
                    token = target_token;
                    virt = rv;
                }
            }
        }
        Ok(LoopAction::Continue)
    }

    /// Replaces the current call frame with a new frame for a tail call target.
    ///
    /// Saves the current frame's return info (caller method, return offset,
    /// caller's evaluation stack, leave target), pops the current frame,
    /// restores the caller's state, and pushes a new frame that returns
    /// directly to the original caller.
    fn enter_tail_call_target(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        target: Token,
        arguments: Vec<EmValue>,
        expects_return: bool,
    ) -> Result<()> {
        // Resolve target method metadata
        let local_cil_flavors = context.get_local_types(target)?;
        let callee_is_instance = !context.is_static_method(target)?;
        let param_types = context.get_parameter_types(target)?;
        let arg_types: Vec<CilFlavor> = if callee_is_instance {
            let mut types = vec![CilFlavor::Object];
            types.extend(param_types);
            types
        } else {
            param_types
        };
        let args_with_types: Vec<(EmValue, CilFlavor)> =
            arguments.into_iter().zip(arg_types).collect();

        // Save return info from the current frame before popping it.
        // The tail-called method must return to our CALLER, not to us.
        let mut popped = thread.pop_frame().ok_or(EmulationError::InternalError {
            description: "tail call requires an active frame".to_string(),
        })?;
        let return_method = popped.return_method();
        let return_offset = popped.return_offset();
        let caller_stack = popped.take_caller_stack();
        let saved_leave_target = popped.take_saved_leave_target();

        // Restore the caller's evaluation stack
        thread.restore_stack(caller_stack)?;

        // Build the new frame with the ORIGINAL caller's return info
        let mut frame = ThreadCallFrame::new(
            target,
            return_method,
            return_offset,
            local_cil_flavors,
            args_with_types,
            expects_return,
        );
        // Save the current stack (caller's) so the tail-called method's
        // return handler can restore it properly.
        let current_stack = thread.take_stack();
        frame.save_caller_stack(current_stack);
        frame.save_leave_target(saved_leave_target);

        thread.push_frame(frame);
        interpreter.set_method(target);
        interpreter.set_offset(0);
        Ok(())
    }

    /// Completes a tail call when the target was resolved by a hook or synthetic.
    ///
    /// Since the hook already produced the return value, this is equivalent to
    /// the current method returning that value. Pops the current frame, restores
    /// the caller's state, and pushes the return value.
    fn complete_tail_as_return(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        return_value: Option<EmValue>,
    ) -> Result<LoopAction> {
        // Trace the implicit return (the tail-called method was hooked)
        if self.trace_calls_enabled() {
            let method = thread.current_frame().map(ThreadCallFrame::method);
            if let Some(m) = method {
                if self.trace_filter_passes(m, thread.call_depth() as u32) {
                    let cid = thread.current_frame().map_or(0, |f| f.call_id());
                    self.trace(TraceEvent::MethodReturn {
                        method: m,
                        has_return_value: return_value.is_some(),
                        call_depth: thread.call_depth(),
                        call_id: cid,
                    });
                }
            }
        }

        let mut popped = thread.pop_frame().ok_or(EmulationError::InternalError {
            description: "tail call requires an active frame".to_string(),
        })?;
        let return_method = popped.return_method();
        let return_offset = popped.return_offset();
        let caller_stack = popped.take_caller_stack();
        let saved_leave_target = popped.take_saved_leave_target();

        // Restore caller's evaluation stack
        thread.restore_stack(caller_stack)?;

        // Restore leave target
        if saved_leave_target.is_some() {
            thread
                .exception_state_mut()
                .set_leave_target(saved_leave_target);
        }

        // If we're at the root level, the emulation is complete
        if thread.call_depth() == 0 {
            return Ok(LoopAction::Return(Box::new(EmulationOutcome::Completed {
                return_value,
                instructions: interpreter.stats().instructions_executed,
            })));
        }

        // Restore caller's execution point
        if let Some(rm) = return_method {
            interpreter.set_method(rm);
            interpreter.set_offset(return_offset);
        }

        // Push return value onto caller's stack
        if let Some(v) = return_value {
            thread.push(v)?;
        }

        Ok(LoopAction::Continue)
    }

    /// Handles `StepResult::Call` — triggers .cctor if needed, then resolves
    /// and enters the call target through the redirect chain.
    #[allow(clippy::too_many_arguments)]
    fn handle_call(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        method: Token,
        is_virtual: bool,
        constrained_type: Option<Token>,
    ) -> Result<LoopAction> {
        // ECMA-335 §II.10.5.3: trigger .cctor before any member access
        if callresolver::maybe_run_type_cctor_for_method(
            &self.context.address_space,
            &self.cctor_tracker,
            interpreter,
            thread,
            context,
            method,
        )? {
            return Ok(LoopAction::Continue);
        }

        self.resolve_and_enter_call(
            interpreter,
            thread,
            context,
            current_method,
            method,
            is_virtual,
            constrained_type,
            false,
        )
    }

    /// Handles `StepResult::TailCall` — the `tail.` prefix before `call` or `callvirt`.
    ///
    /// Per ECMA-335 §III.2.4, the tail prefix causes the current method's stack
    /// frame to be removed before the call executes. The called method returns
    /// directly to the current method's caller, preventing unbounded call depth
    /// growth in recursive or delegate-chain patterns.
    ///
    /// Uses the same resolution pipeline as regular calls (hooks, virtual dispatch,
    /// redirects) but replaces the current frame instead of pushing a new one.
    #[allow(clippy::too_many_arguments)]
    fn handle_tail_call(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        method: Token,
        is_virtual: bool,
        constrained_type: Option<Token>,
    ) -> Result<LoopAction> {
        // ECMA-335 §II.10.5.3: trigger .cctor before any member access
        if callresolver::maybe_run_type_cctor_for_method(
            &self.context.address_space,
            &self.cctor_tracker,
            interpreter,
            thread,
            context,
            method,
        )? {
            return Ok(LoopAction::Continue);
        }

        self.resolve_and_enter_call(
            interpreter,
            thread,
            context,
            current_method,
            method,
            is_virtual,
            constrained_type,
            true,
        )
    }

    /// Handles `StepResult::CallIndirect` — resolves a `calli` instruction
    /// by extracting the function pointer, validating the signature, and
    /// entering the target method.
    fn handle_call_indirect(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        signature: Token,
        function_pointer: EmValue,
    ) -> Result<LoopAction> {
        let standalone_sig = context.get_standalone_signature(signature).ok_or(
            EmulationError::InvalidMethodMetadata {
                token: signature,
                reason: "StandAloneSig not found for calli",
            },
        )?;

        let StandAloneSignature::Method(method_sig) = standalone_sig else {
            return Err(EmulationError::TypeMismatch {
                operation: "calli",
                expected: "method signature",
                found: "non-method signature",
            }
            .into());
        };

        let param_count = method_sig.param_count as usize;
        let has_this = method_sig.has_this;
        let total_args = if has_this {
            param_count.saturating_add(1)
        } else {
            param_count
        };
        let arg_values = thread.pop_args(total_args)?;

        let method_token = match function_pointer {
            EmValue::UnmanagedPtr(ptr) =>
            {
                #[allow(clippy::cast_possible_truncation)]
                Token::new(ptr as u32)
            }
            EmValue::NativeInt(val) =>
            {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                Token::new(val as u32)
            }
            _ => {
                return Err(EmulationError::TypeMismatch {
                    operation: "calli",
                    expected: "function pointer (UnmanagedPtr or NativeInt)",
                    found: "invalid value type",
                }
                .into());
            }
        };

        // Not a MethodDef — return symbolic
        if method_token.table() != 0x06 {
            if !matches!(method_sig.return_type.base, TypeSignature::Void) {
                let return_flavor = CilFlavor::from(&method_sig.return_type.base);
                thread.push(EmValue::Symbolic(SymbolicValue::new(
                    return_flavor,
                    TaintSource::MethodReturn(method_token.value()),
                )))?;
            }
            interpreter.ip_mut().advance_current();
            return Ok(LoopAction::Continue);
        }

        // Push args back and enter resolution loop
        for arg in arg_values {
            thread.push(arg)?;
        }

        // ECMA-335 §II.10.5.3: trigger .cctor for calli target type
        if callresolver::maybe_run_type_cctor_for_method(
            &self.context.address_space,
            &self.cctor_tracker,
            interpreter,
            thread,
            context,
            method_token,
        )? {
            return Ok(LoopAction::Continue);
        }

        self.resolve_and_enter_call(
            interpreter,
            thread,
            context,
            current_method,
            method_token,
            false,
            None,
            false,
        )
    }

    /// Handles `StepResult::NewObj` — triggers .cctor, resolves the constructor
    /// through the redirect chain, and enters it or applies a hook result.
    fn handle_newobj(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
        constructor: Token,
    ) -> Result<LoopAction> {
        // ECMA-335 §II.10.5.3: trigger .cctor before creating instances
        if callresolver::maybe_run_type_cctor_for_method(
            &self.context.address_space,
            &self.cctor_tracker,
            interpreter,
            thread,
            context,
            constructor,
        )? {
            return Ok(LoopAction::Continue);
        }

        let mut ctor = constructor;
        for _ in 0..MAX_REDIRECT_DEPTH {
            match typeops::resolve_newobj(
                self.call_resolver.hooks(),
                context,
                ctor,
                thread,
                self.context.config.pointer_size,
            )? {
                NewObjResolution::Redirect { underlying_token } => {
                    ctor = underlying_token;
                }
                NewObjResolution::ThrowException {
                    exception_type,
                    message,
                } => {
                    if self.trace_exceptions_enabled() {
                        self.trace(TraceEvent::RuntimeException {
                            method: current_method,
                            offset: interpreter.ip().offset(),
                            error_type: message,
                            description: format!(
                                "Hook threw CLR exception at 0x{:04X}",
                                interpreter.ip().offset()
                            ),
                        });
                    }
                    let exception = exhandler::create_exception_from_type(
                        &self.context.address_space,
                        exception_type,
                    )?;
                    if !exhandler::route_clr_exception(
                        &self.context.address_space,
                        context,
                        interpreter,
                        thread,
                        current_method,
                        exception_type,
                        exception.clone(),
                    )? {
                        return Ok(LoopAction::Return(Box::new(
                            EmulationOutcome::UnhandledException {
                                exception,
                                instructions: interpreter.stats().instructions_executed,
                            },
                        )));
                    }
                    return Ok(LoopAction::Continue);
                }
                NewObjResolution::HookedBypass { obj_ref }
                | NewObjResolution::DefaultObject { obj_ref } => {
                    thread.push(EmValue::ObjectRef(obj_ref))?;
                    interpreter.ip_mut().advance_current();
                    return Ok(LoopAction::Continue);
                }
                NewObjResolution::EnterConstructor {
                    constructor_token,
                    obj_ref,
                    arguments,
                } => {
                    // Push obj_ref before saving stack — caller expects it after return
                    thread.push(EmValue::ObjectRef(obj_ref))?;

                    let caller = thread.current_frame().map(ThreadCallFrame::method);
                    let caller_offset = Some(interpreter.ip().next_offset());
                    let arg_count = arguments.len();

                    callresolver::push_method_frame(
                        interpreter,
                        thread,
                        context,
                        constructor_token,
                        arguments,
                        false, // constructors don't return values
                    )?;

                    let cid = self.next_call_id.fetch_add(1, Ordering::Relaxed);
                    if let Some(frame) = thread.current_frame_mut() {
                        frame.set_call_id(cid);
                    }

                    if self.trace_calls_enabled()
                        && self.trace_filter_passes(constructor_token, thread.call_depth() as u32)
                    {
                        self.trace(TraceEvent::MethodCall {
                            target: constructor_token,
                            is_virtual: false,
                            arg_count,
                            call_depth: thread.call_depth(),
                            caller,
                            caller_offset,
                            call_id: cid,
                        });
                    }
                    return Ok(LoopAction::Continue);
                }
            }
        }
        Ok(LoopAction::Continue)
    }

    /// Handles `StepResult::Jmp` — the `jmp` instruction (opcode 0x27).
    ///
    /// Replaces the current frame with a new frame for the target method,
    /// transferring the current method's arguments directly. The evaluation
    /// stack must be empty (ECMA-335 §III.3.37).
    fn handle_jmp(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        method: Token,
    ) -> Result<LoopAction> {
        let target_method = context.get_method(method)?;
        let param_count = target_method.signature.params.len();
        let is_instance = !context.is_static_method(method)?;
        let total_args = if is_instance {
            param_count.saturating_add(1)
        } else {
            param_count
        };

        let arg_values = thread.pop_args(total_args)?;

        let param_types = context.get_parameter_types(method)?;
        let arg_types: Vec<CilFlavor> = if is_instance {
            let mut types = vec![CilFlavor::Object];
            types.extend(param_types);
            types
        } else {
            param_types
        };

        let args_with_types: Vec<(EmValue, CilFlavor)> =
            arg_values.into_iter().zip(arg_types).collect();

        let local_cil_flavors = context.get_local_types(method)?;

        // Pop current frame (tail call replaces it)
        thread.pop_frame();

        let frame = ThreadCallFrame::new(
            method,
            None, // No return method - tail call returns directly to caller's caller
            0,
            local_cil_flavors,
            args_with_types,
            false,
        );
        thread.push_frame(frame);

        let cid = self.next_call_id.fetch_add(1, Ordering::Relaxed);
        if let Some(frame) = thread.current_frame_mut() {
            frame.set_call_id(cid);
        }

        if self.trace_calls_enabled()
            && self.trace_filter_passes(method, thread.call_depth() as u32)
        {
            self.trace(TraceEvent::MethodCall {
                target: method,
                is_virtual: false,
                arg_count: total_args,
                call_depth: thread.call_depth(),
                caller: None, // Tail call has no return point
                caller_offset: None,
                call_id: cid,
            });
        }

        interpreter.set_method(method);
        interpreter.set_offset(0);
        Ok(LoopAction::Continue)
    }

    /// Handles `StepResult::Return` — pops the callee frame, restores caller
    /// state, and handles multicast delegate continuation.
    fn handle_return(
        &self,
        interpreter: &mut Interpreter,
        thread: &mut EmulationThread,
        context: &EmulationContext,
        current_method: Token,
    ) -> Result<LoopAction> {
        // Get return value from stack if method returns value
        let return_value = if context.method_returns_value(current_method)? {
            Some(thread.pop()?)
        } else {
            None
        };

        // Trace return if enabled
        if self.trace_calls_enabled()
            && self.trace_filter_passes(current_method, thread.call_depth() as u32)
        {
            let cid = thread.current_frame().map_or(0, |f| f.call_id());
            self.trace(TraceEvent::MethodReturn {
                method: current_method,
                has_return_value: return_value.is_some(),
                call_depth: thread.call_depth(),
                call_id: cid,
            });
        }

        // Pop the call frame (this is the callee's frame)
        let mut popped_frame = thread.pop_frame();

        // If the popped frame was a .cctor, mark the type as Initialized
        if let Some(ref frame) = popped_frame {
            if frame.is_cctor() {
                if let Some(type_token) = context
                    .assembly()
                    .resolver()
                    .declaring_type(frame.method())
                    .map(|t| t.token)
                {
                    self.context
                        .address_space
                        .statics()
                        .mark_type_initialized(type_token)?;
                }
            }
        }

        if thread.call_depth() == 0 {
            return Ok(LoopAction::Return(Box::new(EmulationOutcome::Completed {
                return_value,
                instructions: interpreter.stats().instructions_executed,
            })));
        }

        // Multicast delegate continuation
        if thread.has_multicast_state() {
            let depth = thread.call_depth();
            if let Some(mut mc) = thread.take_multicast_state() {
                if mc.dispatch_depth == depth && !mc.remaining_entries.is_empty() {
                    let next_entry = mc.remaining_entries.remove(0);
                    let delegate_args = mc.delegate_args.clone();

                    if !mc.remaining_entries.is_empty() {
                        thread.set_multicast_state(mc);
                    }

                    if let Some(callee_frame) = &mut popped_frame {
                        let caller_stack = callee_frame.take_caller_stack();
                        thread.restore_stack(caller_stack)?;
                    }

                    for arg in &delegate_args {
                        thread.push(arg.clone())?;
                    }

                    let target_token = next_entry.method_token;
                    match self.call_resolver.resolve_call(
                        context,
                        target_token,
                        thread,
                        false,
                        None,
                        &self.context.address_space,
                    )? {
                        CallResolution::EnterMethod {
                            token: t,
                            arguments,
                            expects_return,
                            assembly_index: _,
                            method_type_args,
                        } => {
                            callresolver::push_method_frame(
                                interpreter,
                                thread,
                                context,
                                t,
                                arguments,
                                expects_return,
                            )?;
                            if let Some(args) = method_type_args {
                                if let Some(frame) = thread.current_frame_mut() {
                                    frame.set_method_type_args(args);
                                }
                            }
                            return Ok(LoopAction::Continue);
                        }
                        CallResolution::HookedBypass { return_value: rv }
                        | CallResolution::ReturnSynthetic { value: rv } => {
                            if let Some(v) = rv {
                                if !thread.has_multicast_state() {
                                    thread.push(v)?;
                                }
                            }
                            if let Some(callee_frame) = &popped_frame {
                                if let Some(return_method) = callee_frame.return_method() {
                                    interpreter.set_method(return_method);
                                    interpreter.set_offset(callee_frame.return_offset());
                                }
                            }
                            return Ok(LoopAction::Continue);
                        }
                        CallResolution::Redirect {
                            target_token: redirect_target,
                            arguments,
                            ..
                        } => {
                            for arg in arguments {
                                thread.push(arg)?;
                            }
                            match self.call_resolver.resolve_call(
                                context,
                                redirect_target,
                                thread,
                                false,
                                None,
                                &self.context.address_space,
                            )? {
                                CallResolution::EnterMethod {
                                    token: t,
                                    arguments: args,
                                    expects_return,
                                    ..
                                } => {
                                    callresolver::push_method_frame(
                                        interpreter,
                                        thread,
                                        context,
                                        t,
                                        args,
                                        expects_return,
                                    )?;
                                    return Ok(LoopAction::Continue);
                                }
                                _ => {
                                    return Ok(LoopAction::Continue);
                                }
                            }
                        }
                        _ => {
                            // ThrowException or other — abort multicast chain
                            thread.take_multicast_state();
                        }
                    }
                } else {
                    if !mc.remaining_entries.is_empty() {
                        thread.set_multicast_state(mc);
                    }
                }
            }
        }

        // Restore caller's state
        if let Some(callee_frame) = &mut popped_frame {
            let caller_stack = callee_frame.take_caller_stack();
            thread.restore_stack(caller_stack)?;

            let saved_leave_target = callee_frame.take_saved_leave_target();
            if saved_leave_target.is_some() {
                thread
                    .exception_state_mut()
                    .set_leave_target(saved_leave_target);
            }

            if let Some(return_method) = callee_frame.return_method() {
                interpreter.set_method(return_method);
                interpreter.set_offset(callee_frame.return_offset());
            }
        }

        // Push return value onto caller's stack
        if let Some(value) = return_value {
            thread.push(value)?;
        }

        Ok(LoopAction::Continue)
    }
}

impl Default for EmulationController {
    fn default() -> Self {
        // Loop with a fresh RwLock each iteration. `CallResolver::new` only fails
        // on RwLock poison, which is impossible on a freshly-allocated lock; the
        // loop is therefore guaranteed to terminate on the first iteration.
        loop {
            let address_space = Arc::new(AddressSpace::new());
            let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
            let context = Arc::new(ThreadContext::new(
                address_space,
                Arc::new(RwLock::new(RuntimeState::new())),
                Arc::new(CaptureContext::default()),
                Arc::new(EmulationConfig::default()),
                None,
                fake_objects,
                Arc::new(VirtualFs::new()),
            ));
            if let Ok(ctrl) = Self::new(context, None) {
                return ctrl;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use dashmap::DashMap;

    use super::*;
    use crate::{
        emulation::{
            engine::typeops, process::UnknownMethodBehavior, Hook, LimitExceeded, PreHookResult,
            ProcessBuilder,
        },
        testkit::{
            emulation::{create_test_thread, emulation_config},
            fixture,
        },
        CilObject,
    };

    /// Runs crafted_2.exe's entry point under a budget of `limit` instructions, with a hook on
    /// `Console.WriteLine` that charges `units` of native work.
    fn run_charging(units: u64, limit: u64) -> EmulationOutcome {
        let assembly = Arc::new(CilObject::from_path(fixture("crafted_2.exe")).unwrap());
        let entry = Token::new(assembly.cor20header().entry_point_token);
        let process = ProcessBuilder::new()
            .assembly_arc(assembly)
            .with_max_instructions(limit)
            .hook(
                Hook::new("charge")
                    .match_name("System", "Console", "WriteLine")
                    .pre(move |_, thread| {
                        thread.charge_work(units);
                        PreHookResult::Bypass(None)
                    }),
            )
            .build()
            .unwrap();
        process.execute_method(entry, vec![]).unwrap()
    }

    /// Native work a hook charges counts as instructions: past the budget the run ends at
    /// its next limit check, as a long IL loop would.
    #[test]
    fn hook_work_counts_against_the_instruction_budget() {
        let free = run_charging(0, 100_000);
        assert!(
            !matches!(free, EmulationOutcome::LimitReached { .. }),
            "{free:?}"
        );
        let charged = run_charging(1_000_000, 100_000);
        assert!(
            matches!(
                charged,
                EmulationOutcome::LimitReached {
                    limit: LimitExceeded::Instructions { .. },
                    ..
                }
            ),
            "{charged:?}"
        );
    }

    /// Helper function to create a controller for testing with default infrastructure.
    fn create_test_controller() -> EmulationController {
        EmulationController::default()
    }

    /// Helper function to create a controller with custom runtime.
    fn create_test_controller_with_runtime(
        runtime: Arc<RwLock<RuntimeState>>,
    ) -> EmulationController {
        let address_space = Arc::new(AddressSpace::new());
        let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
        let context = Arc::new(ThreadContext::new(
            address_space,
            runtime,
            Arc::new(CaptureContext::default()),
            Arc::new(emulation_config()),
            None,
            fake_objects,
            Arc::new(VirtualFs::new()),
        ));
        EmulationController::new(context, None).unwrap()
    }

    /// Creates a minimal [`EmulationContext`] for unit tests.
    ///
    /// Uses crafted_2.exe as a test assembly.
    fn create_test_context() -> EmulationContext {
        let path = fixture("crafted_2.exe");
        let assembly = CilObject::from_path(&path).expect("Failed to load test assembly");
        EmulationContext::new(Arc::new(assembly), Arc::new(DashMap::new()))
    }

    #[test]
    fn test_controller_creation() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let controller = create_test_controller_with_runtime(runtime);
        // RuntimeState::new() initializes with default hooks
        assert!(!controller.runtime().read().unwrap().hooks().is_empty());
    }

    #[test]
    fn test_controller_with_custom_limits() {
        // Use default controller and verify limits from config
        let controller = create_test_controller();

        // Default config has default limits
        assert!(controller.limits().max_instructions > 0);
        assert!(controller.limits().max_call_depth > 0);
    }

    #[test]
    fn test_controller_with_runtime() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let controller = create_test_controller_with_runtime(runtime);

        // Verify runtime is set and hooks are accessible
        // RuntimeState::new() initializes with default hooks
        let guard = controller.runtime().read().unwrap();
        assert!(
            !guard.hooks().is_empty(),
            "RuntimeState should have default hooks"
        );
    }

    // Note: Static field tests are in addressspace.rs and statics.rs
    // Note: Type size tests are in context.rs (get_type_size and flavor_to_size)

    #[test]
    fn test_hook_registration() {
        let runtime = Arc::new(RwLock::new(RuntimeState::new()));
        let _controller = create_test_controller_with_runtime(runtime.clone());
        let initial_count = runtime.read().unwrap().hooks().len();

        // RuntimeState::new() should have default hooks registered (BCL + native)
        assert!(initial_count > 0, "Should have default hooks registered");

        // Set unknown method behavior
        runtime
            .write()
            .unwrap()
            .set_unknown_method_behavior(UnknownMethodBehavior::Fail);

        // Hook count should remain the same
        assert_eq!(runtime.read().unwrap().hooks().len(), initial_count);

        // Verify behavior was set
        assert_eq!(
            runtime.read().unwrap().unknown_method_behavior(),
            UnknownMethodBehavior::Fail
        );
    }

    #[test]
    fn test_limits_accessors() {
        // Limits come from EmulationConfig via the Default implementation
        let controller = create_test_controller();

        // Default config has reasonable limits
        assert!(controller.limits().max_instructions > 0);
        assert!(controller.limits().max_call_depth > 0);
    }

    // Note: ExceptionState tests were moved to exception/state.rs with ThreadExceptionState

    #[test]
    fn test_handle_box() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Push a value to box
        thread.push(EmValue::I32(42)).unwrap();

        // Box it
        typeops::handle_box(&mut thread, None, type_token).unwrap();

        // Should have a boxed reference on stack
        let result = thread.pop().unwrap();
        assert!(matches!(result, EmValue::ObjectRef(_)));

        // Verify the boxed value
        if let EmValue::ObjectRef(href) = result {
            let unboxed = thread.heap().get_boxed_value(href).unwrap();
            assert_eq!(unboxed, EmValue::I32(42));
        }
    }

    #[test]
    fn test_handle_unbox() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Allocate a boxed value
        let boxed_ref = thread
            .heap_mut()
            .alloc_boxed(type_token, EmValue::I64(100))
            .unwrap();
        thread.push(EmValue::ObjectRef(boxed_ref)).unwrap();

        // Unbox it
        typeops::handle_unbox(&mut thread, None, type_token).unwrap();

        // Should have the unboxed value
        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::I64(100));
    }

    #[test]
    fn test_handle_unbox_null_fails() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        thread.push(EmValue::Null).unwrap();

        let result = typeops::handle_unbox(&mut thread, None, type_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_unbox_already_unboxed() {
        let type_token = Token::new(0x02000001);
        let mut thread = create_test_thread();

        // Push an already unboxed value
        thread.push(EmValue::F64(std::f64::consts::PI)).unwrap();

        // Unbox should pass it through
        typeops::handle_unbox(&mut thread, None, type_token).unwrap();

        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::F64(std::f64::consts::PI));
    }

    // Note: sizeof tests are in context.rs (get_type_size, flavor_to_size)
    // handle_sizeof requires an EmulationContext for type size lookup

    #[test]
    fn test_handle_ldsfld_known_field() {
        let controller = EmulationController::default();
        let context = create_test_context();
        let field = Token::new(0x04000001);
        let mut thread = create_test_thread();

        // Set a static field value via AddressSpace
        controller
            .address_space()
            .set_static(field, EmValue::I32(999))
            .unwrap();

        typeops::handle_ldsfld(controller.address_space(), &mut thread, &context, field).unwrap();

        let result = thread.pop().unwrap();
        assert_eq!(result, EmValue::I32(999));
    }

    #[test]
    fn test_handle_ldsfld_unknown_returns_null() {
        let controller = EmulationController::default();
        let context = create_test_context();
        let field = Token::new(0x04000099); // Unknown field
        let mut thread = create_test_thread();

        typeops::handle_ldsfld(controller.address_space(), &mut thread, &context, field).unwrap();

        let result = thread.pop().unwrap();
        // .NET zero-initializes static fields; unknown type defaults to Null
        assert!(matches!(result, EmValue::Null));
    }

    #[test]
    fn test_heap_array_creation() {
        let mut thread = create_test_thread();

        // Test array creation directly via heap - this is what handle_newarr does internally
        let array_ref = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();
        thread.push(EmValue::ObjectRef(array_ref)).unwrap();

        // Verify array was created
        let result = thread.pop().unwrap();
        if let EmValue::ObjectRef(href) = result {
            let len = thread.heap().get_array_length(href).unwrap();
            assert_eq!(len, 5);
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_heap_array_element_access() {
        let thread = create_test_thread();

        // Create array and set elements
        let array_ref = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();

        // Set elements
        thread
            .heap_mut()
            .set_array_element(array_ref, 0, EmValue::I32(10))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(array_ref, 1, EmValue::I32(20))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(array_ref, 2, EmValue::I32(30))
            .unwrap();

        // Verify elements
        assert_eq!(
            thread.heap().get_array_element(array_ref, 0).unwrap(),
            EmValue::I32(10)
        );
        assert_eq!(
            thread.heap().get_array_element(array_ref, 1).unwrap(),
            EmValue::I32(20)
        );
        assert_eq!(
            thread.heap().get_array_element(array_ref, 2).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_heap_string_creation() {
        let thread = create_test_thread();

        // Create string on heap
        let str_ref = thread.heap().alloc_string("Hello, World!").unwrap();

        // Verify string content
        let content = thread.heap().get_string(str_ref).unwrap();
        assert_eq!(&*content, "Hello, World!");
    }
}
