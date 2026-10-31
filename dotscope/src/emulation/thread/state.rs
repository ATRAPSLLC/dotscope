//! Emulation thread implementation.
//!
//! This module provides the per-thread execution state for .NET emulation,
//! including the call stack, evaluation stack, instruction pointer, and
//! exception handling state.
//!
//! # Thread Structure
//!
//! Each emulation thread maintains:
//!
//! - **Call Stack**: Stack of [`ThreadCallFrame`]s representing method calls
//! - **Evaluation Stack**: The CIL evaluation stack for intermediate values
//! - **Exception State**: Current exception handling context
//! - **Thread-Local Storage**: Per-thread data storage
//!
//! # Call Frame Layout
//!
//! Each call frame ([`ThreadCallFrame`]) contains:
//!
//! - Method token identifying the executing method
//! - Local variables storage
//! - Argument storage
//! - Instruction pointer (current offset in method body)
//! - Saved caller stack for method returns
//!
//! # Thread States
//!
//! Threads transition through [`ThreadState`]:
//!
//! 1. `Ready` - Created but not yet running
//! 2. `Running` - Actively executing instructions
//! 3. `Waiting` - Blocked on synchronization ([`WaitReason`] specifies why)
//! 4. Terminal: `Completed`, `Faulted`, or `Aborted`
//!
//! # Example
//!
//! ```no_run
//! use dotscope::emulation::EmulationThread;
//! use dotscope::emulation::ThreadCallFrame;
//!
//! // Create a thread
//! let mut thread = EmulationThread::new(thread_id, address_space, capture, assembly);
//!
//! // Start executing a method
//! thread.start_method(method_token, locals, args, expects_return);
//!
//! // Push/pop values on evaluation stack
//! thread.push(EmValue::I32(42))?;
//! let value = thread.pop()?;
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, RwLock},
};

use crate::{
    emulation::{
        capture::CaptureContext,
        engine::{EmulationError, SyntheticMethodBody},
        exception::ThreadExceptionState,
        fakeobjects::SharedFakeObjects,
        filesystem::VirtualFs,
        memory::{AddressSpace, DelegateEntry, HeapObject, ManagedHeap},
        process::EmulationConfig,
        runtime::RuntimeState,
        thread::ThreadContext,
        value::PointerTarget,
        ArgumentStorage, EmValue, EvaluationStack, HeapRef, LocalVariables, ManagedPointer,
        ThreadId,
    },
    metadata::{
        token::Token,
        typesystem::{CilFlavor, PointerSize},
    },
    CilObject, Error, Result,
};

/// Thread execution state.
///
/// Represents the current lifecycle stage of an emulation thread. Threads
/// progress through these states during their lifetime, with `Completed`,
/// `Faulted`, and `Aborted` being terminal states.
///
/// # State Transitions
///
/// ```text
/// Ready -> Running -> Completed
///            |           ^
///            v           |
///       Waiting --------'
///            |
///            v
///       Faulted / Aborted
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ThreadState {
    /// Thread is ready to execute but not currently running.
    ///
    /// Threads start in this state and return to it when preempted or
    /// after being woken from a wait.
    #[default]
    Ready,

    /// Thread is currently executing instructions.
    ///
    /// Only one thread can be in this state at a time within a single
    /// scheduler context.
    Running,

    /// Thread is blocked waiting for a condition.
    ///
    /// The [`WaitReason`] specifies what the thread is waiting for.
    Waiting(WaitReason),

    /// Thread completed execution normally.
    ///
    /// The return value (if any) can be retrieved from the thread.
    Completed,

    /// Thread terminated with an unhandled exception.
    ///
    /// The exception details can be retrieved from the thread's exception state.
    Faulted,

    /// Thread was explicitly aborted.
    ///
    /// This occurs when `Thread.Abort()` is called or during forced termination.
    Aborted,
}

/// Reason a thread is blocked in the [`ThreadState::Waiting`] state.
///
/// This enum provides context about what synchronization primitive or
/// condition the thread is waiting for. The scheduler uses this information
/// to determine when to wake the thread.
///
/// Most variants include a [`HeapRef`] identifying the specific synchronization
/// object being waited on. This allows the scheduler to correctly wake threads
/// when the corresponding object is signaled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitReason {
    /// Waiting to acquire a monitor lock (`Monitor.Enter` / `lock`).
    ///
    /// Contains the heap reference of the object being used as a monitor.
    Monitor(HeapRef),

    /// Waiting for an event to be signaled (`WaitHandle.WaitOne`).
    ///
    /// Contains the heap reference of the event object.
    Event(HeapRef),

    /// Waiting for another thread to complete (`Thread.Join`).
    ///
    /// Contains the ID of the thread being waited on.
    Thread(ThreadId),

    /// Sleeping for a specified duration (`Thread.Sleep`).
    ///
    /// The thread should wake when the virtual instruction count reaches
    /// or exceeds `until_instruction`.
    Sleep {
        /// Virtual instruction count at which to wake the thread.
        until_instruction: u64,
    },

    /// Waiting to acquire a mutex (`Mutex.WaitOne`).
    ///
    /// Contains the heap reference of the mutex object.
    Mutex(HeapRef),

    /// Waiting to acquire a semaphore slot (`Semaphore.WaitOne`).
    ///
    /// Contains the heap reference of the semaphore object.
    Semaphore(HeapRef),
}

/// Thread priority levels for scheduling.
///
/// Higher priority threads are scheduled before lower priority threads.
/// Within the same priority level, threads are scheduled in FIFO order.
///
/// These correspond to the .NET `ThreadPriority` enumeration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ThreadPriority {
    /// Lowest scheduling priority.
    Lowest = 0,

    /// Below normal scheduling priority.
    BelowNormal = 1,

    /// Normal (default) scheduling priority.
    #[default]
    Normal = 2,

    /// Above normal scheduling priority.
    AboveNormal = 3,

    /// Highest scheduling priority.
    Highest = 4,
}

/// A call frame on the thread's call stack.
///
/// Each method invocation creates a new call frame that stores the method's
/// execution context: local variables, arguments, instruction pointer, and
/// information needed to return to the caller.
///
/// # Stack Management
///
/// When a method call occurs:
/// 1. A new frame is pushed with the callee's locals and arguments
/// 2. The caller's evaluation stack is saved in the new frame
/// 3. Execution continues in the callee
///
/// When a method returns:
/// 1. The frame is popped
/// 2. The caller's evaluation stack is restored
/// 3. Any return value is pushed onto the restored stack
#[derive(Clone, Debug)]
pub struct ThreadCallFrame {
    /// Metadata token of the method being executed.
    method: Token,

    /// Method token of the caller (used for return navigation).
    return_method: Option<Token>,

    /// Instruction offset in the caller to return to.
    return_offset: u32,

    /// Local variables storage for this method.
    locals: LocalVariables,

    /// Arguments passed to this method.
    arguments: ArgumentStorage,

    /// Current instruction pointer (byte offset in method body).
    instruction_offset: u32,

    /// Whether the caller expects a return value to be pushed.
    expects_return: bool,

    /// Saved evaluation stack from the caller (restored on return).
    caller_stack: Vec<EmValue>,

    /// Saved leave target from the caller's exception state.
    ///
    /// When a method call happens from within a finally handler, the caller's
    /// leave target must be preserved. Without this, the callee's own `leave`
    /// instructions would overwrite the shared `leave_target` field on the
    /// thread's exception state, causing the caller's `endfinally` to lose
    /// its leave target and incorrectly fall through to exception propagation.
    saved_leave_target: Option<u32>,

    /// Whether this frame was entered via a `MethodBase.Invoke` / reflection
    /// invoke redirect. When an exception propagates out of such a frame, it
    /// must be wrapped in `TargetInvocationException`, mirroring real .NET
    /// behavior where `MethodBase.Invoke` wraps all target exceptions.
    is_reflection_invoke: bool,

    /// Whether this frame is executing a static constructor (.cctor).
    /// When an unhandled exception propagates out of a .cctor frame, it
    /// should be recorded in the [`CctorTracker`](crate::emulation::engine::cctors::CctorTracker)
    /// so that subsequent accesses to the type re-throw the same exception.
    is_cctor: bool,

    /// Type arguments from the declaring type's generic instantiation (!0, !1, ...).
    type_type_args: Option<Vec<Token>>,

    /// Type arguments from the method's generic instantiation (!!0, !!1, ...).
    method_type_args: Option<Vec<Token>>,

    /// Trace call ID assigned when this frame was created, for correlating returns.
    call_id: u64,

    /// Index of the assembly this frame's method belongs to.
    ///
    /// `None` means the primary assembly (the one loaded at process start).
    /// `Some(i)` refers to the i-th dynamically loaded assembly registered in
    /// [`AppDomainState`](crate::emulation::runtime::AppDomainState).
    ///
    /// This enables cross-assembly execution: when a method from a dynamically
    /// loaded assembly calls another method, the controller uses this index to
    /// fetch instructions and resolve metadata from the correct assembly.
    assembly_index: Option<u32>,
}

impl ThreadCallFrame {
    /// Creates a new call frame for a method invocation.
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method being called
    /// * `return_method` - Token of the caller method (for return navigation)
    /// * `return_offset` - Instruction offset to return to in the caller
    /// * `local_types` - Types of local variables declared in the method
    /// * `args` - Arguments passed to the method (value and type pairs)
    /// * `expects_return` - Whether the caller expects a return value
    #[must_use]
    pub fn new(
        method: Token,
        return_method: Option<Token>,
        return_offset: u32,
        local_types: Vec<CilFlavor>,
        args: Vec<(EmValue, CilFlavor)>,
        expects_return: bool,
    ) -> Self {
        let (arg_values, arg_types): (Vec<_>, Vec<_>) = args.into_iter().unzip();
        Self {
            method,
            return_method,
            return_offset,
            locals: LocalVariables::new(local_types),
            arguments: ArgumentStorage::new(arg_values, arg_types),
            instruction_offset: 0,
            expects_return,
            caller_stack: Vec::new(),
            saved_leave_target: None,
            is_reflection_invoke: false,
            is_cctor: false,
            type_type_args: None,
            method_type_args: None,
            call_id: 0,
            assembly_index: None,
        }
    }

    /// Returns the method token for this frame.
    #[must_use]
    pub fn method(&self) -> Token {
        self.method
    }

    /// Returns the method token to return to (the caller).
    #[must_use]
    pub fn return_method(&self) -> Option<Token> {
        self.return_method
    }

    /// Returns the instruction offset to resume at in the caller.
    #[must_use]
    pub fn return_offset(&self) -> u32 {
        self.return_offset
    }

    /// Returns the current instruction pointer (byte offset in method body).
    #[must_use]
    pub fn ip(&self) -> u32 {
        self.instruction_offset
    }

    /// Sets the instruction pointer to a specific offset.
    ///
    /// Used for jumps, branches, and exception handling.
    pub fn set_ip(&mut self, offset: u32) {
        self.instruction_offset = offset;
    }

    /// Advances the instruction pointer by the given delta.
    ///
    /// Typically called after executing an instruction to move to the next one.
    pub fn advance_ip(&mut self, delta: u32) {
        self.instruction_offset = self.instruction_offset.saturating_add(delta);
    }

    /// Returns whether the caller expects a return value.
    #[must_use]
    pub fn expects_return(&self) -> bool {
        self.expects_return
    }

    /// Returns the number of local variables in this frame.
    #[must_use]
    pub fn local_count(&self) -> usize {
        self.locals.count()
    }

    /// Gets a local variable by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_local(&self, index: u16) -> Option<&EmValue> {
        self.locals.get(index as usize).ok()
    }

    /// Sets a local variable by index.
    ///
    /// Returns `true` on success, `false` if the index is out of bounds.
    pub fn set_local(&mut self, index: u16, value: EmValue) -> bool {
        self.locals.set(index as usize, value).is_ok()
    }

    /// Returns the type of a local variable.
    #[must_use]
    pub fn local_type(&self, index: u16) -> Option<&CilFlavor> {
        self.locals.get_type(index as usize).ok()
    }

    /// Returns the number of arguments in this frame.
    #[must_use]
    pub fn argument_count(&self) -> usize {
        self.arguments.count()
    }

    /// Gets an argument by index.
    ///
    /// Returns `None` if the index is out of bounds.
    #[must_use]
    pub fn get_argument(&self, index: u16) -> Option<&EmValue> {
        self.arguments.get(index as usize).ok()
    }

    /// Sets an argument by index (for `starg` instruction).
    ///
    /// Returns `true` on success, `false` if the index is out of bounds.
    pub fn set_argument(&mut self, index: u16, value: EmValue) -> bool {
        self.arguments.set(index as usize, value).is_ok()
    }

    /// Returns the type of an argument.
    #[must_use]
    pub fn argument_type(&self, index: u16) -> Option<&CilFlavor> {
        self.arguments.get_type(index as usize).ok()
    }

    /// Saves the caller's evaluation stack for later restoration.
    ///
    /// Called when entering a new method to preserve the caller's stack state.
    pub fn save_caller_stack(&mut self, stack: Vec<EmValue>) {
        self.caller_stack = stack;
    }

    /// Takes the saved caller's stack, leaving an empty vector.
    ///
    /// Used when returning from a method to restore the caller's stack.
    pub fn take_caller_stack(&mut self) -> Vec<EmValue> {
        std::mem::take(&mut self.caller_stack)
    }

    /// Returns a reference to the saved caller's stack.
    #[must_use]
    pub fn caller_stack(&self) -> &[EmValue] {
        &self.caller_stack
    }

    /// Saves the caller's leave target for later restoration.
    ///
    /// Called when entering a new method from within a finally handler to
    /// prevent the callee's `leave` instructions from clobbering the
    /// caller's leave target in the shared exception state.
    pub fn save_leave_target(&mut self, target: Option<u32>) {
        self.saved_leave_target = target;
    }

    /// Takes the saved leave target, leaving `None`.
    ///
    /// Used when returning from a method to restore the caller's leave target.
    pub fn take_saved_leave_target(&mut self) -> Option<u32> {
        self.saved_leave_target.take()
    }

    /// Marks this frame as entered via a reflection invoke (MethodBase.Invoke).
    ///
    /// When an exception propagates out of such a frame, the exception routing
    /// converts the exception type to `TargetInvocationException`.
    pub fn set_reflection_invoke(&mut self) {
        self.is_reflection_invoke = true;
    }

    /// Returns whether this frame was entered via a reflection invoke.
    #[must_use]
    pub fn is_reflection_invoke(&self) -> bool {
        self.is_reflection_invoke
    }

    /// Marks this frame as executing a static constructor (.cctor).
    pub fn set_is_cctor(&mut self) {
        self.is_cctor = true;
    }

    /// Returns whether this frame is executing a .cctor.
    #[must_use]
    pub fn is_cctor(&self) -> bool {
        self.is_cctor
    }

    /// Sets the type arguments from the declaring type's generic instantiation.
    pub fn set_type_type_args(&mut self, args: Vec<Token>) {
        self.type_type_args = Some(args);
    }

    /// Returns the type arguments from the declaring type (!0, !1, ...).
    #[must_use]
    pub fn type_type_args(&self) -> Option<&[Token]> {
        self.type_type_args.as_deref()
    }

    /// Sets the method-level type arguments from a MethodSpec (!!0, !!1, ...).
    pub fn set_method_type_args(&mut self, args: Vec<Token>) {
        self.method_type_args = Some(args);
    }

    /// Returns the method-level type arguments (!!0, !!1, ...).
    #[must_use]
    pub fn method_type_args(&self) -> Option<&[Token]> {
        self.method_type_args.as_deref()
    }

    /// Sets the trace call ID for correlating method returns with their calls.
    pub fn set_call_id(&mut self, call_id: u64) {
        self.call_id = call_id;
    }

    /// Returns the trace call ID assigned when this frame was created.
    #[must_use]
    pub fn call_id(&self) -> u64 {
        self.call_id
    }

    /// Sets the assembly index for this frame.
    ///
    /// `None` = primary assembly, `Some(i)` = i-th dynamically loaded assembly.
    pub fn set_assembly_index(&mut self, index: Option<u32>) {
        self.assembly_index = index;
    }

    /// Returns the assembly index for this frame.
    ///
    /// `None` = primary assembly, `Some(i)` = i-th dynamically loaded assembly.
    #[must_use]
    pub fn assembly_index(&self) -> Option<u32> {
        self.assembly_index
    }

    /// Returns a reference to the local variables storage.
    #[must_use]
    pub fn locals(&self) -> &LocalVariables {
        &self.locals
    }

    /// Returns a mutable reference to the local variables storage.
    pub fn locals_mut(&mut self) -> &mut LocalVariables {
        &mut self.locals
    }

    /// Returns a reference to the arguments storage.
    #[must_use]
    pub fn arguments(&self) -> &ArgumentStorage {
        &self.arguments
    }

    /// Returns a mutable reference to the arguments storage.
    pub fn arguments_mut(&mut self) -> &mut ArgumentStorage {
        &mut self.arguments
    }
}

/// Per-thread execution state for .NET emulation.
///
/// `EmulationThread` represents a single managed thread in the emulated
/// .NET runtime. It maintains all thread-local state including:
///
/// - Call stack with method frames
/// - CIL evaluation stack
/// - Exception handling context
/// - Thread-local storage
///
/// # Shared State
///
/// Threads share access to:
/// - Address space (managed heap, statics, unmanaged memory)
/// - Capture context (for recording decrypted strings, etc.)
/// - Assembly metadata
///
/// # Example
///
/// ```no_run
/// // Create a new thread
/// let thread = EmulationThread::new(
///     ThreadId::new(1),
///     address_space,
///     capture,
///     Some(assembly),
/// );
///
/// // Or create the main thread with ID 1
/// let main = EmulationThread::main(address_space, capture, Some(assembly));
/// ```
pub struct EmulationThread {
    /// Unique identifier for this thread.
    id: ThreadId,

    /// Optional name for debugging (e.g., "Main", "Worker-1").
    name: Option<String>,

    /// Scheduling priority.
    priority: ThreadPriority,

    /// Current execution state.
    state: ThreadState,

    /// Call stack of method frames.
    call_stack: Vec<ThreadCallFrame>,

    /// CIL evaluation stack for intermediate values.
    eval_stack: EvaluationStack,

    /// Exception handling state (current exception, handler stack).
    exception_state: ThreadExceptionState,

    /// Thread-local storage (field token -> value).
    tls: HashMap<Token, EmValue>,

    /// Shared process environment (address space, runtime, capture, config, etc.).
    context: Arc<ThreadContext>,

    /// Total instructions executed by this thread.
    instructions_executed: u64,

    /// Native work hooks do for this thread, against the emulation's instruction budget.
    work: WorkMeter,

    /// Return value when thread completes.
    return_value: Option<EmValue>,

    /// Pending multicast delegate invocation state.
    ///
    /// When a delegate with multiple entries in its invocation list is invoked,
    /// the first entry is dispatched immediately and remaining entries are stored
    /// here. After each entry's method returns, the controller checks this state
    /// and dispatches the next entry until all are exhausted.
    multicast_state: Option<MulticastState>,
}

/// The native work hooks do for a thread (key derivation rounds, modular exponentiation),
/// measured in the units of the emulation's instruction budget: an expensive call costs
/// what the IL that computed it would, so it ends the run where a long loop would rather
/// than under a ceiling of its own.
#[derive(Debug, Clone, Copy, Default)]
struct WorkMeter {
    /// Instructions the run had executed when the current step began
    executed: u64,
    /// The run's instruction budget, 0 for none
    limit: u64,
    /// Work charged since the step began
    charged: u64,
}

/// State for tracking multicast delegate invocation progress.
///
/// When a delegate's `Invoke` is called and the invocation list has multiple
/// entries, the dispatcher stores remaining entries and the original arguments
/// here. The controller processes one entry at a time; only the last entry's
/// return value is propagated to the caller.
#[derive(Debug, Clone)]
pub struct MulticastState {
    /// Remaining delegate entries to invoke (front = next to dispatch).
    pub remaining_entries: Vec<DelegateEntry>,
    /// Arguments passed to each delegate entry (excluding the 'this' delegate ref).
    pub delegate_args: Vec<EmValue>,
    /// Call depth when multicast dispatch started, used to detect when
    /// the current entry's method has returned back to the dispatch level.
    pub dispatch_depth: usize,
}

/// A request to invoke a method via reflection.
///
/// Used by stubs to signal that a reflected method should be invoked.
#[derive(Debug, Clone)]
pub struct ReflectionInvokeRequest {
    /// The method token to invoke.
    pub method_token: Token,
    /// The 'this' reference for instance methods (None for static).
    pub this_ref: Option<EmValue>,
    /// Arguments to pass to the method.
    pub args: Vec<EmValue>,
    /// Method-level generic type arguments (from `MakeGenericMethod`).
    pub method_type_args: Option<Vec<Token>>,
}

impl fmt::Debug for EmulationThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EmulationThread")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("priority", &self.priority)
            .field("state", &self.state)
            .field("call_stack", &self.call_stack)
            .field("eval_stack", &self.eval_stack)
            .field("exception_state", &self.exception_state)
            .field("tls", &self.tls)
            .field("context", &"...")
            .field("instructions_executed", &self.instructions_executed)
            .field("return_value", &self.return_value)
            .finish_non_exhaustive()
    }
}

impl EmulationThread {
    /// Creates a new thread with the given shared context.
    ///
    /// The thread starts in the [`ThreadState::Ready`] state with normal
    /// priority and an empty call stack.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this thread
    /// * `context` - Shared process environment (address space, runtime, config, etc.)
    pub fn new(id: ThreadId, context: Arc<ThreadContext>) -> Self {
        Self {
            id,
            name: None,
            priority: ThreadPriority::Normal,
            state: ThreadState::Ready,
            call_stack: Vec::new(),
            eval_stack: EvaluationStack::new(1000),
            exception_state: ThreadExceptionState::new(),
            tls: HashMap::new(),
            context,
            instructions_executed: 0,
            work: WorkMeter::default(),
            return_value: None,
            multicast_state: None,
        }
    }

    /// Creates the main thread (ID 1) with the name "Main".
    ///
    /// This is a convenience constructor for creating the primary thread
    /// that typically executes the program's entry point.
    pub fn main(context: Arc<ThreadContext>) -> Self {
        let mut thread = Self::new(ThreadId::MAIN, context);
        thread.name = Some("Main".to_string());
        thread
    }

    /// Returns a reference to the shared thread context.
    #[must_use]
    pub fn context(&self) -> &Arc<ThreadContext> {
        &self.context
    }

    /// Returns a reference to the shared fake BCL objects.
    ///
    /// BCL hooks use these pre-allocated objects to return consistent references
    /// for methods like `Assembly.GetExecutingAssembly()`.
    #[must_use]
    pub fn fake_objects(&self) -> &SharedFakeObjects {
        &self.context.fake_objects
    }

    /// Returns a reference to the virtual filesystem.
    #[must_use]
    pub fn virtual_fs(&self) -> &Arc<VirtualFs> {
        &self.context.virtual_fs
    }

    /// Returns a reference to the shared runtime state.
    ///
    /// Used by hooks to access the `AppDomainState` for registering
    /// dynamically loaded assemblies and querying runtime state.
    #[must_use]
    pub fn runtime_state(&self) -> &Arc<RwLock<RuntimeState>> {
        &self.context.runtime
    }

    /// Returns a reference to the emulation configuration.
    #[must_use]
    pub fn config(&self) -> &EmulationConfig {
        &self.context.config
    }

    /// Returns the capture context for recording emulation artifacts.
    ///
    /// Stubs can use this to capture decrypted strings, loaded assemblies,
    /// and other data discovered during emulation.
    #[must_use]
    pub fn capture(&self) -> &Arc<CaptureContext> {
        &self.context.capture
    }

    /// Returns the assembly being emulated.
    ///
    /// Stubs can use this to access metadata, type information, PE data,
    /// and other assembly-level data during emulation.
    #[must_use]
    pub fn assembly(&self) -> Option<&Arc<CilObject>> {
        self.context.assembly.as_ref()
    }

    /// Registers a synthetic method body and returns its unique token.
    ///
    /// Delegates to [`ThreadContext::register_synthetic_method`].
    pub fn register_synthetic_method(&self, body: SyntheticMethodBody) -> Token {
        self.context.register_synthetic_method(body)
    }

    /// Converts a type token to a [`CilFlavor`] via the primary assembly's
    /// type registry.
    ///
    /// Returns `None` if the assembly is not set or the token is unknown.
    #[must_use]
    pub fn type_token_to_cil_flavor(&self, token: Token) -> Option<CilFlavor> {
        let asm = self.context.assembly.as_ref()?;
        asm.types().get(&token).map(|t| t.flavor().clone())
    }

    /// Resolves a .NET type by namespace and name to its metadata token.
    ///
    /// Searches the primary assembly first, then any dynamically loaded assemblies
    /// registered via `Assembly.Load(byte[])`. This allows BCL hooks to tag
    /// heap-allocated wrapper objects with their correct .NET type identity,
    /// enabling virtual dispatch to work correctly.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The type's namespace (e.g., `"System.IO"`)
    /// * `name` - The type's name (e.g., `"MemoryStream"`)
    ///
    /// # Returns
    ///
    /// `Some(Token)` if the type is found, `None` if the assembly doesn't
    /// reference this type (falls back to synthetic tokens).
    #[must_use]
    pub fn resolve_type_token(&self, namespace: &str, name: &str) -> Option<Token> {
        // Check the primary assembly
        if let Some(asm) = &self.context.assembly {
            let fullname = if namespace.is_empty() {
                name.to_string()
            } else {
                format!("{namespace}.{name}")
            };
            if let Some(cil_type) = asm.types().get_by_fullname(&fullname, true) {
                return Some(cil_type.token);
            }
        }

        // Check dynamically loaded assemblies
        if let Ok(state) = self.context.runtime.read() {
            if let Some((_, token)) = state
                .app_domain()
                .find_type_across_assemblies(namespace, name)
            {
                return Some(token);
            }
        }

        None
    }

    /// Returns the thread's unique identifier.
    #[must_use]
    pub fn id(&self) -> ThreadId {
        self.id
    }

    /// Returns the thread's name, if set.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Sets the thread's name for debugging purposes.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = Some(name.into());
    }

    /// Returns the thread's scheduling priority.
    #[must_use]
    pub fn priority(&self) -> ThreadPriority {
        self.priority
    }

    /// Sets the thread's scheduling priority.
    pub fn set_priority(&mut self, priority: ThreadPriority) {
        self.priority = priority;
    }

    /// Returns the thread's current execution state.
    #[must_use]
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// Sets the thread's execution state.
    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Checks if the thread is ready to execute.
    ///
    /// Returns `true` if the thread is in `Ready` or `Running` state.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self.state, ThreadState::Ready | ThreadState::Running)
    }

    /// Checks if the thread has reached a terminal state.
    ///
    /// Returns `true` if the thread is `Completed`, `Faulted`, or `Aborted`.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(
            self.state,
            ThreadState::Completed | ThreadState::Faulted | ThreadState::Aborted
        )
    }

    /// Returns the current (topmost) call frame, if any.
    #[must_use]
    pub fn current_frame(&self) -> Option<&ThreadCallFrame> {
        self.call_stack.last()
    }

    /// Returns a mutable reference to the current call frame.
    pub fn current_frame_mut(&mut self) -> Option<&mut ThreadCallFrame> {
        self.call_stack.last_mut()
    }

    /// Returns the current call stack depth (number of frames).
    #[must_use]
    pub fn call_depth(&self) -> usize {
        self.call_stack.len()
    }

    /// Returns a reference to the call frame at the given depth (0-based index).
    #[must_use]
    pub fn get_frame_at(&self, depth: usize) -> Option<&ThreadCallFrame> {
        self.call_stack.get(depth)
    }

    /// Returns a mutable reference to the call frame at the given depth (0-based index).
    pub fn get_frame_at_mut(&mut self, depth: usize) -> Option<&mut ThreadCallFrame> {
        self.call_stack.get_mut(depth)
    }

    /// Returns a mutable reference to the frame at the given depth, falling back
    /// to the current (topmost) frame if the depth is out of range.
    pub fn resolve_frame_mut(&mut self, depth: usize) -> Option<&mut ThreadCallFrame> {
        let len = self.call_stack.len();
        if depth < len {
            self.call_stack.get_mut(depth)
        } else {
            self.call_stack.last_mut()
        }
    }

    /// Pushes a new call frame onto the call stack.
    ///
    /// Used when entering a method.
    pub fn push_frame(&mut self, frame: ThreadCallFrame) {
        self.call_stack.push(frame);
    }

    /// Pops and returns the current call frame.
    ///
    /// Used when returning from a method.
    ///
    /// Also discards any cleanup handlers still queued against the popped method. Such an entry
    /// can never run correctly — the handler IL reads locals, arguments and the evaluation stack
    /// from whatever frame happens to be current — and left in place it accumulates for the
    /// lifetime of the emulation.
    ///
    /// The check is against the *remaining* call stack rather than the popped method alone,
    /// because a recursive method occupies several frames at once and the outer frames' entries
    /// are still live.
    pub fn pop_frame(&mut self) -> Option<ThreadCallFrame> {
        let popped = self.call_stack.pop()?;

        let method = popped.method();
        if !self.call_stack.iter().any(|frame| frame.method() == method) {
            self.exception_state.discard_finally_for_method(method);
        }

        Some(popped)
    }

    /// Returns a reference to the evaluation stack.
    #[must_use]
    pub fn stack(&self) -> &EvaluationStack {
        &self.eval_stack
    }

    /// Returns a mutable reference to the evaluation stack.
    pub fn stack_mut(&mut self) -> &mut EvaluationStack {
        &mut self.eval_stack
    }

    /// Pushes a value onto the evaluation stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    pub fn push(&mut self, value: EmValue) -> Result<()> {
        self.eval_stack.push(value)
    }

    /// Pops a value from the evaluation stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is empty.
    pub fn pop(&mut self) -> Result<EmValue> {
        self.eval_stack.pop()
    }

    /// Pops multiple arguments from the evaluation stack in correct order.
    ///
    /// CIL method calls push arguments left-to-right, but they're popped in
    /// reverse order. This helper pops `count` values and returns them in
    /// the original left-to-right order (i.e., first parameter first).
    ///
    /// # Arguments
    ///
    /// * `count` - Number of arguments to pop
    ///
    /// # Returns
    ///
    /// A vector of arguments in left-to-right order (first argument at index 0).
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than `count` values.
    ///
    /// # Example
    ///
    /// ```no_run
    /// // For a method call like: Foo(arg1, arg2, arg3)
    /// // Stack before (top on right): [..., arg1, arg2, arg3]
    /// let args = thread.pop_args(3)?;
    /// // args = [arg1, arg2, arg3]
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn pop_args(&mut self, count: usize) -> Result<Vec<EmValue>> {
        let mut args = Vec::with_capacity(count);
        for _ in 0..count {
            args.push(self.eval_stack.pop()?);
        }
        args.reverse();
        Ok(args)
    }

    /// Peeks at multiple arguments on the evaluation stack without removing them.
    ///
    /// Similar to `pop_args`, but returns clones of the values without
    /// modifying the stack. Useful for hook matching where we need to
    /// inspect arguments before deciding whether to handle the call.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of arguments to peek at
    ///
    /// # Returns
    ///
    /// A vector of argument clones in left-to-right order.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack has fewer than `count` values.
    pub fn peek_args(&self, count: usize) -> Result<Vec<EmValue>> {
        let mut args = Vec::with_capacity(count);
        // Arguments are pushed left-to-right, so arg0 is at depth (count-1)
        // and argN is at depth 0 (top of stack)
        for i in 0..count {
            let depth = count.saturating_sub(1).saturating_sub(i);
            args.push(self.eval_stack.peek_at(depth)?.clone());
        }
        Ok(args)
    }

    /// Returns a reference to the exception handling state.
    #[must_use]
    pub fn exception_state(&self) -> &ThreadExceptionState {
        &self.exception_state
    }

    /// Returns a mutable reference to the exception handling state.
    pub fn exception_state_mut(&mut self) -> &mut ThreadExceptionState {
        &mut self.exception_state
    }

    /// Sets a pending multicast delegate invocation state.
    ///
    /// Called by the delegate dispatcher when a delegate with multiple entries
    /// in its invocation list is invoked. The remaining entries (after the first)
    /// and the original arguments are stored here for the controller to process.
    pub fn set_multicast_state(&mut self, state: MulticastState) {
        self.multicast_state = Some(state);
    }

    /// Takes and returns the pending multicast state, leaving `None` in its place.
    ///
    /// Called by the controller after a multicast entry's method returns to
    /// check if there are more entries to dispatch.
    pub fn take_multicast_state(&mut self) -> Option<MulticastState> {
        self.multicast_state.take()
    }

    /// Returns `true` if there is a pending multicast delegate invocation.
    #[must_use]
    pub fn has_multicast_state(&self) -> bool {
        self.multicast_state.is_some()
    }

    /// Returns a reference to the shared address space.
    #[must_use]
    pub fn address_space(&self) -> &AddressSpace {
        &self.context.address_space
    }

    /// Pins a managed array element to a native memory address.
    ///
    /// This implements the `fixed` / pinned array pattern: when CIL code takes
    /// the address of an array element via `ldelema` and converts it to a native
    /// pointer via `conv.i`/`conv.u`, the array must be accessible through
    /// the native address for subsequent `ldind.*`/`stind.*` and
    /// `Marshal.Read*`/`Write*` operations.
    ///
    /// The pinned array uses transparent shared backing: no data is copied.
    /// Instead, a native address range is reserved and registered with the
    /// address space. Reads and writes through the native address are
    /// transparently delegated to the managed heap's `Vec<EmValue>`,
    /// ensuring a single source of truth.
    ///
    /// Re-pinning an array that is already pinned returns its existing base rather than
    /// reserving a second range. A loop that walks an array with `ldelema` + `conv.u` reaches
    /// here on every iteration, so without this the pin table grows once per element access —
    /// and every memory access scans it.
    ///
    /// # Errors
    ///
    /// Returns an error if the array's size overflows, if no free address range remains, or
    /// if pin registration fails.
    pub fn pin_array_element(
        &self,
        array: HeapRef,
        index: usize,
        offset: u32,
        ptr_size: PointerSize,
    ) -> Result<u64> {
        let heap = self.context.address_space.managed_heap();

        let length = heap.get_array_length(array).unwrap_or(0);
        if length == 0 {
            return self
                .context
                .address_space
                .reserve_address_range(1)
                .ok_or_else(|| {
                    Error::from(EmulationError::InvalidAddress {
                        address: 0,
                        reason: "no free address range for pinned array".to_string(),
                    })
                });
        }

        // Determine element size from the element type or first element
        let elem_size = if let Ok(elem_type) = heap.get_array_element_type(array) {
            elem_type.byte_size(ptr_size).unwrap_or(ptr_size.bytes())
        } else {
            match heap.get_array_element(array, 0) {
                Ok(EmValue::I32(_)) => 4usize,
                Ok(EmValue::I64(_) | EmValue::NativeInt(_)) => 8,
                Ok(EmValue::NativeUInt(_)) => ptr_size.bytes(),
                Ok(EmValue::F32(_)) => 4,
                Ok(EmValue::F64(_)) => 8,
                _ => ptr_size.bytes(),
            }
        };

        let total_size = length
            .checked_mul(elem_size)
            .ok_or(EmulationError::ArithmeticOverflow)?;

        let base_addr = match self.context.address_space.pinned_base_of(array) {
            Some(existing) => existing,
            None => {
                let base_addr = self
                    .context
                    .address_space
                    .reserve_address_range(total_size.max(1))
                    .ok_or_else(|| {
                        Error::from(EmulationError::InvalidAddress {
                            address: 0,
                            reason: "no free address range for pinned array".to_string(),
                        })
                    })?;

                // Register the pinned mapping for transparent read/write delegation
                self.context
                    .address_space
                    .register_pinned_array(base_addr, array, elem_size, length)?;
                base_addr
            }
        };

        let index_offset = index
            .checked_mul(elem_size)
            .ok_or(EmulationError::ArithmeticOverflow)?;
        let element_addr = base_addr
            .checked_add(index_offset as u64)
            .and_then(|a| a.checked_add(u64::from(offset)))
            .ok_or(EmulationError::ArithmeticOverflow)?;
        Ok(element_addr)
    }

    /// Gets a thread-local storage value by its field token.
    #[must_use]
    pub fn get_tls(&self, key: Token) -> Option<&EmValue> {
        self.tls.get(&key)
    }

    /// Sets a thread-local storage value.
    pub fn set_tls(&mut self, key: Token, value: EmValue) {
        self.tls.insert(key, value);
    }

    /// Returns the number of instructions executed by this thread.
    #[must_use]
    pub fn instructions_executed(&self) -> u64 {
        self.instructions_executed
    }

    /// Increments the instruction counter.
    ///
    /// Called by the interpreter after each instruction.
    pub fn increment_instructions(&mut self) {
        self.instructions_executed = self.instructions_executed.saturating_add(1);
    }

    /// Charges `units` of native work, in instructions, before a hook does it.
    ///
    /// Returns `false` when the run's instruction budget cannot cover it: the work is
    /// charged all the same, and the hook returns without doing it
    /// (`PreHookResult::Bypass(None)`). The run then ends at its next limit check, before
    /// the emulated code goes on, as it would had the IL done the work. Without a budget
    /// every charge is covered.
    pub fn charge_work(&mut self, units: u64) -> bool {
        self.work.charged = self.work.charged.saturating_add(units);
        let total = self.work.executed.saturating_add(self.work.charged);
        self.work.limit == 0 || total < self.work.limit
    }

    /// Starts a step: `executed` instructions of a `limit` budget (0 for none) are spent.
    pub(crate) fn begin_work(&mut self, executed: u64, limit: u64) {
        self.work = WorkMeter {
            executed,
            limit,
            charged: 0,
        };
    }

    /// The native work charged since the step began, for the run's instruction count.
    pub(crate) fn take_work(&mut self) -> u64 {
        std::mem::take(&mut self.work.charged)
    }

    /// Returns the method token of the currently executing method.
    #[must_use]
    pub fn current_method(&self) -> Option<Token> {
        self.current_frame().map(|f| f.method)
    }

    /// Returns the current instruction offset within the method body.
    #[must_use]
    pub fn current_offset(&self) -> Option<u32> {
        self.current_frame().map(|f| f.instruction_offset)
    }

    /// Sets the return value and marks the thread as completed.
    ///
    /// This transitions the thread to [`ThreadState::Completed`].
    pub fn set_return_value(&mut self, value: Option<EmValue>) {
        self.return_value = value;
        self.state = ThreadState::Completed;
    }

    /// Returns the return value, if the thread completed with one.
    #[must_use]
    pub fn return_value(&self) -> Option<&EmValue> {
        self.return_value.as_ref()
    }

    /// Takes and returns the return value, leaving `None`.
    pub fn take_return_value(&mut self) -> Option<EmValue> {
        self.return_value.take()
    }

    /// Marks the thread as faulted due to an unhandled exception.
    pub fn fault(&mut self) {
        self.state = ThreadState::Faulted;
    }

    /// Marks the thread as aborted.
    pub fn abort(&mut self) {
        self.state = ThreadState::Aborted;
    }

    /// Starts executing a method as the initial entry point.
    ///
    /// Creates a call frame for the method and transitions the thread to
    /// [`ThreadState::Running`].
    ///
    /// # Arguments
    ///
    /// * `method` - Token of the method to execute
    /// * `locals` - Types of local variables declared in the method
    /// * `args` - Arguments to pass (value and type pairs)
    /// * `expects_return` - Whether a return value is expected
    pub fn start_method(
        &mut self,
        method: Token,
        locals: Vec<CilFlavor>,
        args: Vec<(EmValue, CilFlavor)>,
        expects_return: bool,
    ) {
        let frame = ThreadCallFrame::new(method, None, 0, locals, args, expects_return);
        self.push_frame(frame);
        self.state = ThreadState::Running;
    }

    /// Gets a local variable from the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn get_local(&self, index: usize) -> Result<&EmValue> {
        self.current_frame()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .locals
            .get(index)
    }

    /// Sets a local variable in the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn set_local(&mut self, index: usize, value: EmValue) -> Result<()> {
        self.current_frame_mut()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .locals
            .set(index, value)
    }

    /// Gets an argument from the current frame by index.
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn get_arg(&self, index: usize) -> Result<&EmValue> {
        self.current_frame()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .arguments
            .get(index)
    }

    /// Sets an argument in the current frame by index (for `starg` instruction).
    ///
    /// # Errors
    ///
    /// Returns an error if there is no active call frame or the index is out of bounds.
    pub fn set_arg(&mut self, index: usize, value: EmValue) -> Result<()> {
        self.current_frame_mut()
            .ok_or_else(|| {
                Error::from(EmulationError::InternalError {
                    description: "no active call frame".to_string(),
                })
            })?
            .arguments
            .set(index, value)
    }

    /// Returns a reference to the managed heap.
    #[must_use]
    pub fn heap(&self) -> &ManagedHeap {
        self.context.address_space.managed_heap()
    }

    /// Returns a reference to the managed heap for mutation.
    ///
    /// Note: `ManagedHeap` uses interior mutability (e.g., `RefCell`), so
    /// mutation is done through `&self` methods on `ManagedHeap`.
    #[must_use]
    pub fn heap_mut(&self) -> &ManagedHeap {
        self.context.address_space.managed_heap()
    }

    /// Gets an object from the heap.
    ///
    /// Returns a cloned `HeapObject`. For strings and other Arc-backed data,
    /// cloning is cheap (just incrementing a reference count).
    ///
    /// # Errors
    ///
    /// Returns error if reference is invalid.
    pub fn get_heap_object(&self, heap_ref: HeapRef) -> Result<HeapObject> {
        self.context.address_space.managed_heap().get(heap_ref)
    }

    /// Dereferences a managed pointer and returns the value at that location.
    ///
    /// # Errors
    ///
    /// Returns error if the pointer target is invalid or inaccessible.
    pub fn deref_pointer(&self, ptr: &ManagedPointer) -> Result<EmValue> {
        match &ptr.target {
            PointerTarget::Local(index) => {
                let idx = usize::from(*index);
                let frame = self
                    .get_frame_at(ptr.frame_depth)
                    .or_else(|| self.current_frame())
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?;
                frame.locals().get(idx).cloned()
            }
            PointerTarget::Argument(index) => {
                let idx = usize::from(*index);
                let frame = self
                    .get_frame_at(ptr.frame_depth)
                    .or_else(|| self.current_frame())
                    .ok_or_else(|| EmulationError::InternalError {
                        description: "empty call stack".into(),
                    })?;
                frame.arguments().get(idx).cloned()
            }
            PointerTarget::ArrayElement { array, index } => self
                .context
                .address_space
                .managed_heap()
                .get_array_element(*array, *index),
            PointerTarget::ObjectField { object, field } => self
                .context
                .address_space
                .managed_heap()
                .get_field(*object, *field)
                .map_err(|_| {
                    EmulationError::TypeMismatch {
                        operation: "ldind",
                        expected: "valid field",
                        found: "unknown field",
                    }
                    .into()
                }),
            PointerTarget::StaticField(field_token) => self
                .context
                .address_space
                .statics()
                .get(*field_token)?
                .ok_or_else(|| {
                    EmulationError::TypeMismatch {
                        operation: "ldind (static field)",
                        expected: "initialized static field",
                        found: "uninitialized static field",
                    }
                    .into()
                }),
        }
    }

    /// Stores a value through a managed pointer.
    ///
    /// # Errors
    ///
    /// Returns error if the pointer target is invalid or inaccessible.
    pub fn store_through_pointer(&mut self, ptr: &ManagedPointer, value: EmValue) -> Result<()> {
        match &ptr.target {
            PointerTarget::Local(index) => {
                let idx = usize::from(*index);
                let frame = self.resolve_frame_mut(ptr.frame_depth).ok_or_else(|| {
                    EmulationError::InternalError {
                        description: "empty call stack".into(),
                    }
                })?;
                frame.locals_mut().set(idx, value)?;
                Ok(())
            }
            PointerTarget::Argument(index) => {
                let idx = usize::from(*index);
                let frame = self.resolve_frame_mut(ptr.frame_depth).ok_or_else(|| {
                    EmulationError::InternalError {
                        description: "empty call stack".into(),
                    }
                })?;
                frame.arguments_mut().set(idx, value)?;
                Ok(())
            }
            PointerTarget::ArrayElement { array, index } => self
                .context
                .address_space
                .managed_heap()
                .set_array_element(*array, *index, value),
            PointerTarget::ObjectField { object, field } => self
                .context
                .address_space
                .managed_heap()
                .set_field(*object, *field, value),
            PointerTarget::StaticField(field_token) => {
                self.context
                    .address_space
                    .statics()
                    .set(*field_token, value)?;
                Ok(())
            }
        }
    }

    /// Reconfigures the current frame's local variables.
    ///
    /// This is used when returning from a call to restore the caller's
    /// local variable configuration.
    ///
    /// # Arguments
    ///
    /// * `local_types` - Types of local variables in the frame
    pub fn configure_locals(&mut self, local_types: Vec<CilFlavor>) {
        if let Some(frame) = self.current_frame_mut() {
            frame.locals = LocalVariables::new(local_types);
        }
    }

    /// Reconfigures the current frame's arguments.
    ///
    /// This is used when returning from a call to restore the caller's
    /// argument configuration.
    ///
    /// # Arguments
    ///
    /// * `arg_values` - Argument values
    /// * `arg_types` - Argument types
    pub fn configure_arguments(&mut self, arg_values: Vec<EmValue>, arg_types: Vec<CilFlavor>) {
        if let Some(frame) = self.current_frame_mut() {
            frame.arguments = ArgumentStorage::new(arg_values, arg_types);
        }
    }

    /// Restores the evaluation stack with the given values.
    ///
    /// Clears the current stack and pushes all provided values in order.
    /// Used when returning from a method to restore the caller's stack.
    ///
    /// # Errors
    ///
    /// Returns an error if the stack is full.
    pub fn restore_stack(&mut self, values: Vec<EmValue>) -> Result<()> {
        self.eval_stack.clear();
        for value in values {
            self.eval_stack.push(value)?;
        }
        Ok(())
    }

    /// Clears the evaluation stack.
    pub fn clear_stack(&mut self) {
        self.eval_stack.clear();
    }

    /// Takes all values from the evaluation stack and clears it.
    ///
    /// Returns a snapshot of the stack contents before clearing.
    pub fn take_stack(&mut self) -> Vec<EmValue> {
        let values = self.eval_stack.snapshot();
        self.eval_stack.clear();
        values
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::emulation::{create_test_context, create_test_thread};

    /// A hook's work is covered while the run's executed instructions and the work charged
    /// this step stay under the budget; the charge stands either way, for the run's count,
    /// and without a budget every charge is covered.
    #[test]
    fn work_is_charged_against_the_rest_of_the_budget() {
        let mut thread = create_test_thread();
        thread.begin_work(900, 1000);
        assert!(thread.charge_work(50));
        assert!(thread.charge_work(49));
        assert!(!thread.charge_work(1));
        assert_eq!(thread.take_work(), 100);
        assert_eq!(thread.take_work(), 0);

        thread.begin_work(900, 0);
        assert!(thread.charge_work(u64::MAX));
    }

    /// The index selects which loaded assembly's metadata a frame executes against, and
    /// emulated code grows that list. Narrowing it binds the frame to a different assembly
    /// than the one the method token was resolved in — a valid token run against the wrong
    /// method table.
    #[test]
    fn assembly_index_survives_beyond_a_byte() {
        let mut frame = ThreadCallFrame::new(
            Token::new(0x0600_0001),
            None,
            0,
            Vec::new(),
            Vec::new(),
            false,
        );

        for index in [0_u32, 255, 256, 4096, u32::from(u16::MAX) + 1] {
            frame.set_assembly_index(Some(index));
            assert_eq!(frame.assembly_index(), Some(index));
        }
    }

    #[test]
    fn test_thread_creation() {
        let thread = create_test_thread();
        assert_eq!(thread.id(), ThreadId::MAIN);
        assert_eq!(thread.state(), ThreadState::Ready);
        assert!(thread.is_ready());
        assert!(!thread.is_completed());
    }

    #[test]
    fn test_thread_main() {
        let ctx = create_test_context();
        let thread = EmulationThread::main(ctx);
        assert_eq!(thread.id(), ThreadId::MAIN);
        assert_eq!(thread.name(), Some("Main"));
    }

    #[test]
    fn test_call_stack() {
        let mut thread = create_test_thread();

        assert_eq!(thread.call_depth(), 0);
        assert!(thread.current_frame().is_none());

        // Start a method
        thread.start_method(
            Token::new(0x06000001),
            vec![CilFlavor::I4],
            vec![(EmValue::I32(42), CilFlavor::I4)],
            true,
        );

        assert_eq!(thread.call_depth(), 1);
        assert!(thread.current_frame().is_some());
        assert_eq!(thread.current_method(), Some(Token::new(0x06000001)));

        // Push another frame
        let frame = ThreadCallFrame::new(
            Token::new(0x06000002),
            Some(Token::new(0x06000001)), // return to first method
            0x10,
            vec![],
            vec![],
            false,
        );
        thread.push_frame(frame);
        assert_eq!(thread.call_depth(), 2);

        // Pop frame
        let popped = thread.pop_frame().unwrap();
        assert_eq!(popped.method(), Token::new(0x06000002));
        assert_eq!(thread.call_depth(), 1);
    }

    #[test]
    fn test_evaluation_stack() {
        let mut thread = create_test_thread();

        thread.push(EmValue::I32(10)).unwrap();
        thread.push(EmValue::I32(20)).unwrap();

        assert_eq!(thread.stack().depth(), 2);

        let val = thread.pop().unwrap();
        assert_eq!(val, EmValue::I32(20));
    }

    #[test]
    fn test_thread_completion() {
        let mut thread = create_test_thread();

        thread.set_return_value(Some(EmValue::I32(42)));
        assert!(thread.is_completed());
        assert_eq!(thread.state(), ThreadState::Completed);

        let ret = thread.take_return_value();
        assert_eq!(ret, Some(EmValue::I32(42)));
    }

    #[test]
    fn test_thread_priority() {
        let mut thread = create_test_thread();
        assert_eq!(thread.priority(), ThreadPriority::Normal);

        thread.set_priority(ThreadPriority::Highest);
        assert_eq!(thread.priority(), ThreadPriority::Highest);
    }

    #[test]
    fn test_tls() {
        let mut thread = create_test_thread();
        let key = Token::new(0x04000001);

        assert!(thread.get_tls(key).is_none());

        thread.set_tls(key, EmValue::I32(100));
        assert_eq!(thread.get_tls(key), Some(&EmValue::I32(100)));
    }
}
