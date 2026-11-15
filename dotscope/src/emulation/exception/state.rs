//! Per-thread exception handling state for .NET emulation.
//!
//! This module manages the exception handling state for a single thread during emulation.
//! Each thread in a .NET application has its own exception state, tracking the currently
//! active exception, pending cleanup handlers, and control flow during exception handling.
//!
//! # Overview
//!
//! The .NET runtime maintains exception state per thread. When an exception is thrown,
//! this state tracks:
//!
//! - The active exception object and its type
//! - Pending finally blocks that must execute during unwinding
//! - Filter evaluation state (for `catch when` clauses)
//! - Rethrow requests from catch handlers
//! - Leave instruction targets for normal exit from try blocks
//!
//! # State Transitions
//!
//! Exception state transitions through several phases:
//!
//! 1. **Normal execution** - No exception active
//! 2. **Exception thrown** - Exception set, handling begins
//! 3. **Handler search** - Looking for catch/filter handlers
//! 4. **Cleanup execution** - Running finally/fault blocks
//! 5. **Handler entered** - Executing catch handler code
//! 6. **Exception handled** - State cleared, normal execution resumes
//!
//! # Thread Safety
//!
//! This state is designed for single-threaded access per emulated thread.
//! Each emulated thread should have its own [`ThreadExceptionState`] instance.

use crate::{
    emulation::{exception::types::InstructionLocation, EmValue, HeapRef},
    metadata::token::Token,
};

/// Maximum number of cleanup handlers that may be queued for execution at once.
///
/// A backstop, not a semantic limit: legitimate depth is bounded by try nesting times call
/// depth, both of which are already capped elsewhere, so this is only reachable when entries are
/// queued faster than they are drained. Without it the queue is an unbounded `Vec` free to
/// grow for the lifetime of the emulation.
const MAX_PENDING_FINALLY: usize = 4096;

/// Information about a thrown exception.
///
/// This structure captures all the information about an exception at the time
/// it was thrown, including the exception object, its type, the throw location,
/// and the stack trace built during unwinding.
///
/// # Fields
///
/// - `exception_ref` - Reference to the exception object on the managed heap
/// - `type_token` - The metadata token identifying the exception's type
/// - `throw_location` - Where in the IL the exception was thrown
/// - `stack_trace` - Call stack at the point of the throw (built during unwind)
#[derive(Clone, Debug)]
pub struct ExceptionInfo {
    /// Reference to the exception object on the managed heap.
    ///
    /// This is a handle to the exception object, allowing access to its
    /// properties like `Message`, `InnerException`, etc.
    pub exception_ref: HeapRef,

    /// The metadata token of the exception's type.
    ///
    /// Used for type matching against catch clauses during handler search.
    pub type_token: Token,

    /// The instruction location where the exception was thrown.
    ///
    /// This is the original throw point, preserved through rethrows.
    pub throw_location: InstructionLocation,

    /// Stack trace built during exception propagation.
    ///
    /// Contains instruction locations from the throw point through each
    /// frame that was unwound. Used to populate `Exception.StackTrace`.
    pub stack_trace: Vec<InstructionLocation>,
}

impl ExceptionInfo {
    /// Creates new exception information.
    ///
    /// Initializes the exception info with the given parameters and starts
    /// the stack trace with the throw location.
    ///
    /// # Arguments
    ///
    /// * `exception_ref` - Reference to the exception object on the heap
    /// * `type_token` - The metadata token of the exception's type
    /// * `throw_location` - The instruction location where the exception was thrown
    ///
    /// # Returns
    ///
    /// A new `ExceptionInfo` with the stack trace initialized to the throw location.
    #[must_use]
    pub fn new(
        exception_ref: HeapRef,
        type_token: Token,
        throw_location: InstructionLocation,
    ) -> Self {
        Self {
            exception_ref,
            type_token,
            throw_location,
            stack_trace: vec![throw_location],
        }
    }

    /// Adds a stack frame to the exception's stack trace.
    ///
    /// Called during stack unwinding to build the complete stack trace.
    /// Each unwound frame's location is added to record the call path.
    ///
    /// # Arguments
    ///
    /// * `location` - The instruction location of the frame being unwound
    pub fn push_stack_frame(&mut self, location: InstructionLocation) {
        self.stack_trace.push(location);
    }

    /// Converts the exception reference to an [`EmValue`].
    ///
    /// This is useful when the exception needs to be passed to APIs that
    /// expect an `EmValue`, such as returning an unhandled exception.
    ///
    /// # Returns
    ///
    /// An `EmValue::ObjectRef` containing the exception's heap reference.
    #[must_use]
    pub fn as_value(&self) -> EmValue {
        EmValue::ObjectRef(self.exception_ref)
    }
}

/// A pending finally block queued for execution.
///
/// Finally blocks are queued during exception unwinding or when executing
/// `leave` instructions that exit protected regions. This structure tracks
/// the information needed to execute the finally and continue afterward.
///
/// # Usage Scenarios
///
/// - **Exception unwinding**: Finally blocks run before entering catch or propagating
/// - **Leave instruction**: Finally blocks run before transferring to the leave target
#[derive(Clone, Debug)]
pub struct PendingFinally {
    /// The method token containing the finally block.
    pub method: Token,

    /// The IL offset where the finally handler code begins.
    pub handler_offset: u32,

    /// The target IL offset to jump to after the finally completes.
    ///
    /// - `Some(offset)` - For `leave` instructions, the original leave target
    /// - `None` - For exception unwinding, continue the unwind process
    pub leave_target: Option<u32>,
}

/// Per-thread exception handling state.
///
/// This structure tracks the complete exception handling state for a single
/// emulated thread. It manages the current exception, pending cleanup handlers,
/// filter evaluation, and control flow during exception processing.
///
/// # Responsibilities
///
/// - Tracking the active exception and its information
/// - Managing the queue of pending finally blocks
/// - Handling filter clause evaluation state
/// - Processing rethrow requests from catch handlers
/// - Tracking leave instruction targets through finally blocks
///
/// # Lifecycle
///
/// 1. Create with [`new()`](Self::new) (or `Default::default()`)
/// 2. Set exception with [`set_exception()`](Self::set_exception) when thrown
/// 3. Push finally blocks with [`push_finally()`](Self::push_finally)
/// 4. Pop and execute finally blocks with [`pop_finally()`](Self::pop_finally)
/// 5. Enter catch with [`enter_catch()`](Self::enter_catch) to handle exception
/// 6. Clear with [`clear()`](Self::clear) when exception is fully handled
///
/// # Example
///
/// ```
/// use dotscope::emulation::{ExceptionInfo, HeapRef, InstructionLocation, ThreadExceptionState};
/// use dotscope::metadata::token::Token;
///
/// let mut state = ThreadExceptionState::new();
/// let method = Token::new(0x0600_0001);
///
/// // Exception thrown: an object of a type (`System.Exception`'s TypeRef) at IL 0x05
/// let exception_info = ExceptionInfo::new(
///     HeapRef::new(1),
///     Token::new(0x0100_0002),
///     InstructionLocation::new(method, 0x05),
/// );
/// state.set_exception(exception_info);
///
/// // Queue finally blocks found during search
/// state.push_finally(method, 0x10, Some(0x20));
///
/// // Execute finally blocks
/// while let Some(finally) = state.pop_finally() {
///     // Execute finally handler...
/// }
///
/// // Enter catch handler
/// state.enter_catch();
/// ```
#[derive(Clone, Debug, Default)]
pub struct ThreadExceptionState {
    /// The currently active exception, if any.
    ///
    /// Set when an exception is thrown and cleared when caught or propagated.
    current_exception: Option<ExceptionInfo>,

    /// Queue of finally blocks to execute during unwinding.
    ///
    /// Blocks are added during handler search and popped during execution.
    /// Uses LIFO order (last added = first executed, matching .NET semantics).
    pending_finally: Vec<PendingFinally>,

    /// Whether exception handling is currently in progress.
    ///
    /// `true` from when an exception is thrown until it is handled or
    /// propagates out of all frames.
    handling_exception: bool,

    /// Whether a rethrow has been requested from a catch handler.
    ///
    /// Set by the `rethrow` instruction, causes the current exception
    /// to be propagated again after exiting the catch handler.
    rethrow_requested: bool,

    /// The target offset for a `leave` instruction.
    ///
    /// When a `leave` instruction is executed inside a finally block,
    /// this stores the original target to resume after the finally completes.
    leave_target: Option<u32>,

    /// Whether currently evaluating an exception filter.
    ///
    /// Filter clauses (`catch when (condition)`) require evaluating code
    /// to determine if the handler should run.
    in_filter: bool,

    /// The handler offset to jump to if the current filter accepts.
    ///
    /// When entering filter evaluation, this stores the handler's IL offset.
    /// If the filter accepts (EndFilter with non-zero value), execution
    /// should transfer to this offset.
    filter_handler_offset: Option<u32>,

    /// The result of filter evaluation.
    ///
    /// - `Some(true)` - Filter accepted, enter the handler
    /// - `Some(false)` - Filter rejected, continue searching
    /// - `None` - Filter not yet evaluated
    filter_result: Option<bool>,

    /// The IL offset where the current exception originated.
    ///
    /// Used during rethrow to search for handlers starting from the
    /// original throw location rather than the catch handler location.
    exception_origin_offset: Option<u32>,

    /// The IL offset of the currently executing handler.
    ///
    /// Used to skip the current handler when searching during rethrow.
    current_handler_offset: Option<u32>,

    /// The method token of the currently executing catch handler.
    ///
    /// Tracks which method owns the catch handler so that `leave` instructions
    /// in nested method calls don't accidentally clear the handler state.
    current_handler_method: Option<Token>,

    /// Whether we are currently executing a finally block during exception unwinding.
    ///
    /// Per ECMA-335 §II.12.4.2.5: if a new exception is thrown during a finally
    /// that was entered as part of exception unwinding, the old exception is
    /// replaced by the new one and unwinding restarts from the current point.
    in_unwind_finally: bool,
}

impl ThreadExceptionState {
    /// Creates a new exception state with no active exception.
    ///
    /// # Returns
    ///
    /// A new `ThreadExceptionState` in the initial (no exception) state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks if there is an active exception.
    ///
    /// # Returns
    ///
    /// `true` if an exception is currently active.
    #[must_use]
    pub fn has_exception(&self) -> bool {
        self.current_exception.is_some()
    }

    /// Gets a reference to the current exception information.
    ///
    /// # Returns
    ///
    /// A reference to the [`ExceptionInfo`] if an exception is active, or `None`.
    #[must_use]
    pub fn exception(&self) -> Option<&ExceptionInfo> {
        self.current_exception.as_ref()
    }

    /// Gets the current exception as an [`EmValue`].
    ///
    /// # Returns
    ///
    /// `Some(EmValue::ObjectRef(...))` if an exception is active, `None` otherwise.
    #[must_use]
    pub fn get_exception_value(&self) -> Option<EmValue> {
        self.current_exception.as_ref().map(ExceptionInfo::as_value)
    }

    /// Sets the current exception.
    ///
    /// This should be called when an exception is thrown. It sets the
    /// exception info and enters exception handling mode.
    ///
    /// # Arguments
    ///
    /// * `exception` - The exception information to set
    pub fn set_exception(&mut self, exception: ExceptionInfo) {
        self.current_exception = Some(exception);
        self.handling_exception = true;
    }

    /// Takes (consumes) the current exception.
    ///
    /// Removes the exception from this state and returns it. Also clears
    /// the handling flag.
    ///
    /// # Returns
    ///
    /// The exception info if one was active, or `None`.
    pub fn take_exception(&mut self) -> Option<ExceptionInfo> {
        self.handling_exception = false;
        self.current_exception.take()
    }

    /// Takes (consumes) the exception as an [`EmValue`].
    ///
    /// Removes the exception from this state and returns it as an `EmValue`.
    /// Also clears the handling flag.
    ///
    /// # Returns
    ///
    /// `Some(EmValue::ObjectRef(...))` if an exception was active, `None` otherwise.
    pub fn take_exception_as_value(&mut self) -> Option<EmValue> {
        self.handling_exception = false;
        self.current_exception.take().map(|info| info.as_value())
    }

    /// Clears all exception state.
    ///
    /// Resets the exception state to its initial condition, clearing the
    /// exception, pending finally blocks, filter state, and all other fields.
    /// Call this when an exception has been fully handled or when resetting
    /// the thread state.
    pub fn clear(&mut self) {
        self.current_exception = None;
        self.handling_exception = false;
        self.rethrow_requested = false;
        self.pending_finally.clear();
        self.leave_target = None;
        self.in_filter = false;
        self.filter_handler_offset = None;
        self.filter_result = None;
        self.exception_origin_offset = None;
        self.current_handler_offset = None;
        self.in_unwind_finally = false;
    }

    /// Checks if exception handling is in progress.
    ///
    /// # Returns
    ///
    /// `true` if currently handling an exception (from throw until catch or propagation).
    #[must_use]
    pub fn is_handling(&self) -> bool {
        self.handling_exception
    }

    /// Pushes a pending finally block onto the execution queue.
    ///
    /// Finally blocks are executed in LIFO order (last pushed = first executed).
    ///
    /// # Arguments
    ///
    /// * `method` - The method containing the finally block
    /// * `handler_offset` - The IL offset of the finally handler
    /// * `leave_target` - Optional target offset for `leave` instructions
    ///
    /// Silently drops the entry once `MAX_PENDING_FINALLY` entries are queued. The queue is
    /// bounded by real control flow — nesting depth times call depth — so reaching the cap means
    /// entries are being queued faster than they are drained, which is a defect rather than a
    /// deep program. Dropping is the conservative response: a skipped cleanup handler
    /// mis-emulates one method, whereas an unbounded queue exhausts host memory.
    pub fn push_finally(&mut self, method: Token, handler_offset: u32, leave_target: Option<u32>) {
        if self.pending_finally.len() >= MAX_PENDING_FINALLY {
            return;
        }

        self.pending_finally.push(PendingFinally {
            method,
            handler_offset,
            leave_target,
        });
    }

    /// Discards queued cleanup handlers belonging to `method`.
    ///
    /// Called when a frame is popped: entries scheduled against a frame that no longer exists
    /// can never run correctly, since the handler IL would execute against whatever frame
    /// happens to be current.
    pub fn discard_finally_for_method(&mut self, method: Token) {
        self.pending_finally
            .retain(|pending| pending.method != method);
    }

    /// Pops and returns the next pending finally block.
    ///
    /// Returns the most recently pushed finally block (LIFO order).
    ///
    /// # Returns
    ///
    /// The next finally block to execute, or `None` if no blocks are pending.
    pub fn pop_finally(&mut self) -> Option<PendingFinally> {
        self.pending_finally.pop()
    }

    /// Checks if there are pending finally blocks.
    ///
    /// # Returns
    ///
    /// `true` if there are finally blocks waiting to be executed.
    #[must_use]
    pub fn has_pending_finally(&self) -> bool {
        !self.pending_finally.is_empty()
    }

    /// Gets the number of pending finally blocks.
    ///
    /// # Returns
    ///
    /// The count of finally blocks in the queue.
    #[must_use]
    pub fn pending_finally_count(&self) -> usize {
        self.pending_finally.len()
    }

    /// Requests a rethrow of the current exception.
    ///
    /// Called when a `rethrow` instruction is executed inside a catch handler.
    /// The exception will be propagated again after executing any pending
    /// finally blocks.
    pub fn request_rethrow(&mut self) {
        self.rethrow_requested = true;
    }

    /// Takes and clears the rethrow request.
    ///
    /// This method checks if a rethrow was requested and clears the flag.
    /// It should be called after exiting a catch handler to determine if
    /// the exception should be propagated.
    ///
    /// # Returns
    ///
    /// `true` if a rethrow was requested since the last check.
    pub fn take_rethrow_request(&mut self) -> bool {
        let was_requested = self.rethrow_requested;
        self.rethrow_requested = false;
        was_requested
    }

    /// Enters a catch handler, clearing the exception state.
    ///
    /// Called when execution transfers to a catch handler. The exception
    /// is considered handled and the state is cleared.
    ///
    /// Note: Use [`enter_catch_handler`](Self::enter_catch_handler) if you
    /// need to support rethrow from within the catch block.
    pub fn enter_catch(&mut self) {
        // Exception is handled, clear it
        self.current_exception = None;
        self.handling_exception = false;
    }

    /// Enters a finally handler.
    ///
    /// Called when execution transfers to a finally handler. Exception state
    /// is preserved during finally execution.
    pub fn enter_finally(&mut self) {
        // Exception state preserved during finally
    }

    /// Exits a finally handler.
    ///
    /// Called when a finally handler completes (via `endfinally`). If a
    /// rethrow was requested, restores the exception for continued propagation.
    ///
    /// # Arguments
    ///
    /// * `exception_to_restore` - The exception to restore if rethrow was requested
    pub fn exit_finally(&mut self, exception_to_restore: Option<ExceptionInfo>) {
        if self.rethrow_requested {
            self.handling_exception = exception_to_restore.is_some();
            self.current_exception = exception_to_restore;
        }
        self.rethrow_requested = false;
    }

    /// Gets the leave target offset.
    ///
    /// # Returns
    ///
    /// The target IL offset for a pending `leave` instruction, or `None`.
    #[must_use]
    pub fn leave_target(&self) -> Option<u32> {
        self.leave_target
    }

    /// Sets the leave target offset.
    ///
    /// Called when a `leave` instruction is encountered and finally blocks
    /// must execute before reaching the target.
    ///
    /// # Arguments
    ///
    /// * `target` - The target offset, or `None` to clear
    pub fn set_leave_target(&mut self, target: Option<u32>) {
        self.leave_target = target;
    }

    /// Takes the leave target (returns and clears it).
    ///
    /// # Returns
    ///
    /// The leave target offset if one was set, or `None`.
    pub fn take_leave_target(&mut self) -> Option<u32> {
        self.leave_target.take()
    }

    /// Checks if currently in filter evaluation.
    ///
    /// # Returns
    ///
    /// `true` if currently evaluating a filter clause.
    #[must_use]
    pub fn in_filter(&self) -> bool {
        self.in_filter
    }

    /// Enters filter evaluation mode with the given handler offset.
    ///
    /// Call this when starting to evaluate a filter clause. The handler_offset
    /// is stored so that if the filter accepts, execution can transfer to it.
    ///
    /// # Arguments
    ///
    /// * `handler_offset` - The IL offset of the handler to enter if filter accepts
    pub fn enter_filter(&mut self, handler_offset: u32) {
        self.in_filter = true;
        self.filter_handler_offset = Some(handler_offset);
    }

    /// Sets the filter evaluation state.
    ///
    /// # Arguments
    ///
    /// * `in_filter` - `true` when entering filter evaluation, `false` when exiting
    ///
    /// # Note
    ///
    /// Prefer using [`enter_filter`](Self::enter_filter) when entering a filter,
    /// as it also stores the handler offset. Use `set_in_filter(false)` to exit.
    pub fn set_in_filter(&mut self, in_filter: bool) {
        self.in_filter = in_filter;
        if !in_filter {
            self.filter_handler_offset = None;
        }
    }

    /// Gets the handler offset for the current filter.
    ///
    /// If currently evaluating a filter and the filter accepts, execution
    /// should transfer to this offset.
    ///
    /// # Returns
    ///
    /// The handler offset if in a filter, or `None`.
    #[must_use]
    pub fn filter_handler_offset(&self) -> Option<u32> {
        self.filter_handler_offset
    }

    /// Gets the filter evaluation result.
    ///
    /// # Returns
    ///
    /// - `Some(true)` - Filter accepted, enter the handler
    /// - `Some(false)` - Filter rejected, continue searching
    /// - `None` - Filter not yet evaluated
    #[must_use]
    pub fn filter_result(&self) -> Option<bool> {
        self.filter_result
    }

    /// Sets the filter evaluation result.
    ///
    /// Called after evaluating the filter code to record whether the
    /// handler should be entered.
    ///
    /// # Arguments
    ///
    /// * `result` - The filter result (`Some(true)` to accept, `Some(false)` to reject)
    pub fn set_filter_result(&mut self, result: Option<bool>) {
        self.filter_result = result;
    }

    /// Gets the exception origin offset.
    ///
    /// This is the IL offset where the exception was originally thrown,
    /// used for handler search during rethrow.
    ///
    /// # Returns
    ///
    /// The origin offset if set, or `None`.
    #[must_use]
    pub fn exception_origin_offset(&self) -> Option<u32> {
        self.exception_origin_offset
    }

    /// Gets the current handler offset.
    ///
    /// This is the IL offset of the handler currently executing,
    /// used to skip it during rethrow handler search.
    ///
    /// # Returns
    ///
    /// The handler offset if set, or `None`.
    #[must_use]
    pub fn current_handler_offset(&self) -> Option<u32> {
        self.current_handler_offset
    }

    /// Returns the method that owns the current catch handler.
    #[must_use]
    pub fn current_handler_method(&self) -> Option<Token> {
        self.current_handler_method
    }

    /// Enters a catch handler with tracking for rethrow support.
    ///
    /// Unlike [`enter_catch`](Self::enter_catch), this preserves the exception
    /// value to support the `rethrow` instruction within the catch block.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token that owns this catch handler
    /// * `origin_offset` - The IL offset where the exception was thrown
    /// * `handler_offset` - The IL offset of this catch handler
    pub fn enter_catch_handler(&mut self, method: Token, origin_offset: u32, handler_offset: u32) {
        self.exception_origin_offset = Some(origin_offset);
        self.current_handler_offset = Some(handler_offset);
        self.current_handler_method = Some(method);
        // Note: we do NOT clear the exception here - rethrow needs it
    }

    /// Leaves a catch handler normally via `leave` instruction.
    ///
    /// Called when exiting a catch handler through normal control flow
    /// (not via rethrow). Clears exception-related state.
    pub fn leave_catch_handler(&mut self) {
        self.exception_origin_offset = None;
        self.current_handler_offset = None;
        self.current_handler_method = None;
    }

    /// Returns whether we are currently in a finally block entered during exception unwinding.
    #[must_use]
    pub fn in_unwind_finally(&self) -> bool {
        self.in_unwind_finally
    }

    /// Sets the unwind-finally state.
    ///
    /// Set to `true` when entering a finally block during exception unwinding.
    /// Set to `false` when the finally completes normally via `endfinally`.
    pub fn set_in_unwind_finally(&mut self, in_unwind: bool) {
        self.in_unwind_finally = in_unwind;
    }

    /// Gets a mutable reference to the current exception info.
    ///
    /// Used to build stack traces during unwinding without consuming the exception.
    pub fn exception_mut(&mut self) -> Option<&mut ExceptionInfo> {
        self.current_exception.as_mut()
    }

    /// Handles a new exception thrown during an unwind-finally.
    ///
    /// Per ECMA-335 §II.12.4.2.5: the old exception is abandoned and the new
    /// exception replaces it. The pending finally queue is cleared since the old
    /// unwind chain is no longer relevant.
    pub fn replace_exception_in_unwind_finally(&mut self, new_exception: ExceptionInfo) {
        self.current_exception = Some(new_exception);
        self.pending_finally.clear();
        self.in_unwind_finally = false;
        self.handling_exception = true;
    }

    /// Clears exception-related state when fully handled.
    ///
    /// Clears the filter result and handler tracking but does not affect
    /// other state like pending finally blocks.
    pub fn clear_exception(&mut self) {
        self.filter_result = None;
        self.exception_origin_offset = None;
        self.current_handler_offset = None;
        self.current_handler_method = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exception_state_new() {
        let state = ThreadExceptionState::new();
        assert!(!state.has_exception());
        assert!(!state.is_handling());
    }

    #[test]
    fn test_exception_state_set_and_take() {
        let mut state = ThreadExceptionState::new();

        // Test with structured ExceptionInfo
        let heap_ref = HeapRef::new(42);
        let throw_loc = InstructionLocation::new(Token::new(0x06000001), 10);
        let exception_info = ExceptionInfo::new(heap_ref, Token::new(0x02000001), throw_loc);

        state.set_exception(exception_info);
        assert!(state.has_exception());
        assert!(state.is_handling());

        // Use unified method to get exception as EmValue
        let value = state.get_exception_value();
        assert!(value.is_some());
        assert!(matches!(value, Some(EmValue::ObjectRef(_))));

        let taken = state.take_exception_as_value();
        assert!(taken.is_some());
        assert!(!state.has_exception());
    }

    #[test]
    fn test_pending_finally() {
        let mut state = ThreadExceptionState::new();
        let method = Token::new(0x06000001);

        assert!(!state.has_pending_finally());

        state.push_finally(method, 0x50, Some(0x100));
        state.push_finally(method, 0x80, None);

        assert!(state.has_pending_finally());
        assert_eq!(state.pending_finally_count(), 2);

        // Pop in LIFO order
        let f1 = state.pop_finally().unwrap();
        assert_eq!(f1.handler_offset, 0x80);
        assert!(f1.leave_target.is_none());

        let f2 = state.pop_finally().unwrap();
        assert_eq!(f2.handler_offset, 0x50);
        assert_eq!(f2.leave_target, Some(0x100));

        assert!(!state.has_pending_finally());
    }

    #[test]
    fn test_rethrow() {
        let mut state = ThreadExceptionState::new();

        assert!(!state.take_rethrow_request());

        state.request_rethrow();
        assert!(state.take_rethrow_request());
        assert!(!state.take_rethrow_request()); // Cleared after take
    }

    #[test]
    fn test_clear() {
        let mut state = ThreadExceptionState::new();
        let method = Token::new(0x06000001);

        // Set up exception using structured API
        let heap_ref = HeapRef::new(42);
        let throw_loc = InstructionLocation::new(method, 10);
        let exception_info = ExceptionInfo::new(heap_ref, Token::new(0x02000001), throw_loc);
        state.set_exception(exception_info);
        state.push_finally(method, 0x50, None);
        state.request_rethrow();

        state.clear();

        assert!(!state.has_exception());
        assert!(!state.has_pending_finally());
        assert!(!state.take_rethrow_request());
    }

    /// Leaving a filter destroys the handler offset, so every `endfilter` consumer must read
    /// it *first*.
    ///
    /// This coupling is not obvious from either call site and it has already been got wrong
    /// once: `set_in_filter(false)` was hoisted above the reads in the controller's
    /// `EndFilter` arm, which made `filter_handler_offset` unconditionally `None` there. On
    /// the accepting path that skipped the jump and returned without advancing the IP, so
    /// `endfilter` re-executed forever; on the rejecting path it emptied the skip key, so the
    /// handler search re-matched the filter that had just rejected. Every `catch (E) when
    /// (...)` was broken in both directions.
    ///
    /// If this coupling is ever removed, the ordering comments in
    /// `engine::controller`'s `EndFilter` arm and `resume_search_after_filter` become stale.
    #[test]
    fn leaving_a_filter_clears_the_handler_offset() {
        let mut state = ThreadExceptionState::new();

        state.enter_filter(0x42);
        assert!(state.in_filter());
        assert_eq!(state.filter_handler_offset(), Some(0x42));

        state.set_in_filter(false);
        assert!(!state.in_filter());
        assert_eq!(
            state.filter_handler_offset(),
            None,
            "leaving a filter must clear the handler offset; the ordering requirements \
             documented in engine::controller depend on it"
        );
    }
}
