//! Call resolution types for iterative method dispatch.
//!
//! These types replace recursive `handle_call()` / `handle_newobj()` with an
//! iterative resolution loop. Each variant tells the main execution loop what
//! action to take without the resolver itself touching the instruction pointer
//! or call stack.

use crate::{
    emulation::{EmValue, HeapRef},
    metadata::token::Token,
};

/// Maximum number of redirect iterations before aborting.
///
/// Prevents infinite loops when reflection targets itself or delegate chains
/// form cycles.
pub const MAX_REDIRECT_DEPTH: usize = 16;

/// Result of resolving a method call (call/callvirt/calli).
///
/// Returned by `resolve_call()`. The main loop acts on each variant:
/// - Terminal variants (`HookedBypass`, `ReturnSynthetic`) push a value and advance IP.
/// - `EnterMethod` pushes a new call frame.
/// - `Redirect` loops back to `resolve_call()` with a new target token.
pub enum CallResolution {
    /// Hook or native stub handled the call. Push return value, advance IP.
    HookedBypass {
        /// Value to push (None for void returns).
        return_value: Option<EmValue>,
    },

    /// Enter method's CIL body — push a new call frame.
    EnterMethod {
        /// Token of the resolved method to enter.
        token: Token,
        /// Pre-popped arguments (including `this` for instance methods).
        arguments: Vec<EmValue>,
        /// Whether the caller expects a return value on the stack.
        expects_return: bool,
        /// Assembly index for dynamically loaded assemblies (`None` = primary).
        assembly_index: Option<u32>,
        /// Method-level generic type arguments (`!!0`, `!!1`, ...) from MethodSpec.
        method_type_args: Option<Vec<Token>>,
    },

    /// No body/hook — return a synthetic value. Push value, advance IP.
    ReturnSynthetic {
        /// Synthetic value to push (None for void).
        value: Option<EmValue>,
    },

    /// A hook threw a CLR exception during call resolution.
    ///
    /// The main loop should create a synthetic exception object and route it
    /// through CIL exception handling (`try`/`catch`/`finally`).
    ThrowException {
        /// Synthetic exception type token.
        exception_type: Token,
        /// Diagnostic message.
        message: String,
    },

    /// Re-resolve with a different target (MethodSpec, delegate, reflection).
    ///
    /// The main loop pushes any provided arguments back onto the stack and
    /// re-enters `resolve_call()` with the new token.
    Redirect {
        /// New method token to resolve.
        target_token: Token,
        /// Arguments to push back onto the stack before re-resolving.
        /// Empty means args are still on the stack from the original call.
        arguments: Vec<EmValue>,
        /// Whether the redirected call is virtual.
        is_virtual: bool,
        /// For ConstructorInfo.Invoke: push this value onto the stack before
        /// entering the method frame, so it's preserved in the caller's saved
        /// stack across the constructor call.
        pre_push_value: Option<EmValue>,
        /// Whether this redirect originated from a reflection invoke
        /// (`MethodBase.Invoke`). Used to mark the frame so exceptions
        /// are wrapped in `TargetInvocationException`.
        is_reflection_invoke: bool,
        /// Assembly index for cross-assembly redirects (`None` = primary).
        assembly_index: Option<u32>,
        /// Method-level generic type arguments (`!!0`, `!!1`, ...) from MethodSpec.
        method_type_args: Option<Vec<Token>>,
    },
}

/// Result of resolving a `newobj` instruction.
///
/// Returned by `resolve_newobj()`. The main loop acts on each variant.
pub enum NewObjResolution {
    /// Hook handled the constructor. Push the constructed value, advance IP.
    HookedBypass {
        /// The value `newobj` pushes: the one the hook constructed and returned (a value
        /// type the emulator represents as a primitive, as `DateTime` is its ticks), or the
        /// allocated object the hook initialized.
        value: EmValue,
    },

    /// Enter the constructor's CIL body.
    EnterConstructor {
        /// Token of the resolved constructor.
        constructor_token: Token,
        /// The allocated object reference (already on the caller's saved stack).
        obj_ref: HeapRef,
        /// Constructor arguments (including `this` as first element).
        arguments: Vec<EmValue>,
    },

    /// No constructor body to execute. Push the object reference, advance IP.
    DefaultObject {
        /// The allocated object reference.
        obj_ref: HeapRef,
    },

    /// A hook threw a CLR exception during newobj resolution.
    ThrowException {
        /// Synthetic exception type token.
        exception_type: Token,
        /// Diagnostic message.
        message: String,
    },

    /// Re-resolve with an underlying token (MethodSpec → MethodDef).
    Redirect {
        /// The underlying constructor token to resolve.
        underlying_token: Token,
    },
}
