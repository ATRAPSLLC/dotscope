//! Boxing, unboxing, and type casting operations for CIL emulation.
//!
//! Handles `box`, `unbox`, `unbox.any`, `castclass`, and `isinst` instructions.

use crate::{
    emulation::{
        engine::{context::EmulationContext, EmulationError},
        thread::EmulationThread,
        EmValue,
    },
    metadata::token::Token,
    Result,
};

/// Handles `box` instruction — boxes a value type.
///
/// Converts a value type to an object reference by allocating a boxed
/// container on the managed heap.
///
/// Per ECMA-335 §III.4.1, boxing `Nullable<T>`:
/// - If `HasValue` is false (value is Null) → pushes null reference
/// - If `HasValue` is true → boxes the inner value as plain `T`
///
/// # Arguments
///
/// * `thread` - The emulation thread (for heap/stack access)
/// * `context` - Optional emulation context for `Nullable<T>` detection
/// * `type_token` - Token of the value type being boxed
///
/// # Errors
///
/// Returns an error if stack underflow or heap allocation fails.
pub fn handle_box(
    thread: &mut EmulationThread,
    context: Option<&EmulationContext>,
    type_token: Token,
) -> Result<()> {
    let value = thread.pop()?;

    // ECMA-335 §III.4.1: Nullable<T> boxing special case
    if let Some(ctx) = context {
        if let Some(type_info) = ctx.get_type(type_token) {
            if type_info.name == "Nullable`1" && type_info.namespace == "System" {
                // Nullable<T> boxing: null → push null, value → box as T
                if matches!(value, EmValue::Null) {
                    thread.push(EmValue::Null)?;
                    return Ok(());
                }
                // Box as the underlying T type (first generic argument)
                // Fall through to normal boxing if we can't resolve T
            }
        }
    }

    let boxed_ref = thread.heap_mut().alloc_boxed(type_token, value.clone())?;
    thread.push(EmValue::ObjectRef(boxed_ref))?;
    Ok(())
}

/// Handles `unbox` and `unbox.any` instructions.
///
/// Extracts the value from a boxed object. For `unbox.any`, the value is copied
/// directly onto the stack. Verifies type compatibility when context is available.
///
/// # Arguments
///
/// * `thread` - The emulation thread for heap/stack access
/// * `context` - Optional emulation context for type verification
/// * `type_token` - Expected type of the unboxed value
///
/// # Errors
///
/// Returns an error if:
/// - Stack underflow occurs
/// - Null reference is unboxed
/// - Type mismatch when context is provided
pub fn handle_unbox(
    thread: &mut EmulationThread,
    context: Option<&EmulationContext>,
    type_token: Token,
) -> Result<()> {
    let obj = thread.pop()?;

    match obj {
        EmValue::ObjectRef(href) => {
            if let Some(ctx) = context {
                if let Ok(source_type) = thread.heap().get_type_token(href) {
                    if ctx.is_value_type(type_token) {
                        // ECMA-335 III.4.32: value type unboxing requires exact type match
                        if source_type != type_token {
                            let from_type = ctx.format_type_token(source_type);
                            let to_type = ctx.format_type_token(type_token);
                            return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                        }
                    } else if !ctx.is_type_compatible(source_type, type_token) {
                        let from_type = ctx.format_type_token(source_type);
                        let to_type = ctx.format_type_token(type_token);
                        return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                    }
                }
            }

            if let Ok(value) = thread.heap().get_boxed_value(href) {
                thread.push(value)?;
            } else {
                if let Some(ctx) = context {
                    if ctx.is_value_type(type_token) {
                        let from_type = thread.heap().get_type_token(href).map_or_else(
                            |_| "unknown object".to_string(),
                            |t| ctx.format_type_token(t),
                        );
                        let to_type = ctx.format_type_token(type_token);
                        return Err(EmulationError::InvalidCast { from_type, to_type }.into());
                    }
                }
                thread.push(EmValue::ObjectRef(href))?;
            }
        }
        EmValue::Null => {
            return Err(EmulationError::NullReference.into());
        }
        other => {
            thread.push(other)?;
        }
    }

    Ok(())
}

/// Handles `castclass` instruction.
///
/// Attempts to cast an object reference to the specified type. Throws
/// `InvalidCastException` if the cast fails. Null passes through
/// unchanged per ECMA-335 III.4.3.
///
/// # Arguments
///
/// * `thread` - The emulation thread for heap/stack access
/// * `context` - The emulation context for type compatibility checking
/// * `target_type` - Token of the type to cast to
///
/// # Errors
///
/// Returns an error if stack underflow or cast fails due to type incompatibility.
pub fn handle_castclass(
    thread: &mut EmulationThread,
    context: &EmulationContext,
    target_type: Token,
) -> Result<()> {
    let value = thread.pop()?;

    match &value {
        EmValue::Null => {
            thread.push(EmValue::Null)?;
        }

        EmValue::ObjectRef(heap_ref) => {
            let source_type = thread.heap().get_type_token(*heap_ref)?;

            if context.is_type_compatible(source_type, target_type) {
                thread.push(value)?;
            } else {
                let from_type = context.format_type_token(source_type);
                let to_type = context.format_type_token(target_type);
                return Err(EmulationError::InvalidCast { from_type, to_type }.into());
            }
        }

        _ => {
            let from_type = value.cil_flavor().as_str().to_string();
            let to_type = context.format_type_token(target_type);
            return Err(EmulationError::InvalidCast { from_type, to_type }.into());
        }
    }

    Ok(())
}

/// Handles `isinst` instruction.
///
/// Tests if an object reference is an instance of the specified type.
/// Returns the object reference if compatible, or null if not.
/// Unlike `castclass`, this never throws an exception per ECMA-335 III.4.6.
///
/// # Arguments
///
/// * `thread` - The emulation thread for heap/stack access
/// * `context` - The emulation context for type compatibility checking
/// * `target_type` - Token of the type to check against
///
/// # Errors
///
/// Returns an error if stack underflow or heap lookup fails.
pub fn handle_isinst(
    thread: &mut EmulationThread,
    context: &EmulationContext,
    target_type: Token,
) -> Result<()> {
    let value = thread.pop()?;

    match &value {
        EmValue::ObjectRef(heap_ref) => {
            let source_type = thread.heap().get_type_token(*heap_ref)?;

            if context.is_type_compatible(source_type, target_type) {
                thread.push(value)?;
            } else {
                thread.push(EmValue::Null)?;
            }
        }

        _ => {
            thread.push(EmValue::Null)?;
        }
    }

    Ok(())
}
