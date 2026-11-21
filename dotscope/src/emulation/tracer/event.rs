//! Trace event definitions and JSON serialization.
//!
//! This module defines the [`TraceEvent`] enum — the central data type of the
//! tracing subsystem. Each variant captures a specific observable side-effect
//! during CIL emulation. Events are produced by the execution engine
//! ([`EmulationController`](crate::emulation::EmulationController) and
//! [`CallResolver`](crate::emulation::engine::callresolver::CallResolver)) and consumed by the
//! [`TraceWriter`](super::TraceWriter).
//!
//! # Event Categories
//!
//! | Category | Variants |
//! |----------|----------|
//! | Execution | `Instruction`, `Branch`, `BranchCompare` |
//! | Calls | `MethodCall`, `MethodReturn`, `HookInvoke` |
//! | Exceptions | `ExceptionThrow`, `ExceptionCatch`, `FinallyEnter`, `RuntimeException` |
//! | Memory | `HeapAlloc`, `ArrayAlloc`, `ArrayStore`, `ArrayLoad` |
//! | Fields | `StaticFieldAccess`, `StaticFieldValue` |
//!
//! # Serialization
//!
//! Events are serialized as newline-delimited JSON (NDJSON/JSONL) via
//! [`TraceEvent::to_json()`]. Each event produces a self-contained JSON object
//! with a `"type"` discriminator field. Example output:
//!
//! ```json
//! {"type":"call","target":"0x06000D12","is_virtual":false,"arg_count":2,"call_depth":3,"call_id":42}
//! {"type":"instruction","method":"0x06000D12","offset":"0x0000","opcode":"0x0002","mnemonic":"ldarg.0","stack_depth":0}
//! {"type":"return","method":"0x06000D12","has_return_value":true,"call_depth":2,"call_id":42}
//! ```
//!
//! When a context prefix is set on the [`TraceWriter`](super::TraceWriter), each
//! line includes a `"context"` field for distinguishing events from different
//! emulation phases (e.g., "warmup", "decryption-0").

use std::fmt::Write as FmtWrite;

use crate::metadata::token::Token;

/// A trace event recorded during emulation.
///
/// Each event captures a specific point in execution with relevant context.
#[derive(Clone, Debug)]
pub enum TraceEvent {
    /// An instruction was executed.
    Instruction {
        /// Method containing the instruction.
        method: Token,
        /// IL offset within the method.
        offset: u32,
        /// Opcode byte (or FE-prefixed opcode).
        opcode: u16,
        /// Instruction mnemonic (e.g., "ldarg.0", "call").
        mnemonic: String,
        /// Operand description if any.
        operand: Option<String>,
        /// Evaluation stack depth before execution.
        stack_depth: usize,
        /// Top stack values after execution (when `trace_stack_values` is enabled).
        /// Contains up to 3 values from the top of the stack, formatted as strings.
        stack_values: Option<Vec<String>>,
    },

    /// A method was called.
    MethodCall {
        /// The method being called.
        target: Token,
        /// Whether this is a virtual call.
        is_virtual: bool,
        /// Number of arguments.
        arg_count: usize,
        /// Current call depth after this call.
        call_depth: usize,
        /// Caller method token.
        caller: Option<Token>,
        /// IL offset of the call instruction in caller.
        caller_offset: Option<u32>,
        /// Unique call ID for correlating calls with returns.
        call_id: u64,
    },

    /// A method returned.
    MethodReturn {
        /// The method that returned.
        method: Token,
        /// Whether a value was returned.
        has_return_value: bool,
        /// Current call depth after return.
        call_depth: usize,
        /// Correlation ID matching the [`MethodCall`](TraceEvent::MethodCall) that started this frame.
        call_id: u64,
    },

    /// An exception was thrown.
    ExceptionThrow {
        /// Method where the exception was thrown.
        method: Token,
        /// IL offset of the throw.
        offset: u32,
        /// Exception type token if known.
        exception_type: Option<Token>,
        /// Description of the exception.
        description: String,
    },

    /// An exception was caught.
    ExceptionCatch {
        /// Method containing the catch handler.
        method: Token,
        /// IL offset of the catch handler.
        handler_offset: u32,
        /// Exception type being caught.
        catch_type: Token,
    },

    /// A finally block was entered.
    FinallyEnter {
        /// Method containing the finally block.
        method: Token,
        /// IL offset of the finally handler.
        handler_offset: u32,
    },

    /// An object was allocated on the heap.
    HeapAlloc {
        /// Type token of the allocated object.
        type_token: Token,
        /// Heap reference ID.
        heap_ref: u64,
    },

    /// An array was allocated.
    ArrayAlloc {
        /// Element type token.
        element_type: Token,
        /// Array length.
        length: usize,
        /// Heap reference ID.
        heap_ref: u64,
    },

    /// A hook/stub was invoked.
    HookInvoke {
        /// Method token being hooked.
        method: Token,
        /// Hook name.
        hook_name: String,
        /// Whether the hook bypassed execution.
        bypassed: bool,
        /// Debug representation of the return value (if bypassed).
        return_value: Option<String>,
    },

    /// A runtime error was converted to a CLR exception.
    RuntimeException {
        /// Method where the error occurred.
        method: Token,
        /// IL offset where the error occurred.
        offset: u32,
        /// Error type name.
        error_type: String,
        /// Error description.
        description: String,
    },

    /// A branch was taken.
    Branch {
        /// Method containing the branch.
        method: Token,
        /// IL offset of the branch instruction.
        from_offset: u32,
        /// Target IL offset.
        to_offset: u32,
        /// Whether this is a conditional branch.
        conditional: bool,
    },

    /// A branch comparison was performed (for debugging).
    BranchCompare {
        /// Left operand value description.
        left: String,
        /// Right operand value description.
        right: String,
        /// Comparison operation.
        op: String,
        /// Result of the comparison.
        result: bool,
    },

    /// A static field was accessed.
    StaticFieldAccess {
        /// Field token.
        field: Token,
        /// Whether this is a load (true) or store (false).
        is_load: bool,
    },

    /// A static field was accessed with its value captured.
    ///
    /// Richer variant of [`StaticFieldAccess`](Self::StaticFieldAccess) that includes the method
    /// context and the field value at the time of access. Useful for
    /// CFF branch reconstruction and state machine debugging.
    StaticFieldValue {
        /// Method containing the ldsfld/stsfld instruction.
        method: Token,
        /// IL offset of the instruction.
        offset: u32,
        /// Field token.
        field: Token,
        /// Whether this is a load (true) or store (false).
        is_load: bool,
        /// Debug representation of the field value.
        value: String,
    },

    /// An array element was stored.
    ///
    /// This event captures the index and value being written to an array,
    /// which is useful for debugging DynCipher and similar state machines
    /// that build key arrays via stelem operations.
    ArrayStore {
        /// Method containing the stelem instruction.
        method: Token,
        /// IL offset of the stelem instruction.
        offset: u32,
        /// Heap reference of the array.
        heap_ref: u64,
        /// Index being written to.
        index: usize,
        /// String representation of the value being stored.
        value: String,
    },

    /// An array element was loaded.
    ///
    /// This event captures the index and value being read from an array,
    /// which is useful for debugging DynCipher and similar state machines.
    ArrayLoad {
        /// Method containing the ldelem instruction.
        method: Token,
        /// IL offset of the ldelem instruction.
        offset: u32,
        /// Heap reference of the array.
        heap_ref: u64,
        /// Index being read from.
        index: usize,
        /// String representation of the value being loaded.
        value: String,
    },
}

impl TraceEvent {
    /// Converts the event to a JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_json_with_context(None)
    }

    /// Converts the event to a JSON string with an optional context prefix.
    ///
    /// When a context is provided, it is included as a "context" field at the
    /// beginning of the JSON object.
    #[must_use]
    pub fn to_json_with_context(&self, context: Option<&str>) -> String {
        // Build context prefix: either `"context":"value",` or empty
        let context_prefix = context
            .map(|c| format!(r#""context":"{}","#, escape_json(c)))
            .unwrap_or_default();

        match self {
            TraceEvent::Instruction {
                method,
                offset,
                opcode,
                mnemonic,
                operand,
                stack_depth,
                stack_values,
            } => {
                let operand_str = operand
                    .as_ref()
                    .map(|o| format!(r#","operand":"{}""#, escape_json(o)))
                    .unwrap_or_default();
                let stack_str = stack_values
                    .as_ref()
                    .map(|vals| {
                        let items: Vec<String> = vals
                            .iter()
                            .map(|v| format!(r#""{}""#, escape_json(v)))
                            .collect();
                        format!(r#","stack":[{}]"#, items.join(","))
                    })
                    .unwrap_or_default();
                format!(
                    r#"{{{}"type":"instruction","method":"0x{:08X}","offset":"0x{:04X}","opcode":"0x{:04X}","mnemonic":"{}","stack_depth":{}{}{}}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    opcode,
                    escape_json(mnemonic),
                    stack_depth,
                    operand_str,
                    stack_str
                )
            }
            TraceEvent::MethodCall {
                target,
                is_virtual,
                arg_count,
                call_depth,
                caller,
                caller_offset,
                call_id,
            } => {
                let caller_str = caller
                    .map(|c| format!(r#","caller":"0x{:08X}""#, c.value()))
                    .unwrap_or_default();
                let caller_offset_str = caller_offset
                    .map(|o| format!(r#","caller_offset":"0x{o:04X}""#))
                    .unwrap_or_default();
                format!(
                    r#"{{{}"type":"call","target":"0x{:08X}","is_virtual":{},"arg_count":{},"call_depth":{},"call_id":{}{}{}}}"#,
                    context_prefix,
                    target.value(),
                    is_virtual,
                    arg_count,
                    call_depth,
                    call_id,
                    caller_str,
                    caller_offset_str
                )
            }
            TraceEvent::MethodReturn {
                method,
                has_return_value,
                call_depth,
                call_id,
            } => {
                format!(
                    r#"{{{}"type":"return","method":"0x{:08X}","has_return_value":{},"call_depth":{},"call_id":{}}}"#,
                    context_prefix,
                    method.value(),
                    has_return_value,
                    call_depth,
                    call_id
                )
            }
            TraceEvent::ExceptionThrow {
                method,
                offset,
                exception_type,
                description,
            } => {
                let type_str = exception_type
                    .map(|t| format!(r#","exception_type":"0x{:08X}""#, t.value()))
                    .unwrap_or_default();
                format!(
                    r#"{{{}"type":"throw","method":"0x{:08X}","offset":"0x{:04X}","description":"{}"{}}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    escape_json(description),
                    type_str
                )
            }
            TraceEvent::ExceptionCatch {
                method,
                handler_offset,
                catch_type,
            } => {
                format!(
                    r#"{{{}"type":"catch","method":"0x{:08X}","handler_offset":"0x{:04X}","catch_type":"0x{:08X}"}}"#,
                    context_prefix,
                    method.value(),
                    handler_offset,
                    catch_type.value()
                )
            }
            TraceEvent::FinallyEnter {
                method,
                handler_offset,
            } => {
                format!(
                    r#"{{{}"type":"finally","method":"0x{:08X}","handler_offset":"0x{:04X}"}}"#,
                    context_prefix,
                    method.value(),
                    handler_offset
                )
            }
            TraceEvent::HeapAlloc {
                type_token,
                heap_ref,
            } => {
                format!(
                    r#"{{{}"type":"heap_alloc","type_token":"0x{:08X}","heap_ref":{}}}"#,
                    context_prefix,
                    type_token.value(),
                    heap_ref
                )
            }
            TraceEvent::ArrayAlloc {
                element_type,
                length,
                heap_ref,
            } => {
                format!(
                    r#"{{{}"type":"array_alloc","element_type":"0x{:08X}","length":{},"heap_ref":{}}}"#,
                    context_prefix,
                    element_type.value(),
                    length,
                    heap_ref
                )
            }
            TraceEvent::HookInvoke {
                method,
                hook_name,
                bypassed,
                return_value,
            } => {
                let rv_str = return_value
                    .as_ref()
                    .map(|v| format!(r#","return_value":"{}""#, escape_json(v)))
                    .unwrap_or_default();
                format!(
                    r#"{{{}"type":"hook","method":"0x{:08X}","hook_name":"{}","bypassed":{}{}}}"#,
                    context_prefix,
                    method.value(),
                    escape_json(hook_name),
                    bypassed,
                    rv_str
                )
            }
            TraceEvent::RuntimeException {
                method,
                offset,
                error_type,
                description,
            } => {
                format!(
                    r#"{{{}"type":"runtime_exception","method":"0x{:08X}","offset":"0x{:04X}","error_type":"{}","description":"{}"}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    escape_json(error_type),
                    escape_json(description)
                )
            }
            TraceEvent::Branch {
                method,
                from_offset,
                to_offset,
                conditional,
            } => {
                format!(
                    r#"{{{}"type":"branch","method":"0x{:08X}","from":"0x{:04X}","to":"0x{:04X}","conditional":{}}}"#,
                    context_prefix,
                    method.value(),
                    from_offset,
                    to_offset,
                    conditional
                )
            }
            TraceEvent::StaticFieldAccess { field, is_load } => {
                format!(
                    r#"{{{}"type":"static_field","field":"0x{:08X}","is_load":{}}}"#,
                    context_prefix,
                    field.value(),
                    is_load
                )
            }
            TraceEvent::StaticFieldValue {
                method,
                offset,
                field,
                is_load,
                value,
            } => {
                format!(
                    r#"{{{}"type":"static_field_value","method":"0x{:08X}","offset":"0x{:04X}","field":"0x{:08X}","is_load":{},"value":"{}"}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    field.value(),
                    is_load,
                    escape_json(value)
                )
            }
            TraceEvent::BranchCompare {
                left,
                right,
                op,
                result,
            } => {
                format!(
                    r#"{{{}"type":"branch_compare","left":"{}","right":"{}","op":"{}","result":{}}}"#,
                    context_prefix,
                    escape_json(left),
                    escape_json(right),
                    escape_json(op),
                    result
                )
            }
            TraceEvent::ArrayStore {
                method,
                offset,
                heap_ref,
                index,
                value,
            } => {
                format!(
                    r#"{{{}"type":"array_store","method":"0x{:08X}","offset":"0x{:04X}","heap_ref":{},"index":{},"value":"{}"}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    heap_ref,
                    index,
                    escape_json(value)
                )
            }
            TraceEvent::ArrayLoad {
                method,
                offset,
                heap_ref,
                index,
                value,
            } => {
                format!(
                    r#"{{{}"type":"array_load","method":"0x{:08X}","offset":"0x{:04X}","heap_ref":{},"index":{},"value":"{}"}}"#,
                    context_prefix,
                    method.value(),
                    offset,
                    heap_ref,
                    index,
                    escape_json(value)
                )
            }
        }
    }
}

/// Escapes a string for JSON output.
fn escape_json(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(result, "\\u{:04X}", c as u32);
            }
            c => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_event_json() {
        let event = TraceEvent::Instruction {
            method: Token::new(0x06000001),
            offset: 0x0010,
            opcode: 0x28,
            mnemonic: "call".to_string(),
            operand: Some("0x0A000001".to_string()),
            stack_depth: 2,
            stack_values: None,
        };

        let json = event.to_json();
        assert!(json.contains("\"type\":\"instruction\""));
        assert!(json.contains("\"method\":\"0x06000001\""));
        assert!(json.contains("\"mnemonic\":\"call\""));
        assert!(!json.contains("\"context\""));
    }

    #[test]
    fn test_trace_event_json_with_context() {
        let event = TraceEvent::MethodCall {
            target: Token::new(0x06000001),
            is_virtual: false,
            arg_count: 2,
            call_depth: 1,
            caller: None,
            caller_offset: None,
            call_id: 1,
        };

        let json = event.to_json_with_context(Some("warmup"));
        assert!(json.contains("\"context\":\"warmup\""));
        assert!(json.contains("\"type\":\"call\""));
        assert!(json.contains("\"target\":\"0x06000001\""));

        let json_no_ctx = event.to_json_with_context(None);
        assert!(!json_no_ctx.contains("\"context\""));
        assert!(json_no_ctx.contains("\"type\":\"call\""));
    }

    #[test]
    fn test_escape_json() {
        assert_eq!(escape_json("hello"), "hello");
        assert_eq!(escape_json("hello\"world"), "hello\\\"world");
        assert_eq!(escape_json("line1\nline2"), "line1\\nline2");
    }

    #[test]
    fn test_static_field_value_json() {
        let event = TraceEvent::StaticFieldValue {
            method: Token::new(0x06000001),
            offset: 0x0010,
            field: Token::new(0x04000001),
            is_load: true,
            value: "I32(42)".to_string(),
        };
        let json = event.to_json();
        assert!(json.contains("\"type\":\"static_field_value\""));
        assert!(json.contains("\"field\":\"0x04000001\""));
        assert!(json.contains("\"value\":\"I32(42)\""));
    }
}
