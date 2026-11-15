//! Call tree construction from emulation trace events.
//!
//! Provides [`CallTreeBuilder`] which implements [`TraceListener`] to
//! build a hierarchical call tree from method call/return events. Also
//! provides [`build_call_tree`] for post-hoc construction from a slice
//! of events.
//!
//! # Real-time vs Post-hoc
//!
//! The builder can be used in two modes:
//!
//! - **Real-time**: Register as a [`TraceListener`] on a
//!   [`TraceWriter`](super::TraceWriter). The tree is built incrementally
//!   as events arrive during emulation.
//! - **Post-hoc**: Feed a collected `&[TraceEvent]` slice to
//!   [`build_call_tree()`] after emulation completes. Both modes produce
//!   identical trees.
//!
//! # Algorithm
//!
//! The builder maintains a stack of in-progress [`CallTreeNode`]s:
//!
//! 1. **`MethodCall`** — push a new node onto the stack.
//! 2. **`Instruction`** — increment the top-of-stack instruction counter.
//! 3. **`ExceptionThrow`** — append an [`ExceptionRecord`] to the top node.
//! 4. **`ExceptionCatch`** — mark the latest uncaught exception as caught.
//! 5. **`MethodReturn`** — pop the matching node (by `call_id`), mark it
//!    `completed`, and attach it as a child of the new top (or as a root
//!    if the stack is empty).
//!
//! On [`finish()`](CallTreeBuilder::finish), any remaining stack entries
//! are drained as incomplete nodes (`completed: false`).
//!
//! # Output
//!
//! The resulting [`CallTreeNode`] tree can be serialized to JSON via
//! [`to_json()`](CallTreeNode::to_json) or displayed as indented text
//! via the [`Display`](std::fmt::Display) implementation.
//!
//! # Usage
//!
//! ```
//! use dotscope::emulation::{CallTreeBuilder, ProcessBuilder};
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/crafted_2.exe")?;
//! let tree_builder = CallTreeBuilder::new();
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .with_trace_listener(Box::new(tree_builder))
//!     .build()?;
//!
//! // After emulation, retrieve the tree
//! // (or use build_call_tree() for post-hoc construction from events)
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{fmt, sync::Mutex};

use log;

use crate::{
    emulation::tracer::{event::TraceEvent, listener::TraceListener},
    metadata::token::Token,
    Error, Result,
};

/// A node in the call tree representing a single method invocation.
#[derive(Clone, Debug)]
pub struct CallTreeNode {
    /// Unique call ID correlating with [`TraceEvent::MethodCall::call_id`].
    pub call_id: u64,
    /// Method token of the invoked method.
    pub method: Token,
    /// Call depth at time of invocation.
    pub call_depth: usize,
    /// Child method calls made from within this method.
    pub children: Vec<CallTreeNode>,
    /// Exceptions that occurred in this method (not in children).
    pub exceptions: Vec<ExceptionRecord>,
    /// Number of instructions executed within this method (not children).
    pub instruction_count: u64,
    /// Whether the method returned normally.
    pub completed: bool,
}

/// A record of an exception thrown during a method's execution.
#[derive(Clone, Debug)]
pub struct ExceptionRecord {
    /// Exception type token, if known.
    pub exception_type: Option<Token>,
    /// Human-readable exception description.
    pub description: String,
    /// Whether the exception was caught.
    pub caught: bool,
}

/// Internal builder state, protected by a mutex.
struct CallTreeState {
    /// Stack of in-progress method call nodes.
    stack: Vec<CallTreeNode>,
    /// Completed root-level call trees.
    roots: Vec<CallTreeNode>,
}

/// Builds a call tree from emulation trace events.
///
/// Can be used as a real-time [`TraceListener`] or via the standalone
/// [`build_call_tree`] function for post-hoc analysis.
///
/// # Thread Safety
///
/// Uses internal `Mutex` for state; safe to share across threads.
pub struct CallTreeBuilder {
    state: Mutex<CallTreeState>,
}

impl CallTreeBuilder {
    /// Creates a new, empty call tree builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(CallTreeState {
                stack: Vec::new(),
                roots: Vec::new(),
            }),
        }
    }

    /// Processes a single trace event and updates the call tree.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal mutex is poisoned.
    pub fn process_event(&self, event: &TraceEvent) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|e| Error::LockError(format!("CallTreeBuilder lock failed: {e}")))?;
        match event {
            TraceEvent::MethodCall {
                target,
                call_depth,
                call_id,
                ..
            } => {
                state.stack.push(CallTreeNode {
                    call_id: *call_id,
                    method: *target,
                    call_depth: *call_depth,
                    children: Vec::new(),
                    exceptions: Vec::new(),
                    instruction_count: 0,
                    completed: false,
                });
            }
            TraceEvent::MethodReturn { call_id, .. } => {
                // Find and pop the matching frame
                if let Some(pos) = state.stack.iter().rposition(|n| n.call_id == *call_id) {
                    let mut node = state.stack.remove(pos);
                    node.completed = true;
                    if let Some(parent) = state.stack.last_mut() {
                        parent.children.push(node);
                    } else {
                        state.roots.push(node);
                    }
                }
            }
            TraceEvent::Instruction { .. } => {
                if let Some(top) = state.stack.last_mut() {
                    top.instruction_count = top.instruction_count.saturating_add(1);
                }
            }
            TraceEvent::ExceptionThrow {
                exception_type,
                description,
                ..
            } => {
                if let Some(top) = state.stack.last_mut() {
                    top.exceptions.push(ExceptionRecord {
                        exception_type: *exception_type,
                        description: description.clone(),
                        caught: false,
                    });
                }
            }
            TraceEvent::ExceptionCatch { .. } => {
                // Mark the latest uncaught exception as caught
                if let Some(top) = state.stack.last_mut() {
                    if let Some(exc) = top.exceptions.iter_mut().rev().find(|e| !e.caught) {
                        exc.caught = true;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// Consumes the builder and returns the completed call tree roots.
    ///
    /// Any in-progress calls (without matching returns) are finalized
    /// with `completed: false` and attached to their parent or returned
    /// as roots.
    /// # Errors
    ///
    /// Returns an error if the internal mutex is poisoned.
    pub fn finish(self) -> Result<Vec<CallTreeNode>> {
        let mut state = self
            .state
            .into_inner()
            .map_err(|e| Error::LockError(format!("CallTreeBuilder lock failed: {e}")))?;
        // Drain remaining stack items as incomplete nodes
        while let Some(node) = state.stack.pop() {
            if let Some(parent) = state.stack.last_mut() {
                parent.children.push(node);
            } else {
                state.roots.push(node);
            }
        }
        Ok(state.roots)
    }

    /// Returns a snapshot of the current roots without consuming the builder.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal mutex is poisoned.
    pub fn roots_snapshot(&self) -> Result<Vec<CallTreeNode>> {
        let state = self
            .state
            .lock()
            .map_err(|e| Error::LockError(format!("CallTreeBuilder lock failed: {e}")))?;
        Ok(state.roots.clone())
    }
}

impl Default for CallTreeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceListener for CallTreeBuilder {
    fn on_event(&self, event: &TraceEvent) {
        if let Err(e) = self.process_event(event) {
            log::warn!("CallTreeBuilder: failed to process event: {e}");
        }
    }
}

/// Builds a call tree from a slice of trace events (post-hoc analysis).
///
/// This is equivalent to creating a [`CallTreeBuilder`], feeding all events,
/// and calling [`finish()`](CallTreeBuilder::finish).
///
/// # Errors
///
/// Returns an error if the internal mutex is poisoned.
pub fn build_call_tree(events: &[TraceEvent]) -> Result<Vec<CallTreeNode>> {
    let builder = CallTreeBuilder::new();
    for event in events {
        builder.process_event(event)?;
    }
    builder.finish()
}

impl CallTreeNode {
    /// Total instruction count including all descendants.
    #[must_use]
    pub fn total_instructions(&self) -> u64 {
        self.instruction_count.saturating_add(
            self.children
                .iter()
                .map(|c| c.total_instructions())
                .fold(0u64, u64::saturating_add),
        )
    }

    /// Converts the call tree to a JSON string.
    #[must_use]
    pub fn to_json(&self) -> String {
        let children_json: Vec<String> = self.children.iter().map(|c| c.to_json()).collect();
        let exceptions_json: Vec<String> = self
            .exceptions
            .iter()
            .map(|e| {
                let type_str = e
                    .exception_type
                    .map_or("null".to_string(), |t| format!("\"0x{:08X}\"", t.value()));
                format!(
                    r#"{{"type":{},"description":"{}","caught":{}}}"#,
                    type_str,
                    e.description.replace('"', "\\\""),
                    e.caught
                )
            })
            .collect();

        format!(
            r#"{{"call_id":{},"method":"0x{:08X}","depth":{},"instructions":{},"completed":{},"exceptions":[{}],"children":[{}]}}"#,
            self.call_id,
            self.method.value(),
            self.call_depth,
            self.instruction_count,
            self.completed,
            exceptions_json.join(","),
            children_json.join(",")
        )
    }

    /// Formats the tree with indentation for display.
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        let prefix = "  ".repeat(indent);
        let status = if self.completed { "+" } else { "~" };
        writeln!(
            f,
            "{}{} 0x{:08X} (id={}, insns={}, exceptions={})",
            prefix,
            status,
            self.method.value(),
            self.call_id,
            self.instruction_count,
            self.exceptions.len()
        )?;
        for child in &self.children {
            child.fmt_indented(f, indent.saturating_add(1))?;
        }
        Ok(())
    }
}

impl fmt::Display for CallTreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::tracer::{
            calltree::{build_call_tree, CallTreeBuilder},
            event::TraceEvent,
        },
        metadata::token::Token,
    };

    fn call_event(target: u32, call_id: u64, depth: usize) -> TraceEvent {
        TraceEvent::MethodCall {
            target: Token::new(target),
            is_virtual: false,
            arg_count: 0,
            call_depth: depth,
            caller: None,
            caller_offset: None,
            call_id,
        }
    }

    fn return_event(method: u32, call_id: u64, depth: usize) -> TraceEvent {
        TraceEvent::MethodReturn {
            method: Token::new(method),
            has_return_value: false,
            call_depth: depth,
            call_id,
        }
    }

    fn instruction_event(method: u32) -> TraceEvent {
        TraceEvent::Instruction {
            method: Token::new(method),
            offset: 0,
            opcode: 0,
            mnemonic: "nop".to_string(),
            operand: None,
            stack_depth: 0,
            stack_values: None,
        }
    }

    fn throw_event(method: u32) -> TraceEvent {
        TraceEvent::ExceptionThrow {
            method: Token::new(method),
            offset: 0,
            exception_type: Some(Token::new(0x01000001)),
            description: "test exception".to_string(),
        }
    }

    fn catch_event(method: u32) -> TraceEvent {
        TraceEvent::ExceptionCatch {
            method: Token::new(method),
            handler_offset: 0,
            catch_type: Token::new(0x01000001),
        }
    }

    #[test]
    fn test_simple_chain() {
        // A calls B, B returns, A returns
        let events = vec![
            call_event(0x06000001, 1, 1),
            call_event(0x06000002, 2, 2),
            return_event(0x06000002, 2, 1),
            return_event(0x06000001, 1, 0),
        ];
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].method, Token::new(0x06000001));
        assert!(roots[0].completed);
        assert_eq!(roots[0].children.len(), 1);
        assert_eq!(roots[0].children[0].method, Token::new(0x06000002));
        assert!(roots[0].children[0].completed);
    }

    #[test]
    fn test_siblings() {
        // A calls B, B returns, A calls C, C returns, A returns
        let events = vec![
            call_event(0x06000001, 1, 1),
            call_event(0x06000002, 2, 2),
            return_event(0x06000002, 2, 1),
            call_event(0x06000003, 3, 2),
            return_event(0x06000003, 3, 1),
            return_event(0x06000001, 1, 0),
        ];
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].children.len(), 2);
        assert_eq!(roots[0].children[0].method, Token::new(0x06000002));
        assert_eq!(roots[0].children[1].method, Token::new(0x06000003));
    }

    #[test]
    fn test_deep_nesting() {
        let mut events = Vec::new();
        for i in 0..10 {
            events.push(call_event(0x06000001 + i, (i + 1).into(), (i + 1) as usize));
        }
        for i in (0..10).rev() {
            events.push(return_event(0x06000001 + i, (i + 1).into(), i as usize));
        }
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots.len(), 1);
        let mut node = &roots[0];
        for _ in 0..9 {
            assert_eq!(node.children.len(), 1);
            assert!(node.completed);
            node = &node.children[0];
        }
        assert!(node.children.is_empty());
        assert!(node.completed);
    }

    #[test]
    fn test_incomplete() {
        // Call without return
        let events = vec![call_event(0x06000001, 1, 1), call_event(0x06000002, 2, 2)];
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots.len(), 1);
        assert!(!roots[0].completed);
        assert_eq!(roots[0].children.len(), 1);
        assert!(!roots[0].children[0].completed);
    }

    #[test]
    fn test_exception_tracking() {
        let events = vec![
            call_event(0x06000001, 1, 1),
            throw_event(0x06000001),
            catch_event(0x06000001),
            return_event(0x06000001, 1, 0),
        ];
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].exceptions.len(), 1);
        assert!(roots[0].exceptions[0].caught);
    }

    #[test]
    fn test_instruction_counting() {
        let events = vec![
            call_event(0x06000001, 1, 1),
            instruction_event(0x06000001),
            instruction_event(0x06000001),
            instruction_event(0x06000001),
            call_event(0x06000002, 2, 2),
            instruction_event(0x06000002),
            instruction_event(0x06000002),
            return_event(0x06000002, 2, 1),
            instruction_event(0x06000001),
            return_event(0x06000001, 1, 0),
        ];
        let roots = build_call_tree(&events).unwrap();
        assert_eq!(roots[0].instruction_count, 4); // 3 before child + 1 after
        assert_eq!(roots[0].children[0].instruction_count, 2);
        assert_eq!(roots[0].total_instructions(), 6);
    }

    #[test]
    fn test_post_hoc_matches_realtime() {
        let events = vec![
            call_event(0x06000001, 1, 1),
            instruction_event(0x06000001),
            call_event(0x06000002, 2, 2),
            return_event(0x06000002, 2, 1),
            return_event(0x06000001, 1, 0),
        ];

        // Post-hoc
        let post_hoc = build_call_tree(&events).unwrap();

        // Real-time via builder
        let builder = CallTreeBuilder::new();
        for event in &events {
            builder.process_event(event).unwrap();
        }
        let realtime = builder.finish().unwrap();

        // Compare structure
        assert_eq!(post_hoc.len(), realtime.len());
        assert_eq!(post_hoc[0].method, realtime[0].method);
        assert_eq!(post_hoc[0].completed, realtime[0].completed);
        assert_eq!(post_hoc[0].instruction_count, realtime[0].instruction_count);
        assert_eq!(post_hoc[0].children.len(), realtime[0].children.len());
    }
}
