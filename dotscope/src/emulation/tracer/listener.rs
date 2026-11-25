//! Trace listener trait for observing emulation events.
//!
//! Provides a pluggable observer mechanism for consuming [`TraceEvent`]s
//! during emulation without modifying the core tracing pipeline. Listeners
//! are registered on a [`TraceWriter`](super::TraceWriter) via
//! [`add_listener()`](super::TraceWriter::add_listener) and receive every
//! event synchronously before it is written to file or buffer.
//!
//! # Design
//!
//! The trait uses `&self` (not `&mut self`) because [`TraceWriter`](super::TraceWriter)
//! dispatches events under its own lock. Implementations must use interior
//! mutability (`Mutex`, atomics) to accumulate state. The `Send + Sync`
//! bounds allow listeners to be shared across threads via `Arc`.
//!
//! The default [`on_event()`](TraceListener::on_event) implementation
//! dispatches to typed helpers (`on_call`, `on_return`, `on_exception`,
//! `on_instruction`). Override `on_event` directly for custom routing,
//! or override individual helpers for targeted processing.
//!
//! # Built-in Listeners
//!
//! - [`CallTreeBuilder`](super::CallTreeBuilder) — builds a hierarchical
//!   call tree from `MethodCall`/`MethodReturn` events.
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::emulation::{TraceEvent, TraceListener};
//! use std::sync::atomic::{AtomicU64, Ordering};
//!
//! struct InstructionCounter(AtomicU64);
//!
//! impl TraceListener for InstructionCounter {
//!     fn on_instruction(&self, _event: &TraceEvent) {
//!         self.0.fetch_add(1, Ordering::Relaxed);
//!     }
//! }
//! ```

use crate::emulation::tracer::event::TraceEvent;

/// A listener that receives trace events during emulation.
///
/// Listeners use interior mutability (`Mutex`, atomics) since
/// [`TraceWriter`](super::TraceWriter) dispatches under its own lock.
///
/// Implement this trait to build custom analysis passes over the
/// emulation event stream (e.g., call tree construction, coverage
/// tracking, or anomaly detection).
pub trait TraceListener: Send + Sync {
    /// Called for every trace event. Default implementation dispatches
    /// to the typed helper methods.
    fn on_event(&self, event: &TraceEvent) {
        match event {
            TraceEvent::MethodCall { .. } => self.on_call(event),
            TraceEvent::MethodReturn { .. } => self.on_return(event),
            TraceEvent::ExceptionThrow { .. } | TraceEvent::ExceptionCatch { .. } => {
                self.on_exception(event)
            }
            TraceEvent::Instruction { .. } => self.on_instruction(event),
            _ => {}
        }
    }

    /// Called for [`TraceEvent::MethodCall`] events.
    fn on_call(&self, _event: &TraceEvent) {}

    /// Called for [`TraceEvent::MethodReturn`] events.
    fn on_return(&self, _event: &TraceEvent) {}

    /// Called for exception-related events.
    fn on_exception(&self, _event: &TraceEvent) {}

    /// Called for [`TraceEvent::Instruction`] events.
    fn on_instruction(&self, _event: &TraceEvent) {}

    /// Called when the trace writer flushes.
    fn on_flush(&self) {}
}
