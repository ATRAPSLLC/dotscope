//! Execution tracing infrastructure for the CIL emulation engine.
//!
//! This module provides a self-contained tracing subsystem that records, filters,
//! and analyzes events produced during CIL bytecode emulation. It is consumed by
//! the execution engine ([`crate::emulation::engine`]) but has no dependency on
//! engine internals — the dependency flows strictly one way.
//!
//! # Components
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`event`] | [`TraceEvent`] enum (event definitions + JSON serialization) |
//! | [`writer`] | [`TraceWriter`] (file/memory I/O + listener dispatch) |
//! | [`listener`] | [`TraceListener`] trait (pluggable observer interface) |
//! | [`filter`] | [`TraceFilter`] and [`MethodPattern`] (output filtering) |
//! | [`calltree`] | [`CallTreeBuilder`] (hierarchical call tree from events) |
//!
//! # Architecture
//!
//! ```text
//!   ┌───────────────┐       emits        ┌─────────────┐
//!   │  Controller / │ ────────────────►  │ TraceWriter │
//!   │  CallResolver │                    │ (writer.rs) │
//!   └───────────────┘                    └──────┬──────┘
//!                                               │
//!                              dispatches to    │
//!                         ┌─────────────────────┼──────────────┐
//!                         ▼                     ▼              ▼
//!                   File (JSONL)          Memory buffer    Listeners
//!                                                        (listener.rs)
//!                                                             │
//!                                                    ┌────────┴────────┐
//!                                                    │ CallTreeBuilder │
//!                                                    │  (calltree.rs)  │
//!                                                    └─────────────────┘
//! ```
//!
//! # Filtering
//!
//! [`TraceFilter`] controls which methods and call depths produce trace output.
//! It is stored in [`TracingConfig`](crate::emulation::TracingConfig) and checked
//! by the execution engine at each trace point. When the filter rejects an event,
//! no I/O occurs — the overhead is a single `should_trace()` call.
//!
//! # Output Format
//!
//! Trace events are serialized as newline-delimited JSON (NDJSON/JSONL). Each
//! line is a self-contained JSON object with a `"type"` discriminator field.
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::emulation::{
//!     ProcessBuilder, TracingConfig, TraceFilter, CallTreeBuilder,
//! };
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("tests/samples/crafted_2.exe")?;
//!
//! // File-based tracing with depth filter
//! let filter = TraceFilter {
//!     max_depth: Some(5),
//!     ..TraceFilter::default()
//! };
//!
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .with_tracing(TracingConfig::full_trace("trace.log"))
//!     .with_trace_listener(Box::new(CallTreeBuilder::new()))
//!     .build()?;
//! # Ok::<(), dotscope::Error>(())
//! ```

mod calltree;
mod event;
mod filter;
mod listener;
mod writer;

pub use calltree::{build_call_tree, CallTreeBuilder, CallTreeNode, ExceptionRecord};
pub use event::TraceEvent;
pub use filter::{InstructionTraceLevel, MethodPattern, TraceFilter};
pub use listener::TraceListener;
pub use writer::TraceWriter;
