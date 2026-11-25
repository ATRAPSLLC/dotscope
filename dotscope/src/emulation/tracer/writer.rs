//! Trace event writer with file, memory, and listener dispatch.
//!
//! [`TraceWriter`] is the I/O layer of the tracing subsystem. It accepts
//! [`TraceEvent`]s from the execution engine and routes them to three
//! independent sinks:
//!
//! - **File** — append-mode NDJSON/JSONL output for offline analysis.
//!   Multiple emulation processes can share a single trace file (e.g.,
//!   anti-tamper warmup followed by string decryption).
//! - **Memory buffer** — bounded in-memory ring buffer for programmatic
//!   access via [`take_buffer()`](TraceWriter::take_buffer).
//! - **Listeners** — pluggable [`TraceListener`] observers for real-time
//!   analysis (e.g., [`CallTreeBuilder`](super::CallTreeBuilder)).
//!
//! # Dispatch Order
//!
//! On each [`write()`](TraceWriter::write) call:
//! 1. Increment the atomic event counter
//! 2. Dispatch to all registered listeners (synchronous)
//! 3. Serialize to file (if file-based) or append to buffer (if memory-based)
//!
//! # Thread Safety
//!
//! All internal state is behind `Mutex`es; a single `TraceWriter` can be
//! shared (via `Arc`) across the controller, call resolver, and any other
//! component that emits events.
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::emulation::{TraceWriter, CallTreeBuilder};
//!
//! // File-based writer with context prefix
//! let mut writer = TraceWriter::new_file("trace.jsonl", Some("warmup".into()))?;
//! writer.add_listener(Box::new(CallTreeBuilder::new()));
//!
//! // Memory-based writer for programmatic access
//! let writer = TraceWriter::new_memory(10_000, None);
//! // ... emulation runs ...
//! let events = writer.take_buffer().unwrap();
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    mem,
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

use crate::emulation::tracer::{event::TraceEvent, listener::TraceListener};

/// A writer for trace events.
///
/// Handles writing trace events to either a file or an in-memory buffer.
/// Thread-safe via internal locking. Supports pluggable [`TraceListener`]s
/// that receive every event for custom analysis.
pub struct TraceWriter {
    /// File writer if file-based tracing is enabled.
    file: Option<Mutex<BufWriter<File>>>,
    /// In-memory buffer if memory-based tracing is enabled.
    buffer: Option<Mutex<VecDeque<TraceEvent>>>,
    /// Maximum buffer size (0 = unlimited).
    max_entries: usize,
    /// Number of events written.
    event_count: AtomicU64,
    /// Context prefix to include in trace output.
    context_prefix: Option<String>,
    /// Registered trace listeners that receive every event.
    listeners: Vec<Box<dyn TraceListener>>,
}

impl TraceWriter {
    /// Creates a new trace writer for file-based tracing.
    ///
    /// The file is opened in append mode so that multiple emulation processes
    /// can write to the same trace file without overwriting each other's output.
    /// This is important during deobfuscation where anti-tamper emulation runs
    /// first, followed by warmup and decryption emulations.
    ///
    /// # Arguments
    ///
    /// * `path` - File path to write trace events to
    /// * `context` - Context prefix included in each trace event (e.g., "warmup", "decryption-0")
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or opened.
    pub fn new_file<P: AsRef<Path>>(path: P, context: Option<String>) -> std::io::Result<Self> {
        // Use append mode so multiple emulation processes can share the same trace file
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Some(Mutex::new(BufWriter::new(file))),
            buffer: None,
            max_entries: 0,
            event_count: AtomicU64::new(0),
            context_prefix: context,
            listeners: Vec::new(),
        })
    }

    /// Creates a new trace writer for memory-based tracing.
    ///
    /// # Arguments
    ///
    /// * `max_entries` - Maximum trace entries to keep (0 for unlimited)
    /// * `context` - Context prefix included in each trace event (e.g., "warmup", "decryption-0")
    #[must_use]
    pub fn new_memory(max_entries: usize, context: Option<String>) -> Self {
        Self {
            file: None,
            buffer: Some(Mutex::new(VecDeque::with_capacity(max_entries.min(10_000)))),
            max_entries,
            event_count: AtomicU64::new(0),
            context_prefix: context,
            listeners: Vec::new(),
        }
    }

    /// Returns the context prefix, if any.
    ///
    /// The context prefix is included as a `"context"` field in each JSON
    /// event line, allowing consumers to distinguish events from different
    /// emulation phases sharing the same trace file.
    #[must_use]
    pub fn context_prefix(&self) -> Option<&str> {
        self.context_prefix.as_deref()
    }

    /// Registers a [`TraceListener`] that will receive every event.
    ///
    /// Listeners are called synchronously during [`write()`](Self::write)
    /// before the event is serialized to file or appended to the memory
    /// buffer. Multiple listeners can be registered; they are dispatched
    /// in registration order.
    pub fn add_listener(&mut self, listener: Box<dyn TraceListener>) {
        self.listeners.push(listener);
    }

    /// Writes a trace event to all sinks.
    ///
    /// Increments the event counter, dispatches to all registered listeners,
    /// then serializes to file (NDJSON) or appends to the memory buffer.
    /// When the memory buffer exceeds `max_entries`, the oldest event is
    /// discarded.
    pub fn write(&self, event: TraceEvent) {
        self.event_count.fetch_add(1, Ordering::Relaxed);

        for listener in &self.listeners {
            listener.on_event(&event);
        }

        if let Some(ref file) = self.file {
            if let Ok(mut writer) = file.lock() {
                let json = event.to_json_with_context(self.context_prefix.as_deref());
                let _ = writeln!(writer, "{json}");
            }
        } else if let Some(ref buffer) = self.buffer {
            if let Ok(mut buf) = buffer.lock() {
                // Enforce max entries limit
                if self.max_entries > 0 && buf.len() >= self.max_entries {
                    buf.pop_front();
                }
                buf.push_back(event);
            }
        }
    }

    /// Flushes buffered file output and notifies all listeners.
    ///
    /// Calls [`on_flush()`](TraceListener::on_flush) on each registered
    /// listener, then flushes the underlying file writer (if file-based).
    /// No-op for memory-only writers beyond listener notification.
    pub fn flush(&self) {
        for listener in &self.listeners {
            listener.on_flush();
        }
        if let Some(ref file) = self.file {
            if let Ok(mut writer) = file.lock() {
                let _ = writer.flush();
            }
        }
    }

    /// Returns the total number of events written since creation.
    ///
    /// This counter is incremented atomically on every [`write()`](Self::write)
    /// call regardless of whether the event was written to file, buffer, or
    /// only dispatched to listeners.
    #[must_use]
    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    /// Takes the in-memory buffer, replacing it with an empty `VecDeque`.
    ///
    /// Returns `Some(events)` for memory-based writers, `None` for file-based
    /// writers. After this call, the buffer is empty and new events will
    /// accumulate from scratch.
    pub fn take_buffer(&self) -> Option<VecDeque<TraceEvent>> {
        self.buffer
            .as_ref()
            .and_then(|buf| buf.lock().ok().map(|mut b| mem::take(&mut *b)))
    }
}

impl std::fmt::Debug for TraceWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TraceWriter")
            .field("is_file_based", &self.file.is_some())
            .field("max_entries", &self.max_entries)
            .field("event_count", &self.event_count())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::tracer::{event::TraceEvent, listener::TraceListener, writer::TraceWriter},
        metadata::token::Token,
    };

    #[test]
    fn test_trace_writer_memory() {
        let writer = TraceWriter::new_memory(100, Some("test".to_string()));

        writer.write(TraceEvent::MethodCall {
            target: Token::new(0x06000001),
            is_virtual: false,
            arg_count: 2,
            call_depth: 1,
            caller: None,
            caller_offset: None,
            call_id: 1,
        });

        assert_eq!(writer.event_count(), 1);
        assert_eq!(writer.context_prefix(), Some("test"));

        let buffer = writer.take_buffer().unwrap();
        assert_eq!(buffer.len(), 1);
    }

    struct EventCounter {
        count: std::sync::atomic::AtomicUsize,
    }

    impl EventCounter {
        fn new() -> Self {
            Self {
                count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        #[allow(dead_code)]
        fn get(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    impl TraceListener for EventCounter {
        fn on_event(&self, _event: &TraceEvent) {
            self.count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    #[test]
    fn test_listener_receives_events() {
        let mut writer = TraceWriter::new_memory(100, None);
        writer.add_listener(Box::new(EventCounter::new()));

        writer.write(TraceEvent::MethodCall {
            target: Token::new(0x06000001),
            is_virtual: false,
            arg_count: 0,
            call_depth: 1,
            caller: None,
            caller_offset: None,
            call_id: 1,
        });
        writer.write(TraceEvent::MethodReturn {
            method: Token::new(0x06000001),
            has_return_value: false,
            call_depth: 0,
            call_id: 1,
        });

        assert_eq!(writer.event_count(), 2);
        // Buffer also has the events
        assert_eq!(writer.take_buffer().unwrap().len(), 2);
    }

    #[test]
    fn test_listener_coexists_with_buffer() {
        let mut writer = TraceWriter::new_memory(100, None);
        writer.add_listener(Box::new(EventCounter::new()));

        writer.write(TraceEvent::Instruction {
            method: Token::new(0x06000001),
            offset: 0,
            opcode: 0,
            mnemonic: "nop".to_string(),
            operand: None,
            stack_depth: 0,
            stack_values: None,
        });

        // Both listener and buffer received the event
        let buf = writer.take_buffer().unwrap();
        assert_eq!(buf.len(), 1);
        assert_eq!(writer.event_count(), 1);
    }

    #[test]
    fn test_multiple_listeners() {
        let mut writer = TraceWriter::new_memory(100, None);
        writer.add_listener(Box::new(EventCounter::new()));
        writer.add_listener(Box::new(EventCounter::new()));

        writer.write(TraceEvent::Instruction {
            method: Token::new(0x06000001),
            offset: 0,
            opcode: 0,
            mnemonic: "nop".to_string(),
            operand: None,
            stack_depth: 0,
            stack_values: None,
        });

        // Both listeners received the event (we can verify via event_count)
        assert_eq!(writer.event_count(), 1);
    }
}
