//! Exception handler block interleaving engine.
//!
//! Converts flat exception handler metadata into nested `.try`/`.catch`/`.finally`/`.fault`/`.filter`
//! block events that are interleaved with IL instruction output at the correct offsets.

use std::collections::BTreeMap;

use crate::{
    formatting::helpers::assembly_scoped_name,
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags},
        typesystem::CilTypeRc,
    },
    CilObject,
};

/// A block event emitted at a specific IL offset during instruction rendering.
///
/// Events are produced by [`ExceptionBlockLayout::build`] and consumed during
/// instruction output to emit `.try`/`catch`/`finally`/`fault`/`filter` blocks
/// at the correct IL offsets.
#[derive(Debug)]
pub enum BlockEvent {
    /// Open a `.try {` block at the beginning of a protected region.
    TryOpen,
    /// Close a try block `}` at the end of a protected region.
    TryClose,
    /// Open a handler block (e.g., `catch [mscorlib]System.Exception {`).
    HandlerOpen {
        /// The specific kind of exception handler.
        kind: HandlerKind,
    },
    /// Close a handler block `}` at the end of a handler region.
    HandlerClose,
    /// Open a `filter {` block at the filter evaluation offset.
    FilterOpen,
    /// Close a `filter }` block before the handler body.
    FilterClose,
}

/// The kind of exception handler for a [`BlockEvent::HandlerOpen`].
#[derive(Debug)]
pub enum HandlerKind {
    /// A `catch` handler for a specific exception type.
    Catch(String),
    /// A `finally` handler that always executes on region exit.
    Finally,
    /// A `fault` handler that executes only on exceptional exit.
    Fault,
    /// A `filter` handler with a user-defined filter expression.
    Filter,
}

/// Precomputed layout of exception block events, keyed by IL offset.
///
/// Built from a flat list of [`ExceptionHandler`] entries and produces an
/// ordered map where close events precede open events at each offset,
/// enabling correct nesting during instruction output.
pub struct ExceptionBlockLayout {
    /// Events ordered by IL offset. At each offset, closes come before opens.
    pub events: BTreeMap<u32, Vec<BlockEvent>>,
}

impl ExceptionBlockLayout {
    /// Build the block event map from a slice of exception handlers.
    ///
    /// Groups handlers by their try region, then emits `TryOpen`/`TryClose`,
    /// `HandlerOpen`/`HandlerClose`, and `FilterOpen` events at the correct
    /// IL offsets. Close events are ordered before open events at the same offset.
    pub fn build(handlers: &[ExceptionHandler], asm: &CilObject) -> Self {
        if handlers.is_empty() {
            return Self {
                events: BTreeMap::new(),
            };
        }

        // Group handlers by try region (try_offset, try_end)
        let mut try_groups: BTreeMap<(u32, u32), Vec<&ExceptionHandler>> = BTreeMap::new();
        for handler in handlers {
            let try_end = handler.try_offset.saturating_add(handler.try_length);
            try_groups
                .entry((handler.try_offset, try_end))
                .or_default()
                .push(handler);
        }

        // Build events map. Use a temporary vec at each offset to control ordering.
        let mut close_events: BTreeMap<u32, Vec<BlockEvent>> = BTreeMap::new();
        let mut open_events: BTreeMap<u32, Vec<BlockEvent>> = BTreeMap::new();

        for ((try_offset, try_end), group) in &try_groups {
            // TryOpen at try_offset
            open_events
                .entry(*try_offset)
                .or_default()
                .push(BlockEvent::TryOpen);

            // TryClose at try_end
            close_events
                .entry(*try_end)
                .or_default()
                .push(BlockEvent::TryClose);

            // For each handler in this try group
            for handler in group {
                let handler_end = handler
                    .handler_offset
                    .saturating_add(handler.handler_length);
                let kind = handler_kind(handler, asm);

                // Filter block opens at filter_offset (before handler)
                if handler.flags == ExceptionHandlerFlags::FILTER {
                    open_events
                        .entry(handler.filter_offset)
                        .or_default()
                        .push(BlockEvent::FilterOpen);
                    // Filter block closes right before the handler body opens
                    close_events
                        .entry(handler.handler_offset)
                        .or_default()
                        .push(BlockEvent::FilterClose);
                }

                // HandlerOpen at handler_offset
                open_events
                    .entry(handler.handler_offset)
                    .or_default()
                    .push(BlockEvent::HandlerOpen { kind });

                // HandlerClose at handler_end
                close_events
                    .entry(handler_end)
                    .or_default()
                    .push(BlockEvent::HandlerClose);
            }
        }

        // Merge: at each offset, closes come before opens
        let mut events: BTreeMap<u32, Vec<BlockEvent>> = BTreeMap::new();
        let all_offsets: std::collections::BTreeSet<u32> = close_events
            .keys()
            .chain(open_events.keys())
            .copied()
            .collect();

        for offset in all_offsets {
            let entry = events.entry(offset).or_default();
            if let Some(closes) = close_events.remove(&offset) {
                entry.extend(closes);
            }
            if let Some(opens) = open_events.remove(&offset) {
                entry.extend(opens);
            }
        }

        Self { events }
    }

    /// Format a block event as an indented string line for output.
    ///
    /// Produces the ILAsm text for a block event (e.g., `.try\n{`, `catch ...\n{`,
    /// `}  // end handler`) with appropriate indentation at the given depth.
    pub fn format_event(event: &BlockEvent, indent: usize) -> String {
        let pad = "  ".repeat(indent);
        match event {
            BlockEvent::TryOpen => format!("{pad}.try\n{pad}{{"),
            BlockEvent::TryClose => format!("{pad}}}  // end .try"),
            BlockEvent::HandlerOpen { kind } => match kind {
                HandlerKind::Catch(type_name) => format!("{pad}catch {type_name}\n{pad}{{"),
                HandlerKind::Finally => format!("{pad}finally\n{pad}{{"),
                HandlerKind::Fault => format!("{pad}fault\n{pad}{{"),
                HandlerKind::Filter => format!("{pad}{{"),
            },
            BlockEvent::HandlerClose => format!("{pad}}}  // end handler"),
            BlockEvent::FilterOpen => format!("{pad}filter\n{pad}{{"),
            BlockEvent::FilterClose => format!("{pad}}}  // end filter"),
        }
    }
}

/// Determine the [`HandlerKind`] from an [`ExceptionHandler`]'s flags.
///
/// Maps the handler flags to `Catch` (with the caught type name), `Finally`,
/// `Fault`, or `Filter`.
fn handler_kind(handler: &ExceptionHandler, asm: &CilObject) -> HandlerKind {
    match handler.flags {
        ExceptionHandlerFlags::EXCEPTION => {
            let type_name = exception_type_name(handler.handler.as_ref(), asm);
            HandlerKind::Catch(type_name)
        }
        ExceptionHandlerFlags::FINALLY => HandlerKind::Finally,
        ExceptionHandlerFlags::FAULT => HandlerKind::Fault,
        ExceptionHandlerFlags::FILTER => HandlerKind::Filter,
        _ => HandlerKind::Catch("[unknown]".to_string()),
    }
}

/// Get a display name for an exception handler's caught type.
///
/// Returns the assembly-scoped name of the caught type, or falls back to
/// `[mscorlib]System.Object` when no type is specified.
fn exception_type_name(handler_type: Option<&CilTypeRc>, asm: &CilObject) -> String {
    handler_type.map_or_else(
        || "[mscorlib]System.Object".to_string(),
        |t| assembly_scoped_name(t, asm),
    )
}
