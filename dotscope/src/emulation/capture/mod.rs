//! Result capture for .NET emulation.
//!
//! This module provides the infrastructure for collecting and storing data
//! intercepted during .NET emulation. The primary entry point is [`CaptureContext`],
//! which serves as the central collection point for all captured data.
//!
//! # Overview
//!
//! During emulation of .NET assemblies, various interesting events occur that
//! reveal the true behavior of obfuscated or packed code. This module captures:
//!
//! - **Assemblies**: Loaded via `Assembly.Load(byte[])` and similar methods,
//!   enabling extraction of packed or encrypted payloads
//! - **Strings**: Decrypted or dynamically generated strings that may reveal
//!   configuration, URLs, registry keys, or other sensitive data
//! - **Buffers**: Raw byte buffers from `Marshal.Copy`, crypto transforms, and
//!   other memory operations
//! - **File Operations**: File system access patterns including reads, writes,
//!   and directory operations
//! - **Network Operations**: TCP/UDP connections, HTTP requests, DNS lookups,
//!   and data transfers
//! - **Method Returns**: Return values from specific monitored methods
//! - **Memory Snapshots**: Point-in-time captures of configured memory regions
//!
//! # Architecture
//!
//! The module is organized into two main components:
//!
//! - [`context`]: Contains [`CaptureContext`], the thread-safe collection point
//! - [`types`]: Defines all data structures for captured items
//!
//! # Usage
//!
//! The capture context is typically created at the start of emulation and shared
//! with the emulation engine. Data is captured automatically as the emulated
//! code executes.
//!
//! ```no_run
//! use dotscope::emulation::CaptureContext;
//!
//! // Create a capture context (captures everything by default)
//! let ctx = CaptureContext::new();
//!
//! // Pass ctx to the emulation engine...
//!
//! // After emulation, retrieve captured data
//! for assembly in ctx.assemblies() {
//!     println!("Extracted assembly: {} bytes", assembly.data.len());
//!     // Save assembly.data to disk for further analysis
//! }
//!
//! for string in ctx.strings() {
//!     println!("Decrypted: {}", string.value);
//! }
//!
//! // Check statistics
//! let stats = ctx.stats();
//! println!("Total captured: {} assemblies, {} strings",
//!          stats.assembly_bytes, stats.string_count);
//! ```
//!
//! # Configuration
//!
//! Capture behavior can be controlled via [`CaptureConfig`](crate::emulation::process::CaptureConfig):
//!
//! ```no_run
//! use dotscope::emulation::CaptureContext;
//! use dotscope::emulation::CaptureConfig;
//!
//! // Only capture assemblies (minimal overhead)
//! let ctx = CaptureContext::assemblies_only();
//!
//! // Or with full configuration
//! let config = CaptureConfig {
//!     assemblies: true,
//!     strings: true,
//!     file_operations: false,  // Don't capture file ops
//!     network_operations: false,  // Don't capture network ops
//!     ..Default::default()
//! };
//! let ctx = CaptureContext::with_config(config);
//! ```
//!
//! # Thread Safety
//!
//! [`CaptureContext`] is designed for concurrent access from multiple emulation
//! threads. All capture operations use fine-grained locking and are non-blocking
//! for readers.

mod context;
mod types;

pub use context::{CaptureContext, CaptureStats, ResourceRead};
pub use types::{
    AssemblyLoadMethod, BufferSource, CaptureSource, CapturedAssembly, CapturedBuffer,
    CapturedMethodReturn, CapturedString, FileOpKind, FileOperation, MemoryRegionSnapshot,
    MemorySnapshot, NetworkEndpoint, NetworkOpKind, NetworkOperation,
};
