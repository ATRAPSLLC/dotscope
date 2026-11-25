//! Process model for .NET emulation.
//!
//! This module provides the process-based abstraction for .NET emulation,
//! including configuration, process building, and execution management.
//! It serves as the high-level interface for setting up and running
//! emulation sessions.
//!
//! # Overview
//!
//! The process module organizes emulation around an [`EmulationProcess`],
//! which represents a single emulated .NET process with its own:
//!
//! - Address space (memory regions, PE images)
//! - Runtime state (method stubs, type information)
//! - Capture context (for collecting extracted data)
//! - Configuration (limits, behavior settings)
//!
//! # Key Components
//!
//! - [`ProcessBuilder`] - Fluent API for configuring and creating processes
//! - [`EmulationProcess`] - Central orchestrator for emulation execution
//! - [`EmulationConfig`] - Comprehensive configuration with presets
//! - [`CaptureConfig`] - Configuration for runtime data capture
//! - [`EmulationLimits`] - Resource and execution limits
//!
//! # Workflow
//!
//! The typical workflow for using this module is:
//!
//! 1. Create a [`ProcessBuilder`]
//! 2. Configure the builder with assembly, mappings, and settings
//! 3. Call [`build()`](ProcessBuilder::build) to create an [`EmulationProcess`]
//! 4. Execute methods using [`execute_method()`](EmulationProcess::execute_method)
//! 5. Retrieve captured data after execution
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::emulation::{ProcessBuilder, EmulationConfig};
//! use dotscope::CilObject;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Load the target assembly
//! let assembly = CilObject::from_path("packed.exe")?;
//!
//! // Build the emulation process
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .for_extraction()
//!     .capture_assemblies()
//!     .capture_strings()
//!     .build()?;
//!
//! // Find and execute the entry point
//! if let Some(entry_point) = process.find_entry_point() {
//!     let outcome = process.execute_method(entry_point, vec![])?;
//!     println!("Execution completed: {:?}", outcome);
//! }
//!
//! // Retrieve captured assemblies
//! for asm in process.captured_assemblies() {
//!     println!("Captured assembly: {} bytes", asm.data.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Configuration Presets
//!
//! The module provides preset configurations for common scenarios:
//!
//! - [`EmulationConfig::extraction()`] - For unpacking protected assemblies
//! - [`EmulationConfig::analysis()`] - For static analysis with symbolic tracking
//! - [`EmulationConfig::full()`] - For complete emulation with strict mode
//! - [`EmulationConfig::minimal()`] - For simple constant folding
//!
//! # See Also
//!
//! - [`crate::emulation::engine`] - Low-level execution engine
//! - [`crate::emulation::memory`] - Memory subsystem
//! - [`crate::emulation::runtime`] - Method stub implementations (BCL hooks)

mod builder;
mod config;
mod execution;

pub use builder::ProcessBuilder;
pub use config::{
    CaptureConfig, EmulationConfig, EmulationLimits, EnvironmentConfig, MemoryConfig, StubConfig,
    TracingConfig, UnknownMethodBehavior,
};
pub use execution::{EmulationProcess, LimitKind, ProcessSummary, StackTraceEntry};
