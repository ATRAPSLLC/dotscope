//! CIL emulation engine for .NET bytecode execution.
//!
//! This module provides a controlled execution environment for .NET CIL (Common
//! Intermediate Language) bytecode. The emulation engine is essential for
//! deobfuscation as many obfuscators rely on runtime computation of values,
//! dynamic string decryption, and control flow obfuscation that can only be
//! resolved through execution.
//!
//! # Architecture
//!
//! The emulation engine is organized into several sub-modules:
//!
//! - Runtime value representation with type safety and symbolic tracking
//! - Memory model including evaluation stack, locals, and managed heap
//! - Core interpreter and execution controller
//! - Hook system for intercepting method calls and providing custom behavior
//! - Process model for coordinating emulation
//! - Capture context for collecting results
//!
//! # Key Components
//!
//! ## Process Model
//! - [`crate::emulation::EmulationProcess`] - Central emulation process coordinating all components
//! - [`crate::emulation::ProcessBuilder`] - Fluent API for configuring emulation processes
//! - [`crate::emulation::EmulationConfig`] - Comprehensive configuration with presets
//!
//! ## Value System
//! - [`crate::emulation::EmValue`] - Runtime value representation for all CIL types
//! - [`crate::emulation::SymbolicValue`] - Tracks unknown/unresolved values during partial emulation
//! - [`crate::emulation::HeapRef`] - Reference to heap-allocated objects
//!
//! ## Memory Model
//! - [`crate::emulation::EvaluationStack`] - CIL evaluation stack with overflow protection
//! - [`crate::emulation::LocalVariables`] - Local variable storage with type-aware initialization
//! - [`crate::emulation::ManagedHeap`] - Simulated managed heap with memory limits
//! - [`crate::emulation::AddressSpace`] - Process-wide memory management
//!
//! ## Execution Engine
//! - [`crate::emulation::Interpreter`] - Core instruction interpreter
//! - [`crate::emulation::EmulationController`] - High-level execution control with limits
//! - [`crate::emulation::StepResult`] - Result of executing a single instruction
//!
//! ## Hook System
//! - [`crate::emulation::HookManager`] - Registry for method interception hooks
//! - [`crate::emulation::Hook`] - Builder for creating method hooks
//! - [`crate::emulation::HookContext`] - Information passed to hook handlers
//!
//! ## Result Capture
//! - [`crate::emulation::CaptureContext`] - Automatic result collection
//! - [`crate::emulation::CapturedAssembly`] - Captured Assembly.Load data
//! - [`crate::emulation::CapturedString`] - Captured decrypted strings
//!
//! ## Loading
//! - [`crate::emulation::PeLoader`] - PE image loader for memory mapping
//! - [`crate::emulation::DataLoader`] - Raw data loader
//!
//! # Usage Examples
//!
//! ## Process-Based Emulation
//!
//! ```no_run
//! use dotscope::emulation::ProcessBuilder;
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("sample.exe")?;
//! let pe_bytes = std::fs::read("sample.exe")?;
//!
//! let mut process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .map_pe_image(&pe_bytes, "sample.exe")
//!     .for_extraction()
//!     .capture_assemblies()
//!     .build()?;
//!
//! // Get captured assemblies after execution
//! for (idx, asm) in process.captured_assemblies().iter().enumerate() {
//!     std::fs::write(format!("extracted_{}.dll", idx), &asm.data)?;
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## String Decryption Pattern
//!
//! ```no_run
//! use dotscope::emulation::ProcessBuilder;
//! use dotscope::CilObject;
//!
//! let assembly = CilObject::from_path("sample.exe")?;
//! let process = ProcessBuilder::new()
//!     .assembly(assembly)
//!     .for_analysis()
//!     .capture_strings()
//!     .build()?;
//!
//! // After emulation
//! for string in process.captured_strings() {
//!     println!("Decrypted: {}", string.value);
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration with Analysis
//!
//! The emulation engine integrates with the analysis infrastructure:
//!
//! | Component | Usage |
//! |-----------|-------|
//! | CFG | Structured control flow during emulation |
//! | SSA | Value tracking and constant propagation |
//! | Data Flow | Identifying which values need emulation |
//! | Call Graph | Deciding method inlining/hooking |
//!
//! # Execution Limits
//!
//! The emulator enforces several limits to prevent runaway execution:
//!
//! - **Instruction limit**: Maximum instructions to execute
//! - **Call depth limit**: Maximum call stack depth
//! - **Memory limit**: Maximum heap allocation
//! - **Timeout**: Wall-clock time limit
//!
//! # Thread Safety
//!
//! The emulation types are designed for single-threaded use within an analysis
//! context. The [`crate::emulation::EmulationProcess`] and related types are `Send` but not
//! `Sync`, as emulation inherently involves mutable state.

mod capture;
mod engine;
mod exception;
mod fakeobjects;
mod filesystem;
mod loader;
mod memory;
mod process;
mod runtime;
mod thread;
pub mod tokens;
mod tracer;
mod value;

// Re-export primary types from value module
// Re-export primary types from capture module
pub use capture::{
    AssemblyLoadMethod, BufferSource, CaptureContext, CaptureSource, CaptureStats,
    CapturedAssembly, CapturedBuffer, CapturedMethodReturn, CapturedString, FileOpKind,
    FileOperation, MemoryRegionSnapshot, MemorySnapshot, NetworkEndpoint, NetworkOpKind,
    NetworkOperation, ResourceRead,
};
// Re-export primary types from engine module
pub use engine::{
    synthetic_exception, EmulationContext, EmulationController, EmulationError, EmulationOutcome,
    ExecutionStats, GenericRegistry, InstructionPointer, Interpreter, LimitExceeded, MethodCode,
    StepResult, SyntheticMethodBody,
};
// Re-export primary types from exception module
pub use exception::{
    ExceptionClause, ExceptionInfo, HandlerMatch, InstructionLocation, PendingFinally,
    ThreadExceptionState,
};
// Re-export primary types from fakeobjects module
pub use fakeobjects::{FakeObjects, SharedFakeObjects};
// Re-export primary types from filesystem module
pub use filesystem::VirtualFs;
// Re-export primary types from loader module
pub use loader::{
    DataLoader, LoadedImage, LoadedSection, MappedRegionInfo, PeLoader, PeLoaderConfig,
};
// Re-export primary types from memory module
pub use memory::{
    AddressSpace, ArgumentStorage, DelegateEntry, DictionaryKey, EncodingType, EvaluationStack,
    HeapIter, HeapObject, HeapState, LocalVariables, ManagedHeap, ManagedString, MemoryProtection,
    MemoryRegion, Page, PageDataGuard, SectionInfo, SharedHeap, StaticFieldStorage, ThreadId,
    TypeInitState, TypeWrapper, UnmanagedMemory, UnmanagedRef, PAGE_SIZE,
};
// Re-export primary types from process module
pub use process::{
    CaptureConfig, EmulationConfig, EmulationLimits, EmulationProcess, EnvironmentConfig,
    LimitKind, MemoryConfig, ProcessBuilder, ProcessSummary, StackTraceEntry, StubConfig,
    TracingConfig, UnknownMethodBehavior,
};
// Re-export primary types from runtime module
pub use runtime::{
    AppDomainState, Hook, HookContext, HookManager, HookMatcher, HookOutcome, HookPriority,
    InternalMethodMatcher, LoadedAssemblyInfo, NameMatcher, NativeFunction, NativeFunctionRegistry,
    NativeMethodMatcher, PostHookFn, PostHookResult, PreHookFn, PreHookResult, RuntimeMatcher,
    RuntimeState, RuntimeStateBuilder, SignatureMatcher,
};
// Re-export primary types from thread module
pub use thread::{
    EmulationThread, EventState, MonitorState, MulticastState, MutexState, ReflectionInvokeRequest,
    SchedulerOutcome, SemaphoreState, SyncError, SyncState, ThreadCallFrame, ThreadContext,
    ThreadPriority, ThreadScheduler, ThreadState, WaitReason, WakeCondition,
};
// Re-export tracing infrastructure
pub use tracer::{
    build_call_tree, CallTreeBuilder, CallTreeNode, ExceptionRecord, InstructionTraceLevel,
    MethodPattern, TraceEvent, TraceFilter, TraceListener, TraceWriter,
};
pub use value::{
    BinaryOp, CompareOp, ConversionType, EmValue, HeapRef, ManagedPointer, PointerTarget,
    SymbolicValue, TaintSource, UnaryOp,
};

pub use crate::utils::{LeBytes, LeBytesIter};
