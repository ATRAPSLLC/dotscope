//! .NET Runtime simulation for emulation.
//!
//! This module provides runtime services for .NET Common Language Runtime (CLR) emulation,
//! enabling the execution of .NET bytecode in a controlled, sandboxed environment. The runtime
//! module is essential for deobfuscation, malware analysis, and static analysis of .NET
//! assemblies where actual execution is not desirable or possible.
//!
//! # Overview
//!
//! The runtime module simulates key aspects of the .NET CLR:
//!
//! - **Hook System**: Flexible method interception with pattern matching and pre/post hooks
//! - **BCL Implementations**: Native implementations of Base Class Library methods
//! - **Native Interop**: P/Invoke support for Windows API calls commonly used by obfuscators
//! - **Application Domain**: Simulation of .NET AppDomain behavior including assembly loading
//!
//! # Key Components
//!
//! - [`RuntimeState`] - Central runtime state management that coordinates all runtime services
//! - [`HookManager`] - Registry for method interception hooks
//! - [`Hook`] - Builder for creating method hooks with matchers and handlers
//! - [`AppDomainState`] - Application domain simulation with type hierarchy tracking
//! - [`native`] - P/Invoke hooks for Windows API emulation
//!
//! # Architecture
//!
//! The runtime module integrates with the emulation engine through several layers:
//!
//! ```text
//! +-------------------+
//! |  EmulationEngine  |
//! +--------+----------+
//!          |
//!          v
//! +--------+----------+     +-------------------+
//! |   RuntimeState    +---->|   HookManager     |
//! +--------+----------+     | (BCL + Native)    |
//!          |                +-------------------+
//!          |
//!          +--------------->+-------------------+
//!                           |  AppDomainState   |
//!                           +-------------------+
//! ```
//!
//! ## Hook Resolution Order
//!
//! When a method call is encountered during emulation:
//!
//! 1. **Hook Matching**: Check [`HookManager`] for matching hooks (by priority)
//! 2. **Pre-Hook**: Execute pre-hook (can bypass original method)
//! 3. **Original Method**: Execute if not bypassed
//! 4. **Post-Hook**: Execute post-hook (can modify return value)
//! 5. **Default Behavior**: Apply [`UnknownMethodBehavior`] if no hook matches
//!
//! # Examples
//!
//! ## Basic Runtime Setup
//!
//! ```
//! use dotscope::emulation::EmulationConfig;
//! use dotscope::emulation::RuntimeState;
//! use dotscope::emulation::RuntimeStateBuilder;
//!
//! // Create runtime with default BCL hooks
//! let runtime = RuntimeState::new();
//!
//! // Or use the builder for custom configuration
//! let runtime = RuntimeStateBuilder::new()
//!     .config(EmulationConfig::minimal())
//!     .build()?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Registering Custom Hooks
//!
//! ```
//! use dotscope::emulation::EmValue;
//! use dotscope::emulation::RuntimeState;
//! use dotscope::emulation::Hook;
//! use dotscope::emulation::PreHookResult;
//!
//! let runtime = RuntimeState::new();
//! runtime.hooks().register(
//!     Hook::new("my-hook")
//!         .match_name("MyNamespace", "MyType", "MyMethod")
//!         .pre(|_ctx, _thread| {
//!             PreHookResult::Bypass(Some(EmValue::I32(42)))
//!         })
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Use Cases
//!
//! ## Deobfuscation
//!
//! The runtime module is designed to support deobfuscation of protected .NET assemblies:
//!
//! - **String Decryption**: Emulate decryption methods to recover original strings
//! - **Control Flow**: Execute dispatcher methods to reconstruct original control flow
//! - **Anti-Debug Bypass**: Native stubs return "not debugged" for anti-debugging checks
//!
//! ## Malware Analysis
//!
//! Safe analysis of potentially malicious .NET code:
//!
//! - **Sandboxed Execution**: Methods execute in a controlled environment
//! - **API Monitoring**: Track what native APIs the code attempts to call
//! - **Behavior Analysis**: Observe runtime behavior without actual execution
//!
//! # Thread Safety
//!
//! The runtime module is designed for single-threaded emulation. While [`RuntimeState`]
//! uses thread-safe primitives internally, concurrent access to a single runtime instance
//! from multiple threads is not supported. For multi-threaded scenarios, create separate
//! runtime instances per thread.

mod appdomain;
mod bcl;
mod hook;
mod native;
mod state;

pub use appdomain::{AppDomainState, LoadedAssemblyInfo};
pub use bcl::get_bcl_static_field;
pub use hook::{
    Hook, HookContext, HookManager, HookMatcher, HookOutcome, HookPriority, InternalMethodMatcher,
    NameMatcher, NativeMethodMatcher, PostHookFn, PostHookResult, PreHookFn, PreHookResult,
    RuntimeMatcher, SignatureMatcher,
};
pub use state::{RuntimeState, RuntimeStateBuilder};
