//! Emulation configuration types.
//!
//! This module provides comprehensive configuration for the emulation engine,
//! allowing fine-grained control over execution limits, memory settings,
//! stub behavior, and tracing options.
//!
//! # Overview
//!
//! Configuration is organized into several interconnected structures:
//!
//! - [`EmulationConfig`] - Top-level configuration container
//! - [`EmulationLimits`] - Execution limits (instructions, call depth, memory)
//! - [`MemoryConfig`] - Memory subsystem settings
//! - [`StubConfig`] - Method stub behavior
//! - [`TracingConfig`] - Logging and tracing options
//! - [`CaptureConfig`] - Runtime data capture settings
//!
//! # Configuration Presets
//!
//! For common use cases, [`EmulationConfig`] provides preset configurations:
//!
//! - [`EmulationConfig::extraction()`] - Optimized for unpacking/decrypting assemblies
//! - [`EmulationConfig::analysis()`] - Optimized for static analysis
//! - [`EmulationConfig::full()`] - Complete emulation with all features
//! - [`EmulationConfig::minimal()`] - Lightweight constant folding
//!
//! # Example
//!
//! ```rust,no_run
//! use dotscope::emulation::{EmulationConfig, EmulationLimits};
//!
//! // Use a preset
//! let config = EmulationConfig::extraction();
//!
//! // Or customize
//! let config = EmulationConfig {
//!     limits: EmulationLimits::new()
//!         .with_max_instructions(10_000_000)
//!         .with_timeout_ms(30_000),
//!     symbolic_tracking: true,
//!     ..Default::default()
//! };
//! ```

use std::{collections::HashMap, ops::Range, path::PathBuf};

use crate::{emulation::tracer::TraceFilter, metadata::typesystem::PointerSize};

/// Comprehensive emulation configuration with fine-grained control.
///
/// `EmulationConfig` is the top-level configuration container that controls
/// all aspects of .NET emulation behavior. It aggregates sub-configurations
/// for limits, memory, stubs, and tracing.
///
/// # Default Configuration
///
/// The default configuration provides reasonable settings for general use:
/// - 10 million instruction limit
/// - 1000 call depth limit
/// - 256 MB heap limit
/// - Threading and exceptions enabled
/// - All stubs enabled in non-strict mode
///
/// # Presets
///
/// Use the preset methods for common scenarios:
/// - [`extraction()`](Self::extraction) - For unpacking protected assemblies
/// - [`analysis()`](Self::analysis) - For static analysis
/// - [`full()`](Self::full) - For complete emulation
/// - [`minimal()`](Self::minimal) - For simple constant folding
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::emulation::EmulationConfig;
///
/// // Default configuration
/// let config = EmulationConfig::default();
///
/// // Preset for extraction
/// let config = EmulationConfig::extraction();
///
/// // Custom configuration
/// let config = EmulationConfig {
///     symbolic_tracking: true,
///     threading_enabled: false,
///     ..EmulationConfig::analysis()
/// };
/// ```
#[derive(Clone, Debug)]
pub struct EmulationConfig {
    /// Execution limits controlling resource usage.
    ///
    /// Includes maximum instructions, call depth, heap size, and timeout.
    pub limits: EmulationLimits,

    /// Behavior when encountering methods without stubs.
    ///
    /// Determines whether to return symbolic values, fail, use defaults,
    /// or skip the call entirely.
    pub unknown_method: UnknownMethodBehavior,

    /// Whether to track symbolic values for data flow analysis.
    ///
    /// When enabled, operations on unknown values produce symbolic
    /// expressions that can be analyzed for patterns.
    pub symbolic_tracking: bool,

    /// Whether to enable multi-threading support.
    ///
    /// When enabled, the emulator can handle Thread.Start and
    /// related operations. Disable for deterministic single-threaded
    /// execution.
    pub threading_enabled: bool,

    /// Thread scheduling quantum in instructions.
    ///
    /// Number of instructions to execute per thread before
    /// switching to the next ready thread.
    pub thread_quantum: usize,

    /// Maximum number of concurrent threads.
    ///
    /// Limits the number of threads that can be created during
    /// emulation to prevent resource exhaustion.
    pub max_threads: usize,

    /// Whether to enable exception handling.
    ///
    /// When enabled, try/catch/finally blocks are respected.
    /// Disable for simpler analysis that ignores exceptions.
    pub exception_handling: bool,

    /// Whether to allow stack unwinding on unhandled exceptions.
    ///
    /// When true, unhandled exceptions propagate up the call stack.
    /// When false, they immediately terminate emulation.
    pub allow_unwind: bool,

    /// Target pointer size for native int/uint types.
    ///
    /// Derived from the PE header (PE32 → `Bit32`, PE32+ → `Bit64`).
    /// Auto-detected by [`super::ProcessBuilder::build()`] when an assembly is loaded;
    /// defaults to `Bit64`.
    pub pointer_size: PointerSize,

    /// Memory subsystem configuration.
    ///
    /// Controls heap size, stack size, and memory tracking options.
    pub memory: MemoryConfig,

    /// Method stub configuration.
    ///
    /// Controls which categories of stubs are enabled and strict mode.
    pub stubs: StubConfig,

    /// Logging and tracing configuration.
    ///
    /// Controls what events are logged during emulation.
    pub tracing: TracingConfig,

    /// Environment configuration for simulating `System.Environment` properties.
    ///
    /// Controls values returned by hooks for OS version, user name, machine name,
    /// special folder paths, environment variables, and tick counts.
    pub environment: EnvironmentConfig,
}

/// Limits for emulation execution.
///
/// `EmulationLimits` provides safety boundaries to prevent runaway emulation
/// from consuming excessive resources. When any limit is reached, emulation
/// stops with a [`LimitReached`](crate::emulation::engine::EmulationOutcome::LimitReached)
/// outcome.
///
/// # Builder Pattern
///
/// Use the builder methods for fluent configuration:
///
/// ```rust,no_run
/// use dotscope::emulation::EmulationLimits;
///
/// let limits = EmulationLimits::new()
///     .with_max_instructions(5_000_000)
///     .with_max_call_depth(100)
///     .with_timeout_ms(30_000);
/// ```
///
/// # Default Values
///
/// | Limit | Default Value |
/// |-------|---------------|
/// | `max_instructions` | 10,000,000 |
/// | `max_call_depth` | 1,000 |
/// | `max_heap_objects` | 100,000 |
/// | `max_heap_bytes` | 256 MB |
/// | `max_unmanaged_bytes` | 64 MB |
/// | `max_loaded_assemblies` | 64 |
/// | `max_loaded_assembly_bytes` | 32 MB |
/// | `timeout_ms` | 60,000 (1 minute) |
#[derive(Clone, Debug)]
pub struct EmulationLimits {
    /// Maximum instructions to execute.
    ///
    /// Set to 0 for unlimited execution. When exceeded, emulation
    /// stops with an instruction limit error.
    pub max_instructions: u64,

    /// Maximum call stack depth.
    ///
    /// Limits nested method calls to prevent stack overflow from
    /// infinite recursion.
    pub max_call_depth: usize,

    /// Maximum number of heap object allocations.
    ///
    /// Limits the total number of objects that can be created on
    /// the managed heap.
    pub max_heap_objects: usize,

    /// Maximum total heap size in bytes.
    ///
    /// Limits the total memory that can be allocated on the
    /// managed heap.
    pub max_heap_bytes: usize,

    /// Maximum unmanaged memory allocations in bytes.
    ///
    /// Limits memory allocated via Marshal.AllocHGlobal and
    /// similar unmanaged allocation methods.
    pub max_unmanaged_bytes: usize,

    /// Maximum number of assemblies emulated code may load at runtime.
    ///
    /// `Assembly.Load(byte[])` parses its payload into a `CilObject` that the AppDomain
    /// retains for the lifetime of the emulation, for cross-assembly resolution. That
    /// memory is host memory, so `max_heap_bytes` does not see it, and mutating a single
    /// byte between calls defeats any content dedup while leaving the emulated heap
    /// footprint unchanged. This bounds how many are kept.
    ///
    /// The value must stay below `u32::MAX` for the assembly index to remain
    /// representable in a call frame.
    pub max_loaded_assemblies: usize,

    /// Maximum size in bytes of a single assembly payload accepted for parsing.
    ///
    /// Checked before `Assembly.Load(byte[])` hands the bytes to the metadata parser,
    /// which is a full re-entry into attacker-controlled parsing from inside a hook and
    /// so runs outside the instruction and timeout budgets.
    pub max_loaded_assembly_bytes: usize,

    /// Timeout in milliseconds.
    ///
    /// Set to 0 for no timeout. When exceeded, emulation stops
    /// with a timeout error.
    pub timeout_ms: u64,
}

/// Memory subsystem configuration.
///
/// Controls the emulated memory environment including heap sizing,
/// stack allocation, and memory tracking options.
///
/// # Default Values
///
/// | Setting | Default Value |
/// |---------|---------------|
/// | `initial_heap_size` | 16 MB |
/// | `max_heap_size` | 256 MB |
/// | `stack_size` | 1 MB |
/// | `address_space_bits` | 32 |
/// | `track_access` | false |
/// | `zero_init` | true |
#[derive(Clone, Debug)]
pub struct MemoryConfig {
    /// Initial heap size in bytes.
    ///
    /// The heap will be pre-allocated to this size at startup.
    pub initial_heap_size: usize,

    /// Maximum heap size in bytes.
    ///
    /// The heap can grow up to this limit. Allocations beyond
    /// this limit will fail.
    pub max_heap_size: usize,

    /// Default stack size per thread in bytes.
    ///
    /// Each thread receives this amount of stack space for
    /// local variables and call frames.
    pub stack_size: usize,

    /// Address space size in bits.
    ///
    /// Typically 32 for 32-bit processes (4 GB address space)
    /// or 64 for 64-bit processes.
    pub address_space_bits: u8,

    /// Whether to track memory access patterns.
    ///
    /// When enabled, reads and writes are recorded for analysis.
    /// This adds overhead but enables access pattern analysis.
    pub track_access: bool,

    /// Whether to zero-initialize allocations.
    ///
    /// When true, all allocated memory is initialized to zero.
    /// Matches .NET behavior for managed allocations.
    pub zero_init: bool,
}

/// Hook registration configuration.
///
/// Controls which categories of method hooks are registered and how
/// missing hooks are handled. Hooks provide implementations for
/// BCL (Base Class Library) methods that cannot be directly emulated.
///
/// # Hook Categories
///
/// Hooks are organized by functionality:
///
/// - **BCL**: Core types like String, Array, Object
/// - **P/Invoke**: Platform invoke / native interop
/// - **Reflection**: Type inspection and dynamic invocation
/// - **Crypto**: Cryptographic operations (AES, SHA, RSA)
/// - **I/O**: File and stream operations
/// - **Threading**: Thread and synchronization primitives
///
/// # Strict Mode
///
/// When `strict_mode` is enabled, calling a method without a hook
/// causes emulation to fail. When disabled, missing hooks return
/// symbolic or default values based on [`UnknownMethodBehavior`].
///
/// # Default Values
///
/// All hook categories are enabled by default with strict mode disabled.
#[derive(Clone, Debug)]
pub struct StubConfig {
    /// Enable Base Class Library hooks.
    ///
    /// Registers hooks for core types like String, Array,
    /// Object, and basic operations.
    pub bcl_stubs: bool,

    /// Enable P/Invoke hooks.
    ///
    /// Registers hooks for common platform invoke calls
    /// like kernel32 and user32 functions.
    pub pinvoke_stubs: bool,

    /// Enable reflection hooks.
    ///
    /// Registers hooks for Type, MethodInfo, and related
    /// reflection APIs.
    pub reflection_stubs: bool,

    /// Enable cryptographic hooks.
    ///
    /// Registers hooks for AES, SHA, MD5, RSA, and other
    /// cryptographic operations.
    pub crypto_stubs: bool,

    /// Enable I/O hooks.
    ///
    /// Registers hooks for Stream, File, BinaryReader,
    /// and related I/O types.
    pub io_stubs: bool,

    /// Enable threading hooks.
    ///
    /// Registers hooks for Thread, Monitor, Mutex, and
    /// related synchronization types.
    pub threading_stubs: bool,

    /// Enable strict mode.
    ///
    /// When true, calling a method without a registered hook causes
    /// emulation to fail immediately. When false, the behavior is
    /// determined by [`UnknownMethodBehavior`].
    pub strict_mode: bool,
}

/// Tracing and logging configuration.
///
/// Controls what events are logged during emulation for debugging
/// and analysis purposes. Enabling tracing adds overhead but provides
/// visibility into emulation behavior.
///
/// # Performance Impact
///
/// Tracing has varying performance impact:
///
/// - `trace_exceptions`: Low (exceptions are rare)
/// - `trace_calls`: Medium (one event per call)
/// - `trace_hooks`: Medium (one event per hook call)
/// - `trace_heap`: High (one event per allocation)
/// - `trace_instructions`: Very High (one event per instruction)
///
/// # File-Based Tracing
///
/// When `output_path` is set, trace events are written to the specified file
/// instead of being stored in memory. This is useful for analyzing long-running
/// emulations where memory-based tracing would be impractical.
///
/// # Default Values
///
/// Only exception tracing is enabled by default to minimize overhead
/// while capturing error information.
#[derive(Clone, Debug)]
pub struct TracingConfig {
    /// Log individual instruction execution.
    ///
    /// Records each CIL instruction as it executes, including:
    /// - Method token and IL offset
    /// - Opcode mnemonic and operands
    /// - Stack state before/after execution
    ///
    /// Very high overhead but useful for detailed debugging.
    pub trace_instructions: bool,

    /// Log method calls and returns.
    ///
    /// Records method entry and exit with arguments and return values.
    pub trace_calls: bool,

    /// Log heap operations.
    ///
    /// Records object allocations, array creations, and garbage
    /// collection events.
    pub trace_heap: bool,

    /// Log exception handling.
    ///
    /// Records exception throws, catches, and finally block execution.
    /// Enabled by default.
    pub trace_exceptions: bool,

    /// Log stub invocations.
    ///
    /// Records when method stubs are called and their return values.
    pub trace_stubs: bool,

    /// Include stack values in instruction trace events.
    ///
    /// When enabled together with `trace_instructions`, each instruction event
    /// includes the top stack values AFTER execution. This reveals the actual
    /// computed values at each step, essential for debugging arithmetic
    /// divergences between the emulator and the .NET runtime.
    ///
    /// Extreme overhead — use with targeted method filters.
    pub trace_stack_values: bool,

    /// Log array element access operations.
    ///
    /// Records stelem/ldelem operations with index and value information.
    /// Very high overhead but critical for debugging DynCipher state machines
    /// and key derivation routines.
    pub trace_array_ops: bool,

    /// Maximum trace entries to keep in memory.
    ///
    /// Set to 0 for unlimited. When exceeded, oldest entries are
    /// discarded to prevent memory exhaustion. Ignored when
    /// `output_path` is set (file-based tracing is streaming).
    pub max_trace_entries: usize,

    /// Output file path for trace events.
    ///
    /// When set, trace events are written to this file instead of
    /// being stored in memory. The file is created/truncated when
    /// emulation starts. Events are written as they occur for
    /// real-time analysis.
    ///
    /// Format: One JSON object per line (JSONL/NDJSON format).
    pub output_path: Option<PathBuf>,

    /// Context prefix for trace events.
    ///
    /// When set, this prefix is included in each trace event's JSON output
    /// as a "context" field. This helps distinguish events from different
    /// emulation contexts when sharing a trace file.
    ///
    /// Common prefixes:
    /// - "warmup" for static constructor initialization
    /// - "decryption-N" for string decryption calls (N = call index)
    /// - "anti-tamper" for anti-tamper processing
    pub context_prefix: Option<String>,

    /// Filter controlling which methods and call depths produce trace output.
    ///
    /// When set, only trace events matching the filter are emitted. This keeps
    /// trace output manageable for complex samples by restricting tracing to
    /// specific methods, call depths, or name patterns.
    ///
    /// Default: `TraceFilter::default()` (no filtering — all events pass).
    pub filter: TraceFilter,
}

/// Behavior when encountering methods without registered hooks.
///
/// When the emulator encounters a method call for which no hook is
/// registered, this setting determines what happens.
///
/// # Choosing a Behavior
///
/// - Use [`Emulate`](Self::Emulate) to execute the method's CIL bytecode
///   (default, works for user-defined methods with bodies)
/// - Use [`Symbolic`](Self::Symbolic) for data flow analysis where you want
///   to track how unknown values propagate
/// - Use [`Fail`](Self::Fail) for strict emulation where all methods must
///   have hook implementations
/// - Use [`Default`](Self::Default) for extraction scenarios where return
///   values often don't matter
/// - Use [`Skip`](Self::Skip) for simple constant folding where you want
///   to ignore irrelevant calls
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UnknownMethodBehavior {
    /// Attempt to emulate the method's CIL bytecode.
    ///
    /// The emulator will try to execute the method's actual bytecode.
    /// This works for user-defined methods with bodies but will fall back
    /// to symbolic values for methods without bodies (e.g., P/Invoke).
    ///
    /// Best for: User-defined methods, full emulation scenarios.
    #[default]
    Emulate,

    /// Return a symbolic value representing the unknown result.
    ///
    /// The symbolic value can be tracked through subsequent operations
    /// to analyze data flow patterns. Best for static analysis scenarios.
    Symbolic,

    /// Fail with an error immediately.
    ///
    /// Stops emulation with an error indicating the missing method.
    /// Use for strict emulation where all methods must be handled.
    Fail,

    /// Return a default value based on the return type.
    ///
    /// Returns null for reference types, 0 for integers, 0.0 for floats,
    /// false for booleans. Useful for extraction where return values
    /// often don't affect the target behavior.
    Default,

    /// Skip the call entirely (treat as no-op).
    ///
    /// The call is ignored and execution continues. No value is pushed
    /// for methods with return values (may cause stack imbalance if
    /// the return value is used).
    Skip,
}

/// Configuration for what to capture during emulation.
///
/// `CaptureConfig` determines what runtime data is collected and stored
/// during emulation. Captured data can be retrieved after emulation
/// completes for analysis or extraction.
///
/// # Use Cases
///
/// - **Unpacking**: Enable `assemblies` to capture dynamically loaded assemblies
/// - **String Decryption**: Enable `strings` to capture decrypted strings
/// - **Behavioral Analysis**: Enable `file_operations` and `network_operations`
/// - **Memory Dumping**: Add regions to `memory_regions` to capture writes
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::emulation::CaptureConfig;
///
/// let config = CaptureConfig {
///     assemblies: true,
///     strings: true,
///     ..Default::default()
/// };
/// ```
///
/// # Default Values
///
/// By default, no capture is enabled to minimize overhead.
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Capture assemblies loaded via Assembly.Load.
    ///
    /// When enabled, byte arrays passed to Assembly.Load are captured
    /// and can be retrieved via [`super::EmulationProcess::captured_assemblies`].
    pub assemblies: bool,

    /// Capture writes to specific memory regions.
    ///
    /// Ranges are specified as `start..end` (exclusive). Writes within
    /// these ranges are captured with their data.
    pub memory_regions: Vec<Range<u64>>,

    /// Capture decrypted or constructed strings.
    ///
    /// When enabled, strings created during emulation are captured,
    /// useful for extracting obfuscated string literals.
    pub strings: bool,

    /// Capture file system operations.
    ///
    /// Records file opens, reads, writes, and closes performed
    /// during emulation.
    pub file_operations: bool,

    /// Capture network operations.
    ///
    /// Records socket operations, HTTP requests, and other network
    /// activity during emulation.
    pub network_operations: bool,

    /// Capture raw byte buffers from memory operations and crypto transforms.
    ///
    /// Gated like every other capture kind, so a default config records no buffers and
    /// `captured_buffers()` stays empty until this is set to `true`.
    pub buffers: bool,

    /// Maximum number of items retained in each capture collection.
    ///
    /// Capture is driven by hook invocations rather than heap allocations, and captured data
    /// lives outside the managed heap, so `max_heap_bytes` does not see it. Emulated code can
    /// allocate one array and then loop calling `set_Key`/`TransformFinalBlock` on it, appending
    /// a full copy per iteration for a few instructions each. Without a ceiling, emulation
    /// reaches a clean `Completed` outcome having consumed tens of gigabytes.
    ///
    /// Once reached, further captures of that kind are dropped. `usize::MAX` means unlimited.
    pub max_items: usize,

    /// Maximum total bytes retained across all captured buffers, strings and assemblies.
    ///
    /// Complements [`max_items`](Self::max_items): a small number of very large buffers is as
    /// damaging as a large number of small ones. `usize::MAX` means unlimited.
    pub max_total_bytes: usize,
}

impl Default for CaptureConfig {
    /// No capture enabled, with ceilings applied to whatever the caller does enable.
    fn default() -> Self {
        Self {
            assemblies: false,
            memory_regions: Vec::new(),
            strings: false,
            file_operations: false,
            network_operations: false,
            buffers: false,
            max_items: 10_000,
            max_total_bytes: 256 * 1024 * 1024,
        }
    }
}

/// Environment simulation configuration.
///
/// Controls the values returned by `System.Environment` property hooks and
/// related BCL methods like `Module.FullyQualifiedName` and `Assembly.get_Location`.
/// Provides realistic Windows 10 defaults suitable for deobfuscation.
///
/// # Default Values
///
/// | Property | Default |
/// |----------|---------|
/// | `os_version` | `"10.0.19041.0"` |
/// | `processor_count` | `4` |
/// | `is_64bit_os` | `true` |
/// | `is_64bit_process` | `true` |
/// | `user_name` | `"user"` |
/// | `machine_name` | `"DESKTOP-PC"` |
/// | `current_directory` | `"C:\\Users\\user\\Desktop"` |
/// | `tick_count_base` | `300_000` (5 min uptime) |
/// | `tick_count_divisor` | `100` (instructions per ms) |
#[derive(Clone, Debug)]
pub struct EnvironmentConfig {
    /// Simulated OS version string (e.g., `"10.0.19041.0"`).
    pub os_version: String,

    /// Number of logical processors reported by `Environment.ProcessorCount`.
    pub processor_count: i32,

    /// Whether the OS is 64-bit (`Environment.Is64BitOperatingSystem`).
    pub is_64bit_os: bool,

    /// Whether the process is 64-bit (`Environment.Is64BitProcess`).
    pub is_64bit_process: bool,

    /// User name reported by `Environment.UserName`.
    pub user_name: String,

    /// Machine name reported by `Environment.MachineName`.
    pub machine_name: String,

    /// Current directory reported by `Environment.CurrentDirectory`.
    pub current_directory: String,

    /// Base value for `Environment.TickCount` / `TickCount64` in milliseconds.
    pub tick_count_base: i64,

    /// Instructions-per-millisecond divisor for tick count advancement.
    ///
    /// `tick_count = tick_count_base + instructions_executed / tick_count_divisor`
    pub tick_count_divisor: u64,

    /// Pre-configured environment variables.
    ///
    /// `Environment.GetEnvironmentVariable(name)` returns the value from this map
    /// or null if missing. Empty by default.
    pub environment_variables: HashMap<String, String>,

    /// Special folder paths keyed by .NET `SpecialFolder` enum value.
    ///
    /// `Environment.GetFolderPath(SpecialFolder)` returns the path from this map.
    /// Pre-populated with common Windows paths.
    pub folder_paths: HashMap<i32, String>,

    /// Base directory for `Module.FullyQualifiedName`.
    ///
    /// The module name from metadata is appended to this path.
    pub module_base_path: String,

    /// Base directory for `Assembly.get_Location`.
    ///
    /// The module name from metadata is appended to this path.
    pub assembly_location_base: String,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        let mut folder_paths = HashMap::new();
        folder_paths.insert(0, "C:\\Users\\user\\Desktop".to_string());
        folder_paths.insert(26, "C:\\Users\\user\\AppData\\Roaming".to_string());
        folder_paths.insert(28, "C:\\Users\\user\\AppData\\Local".to_string());
        folder_paths.insert(35, "C:\\ProgramData".to_string());
        folder_paths.insert(37, "C:\\Windows".to_string());
        folder_paths.insert(41, "C:\\Program Files".to_string());

        Self {
            os_version: "10.0.19041.0".to_string(),
            processor_count: 4,
            is_64bit_os: true,
            is_64bit_process: true,
            user_name: "user".to_string(),
            machine_name: "DESKTOP-PC".to_string(),
            current_directory: "C:\\Users\\user\\Desktop".to_string(),
            tick_count_base: 300_000,
            tick_count_divisor: 100,
            environment_variables: HashMap::new(),
            folder_paths,
            module_base_path: "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319".to_string(),
            assembly_location_base: "C:\\Users\\user\\AppData\\Local\\Temp".to_string(),
        }
    }
}

impl Default for EmulationConfig {
    /// Creates a default emulation configuration.
    ///
    /// See the struct documentation for default values.
    fn default() -> Self {
        Self {
            limits: EmulationLimits::default(),
            unknown_method: UnknownMethodBehavior::Symbolic,
            symbolic_tracking: false,
            threading_enabled: true,
            thread_quantum: 1000,
            max_threads: 16,
            exception_handling: true,
            allow_unwind: true,
            pointer_size: PointerSize::Bit64,
            memory: MemoryConfig::default(),
            stubs: StubConfig::default(),
            tracing: TracingConfig::default(),
            environment: EnvironmentConfig::default(),
        }
    }
}

impl Default for EmulationLimits {
    /// Creates default execution limits.
    ///
    /// See the struct documentation for default values.
    fn default() -> Self {
        Self {
            max_instructions: 10_000_000,
            max_call_depth: 1000,
            max_heap_objects: 100_000,
            max_heap_bytes: 256 * 1024 * 1024,     // 256 MB
            max_unmanaged_bytes: 64 * 1024 * 1024, // 64 MB
            max_loaded_assemblies: 64,
            max_loaded_assembly_bytes: 32 * 1024 * 1024, // 32 MB
            timeout_ms: 60_000,                          // 1 minute
        }
    }
}

impl Default for MemoryConfig {
    /// Creates default memory configuration.
    ///
    /// See the struct documentation for default values.
    fn default() -> Self {
        Self {
            initial_heap_size: 16 * 1024 * 1024, // 16 MB
            max_heap_size: 256 * 1024 * 1024,    // 256 MB
            stack_size: 1024 * 1024,             // 1 MB
            address_space_bits: 32,
            track_access: false,
            zero_init: true,
        }
    }
}

impl Default for StubConfig {
    /// Creates default stub configuration with all stubs enabled.
    ///
    /// See the struct documentation for default values.
    fn default() -> Self {
        Self {
            bcl_stubs: true,
            pinvoke_stubs: true,
            reflection_stubs: true,
            crypto_stubs: true,
            io_stubs: true,
            threading_stubs: true,
            strict_mode: false,
        }
    }
}

impl TracingConfig {
    /// Creates a tracing configuration that logs everything to a file.
    ///
    /// This enables all tracing categories and writes to the specified file path.
    /// Useful for debugging complex emulation issues.
    ///
    /// # Arguments
    ///
    /// * `path` - File path to write trace events to (created/truncated on start)
    ///
    /// # Example
    ///
    /// ```
    /// use dotscope::emulation::{EmulationConfig, TracingConfig};
    ///
    /// let tracing = TracingConfig::full_trace("emulation.trace");
    /// let config = EmulationConfig {
    ///     tracing,
    ///     ..Default::default()
    /// };
    /// ```
    #[must_use]
    pub fn full_trace<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            trace_instructions: true,
            trace_calls: true,
            trace_heap: true,
            trace_exceptions: true,
            trace_stubs: true,
            trace_stack_values: true,
            trace_array_ops: true,
            max_trace_entries: 0, // Unlimited for file-based
            output_path: Some(path.into()),
            context_prefix: None,
            filter: TraceFilter::default(),
        }
    }

    /// Creates a tracing configuration for call-level tracing to a file.
    ///
    /// Traces method calls, exceptions, and stubs but not individual instructions.
    /// Good balance between detail and performance.
    #[must_use]
    pub fn call_trace<P: Into<PathBuf>>(path: P) -> Self {
        Self {
            trace_instructions: false,
            trace_calls: true,
            trace_heap: false,
            trace_exceptions: true,
            trace_stubs: true,
            trace_stack_values: false,
            trace_array_ops: false,
            max_trace_entries: 0,
            output_path: Some(path.into()),
            context_prefix: None,
            filter: TraceFilter::default(),
        }
    }

    /// Sets the context prefix for trace events.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The context prefix to use (e.g., "warmup", "decryption-0")
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_context(mut self, prefix: impl Into<String>) -> Self {
        self.context_prefix = Some(prefix.into());
        self
    }

    /// Checks if any tracing is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.trace_instructions
            || self.trace_calls
            || self.trace_heap
            || self.trace_exceptions
            || self.trace_stubs
            || self.trace_array_ops
    }

    /// Checks if file-based tracing is configured.
    #[must_use]
    pub fn has_output_file(&self) -> bool {
        self.output_path.is_some()
    }
}

impl Default for TracingConfig {
    /// Creates default tracing configuration.
    ///
    /// Only exception tracing is enabled by default.
    fn default() -> Self {
        Self {
            trace_instructions: false,
            trace_calls: false,
            trace_heap: false,
            trace_exceptions: true,
            trace_stubs: false,
            trace_stack_values: false,
            trace_array_ops: false,
            max_trace_entries: 10_000,
            output_path: None,
            context_prefix: None,
            filter: TraceFilter::default(),
        }
    }
}

/// Preset configurations for common use cases.
impl EmulationConfig {
    /// Creates a configuration optimized for extracting packed/encrypted assemblies.
    ///
    /// This preset is designed for unpacking scenarios where the goal is to
    /// run the unpacker/decryptor and capture the resulting assembly.
    ///
    /// # Settings
    ///
    /// - **Instruction limit**: 50 million (high to allow complex unpacking)
    /// - **Unknown methods**: Return default values (unpacker may call irrelevant BCL methods)
    /// - **Threading**: Enabled (some unpackers use threads)
    /// - **Exceptions**: Enabled (unpackers may use try/catch)
    /// - **Strict mode**: Disabled (tolerate missing stubs)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::{EmulationConfig, ProcessBuilder};
    /// use dotscope::CilObject;
    ///
    /// # fn main() -> Result<(), dotscope::Error> {
    /// # let packed_assembly = CilObject::from_path("sample.exe")?;
    /// let config = EmulationConfig::extraction();
    /// let process = ProcessBuilder::new()
    ///     .assembly(packed_assembly)
    ///     .config(config)
    ///     .capture_assemblies()
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn extraction() -> Self {
        Self {
            limits: EmulationLimits {
                max_instructions: 50_000_000,
                ..Default::default()
            },
            unknown_method: UnknownMethodBehavior::Default,
            symbolic_tracking: false,
            threading_enabled: true,
            exception_handling: true,
            stubs: StubConfig {
                strict_mode: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Creates a configuration optimized for static analysis and constant propagation.
    ///
    /// This preset is designed for analyzing code behavior without full execution,
    /// tracking symbolic values to understand data flow.
    ///
    /// # Settings
    ///
    /// - **Instruction limit**: 1 million (moderate for analysis)
    /// - **Unknown methods**: Return symbolic values (track data flow)
    /// - **Symbolic tracking**: Enabled
    /// - **Threading**: Disabled (for determinism)
    /// - **Exceptions**: Disabled (simplify control flow)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::EmulationConfig;
    ///
    /// let config = EmulationConfig::analysis();
    /// // Use for constant propagation, dead code detection, etc.
    /// ```
    #[must_use]
    pub fn analysis() -> Self {
        Self {
            limits: EmulationLimits {
                max_instructions: 1_000_000,
                ..Default::default()
            },
            unknown_method: UnknownMethodBehavior::Symbolic,
            symbolic_tracking: true,
            threading_enabled: false,
            exception_handling: false,
            stubs: StubConfig {
                strict_mode: false,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Creates a configuration for complete emulation with all features enabled.
    ///
    /// This preset provides the most accurate emulation at the cost of requiring
    /// stubs for all called methods.
    ///
    /// # Settings
    ///
    /// - **Instruction limit**: 100 million (very high for complex programs)
    /// - **Timeout**: 5 minutes
    /// - **Unknown methods**: Fail (strict - all methods must have stubs)
    /// - **Threading**: Enabled
    /// - **Exceptions**: Enabled
    /// - **Strict mode**: Enabled
    ///
    /// # Warning
    ///
    /// This mode will fail if any called method lacks a stub. Only use when
    /// you have comprehensive stub coverage.
    #[must_use]
    pub fn full() -> Self {
        Self {
            limits: EmulationLimits {
                max_instructions: 100_000_000,
                timeout_ms: 300_000, // 5 minutes
                ..Default::default()
            },
            unknown_method: UnknownMethodBehavior::Fail,
            symbolic_tracking: false,
            threading_enabled: true,
            exception_handling: true,
            stubs: StubConfig {
                strict_mode: true,
                ..Default::default()
            },
            tracing: TracingConfig {
                trace_exceptions: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Creates a minimal configuration for simple constant folding.
    ///
    /// This preset is designed for lightweight analysis scenarios like
    /// evaluating simple expressions or folding constants.
    ///
    /// # Settings
    ///
    /// - **Instruction limit**: 10,000 (very low)
    /// - **Call depth**: 10 (shallow)
    /// - **Unknown methods**: Skip (ignore irrelevant calls)
    /// - **Threading**: Disabled
    /// - **Exceptions**: Disabled
    /// - **Stubs**: Only BCL enabled
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::EmulationConfig;
    ///
    /// let config = EmulationConfig::minimal();
    /// // Use for simple constant evaluation
    /// ```
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            limits: EmulationLimits {
                max_instructions: 10_000,
                max_call_depth: 10,
                ..Default::default()
            },
            unknown_method: UnknownMethodBehavior::Skip,
            symbolic_tracking: false,
            threading_enabled: false,
            exception_handling: false,
            stubs: StubConfig {
                bcl_stubs: true,
                pinvoke_stubs: false,
                reflection_stubs: false,
                crypto_stubs: false,
                io_stubs: false,
                threading_stubs: false,
                strict_mode: false,
            },
            ..Default::default()
        }
    }
}

/// Builder methods for [`EmulationLimits`].
impl EmulationLimits {
    /// Creates new limits with default values.
    ///
    /// Equivalent to [`EmulationLimits::default()`]. Use the `with_*` methods
    /// to customize individual limits.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use dotscope::emulation::EmulationLimits;
    ///
    /// let limits = EmulationLimits::new()
    ///     .with_max_instructions(5_000_000)
    ///     .with_timeout_ms(30_000);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum instruction count.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum instructions to execute (0 for unlimited)
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_instructions(mut self, max: u64) -> Self {
        self.max_instructions = max;
        self
    }

    /// Sets the maximum call stack depth.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum nested method calls
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_call_depth(mut self, max: usize) -> Self {
        self.max_call_depth = max;
        self
    }

    /// Sets the maximum number of heap objects.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum objects that can be allocated
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_heap_objects(mut self, max: usize) -> Self {
        self.max_heap_objects = max;
        self
    }

    /// Sets the maximum heap size in bytes.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum total heap allocation in bytes
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_heap_bytes(mut self, max: usize) -> Self {
        self.max_heap_bytes = max;
        self
    }

    /// Sets the maximum number of assemblies emulated code may load at runtime.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum retained runtime-loaded assemblies
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_loaded_assemblies(mut self, max: usize) -> Self {
        self.max_loaded_assemblies = max;
        self
    }

    /// Sets the maximum size of a single runtime-loaded assembly payload.
    ///
    /// # Arguments
    ///
    /// * `max` - Maximum payload size in bytes
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_max_loaded_assembly_bytes(mut self, max: usize) -> Self {
        self.max_loaded_assembly_bytes = max;
        self
    }

    /// Sets the execution timeout in milliseconds.
    ///
    /// # Arguments
    ///
    /// * `ms` - Timeout in milliseconds (0 for no timeout)
    ///
    /// # Returns
    ///
    /// Returns `self` for method chaining.
    #[must_use]
    pub fn with_timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = EmulationConfig::default();
        assert_eq!(config.limits.max_instructions, 10_000_000);
        assert!(config.threading_enabled);
        assert!(config.exception_handling);
    }

    #[test]
    fn test_extraction_preset() {
        let config = EmulationConfig::extraction();
        assert_eq!(config.limits.max_instructions, 50_000_000);
        assert_eq!(config.unknown_method, UnknownMethodBehavior::Default);
    }

    #[test]
    fn test_analysis_preset() {
        let config = EmulationConfig::analysis();
        assert!(config.symbolic_tracking);
        assert!(!config.threading_enabled);
    }

    #[test]
    fn test_full_preset() {
        let config = EmulationConfig::full();
        assert_eq!(config.unknown_method, UnknownMethodBehavior::Fail);
        assert!(config.stubs.strict_mode);
    }

    #[test]
    fn test_minimal_preset() {
        let config = EmulationConfig::minimal();
        assert_eq!(config.limits.max_instructions, 10_000);
        assert!(!config.stubs.pinvoke_stubs);
    }

    #[test]
    fn test_limits_builder() {
        let limits = EmulationLimits::new()
            .with_max_instructions(5000)
            .with_max_call_depth(50)
            .with_timeout_ms(30_000);

        assert_eq!(limits.max_instructions, 5000);
        assert_eq!(limits.max_call_depth, 50);
        assert_eq!(limits.timeout_ms, 30_000);
    }
}
