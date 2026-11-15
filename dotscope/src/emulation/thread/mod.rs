//! Thread model for .NET emulation.
//!
//! This module provides per-thread execution state for .NET emulation,
//! including call frames, evaluation stacks, thread scheduling, and
//! synchronization primitives. It implements a cooperative multithreading
//! model that allows emulating multi-threaded .NET applications.
//!
//! # Architecture
//!
//! The thread subsystem is organized into three main components:
//!
//! - **Thread State** ([`EmulationThread`]): Per-thread execution context including
//!   call stack, evaluation stack, local variables, and exception handling state.
//!
//! - **Scheduling** ([`ThreadScheduler`]): Cooperative scheduler that manages thread
//!   execution order using priority-based scheduling with time quantum slicing.
//!
//! - **Synchronization** ([`SyncState`]): Emulated .NET synchronization primitives
//!   including monitors (`lock`), mutexes, semaphores, and events.
//!
//! # Thread Lifecycle
//!
//! Threads transition through the following states:
//!
//! 1. [`ThreadState::Ready`] - Thread is queued and ready to execute
//! 2. [`ThreadState::Running`] - Thread is actively executing instructions
//! 3. [`ThreadState::Waiting`] - Thread is blocked on a synchronization primitive
//! 4. [`ThreadState::Completed`] / [`ThreadState::Faulted`] / [`ThreadState::Aborted`] - Terminal states
//!
//! # Usage
//!
//! ```
//! use dotscope::emulation::EmulationThread;
//! use dotscope::emulation::ThreadScheduler;
//! # use std::sync::{Arc, RwLock};
//! # use dotscope::emulation::{
//! #     AddressSpace, CaptureContext, EmulationConfig, RuntimeState, SharedFakeObjects,
//! #     ThreadContext, VirtualFs,
//! # };
//! # let address_space = Arc::new(AddressSpace::new());
//! # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
//! # let context = Arc::new(ThreadContext::new(
//! #     address_space,
//! #     Arc::new(RwLock::new(RuntimeState::new())),
//! #     Arc::new(CaptureContext::new()),
//! #     Arc::new(EmulationConfig::default()),
//! #     None,
//! #     fake_objects,
//! #     Arc::new(VirtualFs::new()),
//! # ));
//!
//! // Create a scheduler with 1000 instructions per time quantum
//! let mut scheduler = ThreadScheduler::new(1000);
//!
//! // Add the main thread
//! let main_thread = EmulationThread::main(context);
//! scheduler.add_main_thread(main_thread);
//!
//! // Run until completion or limit reached
//! while let Some(thread_id) = scheduler.select_next() {
//!     // Execute instructions for the current thread: here it returns at once
//!     println!("running {}", thread_id);
//!     scheduler.complete_current(None);
//! }
//! ```
//!
//! # Components
//!
//! ## Thread Execution
//!
//! - [`EmulationThread`] - Per-thread execution state with call stack and evaluation stack
//! - [`ThreadCallFrame`] - Individual call frame with locals, arguments, and instruction pointer
//! - [`ThreadState`] - Current execution state of a thread
//! - [`ThreadPriority`] - Thread scheduling priority levels
//! - [`WaitReason`] - Reason a thread is blocked/waiting
//!
//! ## Scheduling
//!
//! - [`ThreadScheduler`] - Cooperative thread scheduler with priority queues
//! - [`SchedulerOutcome`] - Result of scheduler operations (completion, deadlock, etc.)
//! - [`WakeCondition`] - Conditions for waking blocked threads
//!
//! ## Synchronization
//!
//! - [`SyncState`] - Central state for all synchronization primitives
//! - [`MonitorState`] - State of a monitor lock (used by `lock` keyword)
//! - [`MutexState`] - State of a mutex with ownership tracking
//! - [`SemaphoreState`] - State of a counting semaphore
//! - [`EventState`] - State of manual/auto reset events
//! - [`SyncError`] - Errors from synchronization operations

mod context;
mod scheduler;
mod state;
mod sync;

pub use context::ThreadContext;
pub use scheduler::{SchedulerOutcome, ThreadScheduler, WakeCondition};
pub use state::{
    EmulationThread, MulticastState, ReflectionInvokeRequest, ThreadCallFrame, ThreadPriority,
    ThreadState, WaitReason,
};
pub use sync::{EventState, MonitorState, MutexState, SemaphoreState, SyncError, SyncState};
