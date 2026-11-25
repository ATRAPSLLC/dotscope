//! Thread scheduler for cooperative multithreading.
//!
//! This module provides a cooperative thread scheduler that manages multiple
//! emulation threads, handling thread creation, scheduling, and synchronization.
//! The scheduler uses priority-based scheduling with time quantum slicing to
//! ensure fair execution across threads.
//!
//! # Scheduling Algorithm
//!
//! The scheduler implements a preemptive priority-based algorithm:
//!
//! 1. Threads are organized in a priority queue, with higher priority threads
//!    scheduled before lower priority ones.
//! 2. Within the same priority level, threads are scheduled in FIFO order.
//! 3. Each thread runs for a configurable time quantum (number of instructions).
//! 4. When a thread's quantum is exhausted, it is re-queued and another thread
//!    is selected.
//!
//! # Thread States
//!
//! The scheduler tracks threads in various states:
//! - **Ready**: In the ready queue, waiting to be scheduled
//! - **Running**: Currently executing (at most one at a time)
//! - **Waiting**: Blocked on I/O, synchronization, or sleep
//! - **Completed/Faulted/Aborted**: Terminal states
//!
//! # Deadlock Detection
//!
//! The scheduler can detect deadlock situations where all threads are waiting
//! and none can proceed. This is reported via [`SchedulerOutcome::Deadlock`].

use std::collections::{BinaryHeap, HashMap};

use crate::{
    emulation::{
        engine::EmulationError,
        thread::{EmulationThread, ThreadPriority, ThreadState, WaitReason},
        EmValue, HeapRef, ThreadId,
    },
    Result,
};

/// Outcome of a scheduler step or run operation.
///
/// This enum represents the various states the scheduler can report after
/// executing one or more steps. It is used to communicate progress, completion,
/// and error conditions back to the caller.
///
/// # Terminal Outcomes
///
/// - [`AllCompleted`](Self::AllCompleted): All threads finished successfully
/// - [`Deadlock`](Self::Deadlock): No progress possible, threads are stuck
/// - [`ThreadFaulted`](Self::ThreadFaulted): A thread threw an unhandled exception
///
/// # Progress Outcomes
///
/// - [`Continue`](Self::Continue): More work to do, keep stepping
/// - [`QuantumExhausted`](Self::QuantumExhausted): Current thread's time slice ended
/// - [`LimitReached`](Self::LimitReached): Instruction limit reached
#[derive(Clone, Debug)]
pub enum SchedulerOutcome {
    /// All threads completed successfully.
    AllCompleted,

    /// Instruction limit reached.
    LimitReached {
        /// Total instructions executed.
        executed: u64,
    },

    /// Time quantum exhausted for current thread.
    QuantumExhausted {
        /// Thread that exhausted its quantum.
        thread_id: ThreadId,
    },

    /// Deadlock detected (all threads waiting, none can proceed).
    Deadlock {
        /// Threads involved in the deadlock.
        waiting_threads: Vec<ThreadId>,
    },

    /// A single thread completed (others may still be running).
    ThreadCompleted {
        /// The completed thread.
        thread_id: ThreadId,
        /// Return value if any.
        return_value: Option<EmValue>,
    },

    /// A thread faulted with an unhandled exception.
    ThreadFaulted {
        /// The faulted thread.
        thread_id: ThreadId,
        /// Exception description.
        exception: String,
    },

    /// A thread was explicitly aborted.
    ThreadAborted {
        /// The aborted thread.
        thread_id: ThreadId,
    },

    /// Scheduler needs more work (continue stepping).
    Continue,
}

/// Entry in the priority queue for scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ScheduleEntry {
    priority: ThreadPriority,
    thread_id: ThreadId,
    /// Sequence number for FIFO ordering within same priority.
    sequence: u64,
}

impl Ord for ScheduleEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher priority first, then lower sequence (earlier) first
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}

impl PartialOrd for ScheduleEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Cooperative thread scheduler for managing emulation threads.
///
/// The `ThreadScheduler` manages multiple emulation threads with priority-based
/// scheduling and cooperative multitasking. Each thread runs for a configurable
/// time quantum (measured in instructions) before being preempted to allow
/// other threads to execute.
///
/// # Features
///
/// - Priority-based scheduling with 5 priority levels
/// - FIFO ordering within the same priority level
/// - Configurable time quantum per thread
/// - Deadlock detection for waiting threads
/// - Thread lifecycle management (spawn, complete, abort)
///
/// # Example
///
/// ```
/// use dotscope::emulation::ThreadScheduler;
/// # use std::sync::{Arc, RwLock};
/// # use dotscope::emulation::{
/// #     AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
/// #     SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
/// # };
/// # let address_space = Arc::new(AddressSpace::new());
/// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
/// # let context = Arc::new(ThreadContext::new(
/// #     address_space,
/// #     Arc::new(RwLock::new(RuntimeState::new())),
/// #     Arc::new(CaptureContext::new()),
/// #     Arc::new(EmulationConfig::default()),
/// #     None,
/// #     fake_objects,
/// #     Arc::new(VirtualFs::new()),
/// # ));
///
/// // Create scheduler with 500 instructions per quantum
/// let mut scheduler = ThreadScheduler::new(500);
///
/// // Add threads and run
/// let main_thread = EmulationThread::new(ThreadId::MAIN, context);
/// scheduler.add_main_thread(main_thread);
///
/// loop {
///     match scheduler.select_next() {
///         Some(_thread_id) => {
///             // Execute instructions for this thread
///             if scheduler.record_instruction() {
///                 // Quantum exhausted, will switch on next select
///             }
///             // Here the thread returns after its first instruction
///             scheduler.complete_current(None);
///         }
///         None => break, // No ready threads
///     }
/// }
/// assert!(scheduler.all_completed());
/// ```
#[derive(Debug)]
pub struct ThreadScheduler {
    /// All managed threads.
    threads: HashMap<ThreadId, EmulationThread>,

    /// Ready queue sorted by priority.
    ready_queue: BinaryHeap<ScheduleEntry>,

    /// Currently running thread (if any).
    current: Option<ThreadId>,

    /// Instructions per time slice.
    quantum: usize,

    /// Instructions executed in current quantum.
    quantum_used: usize,

    /// Total instructions executed across all threads.
    total_instructions: u64,

    /// Next sequence number for scheduling.
    next_sequence: u64,

    /// Next thread ID to assign.
    next_thread_id: u32,

    /// Maximum number of threads this scheduler will hold.
    ///
    /// Set from `EmulationLimits::max_threads`. `usize::MAX` means unlimited, which is the
    /// default so that constructing a scheduler directly is unchanged.
    max_threads: usize,
}

impl ThreadScheduler {
    /// Creates a new scheduler with the specified quantum.
    ///
    /// The quantum determines how many instructions each thread can execute
    /// before being preempted. A smaller quantum provides better responsiveness
    /// but increases scheduling overhead.
    ///
    /// # Arguments
    ///
    /// * `quantum` - Number of instructions per time slice. Recommended values
    ///   are between 100 and 10000 depending on workload characteristics.
    ///
    /// # Example
    ///
    /// ```
    /// use dotscope::emulation::ThreadScheduler;
    ///
    /// let scheduler = ThreadScheduler::new(1000);
    /// assert_eq!(scheduler.quantum(), 1000);
    /// ```
    #[must_use]
    pub fn new(quantum: usize) -> Self {
        Self {
            threads: HashMap::new(),
            ready_queue: BinaryHeap::new(),
            current: None,
            quantum,
            quantum_used: 0,
            total_instructions: 0,
            next_sequence: 0,
            next_thread_id: 2, // 1 is reserved for main thread
            max_threads: usize::MAX,
        }
    }

    /// Sets the maximum number of threads this scheduler will hold.
    ///
    /// [`spawn`](Self::spawn) fails once the scheduler is at this many threads.
    pub fn set_max_threads(&mut self, max: usize) {
        self.max_threads = max;
    }

    /// Creates a scheduler with the default quantum of 1000 instructions.
    ///
    /// This is a convenience constructor for typical use cases where the
    /// default quantum provides good balance between responsiveness and overhead.
    #[must_use]
    pub fn with_default_quantum() -> Self {
        Self::new(1000)
    }

    /// Returns the current quantum (instructions per time slice).
    #[must_use]
    pub fn quantum(&self) -> usize {
        self.quantum
    }

    /// Sets the quantum for future time slices.
    ///
    /// This change takes effect on the next thread switch; it does not
    /// affect the currently running thread's remaining quantum.
    ///
    /// # Arguments
    ///
    /// * `quantum` - New number of instructions per time slice
    pub fn set_quantum(&mut self, quantum: usize) {
        self.quantum = quantum;
    }

    /// Returns the total number of instructions executed across all threads.
    ///
    /// This counter is incremented each time [`record_instruction`](Self::record_instruction)
    /// is called and can be used for profiling or setting execution limits.
    #[must_use]
    pub fn total_instructions(&self) -> u64 {
        self.total_instructions
    }

    /// Adds the main thread to the scheduler.
    ///
    /// The main thread is typically the entry point of the emulated program.
    /// It should be added before any worker threads are spawned.
    ///
    /// # Arguments
    ///
    /// * `thread` - The main emulation thread to add
    pub fn add_main_thread(&mut self, thread: EmulationThread) {
        let id = thread.id();
        self.threads.insert(id, thread);
        self.enqueue_ready(id, ThreadPriority::Normal);
    }

    /// Spawns a new thread and adds it to the ready queue.
    ///
    /// The thread is immediately queued for execution based on its priority.
    /// The thread's ID is returned for future reference.
    ///
    /// # Arguments
    ///
    /// * `thread` - The emulation thread to spawn
    ///
    /// # Returns
    ///
    /// The thread ID of the spawned thread.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::ResourceLimitExceeded`] if the scheduler already holds
    /// [`max_threads`](Self::set_max_threads) threads. Emulated code controls how many threads
    /// it asks for, so this ceiling is what stops it from spawning without bound; note that
    /// threads are counted in all states, including completed ones.
    pub fn spawn(&mut self, thread: EmulationThread) -> Result<ThreadId> {
        if self.threads.len() >= self.max_threads {
            return Err(EmulationError::ResourceLimitExceeded(format!(
                "thread limit reached ({} threads)",
                self.max_threads
            ))
            .into());
        }

        let id = thread.id();
        let priority = thread.priority();
        self.threads.insert(id, thread);
        self.enqueue_ready(id, priority);
        Ok(id)
    }

    /// Allocates a new unique thread ID.
    ///
    /// Thread ID 1 is reserved for the main thread. This method returns
    /// sequential IDs starting from 2.
    ///
    /// # Returns
    ///
    /// A unique thread ID that has not been used before in this scheduler.
    pub fn allocate_thread_id(&mut self) -> ThreadId {
        let id = ThreadId::new(self.next_thread_id);
        self.next_thread_id = self.next_thread_id.saturating_add(1);
        id
    }

    /// Returns the total number of threads managed by the scheduler.
    ///
    /// This includes threads in all states: ready, running, waiting, and completed.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Returns the number of threads that are ready to run.
    ///
    /// This includes the currently running thread (if any) plus all threads
    /// in the ready queue.
    #[must_use]
    pub fn ready_count(&self) -> usize {
        self.ready_queue
            .len()
            .saturating_add(usize::from(self.current.is_some()))
    }

    /// Returns the ID of the currently running thread, if any.
    #[must_use]
    pub fn current_thread_id(&self) -> Option<ThreadId> {
        self.current
    }

    /// Returns a reference to a thread by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The thread ID to look up
    ///
    /// # Returns
    ///
    /// A reference to the thread if found, or `None` if no thread exists with that ID.
    #[must_use]
    pub fn get_thread(&self, id: ThreadId) -> Option<&EmulationThread> {
        self.threads.get(&id)
    }

    /// Returns a mutable reference to a thread by its ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The thread ID to look up
    ///
    /// # Returns
    ///
    /// A mutable reference to the thread if found, or `None` if no thread exists with that ID.
    pub fn get_thread_mut(&mut self, id: ThreadId) -> Option<&mut EmulationThread> {
        self.threads.get_mut(&id)
    }

    /// Returns a reference to the currently running thread, if any.
    #[must_use]
    pub fn current_thread(&self) -> Option<&EmulationThread> {
        self.current.and_then(|id| self.threads.get(&id))
    }

    /// Returns a mutable reference to the currently running thread, if any.
    pub fn current_thread_mut(&mut self) -> Option<&mut EmulationThread> {
        self.current.and_then(|id| self.threads.get_mut(&id))
    }

    /// Checks if all threads have reached a terminal state.
    ///
    /// A thread is considered completed if it is in the `Completed`, `Faulted`,
    /// or `Aborted` state.
    #[must_use]
    pub fn all_completed(&self) -> bool {
        self.threads.values().all(EmulationThread::is_completed)
    }

    /// Checks if any thread is ready to execute.
    ///
    /// Returns `true` if there is a current thread running or if there are
    /// threads in the ready queue.
    #[must_use]
    pub fn has_ready_threads(&self) -> bool {
        self.current.is_some() || !self.ready_queue.is_empty()
    }

    /// Enqueue a thread as ready to run.
    fn enqueue_ready(&mut self, id: ThreadId, priority: ThreadPriority) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.ready_queue.push(ScheduleEntry {
            priority,
            thread_id: id,
            sequence,
        });
    }

    /// Selects the next thread to run based on priority and quantum state.
    ///
    /// This method implements the core scheduling algorithm:
    ///
    /// 1. If the current thread is still ready and has remaining quantum, keep it running
    /// 2. Otherwise, put the current thread back in the ready queue (if still ready)
    /// 3. Select the highest priority thread from the ready queue
    ///
    /// # Returns
    ///
    /// The thread ID of the next thread to run, or `None` if no threads are ready.
    /// When `None` is returned, either all threads are completed or all are waiting.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::sync::{Arc, RwLock};
    /// # use dotscope::emulation::{
    /// #     AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
    /// #     SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
    /// # };
    /// # let address_space = Arc::new(AddressSpace::new());
    /// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    /// # let context = Arc::new(ThreadContext::new(
    /// #     address_space,
    /// #     Arc::new(RwLock::new(RuntimeState::new())),
    /// #     Arc::new(CaptureContext::new()),
    /// #     Arc::new(EmulationConfig::default()),
    /// #     None,
    /// #     fake_objects,
    /// #     Arc::new(VirtualFs::new()),
    /// # ));
    /// # let mut scheduler = dotscope::emulation::ThreadScheduler::new(500);
    /// # scheduler.add_main_thread(EmulationThread::new(ThreadId::MAIN, context));
    /// while let Some(thread_id) = scheduler.select_next() {
    ///     // Execute one instruction for this thread: here its last
    ///     println!("Thread {} runs", thread_id);
    ///     scheduler.record_instruction();
    ///     scheduler.complete_current(None);
    /// }
    /// ```
    pub fn select_next(&mut self) -> Option<ThreadId> {
        // If we have a current thread that's still running, keep it
        if let Some(current_id) = self.current {
            if let Some(thread) = self.threads.get(&current_id) {
                if thread.is_ready() && self.quantum_used < self.quantum {
                    return Some(current_id);
                }
            }
        }

        // Put current thread back in queue if still ready
        if let Some(current_id) = self.current.take() {
            if let Some(thread) = self.threads.get(&current_id) {
                if thread.is_ready() {
                    self.enqueue_ready(current_id, thread.priority());
                }
            }
        }

        // Reset quantum for new thread
        self.quantum_used = 0;

        // Find next ready thread from queue
        while let Some(entry) = self.ready_queue.pop() {
            if let Some(thread) = self.threads.get(&entry.thread_id) {
                if thread.is_ready() {
                    self.current = Some(entry.thread_id);
                    return Some(entry.thread_id);
                }
            }
        }

        None
    }

    /// Records that an instruction was executed by the current thread.
    ///
    /// This method should be called after each instruction is executed. It updates
    /// the instruction counters for both the scheduler and the current thread.
    ///
    /// # Returns
    ///
    /// Returns `true` if the current thread's quantum is exhausted and a context
    /// switch should occur on the next [`select_next`](Self::select_next) call.
    /// Returns `false` if the thread still has remaining quantum.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::sync::{Arc, RwLock};
    /// # use dotscope::emulation::{
    /// #     AddressSpace, CaptureContext, EmulationConfig, EmulationThread, RuntimeState,
    /// #     SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
    /// # };
    /// # let address_space = Arc::new(AddressSpace::new());
    /// # let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    /// # let context = Arc::new(ThreadContext::new(
    /// #     address_space,
    /// #     Arc::new(RwLock::new(RuntimeState::new())),
    /// #     Arc::new(CaptureContext::new()),
    /// #     Arc::new(EmulationConfig::default()),
    /// #     None,
    /// #     fake_objects,
    /// #     Arc::new(VirtualFs::new()),
    /// # ));
    /// # let mut scheduler = dotscope::emulation::ThreadScheduler::new(500);
    /// # scheduler.add_main_thread(EmulationThread::new(ThreadId::MAIN, context));
    /// # let thread_id = scheduler.select_next().expect("the main thread is ready");
    /// // Execute instruction, then count it against the quantum
    /// if scheduler.record_instruction() {
    ///     // Quantum exhausted, next select_next() will switch threads
    ///     println!("Thread {} preempted", thread_id);
    /// }
    /// ```
    pub fn record_instruction(&mut self) -> bool {
        self.total_instructions = self.total_instructions.saturating_add(1);
        self.quantum_used = self.quantum_used.saturating_add(1);

        if let Some(id) = self.current {
            if let Some(thread) = self.threads.get_mut(&id) {
                thread.increment_instructions();
            }
        }

        self.quantum_used >= self.quantum
    }

    /// Yields the current thread, allowing other threads to run.
    ///
    /// This forces the current thread's quantum to be exhausted, causing the
    /// scheduler to select a different thread on the next [`select_next`](Self::select_next)
    /// call. The yielding thread remains in the ready state and will be
    /// re-queued for execution.
    ///
    /// This is useful for implementing cooperative yielding behavior or when
    /// a thread wants to give other threads a chance to run.
    pub fn yield_current(&mut self) {
        self.quantum_used = self.quantum; // Force reschedule
    }

    /// Blocks the current thread with the given wait reason.
    ///
    /// The thread is moved from the running state to the waiting state and
    /// will not be scheduled until it is explicitly woken via [`wake`](Self::wake)
    /// or [`wake_thread`](Self::wake_thread).
    ///
    /// # Arguments
    ///
    /// * `reason` - The reason the thread is blocking (monitor, event, sleep, etc.)
    ///
    /// # Errors
    ///
    /// Currently always succeeds and returns `Ok(())`.
    pub fn block_current(&mut self, reason: WaitReason) -> Result<()> {
        if let Some(id) = self.current {
            if let Some(thread) = self.threads.get_mut(&id) {
                thread.set_state(ThreadState::Waiting(reason));
            }
            self.current = None;
            self.quantum_used = 0;
        }
        Ok(())
    }

    /// Wakes threads waiting on a specific condition.
    ///
    /// Iterates through all waiting threads and moves those matching the
    /// condition back to the ready state. The woken threads are added to
    /// the ready queue based on their priority.
    ///
    /// # Arguments
    ///
    /// * `condition` - The wake condition to match against waiting threads
    ///
    /// # Example
    ///
    /// ```
    /// use dotscope::emulation::{HeapRef, ThreadScheduler, WakeCondition};
    ///
    /// let mut scheduler = ThreadScheduler::new(500);
    /// let obj_ref = HeapRef::new(1);
    ///
    /// // Wake all threads sleeping past instruction 1000
    /// scheduler.wake(&WakeCondition::SleepElapsed { current_instruction: 1000 });
    ///
    /// // Wake threads waiting on a specific monitor
    /// scheduler.wake(&WakeCondition::Monitor(obj_ref));
    /// ```
    pub fn wake(&mut self, condition: &WakeCondition) {
        let threads_to_wake: Vec<ThreadId> = self
            .threads
            .iter()
            .filter_map(|(id, thread)| {
                if let ThreadState::Waiting(reason) = thread.state() {
                    if condition.matches(&reason) {
                        return Some(*id);
                    }
                }
                None
            })
            .collect();

        for id in threads_to_wake {
            let priority = if let Some(thread) = self.threads.get_mut(&id) {
                thread.set_state(ThreadState::Ready);
                Some(thread.priority())
            } else {
                None
            };
            if let Some(p) = priority {
                self.enqueue_ready(id, p);
            }
        }
    }

    /// Wakes a specific thread by its ID.
    ///
    /// If the thread is in a waiting state, it is moved to the ready state
    /// and added to the ready queue. If the thread is not waiting (e.g., already
    /// ready, running, or completed), this method has no effect.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the thread to wake
    pub fn wake_thread(&mut self, id: ThreadId) {
        let priority = if let Some(thread) = self.threads.get_mut(&id) {
            if matches!(thread.state(), ThreadState::Waiting(_)) {
                thread.set_state(ThreadState::Ready);
                Some(thread.priority())
            } else {
                None
            }
        } else {
            None
        };
        if let Some(p) = priority {
            self.enqueue_ready(id, p);
        }
    }

    /// Marks the current thread as completed with an optional return value.
    ///
    /// The thread is moved to the completed state and removed from the current
    /// slot. If a return value is provided, it is stored in the thread for later
    /// retrieval.
    ///
    /// # Arguments
    ///
    /// * `return_value` - Optional return value from the thread's execution
    pub fn complete_current(&mut self, return_value: Option<EmValue>) {
        if let Some(id) = self.current.take() {
            if let Some(thread) = self.threads.get_mut(&id) {
                thread.set_return_value(return_value);
            }
        }
        self.quantum_used = 0;
    }

    /// Marks the current thread as faulted due to an unhandled exception.
    ///
    /// The thread is moved to the faulted state and removed from the current
    /// slot. Faulted threads cannot be resumed.
    pub fn fault_current(&mut self) {
        if let Some(id) = self.current.take() {
            if let Some(thread) = self.threads.get_mut(&id) {
                thread.fault();
            }
        }
        self.quantum_used = 0;
    }

    /// Aborts a specific thread by its ID.
    ///
    /// The thread is moved to the aborted state. If the thread is currently
    /// running, it is removed from the current slot. Aborted threads cannot
    /// be resumed.
    ///
    /// # Arguments
    ///
    /// * `id` - The ID of the thread to abort
    pub fn abort_thread(&mut self, id: ThreadId) {
        if let Some(thread) = self.threads.get_mut(&id) {
            thread.abort();
        }
        if self.current == Some(id) {
            self.current = None;
            self.quantum_used = 0;
        }
    }

    /// Removes completed threads from the scheduler and returns them.
    ///
    /// This method removes all threads in terminal states (completed, faulted,
    /// or aborted) from the scheduler. The removed threads are returned so
    /// their final state can be examined.
    ///
    /// # Returns
    ///
    /// A vector of all removed threads. The return values and final states
    /// can be accessed through the returned [`EmulationThread`] instances.
    pub fn collect_completed(&mut self) -> Vec<EmulationThread> {
        let completed_ids: Vec<ThreadId> = self
            .threads
            .iter()
            .filter(|(_, t)| t.is_completed())
            .map(|(id, _)| *id)
            .collect();

        completed_ids
            .into_iter()
            .filter_map(|id| self.threads.remove(&id))
            .collect()
    }

    /// Checks the scheduler state and returns an appropriate outcome.
    ///
    /// This method examines the current state of all threads and returns
    /// a [`SchedulerOutcome`] indicating the overall status:
    ///
    /// - [`AllCompleted`](SchedulerOutcome::AllCompleted) if all threads are done
    /// - [`Deadlock`](SchedulerOutcome::Deadlock) if threads are waiting but none can proceed
    /// - [`Continue`](SchedulerOutcome::Continue) if more work remains
    ///
    /// # Returns
    ///
    /// The current scheduler outcome based on thread states.
    #[must_use]
    pub fn check_state(&self) -> SchedulerOutcome {
        // Check if all threads completed
        if self.all_completed() {
            return SchedulerOutcome::AllCompleted;
        }

        // Check for deadlock (all threads waiting, none ready)
        if !self.has_ready_threads() {
            let waiting: Vec<ThreadId> = self
                .threads
                .iter()
                .filter(|(_, t)| matches!(t.state(), ThreadState::Waiting(_)))
                .map(|(id, _)| *id)
                .collect();

            if !waiting.is_empty() {
                return SchedulerOutcome::Deadlock {
                    waiting_threads: waiting,
                };
            }
        }

        SchedulerOutcome::Continue
    }

    /// Returns an iterator over all threads and their IDs.
    ///
    /// The iterator yields references to (ThreadId, EmulationThread) pairs
    /// for all threads managed by the scheduler, regardless of their state.
    pub fn threads(&self) -> impl Iterator<Item = (&ThreadId, &EmulationThread)> {
        self.threads.iter()
    }

    /// Returns a mutable iterator over all threads and their IDs.
    ///
    /// The iterator yields mutable references to threads, allowing their
    /// state to be modified during iteration.
    pub fn threads_mut(&mut self) -> impl Iterator<Item = (&ThreadId, &mut EmulationThread)> {
        self.threads.iter_mut()
    }
}

/// Condition for waking blocked threads.
///
/// This enum specifies which waiting threads should be woken up when
/// calling [`ThreadScheduler::wake`]. Each variant targets threads
/// blocked on a specific synchronization primitive or condition.
///
/// # Usage
///
/// ```
/// use dotscope::emulation::{HeapRef, ThreadScheduler, WakeCondition};
///
/// let mut scheduler = ThreadScheduler::new(500);
/// let object_ref = HeapRef::new(1);
///
/// // Wake threads waiting on a monitor
/// scheduler.wake(&WakeCondition::Monitor(object_ref));
///
/// // Wake threads whose sleep has elapsed
/// scheduler.wake(&WakeCondition::SleepElapsed {
///     current_instruction: scheduler.total_instructions(),
/// });
///
/// // Wake all waiting threads
/// scheduler.wake(&WakeCondition::All);
/// ```
#[derive(Clone, Debug)]
pub enum WakeCondition {
    /// Wake threads waiting on a specific monitor (lock object).
    ///
    /// Used when releasing a monitor lock to wake threads blocked on
    /// `Monitor.Enter` or `Monitor.Wait`.
    Monitor(HeapRef),

    /// Wake threads waiting on a specific event.
    ///
    /// Used when an event is signaled (`ManualResetEvent.Set` or
    /// `AutoResetEvent.Set`).
    Event(HeapRef),

    /// Wake threads waiting for a specific thread to complete.
    ///
    /// Used when a thread finishes to wake threads blocked on `Thread.Join`.
    Thread(ThreadId),

    /// Wake threads whose sleep time has elapsed.
    ///
    /// Compares the provided instruction count against the wake time
    /// stored in [`WaitReason::Sleep`].
    SleepElapsed {
        /// Current virtual instruction count to compare against sleep targets.
        current_instruction: u64,
    },

    /// Wake threads waiting on a specific mutex.
    ///
    /// Used when a mutex is released to wake threads blocked on
    /// `Mutex.WaitOne`.
    Mutex(HeapRef),

    /// Wake threads waiting on a specific semaphore.
    ///
    /// Used when a semaphore is released to wake threads blocked on
    /// `Semaphore.WaitOne`.
    Semaphore(HeapRef),

    /// Wake all waiting threads unconditionally.
    ///
    /// This is a broadcast wake that moves all waiting threads to the
    /// ready queue. Useful for debugging or forced wake scenarios.
    All,
}

impl WakeCondition {
    /// Checks if this wake condition matches the given wait reason.
    ///
    /// This method is used internally by the scheduler to determine which
    /// waiting threads should be woken when a specific condition is signaled.
    ///
    /// # Arguments
    ///
    /// * `reason` - The wait reason to check against this condition
    ///
    /// # Returns
    ///
    /// Returns `true` if a thread waiting for `reason` should be woken by
    /// this condition, `false` otherwise.
    #[must_use]
    pub fn matches(&self, reason: &WaitReason) -> bool {
        match (self, reason) {
            (WakeCondition::Monitor(wake_href), WaitReason::Monitor(wait_href))
            | (WakeCondition::Event(wake_href), WaitReason::Event(wait_href))
            | (WakeCondition::Mutex(wake_href), WaitReason::Mutex(wait_href))
            | (WakeCondition::Semaphore(wake_href), WaitReason::Semaphore(wait_href)) => {
                wake_href == wait_href
            }
            (WakeCondition::Thread(tid), WaitReason::Thread(waiting_for)) => tid == waiting_for,
            (
                WakeCondition::SleepElapsed {
                    current_instruction,
                },
                WaitReason::Sleep { until_instruction },
            ) => *current_instruction >= *until_instruction,
            (WakeCondition::All, _) => true,
            _ => false,
        }
    }
}

impl Default for ThreadScheduler {
    fn default() -> Self {
        Self::with_default_quantum()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        emulation::{
            thread::{
                EmulationThread, SchedulerOutcome, ThreadPriority, ThreadScheduler, WaitReason,
                WakeCondition,
            },
            EmValue, HeapRef, ThreadId,
        },
        testkit::emulation::create_test_context,
    };

    fn create_test_thread(id: u32) -> EmulationThread {
        EmulationThread::new(ThreadId::new(id), create_test_context())
    }

    #[test]
    fn test_scheduler_creation() {
        let scheduler = ThreadScheduler::new(500);
        assert_eq!(scheduler.quantum(), 500);
        assert_eq!(scheduler.thread_count(), 0);
        assert_eq!(scheduler.total_instructions(), 0);
    }

    #[test]
    fn test_add_main_thread() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        scheduler.add_main_thread(thread);

        assert_eq!(scheduler.thread_count(), 1);
        assert!(scheduler.has_ready_threads());
    }

    #[test]
    fn test_spawn_thread() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        let id = scheduler.spawn(thread).unwrap();

        assert_eq!(id, ThreadId::new(1));
        assert_eq!(scheduler.thread_count(), 1);
    }

    #[test]
    fn test_select_next() {
        let mut scheduler = ThreadScheduler::new(100);

        let thread1 = create_test_thread(1);
        let thread2 = create_test_thread(2);

        scheduler.spawn(thread1).unwrap();
        scheduler.spawn(thread2).unwrap();

        // First selection should get a thread
        let selected = scheduler.select_next();
        assert!(selected.is_some());

        // Should keep same thread until quantum exhausted
        let same = scheduler.select_next();
        assert_eq!(selected, same);
    }

    #[test]
    fn test_quantum_exhaustion() {
        let mut scheduler = ThreadScheduler::new(3);
        let thread = create_test_thread(1);

        scheduler.spawn(thread).unwrap();
        scheduler.select_next();

        // Execute 3 instructions to exhaust quantum
        assert!(!scheduler.record_instruction());
        assert!(!scheduler.record_instruction());
        assert!(scheduler.record_instruction()); // Quantum exhausted

        assert_eq!(scheduler.total_instructions(), 3);
    }

    #[test]
    fn test_thread_priority() {
        let mut scheduler = ThreadScheduler::new(100);

        let ctx = create_test_context();

        let mut low_thread = EmulationThread::new(ThreadId::new(1), Arc::clone(&ctx));
        low_thread.set_priority(ThreadPriority::Lowest);

        let mut high_thread = EmulationThread::new(ThreadId::new(2), ctx);
        high_thread.set_priority(ThreadPriority::Highest);

        // Add low priority first
        scheduler.spawn(low_thread).unwrap();
        // Add high priority second
        scheduler.spawn(high_thread).unwrap();

        // High priority should be selected first
        let selected = scheduler.select_next();
        assert_eq!(selected, Some(ThreadId::new(2)));
    }

    #[test]
    fn test_complete_current() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        scheduler.spawn(thread).unwrap();
        scheduler.select_next();

        scheduler.complete_current(Some(EmValue::I32(42)));

        let thread = scheduler.get_thread(ThreadId::new(1)).unwrap();
        assert!(thread.is_completed());
        assert_eq!(thread.return_value(), Some(&EmValue::I32(42)));
    }

    #[test]
    fn test_all_completed() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        scheduler.spawn(thread).unwrap();
        assert!(!scheduler.all_completed());

        scheduler.select_next();
        scheduler.complete_current(None);

        assert!(scheduler.all_completed());
    }

    #[test]
    fn test_yield_current() {
        let mut scheduler = ThreadScheduler::new(100);

        let thread1 = create_test_thread(1);
        let thread2 = create_test_thread(2);

        scheduler.spawn(thread1).unwrap();
        scheduler.spawn(thread2).unwrap();

        let first = scheduler.select_next();
        scheduler.yield_current();

        // After yield, should select a different thread
        let next = scheduler.select_next();
        assert_ne!(first, next);
    }

    #[test]
    fn test_wake_sleeping_threads() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        scheduler.spawn(thread).unwrap();
        scheduler.select_next();

        // Block thread with sleep
        scheduler
            .block_current(WaitReason::Sleep {
                until_instruction: 100,
            })
            .unwrap();

        assert!(!scheduler.has_ready_threads());

        // Wake sleeping threads
        scheduler.wake(&WakeCondition::SleepElapsed {
            current_instruction: 100,
        });

        assert!(scheduler.has_ready_threads());
    }

    #[test]
    fn test_deadlock_detection() {
        let mut scheduler = ThreadScheduler::new(100);
        let thread = create_test_thread(1);

        scheduler.spawn(thread).unwrap();
        scheduler.select_next();

        // Block thread (use a dummy HeapRef for the monitor object)
        let dummy_monitor = HeapRef::new(1);
        scheduler
            .block_current(WaitReason::Monitor(dummy_monitor))
            .unwrap();

        // Check for deadlock
        let outcome = scheduler.check_state();
        assert!(matches!(outcome, SchedulerOutcome::Deadlock { .. }));
    }
}
