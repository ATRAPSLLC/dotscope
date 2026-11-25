//! Synchronization primitives for thread coordination.
//!
//! This module provides emulated synchronization primitives used by .NET
//! threading constructs like Monitor, Mutex, Semaphore, and events. These
//! primitives allow faithful emulation of multi-threaded .NET code including
//! proper blocking, signaling, and wait queue management.
//!
//! # Supported Primitives
//!
//! ## Monitors (lock keyword)
//!
//! Monitors implement the semantics of C#'s `lock` statement and the
//! `System.Threading.Monitor` class. They support:
//! - Reentrant locking (same thread can acquire multiple times)
//! - Wait/Pulse/PulseAll operations for condition variables
//!
//! ## Mutexes
//!
//! Named or unnamed mutexes with ownership tracking and abandonment detection.
//! Similar to monitors but designed for cross-process synchronization.
//!
//! ## Semaphores
//!
//! Counting semaphores that allow a configurable number of threads to access
//! a resource concurrently.
//!
//! ## Events
//!
//! Both `ManualResetEvent` and `AutoResetEvent` are supported:
//! - Manual reset events stay signaled until explicitly reset
//! - Auto reset events automatically reset after releasing one waiter
//!
//! # Usage
//!
//! The [`SyncState`] struct is the central coordinator for all synchronization
//! primitives. It should be shared across all threads in an emulation session.
//!
//! ```
//! use dotscope::emulation::{HeapRef, SyncState, ThreadId};
//!
//! let mut sync = SyncState::new();
//! let obj_ref = HeapRef::new(1);
//! let thread_id = ThreadId::new(1);
//!
//! // Enter a monitor
//! if sync.monitor_try_enter(obj_ref, thread_id) {
//!     // Critical section
//!     sync.monitor_exit(obj_ref, thread_id)?;
//! }
//! # Ok::<(), dotscope::emulation::SyncError>(())
//! ```

use std::collections::{HashMap, VecDeque};

use crate::emulation::{HeapRef, ThreadId};

/// State of an event synchronization primitive.
///
/// Events are signaling mechanisms that allow threads to wait for a condition
/// to become true. There are two types:
///
/// - **Manual reset events**: Stay signaled until explicitly reset. All waiting
///   threads are released when signaled.
/// - **Auto reset events**: Automatically reset after releasing exactly one
///   waiting thread.
///
/// # Example
///
/// ```
/// use dotscope::emulation::EventState;
///
/// // Create a manual reset event, initially not signaled
/// let event = EventState::manual_reset(false);
///
/// // Create an auto reset event, initially signaled
/// let event = EventState::auto_reset(true);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventState {
    /// Whether the event is currently signaled (set).
    pub signaled: bool,
    /// Whether this is a manual reset event (`true`) or auto-reset event (`false`).
    pub manual_reset: bool,
}

impl EventState {
    /// Creates a new manual reset event with the specified initial state.
    ///
    /// Manual reset events stay signaled after being set until explicitly
    /// reset via [`SyncState::event_reset`]. When signaled, all waiting
    /// threads are released.
    ///
    /// # Arguments
    ///
    /// * `signaled` - Initial signaled state (`true` = signaled, `false` = not signaled)
    #[must_use]
    pub fn manual_reset(signaled: bool) -> Self {
        Self {
            signaled,
            manual_reset: true,
        }
    }

    /// Creates a new auto reset event with the specified initial state.
    ///
    /// Auto reset events automatically transition to the non-signaled state
    /// after releasing exactly one waiting thread. This provides exclusive
    /// one-at-a-time wake-up semantics.
    ///
    /// # Arguments
    ///
    /// * `signaled` - Initial signaled state (`true` = signaled, `false` = not signaled)
    #[must_use]
    pub fn auto_reset(signaled: bool) -> Self {
        Self {
            signaled,
            manual_reset: false,
        }
    }
}

/// Monitor lock state for an object.
///
/// A monitor provides mutual exclusion semantics for a specific object,
/// implementing the behavior of C#'s `lock` statement and `Monitor` class.
/// Monitors are reentrant, meaning the owning thread can acquire the same
/// monitor multiple times without deadlocking.
///
/// # Reentrancy
///
/// When a thread that already owns a monitor tries to acquire it again,
/// the recursion count is incremented. The monitor is only fully released
/// when the recursion count reaches zero (after the same number of exits
/// as entries).
///
/// # Example
///
/// ```
/// use dotscope::emulation::{MonitorState, ThreadId};
///
/// let mut monitor = MonitorState::default();
/// let thread_id = ThreadId::new(1);
///
/// // First acquisition
/// assert!(monitor.try_enter(thread_id));
/// assert_eq!(monitor.recursion_count, 1);
///
/// // Reentrant acquisition
/// assert!(monitor.try_enter(thread_id));
/// assert_eq!(monitor.recursion_count, 2);
///
/// // Must exit twice to fully release
/// monitor.exit(thread_id)?; // recursion_count = 1
/// monitor.exit(thread_id)?; // recursion_count = 0, released
/// # Ok::<(), dotscope::emulation::SyncError>(())
/// ```
#[derive(Clone, Debug, Default)]
pub struct MonitorState {
    /// The thread that currently owns this monitor, or `None` if unlocked.
    pub owner: Option<ThreadId>,
    /// Number of times the owner has acquired this monitor.
    ///
    /// This supports reentrant locking. The monitor is fully released only
    /// when this count reaches zero.
    pub recursion_count: u32,
}

impl MonitorState {
    /// Checks if the monitor is free (not owned by any thread).
    #[must_use]
    pub fn is_free(&self) -> bool {
        self.owner.is_none()
    }

    /// Checks if the given thread owns this monitor.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread ID to check ownership for
    #[must_use]
    pub fn is_owner(&self, thread_id: ThreadId) -> bool {
        self.owner == Some(thread_id)
    }

    /// Attempts to acquire the monitor for a thread.
    ///
    /// This is a non-blocking operation. If the monitor is free or already
    /// owned by the requesting thread (reentrant acquisition), it succeeds
    /// immediately. Otherwise, it fails without blocking.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread attempting to acquire the monitor
    ///
    /// # Returns
    ///
    /// Returns `true` if the monitor was acquired (or already owned by this thread),
    /// `false` if the monitor is owned by a different thread.
    pub fn try_enter(&mut self, thread_id: ThreadId) -> bool {
        match self.owner {
            None => {
                self.owner = Some(thread_id);
                self.recursion_count = 1;
                true
            }
            Some(owner) if owner == thread_id => {
                self.recursion_count = self.recursion_count.saturating_add(1);
                true
            }
            _ => false,
        }
    }

    /// Releases one level of monitor ownership.
    ///
    /// For reentrant locks, this decrements the recursion count. The monitor
    /// is only fully released when the recursion count reaches zero.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread attempting to release the monitor
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the monitor was fully released (recursion count reached 0)
    /// - `Ok(false)` if the monitor is still held (recursion count > 0)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotOwner`] if the thread does not own this monitor
    /// - [`SyncError::NotLocked`] if the monitor is not locked at all
    pub fn exit(&mut self, thread_id: ThreadId) -> Result<bool, SyncError> {
        match self.owner {
            Some(owner) if owner == thread_id => {
                self.recursion_count = self.recursion_count.saturating_sub(1);
                if self.recursion_count == 0 {
                    self.owner = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Some(_) => Err(SyncError::NotOwner),
            None => Err(SyncError::NotLocked),
        }
    }
}

/// Mutex synchronization primitive state.
///
/// A mutex provides mutual exclusion similar to a monitor, but with additional
/// features for cross-process synchronization and abandonment detection.
/// Like monitors, mutexes are reentrant.
///
/// # Abandonment
///
/// When a thread terminates while holding a mutex, the mutex is marked as
/// "abandoned". This is important because subsequent acquirers need to know
/// that the protected resource may be in an inconsistent state.
///
/// # Difference from Monitors
///
/// - Mutexes support cross-process synchronization (not emulated here)
/// - Mutexes track abandonment explicitly
/// - Mutexes do not have Wait/Pulse semantics
#[derive(Clone, Debug, Default)]
pub struct MutexState {
    /// The thread that currently owns this mutex, or `None` if unlocked.
    pub owner: Option<ThreadId>,
    /// Number of times the owner has acquired this mutex (for reentrancy).
    pub recursion_count: u32,
    /// Whether this mutex was abandoned by a terminated thread.
    ///
    /// When `true`, the next acquirer should check for resource consistency.
    pub abandoned: bool,
}

impl MutexState {
    /// Attempts to acquire the mutex for a thread.
    ///
    /// This is a non-blocking operation. The mutex supports reentrant
    /// acquisition by the same thread.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread attempting to acquire the mutex
    ///
    /// # Returns
    ///
    /// Returns `true` if the mutex was acquired, `false` if it is owned
    /// by a different thread.
    pub fn try_acquire(&mut self, thread_id: ThreadId) -> bool {
        match self.owner {
            None => {
                self.owner = Some(thread_id);
                self.recursion_count = 1;
                self.abandoned = false;
                true
            }
            Some(owner) if owner == thread_id => {
                self.recursion_count = self.recursion_count.saturating_add(1);
                true
            }
            _ => false,
        }
    }

    /// Releases one level of mutex ownership.
    ///
    /// For reentrant acquisitions, this decrements the recursion count.
    /// The mutex is only fully released when the count reaches zero.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The thread releasing the mutex
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the mutex was fully released
    /// - `Ok(false)` if the mutex is still held (reentrant)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotOwner`] if the thread does not own this mutex
    /// - [`SyncError::NotLocked`] if the mutex is not locked
    pub fn release(&mut self, thread_id: ThreadId) -> Result<bool, SyncError> {
        match self.owner {
            Some(owner) if owner == thread_id => {
                self.recursion_count = self.recursion_count.saturating_sub(1);
                if self.recursion_count == 0 {
                    self.owner = None;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            Some(_) => Err(SyncError::NotOwner),
            None => Err(SyncError::NotLocked),
        }
    }

    /// Marks the mutex as abandoned due to owner thread termination.
    ///
    /// This releases the mutex and sets the abandoned flag. Future acquirers
    /// can check this flag to handle potential resource inconsistency.
    pub fn abandon(&mut self) {
        self.abandoned = true;
        self.owner = None;
        self.recursion_count = 0;
    }
}

/// Counting semaphore synchronization primitive state.
///
/// A semaphore maintains a count that represents the number of available
/// resources. Threads can acquire the semaphore (decrement the count) if
/// the count is positive, or wait if the count is zero. Releasing the
/// semaphore increments the count.
///
/// Unlike mutexes and monitors, semaphores:
/// - Do not track ownership (any thread can release)
/// - Allow multiple concurrent holders (up to max_count)
/// - Are not reentrant in the traditional sense
///
/// # Example
///
/// ```
/// use dotscope::emulation::SemaphoreState;
///
/// // Create a semaphore allowing 3 concurrent accesses
/// let mut sem = SemaphoreState::new(3, 3);
///
/// // Three threads can acquire
/// assert!(sem.try_acquire()); // count = 2
/// assert!(sem.try_acquire()); // count = 1
/// assert!(sem.try_acquire()); // count = 0
/// assert!(!sem.try_acquire()); // Would block
///
/// // Release one slot
/// sem.release(1)?; // count = 1
/// assert!(sem.try_acquire()); // count = 0
/// # Ok::<(), dotscope::emulation::SyncError>(())
/// ```
#[derive(Clone, Debug)]
pub struct SemaphoreState {
    /// Current available count (0 to max_count).
    pub count: u32,
    /// Maximum count this semaphore can reach.
    pub max_count: u32,
}

impl SemaphoreState {
    /// Creates a new semaphore with the specified initial and maximum counts.
    ///
    /// # Arguments
    ///
    /// * `initial_count` - Starting count (clamped to max_count if greater)
    /// * `max_count` - Maximum count the semaphore can reach
    ///
    /// # Example
    ///
    /// ```
    /// use dotscope::emulation::SemaphoreState;
    ///
    /// // Pool of 5 resources, all initially available
    /// let sem = SemaphoreState::new(5, 5);
    ///
    /// // Pool of 5 resources, 2 initially available
    /// let sem = SemaphoreState::new(2, 5);
    /// ```
    #[must_use]
    pub fn new(initial_count: u32, max_count: u32) -> Self {
        Self {
            count: initial_count.min(max_count),
            max_count,
        }
    }

    /// Attempts to acquire the semaphore (decrement the count).
    ///
    /// This is a non-blocking operation. If the count is positive, it is
    /// decremented and the method returns `true`. If the count is zero,
    /// the method returns `false` without blocking.
    ///
    /// # Returns
    ///
    /// Returns `true` if the semaphore was acquired, `false` if the count
    /// was zero.
    pub fn try_acquire(&mut self) -> bool {
        if self.count > 0 {
            self.count = self.count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Releases the semaphore by incrementing the count.
    ///
    /// # Arguments
    ///
    /// * `count` - Number of releases (typically 1)
    ///
    /// # Returns
    ///
    /// Returns `Ok(previous_count)` where `previous_count` is the count before
    /// the release.
    ///
    /// # Errors
    ///
    /// Returns [`SyncError::SemaphoreOverflow`] if the release would cause the
    /// count to exceed the maximum.
    pub fn release(&mut self, count: u32) -> Result<u32, SyncError> {
        let new_count = self.count.saturating_add(count);
        if new_count > self.max_count {
            Err(SyncError::SemaphoreOverflow)
        } else {
            let previous = self.count;
            self.count = new_count;
            Ok(previous)
        }
    }
}

/// Errors from synchronization operations.
///
/// These errors indicate issues with synchronization primitive usage,
/// typically representing programming errors or exceptional conditions
/// in the emulated code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    /// Thread attempted to release a lock it does not own.
    ///
    /// This typically indicates a programming error where `Monitor.Exit`
    /// or `Mutex.ReleaseMutex` is called without a matching Enter/WaitOne.
    NotOwner,

    /// Operation requires a lock that is not currently held.
    ///
    /// For example, calling `Monitor.Exit` on an object that is not locked.
    NotLocked,

    /// Semaphore release would cause the count to exceed the maximum.
    ///
    /// This indicates more releases than acquisitions, typically a
    /// programming error.
    SemaphoreOverflow,

    /// The referenced synchronization object does not exist.
    ObjectNotFound,

    /// A deadlock was detected.
    ///
    /// This can occur when circular wait dependencies are detected
    /// among threads waiting for locks.
    Deadlock,

    /// A wait operation timed out.
    ///
    /// The thread waited for the specified duration but the condition
    /// was not satisfied.
    Timeout,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NotOwner => write!(f, "thread does not own the lock"),
            SyncError::NotLocked => write!(f, "lock is not held"),
            SyncError::SemaphoreOverflow => write!(f, "semaphore count would overflow"),
            SyncError::ObjectNotFound => write!(f, "synchronization object not found"),
            SyncError::Deadlock => write!(f, "deadlock detected"),
            SyncError::Timeout => write!(f, "wait operation timed out"),
        }
    }
}

impl std::error::Error for SyncError {}

/// Central state manager for all synchronization primitives.
///
/// `SyncState` tracks the state of all synchronization objects (monitors,
/// mutexes, semaphores, and events) across all threads in an emulation
/// session. It also manages wait queues for threads blocked on each
/// primitive.
///
/// # Thread Safety
///
/// `SyncState` is designed to be used from a single-threaded emulation
/// loop. The scheduler is responsible for coordinating access.
///
/// # Wait Queues
///
/// Each synchronization primitive has an associated wait queue. When a
/// thread cannot immediately acquire a resource, it is added to the
/// wait queue. When the resource becomes available, threads are dequeued
/// in FIFO order.
///
/// # Example
///
/// ```
/// use dotscope::emulation::{HeapRef, SyncState, ThreadId};
///
/// let mut sync = SyncState::new();
/// let (obj, event_obj) = (HeapRef::new(1), HeapRef::new(2));
/// let thread_id = ThreadId::new(1);
///
/// // Monitor operations
/// if sync.monitor_try_enter(obj, thread_id) {
///     // Critical section
///     sync.monitor_exit(obj, thread_id)?;
/// }
///
/// // Event operations
/// sync.event_create(event_obj, true, false); // ManualResetEvent
/// let threads_to_wake = sync.event_set(event_obj);
/// # Ok::<(), dotscope::emulation::SyncError>(())
/// ```
#[derive(Debug, Default)]
pub struct SyncState {
    /// Monitor locks (object -> state).
    monitors: HashMap<HeapRef, MonitorState>,

    /// Monitor wait queues (object -> waiting threads).
    monitor_wait_queues: HashMap<HeapRef, VecDeque<ThreadId>>,

    /// Monitor pulse queues (threads signaled by Pulse/PulseAll).
    monitor_pulse_queues: HashMap<HeapRef, VecDeque<ThreadId>>,

    /// Events (object -> state).
    events: HashMap<HeapRef, EventState>,

    /// Event wait queues.
    event_wait_queues: HashMap<HeapRef, VecDeque<ThreadId>>,

    /// Mutexes (object -> state).
    mutexes: HashMap<HeapRef, MutexState>,

    /// Mutex wait queues.
    mutex_wait_queues: HashMap<HeapRef, VecDeque<ThreadId>>,

    /// Semaphores (object -> state).
    semaphores: HashMap<HeapRef, SemaphoreState>,

    /// Semaphore wait queues.
    semaphore_wait_queues: HashMap<HeapRef, VecDeque<ThreadId>>,
}

impl SyncState {
    /// Creates a new empty synchronization state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Attempts to enter a monitor (`Monitor.Enter` / `lock` statement).
    ///
    /// If the monitor is free or already owned by this thread, the acquisition
    /// succeeds immediately. Otherwise, the thread must be blocked and added
    /// to the wait queue separately.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread attempting to acquire the monitor
    ///
    /// # Returns
    ///
    /// Returns `true` if the lock was acquired, `false` if the monitor is
    /// owned by another thread.
    pub fn monitor_try_enter(&mut self, obj: HeapRef, thread_id: ThreadId) -> bool {
        let state = self.monitors.entry(obj).or_default();
        state.try_enter(thread_id)
    }

    /// Exits a monitor (`Monitor.Exit` / end of `lock` block).
    ///
    /// Decrements the recursion count. The monitor is only fully released
    /// when the count reaches zero.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread releasing the monitor
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the monitor was fully released
    /// - `Ok(false)` if still held (reentrant lock)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotLocked`] if no monitor exists for this object
    /// - [`SyncError::NotOwner`] if the thread does not own the monitor
    pub fn monitor_exit(&mut self, obj: HeapRef, thread_id: ThreadId) -> Result<bool, SyncError> {
        let state = self.monitors.get_mut(&obj).ok_or(SyncError::NotLocked)?;
        state.exit(thread_id)
    }

    /// Performs a `Monitor.Wait` operation on the specified object.
    ///
    /// The calling thread must own the monitor. This method:
    /// 1. Saves the current recursion count
    /// 2. Fully releases the monitor
    /// 3. Adds the thread to the wait queue
    ///
    /// The thread should be blocked until pulsed, at which point it must
    /// reacquire the monitor.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread calling Wait
    ///
    /// # Returns
    ///
    /// Returns `Ok(saved_count)` where `saved_count` is the recursion count
    /// that should be restored when reacquiring the monitor.
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotLocked`] if no monitor exists for this object
    /// - [`SyncError::NotOwner`] if the thread does not own the monitor
    pub fn monitor_wait(&mut self, obj: HeapRef, thread_id: ThreadId) -> Result<u32, SyncError> {
        let state = self.monitors.get_mut(&obj).ok_or(SyncError::NotLocked)?;

        if !state.is_owner(thread_id) {
            return Err(SyncError::NotOwner);
        }

        // Save recursion count for later restore
        let saved_count = state.recursion_count;

        // Release the monitor
        state.owner = None;
        state.recursion_count = 0;

        // Add to wait queue
        self.monitor_wait_queues
            .entry(obj)
            .or_default()
            .push_back(thread_id);

        Ok(saved_count)
    }

    /// Signals one waiting thread (`Monitor.Pulse`).
    ///
    /// Moves one thread from the wait queue to the pulse queue. Pulsed
    /// threads will attempt to reacquire the monitor when the current
    /// owner releases it.
    ///
    /// The calling thread must own the monitor.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread calling Pulse (must be owner)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotLocked`] if no monitor exists for this object
    /// - [`SyncError::NotOwner`] if the thread does not own the monitor
    pub fn monitor_pulse(&mut self, obj: HeapRef, thread_id: ThreadId) -> Result<(), SyncError> {
        let state = self.monitors.get(&obj).ok_or(SyncError::NotLocked)?;

        if !state.is_owner(thread_id) {
            return Err(SyncError::NotOwner);
        }

        // Move one thread from wait queue to pulse queue
        if let Some(wait_queue) = self.monitor_wait_queues.get_mut(&obj) {
            if let Some(waiting_thread) = wait_queue.pop_front() {
                self.monitor_pulse_queues
                    .entry(obj)
                    .or_default()
                    .push_back(waiting_thread);
            }
        }

        Ok(())
    }

    /// Signals all waiting threads (`Monitor.PulseAll`).
    ///
    /// Moves all threads from the wait queue to the pulse queue. All pulsed
    /// threads will compete to reacquire the monitor when it is released.
    ///
    /// The calling thread must own the monitor.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread calling PulseAll (must be owner)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotLocked`] if no monitor exists for this object
    /// - [`SyncError::NotOwner`] if the thread does not own the monitor
    pub fn monitor_pulse_all(
        &mut self,
        obj: HeapRef,
        thread_id: ThreadId,
    ) -> Result<(), SyncError> {
        let state = self.monitors.get(&obj).ok_or(SyncError::NotLocked)?;

        if !state.is_owner(thread_id) {
            return Err(SyncError::NotOwner);
        }

        // Move all threads from wait queue to pulse queue
        if let Some(mut wait_queue) = self.monitor_wait_queues.remove(&obj) {
            let pulse_queue = self.monitor_pulse_queues.entry(obj).or_default();
            pulse_queue.append(&mut wait_queue);
        }

        Ok(())
    }

    /// Gets and removes all pulsed threads for a monitor.
    ///
    /// These threads were previously in the wait queue and were signaled
    /// by Pulse/PulseAll. They should now attempt to reacquire the monitor.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    ///
    /// # Returns
    ///
    /// A vector of thread IDs that were pulsed and should try to reacquire
    /// the monitor. Returns an empty vector if no threads were pulsed.
    pub fn monitor_get_pulsed(&mut self, obj: HeapRef) -> Vec<ThreadId> {
        self.monitor_pulse_queues
            .remove(&obj)
            .map(|q| q.into_iter().collect())
            .unwrap_or_default()
    }

    /// Checks if a thread owns a specific monitor.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the lock object
    /// * `thread_id` - The thread to check ownership for
    ///
    /// # Returns
    ///
    /// Returns `true` if the thread owns the monitor, `false` otherwise.
    #[must_use]
    pub fn monitor_is_owner(&self, obj: HeapRef, thread_id: ThreadId) -> bool {
        self.monitors
            .get(&obj)
            .is_some_and(|s| s.is_owner(thread_id))
    }

    /// Creates a new event synchronization primitive.
    ///
    /// If an event already exists for this object reference, it is replaced.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to associate with the event
    /// * `manual_reset` - `true` for `ManualResetEvent`, `false` for `AutoResetEvent`
    /// * `initial_state` - `true` if initially signaled, `false` otherwise
    pub fn event_create(&mut self, obj: HeapRef, manual_reset: bool, initial_state: bool) {
        self.events.insert(
            obj,
            EventState {
                signaled: initial_state,
                manual_reset,
            },
        );
    }

    /// Attempts to wait on an event (non-blocking check).
    ///
    /// If the event is signaled:
    /// - For auto-reset events, the event is automatically reset
    /// - For manual-reset events, the event stays signaled
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the event
    ///
    /// # Returns
    ///
    /// - `Some(true)` if the event was signaled (wait succeeds)
    /// - `Some(false)` if the event was not signaled (would block)
    /// - `None` if no event exists for this reference
    pub fn event_try_wait(&mut self, obj: HeapRef) -> Option<bool> {
        let state = self.events.get_mut(&obj)?;

        if state.signaled {
            if !state.manual_reset {
                state.signaled = false;
            }
            Some(true)
        } else {
            Some(false)
        }
    }

    /// Adds a thread to the event wait queue.
    ///
    /// Called when a thread must block waiting for the event to be signaled.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the event
    /// * `thread_id` - The thread to add to the wait queue
    pub fn event_add_waiter(&mut self, obj: HeapRef, thread_id: ThreadId) {
        self.event_wait_queues
            .entry(obj)
            .or_default()
            .push_back(thread_id);
    }

    /// Signals (sets) an event.
    ///
    /// For manual-reset events, all waiting threads are woken and the event
    /// stays signaled. For auto-reset events, only one waiter is woken and
    /// the event stays signaled if no threads were waiting.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the event
    ///
    /// # Returns
    ///
    /// A vector of thread IDs that should be woken. The caller is responsible
    /// for actually waking these threads via the scheduler.
    pub fn event_set(&mut self, obj: HeapRef) -> Vec<ThreadId> {
        if let Some(state) = self.events.get_mut(&obj) {
            state.signaled = true;

            if state.manual_reset {
                // Wake all waiters
                self.event_wait_queues
                    .remove(&obj)
                    .map(|q| q.into_iter().collect())
                    .unwrap_or_default()
            } else {
                // Wake one waiter
                self.event_wait_queues
                    .get_mut(&obj)
                    .and_then(VecDeque::pop_front)
                    .into_iter()
                    .collect()
            }
        } else {
            Vec::new()
        }
    }

    /// Resets (unsignals) an event.
    ///
    /// After reset, threads attempting to wait on this event will block until
    /// the event is signaled again.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the event
    ///
    /// # Returns
    ///
    /// Returns `true` if the event was reset, `false` if no event exists
    /// for this reference.
    pub fn event_reset(&mut self, obj: HeapRef) -> bool {
        if let Some(state) = self.events.get_mut(&obj) {
            state.signaled = false;
            true
        } else {
            false
        }
    }

    /// Attempts to acquire a mutex.
    ///
    /// This is a non-blocking operation. The mutex supports reentrant
    /// acquisition by the same thread.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the mutex
    /// * `thread_id` - The thread attempting to acquire
    ///
    /// # Returns
    ///
    /// Returns `true` if the mutex was acquired, `false` if it is owned
    /// by another thread.
    pub fn mutex_try_acquire(&mut self, obj: HeapRef, thread_id: ThreadId) -> bool {
        let state = self.mutexes.entry(obj).or_default();
        state.try_acquire(thread_id)
    }

    /// Releases a mutex.
    ///
    /// For reentrant acquisitions, this decrements the recursion count.
    /// The mutex is only fully released when the count reaches zero.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the mutex
    /// * `thread_id` - The thread releasing the mutex
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if the mutex was fully released
    /// - `Ok(false)` if still held (reentrant)
    ///
    /// # Errors
    ///
    /// - [`SyncError::NotLocked`] if no mutex exists for this object
    /// - [`SyncError::NotOwner`] if the thread does not own the mutex
    pub fn mutex_release(&mut self, obj: HeapRef, thread_id: ThreadId) -> Result<bool, SyncError> {
        let state = self.mutexes.get_mut(&obj).ok_or(SyncError::NotLocked)?;
        state.release(thread_id)
    }

    /// Adds a thread to the mutex wait queue.
    ///
    /// Called when a thread must block waiting for the mutex.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the mutex
    /// * `thread_id` - The thread to add to the wait queue
    pub fn mutex_add_waiter(&mut self, obj: HeapRef, thread_id: ThreadId) {
        self.mutex_wait_queues
            .entry(obj)
            .or_default()
            .push_back(thread_id);
    }

    /// Gets and removes the next waiter from the mutex wait queue.
    ///
    /// Used when a mutex is released to determine which waiting thread
    /// should be woken to acquire it next.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the mutex
    ///
    /// # Returns
    ///
    /// The next waiting thread ID in FIFO order, or `None` if no threads
    /// are waiting.
    pub fn mutex_next_waiter(&mut self, obj: HeapRef) -> Option<ThreadId> {
        self.mutex_wait_queues
            .get_mut(&obj)
            .and_then(VecDeque::pop_front)
    }

    /// Handles thread termination by abandoning any held mutexes.
    ///
    /// When a thread terminates while holding mutexes, those mutexes are
    /// marked as abandoned. This allows other threads to detect that the
    /// protected resource may be in an inconsistent state.
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The terminating thread's ID
    ///
    /// # Returns
    ///
    /// A vector of mutex references that were abandoned.
    pub fn mutex_abandon_for_thread(&mut self, thread_id: ThreadId) -> Vec<HeapRef> {
        let mut abandoned = Vec::new();

        for (obj, state) in &mut self.mutexes {
            if state.owner == Some(thread_id) {
                state.abandon();
                abandoned.push(*obj);
            }
        }

        abandoned
    }

    /// Creates a new semaphore synchronization primitive.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to associate with the semaphore
    /// * `initial_count` - Starting count (number of available slots)
    /// * `max_count` - Maximum count the semaphore can reach
    pub fn semaphore_create(&mut self, obj: HeapRef, initial_count: u32, max_count: u32) {
        self.semaphores
            .insert(obj, SemaphoreState::new(initial_count, max_count));
    }

    /// Attempts to acquire a semaphore slot.
    ///
    /// This is a non-blocking operation.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the semaphore
    ///
    /// # Returns
    ///
    /// - `Some(true)` if a slot was acquired (count was > 0)
    /// - `Some(false)` if no slots available (count was 0)
    /// - `None` if no semaphore exists for this reference
    #[allow(clippy::redundant_closure_for_method_calls)]
    pub fn semaphore_try_acquire(&mut self, obj: HeapRef) -> Option<bool> {
        self.semaphores.get_mut(&obj).map(|s| s.try_acquire())
    }

    /// Releases slots back to a semaphore.
    ///
    /// Increments the semaphore count and wakes waiting threads as slots
    /// become available.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the semaphore
    /// * `count` - Number of slots to release (typically 1)
    ///
    /// # Returns
    ///
    /// Returns `Ok((previous_count, woken_threads))` where:
    /// - `previous_count` is the count before release
    /// - `woken_threads` is a list of threads to wake
    ///
    /// # Errors
    ///
    /// - [`SyncError::ObjectNotFound`] if no semaphore exists for this reference
    /// - [`SyncError::SemaphoreOverflow`] if release would exceed max count
    pub fn semaphore_release(
        &mut self,
        obj: HeapRef,
        count: u32,
    ) -> Result<(u32, Vec<ThreadId>), SyncError> {
        let state = self
            .semaphores
            .get_mut(&obj)
            .ok_or(SyncError::ObjectNotFound)?;

        let previous = state.release(count)?;

        // Wake up waiters based on new count
        let mut woken = Vec::new();
        if let Some(queue) = self.semaphore_wait_queues.get_mut(&obj) {
            for _ in 0..count.min(u32::try_from(queue.len()).unwrap_or(u32::MAX)) {
                if let Some(thread_id) = queue.pop_front() {
                    woken.push(thread_id);
                }
            }
        }

        Ok((previous, woken))
    }

    /// Adds a thread to the semaphore wait queue.
    ///
    /// Called when a thread must block waiting for a semaphore slot.
    ///
    /// # Arguments
    ///
    /// * `obj` - Reference to the semaphore
    /// * `thread_id` - The thread to add to the wait queue
    pub fn semaphore_add_waiter(&mut self, obj: HeapRef, thread_id: ThreadId) {
        self.semaphore_wait_queues
            .entry(obj)
            .or_default()
            .push_back(thread_id);
    }

    /// Cleans up synchronization state for a terminated thread.
    ///
    /// This method should be called when a thread terminates to:
    /// - Abandon any mutexes held by the thread
    /// - Remove the thread from all wait queues
    ///
    /// # Arguments
    ///
    /// * `thread_id` - The terminated thread's ID
    pub fn cleanup_thread(&mut self, thread_id: ThreadId) {
        // Abandon mutexes
        self.mutex_abandon_for_thread(thread_id);

        // Remove from all wait queues
        for queue in self.monitor_wait_queues.values_mut() {
            queue.retain(|&id| id != thread_id);
        }
        for queue in self.monitor_pulse_queues.values_mut() {
            queue.retain(|&id| id != thread_id);
        }
        for queue in self.event_wait_queues.values_mut() {
            queue.retain(|&id| id != thread_id);
        }
        for queue in self.mutex_wait_queues.values_mut() {
            queue.retain(|&id| id != thread_id);
        }
        for queue in self.semaphore_wait_queues.values_mut() {
            queue.retain(|&id| id != thread_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_enter_exit() {
        let mut state = MonitorState::default();
        let thread1 = ThreadId::new(1);
        let thread2 = ThreadId::new(2);

        // Thread 1 can enter
        assert!(state.try_enter(thread1));
        assert!(state.is_owner(thread1));

        // Thread 2 cannot enter
        assert!(!state.try_enter(thread2));

        // Thread 1 can enter again (reentrant)
        assert!(state.try_enter(thread1));
        assert_eq!(state.recursion_count, 2);

        // Exit once (still held)
        assert!(!state.exit(thread1).unwrap());
        assert!(state.is_owner(thread1));

        // Exit again (released)
        assert!(state.exit(thread1).unwrap());
        assert!(state.is_free());

        // Thread 2 can now enter
        assert!(state.try_enter(thread2));
    }

    #[test]
    fn test_monitor_exit_errors() {
        let mut state = MonitorState::default();
        let thread1 = ThreadId::new(1);
        let thread2 = ThreadId::new(2);

        // Can't exit if not locked
        assert_eq!(state.exit(thread1), Err(SyncError::NotLocked));

        state.try_enter(thread1);

        // Thread 2 can't exit thread 1's lock
        assert_eq!(state.exit(thread2), Err(SyncError::NotOwner));
    }

    #[test]
    fn test_semaphore() {
        let mut state = SemaphoreState::new(2, 5);

        assert!(state.try_acquire());
        assert!(state.try_acquire());
        assert!(!state.try_acquire()); // Count is 0

        assert_eq!(state.release(1).unwrap(), 0);
        assert!(state.try_acquire());

        // Can't overflow
        assert_eq!(state.release(10), Err(SyncError::SemaphoreOverflow));
    }

    #[test]
    fn test_event_manual_reset() {
        let mut sync = SyncState::new();
        let obj = HeapRef::new(1);

        sync.event_create(obj, true, false); // manual reset, not signaled

        assert_eq!(sync.event_try_wait(obj), Some(false));

        sync.event_set(obj);
        assert_eq!(sync.event_try_wait(obj), Some(true));
        // Still signaled (manual reset)
        assert_eq!(sync.event_try_wait(obj), Some(true));

        sync.event_reset(obj);
        assert_eq!(sync.event_try_wait(obj), Some(false));
    }

    #[test]
    fn test_event_auto_reset() {
        let mut sync = SyncState::new();
        let obj = HeapRef::new(1);

        sync.event_create(obj, false, true); // auto reset, signaled

        assert_eq!(sync.event_try_wait(obj), Some(true));
        // Auto-reset: now not signaled
        assert_eq!(sync.event_try_wait(obj), Some(false));
    }

    #[test]
    fn test_sync_state_monitor() {
        let mut sync = SyncState::new();
        let obj = HeapRef::new(1);
        let thread1 = ThreadId::new(1);
        let thread2 = ThreadId::new(2);

        assert!(sync.monitor_try_enter(obj, thread1));
        assert!(!sync.monitor_try_enter(obj, thread2));
        assert!(sync.monitor_is_owner(obj, thread1));

        sync.monitor_exit(obj, thread1).unwrap();
        assert!(sync.monitor_try_enter(obj, thread2));
    }

    #[test]
    fn test_sync_state_monitor_wait_pulse() {
        let mut sync = SyncState::new();
        let obj = HeapRef::new(1);
        let thread1 = ThreadId::new(1);
        let thread2 = ThreadId::new(2);

        // Thread 1 enters and waits
        sync.monitor_try_enter(obj, thread1);
        sync.monitor_wait(obj, thread1).unwrap();

        // Thread 2 enters and pulses
        sync.monitor_try_enter(obj, thread2);
        sync.monitor_pulse(obj, thread2).unwrap();

        // Thread 1 is in pulse queue
        let pulsed = sync.monitor_get_pulsed(obj);
        assert_eq!(pulsed, vec![thread1]);
    }

    #[test]
    fn test_cleanup_thread() {
        let mut sync = SyncState::new();
        let obj = HeapRef::new(1);
        let thread1 = ThreadId::new(1);

        // Thread holds a mutex
        sync.mutex_try_acquire(obj, thread1);

        // Add to wait queues
        sync.monitor_wait_queues
            .entry(HeapRef::new(2))
            .or_default()
            .push_back(thread1);

        // Cleanup
        sync.cleanup_thread(thread1);

        // Mutex should be abandoned
        assert!(sync.mutexes.get(&obj).unwrap().abandoned);

        // Should be removed from wait queue
        assert!(sync
            .monitor_wait_queues
            .get(&HeapRef::new(2))
            .map(|q| q.is_empty())
            .unwrap_or(true));
    }
}
