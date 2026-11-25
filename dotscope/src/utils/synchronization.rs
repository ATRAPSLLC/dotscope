//! Synchronization utilities for multi-threaded operations.
//!
//! This module provides advanced synchronization primitives that extend beyond
//! the standard library capabilities, specifically designed for dotscope's
//! parallel processing needs.
//!
//! # Key Components
//!
//! - [`FailFastBarrier`] - A barrier that can be broken to prevent deadlocks when threads fail
//!
//! # Design Principles
//!
//! - **Fail-Fast Behavior**: When any thread fails, all waiting threads are unblocked
//! - **Deadlock Prevention**: Ensures threads don't hang indefinitely on failed operations
//! - **Thread Safety**: All operations are thread-safe and can be called concurrently
//! - **Performance**: Optimized for high-throughput parallel processing scenarios

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Condvar, Mutex,
};

use crate::{Error, Result};

/// A fail-fast barrier that can be broken when any thread encounters an error.
///
/// Unlike `std::sync::Barrier`, this barrier allows threads to signal failure
/// and unblock all other waiting threads, preventing deadlocks when some
/// threads fail and never reach the barrier.
///
/// # Use Cases
///
/// This barrier is particularly useful in scenarios where:
/// - Multiple threads are performing parallel work that may fail
/// - All threads need to synchronize at specific points
/// - Failure of any thread should abort the entire operation
/// - Deadlock prevention is critical for system reliability
///
/// # Examples
///
/// The `examples::fail_fast_barrier_example` test in this module runs this example.
pub struct FailFastBarrier {
    /// Number of threads that need to reach the barrier
    count: usize,
    /// Current number of threads that have reached the barrier
    arrived: AtomicUsize,
    /// Condition variable for blocking/waking threads
    condvar: Condvar,
    /// Mutex protecting broken state: None = not broken, Some(msg) = broken with error message
    state: Mutex<Option<String>>,
}

impl FailFastBarrier {
    /// Creates a new `FailFastBarrier` that will wait for `count` threads.
    ///
    /// # Arguments
    ///
    /// * `count` - The number of threads that must reach the barrier before any are released
    ///
    /// # Errors
    ///
    /// Returns an error if `count` is 0, as a zero-count barrier can never be satisfied.
    ///
    /// # Examples
    ///
    /// The `examples::new_example` test in this module runs this example.
    pub fn new(count: usize) -> Result<Self> {
        if count == 0 {
            return Err(Error::LockError(
                "FailFastBarrier count must be greater than 0".to_string(),
            ));
        }

        Ok(Self {
            count,
            arrived: AtomicUsize::new(0),
            condvar: Condvar::new(),
            state: Mutex::new(None),
        })
    }

    /// Wait for all threads to reach the barrier, or until the barrier is broken.
    ///
    /// This method blocks the calling thread until either:
    /// 1. All `count` threads have called `wait()` - returns `Ok(())`
    /// 2. Another thread calls `break_barrier()` - returns `Err(())`
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all threads reached the barrier successfully
    /// * `Err(Error)` if the barrier was broken due to failure in another thread, with details about the failure
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// The barrier ensures proper synchronization between all participating threads.
    ///
    /// # Examples
    ///
    /// The `examples::wait_example` test in this module runs this example.
    pub fn wait(&self) -> Result<()> {
        // Check if already broken
        {
            let guard = self
                .state
                .lock()
                .map_err(|e| Error::LockError(format!("barrier lock poisoned: {e}")))?;
            if let Some(msg) = guard.as_ref() {
                return Err(Error::LockError(format!("Barrier was broken: {msg}")));
            }
        }

        let arrived_count = self
            .arrived
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1);

        if arrived_count == self.count {
            // Last thread to arrive - wake everyone up
            let _guard = self
                .state
                .lock()
                .map_err(|e| Error::LockError(format!("barrier lock poisoned: {e}")))?;
            self.condvar.notify_all();
            Ok(())
        } else {
            // Wait for others or until broken
            let guard = self
                .state
                .lock()
                .map_err(|e| Error::LockError(format!("barrier lock poisoned: {e}")))?;
            let guard = self
                .condvar
                .wait_while(guard, |state| {
                    state.is_none() && self.arrived.load(Ordering::Acquire) < self.count
                })
                .map_err(|e| Error::LockError(format!("barrier condvar poisoned: {e}")))?;

            if let Some(msg) = guard.as_ref() {
                Err(Error::LockError(format!("Barrier was broken: {msg}")))
            } else {
                Ok(())
            }
        }
    }

    /// Break the barrier due to failure, immediately unblocking all waiting threads.
    ///
    /// This method should be called when a thread encounters an unrecoverable error
    /// and needs to signal all other threads to abort their waiting. Once called,
    /// all current and future calls to `wait()` will return `Err(Error)` with the provided message.
    ///
    /// # Arguments
    ///
    /// * `error_message` - A descriptive message about what caused the barrier to break
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    /// Multiple calls to `break_barrier()` are safe - the first error message will be preserved.
    ///
    /// # Examples
    ///
    /// The `examples::break_barrier_example` test in this module runs this example.
    pub fn break_barrier(&self, error_message: impl Into<String>) {
        if let Ok(mut guard) = self.state.lock() {
            // Only set message if not already broken (preserve first error)
            if guard.is_none() {
                *guard = Some(error_message.into());
            }
        }
        // Note: if mutex is poisoned, we can't set the error message,
        // but notify_all will still wake waiting threads (they'll see poisoned mutex)

        self.condvar.notify_all();
    }

    /// Check if the barrier has been broken without blocking.
    ///
    /// # Returns
    ///
    /// `true` if the barrier has been broken, `false` otherwise.
    ///
    /// # Examples
    ///
    /// The `examples::is_broken_example` test in this module runs this example.
    pub fn is_broken(&self) -> bool {
        self.state
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(true) // If poisoned, consider it broken
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;

    #[test]
    fn test_normal_barrier_operation() {
        let barrier = Arc::new(FailFastBarrier::new(3).unwrap());
        let mut handles = vec![];

        for _ in 0..3 {
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || barrier_clone.wait());
            handles.push(handle);
        }

        // All threads should succeed
        for handle in handles {
            assert!(handle.join().unwrap().is_ok());
        }
    }

    #[test]
    fn test_barrier_break() {
        let barrier = Arc::new(FailFastBarrier::new(3).unwrap());
        let mut handles = vec![];

        // Start 2 threads that will wait
        for _ in 0..2 {
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || barrier_clone.wait());
            handles.push(handle);
        }

        // Break the barrier: a thread already waiting is woken with the error, and one that
        // has not reached `wait` yet sees the barrier broken there, so the order does not matter
        barrier.break_barrier("Test failure");

        // All waiting threads should get Err with error message
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result.is_err());
            let error_msg = format!("{}", result.unwrap_err());
            assert!(error_msg.contains("Test failure"));
        }
    }

    #[test]
    fn test_is_broken() {
        let barrier = FailFastBarrier::new(2).unwrap();
        assert!(!barrier.is_broken());

        barrier.break_barrier("Test break");
        assert!(barrier.is_broken());
    }

    #[test]
    fn test_zero_count_returns_error() {
        let result = FailFastBarrier::new(0);
        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("count must be greater than 0"));
    }

    #[test]
    fn test_break_barrier_with_string() {
        // Test that break_barrier works with both &str and String
        let barrier = FailFastBarrier::new(2).unwrap();

        // Works with &str
        barrier.break_barrier("test error");
        assert!(barrier.is_broken());

        // Also works with String (no extra allocation needed)
        let barrier2 = FailFastBarrier::new(2).unwrap();
        barrier2.break_barrier(String::from("owned error"));
        assert!(barrier2.is_broken());
    }
}

#[cfg(test)]
mod examples {
    use std::{sync::Arc, thread};

    use super::*;
    use crate::Result;

    #[test]
    fn fail_fast_barrier_example() -> Result<()> {
        let barrier = Arc::new(FailFastBarrier::new(3)?);
        let mut handles = vec![];

        for i in 0..3 {
            let barrier_clone = Arc::clone(&barrier);
            let handle = thread::spawn(move || {
                // Simulate some work
                if i == 1 {
                    // Thread 1 fails and breaks the barrier
                    barrier_clone.break_barrier("Simulated failure");
                    return Err("Simulated failure");
                }

                // Try to wait for all threads
                match barrier_clone.wait() {
                    Ok(()) => Ok("Success"),
                    Err(_) => Err("Barrier was broken by another thread"),
                }
            });
            handles.push(handle);
        }

        // Thread 1 never arrives, so the others can only return through the break
        let mut results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        results.sort_unstable();
        assert_eq!(
            results,
            [
                Err("Barrier was broken by another thread"),
                Err("Barrier was broken by another thread"),
                Err("Simulated failure"),
            ]
        );
        Ok(())
    }

    #[test]
    fn new_example() -> Result<()> {
        let barrier = FailFastBarrier::new(4)?; // Wait for 4 threads
        assert!(!barrier.is_broken());

        // Zero count returns an error
        assert!(FailFastBarrier::new(0).is_err());
        Ok(())
    }

    #[test]
    fn wait_example() -> Result<()> {
        let barrier = Arc::new(FailFastBarrier::new(2)?);
        let barrier_clone = Arc::clone(&barrier);

        let handle = thread::spawn(move || barrier_clone.wait());

        // Main thread also waits; both pass once both have arrived
        barrier.wait()?;
        handle.join().unwrap()?;
        Ok(())
    }

    #[test]
    fn break_barrier_example() -> Result<()> {
        let barrier = Arc::new(FailFastBarrier::new(3)?);

        // Thread that will fail and break the barrier
        let barrier_clone = Arc::clone(&barrier);
        thread::spawn(move || {
            // Break the barrier on failure
            barrier_clone.break_barrier("Assembly failed to parse due to invalid metadata");
        });

        // Only two of the three parties ever arrive, so this returns through the break
        assert!(barrier.wait().is_err());
        Ok(())
    }

    #[test]
    fn is_broken_example() -> Result<()> {
        let barrier = FailFastBarrier::new(2)?;
        assert!(!barrier.is_broken());

        barrier.break_barrier("test");
        assert!(barrier.is_broken());
        Ok(())
    }
}
