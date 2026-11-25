//! On-demand emulation process with double-checked locking.
//!
//! [`ProcessCell`] encapsulates the `AtomicBool` + `RwLock<Option<EmulationProcess>>`
//! double-checked locking pattern shared by multiple deobfuscation passes
//! ([`OpaqueFieldPredicatePass`], [`DelegateProxyResolutionPass`], [`StaticFieldResolutionPass`]).
//!
//! Each pass needs an emulation process that is lazily forked from the shared
//! [`EmulationTemplatePool`] on first use, with optional targeted `.cctor` warmup.
//! This helper eliminates the duplicated initialization logic while allowing
//! callers to customize what happens after the process is created (via a callback
//! passed to [`ensure_initialized`](ProcessCell::ensure_initialized)).
//!
//! [`OpaqueFieldPredicatePass`]: crate::deobfuscation::passes::OpaqueFieldPredicatePass
//! [`DelegateProxyResolutionPass`]: crate::deobfuscation::passes::DelegateProxyResolutionPass
//! [`StaticFieldResolutionPass`]: crate::deobfuscation::passes::StaticFieldResolutionPass
//! [`EmulationTemplatePool`]: crate::deobfuscation::EmulationTemplatePool

use std::sync::{
    atomic::{AtomicBool, Ordering},
    RwLock, RwLockReadGuard,
};

use crate::{emulation::EmulationProcess, Error, Result};

/// On-demand emulation process with thread-safe double-checked locking.
///
/// Wraps an `AtomicBool` flag and `RwLock<Option<EmulationProcess>>` to provide
/// one-shot lazy initialization. The first caller to [`ensure_initialized`](Self::ensure_initialized)
/// runs the provided initialization closure under a write lock; subsequent callers
/// return a read guard immediately.
///
/// # Thread Safety
///
/// The `initialized` flag uses `Acquire`/`Release` ordering to ensure that
/// readers see the fully-initialized process after the flag is set. The inner
/// `RwLock` provides the actual mutual exclusion for the double-check.
pub struct ProcessCell {
    /// Whether initialization has been attempted (success or failure).
    initialized: AtomicBool,
    /// The lazily-populated emulation process.
    process: RwLock<Option<EmulationProcess>>,
    /// Label for error messages (e.g., `"opaque field"`, `"delegate proxy"`).
    label: &'static str,
}

impl ProcessCell {
    /// Creates a new uninitialized process cell.
    ///
    /// # Arguments
    ///
    /// * `label` - Human-readable label for lock error messages.
    #[must_use]
    pub fn new(label: &'static str) -> Self {
        Self {
            initialized: AtomicBool::new(false),
            process: RwLock::new(None),
            label,
        }
    }

    /// Ensures the emulation process is initialized, returning a read guard.
    ///
    /// Uses double-checked locking: the first caller acquires a write lock and
    /// runs `init_fn` to produce the process. The optional `post_init` callback
    /// runs while the write lock is held, allowing callers to extract data from
    /// the freshly-created process before downgrading to a read lock.
    ///
    /// Subsequent callers skip the write lock entirely thanks to the `Acquire`
    /// load of the `initialized` flag.
    ///
    /// # Arguments
    ///
    /// * `init_fn` - Closure that creates the `EmulationProcess` (e.g., by forking
    ///   the template pool with targeted warmup). Returns `None` if creation fails.
    /// * `post_init` - Optional closure called with the newly-created process while
    ///   the write lock is still held. Used by passes that need to extract data
    ///   (e.g., delegate targets) before releasing exclusivity.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LockError`] if the internal `RwLock` is poisoned.
    pub fn ensure_initialized<F, P>(
        &self,
        init_fn: F,
        post_init: P,
    ) -> Result<RwLockReadGuard<'_, Option<EmulationProcess>>>
    where
        F: FnOnce() -> Option<EmulationProcess>,
        P: FnOnce(&EmulationProcess),
    {
        if !self.initialized.load(Ordering::Acquire) {
            let mut guard = self
                .process
                .write()
                .map_err(|e| Error::LockError(format!("{} process write lock: {e}", self.label)))?;
            if !self.initialized.load(Ordering::Relaxed) {
                let process = init_fn();
                if let Some(ref proc) = process {
                    post_init(proc);
                }
                *guard = process;
                self.initialized.store(true, Ordering::Release);
            }
        }
        self.process
            .read()
            .map_err(|e| Error::LockError(format!("{} process read lock: {e}", self.label)))
    }

    /// Returns whether initialization has been performed.
    ///
    /// This only checks the flag - it does not acquire any lock.
    #[must_use]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// Takes ownership of the stored emulation process, leaving `None` in its place.
    ///
    /// Used by pass `finalize()` methods to release the `Arc<CilObject>` reference
    /// held by the emulation process before code generation needs to unwrap the assembly.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LockError`] if the internal `RwLock` is poisoned.
    pub fn take(&self) -> Result<Option<EmulationProcess>> {
        let mut guard = self
            .process
            .write()
            .map_err(|e| Error::LockError(format!("{} process write lock: {e}", self.label)))?;
        Ok(guard.take())
    }

    /// Clears the stored emulation process, setting it to `None`.
    ///
    /// Equivalent to [`take()`](Self::take) but discards the value. Used by
    /// `finalize()` methods that only need to release the reference.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::LockError`] if the internal `RwLock` is poisoned.
    pub fn clear(&self) -> Result<()> {
        let mut guard = self
            .process
            .write()
            .map_err(|e| Error::LockError(format!("{} process write lock: {e}", self.label)))?;
        *guard = None;
        Ok(())
    }
}
