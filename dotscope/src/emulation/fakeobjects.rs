//! Pre-allocated fake BCL objects for consistent emulation behavior.
//!
//! This module provides [`FakeObjects`], a container for fake .NET runtime objects
//! that are pre-allocated at process initialization time. These objects ensure that
//! BCL hooks return consistent references, which is critical for anti-tamper checks.
//!
//! # Problem
//!
//! Obfuscators often include anti-tamper checks that compare object references:
//!
//! ```csharp
//! // This check must pass for constants decryption to work:
//! if (Assembly.GetExecutingAssembly().Equals(Assembly.GetCallingAssembly())) {
//!     // perform decryption
//! }
//! ```
//!
//! If `GetExecutingAssembly()` and `GetCallingAssembly()` return different heap objects
//! each time, the equality check fails and decryption is skipped.
//!
//! # Solution
//!
//! `FakeObjects` pre-allocates these objects once at process startup and stores their
//! heap references. BCL hooks then return these pre-allocated references, ensuring
//! that multiple calls to the same BCL method return the *same* object reference.
//!
//! # Architecture
//!
//! `FakeObjects` is owned by [`EmulationProcess`](crate::emulation::process::EmulationProcess)
//! and shared via `Arc` with all [`EmulationThread`](crate::emulation::thread::EmulationThread)
//! instances spawned from that process. This ensures that:
//!
//! 1. All threads in a process see the same fake objects
//! 2. Cross-thread comparisons work correctly (e.g., for multi-threaded obfuscators)
//! 3. Memory is efficiently shared without duplication

use std::sync::Arc;

use crate::emulation::{tokens, HeapRef, ManagedHeap};

/// Pre-allocated fake BCL objects for consistent emulation behavior.
///
/// This struct holds heap references to fake .NET runtime objects that BCL hooks
/// return when emulating methods like `Assembly.GetExecutingAssembly()`. By returning
/// the same pre-allocated reference every time, equality checks between these
/// objects pass correctly.
///
/// # Thread Safety
///
/// `FakeObjects` is designed to be wrapped in an `Arc` and shared across all threads
/// in an emulation process. The heap references it contains are immutable after
/// initialization.
///
/// # Example
///
/// ```
/// use dotscope::emulation::{EmValue, FakeObjects, ManagedHeap};
///
/// let heap = ManagedHeap::new(64 * 1024 * 1024);
/// let fake_objects = FakeObjects::initialize(&heap);
///
/// // BCL hooks can now use these references:
/// if let Some(asm_ref) = fake_objects.assembly() {
///     let value = EmValue::ObjectRef(asm_ref);
///     println!("Assembly object: {:?}", value);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct FakeObjects {
    /// Fake `System.Reflection.Assembly` object.
    ///
    /// Used by:
    /// - `Assembly.GetExecutingAssembly()`
    /// - `Assembly.GetCallingAssembly()`
    /// - `Assembly.GetEntryAssembly()`
    assembly: Option<HeapRef>,

    /// Fake `System.AppDomain` object.
    ///
    /// Used by:
    /// - `AppDomain.CurrentDomain`
    app_domain: Option<HeapRef>,
}

impl Default for FakeObjects {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeObjects {
    /// Creates a new empty `FakeObjects` instance.
    ///
    /// The returned instance has no objects allocated. Call [`initialize`](Self::initialize)
    /// with a heap to allocate the fake objects.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            assembly: None,
            app_domain: None,
        }
    }

    /// Initializes the fake objects by allocating them on the provided heap.
    ///
    /// This allocates:
    /// - A fake `Assembly` object (type token 0x7F00_00F0)
    /// - A fake `AppDomain` object (type token 0x7F00_00F1)
    ///
    /// These use synthetic tokens in the 0x7F table range (which doesn't exist in
    /// ECMA-335) to avoid collisions with real TypeRef RIDs in table 0x01.
    ///
    /// # Arguments
    ///
    /// * `heap` - The managed heap to allocate objects on
    ///
    /// # Returns
    ///
    /// A `FakeObjects` instance with all objects allocated.
    #[must_use]
    pub fn initialize(heap: &ManagedHeap) -> Self {
        // Use well-known synthetic tokens for fake type definitions
        // These don't need to resolve to real types - they're just for object identity
        let assembly = heap.alloc_object(tokens::singletons::ASSEMBLY).ok();
        let app_domain = heap.alloc_object(tokens::singletons::APP_DOMAIN).ok();

        Self {
            assembly,
            app_domain,
        }
    }

    /// Returns the fake assembly reference, if initialized.
    ///
    /// BCL hooks for `Assembly.GetExecutingAssembly()`, `GetCallingAssembly()`, and
    /// `GetEntryAssembly()` should return this reference to ensure equality checks pass.
    #[must_use]
    pub fn assembly(&self) -> Option<HeapRef> {
        self.assembly
    }

    /// Returns the fake app domain reference, if initialized.
    ///
    /// BCL hooks for `AppDomain.CurrentDomain` should return this reference.
    #[must_use]
    pub fn app_domain(&self) -> Option<HeapRef> {
        self.app_domain
    }
}

/// Shared fake objects wrapper for process-wide sharing.
///
/// `SharedFakeObjects` wraps `FakeObjects` in an `Arc` for efficient sharing
/// across all threads in an emulation process.
#[derive(Clone, Debug)]
pub struct SharedFakeObjects {
    inner: Arc<FakeObjects>,
}

impl SharedFakeObjects {
    /// Creates a new shared fake objects container by allocating objects on the heap.
    ///
    /// # Arguments
    ///
    /// * `heap` - The managed heap to allocate fake objects on
    #[must_use]
    pub fn new(heap: &ManagedHeap) -> Self {
        Self {
            inner: Arc::new(FakeObjects::initialize(heap)),
        }
    }

    /// Creates a shared wrapper from existing fake objects.
    #[must_use]
    pub fn from_fake_objects(fake_objects: FakeObjects) -> Self {
        Self {
            inner: Arc::new(fake_objects),
        }
    }

    /// Returns a reference to the underlying `FakeObjects`.
    #[must_use]
    pub fn get(&self) -> &FakeObjects {
        &self.inner
    }

    /// Returns the fake assembly reference, if initialized.
    #[must_use]
    pub fn assembly(&self) -> Option<HeapRef> {
        self.inner.assembly()
    }

    /// Returns the fake app domain reference, if initialized.
    #[must_use]
    pub fn app_domain(&self) -> Option<HeapRef> {
        self.inner.app_domain()
    }
}

impl Default for SharedFakeObjects {
    fn default() -> Self {
        Self {
            inner: Arc::new(FakeObjects::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::emulation::{FakeObjects, ManagedHeap, SharedFakeObjects};

    #[test]
    fn test_fake_objects_new_empty() {
        let fake = FakeObjects::new();
        assert!(fake.assembly().is_none());
        assert!(fake.app_domain().is_none());
    }

    #[test]
    fn test_fake_objects_initialize() {
        let heap = ManagedHeap::new(1024 * 1024);
        let fake = FakeObjects::initialize(&heap);

        // Objects should be allocated
        assert!(fake.assembly().is_some());
        assert!(fake.app_domain().is_some());

        // They should be different objects
        assert_ne!(fake.assembly(), fake.app_domain());
    }

    #[test]
    fn test_shared_fake_objects() {
        let heap = ManagedHeap::new(1024 * 1024);
        let shared = SharedFakeObjects::new(&heap);

        // Should have same values as underlying
        assert!(shared.assembly().is_some());
        assert!(shared.app_domain().is_some());

        // Clone should share the same references
        let cloned = shared.clone();
        assert_eq!(shared.assembly(), cloned.assembly());
        assert_eq!(shared.app_domain(), cloned.app_domain());
    }

    #[test]
    fn test_consistency_across_calls() {
        let heap = ManagedHeap::new(1024 * 1024);
        let fake = FakeObjects::initialize(&heap);

        // Multiple calls should return the same reference
        let asm1 = fake.assembly();
        let asm2 = fake.assembly();
        assert_eq!(asm1, asm2);

        let domain1 = fake.app_domain();
        let domain2 = fake.app_domain();
        assert_eq!(domain1, domain2);
    }
}
