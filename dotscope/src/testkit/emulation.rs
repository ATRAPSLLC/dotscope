//! Test utilities for the emulation module.
//!
//! This module provides shared test helpers for creating test fixtures
//! needed by emulation-related tests. Every emulation a test runs is built here without a
//! wall-clock limit ([`emulation_config`], [`emulation_limits`], [`process_builder`]), so its
//! result never depends on how busy the machine is: the instruction, call-depth and memory
//! limits bound it deterministically.

use std::sync::{Arc, RwLock};

use crate::{
    emulation::{
        AddressSpace, CaptureContext, EmulationConfig, EmulationLimits, EmulationThread,
        ProcessBuilder, RuntimeState, SharedFakeObjects, ThreadContext, ThreadId, VirtualFs,
    },
    CilObject,
};

/// The default emulation configuration without its wall-clock limit.
#[must_use]
pub fn emulation_config() -> EmulationConfig {
    let mut config = EmulationConfig::default();
    config.limits.timeout_ms = 0;
    config
}

/// The default emulation limits without the wall-clock limit.
#[must_use]
pub fn emulation_limits() -> EmulationLimits {
    EmulationLimits::default().with_timeout_ms(0)
}

/// A process builder without the wall-clock limit.
#[must_use]
pub fn process_builder() -> ProcessBuilder {
    ProcessBuilder::new().with_timeout_ms(0)
}

/// Creates a minimal [`ThreadContext`] for testing.
///
/// This function provides a standard test context with:
/// - A fresh `AddressSpace` with default managed heap and memory regions
/// - An empty `CaptureContext` for tracking emulation artifacts
/// - Pre-allocated fake BCL objects for consistent hook behavior
/// - No parent assembly context
pub fn create_test_context() -> Arc<ThreadContext> {
    create_test_context_with(None)
}

/// Creates a minimal [`ThreadContext`] for testing, as [`create_test_context`] does, whose
/// thread runs in `assembly`: instructions that read metadata (a struct's field layout, a
/// method's signature) read it there.
pub fn create_test_context_with(assembly: Option<Arc<CilObject>>) -> Arc<ThreadContext> {
    let address_space = Arc::new(AddressSpace::new());
    let fake_objects = SharedFakeObjects::new(address_space.managed_heap());
    Arc::new(ThreadContext::new(
        address_space,
        Arc::new(RwLock::new(RuntimeState::new())),
        Arc::new(CaptureContext::new()),
        Arc::new(emulation_config()),
        assembly,
        fake_objects,
        Arc::new(VirtualFs::new()),
    ))
}

/// Creates a minimal `EmulationThread` for testing.
///
/// This function provides a standard test thread with:
/// - A fresh `AddressSpace` with default managed heap and memory regions
/// - An empty `CaptureContext` for tracking emulation artifacts
/// - Pre-allocated fake BCL objects for consistent hook behavior
/// - The main thread ID
/// - No parent assembly context
///
/// # Example
///
/// ```rust,no_run
/// use dotscope::testkit::emulation::create_test_thread;
///
/// let mut thread = create_test_thread();
/// let handle = thread.heap().alloc_string("test").unwrap();
/// ```
pub fn create_test_thread() -> EmulationThread {
    EmulationThread::new(ThreadId::MAIN, create_test_context())
}
