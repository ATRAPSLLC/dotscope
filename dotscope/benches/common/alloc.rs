//! A counting global allocator: the bytes a piece of work holds at its peak, how many
//! allocations it makes, and what it leaves allocated.
//!
//! The library's trusted computing base is one `unsafe` block, so the allocator lives here,
//! with the benches and tests that install it, not in the crate. A binary installs it with
//!
//! ```ignore
//! #[global_allocator]
//! static ALLOCATOR: alloc::Counting = alloc::Counting;
//! ```
//!
//! and wraps the work in [`measure`]. The counts are process-wide, so work on other threads
//! (rayon's included) is counted, and two measurements must not run at once. The peak and
//! what is still held afterwards depend on how threads interleave (and the crate frees some
//! memory later, on other threads, through crossbeam-epoch); the allocation count and the
//! bytes allocated do not.

#![allow(unsafe_code, dead_code)]

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Mutex,
    },
};

/// The system allocator, counting what passes through it.
pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static ALLOCATED: AtomicU64 = AtomicU64::new(0);

fn grew(bytes: usize) {
    ALLOCATED.fetch_add(bytes as u64, Ordering::Relaxed);
    let live = LIVE.fetch_add(bytes, Ordering::Relaxed).wrapping_add(bytes);
    PEAK.fetch_max(live, Ordering::Relaxed);
}

fn shrank(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::Relaxed);
}

// SAFETY: every call is forwarded to `System` with the caller's arguments unchanged; the
// counters only observe the sizes.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System::alloc`'s.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            grew(layout.size());
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System::alloc_zeroed`'s.
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            grew(layout.size());
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is `System::dealloc`'s.
        unsafe { System.dealloc(pointer, layout) };
        shrank(layout.size());
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract is `System::realloc`'s.
        let moved = unsafe { System.realloc(pointer, layout, new_size) };
        if !moved.is_null() {
            shrank(layout.size());
            grew(new_size);
            ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        }
        moved
    }
}

/// What a piece of work allocated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocStats {
    /// The most bytes held at once above what was held when the work began.
    pub peak_bytes: usize,
    /// How many allocations (and reallocations) it made.
    pub allocations: u64,
    /// The bytes those allocations asked for, all told: what the work allocates whichever way
    /// its threads interleave, and so a bound on its peak that does not depend on scheduling.
    pub allocated_bytes: u64,
    /// The bytes still held when it returned, above what was held when it began (negative
    /// when it freed what was held before).
    pub retained_bytes: i64,
}

/// One measurement at a time: the counters are the process's.
static MEASURING: Mutex<()> = Mutex::new(());

/// Runs `work` and returns what it allocated, with its result.
///
/// # Panics
///
/// When [`Counting`] is not the binary's global allocator: the counts would all be zero.
pub fn measure<R>(work: impl FnOnce() -> R) -> (R, AllocStats) {
    let _one = MEASURING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = ALLOCATIONS.load(Ordering::Relaxed);
    drop(std::hint::black_box(Box::new(0u64)));
    assert!(
        ALLOCATIONS.load(Ordering::Relaxed) > before,
        "the counting allocator is not the global allocator"
    );
    let live = LIVE.load(Ordering::Relaxed);
    PEAK.store(live, Ordering::Relaxed);
    let allocations = ALLOCATIONS.load(Ordering::Relaxed);
    let allocated = ALLOCATED.load(Ordering::Relaxed);
    let result = work();
    let stats = AllocStats {
        peak_bytes: PEAK.load(Ordering::Relaxed).saturating_sub(live),
        allocations: ALLOCATIONS
            .load(Ordering::Relaxed)
            .saturating_sub(allocations),
        allocated_bytes: ALLOCATED.load(Ordering::Relaxed).saturating_sub(allocated),
        retained_bytes: i64::try_from(LIVE.load(Ordering::Relaxed))
            .unwrap_or(i64::MAX)
            .saturating_sub(i64::try_from(live).unwrap_or(i64::MAX)),
    };
    (result, stats)
}
