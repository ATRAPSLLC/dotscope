//! Unified address space management for CIL emulation.
//!
//! This module provides the [`AddressSpace`] type, which offers a unified view of all memory
//! in an emulated .NET process. It combines multiple memory subsystems:
//!
//! - **Managed heap** ([`SharedHeap`]) - Objects, arrays, and strings allocated via `newobj`, `newarr`, etc.
//! - **Memory regions** ([`MemoryRegion`]) - PE images, mapped data, and unmanaged allocations
//! - **Static fields** ([`StaticFieldStorage`]) - Static field values shared across threads
//!
//! # Shared Heap Semantics
//!
//! The managed heap is wrapped in [`SharedHeap`], which uses `Arc<ManagedHeap>` internally.
//! This enables cheap cloning and sharing across threads while maintaining reference semantics
//! for heap objects.
//!
//! # Example
//!
//! ```rust
//! use dotscope::emulation::AddressSpace;
//!
//! // Create a new address space with default settings (64MB heap, 4GB address space)
//! let space = AddressSpace::new();
//!
//! // Allocate a string on the managed heap
//! let string_ref = space.alloc_string("Hello, World!").unwrap();
//!
//! // Map raw data at a specific address
//! space.map_data(0x1000, &[0xDE, 0xAD, 0xBE, 0xEF], "test_data").unwrap();
//!
//! // Read back the data
//! let data = space.read(0x1000, 4).unwrap();
//! assert_eq!(data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
//! ```

use std::{
    collections::BTreeMap,
    ops::Deref,
    result::Result as StdResult,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

use imbl::HashMap as ImHashMap;

use crate::{
    emulation::{
        memory::{
            region::{MemoryProtection, MemoryRegion, SectionInfo},
            statics::StaticFieldStorage,
        },
        EmValue, EmulationError, HeapRef, ManagedHeap,
    },
    metadata::token::Token,
    Error, Result,
};

/// Shared managed heap wrapper for thread-safe heap access.
///
/// `SharedHeap` wraps a [`ManagedHeap`] in an `Arc`, enabling cheap cloning and
/// sharing across threads and method calls. Multiple [`AddressSpace`] instances
/// can share the same heap, allowing objects allocated in one context to be
/// visible in another.
///
/// # Thread Safety
///
/// The underlying [`ManagedHeap`] uses interior mutability via `RwLock`, so
/// `SharedHeap` can be safely shared across threads with just `Clone`.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::SharedHeap;
///
/// let heap = SharedHeap::new(64 * 1024 * 1024); // 64MB
/// let heap2 = heap.clone(); // Cheap clone, shares same underlying heap
///
/// // Allocate in one clone
/// let str_ref = heap.alloc_string("shared").unwrap();
///
/// // Visible in the other
/// let s = heap2.get_string(str_ref).unwrap();
/// assert_eq!(&*s, "shared");
/// ```
#[derive(Clone, Debug)]
pub struct SharedHeap {
    inner: Arc<ManagedHeap>,
}

impl SharedHeap {
    /// Creates a new shared heap with the given size limit.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum heap size in bytes
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::SharedHeap;
    ///
    /// let heap = SharedHeap::new(1024 * 1024); // 1MB heap
    /// ```
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            inner: Arc::new(ManagedHeap::new(max_size)),
        }
    }

    /// Creates a shared heap from an existing [`ManagedHeap`].
    ///
    /// This wraps the given heap in an `Arc` for shared access.
    ///
    /// # Arguments
    ///
    /// * `heap` - The managed heap to wrap
    pub fn from_heap(heap: ManagedHeap) -> Self {
        Self {
            inner: Arc::new(heap),
        }
    }

    /// Returns a reference to the underlying [`ManagedHeap`].
    ///
    /// This provides direct access to the heap for operations not exposed
    /// through the `Deref` implementation.
    #[must_use]
    pub fn heap(&self) -> &ManagedHeap {
        &self.inner
    }

    /// Returns the number of strong references to this heap.
    ///
    /// Useful for debugging and understanding sharing patterns.
    #[must_use]
    pub fn ref_count(&self) -> usize {
        Arc::strong_count(&self.inner)
    }

    /// Returns `true` if this is the only reference to the heap.
    ///
    /// When unique, the heap can be safely modified without affecting
    /// other users.
    #[must_use]
    pub fn is_unique(&self) -> bool {
        Arc::strong_count(&self.inner) == 1
    }

    /// Forks this heap, creating an independent copy with CoW semantics.
    ///
    /// The forked heap shares its data structure with the original via
    /// structural sharing (using `imbl`). Both heaps can be modified
    /// independently - only the modified entries are copied.
    ///
    /// # Performance
    ///
    /// This is an O(1) operation due to `imbl`'s structural sharing.
    ///
    /// # Note
    ///
    /// Unlike `clone()` which shares the same heap via `Arc`, `fork()`
    /// creates a truly independent heap that starts with the same data
    /// but diverges on modification.
    pub fn fork(&self) -> Result<Self> {
        Ok(Self {
            inner: Arc::new(self.inner.fork()?),
        })
    }
}

impl Default for SharedHeap {
    fn default() -> Self {
        Self::new(64 * 1024 * 1024) // 64 MB default
    }
}

impl Deref for SharedHeap {
    type Target = ManagedHeap;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Default ceiling on unmanaged allocations for a newly created address space.
///
/// Matches the `max_unmanaged_bytes` default in
/// [`EmulationConfig`](crate::emulation::EmulationConfig) so that an address space built
/// directly and one built through the process builder behave the same.
pub const DEFAULT_MAX_UNMANAGED_BYTES: usize = 64 * 1024 * 1024;

/// Metadata for a pinned managed array whose native address aliases
/// the managed heap data. Reads and writes through the native address
/// are transparently delegated to the managed heap's `Vec<EmValue>`.
#[derive(Clone, Debug)]
struct PinnedArrayEntry {
    /// The managed array on the heap.
    array_ref: HeapRef,
    /// Base native address for the pinned region.
    base_addr: u64,
    /// Total byte length of the pinned region.
    byte_length: usize,
    /// Size of each element in bytes (1 for U1, 4 for I4, 8 for I8, etc.).
    element_size: usize,
}

/// Unified address space for an emulated .NET process.
///
/// `AddressSpace` provides a complete view of all memory accessible to an emulated
/// .NET process, integrating:
///
/// - **Managed heap** - Objects, arrays, and strings (via [`SharedHeap`])
/// - **Memory regions** - PE images, mapped data, and unmanaged allocations
/// - **Static fields** - Type-level static field storage
/// - **Pinned arrays** - Native pointer aliases for managed arrays
///
/// # Memory Layout
///
/// The address space has a configurable size (default 4GB). Automatic allocations
/// start at address `0x1000_0000` (256MB) and grow upward. PE images should be
/// mapped at their preferred base addresses using [`map_pe_image`](Self::map_pe_image).
///
/// # Pinned Arrays
///
/// When CIL code pins a managed array (via `ldelema` + `conv.u`), the resulting
/// native pointer is registered with the address space. Subsequent reads and writes
/// through native pointers (`ldind.*`/`stind.*`) that target the pinned address
/// range are transparently delegated to the managed heap, ensuring a single source
/// of truth with no synchronization overhead.
///
/// # Thread Safety
///
/// The address space uses interior mutability for thread-safe access:
/// - Heap operations use `RwLock` internally
/// - Region operations are protected by a `RwLock`
/// - Static fields use `RwLock` for concurrent access
///
/// # Cloning Semantics
///
/// When cloned, the heap is shared (via `Arc`), but regions are copied.
/// This means heap objects are visible across clones, but region mappings
/// are independent.
///
/// # Example
///
/// ```rust
/// use dotscope::emulation::{AddressSpace, EmValue};
/// use dotscope::metadata::token::Token;
///
/// let space = AddressSpace::new();
///
/// // Allocate managed objects
/// let str_ref = space.alloc_string("Hello").unwrap();
///
/// // Map raw memory
/// space.map_data(0x1000, &[1, 2, 3, 4], "data").unwrap();
///
/// // Access static fields
/// let field_token = Token::new(0x04000001);
/// space.set_static(field_token, EmValue::I32(42)).unwrap();
/// ```
#[derive(Debug)]
pub struct AddressSpace {
    /// Managed .NET heap (shared across threads).
    heap: SharedHeap,

    /// Memory regions (PE images, mapped data, etc.), keyed by base address.
    ///
    /// Ordered by base so a containing region is found with `range(..=address).next_back()`
    /// rather than a scan. Every access an emulated program makes to unmanaged memory goes
    /// through that lookup, and the region count is attacker-growable: `Marshal.WriteByte`
    /// to an unmapped address maps a fresh region, so a linear structure makes both the
    /// per-access lookup and the insert-time overlap check scale with how many regions the
    /// program has already created.
    regions: RwLock<BTreeMap<u64, MemoryRegion>>,

    /// Static field storage.
    statics: StaticFieldStorage,

    /// Next available address for automatic mapping.
    next_address: AtomicU64,

    /// Address space size limit.
    size: u64,

    /// Protection overrides for VirtualProtect emulation.
    ///
    /// Maps page-aligned addresses to their current protection flags.
    /// This allows VirtualProtect to change protection dynamically,
    /// overriding the default protection derived from PE sections.
    ///
    /// Uses `imbl::HashMap` for O(1) fork via structural sharing.
    protection_overrides: RwLock<ImHashMap<u64, MemoryProtection>>,

    /// Monitor lock state: maps heap object ID → re-entrant lock count.
    ///
    /// Tracks `System.Threading.Monitor.Enter`/`Exit` calls per object.
    /// In single-threaded emulation there is no contention, but we still
    /// track counts so that `Exit` can detect mismatched release attempts
    /// and `TryEnter` can verify the lock is actually held.
    ///
    /// Uses `imbl::HashMap` for O(1) fork via structural sharing.
    monitor_locks: RwLock<ImHashMap<u64, u32>>,

    /// Pinned array mappings: native base address → pinned array metadata.
    ///
    /// When a managed array is pinned (via `ldelema` + `conv.u`), its native
    /// address is registered here. Reads and writes through the native address
    /// are transparently delegated to the managed heap's `Vec<EmValue>`,
    /// ensuring a single source of truth with no data duplication.
    ///
    /// Uses `imbl::HashMap` for O(1) fork via structural sharing.
    pinned_arrays: RwLock<ImHashMap<u64, PinnedArrayEntry>>,

    /// Bytes currently committed to unmanaged allocations.
    ///
    /// Unmanaged allocations (`localloc`, `Marshal.AllocHGlobal`, `Marshal.AllocCoTaskMem`,
    /// `VirtualAlloc`) commit real host pages and are not charged against the managed heap
    /// budget, so they need their own accounting.
    unmanaged_bytes: AtomicUsize,

    /// Ceiling on [`unmanaged_bytes`](Self::unmanaged_bytes).
    ///
    /// Atomic so it can be adjusted after construction through
    /// [`set_max_unmanaged_bytes`](Self::set_max_unmanaged_bytes), which the process builder
    /// uses to apply the configured limit to an address space it does not own exclusively.
    max_unmanaged_bytes: AtomicUsize,
}

impl AddressSpace {
    /// Page size for protection tracking (4KB), derived from [`page::PAGE_SIZE`](crate::emulation::PAGE_SIZE).
    const PAGE_SIZE: u64 = super::page::PAGE_SIZE as u64;

    /// Creates a new address space with default settings.
    ///
    /// Default configuration:
    /// - 64 MB managed heap
    /// - 4 GB address space
    /// - Automatic allocations start at 256 MB
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(64 * 1024 * 1024, 0x1_0000_0000) // 64MB heap, 4GB address space
    }

    /// Creates a new address space with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `heap_size` - Maximum size of the managed heap in bytes
    /// * `address_space_size` - Total address space size in bytes
    #[must_use]
    pub fn with_config(heap_size: usize, address_space_size: u64) -> Self {
        Self {
            heap: SharedHeap::new(heap_size),
            regions: RwLock::new(BTreeMap::new()),
            statics: StaticFieldStorage::new(),
            next_address: AtomicU64::new(0x1000_0000), // Start at 256MB
            size: address_space_size,
            protection_overrides: RwLock::new(ImHashMap::new()),
            monitor_locks: RwLock::new(ImHashMap::new()),
            pinned_arrays: RwLock::new(ImHashMap::new()),
            unmanaged_bytes: AtomicUsize::new(0),
            max_unmanaged_bytes: AtomicUsize::new(DEFAULT_MAX_UNMANAGED_BYTES),
        }
    }

    /// Creates an address space with an existing shared heap.
    ///
    /// This allows multiple address spaces to share the same managed heap,
    /// useful for emulating multi-threaded scenarios where all threads
    /// share the same GC heap.
    ///
    /// # Arguments
    ///
    /// * `heap` - The shared heap to use
    #[must_use]
    pub fn with_heap(heap: SharedHeap) -> Self {
        Self {
            heap,
            regions: RwLock::new(BTreeMap::new()),
            statics: StaticFieldStorage::new(),
            next_address: AtomicU64::new(0x1000_0000),
            size: 0x1_0000_0000,
            protection_overrides: RwLock::new(ImHashMap::new()),
            monitor_locks: RwLock::new(ImHashMap::new()),
            pinned_arrays: RwLock::new(ImHashMap::new()),
            unmanaged_bytes: AtomicUsize::new(0),
            max_unmanaged_bytes: AtomicUsize::new(DEFAULT_MAX_UNMANAGED_BYTES),
        }
    }

    /// Returns a reference to the shared heap.
    #[must_use]
    pub fn heap(&self) -> &SharedHeap {
        &self.heap
    }

    /// Returns a reference to the underlying [`ManagedHeap`].
    #[must_use]
    pub fn managed_heap(&self) -> &ManagedHeap {
        self.heap.heap()
    }

    /// Returns a reference to the static field storage.
    #[must_use]
    pub fn statics(&self) -> &StaticFieldStorage {
        &self.statics
    }

    /// Acquires a monitor lock on the given heap object.
    ///
    /// Increments the re-entrant lock count for the object. In single-threaded
    /// emulation this always succeeds (no contention), but the count is tracked
    /// so that `monitor_exit` can detect mismatched releases.
    ///
    /// Returns the new lock count (1 for first acquisition).
    pub fn monitor_enter(&self, object_id: u64) -> u32 {
        let Ok(mut locks) = self.monitor_locks.write() else {
            return 0;
        };
        let count = locks
            .get(&object_id)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        *locks = locks.update(object_id, count);
        count
    }

    /// Releases a monitor lock on the given heap object.
    ///
    /// Decrements the re-entrant lock count. Returns `true` if the lock was
    /// held and successfully released, `false` if Exit was called without a
    /// matching Enter (would throw `SynchronizationLockException` in .NET).
    pub fn monitor_exit(&self, object_id: u64) -> bool {
        let Ok(mut locks) = self.monitor_locks.write() else {
            return false;
        };
        match locks.get(&object_id).copied() {
            Some(count) if count > 1 => {
                *locks = locks.update(object_id, count.saturating_sub(1));
                true
            }
            Some(1) => {
                *locks = locks.without(&object_id);
                true
            }
            _ => false, // Not locked — mismatched Exit
        }
    }

    /// Checks whether a monitor lock is currently held on the given heap object.
    #[must_use]
    pub fn monitor_is_locked(&self, object_id: u64) -> bool {
        self.monitor_locks
            .read()
            .map(|l| l.get(&object_id).copied().unwrap_or(0) > 0)
            .unwrap_or(false)
    }

    /// Maps a region into the address space at a specific address.
    ///
    /// # Arguments
    ///
    /// * `address` - The base address to map the region at
    /// * `region` - The memory region to map
    ///
    /// # Errors
    ///
    /// Returns an error if the region overlaps with an existing mapping or
    /// if the region lock is poisoned.
    pub fn map_at(&self, address: u64, region: MemoryRegion) -> Result<()> {
        let mut regions = self.regions.write().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        // Only two regions can overlap a new one in a base-ordered map: the last starting at
        // or before it, and the first starting after it. Everything else starts earlier and
        // ends before that predecessor does, or starts later than the successor.
        let base = region.base();
        let predecessor = regions.range(..=base).next_back().map(|(_, r)| r);
        let successor = regions
            .range(base.saturating_add(1)..)
            .next()
            .map(|(_, r)| r);

        for existing in [predecessor, successor].into_iter().flatten() {
            if Self::regions_overlap(existing, &region) {
                return Err(EmulationError::InvalidAddress {
                    address,
                    reason: "region overlaps with existing mapping".to_string(),
                }
                .into());
            }
        }

        regions.insert(base, region);
        Ok(())
    }

    /// Maps a region at an automatically chosen address.
    ///
    /// The address is selected from the available address space and aligned
    /// to a page boundary (4KB). The region's base address is updated to
    /// reflect the chosen location.
    ///
    /// # Arguments
    ///
    /// * `region` - The memory region to map (base address will be updated)
    ///
    /// # Returns
    ///
    /// The base address where the region was mapped.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map(&self, region: MemoryRegion) -> Result<u64> {
        let size = region.size();
        let aligned_size = size.saturating_add(0xFFF) & !0xFFF; // Page align

        // Find next available address
        let base = self
            .next_address
            .fetch_add(aligned_size as u64, Ordering::SeqCst);

        // PE images should use map_at with explicit base
        if region.is_pe_image() {
            return Err(EmulationError::InternalError {
                description: "PE images must use map_at with explicit base address".to_string(),
            }
            .into());
        }

        // Update region base
        let region = region.with_base(base);

        self.map_at(base, region)?;
        Ok(base)
    }

    /// Unmaps a region by its base address.
    ///
    /// # Arguments
    ///
    /// * `base` - The base address of the region to unmap
    ///
    /// # Errors
    ///
    /// Returns an error if no region exists at the given address.
    pub fn unmap(&self, base: u64) -> Result<()> {
        let mut regions = self.regions.write().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        if regions.remove(&base).is_some() {
            Ok(())
        } else {
            Err(EmulationError::InvalidAddress {
                address: base,
                reason: "no region at this address".to_string(),
            }
            .into())
        }
    }

    /// Reads bytes from any mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to read from
    /// * `len` - The number of bytes to read
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped or the read fails.
    pub fn read(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        // Check pinned arrays first (transparent shared backing)
        if let Some(result) = self.read_pinned(address, len) {
            return result;
        }

        // Validate before allocating. `read_mapped` below checks the range too, but only
        // after it has been handed a `len`-sized buffer — so an unmapped address with an
        // attacker-chosen length would commit that much host memory before being refused.
        // `cpblk` reaches here with a size straight off the evaluation stack, so "refused"
        // has to cost nothing. Same rule `init_block` follows: validate first, fill second.
        if !self.covers_range(address, len)? {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: format!("read of {len} bytes is not fully mapped"),
            }
            .into());
        }

        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        let mut buffer = vec![0u8; len];
        self.read_mapped(&regions, address, &mut buffer)?;
        Ok(buffer)
    }

    /// Reads into a caller-supplied buffer, allocating nothing.
    ///
    /// `read` hands back an owned `Vec`, which makes a 1-, 2-, 4- or 8-byte `ldind` — the
    /// interpreter's inner loop — pay a malloc and a free per load. The fixed-size accessors
    /// below fill a stack array through this instead.
    ///
    /// # Errors
    ///
    /// Returns an error if the range is unmapped, unreadable under its protection, or the
    /// region lock is poisoned.
    pub fn read_into(&self, address: u64, dest: &mut [u8]) -> Result<()> {
        if let Some(result) = self.read_pinned(address, dest.len()) {
            let bytes = result?;
            if bytes.len() != dest.len() {
                return Err(EmulationError::InvalidAddress {
                    address,
                    reason: "pinned read length mismatch".to_string(),
                }
                .into());
            }
            dest.copy_from_slice(&bytes);
            return Ok(());
        }

        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        self.read_mapped(&regions, address, dest)
    }

    /// Shared body of [`Self::read`] and [`Self::read_into`], with the regions lock held.
    fn read_mapped(
        &self,
        regions: &BTreeMap<u64, MemoryRegion>,
        address: u64,
        dest: &mut [u8],
    ) -> Result<()> {
        let Some(region) = Self::region_containing(regions, address) else {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: "address not mapped".to_string(),
            }
            .into());
        };

        if !region.contains_range(address, dest.len()) {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: "address not mapped".to_string(),
            }
            .into());
        }

        self.check_access(region, address, dest.len(), MemoryProtection::READ)?;

        if region.read_into(address, dest) {
            Ok(())
        } else {
            Err(EmulationError::InvalidAddress {
                address,
                reason: "read failed".to_string(),
            }
            .into())
        }
    }

    /// Writes bytes to any mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to write to
    /// * `data` - The bytes to write
    ///
    /// # Errors
    ///
    /// Returns an error if the address is not mapped, the region is read-only,
    /// or the write otherwise fails.
    pub fn write(&self, address: u64, data: &[u8]) -> Result<()> {
        // Check pinned arrays first (transparent shared backing)
        if let Some(result) = self.write_pinned(address, data) {
            return result;
        }

        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        let Some(region) = Self::region_containing(&regions, address) else {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: "address not mapped".to_string(),
            }
            .into());
        };

        if !region.contains_range(address, data.len()) {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: "address not mapped".to_string(),
            }
            .into());
        }

        self.check_access(region, address, data.len(), MemoryProtection::WRITE)?;

        if region.write(address, data) {
            Ok(())
        } else {
            // Protection is rejected above, so reaching here means the paged write itself
            // failed — a range or page-level fault, not a permission one.
            Err(EmulationError::InvalidAddress {
                address,
                reason: "write failed".to_string(),
            }
            .into())
        }
    }

    /// Rejects an access whose protection does not permit it.
    ///
    /// Protection is per page, so an access is checked at the first and last page it touches;
    /// a region's pages carry uniform protection unless `VirtualProtect` has overridden some
    /// of them, and an override is page-aligned, so those two are what can differ.
    ///
    /// `GUARD` faults on any access regardless of `required`, matching a Windows guard page.
    ///
    /// Takes the region rather than looking it up, because both callers already hold the
    /// regions read lock — re-acquiring it here would be a recursive read acquisition, which
    /// `std::sync::RwLock` may deadlock on when a writer is queued between the two.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::AccessViolation`] when the access is not permitted.
    fn check_access(
        &self,
        region: &MemoryRegion,
        address: u64,
        len: usize,
        required: MemoryProtection,
    ) -> Result<()> {
        if len == 0 {
            return Ok(());
        }

        let last = address.saturating_add(len.saturating_sub(1) as u64);
        for probe in [address, last] {
            let Some(protection) = self.protection_of(region, probe) else {
                continue;
            };

            if protection.contains(MemoryProtection::GUARD) {
                return Err(EmulationError::AccessViolation {
                    address: probe,
                    reason: "guard page".to_string(),
                }
                .into());
            }

            if !protection.contains(required) {
                return Err(EmulationError::AccessViolation {
                    address: probe,
                    reason: format!("protection {protection:?} does not permit {required:?}"),
                }
                .into());
            }
        }

        Ok(())
    }

    /// Resolves the protection of one address inside a region already in hand.
    ///
    /// Same resolution order as [`Self::get_protection`] — `VirtualProtect` override first,
    /// then the region's own (per-PE-section) protection — without the regions lookup.
    fn protection_of(&self, region: &MemoryRegion, address: u64) -> Option<MemoryProtection> {
        let page_addr = address & !(Self::PAGE_SIZE - 1);
        if let Ok(overrides) = self.protection_overrides.read() {
            if let Some(&protection) = overrides.get(&page_addr) {
                return Some(protection);
            }
        }

        region.protection_at(address).ok()
    }

    /// Reads a fixed-size little-endian value without allocating.
    ///
    /// # Errors
    ///
    /// Returns an error if the range is unmapped or unreadable under its protection.
    pub fn read_exact<const N: usize>(&self, address: u64) -> Result<[u8; N]> {
        let mut buffer = [0u8; N];
        self.read_into(address, &mut buffer)?;
        Ok(buffer)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// See [`Self::read_exact`].
    pub fn read_u8(&self, address: u64) -> Result<u8> {
        Ok(u8::from_le_bytes(self.read_exact::<1>(address)?))
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// See [`Self::read_exact`].
    pub fn read_u16(&self, address: u64) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_exact::<2>(address)?))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// See [`Self::read_exact`].
    pub fn read_u32(&self, address: u64) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_exact::<4>(address)?))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// See [`Self::read_exact`].
    pub fn read_u64(&self, address: u64) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_exact::<8>(address)?))
    }

    /// Returns `true` if the address is within a mapped region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    #[must_use]
    pub fn is_valid(&self, address: u64) -> bool {
        // Check pinned arrays first
        if let Ok(pins) = self.pinned_arrays.read() {
            for entry in pins.values() {
                let end = entry.base_addr.saturating_add(entry.byte_length as u64);
                if address >= entry.base_addr && address < end {
                    return true;
                }
            }
        }

        let Ok(regions) = self.regions.read() else {
            return false;
        };
        Self::region_containing(&regions, address).is_some()
    }

    /// Returns the region containing the given address, if any.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to look up
    #[must_use]
    pub fn get_region(&self, address: u64) -> Option<MemoryRegion> {
        let regions = self.regions.read().ok()?;
        Self::region_containing(&regions, address).cloned()
    }

    /// Returns the memory protection flags for an address.
    ///
    /// This method first checks for any runtime protection overrides (set by
    /// `VirtualProtect` emulation), then falls back to the region's default
    /// protection. For PE images, the default considers the section containing
    /// the address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    #[must_use]
    pub fn get_protection(&self, address: u64) -> Option<MemoryProtection> {
        // Check for override first (page-aligned)
        let page_addr = address & !(Self::PAGE_SIZE - 1);
        if let Ok(overrides) = self.protection_overrides.read() {
            if let Some(&prot) = overrides.get(&page_addr) {
                return Some(prot);
            }
        }

        // Fall back to region's inherent protection
        let regions = self.regions.read().ok()?;
        Self::region_containing(&regions, address).and_then(|r| r.protection_at(address).ok())
    }

    /// Sets the memory protection for a range of addresses.
    ///
    /// This emulates `VirtualProtect` by storing protection overrides at
    /// page granularity. The original protection for the first page is returned.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address (will be page-aligned)
    /// * `size` - The size of the region to protect
    /// * `new_protection` - The new protection flags
    ///
    /// # Returns
    ///
    /// The previous protection of the first affected page, or `None` if the
    /// address is not mapped.
    pub fn set_protection(
        &self,
        address: u64,
        size: usize,
        new_protection: MemoryProtection,
    ) -> Option<MemoryProtection> {
        // Calculate page-aligned range
        let start_page = address & !(Self::PAGE_SIZE - 1);

        // Anti-emulation countermeasure:
        //
        // Some obfuscators (notably ConfuserEx) mark their encrypted sections as RWX
        // in the PE headers, then check VirtualProtect's returned old protection:
        //
        //   uint w = 0x40;  // PAGE_EXECUTE_READWRITE
        //   VirtualProtect(addr, size, w, out w);
        //   if (w == 0x40) return;  // Skip decryption if already RWX
        //
        // A naive emulator that accurately maps PE section characteristics would
        // return 0x40, causing decryption to be skipped. Real Windows apparently
        // behaves differently (possibly due to copy-on-write, DEP, or CLR-specific
        // loading behavior), returning a different value on first access.
        //
        // We handle this by returning READ_EXECUTE (0x20) for the FIRST VirtualProtect
        // call on executable sections, regardless of PE characteristics. Subsequent
        // calls return the actual stored protection, preserving re-entry guards.
        let old_protection = if let Ok(overrides) = self.protection_overrides.read() {
            if overrides.contains_key(&start_page) {
                // Has override - use it
                drop(overrides);
                self.get_protection(address)?
            } else {
                // No override yet - this is the first call.
                // Return READ_EXECUTE for executable sections to simulate
                // fresh process state (before any VirtualProtect calls).
                drop(overrides);
                let region_prot = self.get_protection(address)?;
                if region_prot.contains(MemoryProtection::EXECUTE) {
                    MemoryProtection::READ_EXECUTE
                } else {
                    region_prot
                }
            }
        } else {
            self.get_protection(address)?
        };

        // Calculate end page
        let end_addr = address.saturating_add(size as u64);
        let end_page = end_addr.saturating_add(Self::PAGE_SIZE - 1) & !(Self::PAGE_SIZE - 1);

        // Update protection for all affected pages
        if let Ok(mut overrides) = self.protection_overrides.write() {
            let mut page = start_page;
            while page < end_page {
                overrides.insert(page, new_protection);
                page = page.saturating_add(Self::PAGE_SIZE);
            }
        }

        Some(old_protection)
    }

    /// Gets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the static field
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the static field storage lock is poisoned.
    pub fn get_static(&self, field_token: Token) -> Result<Option<EmValue>> {
        self.statics.get(field_token)
    }

    /// Sets a static field value.
    ///
    /// # Arguments
    ///
    /// * `field_token` - The metadata token of the static field
    /// * `value` - The value to store
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the static field storage lock is poisoned.
    pub fn set_static(&self, field_token: Token, value: EmValue) -> Result<()> {
        self.statics.set(field_token, value)
    }

    /// Allocates unmanaged memory (for `Marshal.AllocHGlobal`, etc.).
    ///
    /// The memory is zeroed and mapped at an automatically chosen address.
    ///
    /// # Arguments
    ///
    /// * `size` - The size of the allocation in bytes
    ///
    /// # Returns
    ///
    /// The base address of the allocated region.
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn alloc_unmanaged(&self, size: usize) -> Result<u64> {
        // Unmanaged allocations commit real host pages and are invisible to the managed heap
        // budget, so they are charged here — before the region is constructed, since
        // `MemoryRegion::unmanaged_alloc` allocates the backing store eagerly.
        let max = self.max_unmanaged_bytes.load(Ordering::Relaxed);
        let current = self.unmanaged_bytes.load(Ordering::Relaxed);
        if current.saturating_add(size) > max {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current,
                limit: max,
            }
            .into());
        }

        let region = MemoryRegion::unmanaged_alloc(0, size);
        let address = self.map(region)?;
        self.unmanaged_bytes.fetch_add(size, Ordering::Relaxed);
        Ok(address)
    }

    /// Maps a zero-filled region at a fixed address, charged against the unmanaged budget.
    ///
    /// This backs the `Marshal.Write*` auto-allocation path, where emulated code writes to an
    /// address that is not mapped and the emulator materialises memory there rather than
    /// aborting. The address is attacker-chosen and the loop is driven by ordinary CIL, so
    /// without a ceiling each unmapped page written to commits real host pages that are never
    /// reclaimed. Charging the same counter as [`Self::alloc_unmanaged`] also bounds the
    /// region *count*, since every auto-allocation is the same fixed size.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] once the unmanaged budget is
    /// exhausted, or an error if the range overlaps an existing mapping.
    pub fn alloc_unmanaged_at(&self, address: u64, size: usize, label: &str) -> Result<()> {
        let max = self.max_unmanaged_bytes.load(Ordering::Relaxed);
        let current = self.unmanaged_bytes.load(Ordering::Relaxed);
        if current.saturating_add(size) > max {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current,
                limit: max,
            }
            .into());
        }

        let region = MemoryRegion::mapped_data(
            address,
            &vec![0u8; size],
            label,
            MemoryProtection::READ_WRITE,
        );
        self.map_at(address, region)?;
        self.unmanaged_bytes.fetch_add(size, Ordering::Relaxed);
        Ok(())
    }

    /// Sets the ceiling on total unmanaged allocation, in bytes.
    ///
    /// Applied after construction because the process builder configures limits on an address
    /// space it shares rather than owns.
    pub fn set_max_unmanaged_bytes(&self, max: usize) {
        self.max_unmanaged_bytes.store(max, Ordering::Relaxed);
    }

    /// Returns the number of bytes currently committed to unmanaged allocations.
    #[must_use]
    pub fn unmanaged_bytes(&self) -> usize {
        self.unmanaged_bytes.load(Ordering::Relaxed)
    }

    /// Returns the ceiling on unmanaged allocation, in bytes.
    #[must_use]
    pub fn max_unmanaged_bytes(&self) -> usize {
        self.max_unmanaged_bytes.load(Ordering::Relaxed)
    }

    /// Frees unmanaged memory previously allocated with [`alloc_unmanaged`](Self::alloc_unmanaged).
    ///
    /// # Arguments
    ///
    /// * `address` - The base address of the allocation to free
    ///
    /// # Errors
    ///
    /// Returns an error if the address does not correspond to an unmanaged allocation.
    pub fn free_unmanaged(&self, address: u64) -> Result<()> {
        // Verify it's an unmanaged allocation
        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        let freed_size = regions
            .get(&address)
            .filter(|r| r.is_unmanaged_alloc())
            .map(MemoryRegion::size);

        drop(regions);

        if let Some(size) = freed_size {
            self.unmap(address)?;
            // Return the budget so an alloc/free cycle cannot ratchet the accounted total
            // upwards and starve later allocations.
            //
            // Saturating rather than a plain `fetch_sub`: a region can be flagged as an
            // unmanaged allocation without having been charged here (a forked address space
            // carries regions over, for instance), and a wrapping subtract would underflow the
            // counter to near `usize::MAX` and reject every later allocation.
            let _ =
                self.unmanaged_bytes
                    .try_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                        Some(current.saturating_sub(size))
                    });
            Ok(())
        } else {
            Err(EmulationError::InvalidAddress {
                address,
                reason: "not an unmanaged allocation".to_string(),
            }
            .into())
        }
    }

    /// Reserves an address range without creating a backing memory region.
    ///
    /// Used for pinned arrays where the backing store is the managed heap.
    ///
    /// The cursor starts at `0x1000_0000` — the default `ImageBase` the C# compiler emits —
    /// so it walks straight into a mapped PE image on any host that opted into
    /// `ProcessBuilder::map_pe_image`. Bumping it blindly there hands out a base that aliases
    /// the image: `read`/`write` consult pins before regions, so the pin would silently
    /// intercept accesses to the image and redirect them into a managed array. The same
    /// cursor also feeds `map`, so once it is inside an image every `alloc_unmanaged` fails
    /// on the overlap check. This therefore skips past any range that overlaps a mapping.
    ///
    /// # Returns
    ///
    /// The reserved base address, or `None` if no free range of this size remains below the
    /// address space limit.
    pub fn reserve_address_range(&self, size: usize) -> Option<u64> {
        let aligned_size = u64::try_from(size.saturating_add(0xFFF) & !0xFFF).ok()?;
        let regions = self.regions.read().ok()?;
        let region_end = |region: &MemoryRegion| {
            region
                .base()
                .saturating_add(u64::try_from(region.size()).unwrap_or(u64::MAX))
        };

        loop {
            let base = self.next_address.load(Ordering::SeqCst);
            let end = base.checked_add(aligned_size)?;
            if end > self.size {
                return None;
            }

            // Regions never overlap, so the only ones that can intersect [base, end) are the
            // last starting before it — if it reaches past base — and the first starting
            // inside it.
            let blocker = regions
                .range(..base)
                .next_back()
                .map(|(_, region)| region)
                .filter(|region| region_end(region) > base)
                .or_else(|| regions.range(base..end).next().map(|(_, region)| region));

            let next = match blocker {
                // Resume at the page after the blocking region and try again.
                Some(region) => (region_end(region).checked_add(0xFFF)?) & !0xFFF,
                None => {
                    if self
                        .next_address
                        .compare_exchange(base, end, Ordering::SeqCst, Ordering::SeqCst)
                        .is_ok()
                    {
                        return Some(base);
                    }
                    continue;
                }
            };

            // Another thread may have moved the cursor further along already; never rewind it.
            let _ = self
                .next_address
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                    if current >= next {
                        None
                    } else {
                        Some(next)
                    }
                });
        }
    }

    /// Registers a pinned managed array so that native pointer access
    /// transparently delegates to the managed heap.
    ///
    /// After registration, `read()` and `write()` calls targeting the
    /// pinned address range will be handled by reading from or writing
    /// to the managed array's elements rather than a separate memory region.
    ///
    /// # Arguments
    ///
    /// * `base_addr` - Native base address of the pinned region
    /// * `array_ref` - The managed array on the heap
    /// * `element_size` - Size of each element in bytes
    /// * `element_count` - Number of elements in the array
    pub fn register_pinned_array(
        &self,
        base_addr: u64,
        array_ref: HeapRef,
        element_size: usize,
        element_count: usize,
    ) -> Result<()> {
        let byte_length = element_size.checked_mul(element_count).ok_or_else(|| {
            EmulationError::InternalError {
                description: "pinned array byte length overflow".to_string(),
            }
        })?;

        // Pins are consulted before regions on every access, so one registered over a mapped
        // range would shadow it: reads and writes to the mapping would be answered from the
        // managed array instead. `reserve_address_range` picks bases that avoid this, but the
        // base is a parameter here, so the invariant is enforced rather than assumed.
        if byte_length > 0 && self.region_overlaps_range(base_addr, byte_length)? {
            return Err(EmulationError::InvalidAddress {
                address: base_addr,
                reason: "pinned array would shadow a mapped region".to_string(),
            }
            .into());
        }

        let entry = PinnedArrayEntry {
            array_ref,
            base_addr,
            byte_length,
            element_size,
        };
        let mut pins = self.pinned_arrays.write().map_err(|_| {
            Error::from(EmulationError::LockPoisoned {
                description: "pinned arrays",
            })
        })?;
        pins.insert(base_addr, entry);
        Ok(())
    }

    /// Returns the native base address an array is already pinned at, if any.
    ///
    /// Lets a re-pin reuse the existing reservation instead of adding another entry for the
    /// same array — the pin table is scanned on every unmanaged access, so duplicates cost
    /// every later access, not just the memory.
    #[must_use]
    pub fn pinned_base_of(&self, array_ref: HeapRef) -> Option<u64> {
        let pins = self.pinned_arrays.read().ok()?;
        let base = pins
            .values()
            .find(|entry| entry.array_ref == array_ref)
            .map(|entry| entry.base_addr);
        base
    }

    /// Attempts to read from a pinned array region.
    ///
    /// Returns `None` if the address is not within a pinned array range.
    /// Returns `Some(Ok(bytes))` if the read succeeded, `Some(Err(...))` on failure.
    fn read_pinned(&self, addr: u64, len: usize) -> Option<Result<Vec<u8>>> {
        if len == 0 {
            return None;
        }
        let pins = self.pinned_arrays.read().ok()?;
        if pins.is_empty() {
            return None;
        }

        for entry in pins.values() {
            let end = entry.base_addr.saturating_add(entry.byte_length as u64);
            let read_end = addr.saturating_add(len as u64);
            if addr >= entry.base_addr && read_end <= end {
                return Some(self.read_pinned_bytes(entry, addr, len));
            }
        }
        None
    }

    /// Reads bytes from a pinned array by delegating to the managed heap.
    fn read_pinned_bytes(
        &self,
        entry: &PinnedArrayEntry,
        addr: u64,
        len: usize,
    ) -> Result<Vec<u8>> {
        let byte_offset =
            addr.checked_sub(entry.base_addr)
                .ok_or_else(|| EmulationError::InvalidAddress {
                    address: addr,
                    reason: "pinned array address underflow".to_string(),
                })? as usize;
        let heap = self.managed_heap();
        let mut result = vec![0u8; len];

        if entry.element_size == 1 {
            // Byte array fast path: each element is one byte
            for (i, slot) in result.iter_mut().enumerate().take(len) {
                let elem_idx = byte_offset.saturating_add(i);
                match heap.get_array_element(entry.array_ref, elem_idx) {
                    Ok(EmValue::I32(v)) => {
                        #[allow(clippy::cast_sign_loss)]
                        {
                            *slot = (v & 0xFF) as u8;
                        }
                    }
                    Ok(_) | Err(_) => *slot = 0,
                }
            }
        } else {
            // Multi-byte element path: deserialize elements to bytes
            let start_elem = byte_offset.checked_div(entry.element_size).unwrap_or(0);
            let read_end_offset = byte_offset.saturating_add(len);
            let end_elem = read_end_offset.div_ceil(entry.element_size);
            let mut elem_buf = vec![0u8; entry.element_size];

            for elem_idx in start_elem..end_elem {
                Self::emvalue_to_bytes(
                    &heap
                        .get_array_element(entry.array_ref, elem_idx)
                        .unwrap_or(EmValue::I32(0)),
                    &mut elem_buf,
                );
                let elem_byte_start = elem_idx.saturating_mul(entry.element_size);
                for (j, &b) in elem_buf.iter().enumerate() {
                    let abs_byte = elem_byte_start.saturating_add(j);
                    if abs_byte >= byte_offset && abs_byte < read_end_offset {
                        if let Some(slot) = result.get_mut(abs_byte.saturating_sub(byte_offset)) {
                            *slot = b;
                        }
                    }
                }
            }
        }
        Ok(result)
    }

    /// Attempts to write to a pinned array region.
    ///
    /// Returns `None` if the address is not within a pinned array range.
    /// Returns `Some(Ok(()))` if the write succeeded, `Some(Err(...))` on failure.
    fn write_pinned(&self, addr: u64, data: &[u8]) -> Option<Result<()>> {
        if data.is_empty() {
            return None;
        }
        let pins = self.pinned_arrays.read().ok()?;
        if pins.is_empty() {
            return None;
        }

        for entry in pins.values() {
            let end = entry.base_addr.saturating_add(entry.byte_length as u64);
            let write_end = addr.saturating_add(data.len() as u64);
            if addr >= entry.base_addr && write_end <= end {
                return Some(self.write_pinned_bytes(entry, addr, data));
            }
        }
        None
    }

    /// Writes bytes to a pinned array by delegating to the managed heap.
    fn write_pinned_bytes(&self, entry: &PinnedArrayEntry, addr: u64, data: &[u8]) -> Result<()> {
        let byte_offset =
            addr.checked_sub(entry.base_addr)
                .ok_or_else(|| EmulationError::InvalidAddress {
                    address: addr,
                    reason: "pinned array address underflow".to_string(),
                })? as usize;
        let heap = self.managed_heap();

        if entry.element_size == 1 {
            // Byte array fast path: each byte is one element
            for (i, &byte) in data.iter().enumerate() {
                let elem_idx = byte_offset.saturating_add(i);
                heap.set_array_element(entry.array_ref, elem_idx, EmValue::I32(i32::from(byte)))?;
            }
        } else {
            // Multi-byte element path: read-modify-write for partial elements
            let start_elem = byte_offset.checked_div(entry.element_size).unwrap_or(0);
            let write_end_offset = byte_offset.saturating_add(data.len());
            let end_elem = write_end_offset.div_ceil(entry.element_size);

            for elem_idx in start_elem..end_elem {
                let elem_byte_start = elem_idx.saturating_mul(entry.element_size);
                let mut elem_buf = vec![0u8; entry.element_size];

                // Read existing element value
                Self::emvalue_to_bytes(
                    &heap
                        .get_array_element(entry.array_ref, elem_idx)
                        .unwrap_or(EmValue::I32(0)),
                    &mut elem_buf,
                );

                // Overwrite the affected bytes
                for (j, byte) in elem_buf.iter_mut().enumerate() {
                    let abs_byte = elem_byte_start.saturating_add(j);
                    if abs_byte >= byte_offset && abs_byte < write_end_offset {
                        if let Some(&src) = data.get(abs_byte.saturating_sub(byte_offset)) {
                            *byte = src;
                        }
                    }
                }

                // Write back
                let value = Self::bytes_to_emvalue(&elem_buf);
                heap.set_array_element(entry.array_ref, elem_idx, value)?;
            }
        }
        Ok(())
    }

    /// Serializes an `EmValue` to little-endian bytes.
    fn emvalue_to_bytes(value: &EmValue, buf: &mut [u8]) {
        fn copy_le(buf: &mut [u8], bytes: &[u8]) {
            let copy_len = buf.len().min(bytes.len());
            if let (Some(dst), Some(src)) = (buf.get_mut(..copy_len), bytes.get(..copy_len)) {
                dst.copy_from_slice(src);
            }
        }
        match value {
            EmValue::I32(v) => copy_le(buf, &v.to_le_bytes()),
            EmValue::I64(v) | EmValue::NativeInt(v) => copy_le(buf, &v.to_le_bytes()),
            EmValue::F32(v) => copy_le(buf, &v.to_le_bytes()),
            EmValue::F64(v) => copy_le(buf, &v.to_le_bytes()),
            _ => buf.fill(0),
        }
    }

    /// Deserializes little-endian bytes to an `EmValue`.
    fn bytes_to_emvalue(bytes: &[u8]) -> EmValue {
        match bytes.len() {
            1 => match bytes.first() {
                Some(&b) => EmValue::I32(i32::from(b)),
                None => EmValue::I32(0),
            },
            2 => match <[u8; 2]>::try_from(bytes) {
                Ok(arr) => EmValue::I32(i32::from(i16::from_le_bytes(arr))),
                Err(_) => EmValue::I32(0),
            },
            4 => match <[u8; 4]>::try_from(bytes) {
                Ok(arr) => EmValue::I32(i32::from_le_bytes(arr)),
                Err(_) => EmValue::I32(0),
            },
            8 => match <[u8; 8]>::try_from(bytes) {
                Ok(arr) => EmValue::I64(i64::from_le_bytes(arr)),
                Err(_) => EmValue::I32(0),
            },
            _ => EmValue::I32(0),
        }
    }

    /// Copies a block of memory from source to destination.
    ///
    /// Implements the CIL `cpblk` instruction semantics. Handles overlapping
    /// regions by reading the source data first.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination address
    /// * `src` - Source address
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    ///
    /// Returns an error if either address is unmapped or the copy fails.
    pub fn copy_block(&self, dest: u64, src: u64, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        // Read source data
        let src_data = self.read(src, size)?;

        // Write to destination
        self.write(dest, &src_data)
    }

    /// Initializes a block of memory with a byte value.
    ///
    /// Implements the CIL `initblk` instruction semantics.
    ///
    /// # Arguments
    ///
    /// * `address` - The starting address to initialize
    /// * `value` - The byte value to fill with
    /// * `size` - Number of bytes to initialize
    ///
    /// # Errors
    ///
    /// Returns an error if the address is unmapped.
    pub fn init_block(&self, address: u64, value: u8, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        // `size` comes from the emulated stack via `initblk`. Building the whole fill buffer
        // first would commit it to the host allocator before the destination is checked, so an
        // out-of-range address with a huge size costs the memory anyway and only then fails.
        // Validate first, fill second.
        if !self.covers_range(address, size)? {
            return Err(EmulationError::InvalidAddress {
                address,
                reason: format!("initblk destination range of {size} bytes is not mapped"),
            }
            .into());
        }

        // Fill through a fixed-size buffer so peak overhead is constant in `size`.
        const CHUNK: usize = 64 * 1024;
        let chunk_len = size.min(CHUNK);
        let chunk = vec![value; chunk_len];

        let mut written: usize = 0;
        while written < size {
            let remaining = size.saturating_sub(written);
            let n = remaining.min(chunk_len);
            let slice = chunk
                .get(..n)
                .ok_or_else(|| EmulationError::InternalError {
                    description: "initblk chunk slice out of range".to_string(),
                })?;
            let offset = u64::try_from(written).map_err(|_| EmulationError::InvalidAddress {
                address,
                reason: "initblk offset exceeds address width".to_string(),
            })?;
            let target =
                address
                    .checked_add(offset)
                    .ok_or_else(|| EmulationError::InvalidAddress {
                        address,
                        reason: "initblk range overflows the address space".to_string(),
                    })?;
            self.write(target, slice)?;
            written = written.saturating_add(n);
        }

        Ok(())
    }

    /// Reports whether any mapped region intersects `[address, address + size)`.
    ///
    /// Unlike [`Self::covers_range`] this asks about *intersection*, not containment, and
    /// ignores pins: it exists to keep a new pin from being laid over a mapping.
    fn region_overlaps_range(&self, address: u64, size: usize) -> Result<bool> {
        let len = u64::try_from(size).map_err(|_| EmulationError::InvalidAddress {
            address,
            reason: "range length exceeds the address width".to_string(),
        })?;
        let Some(end) = address.checked_add(len) else {
            return Ok(false);
        };

        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;

        let predecessor_overlaps =
            regions
                .range(..address)
                .next_back()
                .is_some_and(|(_, region)| {
                    region
                        .base()
                        .saturating_add(u64::try_from(region.size()).unwrap_or(u64::MAX))
                        > address
                });

        Ok(predecessor_overlaps || regions.range(address..end).next().is_some())
    }

    /// Reports whether a contiguous range is backed by a pinned array or a mapped region.
    ///
    /// Used to validate a destination before committing memory proportional to its size.
    fn covers_range(&self, address: u64, size: usize) -> Result<bool> {
        let len = u64::try_from(size).map_err(|_| EmulationError::InvalidAddress {
            address,
            reason: "range length exceeds the address width".to_string(),
        })?;
        let Some(end) = address.checked_add(len) else {
            return Ok(false);
        };

        if let Ok(pins) = self.pinned_arrays.read() {
            for entry in pins.values() {
                let pin_end = entry.base_addr.saturating_add(entry.byte_length as u64);
                if address >= entry.base_addr && end <= pin_end {
                    return Ok(true);
                }
            }
        }

        let regions = self.regions.read().map_err(|_| {
            Error::from(EmulationError::InternalError {
                description: "region lock poisoned".to_string(),
            })
        })?;
        Ok(Self::region_containing(&regions, address)
            .is_some_and(|r| r.contains_range(address, size)))
    }

    /// Maps a PE image at its preferred base address.
    ///
    /// # Arguments
    ///
    /// * `data` - The PE image bytes (should be mapped according to section alignment)
    /// * `preferred_base` - The preferred base address (usually from the PE header)
    /// * `sections` - Section information for protection lookup
    /// * `name` - A label for the image (for debugging)
    ///
    /// # Returns
    ///
    /// The base address where the image was mapped (same as `preferred_base`).
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map_pe_image(
        &self,
        data: &[u8],
        preferred_base: u64,
        sections: Vec<SectionInfo>,
        name: impl Into<String>,
    ) -> Result<u64> {
        let region = MemoryRegion::pe_image(preferred_base, data, sections, name);
        self.map_at(preferred_base, region)?;
        Ok(preferred_base)
    }

    /// Maps raw data at a specific address with read-write protection.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to map the data at
    /// * `data` - The data bytes
    /// * `label` - A label for the region (for debugging)
    ///
    /// # Errors
    ///
    /// Returns an error if the mapping fails.
    pub fn map_data(&self, address: u64, data: &[u8], label: impl Into<String>) -> Result<()> {
        let region = MemoryRegion::mapped_data(address, data, label, MemoryProtection::READ_WRITE);
        self.map_at(address, region)
    }

    /// Returns information about all mapped regions.
    ///
    /// Each tuple contains `(base_address, size, label)`.
    #[must_use]
    pub fn regions(&self) -> Vec<(u64, usize, String)> {
        match self.regions.read() {
            Ok(regions) => regions
                .values()
                .map(|r| (r.base(), r.size(), r.label().to_string()))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Returns the total size of all mapped regions in bytes.
    #[must_use]
    pub fn mapped_size(&self) -> usize {
        match self.regions.read() {
            Ok(regions) => regions.values().map(MemoryRegion::size).sum(),
            Err(_) => 0,
        }
    }

    /// Finds the region containing `address`, in `O(log regions)`.
    ///
    /// Regions never overlap — [`Self::map_at`] rejects a mapping that would create one — so
    /// the only candidate is the last region starting at or before the address.
    fn region_containing(
        regions: &BTreeMap<u64, MemoryRegion>,
        address: u64,
    ) -> Option<&MemoryRegion> {
        regions
            .range(..=address)
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| region.contains(address))
    }

    /// Checks if two regions overlap in the address space.
    ///
    /// Uses the standard interval overlap test: two intervals [a_start, a_end)
    /// and [b_start, b_end) overlap iff a_start < b_end && b_start < a_end.
    fn regions_overlap(a: &MemoryRegion, b: &MemoryRegion) -> bool {
        let a_start = a.base();
        let a_end = a.end();
        let b_start = b.base();
        let b_end = b.end();

        a_start < b_end && b_start < a_end
    }

    /// Allocates a string on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `value` - The string value to allocate
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_string(&self, value: &str) -> Result<HeapRef> {
        self.heap.alloc_string(value)
    }

    /// Gets a string from the managed heap.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the string object
    ///
    /// # Returns
    ///
    /// An `Arc<str>` for efficient, borrow-free access.
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or not a string.
    pub fn get_string(&self, heap_ref: HeapRef) -> Result<std::sync::Arc<str>> {
        self.heap.get_string(heap_ref)
    }

    /// Allocates an empty object on the managed heap.
    ///
    /// # Arguments
    ///
    /// * `type_token` - The type token for the object
    ///
    /// # Errors
    ///
    /// Returns an error if the heap is out of memory.
    pub fn alloc_object(&self, type_token: Token) -> Result<HeapRef> {
        self.heap.alloc_object(type_token)
    }

    /// Gets a field value from a heap object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object
    /// * `field_token` - Token of the field to read
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid, not an object,
    /// or the field does not exist.
    pub fn get_field(&self, heap_ref: HeapRef, field_token: Token) -> Result<EmValue> {
        self.heap.get_field(heap_ref, field_token)
    }

    /// Sets a field value on a heap object.
    ///
    /// # Arguments
    ///
    /// * `heap_ref` - Reference to the object
    /// * `field_token` - Token of the field to set
    /// * `value` - The value to store
    ///
    /// # Errors
    ///
    /// Returns an error if the reference is invalid or not an object.
    pub fn set_field(&self, heap_ref: HeapRef, field_token: Token, value: EmValue) -> Result<()> {
        self.heap.set_field(heap_ref, field_token, value)
    }
}

impl Default for AddressSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressSpace {
    /// Creates a fresh address space that shares memory regions but has independent mutable state.
    ///
    /// This is optimized for spawning lightweight emulation instances from a template:
    /// - **Shared (cheap)**: Memory regions (PE images, mapped data) - data uses `Arc` internally
    /// - **Fresh**: Heap, static fields, protection overrides, allocation pointer
    ///
    /// This pattern is ideal for deobfuscation where you need to run the same decryptor
    /// method many times with different arguments. The expensive PE loading and mapping
    /// is done once in the template, while each spawn gets fresh mutable state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::AddressSpace;
    ///
    /// // Create template with mapped data
    /// let template = AddressSpace::new();
    /// template.map_data(0x10000, &[1, 2, 3, 4], "data").unwrap();
    ///
    /// // Spawn a fresh instance - shares regions, fresh heap/statics
    /// let fresh = template.spawn_fresh();
    ///
    /// // Modifications to fresh don't affect template's heap/statics
    /// fresh.set_static(dotscope::metadata::token::Token::new(0x04000001),
    ///                  dotscope::emulation::EmValue::I32(42)).unwrap();
    /// assert!(template.get_static(dotscope::metadata::token::Token::new(0x04000001)).unwrap().is_none());
    /// ```
    #[must_use]
    pub fn spawn_fresh(&self) -> Self {
        // Clone regions - this is cheap because pages use CoW internally
        let regions = match self.regions.read() {
            Ok(r) => r.clone(),
            Err(_) => BTreeMap::new(),
        };

        Self {
            // Fresh heap - each spawn gets independent heap allocations
            heap: SharedHeap::default(),
            // Shared regions - cheap clone due to CoW pages
            regions: RwLock::new(regions),
            // Fresh statics - each spawn starts with empty static field storage
            statics: StaticFieldStorage::new(),
            // Fresh allocation pointer
            next_address: AtomicU64::new(self.next_address.load(Ordering::SeqCst)),
            // Same size limit
            size: self.size,
            // Fresh protection overrides (VirtualProtect state)
            protection_overrides: RwLock::new(ImHashMap::new()),
            // Fresh monitor locks
            monitor_locks: RwLock::new(ImHashMap::new()),
            // Fresh pinned array mappings
            pinned_arrays: RwLock::new(ImHashMap::new()),
            unmanaged_bytes: AtomicUsize::new(0),
            max_unmanaged_bytes: AtomicUsize::new(DEFAULT_MAX_UNMANAGED_BYTES),
        }
    }

    /// Forks this address space with full Copy-on-Write semantics.
    ///
    /// Creates an independent copy that shares data with the original via
    /// structural sharing. Both the original and fork can be modified independently -
    /// only the modified data is actually copied (true copy-on-write).
    ///
    /// # What Gets Forked
    ///
    /// - **Memory regions**: Forked with per-page CoW (4KB granularity)
    /// - **Managed heap**: Forked via `imbl` structural sharing (O(1))
    /// - **Static fields**: Forked via `imbl` structural sharing (O(1))
    /// - **Protection overrides**: Forked via `imbl` structural sharing (O(1))
    ///
    /// # Performance
    ///
    /// This is an O(1) operation for heap, statics, and protection overrides.
    /// Regions are O(n) where n is the number of regions (not pages), since
    /// each region's pages use CoW internally.
    ///
    /// # Use Case
    ///
    /// Ideal for running many parallel decryption operations from a single
    /// setup. The expensive emulator initialization (PE loading, type resolution,
    /// static initializers) happens once, then `fork()` creates lightweight
    /// copies for each decryptor call.
    ///
    /// # Example
    ///
    /// ```rust
    /// use dotscope::emulation::{AddressSpace, EmValue};
    /// use dotscope::metadata::token::Token;
    ///
    /// // Set up template with data
    /// let template = AddressSpace::new();
    /// template.map_data(0x1000, &[1, 2, 3, 4], "data").unwrap();
    /// template.set_static(Token::new(0x04000001), EmValue::I32(42)).unwrap();
    ///
    /// // Fork creates independent copy with shared backing
    /// let forked = template.fork().unwrap();
    ///
    /// // Modifications are independent
    /// forked.set_static(Token::new(0x04000001), EmValue::I32(100)).unwrap();
    /// forked.write(0x1000, &[0xFF]).unwrap();
    ///
    /// // Original unchanged
    /// assert_eq!(template.get_static(Token::new(0x04000001)).unwrap(), Some(EmValue::I32(42)));
    /// assert_eq!(template.read(0x1000, 1).unwrap(), vec![1]);
    /// ```
    pub fn fork(&self) -> Result<Self> {
        // Fork all regions (each region forks its pages)
        let regions = self
            .regions
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "address space regions",
            })?
            .iter()
            .map(|(&base, region)| region.fork().map(|forked| (base, forked)))
            .collect::<StdResult<BTreeMap<_, _>, _>>()?;

        // Fork protection overrides (O(1) due to imbl)
        let protection_overrides = self
            .protection_overrides
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "address space protection overrides",
            })?
            .clone();

        // Fork monitor locks (O(1) due to imbl)
        let monitor_locks = self
            .monitor_locks
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "address space monitor locks",
            })?
            .clone();

        // Fork pinned array mappings (O(1) due to imbl)
        let pinned_arrays = self
            .pinned_arrays
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "address space pinned arrays",
            })?
            .clone();

        Ok(Self {
            // Fork heap - O(1) due to imbl structural sharing
            heap: self.heap.fork()?,
            // Forked regions - each region's pages use CoW
            regions: RwLock::new(regions),
            // Fork statics - O(1) due to imbl structural sharing
            statics: self.statics.fork()?,
            // Copy allocation pointer
            next_address: AtomicU64::new(self.next_address.load(Ordering::SeqCst)),
            // Same size limit
            size: self.size,
            // Fork protection overrides - O(1) due to imbl
            protection_overrides: RwLock::new(protection_overrides),
            // Fork monitor locks - O(1) due to imbl
            monitor_locks: RwLock::new(monitor_locks),
            // Fork pinned array mappings - O(1) due to imbl
            pinned_arrays: RwLock::new(pinned_arrays),
            // The forked regions are carried over, so their bytes stay charged; the fork
            // inherits the parent's ceiling.
            unmanaged_bytes: AtomicUsize::new(self.unmanaged_bytes.load(Ordering::Relaxed)),
            max_unmanaged_bytes: AtomicUsize::new(self.max_unmanaged_bytes.load(Ordering::Relaxed)),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::{
            memory::{
                addressspace::{AddressSpace, SharedHeap},
                region::MemoryProtection,
            },
            EmValue,
        },
        metadata::{token::Token, typesystem::CilFlavor},
    };

    #[test]
    fn test_address_space_creation() {
        let space = AddressSpace::new();
        assert!(space.regions().is_empty());
    }

    #[test]
    fn test_map_and_read_data() {
        let space = AddressSpace::new();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        space.map_data(0x1000, &data, "test").unwrap();

        let read = space.read(0x1000, 4).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_write_data() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[0u8; 16], "test").unwrap();

        space.write(0x1000, &[0xCA, 0xFE]).unwrap();

        let read = space.read(0x1000, 2).unwrap();
        assert_eq!(read, vec![0xCA, 0xFE]);
    }

    /// Protection is tracked per page; an access that its page forbids must fault rather
    /// than succeed silently, or `VirtualProtect` emulation is pure bookkeeping and an
    /// obfuscator probing by writing where a real process faults detects the emulator.
    #[test]
    fn write_to_read_only_memory_faults() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[0u8; 16], "test").unwrap();
        space
            .set_protection(0x1000, 16, MemoryProtection::READ)
            .unwrap();

        assert!(space.read(0x1000, 4).is_ok(), "reads must still work");
        assert!(space.write(0x1000, &[0xFF]).is_err());
    }

    /// A guard page faults on *any* access, read included.
    #[test]
    fn guard_page_faults_on_read_and_write() {
        let space = AddressSpace::new();
        space.map_data(0x2000, &[0u8; 16], "test").unwrap();
        space
            .set_protection(
                0x2000,
                16,
                MemoryProtection::READ_WRITE | MemoryProtection::GUARD,
            )
            .unwrap();

        assert!(space.read(0x2000, 1).is_err());
        assert!(space.write(0x2000, &[0x01]).is_err());
    }

    /// Fixed-size reads must agree with the allocating path byte for byte.
    #[test]
    fn fixed_size_reads_match_the_allocating_read() {
        let space = AddressSpace::new();
        space
            .map_data(
                0x3000,
                &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
                "test",
            )
            .unwrap();

        assert_eq!(space.read_u8(0x3000).unwrap(), 0x11);
        assert_eq!(space.read_u16(0x3000).unwrap(), 0x2211);
        assert_eq!(space.read_u32(0x3000).unwrap(), 0x4433_2211);
        assert_eq!(space.read_u64(0x3000).unwrap(), 0x8877_6655_4433_2211);
        assert_eq!(
            space.read_exact::<4>(0x3000).unwrap().to_vec(),
            space.read(0x3000, 4).unwrap()
        );
        assert!(space.read_u32(0x9000).is_err(), "unmapped must still fault");
    }

    /// The reservation cursor starts at 0x1000_0000 — the default managed `ImageBase` — so
    /// it must step over a mapping rather than hand out a base that aliases it.
    #[test]
    fn reserved_ranges_skip_mapped_regions() {
        let space = AddressSpace::new();
        let cursor = space.reserve_address_range(0x1000).unwrap();

        // Map exactly where the next reservation would otherwise land.
        let blocked = cursor + 0x1000;
        space.map_data(blocked, &[0u8; 0x2000], "image").unwrap();

        let next = space.reserve_address_range(0x1000).unwrap();
        assert!(
            next >= blocked + 0x2000,
            "reservation {next:#x} overlaps the region at {blocked:#x}"
        );
    }

    /// Pins are consulted before regions on every access, so one laid over a mapping would
    /// shadow it.
    #[test]
    fn pinned_array_cannot_shadow_a_mapped_region() {
        let space = AddressSpace::new();
        space.map_data(0x4000, &[0u8; 0x1000], "image").unwrap();
        let array = space.managed_heap().alloc_array(CilFlavor::I4, 4).unwrap();

        assert!(space.register_pinned_array(0x4000, array, 4, 4).is_err());
    }

    #[test]
    fn test_static_fields() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);

        assert!(space.get_static(field).unwrap().is_none());

        space.set_static(field, EmValue::I32(42)).unwrap();
        assert_eq!(space.get_static(field).unwrap(), Some(EmValue::I32(42)));
    }

    #[test]
    fn test_shared_heap() {
        let space1 = AddressSpace::new();
        let str_ref = space1.alloc_string("Hello").unwrap();

        // Create a second address space sharing the same heap
        let space2 = AddressSpace::with_heap(space1.heap().clone());

        // Both can see the string
        let s1 = space1.get_string(str_ref).unwrap();
        let s2 = space2.get_string(str_ref).unwrap();
        assert_eq!(&*s1, "Hello");
        assert_eq!(&*s2, "Hello");

        // Allocating in one is visible in the other
        let str_ref2 = space2.alloc_string("World").unwrap();
        let s3 = space1.get_string(str_ref2).unwrap();
        assert_eq!(&*s3, "World");
    }

    #[test]
    fn test_unmanaged_alloc() {
        let space = AddressSpace::new();

        let addr = space.alloc_unmanaged(256).unwrap();
        assert!(space.is_valid(addr));

        // Write and read
        space.write(addr, &[1, 2, 3, 4]).unwrap();
        let data = space.read(addr, 4).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);

        // Free
        space.free_unmanaged(addr).unwrap();
        assert!(!space.is_valid(addr));
    }

    #[test]
    fn test_heap_delegation() {
        let space = AddressSpace::new();

        // Test string allocation through AddressSpace
        let str_ref = space.alloc_string("Test").unwrap();
        let s = space.get_string(str_ref).unwrap();
        assert_eq!(&*s, "Test");

        // Test object allocation through AddressSpace
        let type_token = Token::new(0x02000001);
        let field_token = Token::new(0x04000001);
        let obj_ref = space.alloc_object(type_token).unwrap();

        space
            .set_field(obj_ref, field_token, EmValue::I32(100))
            .unwrap();
        let value = space.get_field(obj_ref, field_token).unwrap();
        assert_eq!(value, EmValue::I32(100));
    }

    #[test]
    fn test_fork_memory_isolation() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[1, 2, 3, 4], "test").unwrap();

        // Fork
        let forked = space.fork().unwrap();

        // Both see the same initial data
        assert_eq!(space.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(forked.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);

        // Modify forked
        forked.write(0x1000, &[0xFF, 0xFE]).unwrap();

        // Original unchanged, fork modified
        assert_eq!(space.read(0x1000, 4).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(forked.read(0x1000, 4).unwrap(), vec![0xFF, 0xFE, 3, 4]);
    }

    #[test]
    fn test_fork_heap_isolation() {
        let space = AddressSpace::new();
        let str_ref = space.alloc_string("Original").unwrap();

        // Fork
        let forked = space.fork().unwrap();

        // Both see the same string
        assert_eq!(&*space.get_string(str_ref).unwrap(), "Original");
        assert_eq!(&*forked.get_string(str_ref).unwrap(), "Original");

        // Allocate new string in fork
        let new_ref = forked.alloc_string("Forked").unwrap();
        assert_eq!(&*forked.get_string(new_ref).unwrap(), "Forked");

        // Original doesn't see the new string
        assert!(space.get_string(new_ref).is_err());
    }

    #[test]
    fn test_fork_statics_isolation() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);
        space.set_static(field, EmValue::I32(42)).unwrap();

        // Fork
        let forked = space.fork().unwrap();

        // Both see the same static
        assert_eq!(space.get_static(field).unwrap(), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field).unwrap(), Some(EmValue::I32(42)));

        // Modify in fork
        forked.set_static(field, EmValue::I32(100)).unwrap();

        // Original unchanged
        assert_eq!(space.get_static(field).unwrap(), Some(EmValue::I32(42)));
        assert_eq!(forked.get_static(field).unwrap(), Some(EmValue::I32(100)));
    }

    #[test]
    fn test_fork_protection_isolation() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &vec![0u8; 0x2000], "test").unwrap();

        // Set protection
        space.set_protection(0x1000, 0x1000, MemoryProtection::READ_EXECUTE);

        // Fork
        let forked = space.fork().unwrap();

        // Both see the same protection
        assert_eq!(
            space.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );
        assert_eq!(
            forked.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );

        // Modify in fork
        forked.set_protection(0x1000, 0x1000, MemoryProtection::READ_WRITE);

        // Original unchanged
        assert_eq!(
            space.get_protection(0x1000),
            Some(MemoryProtection::READ_EXECUTE)
        );
        assert_eq!(
            forked.get_protection(0x1000),
            Some(MemoryProtection::READ_WRITE)
        );
    }

    #[test]
    fn test_multiple_forks_isolation() {
        let space = AddressSpace::new();
        let field = Token::new(0x04000001);
        space.set_static(field, EmValue::I32(1)).unwrap();

        // Create multiple forks
        let fork1 = space.fork().unwrap();
        let fork2 = space.fork().unwrap();

        // Modify each independently
        fork1.set_static(field, EmValue::I32(10)).unwrap();
        fork2.set_static(field, EmValue::I32(20)).unwrap();

        // Each has its own value
        assert_eq!(space.get_static(field).unwrap(), Some(EmValue::I32(1)));
        assert_eq!(fork1.get_static(field).unwrap(), Some(EmValue::I32(10)));
        assert_eq!(fork2.get_static(field).unwrap(), Some(EmValue::I32(20)));
    }

    #[test]
    fn test_shared_heap_fork() {
        let heap = SharedHeap::new(1024 * 1024);
        let str_ref = heap.alloc_string("Hello").unwrap();

        // Fork the heap
        let forked = heap.fork().unwrap();

        // Both see the string
        assert_eq!(&*heap.get_string(str_ref).unwrap(), "Hello");
        assert_eq!(&*forked.get_string(str_ref).unwrap(), "Hello");

        // Allocate in forked
        let new_ref = forked.alloc_string("World").unwrap();
        assert_eq!(&*forked.get_string(new_ref).unwrap(), "World");

        // Original doesn't see it
        assert!(heap.get_string(new_ref).is_err());
    }

    /// An unmapped read must be refused without first allocating a buffer for it.
    ///
    /// `read` built its destination `Vec` before `read_mapped` validated the range, so the
    /// length — which arrives from the emulated evaluation stack via `cpblk` — was committed
    /// to the host allocator on the reject path. At these sizes that is `handle_alloc_error`
    /// and an uncatchable abort of the analysis host, not an `Err`. The value below is far
    /// beyond any plausible mapping, so this test asserts the refusal is decided from the
    /// region index rather than by trying and failing to allocate.
    #[test]
    fn unmapped_read_is_refused_without_allocating() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[0u8; 16], "test").unwrap();

        // Wholly unmapped address.
        assert!(space.read(0xDEAD_0000, 1 << 40).is_err());
        // Mapped base, but the range runs off the end of the region.
        assert!(space.read(0x1000, 1 << 40).is_err());
        // The in-bounds case still works.
        assert_eq!(space.read(0x1000, 4).unwrap(), vec![0u8; 4]);
    }

    /// `cpblk` reaches `copy_block` with a size taken straight off the evaluation stack, so
    /// the same refusal has to hold there — this is the path that made the ordering bug
    /// reachable from three emulated instructions.
    #[test]
    fn copy_block_with_an_unmapped_source_is_refused_without_allocating() {
        let space = AddressSpace::new();
        space.map_data(0x1000, &[0u8; 16], "test").unwrap();

        assert!(space.copy_block(0x1000, 0xDEAD_0000, 1 << 40).is_err());
    }
}
