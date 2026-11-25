//! Unmanaged memory simulation for CIL emulation.
//!
//! This module provides [`UnmanagedMemory`] for tracking raw byte-level memory
//! allocations used by CIL instructions that operate on unmanaged memory:
//!
//! - `localloc` - Allocate stack-based unmanaged memory
//! - `cpblk` - Copy a block of bytes between memory locations
//! - `initblk` - Initialize a block of memory to a specific value
//!
//! # Address Space
//!
//! Each allocation gets a unique base address in a simulated address space
//! (starting at `0x7FFF_0000_0000`). These addresses don't correspond to real
//! process memory but provide consistent addressing for the emulated code.
//!
//! # Memory Limits
//!
//! The unmanaged memory has a configurable maximum size (default 16MB) to
//! prevent runaway allocations. Exceeding this limit returns
//! [`EmulationError::HeapMemoryLimitExceeded`].

use std::collections::HashMap;

use crate::{emulation::engine::EmulationError, Result};

/// A handle to an unmanaged memory region.
///
/// `UnmanagedRef` is an opaque reference to an allocated region of unmanaged
/// memory. It contains the base address of the allocation and can be used
/// with [`UnmanagedMemory`] methods to read, write, or free the region.
///
/// # Example
///
/// ```
/// use dotscope::emulation::UnmanagedMemory;
///
/// let mut mem = UnmanagedMemory::new(1024 * 1024);
/// let ptr = mem.alloc(256)?;
/// mem.write(ptr.address(), &[1, 2, 3, 4])?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnmanagedRef(u64);

impl UnmanagedRef {
    /// Creates a new unmanaged reference from a raw address.
    ///
    /// # Arguments
    ///
    /// * `address` - The base address of the allocation
    #[must_use]
    pub fn new(address: u64) -> Self {
        UnmanagedRef(address)
    }

    /// Returns the raw address of this reference.
    #[must_use]
    #[allow(clippy::trivially_copy_pass_by_ref)] // Consistent API style
    pub fn address(&self) -> u64 {
        self.0
    }
}

/// An allocated region of unmanaged memory (internal).
///
/// This structure tracks a single allocation in the simulated unmanaged
/// address space. Each region has contiguous storage and a validity flag
/// that is cleared when the region is freed.
///
/// # Validity
///
/// The `valid` flag enables tracking of freed regions without immediately
/// removing them from the hash map. This allows detection of use-after-free
/// errors in emulated code.
#[derive(Clone, Debug)]
struct InternalRegion {
    /// The raw bytes in this region.
    data: Vec<u8>,

    /// Whether this region is valid (not freed).
    ///
    /// Set to `false` when [`UnmanagedMemory::free`] is called. Operations
    /// on invalid regions will fail with appropriate errors.
    valid: bool,
}

impl InternalRegion {
    /// Creates a new zeroed region of the given size.
    ///
    /// The region is initialized with all zeros and marked as valid.
    fn new(size: usize) -> Self {
        InternalRegion {
            data: vec![0; size],
            valid: true,
        }
    }

    /// Returns the size of this region in bytes.
    #[inline]
    fn size(&self) -> usize {
        self.data.len()
    }
}

/// Simulated unmanaged memory for tracking raw byte allocations.
///
/// This tracks memory regions allocated by `localloc` and supports the
/// byte-level operations needed for `cpblk` and `initblk`.
///
/// # Address Space
///
/// Each allocation gets a unique base address. The address space is simulated
/// and doesn't correspond to real process memory. Allocations are aligned to
/// 16-byte boundaries.
///
/// # Example
///
/// ```no_run
/// use dotscope::emulation::UnmanagedMemory;
///
/// let mut mem = UnmanagedMemory::new(1024 * 1024);
///
/// // Allocate a region
/// let ptr = mem.alloc(256)?;
///
/// // Initialize the region with 0xFF
/// mem.memset(ptr.address(), 0xFF, 256)?;
///
/// // Copy between regions
/// let dest = mem.alloc(128)?;
/// mem.memcpy(dest.address(), ptr.address(), 128)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct UnmanagedMemory {
    /// Memory regions indexed by their base address.
    regions: HashMap<u64, InternalRegion>,
    /// Next address to allocate.
    next_address: u64,
    /// Total bytes currently allocated.
    current_size: usize,
    /// Maximum allowed allocation.
    max_size: usize,
}

impl UnmanagedMemory {
    /// Creates a new unmanaged memory with the specified size limit.
    ///
    /// # Arguments
    ///
    /// * `max_size` - Maximum total allocation size in bytes
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        UnmanagedMemory {
            regions: HashMap::new(),
            // Start at a high address to distinguish from managed pointers
            next_address: 0x7FFF_0000_0000,
            current_size: 0,
            max_size,
        }
    }

    /// Allocates a new zeroed memory region.
    ///
    /// The region is initialized with zeros and aligned to 16 bytes.
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the allocation in bytes
    ///
    /// # Returns
    ///
    /// A reference to the allocated region.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if allocation would
    /// exceed the memory limit.
    pub fn alloc(&mut self, size: usize) -> Result<UnmanagedRef> {
        if self.current_size.saturating_add(size) > self.max_size {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size,
                limit: self.max_size,
            }
            .into());
        }

        let address = self.next_address;
        let next = self.next_address.saturating_add(size as u64);
        // Align next allocation to 16 bytes
        self.next_address = next.saturating_add(15) & !15;

        self.regions.insert(address, InternalRegion::new(size));
        self.current_size = self.current_size.saturating_add(size);

        Ok(UnmanagedRef::new(address))
    }

    /// Frees a previously allocated memory region.
    ///
    /// After freeing, the region becomes invalid and any access to it will fail.
    ///
    /// # Arguments
    ///
    /// * `ptr` - Reference to the region to free
    ///
    /// # Errors
    ///
    /// Returns an error if the address doesn't correspond to a valid allocation
    /// or if the region was already freed.
    pub fn free(&mut self, ptr: UnmanagedRef) -> Result<()> {
        if let Some(region) = self.regions.get_mut(&ptr.address()) {
            if region.valid {
                region.valid = false;
                self.current_size = self.current_size.saturating_sub(region.size());
                return Ok(());
            }
        }
        Err(EmulationError::InvalidPointer {
            address: ptr.address(),
            reason: "not a valid allocation or already freed",
        }
        .into())
    }

    /// Finds the region containing an address and returns the region and offset.
    ///
    /// Searches for a valid region that contains the given address, supporting
    /// both exact base address lookups (O(1)) and interior address lookups (O(n)).
    ///
    /// Returns `None` if the address is not within any valid region.
    fn find_region(&self, address: u64) -> Option<(&InternalRegion, usize)> {
        // Check if this is an exact base address (fast path)
        if let Some(region) = self.regions.get(&address) {
            if region.valid {
                return Some((region, 0));
            }
        }

        // Search for a region that contains this address (slow path)
        for (&base, region) in &self.regions {
            let region_end = base.saturating_add(region.size() as u64);
            if region.valid && address >= base && address < region_end {
                #[allow(clippy::cast_possible_truncation)] // Offset bounded by region size
                let offset = address.saturating_sub(base) as usize;
                return Some((region, offset));
            }
        }

        None
    }

    /// Finds the region containing an address (mutable) and returns the region and offset.
    ///
    /// Mutable version of [`find_region`](Self::find_region) for write operations.
    /// Uses a two-pass approach due to borrow checker constraints.
    fn find_region_mut(&mut self, address: u64) -> Option<(&mut InternalRegion, usize)> {
        // First find the base address
        let mut found_base = None;

        // Check exact base first
        if let Some(region) = self.regions.get(&address) {
            if region.valid {
                found_base = Some(address);
            }
        }

        // Search for containing region
        if found_base.is_none() {
            for (&base, region) in &self.regions {
                let region_end = base.saturating_add(region.size() as u64);
                if region.valid && address >= base && address < region_end {
                    found_base = Some(base);
                    break;
                }
            }
        }

        if let Some(base) = found_base {
            if let Some(region) = self.regions.get_mut(&base) {
                #[allow(clippy::cast_possible_truncation)] // Offset bounded by region size
                let offset = address.saturating_sub(base) as usize;
                return Some((region, offset));
            }
        }

        None
    }

    /// Reads bytes from unmanaged memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to read from (can be within an allocation)
    /// * `size` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// A vector containing the read bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid or the read would exceed
    /// the region bounds.
    pub fn read(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        let (region, offset) = self
            .find_region(address)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "address not in any allocated region",
            })?;

        let end = offset
            .checked_add(size)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "read length overflows",
            })?;
        let slice = region
            .data
            .get(offset..end)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "read would exceed region bounds",
            })?;

        Ok(slice.to_vec())
    }

    /// Writes bytes to unmanaged memory.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to write to (can be within an allocation)
    /// * `data` - The bytes to write
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid or the write would exceed
    /// the region bounds.
    pub fn write(&mut self, address: u64, data: &[u8]) -> Result<()> {
        let (region, offset) =
            self.find_region_mut(address)
                .ok_or(EmulationError::InvalidPointer {
                    address,
                    reason: "address not in any allocated region",
                })?;

        let end = offset
            .checked_add(data.len())
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "write length overflows",
            })?;
        let dest = region
            .data
            .get_mut(offset..end)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "write would exceed region bounds",
            })?;

        dest.copy_from_slice(data);
        Ok(())
    }

    /// Copies memory from one location to another (memcpy/cpblk).
    ///
    /// Implements the `cpblk` instruction semantics. Handles overlapping regions
    /// correctly by reading the source data first into a temporary buffer.
    ///
    /// # Arguments
    ///
    /// * `dest` - Destination address
    /// * `src` - Source address
    /// * `size` - Number of bytes to copy
    ///
    /// # Errors
    ///
    /// Returns an error if either address is invalid or the operation would
    /// exceed region bounds.
    pub fn memcpy(&mut self, dest: u64, src: u64, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        // Read source data first (handles overlapping regions)
        let data = self.read(src, size)?;

        // Write to destination
        self.write(dest, &data)
    }

    /// Initializes a memory region to a specific byte value (memset/initblk).
    ///
    /// Implements the `initblk` instruction semantics.
    ///
    /// # Arguments
    ///
    /// * `address` - Starting address to initialize
    /// * `value` - The byte value to fill with
    /// * `size` - Number of bytes to initialize
    ///
    /// # Errors
    ///
    /// Returns an error if the address is invalid or the operation would
    /// exceed region bounds.
    pub fn memset(&mut self, address: u64, value: u8, size: usize) -> Result<()> {
        if size == 0 {
            return Ok(());
        }

        let (region, offset) =
            self.find_region_mut(address)
                .ok_or(EmulationError::InvalidPointer {
                    address,
                    reason: "address not in any allocated region",
                })?;

        let end = offset
            .checked_add(size)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "memset length overflows",
            })?;
        let dest = region
            .data
            .get_mut(offset..end)
            .ok_or(EmulationError::InvalidPointer {
                address,
                reason: "memset would exceed region bounds",
            })?;

        dest.fill(value);
        Ok(())
    }

    /// Returns `true` if the address is within an allocated, valid region.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to check
    #[must_use]
    pub fn is_valid(&self, address: u64) -> bool {
        self.find_region(address).is_some()
    }

    /// Returns the current total allocation size in bytes.
    #[must_use]
    pub fn current_size(&self) -> usize {
        self.current_size
    }

    /// Returns the maximum allowed allocation size in bytes.
    #[must_use]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Allocates a memory region and initializes it with the given data.
    ///
    /// This is a convenience method that combines [`alloc`](Self::alloc) and
    /// [`write`](Self::write). Useful for loading binary data (like PE files)
    /// into emulator memory.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to store in the new region
    ///
    /// # Returns
    ///
    /// A reference to the allocated region.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::HeapMemoryLimitExceeded`] if allocation would
    /// exceed the memory limit.
    pub fn alloc_with_data(&mut self, data: &[u8]) -> Result<UnmanagedRef> {
        let ptr = self.alloc(data.len())?;
        self.write(ptr.address(), data)?;
        Ok(ptr)
    }

    /// Allocates a memory region at a specific address with the given data.
    ///
    /// This is useful for loading PE files at their expected base address for
    /// anti-tamper emulation where code references absolute addresses.
    ///
    /// # Arguments
    ///
    /// * `address` - The specific address to allocate at
    /// * `data` - The data to store in the region
    ///
    /// # Returns
    ///
    /// A reference to the allocated region.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address is already allocated
    /// - Allocation would exceed the memory limit
    pub fn alloc_at(&mut self, address: u64, data: &[u8]) -> Result<UnmanagedRef> {
        // Check if address is already used
        if self.regions.contains_key(&address) {
            return Err(EmulationError::InvalidPointer {
                address,
                reason: "address already allocated",
            }
            .into());
        }

        let size = data.len();
        if self.current_size.saturating_add(size) > self.max_size {
            return Err(EmulationError::HeapMemoryLimitExceeded {
                current: self.current_size,
                limit: self.max_size,
            }
            .into());
        }

        let mut region = InternalRegion::new(size);
        region.data.copy_from_slice(data);
        self.regions.insert(address, region);
        self.current_size = self.current_size.saturating_add(size);

        // Update next_address if this allocation would conflict
        let end_address = address.saturating_add(size as u64);
        if end_address > self.next_address {
            self.next_address = end_address.saturating_add(15) & !15;
        }

        Ok(UnmanagedRef::new(address))
    }

    /// Returns an iterator over all valid regions.
    ///
    /// Each item is a tuple of `(base_address, data_slice)`.
    pub fn regions(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.regions
            .iter()
            .filter(|(_, r)| r.valid)
            .map(|(&addr, r)| (addr, r.data.as_slice()))
    }

    /// Returns the data for a specific region by its base address.
    ///
    /// # Arguments
    ///
    /// * `base_address` - The base address of the region
    ///
    /// # Returns
    ///
    /// The region's data, or `None` if no valid region exists at that address.
    #[must_use]
    pub fn get_region_data(&self, base_address: u64) -> Option<&[u8]> {
        self.regions
            .get(&base_address)
            .filter(|r| r.valid)
            .map(|r| r.data.as_slice())
    }
}

impl Default for UnmanagedMemory {
    fn default() -> Self {
        // Default to 16MB limit for unmanaged memory
        Self::new(16 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alloc_and_free() {
        let mut mem = UnmanagedMemory::new(1024);

        let ptr = mem.alloc(100).unwrap();
        assert!(mem.is_valid(ptr.address()));

        mem.free(ptr).unwrap();
        assert!(!mem.is_valid(ptr.address()));
    }

    #[test]
    fn test_read_write() {
        let mut mem = UnmanagedMemory::new(1024);

        let ptr = mem.alloc(16).unwrap();
        let data = [1, 2, 3, 4, 5, 6, 7, 8];

        mem.write(ptr.address(), &data).unwrap();
        let read = mem.read(ptr.address(), 8).unwrap();

        assert_eq!(read, data);
    }

    #[test]
    fn test_memset() {
        let mut mem = UnmanagedMemory::new(1024);

        let ptr = mem.alloc(16).unwrap();
        mem.memset(ptr.address(), 0xFF, 16).unwrap();

        let read = mem.read(ptr.address(), 16).unwrap();
        assert!(read.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_memcpy() {
        let mut mem = UnmanagedMemory::new(1024);

        let src = mem.alloc(16).unwrap();
        let dest = mem.alloc(16).unwrap();

        mem.write(src.address(), &[1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        mem.memcpy(dest.address(), src.address(), 8).unwrap();

        let read = mem.read(dest.address(), 8).unwrap();
        assert_eq!(read, [1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[test]
    fn test_offset_access() {
        let mut mem = UnmanagedMemory::new(1024);

        let ptr = mem.alloc(32).unwrap();
        let offset_addr = ptr.address() + 8;

        mem.write(offset_addr, &[0xAB, 0xCD]).unwrap();
        let read = mem.read(offset_addr, 2).unwrap();

        assert_eq!(read, [0xAB, 0xCD]);
    }

    #[test]
    fn test_out_of_bounds() {
        let mut mem = UnmanagedMemory::new(1024);

        let ptr = mem.alloc(8).unwrap();

        // Try to read beyond bounds
        assert!(mem.read(ptr.address(), 16).is_err());

        // Try to write beyond bounds
        assert!(mem.write(ptr.address(), &[0; 16]).is_err());
    }

    #[test]
    fn test_memory_limit() {
        let mut mem = UnmanagedMemory::new(100);

        // First allocation should succeed
        let _ptr1 = mem.alloc(50).unwrap();

        // This allocation should fail (would exceed limit)
        assert!(mem.alloc(60).is_err());
    }
}
