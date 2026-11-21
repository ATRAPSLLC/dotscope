//! Raw data loader for emulation.
//!
//! This module provides [`DataLoader`] for mapping raw data regions
//! into the emulation address space. Unlike [`super::PeLoader`] which handles
//! structured PE images, `DataLoader` works with arbitrary byte sequences.
//!
//! # Overview
//!
//! The [`DataLoader`] is a utility for mapping raw data into the emulation
//! memory address space. It supports various mapping scenarios:
//!
//! - Mapping data at specific addresses with custom protection flags
//! - Mapping data at automatically allocated addresses
//! - Loading file contents into memory
//! - Creating zero-initialized memory regions
//!
//! # Usage
//!
//! ```
//! use dotscope::emulation::AddressSpace;
//! use dotscope::emulation::MemoryProtection;
//! use dotscope::emulation::DataLoader;
//!
//! let address_space = AddressSpace::new();
//!
//! // Map read-only data at a specific address
//! let info = DataLoader::map_readonly(
//!     &address_space,
//!     0x10000,
//!     &[0x01, 0x02, 0x03],
//!     "constants",
//! )?;
//!
//! // Map read-write data
//! let info = DataLoader::map_readwrite(
//!     &address_space,
//!     0x20000,
//!     &[0u8; 0x1000],
//!     "buffer",
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Memory Protection
//!
//! The loader supports all standard memory protection combinations through
//! [`MemoryProtection`] flags:
//!
//! - `READ` - Memory can be read
//! - `WRITE` - Memory can be written
//! - `EXECUTE` - Memory can be executed as code

use crate::{
    emulation::memory::{AddressSpace, MemoryProtection, MemoryRegion},
    Error, Result,
};

/// Information about a mapped data region in the emulation address space.
///
/// This struct is returned by [`DataLoader`] methods after successfully mapping
/// data into memory. It contains metadata about the mapped region that can be
/// used to track and manage memory allocations.
///
/// # Fields
///
/// All fields are public to allow direct access to mapping information:
///
/// - `base_address` - The starting virtual address of the mapped region
/// - `size` - The size in bytes of the mapped data
/// - `label` - A descriptive name for the region (useful for debugging)
/// - `protection` - The memory protection flags applied to the region
#[derive(Clone, Debug)]
pub struct MappedRegionInfo {
    /// Base address where the region was mapped in virtual memory.
    ///
    /// This is the starting address that can be used to read from or write to
    /// the mapped data through the [`AddressSpace`].
    pub base_address: u64,

    /// Size of the mapped region in bytes.
    ///
    /// This reflects the actual size of the data that was mapped, not including
    /// any padding or alignment that may have been applied by the address space.
    pub size: usize,

    /// Label or name identifying this memory region.
    ///
    /// This is a human-readable identifier useful for debugging and logging.
    /// Common labels include file names, section names, or descriptive tags
    /// like "stack", "heap", or "constants".
    pub label: String,

    /// Memory protection flags for this region.
    ///
    /// Defines what operations are permitted on this memory region.
    /// See [`MemoryProtection`] for
    /// available flags (READ, WRITE, EXECUTE).
    pub protection: MemoryProtection,
}

/// Raw data loader for mapping arbitrary data into the address space.
///
/// `DataLoader` provides static methods to map raw byte data into the emulation
/// address space. It is a stateless utility struct - all methods are associated
/// functions that operate directly on an [`AddressSpace`].
///
/// # Design
///
/// Unlike [`PeLoader`](super::PeLoader) which parses and maps PE structures,
/// `DataLoader` treats data as opaque byte sequences. This makes it suitable for:
///
/// - Loading raw binary blobs
/// - Creating memory buffers for emulation
/// - Mapping configuration data or constants
/// - Setting up stack and heap regions
///
/// # Thread Safety
///
/// All methods are thread-safe as they only require shared references to the
/// address space. The underlying memory regions use internal synchronization.
pub struct DataLoader;

impl DataLoader {
    /// Maps raw data at a specific virtual address.
    ///
    /// This method maps the provided data into the address space at the exact
    /// address specified. The address must be available (not already mapped).
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `address` - The virtual address where the data should be mapped
    /// * `data` - The raw bytes to map
    /// * `label` - A descriptive name for the region (accepts any type implementing `Into<String>`)
    /// * `protection` - Memory protection flags to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success, containing details about the mapped region.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address is already mapped to another region
    /// - The address space cannot accommodate the mapping
    /// - Internal memory allocation fails
    ///
    /// # Example
    ///
    /// ```
    /// # use dotscope::emulation::{AddressSpace, DataLoader, MemoryProtection};
    /// # let address_space = AddressSpace::new();
    /// let info = DataLoader::map_at(
    ///     &address_space,
    ///     0x10000,
    ///     &[0xCC; 100],  // INT 3 breakpoints
    ///     "breakpoint_area",
    ///     MemoryProtection::READ | MemoryProtection::EXECUTE,
    /// )?;
    /// assert_eq!(info.base_address, 0x10000);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn map_at(
        address_space: &AddressSpace,
        address: u64,
        data: &[u8],
        label: impl Into<String>,
        protection: MemoryProtection,
    ) -> Result<MappedRegionInfo> {
        let label = label.into();
        let size = data.len();

        let region = MemoryRegion::mapped_data(address, data, label.clone(), protection);

        address_space.map_at(address, region)?;

        Ok(MappedRegionInfo {
            base_address: address,
            size,
            label,
            protection,
        })
    }

    /// Maps raw data at the next available address in the address space.
    ///
    /// Unlike [`map_at`](Self::map_at), this method allows the address space to
    /// automatically choose an appropriate base address for the mapping. This is
    /// useful when the exact address doesn't matter and you want to avoid conflicts.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `data` - The raw bytes to map
    /// * `label` - A descriptive name for the region
    /// * `protection` - Memory protection flags to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success. The `base_address` field in the
    /// returned struct indicates where the data was actually mapped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address space has no available space for the mapping
    /// - Internal memory allocation fails
    ///
    /// # Example
    ///
    /// ```
    /// # use dotscope::emulation::{AddressSpace, DataLoader, MemoryProtection};
    /// # let address_space = AddressSpace::new();
    /// let info = DataLoader::map(
    ///     &address_space,
    ///     &vec![0u8; 0x1000],
    ///     "dynamic_buffer",
    ///     MemoryProtection::READ | MemoryProtection::WRITE,
    /// )?;
    /// println!("Buffer mapped at: 0x{:X}", info.base_address);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn map(
        address_space: &AddressSpace,
        data: &[u8],
        label: impl Into<String>,
        protection: MemoryProtection,
    ) -> Result<MappedRegionInfo> {
        let label = label.into();
        let size = data.len();

        let region = MemoryRegion::mapped_data(0, data, label.clone(), protection);

        let base_address = address_space.map(region)?;

        Ok(MappedRegionInfo {
            base_address,
            size,
            label,
            protection,
        })
    }

    /// Maps read-only data at a specific address.
    ///
    /// This is a convenience wrapper around [`map_at`](Self::map_at) that applies
    /// `MemoryProtection::READ` permission. Ideal for mapping constant data,
    /// string literals, or other immutable content.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `address` - The virtual address where the data should be mapped
    /// * `data` - The raw bytes to map
    /// * `label` - A descriptive name for the region
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success with `protection` set to `READ`.
    ///
    /// # Errors
    ///
    /// See [`map_at`](Self::map_at) for error conditions.
    pub fn map_readonly(
        address_space: &AddressSpace,
        address: u64,
        data: &[u8],
        label: impl Into<String>,
    ) -> Result<MappedRegionInfo> {
        Self::map_at(address_space, address, data, label, MemoryProtection::READ)
    }

    /// Maps read-write data at a specific address.
    ///
    /// This is a convenience wrapper around [`map_at`](Self::map_at) that applies
    /// `MemoryProtection::READ | MemoryProtection::WRITE` permissions. Suitable for
    /// data buffers, scratch memory, or any region that needs modification.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `address` - The virtual address where the data should be mapped
    /// * `data` - The raw bytes to map
    /// * `label` - A descriptive name for the region
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success with `protection` set to `READ | WRITE`.
    ///
    /// # Errors
    ///
    /// See [`map_at`](Self::map_at) for error conditions.
    pub fn map_readwrite(
        address_space: &AddressSpace,
        address: u64,
        data: &[u8],
        label: impl Into<String>,
    ) -> Result<MappedRegionInfo> {
        Self::map_at(
            address_space,
            address,
            data,
            label,
            MemoryProtection::READ | MemoryProtection::WRITE,
        )
    }

    /// Maps executable data (code) at a specific address.
    ///
    /// This is a convenience wrapper around [`map_at`](Self::map_at) that applies
    /// `MemoryProtection::READ | MemoryProtection::EXECUTE` permissions. Use this
    /// for mapping code regions, shellcode, or other executable content.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `address` - The virtual address where the code should be mapped
    /// * `data` - The machine code bytes to map
    /// * `label` - A descriptive name for the region
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success with `protection` set to `READ | EXECUTE`.
    ///
    /// # Errors
    ///
    /// See [`map_at`](Self::map_at) for error conditions.
    ///
    /// # Note
    ///
    /// The data is mapped as read-execute (not write). If the code needs to be
    /// self-modifying, use [`map_at`](Self::map_at) directly with custom permissions.
    pub fn map_executable(
        address_space: &AddressSpace,
        address: u64,
        data: &[u8],
        label: impl Into<String>,
    ) -> Result<MappedRegionInfo> {
        Self::map_at(
            address_space,
            address,
            data,
            label,
            MemoryProtection::READ | MemoryProtection::EXECUTE,
        )
    }

    /// Maps the contents of a file into the address space.
    ///
    /// Reads the entire file from disk and maps it into memory at the specified
    /// address. The file name (without path) is used as the region label.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `path` - Path to the file to load
    /// * `address` - The virtual address where the file contents should be mapped
    /// * `protection` - Memory protection flags to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success. The `size` field reflects the
    /// actual file size that was loaded.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file cannot be read (permission denied, not found, I/O error)
    /// - The mapping fails (see [`map_at`](Self::map_at) for mapping errors)
    ///
    /// # Example
    ///
    /// ```
    /// use std::path::Path;
    /// # use dotscope::emulation::{AddressSpace, DataLoader, MemoryProtection};
    /// # let address_space = AddressSpace::new();
    ///
    /// let info = DataLoader::map_file(
    ///     &address_space,
    ///     Path::new("tests/samples/crafted_2.exe"),
    ///     0x50000,
    ///     MemoryProtection::READ,
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn map_file(
        address_space: &AddressSpace,
        path: &std::path::Path,
        address: u64,
        protection: MemoryProtection,
    ) -> Result<MappedRegionInfo> {
        let data =
            std::fs::read(path).map_err(|e| Error::Other(format!("Failed to read file: {e}")))?;

        let label = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("mapped_file")
            .to_string();

        Self::map_at(address_space, address, &data, label, protection)
    }

    /// Maps a zero-initialized memory region at a specific address.
    ///
    /// Creates a memory region filled with zeros. This is useful for setting up
    /// uninitialized data sections (BSS), stacks, heaps, or scratch buffers.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The address space to map into
    /// * `address` - The virtual address where the zeroed region should be mapped
    /// * `size` - Size in bytes of the region to create
    /// * `label` - A descriptive name for the region
    /// * `protection` - Memory protection flags to apply
    ///
    /// # Returns
    ///
    /// Returns `Ok(MappedRegionInfo)` on success with `size` set to the requested size.
    ///
    /// # Errors
    ///
    /// See [`map_at`](Self::map_at) for error conditions. Additionally may fail
    /// if the system cannot allocate the requested amount of memory.
    ///
    /// # Example
    ///
    /// ```
    /// # use dotscope::emulation::{AddressSpace, DataLoader, MemoryProtection};
    /// # let address_space = AddressSpace::new();
    /// // Create a 1MB stack region
    /// let stack_info = DataLoader::map_zeroed(
    ///     &address_space,
    ///     0x7FFE0000,
    ///     0x100000,  // 1 MB
    ///     "stack",
    ///     MemoryProtection::READ | MemoryProtection::WRITE,
    /// )?;
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    pub fn map_zeroed(
        address_space: &AddressSpace,
        address: u64,
        size: usize,
        label: impl Into<String>,
        protection: MemoryProtection,
    ) -> Result<MappedRegionInfo> {
        let data = vec![0u8; size];
        Self::map_at(address_space, address, &data, label, protection)
    }
}

impl Default for DataLoader {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_address_space() -> AddressSpace {
        AddressSpace::with_config(1024 * 1024, 0x1_0000_0000)
    }

    #[test]
    fn test_map_at() {
        let address_space = create_test_address_space();
        let data = vec![0x01, 0x02, 0x03, 0x04];

        let info = DataLoader::map_at(
            &address_space,
            0x10000,
            &data,
            "test_data",
            MemoryProtection::READ | MemoryProtection::WRITE,
        )
        .unwrap();

        assert_eq!(info.base_address, 0x10000);
        assert_eq!(info.size, 4);
        assert_eq!(info.label, "test_data");

        // Verify data was mapped
        let read_data = address_space.read(0x10000, 4).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_map_readonly() {
        let address_space = create_test_address_space();
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let info = DataLoader::map_readonly(&address_space, 0x20000, &data, "readonly").unwrap();

        assert_eq!(info.protection, MemoryProtection::READ);

        let read_data = address_space.read(0x20000, 4).unwrap();
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_map_zeroed() {
        let address_space = create_test_address_space();

        let info = DataLoader::map_zeroed(
            &address_space,
            0x30000,
            0x100,
            "bss",
            MemoryProtection::READ | MemoryProtection::WRITE,
        )
        .unwrap();

        assert_eq!(info.size, 0x100);

        let read_data = address_space.read(0x30000, 0x100).unwrap();
        assert!(read_data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_mapped_region_info() {
        let info = MappedRegionInfo {
            base_address: 0x40000,
            size: 0x1000,
            label: "test".to_string(),
            protection: MemoryProtection::READ | MemoryProtection::EXECUTE,
        };

        assert_eq!(info.base_address, 0x40000);
        assert_eq!(info.size, 0x1000);
        assert!(info.protection.contains(MemoryProtection::READ));
        assert!(info.protection.contains(MemoryProtection::EXECUTE));
        assert!(!info.protection.contains(MemoryProtection::WRITE));
    }
}
