//! Image and data loading for emulation.
//!
//! This module provides loaders for mapping PE images and raw data into the
//! emulation address space. It serves as the bridge between on-disk file formats
//! and the in-memory representation needed for emulation.
//!
//! # Overview
//!
//! The loader module contains two main components:
//!
//! - **[`PeLoader`]** - Parses and maps Portable Executable (PE) files, handling
//!   section alignment, memory protection, and optional relocation
//! - **[`DataLoader`]** - Maps raw byte data without any format interpretation
//!
//! # Architecture
//!
//! ```text
//! +---------------+     +----------------+
//! | PE File       | --> | PeLoader       | --+
//! +---------------+     +----------------+   |
//!                                            v
//! +---------------+     +----------------+   +------------------+
//! | Raw Data      | --> | DataLoader     | -->| AddressSpace     |
//! +---------------+     +----------------+   +------------------+
//! ```
//!
//! Both loaders ultimately map data into an
//! [`AddressSpace`](crate::emulation::memory::AddressSpace), but they differ
//! in how they interpret and process the input:
//!
//! - `PeLoader` understands PE structure, respects section boundaries, and can
//!   apply relocations for non-preferred base addresses
//! - `DataLoader` treats input as opaque bytes and maps them directly
//!
//! # Choosing a Loader
//!
//! | Scenario | Recommended Loader |
//! |----------|-------------------|
//! | Loading .exe/.dll for analysis | [`PeLoader`] |
//! | Loading .NET assemblies | [`PeLoader`] (detects CLR header) |
//! | Loading raw shellcode | [`DataLoader`] |
//! | Creating stack/heap regions | [`DataLoader`] |
//! | Loading arbitrary binary data | [`DataLoader`] |
//!
//! # Components
//!
//! ## PE Loading
//!
//! - [`PeLoader`] - Main PE image loader with configurable options
//! - [`PeLoaderConfig`] - Configuration for PE loading (base address, permissions, etc.)
//! - [`LoadedImage`] - Metadata about a loaded PE image
//! - [`LoadedSection`] - Information about an individual PE section
//!
//! ## Data Loading
//!
//! - [`DataLoader`] - Raw data mapping utility
//! - [`MappedRegionInfo`] - Metadata about a mapped memory region
//!
//! # Example
//!
//! ```
//! use dotscope::emulation::PeLoader;
//! use dotscope::emulation::DataLoader;
//! use dotscope::emulation::AddressSpace;
//! use dotscope::emulation::MemoryProtection;
//! use std::path::Path;
//!
//! // Create an address space
//! let address_space = AddressSpace::new();
//!
//! // Load a PE file
//! let loader = PeLoader::new();
//! let image = loader.load_file(
//!     Path::new("tests/samples/crafted_2.exe"),
//!     &address_space,
//! )?;
//! println!("Loaded {} at 0x{:X}", image.name, image.base_address);
//!
//! // Map a stack region
//! let stack = DataLoader::map_zeroed(
//!     &address_space,
//!     0x7FFE0000,
//!     0x100000,
//!     "stack",
//!     MemoryProtection::READ | MemoryProtection::WRITE,
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```

mod data;
mod peloader;

pub use data::{DataLoader, MappedRegionInfo};
pub use peloader::{LoadedImage, LoadedSection, PeLoader, PeLoaderConfig};
