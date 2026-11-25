//! Capture context for collecting emulation results.
//!
//! This module provides [`CaptureContext`], the central collection point for all data
//! captured during .NET emulation. It is designed for thread-safe concurrent access
//! and supports configurable capture policies.
//!
//! # Overview
//!
//! The capture context automatically collects various types of data during emulation:
//!
//! - **Assemblies**: Loaded via `Assembly.Load(byte[])` and similar methods, useful for
//!   extracting packed or dynamically decrypted assemblies
//! - **Strings**: Decrypted or dynamically generated strings that may reveal configuration,
//!   URLs, or other sensitive data
//! - **Buffers**: Raw byte buffers from memory operations, crypto transforms, or method returns
//! - **File Operations**: File system access patterns including reads, writes, and deletions
//! - **Network Operations**: Network activity including HTTP requests, TCP connections, and DNS lookups
//! - **Memory Snapshots**: Point-in-time snapshots of configured memory regions
//!
//! # Thread Safety
//!
//! [`CaptureContext`] uses interior mutability with [`RwLock`] to allow safe concurrent
//! access from multiple emulation threads. All capture operations are non-blocking for readers
//! and use fine-grained locking.
//!
//! # Examples
//!
//! Creating a capture context with default settings (captures everything):
//!
//! ```no_run
//! use dotscope::emulation::CaptureContext;
//!
//! let ctx = CaptureContext::new();
//!
//! // After emulation completes, retrieve captured data
//! for assembly in ctx.assemblies() {
//!     println!("Captured assembly: {} bytes", assembly.data.len());
//! }
//!
//! for string in ctx.strings() {
//!     println!("Decrypted string: {}", string.value);
//! }
//! ```
//!
//! Creating a minimal context for assembly extraction only:
//!
//! ```no_run
//! use dotscope::emulation::CaptureContext;
//!
//! let ctx = CaptureContext::assemblies_only();
//! // Strings, file ops, and network ops will not be captured
//! ```

use std::{
    collections::{hash_map::DefaultHasher, HashSet as StdHashSet},
    hash::{Hash, Hasher},
    ops::Range,
    sync::RwLock,
};

use crate::{
    emulation::{
        capture::types::{
            AssemblyLoadMethod, BufferSource, CaptureSource, CapturedAssembly, CapturedBuffer,
            CapturedMethodReturn, CapturedString, FileOpKind, FileOperation, MemoryRegionSnapshot,
            MemorySnapshot, NetworkOperation,
        },
        memory::AddressSpace,
        process::CaptureConfig,
        ThreadId,
    },
    metadata::token::Token,
};

/// Central context for capturing emulation results during .NET analysis.
///
/// `CaptureContext` serves as the primary collection point for all data intercepted
/// during emulation. It automatically captures assemblies loaded dynamically, decrypted
/// strings, memory buffers, file operations, and network activity based on the
/// configured [`CaptureConfig`].
///
/// # Thread Safety
///
/// This struct is designed for concurrent access from multiple emulation threads.
/// All internal collections are protected by [`RwLock`], allowing multiple readers
/// or a single writer at any time. Capture operations silently skip if the lock
/// cannot be acquired to avoid blocking emulation.
///
/// # Configuration
///
/// Capture behavior is controlled by [`CaptureConfig`]. By default, all capture
/// types are enabled. Use [`CaptureContext::with_config`] for fine-grained control,
/// or convenience constructors like [`CaptureContext::assemblies_only`] for common
/// use cases.
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::CaptureContext;
/// use dotscope::emulation::CaptureConfig;
///
/// // Capture only assemblies and strings
/// let config = CaptureConfig {
///     assemblies: true,
///     strings: true,
///     file_operations: false,
///     network_operations: false,
///     ..Default::default()
/// };
/// let ctx = CaptureContext::with_config(config);
/// ```
#[derive(Debug)]
pub struct CaptureContext {
    /// Configuration controlling which types of data to capture.
    config: CaptureConfig,

    /// Assemblies captured from `Assembly.Load` and similar calls.
    ///
    /// Contains raw assembly bytes extracted during emulation, typically from
    /// packed or encrypted loaders that dynamically load assemblies at runtime.
    assemblies: RwLock<Vec<CapturedAssembly>>,

    /// Decrypted or dynamically generated strings.
    ///
    /// Captures strings that are computed at runtime, often revealing obfuscated
    /// configuration data, URLs, registry keys, or other sensitive information.
    strings: RwLock<Vec<CapturedString>>,

    /// Raw byte buffers from various memory operations.
    ///
    /// Includes data from `Marshal.Copy`, crypto transforms, and other buffer
    /// operations that may contain decrypted payloads or extracted data.
    buffers: RwLock<Vec<CapturedBuffer>>,

    /// Total bytes retained across all capture collections.
    ///
    /// Charged by [`admit`](Self::admit) and compared against
    /// [`CaptureConfig::max_total_bytes`]. Captured data lives outside the managed heap, so
    /// this is the only thing bounding it.
    retained_bytes: RwLock<usize>,

    /// Content hashes of captured assemblies, for O(1) duplicate rejection.
    ///
    /// The previous duplicate check compared the candidate byte-for-byte against every
    /// assembly already captured, making capture quadratic in capture count.
    assembly_hashes: RwLock<StdHashSet<u64>>,

    /// Return values from monitored methods.
    ///
    /// Captures return values from specific methods configured for monitoring,
    /// useful for extracting computed values without modifying program flow.
    method_returns: RwLock<Vec<CapturedMethodReturn>>,

    /// File system operations performed during emulation.
    ///
    /// Records file reads, writes, deletions, and directory operations to
    /// understand the program's file system interaction patterns.
    file_operations: RwLock<Vec<FileOperation>>,

    /// Network operations performed during emulation.
    ///
    /// Captures TCP/UDP connections, HTTP requests, DNS lookups, and data
    /// transfers to reveal command-and-control or exfiltration behavior.
    network_operations: RwLock<Vec<NetworkOperation>>,

    /// Point-in-time memory snapshots.
    ///
    /// Contains snapshots of configured memory regions taken at specific points
    /// during emulation, useful for tracking memory state evolution.
    snapshots: RwLock<Vec<MemorySnapshot>>,

    /// The manifest resources the program opened, and which method opened
    /// each, in the order they were first opened.
    ///
    /// Which resource a protection's runtime reads is the one thing its code
    /// says about it for certain, even when the name it asks for is itself
    /// encrypted.
    resource_reads: RwLock<Vec<ResourceRead>>,

    /// Aggregate statistics for all captured data.
    stats: RwLock<CaptureStats>,
}

/// A manifest resource the emulated program opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceRead {
    /// The `ManifestResource` token of the resource.
    pub resource: Token,
    /// The method that asked for it, when one was executing.
    pub reader: Option<Token>,
}

/// Aggregate statistics about data captured during emulation.
///
/// Provides summary metrics for quick assessment of capture results without
/// needing to iterate through all captured items. Updated atomically as new
/// data is captured.
///
/// # Examples
///
/// ```
/// use dotscope::emulation::CaptureContext;
///
/// let ctx = CaptureContext::new();
/// // ... run emulation ...
///
/// let stats = ctx.stats();
/// println!("Captured {} bytes of assemblies", stats.assembly_bytes);
/// println!("Decrypted {} strings", stats.string_count);
/// ```
#[derive(Debug, Default, Clone)]
pub struct CaptureStats {
    /// Total bytes of raw assembly data captured.
    ///
    /// Sum of all `CapturedAssembly::data` lengths. Useful for estimating
    /// memory usage and identifying large payload extractions.
    pub assembly_bytes: usize,

    /// Number of strings captured.
    ///
    /// Count of all decrypted or dynamically generated strings. Does not
    /// include duplicates (each capture is counted separately).
    pub string_count: usize,

    /// Total bytes captured in raw buffers.
    ///
    /// Sum of all `CapturedBuffer::data` lengths, including data from
    /// `Marshal.Copy`, crypto transforms, and memory region captures.
    pub buffer_bytes: usize,

    /// Number of file operations captured.
    ///
    /// Count of all file system operations including reads, writes,
    /// deletions, and directory operations.
    pub file_op_count: usize,

    /// Number of network operations captured.
    ///
    /// Count of all network operations including TCP/UDP connections,
    /// HTTP requests, and DNS lookups.
    pub network_op_count: usize,

    /// Number of memory snapshots taken.
    ///
    /// Count of point-in-time memory region snapshots captured during
    /// emulation.
    pub snapshot_count: usize,
}

impl CaptureContext {
    /// Creates a new capture context with default configuration.
    ///
    /// The default configuration enables capture of assemblies, strings, file operations,
    /// and network operations. Memory region capture and method return capture are
    /// disabled by default.
    ///
    /// # Returns
    ///
    /// A new `CaptureContext` configured to capture all common data types.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::emulation::CaptureContext;
    ///
    /// let ctx = CaptureContext::new();
    /// assert!(ctx.config().assemblies);
    /// assert!(ctx.config().strings);
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(CaptureConfig {
            assemblies: true,
            strings: true,
            file_operations: true,
            network_operations: true,
            // Explicitly on: this constructor means "capture what is useful".
            // `CaptureConfig::default()` captures nothing, which is what that type documents.
            buffers: true,
            ..Default::default()
        })
    }

    /// Creates a new capture context with the specified configuration.
    ///
    /// Use this constructor for fine-grained control over what data types are captured
    /// during emulation.
    ///
    /// # Arguments
    ///
    /// * `config` - The [`CaptureConfig`] specifying which data types to capture.
    ///
    /// # Returns
    ///
    /// A new `CaptureContext` with the specified configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use dotscope::emulation::{CaptureConfig, CaptureContext};
    ///
    /// let config = CaptureConfig {
    ///     assemblies: true,
    ///     strings: false,  // Don't capture strings
    ///     ..Default::default()
    /// };
    /// let ctx = CaptureContext::with_config(config);
    /// ```
    #[must_use]
    pub fn with_config(config: CaptureConfig) -> Self {
        Self {
            config,
            assemblies: RwLock::new(Vec::new()),
            strings: RwLock::new(Vec::new()),
            buffers: RwLock::new(Vec::new()),
            retained_bytes: RwLock::new(0),
            assembly_hashes: RwLock::new(StdHashSet::new()),
            method_returns: RwLock::new(Vec::new()),
            file_operations: RwLock::new(Vec::new()),
            network_operations: RwLock::new(Vec::new()),
            snapshots: RwLock::new(Vec::new()),
            resource_reads: RwLock::new(Vec::new()),
            stats: RwLock::new(CaptureStats::default()),
        }
    }

    /// Creates a capture context configured for assembly extraction only.
    ///
    /// This is a convenience constructor for the common use case of extracting
    /// packed or encrypted assemblies without capturing other data types. Useful
    /// for unpacking scenarios where only the final payload is of interest.
    ///
    /// # Returns
    ///
    /// A new `CaptureContext` that only captures assemblies.
    #[must_use]
    pub fn assemblies_only() -> Self {
        Self::with_config(CaptureConfig {
            assemblies: true,
            ..Default::default()
        })
    }

    /// Creates a capture context configured for string decryption only.
    ///
    /// This is a convenience constructor for scenarios focused on extracting
    /// obfuscated strings without capturing other data types. Ideal for
    /// string deobfuscation analysis.
    ///
    /// # Returns
    ///
    /// A new `CaptureContext` that only captures strings.
    #[must_use]
    pub fn strings_only() -> Self {
        Self::with_config(CaptureConfig {
            strings: true,
            ..Default::default()
        })
    }

    /// Returns a reference to the capture configuration.
    ///
    /// # Returns
    ///
    /// A reference to the [`CaptureConfig`] controlling this context's behavior.
    pub fn config(&self) -> &CaptureConfig {
        &self.config
    }

    /// Captures an assembly load operation.
    ///
    /// Records an assembly that was loaded dynamically during emulation. This is the
    /// primary method for capturing packed or encrypted assemblies as they are unpacked.
    ///
    /// If assembly capture is disabled in the configuration, this method returns
    /// immediately without capturing.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw assembly bytes (PE/COFF format).
    /// * `source` - The [`CaptureSource`] identifying where the capture occurred.
    /// * `load_method` - The `AssemblyLoadMethod` indicating how the assembly was loaded.
    /// * `name` - Optional assembly name if it can be determined from metadata.
    ///
    /// # Thread Safety
    ///
    /// This method acquires a write lock on the assemblies collection. If the lock
    /// cannot be acquired, the capture is silently skipped.
    pub fn capture_assembly(
        &self,
        data: Vec<u8>,
        source: CaptureSource,
        load_method: AssemblyLoadMethod,
        name: Option<String>,
    ) {
        if !self.config.assemblies {
            return;
        }

        // Duplicate rejection by content hash. The previous check compared the candidate
        // byte-for-byte against every assembly already captured, so capture cost grew
        // quadratically in capture count over multi-megabyte payloads.
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        let digest = hasher.finish();

        if let Ok(mut hashes) = self.assembly_hashes.write() {
            if !hashes.insert(digest) {
                return; // Already captured this exact assembly
            }
        }

        let len = data.len();
        if !self.admit(len) {
            return;
        }

        let assembly = CapturedAssembly {
            data,
            source,
            load_method,
            name,
        };

        if let Ok(mut assemblies) = self.assemblies.write() {
            if assemblies.len() >= self.config.max_items {
                return;
            }
            assemblies.push(assembly);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.assembly_bytes = stats.assembly_bytes.saturating_add(len);
        }
    }

    /// Captures an assembly loaded via `Assembly.Load(byte[])`.
    ///
    /// Convenience method for the common case of capturing assemblies loaded from
    /// byte arrays. Automatically constructs the [`CaptureSource`] from the provided
    /// parameters.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw assembly bytes being loaded.
    /// * `method` - The method token where the load occurred.
    /// * `thread_id` - The thread that performed the load.
    /// * `offset` - The IL offset within the method.
    /// * `instruction_count` - The global instruction count at capture time.
    pub fn capture_assembly_load_bytes(
        &self,
        data: Vec<u8>,
        method: Token,
        thread_id: ThreadId,
        offset: u32,
        instruction_count: u64,
    ) {
        let source = CaptureSource::new(method, thread_id, offset, instruction_count);
        self.capture_assembly(data, source, AssemblyLoadMethod::LoadBytes, None);
    }

    /// Returns all captured assemblies.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`CapturedAssembly`] instances captured so far.
    /// Returns an empty vector if no assemblies were captured or if the lock
    /// cannot be acquired.
    pub fn assemblies(&self) -> Vec<CapturedAssembly> {
        self.assemblies
            .read()
            .map(|a| a.clone())
            .unwrap_or_default()
    }

    /// Records that `reader` opened the manifest resource `resource`.
    ///
    /// Recorded whatever the capture configuration: it is two tokens per read,
    /// and the resources a run touched, and whose code touched them, are
    /// needed to know which ones a protection's runtime owns.
    pub fn record_resource_read(&self, resource: Token, reader: Option<Token>) {
        let read = ResourceRead { resource, reader };
        if let Ok(mut reads) = self.resource_reads.write() {
            if !reads.contains(&read) {
                reads.push(read);
            }
        }
    }

    /// The manifest resources the program opened, and which method opened
    /// each, in the order they were first opened.
    pub fn resource_reads(&self) -> Vec<ResourceRead> {
        self.resource_reads
            .read()
            .map(|reads| reads.clone())
            .unwrap_or_default()
    }

    /// Returns the number of captured assemblies.
    ///
    /// # Returns
    ///
    /// The count of assemblies captured, or 0 if the lock cannot be acquired.
    pub fn assembly_count(&self) -> usize {
        self.assemblies.read().map_or(0, |a| a.len())
    }

    /// Captures a decrypted or dynamically generated string.
    ///
    /// Records a string value that was computed at runtime, typically the result
    /// of a string decryption routine or dynamic string construction.
    ///
    /// If string capture is disabled in the configuration, this method returns
    /// immediately without capturing.
    ///
    /// # Arguments
    ///
    /// * `value` - The decrypted/generated string value.
    /// * `source` - The [`CaptureSource`] identifying where the capture occurred.
    pub fn capture_string(&self, value: String, source: CaptureSource) {
        if !self.config.strings {
            return;
        }

        if !self.admit(value.len()) {
            return;
        }

        let string = CapturedString {
            value,
            source,
            encrypted_data: None,
            key: None,
        };

        if let Ok(mut strings) = self.strings.write() {
            if strings.len() >= self.config.max_items {
                return;
            }
            strings.push(string);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.string_count = stats.string_count.saturating_add(1);
        }
    }

    /// Captures a decrypted string along with encryption details.
    ///
    /// Extended version of [`capture_string`](Self::capture_string) that also records
    /// the original encrypted data and decryption key when available. This additional
    /// context is useful for understanding the encryption scheme used.
    ///
    /// # Arguments
    ///
    /// * `value` - The decrypted string value.
    /// * `source` - The [`CaptureSource`] identifying where the capture occurred.
    /// * `encrypted_data` - The original encrypted bytes, if available.
    /// * `key` - The decryption key used, if determinable.
    pub fn capture_string_with_details(
        &self,
        value: String,
        source: CaptureSource,
        encrypted_data: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
    ) {
        if !self.config.strings {
            return;
        }

        let string = CapturedString {
            value,
            source,
            encrypted_data,
            key,
        };

        if let Ok(mut strings) = self.strings.write() {
            strings.push(string);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.string_count = stats.string_count.saturating_add(1);
        }
    }

    /// Returns all captured strings.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`CapturedString`] instances captured so far.
    /// Returns an empty vector if no strings were captured or if the lock
    /// cannot be acquired.
    pub fn strings(&self) -> Vec<CapturedString> {
        self.strings
            .read()
            .map_or_else(|_| Vec::new(), |s| s.clone())
    }

    /// Returns the number of captured strings.
    ///
    /// # Returns
    ///
    /// The count of strings captured, or 0 if the lock cannot be acquired.
    pub fn string_count(&self) -> usize {
        self.strings.read().map_or(0, |s| s.len())
    }

    /// Captures a raw byte buffer.
    ///
    /// Records a byte buffer from memory operations, crypto transforms, or other
    /// sources during emulation.
    ///
    /// Gated on [`CaptureConfig::buffers`] and bounded by
    /// [`CaptureConfig::max_items`]/[`CaptureConfig::max_total_bytes`]. Captures past either
    /// ceiling are dropped silently — emulation continues, it simply stops retaining more.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw buffer bytes.
    /// * `source` - The [`CaptureSource`] identifying where the capture occurred.
    /// * `buffer_source` - The [`BufferSource`] describing how/where the buffer originated.
    /// * `label` - A descriptive label for identifying this buffer.
    pub fn capture_buffer(
        &self,
        data: Vec<u8>,
        source: CaptureSource,
        buffer_source: BufferSource,
        label: impl Into<String>,
    ) {
        if !self.config.buffers {
            return;
        }

        let len = data.len();
        if !self.admit(len) {
            return;
        }

        let buffer = CapturedBuffer {
            data,
            source,
            buffer_source,
            label: label.into(),
        };

        if let Ok(mut buffers) = self.buffers.write() {
            if buffers.len() >= self.config.max_items {
                return;
            }
            buffers.push(buffer);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.buffer_bytes = stats.buffer_bytes.saturating_add(len);
        }
    }

    /// Returns whether `len` more captured bytes fit within
    /// [`CaptureConfig::max_total_bytes`], charging them if so.
    ///
    /// Captured data lives outside the managed heap, so the heap budget never sees it; this is
    /// the only ceiling on it. The counter is monotonic — captures are never released during a
    /// run — so charging on admission is sufficient.
    fn admit(&self, len: usize) -> bool {
        let Ok(mut retained) = self.retained_bytes.write() else {
            return false;
        };

        let next = retained.saturating_add(len);
        if next > self.config.max_total_bytes {
            return false;
        }

        *retained = next;
        true
    }

    /// Returns all captured buffers.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`CapturedBuffer`] instances captured so far.
    /// Returns an empty vector if no buffers were captured or if the lock
    /// cannot be acquired.
    pub fn buffers(&self) -> Vec<CapturedBuffer> {
        self.buffers
            .read()
            .map_or_else(|_| Vec::new(), |b| b.clone())
    }

    /// Returns the number of captured buffers.
    ///
    /// # Returns
    ///
    /// The count of buffers captured, or 0 if the lock cannot be acquired.
    pub fn buffer_count(&self) -> usize {
        self.buffers.read().map_or(0, |b| b.len())
    }

    /// Captures a method return value.
    ///
    /// Records the return value from a method call. This can be called from
    /// hooks to capture return values of interest.
    ///
    /// # Arguments
    ///
    /// * `capture` - The [`CapturedMethodReturn`] containing the return value details.
    pub fn capture_method_return(&self, capture: CapturedMethodReturn) {
        if let Ok(mut returns) = self.method_returns.write() {
            returns.push(capture);
        }
    }

    /// Returns all captured method return values.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`CapturedMethodReturn`] instances captured so far.
    /// Returns an empty vector if no returns were captured or if the lock
    /// cannot be acquired.
    pub fn method_returns(&self) -> Vec<CapturedMethodReturn> {
        self.method_returns
            .read()
            .map(|r| r.clone())
            .unwrap_or_default()
    }

    /// Captures a file system operation.
    ///
    /// Records file system activity including reads, writes, deletions, and
    /// directory operations. This helps understand how the program interacts
    /// with the file system.
    ///
    /// If file operation capture is disabled in the configuration, this method
    /// returns immediately without capturing.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`FileOpKind`] indicating the type of operation.
    /// * `path` - The primary file path involved in the operation.
    /// * `destination` - Secondary path for move/copy operations, if applicable.
    /// * `data` - The data read or written, if captured and available.
    /// * `source` - The [`CaptureSource`] identifying where the capture occurred.
    /// * `success` - Whether the operation completed successfully.
    pub fn capture_file_operation(
        &self,
        operation: FileOpKind,
        path: String,
        destination: Option<String>,
        data: Option<Vec<u8>>,
        source: CaptureSource,
        success: bool,
    ) {
        if !self.config.file_operations {
            return;
        }

        let op = FileOperation {
            operation,
            path,
            destination,
            data,
            source,
            success,
        };

        if let Ok(mut ops) = self.file_operations.write() {
            ops.push(op);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.file_op_count = stats.file_op_count.saturating_add(1);
        }
    }

    /// Returns all captured file operations.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`FileOperation`] instances captured so far.
    /// Returns an empty vector if no operations were captured or if the lock
    /// cannot be acquired.
    pub fn file_operations(&self) -> Vec<FileOperation> {
        self.file_operations
            .read()
            .map(|o| o.clone())
            .unwrap_or_default()
    }

    /// Returns the number of captured file operations.
    ///
    /// # Returns
    ///
    /// The count of file operations captured, or 0 if the lock cannot be acquired.
    pub fn file_operation_count(&self) -> usize {
        self.file_operations.read().map_or(0, |o| o.len())
    }

    /// Captures a network operation.
    ///
    /// Records network activity including TCP/UDP connections, HTTP requests,
    /// DNS lookups, and data transfers. This helps identify command-and-control
    /// communication or data exfiltration patterns.
    ///
    /// If network operation capture is disabled in the configuration, this method
    /// returns immediately without capturing.
    ///
    /// # Arguments
    ///
    /// * `operation` - The [`NetworkOperation`] containing all operation details.
    pub fn capture_network_operation(&self, operation: NetworkOperation) {
        if !self.config.network_operations {
            return;
        }

        if let Ok(mut ops) = self.network_operations.write() {
            ops.push(operation);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.network_op_count = stats.network_op_count.saturating_add(1);
        }
    }

    /// Returns all captured network operations.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`NetworkOperation`] instances captured so far.
    /// Returns an empty vector if no operations were captured or if the lock
    /// cannot be acquired.
    pub fn network_operations(&self) -> Vec<NetworkOperation> {
        self.network_operations
            .read()
            .map_or_else(|_| Vec::new(), |o| o.clone())
    }

    /// Returns the number of captured network operations.
    ///
    /// # Returns
    ///
    /// The count of network operations captured, or 0 if the lock cannot be acquired.
    pub fn network_operation_count(&self) -> usize {
        self.network_operations.read().map_or(0, |o| o.len())
    }

    /// Takes a memory snapshot of all configured regions.
    ///
    /// Captures the current contents of all memory regions specified in
    /// [`CaptureConfig::memory_regions`]. Regions that cannot be read (e.g.,
    /// unmapped memory) are silently skipped.
    ///
    /// If no regions are configured or all configured regions fail to read,
    /// no snapshot is created.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The [`AddressSpace`] to read memory from.
    /// * `label` - A descriptive label for this snapshot (e.g., "after decryption").
    /// * `thread_id` - The thread that triggered the snapshot.
    /// * `instruction_count` - The global instruction count at snapshot time.
    pub fn snapshot_memory(
        &self,
        address_space: &AddressSpace,
        label: impl Into<String>,
        thread_id: ThreadId,
        instruction_count: u64,
    ) {
        let regions: Vec<MemoryRegionSnapshot> = self
            .config
            .memory_regions
            .iter()
            .filter_map(|range| {
                let base = range.start;
                // Safe: capture memory ranges fit in usize
                #[allow(clippy::cast_possible_truncation)]
                let size = range.end.saturating_sub(range.start) as usize;
                address_space
                    .read(base, size)
                    .ok()
                    .map(|data| MemoryRegionSnapshot {
                        base,
                        data,
                        label: format!("0x{:X}-0x{:X}", range.start, range.end),
                    })
            })
            .collect();

        if regions.is_empty() {
            return;
        }

        let snapshot = MemorySnapshot {
            label: label.into(),
            regions,
            instruction_count,
            thread_id,
        };

        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.push(snapshot);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.snapshot_count = stats.snapshot_count.saturating_add(1);
        }
    }

    /// Takes a memory snapshot of specific regions.
    ///
    /// Captures the current contents of the specified memory regions, independent
    /// of the regions configured in [`CaptureConfig`]. Useful for ad-hoc snapshots
    /// triggered by specific events during emulation.
    ///
    /// Regions that cannot be read (e.g., unmapped memory) are silently skipped.
    /// If all regions fail to read, no snapshot is created.
    ///
    /// # Arguments
    ///
    /// * `address_space` - The [`AddressSpace`] to read memory from.
    /// * `regions` - The memory regions to snapshot, as address ranges.
    /// * `label` - A descriptive label for this snapshot.
    /// * `thread_id` - The thread that triggered the snapshot.
    /// * `instruction_count` - The global instruction count at snapshot time.
    pub fn snapshot_regions(
        &self,
        address_space: &AddressSpace,
        regions: &[Range<u64>],
        label: impl Into<String>,
        thread_id: ThreadId,
        instruction_count: u64,
    ) {
        let region_snapshots: Vec<MemoryRegionSnapshot> = regions
            .iter()
            .filter_map(|range| {
                let base = range.start;
                // Safe: capture memory ranges fit in usize
                #[allow(clippy::cast_possible_truncation)]
                let size = range.end.saturating_sub(range.start) as usize;
                address_space
                    .read(base, size)
                    .ok()
                    .map(|data| MemoryRegionSnapshot {
                        base,
                        data,
                        label: format!("0x{:X}-0x{:X}", range.start, range.end),
                    })
            })
            .collect();

        if region_snapshots.is_empty() {
            return;
        }

        let snapshot = MemorySnapshot {
            label: label.into(),
            regions: region_snapshots,
            instruction_count,
            thread_id,
        };

        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.push(snapshot);
        }

        if let Ok(mut stats) = self.stats.write() {
            stats.snapshot_count = stats.snapshot_count.saturating_add(1);
        }
    }

    /// Returns all memory snapshots.
    ///
    /// # Returns
    ///
    /// A cloned vector of all [`MemorySnapshot`] instances captured so far.
    /// Returns an empty vector if no snapshots were taken or if the lock
    /// cannot be acquired.
    pub fn snapshots(&self) -> Vec<MemorySnapshot> {
        self.snapshots
            .read()
            .map_or_else(|_| Vec::new(), |s| s.clone())
    }

    /// Returns the number of memory snapshots.
    ///
    /// # Returns
    ///
    /// The count of snapshots taken, or 0 if the lock cannot be acquired.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.read().map_or(0, |s| s.len())
    }

    /// Returns aggregate statistics for all captured data.
    ///
    /// Provides a quick summary of capture activity without iterating through
    /// individual captured items.
    ///
    /// # Returns
    ///
    /// A clone of the current `CaptureStats`, or default stats if the lock
    /// cannot be acquired.
    pub fn stats(&self) -> CaptureStats {
        self.stats
            .read()
            .ok()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Checks if any data was captured.
    ///
    /// Returns `true` if at least one assembly, string, buffer, file operation,
    /// or network operation was captured. Does not consider memory snapshots.
    ///
    /// # Returns
    ///
    /// `true` if any data was captured, `false` if all collections are empty.
    pub fn has_captures(&self) -> bool {
        self.assembly_count() > 0
            || self.string_count() > 0
            || self.buffer_count() > 0
            || self.file_operation_count() > 0
            || self.network_operation_count() > 0
    }

    /// Clears all captured data and resets statistics.
    ///
    /// Removes all captured assemblies, strings, buffers, method returns,
    /// file operations, network operations, and memory snapshots. Also resets
    /// all statistics to zero.
    ///
    /// This is useful for reusing a capture context across multiple emulation
    /// runs or for freeing memory after processing captured data.
    ///
    /// # Thread Safety
    ///
    /// This method acquires write locks on all internal collections. If any
    /// lock cannot be acquired, that collection is not cleared.
    pub fn clear(&self) {
        if let Ok(mut assemblies) = self.assemblies.write() {
            assemblies.clear();
        }
        if let Ok(mut strings) = self.strings.write() {
            strings.clear();
        }
        if let Ok(mut buffers) = self.buffers.write() {
            buffers.clear();
        }
        if let Ok(mut returns) = self.method_returns.write() {
            returns.clear();
        }
        if let Ok(mut ops) = self.file_operations.write() {
            ops.clear();
        }
        if let Ok(mut ops) = self.network_operations.write() {
            ops.clear();
        }
        if let Ok(mut snapshots) = self.snapshots.write() {
            snapshots.clear();
        }
        if let Ok(mut stats) = self.stats.write() {
            *stats = CaptureStats::default();
        }
    }
}

impl Default for CaptureContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A default config must capture nothing, which is what `CaptureConfig` documents.
    ///
    /// Buffer capture is the kind most easily left running unconditionally, which would
    /// charge an operator who disabled capture for it anyway.
    #[test]
    fn default_config_captures_no_buffers() {
        let ctx = CaptureContext::with_config(CaptureConfig::default());

        ctx.capture_buffer(
            vec![0u8; 64],
            CaptureSource::new(Token::new(0x0600_0001), ThreadId::new(1), 0, 0),
            BufferSource::MarshalCopy { address: 0x1000 },
            "test",
        );

        assert_eq!(ctx.buffer_count(), 0, "capture was not enabled");
    }

    /// The item ceiling stops the loop-and-append pattern: emulated code allocates one array,
    /// then calls a crypto hook on it repeatedly, appending a full copy each time for a handful
    /// of instructions.
    #[test]
    fn buffer_capture_stops_at_the_item_ceiling() {
        let ctx = CaptureContext::with_config(CaptureConfig {
            buffers: true,
            max_items: 10,
            ..Default::default()
        });

        for _ in 0..1000 {
            ctx.capture_buffer(
                vec![0u8; 8],
                CaptureSource::new(Token::new(0x0600_0001), ThreadId::new(1), 0, 0),
                BufferSource::MarshalCopy { address: 0x1000 },
                "test",
            );
        }

        assert_eq!(ctx.buffer_count(), 10);
    }

    /// A few very large buffers must be bounded as well as many small ones.
    #[test]
    fn buffer_capture_stops_at_the_byte_ceiling() {
        let ctx = CaptureContext::with_config(CaptureConfig {
            buffers: true,
            max_items: usize::MAX,
            max_total_bytes: 4096,
            ..Default::default()
        });

        for _ in 0..100 {
            ctx.capture_buffer(
                vec![0u8; 1024],
                CaptureSource::new(Token::new(0x0600_0001), ThreadId::new(1), 0, 0),
                BufferSource::MarshalCopy { address: 0x1000 },
                "test",
            );
        }

        assert_eq!(
            ctx.buffer_count(),
            4,
            "only what fits in the byte budget is retained"
        );
    }

    #[test]
    fn test_capture_context_creation() {
        let ctx = CaptureContext::new();
        assert!(!ctx.has_captures());
        assert_eq!(ctx.assembly_count(), 0);
        assert_eq!(ctx.string_count(), 0);
    }

    #[test]
    fn test_capture_assembly() {
        let ctx = CaptureContext::new();

        ctx.capture_assembly_load_bytes(
            vec![0x4D, 0x5A, 0x90, 0x00],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0x10,
            100,
        );

        assert_eq!(ctx.assembly_count(), 1);
        assert!(ctx.has_captures());

        let assemblies = ctx.assemblies();
        assert_eq!(assemblies.len(), 1);
        assert_eq!(assemblies[0].data, vec![0x4D, 0x5A, 0x90, 0x00]);
        assert_eq!(assemblies[0].load_method, AssemblyLoadMethod::LoadBytes);
    }

    #[test]
    fn test_capture_string() {
        let ctx = CaptureContext::new();

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0x20, 200);
        ctx.capture_string("decrypted secret".to_string(), source);

        assert_eq!(ctx.string_count(), 1);

        let strings = ctx.strings();
        assert_eq!(strings[0].value, "decrypted secret");
    }

    #[test]
    fn test_capture_disabled_by_config() {
        let ctx = CaptureContext::with_config(CaptureConfig {
            assemblies: false,
            strings: false,
            ..Default::default()
        });

        ctx.capture_assembly_load_bytes(
            vec![0x4D, 0x5A],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0, 0);
        ctx.capture_string("test".to_string(), source);

        assert_eq!(ctx.assembly_count(), 0);
        assert_eq!(ctx.string_count(), 0);
    }

    #[test]
    fn test_capture_buffer() {
        let ctx = CaptureContext::new();

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0x30, 300);
        ctx.capture_buffer(
            vec![0x01, 0x02, 0x03, 0x04],
            source,
            BufferSource::MarshalCopy { address: 0x10000 },
            "decrypted data",
        );

        assert_eq!(ctx.buffer_count(), 1);

        let buffers = ctx.buffers();
        assert_eq!(buffers[0].data, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(buffers[0].label, "decrypted data");
    }

    #[test]
    fn test_capture_file_operation() {
        let ctx = CaptureContext::new();

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0, 0);
        ctx.capture_file_operation(
            FileOpKind::Write,
            "C:\\temp\\malware.exe".to_string(),
            None,
            Some(vec![0x4D, 0x5A]),
            source,
            true,
        );

        assert_eq!(ctx.file_operation_count(), 1);

        let ops = ctx.file_operations();
        assert_eq!(ops[0].operation, FileOpKind::Write);
        assert_eq!(ops[0].path, "C:\\temp\\malware.exe");
    }

    #[test]
    fn test_capture_stats() {
        let ctx = CaptureContext::new();

        ctx.capture_assembly_load_bytes(
            vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0, 0);
        ctx.capture_string("test".to_string(), source.clone());
        ctx.capture_string("test2".to_string(), source);

        let stats = ctx.stats();
        assert_eq!(stats.assembly_bytes, 6);
        assert_eq!(stats.string_count, 2);
    }

    #[test]
    fn test_clear() {
        let ctx = CaptureContext::new();

        ctx.capture_assembly_load_bytes(
            vec![0x4D, 0x5A],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        assert!(ctx.has_captures());

        ctx.clear();

        assert!(!ctx.has_captures());
        assert_eq!(ctx.assembly_count(), 0);
    }

    #[test]
    fn test_assemblies_only_preset() {
        let ctx = CaptureContext::assemblies_only();

        ctx.capture_assembly_load_bytes(
            vec![0x4D, 0x5A],
            Token::new(0x06000001),
            ThreadId::MAIN,
            0,
            0,
        );

        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0, 0);
        ctx.capture_string("test".to_string(), source);

        // Assembly captured, string not captured (disabled by config)
        assert_eq!(ctx.assembly_count(), 1);
        assert_eq!(ctx.string_count(), 0);
    }
}
