//! Data types for captured emulation results.
//!
//! This module defines all data structures used to represent captured data
//! during .NET emulation. Each captured item includes metadata about where
//! and when it was captured, enabling correlation with the execution flow.
//!
//! # Structure
//!
//! Captured items are organized by type:
//!
//! - [`CapturedAssembly`]: Dynamically loaded assemblies
//! - [`CapturedString`]: Decrypted or generated strings
//! - [`CapturedBuffer`]: Raw byte buffers from memory operations
//! - [`CapturedMethodReturn`]: Return values from monitored methods
//! - [`FileOperation`]: File system operations
//! - [`NetworkOperation`]: Network operations
//! - [`MemorySnapshot`]: Point-in-time memory captures
//!
//! All captured items include a [`CaptureSource`] that identifies exactly
//! where in the emulation the capture occurred.

use std::{net::SocketAddr, ops::Range};

use crate::{emulation::ThreadId, metadata::token::Token};

/// Source location identifying where a capture occurred during emulation.
///
/// Every captured item includes a `CaptureSource` that records the exact location
/// in the emulation where the capture occurred. This enables correlation between
/// captured data and the execution flow, helping to understand which code path
/// produced each captured item.
///
/// # Fields
///
/// The source location is identified by four components:
/// - The method token (which method was executing)
/// - The thread ID (which emulation thread)
/// - The IL offset within the method
/// - The global instruction count (for ordering captures chronologically)
///
/// # Examples
///
/// ```no_run
/// use dotscope::emulation::CaptureSource;
/// use dotscope::emulation::ThreadId;
/// use dotscope::metadata::token::Token;
///
/// let source = CaptureSource::new(
///     Token::new(0x06000001),  // MethodDef token
///     ThreadId::MAIN,          // Main thread
///     0x0010,                  // IL offset
///     12345,                   // Instruction count
/// );
/// ```
#[derive(Clone, Debug)]
pub struct CaptureSource {
    /// The method token where the capture occurred.
    ///
    /// This is typically a MethodDef token (0x06xxxxxx) identifying the
    /// method that was executing when the capture was triggered.
    pub method: Token,

    /// The thread that performed the captured operation.
    ///
    /// Enables distinguishing captures from different emulation threads
    /// in multi-threaded emulation scenarios.
    pub thread_id: ThreadId,

    /// The IL instruction offset within the method.
    ///
    /// Points to the specific instruction that triggered or is associated
    /// with the capture, relative to the start of the method body.
    pub offset: u32,

    /// The global instruction count at capture time.
    ///
    /// A monotonically increasing counter that enables chronological
    /// ordering of captures across the entire emulation run.
    pub instruction_count: u64,
}

impl CaptureSource {
    /// Creates a new capture source with the specified location information.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token where the capture occurred.
    /// * `thread_id` - The thread that performed the operation.
    /// * `offset` - The IL instruction offset within the method.
    /// * `instruction_count` - The global instruction count at capture time.
    ///
    /// # Returns
    ///
    /// A new `CaptureSource` with the specified values.
    #[must_use]
    pub fn new(method: Token, thread_id: ThreadId, offset: u32, instruction_count: u64) -> Self {
        Self {
            method,
            thread_id,
            offset,
            instruction_count,
        }
    }
}

/// A .NET assembly captured during dynamic loading.
///
/// Represents an assembly that was loaded at runtime via `Assembly.Load` or
/// similar methods. This is the primary mechanism for extracting packed or
/// encrypted assemblies from loaders/crypters.
///
/// # Use Cases
///
/// - Extracting payloads from packed executables
/// - Recovering assemblies decrypted at runtime
/// - Capturing dynamically generated assemblies
///
/// # Examples
///
/// ```no_run
/// # let ctx = dotscope::emulation::CaptureContext::new();
/// for assembly in ctx.assemblies() {
///     // Check if it's a valid PE/COFF file
///     if assembly.data.starts_with(b"MZ") {
///         // Save to disk for analysis
///         std::fs::write(
///             format!("extracted_{}.dll", assembly.name.as_deref().unwrap_or("unknown")),
///             &assembly.data
///         )?;
///     }
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Clone, Debug)]
pub struct CapturedAssembly {
    /// The raw assembly bytes in PE/COFF format.
    ///
    /// This is the complete assembly image as passed to `Assembly.Load`.
    /// Typically starts with the "MZ" DOS header signature.
    pub data: Vec<u8>,

    /// The location where this assembly was captured.
    pub source: CaptureSource,

    /// The method used to load the assembly.
    ///
    /// Indicates which .NET API was used for loading, which may affect
    /// how the assembly is resolved and loaded.
    pub load_method: AssemblyLoadMethod,

    /// The assembly name, if determinable.
    ///
    /// May be extracted from the assembly's metadata or inferred from
    /// the loading context. `None` if the name could not be determined.
    pub name: Option<String>,
}

/// The method used to load an assembly dynamically.
///
/// Different loading methods have different semantics in .NET regarding
/// assembly resolution, binding context, and security. This enum tracks
/// which specific API was used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssemblyLoadMethod {
    /// `Assembly.Load(byte[])` - Load from raw bytes.
    ///
    /// The most common method for loading packed/encrypted assemblies.
    /// The assembly is loaded into the default load context.
    LoadBytes,

    /// `Assembly.Load(byte[], byte[])` - Load from bytes with debug symbols.
    ///
    /// Includes a PDB symbol file for debugging. The second byte array
    /// contains the debug symbols.
    LoadBytesWithSymbols,

    /// `Assembly.LoadFrom(string)` - Load from a file path.
    ///
    /// Loads the assembly from the specified file path into the
    /// LoadFrom context.
    LoadFrom,

    /// `Assembly.LoadFile(string)` - Load from a file path (no context).
    ///
    /// Loads the assembly from the specified file path without adding
    /// it to any load context.
    LoadFile,

    /// `Assembly.Load(AssemblyName)` - Load by assembly name.
    ///
    /// Loads the assembly by searching for it using the standard
    /// assembly resolution process.
    LoadByName,

    /// `Assembly.Load(string)` - Load by display name string.
    ///
    /// Parses the string as an assembly display name and loads it
    /// using standard resolution.
    LoadByString,

    /// `AppDomain.Load` - Load into an AppDomain.
    ///
    /// Assembly was loaded via AppDomain.Load or similar AppDomain
    /// loading methods.
    AppDomainLoad,

    /// Unknown or unrecognized loading method.
    ///
    /// Used when the loading method could not be determined.
    Unknown,
}

/// A string captured during emulation.
///
/// Represents a string value that was decrypted, decoded, or dynamically
/// generated at runtime. String obfuscation is one of the most common
/// protection techniques, and capturing decrypted strings reveals
/// configuration, URLs, registry keys, and other sensitive data.
///
/// # Use Cases
///
/// - Extracting obfuscated configuration strings
/// - Revealing C2 server URLs or IP addresses
/// - Finding file paths and registry keys
/// - Discovering API names used for dynamic resolution
///
/// # Examples
///
/// ```
/// # let ctx = dotscope::emulation::CaptureContext::new();
/// for string in ctx.strings() {
///     // Look for URLs
///     if string.value.starts_with("http") {
///         println!("Found URL: {}", string.value);
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct CapturedString {
    /// The decrypted or generated string value.
    pub value: String,

    /// The location where this string was captured.
    pub source: CaptureSource,

    /// The original encrypted data, if available.
    ///
    /// Contains the raw bytes that were decrypted to produce this string.
    /// Useful for understanding the encryption scheme used.
    pub encrypted_data: Option<Vec<u8>>,

    /// The decryption key, if determinable.
    ///
    /// Contains the key or seed used to decrypt the string.
    /// May be a single byte, an integer, or a full key array.
    pub key: Option<Vec<u8>>,
}

/// Describes the origin of a captured buffer.
///
/// Provides context about how and where a buffer was created or written,
/// enabling better understanding of what the data represents.
#[derive(Clone, Debug)]
pub enum BufferSource {
    /// Buffer written via `Marshal.Copy` or similar interop methods.
    ///
    /// `Marshal.Copy` is commonly used to copy data between managed and
    /// unmanaged memory, often for decrypting or unpacking data.
    MarshalCopy {
        /// The destination memory address where the buffer was written.
        address: u64,
    },

    /// Buffer written via direct memory write operations.
    ///
    /// Includes writes via `Marshal.WriteByte`, `Marshal.WriteInt32`,
    /// or direct unmanaged memory manipulation.
    DirectWrite {
        /// The destination memory address where the buffer was written.
        address: u64,
    },

    /// Output from a cryptographic transform.
    ///
    /// The buffer is the result of a `ICryptoTransform.TransformBlock`
    /// or `TransformFinalBlock` operation.
    CryptoTransform {
        /// The name of the cryptographic algorithm (e.g., "AES", "DES").
        algorithm: String,
    },

    /// Return value from a method call.
    ///
    /// The buffer was returned as a `byte[]` from a method.
    MethodReturn {
        /// The method token that returned this buffer.
        method: Token,
    },

    /// Captured from a specific memory region.
    ///
    /// The buffer was explicitly captured from a monitored memory region.
    MemoryRegion {
        /// The memory address range that was captured.
        region: Range<u64>,
    },

    /// Unknown or unspecified source.
    Unknown,
}

/// A raw byte buffer captured during emulation.
///
/// Represents arbitrary binary data captured from memory operations,
/// crypto transforms, or method returns. May contain decrypted payloads,
/// configuration data, or other interesting binary content.
///
/// # Use Cases
///
/// - Capturing decrypted data before it's processed
/// - Extracting embedded resources or payloads
/// - Monitoring memory writes for suspicious patterns
#[derive(Clone, Debug)]
pub struct CapturedBuffer {
    /// The raw buffer data.
    pub data: Vec<u8>,

    /// The location where this buffer was captured.
    pub source: CaptureSource,

    /// Details about the buffer's origin.
    pub buffer_source: BufferSource,

    /// A descriptive label for this buffer.
    ///
    /// User-provided or auto-generated description of what this
    /// buffer represents (e.g., "AES decryption output").
    pub label: String,
}

/// A return value captured from a monitored method call.
///
/// Captures the return value from specific methods configured for monitoring.
/// This enables extracting computed values without modifying program flow,
/// useful for understanding what values are produced by obfuscated code.
///
/// # Value Representation
///
/// The return value is stored in multiple formats to accommodate different types:
/// - `value_bytes`: Raw serialized bytes for any type
/// - `value_string`: String representation for string/char types
/// - `value_numeric`: Numeric representation for integer types
///
/// The appropriate field is populated based on the method's return type.
#[derive(Clone, Debug)]
pub struct CapturedMethodReturn {
    /// The method token whose return value was captured.
    pub method: Token,

    /// Human-readable method signature.
    ///
    /// Format: `Namespace.Class::MethodName(ParamTypes)` for display purposes.
    pub signature: String,

    /// The return value as serialized bytes.
    ///
    /// Contains the raw byte representation of the return value,
    /// useful for complex types or when the exact type is unknown.
    pub value_bytes: Option<Vec<u8>>,

    /// The return value as a string.
    ///
    /// Populated when the method returns a `System.String` or `System.Char`.
    pub value_string: Option<String>,

    /// The return value as a signed 64-bit integer.
    ///
    /// Populated when the method returns a numeric type (int, long, byte, etc.).
    /// The value is sign-extended or zero-extended as appropriate.
    pub value_numeric: Option<i64>,

    /// The location where this return value was captured.
    pub source: CaptureSource,
}

/// The type of file system operation performed.
///
/// Categorizes file operations to enable filtering and analysis of
/// file system access patterns during emulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileOpKind {
    /// Read data from a file.
    Read,

    /// Write data to a file.
    Write,

    /// Delete a file.
    Delete,

    /// Create a new file.
    Create,

    /// Open an existing file.
    Open,

    /// Close a file handle.
    Close,

    /// Move or rename a file.
    Move,

    /// Copy a file to a new location.
    Copy,

    /// Create a directory.
    CreateDirectory,

    /// Delete a directory.
    DeleteDirectory,

    /// Enumerate files in a directory.
    EnumerateDirectory,

    /// Check if a file or directory exists.
    Exists,

    /// Retrieve file attributes.
    GetAttributes,

    /// Set file attributes.
    SetAttributes,
}

/// A file system operation captured during emulation.
///
/// Records file system access including reads, writes, deletions, and
/// directory operations. This reveals how the program interacts with
/// the file system, which is important for understanding behavior like
/// dropping files, reading configuration, or modifying system files.
///
/// # Use Cases
///
/// - Detecting file drops (malware installation)
/// - Finding configuration file locations
/// - Identifying persistence mechanisms
/// - Tracking data exfiltration to files
#[derive(Clone, Debug)]
pub struct FileOperation {
    /// The type of file operation.
    pub operation: FileOpKind,

    /// The primary file or directory path.
    ///
    /// For most operations, this is the target path. For move/copy
    /// operations, this is the source path.
    pub path: String,

    /// The destination path for move/copy operations.
    ///
    /// Only populated for `Move` and `Copy` operations.
    pub destination: Option<String>,

    /// Data read from or written to the file.
    ///
    /// Contains the actual bytes for `Read` and `Write` operations.
    /// May be `None` if data capture was not enabled or the data
    /// was too large to capture.
    pub data: Option<Vec<u8>>,

    /// The location where this operation was captured.
    pub source: CaptureSource,

    /// Whether the operation completed successfully.
    ///
    /// `true` if the operation succeeded, `false` if it failed.
    pub success: bool,
}

/// The type of network operation performed.
///
/// Categorizes network operations to enable filtering and analysis of
/// network communication patterns during emulation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkOpKind {
    /// Establish a TCP connection to a remote host.
    TcpConnect,

    /// Begin listening for TCP connections.
    TcpListen,

    /// Accept an incoming TCP connection.
    TcpAccept,

    /// Bind a UDP socket to a local port.
    UdpBind,

    /// Send data over a socket.
    Send,

    /// Receive data from a socket.
    Receive,

    /// HTTP GET request.
    HttpGet,

    /// HTTP POST request.
    HttpPost,

    /// HTTP PUT request.
    HttpPut,

    /// HTTP DELETE request.
    HttpDelete,

    /// DNS name resolution.
    DnsLookup,

    /// Close a socket connection.
    Close,
}

/// A network operation captured during emulation.
///
/// Records network activity including TCP/UDP operations, HTTP requests,
/// DNS lookups, and data transfers. This reveals network communication
/// patterns that may indicate command-and-control activity, data
/// exfiltration, or downloading additional payloads.
///
/// # Use Cases
///
/// - Identifying C2 (command-and-control) servers
/// - Detecting data exfiltration attempts
/// - Finding URLs for additional payload downloads
/// - Understanding network-based persistence mechanisms
///
/// # Examples
///
/// ```
/// use dotscope::emulation::NetworkOpKind;
/// # let ctx = dotscope::emulation::CaptureContext::new();
///
/// for op in ctx.network_operations() {
///     match op.operation {
///         NetworkOpKind::HttpGet | NetworkOpKind::HttpPost => {
///             if let Some(url) = &op.url {
///                 println!("HTTP request to: {}", url);
///             }
///         }
///         NetworkOpKind::TcpConnect => {
///             if let Some(remote) = &op.remote {
///                 println!("TCP connection to: {:?}", remote);
///             }
///         }
///         _ => {}
///     }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct NetworkOperation {
    /// The type of network operation.
    pub operation: NetworkOpKind,

    /// The remote endpoint for this operation.
    ///
    /// Populated for connect, send, and HTTP operations.
    pub remote: Option<NetworkEndpoint>,

    /// The local endpoint for this operation.
    ///
    /// Populated for bind and listen operations.
    pub local: Option<NetworkEndpoint>,

    /// The URL for HTTP operations.
    ///
    /// Contains the full URL including scheme, host, path, and query.
    pub url: Option<String>,

    /// HTTP headers for HTTP operations.
    ///
    /// Each tuple contains (header_name, header_value).
    pub headers: Option<Vec<(String, String)>>,

    /// Data sent or received.
    ///
    /// Contains request body for sends or response body for receives.
    /// May be `None` if data capture was not enabled.
    pub data: Option<Vec<u8>>,

    /// The location where this operation was captured.
    pub source: CaptureSource,

    /// Whether the operation completed successfully.
    pub success: bool,
}

/// A network endpoint (address and port).
///
/// Represents either a resolved socket address or a hostname with port,
/// depending on whether DNS resolution has occurred.
#[derive(Clone, Debug)]
pub enum NetworkEndpoint {
    /// A resolved IP address and port.
    Socket(SocketAddr),

    /// An unresolved hostname and port.
    Host {
        /// The hostname (domain name).
        hostname: String,
        /// The port number.
        port: u16,
    },
}

/// A point-in-time snapshot of memory regions.
///
/// Captures the contents of configured memory regions at a specific point
/// during emulation. Memory snapshots enable tracking how memory contents
/// evolve over time, which is useful for understanding decryption routines,
/// self-modifying code, or staged payload deployment.
///
/// # Use Cases
///
/// - Tracking in-place decryption of code or data
/// - Monitoring memory regions for payload extraction
/// - Debugging self-modifying code patterns
/// - Comparing memory state before/after specific operations
#[derive(Clone, Debug)]
pub struct MemorySnapshot {
    /// A descriptive label for this snapshot.
    ///
    /// Examples: "before decryption", "after XOR loop", "at entry point"
    pub label: String,

    /// The captured memory regions.
    ///
    /// Contains the data from each configured region at snapshot time.
    pub regions: Vec<MemoryRegionSnapshot>,

    /// The global instruction count when the snapshot was taken.
    ///
    /// Enables chronological ordering and correlation with other events.
    pub instruction_count: u64,

    /// The thread that triggered the snapshot.
    pub thread_id: ThreadId,
}

/// A single memory region within a snapshot.
///
/// Contains the raw bytes captured from a specific memory address range.
#[derive(Clone, Debug)]
pub struct MemoryRegionSnapshot {
    /// The base address of this region.
    pub base: u64,

    /// The captured bytes from this region.
    pub data: Vec<u8>,

    /// A descriptive label for this region.
    ///
    /// Often formatted as "0x{base:X}-0x{end:X}" to show the address range.
    pub label: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_source() {
        let source = CaptureSource::new(Token::new(0x06000001), ThreadId::MAIN, 0x10, 1000);

        assert_eq!(source.method, Token::new(0x06000001));
        assert_eq!(source.thread_id, ThreadId::MAIN);
        assert_eq!(source.offset, 0x10);
        assert_eq!(source.instruction_count, 1000);
    }

    #[test]
    fn test_assembly_load_method() {
        assert_ne!(AssemblyLoadMethod::LoadBytes, AssemblyLoadMethod::LoadFrom);
        assert_eq!(AssemblyLoadMethod::LoadBytes, AssemblyLoadMethod::LoadBytes);
    }

    #[test]
    fn test_file_op_kind() {
        assert_ne!(FileOpKind::Read, FileOpKind::Write);
        assert_eq!(FileOpKind::Create, FileOpKind::Create);
    }

    #[test]
    fn test_network_endpoint() {
        let socket = NetworkEndpoint::Socket("127.0.0.1:8080".parse().unwrap());
        let host = NetworkEndpoint::Host {
            hostname: "example.com".to_string(),
            port: 443,
        };

        match socket {
            NetworkEndpoint::Socket(addr) => assert_eq!(addr.port(), 8080),
            _ => panic!("Expected Socket variant"),
        }

        match host {
            NetworkEndpoint::Host { hostname, port } => {
                assert_eq!(hostname, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected Host variant"),
        }
    }
}
