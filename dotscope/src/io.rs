//! Readers and writers for the binary encodings .NET metadata uses.
//!
//! Little- and big-endian integers of any width that implements [`CilIO`](crate::io::CilIO),
//! read from a slice at a fixed or advancing offset and written to a buffer;
//! the ECMA-335 compressed integers of II.23.2, signed and unsigned, with the
//! size an unsigned one takes; and the string forms blobs carry. These are the
//! codecs the metadata parsers and the assembly writer are built on, for code
//! that reads or writes a blob or a heap directly.
//!
//! # Examples
//!
//! ```rust
//! use dotscope::io::{compressed_uint_size, read_compressed_uint, write_compressed_uint};
//!
//! let mut buffer = Vec::new();
//! write_compressed_uint(300, &mut buffer)?;
//! assert_eq!(buffer, [0x81, 0x2C]);
//! assert_eq!(compressed_uint_size(300), 2);
//!
//! let mut offset = 0;
//! assert_eq!(read_compressed_uint(&buffer, &mut offset)?, 300);
//! assert_eq!(offset, 2);
//! # Ok::<(), dotscope::Error>(())
//! ```

pub use crate::utils::{
    compressed_uint_size, read_be, read_be_at, read_be_at_dyn, read_compressed_int,
    read_compressed_int_at, read_compressed_uint, read_compressed_uint_at, read_le, read_le_at,
    read_le_at_dyn, write_7bit_encoded_int, write_be, write_be_at, write_be_at_dyn,
    write_compressed_int, write_compressed_uint, write_le, write_le_at, write_le_at_dyn,
    write_prefixed_string_utf16, write_prefixed_string_utf8, write_string_at, write_string_utf8,
    CilIO,
};
#[cfg(feature = "deobfuscation")]
pub use crate::utils::{decode_utf16le, read_packed_len};
