//! General utility functions for the dotscope framework.
//!
//! This module consolidates utility functions from across the framework into a central,
//! reusable location. It provides fundamental operations needed by multiple components,
//! promoting code reuse and maintainability.
//!
//! # Module Organization
//!
//! The utilities are organized by functional area:
//!
//! - [`crate::utils::compression`] - ECMA-335 compressed integer encoding/decoding
//! - [`crate::utils::alignment`] - Memory alignment operations for binary layouts
//! - [`crate::utils::heap_calc`] - Metadata heap size calculation functions
//!
//! # Design Principles
//!
//! - **Framework-Wide Reusability**: Functions can be used across all modules
//! - **High Performance**: Optimized for frequent usage throughout the pipeline
//! - **ECMA-335 Compliance**: All utilities maintain strict .NET specification compliance
//! - **Thread Safety**: All functions are thread-safe with immutable operations
//! - **Comprehensive Testing**: Extensive unit tests ensure reliability
//!
//! # Examples
//!
//! ## Compressed Integer Encoding
//!
//! ```no_run
//! use dotscope::io::write_compressed_uint;
//! use dotscope::io::compressed_uint_size;
//!
//! let mut buffer = Vec::new();
//! write_compressed_uint(300, &mut buffer)?;
//! assert_eq!(compressed_uint_size(300), buffer.len() as u64);
//! ```
//!
//! ## Memory Alignment
//!
//! The `examples::module_example` test in this module runs this example.

mod alignment;
#[cfg(feature = "emulation")]
mod base64;
mod compression;
mod crypto;
#[cfg(feature = "emulation")]
mod decompress;
mod dot;
mod enums;
mod hash;
mod heap_calc;
mod io;
mod lazylist;
#[cfg(feature = "emulation")]
mod lebytes;
mod math;
mod parallel;
mod rowlist;
mod synchronization;
mod text;
mod visitedmap;

pub use alignment::align_to;
#[cfg(feature = "emulation")]
pub use base64::{base64_decode, base64_encode};
pub use compression::compressed_uint_size;
#[cfg(all(feature = "deobfuscation", feature = "legacy-crypto"))]
pub(crate) use crypto::derive_key_iv;
#[cfg(all(feature = "legacy-crypto", feature = "emulation"))]
pub(crate) use crypto::derive_pbkdf1_key;
#[cfg(feature = "deobfuscation")]
pub(crate) use crypto::CryptoParameters;
#[cfg(feature = "emulation")]
pub(crate) use crypto::{
    apply_crypto_transform, derive_pbkdf2_key, pbkdf2_work, rsa_verify_work, verify_rsa_pkcs1v15,
};
#[cfg(feature = "emulation")]
pub(crate) use crypto::{compute_hmac_sha256, compute_hmac_sha512};
#[cfg(feature = "legacy-crypto")]
pub(crate) use crypto::{compute_md5, compute_sha1};
pub(crate) use crypto::{compute_sha256, compute_sha384, compute_sha512};
#[cfg(feature = "deobfuscation")]
#[allow(unused_imports)]
pub(crate) use decompress::{
    decompress_confuserex_lzma, decompress_confuserex_lzma_limited, is_confuserex_lzma,
};
#[cfg(feature = "emulation")]
#[allow(unused_imports)]
pub(crate) use decompress::{
    decompress_deflate, decompress_deflate_limited, decompress_gzip, decompress_gzip_limited,
    MAX_DECOMPRESSED_BYTES,
};
pub use dot::escape_dot;
pub use enums::EnumUtils;
pub use hash::{hash_blob, hash_guid, hash_string};
pub use heap_calc::calculate_table_row_size;
#[cfg(feature = "deobfuscation")]
pub use io::{decode_utf16le, read_packed_len};
#[allow(unused_imports)]
pub use io::{
    read_be, read_be_at, read_be_at_dyn, read_compressed_int, read_compressed_int_at,
    read_compressed_uint, read_compressed_uint_at, read_le, read_le_at, read_le_at_dyn,
    write_7bit_encoded_int, write_be, write_be_at, write_be_at_dyn, write_compressed_int,
    write_compressed_uint, write_le, write_le_at, write_le_at_dyn, write_prefixed_string_utf16,
    write_prefixed_string_utf8, write_string_at, write_string_utf8, CilIO,
};
pub use lazylist::LazyList;
#[allow(unused_imports)]
pub use lazylist::LazyListIter;
#[cfg(feature = "emulation")]
pub use lebytes::LeBytes;
#[cfg(feature = "emulation")]
pub use math::to_i32_saturating;
pub use math::to_u32;
pub(crate) use parallel::TryForEachInOrder;
pub use rowlist::RowList;
#[allow(unused_imports)]
pub use rowlist::RowListIter;
pub use synchronization::FailFastBarrier;
pub(crate) use text::truncate_chars;
pub use visitedmap::VisitedMap;

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{utils::alignment::align_to_4_bytes, Result};

    #[test]
    fn module_example() -> Result<()> {
        assert_eq!(align_to_4_bytes(17), 20);
        assert_eq!(align_to(1000, 512), 1024);
        Ok(())
    }
}
