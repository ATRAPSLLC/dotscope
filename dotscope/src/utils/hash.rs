//! Hash functions for content deduplication.
//!
//! This module provides simple hash functions used throughout the framework
//! for detecting duplicate content in metadata heaps during assembly writing.
//!
//! # Performance
//!
//! These functions use `FxHasher` from `rustc-hash` for better performance
//! compared to the standard library's `DefaultHasher`. FxHasher is optimized
//! for small keys which is ideal for heap deduplication.
//!
//! # Usage
//!
//! These functions are primarily used by:
//! - [`crate::HeapChanges`] for tracking heap modifications
//! - [`crate::cilassembly::writer::heaps`] for deduplication during heap streaming
//!
use std::hash::{Hash, Hasher};

use rustc_hash::FxHasher;

/// Computes a simple hash for string content (for deduplication detection).
///
/// Hashes the UTF-8 bytes of the string to ensure consistency with how strings
/// are stored in the .NET #Strings heap (null-terminated UTF-8 bytes).
///
/// # Arguments
///
/// * `s` - The string to hash
///
/// # Returns
///
/// A 64-bit hash value suitable for deduplication comparisons.
#[must_use]
pub fn hash_string(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    // Hash the bytes, not the str, for consistency with heap scanning
    s.as_bytes().hash(&mut hasher);
    hasher.finish()
}

/// Computes a simple hash for blob content (for deduplication detection).
///
/// Used for deduplicating entries in the .NET #Blob heap.
///
/// # Arguments
///
/// * `data` - The blob data to hash
///
/// # Returns
///
/// A 64-bit hash value suitable for deduplication comparisons.
#[must_use]
pub fn hash_blob(data: &[u8]) -> u64 {
    let mut hasher = FxHasher::default();
    data.hash(&mut hasher);
    hasher.finish()
}

/// Computes a simple hash for GUID content (for deduplication detection).
///
/// Used for deduplicating entries in the .NET #GUID heap.
///
/// # Arguments
///
/// * `guid` - The 16-byte GUID to hash
///
/// # Returns
///
/// A 64-bit hash value suitable for deduplication comparisons.
#[must_use]
pub fn hash_guid(guid: &[u8; 16]) -> u64 {
    let mut hasher = FxHasher::default();
    guid.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_string_deterministic() {
        let hash1 = hash_string("hello");
        let hash2 = hash_string("hello");
        let hash3 = hash_string("world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_hash_string_empty() {
        let hash = hash_string("");
        // Empty string should produce a consistent hash
        assert_eq!(hash, hash_string(""));
    }

    #[test]
    fn test_hash_blob_deterministic() {
        let blob1 = hash_blob(&[1, 2, 3]);
        let blob2 = hash_blob(&[1, 2, 3]);
        let blob3 = hash_blob(&[4, 5, 6]);

        assert_eq!(blob1, blob2);
        assert_ne!(blob1, blob3);
    }

    #[test]
    fn test_hash_blob_empty() {
        let hash = hash_blob(&[]);
        assert_eq!(hash, hash_blob(&[]));
    }

    #[test]
    fn test_hash_guid_deterministic() {
        let guid1 = [1u8; 16];
        let guid2 = [1u8; 16];
        let guid3 = [2u8; 16];

        assert_eq!(hash_guid(&guid1), hash_guid(&guid2));
        assert_ne!(hash_guid(&guid1), hash_guid(&guid3));
    }

    #[test]
    fn test_hash_guid_zero() {
        let zero_guid = [0u8; 16];
        assert_eq!(hash_guid(&zero_guid), hash_guid(&zero_guid));
    }
}
