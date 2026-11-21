//! Utility macros for synchronization and threading.
//!
//! This module provides convenience macros for working with Rust's synchronization primitives
//! like [`std::sync::Mutex`], [`std::sync::RwLock`], and [`std::sync::Arc`]. These macros
//! simplify common patterns when working with shared data in concurrent contexts and are
//! primarily used internally by the metadata loading system.
//!
//! # Architecture
//!
//! The macros are organized into three categories:
//! - **Basic Locking**: Direct lock acquisition with panic handling (`lock!`, `read_lock!`, `write_lock!`)
//! - **Functional Style**: Execute closures with automatic lock management (`with_read!`, `with_write!`)
//! - **Collection Operations**: Specialized operations for working with collections of locked data (`map_get_read!`, `for_each_read!`)
//!
//! All macros follow a consistent pattern of automatic panic handling for lock poisoning,
//! treating poisoned locks as unrecoverable errors in the context of metadata analysis.
//!
//! # Key Components
//!
//! - `lock!` - Acquire a mutex lock with panic on failure
//! - `read_lock!` - Acquire a read lock on an `RwLock` with panic on failure
//! - `write_lock!` - Acquire a write lock on an `RwLock` with panic on failure
//! - `with_read!` - Execute a closure with a read lock
//! - `with_write!` - Execute a closure with a write lock
//! - `map_get_read!` - Get an item from a map and acquire a read lock
//! - `for_each_read!` - Iterate over a collection with read locks
//!
//! # Usage Examples
//!
//! ## Basic Locking
//!
//! The `examples::module_2_example` test in this module runs this example.
//!
//! ## Functional Style
//!
//! The `examples::module_example` test in this module runs this example.
//!
//! # Error Handling
//!
//! All macros in this module use panic-based error handling for lock poisoning:
//! - **Lock Poisoning**: When a thread panics while holding a lock, all macros will panic with descriptive messages
//! - **Timeout**: No timeout handling is provided; locks are acquired with indefinite blocking
//!
//! This design is appropriate for the metadata loading context where lock poisoning indicates
//! an unrecoverable error in the parsing process.
//!
//! # Thread Safety
//!
//! The macros themselves do not impose additional thread safety requirements beyond
//! the underlying synchronization primitives. All operations preserve the thread safety
//! guarantees of the wrapped [`std::sync::Mutex`] and [`std::sync::RwLock`] types.
//! All macros are thread-safe as they operate on already thread-safe synchronization
//! primitives and do not introduce additional shared state.
//!
//! # Integration
//!
//! These macros integrate primarily with:
//! - [`CilObject`](crate::CilObject) loading - Metadata loading system for concurrent parsing
//! - [`crate::metadata::tables`] - Shared access to metadata table structures
//! - Internal caching systems that require synchronized access to parsed data

#![allow(unused_macros)]

/// Unwrap a `Result` inside a BCL hook, converting errors to `PreHookResult::Error`.
///
/// BCL hooks return `PreHookResult`, not `Result`. This macro bridges the gap
/// by converting any `Err(e)` into `PreHookResult::Error(format!("{e}"))` with
/// an early return, while unwrapping `Ok(val)` for normal flow.
///
/// # Usage
///
/// The `examples::try_hook_example` test in this module runs this example.
macro_rules! try_hook {
    ($expr:expr) => {
        match $expr {
            Ok(val) => val,
            Err(e) => return PreHookResult::Error(format!("{e}")),
        }
    };
}

/// Acquire a mutex lock with automatic panic handling.
///
/// This macro simplifies acquiring a lock on a [`std::sync::Mutex`] by automatically
/// handling lock poisoning with a panic. It's designed for use cases where lock
/// poisoning indicates an unrecoverable error.
///
/// # Panics
///
/// Panics if the mutex is poisoned (another thread panicked while holding the lock).
///
/// # Usage Examples
///
/// The `examples::lock_example` test in this module runs this example.
macro_rules! lock {
    ($lock:expr) => {
        $lock.lock().expect("Failed to acquire lock")
    };
}

/// Acquire a read lock on an [`std::sync::RwLock`] with automatic panic handling.
///
/// This macro simplifies acquiring a read lock by automatically handling lock
/// poisoning with a panic. Multiple readers can hold the lock simultaneously.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// The `examples::read_lock_example` test in this module runs this example.
macro_rules! read_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.read().expect("Failed to acquire read lock")
    };
}

/// Acquire a write lock on an [`std::sync::RwLock`] with automatic panic handling.
///
/// This macro simplifies acquiring a write lock by automatically handling lock
/// poisoning with a panic. Only one writer can hold the lock at a time, and
/// no readers can access the data while a write lock is held.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// The `examples::write_lock_example` test in this module runs this example.
macro_rules! write_lock {
    ($arc_rwlock:expr) => {
        $arc_rwlock.write().expect("Failed to acquire write lock")
    };
}

/// Execute a closure with read access to shared data.
///
/// This macro acquires a read lock, executes the provided closure with access
/// to the data, and automatically releases the lock when the closure completes.
/// The closure's return value is passed through.
///
/// # Arguments
/// * `$arc_rwlock` - An [`std::sync::RwLock`] to acquire a read lock on
/// * `$closure` - A closure that takes a reference to the locked data
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// The `examples::with_read_example` test in this module runs this example.
macro_rules! with_read {
    ($arc_rwlock:expr, $closure:expr) => {{
        let guard = $arc_rwlock.read().expect("Failed to acquire read lock");
        $closure(&*guard)
    }};
}

/// Execute a closure with write access to shared data.
///
/// This macro acquires a write lock, executes the provided closure with mutable
/// access to the data, and automatically releases the lock when the closure completes.
/// The closure's return value is passed through.
///
/// # Arguments
/// * `$arc_rwlock` - An [`std::sync::RwLock`] to acquire a write lock on
/// * `$closure` - A closure that takes a mutable reference to the locked data
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// The `examples::with_write_example` test in this module runs this example.
macro_rules! with_write {
    ($arc_rwlock:expr, $closure:expr) => {{
        let mut guard = $arc_rwlock.write().expect("Failed to acquire write lock");
        $closure(&mut *guard)
    }};
}

/// Get an item from a map and acquire a read lock on it.
///
/// This macro combines map lookup with read lock acquisition, returning an
/// [`std::option::Option`] containing the locked data if the key exists.
///
/// # Arguments
/// * `$map` - A map-like collection containing [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>> values
/// * `$key` - The key to look up in the map
///
/// # Returns
/// An [`std::option::Option`] containing a read guard if the key exists, or [`std::option::Option::None`] if not found.
///
/// # Panics
///
/// Panics if the [`std::sync::RwLock`] is poisoned.
///
/// # Usage Examples
///
/// The `examples::map_get_read_example` test in this module runs this example.
macro_rules! map_get_read {
    ($map:expr, $key:expr) => {{
        $map.get($key).map(|arc_rwlock| read_lock!(arc_rwlock))
    }};
}

/// Iterate over a collection of locked items with read access.
///
/// This macro simplifies iterating over a collection where each item is wrapped
/// in an [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>>. It automatically acquires
/// a read lock for each item during iteration.
///
/// # Arguments
/// * `$collection` - A collection containing [`std::sync::Arc`]<[`std::sync::RwLock`]<`T`>> items
/// * `$var` - The variable name to bind the locked data to in each iteration
/// * `$body` - The code block to execute for each item
///
/// # Panics
///
/// Panics if any [`std::sync::RwLock`] in the collection is poisoned.
///
/// # Usage Examples
///
/// The `examples::for_each_read_example` test in this module runs this example.
macro_rules! for_each_read {
    ($collection:expr, $var:ident, $body:block) => {
        for item in $collection.iter() {
            let $var = read_lock!(item);
            $body
        }
    };
}

/// Generates a newtype wrapper for metadata flag/attribute types.
///
/// This macro creates a strongly-typed flags struct with a comprehensive set of trait
/// implementations for bitwise operations, formatting, conversion, and comparison.
/// It replaces the previous patterns of `pub mod Name { pub const X: u32 }` const
/// modules and `bitflags!` macro invocations with a single unified pattern that
/// provides type safety and consistent API across all metadata flag types.
///
/// # Generated API
///
/// For a declaration `metadata_flags! { pub struct Foo(u32); }`, the macro generates:
///
/// ## Derives and Traits
/// - `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash` (derived)
/// - `Debug` — formats as `Foo(0xVALUE)`
/// - `UpperHex`, `LowerHex` — delegates to inner type
/// - `BitOr<Self>`, `BitAnd<Self>`, `BitOrAssign`, `BitAndAssign`, `Not`
/// - `From<inner>` — construct from raw value
///
/// ## Methods
/// - `pub const fn new(v: inner) -> Self` — construct from raw value (const)
/// - `pub const fn bits(self) -> inner` — extract raw value
/// - `pub const fn contains(self, other: Self) -> bool` — test if all bits in `other` are set
/// - `pub const fn is_empty(self) -> bool` — test if no bits are set
///
/// ## Constants
/// - `pub const ZERO: Self = Self(0)` — the zero/empty value
///
/// # Usage
///
/// The `examples::metadata_flags_example` test in this module runs this example.
///
/// # Design Rationale
///
/// Unlike `bitflags!`, this macro intentionally keeps the `impl` block separate so that
/// each flag constant can retain its full doc comment describing ECMA-335 semantics.
/// The macro only generates the boilerplate traits; domain-specific constants, keyword
/// methods, predicates, and `Display` impls are written manually in the `impl` block.
macro_rules! metadata_flags {
    (
        $(#[$outer:meta])*
        $vis:vis struct $Name:ident($inner:ty);
    ) => {
        $(#[$outer])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        $vis struct $Name($inner);

        impl $Name {
            /// The zero (empty) value with no flags set.
            pub const ZERO: Self = Self(0);

            /// Constructs a new flags value from a raw integer.
            #[inline]
            #[must_use]
            pub const fn new(v: $inner) -> Self {
                Self(v)
            }

            /// Returns the raw integer value of the flags.
            #[inline]
            #[must_use]
            pub const fn bits(self) -> $inner {
                self.0
            }

            /// Returns `true` if all bits in `other` are set in `self`.
            #[inline]
            #[must_use]
            pub const fn contains(self, other: Self) -> bool {
                (self.0 & other.0) == other.0
            }

            /// Returns `true` if no flags are set.
            #[inline]
            #[must_use]
            pub const fn is_empty(self) -> bool {
                self.0 == 0
            }
        }

        impl std::fmt::Debug for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}(0x{:X})", stringify!($Name), self.0)
            }
        }

        impl std::fmt::UpperHex for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::UpperHex::fmt(&self.0, f)
            }
        }

        impl std::fmt::LowerHex for $Name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl std::ops::BitOr for $Name {
            type Output = Self;
            #[inline]
            fn bitor(self, rhs: Self) -> Self {
                Self(self.0 | rhs.0)
            }
        }

        impl std::ops::BitAnd for $Name {
            type Output = Self;
            #[inline]
            fn bitand(self, rhs: Self) -> Self {
                Self(self.0 & rhs.0)
            }
        }

        impl std::ops::BitOrAssign for $Name {
            #[inline]
            fn bitor_assign(&mut self, rhs: Self) {
                self.0 |= rhs.0;
            }
        }

        impl std::ops::BitAndAssign for $Name {
            #[inline]
            fn bitand_assign(&mut self, rhs: Self) {
                self.0 &= rhs.0;
            }
        }

        impl std::ops::Not for $Name {
            type Output = Self;
            #[inline]
            fn not(self) -> Self {
                Self(!self.0)
            }
        }

        impl From<$inner> for $Name {
            #[inline]
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl std::ops::Deref for $Name {
            type Target = $inner;
            #[inline]
            fn deref(&self) -> &$inner {
                &self.0
            }
        }

        impl PartialEq<$inner> for $Name {
            #[inline]
            fn eq(&self, other: &$inner) -> bool {
                self.0 == *other
            }
        }

        impl PartialOrd<$inner> for $Name {
            #[inline]
            fn partial_cmp(&self, other: &$inner) -> Option<std::cmp::Ordering> {
                self.0.partial_cmp(other)
            }
        }
    };
}

#[cfg(test)]
mod examples {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex, RwLock},
    };

    use crate::{emulation::PreHookResult, Result};

    #[test]
    fn module_2_example() -> Result<()> {
        let mutex_data = Mutex::new(42);
        *lock!(mutex_data) = 100;
        assert_eq!(*lock!(mutex_data), 100);

        let rwlock_data = RwLock::new(String::from("hello"));
        let reader = read_lock!(rwlock_data);
        assert_eq!(*reader, "hello");
        Ok(())
    }

    #[test]
    fn module_example() -> Result<()> {
        let shared_data = Arc::new(RwLock::new(vec![1, 2, 3]));

        // Execute closure with read access
        let length = with_read!(shared_data, |vec: &Vec<i32>| vec.len());
        assert_eq!(length, 3);

        // Execute closure with write access
        with_write!(shared_data, |vec: &mut Vec<i32>| vec.push(4));
        assert_eq!(with_read!(shared_data, |vec: &Vec<i32>| vec.len()), 4);
        Ok(())
    }

    /// A hook body: `Ok` unwraps, `Err` ends the hook with `PreHookResult::Error`.
    fn string_length(value: std::result::Result<&str, String>) -> PreHookResult {
        let value = try_hook!(value);
        // `value` is the unwrapped Ok variant
        PreHookResult::Bypass(Some(crate::emulation::EmValue::I32(
            i32::try_from(value.len()).unwrap_or(i32::MAX),
        )))
    }

    #[test]
    fn try_hook_example() -> Result<()> {
        assert!(matches!(
            string_length(Ok("four")),
            PreHookResult::Bypass(Some(crate::emulation::EmValue::I32(4)))
        ));
        assert!(matches!(
            string_length(Err("no string".to_string())),
            PreHookResult::Error(message) if message == "no string"
        ));
        Ok(())
    }

    #[test]
    fn lock_example() -> Result<()> {
        let shared_data = Mutex::new(42);
        let mut data = lock!(shared_data);
        *data = 100;
        drop(data);
        // Lock is automatically released when `data` goes out of scope
        assert_eq!(*lock!(shared_data), 100);
        Ok(())
    }

    #[test]
    fn read_lock_example() -> Result<()> {
        let shared_data = RwLock::new("hello world".to_string());
        let first = read_lock!(shared_data);
        // Readers share the lock.
        let second = read_lock!(shared_data);
        assert_eq!(*first, *second);
        Ok(())
    }

    #[test]
    fn write_lock_example() -> Result<()> {
        let shared_data = RwLock::new(vec![1, 2, 3]);
        let mut data = write_lock!(shared_data);
        data.push(4);
        drop(data);
        // Write lock is automatically released when `data` goes out of scope
        assert_eq!(*read_lock!(shared_data), [1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn with_read_example() -> Result<()> {
        let shared_data = Arc::new(RwLock::new("Hello".to_string()));
        let length = with_read!(shared_data, |data: &String| data.len());
        assert_eq!(length, 5);
        Ok(())
    }

    #[test]
    fn with_write_example() -> Result<()> {
        let shared_data = Arc::new(RwLock::new(vec![1, 2, 3]));
        with_write!(shared_data, |data: &mut Vec<i32>| data.push(4));

        let length = with_read!(shared_data, |data: &Vec<i32>| data.len());
        assert_eq!(length, 4);
        Ok(())
    }

    #[test]
    fn map_get_read_example() -> Result<()> {
        let mut map = HashMap::new();
        map.insert(1, Arc::new(RwLock::new("value".to_string())));

        let guard = map_get_read!(map, &1).expect("key 1 is present");
        assert_eq!(*guard, "value");
        assert!(map_get_read!(map, &2).is_none());
        Ok(())
    }

    #[test]
    fn for_each_read_example() -> Result<()> {
        let items = [
            Arc::new(RwLock::new("first".to_string())),
            Arc::new(RwLock::new("second".to_string())),
        ];

        let mut seen = Vec::new();
        for_each_read!(items, item, {
            seen.push(item.clone());
        });
        assert_eq!(seen, ["first", "second"]);
        Ok(())
    }

    #[test]
    fn metadata_flags_example() -> Result<()> {
        metadata_flags! {
            /// ECMA-335 §II.23.1.15 TypeDef attribute flags.
            pub struct TypeAttributes(u32);
        }

        impl TypeAttributes {
            pub const PUBLIC: Self = Self(0x0000_0001);
            pub const SEALED: Self = Self(0x0000_0100);
            // ...
        }

        let flags = TypeAttributes::PUBLIC | TypeAttributes::SEALED;
        assert_eq!(flags.bits(), 0x0101);
        assert!(flags.contains(TypeAttributes::SEALED));
        Ok(())
    }
}
