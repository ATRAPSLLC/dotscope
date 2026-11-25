//! Copy-on-Write memory page implementation.
//!
//! This module provides [`Page`], a memory page with transparent copy-on-write
//! semantics and interior mutability for thread-safe concurrent access.
//!
//! # CoW Semantics
//!
//! Each page has an immutable backing buffer (shared via `Arc`) and an optional
//! local buffer for modifications. On first write, the backing is copied to
//! the local buffer, and subsequent reads/writes use the local copy.
//!
//! # Thread Safety
//!
//! The page uses `RwLock` to allow concurrent reads and exclusive writes.
//! All operations take `&self` for interior mutability.
//!
//! # Fork Support
//!
//! When forking, the current state (backing + local) is consolidated into
//! a new backing, and the forked page starts with a fresh local buffer.

use std::sync::{Arc, RwLock, RwLockReadGuard};

use crate::emulation::engine::EmulationError;

/// Standard page size (4KB).
pub const PAGE_SIZE: usize = 4096;

/// A memory page with copy-on-write semantics.
///
/// Pages are the fundamental unit of memory management in the emulator.
/// They support transparent CoW - reads return data from either the local
/// copy (if modified) or the shared backing, while writes automatically
/// create a local copy on first modification.
///
/// # Thread Safety
///
/// All operations use interior mutability via `RwLock`. Multiple threads
/// can read concurrently, while writes acquire exclusive access.
///
/// # Example
///
/// ```no_run
/// use dotscope::emulation::Page;
///
/// // Create a page with some data
/// let mut data = [0u8; 4096];
/// data[0] = 42;
/// let page = Page::new(data);
///
/// // Read returns the backing data
/// assert_eq!(page.read_byte(0)?, 42);
///
/// // First write triggers CoW
/// page.write_byte(0, 100)?;
/// assert_eq!(page.read_byte(0)?, 100);
///
/// // Fork creates an independent copy
/// let forked = page.fork()?;
/// forked.write_byte(0, 200)?;
/// assert_eq!(page.read_byte(0)?, 100); // Original unchanged
/// assert_eq!(forked.read_byte(0)?, 200);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug)]
pub struct Page {
    /// Immutable backing data (from parent or initial load).
    backing: Arc<[u8; PAGE_SIZE]>,
    /// Local copy for modifications (created on first write).
    /// Uses RwLock for concurrent read/write access.
    local: RwLock<Option<Box<[u8; PAGE_SIZE]>>>,
}

impl Page {
    /// Creates a new page with the given initial data.
    ///
    /// The data becomes the immutable backing, and no local copy exists yet.
    #[must_use]
    pub fn new(data: [u8; PAGE_SIZE]) -> Self {
        Self {
            backing: Arc::new(data),
            local: RwLock::new(None),
        }
    }

    /// Creates a new page initialized with zeros.
    #[must_use]
    pub fn zeroed() -> Self {
        Self::new([0u8; PAGE_SIZE])
    }

    /// Creates a page from a slice, padding with zeros if needed.
    ///
    /// If the slice is shorter than `PAGE_SIZE`, the rest is zero-filled.
    /// If longer, it is truncated.
    #[must_use]
    pub fn from_slice(data: &[u8]) -> Self {
        let mut page_data = [0u8; PAGE_SIZE];
        let copy_len = data.len().min(PAGE_SIZE);
        if let (Some(dst), Some(src)) = (page_data.get_mut(..copy_len), data.get(..copy_len)) {
            dst.copy_from_slice(src);
        }
        Self::new(page_data)
    }

    /// Reads a single byte at the given offset.
    ///
    /// Returns the byte from the local copy if it exists, otherwise from backing.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::PageOutOfBounds`] if `offset >= PAGE_SIZE`.
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn read_byte(&self, offset: usize) -> Result<u8, EmulationError> {
        if offset >= PAGE_SIZE {
            return Err(EmulationError::PageOutOfBounds {
                offset,
                size: 1,
                page_size: PAGE_SIZE,
            });
        }
        let local = self
            .local
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        let byte = local.as_ref().map_or_else(
            || self.backing.get(offset).copied(),
            |data| data.get(offset).copied(),
        );
        byte.ok_or(EmulationError::PageOutOfBounds {
            offset,
            size: 1,
            page_size: PAGE_SIZE,
        })
    }

    /// Reads a range of bytes into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting offset within the page
    /// * `buf` - Buffer to read into
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::PageOutOfBounds`] if `offset + buf.len() > PAGE_SIZE`.
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn read(&self, offset: usize, buf: &mut [u8]) -> Result<(), EmulationError> {
        let end = offset.saturating_add(buf.len());
        if end > PAGE_SIZE || end < offset {
            return Err(EmulationError::PageOutOfBounds {
                offset,
                size: buf.len(),
                page_size: PAGE_SIZE,
            });
        }

        let local = self
            .local
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        let src = local.as_ref().map_or_else(
            || self.backing.get(offset..end),
            |data| data.get(offset..end),
        );
        let src = src.ok_or(EmulationError::PageOutOfBounds {
            offset,
            size: buf.len(),
            page_size: PAGE_SIZE,
        })?;
        buf.copy_from_slice(src);
        Ok(())
    }

    /// Reads a range and returns a new Vec.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::PageOutOfBounds`] if `offset + len > PAGE_SIZE`.
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn read_vec(&self, offset: usize, len: usize) -> Result<Vec<u8>, EmulationError> {
        let mut buf = vec![0u8; len];
        self.read(offset, &mut buf)?;
        Ok(buf)
    }

    /// Writes a single byte at the given offset.
    ///
    /// Triggers copy-on-write if no local copy exists yet.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::PageOutOfBounds`] if `offset >= PAGE_SIZE`.
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn write_byte(&self, offset: usize, value: u8) -> Result<(), EmulationError> {
        if offset >= PAGE_SIZE {
            return Err(EmulationError::PageOutOfBounds {
                offset,
                size: 1,
                page_size: PAGE_SIZE,
            });
        }

        let mut local = self
            .local
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        let buf = local.get_or_insert_with(|| Box::new(*self.backing));
        let slot = buf.get_mut(offset).ok_or(EmulationError::PageOutOfBounds {
            offset,
            size: 1,
            page_size: PAGE_SIZE,
        })?;
        *slot = value;
        Ok(())
    }

    /// Writes bytes from the provided buffer.
    ///
    /// Triggers copy-on-write if no local copy exists yet.
    ///
    /// # Arguments
    ///
    /// * `offset` - Starting offset within the page
    /// * `data` - Data to write
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::PageOutOfBounds`] if `offset + data.len() > PAGE_SIZE`.
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn write(&self, offset: usize, data: &[u8]) -> Result<(), EmulationError> {
        let end = offset.saturating_add(data.len());
        if end > PAGE_SIZE || end < offset {
            return Err(EmulationError::PageOutOfBounds {
                offset,
                size: data.len(),
                page_size: PAGE_SIZE,
            });
        }

        let mut local = self
            .local
            .write()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        let buf = local.get_or_insert_with(|| Box::new(*self.backing));
        let dst = buf
            .get_mut(offset..end)
            .ok_or(EmulationError::PageOutOfBounds {
                offset,
                size: data.len(),
                page_size: PAGE_SIZE,
            })?;
        dst.copy_from_slice(data);
        Ok(())
    }

    /// Returns `true` if this page has been modified (has a local copy).
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn is_modified(&self) -> Result<bool, EmulationError> {
        let local = self
            .local
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        Ok(local.is_some())
    }

    /// Forks this page, creating an independent copy with CoW semantics.
    ///
    /// The new page shares the current state as its backing:
    /// - If this page has local modifications, they become the new backing
    /// - Otherwise, the original backing is shared
    ///
    /// The forked page starts with no local modifications.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn fork(&self) -> Result<Self, EmulationError> {
        let local = self
            .local
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        let new_backing = local.as_ref().map_or_else(
            || Arc::clone(&self.backing), // Share the original backing
            |data| Arc::new(**data),      // Local modifications become the new backing
        );

        Ok(Self {
            backing: new_backing,
            local: RwLock::new(None),
        })
    }

    /// Returns a reference to the current data (either local or backing).
    ///
    /// This acquires a read lock and returns a guard that provides access
    /// to the page data.
    ///
    /// # Errors
    ///
    /// Returns [`EmulationError::LockPoisoned`] if the page lock is poisoned.
    pub fn data(&self) -> Result<PageDataGuard<'_>, EmulationError> {
        let local = self
            .local
            .read()
            .map_err(|_| EmulationError::LockPoisoned {
                description: "page local buffer",
            })?;
        Ok(PageDataGuard { page: self, local })
    }
}

impl Clone for Page {
    fn clone(&self) -> Self {
        // Clone creates a copy with the current state as backing
        // Note: This will panic if the lock is poisoned - use fork() for fallible cloning
        self.fork().unwrap_or_else(|_| Self::zeroed())
    }
}

impl Default for Page {
    fn default() -> Self {
        Self::zeroed()
    }
}

/// Guard providing access to page data.
///
/// This holds the read lock on the page's local buffer and provides
/// access to either the local or backing data.
pub struct PageDataGuard<'a> {
    page: &'a Page,
    local: RwLockReadGuard<'a, Option<Box<[u8; PAGE_SIZE]>>>,
}

impl PageDataGuard<'_> {
    /// Returns a reference to the page data.
    #[must_use]
    pub fn as_slice(&self) -> &[u8; PAGE_SIZE] {
        self.local.as_ref().map_or(&self.page.backing, |data| data)
    }
}

impl std::ops::Deref for PageDataGuard<'_> {
    type Target = [u8; PAGE_SIZE];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use crate::emulation::memory::page::{Page, PAGE_SIZE};

    #[test]
    fn test_page_new() {
        let mut data = [0u8; PAGE_SIZE];
        data[0] = 42;
        data[PAGE_SIZE - 1] = 99;
        let page = Page::new(data);

        assert_eq!(page.read_byte(0).unwrap(), 42);
        assert_eq!(page.read_byte(PAGE_SIZE - 1).unwrap(), 99);
        assert!(!page.is_modified().unwrap());
    }

    #[test]
    fn test_page_write_cow() {
        let page = Page::new([0u8; PAGE_SIZE]);
        assert!(!page.is_modified().unwrap());

        page.write_byte(100, 0xFF).unwrap();
        assert!(page.is_modified().unwrap());
        assert_eq!(page.read_byte(100).unwrap(), 0xFF);
        assert_eq!(page.read_byte(0).unwrap(), 0); // Other bytes unchanged
    }

    #[test]
    fn test_page_fork() {
        let page = Page::new([42u8; PAGE_SIZE]);
        page.write_byte(0, 100).unwrap();

        let forked = page.fork().unwrap();

        // Fork inherits current state
        assert_eq!(forked.read_byte(0).unwrap(), 100);
        assert!(!forked.is_modified().unwrap()); // Fresh local state

        // Modifications are independent
        forked.write_byte(0, 200).unwrap();
        assert_eq!(page.read_byte(0).unwrap(), 100);
        assert_eq!(forked.read_byte(0).unwrap(), 200);
    }

    #[test]
    fn test_page_read_write_range() {
        let page = Page::zeroed();

        let data = [1, 2, 3, 4, 5];
        page.write(10, &data).unwrap();

        let mut buf = [0u8; 5];
        page.read(10, &mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4, 5]);

        // Also test read_vec
        let vec = page.read_vec(10, 5).unwrap();
        assert_eq!(vec, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_page_from_slice() {
        let data = vec![1, 2, 3, 4, 5];
        let page = Page::from_slice(&data);

        assert_eq!(page.read_byte(0).unwrap(), 1);
        assert_eq!(page.read_byte(4).unwrap(), 5);
        assert_eq!(page.read_byte(5).unwrap(), 0); // Zero-padded
    }

    #[test]
    fn test_page_data_guard() {
        let mut data = [0u8; PAGE_SIZE];
        data[0] = 42;
        let page = Page::new(data);

        let guard = page.data().unwrap();
        assert_eq!(guard[0], 42);
    }

    #[test]
    fn test_page_concurrent_reads() {
        let page = Arc::new(Page::new([42u8; PAGE_SIZE]));

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let p = Arc::clone(&page);
                thread::spawn(move || {
                    for _ in 0..1000 {
                        assert_eq!(p.read_byte(0).unwrap(), 42);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_page_out_of_bounds_read_byte() {
        let page = Page::zeroed();
        let result = page.read_byte(PAGE_SIZE);
        assert!(result.is_err());
    }

    #[test]
    fn test_page_out_of_bounds_write_byte() {
        let page = Page::zeroed();
        let result = page.write_byte(PAGE_SIZE, 0xFF);
        assert!(result.is_err());
    }

    #[test]
    fn test_page_out_of_bounds_read_range() {
        let page = Page::zeroed();
        let mut buf = [0u8; 10];
        let result = page.read(PAGE_SIZE - 5, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_page_out_of_bounds_write_range() {
        let page = Page::zeroed();
        let data = [0u8; 10];
        let result = page.write(PAGE_SIZE - 5, &data);
        assert!(result.is_err());
    }
}
