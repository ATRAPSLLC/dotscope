//! Virtual filesystem for sandboxed file access during emulation.
//!
//! [`VirtualFs`] provides a sandboxed filesystem backed by [`CowFile`] instances.
//! Files can be mapped from disk (zero-copy mmap), from in-memory data, or by
//! forking an existing `CowFile`. Path lookups are case-insensitive and
//! slash-normalized to handle Windows-style paths from .NET code.
//!
//! # Fork Semantics
//!
//! `VirtualFs::fork()` creates an independent copy where each entry uses
//! `CowFile::fork()`. For mmap-backed entries this re-opens the same file
//! (zero-copy OS CoW). For vec-backed entries, the data is cloned.

use std::{collections::HashMap, path::Path};

use cowfile::CowFile;

/// A sandboxed virtual filesystem backed by [`CowFile`] instances.
///
/// Provides file access for emulated .NET code (e.g., `FileStream`, `File.Exists`)
/// without touching the real filesystem. Each entry is a `CowFile` that can be
/// read via the existing stream/BinaryReader hooks.
pub struct VirtualFs {
    /// Virtual files keyed by normalized path.
    entries: HashMap<String, CowFile>,
    /// Further names of a mapped file, normalized, each to the normalized path it is mapped
    /// under: one file reached by several paths, as an assembly is under its file name and
    /// its module name, without a copy per name.
    aliases: HashMap<String, String>,
}

impl VirtualFs {
    /// Creates an empty virtual filesystem with no mapped files.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            aliases: HashMap::new(),
        }
    }

    /// Maps a virtual file by taking ownership of an existing [`CowFile`].
    ///
    /// For mmap-backed CowFiles (loaded from disk), the entry shares OS
    /// pages with the source. Pending writes on the source are not carried over.
    ///
    /// # Arguments
    ///
    /// * `vfs_path` - Virtual path to register (normalized: case-insensitive, slash-normalized)
    /// * `cow` - The [`CowFile`] instance to store
    pub fn map_cow(&mut self, vfs_path: &str, cow: CowFile) {
        self.entries.insert(Self::normalize_path(vfs_path), cow);
    }

    /// Maps a virtual file from a disk path (mmap'd directly).
    ///
    /// The file is opened via [`CowFile::open`], which creates a `MAP_PRIVATE`
    /// mmap. Reads share physical pages with the OS cache; writes are
    /// copy-on-write.
    ///
    /// # Arguments
    ///
    /// * `vfs_path` - Virtual path to register
    /// * `disk_path` - Path to the file on disk
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or memory-mapped.
    pub fn map_disk_file(
        &mut self,
        vfs_path: &str,
        disk_path: &Path,
    ) -> Result<(), cowfile::Error> {
        let cow = CowFile::open(disk_path)?;
        self.entries.insert(Self::normalize_path(vfs_path), cow);
        Ok(())
    }

    /// Maps a virtual file from in-memory data.
    ///
    /// Creates a vec-backed [`CowFile`] from the provided data. Unlike
    /// mmap-backed entries, forking a vec-backed entry clones the data.
    ///
    /// # Arguments
    ///
    /// * `vfs_path` - Virtual path to register
    /// * `data` - File contents to store
    pub fn map_data(&mut self, vfs_path: &str, data: Vec<u8>) {
        self.entries
            .insert(Self::normalize_path(vfs_path), CowFile::from_vec(data));
    }

    /// Makes `alias_path` a further name of the file mapped under `target_path`: a lookup of
    /// either finds the same file, and the file is held (and forked) once. An alias of a name
    /// that is itself mapped, or of itself, is ignored.
    ///
    /// # Arguments
    ///
    /// * `alias_path` - The further name to register
    /// * `target_path` - The path the file is mapped under
    pub fn alias(&mut self, alias_path: &str, target_path: &str) {
        let alias = Self::normalize_path(alias_path);
        let target = Self::normalize_path(target_path);
        if alias != target && !self.entries.contains_key(&alias) {
            self.aliases.insert(alias, target);
        }
    }

    /// Looks up a virtual file by path (case-insensitive, slash-normalized).
    ///
    /// First tries an exact (normalized) match. If that fails, falls back to
    /// matching by filename component only, which handles cases where .NET code
    /// uses a full path like `C:\Windows\assembly.exe` but the file was mapped
    /// under just `assembly.exe`.
    ///
    /// # Arguments
    ///
    /// * `vfs_path` - Path to look up (any format — Windows, Unix, or bare filename)
    ///
    /// # Returns
    ///
    /// A reference to the [`CowFile`] if found, or `None`.
    pub fn get(&self, vfs_path: &str) -> Option<&CowFile> {
        let normalized = Self::normalize_path(vfs_path);
        let mapped = |path: &String| {
            self.entries.get(path).or_else(|| {
                self.aliases
                    .get(path)
                    .and_then(|target| self.entries.get(target))
            })
        };
        mapped(&normalized).or_else(|| {
            // Also try matching just the filename component, of a mapped path or an alias
            let filename = Self::extract_filename(&normalized);
            self.entries
                .keys()
                .chain(self.aliases.keys())
                .find(|path| Self::extract_filename(path) == filename)
                .and_then(mapped)
        })
    }

    /// Returns `true` if a virtual file exists at the given path.
    ///
    /// Uses the same lookup logic as [`get`](Self::get), including
    /// filename-only fallback matching.
    pub fn exists(&self, vfs_path: &str) -> bool {
        self.get(vfs_path).is_some()
    }

    /// Returns true if the filesystem has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries in the virtual filesystem.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns the normalized paths of all entries.
    pub fn paths(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// Forks the virtual filesystem, creating an independent copy.
    ///
    /// Aliases name the same entries in the fork. Each entry uses [`CowFile::fork()`]:
    /// - Mmap-backed entries re-open the same file (zero-copy OS CoW)
    /// - Vec-backed entries clone the data
    /// - Pending writes are **not** carried over — the fork starts clean
    ///
    /// # Errors
    ///
    /// Returns an error if any mmap-backed entry fails to re-open its file
    /// (e.g., the file was deleted since original mapping).
    pub fn fork(&self) -> Result<VirtualFs, cowfile::Error> {
        let entries = self
            .entries
            .iter()
            .map(|(path, cow)| Ok((path.clone(), cow.fork()?)))
            .collect::<Result<_, cowfile::Error>>()?;
        Ok(VirtualFs {
            entries,
            aliases: self.aliases.clone(),
        })
    }

    /// Normalizes a path for case-insensitive, platform-agnostic lookup.
    ///
    /// Performs three transformations:
    /// 1. Converts to lowercase
    /// 2. Replaces backslashes with forward slashes
    /// 3. Strips a leading Windows drive letter (e.g., `C:/` → `/`)
    /// 4. Strips leading slash for consistency
    fn normalize_path(path: &str) -> String {
        let mut normalized = path.to_lowercase().replace('\\', "/");
        // Strip leading drive letter (e.g., "c:/...")
        if normalized.len() >= 3
            && normalized
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && normalized.get(1..3) == Some(":/")
        {
            normalized = normalized.get(2..).unwrap_or("").to_string();
        }
        // Strip leading slash for consistency
        normalized.trim_start_matches('/').to_string()
    }

    /// Extracts the filename component from a normalized path.
    ///
    /// Returns the portion after the last `/` separator, or the entire
    /// string if no separator is present.
    fn extract_filename(path: &str) -> &str {
        path.rsplit('/').next().unwrap_or(path)
    }
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use cowfile::CowFile;

    use super::*;

    #[test]
    fn test_normalize_path() {
        assert_eq!(
            VirtualFs::normalize_path(r"C:\Users\test.exe"),
            "users/test.exe"
        );
        assert_eq!(VirtualFs::normalize_path("/usr/bin/test"), "usr/bin/test");
        assert_eq!(VirtualFs::normalize_path("test.exe"), "test.exe");
    }

    #[test]
    fn test_map_and_get() {
        let mut vfs = VirtualFs::new();
        vfs.map_data("test.exe", vec![0x4D, 0x5A]);
        assert!(vfs.exists("test.exe"));
        assert!(vfs.exists("TEST.EXE"));
        let data = vfs.get("test.exe").unwrap();
        assert_eq!(data.data(), &[0x4D, 0x5A]);
    }

    #[test]
    fn test_path_matching() {
        let mut vfs = VirtualFs::new();
        vfs.map_data("test.exe", vec![0x4D, 0x5A]);
        // Should match by filename even with full path
        assert!(vfs.exists(r"C:\Program Files\test.exe"));
    }

    /// An alias names the mapped file itself, held once: a lookup by the alias, by its file
    /// name under another directory and in a fork all find that file. The template mapped the
    /// assembly under its file name and its module name as separate copies, each copied again
    /// with every fork.
    #[test]
    fn an_alias_names_the_mapped_file() {
        let mut vfs = VirtualFs::new();
        vfs.map_data("assembly.exe", vec![0x4D, 0x5A, 1]);
        vfs.alias("Original.exe", "assembly.exe");
        vfs.alias("Module.dll", "assembly.exe");
        assert_eq!(vfs.len(), 1);

        let mapped: *const CowFile = vfs.get("assembly.exe").unwrap();
        assert_eq!(
            vfs.get("ORIGINAL.EXE").map(|file| file as *const CowFile),
            Some(mapped)
        );
        assert_eq!(
            vfs.get(r"C:\some\dir\Module.dll")
                .map(|file| file as *const CowFile),
            Some(mapped)
        );

        let forked = vfs.fork().unwrap();
        assert_eq!(forked.len(), 1);
        assert_eq!(forked.get("module.dll").unwrap().data(), &[0x4D, 0x5A, 1]);

        // An alias does not shadow a file mapped under the same name
        vfs.map_data("other.bin", vec![7]);
        vfs.alias("other.bin", "assembly.exe");
        assert_eq!(vfs.get("other.bin").unwrap().data(), &[7]);
    }

    #[test]
    fn test_fork() {
        let mut vfs = VirtualFs::new();
        vfs.map_data("test.exe", vec![1, 2, 3]);
        let forked = vfs.fork().unwrap();
        assert!(forked.exists("test.exe"));
        assert_eq!(forked.get("test.exe").unwrap().data(), &[1, 2, 3]);
    }

    #[test]
    fn test_fork_from_disk() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        tmpfile.write_all(&[0xDE, 0xAD]).unwrap();
        tmpfile.flush().unwrap();

        let cow = CowFile::open(tmpfile.path()).unwrap();
        let mut vfs = VirtualFs::new();
        vfs.map_cow("sample.exe", cow);

        let forked = vfs.fork().unwrap();
        assert_eq!(forked.get("sample.exe").unwrap().data(), &[0xDE, 0xAD]);
    }
}
