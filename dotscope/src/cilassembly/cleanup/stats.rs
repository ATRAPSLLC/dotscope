//! Statistics tracking for cleanup operations.
//!
//! Provides [`CleanupStats`] to track what was removed during cleanup,
//! useful for reporting and debugging.

use std::{collections::HashMap, fmt};

use crate::metadata::tables::TableId;

/// Statistics from a cleanup operation.
///
/// Tracks the number of items removed in each category, providing
/// visibility into what the cleanup process accomplished.
#[derive(Debug, Clone, Default)]
pub struct CleanupStats {
    /// Per-table removal counts keyed by `TableId`.
    removals: HashMap<TableId, usize>,
    /// Number of PE sections excluded.
    pub sections_excluded: usize,
    /// Number of unreferenced string heap entries marked for removal.
    pub strings_compacted: usize,
    /// Number of unreferenced blob heap entries marked for removal.
    pub blobs_compacted: usize,
    /// Number of unreferenced GUID heap entries marked for removal.
    pub guids_compacted: usize,
}

impl CleanupStats {
    /// Creates a new empty stats instance.
    ///
    /// All counters are initialized to zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the removal count for a specific table.
    #[must_use]
    pub fn get(&self, table: TableId) -> usize {
        self.removals.get(&table).copied().unwrap_or(0)
    }

    /// Adds `count` to the removal counter for the given table.
    pub fn add(&mut self, table: TableId, count: usize) {
        if count > 0 {
            let entry = self.removals.entry(table).or_insert(0);
            *entry = entry.saturating_add(count);
        }
    }

    /// Sets the removal count of each table to `removals`, replacing what the passes added.
    pub fn set_removals(&mut self, removals: HashMap<TableId, usize>) {
        self.removals = removals;
    }

    /// Returns the total number of metadata entries removed.
    ///
    /// This includes all table entries: types, methods, fields, attributes,
    /// parameters, signatures, and all orphaned metadata entries.
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.removals.values().sum()
    }

    /// Returns true if any items were removed or sections excluded.
    ///
    /// Checks all removal counters, section exclusions, and heap compaction.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.total_removed() > 0 || self.sections_excluded > 0 || self.heap_entries_compacted() > 0
    }

    /// Returns the total number of heap entries marked for compaction.
    ///
    /// This is the sum of compacted strings, blobs, and GUIDs.
    #[must_use]
    pub fn heap_entries_compacted(&self) -> usize {
        self.strings_compacted
            .saturating_add(self.blobs_compacted)
            .saturating_add(self.guids_compacted)
    }

    /// Returns the count of primary items removed (types, methods, fields).
    ///
    /// Primary items are the main metadata entries that were explicitly deleted,
    /// as opposed to orphaned entries that were removed as a consequence.
    #[must_use]
    pub fn primary_removed(&self) -> usize {
        self.get(TableId::TypeDef)
            .saturating_add(self.get(TableId::MethodDef))
            .saturating_add(self.get(TableId::Field))
    }

    /// Returns the count of orphaned metadata entries removed.
    ///
    /// Orphaned entries are metadata that became unreferenced after the
    /// primary deletions were applied (e.g., parameters of deleted methods).
    #[must_use]
    pub fn orphans_removed(&self) -> usize {
        self.total_removed()
            .saturating_sub(self.primary_removed())
            .saturating_sub(self.get(TableId::CustomAttribute))
    }

    /// Merges stats from another cleanup operation into this one.
    ///
    /// All counters from `other` are added to the corresponding counters
    /// in `self`. This is useful when combining stats from multiple passes.
    pub fn merge(&mut self, other: &CleanupStats) {
        for (&table, &count) in &other.removals {
            self.add(table, count);
        }
        self.sections_excluded = self
            .sections_excluded
            .saturating_add(other.sections_excluded);
        self.strings_compacted = self
            .strings_compacted
            .saturating_add(other.strings_compacted);
        self.blobs_compacted = self.blobs_compacted.saturating_add(other.blobs_compacted);
        self.guids_compacted = self.guids_compacted.saturating_add(other.guids_compacted);
    }
}

impl fmt::Display for CleanupStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.has_changes() {
            return write!(f, "No changes");
        }

        let mut parts = Vec::new();

        let types = self.get(TableId::TypeDef);
        if types > 0 {
            parts.push(format!("{types} types"));
        }
        let methods = self.get(TableId::MethodDef);
        if methods > 0 {
            parts.push(format!("{methods} methods"));
        }
        let fields = self.get(TableId::Field);
        if fields > 0 {
            parts.push(format!("{fields} fields"));
        }
        let attributes = self.get(TableId::CustomAttribute);
        if attributes > 0 {
            parts.push(format!("{attributes} attributes"));
        }

        let orphans = self.orphans_removed();
        if orphans > 0 {
            parts.push(format!("{orphans} orphaned entries"));
        }

        if self.sections_excluded > 0 {
            parts.push(format!("{} sections excluded", self.sections_excluded));
        }

        let heap_compacted = self.heap_entries_compacted();
        if heap_compacted > 0 {
            parts.push(format!("{heap_compacted} heap entries compacted"));
        }

        write!(f, "Removed: {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use crate::{cilassembly::cleanup::CleanupStats, metadata::tables::TableId};

    #[test]
    fn test_stats_default() {
        let stats = CleanupStats::new();
        assert_eq!(stats.total_removed(), 0);
        assert!(!stats.has_changes());
    }

    #[test]
    fn test_stats_counting() {
        let mut stats = CleanupStats::new();
        stats.add(TableId::TypeDef, 5);
        stats.add(TableId::MethodDef, 10);
        stats.add(TableId::Param, 20);

        assert_eq!(stats.primary_removed(), 15);
        assert_eq!(stats.orphans_removed(), 20);
        assert_eq!(stats.total_removed(), 35);
        assert!(stats.has_changes());
    }

    #[test]
    fn test_stats_merge() {
        let mut stats1 = CleanupStats::new();
        stats1.add(TableId::TypeDef, 5);

        let mut stats2 = CleanupStats::new();
        stats2.add(TableId::MethodDef, 10);

        stats1.merge(&stats2);

        assert_eq!(stats1.get(TableId::TypeDef), 5);
        assert_eq!(stats1.get(TableId::MethodDef), 10);
    }

    #[test]
    fn test_stats_display() {
        let mut stats = CleanupStats::new();
        stats.add(TableId::TypeDef, 3);
        stats.add(TableId::MethodDef, 7);
        stats.add(TableId::Param, 15);

        let display = stats.to_string();
        assert!(display.contains("3 types"));
        assert!(display.contains("7 methods"));
        assert!(display.contains("orphaned"));
    }

    #[test]
    fn test_stats_display_empty() {
        let stats = CleanupStats::new();
        assert_eq!(stats.to_string(), "No changes");
    }

    #[test]
    fn test_stats_get_missing_table() {
        let stats = CleanupStats::new();
        assert_eq!(stats.get(TableId::TypeDef), 0);
    }

    #[test]
    fn test_stats_add_zero() {
        let mut stats = CleanupStats::new();
        stats.add(TableId::TypeDef, 0);
        assert_eq!(stats.get(TableId::TypeDef), 0);
        assert!(stats.removals.is_empty());
    }

    #[test]
    fn test_stats_add_increments() {
        let mut stats = CleanupStats::new();
        stats.add(TableId::TypeDef, 3);
        stats.add(TableId::TypeDef, 2);
        assert_eq!(stats.get(TableId::TypeDef), 5);
    }
}
