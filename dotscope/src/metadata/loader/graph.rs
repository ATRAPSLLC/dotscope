//! Dependency graph management for parallel metadata table loading.
//!
//! This module provides dependency tracking and execution planning for .NET metadata
//! table loaders. It enables efficient parallel loading by analyzing inter-table dependencies,
//! detecting cycles, and generating execution plans that maximize concurrency.
//!
//! # Core Components
//!
//! - [`LoaderGraph`]: Directed acyclic graph of loader dependencies
//! - [`LoaderKey`]: Identifier for table or special loaders
//!
//! # Loading Phases
//!
//! 1. **Level 0**: Independent tables (Assembly, Module, etc.)
//! 2. **Level 1-2**: Simple dependencies (TypeRef, MethodDef, etc.)
//! 3. **Level 3+**: Complex types (GenericParam, InterfaceImpl, etc.)
//! 4. **Final**: Cross-references (CustomAttribute, MethodSemantics)
//!
//! # Thread Safety
//!
//! - Construction: Single-threaded only
//! - Generated plans: Thread-safe for parallel execution
//!
use std::collections::{HashMap, HashSet};

use analyssa::graph::IndexedGraph;

use crate::{
    metadata::{loader::MetadataLoader, tables::TableId},
    Error::GraphError,
    Result,
};

/// Unique identifier for loaders in the dependency graph.
///
/// This enum distinguishes between regular table loaders and special cross-table loaders,
/// enabling the dependency graph to handle both types appropriately while maintaining
/// correct execution order and dependency relationships.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum LoaderKey {
    /// Regular loader that processes a specific metadata table
    Table(TableId),

    /// Special loader that operates across multiple tables
    ///
    /// Special loaders have unique properties:
    /// - Cannot be depended upon by other loaders
    /// - Run immediately when their dependencies are satisfied  
    /// - Execute before other loaders at the same dependency level
    Special {
        /// Sequence number for ordering multiple special loaders with same dependencies
        sequence: usize,
    },
}

/// A directed graph representing dependencies between metadata loaders.
///
/// Manages relationships between table loaders and special cross-table loaders,
/// enabling dependency analysis, cycle detection, and parallel execution planning.
///
/// # Lifecycle
///
/// 1. Create with `LoaderGraph::new()`
/// 2. Add loaders with `add_loader()`
/// 3. Build and validate with `build_relationships()`
/// 4. Generate execution plan with `topological_levels()`
///
/// # Thread Safety
///
/// Graph construction is single-threaded only. Generated execution plans are
/// thread-safe for coordinating parallel loader execution.
#[derive(Default)]
pub struct LoaderGraph<'a> {
    /// Maps a `LoaderKey` to its loader
    loaders: HashMap<LoaderKey, &'a dyn MetadataLoader>,
    /// Maps a `TableId` to the set of `LoaderKeys` that depend on it (reverse dependencies)
    dependents: HashMap<TableId, HashSet<LoaderKey>>,
    /// Maps a `LoaderKey` to the set of `TableIds` it depends on (forward dependencies)
    dependencies: HashMap<LoaderKey, HashSet<TableId>>,
    /// Counter for generating unique sequence numbers for special loaders
    special_counter: usize,
}

impl<'a> LoaderGraph<'a> {
    /// Creates a new empty loader graph.
    ///
    /// # Returns
    ///
    /// A new `LoaderGraph` with empty dependency mappings, ready for loader registration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a loader to the graph.
    ///
    /// The loader's key is determined by `table_id()` - returns `LoaderKey::Table` for
    /// regular loaders or `LoaderKey::Special` for cross-table loaders.
    /// Dependencies are not resolved until `build_relationships()` is called.
    ///
    /// # Arguments
    ///
    /// * `loader` - The metadata loader to register in the graph.
    pub fn add_loader(&mut self, loader: &'a dyn MetadataLoader) {
        let loader_key = if let Some(table_id) = loader.table_id() {
            LoaderKey::Table(table_id)
        } else {
            let key = LoaderKey::Special {
                sequence: self.special_counter,
            };
            self.special_counter = self.special_counter.saturating_add(1);
            key
        };

        self.loaders.insert(loader_key.clone(), loader);
        self.dependencies.entry(loader_key.clone()).or_default();

        // Only table loaders can be depended upon
        if let LoaderKey::Table(table_id) = loader_key {
            self.dependents.entry(table_id).or_default();
        }
    }

    /// Builds dependency relationships after all loaders have been added.
    ///
    /// Queries each loader for dependencies, validates all dependencies have loaders,
    /// constructs bidirectional mappings, and checks the table dependencies for cycles.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the dependency graph is valid and all relationships are built.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if a loader depends on a table without a registered loader,
    /// or if circular dependencies are detected.
    pub fn build_relationships(&mut self) -> Result<()> {
        self.dependencies.values_mut().for_each(HashSet::clear);
        self.dependents.values_mut().for_each(HashSet::clear);

        for (loader_key, loader) in &self.loaders {
            for dep_table_id in loader.dependencies() {
                // Check if dependency is satisfied by any table loader
                let has_table_loader = self.loaders.keys().any(
                    |key| matches!(key, LoaderKey::Table(table_id) if table_id == dep_table_id),
                );

                if !has_table_loader {
                    return Err(GraphError(format!(
                        "Loader {loader_key:?} depends on table {dep_table_id:?}, but no loader for that table exists"
                    )));
                }

                // Add forward dependency (loader depends on table)
                self.dependencies
                    .get_mut(loader_key)
                    .ok_or_else(|| {
                        GraphError(format!(
                            "Internal error: loader {loader_key:?} not found in dependencies map"
                        ))
                    })?
                    .insert(*dep_table_id);

                // Add reverse dependency (table has loader depending on it)
                self.dependents
                    .get_mut(dep_table_id)
                    .ok_or_else(|| {
                        GraphError(format!(
                            "Internal error: table {dep_table_id:?} not found in dependents map"
                        ))
                    })?
                    .insert(loader_key.clone());
            }
        }

        self.check_circular_dependencies()?;

        Ok(())
    }

    /// Checks for circular dependencies using the generic graph algorithm.
    ///
    /// Delegates to [`analyssa::graph::IndexedGraph::find_any_cycle`] for cycle detection
    /// which handles all NodeId mapping internally.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the graph is acyclic.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if a circular dependency is detected.
    fn check_circular_dependencies(&self) -> Result<()> {
        // Build an IndexedGraph from table loader dependencies
        // Note: Only need to check table loaders for cycles since special loaders
        // can only depend on tables but cannot be depended upon
        let graph = self.build_indexed_graph()?;

        if graph.is_empty() {
            return Ok(());
        }

        // Check for any cycle in the graph
        if let Some(cycle) = graph.find_any_cycle() {
            // Use the first table in the cycle for the error message
            if let Some(table_id) = cycle.first() {
                return Err(GraphError(format!(
                    "Circular dependency detected involving table {table_id:?}"
                )));
            }
            return Err(GraphError(
                "Circular dependency detected in loader graph".to_string(),
            ));
        }

        Ok(())
    }

    /// Build an IndexedGraph from table loader dependencies.
    ///
    /// The `IndexedGraph` handles all the mapping between `TableId` and `NodeId`
    /// internally, providing a cleaner API for graph algorithms.
    fn build_indexed_graph(&self) -> Result<IndexedGraph<TableId, ()>> {
        let mut graph: IndexedGraph<TableId, ()> = IndexedGraph::new();

        // Add nodes for all table loaders
        for loader_key in self.loaders.keys() {
            if let LoaderKey::Table(table_id) = loader_key {
                graph.add_node(*table_id);
            }
        }

        // Also add nodes for dependencies that might not have their own loader entry
        for deps in self.dependencies.values() {
            for dep_table_id in deps {
                graph.add_node(*dep_table_id);
            }
        }

        // Add edges: source depends on target (source -> target)
        for (loader_key, deps) in &self.dependencies {
            if let LoaderKey::Table(source_table_id) = loader_key {
                for dep_table_id in deps {
                    graph.add_edge(*source_table_id, *dep_table_id, ())?;
                }
            }
        }

        Ok(graph)
    }

    /// Returns loaders grouped by dependency level (topological sort).
    ///
    /// Computes execution levels where all loaders within a level can run in parallel.
    /// Level 0 contains independent loaders; level N contains loaders depending only on
    /// loaders from levels 0 through N-1.
    ///
    /// # Returns
    ///
    /// A vector of execution levels, where each level contains loaders that can run in parallel.
    ///
    /// # Errors
    ///
    /// Returns `GraphError` if circular dependencies prevent topological ordering.
    pub fn topological_levels(&self) -> Result<Vec<Vec<&'a dyn MetadataLoader>>> {
        let mut execution_levels = Vec::new();
        let mut unscheduled_loaders = self.loaders.keys().cloned().collect::<HashSet<_>>();
        let mut satisfied_dependencies = HashSet::new();

        while !unscheduled_loaders.is_empty() {
            // Phase 1: Find and schedule table loaders that are ready
            let ready_table_loaders =
                self.find_ready_loaders(&unscheduled_loaders, &satisfied_dependencies, |key| {
                    matches!(key, LoaderKey::Table(_))
                });

            let mut current_level = Vec::new();
            for loader_key in &ready_table_loaders {
                if let Some(loader) = self.loaders.get(loader_key) {
                    current_level.push(*loader);
                }
                unscheduled_loaders.remove(loader_key);

                // Mark this table as completed (special loaders can't be dependencies)
                if let LoaderKey::Table(table_id) = loader_key {
                    satisfied_dependencies.insert(*table_id);
                }
            }

            let table_progress = !current_level.is_empty();
            if table_progress {
                execution_levels.push(current_level);
            }

            // Phase 2: Find and schedule special loaders that are now ready
            let ready_special_loaders =
                self.find_ready_loaders(&unscheduled_loaders, &satisfied_dependencies, |key| {
                    matches!(key, LoaderKey::Special { .. })
                });

            let special_progress = !ready_special_loaders.is_empty();
            if special_progress {
                let mut special_level = Vec::new();
                for loader_key in &ready_special_loaders {
                    if let Some(loader) = self.loaders.get(loader_key) {
                        special_level.push(*loader);
                    }
                    unscheduled_loaders.remove(loader_key);
                }
                execution_levels.push(special_level);
            }

            // Check for deadlock: remaining loaders but no progress
            if !unscheduled_loaders.is_empty() && !table_progress && !special_progress {
                return Err(GraphError(
                    "Unable to resolve dependency order, possible circular dependency".to_string(),
                ));
            }
        }

        Ok(execution_levels)
    }

    /// Finds loaders that are ready to execute (all dependencies satisfied).
    ///
    /// # Arguments
    ///
    /// * `unscheduled` - Set of loaders not yet scheduled for execution.
    /// * `satisfied` - Set of table IDs whose loaders have completed.
    /// * `type_filter` - Predicate to filter loader types (table vs special).
    ///
    /// # Returns
    ///
    /// A vector of `LoaderKey`s for loaders whose dependencies are all satisfied.
    fn find_ready_loaders<F>(
        &self,
        unscheduled: &HashSet<LoaderKey>,
        satisfied: &HashSet<TableId>,
        type_filter: F,
    ) -> Vec<LoaderKey>
    where
        F: Fn(&LoaderKey) -> bool,
    {
        unscheduled
            .iter()
            .filter(|loader_key| {
                type_filter(loader_key)
                    && self
                        .dependencies
                        .get(loader_key)
                        .is_none_or(|deps| deps.iter().all(|dep| satisfied.contains(dep)))
            })
            .cloned()
            .collect()
    }
}
