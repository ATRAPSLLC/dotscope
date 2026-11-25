//! Multi-assembly dependency tracking and analysis system.
//!
//! This module provides comprehensive support for tracking, analyzing, and resolving
//! dependencies between .NET assemblies. It forms the foundation for multi-assembly
//! analysis capabilities in dotscope, enabling cross-assembly type resolution,
//! inheritance chain analysis, and project-wide dependency management.
//!
//! # Architecture
//!
//! The dependency system is built around several key components:
//!
//! ## Core Components
//!
//! - [`AssemblyDependencyGraph`](crate::metadata::dependencies::AssemblyDependencyGraph) - Central dependency graph with cycle detection
//! - [`AssemblyDependency`](crate::metadata::dependencies::AssemblyDependency) - Individual dependency relationship representation
//! - [`DependencyAnalyzer`](crate::metadata::dependencies::DependencyAnalyzer) - Extracts dependencies from metadata tables
//! - [`AssemblyIdentity`](crate::metadata::identity::AssemblyIdentity) - Unique assembly identification system
//!
//! ## Dependency Sources
//!
//! The system tracks dependencies from multiple .NET metadata sources:
//! - **AssemblyRef** - References to external assemblies (primary source)
//! - **ModuleRef** - References to external modules in multi-module assemblies
//! - **File** - Files within multi-file assemblies (rare in modern .NET)
//!
//! # Usage Examples
//!
//! ## Basic Dependency Graph Usage
//!
//! ```rust
//! use std::sync::Arc;
//! use dotscope::metadata::dependencies::{
//!     AssemblyDependencyGraph, AssemblyDependency, DependencySource,
//!     DependencyType, VersionRequirement, DependencyResolutionState,
//! };
//! use dotscope::metadata::identity::{AssemblyIdentity, AssemblyVersion};
//!
//! // Create a dependency graph
//! let graph = Arc::new(AssemblyDependencyGraph::new());
//! assert!(graph.is_empty());
//!
//! // Create assembly identities
//! let app = AssemblyIdentity::new(
//!     "MyApp".to_string(),
//!     AssemblyVersion::new(1, 0, 0, 0),
//!     None, None, None,
//! );
//! let lib = AssemblyIdentity::new(
//!     "MyLib".to_string(),
//!     AssemblyVersion::new(2, 0, 0, 0),
//!     None, None, None,
//! );
//!
//! // Get topological loading order (empty graph returns empty order)
//! let load_order = graph.topological_order()?;
//! assert!(load_order.is_empty());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! ## Cycle Detection
//!
//! ```rust
//! use std::sync::Arc;
//! use dotscope::metadata::dependencies::AssemblyDependencyGraph;
//!
//! let graph = Arc::new(AssemblyDependencyGraph::new());
//!
//! // Check for circular dependencies (empty graph has no cycles)
//! let cycles = graph.find_cycles()?;
//! assert!(cycles.is_none());
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration with Metadata Loading
//!
//! The dependency system integrates seamlessly with the existing metadata loading pipeline:
//!
//! 1. **Table Loaders** extract dependency information during loading
//! 2. **DependencyAnalyzer** processes the extracted data
//! 3. **AssemblyDependencyGraph** maintains the complete dependency structure  
//! 4. **Multi-assembly systems** use the graph for resolution and analysis
//!
//! # Thread Safety
//!
//! All components in this module are designed for concurrent access:
//! - **DashMap** for thread-safe dependency storage
//! - **Arc** for shared ownership of dependency data
//! - **Atomic operations** for state management
//! - **Lock-free** algorithms where possible for performance

mod analyzer;
mod graph;
mod types;

pub use analyzer::DependencyAnalyzer;
pub use graph::AssemblyDependencyGraph;
pub use types::{
    AssemblyDependency, DependencyResolutionState, DependencyResolveContext, DependencySource,
    DependencyType, VersionRequirement,
};

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;
    use crate::{
        metadata::{dependencies::DependencyType, identity::AssemblyVersion},
        testkit::helpers::dependencies::{
            create_test_assembly_ref, create_test_dependency, create_test_identity,
        },
    };

    #[test]
    fn test_cross_module_integration() {
        // Test integration between graph, analyzer, and types
        let graph = Arc::new(AssemblyDependencyGraph::new());
        let analyzer = DependencyAnalyzer::new(graph.clone());

        // Create a complex dependency scenario
        let app = create_test_identity("MyApplication", 1, 0);
        let system_dep = create_test_dependency("System", DependencyType::Reference);
        let core_dep = create_test_dependency("System.Core", DependencyType::Reference);

        // Add dependencies through the analyzer's graph
        analyzer
            .dependency_graph()
            .add_dependency_with_source(&app, system_dep)
            .unwrap();
        analyzer
            .dependency_graph()
            .add_dependency_with_source(&app, core_dep)
            .unwrap();

        // Verify the integration
        assert_eq!(graph.assembly_count(), 3); // App + System + System.Core
        assert_eq!(graph.dependency_count(), 2);

        let deps = graph.get_dependencies(&app);
        assert_eq!(deps.len(), 2);

        // Test topological sorting on integrated graph
        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 3);

        // App should come last in loading order
        let app_pos = order
            .iter()
            .position(|id| id.name == "MyApplication")
            .unwrap();
        assert_eq!(app_pos, 2); // Last in loading order
    }

    #[test]
    fn test_cycle_detection_across_modules() {
        let graph = Arc::new(AssemblyDependencyGraph::new());

        // Create A -> B -> C -> A cycle using different dependency types
        let a = create_test_identity("AssemblyA", 1, 0);
        let b = create_test_identity("AssemblyB", 1, 0);
        let c = create_test_identity("AssemblyC", 1, 0);

        let b_dep = AssemblyDependency {
            source: DependencySource::AssemblyRef(create_test_assembly_ref("AssemblyB")),
            target_identity: b.clone(),
            dependency_type: DependencyType::Reference,
            version_requirement: VersionRequirement::Compatible,
            is_optional: false,
            resolution_state: DependencyResolutionState::Unresolved,
        };

        let c_dep = AssemblyDependency {
            source: DependencySource::AssemblyRef(create_test_assembly_ref("AssemblyC")),
            target_identity: c.clone(),
            dependency_type: DependencyType::Friend, // Different dependency type
            version_requirement: VersionRequirement::Exact,
            is_optional: true,
            resolution_state: DependencyResolutionState::Unresolved,
        };

        let a_dep = AssemblyDependency {
            source: DependencySource::AssemblyRef(create_test_assembly_ref("AssemblyA")),
            target_identity: a.clone(),
            dependency_type: DependencyType::TypeForwarding, // Yet another type
            version_requirement: VersionRequirement::Minimum(AssemblyVersion::new(1, 0, 0, 0)),
            is_optional: false,
            resolution_state: DependencyResolutionState::Unresolved,
        };

        graph.add_dependency_with_source(&a, b_dep).unwrap();
        graph.add_dependency_with_source(&b, c_dep).unwrap();
        graph.add_dependency_with_source(&c, a_dep).unwrap();

        // Verify cycle detection works across different dependency types
        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_some());

        let cycle = cycles.unwrap();
        assert!(cycle.len() >= 3); // Should detect the 3-assembly cycle

        // Verify SCC-based topological sort succeeds even with cycles
        let topo_result = graph.topological_order();
        assert!(topo_result.is_ok());

        // The result should contain all assemblies, even in cycles
        let order = topo_result.unwrap();
        assert_eq!(order.len(), 3); // All three assemblies should be in the order
    }

    #[test]
    fn test_concurrent_operations_integration() {
        let graph = Arc::new(AssemblyDependencyGraph::new());
        let mut handles = vec![];

        // Spawn threads that perform different operations concurrently
        for i in 0..5 {
            let graph_clone = graph.clone();
            let handle = thread::spawn(move || {
                let app = create_test_identity(&format!("App{}", i), 1, 0);
                let lib_dep = create_test_dependency("SharedLib", DependencyType::Reference);
                let core_dep = create_test_dependency("System.Core", DependencyType::Reference);

                // Add multiple dependencies per thread
                graph_clone
                    .add_dependency_with_source(&app, lib_dep)
                    .unwrap();
                graph_clone
                    .add_dependency_with_source(&app, core_dep)
                    .unwrap();
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify final state
        assert_eq!(graph.assembly_count(), 7); // 5 Apps + SharedLib + System.Core
        assert_eq!(graph.dependency_count(), 10); // 2 deps per app

        // Verify no cycles were introduced
        let cycles = graph.find_cycles().unwrap();
        assert!(cycles.is_none());

        // Verify topological ordering still works
        let order = graph.topological_order().unwrap();
        assert_eq!(order.len(), 7);
    }
}
