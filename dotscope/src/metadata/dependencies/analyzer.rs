//! The handle that adds dependencies to an assembly dependency graph.

use std::sync::Arc;

use crate::metadata::dependencies::AssemblyDependencyGraph;

/// Adds dependency relationships to an [`AssemblyDependencyGraph`].
///
/// It holds the graph it feeds; dependencies are added through
/// [`dependency_graph`](Self::dependency_graph), whose graph synchronises concurrent updates,
/// so several analyzers can share one graph.
///
/// # Examples
///
/// ```no_run
/// use std::sync::Arc;
///
/// use dotscope::{
///     metadata::{
///         dependencies::{
///             AssemblyDependency, AssemblyDependencyGraph, DependencyAnalyzer,
///             DependencyResolutionState, DependencySource, DependencyType, VersionRequirement,
///         },
///         identity::AssemblyIdentity,
///     },
///     CilObject,
/// };
///
/// // The assemblies an application references, as edges of a dependency graph
/// let assembly = CilObject::from_path("app.dll")?;
/// let app = assembly.identity().expect("an assembly, not a module");
///
/// let graph = Arc::new(AssemblyDependencyGraph::new());
/// let analyzer = DependencyAnalyzer::new(graph.clone());
/// for entry in assembly.refs_assembly().iter() {
///     let reference = entry.value().clone();
///     analyzer.dependency_graph().add_dependency_with_source(
///         &app,
///         AssemblyDependency {
///             target_identity: AssemblyIdentity::from_assembly_ref(&reference),
///             source: DependencySource::AssemblyRef(reference),
///             dependency_type: DependencyType::Reference,
///             version_requirement: VersionRequirement::Compatible,
///             is_optional: false,
///             resolution_state: DependencyResolutionState::Unresolved,
///         },
///     )?;
/// }
///
/// assert_eq!(graph.dependency_count(), assembly.refs_assembly().len());
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct DependencyAnalyzer {
    /// The graph dependencies are added to; it handles concurrent access.
    graph: Arc<AssemblyDependencyGraph>,
}

impl DependencyAnalyzer {
    /// Creates an analyzer that adds dependencies to `graph`.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, DependencyAnalyzer};
    ///
    /// let graph = Arc::new(AssemblyDependencyGraph::new());
    /// let analyzer = DependencyAnalyzer::new(graph);
    /// assert_eq!(analyzer.dependency_graph().assembly_count(), 0);
    /// ```
    #[must_use]
    pub fn new(graph: Arc<AssemblyDependencyGraph>) -> Self {
        Self { graph }
    }

    /// The graph this analyzer adds dependencies to.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::sync::Arc;
    ///
    /// use dotscope::metadata::dependencies::{AssemblyDependencyGraph, DependencyAnalyzer};
    ///
    /// let graph = Arc::new(AssemblyDependencyGraph::new());
    /// let analyzer = DependencyAnalyzer::new(graph);
    /// let graph_ref = analyzer.dependency_graph();
    /// assert_eq!(graph_ref.dependency_count(), 0);
    /// ```
    #[must_use]
    pub fn dependency_graph(&self) -> &Arc<AssemblyDependencyGraph> {
        &self.graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dependency_analyzer_creation() {
        let graph = Arc::new(AssemblyDependencyGraph::new());
        let analyzer = DependencyAnalyzer::new(graph.clone());
        assert_eq!(analyzer.dependency_graph().assembly_count(), 0);
    }
}
