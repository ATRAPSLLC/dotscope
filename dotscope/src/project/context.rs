//! Project context for coordinating multi-assembly parallel loading.
//!
//! This module provides the `ProjectContext` which manages barrier synchronization
//! during parallel assembly loading to handle circular dependencies safely.

use std::sync::Arc;

use boxcar::Vec as BoxcarVec;

use crate::{
    metadata::{identity::AssemblyIdentity, typesystem::TypeRegistry},
    utils::FailFastBarrier,
    Error, Result,
};

/// Coordination context for multi-assembly parallel loading with barrier synchronization.
///
/// `ProjectContext` manages the parallel loading of multiple assemblies that may have circular
/// dependencies. It uses barrier synchronization to ensure all assemblies complete specific
/// loading stages before any assembly proceeds to cross-assembly dependent operations.
///
/// # Loading Stages
///
/// 1. **Stage 1**: Basic setup and TypeRegistry creation
/// 2. **Stage 2**: Type definitions and basic metadata loading
/// 3. **Stage 3**: Cross-assembly references and custom attributes
/// 4. **Stage 4**: All loaders completed (before validation)
///
/// # Thread Safety
///
/// `ProjectContext` is designed for safe concurrent access across multiple loading threads.
/// It uses atomic counters and fail-fast barriers for coordination.
pub(crate) struct ProjectContext {
    /// Total number of assemblies being loaded in parallel
    total_count: usize,

    /// Barrier for stage 1 completion (TypeRegistry creation)
    stage1_barrier: Arc<FailFastBarrier>,

    /// Barrier for stage 2 completion (type definitions loaded)
    stage2_barrier: Arc<FailFastBarrier>,

    /// Barrier for stage 3 completion (inheritance resolution completed)
    stage3_barrier: Arc<FailFastBarrier>,

    /// Barrier for stage 4 completion (all loaders completed, before validation)
    stage4_barrier: Arc<FailFastBarrier>,

    /// Lock-free storage for assembly identities and their TypeRegistries
    /// Used for cross-registry linking after stage 1
    registries: BoxcarVec<(AssemblyIdentity, Arc<TypeRegistry>)>,
}

impl ProjectContext {
    /// Create a new `ProjectContext` for coordinating the loading of `total_count` assemblies.
    ///
    /// # Arguments
    /// * `total_count` - The number of assemblies that will be loaded in parallel
    ///
    /// # Returns
    /// A new `ProjectContext` ready for coordinating multi-assembly loading.
    ///
    /// # Errors
    /// Returns an error if `total_count` is 0.
    pub fn new(total_count: usize) -> Result<Self> {
        Ok(Self {
            total_count,
            stage1_barrier: Arc::new(FailFastBarrier::new(total_count)?),
            stage2_barrier: Arc::new(FailFastBarrier::new(total_count)?),
            stage3_barrier: Arc::new(FailFastBarrier::new(total_count)?),
            stage4_barrier: Arc::new(FailFastBarrier::new(total_count)?),
            registries: BoxcarVec::new(),
        })
    }

    /// Wait for all assemblies to complete stage 1 (TypeRegistry creation).
    ///
    /// This method blocks until all assemblies have created their TypeRegistries
    /// and are ready to proceed to cross-assembly linking.
    ///
    /// # Returns
    /// `Ok(())` if all assemblies completed stage 1 successfully, or an error
    /// if any assembly failed during this stage.
    pub fn wait_stage1(&self) -> Result<()> {
        self.stage1_barrier
            .wait()
            .map_err(|e| Error::LockError(format!("Stage 1 barrier failed: {e}")))
    }

    /// Wait for all assemblies to complete stage 2 (type definitions loaded).
    ///
    /// This method blocks until all assemblies have loaded their basic type
    /// definitions and are ready for inheritance resolution.
    ///
    /// # Returns
    /// `Ok(())` if all assemblies completed stage 2 successfully, or an error
    /// if any assembly failed during this stage.
    pub fn wait_stage2(&self) -> Result<()> {
        self.stage2_barrier
            .wait()
            .map_err(|e| Error::LockError(format!("Stage 2 barrier failed: {e}")))
    }

    /// Wait for all assemblies to complete stage 3 (inheritance resolution completed).
    ///
    /// This method blocks until all assemblies have resolved inheritance relationships
    /// and are ready for final cross-assembly operations.
    ///
    /// # Returns
    /// `Ok(())` if all assemblies completed stage 3 successfully, or an error
    /// if any assembly failed during this stage.
    pub fn wait_stage3(&self) -> Result<()> {
        self.stage3_barrier
            .wait()
            .map_err(|e| Error::LockError(format!("Stage 3 barrier failed: {e}")))
    }

    /// Wait for all assemblies to complete stage 4 (all loaders completed).
    ///
    /// This method blocks until all assemblies have completed all metadata loaders,
    /// including nested class relationships. This ensures all cross-assembly type
    /// references (including nested types) are fully populated before validation.
    ///
    /// # Returns
    /// `Ok(())` if all assemblies completed stage 4 successfully, or an error
    /// if any assembly failed during this stage.
    pub fn wait_stage4(&self) -> Result<()> {
        self.stage4_barrier
            .wait()
            .map_err(|e| Error::LockError(format!("Stage 4 barrier failed: {e}")))
    }

    /// Register a TypeRegistry for cross-assembly linking after stage 1.
    ///
    /// This method should be called by each assembly loading thread after
    /// successfully creating its TypeRegistry during stage 1.
    ///
    /// # Arguments
    /// * `identity` - The identity of the assembly
    /// * `registry` - The TypeRegistry created for this assembly
    pub fn register_type_registry(&self, identity: AssemblyIdentity, registry: Arc<TypeRegistry>) {
        self.registries.push((identity, registry));
    }

    /// Get all registered TypeRegistries for cross-assembly operations.
    ///
    /// This method provides access to all TypeRegistries from assemblies
    /// that have completed stage 1. It should typically be called after
    /// `wait_stage1()` returns successfully.
    ///
    /// # Returns
    /// A vector of (AssemblyIdentity, TypeRegistry) pairs for all registered assemblies.
    pub fn get_registries(&self) -> Vec<(AssemblyIdentity, Arc<TypeRegistry>)> {
        let mut registries = Vec::new();
        for (_, entry) in &self.registries {
            registries.push(entry.clone());
        }
        registries
    }

    /// Get the total number of assemblies being coordinated.
    pub fn total_count(&self) -> usize {
        self.total_count
    }

    /// Break all barriers to prevent deadlocks when any assembly fails.
    ///
    /// This method should be called when any assembly loading thread encounters
    /// a failure that should abort the entire loading process. It breaks all
    /// synchronization barriers to prevent other threads from waiting indefinitely.
    ///
    /// # Arguments
    /// * `error_message` - Description of the failure that triggered the barrier break
    pub fn break_all_barriers(&self, error_message: &str) {
        self.stage1_barrier.break_barrier(error_message);
        self.stage2_barrier.break_barrier(error_message);
        self.stage3_barrier.break_barrier(error_message);
        self.stage4_barrier.break_barrier(error_message);
    }

    /// Register a TypeRegistry and wait for stage 1 completion.
    ///
    /// This combines the registration and waiting operations for convenience.
    ///
    /// # Arguments
    /// * `identity` - The assembly identity to register
    /// * `registry` - The TypeRegistry to register
    ///
    /// # Returns
    /// `Ok(())` if registration and stage 1 completion were successful
    pub fn register_and_wait_stage1(
        &self,
        identity: AssemblyIdentity,
        registry: Arc<TypeRegistry>,
    ) -> Result<()> {
        self.register_type_registry(identity, registry);
        self.wait_stage1()
    }

    /// Link all registries for cross-assembly type resolution.
    ///
    /// This method connects all registered TypeRegistries to enable
    /// cross-assembly type resolution and dependency tracking. Each registry
    /// gets linked to all other registries in the project context.
    ///
    /// # Arguments
    /// * `current_registry` - The current TypeRegistry to link with others
    pub fn link_all_registries(&self, current_registry: &Arc<TypeRegistry>) {
        // Link the current registry to all other registered registries
        for (_, (other_identity, other_registry)) in &self.registries {
            // Don't link a registry to itself
            if !Arc::ptr_eq(current_registry, other_registry) {
                current_registry.registry_link(other_identity.clone(), other_registry);
            }
        }
    }
}
