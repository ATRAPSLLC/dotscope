//! Technique initialization and configuration for the deobfuscation engine.

use std::sync::Arc;

use crate::{
    compiler::PassScheduler,
    deobfuscation::{
        context::AnalysisContext, engine::DeobfuscationEngine, techniques::Detections,
    },
    CilObject,
};

impl DeobfuscationEngine {
    /// Initializes detected techniques by registering decryptors, emulation hooks,
    /// warmup methods, and other state needed by their SSA passes.
    ///
    /// Tracks initialization via `ctx.initialized_techniques` to prevent
    /// double-initialization across detection re-scan rounds.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context for registering hooks, warmup methods, etc.
    /// * `assembly` - The assembly for metadata lookups.
    /// * `detections` - Detection results with findings for each technique.
    pub fn initialize_techniques(
        &self,
        ctx: &AnalysisContext,
        assembly: &CilObject,
        detections: &Detections,
    ) {
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            if tech.ssa_phase().is_none() {
                continue;
            }
            if ctx.initialized_techniques.contains(tech.id()) {
                continue;
            }
            let Some(detection) = detections.get(tech.id()) else {
                continue;
            };
            tech.initialize(ctx, assembly, detection, detections);
            ctx.initialized_techniques.insert(tech.id());
        }
    }

    /// Initializes detected techniques and creates their SSA passes in a single traversal.
    ///
    /// For each detected technique with an SSA phase (in dependency order):
    /// 1. Calls [`Technique::initialize`](crate::deobfuscation::Technique::initialize) if not already initialized
    /// 2. Calls [`Technique::create_pass`](crate::deobfuscation::Technique::create_pass) if pass not already created
    ///
    /// This merges the previously separate `initialize_techniques()` and
    /// `create_technique_passes()` to avoid redundant `sorted_techniques()` traversals.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context for registering hooks, warmup methods, pass creation, etc.
    /// * `assembly` - The assembly (shared reference for initialization and pass construction).
    /// * `detections` - Detection results with findings for each technique.
    /// * `scheduler` - The pass scheduler to add technique passes to.
    pub fn initialize_and_create_passes(
        &self,
        ctx: &AnalysisContext,
        assembly: &Arc<CilObject>,
        detections: &Detections,
        scheduler: &mut PassScheduler,
    ) {
        for tech in self.registry.sorted_techniques(detections) {
            if !detections.is_detected(tech.id()) {
                continue;
            }
            let Some(phase) = tech.ssa_phase() else {
                continue;
            };
            let Some(detection) = detections.get(tech.id()) else {
                continue;
            };

            // Initialize if not already done
            if !ctx.initialized_techniques.contains(tech.id()) {
                tech.initialize(ctx, assembly, detection, detections);
                ctx.initialized_techniques.insert(tech.id());
            }

            // Create passes if not already done
            if !ctx.passes_created.contains(tech.id()) {
                let passes = tech.create_pass(ctx, detection, assembly);
                if !passes.is_empty() {
                    for pass in passes {
                        scheduler.add(pass, phase);
                    }
                    ctx.passes_created.insert(tech.id());
                }
            }
        }
    }

    /// Marks dispatcher and decryptor methods as non-inlinable.
    ///
    /// CFF dispatchers should not be inlined because they are unflattened in
    /// place. Decryptor methods should not be inlined because the
    /// [`DecryptionPass`](crate::deobfuscation::passes::DecryptionPass) needs
    /// to see them as intact call targets.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context containing dispatcher and decryptor token sets.
    pub fn configure_no_inline(&self, ctx: &AnalysisContext) {
        for token in ctx.dispatchers.iter() {
            ctx.compiler.no_inline.insert(*token);
        }
        for token in ctx.decryptors.registered_tokens() {
            ctx.compiler.no_inline.insert(token);
        }
    }

    /// Returns `true` if any technique has registered emulation requirements.
    ///
    /// Checks for decryptors, warmup methods, emulation hooks, or state machine
    /// providers - any of which indicate that passes will need emulation.
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context to inspect for emulation requirements.
    pub fn needs_emulation(ctx: &AnalysisContext) -> bool {
        ctx.decryptors.has_decryptors()
            || ctx.has_warmup_methods()
            || ctx.has_emulation_hooks()
            || ctx.has_statemachine_providers()
    }
}
