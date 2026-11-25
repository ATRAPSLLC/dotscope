//! CIL-side pass scheduler — thin wrapper around
//! [`analyssa::scheduling::PassScheduler`].
//!
//! All scheduling logic (capability layer assignment, fixpoint
//! iteration, parallel per-method dispatch, modification-scope-driven
//! repair) lives in analyssa. This module provides a CIL-flavored facade
//! that:
//!
//! - Maps [`PassPhase`] enum values to fallback layer numbers.
//! - Sets the assembly handle on the context before invoking the
//!   underlying scheduler.
//! - Bridges error types between analyssa and dotscope.
//!
//! Hosts targeting other ISAs use analyssa's scheduler directly.

use std::sync::Arc;

use analyssa::scheduling::{FailurePolicy, PassScheduler as AnalyssaPassScheduler, PipelineConfig};

use crate::{
    analysis::CilTarget,
    compiler::{
        context::CompilerContext,
        pass::{PassPhase, SsaPass},
        state::ProcessingState,
    },
    CilObject, Error, Result,
};

/// Orchestrates CIL SSA pass execution.
///
/// Wraps [`analyssa::scheduling::PassScheduler<CilTarget, CompilerContext>`]
/// with CIL-specific phase mapping. Passes are added with a
/// [`PassPhase`]; layered passes go through capability-based scheduling
/// in analyssa, normalize passes interleave between layer fixpoint
/// iterations.
///
/// # Example
///
/// ```
/// use std::sync::Arc;
/// use dotscope::analysis::CallGraph;
/// use dotscope::compiler::{
///     CompilerContext, ConstantPropagationPass, DeadMethodEliminationPass, PassPhase,
///     PassScheduler,
/// };
/// use dotscope::CilObject;
///
/// let assembly = Arc::new(CilObject::from_path("tests/samples/crafted_2.exe")?);
/// let ctx = CompilerContext::new(Arc::new(CallGraph::build(&assembly)?));
///
/// let mut scheduler = PassScheduler::new();
/// scheduler.add(Box::new(ConstantPropagationPass), PassPhase::Value);
/// scheduler.add(Box::new(DeadMethodEliminationPass::new()), PassPhase::Normalize);
/// scheduler.run_pipeline(&ctx, &assembly, None)?;
/// # Ok::<(), dotscope::Error>(())
/// ```
pub struct PassScheduler {
    inner: AnalyssaPassScheduler<CilTarget, CompilerContext>,
}

impl Default for PassScheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl PassScheduler {
    /// Creates a scheduler with no passes.
    ///
    /// Its rounds are the context's work budget's
    /// ([`CompilerContext::budget`]): the pipeline's
    /// [`Budget::PipelineRounds`](analyssa::analysis::Budget::PipelineRounds),
    /// stopping after [`Budget::StableRounds`](analyssa::analysis::Budget::StableRounds)
    /// that change nothing, and
    /// [`Budget::PhaseRounds`](analyssa::analysis::Budget::PhaseRounds) a layer.
    #[must_use]
    pub fn new() -> Self {
        // dotscope populates the scheduler with its own CIL passes (gated by
        // engine config), so start from an empty analyssa scheduler rather
        // than the default built-in pipeline. Only the `verify_hard` flag and
        // the failure policy are consumed by `empty`; the remaining
        // `PipelineConfig` fields choose analyssa's built-in passes, which we
        // do not register here.
        //
        // A pass that fails on one method is rolled back for that method and
        // recorded as an event: one method no pass can handle used to fail
        // the whole assembly.
        let config = PipelineConfig {
            on_method_failure: FailurePolicy::RollbackAndContinue,
            ..PipelineConfig::default()
        };
        Self {
            inner: AnalyssaPassScheduler::empty(config),
        }
    }

    /// Returns the number of non-normalize passes registered.
    #[must_use]
    pub fn pass_count(&self) -> usize {
        self.inner.pass_count()
    }

    /// Returns the number of normalization passes registered.
    #[must_use]
    pub fn normalize_count(&self) -> usize {
        self.inner.normalize_count()
    }

    /// Adds a pass to the scheduler with its execution phase.
    ///
    /// `Normalize` passes go to the analyssa normalize-pass list (run
    /// between every layer's fixpoint iterations). All other phases map
    /// to their numeric fallback layer via [`PassPhase::as_layer`].
    pub fn add(&mut self, pass: Box<dyn SsaPass<CilTarget, CompilerContext>>, phase: PassPhase) {
        match phase {
            PassPhase::Normalize => self.inner.add_normalize(pass),
            other => self.inner.add_at_layer(pass, other.as_layer()),
        }
    }

    /// Runs the complete deobfuscation pipeline.
    ///
    /// `assembly` is stored on `ctx` via [`CompilerContext::set_assembly`]
    /// so passes that need it (inlining, proxy devirt, constant folding)
    /// can reach it through the host. `state` is currently a no-op
    /// parameter retained for source-compatibility; dirty tracking
    /// flows through `ctx.processing_state`.
    ///
    /// # Errors
    ///
    /// Returns an error if a cycle is detected in the capability
    /// dependency graph or any pass fails.
    pub fn run_pipeline(
        &mut self,
        ctx: &CompilerContext,
        assembly: &Arc<CilObject>,
        _state: Option<&ProcessingState>,
    ) -> Result<usize> {
        ctx.set_assembly(assembly.clone());
        let result = self
            .inner
            .run_pipeline(ctx)
            .map_err(|e| Error::SsaError(e.0));
        // Release the in-context assembly handle so callers can unwrap
        // the `Arc<CilObject>` for code generation. Without this, the
        // strong-count never drops to one and `Arc::try_unwrap` fails.
        ctx.clear_assembly();
        result
    }
}
