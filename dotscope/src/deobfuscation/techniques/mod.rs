//! Technique-centric deobfuscation framework.
//!
//! This module defines the core abstractions for technique-based deobfuscation,
//! where each deobfuscation capability is a standalone [`Technique`] that can
//! detect and transform specific obfuscation patterns independently of which
//! obfuscator produced them.
//!
//! # Trait Design
//!
//! A single [`Technique`] trait covers all capabilities. Optional capabilities
//! are expressed via default method implementations that return `None` / no-ops:
//!
//! - **IL detection**: [`Technique::detect`] — required, runs on raw IL
//! - **SSA detection**: [`Technique::detect_ssa`] — optional, runs after SSA is built
//! - **Byte transform**: [`Technique::byte_transform`] — optional, returns `None` if not applicable
//! - **SSA pass**: [`Technique::ssa_phase`] + [`Technique::create_pass`] — optional
//! - **Initialization**: [`Technique::initialize`] — optional, registers decryptors/hooks
//! - **Cleanup**: [`Technique::cleanup`] — optional, contributes tokens to remove
//! - **Capabilities**: [`Technique::capabilities`] — declares the technique's pattern
//!
//! # Implementation Patterns
//!
//! ## Pattern A — Technique-owned SSA pass
//!
//! `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `Some(pass)`.
//! The technique owns and controls its SSA transformation.
//!
//! Examples: `bitmono.calli` (calli reversal), `generic.opaquefields` (opaque predicate removal)
//!
//! ## Pattern B — Shared infrastructure contributor
//!
//! `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `None`.
//! The technique registers decryptors or hooks in `initialize()` that feed
//! a shared pass like `DecryptionPass`.
//!
//! Examples: `generic.strings`, `confuserex.constants`, `obfuscar.strings`
//!
//! ## Pattern C — Byte-only transform
//!
//! `byte_transform()` returns `Some(...)`, `ssa_phase()` returns `None`.
//! Used for PE/metadata patching without SSA involvement.
//!
//! Examples: `bitmono.pe` (PE header repair), `confuserex.tamper` (anti-tamper decryption)
//!
//! ## Pattern D — Detection only
//!
//! Neither byte transform nor SSA pass. Provides detection for attribution
//! and may contribute cleanup tokens.
//!
//! Examples: `confuserex.marker` (marker attribute detection)

mod assembly;
pub mod bitmono;
mod confuserex;
mod detection;
pub mod generic;
pub mod jiejienet;
pub mod netreactor;
mod obfuscar;
mod registry;
mod result;

use std::sync::Arc;

pub use assembly::WorkingAssembly;
// Re-export findings types needed by infrastructure passes and the engine.
#[cfg(feature = "legacy-crypto")]
pub use bitmono::StringFindings as BitMonoStringFindings;
pub use detection::{AttributionResult, Detection, Detections, Evidence};
pub use registry::{ObfuscatorMatcher, ObfuscatorSignature, TechniqueRegistry};
pub use result::{TechniqueResult, TechniqueResults};

use crate::{
    analysis::CilTarget,
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, EventLog, PassPhase, SsaPass},
    deobfuscation::{config::EngineConfig, context::AnalysisContext},
    metadata::token::Token,
    CilObject, Result,
};

/// Broad category for a technique, used for ordering and grouping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TechniqueCategory {
    /// Metadata-level transformations (renaming, attribute removal).
    Metadata,
    /// Protection removal (anti-tamper, anti-debug, anti-dump).
    Protection,
    /// Structural recovery (control-flow unflattening, proxy removal).
    Structure,
    /// Value recovery (string/constant decryption, array decryption).
    Value,
    /// Call-site transforms (delegate resolution, devirtualization).
    Call,
    /// Neutralization of obfuscation infrastructure.
    Neutralization,
}

/// Declares a capability pattern that a technique provides.
///
/// Used by the engine to understand which lifecycle methods are meaningful
/// for each technique. Techniques implement [`Technique::capabilities()`]
/// to declare their pattern:
///
/// - **ByteTransform**: Modifies raw PE bytes before SSA construction.
///   Engine calls `byte_transform()` and optionally `requires_regeneration()`.
///   Examples: `bitmono.pe` (PE header repair), `confuserex.tamper` (anti-tamper decryption).
///
/// - **SsaPass**: Creates a technique-owned SSA pass for the scheduler.
///   Engine calls `initialize()` + `create_pass()` + `cleanup()`.
///   Examples: `bitmono.calli` (calli reversal), `generic.opaquefields` (opaque predicate removal).
///
/// - **Infrastructure**: Contributes to shared passes (e.g., registers decryptors
///   with `DecryptorContext`). Engine calls `initialize()` but the technique
///   returns `None` from `create_pass()`.
///   Examples: `generic.strings`, `confuserex.constants` — both feed `DecryptionPass`.
///
/// - **DetectionOnly**: Provides detection and attribution only. No byte transform,
///   no SSA pass. May contribute cleanup tokens.
///   Examples: `confuserex.marker` (marker attribute detection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TechniqueCapability {
    /// Modifies raw PE bytes before SSA construction.
    ByteTransform,
    /// Creates a technique-owned SSA pass for the scheduler.
    SsaPass,
    /// Contributes to shared infrastructure (decryptors, hooks) without owning a pass.
    Infrastructure,
    /// Provides detection and attribution only.
    DetectionOnly,
}

/// Unified trait for all deobfuscation techniques.
///
/// Object-safe, `Send + Sync`. Every technique must provide identity, category,
/// and IL-level detection. All other capabilities (byte transform, SSA pass,
/// SSA-level detection) are expressed as optional default implementations.
///
/// # Capability Model
///
/// - **Byte transform** (`byte_transform` returns `Some`): technique can patch raw bytes
///   before SSA is built. Only runs when the technique is detected.
/// - **SSA pass** (`ssa_phase` returns `Some`): technique participates in the pass scheduler.
/// - **SSA detection** (`detect_ssa` returns non-empty): supplements IL detection with
///   def-use chain analysis after SSA is built, enabling cross-block pattern matching.
///
/// # Implementation Patterns
///
/// ## Pattern A — Technique-owned SSA pass
///
/// `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `Some(pass)`.
/// Used when the SSA transform is specific to this technique, e.g.:
/// - `generic.opaquefields` (`GenericOpaquePredicates`): creates `OpaqueFieldPredicatePass`
/// - `generic.delegates` (`GenericDelegateProxy`): creates `DelegateProxyResolutionPass`
///
/// ## Pattern B — Contributes to shared infrastructure
///
/// `ssa_phase()` returns `Some(phase)` and `create_pass()` returns `None`.
/// The technique registers decryptors or hooks in `initialize()`.
/// Used when multiple techniques feed a shared pass:
/// - `generic.strings`, `generic.constants`, `confuserex.constants`: all feed `DecryptionPass`
///
/// ## Pattern C — Byte-only transform
///
/// `byte_transform()` returns `Some(...)`, `ssa_phase()` returns `None`.
/// Used for PE/metadata patching without SSA involvement.
pub trait Technique: Send + Sync {
    /// Unique identifier (e.g. `"confuserex.constants"`).
    fn id(&self) -> &'static str;

    /// Human-readable name (e.g. `"ConfuserEx Constant Decryption"`).
    fn name(&self) -> &'static str;

    /// Broad category for ordering.
    fn category(&self) -> TechniqueCategory;

    /// Detect whether this technique's target pattern is present in raw IL.
    fn detect(&self, assembly: &CilObject) -> Detection;

    /// IDs of techniques that must run before this one.
    fn requires(&self) -> &[&'static str] {
        &[]
    }

    /// IDs of techniques this one replaces (older/weaker versions).
    fn supersedes(&self) -> &[&'static str] {
        &[]
    }

    /// Whether this technique is enabled under the given config.
    fn enabled(&self, _config: &EngineConfig) -> bool {
        true
    }

    /// Optional detection that runs after all methods' SSA is built.
    ///
    /// Returns a non-empty [`Detection`] if the technique found additional
    /// evidence using SSA def-use chains. The engine merges this into the
    /// existing IL-level detections via [`Detections::merge`].
    ///
    /// Use this for patterns that span basic block boundaries and cannot be
    /// reliably detected from raw IL instruction windows.
    fn detect_ssa(&self, _ctx: &AnalysisContext, _assembly: &CilObject) -> Detection {
        Detection::new_empty()
    }

    /// Apply a byte-level transform on the raw assembly bytes.
    ///
    /// Returns `Some(Ok(events))` on success, `Some(Err(e))` on failure,
    /// or `None` if this technique has no byte transform or nothing to transform
    /// in the assembly as it stands. A `None` or a failure is not retried, nor
    /// counted as pending work, until another transform changes the assembly.
    ///
    /// Byte transforms run before SSA is built and can patch raw bytes,
    /// decrypt method bodies, or unpack resources. A transform can add to its
    /// detection's cleanup what it learned while running, such as a resource
    /// it consumed that detection could not name; cleanup requests accumulate
    /// across re-detection, where findings are replaced.
    fn byte_transform(
        &self,
        _assembly: &mut WorkingAssembly,
        _detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        None
    }

    /// If `true`, the assembly must be fully regenerated after this technique's byte transform.
    fn requires_regeneration(&self) -> bool {
        false
    }

    /// Which scheduler phase this technique's pass runs in. `None` = no SSA pass.
    fn ssa_phase(&self) -> Option<PassPhase> {
        None
    }

    /// One-time initialization after detection (e.g. register decryptors).
    ///
    /// Called in Phase 4 after all SSA is available in `ctx`. Techniques
    /// use this to register decryptors, hook factories, or other shared state.
    fn initialize(
        &self,
        _ctx: &AnalysisContext,
        _assembly: &CilObject,
        _detection: &Detection,
        _detections: &Detections,
    ) {
    }

    /// Create an SSA pass instance for the pipeline.
    ///
    /// Called after [`initialize`](Self::initialize), so the context has been
    /// fully populated by all techniques. Returns `None` for Pattern B techniques
    /// that contribute to shared infrastructure instead of owning their own pass.
    ///
    /// # Arguments
    ///
    /// * `_ctx` - The shared analysis context.
    /// * `_detection` - Detection findings for this technique.
    /// * `_assembly` - The assembly being processed (needed for passes that require it at construction).
    ///
    /// # Returns
    ///
    /// A vec of passes owned by this technique, empty for Pattern B techniques.
    /// Most techniques return 0 or 1 passes; techniques that detect multiple
    /// patterns (e.g., `GenericDelegateProxy`) may return multiple passes.
    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        _detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        Vec::new()
    }

    /// Tokens / sections to clean up after all passes complete.
    fn cleanup(&self, _detection: &Detection) -> Option<CleanupRequest> {
        None
    }

    /// Methods this technique was responsible for restoring, reported when its
    /// transform did not succeed.
    ///
    /// A technique that rewrites method bodies — decrypting them, unpacking
    /// them — leaves those methods in their protected form when it fails. Such a
    /// method carries no calls, so nothing it references looks reachable and
    /// cleanup reads the whole region as dead. It is not dead: it is the
    /// original code, and the sample is kept precisely to analyse it later.
    ///
    /// Only consulted when the technique is detected and its transform did not
    /// complete, so an implementation may return its full candidate set without
    /// checking whether the run succeeded.
    fn unrecovered_methods(&self, _detection: &Detection) -> Vec<Token> {
        Vec::new()
    }

    /// Declares the technique's capability patterns.
    ///
    /// The engine uses this to understand which lifecycle methods are
    /// meaningful. Defaults to inferring from `ssa_phase()`:
    /// - If `ssa_phase()` is `Some` → `[SsaPass]`
    /// - Otherwise → `[DetectionOnly]`
    ///
    /// Techniques with byte transforms or infrastructure patterns should
    /// override this method.
    fn capabilities(&self) -> Vec<TechniqueCapability> {
        if self.ssa_phase().is_some() {
            vec![TechniqueCapability::SsaPass]
        } else {
            vec![TechniqueCapability::DetectionOnly]
        }
    }

    /// Called at the start of each outer loop iteration, after work items have
    /// been applied but before the pass scheduler runs.
    ///
    /// Allows techniques to react to assembly changes (e.g., re-extract bytecode
    /// offsets from a reloaded assembly). The default implementation is a no-op.
    fn on_iteration_start(&self, _ctx: &AnalysisContext, _assembly: &CilObject) -> Result<()> {
        Ok(())
    }
}
