//! Built-in SSA optimization passes.
//!
//! This module contains the standard SSA transformation passes used for
//! SSA-based code transformation. Each pass operates on SSA form and returns an
//! [`EventLog`](crate::compiler::EventLog) describing the modifications made.
//!
//! # Pipeline Phases
//!
//! The [`PassScheduler`](crate::compiler::PassScheduler) organizes passes into
//! phases that run in a specific order. Within each phase, passes run
//! iteratively until a fixpoint is reached.
//!
//! ## Phase 1: Normalization
//!
//! Cleans up code and propagates values.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadCodeEliminationPass`] | Removes unreachable blocks, unused definitions, and op-less instructions |
//! | [`BlockMergingPass`] | Eliminates trampoline blocks (single-jump blocks) |
//! | [`ConstantPropagationPass`] | Propagates and folds constant values using SCCP |
//! | [`GlobalValueNumberingPass`] | Eliminates redundant computations via value numbering |
//! | [`CopyPropagationPass`] | Eliminates redundant copy operations and phi nodes |
//! | [`MemoryOptimizationPass`] | Forwards stores to loads, drops redundant loads, removes dead stores |
//! | [`StrengthReductionPass`] | Replaces expensive operations with cheaper equivalents |
//! | [`AlgebraicSimplificationPass`] | Simplifies algebraic expressions (x + 0 → x, etc.) |
//! | [`ReassociationPass`] | Reorders associative operations for optimization |
//!
//! ## Phase 2: Opaque Predicate Removal
//!
//! Removes always-true/false conditions.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`OpaquePredicatePass`] | Removes always-true/false conditions, simplifies comparisons |
//!
//! ## Phase 3: CFG Recovery
//!
//! Simplifies control flow after predicate removal.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`ControlFlowSimplificationPass`] | Jump threading, branch simplification, dead tail removal |
//! | [`LoopCanonicalizationPass`] | Ensures loops have single preheaders and latches |
//! | [`JumpThreadingPass`] | Threads jumps through empty blocks |
//!
//! ## Phase 4: Inlining
//!
//! Inlines small methods and proxy functions.
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`InliningPass`] | Inlines small methods and constant-returning functions |
//!
//! # Utility Passes
//!
//! These passes are available but not part of the standard pipeline:
//!
//! | Pass | Description |
//! |------|-------------|
//! | [`DeadMethodEliminationPass`] | Identifies and marks methods with no live callers |
//! | [`LicmPass`] | Loop-invariant code motion optimization |
//! | [`ProxyDevirtualizationPass`] | Devirtualizes proxy forwarding methods and eliminates no-op calls |
//! | [`ValueRangePropagationPass`] | Propagates value range information |
//!
//! # Pass Execution
//!
//! Passes are executed by the [`PassScheduler`](crate::compiler::PassScheduler)
//! phase by phase. Within each phase, passes run iteratively until no more changes
//! occur. Each pass implements the [`SsaPass`](crate::compiler::SsaPass) trait.
//!
//! # Analysis Integration
//!
//! Many passes integrate with the analysis infrastructure:
//!
//! - **SCCP** ([`ConstantPropagation`](crate::analysis::ConstantPropagation)): Used by
//!   constant propagation for precise value tracking
//! - **Loop Analysis** ([`LoopAnalyzer`](crate::analysis::LoopAnalyzer)): Used by
//!   loop canonicalization to identify and restructure loops

mod constants;
mod copying;
mod deadcode;
mod inlining;
mod proxy;

// Re-export the analyssa-supplied target-agnostic pass structs at the
// dotscope namespace so existing callers (registered via
// `compiler::PassScheduler`) keep working.
pub use analyssa::passes::{
    AlgebraicSimplificationPass, BlockMergingPass, ControlFlowSimplificationPass,
    DeadCodeEliminationPass, GlobalValueNumberingPass, JumpThreadingPass, LicmPass,
    LoopCanonicalizationPass, MemoryOptimizationPass, OpaquePredicatePass, PredicateResult,
    ReassociationPass, StrengthReductionPass, ValueRangePropagationPass,
};
pub use proxy::{ForwardKind, ProxyArgSource};

// CIL-specific pass impls remain dotscope-side. `copying` keeps its custom
// hook (CIL local-type propagation); `deadcode` keeps its CIL-call-graph-aware
// `DeadMethodEliminationPass`; `constants`, `inlining`, `proxy` are
// CIL-specific in their entirety.
pub use self::constants::ConstantPropagationPass;
pub use self::{
    copying::CopyPropagationPass, deadcode::DeadMethodEliminationPass, inlining::InliningPass,
    proxy::ProxyDevirtualizationPass,
};
