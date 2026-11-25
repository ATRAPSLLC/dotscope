//! Compiler infrastructure for SSA-based code transformations.
//!
//! This module provides the middle layer between analysis and code generation:
//!
//! - [`crate::analysis`] — CIL → SSA construction, CFG, dataflow
//! - [`compiler`](self) — SSA optimization passes, codegen (SSA → CIL)
//! - [`crate::deobfuscation`] — Obfuscator detection, orchestration
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      Compiler Pipeline                           │
//! ├──────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  CompilerContext              Shared interprocedural state        │
//! │    ├─ SSA functions           (per-method SSA, call graph,       │
//! │    ├─ Method summaries         known values, dead methods)       │
//! │    └─ EventLog                                                   │
//! │                                                                  │
//! │  PassScheduler               Capability-based layered execution  │
//! │    ├─ Structure layer         (CFF unflattening)                 │
//! │    ├─ Value layer             (decryption)                       │
//! │    ├─ Simplify layer          (predicates, CFG, threading)       │
//! │    ├─ Inline layer            (small method inlining)            │
//! │    └─ Normalize passes        (DCE, const prop, GVN, etc.)      │
//! │    Each layer: run → normalize → repeat until stable             │
//! │                                                                  │
//! │  SsaPass trait               Interface for all passes            │
//! │    ├─ run_on_method()         Per-method transformation          │
//! │    ├─ initialize()            One-time setup before pipeline     │
//! │    └─ finalize()              Cleanup after pipeline completes   │
//! │                                                                  │
//! │  Passes (16 built-in)        Optimization transformations        │
//! │    ├─ Value: const prop, copy prop, GVN, strength reduction      │
//! │    ├─ CFG: branch simplify, jump threading, loop canon           │
//! │    ├─ Cleanup: DCE, block merging, dead method elimination       │
//! │    └─ Other: opaque predicates, algebraic, reassociation, LICM   │
//! │                                                                  │
//! │  SsaCodeGenerator            SSA → CIL roundtrip                 │
//! │    ├─ Register allocation     (SSA vars → CIL locals)            │
//! │    ├─ Phi elimination         (φ nodes → moves)                  │
//! │    └─ Instruction selection   (SSA ops → CIL bytecode)           │
//! │                                                                  │
//! │  EventLog                    Change tracking and diagnostics     │
//! │  MethodSummary               Interprocedural analysis results    │
//! │                                                                  │
//! └──────────────────────────────────────────────────────────────────┘
//! ```

mod codegen;
mod context;
#[cfg(test)]
mod differential;
mod host;
mod pass;
mod passes;
mod scheduler;
mod state;
mod summary;

pub use analyssa::events::{DerivedStats, EventKind, EventListener, NullListener};
pub use codegen::{validate_lift, CompilationResult, SsaCodeGenerator};
pub use context::CompilerContext;

use crate::analysis::CilTarget;

/// CIL-defaulted alias of [`analyssa::events::Event`].
pub type Event = analyssa::events::Event<CilTarget>;
/// CIL-defaulted alias of [`analyssa::events::EventLog`].
pub type EventLog = analyssa::events::EventLog<CilTarget>;
/// CIL-defaulted alias of [`analyssa::events::EventBuilder`].
pub type EventBuilder<'a, L = EventLog> = analyssa::events::EventBuilder<'a, CilTarget, L>;

pub use host::CilHost;
pub use pass::{
    CilCapability, DeobfuscationCapability, ModificationScope, PassCapability, PassPhase, SsaPass,
    SsaPassHost,
};
pub use passes::{
    AlgebraicSimplificationPass, BlockMergingPass, ConstantPropagationPass,
    ControlFlowSimplificationPass, CopyPropagationPass, DeadCodeEliminationPass,
    DeadMethodEliminationPass, ForwardKind, GlobalValueNumberingPass, InliningPass,
    JumpThreadingPass, LicmPass, LoopCanonicalizationPass, MemoryOptimizationPass,
    OpaquePredicatePass, PredicateResult, ProxyArgSource, ProxyDevirtualizationPass,
    ReassociationPass, StrengthReductionPass, ValueRangePropagationPass,
};
pub use scheduler::PassScheduler;
pub use state::ProcessingState;
pub use summary::{CallSiteInfo, MethodSummary, ParameterSummary};
