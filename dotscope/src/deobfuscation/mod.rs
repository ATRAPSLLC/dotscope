//! Deobfuscation framework for .NET assemblies.
//!
//! This module provides a comprehensive deobfuscation system built on SSA
//! (Static Single Assignment) form and a technique-oriented architecture
//! where each protection type is a self-contained module.
//!
//! # Architecture
//!
//! The deobfuscation pipeline is technique-oriented:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Deobfuscation Pipeline                           │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │  Input: Assembly (CilObject)                                            │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 1: Technique Detection                                           │
//! │  • Each registered technique runs detect() on the assembly              │
//! │  • Produces Detection with confidence, evidence, and findings           │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 2: Byte-level Transforms (Technique::byte_transform)             │
//! │  • Anti-tamper decryption, metadata repair, resource extraction         │
//! │  • PE regeneration between transforms                                   │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 2.5: Post-transform IL Re-detection                               │
//! │  • Byte transforms may reveal new patterns in decrypted method bodies   │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 3: SSA Construction                                              │
//! │  • Build call graph, SSA representations, interprocedural analysis      │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 3.5: SSA Detection + Technique Initialization                    │
//! │  • SSA-level detection via Technique::detect_ssa()                      │
//! │  • Technique initialization (register decryptors, hooks, etc.)          │
//! │  • Technique-provided passes + compiler passes in fixpoint scheduler    │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 4: Neutralization                                                │
//! │  • Remove protection infrastructure from module .cctor                  │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 5: Code Generation                                               │
//! │  • Generate CIL bytecode from optimized SSA                             │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 6: Cleanup                                                       │
//! │  • Remove dead types, methods, fields, and metadata artifacts           │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Phase 7: Attribution                                                   │
//! │  • Identify obfuscator from technique detection signatures              │
//! │           │                                                             │
//! │           ▼                                                             │
//! │  Output: DeobfuscationResult (stats, technique results, attribution)   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Key Components
//!
//! ## Engine
//!
//! [`DeobfuscationEngine`](crate::deobfuscation::DeobfuscationEngine) is the main entry point:
//!
//! - Orchestrates detection, byte transforms, SSA passes, and cleanup
//! - Manages the [`TechniqueRegistry`](crate::deobfuscation::TechniqueRegistry) of all registered techniques
//! - Coordinates the pass scheduler for fixpoint iteration
//!
//! ## Technique System
//!
//! Each protection technique is a self-contained module implementing:
//!
//! - [`Technique`](crate::deobfuscation::Technique) - unified trait: `detect()`, `byte_transform()`, `ssa_phase()`, `detect_ssa()`, etc.
//!
//! ## Pass System
//!
//! SSA-based transformation passes ([`crate::compiler::SsaPass`]):
//!
//! - [`crate::compiler::PassScheduler`] - Manages pass execution order and fixpoint iteration
//! - [`crate::compiler::EventLog`] - Tracks changes made by passes
//! - [`AnalysisContext`](crate::deobfuscation::AnalysisContext) - Shared interprocedural analysis data
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::deobfuscation::{DeobfuscationEngine, EngineConfig};
//!
//! let config = EngineConfig::default();
//! let engine = DeobfuscationEngine::new(config);
//!
//! let (deobfuscated, result) = engine.process_file("obfuscated.dll")?;
//! println!("{}", result.summary());
//! # Ok::<(), dotscope::Error>(())
//! ```

mod cleanup;
mod config;
mod context;
mod decryptors;
mod engine;
mod passes;
mod processcell;
mod renamer;
mod repairs;
mod result;
mod statemachine;
mod techniques;
mod template;
pub(crate) mod utils;
mod workqueue;

// Public API - used by CLI, tests, examples, and external consumers
pub use cleanup::INLINED_METHOD_REMOVED;
pub use config::{
    CleanupConfig, DecryptorHeuristics, DetectionWeights, EmulationConfig, EngineConfig,
    IterationConfig, PassConfig, UnflatteningThresholds,
};
pub use context::{AnalysisContext, HookFactory};
pub use decryptors::{CacheKey, DecryptedCall, DecryptorContext, FailedCall, FailureReason};
pub use engine::DeobfuscationEngine;
pub use passes::{
    unflatten, CffDetector, CffPattern, CffReconstructionPass, DecryptionPass,
    DelegateProxyResolutionPass, DelegateTypeInfo, Dispatcher, EntryCondition, EntryPoint,
    NativeMethodConversionPass, NeutralizationPass, OpaqueFieldPredicatePass, UnflattenConfig,
};
// Crate-internal re-exports (only items that are actually imported via this path)
pub(crate) use processcell::ProcessCell;
pub use renamer::SmartRenameConfig;
pub use result::DeobfuscationResult;
pub(crate) use statemachine::{
    CfgInfo, StateMachineCallSite, StateMachineProvider, StateMachineSemantics, StateMachineState,
    StateSlotOperation, StateUpdateCall,
};
pub use techniques::{
    AttributionResult, Detection, Detections, Evidence, ObfuscatorMatcher, ObfuscatorSignature,
    Technique, TechniqueCategory, TechniqueRegistry, TechniqueResult, WorkingAssembly,
};
pub(crate) use template::EmulationTemplatePool;

#[cfg(test)]
mod tests {
    use crate::{
        metadata::validation::ValidationConfig,
        testkit::{engine, fixture},
        CilObject,
    };

    #[test]
    fn test_process_file_api() -> crate::Result<()> {
        let path = fixture("packers/confuserex/1.6.0/original.exe");

        let engine = engine();
        let (deobfuscated, result) = engine.process_file(path)?;

        assert!(deobfuscated.module().is_some());
        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }

    #[test]
    fn test_process_assembly_api() -> crate::Result<()> {
        let path = fixture("packers/confuserex/1.6.0/original.exe");

        let assembly = CilObject::from_path_with_validation(path, ValidationConfig::analysis())?;

        let engine = engine();
        let (deobfuscated, result) = engine.process_assembly(assembly)?;

        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }

    #[test]
    fn test_process_bytes_api() -> crate::Result<()> {
        let path = fixture("packers/confuserex/1.6.0/original.exe");
        let bytes = std::fs::read(path)?;

        let engine = engine();
        let (deobfuscated, result) = engine.process_bytes(bytes)?;

        assert!(deobfuscated.module().is_some());
        assert!(result.total_time.as_millis() > 0);

        Ok(())
    }
}
