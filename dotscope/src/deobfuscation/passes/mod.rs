//! Deobfuscation SSA transformation passes.
//!
//! These passes complement the generic compiler passes in [`crate::compiler`]
//! with transformations that require obfuscator-specific knowledge: decryptor
//! registrations, dispatcher tracking, emulation hooks, and state machines.
//!
//! # Shared Passes
//!
//! | Pass | Phase | Description |
//! |------|-------|-------------|
//! | [`OpaqueFieldPredicatePass`] | Structure | Removes opaque predicates based on static field chains resolved via emulation, before CFF unflattening |
//! | [`CffReconstructionPass`] | Structure | Recovers original control flow from flattened state-machine dispatchers using Z3-backed symbolic analysis and tree-based tracing |
//! | [`ReflectionDevirtualizationPass`] | Simplify | Resolves reflection-based call indirection (ResolveMethod, GetMethod, Invoke, CreateInstance, GetValue/SetValue) to direct calls |
//! | [`DecryptionPass`] | Value | Decrypts obfuscated strings and constants by emulating registered decryptor methods, with caching and state machine support |
//! | [`NeutralizationPass`] | Cleanup | Removes protection code (anti-tamper, anti-debug calls) from method bodies via taint analysis, preserving legitimate initialization |
//! | [`NativeMethodConversionPass`] | Pre-SSA | Converts native x86 methods back to CIL bytecode (runs before the SSA pipeline) |
//!
//! # Obfuscator-Specific Passes
//!
//! Technique-specific passes are organized in sub-modules named after their
//! obfuscator. Each is created by its corresponding detection technique via
//! [`Technique::create_pass`](super::techniques::Technique::create_pass).
//!
//! - [`jiejienet`] - JIEJIE.NET value-level passes (constants, strings, typeof, arrays)
//! - [`bitmono`] - BitMono passes (string decryption, unmanaged strings, anti-debug)
//! - [`netreactor`] - .NET Reactor passes (anti-tamper token resolver)
//!
//! # Relationship to Compiler Passes
//!
//! Generic SSA passes ([`crate::compiler::SsaPass`]) operate only on
//! [`crate::compiler::CompilerContext`] and have no knowledge
//! of obfuscators. The passes here take shared references (via `Arc`) to
//! deobfuscation state from [`AnalysisContext`](crate::deobfuscation::AnalysisContext)
//! at construction time, allowing them to participate in the same
//! [`PassScheduler`](crate::compiler::PassScheduler) pipeline as compiler passes.

pub mod bitmono;
pub mod jiejienet;
pub mod netreactor;

mod antidebug;
mod decryption;
mod delegates;
mod native;
mod neutralize;
mod opaquefields;
mod reflection;
mod staticfields;
mod unflattening;

pub use native::ConversionStats;
pub use unflattening::{
    DispatcherInfo, IndexPattern, Location, StateTransform, StateVarRef, StateVariable,
};

pub use self::{
    antidebug::{SentinelCondition, SentinelTaintRemovalPass},
    decryption::DecryptionPass,
    delegates::{DelegateProxyResolutionPass, DelegateTypeInfo},
    native::NativeMethodConversionPass,
    neutralize::NeutralizationPass,
    opaquefields::OpaqueFieldPredicatePass,
    reflection::{count_resolve_method_calli_sites, ReflectionDevirtualizationPass},
    staticfields::{I32Extractor, StaticFieldResolutionPass, StringExtractor},
    unflattening::{
        unflatten, CffDetector, CffPattern, CffReconstructionPass, Dispatcher, EntryCondition,
        EntryPoint, UnflattenConfig,
    },
};
