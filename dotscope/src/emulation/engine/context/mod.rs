//! Emulation context providing access to assembly metadata.
//!
//! The [`EmulationContext`] provides the interpreter with access to
//! the loaded assembly's metadata, instructions, and strings.

mod code;
mod generics;
mod lookup;
mod metadata;
mod methods;
mod types;

use std::sync::Arc;

pub use code::MethodCode;
use dashmap::DashMap;

use crate::{
    assembly::Instruction,
    metadata::{method::ExceptionHandler, token::Token, typesystem::CilFlavor},
    CilObject,
};

/// A synthetic method body created by `DynamicMethod`/`ILGenerator`.
///
/// Contains decoded instructions, local variable types, and parameter types
/// for methods built at runtime via reflection emit. These are registered
/// by `DynamicMethod.CreateDelegate()` and can be executed by the interpreter.
#[derive(Debug, Clone)]
pub struct SyntheticMethodBody {
    /// Decoded instructions ready for interpretation.
    pub instructions: Vec<Instruction>,
    /// Local variable types (CilFlavor for each local).
    pub local_types: Vec<CilFlavor>,
    /// Parameter types (CilFlavor for each parameter).
    pub param_types: Vec<CilFlavor>,
    /// Whether this is a static method (no `this` parameter).
    pub is_static: bool,
    /// Whether this method returns a value (non-void).
    pub returns_value: bool,
    /// Exception handlers from the ILGenerator.
    pub exception_handlers: Vec<ExceptionHandler>,
}

/// Context for emulation providing access to assembly metadata.
///
/// The emulation context wraps a [`CilObject`] and provides convenient
/// access to methods, instructions, and strings needed during emulation.
pub struct EmulationContext {
    /// The loaded assembly.
    pub assembly: Arc<CilObject>,
    /// Synthetic method bodies created by DynamicMethod/ILGenerator.
    pub synthetic_methods: Arc<DashMap<Token, SyntheticMethodBody>>,
    /// Offset-indexed method bodies, decoded once per method token.
    ///
    /// Shared so that contexts recreated for the same assembly (e.g. per-frame
    /// context resolution in the execution loop) reuse the same decoded bodies.
    /// Only non-synthetic, non-empty bodies are cached — synthetic bodies can be
    /// mutated at runtime by `ILGenerator`, and an empty body may simply mean the
    /// decoder has not populated blocks yet.
    pub code_cache: Arc<DashMap<Token, Arc<MethodCode>>>,
}

impl EmulationContext {
    /// Creates a new emulation context with a shared synthetic methods map.
    #[must_use]
    pub fn new(
        assembly: Arc<CilObject>,
        synthetic_methods: Arc<DashMap<Token, SyntheticMethodBody>>,
    ) -> Self {
        EmulationContext {
            assembly,
            synthetic_methods,
            code_cache: Arc::new(DashMap::new()),
        }
    }

    /// Creates a new emulation context that shares an existing code cache.
    ///
    /// Used when a context must be rebuilt for the same assembly (for example
    /// when resolving the context for a call frame in another loaded assembly)
    /// so the decoded method bodies are not thrown away.
    #[must_use]
    pub fn with_code_cache(
        assembly: Arc<CilObject>,
        synthetic_methods: Arc<DashMap<Token, SyntheticMethodBody>>,
        code_cache: Arc<DashMap<Token, Arc<MethodCode>>>,
    ) -> Self {
        EmulationContext {
            assembly,
            synthetic_methods,
            code_cache,
        }
    }

    /// Returns a reference to the underlying assembly.
    #[must_use]
    pub fn assembly(&self) -> Arc<CilObject> {
        self.assembly.clone()
    }

    /// Checks whether a token refers to a synthetic method.
    #[must_use]
    pub fn is_synthetic_method(&self, token: Token) -> bool {
        self.synthetic_methods.contains_key(&token)
    }

    /// Gets the exception handlers for a synthetic method.
    #[must_use]
    pub fn get_synthetic_exception_handlers(&self, token: Token) -> Option<Vec<ExceptionHandler>> {
        self.synthetic_methods
            .get(&token)
            .map(|s| s.exception_handlers.clone())
    }
}
