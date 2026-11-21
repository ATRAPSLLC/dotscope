//! `SsaPassHost` + CIL extension trait impls on [`CompilerContext`].
//!
//! [`CompilerContext`] is the dotscope-side adapter that the analyssa
//! [`PassScheduler`](analyssa::scheduling::PassScheduler) drives. This
//! module wires it into the analyssa host trait family
//! ([`World`], [`SsaStore`],
//! [`DirtySet`],
//! [`SsaPassHost`]) and adds the CIL
//! extension trait [`CilHost`] which surfaces the assembly handle and
//! other .NET-specific accessors that target-generic analyssa passes don't
//! need to know about.

use std::sync::Arc;

use analyssa::{
    analysis::AnalysisContext,
    events::EventListener,
    host::{DirtySet, SsaStore},
    ir::function::SsaFunction,
    scheduling::SsaPassHost,
    world::World,
};

use crate::{
    analysis::{CilTarget, MethodRef},
    compiler::CompilerContext,
    metadata::token::Token,
    CilObject,
};

/// CIL-side host extension trait. Used by passes that need access to
/// CIL-specific facilities (the assembly handle, member resolution,
/// etc.) that don't make sense in the target-agnostic analyssa host
/// surface.
///
/// `CompilerContext` is the canonical impl. Passes that bound their
/// generics on `H: CilHost` get full access to the CIL host while
/// remaining storable in `Box<dyn SsaPass<CilTarget, CompilerContext>>`.
pub trait CilHost: SsaPassHost<CilTarget> {
    /// The assembly currently under analysis. Returns `None` in test
    /// contexts where [`CompilerContext::set_assembly`] was never
    /// called.
    fn assembly(&self) -> Option<Arc<CilObject>>;

    /// Convenience accessor for the underlying `CompilerContext`. Lets
    /// CIL pass impls reach the rich CIL-only fields (`no_inline`,
    /// `summaries`, `known_values`, etc.) that aren't surfaced through
    /// the analyssa traits.
    fn ctx(&self) -> &CompilerContext;
}

impl World<CilTarget> for CompilerContext {
    fn all_methods(&self) -> Vec<MethodRef> {
        self.ssa_functions
            .iter()
            .map(|e| MethodRef::new(*e.key()))
            .collect()
    }

    fn entry_points(&self) -> Vec<MethodRef> {
        self.entry_points
            .iter()
            .map(|t| MethodRef::new(*t))
            .collect()
    }

    fn callees(&self, method: &MethodRef) -> Vec<MethodRef> {
        // Read direct callees from the call graph.
        self.call_graph
            .callees(method.0)
            .into_iter()
            .map(MethodRef::new)
            .collect()
    }

    fn is_dead(&self, method: &MethodRef) -> bool {
        self.dead_methods.contains(&method.0)
    }

    fn mark_dead(&self, method: &MethodRef) {
        self.dead_methods.insert(method.0);
    }

    // `methods_reverse_topological` is deliberately not overridden: analyssa's
    // default derives the call graph's strongly-connected components from
    // `callees`, which groups mutually recursive methods together. The inherent
    // `CompilerContext::methods_reverse_topological` returns a flat order that
    // cannot express that grouping, so overriding with it would lose
    // information the interprocedural driver needs.
}

impl SsaStore<CilTarget> for CompilerContext {
    fn contains(&self, method: &MethodRef) -> bool {
        self.ssa_functions.contains_key(&method.0)
    }

    fn take_ssa(&self, method: &MethodRef) -> Option<SsaFunction<CilTarget>> {
        self.ssa_functions.remove(&method.0).map(|(_, ssa)| ssa)
    }

    fn insert_ssa(&self, method: MethodRef, ssa: SsaFunction<CilTarget>) {
        self.ssa_functions.insert(method.0, ssa);
    }

    fn clone_ssa(&self, method: &MethodRef) -> Option<SsaFunction<CilTarget>> {
        self.ssa_functions.get(&method.0).map(|r| r.clone())
    }

    fn iter_methods(&self) -> Vec<MethodRef> {
        self.ssa_functions
            .iter()
            .map(|e| MethodRef::new(*e.key()))
            .collect()
    }
}

impl DirtySet<CilTarget> for CompilerContext {
    fn mark_dirty(&self, method: &MethodRef) {
        self.processing_state.mark_method_dirty(method.0);
    }

    fn is_dirty(&self, method: &MethodRef) -> bool {
        self.processing_state.method_dirty.contains(&method.0)
    }

    fn dirty_snapshot(&self) -> Vec<MethodRef> {
        self.processing_state
            .method_dirty
            .iter()
            .map(|t| MethodRef::new(*t))
            .collect()
    }

    fn clear_dirty_for(&self, method: &MethodRef) {
        self.processing_state.mark_method_stable(method.0);
    }

    fn mark_processed(&self, method: &MethodRef) {
        self.processed_methods.insert(method.0);
    }

    fn is_processed(&self, method: &MethodRef) -> bool {
        self.processed_methods.contains(&method.0)
    }
}

impl SsaPassHost<CilTarget> for CompilerContext {
    fn events(&self) -> &dyn EventListener<CilTarget> {
        &self.events
    }

    fn context(&self) -> AnalysisContext<'_> {
        AnalysisContext::new(Self::machine(self)).with_budget(Self::budget(self))
    }
}

impl CilHost for CompilerContext {
    fn assembly(&self) -> Option<Arc<CilObject>> {
        Self::assembly(self)
    }

    fn ctx(&self) -> &CompilerContext {
        self
    }
}

// Helper: convert between CIL `Token` and analyssa `MethodRef`. Both are
// transparent newtypes around `u32`; the `From` impl is provided by the
// existing `MethodRef::from(Token)` definition in `analysis/ssa/types.rs`.
#[allow(dead_code)]
fn _token_methodref_compat() {
    let _: MethodRef = MethodRef::from(Token::new(0));
    // Reverse direction (MethodRef -> Token) is via the `.0` field.
    let _: Token = MethodRef::new(Token::new(0)).0;
}
