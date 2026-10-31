//! Global dead-method elimination — CIL adapter.
//!
//! Per-method DCE uses analyssa's blanket
//! [`analyssa::passes::DeadCodeEliminationPass`] directly. This file keeps
//! [`DeadMethodEliminationPass`], which uses a CIL-specific [`CtxWorld`]
//! adapter that combines the SSA-derived call graph
//! (`ctx.build_ssa_call_graph(..)`) with the static call graph
//! (`ctx.call_graph`) so the reachability walk sees both. The combined
//! view is richer than what `World<CilTarget>` on `CompilerContext`
//! provides today (which only reads the static call graph), so the
//! adapter stays.

use std::collections::{BTreeMap, BTreeSet};

use analyssa::{passes::deadcode, World};

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction},
    compiler::{pass::SsaPass, CompilerContext},
    metadata::token::Token,
};

/// Global dead method elimination pass.
///
/// Operates at the assembly level to identify methods that are never
/// called and not entry points. Delegates the reachability walk to
/// [`analyssa::passes::deadcode::run_global`] via an internal `World`-trait
/// adapter that combines SSA-derived and static call edges.
pub struct DeadMethodEliminationPass;

impl Default for DeadMethodEliminationPass {
    fn default() -> Self {
        Self::new()
    }
}

impl DeadMethodEliminationPass {
    /// Creates a new dead method elimination pass.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl SsaPass<CilTarget, CompilerContext> for DeadMethodEliminationPass {
    fn name(&self) -> &'static str {
        "dead-method-elimination"
    }

    fn is_global(&self) -> bool {
        true
    }

    fn requires_full_scan(&self) -> bool {
        true
    }

    fn description(&self) -> &'static str {
        "Identifies methods that are never called"
    }

    fn run_on_method(
        &self,
        _ssa: &mut SsaFunction,
        _method: &MethodRef,
        _host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        // Global pass — never invoked per-method.
        Ok(false)
    }

    fn run_global(&self, host: &CompilerContext) -> analyssa::Result<bool> {
        let world = CtxWorld::new(host);
        Ok(deadcode::run_global::<CilTarget, _, _>(
            &world,
            &host.events,
        ))
    }
}

/// `World<CilTarget>` adapter over `CompilerContext`.
///
/// Built once per `run_global` invocation. Combines the SSA-derived call
/// graph (from `ctx.build_ssa_call_graph(..)`) with the static call graph
/// (`ctx.call_graph`) so [`World::callees`] returns a single unified view —
/// SSA-derived edges win when present, static edges fill in for methods we
/// haven't built SSA for.
struct CtxWorld<'a> {
    ctx: &'a CompilerContext,
    ssa_callees: BTreeMap<Token, BTreeSet<Token>>,
    methods: Vec<Token>,
    entries: Vec<Token>,
}

impl<'a> CtxWorld<'a> {
    fn new(ctx: &'a CompilerContext) -> Self {
        let ssa_callees = ctx.build_ssa_call_graph(ctx.assembly().as_deref());
        let methods: Vec<Token> = ctx.all_methods().collect();
        let entries: Vec<Token> = ctx.entry_points.iter().map(|e| *e).collect();
        Self {
            ctx,
            ssa_callees,
            methods,
            entries,
        }
    }
}

impl World<CilTarget> for CtxWorld<'_> {
    fn all_methods(&self) -> Vec<MethodRef> {
        self.methods.iter().copied().map(MethodRef::from).collect()
    }

    fn entry_points(&self) -> Vec<MethodRef> {
        self.entries.iter().copied().map(MethodRef::from).collect()
    }

    fn callees(&self, method: &MethodRef) -> Vec<MethodRef> {
        let token = method.token();
        if let Some(ssa_calls) = self.ssa_callees.get(&token) {
            return ssa_calls.iter().copied().map(MethodRef::from).collect();
        }
        self.ctx
            .call_graph
            .callees(token)
            .into_iter()
            .map(MethodRef::from)
            .collect()
    }

    fn is_dead(&self, method: &MethodRef) -> bool {
        self.ctx.is_dead(method.token())
    }

    fn mark_dead(&self, method: &MethodRef) {
        self.ctx.mark_dead(method.token());
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::analysis::{CallGraph, SsaFunctionBuilder};

    /// A method reached from an entry point through the calls its SSA makes is live; one no
    /// live method calls is marked dead.
    #[test]
    fn a_method_no_live_method_calls_is_dead() {
        let (entry, called, uncalled) = (
            Token::new(0x0600_0001),
            Token::new(0x0600_0002),
            Token::new(0x0600_0003),
        );
        let returns = || {
            SsaFunctionBuilder::new(0, 0)
                .build_with(|f| f.block(0, |b| b.ret()))
                .unwrap()
        };
        let calls_called = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.call_void(MethodRef::new(called), &[]);
                    b.ret();
                });
            })
            .unwrap();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        ctx.set_ssa(entry, calls_called);
        ctx.set_ssa(called, returns());
        ctx.set_ssa(uncalled, returns());
        ctx.add_entry_point(entry);

        assert!(DeadMethodEliminationPass::new().run_global(&ctx).unwrap());
        assert!(!ctx.is_dead(entry));
        assert!(!ctx.is_dead(called));
        assert!(ctx.is_dead(uncalled));
    }
}
