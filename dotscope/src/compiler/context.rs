//! Compiler context for interprocedural optimization.
//!
//! The [`CompilerContext`] holds all interprocedural state needed by SSA
//! optimization passes, containing the fields that compiler passes require.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use crossbeam_skiplist::SkipSet;
use dashmap::{DashMap, DashSet};
use rayon::prelude::*;

use crate::{
    analysis::{CallGraph, ConstValue, SsaFunction, SsaFunctionCilExt, SsaOp, SsaVarId},
    compiler::{
        summary::{CallSiteInfo, MethodSummary},
        EventLog, ProcessingState,
    },
    metadata::token::Token,
    CilObject,
};

/// Compiler context for the SSA pipeline phase.
///
/// This struct holds all interprocedural state that pure compiler passes need.
/// It is designed to be self-contained: the `compiler` module can compile
/// independently of `deobfuscation` when only this context is used.
///
/// All collection fields use thread-safe types (`DashMap`, `DashSet`, etc.)
/// to enable parallel processing of methods during pass execution.
pub struct CompilerContext {
    /// Call graph (who calls whom).
    pub call_graph: Arc<CallGraph>,

    /// SSA form for each method (built once, mutated by passes).
    pub ssa_functions: DashMap<Token, SsaFunction>,

    /// Method summaries from interprocedural analysis.
    pub summaries: DashMap<Token, MethodSummary>,

    /// Call site information for each callee.
    /// Key: callee method token, Value: list of call sites.
    pub call_sites: DashMap<Token, boxcar::Vec<CallSiteInfo>>,

    /// Accumulated events from all passes and operations.
    pub events: EventLog,

    /// Methods marked as dead (no live callers, not entry points).
    pub dead_methods: DashSet<Token>,

    /// Methods that have been fully processed by the pass pipeline.
    ///
    /// Ordered, because code generation walks it: the order methods are
    /// emitted in decides where each body lands and the order new user
    /// strings and signatures enter their heaps and tables, so an unordered
    /// set wrote the same program out differently on every run.
    pub processed_methods: SkipSet<Token>,

    /// Entry point methods (Main, event handlers, etc.).
    pub entry_points: DashSet<Token>,

    /// Methods that should not be inlined.
    ///
    /// Populated by the deobfuscation engine with dispatcher and decryptor
    /// tokens before running passes. Pure compiler passes check this set
    /// instead of accessing deobfuscation-specific state.
    pub no_inline: DashSet<Token>,

    /// Methods that were inlined at least once during the inlining pass.
    pub inlined_methods: DashSet<Token>,

    /// Methods whose delegate dispatch was resolved and the delegate proxy deleted.
    /// These are the backing methods (delegate targets) that become orphaned when
    /// the strong proxy stub is removed — they were only reachable through the
    /// delegate's Invoke dispatch, never called directly.
    pub devirtualized_methods: DashSet<Token>,

    /// Metadata tokens neutralized by SSA passes (Call/CallVirt targets that were
    /// NOP'd or replaced). Used by cleanup to cascade-remove orphaned MemberRef,
    /// TypeRef, and AssemblyRef entries that are no longer referenced.
    pub neutralized_tokens: DashSet<Token>,

    /// Assembly under analysis. Set by the pipeline before running passes
    /// via [`set_assembly`](Self::set_assembly). Test contexts may leave
    /// this `None`. Stored as a `parking_lot::RwLock<Option<Arc<CilObject>>>`-like
    /// behavior via interior mutability through `arc_swap`-style atomic
    /// pointer; here we use a once-set `RwLock<Option<...>>` for
    /// simplicity since the assembly set rarely changes after init.
    assembly_slot: RwLock<Option<Arc<CilObject>>>,

    /// Per-method dirty-tracking state for incremental fixpoint
    /// scheduling. Embedded so [`crate::compiler::CompilerContext`] can
    /// implement [`analyssa::DirtySet<crate::analysis::CilTarget>`] without
    /// holding an external reference.
    pub processing_state: ProcessingState,

    /// When analysis started.
    start_time: Instant,
}

impl CompilerContext {
    /// Creates a new compiler context.
    #[must_use]
    pub fn new(call_graph: Arc<CallGraph>) -> Self {
        Self {
            call_graph,
            ssa_functions: DashMap::new(),
            summaries: DashMap::new(),
            call_sites: DashMap::new(),
            events: EventLog::new(),
            dead_methods: DashSet::new(),
            processed_methods: SkipSet::new(),
            entry_points: DashSet::new(),
            no_inline: DashSet::new(),
            inlined_methods: DashSet::new(),
            devirtualized_methods: DashSet::new(),
            neutralized_tokens: DashSet::new(),
            assembly_slot: RwLock::new(None),
            processing_state: ProcessingState::new(),
            start_time: Instant::now(),
        }
    }

    /// Sets the assembly under analysis. Idempotent; the pipeline calls
    /// this before scheduler dispatch so passes can read the assembly
    /// via [`assembly`](Self::assembly).
    pub fn set_assembly(&self, assembly: Arc<CilObject>) {
        if let Ok(mut slot) = self.assembly_slot.write() {
            *slot = Some(assembly);
        }
    }

    /// Returns the assembly currently under analysis, if set. Passes
    /// that need access to .NET metadata reach through this. Returns
    /// `None` in test contexts where no assembly was supplied.
    #[must_use]
    pub fn assembly(&self) -> Option<Arc<CilObject>> {
        self.assembly_slot.read().ok().and_then(|s| s.clone())
    }

    /// Releases the assembly handle held in this context. Required
    /// before unwrapping the assembly from its `Arc` (e.g. for code
    /// generation), since `set_assembly` adds a reference that would
    /// otherwise prevent the strong-count from reaching one.
    pub fn clear_assembly(&self) {
        if let Ok(mut slot) = self.assembly_slot.write() {
            *slot = None;
        }
    }

    /// Returns the elapsed time since analysis started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Checks if a method is marked as dead (has no live callers).
    #[must_use]
    pub fn is_dead(&self, token: Token) -> bool {
        self.dead_methods.contains(&token)
    }

    /// Marks a method as dead.
    pub fn mark_dead(&self, token: Token) {
        self.dead_methods.insert(token);
    }

    /// Checks if a method is an entry point.
    #[must_use]
    pub fn is_entry_point(&self, token: Token) -> bool {
        self.entry_points.contains(&token)
    }

    /// Registers a method as an entry point.
    pub fn add_entry_point(&self, token: Token) {
        self.entry_points.insert(token);
    }

    /// Marks a method as having been inlined at least once.
    pub fn mark_inlined(&self, token: Token) {
        self.inlined_methods.insert(token);
    }

    /// Checks if a method was inlined at least once.
    #[must_use]
    pub fn was_inlined(&self, token: Token) -> bool {
        self.inlined_methods.contains(&token)
    }

    /// Marks a method as a devirtualized delegate target.
    pub fn mark_devirtualized(&self, token: Token) {
        self.devirtualized_methods.insert(token);
    }

    /// Checks if a method was marked as a devirtualized delegate target.
    #[must_use]
    pub fn was_devirtualized(&self, token: Token) -> bool {
        self.devirtualized_methods.contains(&token)
    }

    /// Executes a closure with a reference to the method summary.
    pub fn with_summary<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&MethodSummary) -> R,
    {
        self.summaries.get(&token).map(|r| f(&r))
    }

    /// Checks if a method is an inline candidate.
    #[must_use]
    pub fn is_inline_candidate(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.inline_candidate)
    }

    /// Returns the instruction count for a method.
    #[must_use]
    pub fn instruction_count(&self, token: Token) -> Option<usize> {
        self.summaries.get(&token).map(|r| r.instruction_count)
    }

    /// Checks if a method is a string decryptor.
    #[must_use]
    pub fn is_string_decryptor(&self, token: Token) -> bool {
        self.summaries
            .get(&token)
            .is_some_and(|r| r.is_string_decryptor)
    }

    /// Modifies a method summary in place.
    pub fn modify_summary<F>(&self, token: Token, f: F) -> bool
    where
        F: FnOnce(&mut MethodSummary),
    {
        if let Some(mut entry) = self.summaries.get_mut(&token) {
            f(entry.value_mut());
            true
        } else {
            false
        }
    }

    /// Adds or updates a method summary.
    pub fn set_summary(&self, summary: MethodSummary) {
        self.summaries.insert(summary.token, summary);
    }

    /// Executes a closure with a reference to the call sites for a callee.
    pub fn with_call_sites<R, F>(&self, callee: Token, f: F) -> Option<R>
    where
        F: FnOnce(&boxcar::Vec<CallSiteInfo>) -> R,
    {
        self.call_sites.get(&callee).map(|r| f(&r))
    }

    /// Returns the number of call sites for a callee method.
    #[must_use]
    pub fn call_site_count(&self, callee: Token) -> usize {
        self.call_sites.get(&callee).map_or(0, |r| r.count())
    }

    /// Checks if a callee has any call sites.
    #[must_use]
    pub fn has_call_sites(&self, callee: Token) -> bool {
        self.call_sites.get(&callee).is_some_and(|r| r.count() > 0)
    }

    /// Iterates over all call sites for a callee method.
    pub fn for_each_call_site<F>(&self, callee: Token, mut f: F)
    where
        F: FnMut(&CallSiteInfo),
    {
        if let Some(sites) = self.call_sites.get(&callee) {
            for (_, site) in sites.iter() {
                f(site);
            }
        }
    }

    /// Adds a call site for a callee method.
    pub fn add_call_site(&self, callee: Token, call_site: CallSiteInfo) {
        self.call_sites.entry(callee).or_default().push(call_site);
    }

    /// Returns the constant value of a parameter if all call sites agree.
    #[must_use]
    pub fn parameter_constant(&self, method: Token, param_index: usize) -> Option<ConstValue> {
        self.with_summary(method, |s| s.parameter_constant(param_index).cloned())
            .flatten()
    }

    /// Checks if a method always returns a constant value.
    #[must_use]
    pub fn returns_constant(&self, method: Token) -> Option<ConstValue> {
        self.with_summary(method, |s| s.returns_constant().cloned())
            .flatten()
    }

    /// Executes a closure with a reference to the SSA function.
    pub fn with_ssa<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&SsaFunction) -> R,
    {
        self.ssa_functions.get(&token).map(|r| f(&r))
    }

    /// Executes a closure with a mutable reference to the SSA function.
    pub fn with_ssa_mut<R, F>(&self, token: Token, f: F) -> Option<R>
    where
        F: FnOnce(&mut SsaFunction) -> R,
    {
        self.ssa_functions.get_mut(&token).map(|mut r| f(&mut r))
    }

    /// Checks if an SSA function exists for a method.
    #[must_use]
    pub fn has_ssa(&self, token: Token) -> bool {
        self.ssa_functions.contains_key(&token)
    }

    /// Stores an SSA function for a method.
    pub fn set_ssa(&self, token: Token, ssa: SsaFunction) {
        self.ssa_functions.insert(token, ssa);
    }

    /// Removes and returns the SSA function for a method.
    pub fn take_ssa(&self, token: Token) -> Option<SsaFunction> {
        self.ssa_functions.remove(&token).map(|(_, v)| v)
    }

    /// Returns methods in reverse topological order (callees before callers).
    #[must_use]
    pub fn methods_reverse_topological(&self) -> Vec<Token> {
        self.call_graph.topological_order().to_vec()
    }

    /// Returns methods in topological order (callers before callees).
    #[must_use]
    pub fn methods_topological(&self) -> Vec<Token> {
        let mut order = self.call_graph.topological_order().to_vec();
        order.reverse();
        order
    }

    /// Returns an iterator over all method tokens that have SSA functions.
    pub fn all_methods(&self) -> impl Iterator<Item = Token> + '_ {
        self.ssa_functions.iter().map(|r| *r.key())
    }

    /// Returns the count of methods with SSA representations.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.ssa_functions.len()
    }

    /// Executes a closure with a reference to a known constant value.
    ///
    /// The value's own record answers this. Nothing is kept beside the
    /// function: see [`CilVariableFacts`](crate::analysis::CilVariableFacts)
    /// for why a table keyed by [`SsaVarId`] cannot.
    pub fn with_known_value<R, F>(&self, method: Token, var: SsaVarId, f: F) -> Option<R>
    where
        F: FnOnce(&ConstValue) -> R,
    {
        self.with_ssa(method, |ssa| {
            ssa.variable(var)
                .and_then(|variable| variable.facts().known_value().map(f))
        })
        .flatten()
    }

    /// Checks if a known value exists for an SSA variable.
    #[must_use]
    pub fn has_known_value(&self, method: Token, var: SsaVarId) -> bool {
        self.with_known_value(method, var, |_| ()).is_some()
    }

    /// Checks if a known value satisfies a predicate.
    #[must_use]
    pub fn known_value_is<F>(&self, method: Token, var: SsaVarId, predicate: F) -> bool
    where
        F: FnOnce(&ConstValue) -> bool,
    {
        self.with_known_value(method, var, predicate)
            .unwrap_or(false)
    }

    /// Iterates over all known values for a method.
    pub fn for_each_known_value<F>(&self, method: Token, mut f: F)
    where
        F: FnMut(SsaVarId, &ConstValue),
    {
        self.with_ssa(method, |ssa| {
            for variable in ssa.variables().iter() {
                if let Some(value) = variable.facts().known_value() {
                    f(variable.id(), value);
                }
            }
        });
    }

    /// Records a known constant value for an SSA variable.
    ///
    /// Stored on the variable, so it travels with the value through every
    /// renumbering and is restored with the function when a pass group rolls
    /// back. A method with no SSA loaded records nothing: there is no value to
    /// record it against.
    pub fn add_known_value(&self, method: Token, var: SsaVarId, value: ConstValue) {
        self.with_ssa_mut(method, |ssa| {
            if let Some(variable) = ssa.variable_mut(var) {
                variable.facts_mut().set_known_value(value);
            }
        });
    }

    /// Clears known values for a method when its SSA is modified.
    pub fn clear_known_values(&self, method: Token) {
        self.with_ssa_mut(method, |ssa| {
            let ids: Vec<SsaVarId> = ssa
                .variables()
                .iter()
                .map(|variable| variable.id())
                .collect();
            for var in ids {
                if let Some(variable) = ssa.variable_mut(var) {
                    variable.facts_mut().clear_known_value();
                }
            }
        });
    }

    /// Returns the number of known values for a method.
    #[must_use]
    pub fn known_value_count(&self, method: Token) -> usize {
        self.with_ssa(method, |ssa| {
            ssa.variables()
                .iter()
                .filter(|variable| variable.facts().known_value().is_some())
                .count()
        })
        .unwrap_or(0)
    }

    /// Canonicalizes all SSA functions in preparation for code generation.
    pub fn canonicalize_all_ssa(&self) {
        let tokens: Vec<Token> = self.all_methods().collect();

        tokens.par_iter().for_each(|&token| {
            let Some((_, mut ssa)) = self.ssa_functions.remove(&token) else {
                return;
            };

            ssa.canonicalize();
            // The remapping says where each original local moved. Nothing reads
            // it: code generation reads the optimized function, and a consumer
            // that wants to relate a value back to its original slot reads the
            // variable's own origin. Keeping it meant a per-method table that
            // no edit ever updated.
            let _ = ssa.optimize_locals();

            self.ssa_functions.insert(token, ssa);
        });
    }

    /// Builds a live call graph from actual SSA instructions.
    ///
    /// Scans all SSA functions for `Call`, `CallVirt`, `NewObj`,
    /// `LoadFunctionPtr`, and `LoadVirtFunctionPtr` instructions and records
    /// the caller → callee edges. This accounts for inlining and other
    /// transformations that may have removed or added calls since the
    /// initial static call graph was built.
    ///
    /// A call through a MemberRef or MethodSpec naming a method of this assembly records that
    /// method as well as the token: a generic method's instantiation, or a method of a generic
    /// type, is called through one, and is called all the same. Without `assembly` such a call
    /// records the token alone.
    ///
    /// Note this graph only has entries for methods that *have* an SSA function. A method whose
    /// body never converted contributes no edges at all, which reads as "calls nothing" rather
    /// than "unknown". Reachability consumers must use [`Self::build_effective_call_graph`];
    /// this one is for consumers that specifically want the post-transformation view.
    #[must_use]
    pub fn build_ssa_call_graph(
        &self,
        assembly: Option<&CilObject>,
    ) -> BTreeMap<Token, BTreeSet<Token>> {
        let mut call_graph = BTreeMap::new();
        for entry in &self.ssa_functions {
            let caller_token = *entry.key();
            let ssa = entry.value();
            let mut callees = BTreeSet::new();
            for block in ssa.blocks() {
                for instr in block.instructions() {
                    match instr.op() {
                        SsaOp::Call { method, .. }
                        | SsaOp::CallVirt { method, .. }
                        | SsaOp::LoadFunctionPtr { method, .. }
                        | SsaOp::LoadVirtFunctionPtr { method, .. } => {
                            callees.insert(method.token());
                        }
                        SsaOp::NewObj { ctor, .. } => {
                            callees.insert(ctor.token());
                        }
                        _ => {}
                    }
                }
            }
            if let Some(assembly) = assembly {
                let resolver = assembly.resolver();
                let local: Vec<Token> = callees
                    .iter()
                    .filter_map(|&callee| resolver.resolve_method(callee))
                    .collect();
                callees.extend(local);
            }
            call_graph.insert(caller_token, callees);
        }
        call_graph
    }

    /// Builds a call graph safe to drive reachability and deletion from.
    ///
    /// [`Self::build_ssa_call_graph`] is the post-transformation view, and it is the right
    /// input wherever inlining and devirtualization must be reflected. It is the wrong input
    /// for deciding what to *delete*: it only has entries for methods that converted to SSA,
    /// so a method whose body never converted -- an encrypted or native body, or one that
    /// failed to decode -- contributes no edges, and everything it references reads as
    /// unreachable. Deleting on that basis strips types the surviving body still names, which
    /// produces a structurally invalid assembly rather than a smaller one.
    ///
    /// So SSA edges win where they exist, and the static call graph fills in for every method
    /// that has none. This mirrors what `CtxWorld::callees` does for dead-method elimination.
    #[must_use]
    pub fn build_effective_call_graph(
        &self,
        assembly: &CilObject,
    ) -> BTreeMap<Token, BTreeSet<Token>> {
        let mut call_graph = self.build_ssa_call_graph(Some(assembly));
        for node in self.call_graph.nodes() {
            call_graph
                .entry(node.token)
                .or_insert_with(|| self.call_graph.callees(node.token).into_iter().collect());
        }
        call_graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::helpers::load_sample;

    #[test]
    fn a_call_through_a_method_spec_is_a_call_of_its_method() {
        // ConfuserEx's type scrambler: SayHello calls `BuildMessage<string>` through MethodSpec
        // 0x2B000013.
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_typescramble.exe");
        let say_hello = Token::new(0x0600_0007);
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let ssa = assembly
            .method(&say_hello)
            .and_then(|method| method.ssa(&assembly))
            .expect("SayHello converts");
        ctx.ssa_functions.insert(say_hello, ssa);

        let callees = ctx.build_ssa_call_graph(Some(&assembly));
        let callees = callees.get(&say_hello).expect("SayHello's calls");
        assert!(callees.contains(&Token::new(0x2B00_0013)), "{callees:x?}");
        assert!(callees.contains(&Token::new(0x0600_0009)), "{callees:x?}");
    }
}
