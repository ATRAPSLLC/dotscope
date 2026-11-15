//! Analysis context for interprocedural deobfuscation.
//!
//! The [`AnalysisContext`] wraps a [`CompilerContext`] with deobfuscation-specific
//! state. It implements `Deref<Target = CompilerContext>` so all compiler context
//! methods are accessible directly through `&AnalysisContext`.

use std::{
    collections::HashSet,
    ops::Deref,
    sync::{atomic::AtomicBool, Arc, OnceLock},
};

use dashmap::DashSet;

use crate::{
    analysis::CallGraph,
    compiler::{CompilerContext, ProcessingState},
    deobfuscation::{
        config::EngineConfig,
        decryptors::DecryptorContext,
        statemachine::StateMachineProvider,
        workqueue::{DrainedWorkItems, WorkItem, WorkQueue},
        EmulationTemplatePool,
    },
    emulation::{EmValue, Hook},
    metadata::token::Token,
    Result,
};

/// A named factory that creates a new [`Hook`] instance.
///
/// Hook factories are used instead of storing hooks directly because hooks
/// contain non-Clone types (closures, trait objects). Each emulation process
/// gets fresh hook instances by calling all registered factories.
pub struct HookFactory {
    /// Identifies which technique/obfuscator registered this hook.
    pub source: &'static str,
    /// The factory closure that produces a fresh hook.
    pub factory: Box<dyn Fn() -> Hook + Send + Sync>,
}

/// Analysis context for the SSA pipeline phase.
///
/// This wraps a [`CompilerContext`] (which holds all generic compiler state) with
/// deobfuscation-specific fields for obfuscator detection, emulation hooks,
/// warmup methods, and state machine providers.
///
/// All `CompilerContext` methods and fields are accessible via `Deref`:
/// ```text
/// let ctx: &AnalysisContext = ...;
/// ctx.events.record(...);           // via Deref to CompilerContext
/// ctx.add_known_value(...);         // via Deref to CompilerContext
/// ctx.register_warmup_method(...);  // on AnalysisContext directly
/// ```
pub struct AnalysisContext {
    /// The underlying compiler context with all generic pass state.
    pub compiler: CompilerContext,

    /// Decryptor tracking for obfuscator-specific string/resource decryption.
    ///
    /// Obfuscator modules register decryptors here during detection, and SSA
    /// passes use it to identify and process decryption calls.
    pub decryptors: Arc<DecryptorContext>,

    /// Dispatcher methods (control flow obfuscation).
    /// Methods are added here when a dispatcher is DETECTED, even if unflattening fails.
    /// Used to prevent inlining of dispatcher methods.
    pub dispatchers: Arc<DashSet<Token>>,

    /// Successfully unflattened dispatcher methods.
    /// Methods are added here only when redirects were actually computed and applied.
    /// Used to skip methods that have already been processed.
    pub unflattened_dispatchers: Arc<DashSet<Token>>,

    /// Engine configuration (for pass-specific thresholds).
    pub config: EngineConfig,

    /// Registered hook factories for emulation.
    ///
    /// Obfuscators register hook factories during `initialize_context()` to provide
    /// obfuscator-specific emulation hooks. The decryption pass calls these factories
    /// to get fresh hooks for each emulation process.
    pub emulation_hooks: Arc<boxcar::Vec<HookFactory>>,

    /// Methods to execute during emulation template warmup, with optional arguments.
    ///
    /// Entries with empty args are typically .cctors (static constructors) that
    /// initialize decryptor state. Entries with args are decryptor methods called
    /// once to trigger lazy initialization (e.g., PureLogs string table loading).
    ///
    /// Warmup runs on the template process before forking, so the expensive
    /// initialization happens once instead of on every fork.
    pub warmup_methods: Arc<boxcar::Vec<(Token, Vec<EmValue>)>>,

    /// State machine providers for order-dependent constant decryption.
    ///
    /// Each obfuscator that uses state machines for encryption (e.g., ConfuserEx
    /// with CFGCtx) registers a provider during detection. The decryption pass
    /// queries these providers to determine how to process each method.
    pub statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,

    /// Tracks which techniques have already been initialized.
    ///
    /// Prevents double-initialization when detection re-scan discovers a technique
    /// that was already initialized in an earlier round. Keyed by technique ID.
    pub initialized_techniques: DashSet<&'static str>,

    /// Tracks which techniques have had their SSA passes created and added to the scheduler.
    ///
    /// Prevents duplicate pass instances when the detection loop re-discovers techniques
    /// that were already set up in earlier rounds. Keyed by technique ID.
    pub passes_created: DashSet<&'static str>,

    /// Shared emulation template pool for all passes needing emulation.
    ///
    /// Set once after technique initialization via [`OnceLock::set`]. Passes
    /// access it through [`template_pool()`](Self::template_pool) to get O(1) CoW forks
    /// instead of independently creating and warming up emulation processes.
    pub template_pool: OnceLock<Arc<EmulationTemplatePool>>,

    /// Work item queue for the unified work queue loop.
    pub work_queue: WorkQueue,

    /// Dirty tracking state for fixpoint iteration.
    pub processing_state: ProcessingState,

    /// Set by the engine when a newly-detected technique requires a byte transform.
    /// Checked after SSA fixpoint returns to determine if the pipeline should loop.
    pub needs_byte_transform: AtomicBool,
}

impl Deref for AnalysisContext {
    type Target = CompilerContext;

    fn deref(&self) -> &CompilerContext {
        &self.compiler
    }
}

impl AnalysisContext {
    /// Creates a new analysis context with default configuration.
    pub fn new(call_graph: Arc<CallGraph>) -> Self {
        Self::with_config(call_graph, EngineConfig::default())
    }

    /// Creates a new analysis context with custom configuration.
    pub fn with_config(call_graph: Arc<CallGraph>, config: EngineConfig) -> Self {
        Self {
            compiler: CompilerContext::new(call_graph).with_budget(config.budget),
            decryptors: Arc::new(DecryptorContext::new()),
            dispatchers: Arc::new(DashSet::new()),
            unflattened_dispatchers: Arc::new(DashSet::new()),
            config,
            emulation_hooks: Arc::new(boxcar::Vec::new()),
            warmup_methods: Arc::new(boxcar::Vec::new()),
            statemachine_providers: Arc::new(boxcar::Vec::new()),
            initialized_techniques: DashSet::new(),
            passes_created: DashSet::new(),
            template_pool: OnceLock::new(),
            work_queue: WorkQueue::new(),
            processing_state: ProcessingState::new(),
            needs_byte_transform: AtomicBool::new(false),
        }
    }

    /// Checks if a method is a dispatcher (control flow obfuscation).
    #[must_use]
    pub fn is_dispatcher(&self, token: Token) -> bool {
        self.dispatchers.contains(&token)
    }

    /// Marks a method as a dispatcher and adds it to the no-inline set.
    pub fn mark_dispatcher(&self, token: Token) {
        self.dispatchers.insert(token);
        self.compiler.no_inline.insert(token);
    }

    /// Registers an emulation hook factory.
    ///
    /// Obfuscators call this during `initialize_context()` to provide hooks
    /// that should be used during decryption emulation.
    pub fn register_emulation_hook<F>(&self, source: &'static str, factory: F)
    where
        F: Fn() -> Hook + Send + Sync + 'static,
    {
        // Deduplicate: skip if a hook from this source is already registered.
        let already_registered = self.emulation_hooks.iter().any(|(_, h)| h.source == source);
        if already_registered {
            return;
        }
        self.emulation_hooks.push(HookFactory {
            source,
            factory: Box::new(factory),
        });
    }

    /// Creates fresh hook instances from all registered factories.
    #[must_use]
    pub fn create_emulation_hooks(&self) -> Vec<Hook> {
        self.emulation_hooks
            .iter()
            .map(|(_, h)| (h.factory)())
            .collect()
    }

    /// Returns true if any emulation hooks are registered.
    #[must_use]
    pub fn has_emulation_hooks(&self) -> bool {
        !self.emulation_hooks.is_empty()
    }

    /// Registers a method to be executed during emulation template warmup.
    ///
    /// Pass empty `args` for .cctors, or provide arguments for decryptor methods
    /// that need a single call to trigger lazy initialization.
    pub fn register_warmup_method(&self, method: Token, args: Vec<EmValue>) {
        if self.warmup_methods.iter().any(|(_, (m, _))| *m == method) {
            return;
        }
        self.warmup_methods.push((method, args));
    }

    /// Returns all registered warmup methods with their arguments.
    #[must_use]
    pub fn warmup_methods(&self) -> Vec<(Token, Vec<EmValue>)> {
        self.warmup_methods
            .iter()
            .map(|(_, entry)| entry.clone())
            .collect()
    }

    /// Returns true if any warmup methods are registered.
    #[must_use]
    pub fn has_warmup_methods(&self) -> bool {
        !self.warmup_methods.is_empty()
    }

    /// Registers a state machine provider for order-dependent decryption.
    ///
    /// Idempotent: skips registration if an existing provider already covers
    /// any of the same methods (indicating duplicate registration).
    pub fn register_statemachine_provider(&self, provider: Arc<dyn StateMachineProvider>) {
        let new_methods: HashSet<Token> = provider.methods().into_iter().collect();
        let already_covered = self.statemachine_providers.iter().any(|(_, existing)| {
            let existing_methods: HashSet<Token> = existing.methods().into_iter().collect();
            !existing_methods.is_disjoint(&new_methods)
        });
        if already_covered {
            return;
        }
        self.statemachine_providers.push(provider);
    }

    /// Returns true if any state machine providers are registered.
    #[must_use]
    pub fn has_statemachine_providers(&self) -> bool {
        self.statemachine_providers.count() > 0
    }

    /// Finds the state machine provider that applies to a method.
    #[must_use]
    pub fn get_statemachine_provider_for_method(
        &self,
        method: Token,
    ) -> Option<Arc<dyn StateMachineProvider>> {
        for (_, provider) in self.statemachine_providers.iter() {
            if provider.applies_to_method(method) {
                return Some(Arc::clone(provider));
            }
        }
        None
    }

    /// Returns true if a method uses any state machine for encryption.
    #[must_use]
    pub fn is_statemachine_method(&self, method: Token) -> bool {
        self.get_statemachine_provider_for_method(method).is_some()
    }

    /// Returns all methods that use state machines.
    #[must_use]
    pub fn statemachine_methods(&self) -> Vec<Token> {
        let mut methods = Vec::new();
        for (_, provider) in self.statemachine_providers.iter() {
            methods.extend(provider.methods());
        }
        methods
    }

    /// Submits a single work item to the work queue.
    pub fn submit_work_item(&self, item: WorkItem) -> Result<()> {
        self.work_queue.submit(item)
    }

    /// Drains all pending work items from the work queue.
    pub fn drain_work_items(&self) -> DrainedWorkItems {
        self.work_queue.drain()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, thread};

    use super::*;
    use crate::{
        analysis::{
            CallGraph, ConstValue, DefSite, SsaFunction, SsaType, SsaVarId, VariableOrigin,
        },
        compiler::CallSiteInfo,
        metadata::token::Token,
    };

    /// Registers `method` with a function holding `count` values, and returns
    /// their ids.
    ///
    /// A known value is a fact *about a value*, so there has to be one to
    /// attach it to. This is what a real caller has: constant propagation
    /// records what it proved about the function it just walked.
    fn method_with_values(ctx: &AnalysisContext, method: Token, count: usize) -> Vec<SsaVarId> {
        let mut ssa = SsaFunction::new(0, count);
        let ids: Vec<SsaVarId> = (0..count)
            .map(|index| {
                ssa.create_variable(
                    VariableOrigin::Local(u16::try_from(index).unwrap_or(u16::MAX)),
                    0,
                    DefSite::entry(),
                    SsaType::I32,
                )
            })
            .collect();
        ctx.set_ssa(method, ssa);
        ids
    }

    #[test]
    fn test_call_site_info() {
        let info = CallSiteInfo {
            caller: Token::new(0x06000001),
            site: None,
            arguments: vec![Some(ConstValue::I32(42)), None],
            is_live: true,
        };

        assert_eq!(info.caller, Token::new(0x06000001));
        assert_eq!(info.arguments.len(), 2);
        assert_eq!(info.argument_constant(0), Some(&ConstValue::I32(42)));
    }

    #[test]
    fn test_known_values() {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        let method = Token::new(0x06000001);
        let vars = method_with_values(&ctx, method, 3);
        let (var1, var2, var3) = (vars[0], vars[1], vars[2]);

        // Initially no known values
        assert!(!ctx.has_known_value(method, var1));
        assert_eq!(ctx.known_value_count(method), 0);

        // Add some values
        ctx.add_known_value(method, var1, ConstValue::I32(42));
        ctx.add_known_value(method, var2, ConstValue::I64(100));
        ctx.add_known_value(method, var3, ConstValue::True);

        // Retrieve values
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(42)));
        assert!(ctx.known_value_is(method, var2, |v| *v == ConstValue::I64(100)));
        assert!(ctx.known_value_is(method, var3, |v| *v == ConstValue::True));
        assert_eq!(ctx.known_value_count(method), 3);

        // Update a value
        ctx.add_known_value(method, var1, ConstValue::I32(99));
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(99)));

        // Different method has different values
        let method2 = Token::new(0x06000002);
        let other_vars = method_with_values(&ctx, method2, 1);
        let other_var = other_vars[0];
        assert!(!ctx.has_known_value(method2, other_var));
        ctx.add_known_value(method2, other_var, ConstValue::I32(1));
        assert!(ctx.known_value_is(method2, other_var, |v| *v == ConstValue::I32(1)));
        assert!(ctx.known_value_is(method, var1, |v| *v == ConstValue::I32(99)));

        // Clear values for one method
        ctx.clear_known_values(method);
        assert!(!ctx.has_known_value(method, var1));
        assert_eq!(ctx.known_value_count(method), 0);
        // Other method unaffected
        assert!(ctx.known_value_is(method2, other_var, |v| *v == ConstValue::I32(1)));
    }

    #[test]
    fn test_known_values_iterator() {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);

        let method = Token::new(0x06000001);
        let vars = method_with_values(&ctx, method, 3);
        ctx.add_known_value(method, vars[0], ConstValue::I32(1));
        ctx.add_known_value(method, vars[1], ConstValue::I32(2));
        ctx.add_known_value(method, vars[2], ConstValue::I32(3));

        let mut count = 0;
        ctx.for_each_known_value(method, |_, _| count += 1);
        assert_eq!(count, 3);
    }

    #[test]
    fn test_thread_safe_access() {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = Arc::new(AnalysisContext::new(call_graph));

        let method1 = Token::new(0x06000001);
        let method2 = Token::new(0x06000002);
        let var1 = method_with_values(&ctx, method1, 1)[0];
        let var2 = method_with_values(&ctx, method2, 1)[0];

        // Spawn multiple threads that access different parts of the context
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let ctx = Arc::clone(&ctx);
                let (method, var) = if i % 2 == 0 {
                    (method1, var1)
                } else {
                    (method2, var2)
                };
                thread::spawn(move || {
                    for j in 0..100 {
                        ctx.add_known_value(method, var, ConstValue::I32(j));
                        ctx.mark_dead(Token::new(0x06000000 + i * 1000 + j as u32));
                        ctx.add_entry_point(Token::new(0x06000000 + i * 1000 + j as u32));
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }

        // Verify counts
        assert!(ctx.known_value_count(method1) > 0);
        assert!(ctx.known_value_count(method2) > 0);
    }
}
