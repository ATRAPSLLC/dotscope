//! Shared emulation template pool for the deobfuscation pipeline.
//!
//! [`EmulationTemplatePool`] provides a single warmed-up emulation process that
//! is shared across all passes needing emulation (e.g., [`DecryptionPass`],
//! [`OpaqueFieldPredicatePass`]). Each pass gets O(1) CoW forks via
//! [`fork()`](EmulationTemplatePool::fork) instead of independently creating
//! and warming up their own emulation processes.
//!
//! # Lifecycle
//!
//! 1. Created after technique initialization (Phase 3.5)
//! 2. Warmed up once - runs `<Module>.cctor` and all registered warmup methods
//! 3. Stored in [`AnalysisContext::template_pool`]
//! 4. Passes call [`fork()`](EmulationTemplatePool::fork) to get independent copies
//! 5. Released after the SSA pipeline completes
//!
//! # Why a pool?
//!
//! Without a shared pool, `DecryptionPass` and `OpaqueFieldPredicatePass` each
//! create their own `EmulationProcess` and run the same expensive warmup
//! (Module.cctor, type .cctors, decryptor init). With the pool, warmup runs
//! once and forks are zero-cost (CoW memory sharing).
//!
//! [`DecryptionPass`]: crate::deobfuscation::passes::DecryptionPass
//! [`OpaqueFieldPredicatePass`]: crate::deobfuscation::passes::opaquefields::OpaqueFieldPredicatePass
//! [`AnalysisContext::template_pool`]: crate::deobfuscation::context::AnalysisContext::template_pool

use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};

use cowfile::CowFile;
use log::debug;

use crate::{
    deobfuscation::{
        config::EngineConfig, context::HookFactory, statemachine::StateMachineProvider,
    },
    emulation::{
        EmValue, EmulationError, EmulationOutcome, EmulationProcess, Hook, HookPriority,
        PreHookResult, ProcessBuilder,
    },
    metadata::{tables::ModuleRaw, token::Token},
    CilObject, Error, Result,
};

/// Shared emulation template pool for the deobfuscation pipeline.
///
/// Created once after technique initialization, warmed up once, then
/// shared across all passes that need emulation. Each pass gets O(1)
/// CoW forks via [`fork()`](Self::fork).
pub struct EmulationTemplatePool {
    /// The warmed-up template process (ready to fork).
    template: RwLock<Option<EmulationProcess>>,

    /// Assembly reference. Cleared by [`release()`](Self::release) to allow
    /// `Arc::try_unwrap` on the assembly after the pipeline completes.
    assembly: RwLock<Option<Arc<CilObject>>>,

    /// Forked CowFile of the original PE (for virtual filesystem mapping).
    ///
    /// Mmap-backed: zero-copy fork via re-open.
    /// Vec-backed: cloned data.
    original_pe_cow: CowFile,

    /// Hook factories from technique detection.
    hooks: Arc<boxcar::Vec<HookFactory>>,

    /// Warmup methods from technique initialization.
    warmup_methods: Arc<boxcar::Vec<(Token, Vec<EmValue>)>>,

    /// State machine providers.
    statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,

    /// Engine config.
    config: EngineConfig,
}

impl EmulationTemplatePool {
    /// Creates a new template pool.
    ///
    /// Does **not** perform warmup - call [`warmup()`](Self::warmup) separately.
    ///
    /// # Arguments
    ///
    /// * `assembly` - Shared reference to the assembly being deobfuscated
    /// * `original_pe_cow` - Forked CowFile of the original PE bytes (for VirtualFs)
    /// * `hooks` - Hook factories from technique detection
    /// * `warmup_methods` - Methods to execute during warmup
    /// * `statemachine_providers` - State machine providers for order-dependent decryption
    /// * `config` - Engine configuration
    #[must_use]
    pub fn new(
        assembly: Arc<CilObject>,
        original_pe_cow: CowFile,
        hooks: Arc<boxcar::Vec<HookFactory>>,
        warmup_methods: Arc<boxcar::Vec<(Token, Vec<EmValue>)>>,
        statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,
        config: EngineConfig,
    ) -> Self {
        Self {
            template: RwLock::new(None),
            assembly: RwLock::new(Some(assembly)),
            original_pe_cow,
            hooks,
            warmup_methods,
            statemachine_providers,
            config,
        }
    }

    /// Warms up the template process.
    ///
    /// Creates an [`EmulationProcess`] with all technique hooks, maps the
    /// original PE into the virtual filesystem, then runs:
    ///
    /// 1. `<Module>.cctor` - initializes delegate proxy tables, opaque fields, etc.
    /// 2. All registered warmup methods - multi-pass fork-based warmup handles
    ///    dependency chains between .cctors and decryptor init calls
    ///
    /// After warmup, the template is stored and subsequent [`fork()`](Self::fork)
    /// calls return O(1) CoW copies.
    ///
    /// # Errors
    ///
    /// Returns an error if process creation fails. Warmup method failures are
    /// tolerated (partial state is adopted) - only process creation failure is fatal.
    pub fn warmup(&self) -> Result<()> {
        let assembly = self
            .assembly
            .read()
            .map_err(|e| Error::LockError(format!("template pool assembly read lock: {e}")))?
            .as_ref()
            .ok_or_else(|| Error::Deobfuscation("template pool assembly already released".into()))?
            .clone();

        let mut builder = ProcessBuilder::new()
            .assembly_arc(assembly.clone())
            .with_limits(self.config.emulation.limits.clone())
            .name("template_pool");

        // Add tracing configuration if provided
        if let Some(ref tracing) = self.config.emulation.tracing {
            let pool_tracing = tracing.clone().with_context("template_warmup");
            builder = builder.with_tracing(pool_tracing);
        }

        // Register all technique hooks
        for (_, hook_factory) in self.hooks.iter() {
            builder = builder.hook((hook_factory.factory)());
        }

        // Register defensive bypass hook for RSA VerifyHash (anti-tamper).
        // This is harmless on all assemblies and prevents tamper exceptions
        // during warmup and subsequent emulation.
        builder = builder.hook(
            Hook::new("bypass-tamper-verify-hash")
                .match_name(
                    "System.Security.Cryptography",
                    "RSACryptoServiceProvider",
                    "VerifyHash",
                )
                .with_priority(HookPriority::HIGH)
                .pre(|_ctx, _thread| PreHookResult::Bypass(Some(EmValue::I32(1)))),
        );

        // Map original PE as virtual file via CowFile::fork().
        // For mmap-backed: re-opens the same file (zero-copy, OS shares pages).
        // For vec-backed: clones the data.
        if let Ok(pe_cow) = self.original_pe_cow.fork() {
            builder = builder.with_virtual_file_cow("assembly.exe", pe_cow);
        }

        // Also map under the original filename if known
        if let Some(path) = self.original_pe_cow.source_path() {
            if let Some(filename) = path.file_name() {
                if let Ok(pe_cow2) = self.original_pe_cow.fork() {
                    builder = builder.with_virtual_file_cow(&filename.to_string_lossy(), pe_cow2);
                }
            }
        }

        // Also map under the .NET module name (e.g., "ClassLibrary4.dll").
        // This is what Assembly.Location returns and what anti-tamper checks open.
        // Try owned metadata first, fall back to raw Module table for obfuscated binaries.
        let module_name = assembly.module().map(|m| m.name.clone()).or_else(|| {
            let tables = assembly.tables()?;
            let strings = assembly.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            // Module is RID 1 by definition (ECMA-335 II.22.30).
            let module_row = module_table.get(1).ok().flatten()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        });
        if let Some(ref name) = module_name {
            if let Ok(pe_cow) = self.original_pe_cow.fork() {
                builder = builder.with_virtual_file_cow(name, pe_cow);
            }
        }

        let mut process = builder.build()?;

        // Run Module.cctor first - initializes delegate proxy tables, opaque
        // fields, and other runtime state that decryptors depend on.
        if let Some(module_cctor) = assembly.types().module_cctor() {
            let fork = process.fork()?;
            match fork.execute_method(module_cctor, vec![]) {
                Ok(EmulationOutcome::Completed { instructions, .. }) => {
                    debug!(
                        "Template warmup: <Module>.cctor completed ({} instructions)",
                        instructions
                    );
                    process = fork;
                }
                Ok(outcome) => {
                    debug!(
                        "Template warmup: <Module>.cctor did not complete: {} - adopting partial state",
                        outcome
                    );
                    process = fork;
                }
                Err(e) => {
                    debug!(
                        "Template warmup: <Module>.cctor error: {} - adopting partial state",
                        e
                    );
                    process = fork;
                }
            }
        }

        // Execute warmup methods (e.g., type .cctors and lazy-init decryptor calls).
        // Uses fork-based isolation with multi-pass retry for dependency chains.
        self.run_warmup_methods(&mut process);

        // Store the warmed template
        let mut guard = self
            .template
            .write()
            .map_err(|e| Error::LockError(format!("template pool write lock: {e}")))?;
        *guard = Some(process);

        Ok(())
    }

    /// Forks the warmed template process.
    ///
    /// Returns an O(1) CoW copy of the template with isolated address space,
    /// virtual filesystem, and capture context. Returns `None` if the template
    /// has not been warmed up or was released.
    ///
    /// # Errors
    ///
    /// Returns an error if the template is not available (not warmed up or released).
    pub fn fork(&self) -> Result<EmulationProcess> {
        let guard = self
            .template
            .read()
            .map_err(|e| Error::LockError(format!("template pool read lock: {e}")))?;

        match *guard {
            Some(ref template) => {
                template.fork_with_limits(self.config.emulation.execution_limits())
            }
            None => Err(Error::Emulation(Box::new(EmulationError::InternalError {
                description: "template pool not warmed up".to_string(),
            }))),
        }
    }

    /// Forks the template and runs additional targeted warmup on the fork.
    ///
    /// Used by [`OpaqueFieldPredicatePass`] which needs targeted `.cctor`
    /// execution for types owning opaque predicate fields. The base template
    /// already has Module.cctor and registered warmup methods done; this adds
    /// type-specific .cctors on top.
    ///
    /// # Arguments
    ///
    /// * `cctors` - Additional `.cctor` tokens to execute on the fork
    ///
    /// # Returns
    ///
    /// The forked process with targeted warmup applied, or `None` if
    /// the template is unavailable.
    ///
    /// [`OpaqueFieldPredicatePass`]: crate::deobfuscation::passes::opaquefields::OpaqueFieldPredicatePass
    pub fn fork_for_targeted_warmup(&self, cctors: &[Token]) -> Option<EmulationProcess> {
        let guard = self.template.read().ok()?;
        let template = guard.as_ref()?;
        // Targeted warmup runs extra `.cctor`s on the fork, so it gets the warmup budget
        // rather than the per-method one - that is what the longer budget is *for*.
        let mut process = match template.fork() {
            Ok(p) => p,
            Err(e) => {
                debug!("Targeted warmup: failed to fork template: {e}");
                return None;
            }
        };

        if cctors.is_empty() {
            return Some(process);
        }

        // Multi-pass fork-based warmup for the targeted .cctors
        let mut completed: HashSet<Token> = HashSet::new();
        let mut permanently_failed: HashSet<Token> = HashSet::new();
        let mut pass: u32 = 0;

        loop {
            pass = pass.saturating_add(1);
            let mut new_completions: u32 = 0;

            for cctor in cctors {
                if completed.contains(cctor) || permanently_failed.contains(cctor) {
                    continue;
                }

                let Ok(fork) = process.fork() else {
                    continue;
                };
                match fork.execute_method(*cctor, vec![]) {
                    Ok(EmulationOutcome::Completed { .. }) => {
                        debug!(
                            "Targeted warmup: .cctor 0x{:08X} completed (pass {})",
                            cctor.value(),
                            pass
                        );
                        process = fork;
                        completed.insert(*cctor);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(EmulationOutcome::UnhandledException { instructions, .. }) => {
                        debug!(
                            "Targeted warmup: .cctor 0x{:08X} threw after {} instructions - adopting partial state (pass {})",
                            cctor.value(), instructions, pass
                        );
                        process = fork;
                        permanently_failed.insert(*cctor);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(EmulationOutcome::LimitReached { ref limit, .. }) => {
                        debug!(
                            "Targeted warmup: .cctor 0x{:08X} hit limit: {} - adopting partial state (pass {})",
                            cctor.value(), limit, pass
                        );
                        process = fork;
                        permanently_failed.insert(*cctor);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(outcome) => {
                        debug!(
                            "Targeted warmup: .cctor 0x{:08X} did not complete: {} (pass {})",
                            cctor.value(),
                            outcome,
                            pass
                        );
                        permanently_failed.insert(*cctor);
                    }
                    Err(ref e) => {
                        let is_resource_limit = matches!(
                            e,
                            Error::Emulation(em) if matches!(
                                **em,
                                EmulationError::Timeout { .. }
                                    | EmulationError::InstructionLimitExceeded { .. }
                                    | EmulationError::HeapMemoryLimitExceeded { .. }
                            )
                        );
                        if is_resource_limit {
                            process = fork;
                            permanently_failed.insert(*cctor);
                            new_completions = new_completions.saturating_add(1);
                        } else if pass == 1 {
                            debug!(
                                "Targeted warmup: .cctor 0x{:08X} failed: {} (pass {})",
                                cctor.value(),
                                e,
                                pass
                            );
                        }
                    }
                }
            }

            if new_completions == 0 || pass >= 5 {
                break;
            }
        }

        Some(process)
    }

    /// Returns a clone of the assembly Arc.
    ///
    /// Returns `None` after [`release()`](Self::release) has been called.
    #[must_use]
    pub fn assembly(&self) -> Option<Arc<CilObject>> {
        self.assembly.read().ok()?.clone()
    }

    /// Returns a reference to the state machine providers.
    #[must_use]
    pub fn statemachine_providers(&self) -> &Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>> {
        &self.statemachine_providers
    }

    /// Releases all references held by the pool.
    ///
    /// Clears both the template process and the `Arc<CilObject>` reference.
    /// Called after all passes complete, before `Arc::try_unwrap(assembly)`.
    /// After this call, [`fork()`](Self::fork) and [`assembly()`](Self::assembly)
    /// will return `None`.
    pub fn release(&self) {
        if let Ok(mut guard) = self.template.write() {
            *guard = None;
        }
        if let Ok(mut guard) = self.assembly.write() {
            *guard = None;
        }
    }

    /// Runs fork-based multi-pass warmup on the given process.
    ///
    /// Each warmup method is executed on a forked copy of the process.
    /// Successful forks are adopted as the new baseline. Methods that throw
    /// or hit limits still contribute partial state (fields may have been
    /// initialized before the failure). Multi-pass retry handles dependency
    /// chains between .cctors and decryptor init calls.
    fn run_warmup_methods(&self, process: &mut EmulationProcess) {
        let warmup_methods: Vec<(Token, Vec<EmValue>)> = self
            .warmup_methods
            .iter()
            .map(|(_, entry)| entry.clone())
            .collect();

        if warmup_methods.is_empty() {
            return;
        }

        let mut completed = HashSet::new();
        let mut permanently_failed = HashSet::new();

        for pass in 1..=self.config.emulation.warmup_retry_passes {
            let mut new_completions: u32 = 0;

            for (warmup_token, warmup_args) in &warmup_methods {
                if completed.contains(warmup_token) || permanently_failed.contains(warmup_token) {
                    continue;
                }

                let Ok(fork) = process.fork() else {
                    continue;
                };
                match fork.execute_method(*warmup_token, warmup_args.clone()) {
                    Ok(EmulationOutcome::Completed { instructions, .. }) => {
                        debug!(
                            "Template warmup: 0x{:08X} completed (pass {}, {} instructions)",
                            warmup_token.value(),
                            pass,
                            instructions
                        );
                        *process = fork;
                        completed.insert(*warmup_token);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(EmulationOutcome::UnhandledException { instructions, .. }) => {
                        debug!(
                            "Template warmup: 0x{:08X} threw after {} instructions - adopting partial state (pass {})",
                            warmup_token.value(), instructions, pass
                        );
                        *process = fork;
                        permanently_failed.insert(*warmup_token);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(EmulationOutcome::LimitReached { ref limit, .. }) => {
                        debug!(
                            "Template warmup: 0x{:08X} hit limit: {} - adopting partial state (pass {})",
                            warmup_token.value(), limit, pass
                        );
                        *process = fork;
                        permanently_failed.insert(*warmup_token);
                        new_completions = new_completions.saturating_add(1);
                    }
                    Ok(outcome) => {
                        debug!(
                            "Template warmup: 0x{:08X} did not complete: {} (pass {})",
                            warmup_token.value(),
                            outcome,
                            pass
                        );
                        permanently_failed.insert(*warmup_token);
                    }
                    Err(ref e) => {
                        let is_resource_limit = matches!(
                            e,
                            Error::Emulation(em) if matches!(
                                **em,
                                EmulationError::Timeout { .. }
                                    | EmulationError::InstructionLimitExceeded { .. }
                                    | EmulationError::HeapMemoryLimitExceeded { .. }
                            )
                        );
                        if is_resource_limit {
                            debug!(
                                "Template warmup: 0x{:08X} hit resource limit: {} - adopting partial state (pass {})",
                                warmup_token.value(), e, pass
                            );
                            *process = fork;
                            permanently_failed.insert(*warmup_token);
                            new_completions = new_completions.saturating_add(1);
                        } else if pass == 1 {
                            debug!(
                                "Template warmup: 0x{:08X} failed: {} (pass {})",
                                warmup_token.value(),
                                e,
                                pass
                            );
                        }
                    }
                }
            }

            if new_completions == 0 {
                break;
            }
        }

        debug!(
            "Template warmup: {}/{} methods completed",
            completed.len(),
            warmup_methods.len(),
        );
    }
}
