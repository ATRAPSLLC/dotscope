//! Decryption pass for obfuscated values.
//!
//! This pass decrypts obfuscated constants and strings by emulating calls to
//! registered decryptor methods. The [`DecryptorContext`] is populated during
//! the detection phase by:
//!
//! - **Obfuscator-specific detectors** (ConfuserEx, etc.) with high confidence
//! - **Heuristic detectors** that identify potential decryptors by signature
//!
//! # Flow
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                        Decryption Flow                              │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                     │
//! │  1. Detection Phase                                                 │
//! │     ├─> Obfuscator detector: ctx.decryptors.register(token, info)  │
//! │     └─> Heuristic detector: ctx.decryptors.register(token, info)   │
//! │                                                                     │
//! │  2. DecryptionPass (this pass)                                     │
//! │     For each call instruction:                                     │
//! │     └─> Check if target is a registered decryptor                  │
//! │     └─> Get constant arguments from known_values                   │
//! │     └─> Check cache for previous emulation result                  │
//! │     └─> Emulate the decryptor method                               │
//! │     └─> Replace call with constant value                           │
//! │     └─> Record success/failure in DecryptorContext                 │
//! │                                                                     │
//! │  3. Cleanup (obfuscator postprocess)                               │
//! │     └─> Remove decryptor methods where all calls were handled      │
//! │                                                                     │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! Before (obfuscated constant):
//! ```text
//! v0 = call DecryptorModule::Get<int32>(12345)
//! v1 = add v0, 100
//! ```
//!
//! After:
//! ```text
//! v0 = 42
//! v1 = add v0, 100
//! ```
//!
//! Before (obfuscated string):
//! ```text
//! v0 = call StringDecryptor::Decrypt(98765)
//! call Console::WriteLine(v0)
//! ```
//!
//! After:
//! ```text
//! v0 = "Hello, World!"
//! call Console::WriteLine(v0)
//! ```

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use analyssa::{
    graph::{
        algorithms::{compute_dominators, DominatorTree},
        GraphBase, NodeId,
    },
    ir::value::DecryptedArrayData,
};
use rayon::prelude::*;

use crate::{
    analysis::{
        CilTarget, ConstValue, InstrId, MethodRef, SsaCfg, SsaFunction, SsaOp, SsaVarId, TypeRef,
        ValueResolver,
    },
    compiler::{CompilerContext, EventKind, EventLog, ModificationScope, PassCapability, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        decryptors::{DecryptorContext, FailureReason},
        CfgInfo, EmulationTemplatePool, StateMachineProvider, StateMachineState, StateUpdateCall,
    },
    emulation::{
        EmValue, EmulationError, EmulationOutcome, EmulationProcess, EmulationThread, StepResult,
    },
    metadata::{
        token::Token,
        typesystem::{CilFlavor, CilPrimitive, CilPrimitiveKind, PointerSize},
    },
    CilObject, Error, Result,
};

/// Decryption pass for obfuscated constants and strings.
///
/// This pass finds calls to registered decryptor methods and attempts to
/// evaluate them through emulation, replacing call sites with the decrypted
/// values (constants, strings, or other types).
///
/// It works in tandem with the [`DecryptorContext`](crate::deobfuscation::DecryptorContext)
/// which is populated during the detection phase by obfuscator-specific and
/// heuristic detectors.
///
/// # Emulation Template
///
/// The pass uses the shared emulation-template pool (an internal CoW snapshot
/// store, see `crate::deobfuscation::context`) for O(1) forks. The pool is
/// warmed up once during engine initialization; this pass forks a fresh
/// emulator state from it for each decryption attempt.
///
/// If the pool is unavailable (no techniques registered emulation hooks),
/// decryption is silently skipped.
pub struct DecryptionPass {
    /// Shared emulation template pool for O(1) forks.
    ///
    /// `None` when no techniques registered emulation requirements.
    /// Each decryption call forks the pool's warmed template.
    template_pool: Option<Arc<EmulationTemplatePool>>,

    /// Decryptor tracking context (shared with AnalysisContext).
    decryptors: Arc<DecryptorContext>,
    /// State machine providers for order-dependent decryption.
    statemachine_providers: Arc<boxcar::Vec<Arc<dyn StateMachineProvider>>>,
    /// Ceiling on how many emulations the whole run may perform, or 0 for unlimited.
    ///
    /// The per-emulation instruction and wall-clock budgets are applied by the template pool
    /// when it forks; this is the run-level budget they do not provide.
    max_emulations: usize,
}

/// Owned CFG analysis info, storing dominator tree and predecessors.
///
/// This is an internal struct used by `DecryptionPass` to hold CFG analysis
/// data that can be borrowed as a `CfgInfo` reference.
struct CfgInfoOwned {
    dom_tree: DominatorTree,
    predecessors: Vec<Vec<usize>>,
    node_count: usize,
    entry: NodeId,
}

impl CfgInfoOwned {
    /// Borrows this owned info as a `CfgInfo` reference.
    fn as_ref(&self) -> CfgInfo<'_> {
        CfgInfo {
            dom_tree: &self.dom_tree,
            predecessors: &self.predecessors,
            node_count: self.node_count,
            entry: self.entry,
        }
    }
}

impl DecryptionPass {
    /// Creates a new constant decryption pass from an analysis context.
    ///
    /// Captures shared references to the context's decryptors and state machine
    /// providers. Emulation is backed by the shared emulation-template pool
    /// stored in the context (if available).
    ///
    /// # Arguments
    ///
    /// * `ctx` - The analysis context providing registered decryptors, state
    ///   machine providers, configuration, and the shared template pool.
    ///
    /// # Returns
    ///
    /// A new `DecryptionPass` ready for pipeline execution.
    #[must_use]
    pub fn new(ctx: &AnalysisContext) -> Self {
        Self {
            template_pool: ctx.template_pool.get().cloned(),
            decryptors: Arc::clone(&ctx.decryptors),
            statemachine_providers: Arc::clone(&ctx.statemachine_providers),
            max_emulations: ctx.config.emulation.max_emulations,
        }
    }

    /// Finds the state machine provider that applies to a method.
    fn get_statemachine_provider_for_method(
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

    /// Forks the shared emulation template for a decryption call.
    ///
    /// Returns an O(1) CoW copy of the pre-warmed template from the
    /// [`EmulationTemplatePool`]. Returns an error if no pool is available
    /// or if warmup previously failed.
    fn fork_template_process(&self) -> Result<EmulationProcess> {
        match &self.template_pool {
            Some(pool) => pool.fork(),
            None => Err(Error::Emulation(Box::new(EmulationError::InternalError {
                description: "no emulation template available".to_string(),
            }))),
        }
    }

    /// Tries to decrypt a constant at a specific call site.
    ///
    /// Checks the DecryptorContext cache first, then attempts emulation.
    ///
    /// # Arguments
    ///
    /// * `decryptor` - The resolved decryptor MethodDef token.
    /// * `args` - The constant argument values.
    ///
    /// # Returns
    ///
    /// The decrypted value if successful, `None` otherwise along with an
    /// optional failure reason.
    fn try_decrypt_at_call(
        &self,
        decryptor: Token,
        call_target: Token,
        args: &[ConstValue],
    ) -> (Option<ConstValue>, Option<FailureReason>) {
        if let Some(cached) = self
            .decryptors
            .with_cached(decryptor, args, ConstValue::clone)
        {
            return (Some(cached), None);
        }

        // Use the original call target (which may be a MethodSpec) for emulation
        // so that generic type arguments are preserved for ldtoken resolution.
        let (result, failure) = self.emulate_call(call_target, args);

        if let Some(ref value) = result {
            self.decryptors.cache_value(decryptor, args, value.clone());
        }

        (result, failure)
    }

    /// The value a decryptor receives for the constant `value`, allocated in `process` where
    /// it is an object: a user string read from the assembly's `#US` heap, a string or an
    /// array an earlier decryption produced.
    ///
    /// # Errors
    ///
    /// Why `process` cannot build the value: a user string the heap does not hold, an array
    /// whose element type or data does not resolve, a constant with no CIL value.
    fn argument(
        process: &EmulationProcess,
        value: &ConstValue,
    ) -> std::result::Result<EmValue, String> {
        let heap = process.address_space();
        match value {
            ConstValue::String(offset) => {
                let text = process
                    .assembly()
                    .and_then(|assembly| assembly.userstrings())
                    .and_then(|strings| strings.get(*offset as usize).ok())
                    .ok_or_else(|| format!("no user string at 0x{offset:X}"))?
                    .to_string_lossy();
                heap.alloc_string(&text)
                    .map(EmValue::ObjectRef)
                    .map_err(|e| e.to_string())
            }
            ConstValue::DecryptedString(text) => heap
                .alloc_string(text)
                .map(EmValue::ObjectRef)
                .map_err(|e| e.to_string()),
            ConstValue::DecryptedArray(array) => {
                let token = array.element_type_ref.token();
                let flavor = process
                    .assembly()
                    .and_then(|assembly| assembly.types().get(&token))
                    .map(|element| element.flavor().clone())
                    .ok_or_else(|| format!("array element type {token} does not resolve"))?;
                let size = array.element_size;
                if array.data.len().checked_rem(size) != Some(0) {
                    return Err(format!(
                        "{} bytes of array data are no whole number of {size}-byte elements",
                        array.data.len()
                    ));
                }
                let elements = array
                    .data
                    .chunks_exact(size)
                    .map(|bytes| EmValue::from_le_bytes(bytes, &flavor, PointerSize::Bit32))
                    .collect();
                heap.managed_heap()
                    .alloc_array_with_values(flavor, elements)
                    .map(EmValue::ObjectRef)
                    .map_err(|e| e.to_string())
            }
            other => EmValue::try_from(other).map_err(|e| e.to_string()),
        }
    }

    /// Emulates a call to get the decrypted constant.
    ///
    /// Uses Copy-on-Write fork semantics for efficient emulation. A template
    /// process is created once (expensive: PE loading, mapping, hooks) and stored
    /// in the pass. Each call forks the template in O(1) time via structural
    /// sharing, with fresh mutable state for independent execution.
    ///
    /// # Arguments
    ///
    /// * `method` - The method token to emulate (may be MethodSpec for generics).
    /// * `args` - The constant arguments to pass.
    ///
    /// # Returns
    ///
    /// A tuple of (result, failure_reason).
    fn emulate_call(
        &self,
        method: Token,
        args: &[ConstValue],
    ) -> (Option<ConstValue>, Option<FailureReason>) {
        // Reserve against the run budget before doing any work. Taking the reservation up
        // front means two concurrent callers cannot both pass the check on the last slot.
        if !self.decryptors.try_reserve_emulation(self.max_emulations) {
            return (None, Some(FailureReason::EmulationBudgetExhausted));
        }

        // Fork from the template process - O(1) due to CoW semantics.
        // The template is created lazily on first call with expensive PE loading,
        // hooks, etc. Subsequent calls share memory via structural sharing.
        let process = match self.fork_template_process() {
            Ok(p) => p,
            Err(e) => {
                return (None, Some(FailureReason::EmulationFailed(e.to_string())));
            }
        };

        // A decryptor receives each argument as the value the evaluation stack holds,
        // objects allocated in the process; one the process cannot build fails the site
        // rather than reaching the decryptor as something else.
        let mut em_args = Vec::with_capacity(args.len());
        for (index, arg) in args.iter().enumerate() {
            match Self::argument(&process, arg) {
                Ok(value) => em_args.push(value),
                Err(reason) => {
                    return (
                        None,
                        Some(FailureReason::EmulationFailed(format!(
                            "argument {index}: {reason}"
                        ))),
                    );
                }
            }
        }

        // Use thread-safe container to capture the return value
        let captured_value: Arc<Mutex<Option<ConstValue>>> = Arc::new(Mutex::new(None));
        let captured_clone = captured_value.clone();

        // Use emulate_until to stop when we see a return from the TARGET method.
        // IMPORTANT: Only capture returns at call_depth == 1 (the outermost method).
        // The condition fires for every `ret` instruction including nested calls.
        // Without this check, we'd capture the return value from the first inner
        // method call (e.g., the native x86 helper returning I32) instead of the
        // actual decryptor result (e.g., a DecryptedString).
        let outcome = match process.emulate_until(
            method,
            em_args,
            move |step_result: &StepResult, thread: &EmulationThread| {
                match step_result {
                    StepResult::Return { .. } => {
                        // Only capture returns from the outermost (target) method.
                        // call_depth == 1 means only the target method is on the stack.
                        if thread.call_depth() != 1 {
                            return false;
                        }
                        // Method is returning - the return value is on the stack
                        // (the StepResult::Return { value } field is always None for ret instructions)
                        if let Ok(em_value) = thread.stack().peek() {
                            let const_value = Self::emvalue_to_constvalue(em_value, thread);
                            if const_value.is_some() {
                                if let Ok(mut guard) = captured_clone.lock() {
                                    *guard = const_value;
                                }
                                return true; // Stop - we have a valid return value
                            }
                        }
                        false
                    }
                    _ => false,
                }
            },
        ) {
            Ok(o) => o,
            Err(e) => {
                return (None, Some(FailureReason::EmulationFailed(format!("{e}"))));
            }
        };

        // Extract the captured value
        match &outcome {
            EmulationOutcome::Stopped { .. } | EmulationOutcome::Completed { .. } => {
                let result = captured_value.lock().ok().and_then(|guard| guard.clone());
                if result.is_some() {
                    (result, None)
                } else {
                    (None, Some(FailureReason::InvalidReturnValue))
                }
            }
            EmulationOutcome::UnhandledException { exception, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "unhandled exception: {exception:?}"
                ))),
            ),
            EmulationOutcome::LimitReached { limit, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "limit reached: {limit:?}"
                ))),
            ),
            EmulationOutcome::RequiresSymbolic { reason, .. } => (
                None,
                Some(FailureReason::EmulationFailed(format!(
                    "requires symbolic: {reason}"
                ))),
            ),
            EmulationOutcome::Breakpoint { .. } => {
                // Breakpoint hit - try to get the captured value anyway
                let result = captured_value.lock().ok().and_then(|guard| guard.clone());
                if result.is_some() {
                    (result, None)
                } else {
                    (
                        None,
                        Some(FailureReason::EmulationFailed("breakpoint".to_string())),
                    )
                }
            }
        }
    }

    /// Resolves a `CilFlavor` to a real TypeRef/TypeDef token using the assembly's
    /// type registry and the existing `CilPrimitiveData::clr_full_name()` mapping.
    /// Resolves a `CilFlavor` to a real TypeRef token from the assembly's metadata.
    ///
    /// Finds the core library TypeRef for the .NET type matching the flavor
    /// (e.g., `U1` → TypeRef for `System.Byte`). Returns `None` if the assembly
    /// doesn't reference this type.
    fn resolve_flavor_to_typeref(flavor: &CilFlavor, thread: &EmulationThread) -> Option<Token> {
        let kind = CilPrimitiveKind::try_from(flavor.clone()).ok()?;
        let fullname = CilPrimitive::new(kind).clr_full_name();
        thread
            .assembly()?
            .types()
            .get_corelib_typeref(fullname)
            .map(|ty| ty.token)
    }

    /// Converts an EmValue to a ConstValue for decryption purposes.
    ///
    /// Handles primitive types via [`EmValue::to_const_value`] and additionally
    /// supports string objects by reading them from the emulation heap.
    ///
    /// **IMPORTANT**: Unlike `EmValue::to_const_value()`, this function rejects
    /// `Null` values. In a decryption context, null means the decryption failed
    /// (e.g., wrong key leading to out-of-bounds array access). Accepting null
    /// would silence actual decryption failures.
    fn emvalue_to_constvalue(em_value: &EmValue, thread: &EmulationThread) -> Option<ConstValue> {
        // Reject Null - typically means decryption failed (wrong key, OOB access, etc.).
        // Some decryptors may legitimately return null for conditional paths; if this
        // becomes an issue, the caller should distinguish emulation-error from returned-null.
        if matches!(em_value, EmValue::Null) {
            log::debug!("Decryption: emulation returned Null - treating as failure");
            return None;
        }

        // First try the basic conversion for primitives
        if let Some(cv) = em_value.to_const_value() {
            return Some(cv);
        }

        // Handle ObjectRef specially - try string, unbox, or array from heap
        if let EmValue::ObjectRef(href) = em_value {
            if let Ok(s) = thread.heap().get_string(*href) {
                return Some(ConstValue::DecryptedString(s.to_string().into_boxed_str()));
            }
            // Try to unbox a boxed primitive value from the heap
            if let Ok(unboxed) = thread.heap().unbox(*href) {
                if let Some(cv) = unboxed.to_const_value() {
                    return Some(cv);
                }
            }
            // Try to extract array data as bytes
            if let Ok(Some(bytes)) = thread.heap().get_array_as_bytes(*href, PointerSize::Bit32) {
                if let Ok(elem_flavor) = thread.heap().get_array_element_type(*href) {
                    let elem_size = elem_flavor.byte_size(PointerSize::Bit32).unwrap_or(1);
                    // Resolve the element CilFlavor to a real TypeRef token from the assembly
                    if let Some(token) = Self::resolve_flavor_to_typeref(&elem_flavor, thread) {
                        return Some(ConstValue::DecryptedArray(Box::new(DecryptedArrayData {
                            data: bytes,
                            element_type_ref: TypeRef::new(token),
                            element_size: elem_size,
                        })));
                    }
                }
            }
        }

        // Handle ValueType with TypeSpec token - this happens with generic methods
        // where the return type is a type parameter. Try to extract the actual value.
        if let EmValue::ValueType { fields, .. } = em_value {
            // If the ValueType has a single field that's an ObjectRef, try to get string from it
            if let Some(first_field) = fields.first().filter(|_| fields.len() == 1) {
                if let EmValue::ObjectRef(href) = first_field {
                    if let Ok(s) = thread.heap().get_string(*href) {
                        return Some(ConstValue::DecryptedString(s.to_string().into_boxed_str()));
                    }
                }
                // Try primitive conversion on the single field (but not if it's Null)
                if !matches!(first_field, EmValue::Null) {
                    if let Some(cv) = first_field.to_const_value() {
                        return Some(cv);
                    }
                }
            }
        }

        None
    }

    /// Gets constant values for call arguments using the [`ValueResolver`].
    ///
    /// This function supports PHI-aware tracing: if an argument is defined by
    /// a PHI node where all operands resolve to the same constant, that constant
    /// is returned. This is essential for handling control flow flattening where
    /// constants flow through PHI nodes before reaching decryptor calls.
    ///
    /// # Arguments
    ///
    /// * `args` - The SSA variable IDs of the arguments.
    /// * `resolver` - The value resolver pre-loaded with known values.
    ///
    /// # Returns
    ///
    /// A vector of constant values if all arguments resolve to constants, `None` otherwise.
    fn get_arg_constants(
        args: &[SsaVarId],
        resolver: &mut ValueResolver<'_>,
    ) -> Option<Vec<ConstValue>> {
        resolver.resolve_all(args)
    }

    /// Processes CFG mode decryption for a method using dominator-based path analysis.
    ///
    /// CFG mode encryption uses a state machine (CFGCtx) where each `Next()` call
    /// updates the state. The challenge is that different execution paths may have
    /// different sequences of `Next()` calls, so we can't just simulate them all
    /// linearly.
    ///
    /// # Algorithm
    ///
    /// For each decryptor call:
    /// 1. Find the `Next()` call that feeds its XOR operand
    /// 2. Build the dominator tree to find which blocks are guaranteed to execute
    ///    before the decryptor on ALL paths
    /// 3. Simulate only the `Next()` calls in dominating blocks (these are guaranteed
    ///    to have executed) plus same-block calls that precede the decryptor
    /// 4. Use the resulting state to compute the decryption key
    ///
    /// This is correct because:
    /// - A `Next()` call in a dominating block executes on ALL paths to the decryptor
    /// - A `Next()` call in the same block before the decryptor always executes first
    /// - `Next()` calls in non-dominating blocks are path-specific and may not execute
    ///
    /// # CFG Mode Pattern
    ///
    /// ```text
    /// v1 = const FLAG
    /// v2 = const INCREMENT
    /// v3 = call CFGCtx.Next(&ctx, v1, v2)   ; returns state value
    /// v4 = const ENCODED
    /// v5 = xor v3, v4                       ; actual_key = state_value ^ encoded
    /// v6 = call Decryptor(v5)
    /// ```
    ///
    /// The processing is delegated to the state machine provider, which implements
    /// obfuscator-specific logic for finding call sites and collecting relevant
    /// state updates.
    fn process_state_machine_mode(
        &self,
        ssa: &mut SsaFunction,
        method_token: Token,
        ctx: &CompilerContext,
        assembly: &CilObject,
        provider: &dyn StateMachineProvider,
        ptr_size: PointerSize,
    ) -> (bool, EventLog) {
        let changes = EventLog::new();

        // Clone semantics into Arc for StateMachineState
        let semantics = Arc::new(provider.semantics().clone());

        // Find all state update calls using the provider
        let state_updates = provider.find_state_updates(ssa);
        if state_updates.is_empty() {
            return (false, changes);
        }

        // Build CFG info for path-sensitive analysis
        let cfg_info = Self::build_cfg_info(ssa);

        // Find decryptor call sites using the provider's pattern matching.
        // Use all_resolvable_tokens() to include MethodSpec tokens that map to
        // registered decryptors via MemberRef - these are needed for generic
        // instantiations like Get<int32>() that may use MemberRef indirection.
        let decryptor_tokens = self.decryptors.all_resolvable_tokens();
        let call_sites =
            provider.find_decryptor_call_sites(ssa, &state_updates, &decryptor_tokens, assembly);

        if call_sites.is_empty() {
            return (false, changes);
        }

        // Find ALL state machine seeds in the method using the provider
        let all_seeds = provider.find_initializations(ssa, ctx, method_token, assembly);

        let mut changed = false;
        let mut failures: Vec<(Token, Option<InstrId>, FailureReason)> = Vec::new();

        // Process each decryptor call independently with its own state machine
        for call_site in &call_sites {
            let location = call_site.identity();

            if self.decryptors.is_already_decrypted(method_token, location) {
                continue;
            }
            if self
                .decryptors
                .has_permanent_failure(method_token, location)
            {
                continue;
            }

            // Find the correct seed for this call site using the provider
            let seed = provider
                .find_seed_for_call(&all_seeds, call_site, &cfg_info.as_ref())
                .unwrap_or(0);

            // Initialize fresh state machine from seed
            let mut state = StateMachineState::from_seed_u32(seed, Arc::clone(&semantics));

            // Find the seed's block location for filtering.
            let seed_block = all_seeds
                .iter()
                .filter(|(_, _, val)| *val == seed)
                .map(|(block, _, _)| *block)
                .min();

            // Collect relevant updates using the provider's BFS path algorithm.
            // Seed-block filtering is now done inside collect_updates_for_call
            // using path position (not block index) for correct execution ordering.
            let relevant_updates = provider.collect_updates_for_call(
                call_site,
                &state_updates,
                &cfg_info.as_ref(),
                seed_block,
            );

            // Construct ValueResolver for this iteration (reborrow ssa as shared)
            let mut resolver = ValueResolver::new(&*ssa, ptr_size).with_path_aware_fallback();
            resolver.load_known_values();

            // Simulate the relevant state updates in order.
            // If any prior update can't be resolved, the state machine is
            // desynchronized - skip this call site for now (retriable).
            let simulation_ok = Self::simulate_state_updates(
                &mut state,
                &relevant_updates,
                &state_updates,
                &mut resolver,
            );

            if !simulation_ok {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            }

            // Simulate the feeding update call itself
            let Some(feeding_update) = state_updates.get(call_site.feeding_update_idx) else {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            };

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let flag = resolver
                .resolve(feeding_update.flag_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u8);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let increment = resolver
                .resolve(feeding_update.increment_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u32);

            let (Some(flag), Some(increment)) = (flag, increment) else {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            };

            let state_value = state.next_u32(flag, increment);

            // Get the encoded constant
            let encoded = resolver
                .resolve(call_site.encoded_var)
                .and_then(|v| v.as_i32());

            let Some(encoded) = encoded else {
                failures.push((
                    call_site.decryptor,
                    location,
                    FailureReason::NonConstantArgs,
                ));
                continue;
            };

            // Compute actual key using the provider
            let actual_key = provider.compute_key(u64::from(state_value), encoded);

            // Decrypt using the computed key
            let args = vec![ConstValue::I32(actual_key)];
            let (result, failure) =
                self.try_decrypt_at_call(call_site.decryptor, call_site.call_target, &args);
            if let Some(value) = result {
                self.decryptors.record_success(
                    call_site.decryptor,
                    method_token,
                    location,
                    value.clone(),
                );

                let event_kind = if value.is_string_like() {
                    EventKind::StringDecrypted
                } else {
                    EventKind::ConstantDecrypted
                };
                changes
                    .record(event_kind)
                    .at(method_token, call_site.instr_idx)
                    .message(format!(
                        "decrypted (CFG mode, flag=0x{flag:02X}, inc=0x{increment:08X}): {value}"
                    ));

                ctx.add_known_value(method_token, call_site.dest, value.clone());

                if let Some(block) = ssa.block_mut(call_site.block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(call_site.instr_idx) {
                        instr.set_op(SsaOp::Const {
                            dest: call_site.dest,
                            value,
                        });
                    }
                }

                changed = true;
            } else {
                failures.push((
                    call_site.decryptor,
                    location,
                    failure.unwrap_or(FailureReason::InvalidReturnValue),
                ));
            }
        }

        // Record failures
        for (decryptor, location, reason) in &failures {
            self.decryptors
                .record_failure(*decryptor, method_token, *location, reason.clone());

            log::warn!(
                "CFG mode decryption failed for decryptor 0x{:08X} in method {}: {reason}",
                decryptor.value(),
                method_token
            );
        }

        // Only clean up state machine instructions when ALL call sites have been
        // resolved (successfully decrypted or permanently failed). If retriable
        // failures remain, preserve the state update calls so the next fixpoint
        // iteration can retry with more constants resolved.
        let all_resolved = call_sites.iter().all(|cs| {
            let loc = cs.identity();
            self.decryptors.is_already_decrypted(method_token, loc)
                || self.decryptors.has_permanent_failure(method_token, loc)
        });

        if all_resolved {
            // Replace state update calls with Const operations.
            // IMPORTANT: Only clean up the state updates that directly feed
            // decryptor call sites (those whose results are consumed by
            // the XOR+call pattern). Non-feeding updates ("padding") may
            // have their results used as stack values (e.g. popped by the
            // original IL), but replacing them with Const changes the
            // stack-observable behavior when the dest variable is live.
            let feeding_indices: HashSet<usize> =
                call_sites.iter().map(|cs| cs.feeding_update_idx).collect();
            let feeding_updates: Vec<StateUpdateCall> = state_updates
                .iter()
                .enumerate()
                .filter(|(i, _)| feeding_indices.contains(i))
                .map(|(_, u)| u.clone())
                .collect();

            Self::cleanup_state_updates(
                ssa,
                &feeding_updates,
                method_token,
                &changes,
                &mut changed,
            );

            // The padding updates whose result nothing but a `pop` reads (ConfuserEx discards
            // it) advance a state nothing observes any more, and keep the context type alive:
            // they go with their pops, before the initialization, which a `newobj` context
            // they read keeps
            let padding: Vec<&StateUpdateCall> = state_updates
                .iter()
                .enumerate()
                .filter(|(i, _)| !feeding_indices.contains(i))
                .map(|(_, update)| update)
                .collect();
            let padding_results: HashSet<SsaVarId> =
                padding.iter().map(|update| update.dest).collect();
            let mut sites: Vec<(usize, usize)> = padding
                .iter()
                .map(|update| (update.block_idx, update.instr_idx))
                .collect();
            for (block_idx, block) in ssa.iter_blocks() {
                for (instr_idx, instr) in block.instructions().iter().enumerate() {
                    if let SsaOp::Pop { value } = instr.op() {
                        if padding_results.contains(value) {
                            sites.push((block_idx, instr_idx));
                        }
                    }
                }
            }
            for (block_idx, instr_idx, op) in ssa.remove_unread_instructions(sites) {
                changed = true;
                if !matches!(op, SsaOp::Pop { .. }) {
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(
                            method_token,
                            block_idx.saturating_mul(1000).saturating_add(instr_idx),
                        )
                        .message("removed state machine update call nothing reads");
                }
            }

            // Remove state machine initialization calls (constructor)
            Self::cleanup_state_initialization(
                ssa,
                &all_seeds,
                method_token,
                &changes,
                &mut changed,
            );
        }

        (changed, changes)
    }

    /// Builds CFG analysis info for a method.
    fn build_cfg_info(ssa: &SsaFunction) -> CfgInfoOwned {
        let cfg = SsaCfg::from_ssa(ssa);
        let node_count = cfg.node_count();
        let entry = NodeId::new(0);
        let dom_tree = compute_dominators(&cfg, entry);

        let predecessors: Vec<Vec<usize>> = (0..node_count)
            .map(|i| cfg.block_predecessors(i).to_vec())
            .collect();

        CfgInfoOwned {
            dom_tree,
            predecessors,
            node_count,
            entry,
        }
    }

    /// Simulates state updates in order, advancing the state machine.
    ///
    /// Returns `true` if all updates were successfully resolved and applied.
    /// Returns `false` if any update's flag or increment could not be resolved,
    /// which means the state machine is desynchronized and all subsequent
    /// values would be wrong.
    fn simulate_state_updates(
        state: &mut StateMachineState,
        relevant_updates: &[usize],
        all_updates: &[StateUpdateCall],
        resolver: &mut ValueResolver<'_>,
    ) -> bool {
        for &idx in relevant_updates {
            let Some(update) = all_updates.get(idx) else {
                return false;
            };

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let flag = resolver
                .resolve(update.flag_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u8);

            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let inc = resolver
                .resolve(update.increment_var)
                .and_then(|v| v.as_i64())
                .map(|x| x as u32);

            if let (Some(flag), Some(inc)) = (flag, inc) {
                let _ = state.next_u32(flag, inc);
            } else {
                return false;
            }
        }
        true
    }

    /// Replaces state update calls with Const operations.
    ///
    /// This is needed because Call ops aren't "pure" so DCE won't remove them.
    fn cleanup_state_updates(
        ssa: &mut SsaFunction,
        state_updates: &[StateUpdateCall],
        method_token: Token,
        changes: &EventLog,
        changed: &mut bool,
    ) {
        for update in state_updates {
            if let Some(block) = ssa.block_mut(update.block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(update.instr_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: update.dest,
                        value: ConstValue::I32(0),
                    });
                    *changed = true;
                    changes
                        .record(EventKind::InstructionRemoved)
                        .at(
                            method_token,
                            update
                                .block_idx
                                .saturating_mul(1000)
                                .saturating_add(update.instr_idx),
                        )
                        .message(format!(
                            "replaced state machine update call with const (result {:?})",
                            update.dest
                        ));
                }
            }
        }
    }

    /// Removes state machine initialization calls (constructor).
    ///
    /// After decryption, the CFGCtx constructor calls are dead code but DCE
    /// won't remove them since Call ops aren't pure. A value-type constructor
    /// `call` defines nothing and always goes. A `newobj` defines the context
    /// object, which a state update the cleanup leaves in place (one feeding
    /// no decryptor) still reads, so it goes only once nothing reads it.
    fn cleanup_state_initialization(
        ssa: &mut SsaFunction,
        seeds: &[(usize, usize, u32)],
        method_token: Token,
        changes: &EventLog,
        changed: &mut bool,
    ) {
        let sites = seeds
            .iter()
            .map(|&(block_idx, instr_idx, _seed)| (block_idx, instr_idx));
        for (block_idx, instr_idx, _) in ssa.remove_unread_instructions(sites) {
            *changed = true;
            changes
                .record(EventKind::InstructionRemoved)
                .at(
                    method_token,
                    block_idx.saturating_mul(1000).saturating_add(instr_idx),
                )
                .message("removed state machine initialization call");
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for DecryptionPass {
    fn name(&self) -> &'static str {
        "decryption"
    }

    fn description(&self) -> &'static str {
        "Decrypts obfuscated values by emulating registered decryptor methods"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::DecryptedStrings]
    }

    fn initialize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        // This pass relies on DecryptorContext being populated by obfuscator
        // detection before it runs. No additional setup needed.
        Ok(())
    }

    fn finalize(&mut self, _host: &CompilerContext) -> analyssa::Result<()> {
        // Pool lifecycle is managed by the engine - nothing to release here.
        Ok(())
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly_arc = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("DecryptionPass requires an assembly"))?;
        let assembly: &CilObject = &assembly_arc;
        let ctx = host;
        let method_token = method.0;
        // Early exit if no decryptors are registered
        if !self.decryptors.has_decryptors() {
            return Ok(false);
        }

        let ptr_size = PointerSize::from_is_64bit(assembly.file().pe().is_64bit);

        // Track whether any mode made changes
        let mut any_changed = false;

        // Check if this method uses a state machine (CFG mode) - requires sequential processing
        if let Some(provider) = self.get_statemachine_provider_for_method(method_token) {
            let (sm_changed, sm_changes) = self.process_state_machine_mode(
                ssa,
                method_token,
                ctx,
                assembly,
                &*provider,
                ptr_size,
            );
            if sm_changed {
                any_changed = true;
            }
            if !sm_changes.is_empty() {
                ctx.events.merge(&sm_changes);
            }
            // Fall through to normal-mode processing to catch any remaining
            // decryptor calls not matched by the CFG XOR pattern. In CFG-mode
            // methods, some calls may have pre-folded arguments that appear as
            // direct constants (the XOR was computed at IL generation time).
            // Normal-mode processing handles these correctly since the constant
            // IS the correct key.
        }

        let changes = EventLog::new();

        let mut resolver = ValueResolver::new(&*ssa, ptr_size).with_path_aware_fallback();
        resolver.load_known_values();

        // Phase 1: Collect decryption candidates (sequential)
        /// `(block, instruction, destination, decryptor, call target, call
        /// identity, constant arguments)`.
        ///
        /// The block and instruction say where to rewrite; the identity is what
        /// the result is recorded against, and survives the rewrite.
        type DecryptionCandidate = (
            usize,
            usize,
            SsaVarId,
            Token,
            Token,
            Option<InstrId>,
            Vec<ConstValue>,
        );
        let mut candidates: Vec<DecryptionCandidate> = Vec::new();
        let mut failures: Vec<(Token, Option<InstrId>, FailureReason)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let (call_target, args, dest) = match instr.op() {
                    SsaOp::Call {
                        method, args, dest, ..
                    }
                    | SsaOp::CallVirt {
                        method, args, dest, ..
                    } => (method.token(), args, *dest),
                    _ => continue,
                };

                let Some(dest) = dest else { continue };
                let Some(decryptor) = self.decryptors.resolve_decryptor(call_target) else {
                    continue;
                };

                // The call's identity, not where it sits: every rewrite above
                // it renumbers the position, and a block of a thousand
                // instructions collides with the next block outright.
                let location = instr.id();

                if self.decryptors.is_already_decrypted(method_token, location) {
                    continue;
                }
                if self
                    .decryptors
                    .has_permanent_failure(method_token, location)
                {
                    continue;
                }

                let Some(arg_constants) = Self::get_arg_constants(args, &mut resolver) else {
                    failures.push((decryptor, location, FailureReason::NonConstantArgs));
                    continue;
                };

                candidates.push((
                    block_idx,
                    instr_idx,
                    dest,
                    decryptor,
                    call_target,
                    location,
                    arg_constants,
                ));
            }
        }

        // Phase 2: Run decryptions in parallel (O(1) CoW fork per emulation)
        // Collect results as Option - Some for success, None signals failure stored in parallel vec
        let parallel_failures = Mutex::new(Vec::new());

        let successes: Vec<_> = candidates
            .into_par_iter()
            .filter_map(
                |(block_idx, instr_idx, dest, decryptor, call_target, location, args)| {
                    let (result, failure) = self.try_decrypt_at_call(decryptor, call_target, &args);

                    if let Some(value) = result {
                        Some((block_idx, instr_idx, dest, decryptor, location, value))
                    } else {
                        if let Ok(mut guard) = parallel_failures.lock() {
                            guard.push((
                                decryptor,
                                location,
                                failure.unwrap_or(FailureReason::InvalidReturnValue),
                            ));
                        }
                        None
                    }
                },
            )
            .collect();

        // Merge parallel failures into main failures vec
        failures.extend(
            parallel_failures
                .into_inner()
                .map_err(|e| Error::LockError(format!("parallel failures lock: {e}")))?,
        );

        // Phase 3: Apply results (sequential - SSA mutation not thread-safe)
        for (block_idx, instr_idx, dest, decryptor, location, value) in successes {
            self.decryptors
                .record_success(decryptor, method_token, location, value.clone());

            let event_kind = if value.is_string_like() {
                EventKind::StringDecrypted
            } else {
                EventKind::ConstantDecrypted
            };
            changes
                .record(event_kind)
                .at(
                    method_token,
                    block_idx.saturating_mul(1000).saturating_add(instr_idx),
                )
                .message(format!("decrypted: {value}"));

            ctx.add_known_value(method_token, dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                }
            }
        }

        // Record failures
        for (decryptor, location, reason) in &failures {
            self.decryptors
                .record_failure(*decryptor, method_token, *location, reason.clone());

            log::warn!(
                "Decryption failed for decryptor 0x{:08X} in method {}: {reason}",
                decryptor.value(),
                method_token
            );
        }

        // Determine if actual transformations were made
        let normal_changed = changes.iter().any(|e| e.kind.is_transformation());
        if !changes.is_empty() {
            ctx.events.merge(&changes);
        }
        Ok(any_changed || normal_changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{
            CallGraph, ConstValue, DefSite, MethodRef, SsaFunction, SsaFunctionBuilder, SsaOp,
            SsaType, SsaVarId, ValueResolver, VariableOrigin,
        },
        compiler::{EventLog, SsaPass},
        deobfuscation::{
            context::AnalysisContext, passes::DecryptionPass, DeobfuscationEngine, EngineConfig,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::{
            emulation::process_builder, fixture, helpers::test_assembly_arc, passes::run_verified,
        },
    };

    /// A decryptor receives each constant as the value the stack holds: strings and arrays as
    /// objects of the process, handles as `ldtoken` pushes them. Each went in as null, and a
    /// user string the heap does not hold as its offset.
    #[test]
    fn a_decryptor_receives_its_arguments_as_the_stack_holds_them() {
        let assembly = test_assembly_arc();
        let process = process_builder()
            .assembly_arc(Arc::clone(&assembly))
            .build()
            .unwrap();
        let heap = process.address_space().managed_heap();
        let object = |value: &ConstValue| match DecryptionPass::argument(&process, value) {
            Ok(EmValue::ObjectRef(object)) => object,
            other => panic!("{value:?} became {other:?}"),
        };

        let decrypted = object(&ConstValue::DecryptedString("decrypted".into()));
        assert_eq!(&*heap.get_string(decrypted).unwrap(), "decrypted");

        let (offset, text) = assembly
            .userstrings()
            .and_then(|strings| strings.iter().find(|(offset, _)| *offset != 0))
            .expect("the sample has a user string");
        let user = object(&ConstValue::String(u32::try_from(offset).unwrap()));
        assert_eq!(*heap.get_string(user).unwrap(), *text.to_string_lossy());
        assert!(
            DecryptionPass::argument(&process, &ConstValue::String(u32::MAX)).is_err(),
            "a user string the heap does not hold is no argument"
        );

        let int32 = assembly
            .types()
            .iter()
            .find(|entry| *entry.value().flavor() == CilFlavor::I4)
            .map(|entry| *entry.key())
            .expect("the sample names System.Int32");
        let array = |data: Vec<u8>| {
            ConstValue::DecryptedArray(Box::new(DecryptedArrayData {
                data,
                element_type_ref: TypeRef::new(int32),
                element_size: 4,
            }))
        };
        let elements = object(&array(
            [1_i32, -2].iter().flat_map(|v| v.to_le_bytes()).collect(),
        ));
        assert_eq!(
            heap.get_array_element(elements, 0).unwrap(),
            EmValue::I32(1)
        );
        assert_eq!(
            heap.get_array_element(elements, 1).unwrap(),
            EmValue::I32(-2)
        );
        assert!(
            DecryptionPass::argument(&process, &array(vec![0; 5])).is_err(),
            "five bytes are no whole number of int32s"
        );

        assert_eq!(
            DecryptionPass::argument(&process, &ConstValue::Type(TypeRef::new(int32))).unwrap(),
            EmValue::NativeInt(i64::from(int32.value()))
        );
    }

    /// Helper to create a minimal analysis context for testing.
    fn create_test_context() -> AnalysisContext {
        let call_graph = Arc::new(CallGraph::new());
        let ctx = AnalysisContext::new(call_graph);
        ctx.compiler.set_assembly(test_assembly_arc());
        ctx
    }

    /// A state machine's `newobj` stays while a state update the cleanup left
    /// in place still reads the object it creates, and a value-type
    /// constructor `call`, which defines nothing, goes.
    #[test]
    fn test_cleanup_state_initialization_keeps_a_context_still_read() {
        let ctor = MethodRef::new(Token::new(0x0600_0010));
        let next = MethodRef::new(Token::new(0x0600_0011));
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let seed = b.const_i32(0x1234);
                    let context = b.newobj(ctor, &[seed]);
                    let flag = b.const_i32(1);
                    let increment = b.const_i32(2);
                    let _ = b.call(next, &[context, flag, increment], SsaType::I32);
                    let address = b.const_i32(0);
                    b.call_void(ctor, &[address, seed]);
                    b.ret();
                });
            })
            .unwrap();
        let position = |ssa: &SsaFunction, wanted: fn(&SsaOp) -> bool| {
            ssa.block(0)
                .and_then(|block| block.instructions().iter().position(|i| wanted(i.op())))
        };
        let newobj = position(&ssa, |op| matches!(op, SsaOp::NewObj { .. })).unwrap();
        let ctor_call = position(&ssa, |op| matches!(op, SsaOp::Call { dest: None, .. })).unwrap();

        let changes = EventLog::new();
        let mut changed = false;
        DecryptionPass::cleanup_state_initialization(
            &mut ssa,
            &[(0, newobj, 0x1234), (0, ctor_call, 0x1234)],
            Token::new(0x0600_0001),
            &changes,
            &mut changed,
        );

        assert!(changed, "the constructor call is removed");
        let block = ssa.block(0).unwrap();
        assert!(
            matches!(block.instructions()[newobj].op(), SsaOp::NewObj { .. }),
            "the context object is still read by a state update"
        );
        assert!(matches!(block.instructions()[ctor_call].op(), SsaOp::Nop));
    }

    #[test]
    fn test_pass_creation() {
        let ctx = create_test_context();
        let pass = DecryptionPass::new(&ctx);
        assert_eq!(pass.name(), "decryption");
        assert!(!pass.description().is_empty());
    }

    #[test]
    fn test_run_no_decryptors() {
        let ctx = create_test_context();
        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.ret();
                });
            })
            .unwrap();

        // No decryptors registered, should return false (no changes)
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_with_decryptor_no_calls() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _ = b.const_i32(42);
                    b.ret();
                });
            })
            .unwrap();

        // Has decryptors but no calls to them
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_call_to_decryptor_no_dest() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // Call with no destination
                    b.call_void(MethodRef::new(decryptor_token), &[]);
                    b.ret();
                });
            })
            .unwrap();

        // Call without destination, can't replace
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_run_call_to_decryptor_non_constant_args() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    // Call with non-constant argument
                    let _ = b.call(MethodRef::new(decryptor_token), &[arg0], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        // Argument is not in known_values, should fail
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        )
        .unwrap();
        assert!(!changed);

        // Should have recorded a failure
        assert_eq!(ctx.decryptors.total_failed(), 1);
    }

    #[test]
    fn test_run_call_to_non_decryptor() {
        let ctx = create_test_context();

        // Register a decryptor
        let decryptor_token = Token::new(0x06000002);
        ctx.decryptors.register(decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let other_method = Token::new(0x06000003);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    // Call to a different method (not a decryptor)
                    let _ = b.call(MethodRef::new(other_method), &[], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        )
        .unwrap();
        assert!(!changed);
    }

    #[test]
    fn test_methodspec_resolution() {
        let ctx = create_test_context();

        // Register a decryptor and map a MethodSpec to it
        let decryptor_token = Token::new(0x06000002);
        let methodspec_token = Token::new(0x2b000001);
        ctx.decryptors.register(decryptor_token);
        ctx.decryptors
            .map_methodspec(methodspec_token, decryptor_token);

        let pass = DecryptionPass::new(&ctx);

        let method_token = Token::new(0x06000001);
        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let c = b.const_i32(42);
                    // Call via MethodSpec with a destination so we can attempt decryption
                    let _ = b.call(MethodRef::new(methodspec_token), &[c], SsaType::I32);
                    b.ret();
                });
            })
            .unwrap();

        // Set up the constant arg
        let var_id = ssa.block(0).unwrap().instructions()[0].op().dest().unwrap();
        ctx.add_known_value(method_token, var_id, ConstValue::I32(42));

        // This will try to decrypt but fail (no assembly for emulation)
        // The point is that it recognized the MethodSpec as a decryptor call
        let _ = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(method_token),
            &ctx.compiler,
        );

        // Verify the MethodSpec was resolved to the decryptor and a failure was recorded
        // (failure because there's no assembly to emulate against)
        assert_eq!(
            ctx.decryptors.total_failed(),
            1,
            "Should record failure for MethodSpec call (recognized but emulation failed)"
        );
    }

    #[test]
    fn test_pass_initialize() {
        let ctx = create_test_context();
        let mut pass = DecryptionPass::new(&ctx);

        let result = pass.initialize(&ctx);
        assert!(result.is_ok());
    }

    /// A function with `values.len()` locals, each recorded as holding the
    /// constant given.
    ///
    /// The shape a decryptor sees: constant propagation has already proved what
    /// the arguments are, and recorded it on the values themselves.
    fn function_with_known(values: &[i32]) -> (SsaFunction, Vec<SsaVarId>) {
        let mut ssa: SsaFunction = SsaFunction::new(0, values.len());
        let vars: Vec<SsaVarId> = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let var = ssa.create_variable(
                    VariableOrigin::Local(u16::try_from(index).unwrap_or(u16::MAX)),
                    0,
                    DefSite::entry(),
                    SsaType::I32,
                );
                if let Some(variable) = ssa.variable_mut(var) {
                    variable
                        .facts_mut()
                        .set_known_value(ConstValue::I32(*value));
                }
                var
            })
            .collect();
        (ssa, vars)
    }

    #[test]
    fn test_get_arg_constants_all_known() {
        let (ssa, vars) = function_with_known(&[42, 100]);
        let (var1, var2) = (vars[0], vars[1]);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values();
        let args = vec![var1, var2];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);

        assert!(result.is_some());
        let constants = result.unwrap();
        assert_eq!(constants.len(), 2);
        assert_eq!(constants[0], ConstValue::I32(42));
        assert_eq!(constants[1], ConstValue::I32(100));
    }

    #[test]
    fn test_get_arg_constants_partial() {
        let (mut ssa, vars) = function_with_known(&[42, 0]);
        let (var1, var2) = (vars[0], vars[1]);
        // The second argument is not known.
        if let Some(variable) = ssa.variable_mut(var2) {
            variable.facts_mut().clear_known_value();
        }

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values();
        let args = vec![var1, var2];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);

        // Should return None because not all args are known
        assert!(result.is_none());
    }

    #[test]
    fn test_get_arg_constants_empty() {
        let (ssa, _vars) = function_with_known(&[]);

        let mut resolver = ValueResolver::new(&ssa, PointerSize::Bit64);
        resolver.load_known_values();
        let args: Vec<SsaVarId> = vec![];
        let result = DecryptionPass::get_arg_constants(&args, &mut resolver);
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }

    /// Integration test: Verifies constants decryption on a real ConfuserEx sample.
    ///
    /// This test runs the full deobfuscation pipeline on `mkaring_constants.exe`
    /// which has ConfuserEx constants protection enabled.
    #[test]
    fn test_constants_decryption_integration() {
        const CONSTANTS_PATH: &str = "packers/confuserex/1.6.0/mkaring_constants.exe";

        // Run full deobfuscation pipeline (ConfuserEx is auto-registered)
        let engine = DeobfuscationEngine::new(EngineConfig::default());
        let result = engine.process_file(fixture(CONSTANTS_PATH));

        match result {
            Ok((_deobfuscated, result)) => {
                // Verify that constants were actually decrypted.
                // The mkaring_constants.exe sample has ConfuserEx constants protection.
                let stats = result.stats();

                // Assert meaningful decryption occurred
                assert!(
                    stats.constants_folded > 30,
                    "Expected at least 30 constants decrypted/folded, got {}",
                    stats.constants_folded
                );

                assert!(
                    stats.methods_transformed > 0,
                    "Expected some methods to be transformed"
                );

                assert!(
                    stats.methods_regenerated > 0,
                    "Expected some methods to have code regenerated"
                );
            }
            Err(e) => {
                panic!("Deobfuscation should succeed: {:?}", e);
            }
        }
    }
}
