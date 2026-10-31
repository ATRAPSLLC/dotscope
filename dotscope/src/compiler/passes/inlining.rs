//! Small method inlining pass.
//!
//! This pass inlines small, pure methods at their call sites. It is particularly
//! effective for:
//!
//! - Simple getters/setters
//! - Constant-returning methods
//! - String decryptor helpers
//!
//! # Inlining Criteria
//!
//! A method is considered for inlining if:
//! 1. It's small enough (instruction count <= threshold)
//! 2. It's pure or read-only (no global side effects)
//! 3. It doesn't recurse (directly or indirectly)
//! 4. The call is non-virtual (single target)
//! 5. The callee SSA is available in the context
//!
//! # Safety
//!
//! Inlining preserves semantics by:
//! - Only inlining pure/read-only methods
//! - Properly remapping all variable IDs
//! - Handling parameter binding correctly
//! - Replacing return with assignment to destination
//!
//! # Related Passes
//!
//! Proxy devirtualization and no-op elimination are handled by the standalone
//! [`ProxyDevirtualizationPass`](super::ProxyDevirtualizationPass) which runs
//! in the normalize phase unconditionally.

use std::collections::BTreeMap;

use crate::{
    analysis::{
        CilTarget, DefSite, MethodRef, ReturnInfo, SsaFunction, SsaInstruction, SsaOp, SsaType,
        SsaVarId, VariableOrigin,
    },
    compiler::{
        pass::{PassCapability, SsaPass},
        CompilerContext, EventKind, EventLog,
    },
    metadata::{tables::TableId, token::Token},
    CilObject,
};

/// A candidate call site for inlining.
#[derive(Debug, Clone)]
struct InlineCandidate {
    /// Block index containing the call
    block_idx: usize,
    /// Instruction index within the block
    instr_idx: usize,
    /// Token of the method being called
    callee_token: Token,
}

/// Method-specific context for inlining operations.
///
/// This struct holds all the common parameters needed during inlining of a single
/// method, reducing parameter passing overhead and making the code cleaner.
struct InliningContext<'a> {
    /// Reference to the pass configuration (for thresholds, etc.)
    pass: &'a InliningPass,
    /// The caller's SSA being modified
    caller_ssa: &'a mut SsaFunction,
    /// Token of the method being processed
    caller_token: Token,
    /// The analysis context with method summaries, call graph, etc.
    analysis_ctx: &'a CompilerContext,
    /// The assembly for resolving tokens
    assembly: &'a CilObject,
    /// Event log for recording changes
    changes: EventLog,
}

impl<'a> InliningContext<'a> {
    /// Creates a new inlining context for processing a method.
    ///
    /// The context holds all the state needed for inlining operations on a single
    /// method, reducing parameter passing overhead in helper methods.
    ///
    /// # Arguments
    ///
    /// * `pass` - Reference to the inlining pass configuration.
    /// * `caller_ssa` - Mutable reference to the caller's SSA being modified.
    /// * `caller_token` - Token identifying the method being processed.
    /// * `analysis_ctx` - Analysis context with method summaries and call graph.
    /// * `assembly` - Assembly for resolving tokens.
    fn new(
        pass: &'a InliningPass,
        caller_ssa: &'a mut SsaFunction,
        caller_token: Token,
        analysis_ctx: &'a CompilerContext,
        assembly: &'a CilObject,
    ) -> Self {
        Self {
            pass,
            caller_ssa,
            caller_token,
            analysis_ctx,
            assembly,
            changes: EventLog::new(),
        }
    }

    /// Returns whether any changes were made during inlining.
    ///
    /// # Returns
    ///
    /// `true` if at least one inlining operation was performed.
    fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Consumes the context and returns the accumulated event log.
    ///
    /// # Returns
    ///
    /// The event log containing all recorded changes from inlining operations.
    fn into_changes(self) -> EventLog {
        self.changes
    }

    /// Checks if a callee is a valid target for inlining.
    ///
    /// A method is invalid for inlining if it:
    /// - Is the same as the caller (self-recursion)
    /// - Is a registered decryptor (handled by decryption passes)
    /// - Is a registered dispatcher (control flow dispatcher)
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered for inlining.
    ///
    /// # Returns
    ///
    /// `true` if the callee can potentially be inlined.
    fn is_valid_target(&self, callee_token: Token) -> bool {
        // Don't inline self-recursion
        if callee_token == self.caller_token {
            return false;
        }

        // Check if this method should not be inlined (decryptors, dispatchers, etc.)
        if self.analysis_ctx.no_inline.contains(&callee_token) {
            return false;
        }

        true
    }

    /// Checks if a method should be fully inlined at a call site.
    ///
    /// A method qualifies for full inlining if it:
    /// - Is a valid target (not self-recursion, decryptor, or dispatcher)
    /// - Is smaller than the inlining threshold
    /// - Is pure or read-only (no global side effects)
    /// - Does not contain recursive calls
    ///
    /// # Arguments
    ///
    /// * `callee_token` - Token of the method being considered for inlining.
    ///
    /// # Returns
    ///
    /// `true` if the method should be inlined.
    fn should_inline(&self, callee_token: Token) -> bool {
        if !self.is_valid_target(callee_token) {
            return false;
        }

        // Check if we have the callee's SSA and evaluate criteria
        self.analysis_ctx
            .with_ssa(callee_token, |callee_ssa| {
                // Check size threshold
                let instr_count = callee_ssa.instruction_count();
                if instr_count > self.pass.inline_threshold {
                    return false;
                }

                // Check purity - only inline pure or read-only methods
                if !callee_ssa.purity().can_inline() {
                    return false;
                }

                // Check for recursive calls in the callee
                if self.has_recursive_call(callee_token, callee_ssa) {
                    return false;
                }

                true
            })
            .unwrap_or(false)
    }

    /// Checks if a method has any recursive calls (direct or indirect).
    ///
    /// This checks for both direct self-calls and indirect recursion through
    /// the call graph (e.g., A calls B which calls A).
    ///
    /// # Arguments
    ///
    /// * `method_token` - Token of the method to check for recursion.
    /// * `ssa` - The SSA representation of the method.
    ///
    /// # Returns
    ///
    /// `true` if the method contains any recursive calls.
    fn has_recursive_call(&self, method_token: Token, ssa: &SsaFunction) -> bool {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } = instr.op() {
                    if method.token() == method_token {
                        return true;
                    }
                    // Check for indirect recursion via call graph
                    let callees = self.analysis_ctx.call_graph.callees(method.token());
                    if callees.contains(&method_token) {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Resolves a token to its MethodDef equivalent.
    ///
    /// SSA forms are stored under MethodDef tokens, but call instructions may
    /// name an internal method through a MemberRef. The resolution matches the
    /// reference's signature, so an overloaded name is never inlined as the
    /// wrong overload.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to resolve (may be MethodDef, MemberRef, or MethodSpec).
    ///
    /// # Returns
    ///
    /// The resolved MethodDef token, or the original token if resolution fails.
    fn resolve_to_method_def(&self, token: Token) -> Token {
        if !token.is_table(TableId::MemberRef) {
            return token;
        }
        self.assembly
            .resolver()
            .resolve_memberref_method(token)
            .unwrap_or(token)
    }

    /// Finds all inlinable call sites in the method.
    ///
    /// Scans the caller's SSA for call instructions and evaluates each one
    /// against the inlining criteria.
    ///
    /// # Returns
    ///
    /// A vector of candidates that can be inlined.
    fn find_candidates(&self) -> Vec<InlineCandidate> {
        let mut candidates = Vec::new();

        for (block_idx, instr_idx, instr) in self.caller_ssa.iter_instructions() {
            let raw_callee_token = match instr.op() {
                SsaOp::Call { method, .. } => method.token(),
                SsaOp::CallVirt { method, .. } => {
                    let token = method.token();
                    // Check if this is actually polymorphic
                    if self
                        .analysis_ctx
                        .call_graph
                        .resolver()
                        .is_polymorphic(token)
                    {
                        continue;
                    }
                    token
                }
                _ => continue,
            };

            // Resolve MemberRef tokens to MethodDef tokens for SSA lookup
            let callee_token = self.resolve_to_method_def(raw_callee_token);

            // Try full inlining (for pure methods)
            if self.should_inline(callee_token) {
                candidates.push(InlineCandidate {
                    block_idx,
                    instr_idx,
                    callee_token,
                });
            }
        }

        candidates
    }

    /// Processes a single inlining candidate.
    ///
    /// Performs full body inlining and marks successfully inlined methods in
    /// the analysis context.
    ///
    /// # Arguments
    ///
    /// * `candidate` - The inlining candidate to process.
    ///
    /// # Returns
    ///
    /// `true` if the inlining operation was successful.
    fn process_candidate(&mut self, candidate: &InlineCandidate) -> bool {
        let call_op = match self.caller_ssa.block(candidate.block_idx) {
            Some(block) => match block.instructions().get(candidate.instr_idx) {
                Some(instr) => instr.op().clone(),
                None => return false,
            },
            None => return false,
        };

        // Get the callee SSA
        let Some(callee_ssa) = self
            .analysis_ctx
            .with_ssa(candidate.callee_token, Clone::clone)
        else {
            return false;
        };

        let success = self.inline_call(
            &callee_ssa,
            candidate.block_idx,
            candidate.instr_idx,
            &call_op,
            candidate.callee_token,
        );

        if success {
            self.analysis_ctx.mark_inlined(candidate.callee_token);
        }
        success
    }

    /// Inlines a callee method at a specific call site.
    ///
    /// This method handles different return patterns optimally:
    /// - Constant returns: Replace call with constant assignment
    /// - Pass-through returns: Replace call with copy from argument
    /// - Void returns: Replace a call expecting no value with Nop, when the
    ///   callee returns at all
    /// - Pure computation: Perform full block inlining
    ///
    /// # Arguments
    ///
    /// * `callee_ssa` - The callee's SSA representation.
    /// * `call_block_idx` - Block index of the call instruction in the caller.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `call_op` - The call operation being inlined.
    /// * `callee_token` - Token of the callee (for logging).
    ///
    /// # Returns
    ///
    /// `true` if inlining was successful.
    fn inline_call(
        &mut self,
        callee_ssa: &SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        call_op: &SsaOp,
        callee_token: Token,
    ) -> bool {
        // Extract call information
        let (dest, args) = match call_op {
            SsaOp::Call { dest, args, .. } | SsaOp::CallVirt { dest, args, .. } => {
                (*dest, args.clone())
            }
            _ => return false,
        };

        // The shortcuts below replace the call with its result, or delete it,
        // without the callee's body. That drops whatever the body does besides
        // compute the result - which purity rules out for writes, but not for a
        // division by zero, a null dereference or an overflow check, each of
        // which throws. A body that may throw is inlined whole instead, so the
        // throw stays where the call was.
        let body_may_throw = callee_ssa.blocks().iter().any(|block| {
            block
                .instructions()
                .iter()
                .any(|instr| instr.may_throw() && !matches!(instr.op(), SsaOp::Return { .. }))
        });
        let return_info = if body_may_throw {
            ReturnInfo::Unknown
        } else {
            callee_ssa.return_info()
        };

        match return_info {
            ReturnInfo::Constant(value) => {
                if let Some(dest_var) = dest {
                    if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                        if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                            instr.set_op(SsaOp::Const {
                                dest: dest_var,
                                value: value.clone(),
                            });
                            self.changes
                                .record(EventKind::MethodInlined)
                                .at(self.caller_token, call_instr_idx)
                                .message(format!("inlined constant {callee_token:?}"));
                            return true;
                        }
                    }
                } else {
                    // Void destination but constant return - just remove the call
                    if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                        if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                            instr.set_op(SsaOp::Nop);
                            self.changes
                                .record(EventKind::MethodInlined)
                                .at(self.caller_token, call_instr_idx)
                                .message(format!("eliminated pure call {callee_token:?}"));
                            return true;
                        }
                    }
                }
            }
            ReturnInfo::PassThrough(param_idx) => {
                if let Some(dest_var) = dest {
                    if let Some(&src_var) = args.get(param_idx) {
                        if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                            if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                                instr.set_op(SsaOp::Copy {
                                    dest: dest_var,
                                    src: src_var,
                                });
                                self.changes
                                    .record(EventKind::MethodInlined)
                                    .at(self.caller_token, call_instr_idx)
                                    .message(format!("inlined passthrough {callee_token:?}"));
                                return true;
                            }
                        }
                    }
                }
            }
            ReturnInfo::Void => {
                // Removing the call is right only for a call expecting no
                // value from a callee that comes back. A callee with no
                // `Return` never does, and a value the call defines would be
                // left with no definition.
                let returns = callee_ssa
                    .iter_instructions()
                    .any(|(_, _, instr)| matches!(instr.op(), SsaOp::Return { .. }));
                if dest.is_some() || !returns {
                    return false;
                }
                if let Some(block) = self.caller_ssa.block_mut(call_block_idx) {
                    if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
                        instr.set_op(SsaOp::Nop);
                        self.changes
                            .record(EventKind::MethodInlined)
                            .at(self.caller_token, call_instr_idx)
                            .message(format!("eliminated void call {callee_token:?}"));
                        return true;
                    }
                }
            }
            ReturnInfo::PureComputation | ReturnInfo::Dynamic | ReturnInfo::Unknown => {
                return self.inline_full(
                    callee_ssa,
                    call_block_idx,
                    call_instr_idx,
                    dest,
                    &args,
                    callee_token,
                );
            }
        }

        false
    }

    /// Performs full SSA inlining by copying blocks from callee into caller.
    ///
    /// This handles the complex case where simple replacement isn't possible.
    /// The algorithm:
    /// 1. Map callee parameters to call arguments
    /// 2. Copy callee instructions with remapped variable IDs
    /// 3. Replace the call with inlined instructions
    /// 4. Handle return value assignment if needed
    ///
    /// Currently only supports single-block callees to keep complexity manageable.
    ///
    /// # Arguments
    ///
    /// * `callee_ssa` - The callee's SSA representation.
    /// * `call_block_idx` - Block index of the call instruction.
    /// * `call_instr_idx` - Instruction index within the block.
    /// * `dest` - Optional destination variable for the call result.
    /// * `args` - Arguments passed to the call.
    /// * `callee_token` - Token of the callee (for logging).
    ///
    /// # Returns
    ///
    /// `true` if full inlining was successful.
    fn inline_full(
        &mut self,
        callee_ssa: &SsaFunction,
        call_block_idx: usize,
        call_instr_idx: usize,
        dest: Option<SsaVarId>,
        args: &[SsaVarId],
        callee_token: Token,
    ) -> bool {
        // Only inline single-block callees for now
        if callee_ssa.blocks().len() != 1 {
            return false;
        }

        let Some(callee_block) = callee_ssa.blocks().first() else {
            return false;
        };

        // The body is spliced into the middle of the caller's block, so it must
        // fall through to a `Return` and nowhere else. And it must not name the
        // callee's frame: a `ldarg`, `ldloc` or the address of either refers to
        // a slot by number, and in the caller that number is a different slot.
        let ends_in_return = matches!(
            callee_block.instructions().last().map(SsaInstruction::op),
            Some(SsaOp::Return { .. })
        );
        let names_callee_frame = callee_block.instructions().iter().any(|instr| {
            matches!(
                instr.op(),
                SsaOp::LoadArg { .. }
                    | SsaOp::LoadLocal { .. }
                    | SsaOp::LoadArgAddr { .. }
                    | SsaOp::LoadLocalAddr { .. }
                    | SsaOp::RuntimeValue { .. }
            )
        });
        if !ends_in_return || names_callee_frame || callee_ssa.has_exception_handlers() {
            return false;
        }

        // Build variable remapping
        let mut var_remap: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();

        // Map callee parameters to call arguments
        for (param_idx, &arg_var) in args.iter().enumerate() {
            // Safe: .NET methods have at most 65535 parameters
            #[allow(clippy::cast_possible_truncation)]
            if let Some(param_var) = callee_ssa
                .variables_from_argument(param_idx as u16)
                .find(|v| v.version() == 0)
            {
                var_remap.insert(param_var.id(), arg_var);
            }
        }

        // Collect instructions to inline (excluding return)
        let mut inlined_ops: Vec<SsaOp> = Vec::new();
        let mut return_value: Option<SsaVarId> = None;

        for instr in callee_block.instructions() {
            let op = instr.op();
            if let SsaOp::Return { value } = op {
                return_value = *value;
            } else {
                let Some(remapped_op) =
                    Self::remap_op(op, &mut var_remap, callee_ssa, self.caller_ssa)
                else {
                    return false;
                };
                inlined_ops.push(remapped_op);
            }
        }
        if return_value.is_some_and(|value| !var_remap.contains_key(&value)) {
            return false;
        }
        // The call's result is defined by the copy of the returned value; with
        // nothing returned it would have no definition at all.
        if dest.is_some() && return_value.is_none() {
            return false;
        }

        // Modify the caller
        let Some(block) = self.caller_ssa.block_mut(call_block_idx) else {
            return false;
        };

        // Replace call instruction with first inlined op (or Nop if empty)
        let first_op = inlined_ops.first().cloned();
        if let Some(instr) = block.instructions_mut().get_mut(call_instr_idx) {
            if let Some(op) = first_op {
                instr.set_op(op);
            } else {
                instr.set_op(SsaOp::Nop);
            }
        } else {
            return false;
        }

        // Insert remaining inlined ops.
        //
        // Capture the count before `into_iter` consumes the vector: the return-value copy below
        // must land *after* every spliced op, and it needs this length to know where that is.
        let spliced_count = inlined_ops.len().saturating_sub(1);
        let instructions = block.instructions_mut();
        let base = call_instr_idx.saturating_add(1);
        for (i, op) in inlined_ops.into_iter().skip(1).enumerate() {
            instructions.insert(base.saturating_add(i), SsaInstruction::synthetic(op));
        }

        // Handle return value
        if let (Some(dest_var), Some(ret_var)) = (dest, return_value) {
            let remapped_ret = var_remap.get(&ret_var).copied().unwrap_or(ret_var);

            if dest_var != remapped_ret {
                let Some(block) = self.caller_ssa.block_mut(call_block_idx) else {
                    return false;
                };
                // *After* the spliced body, not at its start. Inserting at
                // `call_instr_idx + 1` puts the copy between the callee's first op and the
                // rest, so for any callee with two or more non-`Return` ops the copy reads
                // `remapped_ret` before the op that defines it — a use-before-def that hands
                // `dest_var` whatever the unwritten storage holds. Nothing downstream re-sorts
                // block instructions before codegen.
                let insert_pos = call_instr_idx
                    .saturating_add(1)
                    .saturating_add(spliced_count);
                block.instructions_mut().insert(
                    insert_pos,
                    SsaInstruction::synthetic(SsaOp::Copy {
                        dest: dest_var,
                        src: remapped_ret,
                    }),
                );
            }
        }

        self.changes
            .record(EventKind::MethodInlined)
            .at(self.caller_token, call_instr_idx)
            .message(format!("fully inlined {callee_token:?}"));
        true
    }

    /// Remaps variables in an SSA operation using the given mapping.
    ///
    /// Creates fresh variables in the caller for the variables the operation
    /// defines, then rewrites every operand at once. At once is the point: the
    /// callee's numbering and the caller's overlap, so rewriting one operand at
    /// a time lets a later rewrite catch an operand an earlier one produced -
    /// a call passing `(v1, v0)` to a callee computing `v0 + v1` would come out
    /// as `v0 + v0`.
    ///
    /// # Arguments
    ///
    /// * `op` - The SSA operation to remap.
    /// * `var_remap` - Mapping from callee variables to caller variables.
    /// * `callee_ssa` - The callee's SSA (for variable metadata).
    /// * `caller_ssa` - The caller's SSA (for creating new variables).
    ///
    /// # Returns
    ///
    /// The operation in the caller's variables, or `None` when it reads a callee
    /// variable nothing maps: one the callee neither receives as a parameter nor
    /// defines before this point, which has no counterpart in the caller.
    fn remap_op(
        op: &SsaOp,
        var_remap: &mut BTreeMap<SsaVarId, SsaVarId>,
        callee_ssa: &SsaFunction,
        caller_ssa: &mut SsaFunction,
    ) -> Option<SsaOp> {
        if op.uses().iter().any(|used| !var_remap.contains_key(used)) {
            return None;
        }

        // Every definition, not just the primary destination: an operation
        // with secondary or flag outputs defines those too.
        for def in op.defs() {
            Self::get_or_create_var(def, var_remap, callee_ssa, caller_ssa);
        }

        Some(op.remap_variables(|var| var_remap.get(&var).copied()))
    }

    /// Gets the remapped variable or creates a new one in the caller.
    ///
    /// When creating a new variable, copies the metadata from the callee's
    /// variable to ensure proper type information. The new variable is
    /// registered as a stack temporary in the caller.
    ///
    /// # Arguments
    ///
    /// * `var` - The callee variable to look up or create.
    /// * `var_remap` - Mapping from callee variables to caller variables.
    /// * `callee_ssa` - The callee's SSA (for variable metadata).
    /// * `caller_ssa` - The caller's SSA (for creating new variables).
    ///
    /// # Returns
    ///
    /// The remapped variable ID in the caller's SSA.
    fn get_or_create_var(
        var: SsaVarId,
        var_remap: &mut BTreeMap<SsaVarId, SsaVarId>,
        callee_ssa: &SsaFunction,
        caller_ssa: &mut SsaFunction,
    ) -> SsaVarId {
        if let Some(&remapped) = var_remap.get(&var) {
            return remapped;
        }

        // Allocate a Phi-origin variable for the inlined callee variable.
        // Inlined callee variables are synthetic — use Phi origin since
        // they don't correspond to any real CIL local in the caller.
        let var_type = callee_ssa
            .variable(var)
            .map(|v| v.var_type().clone())
            .unwrap_or(SsaType::Unknown);
        let new_id = caller_ssa.create_variable(
            VariableOrigin::Phi,
            0,
            DefSite::instruction(0, 0),
            var_type,
        );

        var_remap.insert(var, new_id);
        new_id
    }
}

/// Pass that inlines small, pure methods at their call sites.
///
/// This pass operates on a per-method basis but consults the global context
/// to access callee method SSA forms. It identifies call sites where the
/// callee is small and pure, then replaces the call with the inlined body.
#[derive(Debug)]
pub struct InliningPass {
    /// Maximum instruction count for inlining candidates.
    inline_threshold: usize,
}

impl InliningPass {
    /// Creates a new inlining pass.
    ///
    /// # Arguments
    ///
    /// * `threshold` - Maximum instruction count for methods to be inlined.
    #[must_use]
    pub fn new(threshold: usize) -> Self {
        Self {
            inline_threshold: threshold,
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for InliningPass {
    fn name(&self) -> &'static str {
        "InliningPass"
    }

    fn description(&self) -> &'static str {
        "Inlines small, pure methods at their call sites"
    }

    fn reads_peer_ssa(&self) -> bool {
        true
    }

    fn provides(&self) -> &[PassCapability] {
        &[PassCapability::InlinedMethods]
    }

    fn requires(&self) -> &[PassCapability] {
        &[PassCapability::DevirtualizedCalls]
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("InliningPass requires an assembly"))?;

        // Create method-specific inlining context
        let mut inline_ctx = InliningContext::new(self, ssa, method.0, host, &assembly);

        // Find all candidates
        let candidates = inline_ctx.find_candidates();
        if candidates.is_empty() {
            return Ok(false);
        }

        // Process candidates in reverse order to maintain valid indices
        for candidate in candidates.into_iter().rev() {
            inline_ctx.process_candidate(&candidate);
        }

        // Merge changes back to the analysis context
        let changed = inline_ctx.has_changes();
        if changed {
            host.events.merge(&inline_ctx.into_changes());
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{
            CallGraph, ConstValue, MethodRef, ReturnInfo, SsaFunction, SsaFunctionBuilder, SsaOp,
            SsaType, SsaVarId,
        },
        compiler::{
            passes::inlining::{InliningContext, InliningPass},
            CompilerContext, SsaPass,
        },
        metadata::token::Token,
        testkit::helpers::test_assembly_arc,
        CilObject,
    };

    fn test_context() -> CompilerContext {
        CompilerContext::new(Arc::new(CallGraph::new()))
    }

    /// Returns a cached test assembly for use in tests.
    fn test_assembly() -> Arc<CilObject> {
        test_assembly_arc()
    }

    #[test]
    fn test_pass_creation() {
        let pass = InliningPass::new(20);
        assert_eq!(pass.name(), "InliningPass");
        assert_eq!(pass.inline_threshold, 20);

        let pass_custom = InliningPass::new(50);
        assert_eq!(pass_custom.inline_threshold, 50);
    }

    #[test]
    fn test_inline_constant_return() {
        // Callee: returns constant 42
        let callee_token = Token::new(0x06000002);
        let (callee_ssa, callee_v0) = {
            let mut v0_out = SsaVarId::from_index(0);
            let ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let v0 = b.const_i32(42);
                        v0_out = v0;
                        b.ret_val(v0);
                    });
                })
                .unwrap();
            (ssa, v0_out)
        };

        // Caller: calls callee
        let caller_token = Token::new(0x06000001);
        let (mut caller_ssa, call_dest) = {
            let mut dest_out = SsaVarId::from_index(1);
            let ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let dest = b.call(MethodRef::new(callee_token), &[], SsaType::I32);
                        dest_out = dest;
                        b.ret_val(dest);
                    });
                })
                .unwrap();
            (ssa, dest_out)
        };

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context (need to borrow caller_ssa)
        let call_op = caller_ssa.block(0).unwrap().instructions()[0].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new(20);
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 0, &call_op, callee_token);

        assert!(result, "Inlining should succeed");

        // Check that the call was replaced with a constant
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        match first_instr.op() {
            SsaOp::Const { dest, value } => {
                assert_eq!(*dest, call_dest);
                assert_eq!(*value, ConstValue::I32(42));
            }
            other => panic!("Expected Const, got {:?}", other),
        }

        // Verify the callee's const was created correctly
        let _ = callee_v0;
    }

    /// Inlines `callee` at the single call in block 0 of `caller`.
    fn inline_first_call(
        callee_ssa: &SsaFunction,
        caller_ssa: &mut SsaFunction,
        call_instr_idx: usize,
    ) -> bool {
        let callee_token = Token::new(0x06000002);
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());
        let call_op = caller_ssa.block(0).unwrap().instructions()[call_instr_idx]
            .op()
            .clone();
        let pass = InliningPass::new(20);
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, caller_ssa, Token::new(0x06000001), &ctx, &assembly);
        inline_ctx.inline_call(callee_ssa, 0, call_instr_idx, &call_op, callee_token)
    }

    /// A callee with no `Return` never comes back, so its call is not removed
    /// as a void one: not when the call expects a value, which would then have
    /// no definition, and not when it expects none, which would let the
    /// caller run past a call that never returns.
    #[test]
    fn a_callee_that_never_returns_is_not_removed() {
        // Callee: `for (;;) {}`, which the return classification reads as void.
        let callee_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.jump(0));
            })
            .unwrap();
        assert!(matches!(callee_ssa.return_info(), ReturnInfo::Void));

        for expects_value in [true, false] {
            let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let callee = MethodRef::new(Token::new(0x06000002));
                        if expects_value {
                            let result = b.call(callee, &[], SsaType::I32);
                            b.ret_val(result);
                        } else {
                            b.call_void(callee, &[]);
                            b.ret();
                        }
                    });
                })
                .unwrap();
            assert!(
                !inline_first_call(&callee_ssa, &mut caller_ssa, 0),
                "the call is kept (expects a value: {expects_value})"
            );
            assert!(matches!(
                caller_ssa.block(0).unwrap().instructions()[0].op(),
                SsaOp::Call { .. }
            ));
        }
    }

    /// A void callee's call that nonetheless expects a value is not removed:
    /// the value would have no definition.
    #[test]
    fn a_void_callee_called_for_a_value_is_not_removed() {
        let callee_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let result = b.call(MethodRef::new(Token::new(0x06000002)), &[], SsaType::I32);
                    b.ret_val(result);
                });
            })
            .unwrap();
        assert!(!inline_first_call(&callee_ssa, &mut caller_ssa, 0));
        assert!(matches!(
            caller_ssa.block(0).unwrap().instructions()[0].op(),
            SsaOp::Call { dest: Some(_), .. }
        ));
    }

    /// A body that may throw is inlined whole, and when it returns nothing
    /// the call expecting a value is kept: the value would have no definition.
    #[test]
    fn a_whole_body_returning_nothing_is_not_inlined_for_a_value() {
        let callee_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (a, b) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                f.block(0, |blk| {
                    let _ = blk.div(a, b);
                    blk.ret();
                });
            })
            .unwrap();
        let mut caller_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (x, y) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                f.block(0, |blk| {
                    let result = blk.call(
                        MethodRef::new(Token::new(0x06000002)),
                        &[x, y],
                        SsaType::I32,
                    );
                    blk.ret_val(result);
                });
            })
            .unwrap();
        assert!(!inline_first_call(&callee_ssa, &mut caller_ssa, 0));
        assert!(matches!(
            caller_ssa.block(0).unwrap().instructions()[0].op(),
            SsaOp::Call { dest: Some(_), .. }
        ));
    }

    #[test]
    fn an_inlined_body_reads_the_arguments_in_the_order_they_were_passed() {
        // Callee `(a, b) => a - b`, whose parameters are v0 and v1.
        let callee_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (a, b) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                f.block(0, |blk| {
                    let diff = blk.sub(a, b);
                    blk.ret_val(diff);
                });
            })
            .unwrap();

        // Caller `(x, y) => callee(y, x)`: its own v0 and v1, passed crosswise.
        let mut params = (SsaVarId::from_index(0), SsaVarId::from_index(0));
        let mut caller_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let (x, y) = (f.arg(0, SsaType::I32), f.arg(1, SsaType::I32));
                params = (x, y);
                f.block(0, |blk| {
                    let r = blk.call(
                        MethodRef::new(Token::new(0x06000002)),
                        &[y, x],
                        SsaType::I32,
                    );
                    blk.ret_val(r);
                });
            })
            .unwrap();

        assert!(inline_first_call(&callee_ssa, &mut caller_ssa, 0));

        let (x, y) = params;
        let sub = caller_ssa
            .block(0)
            .unwrap()
            .instructions()
            .iter()
            .find_map(|instr| match instr.op() {
                SsaOp::Sub { left, right, .. } => Some((*left, *right)),
                _ => None,
            })
            .expect("the callee's subtraction is inlined");
        assert_eq!(sub, (y, x), "callee(y, x) computes y - x");
    }

    #[test]
    fn a_callee_that_may_throw_is_not_replaced_by_its_constant_result() {
        // Callee `(a) => { _ = 10 / a; return 5; }`: always 5, but it throws for 0.
        let callee_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let a = f.arg(0, SsaType::I32);
                f.block(0, |blk| {
                    let ten = blk.const_i32(10);
                    let _quotient = blk.div(ten, a);
                    let five = blk.const_i32(5);
                    blk.ret_val(five);
                });
            })
            .unwrap();
        assert!(
            matches!(callee_ssa.return_info(), ReturnInfo::Constant(_)),
            "the shortcut this guards against must be the one on offer"
        );

        let mut caller_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let x = f.arg(0, SsaType::I32);
                f.block(0, |blk| {
                    let r = blk.call(MethodRef::new(Token::new(0x06000002)), &[x], SsaType::I32);
                    blk.ret_val(r);
                });
            })
            .unwrap();

        assert!(inline_first_call(&callee_ssa, &mut caller_ssa, 0));
        assert!(
            caller_ssa
                .block(0)
                .unwrap()
                .instructions()
                .iter()
                .any(|instr| matches!(instr.op(), SsaOp::Div { .. })),
            "the division that may throw must survive the inline"
        );
    }

    #[test]
    fn a_callee_reading_its_own_frame_slot_is_not_inlined() {
        let callee_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let loaded = f.var();
                f.block(0, |blk| {
                    blk.op_typed(
                        SsaOp::LoadArg {
                            dest: loaded,
                            arg_index: 0,
                        },
                        SsaType::I32,
                    );
                    blk.ret_val(loaded);
                });
            })
            .unwrap();
        let mut caller_ssa = SsaFunctionBuilder::new(2, 0)
            .build_with(|f| {
                let y = f.arg(1, SsaType::I32);
                f.block(0, |blk| {
                    let r = blk.call(MethodRef::new(Token::new(0x06000002)), &[y], SsaType::I32);
                    blk.ret_val(r);
                });
            })
            .unwrap();

        assert!(
            !inline_first_call(&callee_ssa, &mut caller_ssa, 0),
            "`ldarg.0` in the callee is not the caller's argument 0"
        );
    }

    #[test]
    fn test_inline_void_pure() {
        // Callee: void method that does nothing impure
        let callee_token = Token::new(0x06000002);
        let callee_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();

        // Caller: calls callee
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.call_void(MethodRef::new(callee_token), &[]);
                    b.ret();
                });
            })
            .unwrap();

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context
        let call_op = caller_ssa.block(0).unwrap().instructions()[0].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new(20);
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 0, &call_op, callee_token);

        assert!(result, "Inlining should succeed");

        // Check that the call was replaced with Nop
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        let first_instr = &block.instructions()[0];
        assert!(
            matches!(first_instr.op(), SsaOp::Nop),
            "Expected Nop, got {:?}",
            first_instr.op()
        );
    }

    #[test]
    fn test_no_inline_self_recursion() {
        let pass = InliningPass::new(20);
        let token = Token::new(0x06000001);
        let ctx = test_context();
        let assembly = test_assembly();

        // Create a dummy SSA for the context
        let mut dummy_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();

        let inline_ctx = InliningContext::new(&pass, &mut dummy_ssa, token, &ctx, &assembly);

        // Self-recursion check - is_valid_target returns false for self
        assert!(!inline_ctx.is_valid_target(token));
    }

    #[test]
    fn test_no_inline_large_method() {
        let callee_token = Token::new(0x06000002);
        let caller_token = Token::new(0x06000001);

        // Create a callee with many instructions (> threshold)
        let callee_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    for _ in 0..30 {
                        let _ = b.const_i32(0);
                    }
                    b.ret();
                });
            })
            .unwrap();

        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa);

        let pass = InliningPass::new(20);
        let assembly = test_assembly();

        // Create a dummy caller SSA
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| b.ret());
            })
            .unwrap();

        let inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        assert!(!inline_ctx.should_inline(callee_token));
    }

    #[test]
    fn test_inline_full_computation() {
        // Callee: returns arg0 + 10
        // This is a PureComputation that requires full inlining
        let callee_token = Token::new(0x06000002);
        let callee_ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let param0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    let v1 = b.const_i32(10);
                    let v2 = b.add(param0, v1);
                    b.ret_val(v2);
                });
            })
            .unwrap();

        // Caller: calls callee with v0=5, stores result in v3
        let caller_token = Token::new(0x06000001);
        let mut caller_ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let v0 = b.const_i32(5);
                    let v1 = b.call(MethodRef::new(callee_token), &[v0], SsaType::I32);
                    b.ret_val(v1);
                });
            })
            .unwrap();

        // Set up context
        let ctx = test_context();
        ctx.set_ssa(callee_token, callee_ssa.clone());

        // Get the call op before creating context
        let call_op = caller_ssa.block(0).unwrap().instructions()[1].op().clone();

        // Create inlining context and inline
        let pass = InliningPass::new(20);
        let assembly = test_assembly();
        let mut inline_ctx =
            InliningContext::new(&pass, &mut caller_ssa, caller_token, &ctx, &assembly);
        let result = inline_ctx.inline_call(&callee_ssa, 0, 1, &call_op, callee_token);

        assert!(result, "Full inlining should succeed");

        // Verify the caller now has more instructions
        let block = inline_ctx.caller_ssa.block(0).unwrap();
        assert!(
            block.instructions().len() > 3,
            "Expected inlined instructions, got {} instructions",
            block.instructions().len()
        );

        // Check that the second instruction is now the inlined const 10
        let second_instr = &block.instructions()[1];
        match second_instr.op() {
            SsaOp::Const { value, .. } => {
                assert_eq!(*value, ConstValue::I32(10), "Expected inlined constant 10");
            }
            other => panic!("Expected Const for inlined instruction, got {:?}", other),
        }

        // Check that there's an Add instruction
        let has_add = block
            .instructions()
            .iter()
            .any(|i| matches!(i.op(), SsaOp::Add { .. }));
        assert!(has_add, "Expected Add instruction after inlining");
    }
}
