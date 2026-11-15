//! JIEJIE.NET typeof() restoration pass.
//!

//! Replaces `Call(GetTypeInstance, index)` operations with the original
//! `LoadToken` + `Call(GetTypeFromHandle)` pattern that JIEJIE.NET replaced
//! with its RuntimeTypeHandleContainer indirection.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Value** phase, after Int32ValueContainer resolution
//! (which resolves the index constants) and before CFF unflattening.
//!
//! # Algorithm
//!
//! 1. During technique initialization, parse the container's `.cctor` to extract
//!    the ordered list of `ldtoken` type tokens (index 0, 1, 2, ...)
//! 2. For each method, scan for `Call { method: accessor_token, args: [index_var] }`
//! 3. Resolve `index_var` to a `Const(I32(N))` via the SSA constant map
//! 4. Replace the Call with `LoadToken` + `Call(GetTypeFromHandle)` to produce
//!    a `System.Type` object (not just a `RuntimeTypeHandle`)
//!
//! # Example
//!
//! ```text
//! // Before:
//! v1 = Const(I32(2))
//! v2 = call GetTypeInstance(v1)   // returns System.Type
//!
//! // After:
//! v1 = Const(I32(2))
//! vN = ldtoken TypeRef(0x01000005)           // RuntimeTypeHandle
//! v2 = call GetTypeFromHandle(vN)            // System.Type
//! ```

use log::debug;

use crate::{
    analysis::{
        resolve_corelib_valuetype, CallData, Callee, CilTarget, ConstValue, DefSite, MethodRef,
        SsaFunction, SsaInstruction, SsaOp, SsaOpCilExt, SsaVarId, TypeRef, VariableOrigin,
    },
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
    CilObject, Error,
};

/// SSA pass that replaces JIEJIE.NET typeof container calls with
/// `LoadToken` + `Call(GetTypeFromHandle)`.
///
/// Created by the `jiejienet.typeof` technique after detection identifies the
/// container class and its `.cctor` is parsed for the type token mapping.
pub struct TypeOfRestorationPass {
    /// Token of the GetTypeInstance accessor method.
    accessor_token: Token,
    /// Ordered type tokens extracted from the container's .cctor.
    /// Index in the vector corresponds to the integer argument passed to the accessor.
    type_tokens: Vec<Token>,
    /// MemberRef token for `System.Type::GetTypeFromHandle(RuntimeTypeHandle)`.
    get_type_from_handle_token: Token,
}

impl TypeOfRestorationPass {
    /// Creates a new typeof restoration pass.
    ///
    /// # Arguments
    ///
    /// * `accessor_token` - Token of the container's GetTypeInstance method
    /// * `type_tokens` - Ordered type tokens from the container's .cctor ldtoken instructions
    /// * `get_type_from_handle_token` - MemberRef token for `Type.GetTypeFromHandle`
    #[must_use]
    pub fn new(
        accessor_token: Token,
        type_tokens: Vec<Token>,
        get_type_from_handle_token: Token,
    ) -> Self {
        Self {
            accessor_token,
            type_tokens,
            get_type_from_handle_token,
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for TypeOfRestorationPass {
    fn name(&self) -> &'static str {
        "jiejie-typeof-restore"
    }

    fn description(&self) -> &'static str {
        "Replaces JIEJIE.NET typeof container calls with ldtoken + GetTypeFromHandle"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly_arc = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("TypeOfRestorationPass requires an assembly"))?;
        let assembly: &CilObject = &assembly_arc;
        let ctx = host;
        if self.type_tokens.is_empty() {
            return Ok(false);
        }

        // Build constant map to resolve index arguments
        let constants = ssa.find_constants();

        // Collect replacement info: (block_idx, instr_idx, type_token, original_dest)
        let mut replacements: Vec<(usize, usize, Token, SsaVarId)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((method_token, call)) = instr.op().method_call() {
                    let (dest, args) = (&call.dest, &call.args);
                    if method_token != self.accessor_token {
                        continue;
                    }

                    // The accessor takes a single int32 argument (the index)
                    if args.len() != 1 {
                        continue;
                    }

                    // Resolve the index argument to a constant
                    let Some(arg0) = args.first() else { continue };
                    let Some(ConstValue::I32(index)) = constants.get(arg0) else {
                        continue;
                    };

                    let index = *index as usize;
                    let Some(&type_token) = self.type_tokens.get(index) else {
                        debug!(
                            "jiejie-typeof: index {} out of bounds (max {}), skipping",
                            index,
                            self.type_tokens.len()
                        );
                        continue;
                    };

                    if let Some(dest) = dest {
                        replacements.push((block_idx, instr_idx, type_token, *dest));
                    }
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        // Apply replacements in reverse order within each block to maintain indices
        // when inserting new instructions.
        // Sort by (block_idx, instr_idx) descending so later indices are processed first.
        replacements.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.cmp(&a.1)));

        for (block_idx, instr_idx, type_token, orig_dest) in &replacements {
            // Create a temporary variable for the RuntimeTypeHandle (LoadToken result).
            // Resolve the corelib TypeRef now so the SSA variable carries a
            // proper `valuetype [mscorlib]System.RuntimeTypeHandle` token -
            // a tokenless placeholder would produce invalid CIL if this
            // variable ever spilled to a local slot downstream.
            let handle_type = resolve_corelib_valuetype(assembly, "System.RuntimeTypeHandle");
            let handle_var = ssa.create_variable(
                VariableOrigin::Phi, // synthetic origin
                0,
                DefSite::instruction(*block_idx, *instr_idx),
                handle_type,
            );

            // Replace the original Call with LoadToken into the temp variable
            ssa.replace_instruction_op(
                *block_idx,
                *instr_idx,
                SsaOp::LoadToken {
                    dest: handle_var,
                    token: TypeRef::new(*type_token),
                },
            );

            // Insert a Call(GetTypeFromHandle) instruction right after the LoadToken.
            // This converts RuntimeTypeHandle → System.Type, matching what GetTypeInstance did.
            let call_instr = SsaInstruction::synthetic(
                CallData::new(
                    Some(*orig_dest),
                    Callee::Direct(MethodRef::new(self.get_type_from_handle_token)),
                    vec![handle_var],
                )
                .into(),
            );

            let block = ssa.blocks_mut().get_mut(*block_idx).ok_or_else(|| {
                Error::Deobfuscation(format!(
                    "jiejie-typeof: block index {} out of bounds",
                    *block_idx
                ))
            })?;
            block
                .instructions_mut()
                .insert(instr_idx.saturating_add(1), call_instr);

            ctx.events.record(EventKind::ValueResolved);
        }

        Ok(true)
    }
}
