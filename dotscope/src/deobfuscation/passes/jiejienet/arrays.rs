//! JIEJIE.NET array initialization restoration pass.
//!
//! Replaces `Call(GetHandle, index)` operations with `Const(FieldHandle(...))`
//! to restore the original `ldtoken <field>` that JIEJIE.NET replaced with its
//! RuntimeFieldHandleContainer indirection.
//!
//! Also handles `Call(MyInitializeArray, array, handle, xorKey)` by replacing it
//! with `Call(RuntimeHelpers.InitializeArray, array, handle)`, removing the XOR
//! key argument. The actual FieldRVA data decryption is done in the byte transform
//! phase (see [`crate::deobfuscation::techniques::jiejienet::arrays`]).
//!
//! # Pipeline Position
//!
//! This pass runs in the **Value** phase, after Int32ValueContainer resolution
//! (which resolves the index constants) and before CFF unflattening.
//!
//! # Algorithm
//!
//! 1. During technique initialization, parse the container's `.cctor` to extract
//!    the ordered list of `ldtoken` field tokens (index 0, 1, 2, ...)
//! 2. For each method, scan for `Call { method: accessor_token, args: [index_var] }`
//! 3. Resolve `index_var` to a `Const(I32(N))` via the SSA constant map
//! 4. Replace the Call with `Const { dest, value: FieldHandle(field_tokens[N]) }`
//! 5. For `Call { method: init_array_method, args: [array, handle, xorKey] }`,
//!    replace with `Call { method: init_array_target, args: [array, handle] }`
//!
//! # Example
//!
//! ```text
//! // Before:
//! v3 = Const(I32(1))
//! v4 = call GetHandle(v3)          // accessor method token
//! call MyInitializeArray(v2, v4, v5)  // XOR-encrypted init
//!
//! // After:
//! v3 = Const(I32(1))
//! v4 = Const(FieldHandle(0x04000010))  // the actual field token at index 1
//! call RuntimeHelpers.InitializeArray(v2, v4)  // standard BCL call
//! ```

use crate::{
    analysis::{
        Callee, CilTarget, ConstValue, FieldRef, MethodRef, SsaFunction, SsaOp, SsaOpCilExt,
    },
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
};

/// SSA pass that replaces JIEJIE.NET field handle container calls with direct field handle constants
/// and restores `MyInitializeArray` calls to standard `RuntimeHelpers.InitializeArray`.
///
/// Created by the `jiejienet.arrays` technique after detection identifies the
/// container class and its `.cctor` is parsed for the field token mapping.
pub struct ArrayInitRestorationPass {
    /// Token of the GetHandle accessor method.
    accessor_token: Token,
    /// Ordered field tokens extracted from the container's .cctor.
    /// Index in the vector corresponds to the integer argument passed to the accessor.
    field_tokens: Vec<Token>,
    /// Token of the `MyInitializeArray` wrapper method, if detected.
    init_array_method: Option<Token>,
    /// Token of `RuntimeHelpers.InitializeArray` MemberRef to replace with.
    init_array_target: Option<Token>,
}

impl ArrayInitRestorationPass {
    /// Creates a new array init restoration pass.
    ///
    /// # Arguments
    ///
    /// * `accessor_token` - Token of the container's GetHandle method
    /// * `field_tokens` - Ordered field tokens from the container's .cctor ldtoken instructions
    /// * `init_array_method` - Optional token of `MyInitializeArray`
    /// * `init_array_target` - Optional token of `RuntimeHelpers.InitializeArray` MemberRef
    #[must_use]
    pub fn new(
        accessor_token: Token,
        field_tokens: Vec<Token>,
        init_array_method: Option<Token>,
        init_array_target: Option<Token>,
    ) -> Self {
        Self {
            accessor_token,
            field_tokens,
            init_array_method,
            init_array_target,
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for ArrayInitRestorationPass {
    fn name(&self) -> &'static str {
        "jiejie-array-init-restore"
    }

    fn description(&self) -> &'static str {
        "Replaces JIEJIE.NET field handle container calls with direct field handle constants"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        _method: &MethodRef,
        ctx: &CompilerContext,
    ) -> analyssa::Result<bool> {
        if self.field_tokens.is_empty() {
            return Ok(false);
        }

        // Build constant map to resolve index arguments
        let constants = ssa.find_constants();

        // Scan for Call ops targeting the accessor method or MyInitializeArray
        let mut replacements: Vec<(usize, usize, SsaOp)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((method_token, call)) = instr.op().method_call() {
                    let (dest, args) = (&call.dest, &call.args);

                    // Case 1: GetHandle accessor replacement
                    if method_token == self.accessor_token {
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
                        let Some(&field_token) = self.field_tokens.get(index) else {
                            continue;
                        };

                        // Replace Call with Const(FieldHandle(...))
                        if let Some(dest) = dest {
                            replacements.push((
                                block_idx,
                                instr_idx,
                                SsaOp::Const {
                                    dest: *dest,
                                    value: ConstValue::FieldHandle(FieldRef::new(field_token)),
                                },
                            ));
                        }
                        continue;
                    }

                    // Case 2: MyInitializeArray replacement
                    if let (Some(init_method), Some(init_target)) =
                        (self.init_array_method, self.init_array_target)
                    {
                        if method_token == init_method && args.len() == 3 {
                            // Replace Call(MyInitializeArray, array, handle, xorKey)
                            // with Call(RuntimeHelpers.InitializeArray, array, handle)
                            if let (Some(&a0), Some(&a1)) = (args.first(), args.get(1)) {
                                let callee = Callee::Direct(MethodRef::new(init_target));
                                replacements.push((
                                    block_idx,
                                    instr_idx,
                                    call.redirected(callee, vec![a0, a1]).into(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        // Apply replacements
        for (block_idx, instr_idx, new_op) in &replacements {
            ssa.replace_instruction_op(*block_idx, *instr_idx, new_op.clone());
        }

        for (_, _, new_op) in &replacements {
            let kind = match new_op {
                SsaOp::Const { .. } => EventKind::ConstantFolded,
                _ => EventKind::ArtifactRemoved,
            };
            ctx.events.record(kind);
        }

        Ok(true)
    }
}
