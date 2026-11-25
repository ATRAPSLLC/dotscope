//! SSA pass that folds NR's anti-tamper metadata-token accessors.
//!
//! NR's anti-tamper stage rewrites every user `ldtoken X` instruction into
//! `ldc.i4 <metadata_token>; call resolver.GetTypeHandle(int32)`. The
//! resolver caches a `ModuleHandle` and dispatches to
//! `ModuleHandle::GetRuntime{Type|Field|Method}HandleFromMetadataToken`.
//!
//! This pass reverses the rewrite: when the int argument is constant, it
//! replaces the `Call` with a single `LoadToken` carrying the recovered
//! token. After this pass the resolver type itself becomes orphan and the
//! generic cleanup pipeline removes it.
//!
//! # Pipeline Position
//!
//! Runs in the **Value** phase, alongside other constant-resolution passes
//! (string decryption, JIEJIE.NET typeof restoration). The pass is purely
//! intra-method and `InstructionsOnly` - it does not change CFG structure.

use std::collections::HashSet;

use crate::{
    analysis::{
        CilTarget, ConstValue, MethodRef, SsaFunction, SsaOp, SsaOpCilExt, SsaVarId, TypeRef,
    },
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
};

/// Folds `accessor(<const>)` calls into `ldtoken X` for the NR
/// anti-tamper metadata-token resolver.
pub struct TokenResolverPass {
    accessor_tokens: HashSet<Token>,
}

impl TokenResolverPass {
    /// Builds the pass from the resolver's accessor method tokens.
    ///
    /// All accessor flavours (`RuntimeTypeHandle` / `RuntimeFieldHandle` /
    /// `RuntimeMethodHandle`) are handled identically: the int argument is
    /// the raw metadata token, and `LoadToken` accepts any token kind.
    #[must_use]
    pub fn new(accessor_tokens: impl IntoIterator<Item = Token>) -> Self {
        Self {
            accessor_tokens: accessor_tokens.into_iter().collect(),
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for TokenResolverPass {
    fn name(&self) -> &'static str {
        "netreactor-token-resolver"
    }

    fn description(&self) -> &'static str {
        "Folds NR anti-tamper metadata-token accessor calls back to ldtoken"
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
        if self.accessor_tokens.is_empty() {
            return Ok(false);
        }

        let constants = ssa.find_constants();

        let mut replacements: Vec<(usize, usize, Token, SsaVarId)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((method_token, call)) = instr.op().method_call() {
                    let (dest, args) = (&call.dest, &call.args);
                    if !self.accessor_tokens.contains(&method_token) {
                        continue;
                    }
                    if args.len() != 1 {
                        continue;
                    }
                    let Some(dest_var) = dest else {
                        continue;
                    };
                    let Some(arg0) = args.first() else {
                        continue;
                    };
                    let Some(const_val) = constants.get(arg0) else {
                        continue;
                    };
                    let raw_token = match const_val {
                        ConstValue::I32(v) => *v as u32,
                        ConstValue::U32(v) => *v,
                        _ => continue,
                    };
                    if raw_token == 0 {
                        continue;
                    }
                    replacements.push((block_idx, instr_idx, Token::new(raw_token), *dest_var));
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        for (block_idx, instr_idx, token, dest) in &replacements {
            ssa.replace_instruction_op(
                *block_idx,
                *instr_idx,
                SsaOp::LoadToken {
                    dest: *dest,
                    token: TypeRef::new(*token),
                },
            );
            ctx.events.record(EventKind::ValueResolved);
        }

        Ok(true)
    }
}
