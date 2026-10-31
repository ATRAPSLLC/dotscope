//! SSA pass that rewrites NR's resource-resolver shim call sites.
//!
//! After [`netreactor.resources`] has emulation-decrypted and re-injected
//! the original `ManifestResource` rows, the protected user code still
//! routes through two NR shims:
//!
//! - **Lazy init** - `Main` and every protector-injected `.cctor` start
//!   with `call <lazy_init>;`. Once the resources are real
//!   `ManifestResource` rows, the resolver type's runtime registration is
//!   pure overhead - there is nothing to resolve. We replace the call
//!   with `Nop` so the resolver type can be deleted by the cleanup
//!   pipeline.
//!
//! - **`GetManifestResourceNames` shim** - user code calls
//!   `<resolver>::eBxqprrF8(Assembly) -> string[]` instead of
//!   `Assembly::GetManifestResourceNames()`. Same arity, same return
//!   type. We rewrite the `Call` to a `CallVirt` against the BCL
//!   MemberRef (resolved at construction time from the assembly's import
//!   table - every NR resources sample already references that
//!   MemberRef inside the resolver type body).
//!
//! After both rewrites land the resolver type is unreferenced from user
//! code and the encrypted blob is unreferenced from the assembly, so the
//! generic cleanup pipeline can delete the type, the injected `.cctor`s,
//! and the manifest-resource row in one sweep.
//!
//! # Pipeline Position
//!
//! Runs in the **Value** phase, like the other NR-specific shim
//! folders. Pure intra-method rewrite, no CFG changes -
//! [`ModificationScope::InstructionsOnly`].
//!
//! [`netreactor.resources`]: crate::deobfuscation::techniques::netreactor::NetReactorResources

use std::collections::HashSet;

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction, SsaOp},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
};

/// Rewrites NR resource-resolver shim calls in user code.
pub struct ResourceShimRewritePass {
    /// `static (Assembly) -> string[]` shim methods on the resolver type.
    /// Each `Call` to one of these gets retargeted to
    /// `bcl_get_manifest_resource_names`.
    shim_method_tokens: HashSet<Token>,
    /// `static void` lazy-init method. Each `Call` to it is replaced with
    /// `Nop` (the call has no args and no destination so the surrounding
    /// IL stays valid).
    lazy_init_token: Token,
    /// MemberRef token for `[mscorlib]System.Reflection.Assembly::
    /// GetManifestResourceNames()`. Resolved by detection from the
    /// assembly's import table.
    bcl_get_manifest_resource_names: Token,
}

impl ResourceShimRewritePass {
    /// Builds the pass from detection findings.
    ///
    /// `shim_method_tokens` is empty when no shims were found - the pass
    /// still runs but only the lazy-init NOP rewrites apply. Same for an
    /// empty `bcl_get_manifest_resource_names` (zero token): shim
    /// rewrites are skipped, lazy-init NOPs still run.
    #[must_use]
    pub fn new(
        shim_method_tokens: impl IntoIterator<Item = Token>,
        lazy_init_token: Token,
        bcl_get_manifest_resource_names: Token,
    ) -> Self {
        Self {
            shim_method_tokens: shim_method_tokens.into_iter().collect(),
            lazy_init_token,
            bcl_get_manifest_resource_names,
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for ResourceShimRewritePass {
    fn name(&self) -> &'static str {
        "netreactor-resource-shim-rewrite"
    }

    fn description(&self) -> &'static str {
        "Rewrites NR resource-resolver shim calls (eBxqprrF8 → \
         GetManifestResourceNames; lazy_init → Nop)"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        ctx: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let method_token = method.0;
        // Skip work for the resolver's own methods - the cleanup pipeline
        // deletes them wholesale, so rewriting here would be wasted.
        if self.shim_method_tokens.contains(&method_token) || self.lazy_init_token == method_token {
            return Ok(false);
        }

        let bcl_target = MethodRef::new(self.bcl_get_manifest_resource_names);
        let mut shim_rewrites = 0usize;
        let mut init_nops = 0usize;

        let block_count = ssa.blocks().len();
        for block_idx in 0..block_count {
            let Some(block) = ssa.block_mut(block_idx) else {
                continue;
            };
            let instr_count = block.instructions().len();
            for instr_idx in 0..instr_count {
                let Some(instr) = block.instruction_mut(instr_idx) else {
                    continue;
                };
                let new_op = match instr.op() {
                    SsaOp::Call {
                        dest, method, args, ..
                    } if self.shim_method_tokens.contains(&method.token())
                        && self.bcl_get_manifest_resource_names.value() != 0 =>
                    {
                        // Same arity (Assembly arg → instance receiver),
                        // same return type (string[]). The shim's stack
                        // effect matches `callvirt
                        // Assembly::GetManifestResourceNames()`.
                        let new = SsaOp::CallVirt {
                            dest: *dest,
                            method: bcl_target,
                            args: args.clone(),
                            effects: None,
                        };
                        shim_rewrites = shim_rewrites.saturating_add(1);
                        Some(new)
                    }
                    SsaOp::Call {
                        dest, method, args, ..
                    } if method.token() == self.lazy_init_token
                        && dest.is_none()
                        && args.is_empty() =>
                    {
                        init_nops = init_nops.saturating_add(1);
                        Some(SsaOp::Nop)
                    }
                    _ => None,
                };
                if let Some(op) = new_op {
                    instr.set_op(op);
                }
            }
        }

        if shim_rewrites > 0 {
            ctx.events
                .record(EventKind::ConstantFolded)
                .at(method_token, 0)
                .message(format!(
                    "NR resources: rewrote {shim_rewrites} GetManifestResourceNames shim call(s)"
                ));
        }
        if init_nops > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .at(method_token, 0)
                .message(format!(
                    "NR resources: nopped {init_nops} lazy-init call(s)"
                ));
        }

        Ok(shim_rewrites > 0 || init_nops > 0)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{CallGraph, MethodRef, SsaFunctionBuilder, SsaType},
        deobfuscation::context::AnalysisContext,
        testkit::{helpers::test_assembly_arc, passes::run_verified},
    };

    fn make_ctx() -> AnalysisContext {
        let ctx = AnalysisContext::new(Arc::new(CallGraph::new()));
        ctx.compiler.set_assembly(test_assembly_arc());
        ctx
    }

    #[test]
    fn rewrites_shim_call_to_callvirt() {
        let shim = Token::new(0x0600009b);
        let bcl = Token::new(0x0a000099);
        let lazy_init = Token::new(0x0600009e);

        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::Object);
                f.block(0, |b| {
                    let _ = b.call(MethodRef::new(shim), &[arg0], SsaType::Object);
                    b.ret();
                });
            })
            .unwrap();

        let pass = ResourceShimRewritePass::new(vec![shim], lazy_init, bcl);
        let ctx = make_ctx();
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(Token::new(0x06000003)),
            &ctx.compiler,
        )
        .unwrap();
        assert!(changed);
        let block = ssa.block(0).unwrap();
        match block.instructions()[0].op() {
            SsaOp::CallVirt { method, args, .. } => {
                assert_eq!(method.token(), bcl);
                assert_eq!(args.len(), 1);
            }
            other => panic!("expected CallVirt, got {other:?}"),
        }
    }

    #[test]
    fn nops_lazy_init_call() {
        let shim = Token::new(0x0600009b);
        let bcl = Token::new(0x0a000099);
        let lazy_init = Token::new(0x0600009e);

        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.call_void(MethodRef::new(lazy_init), &[]);
                    b.ret();
                });
            })
            .unwrap();

        let pass = ResourceShimRewritePass::new(vec![shim], lazy_init, bcl);
        let ctx = make_ctx();
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(Token::new(0x06000003)),
            &ctx.compiler,
        )
        .unwrap();
        assert!(changed);
        // The call is gone: the block is its return
        let block = ssa.block(0).unwrap();
        assert!(
            matches!(block.instructions(), [only] if matches!(only.op(), SsaOp::Return { value: None })),
            "{:?}",
            block.instructions()
        );
    }

    #[test]
    fn skips_resolver_own_methods() {
        let shim = Token::new(0x0600009b);
        let bcl = Token::new(0x0a000099);
        let lazy_init = Token::new(0x0600009e);

        let mut ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    b.call_void(MethodRef::new(lazy_init), &[]);
                    b.ret();
                });
            })
            .unwrap();

        let pass = ResourceShimRewritePass::new(vec![shim], lazy_init, bcl);
        let ctx = make_ctx();
        // Running on the lazy_init method itself should NOT touch its body.
        let changed =
            run_verified(&pass, &mut ssa, &MethodRef::from(lazy_init), &ctx.compiler).unwrap();
        assert!(!changed);
    }

    #[test]
    fn skips_shim_rewrite_when_bcl_token_zero() {
        let shim = Token::new(0x0600009b);
        let lazy_init = Token::new(0x0600009e);
        let bcl_unset = Token::new(0);

        let mut ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::Object);
                f.block(0, |b| {
                    let _ = b.call(MethodRef::new(shim), &[arg0], SsaType::Object);
                    b.ret();
                });
            })
            .unwrap();

        let pass = ResourceShimRewritePass::new(vec![shim], lazy_init, bcl_unset);
        let ctx = make_ctx();
        let changed = run_verified(
            &pass,
            &mut ssa,
            &MethodRef::from(Token::new(0x06000003)),
            &ctx.compiler,
        )
        .unwrap();
        // Shim left intact - fallback is to leave the call alone.
        assert!(!changed);
    }
}
