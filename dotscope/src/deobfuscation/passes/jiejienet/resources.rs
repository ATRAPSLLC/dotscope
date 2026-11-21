//! JIEJIE.NET resource interception reversal pass.
//!
//! Replaces calls to JIEJIE.NET's `SMF_*` resource interception methods with
//! direct calls to the original `Assembly.GetManifestResourceStream` and
//! `Assembly.GetManifestResourceNames` BCL methods.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Simplify** phase, BEFORE cleanup removes the helper
//! class. This ensures the resource access calls are restored to their original
//! BCL targets before the helper methods are deleted.
//!
//! # Algorithm
//!
//! 1. The technique's detection phase builds a redirect map by analyzing each
//!    interception method's body for calls to the original BCL method
//! 2. The pre-built mapping (interception_token -> original_bcl_token) is passed
//!    to the pass constructor
//! 3. For each method in the assembly, scan for `Call` SSA ops referencing
//!    interception tokens and replace with the original BCL call
//!
//! # Example
//!
//! ```text
//! // Before:
//! v3 = Call(JIEJIEHelper::SMF_GetManifestResourceStream, [v1, v2])
//!
//! // After:
//! v3 = callvirt(Assembly::GetManifestResourceStream, [v1, v2])
//! ```

use std::collections::HashMap;

use log::info;

use crate::{
    analysis::{Callee, CilTarget, MethodRef, SsaFunction, SsaOp, SsaOpCilExt},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
};

/// Target information for a resource interception method.
#[derive(Debug, Clone)]
pub struct ResourceTarget {
    /// Token of the original BCL method (e.g., Assembly.GetManifestResourceStream).
    pub target_token: Token,
    /// Whether the original call is virtual.
    pub is_virtual: bool,
}

/// SSA pass that replaces JIEJIE.NET resource interception calls with direct
/// BCL calls to `Assembly.GetManifestResourceStream` etc.
pub struct ResourceRestorationPass {
    /// Mapping from interception method token to original BCL target.
    redirects: HashMap<Token, ResourceTarget>,
}

impl ResourceRestorationPass {
    /// Creates a new resource restoration pass from a pre-built redirect map.
    ///
    /// The redirect map should be built during detection by calling
    /// [`find_original_bcl_call`](crate::deobfuscation::techniques::jiejienet::resources)
    /// for each interception method token.
    ///
    /// # Arguments
    ///
    /// * `redirects` - Pre-built mapping from interception method token to BCL target
    #[must_use]
    pub fn new(redirects: HashMap<Token, ResourceTarget>) -> Self {
        info!(
            "JIEJIE.NET resources: received {} interception→BCL redirects",
            redirects.len()
        );

        Self { redirects }
    }
}

impl SsaPass<CilTarget, CompilerContext> for ResourceRestorationPass {
    fn name(&self) -> &'static str {
        "jiejie-resource-restoration"
    }

    fn description(&self) -> &'static str {
        "Replaces JIEJIE.NET resource interception calls with original BCL calls"
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
        if self.redirects.is_empty() {
            return Ok(false);
        }

        let mut replacements: Vec<(usize, usize, SsaOp)> = Vec::new();

        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let Some((method_token, call)) = instr.op().method_call() else {
                    continue;
                };

                if let Some(target) = self.redirects.get(&method_token) {
                    let method = MethodRef::new(target.target_token);
                    let callee = if target.is_virtual {
                        Callee::Virtual(method)
                    } else {
                        Callee::Direct(method)
                    };
                    let new_op = call.redirected(callee, call.args.clone()).into();
                    replacements.push((block_idx, instr_idx, new_op));
                }
            }
        }

        if replacements.is_empty() {
            return Ok(false);
        }

        for (block_idx, instr_idx, new_op) in replacements.iter() {
            ssa.replace_instruction_op(*block_idx, *instr_idx, new_op.clone());
        }

        for _ in &replacements {
            ctx.events.record(EventKind::ArtifactRemoved);
        }

        Ok(true)
    }
}
