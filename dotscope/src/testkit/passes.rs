//! Running a pass in a test the way the scheduler runs it, verified.
//!
//! A test that calls [`SsaPass::run_on_method`] itself skips what the scheduler does around
//! the pass: the edit-failure check, and the SSA repair or rebuild the pass's modification
//! scope asks for. And it verifies nothing, so a pass that leaves invalid SSA passes its test.
//! [`run_verified`] runs the scheduler's own step and verifies the result as a pipeline under
//! `verify_hard` does. It verifies what it is handed first, so a test whose own SSA is invalid
//! is told apart from a pass that breaks valid SSA.

use analyssa::{scheduling::PassScheduler, Verify};

use crate::{
    analysis::{CilTarget, MethodRef, SsaFunction, SsaVerifier, VerifyLevel},
    compiler::{CompilerContext, SsaPass},
    Error, Result,
};

/// Runs `pass` on `ssa` as the scheduler runs it on `method`, and verifies the result at the
/// standard level whether or not the pass changed it.
///
/// # Errors
///
/// When `ssa` is invalid before the pass runs, or when the pass fails or panics, its change needs a rebuild that fails, or it leaves SSA the
/// verifier rejects (with the verifier's errors); `ssa` is then as it was before the pass.
pub fn run_verified(
    pass: &dyn SsaPass<CilTarget, CompilerContext>,
    ssa: &mut SsaFunction,
    method: &MethodRef,
    ctx: &CompilerContext,
) -> Result<bool> {
    let findings = SsaVerifier::new(ssa).verify(VerifyLevel::Standard);
    if !findings.is_empty() {
        let findings: Vec<String> = findings.iter().map(ToString::to_string).collect();
        return Err(Error::SsaError(format!(
            "the SSA handed to '{}' is invalid before it runs: {}",
            pass.name(),
            findings.join("; ")
        )));
    }
    PassScheduler::run_once(
        pass,
        ssa,
        method,
        ctx,
        Verify::Always(VerifyLevel::Standard),
    )
    .map_err(|error| Error::SsaError(error.0))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{CallGraph, SsaFunctionBuilder, SsaOp, SsaType, SsaVarId},
        compiler::ModificationScope,
        metadata::token::Token,
    };

    /// Returns a variable the function does not have: SSA no repair makes valid. It claims to
    /// change uses only, so the scheduler repairs uses rather than rebuilding (which validates
    /// on its own), and only the verifier stands between it and its caller.
    struct ReturnsNothingDefined;

    impl SsaPass<CilTarget, CompilerContext> for ReturnsNothingDefined {
        fn name(&self) -> &'static str {
            "returns-nothing-defined"
        }

        fn modification_scope(&self) -> ModificationScope {
            ModificationScope::UsesOnly
        }

        fn run_on_method(
            &self,
            ssa: &mut SsaFunction,
            _method: &MethodRef,
            _host: &CompilerContext,
        ) -> analyssa::Result<bool> {
            if let Some(block) = ssa.block_mut(0) {
                if let Some(last) = block.instructions_mut().last_mut() {
                    last.set_op(SsaOp::Return {
                        value: Some(SsaVarId::from_index(999)),
                    });
                }
            }
            Ok(true)
        }
    }

    fn returns_its_argument() -> SsaFunction {
        SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let a = f.arg(0, SsaType::I32);
                f.block(0, |b| b.ret_val(a));
            })
            .unwrap()
    }

    /// A pass that leaves invalid SSA fails its test, and the function is as it was.
    #[test]
    fn a_pass_leaving_invalid_ssa_is_refused() {
        let mut ssa = returns_its_argument();
        let before = format!("{ssa}");
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let method = MethodRef::new(Token::new(0x0600_0001));
        let error = run_verified(&ReturnsNothingDefined, &mut ssa, &method, &ctx).unwrap_err();
        assert!(error.to_string().contains("invalid SSA"), "{error}");
        assert_eq!(format!("{ssa}"), before);
    }

    /// A test whose own SSA is invalid is told so, before any pass is blamed.
    #[test]
    fn invalid_input_is_reported_as_the_tests() {
        let mut ssa = returns_its_argument();
        ReturnsNothingDefined
            .run_on_method(
                &mut ssa,
                &MethodRef::new(Token::new(0x0600_0001)),
                &CompilerContext::new(Arc::new(CallGraph::new())),
            )
            .unwrap();
        let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
        let error = run_verified(
            &ReturnsNothingDefined,
            &mut ssa,
            &MethodRef::new(Token::new(0x0600_0001)),
            &ctx,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("invalid before it runs"),
            "{error}"
        );
    }
}
