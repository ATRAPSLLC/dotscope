//! BitMono UnmanagedString reversal SSA pass.
//!
//! Replaces `call <fake_native>` + `newobj string::.ctor(ptr)` patterns with
//! `DecryptedString` constants, which the codegen pipeline emits as `ldstr`
//! instructions.
//!
//! # Pipeline Position
//!
//! This pass runs in the **Simplify** phase, after detection has extracted
//! embedded strings from native method bodies.
//!
//! # Algorithm
//!
//! 1. For each block, scan for `Call` instructions targeting a known fake native
//!    method token
//! 2. Look for a subsequent `NewObj` string constructor that consumes the call result
//! 3. Replace the `NewObj` with `Const(DecryptedString(...))` and NOP the `Call`
//!    unless something else still reads its result
//!
//! # Example
//!
//! ```text
//! // Before:
//! v1 = Call { method: <fake_native_token>, args: [] }
//! v2 = NewObj { ctor: <string_ctor_token>, args: [v1] }
//!
//! // After:
//! Nop  (was Call)
//! v2 = Const(DecryptedString("Hello"))
//! ```

use std::collections::HashMap;

use crate::{
    analysis::{CilTarget, ConstValue, MethodRef, SsaFunction, SsaOp, SsaVarId},
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    metadata::token::Token,
};

/// SSA pass that replaces UnmanagedString call+newobj patterns with string constants.
///
/// For each method, scans for the pattern:
/// ```text
/// v1 = Call { method: <fake_native_token>, args: [] }
/// v2 = NewObj { ctor: <string_ctor_token>, args: [v1] }
/// ```
/// and replaces with:
/// ```text
/// Nop  (was Call)
/// v2 = Const { value: DecryptedString("...") }  (was NewObj)
/// ```
///
/// The `Call` stays when another instruction still reads the pointer it
/// returned.
///
/// The codegen pipeline handles `DecryptedString` constants by pre-interning them
/// to the #US heap and emitting proper `ldstr` instructions.
pub struct UnmanagedStringReversalPass {
    /// Maps fake native method tokens to their decrypted string values.
    pub(crate) native_string_map: HashMap<Token, String>,
}

impl SsaPass<CilTarget, CompilerContext> for UnmanagedStringReversalPass {
    fn name(&self) -> &'static str {
        "BitMonoUnmanagedString"
    }

    fn description(&self) -> &'static str {
        "Replaces calls to fake native string methods with ldstr constants"
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
        let mut native_calls: Vec<(usize, usize)> = Vec::new();

        for block_idx in 0..ssa.blocks().len() {
            let sites = find_unmanaged_string_sites(ssa, block_idx, &self.native_string_map);
            if sites.is_empty() {
                continue;
            }

            let block = match ssa.block_mut(block_idx) {
                Some(b) => b,
                None => continue,
            };

            // Replace each NewObj with its DecryptedString constant
            for site in &sites {
                if let Some(instr) = block.instruction_mut(site.newobj_idx) {
                    instr.set_op(SsaOp::Const {
                        dest: site.newobj_dest,
                        value: ConstValue::DecryptedString(site.decrypted.clone().into()),
                    });
                }
                native_calls.push((block_idx, site.call_idx));
            }

            ctx.events
                .record(EventKind::StringDecrypted)
                .message(format!(
                    "BitMonoUnmanagedString: reversed {} call+newobj sites in block {}",
                    sites.len(),
                    block_idx,
                ));
        }

        // The native call goes once the constructor no longer reads its
        // result. Anything else that reads the pointer keeps it: the search
        // above deliberately looks past other readers to find the constructor.
        ssa.remove_unread_instructions(native_calls.iter().copied());

        Ok(!native_calls.is_empty())
    }
}

/// A detected call+newobj site for UnmanagedString reversal.
struct UnmanagedStringSite {
    /// Index of the `Call` instruction in the block.
    call_idx: usize,
    /// Index of the `NewObj` instruction in the block.
    newobj_idx: usize,
    /// SSA variable defined by the NewObj (destination of the string value).
    newobj_dest: SsaVarId,
    /// The decrypted string value.
    decrypted: String,
}

/// Finds `call <native>` + `newobj string::.ctor(ptr)` patterns in a block.
///
/// Scans a single SSA block for pairs where a `Call` targets a known fake native
/// method token and is immediately consumed by a `NewObj` string constructor.
/// Returns one [`UnmanagedStringSite`] per matched pair.
///
/// # Arguments
///
/// * `ssa` - The SSA function graph containing the block.
/// * `block_idx` - Index of the block to scan.
/// * `native_map` - Map from fake native method token to its decrypted string.
///
/// # Returns
///
/// A [`Vec`] of detected sites, in forward order within the block. Empty if
/// no matching patterns exist in the block.
fn find_unmanaged_string_sites(
    ssa: &SsaFunction,
    block_idx: usize,
    native_map: &HashMap<Token, String>,
) -> Vec<UnmanagedStringSite> {
    let mut sites = Vec::new();

    let Some(block) = ssa.block(block_idx) else {
        return sites;
    };

    let instructions = block.instructions();

    for (i, instr) in instructions.iter().enumerate() {
        // Look for Call to a fake native method
        let (call_dest, call_token) = match instr.op() {
            SsaOp::Call { dest, method, .. } => {
                let Some(d) = dest else { continue };
                (*d, method.token())
            }
            _ => continue,
        };

        // Check if this call targets a known fake native method
        let Some(decrypted) = native_map.get(&call_token) else {
            continue;
        };

        // Look for NewObj in subsequent instructions that uses the call result.
        // Only stop on a NewObj consuming call_dest - other uses (e.g., debug
        // traces) should not prevent finding the actual string constructor.
        // Limit search distance to avoid O(n²) behaviour across many call sites.
        const MAX_SEARCH_DISTANCE: usize = 20;
        let start = i.saturating_add(1);
        let search_end = start
            .saturating_add(MAX_SEARCH_DISTANCE)
            .min(instructions.len());
        let take = search_end.saturating_sub(start);
        for (j, next) in instructions.iter().enumerate().skip(start).take(take) {
            if let SsaOp::NewObj { dest, args, .. } = next.op() {
                if args.len() == 1 && args.first() == Some(&call_dest) {
                    sites.push(UnmanagedStringSite {
                        call_idx: i,
                        newobj_idx: j,
                        newobj_dest: *dest,
                        decrypted: decrypted.clone(),
                    });
                    break;
                }
            }
        }
    }

    sites
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        analysis::{CallGraph, SsaFunctionBuilder, SsaType},
        testkit::passes::run_verified,
    };

    /// The fake native call goes once its string is a constant, and stays
    /// while another instruction still reads the pointer it returned.
    #[test]
    fn native_call_is_removed_only_when_unread() {
        let native = Token::new(0x0600_0002);
        let ctor = MethodRef::new(Token::new(0x0A00_0001));
        let trace = MethodRef::new(Token::new(0x0A00_0002));
        let native_call_kept = |traced: bool| {
            let mut ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let pointer = b.call(MethodRef::new(native), &[], SsaType::NativeInt);
                        let _ = b.newobj(ctor, &[pointer]);
                        if traced {
                            b.call_void(trace, &[pointer]);
                        }
                        b.ret();
                    });
                })
                .unwrap();
            let pass = UnmanagedStringReversalPass {
                native_string_map: HashMap::from([(native, "Hello".to_string())]),
            };
            let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
            let changed = run_verified(
                &pass,
                &mut ssa,
                &MethodRef::new(Token::new(0x0600_0001)),
                &ctx,
            )
            .unwrap();
            assert!(changed, "the constructor becomes a constant");
            let instructions = ssa.block(0).unwrap().instructions();
            assert!(instructions.iter().any(|instruction| matches!(
                instruction.op(),
                SsaOp::Const {
                    value: ConstValue::DecryptedString(_),
                    ..
                }
            )));
            instructions.iter().any(|instruction| {
                matches!(instruction.op(), SsaOp::Call { method, .. } if *method == MethodRef::new(native))
            })
        };
        assert!(!native_call_kept(false), "an unread native call is removed");
        assert!(native_call_kept(true), "a native call still read is kept");
    }
}
