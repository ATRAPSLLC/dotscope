//! Constant propagation and folding pass.
//!
//! This pass uses the Sparse Conditional Constant Propagation (SCCP) analysis
//! from the dataflow framework, then applies additional optimizations including:
//!
//! - **Constant folding**: Evaluate operations with constant operands at compile time
//! - **Identity simplification**: Recognize `x + 0 = x`, `x * 1 = x`, etc.
//! - **Absorbing elements**: Recognize `x * 0 = 0`, `x & 0 = 0`, etc.
//! - **Branch simplification**: Convert conditional branches to jumps when condition is known
//! - **Switch simplification**: Convert switches to jumps when value is known
//! - **Conversion folding**: Fold type conversions with constant operands
//! - **Overflow-checked operations**: Fold when result doesn't overflow
//!
//! # Example
//!
//! Before:
//! ```text
//! v0 = 5
//! v1 = 3
//! v2 = add v0, v1
//! v3 = mul v2, 2
//! v4 = add v3, 0   // identity
//! v5 = mul v4, 0   // absorbing
//! ```
//!
//! After:
//! ```text
//! v0 = 5
//! v1 = 3
//! v2 = 8
//! v3 = 16
//! v4 = 16          // identity simplified
//! v5 = 0           // absorbing element
//! ```

use std::collections::{BTreeMap, BTreeSet};

use analyssa::{
    analysis::{Budget, Machine, Rounds},
    events::{Event, EventListener},
    passes::utils::resolve_chains,
    BitSet,
};

use crate::{
    analysis::{
        simplify_op, CallResolver, Callee, CilTarget, ConstValue, ConstValueCilExt,
        ConstantPropagation, LoopAnalyzer, MethodPurity, MethodRef, SccpResult, SimplifyResult,
        SsaCfg, SsaEvaluator, SsaFunction, SsaOp, SsaType, SsaVarId,
    },
    compiler::{
        pass::{ModificationScope, SsaPass},
        CompilerContext, EventKind, EventLog,
    },
    metadata::{tables::TableId, token::Token},
    CilObject,
};

/// Result of checking an algebraic identity.
///
/// Either the operation simplifies to a constant value (absorbing elements)
/// or to a copy of another variable (identity operations).
#[derive(Debug, Clone)]
enum AlgebraicResult {
    /// Operation result is a constant value (e.g., x * 0 = 0)
    Constant { dest: SsaVarId, value: ConstValue },
    /// Operation result is a copy of another variable (e.g., x + 0 = x)
    Copy { dest: SsaVarId, src: SsaVarId },
}

/// Information about a conversion operation for redundancy analysis.
#[derive(Debug, Clone)]
struct ConvInfo {
    /// The source operand of the conversion.
    operand: SsaVarId,
    /// The target type of the conversion.
    target: SsaType,
    /// Whether this is an overflow-checked conversion.
    overflow_check: bool,
    /// Whether the source is treated as unsigned.
    unsigned: bool,
    /// Block index where this conversion is defined.
    block_idx: usize,
    /// Instruction index within the block.
    instr_idx: usize,
}

/// Transformation to apply for redundant conversion elimination.
#[derive(Debug)]
enum ConvTransform {
    /// Replace the conversion's operand with a different source.
    /// Used for duplicate conversions and widening chains.
    ReplaceOperand {
        block_idx: usize,
        instr_idx: usize,
        dest: SsaVarId,
        new_operand: SsaVarId,
        target: SsaType,
        unsigned: bool,
        reason: &'static str,
    },
    /// Replace the conversion with a simple copy.
    /// Used for unnecessary conversions where types match.
    ReplaceWithCopy {
        block_idx: usize,
        instr_idx: usize,
        dest: SsaVarId,
        src: SsaVarId,
        reason: &'static str,
    },
}

/// Recognized string operation that can be folded when all arguments are constants.
#[derive(Debug, Clone, Copy)]
enum StringFoldOp {
    /// `String.Concat(String, String)` — static, 2 args.
    Concat2,
    /// `String.Concat(String, String, String)` — static, 3 args.
    Concat3,
    /// `String.Concat(String, String, String, String)` — static, 4 args.
    Concat4,
    /// `String.Substring(Int32)` — instance, args = [this, start].
    SubstringFrom,
    /// `String.Substring(Int32, Int32)` — instance, args = [this, start, len].
    SubstringRange,
    /// `String.Replace(String, String)` — instance, args = [this, old, new].
    Replace,
    /// `String.ToLower()` — instance, args = \[this\].
    ToLower,
    /// `String.ToUpper()` — instance, args = \[this\].
    ToUpper,
}

/// Constant propagation and folding pass.
///
/// This pass combines the SCCP analysis with additional optimizations
/// for identity operations, absorbing elements, and type conversions, folded
/// as many rounds as the host's
/// [`Budget::FoldRounds`] allows.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConstantPropagationPass;

impl ConstantPropagationPass {
    /// Runs the constant propagation pass on an SSA function.
    ///
    /// This uses the existing SCCP analysis and applies additional optimizations.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze and transform.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    /// * `machine` - The machine the method computes on.
    /// * `rounds` - The folding rounds the host's budget allows, which this
    ///   takes until a round folds nothing new.
    ///
    /// # Returns
    ///
    /// A map from SSA variables to their constant values.
    fn run_constant_propagation(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
        machine: Machine,
        rounds: &mut Rounds,
        assembly: &CilObject,
        resolver: &CallResolver,
    ) -> BTreeMap<SsaVarId, ConstValue> {
        let block_count = ssa.block_count();
        if block_count == 0 {
            return BTreeMap::new();
        }

        // Recompute use tracking before SCCP analysis.
        // Use information may be stale after SSA transformations (e.g., CFF reconstruction),
        // which can cause SCCP to miss re-evaluating instructions when phi values change.
        ssa.recompute_uses();

        // Build CFG from SSA and run SCCP analysis using the dataflow framework.
        //
        // SCCP is rooted at the entry and walks forward, so it needs the
        // exception-aware view: over terminator edges alone a handler block is
        // unreachable, and every value defined in one would be left Top and
        // folded as if it were a constant nobody wrote.
        let cfg = SsaCfg::from_ssa(ssa);
        let mut sccp = ConstantPropagation::new(machine);
        let mut sccp_result = sccp.analyze(ssa, &cfg);

        // Collect constants from SCCP result
        let mut constants: BTreeMap<SsaVarId, ConstValue> = sccp_result
            .constants()
            .map(|(var, c)| (var, c.clone()))
            .collect();

        // Resolve calls to pure methods with all-constant arguments.
        // This enables constant propagation through converted x86 stubs
        // (ConfuserEx CFF state computation calls). If calls are folded,
        // re-run SCCP so the new constants propagate through dependent
        // operations (e.g., rem.un → switch in handler CFF dispatchers).
        let pre_fold_count = constants.len();
        Self::fold_pure_calls(
            ssa,
            &mut constants,
            method_token,
            changes,
            assembly,
            resolver,
            machine,
        );
        if constants.len() > pre_fold_count {
            ssa.recompute_uses();
            let cfg = SsaCfg::from_ssa(ssa);
            let mut sccp2 = ConstantPropagation::new(machine);
            let sccp_result2 = sccp2.analyze(ssa, &cfg);
            for (var, c) in sccp_result2.constants() {
                constants.entry(var).or_insert_with(|| c.clone());
            }
            // Update the sccp_result for downstream use
            sccp_result = sccp_result2;
        }

        // Apply additional optimizations iteratively
        while rounds.next_round() {
            let prev_count = constants.len();

            // Run identity and absorbing element optimizations
            Self::optimize_algebraic_identities(ssa, &mut constants, method_token, changes);

            // Run involutory operation simplification (--x=x, ~~x=x)
            Self::simplify_involutory_ops(ssa, method_token, changes);

            // Run conversion folding
            Self::fold_conversions(ssa, &mut constants, method_token, changes, machine);

            // Eliminate redundant conversions
            Self::eliminate_redundant_conversions(ssa, method_token, changes);

            // Run overflow-checked operation folding
            Self::fold_overflow_checked_ops(ssa, &mut constants, method_token, changes, machine);

            // Run string operation folding (Concat, Substring, Replace, etc.)
            Self::fold_string_operations(ssa, &mut constants, method_token, changes, assembly);

            // If no new constants discovered, we're done
            if constants.len() == prev_count {
                rounds.settle();
            }
        }

        // Apply all constant folding transformations
        Self::apply_constant_folding(ssa, &constants, &sccp_result, method_token, changes);

        // Apply control flow simplifications
        Self::simplify_control_flow(
            ssa,
            &constants,
            &sccp_result,
            method_token,
            changes,
            machine,
        );

        constants
    }

    /// Optimizes algebraic identity operations and absorbing elements.
    ///
    /// Identity operations: `x + 0 = x`, `x * 1 = x`, `x - 0 = x`, etc.
    /// Absorbing elements: `x * 0 = 0`, `x & 0 = 0`, `x | -1 = -1`, etc.
    ///
    /// This handles both cases:
    /// - When both operands are constants → replace with constant
    /// - When one operand is identity element → replace with copy of the other operand
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn optimize_algebraic_identities(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        let mut transformations: Vec<(usize, usize, AlgebraicResult)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let op = instr.op();
                // The *operand* type decides whether a self-cancelling identity
                // holds (`x - x` is NaN for a NaN float) and at what width its
                // constant should be materialised. A comparison's destination is
                // a boolean, so the destination type would answer neither.
                let operand_type = op
                    .uses()
                    .first()
                    .and_then(|operand| ssa.variable(*operand))
                    .map(|var| var.var_type().clone());
                if let Some(result) =
                    Self::check_algebraic_identity(op, constants, operand_type.as_ref())
                {
                    transformations.push((block_idx, instr_idx, result));
                }
            }
        }

        // Apply the transformations
        for (block_idx, instr_idx, result) in transformations {
            if let Some(block) = ssa.block_mut(block_idx) {
                let Some(instr) = block.instructions_mut().get_mut(instr_idx) else {
                    continue;
                };
                let old_op_str = format!("{}", instr.op());

                match result {
                    AlgebraicResult::Constant { dest, value } => {
                        constants.insert(dest, value.clone());
                        instr.set_op(SsaOp::Const {
                            dest,
                            value: value.clone(),
                        });
                        changes
                            .record(EventKind::ConstantFolded)
                            .at(method_token, instr_idx)
                            .message(format!("{old_op_str} → {value} (algebraic)"));
                    }
                    AlgebraicResult::Copy { dest, src } => {
                        // If src is a known constant, propagate it
                        if let Some(value) = constants.get(&src).cloned() {
                            constants.insert(dest, value.clone());
                            instr.set_op(SsaOp::Const {
                                dest,
                                value: value.clone(),
                            });
                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → {value} (identity)"));
                        } else {
                            // Replace with copy - copy propagation will handle this
                            instr.set_op(SsaOp::Copy { dest, src });
                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → copy {src} (identity)"));
                        }
                    }
                }
            }
        }
    }

    /// Checks if an operation can be simplified via algebraic identities.
    ///
    /// Uses the shared `simplify_op` function for common patterns.
    fn check_algebraic_identity(
        op: &SsaOp,
        constants: &BTreeMap<SsaVarId, ConstValue>,
        operand_type: Option<&SsaType>,
    ) -> Option<AlgebraicResult> {
        let dest = op.dest()?;
        match simplify_op(op, constants, operand_type) {
            SimplifyResult::Constant(value) => Some(AlgebraicResult::Constant { dest, value }),
            SimplifyResult::Copy(src) => Some(AlgebraicResult::Copy { dest, src }),
            SimplifyResult::None => None,
        }
    }

    /// Folds type conversion operations with constant operands.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::cast_sign_loss)]
    #[allow(clippy::cast_lossless)]
    #[allow(clippy::cast_possible_wrap)]
    fn fold_conversions(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        machine: Machine,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::IntConv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                    ..
                } = instr.op()
                {
                    if let Some(operand_val) = constants.get(operand) {
                        let ptr_bytes = machine.ptr_size.bytes() as u32;
                        let result = if *overflow_check {
                            operand_val.convert_to_checked(target, *unsigned, ptr_bytes)
                        } else {
                            operand_val.convert_to(target, *unsigned, ptr_bytes)
                        };
                        if let Some(result) = result {
                            new_constants.push((*dest, result, block_idx, instr_idx));
                        }
                    }
                }
            }
        }

        // Apply the transformations
        for (dest, value, block_idx, instr_idx) in new_constants {
            constants.insert(dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    let old_op_str = format!("{}", instr.op());

                    instr.set_op(SsaOp::Const {
                        dest,
                        value: value.clone(),
                    });

                    changes
                        .record(EventKind::ConstantFolded)
                        .at(method_token, instr_idx)
                        .message(format!("{old_op_str} → {value} (conv)"));
                }
            }
        }
    }

    /// Eliminates redundant type conversions.
    ///
    /// This handles three patterns of redundant conversions:
    ///
    /// 1. **Duplicate conversions**: `conv.i4(conv.i4(x))` → `conv.i4(x)`
    ///    When the same conversion is applied twice, the outer one is redundant.
    ///
    /// 2. **Unnecessary conversions**: `conv.i4(x)` where x is already i32 → `x`
    ///    When converting to a type the value already has.
    ///
    /// 3. **Widening chain simplification**: `conv.i8(conv.i4(x))` → `conv.i8(x)`
    ///    For unsigned widening conversions, the intermediate conversion can be skipped.
    ///    Only applied when the intermediate conversion is lossless and the unsigned flag
    ///    is consistent.
    ///
    /// Note: Narrowing conversions and lossy float conversions (`conv.r8(conv.r4(x))`)
    /// are NOT optimized as they may change semantics.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze and transform.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    fn eliminate_redundant_conversions(
        ssa: &mut SsaFunction,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        // Build a map of variable definitions: var_id -> (block_idx, instr_idx, SsaOp)
        // We need the full op to analyze Conv chains
        let mut definitions: BTreeMap<SsaVarId, ConvInfo> = BTreeMap::new();

        // First pass: collect all Conv definitions and variable types
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::IntConv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                    ..
                } = instr.op()
                {
                    definitions.insert(
                        *dest,
                        ConvInfo {
                            operand: *operand,
                            target: target.clone(),
                            overflow_check: *overflow_check,
                            unsigned: *unsigned,
                            block_idx,
                            instr_idx,
                        },
                    );
                }
            }
        }

        // Second pass: find redundant conversions
        let mut transformations: Vec<ConvTransform> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let SsaOp::IntConv {
                    dest,
                    operand,
                    target,
                    overflow_check,
                    unsigned,
                    ..
                } = instr.op()
                {
                    // Skip overflow-checked conversions - these have different semantics
                    if *overflow_check {
                        continue;
                    }

                    // Check if operand was also produced by a conversion
                    if let Some(inner_conv) = definitions.get(operand) {
                        // Skip if inner has overflow check - may throw
                        if inner_conv.overflow_check {
                            continue;
                        }

                        // Pattern 1: Duplicate conversion - conv.T(conv.T(x)) → conv.T(x)
                        if inner_conv.target == *target && inner_conv.unsigned == *unsigned {
                            transformations.push(ConvTransform::ReplaceOperand {
                                block_idx,
                                instr_idx,
                                dest: *dest,
                                new_operand: inner_conv.operand,
                                target: target.clone(),
                                unsigned: *unsigned,
                                reason: "duplicate conversion",
                            });
                            continue;
                        }

                        // Pattern 3: Widening chain - conv.T2(conv.T1(x)) → conv.T2(x)
                        // Only when BOTH conversions are widening and semantics are preserved.
                        // If the inner conversion narrows (truncates), we must keep it.
                        //
                        // Example that must NOT be optimized:
                        //   conv.i4(conv.u1(x)) where x is I32
                        //   conv.u1 truncates to 8 bits, conv.i4 widens back
                        //   Skipping conv.u1 would lose the truncation!
                        //
                        // We check the SOURCE type of the inner conversion to determine
                        // if the inner conversion is narrowing.
                        if let Some(source_var) = ssa.variable(inner_conv.operand) {
                            let source_type = source_var.var_type();
                            if Self::is_safe_widening_chain(
                                source_type,
                                &inner_conv.target,
                                target,
                                inner_conv.unsigned,
                            ) {
                                transformations.push(ConvTransform::ReplaceOperand {
                                    block_idx,
                                    instr_idx,
                                    dest: *dest,
                                    new_operand: inner_conv.operand,
                                    target: target.clone(),
                                    unsigned: *unsigned,
                                    reason: "widening chain",
                                });
                                continue;
                            }
                        }
                    }

                    // Pattern 2: Unnecessary conversion - check if operand already has target type
                    if let Some(var) = ssa.variable(*operand) {
                        if Self::types_match(var.var_type(), target) {
                            transformations.push(ConvTransform::ReplaceWithCopy {
                                block_idx,
                                instr_idx,
                                dest: *dest,
                                src: *operand,
                                reason: "unnecessary conversion",
                            });
                        }
                    }
                }
            }
        }

        // Apply transformations
        for transform in transformations {
            match transform {
                ConvTransform::ReplaceOperand {
                    block_idx,
                    instr_idx,
                    dest,
                    new_operand,
                    target,
                    unsigned,
                    reason,
                } => {
                    if let Some(block) = ssa.block_mut(block_idx) {
                        if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                            let old_op_str = format!("{}", instr.op());

                            instr.set_op(SsaOp::conversion_between(
                                dest,
                                new_operand,
                                target.clone(),
                                None,
                                unsigned,
                                false,
                            ));

                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!(
                                    "{old_op_str} → conv.{target} {new_operand} ({reason})"
                                ));
                        }
                    }
                }
                ConvTransform::ReplaceWithCopy {
                    block_idx,
                    instr_idx,
                    dest,
                    src,
                    reason,
                } => {
                    if let Some(block) = ssa.block_mut(block_idx) {
                        if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                            let old_op_str = format!("{}", instr.op());

                            instr.set_op(SsaOp::Copy { dest, src });

                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → copy {src} ({reason})"));
                        }
                    }
                }
            }
        }
    }

    /// Checks if two types match for the purpose of conversion elimination.
    ///
    /// This is conservative - types must match exactly or be equivalent on the stack.
    fn types_match(var_type: &SsaType, target: &SsaType) -> bool {
        if var_type == target {
            return true;
        }

        // Check stack type equivalence - CIL promotes small integers to I32
        // So if converting to I32 and var is already I8/I16/U8/U16, it's unnecessary
        matches!(
            (var_type, target),
            // Small integers (I8, U8, I16, U16, Bool, Char) are already I32 on the stack
            // U32 is treated as I32 on stack (bidirectional)
            // I64 and U64 are interchangeable for bit patterns
            // Native int types are interchangeable
            (
                SsaType::I8
                    | SsaType::U8
                    | SsaType::I16
                    | SsaType::U16
                    | SsaType::Bool
                    | SsaType::Char
                    | SsaType::U32,
                SsaType::I32
            ) | (SsaType::I32, SsaType::U32)
                | (SsaType::U64, SsaType::I64)
                | (SsaType::I64, SsaType::U64)
                | (SsaType::NativeInt, SsaType::NativeUInt)
                | (SsaType::NativeUInt, SsaType::NativeInt)
        )
    }

    /// Whether `conv.T2(conv.T1(x))` computes what `conv.T2(x)` does, for `x` of type
    /// `source_type`, `T1` = `inner_target` and `T2` = `outer_target`, so that the inner
    /// conversion can be skipped.
    ///
    /// It can exactly when the inner conversion leaves `x`'s stack value as it is: the outer
    /// conversion then sees the same value either way. On the evaluation stack a value
    /// narrower than 32 bits is held extended to 32 bits by its own signedness (`int8` -1 is
    /// `0xFFFFFFFF`, `uint8` 255 is `0x000000FF`), and a conversion to a narrow type
    /// truncates and extends again by the *target's* signedness (ECMA-335 III.3.27). So:
    ///
    /// - a source wider than `T1` is truncated, and the conversion cannot be skipped;
    /// - a 4-byte `T1` leaves any 32-bit stack value as it is (`conv.i4`, `conv.u4`);
    /// - a narrower `T1` leaves the value as it is when the source has its width and its
    ///   signedness, or is narrower and either unsigned (its upper bits are zero, which any
    ///   extension keeps) or held under a signed `T1` (sign extension of a sign-extended
    ///   value). An `int16` -1 through `conv.u2` becomes 65535, not -1, and `conv.i8` then
    ///   differs from `conv.i8` of the source.
    ///
    /// The chain is only considered when the outer conversion widens past `T1`, and float
    /// conversions are left alone (`conv.r8(conv.r4(x))` rounds twice). The outer
    /// conversion's own signedness does not matter: it is applied to the same value.
    ///
    /// # Arguments
    ///
    /// * `source_type` - The type of the inner conversion's operand
    /// * `inner_target` - `T1`
    /// * `outer_target` - `T2`
    /// * `inner_unsigned` - Whether `T1` is unsigned (`conv.u1`, `conv.u2`, `conv.u4`)
    fn is_safe_widening_chain(
        source_type: &SsaType,
        inner_target: &SsaType,
        outer_target: &SsaType,
        inner_unsigned: bool,
    ) -> bool {
        if source_type.is_float() || inner_target.is_float() || outer_target.is_float() {
            return false;
        }
        let (Some(source_size), Some(inner_size), Some(outer_size)) = (
            source_type.size_bytes(),
            inner_target.size_bytes(),
            outer_target.size_bytes(),
        ) else {
            // Native widths depend on the machine: be conservative
            return false;
        };
        if source_size > inner_size || inner_size >= outer_size {
            return false;
        }
        if inner_size >= 4 {
            return true;
        }
        let source_unsigned = matches!(
            source_type,
            SsaType::U8
                | SsaType::U16
                | SsaType::U32
                | SsaType::U64
                | SsaType::Bool
                | SsaType::Char
        );
        if source_size == inner_size {
            source_unsigned == inner_unsigned
        } else {
            source_unsigned || !inner_unsigned
        }
    }

    /// Folds overflow-checked arithmetic operations when result doesn't overflow.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to analyze.
    /// * `constants` - Map of known constants (updated with new discoveries).
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    fn fold_overflow_checked_ops(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        machine: Machine,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((dest, value)) = Self::check_overflow_op(instr.op(), constants, machine)
                {
                    new_constants.push((dest, value, block_idx, instr_idx));
                }
            }
        }

        // Apply the transformations
        for (dest, value, block_idx, instr_idx) in new_constants {
            constants.insert(dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    let old_op_str = format!("{}", instr.op());

                    instr.set_op(SsaOp::Const {
                        dest,
                        value: value.clone(),
                    });

                    changes
                        .record(EventKind::ConstantFolded)
                        .at(method_token, instr_idx)
                        .message(format!("{old_op_str} → {value} (ovf)"));
                }
            }
        }
    }

    /// Checks if an overflow-checked operation can be folded.
    ///
    /// `add.ovf`/`sub.ovf`/`mul.ovf` throw `OverflowException` when the result does not fit
    /// the operand width, so folding one is only sound when the operation provably does *not*
    /// overflow. Getting that test wrong turns a throwing path into a wrong constant, which is
    /// worse than not folding at all.
    ///
    /// The width test must therefore happen at the *operand's* own width.
    /// [`ConstValue::add_checked`] and its siblings do exactly that — `checked_*` per variant,
    /// `None` on overflow, signed or unsigned per the instruction's flag — so the whole
    /// decision is delegated rather than reimplemented here. The plain `add`/`sub`/`mul` are
    /// deliberately *not* used: they wrap silently, so they cannot serve as their own overflow
    /// oracle. Nor is `as_i64`, which sign-extends to 64 bits and so reports no overflow for
    /// any pair of 32-bit operands — `i32::MAX + 1` folded to `i32::MIN` under it.
    fn check_overflow_op(
        op: &SsaOp,
        constants: &BTreeMap<SsaVarId, ConstValue>,
        machine: Machine,
    ) -> Option<(SsaVarId, ConstValue)> {
        // No `x * 0 == 0` short-circuit for `MulOvf`: a multiply by zero cannot overflow, so
        // `mul_checked` already folds it. The short-circuit that used to sit here returned the
        // *zero operand's own* variant, so `I32(0) * I64(5)` yielded `I32(0)` and
        // `I64(0) * I32(5)` yielded `I64(0)` — the result width depended on which side
        // happened to be zero.
        let (dest, folded) = match op {
            SsaOp::AddOvf {
                dest,
                left,
                right,
                unsigned,
                ..
            } => {
                let (l, r) = (constants.get(left)?, constants.get(right)?);
                (dest, l.add_checked(r, *unsigned, machine.ptr_size))
            }

            SsaOp::SubOvf {
                dest,
                left,
                right,
                unsigned,
                ..
            } => {
                let (l, r) = (constants.get(left)?, constants.get(right)?);
                (dest, l.sub_checked(r, *unsigned, machine.ptr_size))
            }

            SsaOp::MulOvf {
                dest,
                left,
                right,
                unsigned,
                ..
            } => {
                let (l, r) = (constants.get(left)?, constants.get(right)?);
                (dest, l.mul_checked(r, *unsigned, machine.ptr_size))
            }

            _ => return None,
        };

        folded.map(|value| (*dest, value))
    }

    /// Folds calls to pure methods with all-constant arguments.
    ///
    /// This enables interprocedural constant propagation for simple helper methods,
    /// particularly converted x86 native stubs from ConfuserEx CFF. When all arguments
    /// to a call are known constants and the callee is a MethodDef in the same assembly
    /// with a CIL body, the callee is evaluated and the call is replaced with the result.
    fn fold_pure_calls(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        assembly: &CilObject,
        resolver: &CallResolver,
        machine: Machine,
    ) {
        let mut replacements: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let Some(call) = instr.op().as_named_call() else {
                    continue;
                };
                let (Some(dest), Some(method)) = (call.dest, call.callee.method()) else {
                    continue;
                };
                let (callee_token, args) = (method.token(), &call.args);
                // A `callvirt` runs the body it names only where nothing in the
                // assembly overrides that method - C# emits one for every
                // instance call, virtual or not.
                let is_virtual = !matches!(call.callee, Callee::Direct(_));
                if is_virtual && resolver.is_polymorphic(callee_token) {
                    continue;
                }

                // Only handle MethodDef tokens (same-assembly methods)
                if !callee_token.is_table(TableId::MethodDef) {
                    continue;
                }

                // Check if all arguments are known constants.
                let concrete_args: Option<Vec<ConstValue>> = args
                    .iter()
                    .map(|&a| {
                        constants
                            .get(&a)
                            .cloned()
                            .or_else(|| match ssa.get_definition(a) {
                                Some(SsaOp::Const { value, .. }) => Some(value.clone()),
                                _ => None,
                            })
                    })
                    .collect();

                let Some(concrete_args) = concrete_args else {
                    continue;
                };
                // ...and on a receiver that is not null, where it throws instead.
                if is_virtual && matches!(concrete_args.first(), Some(ConstValue::Null)) {
                    continue;
                }

                // Try to evaluate the callee
                let Some(result) =
                    Self::evaluate_pure_call(assembly, callee_token, &concrete_args, machine)
                else {
                    continue;
                };

                replacements.push((block_idx, instr_idx, dest, result));
            }
        }

        for (block_idx, instr_idx, dest, value) in replacements {
            constants.insert(dest, value.clone());
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                    changes
                        .record(EventKind::ConstantFolded)
                        .at(
                            method_token,
                            block_idx.saturating_mul(1000).saturating_add(instr_idx),
                        )
                        .message("folded pure call with constant arguments");
                }
            }
        }

        // Forward-propagate folded call results through simple arithmetic in the
        // same block (e.g., rem.un used for CFF switch dispatch). This is needed
        // because SCCP doesn't visit exception handler blocks, so constants from
        // folded x86 calls wouldn't otherwise reach the switch variable.
        if !constants.is_empty() {
            Self::propagate_folded_arithmetic(ssa, constants, method_token, changes, machine);
        }
    }

    /// Propagates known constants through remainders.
    ///
    /// After folding pure calls, a `rem` (the `rem.un` of a flattened switch
    /// dispatch) may have both operands constant and not yet be folded. Each
    /// is folded as SCCP folds it ([`Machine::evaluate`]), so the remainder
    /// keeps its operands' width and signedness, and a divisor of zero or
    /// `MIN % -1` stays in place for the runtime to raise.
    fn propagate_folded_arithmetic(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        machine: Machine,
    ) {
        let mut new_constants: Vec<(usize, usize, SsaVarId, ConstValue)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let op = instr.op();
                let SsaOp::Rem { dest, .. } = op else {
                    continue;
                };
                let known = |var: SsaVarId| {
                    constants
                        .get(&var)
                        .or_else(|| match ssa.get_definition(var) {
                            Some(SsaOp::Const { value, .. }) => Some(value),
                            _ => None,
                        })
                        .cloned()
                };
                if let Some(value) =
                    machine.evaluate(op, op.dest().and_then(|dest| ssa.bit_width(dest)), known)
                {
                    new_constants.push((block_idx, instr_idx, *dest, value));
                }
            }
        }

        for (block_idx, instr_idx, dest, value) in new_constants {
            constants.insert(dest, value.clone());
            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    instr.set_op(SsaOp::Const { dest, value });
                    changes
                        .record(EventKind::ConstantFolded)
                        .at(
                            method_token,
                            block_idx.saturating_mul(1000).saturating_add(instr_idx),
                        )
                        .message("folded arithmetic with constant operands");
                }
            }
        }
    }

    /// Evaluates a pure method call with concrete arguments.
    ///
    /// Builds SSA for the callee, executes it with the given arguments using
    /// the SSA evaluator, and returns the result if execution completes.
    fn evaluate_pure_call(
        assembly: &CilObject,
        callee_token: Token,
        args: &[ConstValue],
        machine: Machine,
    ) -> Option<ConstValue> {
        let method = assembly.method(&callee_token).ok()?;
        let callee_ssa = method.ssa(assembly).ok()?;
        Self::evaluate_pure_function(&callee_ssa, args, machine)
    }

    /// Evaluates `callee` over concrete arguments, when replacing a call to it
    /// with the result loses nothing.
    ///
    /// A call is its result only when computing the result is all it does. The
    /// evaluator steps over a store to a field or a static - it computes values,
    /// it does not model memory - so a callee that writes one and returns a
    /// function of its arguments evaluates cleanly, and folding the call would
    /// delete the write. Only a callee whose purity is proven is evaluated: one
    /// that writes nothing, calls nothing and throws nothing, and at most reads.
    ///
    /// # Arguments
    ///
    /// * `callee` - The called method's SSA.
    /// * `args` - The call's arguments, all known.
    /// * `machine` - The machine the method computes on.
    ///
    /// # Returns
    ///
    /// The value the call returns, or `None` when the callee is not proven pure
    /// or its evaluation does not complete to a return.
    fn evaluate_pure_function(
        callee_ssa: &SsaFunction,
        args: &[ConstValue],
        machine: Machine,
    ) -> Option<ConstValue> {
        // A callee that may raise is evaluated too: a run that raises does not
        // complete to a return, and is not folded.
        if !matches!(
            callee_ssa.purity(|_| None),
            MethodPurity::Pure | MethodPurity::ReadOnly | MethodPurity::MayThrow
        ) {
            return None;
        }

        let mut eval = SsaEvaluator::new(callee_ssa, machine);
        for (var, value) in callee_ssa.argument_variables().zip(args) {
            eval.set_concrete(var.id(), value.clone());
        }

        let trace = eval.execute(0, None, 50);
        if !trace.is_complete() {
            return None;
        }

        let last_block_idx = trace.last_block()?;
        let last_block = callee_ssa.block(last_block_idx)?;

        for instr in last_block.instructions() {
            if let SsaOp::Return {
                value: Some(ret_var),
                ..
            } = instr.op()
            {
                return eval.get_concrete(*ret_var).cloned();
            }
        }

        None
    }

    /// Folds string method calls with constant arguments into `DecryptedString` constants.
    ///
    /// Scans all calls naming their method for recognized `System.String` methods
    /// (Concat, Substring, Replace, ToLower, ToUpper) where every argument resolves to
    /// a known string constant. Matching calls are replaced with `SsaOp::Const` holding
    /// the folded `ConstValue::DecryptedString`.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to scan and transform.
    /// * `constants` - Map of known constants; newly folded strings are inserted here.
    /// * `method_token` - Method token for event logging.
    /// * `changes` - Event log for recording transformations.
    /// * `assembly` - Assembly metadata for resolving method tokens and `#US` heap strings.
    fn fold_string_operations(
        ssa: &mut SsaFunction,
        constants: &mut BTreeMap<SsaVarId, ConstValue>,
        method_token: Token,
        changes: &mut EventLog,
        assembly: &CilObject,
    ) {
        let mut new_constants: Vec<(SsaVarId, ConstValue, usize, usize)> = Vec::new();

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let folded = instr.op().as_named_call().and_then(|call| {
                    let (dest, method) = (call.dest?, call.callee.method()?);
                    Self::try_fold_string_call(dest, method, &call.args, constants, assembly)
                });
                if let Some((dest, value)) = folded {
                    new_constants.push((dest, value, block_idx, instr_idx));
                }
            }
        }

        for (dest, value, block_idx, instr_idx) in new_constants {
            constants.insert(dest, value.clone());

            if let Some(block) = ssa.block_mut(block_idx) {
                if let Some(instr) = block.instructions_mut().get_mut(instr_idx) {
                    let old_op_str = format!("{}", instr.op());

                    instr.set_op(SsaOp::Const {
                        dest,
                        value: value.clone(),
                    });

                    changes
                        .record(EventKind::ConstantFolded)
                        .at(method_token, instr_idx)
                        .message(format!("{old_op_str} → {value} (string fold)"));
                }
            }
        }
    }

    /// Identifies a recognized `System.String` method that can be constant-folded.
    ///
    /// Resolves the method token through assembly metadata to check both the
    /// declaring type (`System.String`) and method name. Returns `None` if the
    /// method is not a foldable string operation or cannot be resolved.
    ///
    /// # Arguments
    ///
    /// * `method` - The SSA method reference to check.
    /// * `args_len` - Number of arguments (used to disambiguate overloads).
    /// * `assembly` - Assembly metadata for token resolution.
    ///
    /// # Returns
    ///
    /// The identified [`StringFoldOp`], or `None` if not a recognized operation.
    fn identify_string_op(
        method: &MethodRef,
        args_len: usize,
        assembly: &CilObject,
    ) -> Option<StringFoldOp> {
        let token = method.token();
        // Exactly `System.String`: a substring match would fold a user's
        // `StringHelper.Concat` as if it concatenated.
        let declaring = assembly.resolve_method_declaring_type(token);
        if declaring.as_deref() != Some("System.String") {
            return None;
        }
        let name = assembly.resolve_method_name(token)?;
        match (name.as_str(), args_len) {
            ("Concat", 2) => Some(StringFoldOp::Concat2),
            ("Concat", 3) => Some(StringFoldOp::Concat3),
            ("Concat", 4) => Some(StringFoldOp::Concat4),
            ("Substring", 2) => Some(StringFoldOp::SubstringFrom),
            ("Substring", 3) => Some(StringFoldOp::SubstringRange),
            ("Replace", 3) => Some(StringFoldOp::Replace),
            ("ToLower", 1) => Some(StringFoldOp::ToLower),
            ("ToUpper", 1) => Some(StringFoldOp::ToUpper),
            ("ToLowerInvariant", 1) => Some(StringFoldOp::ToLower),
            ("ToUpperInvariant", 1) => Some(StringFoldOp::ToUpper),
            _ => None,
        }
    }

    /// Attempts to fold a single string method call with constant arguments.
    ///
    /// If the method is a recognized `System.String` operation and all arguments
    /// are known string constants, evaluates the operation and returns the result
    /// as a `DecryptedString`. Returns `None` if any argument is non-constant,
    /// the method is unrecognized, or the operation cannot be safely evaluated
    /// (e.g., non-ASCII strings for `Substring`).
    ///
    /// # Arguments
    ///
    /// * `dest` - The SSA variable that receives the call result.
    /// * `method` - The method being called.
    /// * `args` - SSA variables for the call arguments.
    /// * `constants` - Map of known constant values for argument lookup.
    /// * `assembly` - Assembly metadata for method resolution and heap access.
    ///
    /// # Returns
    ///
    /// `Some((dest, folded_value))` if successfully folded, `None` otherwise.
    fn try_fold_string_call(
        dest: SsaVarId,
        method: &MethodRef,
        args: &[SsaVarId],
        constants: &BTreeMap<SsaVarId, ConstValue>,
        assembly: &CilObject,
    ) -> Option<(SsaVarId, ConstValue)> {
        let string_op = Self::identify_string_op(method, args.len(), assembly)?;
        match string_op {
            StringFoldOp::Concat2 | StringFoldOp::Concat3 | StringFoldOp::Concat4 => {
                let strings: Option<Vec<String>> = args
                    .iter()
                    .map(|arg| {
                        constants
                            .get(arg)
                            .and_then(|v| v.as_string_content(assembly))
                    })
                    .collect();
                let result = strings?.concat();
                Some((dest, ConstValue::DecryptedString(result.into())))
            }
            StringFoldOp::SubstringFrom => {
                let this_str = constants.get(args.first()?)?.as_string_content(assembly)?;
                // Bail on non-ASCII: .NET uses UTF-16 char indices, Rust uses bytes.
                if !this_str.is_ascii() {
                    return None;
                }
                let start = constants.get(args.get(1)?)?.as_i32()? as usize;
                let tail = this_str.get(start..)?;
                Some((dest, ConstValue::DecryptedString(tail.into())))
            }
            StringFoldOp::SubstringRange => {
                let this_str = constants.get(args.first()?)?.as_string_content(assembly)?;
                if !this_str.is_ascii() {
                    return None;
                }
                let start = constants.get(args.get(1)?)?.as_i32()? as usize;
                let len = constants.get(args.get(2)?)?.as_i32()? as usize;
                let end = start.checked_add(len)?;
                let slice = this_str.get(start..end)?;
                Some((dest, ConstValue::DecryptedString(slice.into())))
            }
            StringFoldOp::Replace => {
                let this_str = constants.get(args.first()?)?.as_string_content(assembly)?;
                let old = constants.get(args.get(1)?)?.as_string_content(assembly)?;
                let new = constants.get(args.get(2)?)?.as_string_content(assembly)?;
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str.replace(&old, &new).into()),
                ))
            }
            StringFoldOp::ToLower => {
                let this_str = constants.get(args.first()?)?.as_string_content(assembly)?;
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str.to_lowercase().into()),
                ))
            }
            StringFoldOp::ToUpper => {
                let this_str = constants.get(args.first()?)?.as_string_content(assembly)?;
                Some((
                    dest,
                    ConstValue::DecryptedString(this_str.to_uppercase().into()),
                ))
            }
        }
    }

    /// Applies constant folding transformations to the SSA function.
    ///
    /// This replaces non-constant operations with constant loads when
    /// the result is known to be constant.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to transform.
    /// * `constants` - Map of known constants.
    /// * `sccp_result` - The SCCP analysis results.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    #[allow(clippy::cast_possible_truncation)]
    fn apply_constant_folding(
        ssa: &mut SsaFunction,
        constants: &BTreeMap<SsaVarId, ConstValue>,
        sccp_result: &SccpResult,
        method_token: Token,
        changes: &mut EventLog,
    ) {
        for block_idx in 0..ssa.block_count() {
            if !sccp_result.is_block_executable(block_idx) {
                continue;
            }

            if let Some(block) = ssa.block_mut(block_idx) {
                for (instr_idx, instr) in block.instructions_mut().iter_mut().enumerate() {
                    let op = instr.op();
                    // Skip if already a constant
                    if matches!(op, SsaOp::Const { .. }) {
                        continue;
                    }

                    // Check if this instruction's result is a known constant
                    if let Some(dest) = op.dest() {
                        if let Some(value) = constants.get(&dest) {
                            // Skip DecryptedArray: arrays are mutable reference types.
                            // Propagating them materializes a fresh array at each use
                            // site, breaking in-place modifications (e.g., XOR loops
                            // that modify the array and then read the result).
                            if matches!(value, ConstValue::DecryptedArray { .. }) {
                                continue;
                            }

                            let old_op_str = format!("{op}");

                            instr.set_op(SsaOp::Const {
                                dest,
                                value: value.clone(),
                            });

                            changes
                                .record(EventKind::ConstantFolded)
                                .at(method_token, instr_idx)
                                .message(format!("{old_op_str} → {value}"));
                        }
                    }
                }
            }
        }
    }

    /// Simplifies chains of involutory operations (Neg/Not).
    ///
    /// Involutory operations satisfy f(f(x)) = x. This pass finds maximal chains
    /// of same-type operations and collapses them:
    ///
    /// - **Even-length chains** (e.g., neg(neg(neg(neg(x))))): cancel completely,
    ///   replacing all uses of the outermost result with the innermost operand.
    /// - **Odd-length chains** (e.g., neg(neg(neg(x)))): collapse to a single
    ///   operation on the innermost operand.
    ///
    /// # Chain-based algorithm
    ///
    /// 1. Build a set of all Neg/Not operands to identify outermost instructions
    ///    (an instruction is outermost if its result is NOT used as the operand
    ///    of another same-type operation).
    /// 2. From each outermost instruction, walk backwards through same-op
    ///    definitions to collect the full chain.
    /// 3. Verify all intermediates have exactly 1 use (only the next chain member).
    /// 4. Apply the appropriate transform based on chain parity.
    fn simplify_involutory_ops(ssa: &mut SsaFunction, method_token: Token, changes: &mut EventLog) {
        // Step 1: Build definition map and use counts
        let mut definitions: BTreeMap<SsaVarId, (usize, usize)> = BTreeMap::new();
        let mut use_counts: BTreeMap<SsaVarId, usize> = BTreeMap::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            if let Some(dest) = instr.op().dest() {
                definitions.insert(dest, (block_idx, instr_idx));
            }
            for use_var in instr.op().uses() {
                let slot = use_counts.entry(use_var).or_default();
                *slot = slot.saturating_add(1);
            }
        }
        for phi in ssa.all_phi_nodes() {
            for operand in phi.operands() {
                let slot = use_counts.entry(operand.value()).or_default();
                *slot = slot.saturating_add(1);
            }
        }

        // Step 2: Identify outermost Neg/Not instructions.
        // A Neg is outermost if its dest is NOT used as the operand of another Neg.
        let mut neg_operands = BitSet::new(ssa.var_id_capacity());
        let mut not_operands = BitSet::new(ssa.var_id_capacity());
        for (_, _, instr) in ssa.iter_instructions() {
            match instr.op() {
                SsaOp::Neg { operand, .. } => {
                    neg_operands.insert(operand.index());
                }
                SsaOp::Not { operand, .. } => {
                    not_operands.insert(operand.index());
                }
                _ => {}
            }
        }

        // Step 3: From each outermost instruction, walk backwards to find chains
        struct ChainTransform {
            outermost_dest: SsaVarId,
            innermost_operand: SsaVarId,
            chain_length: usize,
            instructions_to_nop: Vec<(usize, usize)>,
            outermost_location: (usize, usize),
            is_neg: bool,
        }

        let mut processed = BitSet::new(ssa.var_id_capacity());
        let mut transforms: Vec<ChainTransform> = Vec::new();

        for (block_idx, instr_idx, instr) in ssa.iter_instructions() {
            let (dest, operand, is_neg) = match instr.op() {
                SsaOp::Neg { dest, operand, .. } => (*dest, *operand, true),
                SsaOp::Not { dest, operand, .. } => (*dest, *operand, false),
                _ => continue,
            };

            if processed.contains(dest.index()) {
                continue;
            }

            // Only start chains from outermost instructions
            let is_outermost = if is_neg {
                !neg_operands.contains(dest.index())
            } else {
                !not_operands.contains(dest.index())
            };
            if !is_outermost {
                continue;
            }

            // Walk chain backwards through same-op definitions
            let mut chain_locations: Vec<(usize, usize)> = vec![(block_idx, instr_idx)];
            let mut chain_dests: Vec<SsaVarId> = vec![dest];
            let mut current_operand = operand;
            let mut all_intermediates_single_use = true;

            loop {
                // Check that this intermediate has exactly 1 use (the previous chain member)
                let uses = use_counts.get(&current_operand).copied().unwrap_or(0);
                if uses != 1 {
                    all_intermediates_single_use = false;
                    break;
                }

                let Some(&(def_block, def_instr)) = definitions.get(&current_operand) else {
                    break;
                };
                let Some(def_block_ref) = ssa.block(def_block) else {
                    break;
                };

                let Some(def_instr_ref) = def_block_ref.instructions().get(def_instr) else {
                    break;
                };
                let inner = match def_instr_ref.op() {
                    SsaOp::Neg {
                        dest: d,
                        operand: inner,
                        ..
                    } if is_neg => (*d, *inner),
                    SsaOp::Not {
                        dest: d,
                        operand: inner,
                        ..
                    } if !is_neg => (*d, *inner),
                    _ => break,
                };

                chain_locations.push((def_block, def_instr));
                chain_dests.push(inner.0);
                current_operand = inner.1;
            }

            // Mark all chain members as processed
            for d in &chain_dests {
                processed.insert(d.index());
            }

            let chain_len = chain_locations.len();
            if chain_len < 2 || !all_intermediates_single_use {
                continue;
            }

            transforms.push(ChainTransform {
                outermost_dest: dest,
                innermost_operand: current_operand,
                chain_length: chain_len,
                instructions_to_nop: chain_locations,
                outermost_location: (block_idx, instr_idx),
                is_neg,
            });
        }

        // Step 4: Apply transforms.
        //
        // The even chains are substitutions, and one chain's innermost operand
        // can be another's outermost result: `a = neg(neg x)` feeding
        // `b = not(not a)` gives `(a -> x)` and `(b -> a)`. Applied one at a
        // time the second writes `a` back into use after its definition is
        // gone, so they are resolved together, and an odd chain's surviving
        // operation reads the resolved operand too.
        let substitutions: Vec<(SsaVarId, SsaVarId)> = transforms
            .iter()
            .filter(|t| t.chain_length % 2 == 0)
            .map(|t| (t.outermost_dest, t.innermost_operand))
            .collect();
        let resolved = resolve_chains(&substitutions);
        let resolve = |var: SsaVarId| resolved.get(&var).copied().unwrap_or(var);

        for t in &transforms {
            let op_name = if t.is_neg { "neg" } else { "not" };

            if t.chain_length % 2 == 0 {
                // Even chain: all cancel out, result = innermost_operand
                for &(b, i) in &t.instructions_to_nop {
                    ssa.replace_instruction_op(b, i, SsaOp::Nop);
                }
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, t.outermost_location.1)
                    .message(format!(
                        "{} → {} ({op_name}^{}(x))",
                        t.outermost_dest,
                        resolve(t.outermost_dest),
                        t.chain_length
                    ));
            } else {
                // Odd chain: one operation remains, rewrite outermost to use innermost_operand
                let operand = resolve(t.innermost_operand);
                let (b, i) = t.outermost_location;
                if let Some(block) = ssa.block_mut(b) {
                    if let Some(instr) = block.instructions_mut().get_mut(i) {
                        if t.is_neg {
                            instr.set_op(SsaOp::Neg {
                                dest: t.outermost_dest,
                                operand,
                                flags: None,
                            });
                        } else {
                            instr.set_op(SsaOp::Not {
                                dest: t.outermost_dest,
                                operand,
                                flags: None,
                            });
                        }
                    }
                }
                // Nop all except the outermost
                if let Some(rest) = t.instructions_to_nop.get(1..) {
                    for &(b, i) in rest {
                        ssa.replace_instruction_op(b, i, SsaOp::Nop);
                    }
                }
                changes
                    .record(EventKind::ConstantFolded)
                    .at(method_token, t.outermost_location.1)
                    .message(format!(
                        "{} = {op_name}({operand}) ({op_name}^{}(x))",
                        t.outermost_dest, t.chain_length
                    ));
            }
        }
        ssa.replace_uses_resolved(&substitutions);
    }

    /// The header block of every natural loop in `ssa`.
    ///
    /// Switch folding has to be skipped at a loop header: the switch value can
    /// be constant on the entry edge and something else on the back edge, and
    /// folding it to the entry value makes every other case unreachable. That is
    /// what a control-flow-flattening dispatcher is, so getting this wrong
    /// deletes the body of the loop rather than one arm of a branch.
    ///
    /// Which blocks are headers is asked of the dominator tree, through
    /// [`LoopAnalyzer`], because a back edge is a dominance relation and nothing
    /// else. This used to test whether any *higher-indexed* block branched to
    /// the block, taking block order as a proxy for the edge direction. It reads
    /// a back edge only when the latch happens to be numbered after the header,
    /// which is a property of how the blocks were laid out rather than of the
    /// loop. A JIEJIE.NET dispatcher reached through a one-instruction
    /// trampoline - `b21 -> b1 -> b2`, where the trampoline `b1` is numbered
    /// before the dispatcher `b2` it jumps to - has a loop the test cannot see,
    /// and `DemoEmbeddedResources` lost its whole trailing `foreach` to a switch
    /// folded on the entry state.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The function whose loops to find.
    fn loop_headers(ssa: &SsaFunction) -> BTreeSet<usize> {
        LoopAnalyzer::new(ssa)
            .analyze()
            .loops()
            .iter()
            .map(|loop_info| loop_info.header.index())
            .collect()
    }

    /// Simplifies control flow based on constant conditions.
    ///
    /// Converts branches and switches with known conditions to unconditional jumps.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to transform.
    /// * `constants` - Map of known constants.
    /// * `sccp_result` - The SCCP analysis results.
    /// * `method_token` - The method token for change tracking.
    /// * `changes` - The change set to record modifications.
    /// * `machine` - The machine the method computes on.
    fn simplify_control_flow(
        ssa: &mut SsaFunction,
        constants: &BTreeMap<SsaVarId, ConstValue>,
        sccp_result: &SccpResult,
        method_token: Token,
        changes: &mut EventLog,
        machine: Machine,
    ) {
        // One dominator-tree walk answers for every block, and the answer has
        // to be taken before the first rewrite: folding a terminator changes
        // the edges the next block's answer would be computed from.
        let loop_headers = Self::loop_headers(ssa);

        for block_idx in 0..ssa.block_count() {
            if !sccp_result.is_block_executable(block_idx) {
                continue;
            }

            // First pass: analyze the terminator without mutable borrow
            let simplification = if let Some(block) = ssa.block(block_idx) {
                if let Some(op) = block.control_terminator() {
                    match op {
                        SsaOp::Branch {
                            condition,
                            true_target,
                            false_target,
                        } => {
                            if let Some(c) = constants.get(condition) {
                                if let Some(is_true) = c.as_bool() {
                                    let target = if is_true { *true_target } else { *false_target };
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        SsaOp::Switch {
                            value,
                            targets,
                            default,
                        } => {
                            if loop_headers.contains(&block_idx) {
                                // Don't fold switches at loop headers. A switch whose
                                // value is constant on the initial iteration may take
                                // different values on subsequent iterations (via the
                                // PHI at the loop header). Folding it would make all
                                // non-initial-state switch cases unreachable, which is
                                // incorrect for CFF inner state machines (e.g.,
                                // JIEJIE.NET nested dispatchers within using blocks).
                                None
                            } else if let Some(c) = constants.get(value) {
                                if let Some(idx) = c.as_i32() {
                                    let target = usize::try_from(idx)
                                        .ok()
                                        .and_then(|i| targets.get(i).copied())
                                        .unwrap_or(*default);
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        SsaOp::BranchCmp {
                            left,
                            right,
                            cmp,
                            unsigned,
                            true_target,
                            false_target,
                        } => {
                            // Try to evaluate comparison when both operands are constant
                            if let (Some(left_val), Some(right_val)) =
                                (constants.get(left), constants.get(right))
                            {
                                if let Some(is_true) = SsaEvaluator::evaluate_comparison(
                                    left_val,
                                    right_val,
                                    *cmp,
                                    *unsigned,
                                    machine.ptr_size,
                                ) {
                                    let target = if is_true { *true_target } else { *false_target };
                                    Some((SsaOp::Jump { target }, target))
                                } else {
                                    None
                                }
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            // Second pass: apply the simplification with mutable borrow
            if let Some((new_op, target)) = simplification {
                if let Some(block) = ssa.block_mut(block_idx) {
                    if let Some(last_instr) = block.instructions_mut().last_mut() {
                        last_instr.set_op(new_op);
                        changes
                            .record(EventKind::BranchSimplified)
                            .at(method_token, block_idx)
                            .message(format!("simplified to unconditional branch to {target}"));
                    }
                }
            }
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for ConstantPropagationPass {
    fn name(&self) -> &'static str {
        "constant-propagation"
    }

    fn description(&self) -> &'static str {
        "Propagates constant values and folds constant expressions using SCCP"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly = host
            .assembly()
            .ok_or_else(|| analyssa::Error::new("ConstantPropagationPass requires an assembly"))?;
        let method_token = method.0;
        let mut changes = EventLog::new();
        let machine = host.machine();

        // Run constant propagation and transformation
        let mut rounds = Rounds::new(Budget::FoldRounds, host.budget().limit(Budget::FoldRounds));
        let constants = Self::run_constant_propagation(
            ssa,
            method_token,
            &mut changes,
            machine,
            &mut rounds,
            &assembly,
            host.call_graph.resolver(),
        );
        // Reported to the host, not with the changes: running out of rounds is
        // no change of the function's.
        if let Some(exhaustion) = rounds.exhausted() {
            host.events.push(Event::exhausted(Some(method), exhaustion));
        }

        // Record what was proved, on the values it was proved about.
        //
        // Written into the function this pass is holding, not through the host:
        // the host would look up *its* copy of the method, and a pass is handed
        // the function precisely because that copy is not the one being
        // transformed. Recording here also means the facts are rolled back with
        // the function if this pass group is, rather than outliving the IR they
        // describe.
        for (var, value) in &constants {
            if let Some(variable) = ssa.variable_mut(*var) {
                variable.facts_mut().set_known_value(value.clone());
            }
        }

        let changed = !changes.is_empty();
        if changed {
            host.events.merge(&changes);
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests;
