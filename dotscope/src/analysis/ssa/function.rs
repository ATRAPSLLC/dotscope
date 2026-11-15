//! CIL-pinned extension traits on `SsaFunction`.
//!
//! - [`SsaFunctionCilExt`] adds CIL-typed local-variable utilities
//!   (`optimize_locals`, `generate_local_signature`, `infer_local_type`) that
//!   reference `SsaType` / `SignatureLocalVariable` and so cannot live inside
//!   analyssa.
//! - [`SsaFunctionSemanticsExt`] delegates block- and loop-classification to
//!   [`SemanticAnalyzer`](crate::analysis::cfg::SemanticAnalyzer), which itself
//!   depends on dotscope's CFG-loop machinery (`LoopInfo`, dominator-based
//!   loop detection).
//!
//! Both traits exist because Rust's orphan rules forbid inherent impls on the
//! foreign `analyssa::ir::function::SsaFunction` type.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use analyssa::{
    ir::{
        function::SsaFunction,
        ops::SsaOp,
        variable::{SsaVarId, VariableOrigin},
    },
    target::Target,
};

use crate::{
    analysis::{
        cfg::{BlockSemantics, LoopSemantics, SemanticAnalyzer},
        ssa::{target::CilTarget, types::SsaType},
        LoopInfo,
    },
    metadata::signatures::{CustomModifiers, SignatureLocalVariable, SignatureLocalVariables},
    Error, Result,
};

/// CIL-specific extension methods on `SsaFunction<CilTarget>`.
///
/// `optimize_locals` / `generate_local_signature` / `infer_local_type` use
/// `SsaType` and `SignatureLocalVariable` which are CIL-side only.
pub trait SsaFunctionCilExt {
    /// Optimizes local variables by removing unused ones and compacting indices.
    fn optimize_locals(&mut self) -> Vec<Option<u16>>;

    /// Generates a `SignatureLocalVariables` from the function's locals.
    fn generate_local_signature(
        &self,
        override_count: Option<u16>,
        temporary_types: Option<&BTreeMap<u16, SsaType>>,
    ) -> Result<SignatureLocalVariables>;

    /// Infers a CIL `SsaType` for a local index from its SSA variable definitions.
    fn infer_local_type(&self, local_idx: usize) -> Option<SsaType>;
}

impl SsaFunctionCilExt for SsaFunction<CilTarget> {
    fn optimize_locals(&mut self) -> Vec<Option<u16>> {
        // Collect all used local indices.
        let mut used_locals: BTreeSet<u16> = BTreeSet::new();

        // From variables
        for var in self.variables() {
            if let VariableOrigin::Local(idx) = var.origin() {
                used_locals.insert(idx);
            }
        }

        // From phi nodes
        for block in self.blocks() {
            for phi in block.phi_nodes() {
                if let VariableOrigin::Local(idx) = phi.origin() {
                    used_locals.insert(idx);
                }
            }
        }

        // From LoadLocal and LoadLocalAddr instructions
        for block in self.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::LoadLocal { local_index, .. }
                    | SsaOp::LoadLocalAddr { local_index, .. } => {
                        used_locals.insert(*local_index);
                    }
                    _ => {}
                }
            }
        }

        // Determine the actual range of local indices (may exceed num_locals
        // if SSA construction allocated extras).
        let max_idx = used_locals.iter().copied().max().unwrap_or(0);
        let max_known = u16::try_from(self.num_locals())
            .unwrap_or(u16::MAX)
            .saturating_sub(1)
            .max(max_idx);

        // Build remapping (old → new).
        let mut remap: Vec<Option<u16>> = vec![None; usize::from(max_known) + 1];
        let mut new_idx: u16 = 0;
        for old_idx in 0..=max_known {
            if used_locals.contains(&old_idx) {
                if let Some(slot) = remap.get_mut(usize::from(old_idx)) {
                    *slot = Some(new_idx);
                }
                new_idx = new_idx.saturating_add(1);
            }
        }

        let new_count = new_idx;

        // Apply remap to variables.
        let mut new_origins: Vec<(SsaVarId, VariableOrigin)> = Vec::new();
        for var in self.variables() {
            if let VariableOrigin::Local(old) = var.origin() {
                if let Some(Some(new)) = remap.get(usize::from(old)) {
                    new_origins.push((var.id(), VariableOrigin::Local(*new)));
                }
            }
        }
        // Renumbering a local moves its rename group too. Construction groups
        // variables by rename group but resolves argument/local representatives
        // by origin, so leaving the group pointing at the old slot silently
        // splits the value: the two views disagree about which names denote the
        // same local, and the value ends up with no reaching definition. The
        // group for a local is `num_args + index`, per the assignment rules
        // documented on `SsaFunction::rename_groups`.
        let num_args = u32::try_from(self.num_args()).unwrap_or(0);
        for (id, origin) in new_origins {
            if let Some(v) = self.variable_mut(id) {
                v.set_origin(origin);
            }
            if let VariableOrigin::Local(new) = origin {
                self.set_rename_group(id, num_args.saturating_add(u32::from(new)));
            }
        }

        // Apply remap to phi nodes
        for block in self.blocks_mut() {
            for phi in block.phi_nodes_mut() {
                if let VariableOrigin::Local(old) = phi.origin() {
                    if let Some(Some(new)) = remap.get(usize::from(old)) {
                        phi.set_origin(VariableOrigin::Local(*new));
                    }
                }
            }
        }

        // Apply remap to LoadLocal/LoadLocalAddr instructions
        for block in self.blocks_mut() {
            for instr in block.instructions_mut() {
                let op = instr.op_mut();
                let new_index = match op {
                    SsaOp::LoadLocal { local_index, .. }
                    | SsaOp::LoadLocalAddr { local_index, .. } => {
                        remap.get(usize::from(*local_index)).copied().flatten()
                    }
                    _ => None,
                };
                if let Some(new) = new_index {
                    match op {
                        SsaOp::LoadLocal { local_index, .. }
                        | SsaOp::LoadLocalAddr { local_index, .. } => *local_index = new,
                        _ => {}
                    }
                }
            }
        }

        let original = self.original_num_locals();
        self.set_num_locals(usize::from(new_count), original);
        remap
    }

    fn generate_local_signature(
        &self,
        override_count: Option<u16>,
        temporary_types: Option<&BTreeMap<u16, SsaType>>,
    ) -> Result<SignatureLocalVariables> {
        let empty_temps = BTreeMap::new();
        let temps = temporary_types.unwrap_or(&empty_temps);

        let local_count = override_count
            .map(usize::from)
            .unwrap_or_else(|| self.num_locals());

        // Path 1: original local types preserved from source assembly
        if let Some(orig) = self.original_local_types() {
            let mut locals: Vec<SignatureLocalVariable> = Vec::with_capacity(local_count);
            for sig in orig.iter().take(local_count) {
                locals.push(SignatureLocalVariable {
                    modifiers: sig.modifiers.clone(),
                    is_byref: sig.is_byref,
                    is_pinned: sig.is_pinned,
                    base: sig.base.clone(),
                });
            }
            // Pad with inferred types if needed
            while locals.len() < local_count {
                let idx = u16::try_from(locals.len()).unwrap_or(u16::MAX);
                let ty = temps
                    .get(&idx)
                    .cloned()
                    .or_else(|| self.infer_local_type(usize::from(idx)));
                let Some(ty) = ty else {
                    return Err(Error::SsaError(format!(
                        "missing type info for local index {idx} during signature generation"
                    )));
                };
                locals.push(SignatureLocalVariable {
                    modifiers: CustomModifiers::default(),
                    is_byref: false,
                    is_pinned: false,
                    base: ty.to_type_signature(),
                });
            }
            return Ok(SignatureLocalVariables { locals });
        }

        // Path 2: temporary_types map + SSA inference
        let mut local_types: Vec<Option<SsaType>> = vec![None; local_count];
        for (idx, ty) in temps.iter() {
            if let Some(slot) = local_types.get_mut(usize::from(*idx)) {
                *slot = Some(ty.clone());
            }
        }
        for (idx, slot) in local_types.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = self.infer_local_type(idx);
            }
        }

        let mut locals: Vec<SignatureLocalVariable> = Vec::with_capacity(local_types.len());
        for (idx, ty) in local_types.iter().enumerate() {
            let Some(ty) = ty else {
                return Err(Error::SsaError(format!(
                    "missing type info for local index {idx} during signature generation"
                )));
            };
            locals.push(SignatureLocalVariable {
                modifiers: CustomModifiers::default(),
                is_byref: false,
                is_pinned: false,
                base: ty.to_type_signature(),
            });
        }

        Ok(SignatureLocalVariables { locals })
    }

    fn infer_local_type(&self, local_idx: usize) -> Option<SsaType> {
        let target_origin = VariableOrigin::Local(u16::try_from(local_idx).ok()?);

        // Search variables for the first concrete type for this local origin
        for var in self.variables() {
            if var.origin() == target_origin {
                let ty = var.var_type();
                if !CilTarget::is_unknown(ty) {
                    return Some(ty.clone());
                }
            }
        }
        None
    }
}

/// Block- and loop-semantic-analysis extension methods on `SsaFunction<T>`.
pub trait SsaFunctionSemanticsExt<T: Target> {
    /// Analyzes the semantic role of a specific block.
    fn analyze_block_semantics(&self, block_idx: usize) -> BlockSemantics;

    /// Analyzes semantic roles of multiple blocks.
    fn analyze_blocks_semantics(&self, blocks: &[usize]) -> HashMap<usize, BlockSemantics>;

    /// Analyzes the semantic structure of a structural loop.
    fn analyze_loop_semantics(&self, loop_info: &LoopInfo) -> LoopSemantics;

    /// Recovers loop semantics from flattened dispatcher case blocks.
    fn recover_loop_from_cases(
        &self,
        case_blocks: &[usize],
        dispatcher_block: Option<usize>,
    ) -> LoopSemantics;

    /// Creates a semantic analyzer for this function (cache-friendly for
    /// multiple analyses).
    fn semantic_analyzer(&self) -> SemanticAnalyzer<'_, T>;
}

impl<T: Target> SsaFunctionSemanticsExt<T> for SsaFunction<T> {
    fn analyze_block_semantics(&self, block_idx: usize) -> BlockSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_block(block_idx).clone()
    }

    fn analyze_blocks_semantics(&self, blocks: &[usize]) -> HashMap<usize, BlockSemantics> {
        let mut analyzer = SemanticAnalyzer::new(self);
        let mut results = HashMap::new();
        for &block in blocks {
            results.insert(block, analyzer.analyze_block(block).clone());
        }
        results
    }

    fn analyze_loop_semantics(&self, loop_info: &LoopInfo) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        analyzer.analyze_loop(loop_info)
    }

    fn recover_loop_from_cases(
        &self,
        case_blocks: &[usize],
        dispatcher_block: Option<usize>,
    ) -> LoopSemantics {
        let mut analyzer = SemanticAnalyzer::new(self);
        if let Some(disp) = dispatcher_block {
            analyzer.mark_dispatcher(disp);
        }
        analyzer.recover_loop_from_cases(case_blocks)
    }

    fn semantic_analyzer(&self) -> SemanticAnalyzer<'_, T> {
        SemanticAnalyzer::new(self)
    }
}
