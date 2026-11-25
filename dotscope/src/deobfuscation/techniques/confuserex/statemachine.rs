//! ConfuserEx CFGCtx state machine detection and emulation support.
//!
//! When ConfuserEx constants protection runs in CFG mode (`cfg=true`), it uses
//! a `CFGCtx` value type to make constant decryption order-dependent per method.
//! This module detects the CFGCtx structure, extracts its semantics, and provides
//! a [`StateMachineProvider`] implementation for the shared decryption pass.
//!
//! # CFGCtx Structure
//!
//! ```text
//! internal struct CFGCtx {
//!     uint A, B, C, D;   // 4 state slots
//!
//!     public CFGCtx(uint seed) {
//!         A = seed *= MULTIPLIER;
//!         B = seed *= MULTIPLIER;
//!         C = seed *= MULTIPLIER;
//!         D = seed *= MULTIPLIER;
//!     }
//!
//!     public uint Next(byte flag, uint value) {
//!         // Update slot (flag & 0x3) with value using operation from slot_ops
//!         // Return slot ((flag >> 2) & 0x3)
//!     }
//! }
//! ```
//!
//! # Call Site Analysis
//!
//! [`find_call_sites`] uses SSA-based backward taint analysis to classify each
//! decryptor call as either Normal mode (direct constant key) or CFG mode
//! (key computed via XOR with state machine output).

use std::collections::{hash_map::Entry, HashMap, HashSet, VecDeque};

use analyssa::{analysis::WorkBudget, graph::NodeId};
use dashmap::DashSet;

use crate::{
    analysis::{
        ConstValue, PhiTaintMode, SsaFunction, SsaInstruction, SsaOp, SsaOpCilExt, SsaVarId,
        TaintAnalysis, TaintConfig,
    },
    assembly::Operand,
    compiler::CompilerContext,
    deobfuscation::{
        CfgInfo, StateMachineCallSite, StateMachineProvider, StateMachineSemantics,
        StateSlotOperation, StateUpdateCall,
    },
    metadata::{
        method::MethodModifiers, signatures::TypeSignature, tables::TableId, token::Token,
        typesystem::CilType,
    },
    prelude::FlowType,
    CilObject,
};

/// Information about a call site to a decryptor method.
pub struct DetectedCallSite {
    /// Method containing the call.
    pub caller: Token,
    /// Whether this call uses state machine mode.
    pub uses_statemachine: bool,
}

impl DetectedCallSite {
    /// Creates a new call site with direct mode.
    fn direct(caller: Token) -> Self {
        Self {
            caller,
            uses_statemachine: false,
        }
    }

    /// Creates a new call site with state machine mode.
    fn statemachine(caller: Token) -> Self {
        Self {
            caller,
            uses_statemachine: true,
        }
    }
}

/// ConfuserEx state machine provider for CFG mode constant decryption.
///
/// This implements the [`StateMachineProvider`] trait for ConfuserEx's CFGCtx
/// state machine. It encapsulates:
/// - The detected semantics (multiplier, slot operations)
/// - The set of methods that use CFG mode
/// - Methods to find initializations and state updates in SSA
#[derive(Debug)]
pub struct ConfuserExStateMachine {
    /// The detected CFGCtx semantics.
    semantics: StateMachineSemantics,
    /// Methods that use this state machine for encryption.
    methods: DashSet<Token>,
}

impl ConfuserExStateMachine {
    /// Creates a new ConfuserEx state machine provider.
    ///
    /// # Arguments
    ///
    /// * `semantics` - The detected CFGCtx semantics.
    /// * `methods` - Iterator of method tokens that use CFG mode.
    pub fn new(semantics: StateMachineSemantics, methods: impl IntoIterator<Item = Token>) -> Self {
        let method_set = DashSet::new();
        for method in methods {
            method_set.insert(method);
        }
        Self {
            semantics,
            methods: method_set,
        }
    }
}

impl StateMachineProvider for ConfuserExStateMachine {
    fn name(&self) -> &'static str {
        "ConfuserEx CFGCtx"
    }

    fn semantics(&self) -> &StateMachineSemantics {
        &self.semantics
    }

    fn applies_to_method(&self, method: Token) -> bool {
        self.methods.contains(&method)
    }

    fn methods(&self) -> Vec<Token> {
        self.methods.iter().map(|r| *r).collect()
    }

    fn find_initializations(
        &self,
        ssa: &SsaFunction,
        ctx: &CompilerContext,
        method_token: Token,
        _assembly: &CilObject,
    ) -> Vec<(usize, usize, u32)> {
        let mut seeds = Vec::new();

        let Some(init_method_token) = self.semantics.init_method else {
            return seeds;
        };

        // Look for all calls to the CFGCtx constructor
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                match instr.op() {
                    // Value type initialization uses Call to .ctor
                    // .ctor for value type: args are (&this, seed)
                    op @ SsaOp::Call(_) => {
                        let Some((token, call)) = op.method_call() else {
                            continue;
                        };
                        let Some(&seed_var) = call.args.get(1) else {
                            continue;
                        };
                        if token != init_method_token {
                            continue;
                        }
                        if let Some(ConstValue::I32(seed)) =
                            self.trace_to_constant(seed_var, ssa, ctx, method_token)
                        {
                            #[allow(clippy::cast_sign_loss)]
                            seeds.push((block_idx, instr_idx, seed as u32));
                        }
                    }
                    // NewObj for reference types (less common for CFGCtx)
                    SsaOp::NewObj { ctor, args, .. }
                        if ctor.token() == init_method_token && args.len() == 1 =>
                    {
                        let Some(&first_arg) = args.first() else {
                            continue;
                        };
                        if let Some(ConstValue::I32(seed)) =
                            self.trace_to_constant(first_arg, ssa, ctx, method_token)
                        {
                            #[allow(clippy::cast_sign_loss)]
                            seeds.push((block_idx, instr_idx, seed as u32));
                        }
                    }
                    _ => {}
                }
            }
        }

        seeds
    }

    fn find_state_updates(&self, ssa: &SsaFunction) -> Vec<StateUpdateCall> {
        let mut updates = Vec::new();

        let Some(update_method_token) = self.semantics.update_method else {
            return updates;
        };

        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                if let Some((token, call)) = instr.op().method_call() {
                    if token == update_method_token {
                        // CFGCtx.Next takes 3 args: &this, flag (byte), increment (uint)
                        if let (Some(&flag_var), Some(&increment_var), Some(dest)) =
                            (call.args.get(1), call.args.get(2), call.dest.as_ref())
                        {
                            updates.push(StateUpdateCall {
                                block_idx,
                                instr_idx,
                                dest: *dest,
                                flag_var,
                                increment_var,
                            });
                        }
                    }
                }
            }
        }

        updates
    }

    fn find_decryptor_call_sites(
        &self,
        ssa: &SsaFunction,
        state_updates: &[StateUpdateCall],
        decryptor_tokens: &HashSet<Token>,
        assembly: &CilObject,
    ) -> Vec<StateMachineCallSite> {
        let mut call_sites = Vec::new();

        // Build a map from Next() result var -> StateUpdateCall index
        let mut next_info_map: HashMap<SsaVarId, usize> = HashMap::new();
        for (idx, update) in state_updates.iter().enumerate() {
            next_info_map.insert(update.dest, idx);
        }

        // Find decryptor calls that use XOR results
        for (block_idx, block) in ssa.iter_blocks() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let Some((call_target, call)) = instr.op().method_call() else {
                    continue;
                };
                let (args, Some(dest)) = (&call.args, call.dest) else {
                    continue;
                };

                // Resolve MethodSpec to MethodDef for generic method calls
                // Generic decryptors like T Get<T>(int32) are called via MethodSpec tokens
                let resolved_target =
                    resolve_method_spec_to_def(assembly, call_target).unwrap_or(call_target);

                // Check if this is a decryptor call
                if !decryptor_tokens.contains(&resolved_target) {
                    continue;
                }

                if args.len() != 1 {
                    continue;
                }

                // Check if argument comes from XOR, possibly through a
                // conversion (conv.i4, conv.u4) that the SSA builder may insert.
                let Some(&first_arg) = args.first() else {
                    continue;
                };
                let arg_def = ssa.get_definition(first_arg);
                let xor_def = match arg_def {
                    Some(SsaOp::Xor { .. }) => arg_def,
                    Some(
                        SsaOp::IntConv { operand, .. }
                        | SsaOp::IntToPtr { operand, .. }
                        | SsaOp::PtrToInt { operand, .. }
                        | SsaOp::IntToFloat { operand, .. }
                        | SsaOp::FloatToInt { operand, .. }
                        | SsaOp::FloatConv { operand, .. },
                    ) => ssa.get_definition(*operand),
                    _ => None,
                };
                let Some(SsaOp::Xor { left, right, .. }) = xor_def else {
                    continue;
                };

                // Determine which XOR operand is from state update (CFGCtx.Next())
                let (state_var, encoded_var, feeding_idx) =
                    if let Some(&idx) = next_info_map.get(left) {
                        (*left, *right, idx)
                    } else if let Some(&idx) = next_info_map.get(right) {
                        (*right, *left, idx)
                    } else {
                        continue;
                    };

                call_sites.push(StateMachineCallSite {
                    block_idx,
                    instr_idx,
                    instr_id: ssa
                        .block(block_idx)
                        .and_then(|block| block.instructions().get(instr_idx))
                        .and_then(SsaInstruction::id),
                    dest,
                    decryptor: resolved_target,
                    call_target,
                    state_var,
                    encoded_var,
                    feeding_update_idx: feeding_idx,
                });
            }
        }

        call_sites
    }

    fn collect_updates_for_call(
        &self,
        call_site: &StateMachineCallSite,
        all_updates: &[StateUpdateCall],
        cfg_info: &CfgInfo<'_>,
        seed_block: Option<usize>,
    ) -> Vec<usize> {
        let Some(feeding_update) = all_updates.get(call_site.feeding_update_idx) else {
            return Vec::new();
        };

        let target_block = feeding_update.block_idx;
        if target_block >= cfg_info.node_count {
            return Vec::new();
        }

        // Group state update calls by block, sorted by instruction index
        let mut updates_by_block: HashMap<usize, Vec<usize>> = HashMap::new();
        for (idx, update) in all_updates.iter().enumerate() {
            updates_by_block
                .entry(update.block_idx)
                .or_default()
                .push(idx);
        }
        for indices in updates_by_block.values_mut() {
            indices.sort_by_key(|&idx| {
                all_updates
                    .get(idx)
                    .map(|u| u.instr_idx)
                    .unwrap_or(usize::MAX)
            });
        }

        // Find a path from entry to the feeding update's block.
        //
        // ConfuserEx's KeySequence.ComputeKeys() uses a max-propagation fixpoint
        // that ensures all paths to a merge point produce the same CFGCtx state.
        // Therefore ANY single complete path from entry to the target block yields
        // the correct update sequence. We use backward BFS to find such a path.
        let path = find_path_to_block(cfg_info, target_block);

        // Map block → position on path (for execution-order sorting)
        let block_position: HashMap<usize, usize> = path
            .iter()
            .enumerate()
            .map(|(pos, &block)| (block, pos))
            .collect();

        // Determine the minimum path position for seed-block filtering.
        // Updates before the seed's position on the path are irrelevant because
        // the seed reinitializes the state machine. We use path position (not
        // block index) because SSA block indices don't reflect execution order.
        let seed_path_pos = seed_block.and_then(|sb| block_position.get(&sb).copied());

        // Collect updates from blocks on the path, at or after the seed position
        let mut relevant_updates: Vec<usize> = Vec::new();
        for (&block_idx, update_indices) in &updates_by_block {
            let Some(&pos) = block_position.get(&block_idx) else {
                continue;
            };

            // Skip blocks before the seed's position on the path
            if let Some(seed_pos) = seed_path_pos {
                if pos < seed_pos {
                    continue;
                }
            }

            if block_idx == target_block {
                // Same block: only updates BEFORE the feeding update
                for &idx in update_indices {
                    if let Some(update) = all_updates.get(idx) {
                        if update.instr_idx < feeding_update.instr_idx {
                            relevant_updates.push(idx);
                        }
                    }
                }
            } else {
                relevant_updates.extend(update_indices.iter().copied());
            }
        }

        // Sort by path position (entry first), then instruction index
        relevant_updates.sort_by_key(|&idx| {
            let Some(update) = all_updates.get(idx) else {
                return (usize::MAX, usize::MAX);
            };
            let pos = block_position
                .get(&update.block_idx)
                .copied()
                .unwrap_or(usize::MAX);
            (pos, update.instr_idx)
        });

        relevant_updates
    }
}

/// Finds a path from CFG entry to `target` via backward BFS through predecessors.
///
/// Returns block indices in forward order (entry first, target last).
/// BFS finds the shortest path, naturally avoiding loop back-edges.
///
/// ConfuserEx's `KeySequence.ComputeKeys()` ensures all paths to a merge
/// point produce the same CFGCtx state, so any single path is correct.
fn find_path_to_block(cfg_info: &CfgInfo<'_>, target: usize) -> Vec<usize> {
    let entry = cfg_info.entry.index();
    if target == entry {
        return vec![entry];
    }

    // Backward BFS from target to entry.
    // parent[block] = the child block that discovered it (one step toward target).
    let mut parent: HashMap<usize, usize> = HashMap::new();
    parent.insert(target, usize::MAX);
    let mut queue = VecDeque::new();
    queue.push_back(target);

    let mut found = false;
    while let Some(block) = queue.pop_front() {
        if block == entry {
            found = true;
            break;
        }
        let Some(preds) = cfg_info.predecessors.get(block) else {
            continue;
        };
        for &pred in preds {
            if let Entry::Vacant(e) = parent.entry(pred) {
                e.insert(block);
                queue.push_back(pred);
            }
        }
    }

    if !found {
        // Fallback for exception handler blocks that lack normal CFG predecessor
        // edges: walk the dominator tree from target to entry.
        let mut path = vec![target];
        let mut current = target;
        let mut visited = HashSet::new();
        visited.insert(target);
        while current != entry {
            if current >= cfg_info.node_count {
                break;
            }
            match cfg_info.dom_tree.immediate_dominator(NodeId::new(current)) {
                Some(idom) if visited.insert(idom.index()) => {
                    path.push(idom.index());
                    current = idom.index();
                }
                _ => break,
            }
        }
        path.reverse();
        return path;
    }

    // Reconstruct forward path: entry → ... → target
    let mut path = Vec::new();
    let mut current = entry;
    loop {
        path.push(current);
        if current == target {
            break;
        }
        match parent.get(&current) {
            Some(&child) if child != usize::MAX => current = child,
            _ => break,
        }
    }
    path
}

/// Detects CFGCtx state machine semantics from the assembly.
///
/// This function fully analyzes the CFGCtx value type to extract:
/// - The type token
/// - The constructor and its multiplier
/// - The Next method and its slot operations
pub fn detect_cfgctx_semantics(assembly: &CilObject) -> Option<StateMachineSemantics> {
    // First, try nested types inside <Module> (ConfuserEx sometimes nests CFGCtx there)
    if let Some(module_type) = assembly.types().module_type() {
        for (_, nested_ref) in module_type.nested_types.iter() {
            let nested_type = nested_ref.upgrade()?;
            if let Some(semantics) = try_detect_cfgctx_from_type(assembly, &nested_type) {
                return Some(semantics);
            }
        }
    }

    // If not found in <Module>, scan all top-level types in the assembly
    // ConfuserEx can inject CFGCtx as a top-level type
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        // Skip types with ASCII names (CFGCtx has obfuscated names)
        if cil_type.name.is_ascii() && !cil_type.name.is_empty() {
            continue;
        }

        // Check if this type could be CFGCtx
        if let Some(semantics) = try_detect_cfgctx_from_type(assembly, cil_type) {
            return Some(semantics);
        }
    }

    None
}

/// Attempts to detect CFGCtx from a type definition.
///
/// CFGCtx characteristics:
/// - Value type (struct) with exactly 4 fields (A, B, C, D)
/// - Constructor with multiplicative chain initialization
/// - Next method with signature (byte, uint) -> uint
fn try_detect_cfgctx_from_type(
    assembly: &CilObject,
    cil_type: &CilType,
) -> Option<StateMachineSemantics> {
    // CFGCtx is a value type (struct) with uint fields
    if !cil_type.is_value_type() {
        return None;
    }

    // Must have exactly 4 fields (A, B, C, D)
    if cil_type.fields.count() != 4 {
        return None;
    }

    // Look for constructor and Next method
    let mut ctor_token: Option<Token> = None;
    let mut next_token: Option<Token> = None;
    let mut multiplier: Option<u32> = None;

    for method in &cil_type.query_methods() {
        if method.is_ctor() && ctor_token.is_none() {
            // Found constructor - extract multiplier using SSA dataflow analysis
            if let Ok(ssa) = method.ssa(assembly) {
                if let Some(mult) = extract_multiplier_from_ssa(&ssa) {
                    multiplier = Some(mult);
                    ctor_token = Some(method.token);
                }
            }
        } else if next_token.is_none() {
            // Check for Next-like method - may have obfuscated name
            // Look for signature with 2 params (byte, uint) that returns uint
            let sig = &method.signature;
            if sig.params.len() == 2 && method.name != ".ctor" {
                // Use SSA to look for characteristic patterns (switch, field stores/loads)
                if let Ok(ssa) = method.ssa(assembly) {
                    let mut has_switch = false;
                    let mut has_stfld = false;
                    let mut has_ldfld = false;

                    for (_, block) in ssa.iter_blocks() {
                        for instr in block.instructions() {
                            match instr.op() {
                                SsaOp::Switch { .. } => has_switch = true,
                                SsaOp::StoreField { .. } => has_stfld = true,
                                SsaOp::LoadField { .. } => has_ldfld = true,
                                _ => {}
                            }
                        }
                    }

                    if has_switch && has_stfld && has_ldfld {
                        next_token = Some(method.token);
                    }
                }
            }
        }
    }

    // Need both ctor (with multiplier) and Next method
    let (Some(init_method), Some(update_method), Some(mult)) = (ctor_token, next_token, multiplier)
    else {
        return None;
    };

    // Collect field tokens in order (for mapping stfld targets to slot indices)
    let field_tokens: Vec<Token> = (0..cil_type.fields.count())
        .filter_map(|i| cil_type.fields.get(i))
        .map(|f| f.token)
        .collect();

    // Extract slot operations from the Next method by analyzing its IL
    // This must succeed for CFGCtx to be usable
    let slot_ops = extract_slot_operations(assembly, update_method, &field_tokens)?;

    Some(StateMachineSemantics {
        type_token: Some(cil_type.token),
        init_method: Some(init_method),
        update_method: Some(update_method),
        slot_count: 4,
        slot_ops,
        init_ops: vec![
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
            StateSlotOperation::mul(),
        ],
        init_constant: Some(u64::from(mult)),
        explicit_flag_bit: 7,
        update_slot_mask: 0x03,
        get_slot_mask: 0x03,
        get_slot_shift: 2,
    })
}

/// Extracts the multiplier constant from a CFGCtx constructor using SSA analysis.
///
/// The constructor initializes fields with a multiplicative chain:
/// ```text
/// A = seed *= MULTIPLIER
/// B = seed *= MULTIPLIER
/// C = seed *= MULTIPLIER
/// D = seed *= MULTIPLIER
/// ```
fn extract_multiplier_from_ssa(ssa: &SsaFunction) -> Option<u32> {
    for (_, block) in ssa.iter_blocks() {
        for instr in block.instructions() {
            // Look for Mul operations
            let (left, right) = match instr.op() {
                SsaOp::Mul { left, right, .. } | SsaOp::MulOvf { left, right, .. } => {
                    (*left, *right)
                }
                _ => continue,
            };

            // Check if either operand is a constant that looks like a multiplier
            for operand in [left, right] {
                if let Some(mult) = get_i32_constant(ssa, operand) {
                    // Filter out small constants (unlikely to be the multiplier)
                    // The ConfuserEx default is 0x21412321
                    if mult != 0 && mult.abs() > 0x1000 {
                        #[allow(clippy::cast_sign_loss)]
                        return Some(mult as u32);
                    }
                }
            }
        }
    }

    None
}

/// Extracts slot operations from the CFGCtx.Next method using SSA dataflow analysis.
///
/// The Next method has switch cases for each slot:
/// - Case 0: A ^= value (XOR)
/// - Case 1: B += value (ADD)
/// - Case 2: C ^= value (XOR)
/// - Case 3: D -= value (SUB)
///
/// This function uses SSA-based backward tracing from StoreField operations to find
/// the arithmetic operation that produces the stored value.
fn extract_slot_operations(
    assembly: &CilObject,
    next_method: Token,
    field_tokens: &[Token],
) -> Option<Vec<StateSlotOperation>> {
    let method = assembly.method(&next_method).ok()?;

    // Build SSA for the method - this gives us proper data flow analysis
    let ssa = method.ssa(assembly).ok()?;

    let mut ops_found: Vec<(usize, StateSlotOperation)> = Vec::new();

    // Find all StoreField operations and trace backward to find the arithmetic op
    for (_, block) in ssa.iter_blocks() {
        for instr in block.instructions() {
            // Look for StoreField (stfld) operations
            let (field_token, value_var) = match instr.op() {
                SsaOp::StoreField { field, value, .. } => (field.token(), *value),
                _ => continue,
            };

            // Map field to slot index
            let Some(slot_idx) = field_tokens.iter().position(|t| *t == field_token) else {
                continue;
            };

            // Trace backward from the stored value to find the operation
            if let Some(slot_op) = trace_to_arithmetic_op(&ssa, value_var) {
                ops_found.push((slot_idx, slot_op));
            }
        }
    }

    // Sort by slot index and deduplicate (take first occurrence for each slot)
    ops_found.sort_by_key(|(idx, _)| *idx);
    ops_found.dedup_by_key(|(idx, _)| *idx);

    // Must have exactly 4 operations in order to be valid
    if ops_found.len() == 4 && ops_found.iter().enumerate().all(|(i, (idx, _))| *idx == i) {
        return Some(ops_found.into_iter().map(|(_, op)| op).collect());
    }

    // Detection failed - return None instead of using defaults
    None
}

/// Traces backward from an SSA variable to find the arithmetic operation that produces it.
///
/// Uses an iterative worklist algorithm instead of recursion to avoid stack overflow
/// on deeply nested or cyclic graphs.
fn trace_to_arithmetic_op(ssa: &SsaFunction, start_var: SsaVarId) -> Option<StateSlotOperation> {
    // Worklist of variables to examine
    let mut worklist = vec![start_var];
    // Track visited variables to prevent infinite loops
    let mut visited: HashSet<SsaVarId> = HashSet::new();

    while let Some(var) = worklist.pop() {
        // Skip if already visited (handles cycles)
        if !visited.insert(var) {
            continue;
        }

        // Get the definition of this variable
        let Some(def) = ssa.get_definition(var) else {
            continue;
        };

        match def {
            // Direct arithmetic operations - found what we're looking for
            SsaOp::Xor { .. } => return Some(StateSlotOperation::xor()),
            SsaOp::Add { .. } | SsaOp::AddOvf { .. } => return Some(StateSlotOperation::add()),
            SsaOp::Sub { .. } | SsaOp::SubOvf { .. } => return Some(StateSlotOperation::sub()),
            SsaOp::Mul { .. } | SsaOp::MulOvf { .. } => return Some(StateSlotOperation::mul()),
            SsaOp::And { .. } => return Some(StateSlotOperation::and()),
            SsaOp::Or { .. } => return Some(StateSlotOperation::or()),

            // Conversion - add operand to worklist to trace through
            SsaOp::IntConv { operand, .. }
            | SsaOp::IntToPtr { operand, .. }
            | SsaOp::PtrToInt { operand, .. }
            | SsaOp::IntToFloat { operand, .. }
            | SsaOp::FloatToInt { operand, .. }
            | SsaOp::FloatConv { operand, .. } => {
                worklist.push(*operand);
            }

            // Other operations - check if this is a PHI result
            _ => {
                // Look for PHI nodes that define this variable
                for (_, block) in ssa.iter_blocks() {
                    for phi in block.phi_nodes() {
                        if phi.result() == var {
                            // Add first operand to worklist
                            // (all operands should have same operation in well-formed CFGCtx)
                            if let Some(operand) = phi.operands().first() {
                                worklist.push(operand.value());
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Finds the constants Initialize() method that should be used for warmup.
///
/// ConfuserEx injects a separate `Initialize()` method into `<Module>` that performs
/// the expensive one-time initialization (LZMA decompression of the constants buffer).
/// This method is called from `.cctor`, but running the full `.cctor` also executes
/// anti-tamper/anti-debug code which can fail during emulation.
///
/// By finding and running `Initialize()` directly, we skip the protection code while
/// still initializing the decryptor state.
pub fn find_constants_initializer(assembly: &CilObject) -> Option<Token> {
    let module_type = assembly.types().module_type()?;

    // Get .cctor to find what methods it calls first
    let cctor_token = assembly.types().module_cctor()?;
    let cctor = assembly.method(&cctor_token).ok()?;

    // Look at ALL call instructions in .cctor
    // ConfuserEx injects multiple calls: anti-tamper, constants, anti-debug, etc.
    let mut init_candidates: Vec<Token> = Vec::new();

    for instr in cctor.instructions() {
        if instr.flow_type == FlowType::Call {
            if let Operand::Token(call_target) = &instr.operand {
                // Check if this is a MethodDef (not MemberRef to external)
                if call_target.is_table(TableId::MethodDef) {
                    init_candidates.push(*call_target);
                }
            }
        }
    }

    // Now check each candidate to see if it matches Initialize() pattern
    for candidate in init_candidates {
        let Ok(method) = assembly.method(&candidate) else {
            continue;
        };

        // Must be static
        if !method.is_static() {
            continue;
        }

        // Must be void with no parameters
        let sig = &method.signature;
        if sig.return_type.base != TypeSignature::Void || !sig.params.is_empty() {
            continue;
        }

        // Must be in <Module>
        let is_in_module = method
            .declaring_type_rc()
            .is_some_and(|t| t.is_module_type());

        if !is_in_module {
            continue;
        }

        // Check if it looks like an initializer:
        // - Contains ldsfld/stsfld to byte[] field
        // - Contains call to some decompression method
        // - Contains array allocation
        let mut has_array_ops = false;
        let mut has_field_store = false;

        for instr in method.instructions() {
            match instr.mnemonic {
                "newarr" | "newobj" => has_array_ops = true,
                "stsfld" => has_field_store = true,
                _ => {}
            }
        }

        // If it has array ops and stores to a static field, it's likely the initializer
        if has_array_ops && has_field_store {
            return Some(candidate);
        }
    }

    // Fallback: look for methods in <Module> that match the pattern without .cctor hint
    for method in &module_type.query_methods() {
        // Skip .cctor itself
        if method.is_cctor() {
            continue;
        }

        // Must be static void with no params
        if !method.flags_modifiers.contains(MethodModifiers::STATIC) {
            continue;
        }
        let sig = &method.signature;
        if sig.return_type.base != TypeSignature::Void || !sig.params.is_empty() {
            continue;
        }

        // Check for LZMA-related call pattern or Decompress in name
        for instr in method.instructions() {
            if instr.flow_type == FlowType::Call {
                if let Operand::Token(call_target) = &instr.operand {
                    // Check if calling a method with "Decompress" in name
                    if let Ok(callee) = assembly.method(call_target) {
                        if callee.name.contains("Decompress") || callee.name.contains("LZMA") {
                            return Some(method.token);
                        }
                    }
                    // Check MemberRef too
                    if let Some(memberref) = assembly.member_ref(call_target) {
                        if memberref.name.contains("Decompress") || memberref.name.contains("LZMA")
                        {
                            return Some(method.token);
                        }
                    }
                }
            }
        }
    }

    None
}

/// Finds all call sites to the specified decryptor methods using SSA dataflow analysis.
///
/// Uses proper SSA-based backward tracing to find argument values, handling:
/// - Direct constants (Normal mode)
/// - XOR results where one operand is a constant (CFG mode)
/// - Values traced through PHI nodes and other operations
pub fn find_call_sites(
    assembly: &CilObject,
    decryptor_tokens: &[Token],
    budget: &WorkBudget,
) -> Vec<DetectedCallSite> {
    let decryptor_set: HashSet<_> = decryptor_tokens.iter().copied().collect();
    let call_sites: boxcar::Vec<DetectedCallSite> = boxcar::Vec::new();

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Skip the decryptor methods themselves
        if decryptor_set.contains(&method.token) {
            continue;
        }

        // Build SSA for the method
        let Ok(ssa) = method.ssa(assembly) else {
            continue;
        };

        // Find call instructions to decryptors
        for (_, block) in ssa.iter_blocks() {
            for instr in block.instructions() {
                // Look for calls of decryptors
                let Some((call_target, call)) = instr.op().method_call() else {
                    continue;
                };
                let args = &call.args;

                // Resolve MethodSpec to MethodDef if needed (for generic method calls)
                let resolved_target =
                    resolve_method_spec_to_def(assembly, call_target).unwrap_or(call_target);

                if !decryptor_set.contains(&resolved_target) {
                    continue;
                }

                // Decryptors take a single int32 argument
                let Some(&arg_var) = args.first() else {
                    continue;
                };

                // Use backward taint analysis to trace the argument's data flow
                match analyze_argument_dataflow(&ssa, arg_var, budget) {
                    ArgumentAnalysis::DirectConstant(_) => {
                        // Normal mode: direct constant key
                        call_sites.push(DetectedCallSite::direct(method.token));
                    }
                    ArgumentAnalysis::XorWithConstant(_) => {
                        // CFG mode pattern: XOR with constant (no call in slice)
                        call_sites.push(DetectedCallSite::statemachine(method.token));
                    }
                    ArgumentAnalysis::FlowsThroughCall { constant } => {
                        // CFG mode: value depends on call result (likely CFGCtx.Next)
                        if constant.is_some() {
                            call_sites.push(DetectedCallSite::statemachine(method.token));
                        }
                        // If no constant found, we can't classify
                    }
                    ArgumentAnalysis::Unknown => {
                        // Cannot determine mode statically - assume direct
                        call_sites.push(DetectedCallSite::direct(method.token));
                    }
                }
            }
        }
    }

    call_sites.into_iter().collect()
}

/// Resolves a MethodSpec token to its underlying MethodDef token.
///
/// MethodSpec tokens (table 0x2B) are used for generic method instantiations.
/// Returns `None` if the token is not a MethodSpec or if the underlying
/// method is a MemberRef (external method).
fn resolve_method_spec_to_def(assembly: &CilObject, token: Token) -> Option<Token> {
    if token.table() != 0x2B {
        return None; // Not a MethodSpec
    }

    let method_spec = assembly.method_spec(&token).ok()?;
    let method_token = method_spec.method.token()?;

    // Only return if it's a MethodDef (0x06), not a MemberRef
    if method_token.is_table(TableId::MethodDef) {
        Some(method_token)
    } else {
        None
    }
}

/// Result of analyzing a decryptor call argument using backward taint analysis.
enum ArgumentAnalysis {
    /// Direct constant value (Normal mode) - the actual decryption key.
    DirectConstant(i32),
    /// Value computed via XOR with a constant (CFG mode).
    XorWithConstant(i32),
    /// Value flows through a call (potentially CFGCtx.Next or other method).
    FlowsThroughCall { constant: Option<i32> },
    /// Cannot determine the value statically.
    Unknown,
}

/// Analyzes a decryptor call argument using backward taint analysis.
///
/// Uses proper SSA-based dataflow analysis to trace all operations
/// contributing to the argument value. This is robust against control
/// flow flattening and other obfuscations.
fn analyze_argument_dataflow(
    ssa: &SsaFunction,
    arg_var: SsaVarId,
    budget: &WorkBudget,
) -> ArgumentAnalysis {
    // Quick check: if it's already a constant, we're done
    if let Some(key) = get_i32_constant(ssa, arg_var) {
        return ArgumentAnalysis::DirectConstant(key);
    }

    // Set up backward taint analysis
    let config = TaintConfig {
        forward: false,
        backward: true,
        phi_mode: PhiTaintMode::TaintAllOperands,
    };

    let mut taint = TaintAnalysis::new(config, budget);
    taint.add_tainted_var(arg_var);
    taint.propagate(ssa);

    // Collect all tainted operations for analysis
    let mut has_xor_with_const = None;
    let mut has_call = false;
    let mut call_const = None;

    // Examine all tainted variables and their definitions
    for var in taint.tainted_variables() {
        let Some(def) = ssa.get_definition(*var) else {
            continue;
        };

        match def {
            // Found an XOR - check if one operand is a constant
            SsaOp::Xor { left, right, .. } => {
                if let Some(c) = get_i32_constant(ssa, *left) {
                    has_xor_with_const = Some(c);
                } else if let Some(c) = get_i32_constant(ssa, *right) {
                    has_xor_with_const = Some(c);
                }
            }

            // Found a call - this indicates state machine or other method dependency
            op if op.method_call().is_some() => {
                has_call = true;
                // If we already found a constant in an XOR, preserve it
                if has_xor_with_const.is_some() {
                    call_const = has_xor_with_const;
                }
            }

            _ => {}
        }
    }

    // Classify based on what we found
    if has_call {
        // CFG mode: value depends on a call result (likely CFGCtx.Next)
        ArgumentAnalysis::FlowsThroughCall {
            constant: call_const.or(has_xor_with_const),
        }
    } else if let Some(constant) = has_xor_with_const {
        // XOR with constant but no call - still CFG-like pattern
        ArgumentAnalysis::XorWithConstant(constant)
    } else {
        ArgumentAnalysis::Unknown
    }
}

/// Gets the i32-equivalent constant value of an SSA variable.
///
/// Strategy for maximum coverage:
/// 1. `as_i32()` - handles I8, I16, I32, U8, U16, bool (including negative values)
/// 2. `as_u64()` + truncate - handles U32, U64, NativeUInt (positive values only)
fn get_i32_constant(ssa: &SsaFunction, var: SsaVarId) -> Option<i32> {
    let value = ssa
        .get_var_constant(var)
        .or_else(|| match ssa.get_definition(var) {
            Some(SsaOp::Const { value, .. }) => Some(value),
            _ => None,
        })?;

    // Try as_i32 first (handles signed types including negative values)
    // Then fall back to as_u64 + truncate (handles U32, U64, etc.)
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    value.as_i32().or_else(|| value.as_u64().map(|v| v as i32))
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::confuserex::statemachine::{
            detect_cfgctx_semantics, find_constants_initializer,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_cfgctx_on_cfg_sample() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_constants_cfg.exe");

        let semantics = detect_cfgctx_semantics(&assembly);
        assert!(
            semantics.is_some(),
            "CFG mode sample should have detectable CFGCtx semantics"
        );

        let semantics = semantics.unwrap();
        assert_eq!(semantics.slot_count, 4, "CFGCtx should have 4 slots");
        assert!(
            semantics.init_method.is_some(),
            "Should detect init method (constructor)"
        );
        assert!(
            semantics.update_method.is_some(),
            "Should detect update method (Next)"
        );
        assert!(semantics.type_token.is_some(), "Should detect type token");
    }

    #[test]
    fn test_detect_cfgctx_on_original() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let semantics = detect_cfgctx_semantics(&assembly);
        assert!(
            semantics.is_none(),
            "Original sample should not have CFGCtx semantics"
        );
    }

    #[test]
    fn test_find_constants_initializer_on_constants_sample() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_constants.exe");

        let init = find_constants_initializer(&assembly);
        assert!(
            init.is_some(),
            "Constants sample should have an initializer method"
        );
    }

    #[test]
    fn test_find_constants_initializer_on_original() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let init = find_constants_initializer(&assembly);
        assert!(
            init.is_none(),
            "Original sample should not have a constants initializer"
        );
    }
}
