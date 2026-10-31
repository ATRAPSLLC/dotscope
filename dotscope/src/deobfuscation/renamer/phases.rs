//! Method phase decomposition for semantic labeling.
//!
//! Decomposes SSA methods into semantic "phases" — contiguous regions of blocks
//! that share a common purpose (e.g., "load resource", "decrypt data", "write output").
//! Phase boundaries are detected using heuristics:
//!
//! - Namespace change in call targets (e.g., System.IO → System.Security)
//! - Back-edges (loop headers)
//! - Exception handler boundaries
//! - Transform regions (heavy bitwise/arithmetic with no external calls)

use std::collections::HashSet;

use crate::{
    analysis::{ConstValue, SsaFunction, SsaOp},
    deobfuscation::{
        renamer::{
            context::{OpcodeProfile, PhaseInfo},
            features,
        },
        utils::is_obfuscated_name,
    },
    utils::truncate_chars,
    CilObject,
};

/// Decomposes a method into semantic phases.
///
/// For small methods (≤ `small_threshold` instructions), returns
/// a single phase encompassing the whole method. For larger methods, segments
/// by call-target namespace changes, back-edges, exception handlers, and
/// transform regions.
///
/// # Arguments
///
/// * `ssa` - The SSA function to decompose.
/// * `assembly` - The assembly for metadata resolution.
/// * `small_threshold` - Methods with this many instructions or fewer get
///   a single phase instead of full decomposition.
///
/// # Returns
///
/// A list of [`PhaseInfo`] entries, each representing a contiguous segment.
pub fn decompose_method(
    ssa: &SsaFunction,
    assembly: &CilObject,
    small_threshold: usize,
) -> Vec<PhaseInfo> {
    let block_count = ssa.blocks().len();
    if block_count == 0 {
        return Vec::new();
    }

    let total_instructions = ssa.instruction_count();
    if total_instructions <= small_threshold {
        // Small method: single phase with all features
        let call_targets = features::collect_call_targets(ssa, assembly);
        let profile = features::build_opcode_profile(ssa);
        return vec![PhaseInfo {
            label: String::new(), // To be filled by LLM
            call_targets,
            opcode_profile: Some(profile),
            structure: Some("linear".to_string()),
        }];
    }

    // Identify phase boundaries
    let (boundaries, loop_headers) = find_phase_boundaries(ssa, assembly);

    // Build phases from boundary ranges
    build_phases_from_boundaries(ssa, assembly, &boundaries, &loop_headers)
}

/// Builds a C#-like pseudocode skeleton for small methods.
///
/// Walks the SSA instructions and produces a simplified representation:
/// - External call targets are preserved as-is (e.g., `File.WriteAllText(...)`)
/// - Obfuscated identifiers use placeholders (`var_0`, `param_1`, `field_0`)
/// - Only call/field/string instructions are included (skip arithmetic etc.)
///
/// # Arguments
///
/// * `ssa` - The SSA function to build the skeleton from.
/// * `assembly` - The assembly for resolving names.
///
/// # Returns
///
/// A pseudocode string, or `None` if no meaningful operations are found.
pub fn build_call_site_skeleton(ssa: &SsaFunction, assembly: &CilObject) -> Option<String> {
    let mut lines = Vec::new();

    for (_block_idx, _instr_idx, instr) in ssa.iter_instructions() {
        match instr.op() {
            SsaOp::Call { method, args, .. } | SsaOp::CallVirt { method, args, .. } => {
                let name = assembly
                    .resolve_method_name(method.token())
                    .unwrap_or_else(|| format!("method_0x{:08X}", method.token().value()));
                let arg_list: Vec<String> = args
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("var_{i}"))
                    .collect();
                lines.push(format!("    {name}({});", arg_list.join(", ")));
            }
            SsaOp::NewObj { ctor, args, .. } => {
                let name = assembly
                    .resolve_method_name(ctor.token())
                    .unwrap_or_else(|| "Type_0".to_string());
                let arg_list: Vec<String> = args
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("var_{i}"))
                    .collect();
                lines.push(format!("    new {name}({});", arg_list.join(", ")));
            }
            SsaOp::LoadField {
                dest,
                object,
                field,
            } => {
                let name = assembly
                    .resolve_method_name(field.token())
                    .unwrap_or_else(|| format!("field_0x{:08X}", field.token().value()));
                lines.push(format!(
                    "    var_{} = var_{}.{name};",
                    dest.index(),
                    object.index()
                ));
            }
            SsaOp::StoreField {
                object,
                field,
                value,
            } => {
                let name = assembly
                    .resolve_method_name(field.token())
                    .unwrap_or_else(|| format!("field_0x{:08X}", field.token().value()));
                lines.push(format!(
                    "    var_{}.{name} = var_{};",
                    object.index(),
                    value.index()
                ));
            }
            SsaOp::LoadStaticField { dest, field, .. } => {
                let name = assembly
                    .resolve_method_name(field.token())
                    .unwrap_or_else(|| format!("field_0x{:08X}", field.token().value()));
                lines.push(format!("    var_{} = {name};", dest.index()));
            }
            SsaOp::StoreStaticField { field, value, .. } => {
                let name = assembly
                    .resolve_method_name(field.token())
                    .unwrap_or_else(|| format!("field_0x{:08X}", field.token().value()));
                lines.push(format!("    {name} = var_{};", value.index()));
            }

            // Arithmetic
            SsaOp::Add {
                dest, left, right, ..
            }
            | SsaOp::AddOvf {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} + var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Sub {
                dest, left, right, ..
            }
            | SsaOp::SubOvf {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} - var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Mul {
                dest, left, right, ..
            }
            | SsaOp::MulOvf {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} * var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Div {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} / var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Rem {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} % var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Neg { dest, operand, .. } => {
                lines.push(format!(
                    "    var_{} = -var_{};",
                    dest.index(),
                    operand.index()
                ));
            }

            // Bitwise
            SsaOp::And {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} & var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Or {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} | var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Xor {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} ^ var_{};",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Not { dest, operand, .. } => {
                lines.push(format!(
                    "    var_{} = ~var_{};",
                    dest.index(),
                    operand.index()
                ));
            }
            SsaOp::Shl {
                dest,
                value,
                amount,
                ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} << var_{};",
                    dest.index(),
                    value.index(),
                    amount.index()
                ));
            }
            SsaOp::Shr {
                dest,
                value,
                amount,
                ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{} >> var_{};",
                    dest.index(),
                    value.index(),
                    amount.index()
                ));
            }

            // Comparison
            SsaOp::Ceq { dest, left, right } => {
                lines.push(format!(
                    "    var_{} = (var_{} == var_{});",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Clt {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = (var_{} < var_{});",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }
            SsaOp::Cgt {
                dest, left, right, ..
            } => {
                lines.push(format!(
                    "    var_{} = (var_{} > var_{});",
                    dest.index(),
                    left.index(),
                    right.index()
                ));
            }

            // Conversion
            SsaOp::IntConv {
                dest,
                operand,
                target,
                ..
            }
            | SsaOp::IntToPtr {
                dest,
                operand,
                target,
            }
            | SsaOp::PtrToInt {
                dest,
                operand,
                target,
            }
            | SsaOp::IntToFloat {
                dest,
                operand,
                target,
                ..
            }
            | SsaOp::FloatToInt {
                dest,
                operand,
                target,
                ..
            }
            | SsaOp::FloatConv {
                dest,
                operand,
                target,
                ..
            } => {
                lines.push(format!(
                    "    var_{} = ({target})var_{};",
                    dest.index(),
                    operand.index()
                ));
            }

            // Array operations
            SsaOp::NewArr { dest, length, .. } => {
                lines.push(format!(
                    "    var_{} = new array[var_{}];",
                    dest.index(),
                    length.index()
                ));
            }
            SsaOp::LoadElement {
                dest, array, index, ..
            } => {
                lines.push(format!(
                    "    var_{} = var_{}[var_{}];",
                    dest.index(),
                    array.index(),
                    index.index()
                ));
            }
            SsaOp::StoreElement {
                array,
                index,
                value,
                ..
            } => {
                lines.push(format!(
                    "    var_{}[var_{}] = var_{};",
                    array.index(),
                    index.index(),
                    value.index()
                ));
            }
            SsaOp::ArrayLength { dest, array } => {
                lines.push(format!(
                    "    var_{} = var_{}.Length;",
                    dest.index(),
                    array.index()
                ));
            }

            // String constants (both ldstr and decrypted)
            SsaOp::Const {
                value: ConstValue::DecryptedString(s),
                ..
            } => {
                let truncated = if s.chars().count() > 30 {
                    format!("\"{}...\"", truncate_chars(s, 27))
                } else {
                    format!("\"{s}\"")
                };
                lines.push(format!("    // string: {truncated}"));
            }
            SsaOp::Const {
                value: ConstValue::String(idx),
                ..
            } => {
                if let Some(us) = assembly.userstrings() {
                    if let Ok(s) = us.get(*idx as usize) {
                        if let Ok(decoded) = s.to_string() {
                            if !decoded.is_empty() {
                                let truncated = if decoded.chars().count() > 30 {
                                    format!("\"{}...\"", truncate_chars(&decoded, 27))
                                } else {
                                    format!("\"{decoded}\"")
                                };
                                lines.push(format!("    // string: {truncated}"));
                            }
                        }
                    }
                }
            }

            // Return with value
            SsaOp::Return { value: Some(v) } => {
                lines.push(format!("    return var_{};", v.index()));
            }
            SsaOp::Return { value: None } => {
                lines.push("    return;".to_string());
            }
            _ => {}
        }
    }

    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

/// Identifies block indices where phase boundaries should be placed.
///
/// Combines multiple heuristics to detect semantically meaningful
/// boundaries: exception handler entries, loop headers (back-edges),
/// namespace changes in call targets, and transform regions.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
/// * `assembly` - The assembly for method name resolution.
///
/// # Returns
///
/// A tuple of `(sorted_boundaries, loop_headers)` where `loop_headers`
/// contains block indices that are back-edge targets (loop entry points).
fn find_phase_boundaries(ssa: &SsaFunction, assembly: &CilObject) -> (Vec<usize>, HashSet<usize>) {
    let blocks = ssa.blocks();
    let block_count = blocks.len();
    let mut boundaries: HashSet<usize> = HashSet::new();
    let mut loop_headers: HashSet<usize> = HashSet::new();

    // Always start at block 0
    boundaries.insert(0);

    // Exception handler entries are phase boundaries
    for handler in ssa.exception_handlers() {
        if let Some(handler_start) = handler.handler_range.map(|range| range.start()) {
            boundaries.insert(handler_start);
        }
        if let Some(try_start) = handler.protected_range.map(|range| range.start()) {
            boundaries.insert(try_start);
        }
    }

    // Detect back-edges (loop headers)
    let mut visited = vec![false; block_count];
    let mut in_stack = vec![false; block_count];
    detect_back_edges(ssa, 0, &mut visited, &mut in_stack, &mut loop_headers);
    boundaries.extend(&loop_headers);

    // Detect namespace changes in call targets
    let mut prev_namespace: Option<String> = None;
    for (block_idx, block) in blocks.iter().enumerate() {
        for instr in block.instructions() {
            if let SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } = instr.op() {
                if let Some(name) = assembly.resolve_method_name(method.token()) {
                    let ns = extract_namespace(&name);
                    if let Some(ref prev) = prev_namespace {
                        if ns != *prev {
                            boundaries.insert(block_idx);
                        }
                    }
                    prev_namespace = Some(ns);
                }
            }
        }
    }

    // Detect transform regions (bitwise-heavy blocks with no external calls)
    detect_transform_boundaries(ssa, &mut boundaries);

    let mut sorted: Vec<usize> = boundaries.into_iter().collect();
    sorted.sort_unstable();
    (sorted, loop_headers)
}

/// Builds [`PhaseInfo`] entries from boundary block indices.
///
/// Each boundary starts a new phase that extends to the next boundary
/// (or the end of the method). Classifies each phase's structure as
/// "try/catch", "loop", "transform", "conditional", or "linear".
///
/// # Arguments
///
/// * `ssa` - The SSA function containing the blocks.
/// * `assembly` - The assembly for resolving call target names.
/// * `boundaries` - Sorted block indices marking phase starts.
/// * `loop_headers` - Block indices that are back-edge targets (loop entry points).
///
/// # Returns
///
/// A vector of [`PhaseInfo`] entries with call targets and opcode profiles.
fn build_phases_from_boundaries(
    ssa: &SsaFunction,
    assembly: &CilObject,
    boundaries: &[usize],
    loop_headers: &HashSet<usize>,
) -> Vec<PhaseInfo> {
    let blocks = ssa.blocks();
    let block_count = blocks.len();
    let mut phases = Vec::new();

    for (i, &start) in boundaries.iter().enumerate() {
        let end = boundaries
            .get(i.saturating_add(1))
            .copied()
            .unwrap_or(block_count);

        if start >= block_count {
            continue;
        }

        let mut call_targets = Vec::new();
        let mut call_seen = HashSet::new();
        let mut profile = OpcodeProfile::default();
        let mut structure = None;

        // Check if this range is an exception handler
        for handler in ssa.exception_handlers() {
            if handler.handler_range.map(|range| range.start()) == Some(start) {
                structure = Some("try/catch".to_string());
            }
        }

        // Check if this phase starts at a loop header (back-edge target)
        if structure.is_none() && loop_headers.contains(&start) {
            structure = Some("loop".to_string());
        }

        for (block_idx, block) in blocks
            .iter()
            .enumerate()
            .take(end.min(block_count))
            .skip(start)
        {
            for instr in block.instructions() {
                classify_op_into_profile(instr.op(), &mut profile);

                if let SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } = instr.op() {
                    if let Some(name) = assembly.resolve_method_name(method.token()) {
                        if !is_obfuscated_name(&name) && call_seen.insert(name.clone()) {
                            call_targets.push(name);
                        }
                    }
                }
            }

            // Detect loops via back-edges within this range
            if structure.is_none() {
                for succ in block.successors() {
                    if succ >= start && succ < end && succ <= block_idx {
                        structure = Some("loop".to_string());
                    }
                }
            }
        }

        // Classify as "transform" if heavy bitwise/arithmetic and no calls
        if structure.is_none() {
            if profile.calls == 0 && (profile.bitwise >= 3 || profile.arithmetic >= 3) {
                structure = Some("transform".to_string());
            } else if profile.comparison > 0 {
                structure = Some("conditional".to_string());
            } else {
                structure = Some("linear".to_string());
            }
        }

        phases.push(PhaseInfo {
            label: String::new(), // To be filled by LLM
            call_targets,
            opcode_profile: Some(profile),
            structure,
        });
    }

    phases
}

/// Detects loop headers via DFS back-edge classification.
///
/// Performs a depth-first traversal from `block_idx`, marking blocks
/// that are targets of back-edges (i.e., loop headers) as phase boundaries.
///
/// # Arguments
///
/// * `ssa` - The SSA function with block successors.
/// * `block_idx` - Current block in the DFS traversal.
/// * `visited` - Tracks which blocks have been visited.
/// * `in_stack` - Tracks which blocks are on the current DFS path.
/// * `boundaries` - Set of boundary block indices to populate.
fn detect_back_edges(
    ssa: &SsaFunction,
    block_idx: usize,
    visited: &mut [bool],
    in_stack: &mut [bool],
    boundaries: &mut HashSet<usize>,
) {
    let blocks = ssa.blocks();
    let Some(block) = blocks.get(block_idx) else {
        return;
    };
    if let Some(slot) = visited.get_mut(block_idx) {
        *slot = true;
    }
    if let Some(slot) = in_stack.get_mut(block_idx) {
        *slot = true;
    }

    let successors = block.successors();
    for succ in successors {
        if succ < visited.len() {
            if in_stack.get(succ).copied().unwrap_or(false) {
                // Back-edge found: succ is a loop header
                boundaries.insert(succ);
            } else if !visited.get(succ).copied().unwrap_or(true) {
                detect_back_edges(ssa, succ, visited, in_stack, boundaries);
            }
        }
    }

    if let Some(slot) = in_stack.get_mut(block_idx) {
        *slot = false;
    }
}

/// Detects contiguous blocks with heavy bitwise/arithmetic and no calls.
///
/// Identifies "transform regions" — sequences of 3+ blocks where each
/// block has at least 3 bitwise or arithmetic operations and no call
/// instructions. The start and end of such regions become phase boundaries.
///
/// # Arguments
///
/// * `ssa` - The SSA function to analyze.
/// * `boundaries` - Set of boundary block indices to populate.
fn detect_transform_boundaries(ssa: &SsaFunction, boundaries: &mut HashSet<usize>) {
    let blocks = ssa.blocks();
    let mut consecutive_transform: u32 = 0;

    for (block_idx, block) in blocks.iter().enumerate() {
        let mut has_calls = false;
        let mut bitwise_count: u32 = 0;
        let mut arithmetic_count: u32 = 0;

        for instr in block.instructions() {
            match instr.op() {
                SsaOp::Call { .. } | SsaOp::CallVirt { .. } | SsaOp::CallIndirect { .. } => {
                    has_calls = true;
                }
                SsaOp::And { .. }
                | SsaOp::Or { .. }
                | SsaOp::Xor { .. }
                | SsaOp::Not { .. }
                | SsaOp::Shl { .. }
                | SsaOp::Shr { .. } => {
                    bitwise_count = bitwise_count.saturating_add(1);
                }
                SsaOp::Add { .. }
                | SsaOp::Sub { .. }
                | SsaOp::Mul { .. }
                | SsaOp::Div { .. }
                | SsaOp::Rem { .. } => {
                    arithmetic_count = arithmetic_count.saturating_add(1);
                }
                _ => {}
            }
        }

        if !has_calls && bitwise_count.saturating_add(arithmetic_count) >= 3 {
            if consecutive_transform == 0 {
                // Start of transform region
                boundaries.insert(block_idx);
            }
            consecutive_transform = consecutive_transform.saturating_add(1);
        } else {
            if consecutive_transform >= 3 {
                // End of transform region, start new phase
                boundaries.insert(block_idx);
            }
            consecutive_transform = 0;
        }
    }
}

/// Classifies an SSA operation into the appropriate opcode profile bucket.
///
/// Increments the matching counter in `profile` based on the operation
/// kind (calls, strings, field I/O, bitwise, arithmetic, array,
/// comparison, or conversion).
///
/// # Arguments
///
/// * `op` - The SSA operation to classify.
/// * `profile` - The profile to update.
fn classify_op_into_profile(op: &SsaOp, profile: &mut OpcodeProfile) {
    match op {
        SsaOp::Call { .. } | SsaOp::CallVirt { .. } | SsaOp::CallIndirect { .. } => {
            profile.calls = profile.calls.saturating_add(1);
        }
        SsaOp::Const {
            value: ConstValue::String(_) | ConstValue::DecryptedString(_),
            ..
        } => {
            profile.strings = profile.strings.saturating_add(1);
        }
        SsaOp::LoadField { .. }
        | SsaOp::StoreField { .. }
        | SsaOp::LoadStaticField { .. }
        | SsaOp::StoreStaticField { .. } => {
            profile.field_io = profile.field_io.saturating_add(1);
        }
        SsaOp::And { .. }
        | SsaOp::Or { .. }
        | SsaOp::Xor { .. }
        | SsaOp::Not { .. }
        | SsaOp::Shl { .. }
        | SsaOp::Shr { .. } => {
            profile.bitwise = profile.bitwise.saturating_add(1);
        }
        SsaOp::Add { .. }
        | SsaOp::AddOvf { .. }
        | SsaOp::Sub { .. }
        | SsaOp::SubOvf { .. }
        | SsaOp::Mul { .. }
        | SsaOp::MulOvf { .. }
        | SsaOp::Div { .. }
        | SsaOp::Rem { .. }
        | SsaOp::Neg { .. } => {
            profile.arithmetic = profile.arithmetic.saturating_add(1);
        }
        SsaOp::NewArr { .. }
        | SsaOp::LoadElement { .. }
        | SsaOp::StoreElement { .. }
        | SsaOp::ArrayLength { .. } => {
            profile.array = profile.array.saturating_add(1);
        }
        SsaOp::Ceq { .. }
        | SsaOp::Clt { .. }
        | SsaOp::Cgt { .. }
        | SsaOp::Branch { .. }
        | SsaOp::BranchCmp { .. } => {
            profile.comparison = profile.comparison.saturating_add(1);
        }
        SsaOp::IntConv { .. }
        | SsaOp::IntToPtr { .. }
        | SsaOp::PtrToInt { .. }
        | SsaOp::IntToFloat { .. }
        | SsaOp::FloatToInt { .. }
        | SsaOp::FloatConv { .. } => {
            profile.conversion = profile.conversion.saturating_add(1);
        }
        _ => {}
    }
}

/// Extracts the namespace part from a qualified method name.
///
/// Given `"System.IO.File::ReadAllText"`, returns `"System.IO"`.
/// Given `"MyClass::DoWork"`, returns `"MyClass"`.
/// Given `"SimpleMethod"` (no qualifier), returns the input as-is.
///
/// # Arguments
///
/// * `method_name` - Qualified method name in `"Namespace.Type::Method"` format.
///
/// # Returns
///
/// The namespace portion of the name.
fn extract_namespace(method_name: &str) -> String {
    // `rsplit_once` rather than `rfind` + slice: the byte offsets from `rfind` are always
    // character boundaries so the slicing was sound, but expressing it this way keeps the
    // crate free of `str` range indexing and so needs no `clippy::string_slice` escape.
    let Some((type_part, _)) = method_name.rsplit_once("::") else {
        return method_name.to_string();
    };

    match type_part.rsplit_once('.') {
        Some((namespace, _)) => namespace.to_string(),
        None => type_part.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::renamer::phases::{
            build_call_site_skeleton, decompose_method, extract_namespace,
        },
        metadata::validation::ValidationConfig,
        testkit::fixture,
        CilObject,
    };

    const ORIGINAL_EXE: &str = "packers/confuserex/1.6.0/original.exe";

    /// Loads original.exe and builds SSA for a named method.
    fn load_and_build_ssa(method_name: &str) -> (crate::analysis::SsaFunction, CilObject) {
        let path = fixture(ORIGINAL_EXE);
        let assembly =
            CilObject::from_path_with_validation(path, ValidationConfig::analysis()).unwrap();
        let method = assembly
            .methods()
            .iter()
            .find(|e| e.value().name == method_name)
            .unwrap_or_else(|| panic!("{ORIGINAL_EXE} has no method {method_name}"))
            .value()
            .clone();
        let ssa = method.ssa(&assembly).expect("SSA builds");
        (ssa, assembly)
    }

    #[test]
    fn test_extract_namespace() {
        assert_eq!(
            extract_namespace("System.IO.File::ReadAllText"),
            "System.IO"
        );
        assert_eq!(
            extract_namespace("System.Security.Cryptography.Aes::Create"),
            "System.Security.Cryptography"
        );
        assert_eq!(extract_namespace("MyClass::DoWork"), "MyClass");
        assert_eq!(extract_namespace("SimpleMethod"), "SimpleMethod");
    }

    /// SayHello is a small method that calls Console.WriteLine with a string.
    /// With a generous small_threshold it should produce a single linear phase.
    #[test]
    fn test_decompose_sayhello_single_phase() {
        let (ssa, assembly) = load_and_build_ssa("SayHello");

        // Use a large threshold so it falls into the small-method path
        let phases = decompose_method(&ssa, &assembly, 100);
        assert_eq!(phases.len(), 1, "SayHello should be a single phase");
        assert_eq!(
            phases[0].structure.as_deref(),
            Some("linear"),
            "Simple method should be classified as linear"
        );
        // Should have at least one call target (Console.WriteLine)
        assert!(
            !phases[0].call_targets.is_empty(),
            "SayHello should have call targets (Console.WriteLine)"
        );
        assert!(
            phases[0]
                .call_targets
                .iter()
                .any(|t| t.contains("WriteLine")),
            "SayHello should call WriteLine, got: {:?}",
            phases[0].call_targets
        );
    }

    /// SayHello's call-site skeleton should show the Console.WriteLine call.
    #[test]
    fn test_skeleton_sayhello() {
        let (ssa, assembly) = load_and_build_ssa("SayHello");

        let skeleton = build_call_site_skeleton(&ssa, &assembly);
        assert!(skeleton.is_some(), "SayHello should produce a skeleton");
        let skeleton = skeleton.unwrap();
        assert!(
            skeleton.contains("WriteLine"),
            "Skeleton should mention WriteLine, got:\n{skeleton}"
        );
        assert!(
            skeleton.contains("return"),
            "Skeleton should contain a return statement"
        );
    }

    /// DemoLoop has a loop construct — when decomposed with a small threshold
    /// (forcing full decomposition), it should produce multiple phases with at
    /// least one loop-structured phase.
    #[test]
    fn test_decompose_demoloop_has_loop_phase() {
        let (ssa, assembly) = load_and_build_ssa("DemoLoop");

        // Use threshold=0 to force full decomposition
        let phases = decompose_method(&ssa, &assembly, 0);
        assert!(
            phases.len() > 1,
            "DemoLoop should produce multiple phases, got {}",
            phases.len()
        );
        let has_loop = phases
            .iter()
            .any(|p| p.structure.as_deref() == Some("loop"));
        assert!(
            has_loop,
            "DemoLoop should have at least one loop phase, structures: {:?}",
            phases.iter().map(|p| &p.structure).collect::<Vec<_>>()
        );
    }

    /// Fibonacci has a loop — similar to DemoLoop, it should produce a
    /// loop-structured phase when fully decomposed.
    #[test]
    fn test_decompose_fibonacci_has_loop_phase() {
        let (ssa, assembly) = load_and_build_ssa("Fibonacci");

        let phases = decompose_method(&ssa, &assembly, 0);
        assert!(
            phases.len() > 1,
            "Fibonacci should produce multiple phases, got {}",
            phases.len()
        );
        let has_loop = phases
            .iter()
            .any(|p| p.structure.as_deref() == Some("loop"));
        assert!(
            has_loop,
            "Fibonacci should have a loop phase, structures: {:?}",
            phases.iter().map(|p| &p.structure).collect::<Vec<_>>()
        );
    }

    /// DemoIfElse has conditional branching — when fully decomposed, at least
    /// one phase should be classified as "conditional".
    #[test]
    fn test_decompose_demoifelse_has_conditional() {
        let (ssa, assembly) = load_and_build_ssa("DemoIfElse");

        let phases = decompose_method(&ssa, &assembly, 0);
        assert!(
            !phases.is_empty(),
            "DemoIfElse should produce at least one phase"
        );
        let has_conditional = phases
            .iter()
            .any(|p| p.structure.as_deref() == Some("conditional"));
        assert!(
            has_conditional,
            "DemoIfElse should have a conditional phase, structures: {:?}",
            phases.iter().map(|p| &p.structure).collect::<Vec<_>>()
        );
    }

    /// Add is a trivial arithmetic method — even with threshold=0 it should
    /// produce phases, and the opcode profile should show arithmetic operations.
    #[test]
    fn test_decompose_add_opcode_profile() {
        let (ssa, assembly) = load_and_build_ssa("Add");

        // Even with threshold=0, a very small method gets decomposed
        let phases = decompose_method(&ssa, &assembly, 100);
        assert_eq!(phases.len(), 1, "Add should be a single phase");
        let profile = phases[0].opcode_profile.as_ref().unwrap();
        assert!(
            profile.arithmetic > 0,
            "Add method should have arithmetic operations in its profile"
        );
    }
}
