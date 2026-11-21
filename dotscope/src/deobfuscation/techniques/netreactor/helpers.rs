//! Generic structural detection utilities for .NET Reactor protections.
//!
//! All detection is based on behavioral patterns, never on hardcoded type
//! names, method names, or version-specific constants.

use std::collections::{HashMap, HashSet};

use crate::{
    assembly::{BasicBlock, FlowType, Instruction, Operand},
    deobfuscation::utils::find_methods_calling_apis,
    metadata::{method::Method, token::Token},
    CilObject,
};

// Minimum .cctor fan-in to consider a target as the NecroBit init method.
const MIN_CCTOR_FAN_IN: usize = 5;

/// Classification of a NecroBit stub method body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubKind {
    /// `nop; nop; nop; ret` — void return.
    Void,
    /// `nop; nop; ldc.i4.0; ret` — value-type return.
    Value,
    /// `nop; nop; ldnull; ret` — reference-type return.
    Reference,
}

/// Result of scanning an assembly for NecroBit stub methods.
#[derive(Debug)]
pub struct StubScanResult {
    /// Tokens of methods with NecroBit stub bodies.
    pub stub_methods: Vec<(Token, StubKind)>,
    /// Total number of IL methods in the assembly (for ratio calculation).
    pub total_il_methods: usize,
    /// Entry point token (never encrypted by NecroBit).
    pub entry_point_token: Option<Token>,
}

/// Scans an assembly for methods with the characteristic NecroBit stub pattern.
///
/// NecroBit replaces encrypted method bodies with exactly 4 instructions:
/// - `nop; nop; nop; ret` for void returns
/// - `nop; nop; ldc.i4.0; ret` for value-type returns
/// - `nop; nop; ldnull; ret` for reference-type returns
///
/// The entry point method (Main) is never encrypted and is excluded from results.
pub fn scan_stub_methods(assembly: &CilObject) -> StubScanResult {
    let entry_point_raw = assembly.cor20header().entry_point_token;
    let entry_point_token = if entry_point_raw != 0 && Token::new(entry_point_raw).table() == 0x06 {
        Some(Token::new(entry_point_raw))
    } else {
        None
    };

    let mut stub_methods = Vec::new();
    let mut total_il_methods = 0usize;

    for method_entry in assembly.methods() {
        let method = method_entry.value();

        // Skip methods without IL bodies (native, runtime, abstract, pinvoke)
        if !method.has_body() {
            continue;
        }
        if method.rva.is_none_or(|rva| rva == 0) {
            continue;
        }

        total_il_methods = total_il_methods.saturating_add(1);

        // Skip the entry point — it's never encrypted
        if entry_point_token.is_some_and(|ep| ep == method.token) {
            continue;
        }

        // Collect instructions to check the stub pattern
        let instrs: Vec<_> = method.instructions().collect();
        if instrs.len() != 4 {
            continue;
        }

        // Check the exact 4-instruction stub pattern
        let (Some(i0), Some(i1), Some(i2), Some(i3)) =
            (instrs.first(), instrs.get(1), instrs.get(2), instrs.get(3))
        else {
            continue;
        };
        if i0.mnemonic != "nop" || i1.mnemonic != "nop" || i3.mnemonic != "ret" {
            continue;
        }

        let kind = match i2.mnemonic {
            "nop" => StubKind::Void,
            "ldc.i4.0" => StubKind::Value,
            "ldnull" => StubKind::Reference,
            _ => continue,
        };

        stub_methods.push((method.token, kind));
    }

    StubScanResult {
        stub_methods,
        total_il_methods,
        entry_point_token,
    }
}

/// Result of .cctor fan-in analysis.
#[derive(Debug)]
pub struct CctorFanInResult {
    /// Token of the method called by the most type .cctors, the lowest token
    /// among equals.
    pub target_token: Token,
    /// Every runtime initializer the .cctors call: each method of the target's
    /// declaring type that is called from at least [`MIN_CCTOR_FAN_IN`]
    /// .cctors, in token order. .NET Reactor injects more than one call into a
    /// protected type's .cctor, and all of them go when the runtime does.
    pub initializers: Vec<Token>,
    /// Tokens of all .cctors that call any of the initializers, in token order.
    pub calling_cctors: Vec<Token>,
    /// Number of local variables in the target method.
    pub target_local_count: usize,
    /// Number of instructions in the target method.
    pub target_instruction_count: usize,
}

/// Finds the runtime initializers the most type .cctors call.
///
/// NecroBit injects .cctors into every type, all calling the same
/// initialization methods. No legitimate program has 5+ types whose .cctors
/// all call the same single target. The result names the target with the
/// highest fan-in and every other method of its type called as widely.
///
/// Returns `None` if no target has fan-in >= [`MIN_CCTOR_FAN_IN`].
pub fn find_cctor_fan_in_target(assembly: &CilObject) -> Option<CctorFanInResult> {
    // Map: call target token -> list of .cctors that call it
    let mut call_target_to_cctors: HashMap<Token, Vec<Token>> = HashMap::new();

    let types = assembly.types();
    for type_entry in types.iter() {
        let ty = type_entry.value();
        let Some(cctor_token) = ty.cctor() else {
            continue;
        };

        let Ok(cctor_method) = assembly.method(&cctor_token) else {
            continue;
        };

        for instr in cctor_method.instructions() {
            if instr.mnemonic != "call" {
                continue;
            }
            let Some(target) = instr.get_token_operand() else {
                continue;
            };
            // Only consider MethodDef targets (internal methods)
            if target.table() != 0x06 {
                continue;
            }
            call_target_to_cctors
                .entry(target)
                .or_default()
                .push(cctor_token);
        }
    }

    // The target with the most calling .cctors, the lowest token among
    // equals: two initializers can be called from exactly the same .cctors,
    // and the map's own order would pick one at random.
    let (target_token, target_cctors) = call_target_to_cctors
        .iter()
        .max_by_key(|(token, cctors)| (cctors.len(), std::cmp::Reverse(token.value())))?;
    let target_token = *target_token;

    if target_cctors.len() < MIN_CCTOR_FAN_IN {
        return None;
    }

    // Every other method of the target's type that the .cctors call as often
    // is an initializer of the same runtime.
    let runtime_type = assembly
        .method(&target_token)
        .ok()
        .and_then(|m| m.declaring_type_rc())
        .map(|t| t.token);
    let mut initializers: Vec<Token> = call_target_to_cctors
        .iter()
        .filter(|(token, cctors)| {
            cctors.len() >= MIN_CCTOR_FAN_IN
                && (**token == target_token
                    || runtime_type.is_some()
                        && assembly
                            .method(token)
                            .ok()
                            .and_then(|m| m.declaring_type_rc())
                            .map(|t| t.token)
                            == runtime_type)
        })
        .map(|(token, _)| *token)
        .collect();
    initializers.sort();
    let mut calling_cctors: Vec<Token> = initializers
        .iter()
        .filter_map(|token| call_target_to_cctors.get(token))
        .flatten()
        .copied()
        .collect();
    calling_cctors.sort();
    calling_cctors.dedup();

    // Extract structural properties of the target method
    let (target_local_count, target_instruction_count) = assembly
        .method(&target_token)
        .ok()
        .map(|m| (m.local_vars.count(), m.instruction_count()))
        .unwrap_or((0, 0));

    Some(CctorFanInResult {
        target_token,
        initializers,
        calling_cctors,
        target_local_count,
        target_instruction_count,
    })
}

/// Result of trial/time-bomb pattern detection.
#[derive(Debug)]
pub struct TrialCheckResult {
    /// Token of the trial check method.
    pub method_token: Token,
    /// Whether this method is defined on the `<Module>` type.
    pub is_on_module_type: bool,
}

/// Finds methods that match the .NET Reactor trial/time-bomb pattern.
///
/// The trial check constructs a `DateTime`, subtracts it from the current time,
/// reads `TimeSpan.Days`, compares against thresholds, and throws if expired.
/// This behavioral pattern is unique to .NET Reactor's trial guard.
pub fn find_trial_checks(assembly: &CilObject) -> Vec<TrialCheckResult> {
    // Find methods that reference DateTime or get_Days — these are the core
    // signals of the trial check pattern.
    let api_hits = find_methods_calling_apis(assembly, &["DateTime", "get_Days"]);

    let mut results = Vec::new();

    for (method_token, indices) in &api_hits {
        // Must reference both DateTime and get_Days
        if !indices.contains(&0) || !indices.contains(&1) {
            continue;
        }

        let Ok(method) = assembly.method(method_token) else {
            continue;
        };

        // Verify the behavioral pattern at instruction level:
        // 1. newobj DateTime(...) — constructs a build date
        // 2. call to get_Days — reads the day count from a TimeSpan
        // 3. throw — throws if expired
        let mut has_datetime_ctor = false;
        let mut has_get_days = false;
        let mut has_throw = false;

        for instr in method.instructions() {
            match instr.mnemonic {
                "newobj" => {
                    if let Some(ctor_token) = instr.get_token_operand() {
                        if let Some(name) =
                            crate::deobfuscation::utils::resolve_qualified_method_name(
                                assembly, ctor_token,
                            )
                        {
                            if name.contains("DateTime") {
                                has_datetime_ctor = true;
                            }
                        }
                    }
                }
                "call" | "callvirt" => {
                    if let Some(call_token) = instr.get_token_operand() {
                        if let Some(name) =
                            crate::deobfuscation::utils::resolve_qualified_method_name(
                                assembly, call_token,
                            )
                        {
                            if name.contains("get_Days") {
                                has_get_days = true;
                            }
                        }
                    }
                }
                "throw" => {
                    has_throw = true;
                }
                _ => {}
            }
        }

        // Require DateTime construction + get_Days + throw
        if !has_datetime_ctor || !has_get_days || !has_throw {
            continue;
        }

        let is_on_module_type = method
            .declaring_type_rc()
            .is_some_and(|t| t.is_module_type());

        results.push(TrialCheckResult {
            method_token: *method_token,
            is_on_module_type,
        });
    }

    results
}

/// Finds a method that matches the NecroBit body patcher pattern.
///
/// The patcher uses `Marshal.Copy` to write decrypted bytes back to method
/// memory, `Marshal.ReadInt32`/`ReadInt64` for pointer arithmetic, and checks
/// `IntPtr.Size` for 32/64-bit runtime detection.
pub fn find_body_patcher(assembly: &CilObject) -> Option<Token> {
    const PAT_MARSHAL_COPY: usize = 0;
    const PAT_READ_INT32: usize = 1;
    const PAT_READ_INT64: usize = 2;
    const PAT_INTPTR_SIZE: usize = 3;

    let api_hits = find_methods_calling_apis(
        assembly,
        &["Marshal.Copy", "ReadInt32", "ReadInt64", "IntPtr.get_Size"],
    );

    for (method_token, indices) in &api_hits {
        let has_marshal_copy = indices.contains(&PAT_MARSHAL_COPY);
        let has_read_int = indices.contains(&PAT_READ_INT32) || indices.contains(&PAT_READ_INT64);
        let has_intptr_size = indices.contains(&PAT_INTPTR_SIZE);

        if has_marshal_copy && has_read_int && has_intptr_size {
            return Some(*method_token);
        }
    }

    None
}

/// A `<PrivateImplementationDetails>{GUID}` container injected by NR.
///
/// The container is a sealed type whose name is `<PrivateImplementationDetails>`
/// followed by a GUID-shaped suffix, holding SHA-256-named static fields
/// pointing at PE-mapped raw bytes consumed by NR's runtime decryptors.
#[derive(Debug)]
pub struct PrivateImplContainer {
    /// TypeDef token of the container itself.
    pub container_token: Token,
}

/// Returns whether `name` matches the structural pattern of an NR-injected
/// `<PrivateImplementationDetails>{GUID}` container.
///
/// The match requires:
/// 1. Exact prefix `<PrivateImplementationDetails>{`
/// 2. Suffix `}`
/// 3. The bracketed body is a canonical 8-4-4-4-12 hex GUID (`X` = `[0-9A-Fa-f]`)
///
/// The naked compiler-generated `<PrivateImplementationDetails>` (no
/// suffix) is rejected — that one must always survive cleanup.
fn is_nr_private_impl_name(name: &str) -> bool {
    const PREFIX: &str = "<PrivateImplementationDetails>{";
    if !name.starts_with(PREFIX) || !name.ends_with('}') {
        return false;
    }
    let Some(end) = name.len().checked_sub(1) else {
        return false;
    };
    let Some(body) = name.get(PREFIX.len()..end) else {
        return false;
    };

    // Canonical GUID layout: 8-4-4-4-12 hex chars separated by '-'
    let segments: Vec<&str> = body.split('-').collect();
    if segments.len() != 5 {
        return false;
    }
    let expected_lens = [8usize, 4, 4, 4, 12];
    for (seg, expected) in segments.iter().zip(expected_lens.iter()) {
        if seg.len() != *expected {
            return false;
        }
        if !seg.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Returns whether `name` matches the structural pattern of an NR-injected
/// `<Module>{GUID}` marker type.
///
/// Same matching rules as [`is_nr_private_impl_name`] but with the
/// `<Module>` prefix. NR's anti-tamper stage injects this type alongside
/// the GUID-suffixed `<PrivateImplementationDetails>` container; the
/// compiler-generated `<Module>` (no suffix) must always survive cleanup.
fn is_nr_guid_module_name(name: &str) -> bool {
    const PREFIX: &str = "<Module>{";
    if !name.starts_with(PREFIX) || !name.ends_with('}') {
        return false;
    }
    let Some(end) = name.len().checked_sub(1) else {
        return false;
    };
    let Some(body) = name.get(PREFIX.len()..end) else {
        return false;
    };

    let segments: Vec<&str> = body.split('-').collect();
    if segments.len() != 5 {
        return false;
    }
    let expected_lens = [8usize, 4, 4, 4, 12];
    for (seg, expected) in segments.iter().zip(expected_lens.iter()) {
        if seg.len() != *expected {
            return false;
        }
        if !seg.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }
    true
}

/// Finds every NR-injected `<Module>{GUID}` marker type in the assembly.
///
/// Used by [`netreactor.antitamp`] as a corroborating structural signal
/// alongside the .cctor fan-in pattern. The container has no useful
/// members (just a `.cctor` calling the anti-tamper init) and must be
/// explicitly added to the [`CleanupRequest`] — the orphan sweep skips it
/// because it has no non-cctor methods.
///
/// [`netreactor.antitamp`]: super::antitamp
/// [`CleanupRequest`]: crate::cilassembly::CleanupRequest
pub fn find_nr_guid_module_containers(assembly: &CilObject) -> Vec<Token> {
    let mut results = Vec::new();
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();
        if cil_type.token.table() != 0x02 {
            continue;
        }
        if !is_nr_guid_module_name(&cil_type.name) {
            continue;
        }
        results.push(cil_type.token);
    }
    results
}

/// Finds every NR-injected `<PrivateImplementationDetails>{GUID}` container
/// in the assembly.
///
/// Detection is purely structural — it inspects only the type name shape
/// (see [`is_nr_private_impl_name`]). The container's nested
/// `__StaticArrayInitTypeSize=N` value-types and SHA-256-named fields are
/// not enumerated here; the cleanup pipeline's `expand_type_tokens`
/// cascade handles them automatically when the container itself is added
/// to a [`CleanupRequest`].
///
/// [`CleanupRequest`]: crate::cilassembly::CleanupRequest
pub fn find_nr_private_impl_containers(assembly: &CilObject) -> Vec<PrivateImplContainer> {
    let mut results = Vec::new();
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();
        if cil_type.token.table() != 0x02 {
            continue;
        }
        if !is_nr_private_impl_name(&cil_type.name) {
            continue;
        }
        results.push(PrivateImplContainer {
            container_token: cil_type.token,
        });
    }
    results
}

/// Detects the single-shot bool field guard pattern used by NR's secondary
/// trial-check methods (the license-check class).
///
/// NR's license check executes at most once per AppDomain by reading and
/// writing the same static field. Structurally that produces:
///
/// ```text
/// ... ldsfld   <field>   ; read the guard somewhere
/// ... brtrue   <skip>    ; (or brfalse) to early-out when set
/// ... stsfld   <field>   ; write the guard so subsequent calls early-out
/// ```
///
/// The detector matches **any** position in the method body — both the
/// degenerate small form (raw NR-emitted, guard at the head) and the
/// CFF-wrapped form (NR + control-flow obfuscation, where the entire
/// body sits behind a switch dispatcher and the guard lives in dispatch
/// arms at arbitrary offsets). Required signals:
///
/// 1. At least one `ldsfld` of some static field token `T`
/// 2. At least one conditional branch (`brtrue` / `brfalse`) anywhere
/// 3. At least one `stsfld` to the **same** token `T`
///
/// A legitimate singleton-init pattern can hit this triplet, but combined
/// with the behavioral trial-check signature ([`find_trial_checks`]) and
/// an `<Module>`-trial NR-context gate it is highly specific to NR's
/// license-verification stub.
pub fn has_single_shot_bool_guard(assembly: &CilObject, method_token: Token) -> bool {
    let Ok(method) = assembly.method(&method_token) else {
        return false;
    };

    let mut loaded_static_fields: HashSet<Token> = HashSet::new();
    let mut stored_static_fields: HashSet<Token> = HashSet::new();
    let mut has_conditional_branch = false;

    for instr in method.instructions() {
        match instr.mnemonic {
            "ldsfld" => {
                if let Some(t) = instr.get_token_operand() {
                    loaded_static_fields.insert(t);
                }
            }
            "stsfld" => {
                if let Some(t) = instr.get_token_operand() {
                    stored_static_fields.insert(t);
                }
            }
            "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" => {
                has_conditional_branch = true;
            }
            _ => {}
        }
    }

    if !has_conditional_branch {
        return false;
    }
    loaded_static_fields
        .intersection(&stored_static_fields)
        .next()
        .is_some()
}

/// Information about NR's anti-tamper metadata-token resolver type.
#[derive(Debug)]
pub struct TokenResolverInfo {
    /// TypeDef token of the resolver type.
    pub type_token: Token,
    /// Tokens of accessor methods returning `RuntimeTypeHandle` from an int32 token.
    /// Resolves: `accessor(metadata_token: int32) -> RuntimeTypeHandle`.
    pub type_handle_accessors: Vec<Token>,
    /// Tokens of accessor methods returning `RuntimeFieldHandle` from an int32 token.
    /// Resolves: `accessor(metadata_token: int32) -> RuntimeFieldHandle`.
    pub field_handle_accessors: Vec<Token>,
    /// Tokens of accessor methods returning `RuntimeMethodHandle` from an int32 token.
    pub method_handle_accessors: Vec<Token>,
}

/// Detects NR's anti-tamper metadata-token resolver type.
///
/// NR's anti-tamper stage injects a helper type that wraps a cached
/// `ModuleHandle` static field and exposes accessor methods that resolve
/// metadata tokens to runtime handles. User code that originally used
/// `ldtoken X` is rewritten by NR to call these accessors with the raw
/// metadata token as an int32 — denying static analysis the type/field
/// reference and gating resolution behind the cached handle.
///
/// The accessor body is a fixed 4-instruction shape:
///
/// ```text
/// ldsflda    <static ModuleHandle field>
/// ldarg.0
/// call instance ModuleHandle::GetRuntime{Type|Field|Method}HandleFromMetadataToken(int32)
/// ret
/// ```
///
/// Returns `None` if no type with this exact accessor pattern is found.
/// All accessors of every kind on a single type are reported in one
/// [`TokenResolverInfo`] (NR ships at minimum a TypeHandle and FieldHandle
/// accessor; MethodHandle is included for forward compatibility).
pub fn find_nr_token_resolver(assembly: &CilObject) -> Option<TokenResolverInfo> {
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();
        if cil_type.token.table() != 0x02 {
            continue;
        }

        let mut type_acc = Vec::new();
        let mut field_acc = Vec::new();
        let mut method_acc = Vec::new();

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            if !method.is_static() {
                continue;
            }
            if method.signature.params.len() != 1 {
                continue;
            }
            let Some(first_param) = method.signature.params.first() else {
                continue;
            };
            if !matches!(
                first_param.base,
                crate::metadata::signatures::TypeSignature::I4
            ) {
                continue;
            }

            let Some(kind) = classify_token_accessor_body(assembly, method.token) else {
                continue;
            };
            match kind {
                AccessorKind::Type => type_acc.push(method.token),
                AccessorKind::Field => field_acc.push(method.token),
                AccessorKind::Method => method_acc.push(method.token),
            }
        }

        // Require at least the TypeHandle accessor — that's the one user code
        // calls most often and the cheapest signal that this type is the
        // anti-tamper resolver and not some unrelated helper.
        if type_acc.is_empty() {
            continue;
        }

        return Some(TokenResolverInfo {
            type_token: cil_type.token,
            type_handle_accessors: type_acc,
            field_handle_accessors: field_acc,
            method_handle_accessors: method_acc,
        });
    }

    None
}

/// Kind of metadata handle returned by an accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessorKind {
    Type,
    Field,
    Method,
}

/// The instructions a call to `method` executes, in order, along the path
/// from its entry: `nop`s are dropped and unconditional branches followed
/// rather than yielded.
///
/// .NET Reactor pads protected helpers with a `br` over junk bytes, so the
/// instructions a body executes are not the ones laid out in it. The walk
/// ends after the first instruction that does not simply continue (a `ret`,
/// a conditional branch, a switch, a throw), which it yields last: a body is
/// one straight path exactly when that instruction is a `ret`. A loop or a
/// jump out of the body ends it without that.
///
/// Walks the decoded blocks in place; nothing is copied or indexed.
pub fn executed_path(method: &Method) -> ExecutedPath<'_> {
    ExecutedPath {
        blocks: method.blocks.get().map_or(&[], Vec::as_slice),
        block: 0,
        index: 0,
        hops: 0,
        done: false,
    }
}

/// Iterator returned by [`executed_path`].
pub struct ExecutedPath<'a> {
    blocks: &'a [BasicBlock],
    block: usize,
    index: usize,
    /// Blocks entered so far; a straight path enters each at most once.
    hops: usize,
    done: bool,
}

impl ExecutedPath<'_> {
    /// Continues in `next`, the block control reaches from the current one.
    fn enter(&mut self, next: Option<usize>) {
        self.hops = self.hops.saturating_add(1);
        match next {
            Some(block) if self.hops <= self.blocks.len() => {
                self.block = block;
                self.index = 0;
            }
            _ => self.done = true,
        }
    }
}

impl<'a> Iterator for ExecutedPath<'a> {
    type Item = &'a Instruction;

    fn next(&mut self) -> Option<&'a Instruction> {
        while !self.done {
            let Some(block) = self.blocks.get(self.block) else {
                self.done = true;
                break;
            };
            let Some(instruction) = block.instructions.get(self.index) else {
                // Off the end of a block that falls through to the next.
                self.enter(block.successors.first().copied());
                continue;
            };
            self.index = self.index.saturating_add(1);
            match instruction.flow_type {
                FlowType::UnconditionalBranch => {
                    self.enter(block.successors.first().copied());
                }
                FlowType::Sequential | FlowType::Call | FlowType::CallIndirect => {
                    if instruction.mnemonic != "nop" {
                        return Some(instruction);
                    }
                }
                _ => {
                    self.done = true;
                    return Some(instruction);
                }
            }
        }
        None
    }
}

/// Returns the accessor kind if `method_token`'s body matches the NR
/// metadata-token resolver shape; otherwise `None`.
///
/// Body shape (4 instructions, in execution order - see [`executed_path`]):
/// `ldsflda <static_field>` → `ldarg.0` → `call instance ModuleHandle::Get*FromMetadataToken` → `ret`.
fn classify_token_accessor_body(assembly: &CilObject, method_token: Token) -> Option<AccessorKind> {
    let method = assembly.method(&method_token).ok()?;
    let mut path = executed_path(&method);
    let (Some(i0), Some(i1), Some(i2), Some(i3), None) = (
        path.next(),
        path.next(),
        path.next(),
        path.next(),
        path.next(),
    ) else {
        return None;
    };
    if i0.mnemonic != "ldsflda"
        || i1.mnemonic != "ldarg.0"
        || i2.mnemonic != "call"
        || i3.mnemonic != "ret"
    {
        return None;
    }

    let call_token = i2.get_token_operand()?;
    let name = crate::deobfuscation::utils::resolve_qualified_method_name(assembly, call_token)?;
    if !name.contains("ModuleHandle") {
        return None;
    }
    if name.contains("GetRuntimeTypeHandleFromMetadataToken") {
        Some(AccessorKind::Type)
    } else if name.contains("GetRuntimeFieldHandleFromMetadataToken") {
        Some(AccessorKind::Field)
    } else if name.contains("GetRuntimeMethodHandleFromMetadataToken") {
        Some(AccessorKind::Method)
    } else {
        None
    }
}

/// Finds `ManifestResource` tokens referenced by name from the given
/// methods' IL.
///
/// Scans each method's body for `ldstr <name>` instructions and looks
/// up `<name>` in the assembly's resources table. Every match is a
/// manifest-resource token that is only reachable through the scanned
/// methods — once those methods are cleaned up, the resource's data
/// payload is dead weight. This is the structural signal used by
/// [`netreactor.antitamp`](crate::deobfuscation::techniques::netreactor::NetReactorAntiTamp) to mark the NR anti-tamper encrypted resource
/// for removal.
///
/// The `assembly::Operand::Token` branch is *not* checked here — NR's
/// anti-tamper init carries the resource name as a user string, not a
/// `ManifestResource` token reference. Scanning only `ldstr` keeps the
/// helper focused and prevents false positives from token operands on
/// unrelated instructions.
pub fn find_resources_referenced_by_methods(
    assembly: &CilObject,
    method_tokens: &[Token],
) -> Vec<Token> {
    let Some(userstrings) = assembly.userstrings() else {
        return Vec::new();
    };

    let mut seen: HashSet<Token> = HashSet::new();
    let mut results = Vec::new();

    for &method_token in method_tokens {
        let Ok(method) = assembly.method(&method_token) else {
            continue;
        };
        for instr in method.instructions() {
            if instr.mnemonic != "ldstr" {
                continue;
            }
            let Operand::Token(token) = &instr.operand else {
                continue;
            };
            if token.table() != 0x70 {
                continue;
            }
            let Ok(s) = userstrings.get(token.row() as usize) else {
                continue;
            };
            let name = s.to_string_lossy();
            let Some(resource) = assembly.resources().get(&name) else {
                continue;
            };
            if seen.insert(resource.token) {
                results.push(resource.token);
            }
        }
    }

    results
}

/// Classification of injected .cctors.
#[derive(Debug)]
pub struct InjectedCctorClassification {
    /// .cctors whose entire body is just `call init; ret` — safe to delete.
    pub purely_injected: Vec<Token>,
    /// .cctors that had the init call prepended to original code.
    pub modified: Vec<Token>,
}

/// Classifies .cctors that call the runtime's initializers as purely-injected
/// or modified.
///
/// A purely-injected .cctor has a very small body (<=5 instructions) whose only
/// `call` targets are initializers. A modified .cctor has additional code after
/// the init calls (the original .cctor body was preserved).
pub fn classify_injected_cctors(
    assembly: &CilObject,
    initializers: &[Token],
    calling_cctors: &[Token],
) -> InjectedCctorClassification {
    let mut purely_injected = Vec::new();
    let mut modified = Vec::new();

    for &cctor_token in calling_cctors {
        let Ok(method) = assembly.method(&cctor_token) else {
            continue;
        };

        let instr_count = method.instruction_count();
        let instrs: Vec<_> = method.instructions().collect();

        // Count how many distinct call targets this .cctor has
        let call_targets: Vec<Token> = instrs
            .iter()
            .filter(|i| i.mnemonic == "call")
            .filter_map(|i| i.get_token_operand())
            .collect();

        // A purely-injected .cctor:
        // - Has a small body (<=5 instructions)
        // - Its only call targets are initializers
        let only_calls_init = call_targets.iter().all(|t| initializers.contains(t));

        if instr_count <= 5 && only_calls_init {
            purely_injected.push(cctor_token);
        } else {
            modified.push(cctor_token);
        }
    }

    InjectedCctorClassification {
        purely_injected,
        modified,
    }
}
