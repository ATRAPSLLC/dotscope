//! JIEJIE.NET array initialization encryption detection.
//!
//! Detects the field handle container class injected by JIEJIE.NET (typically
//! named `_RuntimeFieldHandleContainer`, but detection is purely structural and
//! works when renamed).
//!
//! # Structural Pattern
//!
//! The container class has:
//! - Exactly 1 static field: a `ValueType[]` array (`RuntimeFieldHandle[]`)
//! - A `.cctor` that populates the array with `ldtoken <field>` instructions
//! - An accessor method: `static ValueType(int32)` — indexes the array and
//!   returns a `RuntimeFieldHandle`
//!
//! This is structurally similar to the typeof container ([`super::typeofs`]),
//! but distinguished by the accessor's return type: `ValueType` (field handle)
//! vs `Class` (System.Type).
//!
//! # MyInitializeArray
//!
//! JIEJIE.NET may also replace `RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle)`
//! with `MyInitializeArray(Array, RuntimeFieldHandle, int32 xorKey)`. This method:
//! 1. Calls `RuntimeHelpers.InitializeArray` to populate the array from RVA data
//! 2. XOR-decrypts the array in-place: 4-byte (int32) blocks, key = `xorKey + 13`,
//!    from end to start
//!
//! Detection finds `MyInitializeArray` by structural signature (static, 3 params:
//! Class, ValueType, I4) and verifying its body calls `RuntimeHelpers.InitializeArray`.
//! The byte transform decrypts the FieldRVA data; the SSA pass replaces
//! `Call(MyInitializeArray, ...)` with `Call(RuntimeHelpers.InitializeArray, ...)`.
//!
//! # Detection
//!
//! 1. Scan for classes with exactly 1 static `ValueType[]` field
//! 2. Look for an accessor method with signature `ValueType(int32)`
//! 3. Count `ldtoken` instructions in `.cctor` to determine handle count
//! 4. Scan for `MyInitializeArray` method (static, 3 params, calls `InitializeArray`)
//! 5. Populate [`ArrayFindings`] with tokens and handle count

use std::{any::Any, collections::HashMap, sync::Arc};

use crate::{
    analysis::CilTarget,
    assembly::{Immediate, Instruction, Operand},
    compiler::{CompilerContext, EventLog, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::jiejienet::ArrayInitRestorationPass,
        techniques::{
            Detection, Detections, Evidence, Technique, TechniqueCapability, TechniqueCategory,
            WorkingAssembly,
        },
    },
    metadata::{
        signatures::{parse_field_signature, TypeSignature},
        tables::{ClassLayoutRaw, FieldRaw, FieldRvaRaw, TableId},
        token::Token,
        typesystem::{wellknown, PointerSize},
    },
    CilObject, Error, Result,
};

/// Findings from RuntimeFieldHandleContainer detection.
#[derive(Debug)]
pub struct ArrayFindings {
    /// Token of the container class.
    pub container_type: Token,
    /// Token of the GetHandle accessor method.
    pub accessor_token: Token,
    /// Token of the .cctor that populates the handle array.
    pub cctor_token: Option<Token>,
    /// Number of field handles stored.
    pub handle_count: usize,
    /// Token of the `MyInitializeArray` method, if present.
    pub init_array_method: Option<Token>,
    /// Token of `RuntimeHelpers.InitializeArray` MemberRef extracted from
    /// `MyInitializeArray`'s body.
    pub init_array_target: Option<Token>,
}

/// Detects the JIEJIE.NET RuntimeFieldHandleContainer.
pub struct JiejieNetArrays;

impl Technique for JiejieNetArrays {
    fn id(&self) -> &'static str {
        "jiejienet.arrays"
    }

    fn name(&self) -> &'static str {
        "JIEJIE.NET Array Init Encryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![
            TechniqueCapability::ByteTransform,
            TechniqueCapability::SsaPass,
        ]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Must have exactly 1 field (the RuntimeFieldHandle[] array)
            if cil_type.fields.count() != 1 {
                continue;
            }

            let Some((_, field)) = cil_type.fields.iter().next() else {
                continue;
            };

            // Check if the field is a value type array (RuntimeFieldHandle[])
            let is_handle_array = match &field.signature.base {
                TypeSignature::SzArray(elem) => matches!(*elem.base, TypeSignature::ValueType(_)),
                _ => false,
            };

            if !is_handle_array || !field.flags.is_static() {
                continue;
            }

            // Look for accessor: static, takes int32, returns value type (RuntimeFieldHandle)
            let mut accessor_token: Option<Token> = None;
            let mut cctor_token: Option<Token> = None;

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };

                if method.name == wellknown::members::CCTOR {
                    cctor_token = Some(method.token);
                    continue;
                }

                if method.name == ".ctor" {
                    continue;
                }

                let sig = &method.signature;
                // Accessor: static, single int32 param, returns value type (RuntimeFieldHandle)
                if method.is_static()
                    && sig.params.len() == 1
                    && sig
                        .params
                        .first()
                        .is_some_and(|p| matches!(p.base, TypeSignature::I4))
                    && matches!(sig.return_type.base, TypeSignature::ValueType(_))
                {
                    accessor_token = Some(method.token);
                }
            }

            let Some(accessor) = accessor_token else {
                continue;
            };

            // Count ldtoken instructions in .cctor
            let handle_count = cctor_token
                .and_then(|t| assembly.method(&t).ok())
                .map(|m| m.instructions().filter(|i| i.mnemonic == "ldtoken").count())
                .unwrap_or(0);

            if handle_count == 0 {
                continue;
            }

            // Disambiguate from typeof container: this one returns ValueType,
            // typeof returns Class. But both have ValueType[] fields.
            // The typeof container was already filtered above by return type check.
            // Additional check: typeof container's cctor has ldtoken for types,
            // this one has ldtoken for fields. We've already verified structural
            // difference via return type (ValueType vs Class).

            // Scan for MyInitializeArray: a static method with 3 params
            // (Class, ValueType, I4) that calls RuntimeHelpers.InitializeArray.
            let (init_array_method, init_array_target) = find_my_initialize_array(assembly);

            let mut evidence = vec![Evidence::Structural(format!(
                "RuntimeFieldHandle[] container with {} field handles and index accessor",
                handle_count,
            ))];

            if init_array_method.is_some() {
                evidence.push(Evidence::Structural(
                    "MyInitializeArray XOR-encrypted array init wrapper".to_string(),
                ));
            }

            let findings = ArrayFindings {
                container_type: cil_type.token,
                accessor_token: accessor,
                cctor_token,
                handle_count,
                init_array_method,
                init_array_target,
            };

            let mut detection = Detection::new_detected(
                evidence,
                Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
            );

            detection.cleanup_mut().add_type(cil_type.token);

            return detection;
        }

        Detection::new_empty()
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();
        let Some(findings) = detection.findings::<ArrayFindings>() else {
            return Some(Ok(events));
        };

        // Only apply byte transform if MyInitializeArray was detected
        let init_method = findings.init_array_method?;

        let cctor_token = findings.cctor_token?;

        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Extract the ordered field tokens from the container's .cctor
        let field_tokens = extract_cctor_field_tokens(co, cctor_token);
        if field_tokens.is_empty() {
            return Some(Ok(events));
        }

        // Scan all methods for calls to MyInitializeArray and extract
        // (field_token, xor_key) pairs by analysing the IL call sites.
        let decrypt_entries =
            extract_init_array_call_sites(co, init_method, findings.accessor_token, &field_tokens);

        if decrypt_entries.is_empty() {
            return Some(Ok(events));
        }

        // Decrypt each FieldRVA data block and store through the changes system.
        // Skip entries with xor_key=0 — these arrays were not XOR-encrypted.
        // Using store_field_data (not file.write) ensures the decrypted data
        // persists across PE regeneration iterations.
        let mut field_data_entries = Vec::new();
        for (field_token, xor_key) in &decrypt_entries {
            if *xor_key == 0 {
                continue;
            }
            match decrypt_field_rva_data_to_bytes(co, *field_token, *xor_key) {
                Ok(Some((fieldrva_rid, data))) => {
                    field_data_entries.push((fieldrva_rid, data));
                }
                Ok(None) => {}
                Err(e) => {
                    log::warn!(
                        "JIEJIE.NET arrays: failed to decrypt FieldRVA for 0x{:08X}: {}",
                        field_token.value(),
                        e,
                    );
                }
            }
        }

        if !field_data_entries.is_empty() {
            let count = field_data_entries.len();
            if let Err(e) = assembly.store_field_data(field_data_entries) {
                log::warn!("JIEJIE.NET arrays: failed to store decrypted field data: {e}");
            } else {
                log::info!(
                    "JIEJIE.NET arrays: XOR-decrypted {} FieldRVA data block(s)",
                    count,
                );
            }
        }

        Some(Ok(events))
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        _ctx: &AnalysisContext,
        _assembly: &CilObject,
        _detection: &Detection,
        _detections: &Detections,
    ) {
        // No warmup needed — we parse the .cctor statically in create_pass(),
        // so no emulation is required for array init restoration.
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<ArrayFindings>() else {
            return Vec::new();
        };
        let Some(cctor_token) = findings.cctor_token else {
            return Vec::new();
        };

        // Parse the .cctor to extract the ordered field tokens from ldtoken instructions
        let field_tokens = extract_cctor_field_tokens(assembly, cctor_token);

        if field_tokens.is_empty() {
            return Vec::new();
        }

        log::info!(
            "JIEJIE.NET arrays: extracted {} field tokens from .cctor, accessor=0x{:08X}{}",
            field_tokens.len(),
            findings.accessor_token.value(),
            if findings.init_array_method.is_some() {
                ", MyInitializeArray detected"
            } else {
                ""
            },
        );

        vec![Box::new(ArrayInitRestorationPass::new(
            findings.accessor_token,
            field_tokens,
            findings.init_array_method,
            findings.init_array_target,
        ))]
    }
}

/// Extracts the ordered list of field tokens from `ldtoken` instructions in the
/// container's `.cctor`.
///
/// The `.cctor` populates a `RuntimeFieldHandle[]` array with a sequence of
/// `ldtoken <field>` instructions. The order of `ldtoken` instructions corresponds
/// to array indices 0, 1, 2, ...
fn extract_cctor_field_tokens(assembly: &CilObject, cctor_token: Token) -> Vec<Token> {
    let Ok(method) = assembly.method(&cctor_token) else {
        return Vec::new();
    };

    method
        .instructions()
        .filter(|i| i.mnemonic == "ldtoken")
        .filter_map(|i| match &i.operand {
            Operand::Token(token) => Some(*token),
            _ => None,
        })
        .collect()
}

/// Finds the `MyInitializeArray` method across all types in the assembly.
///
/// `MyInitializeArray` is a static method with signature `void(Array, RuntimeFieldHandle, int32)`
/// that internally calls `RuntimeHelpers.InitializeArray`. Detection is purely structural:
/// - Static method with 3 parameters
/// - First param is Class (Array)
/// - Second param is ValueType (RuntimeFieldHandle)
/// - Third param is I4 (the XOR key)
/// - The method body contains a `call` to a MemberRef named `InitializeArray`
///
/// Returns `(method_token, init_array_memberref_token)` if found.
fn find_my_initialize_array(assembly: &CilObject) -> (Option<Token>, Option<Token>) {
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            // Skip constructors
            if method.name == wellknown::members::CTOR || method.name == wellknown::members::CCTOR {
                continue;
            }

            // Must be static with 3 parameters
            if !method.is_static() || method.signature.params.len() != 3 {
                continue;
            }

            let params = &method.signature.params;

            // First param: Class (System.Array)
            let Some(p0) = params.first() else { continue };
            if !matches!(p0.base, TypeSignature::Class(_)) {
                continue;
            }

            // Second param: ValueType (RuntimeFieldHandle)
            let Some(p1) = params.get(1) else { continue };
            if !matches!(p1.base, TypeSignature::ValueType(_)) {
                continue;
            }

            // Third param: I4 (the XOR key)
            let Some(p2) = params.get(2) else { continue };
            if !matches!(p2.base, TypeSignature::I4) {
                continue;
            }

            // Return type should be void
            if !matches!(method.signature.return_type.base, TypeSignature::Void) {
                continue;
            }

            // Scan the method body for a `call` to `RuntimeHelpers.InitializeArray`
            let Ok(method_body) = assembly.method(&method.token) else {
                continue;
            };

            let mut init_array_target = None;
            for instr in method_body.instructions() {
                if instr.mnemonic != "call" {
                    continue;
                }
                let Operand::Token(call_token) = &instr.operand else {
                    continue;
                };
                // Check if this is a MemberRef named "InitializeArray"
                if call_token.is_table(TableId::MemberRef) {
                    if let Some(mr) = assembly.member_ref(call_token) {
                        if mr.name == "InitializeArray" {
                            init_array_target = Some(*call_token);
                            break;
                        }
                    }
                }
            }

            if let Some(target) = init_array_target {
                return (Some(method.token), Some(target));
            }
        }
    }

    (None, None)
}

/// Extracts `(field_token, xor_key)` pairs from call sites to `MyInitializeArray`
/// in any method's IL.
///
/// The IL pattern around a `MyInitializeArray` call is:
/// ```text
/// ldc.i4 <index>          // index for GetHandle
/// call GetHandle           // returns RuntimeFieldHandle
/// ldc.i4 <xorKey>         // XOR key
/// call MyInitializeArray   // (array, handle, xorKey)
/// ```
///
/// We scan for `call MyInitializeArray`, then look backward for the xorKey
/// (`ldc.i4*` immediately before the call) and the handle index (`ldc.i4*`
/// before the `call GetHandle`).
fn extract_init_array_call_sites(
    assembly: &CilObject,
    init_method: Token,
    accessor_token: Token,
    field_tokens: &[Token],
) -> Vec<(Token, i32)> {
    let mut entries = Vec::new();

    // Build a map from Int32ValueContainer field tokens to resolved values.
    // This is needed because the xorKey is typically loaded via `ldsfld` from
    // the Int32ValueContainer, not via direct `ldc.i4*`.
    let container_values = resolve_int32_container_values(assembly);

    // Scan all methods for calls to MyInitializeArray
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };

            let Ok(method_body) = assembly.method(&method.token) else {
                continue;
            };

            let instructions: Vec<_> = method_body.instructions().collect();

            for (i, instr) in instructions.iter().enumerate() {
                if instr.mnemonic != "call" {
                    continue;
                }
                let Operand::Token(call_token) = &instr.operand else {
                    continue;
                };
                if *call_token != init_method {
                    continue;
                }

                // Found a call to MyInitializeArray. Extract xorKey and field index.
                // The xorKey may come from ldc.i4* or ldsfld (Int32ValueContainer).
                let xor_key = find_preceding_i32_value(&instructions, i, &container_values);

                // Look further back for `call GetHandle` and the index before it.
                // The handle index may also come from ldsfld or ldc.i4*.
                let field_index = find_preceding_get_handle_index(
                    &instructions,
                    i,
                    accessor_token,
                    &container_values,
                );

                if let (Some(xor_key), Some(index)) = (xor_key, field_index) {
                    let index = index as usize;
                    if let Some(&token) = field_tokens.get(index) {
                        entries.push((token, xor_key));
                    }
                }
            }
        }
    }

    entries
}

/// Resolves the Int32ValueContainer field values by statically emulating the
/// delta-chain `.cctor` pattern.
///
/// The `.cctor` has the form:
/// ```text
/// ldc.i8 <seed>
/// ldc.i8 <delta>
/// add
/// dup
/// conv.i4
/// stsfld <field>
/// ldc.i8 <delta>
/// add
/// ...
/// ```
///
/// Returns a map from field token -> resolved i32 value.
fn resolve_int32_container_values(assembly: &CilObject) -> HashMap<Token, i32> {
    // Find the Int32ValueContainer by its structural pattern: a class where
    // ALL fields are static initonly int32, with 10+ fields.
    for type_entry in assembly.types().iter() {
        let cil_type = type_entry.value();

        if cil_type.fields.count() < 10 {
            continue;
        }

        let mut all_static_int32 = true;
        for (_, field) in cil_type.fields.iter() {
            let is_static = field.flags.is_static();
            let is_initonly = field.flags.is_init_only();
            let is_int32 = matches!(field.signature.base, TypeSignature::I4);

            if !(is_static && is_initonly && is_int32) {
                all_static_int32 = false;
                break;
            }
        }

        if !all_static_int32 {
            continue;
        }

        // Found the container. Find and emulate its .cctor.
        let cctor_token = cil_type.methods.iter().find_map(|(_, method_ref)| {
            let method = method_ref.upgrade()?;
            if method.name == wellknown::members::CCTOR {
                Some(method.token)
            } else {
                None
            }
        });

        let Some(cctor_token) = cctor_token else {
            continue;
        };

        // Properly emulate the delta chain using stack simulation
        let values = emulate_delta_chain_cctor(assembly, cctor_token);
        if !values.is_empty() {
            return values;
        }
    }

    HashMap::new()
}

/// Emulates the delta-chain .cctor using stack simulation.
///
/// The delta chain pushes i64 values, adds them, dups the accumulator,
/// truncates to i32, and stores to fields. JIEJIE.NET may control-flow-obfuscate
/// the .cctor with branches, so this function follows `br`/`br.s` instructions
/// to process in execution order rather than linear instruction order.
fn emulate_delta_chain_cctor(assembly: &CilObject, cctor_token: Token) -> HashMap<Token, i32> {
    let mut values = HashMap::new();

    let Ok(method) = assembly.method(&cctor_token) else {
        return values;
    };

    // Branch targets are instruction RVAs, so following one is a lookup by RVA.
    let instructions: Vec<_> = method.instructions().collect();
    let rva_map: HashMap<u64, usize> = instructions
        .iter()
        .enumerate()
        .map(|(i, instr)| (instr.rva, i))
        .collect();

    let mut stack: Vec<i64> = Vec::new();
    let mut pc = 0usize;
    let mut visited = 0u32; // safety counter

    while pc < instructions.len() {
        visited = visited.saturating_add(1);
        if visited > 1000 {
            break; // safety limit
        }

        let Some(instr) = instructions.get(pc) else {
            break;
        };
        let instr = *instr;
        pc = pc.saturating_add(1);

        match instr.mnemonic {
            "ldc.i8" => {
                if let Operand::Immediate(Immediate::Int64(v)) = &instr.operand {
                    stack.push(*v);
                }
            }
            "ldc.i4" | "ldc.i4.s" | "ldc.i4.0" | "ldc.i4.1" | "ldc.i4.2" | "ldc.i4.3"
            | "ldc.i4.4" | "ldc.i4.5" | "ldc.i4.6" | "ldc.i4.7" | "ldc.i4.8" | "ldc.i4.m1" => {
                if let Some(v) = instr.get_ldc_i4_value() {
                    stack.push(i64::from(v));
                }
            }
            "add" => {
                let (Some(b), Some(a)) = (stack.pop(), stack.pop()) else {
                    break;
                };
                stack.push(a.wrapping_add(b));
            }
            "dup" => {
                if let Some(&top) = stack.last() {
                    stack.push(top);
                }
            }
            "conv.i4" => {
                if let Some(top) = stack.last_mut() {
                    *top = i64::from(*top as i32);
                }
            }
            "stsfld" => {
                if let Operand::Token(field_token) = &instr.operand {
                    if let Some(val) = stack.pop() {
                        values.insert(*field_token, val as i32);
                    }
                }
            }
            "pop" => {
                stack.pop();
            }
            "br" | "br.s" => {
                match instr
                    .get_branch_target()
                    .and_then(|target| rva_map.get(&target))
                {
                    Some(&target_idx) => pc = target_idx,
                    None => break,
                }
            }
            "ret" => break,
            _ => {}
        }
    }

    values
}

/// Finds the i32 value from the nearest `ldc.i4*` or `ldsfld` (Int32ValueContainer)
/// instruction preceding `pos`.
fn find_preceding_i32_value(
    instructions: &[&Instruction],
    pos: usize,
    container_values: &HashMap<Token, i32>,
) -> Option<i32> {
    // Search backward from pos-1, limited distance
    for j in (0..pos).rev() {
        let Some(instr) = instructions.get(j) else {
            break;
        };
        // Try direct ldc.i4* constant
        if let Some(val) = instr.get_ldc_i4_value() {
            return Some(val);
        }
        // Try ldsfld from Int32ValueContainer
        if instr.mnemonic == "ldsfld" {
            if let Operand::Token(field_token) = &instr.operand {
                if let Some(&val) = container_values.get(field_token) {
                    return Some(val);
                }
            }
        }
        // Stop searching after a few instructions
        if pos.saturating_sub(j) > 5 {
            break;
        }
    }
    None
}

/// Finds the i32 index constant preceding a `call GetHandle` instruction
/// that occurs before `pos`.
fn find_preceding_get_handle_index(
    instructions: &[&Instruction],
    pos: usize,
    accessor_token: Token,
    container_values: &HashMap<Token, i32>,
) -> Option<i32> {
    // Search backward for `call GetHandle` (the accessor)
    for j in (0..pos).rev() {
        let Some(instr) = instructions.get(j) else {
            break;
        };
        if instr.mnemonic == "call" {
            if let Operand::Token(t) = &instr.operand {
                if *t == accessor_token {
                    // Found GetHandle call; now find the value before it
                    return find_preceding_i32_value(instructions, j, container_values);
                }
            }
        }
        // Don't search too far back
        if pos.saturating_sub(j) > 10 {
            break;
        }
    }
    None
}

/// XOR-decrypts a FieldRVA data block and returns the decrypted bytes
/// along with the FieldRVA row RID for use with the changes system.
///
/// Returns `Ok(Some((fieldrva_rid, decrypted_data)))` on success,
/// `Ok(None)` if the RVA is 0 or size is 0, `Err` on failure.
fn decrypt_field_rva_data_to_bytes(
    assembly: &CilObject,
    field_token: Token,
    xor_key: i32,
) -> Result<Option<(u32, Vec<u8>)>> {
    let file = assembly.file();

    let tables = assembly
        .tables()
        .ok_or_else(|| Error::Other("No metadata tables available".to_string()))?;
    let fieldrva_table = tables
        .table::<FieldRvaRaw>()
        .ok_or_else(|| Error::Other("No FieldRVA table found".to_string()))?;

    let field_rid = field_token.row();
    let rva_entry = fieldrva_table
        .iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|row| row.field == field_rid)
        .ok_or_else(|| {
            Error::Other(format!(
                "No FieldRVA entry for field 0x{:08X}",
                field_token.value(),
            ))
        })?;

    let rva = rva_entry.rva;
    if rva == 0 {
        return Ok(None);
    }

    let data_size = calculate_field_data_size(assembly, field_rid)?;
    if data_size == 0 {
        return Ok(None);
    }

    let mut decrypted = file.rva_slice(rva as usize, data_size)?.into_owned();

    xor_decrypt_array_data(&mut decrypted, xor_key);

    Ok(Some((rva_entry.rid, decrypted)))
}

/// Calculates the data size for a field from its FieldRVA entry.
///
/// Uses the ClassLayout table for ValueType fields (the common case for
/// array-init backing fields which are ExplicitLayout structs).
fn calculate_field_data_size(assembly: &CilObject, field_rid: u32) -> Result<usize> {
    let tables = assembly
        .tables()
        .ok_or_else(|| Error::Other("No metadata tables".to_string()))?;

    let field_table = tables
        .table::<FieldRaw>()
        .ok_or_else(|| Error::Other("No Field table".to_string()))?;
    let field_row = field_table
        .iter()
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .find(|r| r.rid == field_rid)
        .ok_or_else(|| Error::Other(format!("Field {field_rid} not found")))?;

    let blobs = assembly
        .blob()
        .ok_or_else(|| Error::Other("No blob heap".to_string()))?;
    let sig_data = blobs
        .get(field_row.signature as usize)
        .map_err(|_| Error::Other(format!("Cannot read signature for field {field_rid}")))?;
    let field_sig = parse_field_signature(sig_data)
        .map_err(|e| Error::Other(format!("Cannot parse field {field_rid} signature: {e}")))?;

    // Try primitive size first
    let ptr_size = PointerSize::from_is_64bit(assembly.file().pe().is_64bit);
    if let Some(size) = field_sig.base.byte_size(ptr_size) {
        return Ok(size);
    }

    // For ValueType, look up ClassLayout
    if let TypeSignature::ValueType(type_token) = &field_sig.base {
        if type_token.is_table(TableId::TypeDef) {
            let row = type_token.row();
            if let Some(class_layout_table) = tables.table::<ClassLayoutRaw>() {
                for layout_row in class_layout_table {
                    let layout_row = layout_row?;
                    if layout_row.parent == row {
                        return Ok(layout_row.class_size as usize);
                    }
                }
            }
        }
    }

    Err(Error::Other(format!(
        "Cannot determine size for field {field_rid}"
    )))
}

/// XOR-decrypts array data using the JIEJIE.NET algorithm.
///
/// Processes 4-byte blocks from end to start. The key starts at `xor_key`
/// and increments by 13 after each block (rolling key).
fn xor_decrypt_array_data(data: &mut [u8], xor_key: i32) {
    let block_count = data.len() / 4;
    let mut key = xor_key;
    // Iterate from end to start in 4-byte blocks
    for i in (0..block_count).rev() {
        let offset = i.saturating_mul(4);
        let key_bytes = key.to_le_bytes();
        let Some(block) = data.get_mut(offset..offset.saturating_add(4)) else {
            break;
        };
        for (b, k) in block.iter_mut().zip(key_bytes.iter()) {
            *b ^= *k;
        }
        key = key.wrapping_add(13);
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            jiejienet::arrays::{xor_decrypt_array_data, ArrayFindings, JiejieNetArrays},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive_controlflow() {
        let asm = load_sample("packers/jiejie/source/jiejie_controlflow_no_rename.exe");
        let technique = JiejieNetArrays;
        let detection = technique.detect(&asm);

        assert!(
            detection.is_detected(),
            "Should detect field handle container"
        );

        let findings = detection
            .findings::<ArrayFindings>()
            .expect("Should have ArrayFindings");

        assert_eq!(findings.handle_count, 3, "Should find 3 field handles");
    }

    #[test]
    fn test_detect_negative_strings_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_strings_only.exe");
        let technique = JiejieNetArrays;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "Should not detect in strings-only"
        );
    }

    #[test]
    fn test_detect_negative_original() {
        let asm = load_sample("packers/jiejie/source/original.exe");
        let technique = JiejieNetArrays;
        let detection = technique.detect(&asm);

        assert!(!detection.is_detected(), "Should not detect in original");
    }

    #[test]
    fn test_xor_decrypt_round_trip() {
        // Encrypt then decrypt should yield original
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let mut data = original.clone();
        let xor_key = 42;

        // Encrypt (same algorithm, it's XOR so it's its own inverse applied in same order)
        xor_decrypt_array_data(&mut data, xor_key);
        // The data should now be different
        assert_ne!(data, original);
        // Decrypt
        xor_decrypt_array_data(&mut data, xor_key);
        // Should match original
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_decrypt_known_values() {
        // Decryption iterates blocks in reverse: block[1] gets key=0, block[0] gets key=13
        let xor_key: i32 = 0;

        // Block 0 = [0x0D,0,0,0] XOR key=13 => [0,0,0,0]; Block 1 = [0,0,0,0] XOR key=0 => [0,0,0,0]
        let mut data = vec![0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        xor_decrypt_array_data(&mut data, xor_key);
        assert_eq!(data, vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // Trailing bytes (less than 4) are not touched; single block uses key=0
        let mut data_with_trail = vec![0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF];
        xor_decrypt_array_data(&mut data_with_trail, xor_key);
        assert_eq!(data_with_trail[0..4], [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(data_with_trail[4], 0xFF);
        assert_eq!(data_with_trail[5], 0xFF);
    }
}
