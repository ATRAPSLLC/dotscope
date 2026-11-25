//! BitMono DotNetHook detection and reversal technique.
//!
//! Detects and reverses BitMono's DotNetHook protection, which redirects method
//! calls through dynamically-generated stubs. The hook infrastructure type
//! contains methods referencing `PrepareMethod`, `GetFunctionPointer`,
//! `VirtualProtect` (JIT hooking setup) and `Marshal.Write*` (memory patching)
//! APIs. A `RedirectStub` method with signature `static void(int32, int32)`
//! patches method entry points at runtime.
//!
//! # Protection
//!
//! For every call site it hooks, DotNetHook adds two methods to `<Module>`, one right after
//! the other: a dummy, whose body is never run, and an init method,
//! `ldc.i4 <dummy>; ldc.i4 <target>; call RedirectStub; ret`, which the module initializer
//! calls to patch the dummy's native code into a jump to the target. The call site calls the
//! dummy instead of the target. The dummy takes the target's parameters: BitMono 0.39 copies
//! the target's signature as is, its `HasThis` flag included; later versions make an instance
//! target's `this` the dummy's first parameter, and skip value types and generic types.
//!
//! The two tokens in an init method are stale in the protected file: see
//! [`bitmono.tokens`](super::tokens), which rewrites them before this technique runs.
//!
//! # Transform
//!
//! Every `call`, `callvirt` or `newobj` of a dummy, and every CallToCalli `ldc.i4` naming one,
//! is redirected to the dummy's target. A pair whose dummy is not the method before its init
//! method, or whose target the dummy's signature does not admit, fails the transform: patching
//! it would redirect calls to a method they never called.

use std::{any::Any, collections::HashMap};

use crate::{
    assembly::Instruction,
    compiler::{EventKind, EventLog},
    deobfuscation::techniques::{
        Detection, Evidence, Technique, TechniqueCapability, TechniqueCategory, WorkingAssembly,
    },
    metadata::{
        method::Method,
        signatures::{SignatureMethod, TypeSignature},
        tables::{MemberRefRaw, TableId},
        token::Token,
    },
    CilObject, Error, Result,
};

/// Findings from BitMono DotNetHook detection.
#[derive(Debug)]
pub struct HookFindings {
    /// Token of the type containing hook infrastructure (PrepareMethod + Marshal.Write).
    pub infrastructure_type: Option<Token>,
    /// Token of the `RedirectStub` method: `static void(int32, int32)`.
    pub redirect_stub: Option<Token>,
    /// Number of hook redirect pairs detected.
    pub hook_count: usize,
    /// The dummy methods, one per init method.
    pub dummy_methods: Vec<Token>,
    /// The init methods, which call `RedirectStub` to set up the hooks.
    pub init_methods: Vec<Token>,
}

/// A DotNetHook init method and the two tokens it passes to `RedirectStub`.
#[derive(Debug, Clone, Copy)]
pub struct InitPair {
    /// The init method.
    pub init: Token,
    /// The file offset of the dummy token's `ldc.i4` operand.
    pub dummy_operand: u64,
    /// The dummy token, as the init method holds it.
    pub dummy: u32,
    /// The file offset of the target token's `ldc.i4` operand.
    pub target_operand: u64,
    /// The target token, as the init method holds it.
    pub target: u32,
}

/// Detects and reverses BitMono's DotNetHook method redirection.
///
/// DotNetHook replaces direct `call <target>` instructions with calls to dummy
/// methods whose native entry points are patched at runtime to jump to the real
/// targets. Detection identifies the infrastructure type by scanning for
/// `PrepareMethod` + `Marshal.Write*` API references, and the `RedirectStub`
/// by its `static void(int32, int32)` signature.
pub struct BitMonoHooks;

impl Technique for BitMonoHooks {
    fn id(&self) -> &'static str {
        "bitmono.hooks"
    }

    fn name(&self) -> &'static str {
        "BitMono DotNetHook Reversal"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Protection
    }

    fn requires(&self) -> &[&'static str] {
        &["bitmono.tokens"]
    }

    fn capabilities(&self) -> Vec<TechniqueCapability> {
        vec![TechniqueCapability::ByteTransform]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let Some(infrastructure_type) = infrastructure_type(assembly) else {
            return Detection::new_empty();
        };
        let redirect_stub = find_redirect_stub(assembly);

        // The dummies and init methods live in <Module>, not the infrastructure type, so they
        // must be marked for removal on their own.
        let pairs = redirect_stub.map_or_else(Vec::new, |stub| init_pairs(assembly, stub));
        let init_methods: Vec<Token> = pairs.iter().map(|pair| pair.init).collect();
        let dummy_methods: Vec<Token> = pairs
            .iter()
            .filter_map(|pair| dummy_of(assembly, pair.init))
            .collect();

        let mut evidence = vec![Evidence::Structural(
            "BitMono DotNetHook infrastructure (PrepareMethod + Marshal.Write)".to_string(),
        )];
        if redirect_stub.is_some() {
            evidence.push(Evidence::Structural(
                "RedirectStub identified: static void(int32, int32)".to_string(),
            ));
        }

        let mut detection = Detection::new_detected(
            evidence,
            Some(Box::new(HookFindings {
                infrastructure_type: Some(infrastructure_type),
                redirect_stub,
                hook_count: pairs.len(),
                dummy_methods: dummy_methods.clone(),
                init_methods: init_methods.clone(),
            }) as Box<dyn Any + Send + Sync>),
        );

        // Mark infrastructure type for cleanup so post-deobfuscation
        // re-detection doesn't re-trigger.
        detection.cleanup_mut().add_type(infrastructure_type);
        detection.cleanup_mut().add_methods(dummy_methods);
        detection.cleanup_mut().add_methods(init_methods);

        detection
    }

    fn byte_transform(
        &self,
        assembly: &mut WorkingAssembly,
        detection: &mut Detection,
    ) -> Option<Result<EventLog>> {
        let events = EventLog::new();

        if detection.findings::<HookFindings>().is_none() {
            return Some(Ok(events));
        }

        let co = match assembly.cilobject() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let Some(redirect_stub) = find_redirect_stub(co) else {
            events.record(EventKind::ArtifactRemoved).message(
                "DotNetHook: infrastructure detected but RedirectStub not found".to_string(),
            );
            return Some(Ok(events));
        };

        // Dummy token -> target token, each pair checked against the layout DotNetHook writes.
        let mut redirect: HashMap<u32, u32> = HashMap::new();
        for pair in init_pairs(co, redirect_stub) {
            let dummy = dummy_of(co, pair.init);
            let admitted = dummy
                .filter(|dummy| dummy.value() == pair.dummy)
                .and_then(|dummy| co.method(&dummy).ok())
                .zip(co.method(&Token::new(pair.target)).ok())
                .is_some_and(|(dummy, target)| dummy_admits(&dummy.signature, &target));
            if !admitted {
                return Some(Err(Error::Deobfuscation(format!(
                    "DotNetHook: init method {} pairs 0x{:08X} with 0x{:08X}, which is not a \
                     dummy and the target its signature stands for",
                    pair.init, pair.dummy, pair.target
                ))));
            }
            redirect.insert(pair.dummy, pair.target);
        }

        if redirect.is_empty() {
            events
                .record(EventKind::ArtifactRemoved)
                .message("DotNetHook: no redirect mappings found".to_string());
            return Some(Ok(events));
        }

        // Every operand naming a dummy: the call sites DotNetHook rewrote, and the `ldc.i4` of a
        // CallToCalli site that rewrote one of those calls in turn.
        let mut patches: Vec<(u64, u32)> = Vec::new();
        for method_entry in co.methods() {
            let instructions: Vec<&Instruction> = method_entry.value().instructions().collect();
            for (i, instr) in instructions.iter().enumerate() {
                let named = match instr.mnemonic {
                    "call" | "callvirt" | "newobj" => {
                        instr.get_token_operand().map(|token| token.value())
                    }
                    "ldc.i4"
                        if instructions
                            .get(i.saturating_add(1))
                            .is_some_and(|next| is_resolve_method_call(co, next)) =>
                    {
                        instr.get_i32_operand().map(i32::cast_unsigned)
                    }
                    _ => None,
                };
                let Some(&target) = named.and_then(|token| redirect.get(&token)) else {
                    continue;
                };
                // The token operand is the last 4 bytes of the instruction.
                let Some(operand) = instr
                    .offset
                    .checked_add(instr.size)
                    .and_then(|end| end.checked_sub(4))
                else {
                    return Some(Err(Error::Deobfuscation(
                        "DotNetHook: instruction offset overflow computing operand position".into(),
                    )));
                };
                patches.push((operand, target));
            }
        }

        for &(operand, target) in &patches {
            let Ok(operand) = usize::try_from(operand) else {
                return Some(Err(Error::Deobfuscation(format!(
                    "DotNetHook: operand offset 0x{operand:X} exceeds the address space"
                ))));
            };
            if let Err(e) = assembly.write_le::<u32>(operand, target) {
                return Some(Err(e));
            }
        }

        events.record(EventKind::ArtifactRemoved).message(format!(
            "Reversed {} DotNetHook redirections, patched {} call sites",
            redirect.len(),
            patches.len()
        ));

        Some(Ok(events))
    }

    fn requires_regeneration(&self) -> bool {
        true
    }
}

/// The type holding the hook infrastructure: a method setting up the JIT hook
/// (`PrepareMethod`, `GetFunctionPointer`, `VirtualProtect`, `mprotect`) and one writing
/// through `Marshal.Write*`.
fn infrastructure_type(assembly: &CilObject) -> Option<Token> {
    assembly.types().iter().find_map(|type_entry| {
        let cil_type = type_entry.value();
        let mut has_jit_hook_setup = false;
        let mut has_marshal_write = false;
        for (_, method_ref) in cil_type.methods.iter() {
            let Some(method) = method_ref.upgrade() else {
                continue;
            };
            for instr in method.instructions() {
                let Some(token) = instr.get_token_operand() else {
                    continue;
                };
                if assembly.resolve_method_name(token).is_some_and(|name| {
                    name.contains("PrepareMethod")
                        || name.contains("GetFunctionPointer")
                        || name.contains("VirtualProtect")
                        || name.contains("mprotect")
                }) {
                    has_jit_hook_setup = true;
                }
                if assembly.member_ref(&token).is_some_and(|member| {
                    member.name.contains("Write")
                        && member
                            .declaredby
                            .fullname()
                            .is_some_and(|t| t.contains("Marshal"))
                }) {
                    has_marshal_write = true;
                }
            }
        }
        (has_jit_hook_setup && has_marshal_write).then_some(cil_type.token)
    })
}

/// Finds the `RedirectStub` method token by signature and body content.
///
/// Scans all methods for a `static void(int32, int32)` whose body references
/// `PrepareMethod` or `GetFunctionPointer`. This signature-based search is
/// robust to FullRenamer obfuscation where the method name is gone.
///
/// # Arguments
///
/// * `assembly` - The assembly to scan.
///
/// # Returns
///
/// `Some(token)` of the first matching `RedirectStub` method, or `None` if
/// no method matches the signature and body criteria.
pub fn find_redirect_stub(assembly: &CilObject) -> Option<Token> {
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        if !method.is_static() {
            continue;
        }
        if !matches!(method.signature.return_type.base, TypeSignature::Void) {
            continue;
        }
        if method.signature.params.len() != 2 {
            continue;
        }
        let both_i4 = method
            .signature
            .params
            .iter()
            .all(|p| matches!(p.base, TypeSignature::I4));
        if !both_i4 {
            continue;
        }
        let has_hook_api = method.instructions().any(|instr| {
            instr
                .get_token_operand()
                .and_then(|t| assembly.resolve_method_name(t))
                .is_some_and(|n| n.contains("PrepareMethod") || n.contains("GetFunctionPointer"))
        });
        if has_hook_api {
            return Some(method.token);
        }
    }
    None
}

/// The init methods calling `redirect_stub`: `ldc.i4 <dummy>; ldc.i4 <target>; call
/// RedirectStub`, both tokens MethodDef tokens.
pub fn init_pairs(assembly: &CilObject, redirect_stub: Token) -> Vec<InitPair> {
    let mut pairs = Vec::new();
    for method_entry in assembly.methods() {
        let method = method_entry.value();
        let instructions: Vec<&Instruction> = method.instructions().collect();
        for window in instructions.windows(3) {
            let [dummy, target, call] = window else {
                continue;
            };
            if call.mnemonic != "call"
                || !call.get_token_operand().is_some_and(|callee| {
                    callee == redirect_stub
                        || is_redirect_stub_memberref(assembly, callee, redirect_stub)
                })
            {
                continue;
            }
            let operand = |instr: &Instruction| {
                (instr.mnemonic == "ldc.i4")
                    .then(|| instr.get_i32_operand())
                    .flatten()
                    .map(|value| (instr.offset.saturating_add(1), value.cast_unsigned()))
            };
            let (Some((dummy_operand, dummy)), Some((target_operand, target))) =
                (operand(dummy), operand(target))
            else {
                continue;
            };
            if dummy >> 24 == 0x06 && target >> 24 == 0x06 {
                pairs.push(InitPair {
                    init: method.token,
                    dummy_operand,
                    dummy,
                    target_operand,
                    target,
                });
            }
        }
    }
    pairs.sort_by_key(|pair| pair.init.value());
    pairs
}

/// The dummy an init method sets up: DotNetHook adds it to `<Module>` right before the init
/// method. `None` when the method before is not a static `<Module>` method with a dummy's
/// body.
pub fn dummy_of(assembly: &CilObject, init: Token) -> Option<Token> {
    let module = assembly.types().module_type()?.token;
    let dummy = assembly
        .method(&Token::from_parts(
            TableId::MethodDef,
            init.row().checked_sub(1)?,
        ))
        .ok()?;
    let in_module = dummy
        .declaring_type_rc()
        .is_some_and(|declaring| declaring.token == module);
    let instructions: Vec<&Instruction> = dummy.instructions().collect();
    (in_module && dummy.is_static() && is_dummy_body(&instructions)).then_some(dummy.token)
}

/// Whether a dummy with signature `dummy` stands for `target`: a static target's signature
/// is the dummy's; an instance target's is the dummy's with its `HasThis` flag (BitMono
/// 0.39), or without the first parameter, which is the target's declaring type (later
/// versions).
pub fn dummy_admits(dummy: &SignatureMethod, target: &Method) -> bool {
    let signature = &target.signature;
    let returns = dummy.return_type.by_ref == signature.return_type.by_ref
        && dummy.return_type.base == signature.return_type.base;
    if !returns || dummy.param_count_generic != signature.param_count_generic {
        return false;
    }
    if target.is_static() || dummy.has_this {
        return dummy.has_this != target.is_static() && dummy.has_same_parameters(signature);
    }
    let Some((this, rest)) = dummy.params.split_first() else {
        return false;
    };
    let declaring = target.declaring_type_rc().map(|declaring| declaring.token);
    !this.by_ref
        && declaring.is_some_and(|declaring| this.base == TypeSignature::Class(declaring))
        && rest.len() == signature.params.len()
        && rest
            .iter()
            .zip(&signature.params)
            .all(|(a, b)| a.by_ref == b.by_ref && a.base == b.base)
}

/// Whether `instr` calls `System.Reflection.Module::ResolveMethod`, as a CallToCalli site
/// does right after the `ldc.i4` holding the token it resolves.
pub fn is_resolve_method_call(assembly: &CilObject, instr: &Instruction) -> bool {
    instr.mnemonic == "call"
        && instr
            .get_token_operand()
            .and_then(|token| assembly.member_ref(&token))
            .is_some_and(|member| {
                member.name == "ResolveMethod"
                    && member
                        .declaredby
                        .fullname()
                        .is_some_and(|t| t == "System.Reflection.Module")
            })
}

/// Returns `true` if a method body matches the DotNetHook dummy pattern.
///
/// Dummies are created with an empty `CilMethodBody` that AsmResolver fills with
/// just `ret` (void return) or a simple default-value push followed by `ret`
/// (non-void return). Their native code is patched at runtime so the body is
/// never executed.
///
/// # Arguments
///
/// * `instructions` - Slice of instruction references from the method body.
///
/// # Returns
///
/// `true` if the body matches one of the recognized dummy patterns:
/// - 1 instruction: `ret`
/// - 2 instructions: `ldc.*` or `ldnull`, then `ret`
/// - 3 instructions: `ldc.*` + `conv.*` + `ret`, or `ldloca` + `initobj` + `ret`
fn is_dummy_body(instructions: &[&Instruction]) -> bool {
    let Some(last) = instructions.last() else {
        return false;
    };
    if last.mnemonic != "ret" {
        return false;
    }
    match instructions.len() {
        1 => true, // just ret (void or stack-underflow dummy)
        2 => {
            let Some(first) = instructions.first() else {
                return false;
            };
            let m = first.mnemonic;
            m.starts_with("ldc.") || m == "ldnull"
        }
        3 => {
            let Some(i0) = instructions.first() else {
                return false;
            };
            let Some(i1) = instructions.get(1) else {
                return false;
            };
            let m0 = i0.mnemonic;
            let m1 = i1.mnemonic;
            // ldc.i4.0 + conv.i8 + ret (int64 return)
            // ldloca.s + initobj + ret (value type return, rare)
            (m0.starts_with("ldc.") && m1.starts_with("conv."))
                || (m0.starts_with("ldloca") && m1 == "initobj")
        }
        _ => false,
    }
}

/// Returns `true` if `token` is a `MemberRef` that resolves to the same declaring
/// type as `redirect_stub_token`.
///
/// Used to handle cross-assembly references where the caller uses a `MemberRef`
/// (table `0x0A`) rather than a direct `MethodDef` token. Matches by declaring
/// type: if the `MemberRef`'s class points to the same `TypeDef` row that
/// contains the identified `RedirectStub`.
///
/// # Arguments
///
/// * `assembly` - The assembly containing both tokens.
/// * `token` - Candidate token to test (must be a `MemberRef`, table `0x0A`).
/// * `redirect_stub_token` - The known `RedirectStub` `MethodDef` token.
///
/// # Returns
///
/// `true` if `token` is a `MemberRef` whose class is the `TypeDef` that
/// declares `redirect_stub_token`, `false` otherwise.
fn is_redirect_stub_memberref(
    assembly: &CilObject,
    token: Token,
    redirect_stub_token: Token,
) -> bool {
    if token.table() != 0x0A {
        return false;
    }

    let Some(tables) = assembly.tables() else {
        return false;
    };
    let Some(memberref_table) = tables.table::<MemberRefRaw>() else {
        return false;
    };
    let Some(memberref) = memberref_table.get(token.row()).ok().flatten() else {
        return false;
    };

    if memberref.class.tag == TableId::TypeDef {
        if let Ok(stub_method) = assembly.method(&redirect_stub_token) {
            if let Some(stub_type) = stub_method.declaring_type_rc() {
                return memberref.class.row == stub_type.token.row();
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::helpers::load_sample;

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/bitmono/0.39.0/bitmono_dotnethook.exe");

        let technique = BitMonoHooks;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "BitMonoHooks should detect DotNetHook infrastructure in bitmono_dotnethook.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should include evidence"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = BitMonoHooks;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "BitMonoHooks should not detect DotNetHook in a non-BitMono assembly"
        );
    }

    #[test]
    fn every_dummy_is_the_method_before_its_init_method() {
        // BitMono 0.39 hooks `newobj` as well; later versions leave object construction alone.
        for (version, hooks) in [("0.39.0", 36), ("0.45.0", 31)] {
            let assembly =
                load_sample(&format!("packers/bitmono/{version}/bitmono_dotnethook.exe"));
            let stub = find_redirect_stub(&assembly).expect("RedirectStub");
            let pairs = init_pairs(&assembly, stub);
            assert_eq!(pairs.len(), hooks, "{version}");
            for pair in &pairs {
                let dummy = dummy_of(&assembly, pair.init);
                assert!(
                    dummy.is_some(),
                    "{version}: init {} has no dummy before it",
                    pair.init
                );
            }
        }
    }

    #[test]
    fn stale_pairs_are_refused_not_patched() {
        // Without bitmono.tokens, the init methods still hold the rows of the module BitMono
        // loaded: patching by them would redirect every hooked call to the wrong method.
        let mut assembly =
            WorkingAssembly::new(load_sample("packers/bitmono/0.45.0/bitmono_dotnethook.exe"));
        let technique = BitMonoHooks;
        let mut detection = technique.detect(assembly.cilobject().expect("loaded"));
        let result = technique
            .byte_transform(&mut assembly, &mut detection)
            .expect("a transform");
        assert!(result.is_err(), "stale pairs are refused");
        assert!(!assembly.has_pending(), "nothing is patched");
    }
}
