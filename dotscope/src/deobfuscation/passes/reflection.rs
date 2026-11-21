//! Reflection devirtualization SSA pass.
//!
//! Resolves reflection-based call indirection by tracing SSA def-use chains
//! from reflection API calls back to constant-resolvable targets, then
//! replacing the indirect call with a direct or virtual `Call`, a `NewObj`, a
//! `LoadField`, or a `StoreField`.
//!
//! # Supported Patterns
//!
//! | ID | Pattern | Replacement |
//! |----|---------|-------------|
//! | P1 | `ResolveMethod(module, Const(token)) → GetFunctionPointer → calli` | `Call(token, args)` |
//! | P2 | `ResolveMethod(module, Const(token)) → MethodInfo.Invoke(obj, args[])` | `Call(token, unpacked_args)` |
//! | P3 | `Type.GetMethod(Const("name")) → Invoke(obj, args[])` | `Call(resolved, unpacked_args)` |
//! | P5 | `Activator.CreateInstance(Const(type))` | `NewObj(type::.ctor)` |
//! | P6 | `ResolveField(Const(token)) → GetValue/SetValue` | `LoadField`/`StoreField` |
//!
//! # Pipeline Position
//!
//! This pass runs in the **Simplify** phase, before string decryption passes
//! that depend on resolved direct calls. Created by
//! [`GenericDelegateProxy::create_pass()`](crate::deobfuscation::techniques::generic::GenericDelegateProxy).
//!
//! # Algorithm
//!
//! For each method in the pre-detected affected set, scans all instructions:
//! - `calli`: attempts P1 chain trace (ResolveMethod → GetFunctionPointer)
//! - `call`/`callvirt` to `Invoke`: attempts P2 (ResolveMethod) then P3 (GetMethod)
//! - `call`/`callvirt` to `CreateInstance`: attempts P5 (Activator)
//! - `call`/`callvirt` to `GetValue`/`SetValue`: attempts P6 (FieldInfo)
//!
//! All patterns trace backward through SSA def-use chains to find
//! constant-resolvable targets. If any step in the chain fails to resolve,
//! the site is silently skipped - no false positives are possible.
//!
//! # Example (P1 - ResolveMethod + calli)
//!
//! ```text
//! // Before:
//! v0 = LoadToken(<Module>)
//! v1 = call GetTypeFromHandle(v0)
//! v2 = callvirt get_Module(v1)
//! v3 = Const(I32(0x06000042))
//! v4 = call ResolveMethod(v2, v3)
//! v5 = callvirt get_MethodHandle(v4)
//! v6 = call GetFunctionPointer(v5)
//! v7 = calli(v6, args...)
//!
//! // After:
//! Nop (intermediates cleaned up)
//! v7 = call 0x06000042(args...)
//! ```
//!
//! # Example (P2 - ResolveMethod + Invoke)
//!
//! ```text
//! // Before:
//! v0-v4 = ResolveMethod chain (same as P1 steps 0-4)
//! v5 = NewArr(Object, 2)
//!      StoreElement(v5, 0, Box(arg1))
//!      StoreElement(v5, 1, Box(arg2))
//! v6 = callvirt Invoke(v4, null, v5)
//!
//! // After:
//! v6 = call 0x06000042(arg1, arg2)
//! ```
//!
//! # Argument Unpacking
//!
//! Patterns P2 and P3 pass arguments via `object[]`. The [`unpack_object_array`]
//! utility traces the array construction backward:
//! 1. Find the `NewArr` that allocates the array
//! 2. Collect all `StoreElement` writes with constant indices
//! 3. Unwrap `Box` on each element to recover the original pre-boxed value
//! 4. Return the arguments sorted by index
//!
//! If the array cannot be fully traced (dynamic indices, missing elements),
//! the entire reflection site is skipped.

use std::collections::HashSet;

use dashmap::DashSet;

use crate::{
    analysis::{
        AccessQualifiers, CallData, Callee, CilTarget, ConstValue, FieldRef, MethodRef,
        SsaFunction, SsaInstruction, SsaOp, SsaOpCilExt, SsaVarId, VariableOrigin,
    },
    compiler::{CompilerContext, EventKind, ModificationScope, SsaPass},
    deobfuscation::utils::is_method_named,
    metadata::token::Token,
    CilObject,
};

/// A detected reflection call site with its resolved target and location.
///
/// Each variant captures enough information to rewrite the reflection call
/// to a direct operation: the SSA location `(block, idx)`, the resolved
/// target (method/field token), and the list of intermediate trampoline
/// instructions to NOP out after rewriting.
#[derive(Debug)]
enum ReflectionSite {
    /// P1: `Module.ResolveMethod(Const(token)) → GetFunctionPointer → calli`
    ///
    /// The full chain from `LoadToken` through `GetTypeFromHandle`, `get_Module`,
    /// `ResolveMethod`, `get_MethodHandle`, `GetFunctionPointer` to `calli`.
    /// All intermediate instructions are collected for cleanup.
    ResolveMethodCalli {
        block: usize,
        idx: usize,
        target_token: u32,
        dest: Option<SsaVarId>,
        args: Vec<SsaVarId>,
        intermediates: Vec<(usize, usize)>,
    },
    /// P2: `Module.ResolveMethod(Const(token)) → MethodInfo.Invoke(obj, object[])`
    ///
    /// Same ResolveMethod chain as P1, but instead of `GetFunctionPointer → calli`,
    /// the resolved `MethodInfo` is called via `Invoke(obj, params)`. Requires
    /// unpacking the `object[]` argument array.
    ResolveMethodInvoke {
        block: usize,
        idx: usize,
        target_token: u32,
        dest: Option<SsaVarId>,
        obj_var: SsaVarId,
        array_var: SsaVarId,
        intermediates: Vec<(usize, usize)>,
    },
    /// P3: `Type.GetMethod(Const("name")) → MethodInfo.Invoke(obj, object[])`
    ///
    /// The method is resolved by name against a type loaded via
    /// `LoadToken → GetTypeFromHandle → GetMethod("name")`. Requires both
    /// metadata name lookup and `object[]` argument unpacking.
    GetMethodInvoke {
        block: usize,
        idx: usize,
        type_token: Token,
        method_name: String,
        dest: Option<SsaVarId>,
        obj_var: SsaVarId,
        array_var: SsaVarId,
        intermediates: Vec<(usize, usize)>,
    },
    /// P5: `Activator.CreateInstance(Type)` where the type is constant.
    ///
    /// Replaced with `NewObj(type::.ctor())` when the type has a parameterless
    /// constructor. The `Type` argument must trace back to
    /// `GetTypeFromHandle(LoadToken(type))`.
    ActivatorCreate {
        block: usize,
        idx: usize,
        type_token: Token,
        dest: Option<SsaVarId>,
        intermediates: Vec<(usize, usize)>,
    },
    /// P6: `FieldInfo.GetValue(obj)` or `FieldInfo.SetValue(obj, value)`
    ///
    /// The `FieldInfo` must trace back to `Module.ResolveField(Const(token))`.
    /// Replaced with `LoadField`/`LoadStaticField` (GetValue) or
    /// `StoreField`/`StoreStaticField` (SetValue) depending on whether
    /// `obj` is null (static) or non-null (instance).
    FieldAccess {
        block: usize,
        idx: usize,
        field_token: u32,
        is_set: bool,
        dest: Option<SsaVarId>,
        obj_var: SsaVarId,
        value_var: Option<SsaVarId>,
        intermediates: Vec<(usize, usize)>,
    },
}

/// SSA pass that resolves reflection-based call indirection to direct calls.
///
/// Created by [`GenericDelegateProxy::create_pass()`](crate::deobfuscation::techniques::generic::GenericDelegateProxy)
/// from [`ReflectionFindings`](crate::deobfuscation::techniques::generic::delegates::ReflectionFindings)
/// produced during `detect_ssa()`. The findings provide the set of affected
/// method tokens; the pass re-scans each method's current SSA state (which
/// may have changed since detection) to find and rewrite reflection sites.
///
/// Runs in [`PassPhase::Simplify`](crate::compiler::PassPhase::Simplify),
/// before string decryption passes that depend on resolved direct calls.
pub struct ReflectionDevirtualizationPass {
    /// Methods identified during detection as containing reflection call sites.
    target_methods: HashSet<Token>,
    /// Methods already processed (prevents redundant work across iterations).
    processed: DashSet<Token>,
}

impl ReflectionDevirtualizationPass {
    /// Creates a pass targeting the given methods identified during detection.
    ///
    /// # Arguments
    ///
    /// * `methods` - Method tokens containing reflection call indirection sites,
    ///   as detected by [`GenericDelegateProxy::detect_ssa()`](crate::deobfuscation::techniques::generic::GenericDelegateProxy).
    pub fn with_methods(methods: HashSet<Token>) -> Self {
        Self {
            target_methods: methods,
            processed: DashSet::new(),
        }
    }
}

impl SsaPass<CilTarget, CompilerContext> for ReflectionDevirtualizationPass {
    fn name(&self) -> &'static str {
        "reflection-devirtualization"
    }

    fn description(&self) -> &'static str {
        "Resolves reflection-based call indirection to direct calls"
    }

    fn modification_scope(&self) -> ModificationScope {
        ModificationScope::InstructionsOnly
    }

    fn should_run(&self, method: &MethodRef, _host: &CompilerContext) -> bool {
        self.target_methods.contains(&method.0) && !self.processed.contains(&method.0)
    }

    fn run_on_method(
        &self,
        ssa: &mut SsaFunction,
        method: &MethodRef,
        host: &CompilerContext,
    ) -> analyssa::Result<bool> {
        let assembly_arc = host.assembly().ok_or_else(|| {
            analyssa::Error::new("ReflectionDevirtualizationPass requires an assembly")
        })?;
        let assembly: &CilObject = &assembly_arc;
        let ctx = host;
        let method_token = method.0;
        let sites = find_reflection_sites(ssa, assembly);
        if sites.is_empty() {
            self.processed.insert(method_token);
            return Ok(false);
        }

        let mut count = 0usize;
        for site in &sites {
            let success = match site {
                ReflectionSite::ResolveMethodCalli { .. } => {
                    rewrite_resolve_method_calli(ssa, site, ctx)
                }
                ReflectionSite::ResolveMethodInvoke { .. } => {
                    rewrite_resolve_method_invoke(ssa, site, ctx)
                }
                ReflectionSite::GetMethodInvoke { .. } => {
                    rewrite_get_method_invoke(ssa, site, ctx, assembly)
                }
                ReflectionSite::ActivatorCreate { .. } => {
                    rewrite_activator_create(ssa, site, ctx, assembly)
                }
                ReflectionSite::FieldAccess { .. } => rewrite_field_access(ssa, site, ctx),
            };
            if success {
                count = count.saturating_add(1);
            }
        }

        if count > 0 {
            ctx.events
                .record(EventKind::InstructionRemoved)
                .method(method_token)
                .message(format!("Devirtualized {count} reflection call sites"));
        }

        self.processed.insert(method_token);
        Ok(count > 0)
    }
}

/// Counts `ResolveMethod → GetFunctionPointer → calli` sites (P1 only).
///
/// Used by [`BitMonoCalli::detect_ssa()`](crate::deobfuscation::techniques::bitmono::BitMonoCalli)
/// for attribution and by [`GenericDelegateProxy::detect_ssa()`](crate::deobfuscation::techniques::generic::GenericDelegateProxy)
/// for reflection findings.
///
/// # Arguments
///
/// * `ssa` - The SSA function to scan for P1 trampoline chains.
/// * `assembly` - The assembly metadata, used to resolve method names during tracing.
///
/// # Returns
///
/// The number of confirmed P1 (ResolveMethod + GetFunctionPointer + calli) sites.
pub fn count_resolve_method_calli_sites(ssa: &SsaFunction, assembly: &CilObject) -> usize {
    let tracer = ChainTracer { ssa, assembly };
    let mut count: usize = 0;
    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        for (i, instr) in block.instructions().iter().enumerate() {
            let Some((call, fptr)) = instr
                .op()
                .as_call()
                .and_then(|call| Some((call, call.callee.fptr()?)))
            else {
                continue;
            };
            if tracer
                .trace_resolve_method_calli(block_idx, i, call.dest, fptr, &call.args)
                .is_some()
            {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

/// Bundles `&SsaFunction` and `&CilObject` to reduce parameter repetition
/// across the many chain-tracing helper functions.
struct ChainTracer<'a> {
    ssa: &'a SsaFunction,
    assembly: &'a CilObject,
}

impl<'a> ChainTracer<'a> {
    /// Checks whether a method token's declaring type name contains `type_name`.
    ///
    /// Handles both MethodDef (table 0x06) and MemberRef (table 0x0A) tokens
    /// by resolving through assembly metadata.
    ///
    /// # Arguments
    ///
    /// * `token` - The method token (MethodDef or MemberRef) to check.
    /// * `type_name` - Substring to match against the declaring type's name.
    ///
    /// # Returns
    ///
    /// `true` if the declaring type name contains `type_name`, `false` otherwise
    /// or if the token cannot be resolved.
    fn is_method_from_type(&self, token: Token, type_name: &str) -> bool {
        let table = token.table();
        if table == 0x06 {
            if let Ok(method) = self.assembly.method(&token) {
                if let Some(ty) = method.declaring_type_rc() {
                    return ty.name.contains(type_name);
                }
            }
        } else if table == 0x0A {
            if let Some(entry) = self.assembly.refs_members().get(&token) {
                let member = entry.value();
                if let Some(fullname) = member.declaredby.fullname() {
                    return fullname.contains(type_name);
                }
            }
        }
        false
    }

    /// Returns the `(block, instruction)` location of a variable's definition,
    /// or `None` if the variable is defined by a phi or has no known location.
    fn def_site(&self, var: SsaVarId) -> Option<(usize, usize)> {
        let variable = self.ssa.variable(var)?;
        let ds = variable.def_site();
        Some((ds.block(), ds.index()?))
    }

    /// Checks whether `var` is defined as `Const(Null)`.
    fn is_null(&self, var: SsaVarId) -> bool {
        matches!(
            self.ssa.get_definition(var),
            Some(SsaOp::Const {
                value: ConstValue::Null,
                ..
            })
        )
    }

    /// Extracts a metadata token from a `Const(I32)` definition, validating
    /// that it belongs to one of the given ECMA-335 metadata tables.
    ///
    /// The table ID is the high byte of the 32-bit token value (e.g., `0x06`
    /// for MethodDef, `0x04` for FieldDef).
    ///
    /// # Arguments
    ///
    /// * `var` - The SSA variable whose definition should be a `Const(I32)`.
    /// * `valid_tables` - Allowed table IDs (high byte of the token).
    ///
    /// # Returns
    ///
    /// The raw 32-bit token value if valid, `None` if the definition is not
    /// a constant or the table ID is not in `valid_tables`.
    fn extract_token_from_const(&self, var: SsaVarId, valid_tables: &[u8]) -> Option<u32> {
        let SsaOp::Const { value, .. } = self.ssa.get_definition(var)? else {
            return None;
        };
        let raw = value.as_i32()? as u32;
        let table = (raw >> 24) as u8;
        if valid_tables.contains(&table) {
            Some(raw)
        } else {
            None
        }
    }

    /// Extracts a method token: MethodDef (0x06), MemberRef (0x0A), or MethodSpec (0x2B).
    fn extract_method_token(&self, var: SsaVarId) -> Option<u32> {
        self.extract_token_from_const(var, &[0x06, 0x0A, 0x2B])
    }

    /// Extracts a field token: FieldDef (0x04) or MemberRef (0x0A).
    fn extract_field_token(&self, var: SsaVarId) -> Option<u32> {
        self.extract_token_from_const(var, &[0x04, 0x0A])
    }

    /// Extracts a string from a `Const(DecryptedString)` definition.
    fn extract_string_const(&self, var: SsaVarId) -> Option<String> {
        let SsaOp::Const { value, .. } = self.ssa.get_definition(var)? else {
            return None;
        };
        match value {
            ConstValue::DecryptedString(s) => Some(s.to_string()),
            _ => None,
        }
    }

    /// Traces `var` back through `Call GetTypeFromHandle(LoadToken(type))`.
    ///
    /// Returns the type token embedded in the `LoadToken` instruction at the
    /// start of the chain, or `None` if the chain doesn't match.
    fn trace_type_from_handle(&self, var: SsaVarId) -> Option<Token> {
        let handle = *self.named_call(var, "GetTypeFromHandle")?.args.first()?;
        match self.ssa.get_definition(handle)? {
            SsaOp::LoadToken { token, .. } => Some(token.0),
            _ => None,
        }
    }

    /// Traces `var` back to `Call ResolveMethod(module, token_const)`.
    ///
    /// Returns `(module_var, token_const_var)` - the two arguments to
    /// `Module.ResolveMethod` - or `None` if the chain doesn't match.
    fn trace_resolve_method_call(&self, var: SsaVarId) -> Option<(SsaVarId, SsaVarId)> {
        // `Module.ResolveMethod` is an instance method: compilers emit `callvirt`.
        let rm_args = &self.named_call(var, "ResolveMethod")?.args;
        Some((*rm_args.first()?, *rm_args.get(1)?))
    }

    /// Traces `field_info_var` back through `Module.ResolveField(Const(token))`.
    ///
    /// # Arguments
    ///
    /// * `field_info_var` - The SSA variable holding the `FieldInfo` object.
    ///
    /// # Returns
    ///
    /// `Some((field_token, intermediates))` where `field_token` is the raw ECMA-335
    /// field token and `intermediates` are instruction locations to NOP. Returns
    /// `None` if the chain does not match `Call ResolveField(module, Const(token))`.
    fn trace_resolve_field(&self, field_info_var: SsaVarId) -> Option<(u32, Vec<(usize, usize)>)> {
        let mut intermediates = Vec::new();
        // `Module.ResolveField` is an instance method: compilers emit `callvirt`.
        let rf_args = &self.named_call(field_info_var, "ResolveField")?.args;
        intermediates.extend(self.def_site(field_info_var));
        let token_var = *rf_args.get(1)?;
        let field_token = self.extract_field_token(token_var)?;
        intermediates.extend(self.def_site(token_var));
        Some((field_token, intermediates))
    }

    /// Traces the `Module` acquisition chain backward from `module_var`:
    /// `get_Module(type_handle)` ← `GetTypeFromHandle(token)` ← `LoadToken`.
    ///
    /// Each intermediate instruction location is appended to `intermediates`
    /// for post-rewrite NOP cleanup.
    fn trace_module_chain(&self, module_var: SsaVarId, intermediates: &mut Vec<(usize, usize)>) {
        // Each step is the call it is named for: a removed call must be one
        // whose only effect was the value the trampoline consumed.
        let Some(&type_handle_var) = self.named_call_argument(module_var, "get_Module") else {
            return;
        };
        intermediates.extend(self.def_site(module_var));

        let Some(&loadtoken_arg) = self.named_call_argument(type_handle_var, "GetTypeFromHandle")
        else {
            return;
        };
        intermediates.extend(self.def_site(type_handle_var));

        if matches!(
            self.ssa.get_definition(loadtoken_arg),
            Some(SsaOp::LoadToken { .. })
        ) {
            intermediates.extend(self.def_site(loadtoken_arg));
        }
    }

    /// Returns the first argument of the call defining `var`, when that call
    /// names the method `name` ([`Self::named_call`]).
    fn named_call_argument(&self, var: SsaVarId, name: &str) -> Option<&SsaVarId> {
        self.named_call(var, name)?.args.first()
    }

    /// The call defining `var`, when it names the method `name`, by any
    /// dispatch.
    fn named_call(&self, var: SsaVarId, name: &str) -> Option<&CallData> {
        let (token, call) = self.ssa.get_definition(var)?.method_call()?;
        is_method_named(self.assembly, token, name).then_some(call)
    }

    /// Resolves a `calli` function pointer back to `Call GetFunctionPointer`,
    /// handling PHI indirection from junk branches that split the block.
    ///
    /// # Arguments
    ///
    /// * `fptr` - The SSA variable holding the function pointer at the `calli` site.
    ///
    /// # Returns
    ///
    /// `Some((def_var, method_token, first_arg))` where `def_var` is the SSA variable
    /// defined by `GetFunctionPointer`, `method_token` is its token, and `first_arg`
    /// is the method handle argument. Returns `None` if the chain doesn't match.
    fn resolve_fptr_source(&self, fptr: SsaVarId) -> Option<(SsaVarId, Token, SsaVarId)> {
        let get_function_pointer = |var: SsaVarId| {
            let call = self.named_call(var, "GetFunctionPointer")?;
            Some((var, call.callee.method()?.token(), *call.args.first()?))
        };

        // Fast path: fptr directly defined by Call GetFunctionPointer.
        if self.ssa.get_definition(fptr).is_some() {
            return get_function_pointer(fptr);
        }

        // Slow path: fptr defined by PHI (junk branch created an extra block).
        let (_block_idx, phi) = self.ssa.find_phi_defining(fptr)?;
        phi.operands()
            .iter()
            .find_map(|operand| get_function_pointer(operand.value()))
    }

    /// Finds `callvirt get_MethodHandle` whose result was stored to the given
    /// local via `Copy`/`stloc`, bridging the pointer gap when the obfuscator
    /// uses `ldloca` to load the address of a value-type local.
    ///
    /// # Arguments
    ///
    /// * `intermediates` - Accumulator for trampoline instruction locations;
    ///   the found `get_MethodHandle` and `Copy` locations are appended.
    /// * `local_index` - The local variable index from the `LoadLocalAddr` instruction.
    ///
    /// # Returns
    ///
    /// The first argument to `get_MethodHandle` (the `MethodBase` value),
    /// or `None` if no matching chain can be found.
    fn find_get_method_handle(
        &self,
        intermediates: &mut Vec<(usize, usize)>,
        local_index: u16,
    ) -> Option<SsaVarId> {
        for (block_idx, block) in self.ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let SsaOp::Copy { dest, src } = instr.op() else {
                    continue;
                };
                let is_target_local = self
                    .ssa
                    .variable(*dest)
                    .is_some_and(|v| v.origin() == VariableOrigin::Local(local_index));
                if !is_target_local {
                    continue;
                }
                if let Some(&first) = self.named_call_argument(*src, "get_MethodHandle") {
                    intermediates.extend(self.def_site(*src));
                    intermediates.push((block_idx, instr_idx));
                    return Some(first);
                }
            }
        }
        None
    }

    /// P1: Traces a `calli` backward through the full ResolveMethod +
    /// GetFunctionPointer trampoline chain.
    ///
    /// Expected chain (7 steps):
    /// ```text
    /// LoadToken <Module>
    ///   → Call GetTypeFromHandle(token)
    ///   → callvirt get_Module(type)
    ///   → Call ResolveMethod(module, Const(target_token))
    ///   → callvirt get_MethodHandle(method_base)
    ///   → Call GetFunctionPointer(handle)
    ///   → calli(fptr, args...)
    /// ```
    ///
    /// # Arguments
    ///
    /// * `ci_block` - Block index of the `calli` instruction.
    /// * `ci_idx` - Instruction index within the block.
    /// * `dest` - Optional destination variable of the indirect call.
    /// * `fptr` - The function pointer variable passed to `calli`.
    /// * `args` - Arguments to the indirect call (excluding the function pointer).
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::ResolveMethodCalli`] if the full chain is confirmed,
    /// `None` if any step in the def-use chain doesn't match.
    fn trace_resolve_method_calli(
        &self,
        ci_block: usize,
        ci_idx: usize,
        dest: Option<SsaVarId>,
        fptr: SsaVarId,
        args: &[SsaVarId],
    ) -> Option<ReflectionSite> {
        let mut intermediates: Vec<(usize, usize)> = Vec::new();

        // Step 1: fptr ← Call GetFunctionPointer(handle_addr)
        let (getfp_var, _getfp_method, getfp_arg) = self.resolve_fptr_source(fptr)?;
        intermediates.extend(self.def_site(getfp_var));

        // Step 2: handle_addr ← callvirt get_MethodHandle(method_base)
        //   or via LoadLocalAddr bridge when obfuscator uses ldloca
        let resolved_var = match self.ssa.get_definition(getfp_arg)? {
            SsaOp::LoadLocalAddr { local_index, .. } => {
                let local_idx = *local_index;
                intermediates.extend(self.def_site(getfp_arg));
                self.find_get_method_handle(&mut intermediates, local_idx)?
            }
            _ => {
                let method_base = *self.named_call_argument(getfp_arg, "get_MethodHandle")?;
                intermediates.extend(self.def_site(getfp_arg));
                method_base
            }
        };

        // Step 3: method_base ← Call ResolveMethod(module, token_const)
        let (module_var, token_const_var) = self.trace_resolve_method_call(resolved_var)?;
        intermediates.extend(self.def_site(resolved_var));

        // Step 4: Extract the embedded target method token
        let target_token = self.extract_method_token(token_const_var)?;
        intermediates.extend(self.def_site(token_const_var));

        // Steps 5-7: module ← get_Module ← GetTypeFromHandle ← LoadToken
        self.trace_module_chain(module_var, &mut intermediates);

        Some(ReflectionSite::ResolveMethodCalli {
            block: ci_block,
            idx: ci_idx,
            target_token,
            dest,
            args: args.to_vec(),
            intermediates,
        })
    }

    /// P2: Traces a `MethodInfo.Invoke` call back through `Module.ResolveMethod`.
    ///
    /// The `this` argument (MethodInfo) must be defined by a `ResolveMethod` call
    /// with a constant token argument.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `Invoke` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[method_info, obj, params_array]`.
    /// * `dest` - Optional destination variable for the return value.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::ResolveMethodInvoke`] if the chain resolves to a
    /// constant method token, `None` otherwise.
    fn trace_resolve_method_invoke(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
        dest: Option<SsaVarId>,
    ) -> Option<ReflectionSite> {
        let (method_info_var, obj_var, array_var) = (*args.first()?, *args.get(1)?, *args.get(2)?);
        let mut intermediates: Vec<(usize, usize)> = Vec::new();

        let (module_var, token_const_var) = self.trace_resolve_method_call(method_info_var)?;
        intermediates.extend(self.def_site(method_info_var));

        let target_token = self.extract_method_token(token_const_var)?;
        intermediates.extend(self.def_site(token_const_var));

        self.trace_module_chain(module_var, &mut intermediates);

        Some(ReflectionSite::ResolveMethodInvoke {
            block,
            idx,
            target_token,
            dest,
            obj_var,
            array_var,
            intermediates,
        })
    }

    /// P3: Traces a `MethodInfo.Invoke` call back through `Type.GetMethod("name")`.
    ///
    /// The `this` argument (MethodInfo) must be defined by a `GetMethod` call
    /// whose type argument traces to `GetTypeFromHandle(LoadToken(type))` and
    /// whose name argument is a constant `DecryptedString`.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `Invoke` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[method_info, obj, params_array]`.
    /// * `dest` - Optional destination variable for the return value.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::GetMethodInvoke`] with the resolved type token and
    /// method name, `None` if the chain can't be fully traced.
    fn trace_get_method_invoke(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
        dest: Option<SsaVarId>,
    ) -> Option<ReflectionSite> {
        let (method_info_var, obj_var, array_var) = (*args.first()?, *args.get(1)?, *args.get(2)?);
        let mut intermediates: Vec<(usize, usize)> = Vec::new();

        // method_info_var ← call/callvirt GetMethod(type, Const("name"))
        let get_method = &self.named_call(method_info_var, "GetMethod")?.args;
        let (type_var, name_var) = (*get_method.first()?, *get_method.get(1)?);
        intermediates.extend(self.def_site(method_info_var));

        let method_name = self.extract_string_const(name_var)?;
        intermediates.extend(self.def_site(name_var));

        let type_token = self.trace_type_from_handle(type_var)?;
        intermediates.extend(self.def_site(type_var));

        Some(ReflectionSite::GetMethodInvoke {
            block,
            idx,
            type_token,
            method_name,
            dest,
            obj_var,
            array_var,
            intermediates,
        })
    }

    /// Attempts to match a `call`/`callvirt` `Invoke` to P2 or P3.
    ///
    /// Tries P2 (ResolveMethod chain) first since it requires no metadata name
    /// resolution. Falls back to P3 (GetMethod name lookup) if P2 doesn't match.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `Invoke` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[method_info, obj, params_array]`.
    /// * `dest` - Optional destination variable for the return value.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite`] for P2 or P3, `None` if neither pattern matches.
    fn try_invoke_site(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
        dest: Option<SsaVarId>,
    ) -> Option<ReflectionSite> {
        self.trace_resolve_method_invoke(block, idx, args, dest)
            .or_else(|| self.trace_get_method_invoke(block, idx, args, dest))
    }

    /// P5: Traces `Activator.CreateInstance(type)` to a constant type token.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `CreateInstance` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[type_object]` (possibly with a second `bool` arg).
    /// * `dest` - Optional destination variable for the created instance.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::ActivatorCreate`] if the type argument traces to a
    /// constant `LoadToken`, `None` otherwise.
    fn trace_activator_create(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
        dest: Option<SsaVarId>,
    ) -> Option<ReflectionSite> {
        let type_var = *args.first()?;
        let mut intermediates = Vec::new();

        let type_token = self.trace_type_from_handle(type_var)?;
        intermediates.extend(self.def_site(type_var));

        Some(ReflectionSite::ActivatorCreate {
            block,
            idx,
            type_token,
            dest,
            intermediates,
        })
    }

    /// P6 (read): Traces `FieldInfo.GetValue(obj)` to a constant field token.
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `GetValue` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[field_info, obj]`.
    /// * `dest` - Destination variable for the field value.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::FieldAccess`] with `is_set: false`, or `None` if the
    /// FieldInfo doesn't trace to a constant `ResolveField` token.
    fn trace_field_get_value(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
        dest: Option<SsaVarId>,
    ) -> Option<ReflectionSite> {
        let (field_info_var, obj_var) = (*args.first()?, *args.get(1)?);
        let (field_token, intermediates) = self.trace_resolve_field(field_info_var)?;

        Some(ReflectionSite::FieldAccess {
            block,
            idx,
            field_token,
            is_set: false,
            dest,
            obj_var,
            value_var: None,
            intermediates,
        })
    }

    /// P6 (write): Traces `FieldInfo.SetValue(obj, value)` to a constant field token.
    ///
    /// Unwraps `Box` on the value argument if present (value types are boxed
    /// when passed through `SetValue(object, object)`).
    ///
    /// # Arguments
    ///
    /// * `block` - Block index of the `SetValue` instruction.
    /// * `idx` - Instruction index within the block.
    /// * `args` - SSA args: `[field_info, obj, value]`.
    ///
    /// # Returns
    ///
    /// A [`ReflectionSite::FieldAccess`] with `is_set: true`, or `None` if the
    /// FieldInfo doesn't trace to a constant `ResolveField` token.
    fn trace_field_set_value(
        &self,
        block: usize,
        idx: usize,
        args: &[SsaVarId],
    ) -> Option<ReflectionSite> {
        let (field_info_var, obj_var, value_var) = (*args.first()?, *args.get(1)?, *args.get(2)?);
        let (field_token, intermediates) = self.trace_resolve_field(field_info_var)?;

        // Unwrap Box on the value if present
        let actual_value = unwrap_box(self.ssa, value_var).unwrap_or(value_var);

        Some(ReflectionSite::FieldAccess {
            block,
            idx,
            field_token,
            is_set: true,
            dest: None,
            obj_var,
            value_var: Some(actual_value),
            intermediates,
        })
    }
}

/// Scans an SSA function for all reflection call indirection sites (P1–P6).
///
/// Iterates every instruction in every block. `calli` instructions are
/// checked for the P1 pattern; `call`/`callvirt` instructions are matched
/// against known reflection API names for P2, P3, P5, and P6.
///
/// # Arguments
///
/// * `ssa` - The SSA function to scan.
/// * `assembly` - Assembly metadata for method name resolution.
///
/// # Returns
///
/// All confirmed reflection sites. Empty if no patterns match.
fn find_reflection_sites(ssa: &SsaFunction, assembly: &CilObject) -> Vec<ReflectionSite> {
    let tracer = ChainTracer { ssa, assembly };
    let mut sites = Vec::new();

    for (block_idx, block) in ssa.blocks().iter().enumerate() {
        for (i, instr) in block.instructions().iter().enumerate() {
            let Some(call) = instr.op().as_call() else {
                continue;
            };
            let site = match &call.callee {
                Callee::Indirect { fptr, .. } => {
                    tracer.trace_resolve_method_calli(block_idx, i, call.dest, *fptr, &call.args)
                }
                // A constrained call passes the address of its receiver,
                // which the rewritten operation does not take.
                Callee::Direct(method) | Callee::Virtual(method) => try_reflection_api_site(
                    &tracer,
                    block_idx,
                    i,
                    method.token(),
                    &call.args,
                    call.dest,
                ),
                Callee::Constrained { .. } => None,
            };
            sites.extend(site);
        }
    }

    sites
}

/// Attempts to match a `call`/`callvirt` to a known reflection API pattern.
///
/// Resolves the callee method name from assembly metadata and dispatches to
/// the appropriate pattern tracer based on the API name and argument count.
///
/// # Arguments
///
/// * `tracer` - The chain tracer with SSA and assembly context.
/// * `block` - Block index of the call instruction.
/// * `idx` - Instruction index within the block.
/// * `method_token` - Token of the callee method.
/// * `args` - SSA arguments to the call.
/// * `dest` - Optional destination variable for the return value.
///
/// # Returns
///
/// A [`ReflectionSite`] if the call matches a known pattern, `None` otherwise.
fn try_reflection_api_site(
    tracer: &ChainTracer,
    block: usize,
    idx: usize,
    method_token: Token,
    args: &[SsaVarId],
    dest: Option<SsaVarId>,
) -> Option<ReflectionSite> {
    let name = tracer.assembly.resolve_method_name(method_token)?;

    // P2/P3: MethodBase.Invoke(object obj, object[] parameters)
    // SSA args: [this=MethodInfo, obj, params_array]
    if name == "Invoke" && args.len() == 3 {
        return tracer.try_invoke_site(block, idx, args, dest);
    }

    // P5: Activator.CreateInstance(Type) or CreateInstance(Type, bool)
    if name.contains("CreateInstance")
        && (args.len() == 1 || args.len() == 2)
        && tracer.is_method_from_type(method_token, "Activator")
    {
        return tracer.trace_activator_create(block, idx, args, dest);
    }

    // P6: FieldInfo.GetValue(object)
    if name == "GetValue"
        && args.len() == 2
        && tracer.is_method_from_type(method_token, "FieldInfo")
    {
        return tracer.trace_field_get_value(block, idx, args, dest);
    }

    // P6: FieldInfo.SetValue(object, object)
    if name == "SetValue"
        && args.len() == 3
        && tracer.is_method_from_type(method_token, "FieldInfo")
    {
        return tracer.trace_field_set_value(block, idx, args);
    }

    None
}

/// Traces an `object[]` argument array backward to extract individual arguments.
///
/// Reflection `Invoke` methods pass arguments as `object[]`. This function
/// recovers the original pre-boxed arguments by:
///
/// 1. Finding the `NewArr` that creates the array (or `Const(Null)` for no args)
/// 2. Collecting all `StoreElement` writes with constant indices
/// 3. Unwrapping `Box` on each element to get the original value-type variable
/// 4. Returning arguments sorted by index
///
/// # Arguments
///
/// * `ssa` - The SSA function containing the array construction.
/// * `array_var` - The SSA variable holding the `object[]` reference.
///
/// # Returns
///
/// `Some(args)` with the unpacked argument variables in index order, or
/// `None` if any element slot is unfilled or uses a non-constant index.
/// An empty `Vec` is returned for null arrays or zero-length arrays.
fn unpack_object_array(ssa: &SsaFunction, array_var: SsaVarId) -> Option<Vec<SsaVarId>> {
    let def = ssa.get_definition(array_var)?;

    // Null array means no arguments (static method with no params)
    let SsaOp::NewArr { length, .. } = def else {
        if matches!(
            def,
            SsaOp::Const {
                value: ConstValue::Null,
                ..
            }
        ) {
            return Some(Vec::new());
        }
        return None;
    };

    // Get the array length from a Const(I32) definition
    let SsaOp::Const { value, .. } = ssa.get_definition(*length)? else {
        return None;
    };
    let arr_len = value.as_i32()? as usize;
    if arr_len == 0 {
        return Some(Vec::new());
    }

    // Scan all blocks for StoreElement writes to this array
    let mut elements: Vec<Option<SsaVarId>> = vec![None; arr_len];
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let SsaOp::StoreElement {
                array,
                index,
                value,
                ..
            } = instr.op()
            {
                if *array != array_var {
                    continue;
                }
                if let Some(SsaOp::Const { value: idx_val, .. }) = ssa.get_definition(*index) {
                    if let Some(i) = idx_val.as_i32() {
                        let i = i as usize;
                        if let Some(slot) = elements.get_mut(i) {
                            let actual_val = unwrap_box(ssa, *value).unwrap_or(*value);
                            *slot = Some(actual_val);
                        }
                    }
                }
            }
        }
    }

    // All slots must be filled - partial arrays cannot be safely unpacked
    elements.into_iter().collect()
}

/// If `var` is defined by `Box { value, .. }`, returns the pre-boxed value.
///
/// Boxing is inserted by the compiler when storing value types into `object[]`.
/// Unwrapping recovers the original typed variable.
fn unwrap_box(ssa: &SsaFunction, var: SsaVarId) -> Option<SsaVarId> {
    if let Some(SsaOp::Box { value, .. }) = ssa.get_definition(var) {
        Some(*value)
    } else {
        None
    }
}

/// Builds a `Call` argument list that prepends `obj_var` (for instance methods)
/// or passes `unpacked_args` directly (for static methods where obj is null).
fn build_call_args(
    tracer: &ChainTracer,
    obj_var: SsaVarId,
    unpacked_args: Vec<SsaVarId>,
) -> Vec<SsaVarId> {
    if tracer.is_null(obj_var) {
        unpacked_args
    } else {
        let mut a = vec![obj_var];
        a.extend(unpacked_args);
        a
    }
}

/// P1: Replaces `calli` with a direct `Call` to the embedded method token.
///
/// All intermediate trampoline instructions (LoadToken, GetTypeFromHandle,
/// get_Module, ResolveMethod, get_MethodHandle, GetFunctionPointer) are NOP'd.
fn rewrite_resolve_method_calli(
    ssa: &mut SsaFunction,
    site: &ReflectionSite,
    ctx: &CompilerContext,
) -> bool {
    let ReflectionSite::ResolveMethodCalli {
        block,
        idx,
        target_token,
        dest,
        args,
        intermediates,
    } = site
    else {
        return false;
    };

    let target_method = MethodRef::new(Token::new(*target_token));

    if let Some(blk) = ssa.block_mut(*block) {
        if let Some(instr) = blk.instruction_mut(*idx) {
            retarget_call(instr, *dest, Callee::Direct(target_method), args.clone());
        }
    }

    nop_intermediates(ssa, intermediates, ctx);
    true
}

/// Redirects the call `instr` to `callee` with `args`, its result in `dest`
/// ([`CallData::redirected`]), keeping its result type.
fn retarget_call(
    instr: &mut SsaInstruction,
    dest: Option<SsaVarId>,
    callee: Callee,
    args: Vec<SsaVarId>,
) {
    let Some(redirected) = instr.op().as_call().map(|call| CallData {
        dest,
        ..call.redirected(callee, args)
    }) else {
        return;
    };
    let stored_type = instr.result_type().cloned();
    instr.set_op(redirected.into());
    instr.set_result_type(stored_type);
}

/// P2: Replaces `MethodInfo.Invoke(obj, object[])` with a direct `Call`.
///
/// Unpacks the `object[]` argument array and determines whether the call is
/// static (obj is null) or instance (obj prepended to args).
fn rewrite_resolve_method_invoke(
    ssa: &mut SsaFunction,
    site: &ReflectionSite,
    ctx: &CompilerContext,
) -> bool {
    let ReflectionSite::ResolveMethodInvoke {
        block,
        idx,
        target_token,
        dest,
        obj_var,
        array_var,
        intermediates,
    } = site
    else {
        return false;
    };

    let Some(unpacked_args) = unpack_object_array(ssa, *array_var) else {
        return false;
    };

    let is_null_obj = matches!(
        ssa.get_definition(*obj_var),
        Some(SsaOp::Const {
            value: ConstValue::Null,
            ..
        })
    );

    let call_args = if is_null_obj {
        unpacked_args
    } else {
        let mut a = vec![*obj_var];
        a.extend(unpacked_args);
        a
    };

    let target_method = MethodRef::new(Token::new(*target_token));

    if let Some(blk) = ssa.block_mut(*block) {
        if let Some(instr) = blk.instruction_mut(*idx) {
            // `Invoke` on an instance dispatches on the receiver as `callvirt`
            // does - a virtual method runs its override, any other is
            // null-checked - so only a static target is a plain call.
            let callee = if is_null_obj {
                Callee::Direct(target_method)
            } else {
                Callee::Virtual(target_method)
            };
            retarget_call(instr, *dest, callee, call_args);
        }
    }

    nop_intermediates(ssa, intermediates, ctx);
    true
}

/// P3: Replaces `Type.GetMethod("name").Invoke(obj, object[])` with a direct `Call`.
///
/// Resolves the method by name against the type's metadata method table,
/// unpacks the `object[]` argument array, and rewrites the call.
fn rewrite_get_method_invoke(
    ssa: &mut SsaFunction,
    site: &ReflectionSite,
    ctx: &CompilerContext,
    assembly: &CilObject,
) -> bool {
    let ReflectionSite::GetMethodInvoke {
        block,
        idx,
        type_token,
        method_name,
        dest,
        obj_var,
        array_var,
        intermediates,
    } = site
    else {
        return false;
    };

    let Some(resolved_method) = resolve_method_by_name(assembly, *type_token, method_name) else {
        return false;
    };

    let Some(unpacked_args) = unpack_object_array(ssa, *array_var) else {
        return false;
    };

    let is_null_obj = matches!(
        ssa.get_definition(*obj_var),
        Some(SsaOp::Const {
            value: ConstValue::Null,
            ..
        })
    );

    let call_args = if is_null_obj {
        unpacked_args
    } else {
        let mut a = vec![*obj_var];
        a.extend(unpacked_args);
        a
    };

    let target_method = MethodRef::new(resolved_method);

    if let Some(blk) = ssa.block_mut(*block) {
        if let Some(instr) = blk.instruction_mut(*idx) {
            // `Invoke` on an instance dispatches on the receiver as `callvirt`
            // does - a virtual method runs its override, any other is
            // null-checked - so only a static target is a plain call.
            let callee = if is_null_obj {
                Callee::Direct(target_method)
            } else {
                Callee::Virtual(target_method)
            };
            retarget_call(instr, *dest, callee, call_args);
        }
    }

    nop_intermediates(ssa, intermediates, ctx);
    true
}

/// P5: Replaces `Activator.CreateInstance(type)` with `NewObj(type::.ctor())`.
///
/// Only succeeds if the type has a parameterless constructor.
fn rewrite_activator_create(
    ssa: &mut SsaFunction,
    site: &ReflectionSite,
    ctx: &CompilerContext,
    assembly: &CilObject,
) -> bool {
    let ReflectionSite::ActivatorCreate {
        block,
        idx,
        type_token,
        dest,
        intermediates,
    } = site
    else {
        return false;
    };

    let Some(ctor_token) = find_parameterless_ctor(assembly, *type_token) else {
        return false;
    };
    let Some(dest_var) = dest else {
        return false;
    };

    if let Some(blk) = ssa.block_mut(*block) {
        if let Some(instr) = blk.instruction_mut(*idx) {
            instr.set_op(SsaOp::NewObj {
                dest: *dest_var,
                ctor: MethodRef::new(ctor_token),
                args: Vec::new(),
            });
        }
    }

    nop_intermediates(ssa, intermediates, ctx);
    true
}

/// P6: Replaces `FieldInfo.GetValue`/`SetValue` with direct field access.
///
/// Uses `LoadStaticField`/`StoreStaticField` when `obj` is null (static field),
/// or `LoadField`/`StoreField` when `obj` is non-null (instance field).
fn rewrite_field_access(
    ssa: &mut SsaFunction,
    site: &ReflectionSite,
    ctx: &CompilerContext,
) -> bool {
    let ReflectionSite::FieldAccess {
        block,
        idx,
        field_token,
        is_set,
        dest,
        obj_var,
        value_var,
        intermediates,
    } = site
    else {
        return false;
    };

    let field = FieldRef(Token::new(*field_token));
    let is_null_obj = matches!(
        ssa.get_definition(*obj_var),
        Some(SsaOp::Const {
            value: ConstValue::Null,
            ..
        })
    );

    if *is_set {
        let Some(val) = value_var else {
            return false;
        };
        // Reflection reads and writes a field as a plain access.
        let new_op = if is_null_obj {
            SsaOp::StoreStaticField {
                field,
                value: *val,
                access: AccessQualifiers::FLAT,
            }
        } else {
            SsaOp::StoreField {
                object: *obj_var,
                field,
                value: *val,
                access: AccessQualifiers::FLAT,
            }
        };
        if let Some(blk) = ssa.block_mut(*block) {
            if let Some(instr) = blk.instruction_mut(*idx) {
                instr.set_op(new_op);
            }
        }
    } else {
        let Some(dest_var) = dest else {
            return false;
        };
        let new_op = if is_null_obj {
            SsaOp::LoadStaticField {
                dest: *dest_var,
                field,
                access: AccessQualifiers::FLAT,
            }
        } else {
            SsaOp::LoadField {
                dest: *dest_var,
                object: *obj_var,
                field,
                access: AccessQualifiers::FLAT,
            }
        };
        if let Some(blk) = ssa.block_mut(*block) {
            if let Some(instr) = blk.instruction_mut(*idx) {
                instr.set_op(new_op);
            }
        }
    }

    nop_intermediates(ssa, intermediates, ctx);
    true
}

/// NOPs the intermediate trampoline instructions nothing else reads, and marks
/// their call targets as neutralized so dead method elimination can remove
/// them.
///
/// An intermediate is removed only once no instruction still uses its result:
/// the module, type or method object a trampoline computes may be shared with
/// code the rewrite did not touch (a value another site reuses, or a local the
/// program reads again), and removing its definition would leave those uses
/// reading nothing. Removing one can free the intermediates it read, so
/// [`SsaFunction::remove_unread_instructions`] settles the set to a fixpoint;
/// what stays is still correct code.
///
/// # Arguments
///
/// * `ssa` - The SSA function to modify.
/// * `intermediates` - `(block_idx, instr_idx)` pairs identifying instructions to NOP.
/// * `ctx` - Compiler context for recording neutralized method tokens.
fn nop_intermediates(
    ssa: &mut SsaFunction,
    intermediates: &[(usize, usize)],
    ctx: &CompilerContext,
) {
    for (_, _, op) in ssa.remove_unread_instructions(intermediates.iter().copied()) {
        if let Some((token, _)) = op.method_call() {
            ctx.neutralized_tokens.insert(token);
        }
    }
}

/// Resolves a method by name against a type's method table in assembly metadata.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the type definition.
/// * `type_token` - Token of the type to search.
/// * `name` - Method name to match.
///
/// # Returns
///
/// The first matching MethodDef token, or `None` if no method with that name
/// exists on the type. Does not disambiguate overloads - returns the first match.
fn resolve_method_by_name(assembly: &CilObject, type_token: Token, name: &str) -> Option<Token> {
    let ty = assembly.types().get(&type_token)?;
    let result = ty.query_methods().name(name).find_first().map(|m| m.token);
    result
}

/// Finds the parameterless `.ctor` for a type in assembly metadata.
///
/// # Arguments
///
/// * `assembly` - The assembly containing the type definition.
/// * `type_token` - Token of the type to search.
///
/// # Returns
///
/// The `.ctor` MethodDef token if one exists with zero parameters
/// (excluding the implicit `this`), `None` otherwise.
fn find_parameterless_ctor(assembly: &CilObject, type_token: Token) -> Option<Token> {
    let ty = assembly.types().get(&type_token)?;
    let ctor_token = ty.ctor()?;
    let method = assembly.method(&ctor_token).ok()?;
    if method.params.is_empty() {
        Some(ctor_token)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::{
        analysis::{
            CallGraph, Callee, ConstValue, MethodRef, SsaFunctionBuilder, SsaOp, SsaOpCilExt,
            SsaType,
        },
        compiler::CompilerContext,
        deobfuscation::passes::reflection::{nop_intermediates, unpack_object_array, unwrap_box},
        metadata::token::Token,
    };

    /// A trampoline's `GetTypeFromHandle` and `get_Module` are removed once the
    /// rewritten site no longer reads them - the type first in the list, so
    /// only the module's removal frees it - and kept while another
    /// instruction still reads the module: removing them then left that
    /// instruction reading a value nothing defines.
    #[test]
    fn test_nop_intermediates_keeps_values_still_read() {
        let removed = |shared: bool| {
            let mut ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let token = b.const_i32(0x0200_0001);
                        let ty = b.call(
                            Callee::Direct(MethodRef::from(Token::new(0x0A00_0001))),
                            &[token],
                            SsaType::Object,
                        );
                        let module = b.call(
                            Callee::Virtual(MethodRef::from(Token::new(0x0A00_0002))),
                            &[ty],
                            SsaType::Object,
                        );
                        if shared {
                            b.call_void(
                                Callee::Direct(MethodRef::from(Token::new(0x0A00_0003))),
                                &[module],
                            );
                        }
                        b.ret();
                    });
                })
                .unwrap();
            let site = |ssa: &crate::analysis::SsaFunction, token: u32| {
                ssa.block(0)?
                    .instructions()
                    .iter()
                    .position(|instr| {
                        instr
                            .op()
                            .method_call()
                            .is_some_and(|(method, _)| method == Token::new(token))
                    })
                    .map(|idx| (0, idx))
            };
            let intermediates = [
                site(&ssa, 0x0A00_0001).unwrap(),
                site(&ssa, 0x0A00_0002).unwrap(),
            ];
            let ctx = CompilerContext::new(Arc::new(CallGraph::new()));
            nop_intermediates(&mut ssa, &intermediates, &ctx);
            [
                site(&ssa, 0x0A00_0001).is_none(),
                site(&ssa, 0x0A00_0002).is_none(),
            ]
        };
        assert_eq!(removed(false), [true, true], "an unread chain is removed");
        assert_eq!(removed(true), [false, false], "a module still read is kept");
    }

    #[test]
    fn test_unpack_null_array() {
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _null = b.const_null();
                    b.ret();
                });
            })
            .unwrap();

        let block = ssa.block(0).unwrap();
        let mut null_var = None;
        for instr in block.instructions() {
            if let SsaOp::Const {
                dest,
                value: ConstValue::Null,
            } = instr.op()
            {
                null_var = Some(*dest);
            }
        }

        let result = unpack_object_array(&ssa, null_var.unwrap());
        assert!(result.is_some(), "null array should unpack as empty");
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_unwrap_box_absent() {
        let ssa = SsaFunctionBuilder::new(0, 0)
            .build_with(|f| {
                f.block(0, |b| {
                    let _val = b.const_i32(42);
                    b.ret();
                });
            })
            .unwrap();

        let block = ssa.block(0).unwrap();
        let mut val_var = None;
        for instr in block.instructions() {
            if let SsaOp::Const { dest, .. } = instr.op() {
                val_var = Some(*dest);
            }
        }

        let result = unwrap_box(&ssa, val_var.unwrap());
        assert!(result.is_none(), "non-Box should return None");
    }

    #[test]
    fn test_no_reflection_sites_in_clean_function() {
        let ssa = SsaFunctionBuilder::new(1, 0)
            .build_with(|f| {
                let arg0 = f.arg(0, SsaType::I32);
                f.block(0, |b| {
                    let one = b.const_i32(1);
                    let _sum = b.add(arg0, one);
                    b.ret();
                });
            })
            .unwrap();

        assert_eq!(ssa.blocks().len(), 1);
    }
}
