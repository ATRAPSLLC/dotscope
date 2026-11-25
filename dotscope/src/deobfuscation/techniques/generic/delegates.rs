//! Call indirection detection via SSA analysis.
//!
//! Detects two categories of call indirection:
//!
//! ## Delegate Proxies
//!
//! Delegate-based call indirection where every method call is hidden behind a
//! delegate proxy class. Each proxy class:
//!
//! 1. Inherits from `System.MulticastDelegate`
//! 2. Has a static singleton field of its own type
//! 3. Has a static wrapper method that takes `N+1` args (last is the delegate)
//!    and internally `callvirt`s the delegate's `Invoke()`
//!
//! Creates a [`DelegateProxyResolutionPass`] with pre-computed findings from
//! detection, which emulates delegate `.cctor`s and resolves target methods.
//!
//! ## Reflection Call Indirection
//!
//! Reflection-based call indirection where direct calls are hidden behind
//! `Module.ResolveMethod`, `Type.GetMethod`, `MethodInfo.Invoke`,
//! `Activator.CreateInstance`, or `FieldInfo.GetValue/SetValue`.
//!
//! Produces [`ReflectionFindings`] consumed by the engine-owned
//! [`ReflectionDevirtualizationPass`].
//!
//! ## Detection
//!
//! Detection uses `detect_ssa()` to:
//! 1. Pre-scan assembly types for delegate types with static fields
//! 2. Verify wrapper methods via their SSA structure
//! 3. Scan SSA functions for delegate proxy and reflection call patterns

use std::{
    any::Any,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use log::debug;

use crate::{
    analysis::{CilTarget, SsaFunction, SsaOp, SsaOpCilExt, SsaVarId},
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{
            count_resolve_method_calli_sites, DelegateProxyResolutionPass, DelegateTypeInfo,
            ReflectionDevirtualizationPass,
        },
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Findings from delegate proxy detection.
#[derive(Debug)]
pub struct DelegateProxyFindings {
    /// delegate_type_token → singleton field + wrapper method info.
    pub delegate_types: HashMap<Token, DelegateTypeInfo>,
    /// Method tokens containing at least one delegate proxy call.
    pub affected_methods: HashSet<Token>,
}

/// Findings from reflection call indirection detection.
#[derive(Debug, Default)]
pub struct ReflectionFindings {
    /// Method tokens containing reflection call sites.
    pub affected_methods: HashSet<Token>,
    /// Total number of reflection sites detected.
    pub site_count: usize,
}

/// Combined findings from delegate proxy AND reflection detection.
///
/// `GenericDelegateProxy::detect_ssa()` produces this because both analyses
/// share the same SSA scanning pass. The engine extracts [`ReflectionFindings`]
/// to create [`ReflectionDevirtualizationPass`];
/// the technique uses [`DelegateProxyFindings`] for [`DelegateProxyResolutionPass`].
#[derive(Debug)]
pub struct CallIndirectionFindings {
    /// Delegate proxy detection results.
    pub delegate: DelegateProxyFindings,
    /// Reflection call indirection results.
    pub reflection: ReflectionFindings,
}

/// Traces a variable backwards through def-use chains to check if it
/// originates from a method argument.
///
/// Checks the variable's `VariableOrigin` directly (O(1) for argument vars),
/// and follows `Copy` and single-input `Phi` nodes for indirect references.
/// Limits traversal depth to prevent infinite loops.
fn traces_to_argument(ssa: &SsaFunction, var: SsaVarId) -> bool {
    let mut current = var;
    for _ in 0..20 {
        // Check the variable's origin — if it's an argument, we're done
        if let Some(variable) = ssa.variable(current) {
            if variable.origin().is_argument() {
                return true;
            }
        }

        // Check if defined by an instruction (Copy, LoadArg, etc.)
        if let Some(op) = ssa.get_definition(current) {
            match op {
                SsaOp::LoadArg { .. } => return true,
                SsaOp::Copy { src, .. } => {
                    current = *src;
                    continue;
                }
                _ => return false,
            }
        }

        // Check if defined by a phi node
        if let Some((_block_idx, phi)) = ssa.find_phi_defining(current) {
            let operands = phi.operands();
            if operands.len() == 1 {
                if let Some(first) = operands.first() {
                    current = first.value();
                    continue;
                }
            }
            return false;
        }

        return false;
    }
    false
}

/// Checks if a method's SSA matches the delegate wrapper pattern.
///
/// A wrapper method contains a `callvirt` to an `Invoke` method where the
/// object (first arg) traces back to a `LoadArg`, meaning it receives the
/// delegate as a parameter and calls its `Invoke`. This is checked purely
/// via SSA def-use chains, making it immune to junk code insertions.
fn is_delegate_wrapper_ssa(ssa: &SsaFunction, assembly: &CilObject) -> bool {
    for block in ssa.blocks() {
        for instr in block.instructions() {
            // The receiver of a virtual call is the object (delegate instance).
            let Some((method_token, obj_var)) = instr
                .op()
                .method_call()
                .and_then(|(token, call)| Some((token, call.receiver()?)))
            else {
                continue;
            };

            // Check if the target method is "Invoke" on a delegate type
            let Some(method_name) = assembly.resolve_method_name(method_token) else {
                continue;
            };
            if method_name != "Invoke" {
                continue;
            }

            // The receiver must trace back to a method argument - meaning the
            // wrapper receives the delegate as a parameter and calls its Invoke.
            if traces_to_argument(ssa, obj_var) {
                return true;
            }
        }
    }
    false
}

/// Scans an SSA function for calls to known delegate wrapper methods.
///
/// Returns `true` if at least one `Call` instruction references a wrapper
/// method from the pre-computed set.
fn has_delegate_proxy_calls(ssa: &SsaFunction, wrapper_methods: &HashMap<Token, Token>) -> bool {
    for block in ssa.blocks() {
        for instr in block.instructions() {
            if let Some((method_token, _)) = instr.op().method_call() {
                if wrapper_methods.contains_key(&method_token) {
                    return true;
                }
            }
        }
    }
    false
}

/// Detects delegate proxy call indirection via SSA analysis.
///
/// Identifies delegate types used as call proxies and the methods affected
/// by this pattern. Creates a [`DelegateProxyResolutionPass`] to resolve
/// indirect calls to their actual targets via emulation.
pub struct GenericDelegateProxy;

impl Technique for GenericDelegateProxy {
    fn id(&self) -> &'static str {
        "generic.delegates"
    }

    fn name(&self) -> &'static str {
        "Delegate Proxy Resolution"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Call
    }

    fn detect(&self, _assembly: &CilObject) -> Detection {
        // IL-level detection is not used — all detection happens in detect_ssa()
        // where we can follow exact def-use chains and verify wrapper patterns.
        Detection::new_empty()
    }

    fn detect_ssa(&self, ctx: &AnalysisContext, assembly: &CilObject) -> Detection {
        // Phase 1: Find delegate proxy types by scanning all types.
        //
        // A delegate proxy type:
        // - Inherits from System.MulticastDelegate (is_delegate())
        // - Has at least one static field (the singleton instance)
        // - Has a static wrapper method whose SSA contains callvirt(Invoke)
        //   where the delegate object comes from a LoadArg parameter
        let mut delegate_types: HashMap<Token, DelegateTypeInfo> = HashMap::new();
        let mut wrapper_to_delegate: HashMap<Token, Token> = HashMap::new();

        let mut delegate_count = 0usize;
        let mut has_static_field = 0usize;
        let mut has_static_method = 0usize;
        let mut has_ssa = 0usize;
        let mut is_wrapper = 0usize;

        for type_entry in assembly.types().iter() {
            let ty = type_entry.value();
            if !ty.is_delegate() {
                continue;
            }
            delegate_count = delegate_count.saturating_add(1);

            // Find the singleton static field. Delegate types normally have no
            // static fields, so any static field is the singleton instance.
            let Some(singleton_field_token) = ty
                .fields
                .iter()
                .find(|(_, f)| f.flags.is_static())
                .map(|(_, f)| f.token)
            else {
                continue;
            };
            has_static_field = has_static_field.saturating_add(1);

            // Find the wrapper method: static (not .cctor/.ctor), whose SSA
            // shows a callvirt(Invoke) pattern with the delegate from a parameter.
            let wrapper_method_token = ty.methods.iter().find_map(|(_, method_ref)| {
                let method = method_ref.upgrade()?;
                if !method.is_static() || method.is_cctor() || method.is_ctor() {
                    return None;
                }
                has_static_method = has_static_method.saturating_add(1);

                // Look up this method's SSA function from the analysis context
                let Some(ssa) = ctx.ssa_functions.get(&method.token) else {
                    debug!(
                        "Delegate detect: type {}.{} method 0x{:08X} ({}) has no SSA",
                        ty.namespace, ty.name, method.token.value(), method.name
                    );
                    return None;
                };
                has_ssa = has_ssa.saturating_add(1);

                if is_delegate_wrapper_ssa(ssa.value(), assembly) {
                    is_wrapper = is_wrapper.saturating_add(1);
                    Some(method.token)
                } else {
                    debug!(
                        "Delegate detect: type {}.{} method 0x{:08X} ({}) SSA did not match wrapper pattern",
                        ty.namespace, ty.name, method.token.value(), method.name
                    );
                    None
                }
            });

            let Some(wrapper_method_token) = wrapper_method_token else {
                continue;
            };

            delegate_types.insert(
                ty.token,
                DelegateTypeInfo {
                    singleton_field_token,
                    wrapper_method_token,
                },
            );
            wrapper_to_delegate.insert(wrapper_method_token, ty.token);
        }

        debug!(
            "Delegate detect: {} delegate types, {} with static fields, {} with static methods, {} with SSA, {} matched wrapper pattern",
            delegate_count, has_static_field, has_static_method, has_ssa, is_wrapper
        );

        // Phase 2: Scan SSA functions for delegate proxy calls AND reflection patterns.
        let mut delegate_affected: HashSet<Token> = HashSet::new();
        let mut reflection_affected: HashSet<Token> = HashSet::new();
        let mut reflection_site_count = 0usize;

        for entry in ctx.ssa_functions.iter() {
            let method_token = *entry.key();
            let ssa = entry.value();

            // Delegate proxy calls
            if !delegate_types.is_empty() && has_delegate_proxy_calls(ssa, &wrapper_to_delegate) {
                delegate_affected.insert(method_token);
            }

            // Reflection patterns: calli with ResolveMethod chain (P1)
            let calli_count = count_resolve_method_calli_sites(ssa, assembly);
            if calli_count > 0 {
                reflection_affected.insert(method_token);
                reflection_site_count = reflection_site_count.saturating_add(calli_count);
            }

            // Reflection patterns: call/callvirt to reflection APIs (P2, P3, P5, P6)
            let api_count = count_reflection_api_calls(ssa, assembly);
            if api_count > 0 {
                reflection_affected.insert(method_token);
                reflection_site_count = reflection_site_count.saturating_add(api_count);
            }
        }

        let has_delegates = !delegate_types.is_empty() && !delegate_affected.is_empty();
        let has_reflection = !reflection_affected.is_empty();

        if !has_delegates && !has_reflection {
            return Detection::new_empty();
        }

        let mut evidence = Vec::new();
        if has_delegates {
            let type_count = delegate_types.len();
            let method_count = delegate_affected.len();
            evidence.push(Evidence::Structural(format!(
                "{type_count} delegate proxy types affecting {method_count} methods"
            )));
        }
        if has_reflection {
            let method_count = reflection_affected.len();
            evidence.push(Evidence::Structural(format!(
                "{reflection_site_count} reflection call indirection sites in {method_count} methods"
            )));
        }

        let findings = CallIndirectionFindings {
            delegate: DelegateProxyFindings {
                delegate_types,
                affected_methods: delegate_affected,
            },
            reflection: ReflectionFindings {
                affected_methods: reflection_affected,
                site_count: reflection_site_count,
            },
        };

        Detection::new_detected(
            evidence,
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Inline)
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(combined) = detection.findings::<CallIndirectionFindings>() else {
            return Vec::new();
        };

        let mut passes: Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> = Vec::new();

        // Delegate proxy resolution pass (emulation-based)
        let delegate = &combined.delegate;
        if !delegate.delegate_types.is_empty() {
            if let Some(pool) = ctx.template_pool.get().cloned() {
                passes.push(Box::new(DelegateProxyResolutionPass::new(
                    pool,
                    delegate.delegate_types.clone(),
                    delegate.affected_methods.clone(),
                )));
            }
        }

        // Reflection devirtualization pass (SSA chain tracing)
        let reflection = &combined.reflection;
        if !reflection.affected_methods.is_empty() {
            passes.push(Box::new(ReflectionDevirtualizationPass::with_methods(
                reflection.affected_methods.clone(),
            )));
        }

        passes
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let combined = detection.findings::<CallIndirectionFindings>()?;
        let delegate = &combined.delegate;
        if delegate.delegate_types.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for &type_token in delegate.delegate_types.keys() {
            request.add_type(type_token);
        }
        Some(request)
    }
}

/// Counts reflection API call sites in an SSA function (P2, P3, P5, P6).
///
/// Matches `call`/`callvirt` to `MethodInfo.Invoke`, `Activator.CreateInstance`,
/// `FieldInfo.GetValue`, and `FieldInfo.SetValue` where the target comes from
/// a traceable reflection chain.
fn count_reflection_api_calls(ssa: &SsaFunction, assembly: &CilObject) -> usize {
    let mut count: usize = 0;
    for block in ssa.blocks() {
        for instr in block.instructions() {
            let Some((method_token, call)) = instr.op().method_call() else {
                continue;
            };
            let arg_count = call.args.len();

            let Some(name) = assembly.resolve_method_name(method_token) else {
                continue;
            };
            let declaring = assembly.resolve_method_declaring_type(method_token);
            let declared_by = |fullname: &str| declaring.as_deref() == Some(fullname);

            // P2/P3: MethodInfo.Invoke with 3 args (this, obj, params[])
            if name == "Invoke" && arg_count == 3 {
                // Verify this is MethodBase/MethodInfo.Invoke, not Delegate.Invoke
                if declared_by("System.Reflection.MethodBase")
                    || declared_by("System.Reflection.MethodInfo")
                {
                    count = count.saturating_add(1);
                    continue;
                }
            }

            // P5: Activator.CreateInstance
            if name.contains("CreateInstance") && declared_by("System.Activator") {
                count = count.saturating_add(1);
                continue;
            }

            // P6: FieldInfo.GetValue / SetValue
            if (name == "GetValue" || name == "SetValue")
                && declared_by("System.Reflection.FieldInfo")
            {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis::{Callee, MethodRef, SsaFunctionBuilder},
        compiler::PassPhase,
        deobfuscation::techniques::{
            generic::delegates::{CallIndirectionFindings, GenericDelegateProxy},
            Technique, TechniqueCategory,
        },
        testkit::helpers::{load_sample, method_token, mono_mscorlib},
    };

    #[test]
    fn test_detect_negative_confuserex_original() {
        let asm = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = GenericDelegateProxy;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "GenericDelegateProxy should not detect anything in a ConfuserEx original sample"
        );
        assert!(
            detection.evidence().is_empty(),
            "No evidence should be present for a non-obfuscated sample"
        );
        assert!(
            detection.findings::<CallIndirectionFindings>().is_none(),
            "No findings should be present for a non-obfuscated sample"
        );
    }

    #[test]
    fn test_detect_negative_obfuscar_sample() {
        let asm = load_sample("packers/obfuscar/2.2.50/obfuscar_strings_only.exe");

        let technique = GenericDelegateProxy;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "GenericDelegateProxy should not detect anything in an Obfuscar sample"
        );
    }

    #[test]
    fn test_technique_metadata() {
        let technique = GenericDelegateProxy;
        assert_eq!(technique.id(), "generic.delegates");
        assert_eq!(technique.name(), "Delegate Proxy Resolution");
        assert_eq!(technique.category(), TechniqueCategory::Call);
        assert!(technique.supersedes().is_empty());
    }

    #[test]
    fn test_technique_ssa_phase() {
        let technique = GenericDelegateProxy;
        assert_eq!(
            technique.ssa_phase(),
            Some(PassPhase::Inline),
            "GenericDelegateProxy should run in the Inline SSA phase"
        );
    }

    /// Reflection calls count by the type that declares them: `MethodBase.Invoke`,
    /// `Activator.CreateInstance` and `FieldInfo.GetValue` do, and a delegate's
    /// `Invoke` of the same arity does not. The check once asked whether the
    /// method's *name* contained the type's, which no reflection call's does,
    /// so none was counted.
    #[test]
    fn reflection_calls_count_by_their_declaring_type() {
        let mscorlib = mono_mscorlib();
        let count = |token: Token, args: usize| {
            let ssa = SsaFunctionBuilder::new(0, 0)
                .build_with(|f| {
                    f.block(0, |b| {
                        let args: Vec<SsaVarId> = (0..args).map(|_| b.const_i32(0)).collect();
                        b.call_void(Callee::Direct(MethodRef::new(token)), &args);
                        b.ret();
                    });
                })
                .unwrap();
            count_reflection_api_calls(&ssa, &mscorlib)
        };
        let invoke = method_token(&mscorlib, "System.Reflection.MethodBase", "Invoke", 2);
        let create = method_token(&mscorlib, "System.Activator", "CreateInstance", 1);
        let get_value = method_token(&mscorlib, "System.Reflection.FieldInfo", "GetValue", 1);
        let func_invoke = method_token(&mscorlib, "System.Func`3", "Invoke", 2);
        assert_eq!(count(invoke, 3), 1, "MethodBase.Invoke");
        assert_eq!(count(create, 1), 1, "Activator.CreateInstance");
        assert_eq!(count(get_value, 2), 1, "FieldInfo.GetValue");
        assert_eq!(count(func_invoke, 3), 0, "a delegate's Invoke");
    }
}
