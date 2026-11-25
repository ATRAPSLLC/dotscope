//! `System.Reflection` method hooks for the CIL emulator.
//!
//! This module provides comprehensive hook implementations for the .NET reflection
//! subsystem, enabling the emulator to handle runtime type inspection, member lookup,
//! dynamic method invocation, and assembly/module metadata queries. These capabilities
//! are essential for deobfuscation analysis because obfuscators use reflection
//! extensively to hide control flow and data dependencies from static analysis.
//!
//! # Module Organization
//!
//! The reflection hooks are split across four submodules by functional area:
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`types`] | `System.Type` properties and methods, `Object.GetType`, `Activator`, delegates, custom attributes |
//! | [`methods`] | `MethodBase`/`MethodInfo` invocation and metadata, `DynamicMethod`/`ILGenerator` |
//! | [`members`] | `FieldInfo`, `PropertyInfo`, `ParameterInfo`, and `MemberInfo` operations |
//! | [`modules`] | `Module`, `Assembly`, `ModuleHandle`, `Debugger`, `StackFrame` |
//!
//! Shared helper functions used across submodules (e.g., token extraction, type
//! normalization, value boxing/unboxing) are defined in [`helpers`] and re-exported
//! here; the module is private to the BCL, so they stay internal.
//!
//! # Deobfuscation Use Cases
//!
//! ## Dynamic Method Resolution
//!
//! ```csharp
//! // Common obfuscation pattern — encrypted token resolved at runtime
//! Module mod = typeof(Program).Module;
//! MethodBase method = mod.ResolveMethod(encryptedToken ^ key);
//! method.Invoke(null, new object[] { args });
//! ```
//!
//! ## Type-Based Dispatch
//!
//! ```csharp
//! // CFF state machine querying type metadata
//! Type t = Type.GetTypeFromHandle(handle);
//! MethodInfo decrypt = t.GetMethod("Decrypt");
//! string result = (string)decrypt.Invoke(null, new object[] { data });
//! ```
//!
//! ## Delegate Proxy Construction
//!
//! ```csharp
//! // DynamicMethod-based delegate proxy (e.g., ConfuserEx reference proxy)
//! var dm = new DynamicMethod("proxy", returnType, paramTypes, module, true);
//! var il = dm.GetILGenerator();
//! il.Emit(OpCodes.Ldarg_0);
//! il.Emit(OpCodes.Call, targetMethodInfo);
//! il.Emit(OpCodes.Ret);
//! var del = dm.CreateDelegate(delegateType);
//! ```
//!
//! # Hook Registration
//!
//! All 120 hooks are registered by the [`register`] function, which delegates to
//! qualified paths in the submodules (e.g., `types::type_get_method_pre`).
//!
//! # Limitations
//!
//! - All returned reflection objects are **symbolic** (fake tokens on the heap)
//! - `Invoke` dispatches to the emulator's method execution, not real .NET execution
//! - Field values come from the emulator's heap/static storage, not real memory
//! - Method resolution does not validate generic constraints

mod helpers;
mod members;
mod methods;
mod modules;
mod types;

pub use helpers::{
    alloc_type_array_from_tokens, box_value_if_needed, extract_type_token, find_method_by_name,
    normalize_type_token, resolve_attribute_type_token, resolve_method_from_token, unbox_value,
};

use crate::{
    emulation::{
        runtime::hook::{HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Hook for object reference equality comparison (`op_Equality`).
///
/// Used for `MethodBase.op_Equality`, `MethodInfo.op_Equality`, `Assembly.op_Equality`,
/// and similar reference-type comparison operators. Compares by heap reference identity:
/// two non-null references are equal iff they point to the same heap object.
pub fn object_ref_equality_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let equal = match (ctx.args.first(), ctx.args.get(1)) {
        (Some(EmValue::Null) | None, Some(EmValue::Null) | None) => true,
        (Some(EmValue::Null) | None, _) | (_, Some(EmValue::Null) | None) => false,
        (Some(EmValue::ObjectRef(a)), Some(EmValue::ObjectRef(b))) => a == b,
        _ => false,
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for object reference inequality comparison (`op_Inequality`).
///
/// Used for `MethodBase.op_Inequality`, `MethodInfo.op_Inequality`, `Assembly.op_Inequality`,
/// and similar reference-type comparison operators.
pub fn object_ref_inequality_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let not_equal = match (ctx.args.first(), ctx.args.get(1)) {
        (Some(EmValue::Null) | None, Some(EmValue::Null) | None) => false,
        (Some(EmValue::Null) | None, _) | (_, Some(EmValue::Null) | None) => true,
        (Some(EmValue::ObjectRef(a)), Some(EmValue::ObjectRef(b))) => a != b,
        _ => true,
    };
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(not_equal))))
}

/// Registers all reflection method hooks with the given hook manager.
///
/// Delegates to each submodule's `register()` function to install the complete
/// set of reflection hooks. See module documentation for the full list of
/// 120 hooks covering `Type`, `MethodBase`, `FieldInfo`, `PropertyInfo`,
/// `Module`, `Assembly`, `DynamicMethod`, delegates, and diagnostics.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
pub fn register(manager: &HookManager) -> Result<()> {
    types::register(manager)?;
    methods::register(manager)?;
    members::register(manager)?;
    modules::register(manager)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::emulation::runtime::{bcl::reflection::register, hook::HookManager};

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 141);
    }
}
