//! Module, assembly, debugger, and stack frame hooks for the CIL emulator.
//!
//! This module provides hook implementations for `System.Reflection.Module`,
//! `System.Reflection.Assembly`, `System.ModuleHandle`, `System.Diagnostics.Debugger`,
//! and `System.Diagnostics.StackFrame` operations.
//!
//! These hooks are critical for deobfuscation because obfuscators rely heavily on
//! module and assembly reflection for:
//!
//! - **Dynamic token resolution**: `Module.ResolveMethod(int)`, `Module.ResolveType(int)`,
//!   and `Module.ResolveField(int)` are used to resolve encrypted metadata tokens at runtime,
//!   bypassing static analysis of `call`/`callvirt` instructions
//! - **Module handle operations**: `ModuleHandle.GetRuntimeTypeHandleFromMetadataToken(int)`
//!   and related methods convert metadata tokens to runtime handles, used in conjunction
//!   with `Type.GetTypeFromHandle` for indirect type resolution
//! - **Anti-tamper checks**: `Assembly.Location`, `Assembly.FullName`, and
//!   `Module.FullyQualifiedName` are used to verify the assembly file hasn't been modified
//! - **Anti-debug**: `Debugger.IsAttached` is checked by anti-debug protections that throw
//!   or alter behavior when a debugger is detected
//! - **Caller verification**: `StackFrame.GetMethod()` is used in anti-tamper schemes
//!   that verify the calling method matches expected patterns
//! - **Assembly enumeration**: `Assembly.GetTypes()`, `GetReferencedAssemblies()`, and
//!   `GetModules()` are used by obfuscators to discover and initialize decryption infrastructure

use log::warn;

use crate::{
    emulation::{
        runtime::{
            bcl::reflection::{object_ref_equality_pre, object_ref_inequality_pre},
            hook::{Hook, HookContext, HookManager, PreHookResult},
        },
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::{tables::ModuleRaw, token::Token, typesystem::CilFlavor},
    Result,
};

/// Registers all module, assembly, debugger, and stack frame hooks.
///
/// Called by the parent `reflection::register()` to wire up `Module`, `Assembly`,
/// `ModuleHandle`, `Debugger`, and `StackFrame` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    // Module methods
    manager.register(
        Hook::new("System.Reflection.Module.get_FullyQualifiedName")
            .match_name("System.Reflection", "Module", "get_FullyQualifiedName")
            .pre(module_get_fully_qualified_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Module.get_Assembly")
            .match_name("System.Reflection", "Module", "get_Assembly")
            .pre(module_get_assembly_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Module.get_ModuleHandle")
            .match_name("System.Reflection", "Module", "get_ModuleHandle")
            .pre(module_get_module_handle_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Module.ResolveMethod")
            .match_name("System.Reflection", "Module", "ResolveMethod")
            .pre(module_resolve_method_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Module.ResolveType")
            .match_name("System.Reflection", "Module", "ResolveType")
            .pre(module_resolve_type_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Module.ResolveField")
            .match_name("System.Reflection", "Module", "ResolveField")
            .pre(module_resolve_field_pre),
    )?;

    // Assembly properties
    manager.register(
        Hook::new("System.Reflection.Assembly.get_GlobalAssemblyCache")
            .match_name("System.Reflection", "Assembly", "get_GlobalAssemblyCache")
            .pre(assembly_get_global_assembly_cache_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.get_Location")
            .match_name("System.Reflection", "Assembly", "get_Location")
            .pre(assembly_get_location_pre),
    )?;

    // Debugger
    manager.register(
        Hook::new("System.Diagnostics.Debugger.get_IsAttached")
            .match_name("System.Diagnostics", "Debugger", "get_IsAttached")
            .pre(debugger_get_is_attached_pre),
    )?;

    // Assembly type enumeration
    manager.register(
        Hook::new("System.Reflection.Assembly.GetTypes")
            .match_name("System.Reflection", "Assembly", "GetTypes")
            .pre(assembly_get_types_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.GetExportedTypes")
            .match_name("System.Reflection", "Assembly", "GetExportedTypes")
            .pre(assembly_get_exported_types_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.GetType")
            .match_name("System.Reflection", "Assembly", "GetType")
            .pre(assembly_get_type_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.get_FullName")
            .match_name("System.Reflection", "Assembly", "get_FullName")
            .pre(assembly_get_full_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.GetName")
            .match_name("System.Reflection", "Assembly", "GetName")
            .pre(assembly_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.AssemblyName.get_Name")
            .match_name("System.Reflection", "AssemblyName", "get_Name")
            .pre(assembly_name_get_name_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.GetManifestResourceNames")
            .match_name("System.Reflection", "Assembly", "GetManifestResourceNames")
            .pre(assembly_get_manifest_resource_names_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.GetModules")
            .match_name("System.Reflection", "Assembly", "GetModules")
            .pre(assembly_get_modules_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.get_ManifestModule")
            .match_name("System.Reflection", "Assembly", "get_ManifestModule")
            .pre(assembly_get_manifest_module_pre),
    )?;

    // ModuleHandle — converts metadata tokens to runtime handles
    manager.register(
        Hook::new("System.ModuleHandle.GetRuntimeTypeHandleFromMetadataToken")
            .match_name(
                "System",
                "ModuleHandle",
                "GetRuntimeTypeHandleFromMetadataToken",
            )
            .pre(module_handle_resolve_token_pre),
    )?;
    manager.register(
        Hook::new("System.ModuleHandle.ResolveTypeHandle")
            .match_name("System", "ModuleHandle", "ResolveTypeHandle")
            .pre(module_handle_resolve_token_pre),
    )?;

    manager.register(
        Hook::new("System.ModuleHandle.GetRuntimeFieldHandleFromMetadataToken")
            .match_name(
                "System",
                "ModuleHandle",
                "GetRuntimeFieldHandleFromMetadataToken",
            )
            .pre(module_handle_resolve_token_pre),
    )?;
    manager.register(
        Hook::new("System.ModuleHandle.ResolveFieldHandle")
            .match_name("System", "ModuleHandle", "ResolveFieldHandle")
            .pre(module_handle_resolve_token_pre),
    )?;

    manager.register(
        Hook::new("System.ModuleHandle.GetRuntimeMethodHandleFromMetadataToken")
            .match_name(
                "System",
                "ModuleHandle",
                "GetRuntimeMethodHandleFromMetadataToken",
            )
            .pre(module_handle_resolve_token_pre),
    )?;
    manager.register(
        Hook::new("System.ModuleHandle.ResolveMethodHandle")
            .match_name("System", "ModuleHandle", "ResolveMethodHandle")
            .pre(module_handle_resolve_token_pre),
    )?;

    // StackFrame — anti-tamper caller verification
    manager.register(
        Hook::new("System.Diagnostics.StackFrame..ctor")
            .match_name("System.Diagnostics", "StackFrame", ".ctor")
            .pre(stack_frame_ctor_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.StackFrame.GetMethod")
            .match_name("System.Diagnostics", "StackFrame", "GetMethod")
            .pre(stack_frame_get_method_pre),
    )?;

    // Assembly.GetReferencedAssemblies
    manager.register(
        Hook::new("System.Reflection.Assembly.GetReferencedAssemblies")
            .match_name("System.Reflection", "Assembly", "GetReferencedAssemblies")
            .pre(assembly_get_referenced_assemblies_pre),
    )?;

    // Assembly comparison operators
    manager.register(
        Hook::new("System.Reflection.Assembly.op_Equality")
            .match_name("System.Reflection", "Assembly", "op_Equality")
            .pre(object_ref_equality_pre),
    )?;

    manager.register(
        Hook::new("System.Reflection.Assembly.op_Inequality")
            .match_name("System.Reflection", "Assembly", "op_Inequality")
            .pre(object_ref_inequality_pre),
    )?;

    // Assembly.get_EntryPoint
    manager.register(
        Hook::new("System.Reflection.Assembly.get_EntryPoint")
            .match_name("System.Reflection", "Assembly", "get_EntryPoint")
            .pre(assembly_get_entry_point_pre),
    )?;

    Ok(())
}

/// Hook for `System.Reflection.Module.get_FullyQualifiedName` property.
///
/// Gets a string representing the fully qualified name and path to this module.
/// Reads the module name from metadata and combines it with the configured base path.
fn module_get_fully_qualified_name_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let module_name = thread
        .assembly()
        .and_then(|asm| {
            let tables = asm.tables()?;
            let strings = asm.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            // The Module table has exactly one row and it is RID 1 (ECMA-335 II.22.30), so
            // fetch it by RID. Taking the first row that *parses* silently promotes row 2
            // when row 1 is malformed.
            let module_row = module_table.get(1).ok().flatten()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        })
        .unwrap_or_else(|| "module.exe".to_string());

    let base = &thread.config().environment.module_base_path;
    let path = format!("{base}\\{module_name}");

    match thread.heap_mut().alloc_string(&path) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Reflection.Module.get_Assembly` property.
///
/// Gets the assembly for this module. Returns the pre-allocated fake Assembly
/// object from [`FakeObjects`](crate::emulation::FakeObjects), ensuring that multiple calls return the same
/// reference. This is critical for anti-tamper checks that compare assembly references.
fn module_get_assembly_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Return the pre-allocated fake assembly from FakeObjects.
    // This ensures Assembly.GetExecutingAssembly() == module.Assembly passes.
    if let Some(asm_ref) = thread.fake_objects().assembly() {
        return PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref)));
    }

    // Fallback: allocate a new fake assembly if FakeObjects not initialized
    match thread.heap_mut().alloc_object(tokens::singletons::ASSEMBLY) {
        Ok(asm_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(asm_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Reflection.Module.get_ModuleHandle` property.
///
/// Returns a `ModuleHandle` struct for this module. In real .NET, `ModuleHandle`
/// wraps an `IntPtr` to internal runtime data. We return the PE image base
/// address, which is what obfuscated code typically extracts from the handle
/// for pointer arithmetic on the in-memory PE image.
fn module_get_module_handle_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let image_base = thread
        .assembly()
        .map_or(tokens::native_addresses::CURRENT_MODULE as u64, |asm| {
            asm.file().imagebase()
        });
    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::NativeInt(image_base as i64)))
}

/// Hook for `System.Reflection.Module.ResolveMethod` method.
///
/// Returns the method identified by the specified metadata token. Validates that
/// the token table is MethodDef (0x06), MemberRef (0x0A), or MethodSpec (0x2B).
fn module_resolve_method_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let method_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        Token::new(token_value as u32)
    } else {
        return PreHookResult::throw_argument_exception("Missing metadata token argument");
    };

    // Validate: only MethodDef (0x06), MemberRef (0x0A), MethodSpec (0x2B) are valid
    let table = method_token.table();
    if table != 0x06 && table != 0x0A && table != 0x2B {
        warn!(
            "Module.ResolveMethod: invalid token table 0x{:02X} for 0x{:08X}",
            table,
            method_token.value()
        );
        return PreHookResult::throw_argument_exception("Token is not a valid method token");
    }

    match thread.heap_mut().alloc_reflection_method(method_token) {
        Ok(method_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(method_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Reflection.Module.ResolveType` method.
///
/// Returns the type identified by the specified metadata token.
fn module_resolve_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let type_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        Token::new(token_value as u32)
    } else {
        return PreHookResult::throw_argument_exception("Missing metadata token argument");
    };

    match thread.heap_mut().alloc_reflection_type(type_token, None) {
        Ok(type_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(type_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Reflection.Module.ResolveField` method.
///
/// Returns the field identified by the specified metadata token, along with its
/// declaring type and static flag so that downstream `FieldInfo.GetValue`/`SetValue`
/// hooks can read and write the correct storage.
fn module_resolve_field_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Extract the metadata token from the first argument (int32)
    #[allow(clippy::cast_sign_loss)]
    let field_token = if let Some(token_value) = ctx.args.first().and_then(EmValue::as_i32) {
        Token::new(token_value as u32)
    } else {
        return PreHookResult::throw_argument_exception("Missing metadata token argument");
    };

    // Find the declaring type and static flag by scanning all types for this field token
    if let Some(asm) = thread.assembly().cloned() {
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            for (_, field) in cil_type.fields.iter() {
                if field.token == field_token {
                    match thread.heap_mut().alloc_reflection_field(
                        field_token,
                        cil_type.token,
                        field.flags.is_static(),
                    ) {
                        Ok(fi_ref) => {
                            return PreHookResult::Bypass(Some(EmValue::ObjectRef(fi_ref)));
                        }
                        Err(e) => {
                            return PreHookResult::Error(format!("heap allocation failed: {e}"))
                        }
                    }
                }
            }
        }
    }

    // Field not found in assembly — return null
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Shared hook for all `ModuleHandle` token-resolution methods.
///
/// In real .NET, `GetRuntime{Type,Field,Method}HandleFromMetadataToken(int)`
/// delegates to `Resolve{Type,Field,Method}Handle(int)`, which ultimately
/// QCalls into the CLR VM to look up a token in the module's metadata.
///
/// For emulation, all six methods do the same thing: extract the metadata token
/// from the first argument and pass it through as a `NativeInt`. Downstream
/// hooks extract the token from the `NativeInt` to resolve the corresponding
/// metadata object.
fn module_handle_resolve_token_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let token_value = match ctx.args.first() {
        Some(EmValue::I32(v)) => i64::from(*v),
        Some(EmValue::NativeInt(v)) => *v,
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::NativeInt(token_value)))
}

/// Hook for `Assembly.get_GlobalAssemblyCache`.
///
/// Local assemblies are not in the GAC, always returns false.
fn assembly_get_global_assembly_cache_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Reflection.Assembly.get_Location` property.
///
/// Returns a plausible file path for the assembly using the module name from metadata
/// and the configured assembly location base path.
fn assembly_get_location_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let module_name = thread
        .assembly()
        .and_then(|asm| {
            let tables = asm.tables()?;
            let strings = asm.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            // The Module table has exactly one row and it is RID 1 (ECMA-335 II.22.30), so
            // fetch it by RID. Taking the first row that *parses* silently promotes row 2
            // when row 1 is malformed.
            let module_row = module_table.get(1).ok().flatten()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        })
        .unwrap_or_else(|| "module.exe".to_string());

    let base = &thread.config().environment.assembly_location_base;
    let path = format!("{base}\\{module_name}");

    match thread.heap_mut().alloc_string(&path) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.get_FullName`.
///
/// Returns the real assembly full name from metadata, including version information.
fn assembly_get_full_name_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        if let Some(assembly_meta) = asm.assembly() {
            let full_name = format!(
                "{}, Version={}.{}.{}.{}",
                assembly_meta.name,
                assembly_meta.major_version,
                assembly_meta.minor_version,
                assembly_meta.build_number,
                assembly_meta.revision_number
            );
            match thread.heap_mut().alloc_string(&full_name) {
                Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    match thread.heap_mut().alloc_string("Assembly, Version=0.0.0.0") {
        Ok(s_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetName()`.
///
/// Returns a stub `AssemblyName` object.
fn assembly_get_name_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread
        .heap_mut()
        .alloc_object(tokens::reflection::ASSEMBLY_NAME)
    {
        Ok(obj_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(obj_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `AssemblyName.get_Name`.
///
/// Returns the real assembly name from metadata.
fn assembly_name_get_name_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        if let Some(assembly_meta) = asm.assembly() {
            match thread.heap_mut().alloc_string(&assembly_meta.name) {
                Ok(s_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    match thread.heap_mut().alloc_string("Assembly") {
        Ok(s_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(s_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetManifestResourceNames()`.
///
/// Returns an empty string array.
fn assembly_get_manifest_resource_names_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.get_ManifestModule`.
///
/// Returns a fake Module reflection object representing the primary module of
/// the loaded assembly. This is used by obfuscators to obtain a module handle
/// for native interop (`Marshal.GetHINSTANCE(module)`).
fn assembly_get_manifest_module_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    match thread.heap_mut().alloc_object(tokens::reflection::MODULE) {
        Ok(m_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(m_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetModules()`.
///
/// Returns a single-element array with a fake Module object.
fn assembly_get_modules_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let m_ref = try_hook!(thread.heap_mut().alloc_object(tokens::reflection::MODULE));
    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Object, vec![EmValue::ObjectRef(m_ref)])
    {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetTypes()`.
///
/// Returns an array of all types defined in the assembly.
fn assembly_get_types_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        let mut type_elements = Vec::new();
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            match thread
                .heap_mut()
                .alloc_reflection_type(cil_type.token, None)
            {
                Ok(t_ref) => type_elements.push(EmValue::ObjectRef(t_ref)),
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
        match thread
            .heap_mut()
            .alloc_array_with_values(CilFlavor::Object, type_elements)
        {
            Ok(arr_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetExportedTypes()` -- same as GetTypes but only public.
///
/// Returns an array of all public types defined in the assembly.
fn assembly_get_exported_types_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        let mut type_elements = Vec::new();
        for entry in asm.types().iter() {
            let cil_type = entry.value();
            if cil_type.flags.is_public() {
                match thread
                    .heap_mut()
                    .alloc_reflection_type(cil_type.token, None)
                {
                    Ok(t_ref) => type_elements.push(EmValue::ObjectRef(t_ref)),
                    Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
                }
            }
        }
        match thread
            .heap_mut()
            .alloc_array_with_values(CilFlavor::Object, type_elements)
        {
            Ok(arr_ref) => return PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        }
    }
    match thread.heap_mut().alloc_array(CilFlavor::Object, 0) {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.GetType(string)` / `Assembly.GetType(string, bool)`.
///
/// Searches the assembly's type registry for a type matching the given name.
fn assembly_get_type_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if let Some(EmValue::ObjectRef(name_ref)) = ctx.args.first() {
        if let Ok(type_name) = thread.heap().get_string(*name_ref) {
            if let Some(asm) = thread.assembly().cloned() {
                for entry in asm.types().iter() {
                    let cil_type = entry.value();
                    let full_name: std::borrow::Cow<'_, str> = if cil_type.namespace.is_empty() {
                        std::borrow::Cow::Borrowed(cil_type.name.as_str())
                    } else {
                        // Check both "Namespace.Name" formats
                        std::borrow::Cow::Owned(format!("{}.{}", cil_type.namespace, cil_type.name))
                    };
                    if full_name == type_name.as_ref() || cil_type.name == type_name.as_ref() {
                        match thread
                            .heap_mut()
                            .alloc_reflection_type(cil_type.token, None)
                        {
                            Ok(t_ref) => {
                                return PreHookResult::Bypass(Some(EmValue::ObjectRef(t_ref)))
                            }
                            Err(e) => {
                                return PreHookResult::Error(format!("heap allocation failed: {e}"))
                            }
                        }
                    }
                }
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Assembly.GetReferencedAssemblies()`.
///
/// Reads the AssemblyRef metadata table and returns an `AssemblyName[]` array
/// with one stub `AssemblyName` object per referenced assembly.
fn assembly_get_referenced_assemblies_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let assembly_names: Vec<EmValue> = thread
        .assembly()
        .cloned()
        .map(|asm| {
            asm.refs_assembly()
                .iter()
                .filter_map(|entry| {
                    let aref = entry.value();
                    // Allocate an AssemblyName stub object
                    let name_obj = thread
                        .heap_mut()
                        .alloc_object(tokens::reflection::ASSEMBLY_NAME)
                        .ok()?;
                    // Store the name as a string field so AssemblyName.get_Name can find it
                    if let Ok(name_str) = thread.heap_mut().alloc_string(&aref.name) {
                        if thread
                            .heap()
                            .set_field(
                                name_obj,
                                tokens::misc_fields::ASSEMBLY_NAME_NAME,
                                EmValue::ObjectRef(name_str),
                            )
                            .is_err()
                        {
                            return None;
                        }
                    }
                    Some(EmValue::ObjectRef(name_obj))
                })
                .collect()
        })
        .unwrap_or_default();

    match thread
        .heap_mut()
        .alloc_array_with_values(CilFlavor::Object, assembly_names)
    {
        Ok(arr_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(arr_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Assembly.get_EntryPoint`.
///
/// Returns a `ReflectionMethod` for the assembly's entry point token from the
/// COR20 header. Returns null if the assembly has no entry point.
fn assembly_get_entry_point_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(asm) = thread.assembly().cloned() {
        let entry_token = asm.cor20header().entry_point_token;
        if entry_token != 0 {
            match thread
                .heap_mut()
                .alloc_reflection_method(Token::new(entry_token))
            {
                Ok(method_ref) => {
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(method_ref)))
                }
                Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
            }
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Debugger.get_IsAttached`.
///
/// Returns false so anti-debug checks that throw when a debugger is detected
/// are bypassed during emulation.
fn debugger_get_is_attached_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `StackFrame::.ctor(int skipFrames)`.
///
/// Walks the emulation call stack by `skipFrames` levels from the current frame
/// (the method that executed `newobj StackFrame`), resolves the method token at
/// that depth, allocates a `ReflectionMethod` for it, and stores it as a field
/// on the StackFrame object.
fn stack_frame_ctor_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let skip_frames = match ctx.args.first() {
        Some(EmValue::I32(v)) => *v as usize,
        _ => 0,
    };

    // When the pre-hook fires, the .ctor hasn't been entered yet.
    // current_frame() is the method that executed `newobj StackFrame(...)`.
    // skip_frames=0 → current frame (the caller of StackFrame)
    // skip_frames=1 → one frame below (the caller's caller)
    let depth = thread.call_depth();
    let target_index = depth.saturating_sub(1).saturating_sub(skip_frames);
    let method_token = thread
        .get_frame_at(target_index)
        .map(|f| f.method())
        .unwrap_or(Token::new(0));

    // Store the resolved method as a ReflectionMethod on the StackFrame object
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if method_token.value() != 0 {
            if let Ok(method_ref) = thread.heap_mut().alloc_reflection_method(method_token) {
                try_hook!(thread.heap().set_field(
                    *this_ref,
                    tokens::misc_fields::STACKFRAME_METHOD,
                    EmValue::ObjectRef(method_ref),
                ));
            }
        }
    }

    PreHookResult::Bypass(None)
}

/// Hook for `StackFrame.GetMethod()`.
///
/// Returns the `ReflectionMethod` that was stored by the `.ctor` hook.
fn stack_frame_get_method_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(this_ref)) = ctx.this {
        if let Ok(method_val) = thread
            .heap()
            .get_field(*this_ref, tokens::misc_fields::STACKFRAME_METHOD)
        {
            return PreHookResult::Bypass(Some(method_val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}
