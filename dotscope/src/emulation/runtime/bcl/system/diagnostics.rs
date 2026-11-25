//! `System.Diagnostics.Process` and `ProcessModule` method hooks.
//!
//! Provides comprehensive stub implementations for the Process/ProcessModule
//! object hierarchy commonly used by obfuscated .NET code to discover the
//! executable path, base address, and memory layout at runtime.
//!
//! # Supported Call Chains
//!
//! - `Process.GetCurrentProcess()` → `Process` object
//! - `Process.get_MainModule` → `ProcessModule` object
//! - `Process.get_Modules` → collection containing `ProcessModule`
//! - `ProcessModule.get_FileName` → executable path string
//! - `ProcessModule.get_BaseAddress` → PE image base as `IntPtr`
//! - `ProcessModule.get_ModuleMemorySize` → size of image in memory
//! - `ProcessModule.get_ModuleName` → module filename string

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        tokens, EmValue,
    },
    metadata::{tables::ModuleRaw, typesystem::CilFlavor},
    Result,
};

/// Registers all `System.Diagnostics.Process` and `ProcessModule` hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Diagnostics.Process.GetCurrentProcess")
            .match_name("System.Diagnostics", "Process", "GetCurrentProcess")
            .pre(process_get_current_process_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.Process.get_MainModule")
            .match_name("System.Diagnostics", "Process", "get_MainModule")
            .pre(process_get_main_module_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.Process.get_Modules")
            .match_name("System.Diagnostics", "Process", "get_Modules")
            .pre(process_get_modules_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.ProcessModule.get_FileName")
            .match_name("System.Diagnostics", "ProcessModule", "get_FileName")
            .pre(process_module_get_file_name_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.ProcessModule.get_BaseAddress")
            .match_name("System.Diagnostics", "ProcessModule", "get_BaseAddress")
            .pre(process_module_get_base_address_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.ProcessModule.get_ModuleMemorySize")
            .match_name(
                "System.Diagnostics",
                "ProcessModule",
                "get_ModuleMemorySize",
            )
            .pre(process_module_get_module_memory_size_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.ProcessModule.get_ModuleName")
            .match_name("System.Diagnostics", "ProcessModule", "get_ModuleName")
            .pre(process_module_get_module_name_pre),
    )?;

    manager.register(
        Hook::new("System.Diagnostics.Process.get_Id")
            .match_name("System.Diagnostics", "Process", "get_Id")
            .pre(process_get_id_pre),
    )?;

    Ok(())
}

/// Hook for `Process.GetCurrentProcess()` (static).
///
/// Allocates a `Process` object with a linked `ProcessModule` populated with:
/// - `FileName`: full path from assembly location config
/// - `BaseAddress`: PE image base address from the loaded assembly
/// - `ModuleMemorySize`: size of image from the PE header
/// - `ModuleName`: module filename from metadata
fn process_get_current_process_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // Resolve the module name from assembly metadata
    let module_name = thread
        .assembly()
        .and_then(|asm| {
            let tables = asm.tables()?;
            let strings = asm.strings()?;
            let module_table = tables.table::<ModuleRaw>()?;
            // Module is RID 1 by definition (ECMA-335 II.22.30); see `modules.rs`.
            let module_row = module_table.get(1).ok().flatten()?;
            strings.get(module_row.name as usize).ok().map(String::from)
        })
        .unwrap_or_else(|| "module.exe".to_string());

    // Get the PE image base address and size from the loaded assembly
    let (image_base, size_of_image) = thread
        .assembly()
        .map(|asm| {
            let file = asm.file();
            #[allow(clippy::cast_possible_wrap)]
            let base = file.imagebase() as i64;
            #[allow(clippy::cast_possible_wrap)]
            let size = file
                .pe()
                .optional_header
                .as_ref()
                .map_or(0, |oh| oh.windows_fields.size_of_image as i32);
            (base, size)
        })
        .unwrap_or((
            crate::emulation::tokens::native_addresses::CURRENT_MODULE,
            0,
        ));

    let base = &thread.config().environment.assembly_location_base;
    let path = format!("{base}\\{module_name}");

    // Allocate filename string
    let filename_ref = try_hook!(thread.heap_mut().alloc_string(&path));

    // Allocate module name string
    let modname_ref = try_hook!(thread.heap_mut().alloc_string(&module_name));

    // Allocate ProcessModule with all fields populated
    let pm_ref = try_hook!(thread
        .heap_mut()
        .alloc_object(tokens::system::PROCESS_MODULE));
    try_hook!(thread.heap_mut().set_field(
        pm_ref,
        tokens::process_fields::FILE_NAME,
        EmValue::ObjectRef(filename_ref),
    ));
    try_hook!(thread.heap_mut().set_field(
        pm_ref,
        tokens::process_fields::BASE_ADDRESS,
        EmValue::NativeInt(image_base),
    ));
    try_hook!(thread.heap_mut().set_field(
        pm_ref,
        tokens::process_fields::MODULE_MEMORY_SIZE,
        EmValue::I32(size_of_image),
    ));
    try_hook!(thread.heap_mut().set_field(
        pm_ref,
        tokens::process_fields::MODULE_NAME,
        EmValue::ObjectRef(modname_ref),
    ));

    // Allocate Process and set MainModule field
    let proc_ref = try_hook!(thread.heap_mut().alloc_object(tokens::system::PROCESS));
    try_hook!(thread.heap_mut().set_field(
        proc_ref,
        tokens::process_fields::MAIN_MODULE,
        EmValue::ObjectRef(pm_ref),
    ));

    PreHookResult::Bypass(Some(EmValue::ObjectRef(proc_ref)))
}

/// Hook for `Process.get_MainModule` (instance).
///
/// Reads the `MAIN_MODULE` field from the Process object.
fn process_get_main_module_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(proc_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*proc_ref, tokens::process_fields::MAIN_MODULE)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Process.get_Modules` (instance).
///
/// Returns a collection containing only the main module. In a real process,
/// this would enumerate all loaded DLLs, but for emulation we only need
/// the primary assembly module.
fn process_get_modules_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    // Get the main module first
    if let Some(EmValue::ObjectRef(proc_ref)) = ctx.this {
        if let Ok(main_module) = thread
            .heap()
            .get_field(*proc_ref, tokens::process_fields::MAIN_MODULE)
        {
            // Allocate an array containing just the main module
            let array_ref = try_hook!(thread
                .heap_mut()
                .alloc_array_with_values(CilFlavor::Object, vec![main_module]));
            return PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref)));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `ProcessModule.get_FileName` (instance).
///
/// Reads the `FILE_NAME` field from the ProcessModule object.
fn process_module_get_file_name_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(pm_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*pm_ref, tokens::process_fields::FILE_NAME)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `ProcessModule.get_BaseAddress` (instance).
///
/// Returns the PE image base address as a native `IntPtr`. This is the same
/// value that `Marshal.GetHINSTANCE(module)` returns, but accessed through
/// the Process/ProcessModule object hierarchy.
fn process_module_get_base_address_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(pm_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*pm_ref, tokens::process_fields::BASE_ADDRESS)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    // Fallback: get from assembly PE header
    let image_base = thread.assembly().map_or(
        crate::emulation::tokens::native_addresses::CURRENT_MODULE as u64,
        |asm| asm.file().imagebase(),
    );
    #[allow(clippy::cast_possible_wrap)]
    PreHookResult::Bypass(Some(EmValue::NativeInt(image_base as i64)))
}

/// Hook for `ProcessModule.get_ModuleMemorySize` (instance).
///
/// Returns the size of the PE image in memory.
fn process_module_get_module_memory_size_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(pm_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*pm_ref, tokens::process_fields::MODULE_MEMORY_SIZE)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `ProcessModule.get_ModuleName` (instance).
///
/// Returns the module filename (without path).
fn process_module_get_module_name_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    if let Some(EmValue::ObjectRef(pm_ref)) = ctx.this {
        if let Ok(val) = thread
            .heap()
            .get_field(*pm_ref, tokens::process_fields::MODULE_NAME)
        {
            return PreHookResult::Bypass(Some(val));
        }
    }
    PreHookResult::Bypass(Some(EmValue::Null))
}

/// Hook for `Process.get_Id` — returns a fake PID.
///
/// NR's anti-tamper uses `Process.GetCurrentProcess().Id` for process
/// identification. Returning Symbolic (unhooked default) poisons CFF state
/// computations downstream.
fn process_get_id_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(1234)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::HookManager,
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 8);
    }

    #[test]
    fn test_process_chain() {
        let mut thread = create_test_thread();

        let args: [EmValue; 0] = [];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Diagnostics",
            "Process",
            "GetCurrentProcess",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let result = process_get_current_process_pre(&ctx, &mut thread);
        let proc_ref = match result {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        };

        // get_MainModule
        let this = EmValue::ObjectRef(proc_ref);
        let ctx2 = HookContext::new(
            Token::new(0x0A000002),
            "System.Diagnostics",
            "Process",
            "get_MainModule",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result2 = process_get_main_module_pre(&ctx2, &mut thread);
        let pm_ref = match result2 {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => r,
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        };

        // get_FileName
        let this2 = EmValue::ObjectRef(pm_ref);
        let ctx3 = HookContext::new(
            Token::new(0x0A000003),
            "System.Diagnostics",
            "ProcessModule",
            "get_FileName",
            PointerSize::Bit64,
        )
        .with_this(Some(&this2));

        let result3 = process_module_get_file_name_pre(&ctx3, &mut thread);
        match result3 {
            PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) => {
                let s = thread.heap().get_string(r).unwrap();
                assert!(
                    s.contains("module.exe"),
                    "Expected path with module.exe, got: {s}"
                );
            }
            other => panic!("Expected Bypass with ObjectRef, got {other:?}"),
        }

        // get_BaseAddress
        let ctx4 = HookContext::new(
            Token::new(0x0A000004),
            "System.Diagnostics",
            "ProcessModule",
            "get_BaseAddress",
            PointerSize::Bit64,
        )
        .with_this(Some(&this2));

        let result4 = process_module_get_base_address_pre(&ctx4, &mut thread);
        match result4 {
            PreHookResult::Bypass(Some(EmValue::NativeInt(addr))) => {
                assert!(addr > 0, "BaseAddress should be non-zero, got {addr}");
            }
            other => panic!("Expected Bypass with NativeInt, got {other:?}"),
        }
    }
}
