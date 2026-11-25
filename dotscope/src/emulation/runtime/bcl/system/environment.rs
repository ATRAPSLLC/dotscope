//! `System.Environment` method hooks for .NET emulation.
//!
//! This module provides hook implementations for `System.Environment` properties and methods
//! commonly queried by obfuscators for environment fingerprinting, anti-analysis checks,
//! and runtime behavior decisions.
//!
//! # Overview
//!
//! Obfuscators and packers frequently query environment properties to:
//! - Detect analysis environments (processor count, OS bitness)
//! - Derive encryption keys from machine-specific values (machine name, user name)
//! - Implement time-based anti-debug checks (tick counts)
//! - Resolve file paths for resource loading (special folders, current directory)
//! - Check environment variables for configuration or licensing
//!
//! # Emulated .NET Methods
//!
//! ## Properties
//!
//! | Property | Return Type | Implementation |
//! |----------|-------------|----------------|
//! | `Environment.ProcessorCount` | `Int32` | Returns configured processor count |
//! | `Environment.Is64BitOperatingSystem` | `Boolean` | Returns configured bitness flag |
//! | `Environment.Is64BitProcess` | `Boolean` | Returns configured bitness flag |
//! | `Environment.UserName` | `String` | Returns configured user name |
//! | `Environment.MachineName` | `String` | Returns configured machine name |
//! | `Environment.CurrentDirectory` | `String` | Returns configured directory |
//! | `Environment.TickCount` | `Int32` | Returns base + elapsed ticks (truncated) |
//! | `Environment.TickCount64` | `Int64` | Returns base + elapsed ticks |
//! | `Environment.StackTrace` | `String` | Returns empty string |
//! | `Environment.OSVersion` | `OperatingSystem` | Returns version string (simplified) |
//!
//! ## Methods
//!
//! | Method | Description | Implementation |
//! |--------|-------------|----------------|
//! | `Environment.GetEnvironmentVariable(String)` | Lookup variable | Returns from configured map or null |
//! | `Environment.Exit(Int32)` | Terminate process | No-op bypass to prevent hard exit |
//! | `Environment.GetFolderPath(SpecialFolder)` | Get special folder | Returns from configured folder map |
//!
//! # Configuration
//!
//! All values are controlled by [`EnvironmentConfig`] in [`EmulationConfig`]. The defaults
//! simulate a Windows 10 x64 environment suitable for most deobfuscation scenarios.
//!
//! [`EnvironmentConfig`]: crate::emulation::EnvironmentConfig
//! [`EmulationConfig`]: crate::emulation::EmulationConfig

use crate::{
    emulation::{
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    Result,
};

/// Registers all `System.Environment` method hooks.
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Environment.get_ProcessorCount")
            .match_name("System", "Environment", "get_ProcessorCount")
            .pre(get_processor_count_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_Is64BitOperatingSystem")
            .match_name("System", "Environment", "get_Is64BitOperatingSystem")
            .pre(get_is_64bit_os_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_Is64BitProcess")
            .match_name("System", "Environment", "get_Is64BitProcess")
            .pre(get_is_64bit_process_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_UserName")
            .match_name("System", "Environment", "get_UserName")
            .pre(get_user_name_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_MachineName")
            .match_name("System", "Environment", "get_MachineName")
            .pre(get_machine_name_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_CurrentDirectory")
            .match_name("System", "Environment", "get_CurrentDirectory")
            .pre(get_current_directory_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.GetEnvironmentVariable")
            .match_name("System", "Environment", "GetEnvironmentVariable")
            .pre(get_environment_variable_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_TickCount")
            .match_name("System", "Environment", "get_TickCount")
            .pre(get_tick_count_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_TickCount64")
            .match_name("System", "Environment", "get_TickCount64")
            .pre(get_tick_count64_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.Exit")
            .match_name("System", "Environment", "Exit")
            .pre(exit_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_StackTrace")
            .match_name("System", "Environment", "get_StackTrace")
            .pre(get_stack_trace_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.GetFolderPath")
            .match_name("System", "Environment", "GetFolderPath")
            .pre(get_folder_path_pre),
    )?;
    manager.register(
        Hook::new("System.Environment.get_OSVersion")
            .match_name("System", "Environment", "get_OSVersion")
            .pre(get_os_version_pre),
    )?;

    Ok(())
}

/// Hook for `System.Environment.get_ProcessorCount` property.
///
/// # Handled Overloads
///
/// - `Environment.ProcessorCount { get; } -> Int32`
///
/// # Returns
///
/// The configured processor count from `EnvironmentConfig`
fn get_processor_count_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(
        thread.config().environment.processor_count,
    )))
}

/// Hook for `System.Environment.get_Is64BitOperatingSystem` property.
///
/// # Handled Overloads
///
/// - `Environment.Is64BitOperatingSystem { get; } -> Boolean`
///
/// # Returns
///
/// `true` if the configured environment simulates a 64-bit OS
fn get_is_64bit_os_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(
        thread.config().environment.is_64bit_os as i32,
    )))
}

/// Hook for `System.Environment.get_Is64BitProcess` property.
///
/// # Handled Overloads
///
/// - `Environment.Is64BitProcess { get; } -> Boolean`
///
/// # Returns
///
/// `true` if the configured environment simulates a 64-bit process
fn get_is_64bit_process_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(
        thread.config().environment.is_64bit_process as i32,
    )))
}

/// Hook for `System.Environment.get_UserName` property.
///
/// # Handled Overloads
///
/// - `Environment.UserName { get; } -> String`
///
/// # Returns
///
/// The configured user name as a heap-allocated string
fn get_user_name_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let name = &thread.config().environment.user_name;
    match thread.heap_mut().alloc_string(name) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Environment.get_MachineName` property.
///
/// # Handled Overloads
///
/// - `Environment.MachineName { get; } -> String`
///
/// # Returns
///
/// The configured machine name as a heap-allocated string
fn get_machine_name_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let name = &thread.config().environment.machine_name;
    match thread.heap_mut().alloc_string(name) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Environment.get_CurrentDirectory` property.
///
/// # Handled Overloads
///
/// - `Environment.CurrentDirectory { get; } -> String`
///
/// # Returns
///
/// The configured current directory as a heap-allocated string
fn get_current_directory_pre(
    _ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let dir = &thread.config().environment.current_directory;
    match thread.heap_mut().alloc_string(dir) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Environment.GetEnvironmentVariable` method.
///
/// # Handled Overloads
///
/// - `Environment.GetEnvironmentVariable(String) -> String`
///
/// # Parameters
///
/// - `variable`: The name of the environment variable to retrieve
///
/// # Returns
///
/// The value of the environment variable from the configured map, or null if not found
fn get_environment_variable_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let var_name = match ctx.args.first() {
        Some(EmValue::ObjectRef(r)) => match thread.heap().get_string(*r).map(|s| s.to_string()) {
            Ok(s) => s,
            Err(e) => return PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread
        .config()
        .environment
        .environment_variables
        .get(&var_name)
    {
        Some(value) => match thread.heap_mut().alloc_string(value) {
            Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
            Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        None => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Environment.get_TickCount` property.
///
/// # Handled Overloads
///
/// - `Environment.TickCount { get; } -> Int32`
///
/// # Returns
///
/// A simulated tick count computed as `tick_count_base + instructions_executed / divisor`,
/// truncated to 32 bits. The tick count advances as more instructions are executed,
/// providing realistic time progression for anti-debug checks.
fn get_tick_count_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let config = &thread.config().environment;
    let divisor = config.tick_count_divisor.max(1); // avoid division by zero
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    let ticks = config.tick_count_base.saturating_add(
        thread
            .instructions_executed()
            .checked_div(divisor)
            .unwrap_or(0) as i64,
    );
    PreHookResult::Bypass(Some(EmValue::I32(ticks as i32)))
}

/// Hook for `System.Environment.get_TickCount64` property.
///
/// # Handled Overloads
///
/// - `Environment.TickCount64 { get; } -> Int64`
///
/// # Returns
///
/// A simulated tick count computed as `tick_count_base + instructions_executed / divisor`,
/// returned as a full 64-bit value without truncation.
fn get_tick_count64_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let config = &thread.config().environment;
    let divisor = config.tick_count_divisor.max(1); // avoid division by zero
    #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
    let ticks = config.tick_count_base.saturating_add(
        thread
            .instructions_executed()
            .checked_div(divisor)
            .unwrap_or(0) as i64,
    );
    PreHookResult::Bypass(Some(EmValue::I64(ticks)))
}

/// Hook for `System.Environment.Exit` method.
///
/// # Handled Overloads
///
/// - `Environment.Exit(Int32) -> void`
///
/// # Parameters
///
/// - `exitCode`: The exit code for the process (ignored)
///
/// # Returns
///
/// No-op bypass to prevent the emulated process from terminating
fn exit_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Environment.get_StackTrace` property.
///
/// # Handled Overloads
///
/// - `Environment.StackTrace { get; } -> String`
///
/// # Returns
///
/// An empty string, as stack trace generation is not meaningful in emulation
fn get_stack_trace_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    match thread.heap_mut().alloc_string("") {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Environment.GetFolderPath` method.
///
/// # Handled Overloads
///
/// - `Environment.GetFolderPath(SpecialFolder) -> String`
///
/// # Parameters
///
/// - `folder`: The `SpecialFolder` enum value (as `Int32`) identifying the folder
///
/// # Returns
///
/// The configured path for the requested special folder, or an empty string if not found.
/// Common folder values: Desktop (0), ApplicationData (26), LocalApplicationData (28),
/// CommonApplicationData (35), Windows (37), ProgramFiles (41).
fn get_folder_path_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let folder_id = match ctx.args.first() {
        Some(EmValue::I32(id)) => *id,
        _ => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    let path = thread
        .config()
        .environment
        .folder_paths
        .get(&folder_id)
        .cloned()
        .unwrap_or_default();

    match thread.heap_mut().alloc_string(&path) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Environment.get_OSVersion` property.
///
/// # Handled Overloads
///
/// - `Environment.OSVersion { get; } -> OperatingSystem`
///
/// # Returns
///
/// A simplified representation of the OS version as a heap-allocated string.
/// In a full .NET runtime, this returns an `OperatingSystem` object, but for
/// emulation purposes the version string is sufficient for most obfuscator checks.
fn get_os_version_pre(_ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let version = &thread.config().environment.os_version;
    match thread.heap_mut().alloc_string(version) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::runtime::hook::{HookContext, HookManager, PreHookResult},
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 13);
    }

    #[test]
    fn test_get_processor_count() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Environment",
            "get_ProcessorCount",
            PointerSize::Bit64,
        );
        let result = get_processor_count_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(4)))
        ));
    }

    #[test]
    fn test_get_tick_count_advances() {
        let mut thread = create_test_thread();
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Environment",
            "get_TickCount",
            PointerSize::Bit64,
        );
        let result = get_tick_count_pre(&ctx, &mut thread);
        // With 0 instructions executed and base of 300_000, should return 300_000
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(300_000)))
        ));
    }

    #[test]
    fn test_get_folder_path() {
        let mut thread = create_test_thread();
        let args = [EmValue::I32(0)]; // Desktop
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Environment",
            "GetFolderPath",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = get_folder_path_pre(&ctx, &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "C:\\Users\\user\\Desktop");
        } else {
            panic!("Expected ObjectRef");
        }
    }

    fn ctx<'a>(method: &'a str, args: &'a [EmValue]) -> HookContext<'a> {
        HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Environment",
            method,
            PointerSize::Bit64,
        )
        .with_args(args)
    }

    #[test]
    fn test_is_64bit_os() {
        let mut thread = create_test_thread();
        let result = get_is_64bit_os_pre(&ctx("get_Is64BitOperatingSystem", &[]), &mut thread);
        // Returns I32(1) for true
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_is_64bit_process() {
        let mut thread = create_test_thread();
        let result = get_is_64bit_process_pre(&ctx("get_Is64BitProcess", &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_get_user_name() {
        let mut thread = create_test_thread();
        let result = get_user_name_pre(&ctx("get_UserName", &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert!(!s.is_empty());
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_get_machine_name() {
        let mut thread = create_test_thread();
        let result = get_machine_name_pre(&ctx("get_MachineName", &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert!(!s.is_empty());
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_get_current_directory() {
        let mut thread = create_test_thread();
        let result = get_current_directory_pre(&ctx("get_CurrentDirectory", &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert!(!s.is_empty());
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_tick_count64() {
        let mut thread = create_test_thread();
        let result = get_tick_count64_pre(&ctx("get_TickCount64", &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I64(_)))
        ));
    }

    #[test]
    fn test_exit() {
        let mut thread = create_test_thread();
        let result = exit_pre(&ctx("Exit", &[EmValue::I32(0)]), &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));
    }

    #[test]
    fn test_get_stack_trace() {
        let mut thread = create_test_thread();
        let result = get_stack_trace_pre(&ctx("get_StackTrace", &[]), &mut thread);
        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(r))) = result {
            let s = thread.heap().get_string(r).unwrap();
            assert_eq!(s.as_ref(), "");
        } else {
            panic!("Expected ObjectRef");
        }
    }

    #[test]
    fn test_get_os_version() {
        let mut thread = create_test_thread();
        let result = get_os_version_pre(&ctx("get_OSVersion", &[]), &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::ObjectRef(_)))
        ));
    }

    #[test]
    fn test_get_environment_variable_missing() {
        let mut thread = create_test_thread();
        let var_ref = thread.heap_mut().alloc_string("NONEXISTENT").unwrap();
        let args = [EmValue::ObjectRef(var_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Environment",
            "GetEnvironmentVariable",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = get_environment_variable_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(Some(EmValue::Null))));
    }
}
