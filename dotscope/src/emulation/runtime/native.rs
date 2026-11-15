//! Native/P/Invoke hook support for Windows API emulation.
//!
//! This module provides hooks for emulating Platform Invocation Services (P/Invoke)
//! calls to native Windows DLLs. P/Invoke is the .NET mechanism for calling unmanaged code,
//! and is commonly used by obfuscators and packers for:
//!
//! - Memory manipulation (`VirtualProtect`, `VirtualAlloc`)
//! - Anti-debugging checks (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`)
//! - Dynamic code loading (`LoadLibrary`, `GetProcAddress`)
//! - Process/thread introspection (`GetCurrentProcess`, `GetCurrentThread`)
//!
//! # Overview
//!
//! Native hooks are registered with the [`HookManager`](super::HookManager) using the
//! [`register`] function. They use the [`NativeMethodMatcher`](super::NativeMethodMatcher)
//! to match P/Invoke calls by DLL name and function name.
//!
//! # Default Hooks
//!
//! The following native hooks are registered by default via [`register`]:
//!
//! ## Memory Management (kernel32.dll)
//! - `VirtualProtect` - Changes memory page protection (returns success, tracks protection)
//! - `VirtualAlloc` - Allocates virtual memory from the address space
//! - `VirtualFree` - Frees virtual memory (validates but doesn't actually free)
//!
//! ## Module Loading (kernel32.dll)
//! - `GetModuleHandleA/W` - Returns fake module handle (see [`tokens::native_addresses`])
//! - `GetProcAddress` - Returns fake function pointer
//! - `LoadLibraryA/W` - Returns fake module handle
//!
//! ## Anti-Debug Bypass (kernel32.dll)
//! - `IsDebuggerPresent` - Always returns FALSE (no debugger)
//! - `CheckRemoteDebuggerPresent` - Writes FALSE to output, returns success
//!
//! ## Process/Thread Handles (kernel32.dll)
//! - `GetCurrentProcess` - Returns pseudo-handle (-1)
//! - `GetCurrentThread` - Returns pseudo-handle (-2)
//!
//! # Examples
//!
//! ## Using Native Hooks
//!
//! The `examples::module_example` test in this module runs this example.
//!
//! ## Adding Custom Native Hooks
//!
//! ```
//! use dotscope::emulation::{EmValue, Hook, HookManager, PreHookResult};
//!
//! let manager = HookManager::new();
//!
//! manager.register(
//!     Hook::new("custom-get-tick-count")
//!         .match_native("kernel32", "GetTickCount")
//!         .pre(|_ctx, _thread| {
//!             // Return a fixed tick count for deterministic emulation
//!             PreHookResult::Bypass(Some(EmValue::I32(12345678)))
//!         })
//! )?;
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Use Cases
//!
//! ## Deobfuscation
//!
//! Many obfuscators use P/Invoke calls for:
//!
//! - **Anti-tamper**: `VirtualProtect` to modify code section permissions
//! - **Anti-debug**: `IsDebuggerPresent` to detect analysis
//! - **Dynamic unpacking**: `VirtualAlloc` to allocate memory for decrypted code
//!
//! The default hooks are designed to allow these operations to succeed while
//! bypassing protection checks.
//!
//! ## ConfuserEx Anti-Tamper
//!
//! The `VirtualProtect` hook specifically returns 0x20 (PAGE_EXECUTE_READ) as the
//! old protection value. This is important because ConfuserEx's anti-tamper checks
//! if the old protection was 0x40 (PAGE_EXECUTE_READWRITE) and skips decryption
//! if so. By returning 0x20, the decryption path is taken.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use dashmap::DashMap;

use crate::{
    emulation::{
        memory::MemoryProtection,
        runtime::{
            hook::{HookContext, PreHookResult},
            Hook, HookManager, HookPriority,
        },
        thread::EmulationThread,
        tokens::{self, native_addresses},
        EmValue,
    },
    metadata::token::Token,
    Result,
};

/// A native function resolved at runtime, and the module it came from.
///
/// The module matters because hooks are registered against a `(dll, function)`
/// pair. A function resolved through `GetProcAddress` only reaches its hook if
/// the library that produced the handle is known, so the name is carried
/// alongside the function rather than reconstructed later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeFunction {
    /// Owning module, as passed to `LoadLibrary` (e.g. `"kernel32.dll"`).
    ///
    /// `None` when the handle did not come from an observed `LoadLibrary` — the
    /// function is still dispatchable, but only against hooks that do not
    /// constrain the module.
    pub dll: Option<Arc<str>>,
    /// Exported function name, as passed to `GetProcAddress`.
    pub name: Arc<str>,
}

/// Shared registry that maps fake function pointer addresses to their names
/// and native function tokens to their names. This allows the full chain
/// (`LoadLibrary` → `GetProcAddress` → `GetDelegateForFunctionPointer` →
/// delegate dispatch) to preserve function identity.
#[derive(Clone, Debug)]
pub struct NativeFunctionRegistry {
    address_to_name: Arc<DashMap<u64, NativeFunction>>,
    token_to_name: Arc<DashMap<u32, NativeFunction>>,
    module_handles: Arc<DashMap<u64, Arc<str>>>,
    next_address: Arc<AtomicU64>,
    next_token_id: Arc<AtomicU64>,
    next_module: Arc<AtomicU64>,
}

impl NativeFunctionRegistry {
    pub fn new() -> Self {
        Self {
            address_to_name: Arc::new(DashMap::new()),
            token_to_name: Arc::new(DashMap::new()),
            module_handles: Arc::new(DashMap::new()),
            next_address: Arc::new(AtomicU64::new(native_addresses::PROC_ADDRESS_BASE)),
            next_token_id: Arc::new(AtomicU64::new(1)),
            next_module: Arc::new(AtomicU64::new(
                native_addresses::LOADED_LIBRARY.cast_unsigned(),
            )),
        }
    }

    /// Registers a loaded module and returns the handle standing in for it.
    ///
    /// Handles are distinct per module so a later `GetProcAddress` can name the
    /// library its function came from. Loading the same module twice returns the
    /// same handle, as the real loader does.
    pub fn register_module(&self, name: &str) -> u64 {
        let name: Arc<str> = Arc::from(name);
        for entry in self.module_handles.iter() {
            if *entry.value() == name {
                return *entry.key();
            }
        }
        let handle = self
            .next_module
            .fetch_add(native_addresses::PROC_ADDRESS_PAGE, Ordering::Relaxed);
        self.module_handles.insert(handle, name);
        handle
    }

    /// Looks up the module registered for a handle.
    pub fn lookup_module(&self, handle: u64) -> Option<Arc<str>> {
        self.module_handles
            .get(&handle)
            .map(|v| Arc::clone(v.value()))
    }

    /// Registers a native function and returns a unique fake address for it.
    pub fn register_proc(&self, dll: Option<&str>, name: &str) -> u64 {
        let function = NativeFunction {
            dll: dll.map(Arc::from),
            name: Arc::from(name),
        };
        // Check if already registered
        for entry in self.address_to_name.iter() {
            if *entry.value() == function {
                return *entry.key();
            }
        }
        let addr = self
            .next_address
            .fetch_add(native_addresses::PROC_ADDRESS_PAGE, Ordering::Relaxed);
        self.address_to_name.insert(addr, function);
        addr
    }

    /// Looks up the function registered at a given fake address.
    pub fn lookup_by_address(&self, addr: u64) -> Option<NativeFunction> {
        self.address_to_name.get(&addr).map(|v| v.value().clone())
    }

    /// Allocates a unique native function pointer token for a function and
    /// returns the token. If a token was already allocated for it, returns
    /// the existing one.
    pub fn allocate_token(&self, function: &NativeFunction) -> Token {
        for entry in self.token_to_name.iter() {
            if entry.value() == function {
                return tokens::native::token_for_id(*entry.key());
            }
        }
        let id = self.next_token_id.fetch_add(1, Ordering::Relaxed);
        self.token_to_name.insert(id as u32, function.clone());
        tokens::native::token_for_id(id as u32)
    }

    /// Finds the fake address registered for the given function name.
    pub fn lookup_address_by_name(&self, name: &str) -> Option<u64> {
        for entry in self.address_to_name.iter() {
            if entry.value().name.as_ref() == name {
                return Some(*entry.key());
            }
        }
        None
    }

    /// Looks up the function for a native function pointer token.
    pub fn lookup_by_token(&self, token: Token) -> Option<NativeFunction> {
        let id = token.value() & 0x0000_FFFF;
        self.token_to_name.get(&id).map(|v| v.value().clone())
    }
}

/// Registers all default native P/Invoke hooks with the hook manager.
///
/// This function registers hooks for common Windows API functions used by
/// obfuscators and packers. Call this to enable P/Invoke emulation.
///
/// # Arguments
///
/// * `manager` - The hook manager to register hooks with
///
/// # Registered Hooks
///
/// **Memory Management:**
/// - `kernel32!VirtualProtect`
/// - `kernel32!VirtualAlloc`
/// - `kernel32!VirtualFree`
///
/// **Module Loading:**
/// - `kernel32!GetModuleHandleA`
/// - `kernel32!GetModuleHandleW`
/// - `kernel32!GetProcAddress`
/// - `kernel32!LoadLibraryA`
/// - `kernel32!LoadLibraryW`
///
/// **Anti-Debug Bypass:**
/// - `kernel32!IsDebuggerPresent`
/// - `kernel32!CheckRemoteDebuggerPresent`
///
/// **Process/Thread Handles:**
/// - `kernel32!GetCurrentProcess`
/// - `kernel32!GetCurrentThread`
pub fn register(manager: &HookManager, registry: &NativeFunctionRegistry) -> Result<()> {
    // Memory management hooks
    register_virtual_protect(manager)?;
    register_virtual_alloc(manager)?;
    register_virtual_free(manager)?;

    // Module loading hooks
    register_get_module_handle(manager)?;
    register_get_proc_address(manager, registry)?;
    register_load_library(manager, registry)?;

    // Anti-debug bypass hooks
    register_is_debugger_present(manager)?;
    register_check_remote_debugger_present(manager)?;

    // Process/thread handle hooks
    register_get_current_process(manager)?;
    register_get_current_thread(manager)?;

    Ok(())
}

/// Registers the VirtualProtect hook.
fn register_virtual_protect(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-virtual-protect")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualProtect")
            .pre(|ctx, thread| {
                // VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate we have enough arguments
                if args.len() < 4 {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Validate lpAddress is not null
                let lp_address = match args.first() {
                    Some(EmValue::UnmanagedPtr(addr)) if *addr != 0 => *addr,
                    Some(EmValue::NativeInt(addr)) if *addr > 0 => (*addr).cast_unsigned(),
                    Some(EmValue::NativeUInt(addr)) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Validate dwSize is non-zero
                #[allow(clippy::cast_possible_truncation)]
                let dw_size = match args.get(1) {
                    Some(EmValue::I32(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeInt(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeUInt(size)) if *size > 0 => *size as usize,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Get the new protection value
                #[allow(clippy::cast_possible_truncation)]
                let fl_new_protect = match args.get(2) {
                    Some(EmValue::I32(p)) => (*p).cast_unsigned(),
                    Some(EmValue::NativeInt(p)) => (*p).cast_unsigned() as u32,
                    Some(EmValue::NativeUInt(p)) => *p as u32,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Check if address range is valid
                let space = thread.address_space();
                let last_addr = match (dw_size as u64)
                    .checked_sub(1)
                    .and_then(|s| lp_address.checked_add(s))
                {
                    Some(v) => v,
                    None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };
                if !space.is_valid(lp_address) || !space.is_valid(last_addr) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Convert new protection to our format and set it, getting old protection back
                let new_protection = MemoryProtection::from_windows(fl_new_protect);
                let old_protection = space
                    .set_protection(lp_address, dw_size, new_protection)
                    .unwrap_or(MemoryProtection::READ_EXECUTE);

                // Convert old protection back to Windows constant
                let old_protect_windows = old_protection.to_windows();

                // Write old protection value to the out parameter
                let old_protect_value = EmValue::I32(old_protect_windows.cast_signed());
                match args.get(3) {
                    None => {
                        // missing arg - treat as null pointer (allowed)
                    }
                    Some(EmValue::ManagedPtr(ptr))
                        if thread
                            .store_through_pointer(ptr, old_protect_value)
                            .is_err() =>
                    {
                        return PreHookResult::Bypass(Some(EmValue::I32(0)));
                    }
                    Some(EmValue::UnmanagedPtr(addr)) if *addr != 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write(*addr, &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    Some(EmValue::NativeInt(addr)) if *addr > 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write((*addr).cast_unsigned(), &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    Some(EmValue::NativeUInt(addr)) if *addr > 0 => {
                        let old_protect_bytes = old_protect_windows.to_le_bytes();
                        if thread
                            .address_space()
                            .write(*addr, &old_protect_bytes)
                            .is_err()
                        {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                    _ => {
                        // lpflOldProtect is null - technically allowed but unusual
                    }
                }

                // VirtualProtect returns BOOL (int32), 1 = success
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    )?;

    Ok(())
}

/// Registers the VirtualAlloc hook.
fn register_virtual_alloc(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-virtual-alloc")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualAlloc")
            .pre(|ctx, thread| {
                // VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)
                // Returns pointer to allocated memory, or NULL on failure
                let args = ctx.args;

                // Extract and validate dwSize
                #[allow(clippy::cast_possible_truncation)]
                let size = match args.get(1) {
                    Some(EmValue::I32(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeInt(size)) if *size > 0 => (*size).cast_unsigned() as usize,
                    Some(EmValue::NativeUInt(size)) if *size > 0 => *size as usize,
                    _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                };

                // Validate flAllocationType (arg 2) - must be non-zero
                #[allow(clippy::cast_possible_truncation)]
                let alloc_type = match args.get(2) {
                    Some(EmValue::I32(t)) if *t != 0 => (*t).cast_unsigned(),
                    Some(EmValue::NativeInt(t)) if *t != 0 => (*t).cast_unsigned() as u32,
                    _ => return PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                };

                // MEM_COMMIT = 0x1000, MEM_RESERVE = 0x2000
                // At least one of these must be set
                if (alloc_type & 0x3000) == 0 {
                    return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
                }

                // Allocate from address space
                match thread.address_space().alloc_unmanaged(size) {
                    Ok(addr) => PreHookResult::Bypass(Some(EmValue::NativeInt(addr.cast_signed()))),
                    Err(_) => PreHookResult::Bypass(Some(EmValue::NativeInt(0))),
                }
            }),
    )?;

    Ok(())
}

/// Registers the VirtualFree hook.
fn register_virtual_free(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-virtual-free")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "VirtualFree")
            .pre(|ctx, thread| {
                // VirtualFree(lpAddress, dwSize, dwFreeType)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate lpAddress is not null
                let lp_address = match args.first() {
                    Some(EmValue::UnmanagedPtr(addr)) if *addr != 0 => *addr,
                    Some(EmValue::NativeInt(addr)) if *addr > 0 => (*addr).cast_unsigned(),
                    Some(EmValue::NativeUInt(addr)) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Validate dwFreeType (arg 2) if provided
                // MEM_DECOMMIT = 0x4000, MEM_RELEASE = 0x8000
                if let Some(free_type) = args.get(2) {
                    #[allow(clippy::cast_possible_truncation)]
                    let ft = match free_type {
                        EmValue::I32(t) => (*t).cast_unsigned(),
                        EmValue::NativeInt(t) => (*t).cast_unsigned() as u32,
                        _ => 0,
                    };

                    // If MEM_RELEASE (0x8000), dwSize must be 0
                    if (ft & 0x8000) != 0 {
                        #[allow(clippy::cast_possible_truncation)]
                        let dw_size = args
                            .get(1)
                            .and_then(|v| match v {
                                EmValue::I32(s) => Some((*s).cast_unsigned()),
                                EmValue::NativeInt(s) => Some((*s).cast_unsigned() as u32),
                                _ => None,
                            })
                            .unwrap_or(0);

                        if dw_size != 0 {
                            return PreHookResult::Bypass(Some(EmValue::I32(0)));
                        }
                    }
                }

                // Check if address is valid
                if !thread.address_space().is_valid(lp_address) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Return success (we don't actually free memory)
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    )?;

    Ok(())
}

/// Registers GetModuleHandle hooks (both A and W variants).
fn register_get_module_handle(manager: &HookManager) -> Result<()> {
    // GetModuleHandleA
    manager.register(
        Hook::new("native-get-module-handle-a")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetModuleHandleA")
            .pre(|ctx, _thread| {
                // GetModuleHandle(lpModuleName)
                // If NULL, return base of current module
                let is_null = ctx.args.first().is_none_or(|v| {
                    v.is_null()
                        || matches!(v, EmValue::NativeInt(0))
                        || matches!(v, EmValue::NativeUInt(0))
                        || matches!(v, EmValue::UnmanagedPtr(0))
                });

                if is_null {
                    // Return a fake module base for the current module
                    PreHookResult::Bypass(Some(EmValue::NativeInt(
                        native_addresses::CURRENT_MODULE,
                    )))
                } else {
                    // Return a fake handle for other modules
                    PreHookResult::Bypass(Some(EmValue::NativeInt(native_addresses::OTHER_MODULE)))
                }
            }),
    )?;

    // GetModuleHandleW
    manager.register(
        Hook::new("native-get-module-handle-w")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetModuleHandleW")
            .pre(|ctx, _thread| {
                let is_null = ctx.args.first().is_none_or(|v| {
                    v.is_null()
                        || matches!(v, EmValue::NativeInt(0))
                        || matches!(v, EmValue::NativeUInt(0))
                        || matches!(v, EmValue::UnmanagedPtr(0))
                });

                if is_null {
                    PreHookResult::Bypass(Some(EmValue::NativeInt(
                        native_addresses::CURRENT_MODULE,
                    )))
                } else {
                    PreHookResult::Bypass(Some(EmValue::NativeInt(native_addresses::OTHER_MODULE)))
                }
            }),
    )?;

    Ok(())
}

/// Registers the GetProcAddress hook.
///
/// Extracts the function name from the second argument (lpProcName) and
/// registers it in the native function registry with a unique fake address.
/// This preserves function identity through the GetDelegateForFunctionPointer
/// and delegate dispatch chain.
fn register_get_proc_address(
    manager: &HookManager,
    registry: &NativeFunctionRegistry,
) -> Result<()> {
    let registry = registry.clone();
    manager.register(
        Hook::new("native-get-proc-address")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetProcAddress")
            .pre(move |ctx, thread| {
                // GetProcAddress(hModule, lpProcName)
                let func_name = ctx.args.get(1).and_then(|arg| match arg {
                    EmValue::ObjectRef(href) => {
                        thread.heap().get_string(*href).ok().map(|s| s.to_string())
                    }
                    _ => None,
                });

                // An unreadable name cannot be told apart from any other
                // unreadable name. Registering them all under one label would
                // collapse them onto a single address and dispatch the wrong
                // function; leave the resolution to fail instead.
                let Some(func_name) = func_name else {
                    log::debug!("GetProcAddress: could not read the requested name");
                    return PreHookResult::Bypass(Some(EmValue::NativeInt(0)));
                };

                let dll = ctx
                    .args
                    .first()
                    .and_then(|arg| match arg {
                        EmValue::NativeInt(v) => Some((*v).cast_unsigned()),
                        EmValue::NativeUInt(v) => Some(*v),
                        EmValue::UnmanagedPtr(v) => Some(*v),
                        _ => None,
                    })
                    .and_then(|handle| registry.lookup_module(handle));

                let addr = registry.register_proc(dll.as_deref(), &func_name);
                log::debug!(
                    "GetProcAddress({}!{func_name}) → 0x{addr:X}",
                    dll.as_deref().unwrap_or("?")
                );
                PreHookResult::Bypass(Some(EmValue::NativeInt(addr as i64)))
            }),
    )?;

    Ok(())
}

/// Registers LoadLibrary hooks (A, W, and unsuffixed variants).
///
/// Some obfuscators (e.g., .NET Reactor) use the unsuffixed `LoadLibrary`
/// import name in their P/Invoke declarations, which doesn't match the
/// standard `LoadLibraryA`/`LoadLibraryW` exports.
fn register_load_library(manager: &HookManager, registry: &NativeFunctionRegistry) -> Result<()> {
    // Each library gets its own handle so a later `GetProcAddress` can name the
    // module its function came from — which is what lets the resolved function
    // reach a hook registered against a `(dll, function)` pair.
    let make_handler = |registry: NativeFunctionRegistry| {
        move |ctx: &HookContext<'_>, thread: &mut EmulationThread| -> PreHookResult {
            let module = ctx.args.first().and_then(|arg| match arg {
                EmValue::ObjectRef(href) => {
                    thread.heap().get_string(*href).ok().map(|s| s.to_string())
                }
                _ => None,
            });
            let Some(module) = module else {
                return PreHookResult::Bypass(Some(EmValue::NativeInt(
                    native_addresses::LOADED_LIBRARY,
                )));
            };
            let handle = registry.register_module(&module);
            log::debug!("LoadLibrary({module}) → 0x{handle:X}");
            PreHookResult::Bypass(Some(EmValue::NativeInt(handle as i64)))
        }
    };

    manager.register(
        Hook::new("native-load-library-a")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "LoadLibraryA")
            .pre(make_handler(registry.clone())),
    )?;

    manager.register(
        Hook::new("native-load-library-w")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "LoadLibraryW")
            .pre(make_handler(registry.clone())),
    )?;

    manager.register(
        Hook::new("native-load-library")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "LoadLibrary")
            .pre(make_handler(registry.clone())),
    )?;

    Ok(())
}

/// Registers the IsDebuggerPresent hook.
fn register_is_debugger_present(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-is-debugger-present")
            .with_priority(HookPriority::HIGHEST) // Anti-debug bypass should have highest priority
            .match_native("kernel32", "IsDebuggerPresent")
            .pre(|_ctx, _thread| {
                // IsDebuggerPresent() returns BOOL
                // Return FALSE to indicate no debugger
                PreHookResult::Bypass(Some(EmValue::I32(0)))
            }),
    )?;

    Ok(())
}

/// Registers the CheckRemoteDebuggerPresent hook.
fn register_check_remote_debugger_present(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-check-remote-debugger-present")
            .with_priority(HookPriority::HIGHEST)
            .match_native("kernel32", "CheckRemoteDebuggerPresent")
            .pre(|ctx, thread| {
                // CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent)
                // Returns BOOL: 1 = success, 0 = failure
                let args = ctx.args;

                // Validate hProcess is a valid handle (-1 for current process, or non-null)
                match args.first() {
                    Some(EmValue::NativeInt(-1)) => {} // Current process pseudo-handle is valid
                    Some(EmValue::NativeInt(h)) if *h > 0 => {}
                    Some(EmValue::NativeUInt(h)) if *h > 0 => {}
                    Some(EmValue::UnmanagedPtr(h)) if *h > 0 => {}
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                }

                // Get output pointer address - must be valid
                let output_addr = match args.get(1) {
                    Some(EmValue::UnmanagedPtr(addr)) if *addr != 0 => *addr,
                    Some(EmValue::NativeInt(addr)) if *addr > 0 => (*addr).cast_unsigned(),
                    Some(EmValue::NativeUInt(addr)) if *addr > 0 => *addr,
                    _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
                };

                // Write FALSE (0) to the output parameter
                let false_bytes = 0u32.to_le_bytes();

                let space = thread.address_space();
                if !space.is_valid(output_addr) {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                if space.write(output_addr, &false_bytes).is_err() {
                    return PreHookResult::Bypass(Some(EmValue::I32(0)));
                }

                // Return TRUE for success
                PreHookResult::Bypass(Some(EmValue::I32(1)))
            }),
    )?;

    Ok(())
}

/// Registers the GetCurrentProcess hook.
fn register_get_current_process(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-get-current-process")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetCurrentProcess")
            .pre(|_ctx, _thread| {
                // GetCurrentProcess() returns HANDLE
                // Return pseudo-handle -1 (0xFFFFFFFFFFFFFFFF)
                PreHookResult::Bypass(Some(EmValue::NativeInt(-1)))
            }),
    )?;

    Ok(())
}

/// Registers the GetCurrentThread hook.
fn register_get_current_thread(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("native-get-current-thread")
            .with_priority(HookPriority::HIGH)
            .match_native("kernel32", "GetCurrentThread")
            .pre(|_ctx, _thread| {
                // GetCurrentThread() returns HANDLE
                // Return pseudo-handle -2 (0xFFFFFFFFFFFFFFFE)
                PreHookResult::Bypass(Some(EmValue::NativeInt(-2)))
            }),
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{register, NativeFunctionRegistry};
    use crate::{
        emulation::{
            runtime::{HookContext, HookManager, HookOutcome},
            tokens::native_addresses,
            EmValue,
        },
        metadata::{token::Token, typesystem::PointerSize},
        testkit::emulation::create_test_thread,
    };

    fn create_native_context<'a>(dll: &'a str, function: &'a str) -> HookContext<'a> {
        HookContext::native(Token::new(0x06000001), dll, function, PointerSize::Bit64)
    }

    #[test]
    fn test_native_hooks_registered() {
        let manager = HookManager::new();
        register(&manager, &NativeFunctionRegistry::new()).unwrap();

        // Should have at least 12 hooks (one for each function, with A/W variants)
        assert!(manager.len() >= 12);
    }

    /// A function resolved through `GetProcAddress` only reaches its hook if the
    /// module that produced the handle is known, because hooks are registered
    /// against a `(dll, function)` pair.
    #[test]
    fn resolved_function_remembers_its_module() {
        let registry = NativeFunctionRegistry::new();

        let handle = registry.register_module("kernel32.dll");
        assert_eq!(
            registry.lookup_module(handle).as_deref(),
            Some("kernel32.dll")
        );

        let dll = registry.lookup_module(handle);
        let addr = registry.register_proc(dll.as_deref(), "VirtualProtect");

        let resolved = registry
            .lookup_by_address(addr)
            .expect("the address just registered must resolve");
        assert_eq!(resolved.name.as_ref(), "VirtualProtect");
        assert_eq!(resolved.dll.as_deref(), Some("kernel32.dll"));

        // The token carried through GetDelegateForFunctionPointer must round-trip
        // to the same pair, which is what the delegate dispatch matches on.
        let token = registry.allocate_token(&resolved);
        assert_eq!(registry.lookup_by_token(token), Some(resolved));
    }

    /// Loading the same module twice yields one handle, as the real loader does;
    /// distinct modules must not collide, or a function would be attributed to
    /// whichever library was loaded last.
    #[test]
    fn module_handles_are_stable_and_distinct() {
        let registry = NativeFunctionRegistry::new();

        let kernel32 = registry.register_module("kernel32.dll");
        let user32 = registry.register_module("user32.dll");

        assert_eq!(registry.register_module("kernel32.dll"), kernel32);
        assert_ne!(kernel32, user32);
        assert_eq!(
            registry.lookup_module(user32).as_deref(),
            Some("user32.dll")
        );
    }

    /// The same exported name in two libraries is two different functions, and
    /// must not share one fake address.
    #[test]
    fn same_name_in_two_modules_stays_distinct() {
        let registry = NativeFunctionRegistry::new();

        let a = registry.register_proc(Some("kernel32.dll"), "Sleep");
        let b = registry.register_proc(Some("winmm.dll"), "Sleep");

        assert_ne!(a, b);
        assert_eq!(
            registry.lookup_by_address(a).and_then(|f| f.dll),
            Some("kernel32.dll".into())
        );
    }

    #[test]
    fn test_is_debugger_present_hook() {
        let manager = HookManager::new();
        register(&manager, &NativeFunctionRegistry::new()).unwrap();

        let mut thread = create_test_thread();
        let context = create_native_context("kernel32", "IsDebuggerPresent").with_args(&[]);

        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();
        assert!(
            matches!(outcome, HookOutcome::Handled(Some(EmValue::I32(0)))),
            "IsDebuggerPresent should return 0"
        );
    }

    #[test]
    fn test_get_current_process_hook() {
        let manager = HookManager::new();
        register(&manager, &NativeFunctionRegistry::new()).unwrap();

        let mut thread = create_test_thread();
        let context = create_native_context("kernel32", "GetCurrentProcess").with_args(&[]);

        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();
        assert!(
            matches!(outcome, HookOutcome::Handled(Some(EmValue::NativeInt(-1)))),
            "GetCurrentProcess should return -1"
        );
    }

    #[test]
    fn test_get_module_handle_null() {
        let manager = HookManager::new();
        register(&manager, &NativeFunctionRegistry::new()).unwrap();

        let mut thread = create_test_thread();
        let args = [EmValue::NativeInt(0)];
        let context = create_native_context("kernel32", "GetModuleHandleA").with_args(&args);

        let outcome = manager.execute(&context, &mut thread, |_| None).unwrap();
        assert!(
            matches!(
                outcome,
                HookOutcome::Handled(Some(EmValue::NativeInt(native_addresses::CURRENT_MODULE)))
            ),
            "GetModuleHandleA(null) should return base address"
        );
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{emulation::HookManager, Result};

    /// Registering the native hooks fills the hook manager.
    #[test]
    fn module_example() -> Result<()> {
        let manager = HookManager::new();
        let registry = NativeFunctionRegistry::new();
        register(&manager, &registry)?;

        // VirtualProtect, IsDebuggerPresent, etc. are now hooked
        assert!(!manager.is_empty());
        Ok(())
    }
}
