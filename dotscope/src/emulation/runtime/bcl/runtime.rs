//! `System.Runtime.CompilerServices.RuntimeHelpers` and `System.Object` method hooks.
//!
//! This module provides hook implementations for `RuntimeHelpers` and `Object` methods
//! commonly used by obfuscators for array initialization, hash code computation,
//! equality checks, and runtime support operations.
//!
//! # Overview
//!
//! `RuntimeHelpers` provides low-level runtime support methods. The most important
//! for deobfuscation is `InitializeArray`, which is used by the C# compiler to
//! efficiently initialize arrays from embedded data.
//!
//! # Emulated .NET Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `InitializeArray(Array, RuntimeFieldHandle)` | Copies FieldRVA data to array |
//! | `GetHashCode(object)` | Returns identity hash code |
//! | `Equals(object, object)` | Reference equality check |
//! | `GetObjectValue(object)` | Returns object (boxes value types) |
//! | `RunClassConstructor(RuntimeTypeHandle)` | Runs static constructor (no-op) |
//! | `RunModuleConstructor(ModuleHandle)` | Runs module constructor (no-op) |
//! | `Object.Equals(object)` | Instance reference/value equality |
//! | `Object.Equals(object, object)` | Static reference/value equality |
//! | `Object.MemberwiseClone()` | Shallow clone heap object |
//! | `ValueType.Equals(object)` | Field-by-field value type equality |
//! | `GC.Collect()` | No-op (GC not emulated) |
//! | `GC.SuppressFinalize(object)` | No-op (GC not emulated) |
//! | `GC.KeepAlive(object)` | No-op (GC not emulated) |
//! | `GC.WaitForPendingFinalizers()` | No-op (GC not emulated) |
//!
//! # Deobfuscation Use Cases
//!
//! ## Static Array Initialization
//!
//! The C# compiler uses `InitializeArray` for static array literals:
//!
//! ```csharp
//! // This C# code:
//! static byte[] data = { 0x01, 0x02, 0x03 };
//!
//! // Compiles to IL like:
//! // ldsfld byte[] ::data
//! // ldtoken RuntimeFieldHandle (points to embedded data)
//! // call RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle)
//! ```
//!
//! The hook reads the actual embedded data from the PE file's FieldRVA table.
//!
//! ## ConfuserEx String Encryption
//!
//! ConfuserEx stores encrypted string data in static arrays initialized via
//! `InitializeArray`. This hook extracts the encrypted data for analysis.
//!
//! # Implementation Notes
//!
//! - `InitializeArray` reads from the actual PE file via `thread.assembly()`
//! - Hash codes are based on heap reference IDs for consistency
//! - Constructor runners are no-ops (we don't track static initialization)

use crate::{
    emulation::{
        memory::HeapObject,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::{
        tables::FieldRvaRaw,
        typesystem::{CilFlavor, PointerSize},
    },
    Result,
};

/// Registers all `RuntimeHelpers` method hooks with the given hook manager.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - `RuntimeHelpers.InitializeArray` - Copy FieldRVA data to array
/// - `RuntimeHelpers.GetHashCode` - Identity hash code
/// - `RuntimeHelpers.Equals` - Reference equality
/// - `RuntimeHelpers.GetObjectValue` - Return object (box value types)
/// - `RuntimeHelpers.RunClassConstructor` - No-op
/// - `RuntimeHelpers.RunModuleConstructor` - No-op
/// - `Object.Equals` - Reference/value equality (instance and static)
/// - `Object.MemberwiseClone` - Shallow clone heap object
/// - `ValueType.Equals` - Field-by-field value type equality
/// - `GC.Collect` - No-op
/// - `GC.SuppressFinalize` - No-op
/// - `GC.KeepAlive` - No-op
/// - `GC.WaitForPendingFinalizers` - No-op
pub fn register(manager: &HookManager) -> Result<()> {
    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "InitializeArray",
            )
            .pre(runtime_helpers_initialize_array_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "GetHashCode",
            )
            .pre(runtime_helpers_get_hash_code_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.Equals")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "Equals",
            )
            .pre(runtime_helpers_equals_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.GetObjectValue")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "GetObjectValue",
            )
            .pre(runtime_helpers_get_object_value_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "RunClassConstructor",
            )
            .pre(runtime_helpers_run_class_constructor_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.RunModuleConstructor")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "RunModuleConstructor",
            )
            .pre(runtime_helpers_run_module_constructor_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.PrepareDelegate")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "PrepareDelegate",
            )
            .pre(runtime_helpers_prepare_noop_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.RuntimeHelpers.PrepareMethod")
            .match_name(
                "System.Runtime.CompilerServices",
                "RuntimeHelpers",
                "PrepareMethod",
            )
            .pre(runtime_helpers_prepare_noop_pre),
    )?;

    // System.Object.Equals - handles both instance and static overloads.
    // Critical for ConfuserEx anti-tamper: Assembly.GetExecutingAssembly().Equals(...)
    manager.register(
        Hook::new("System.Object.Equals")
            .match_name("System", "Object", "Equals")
            .pre(object_equals_pre),
    )?;

    // System.Object..ctor() - base constructor, no-op.
    // Every .NET type's constructor calls base Object::.ctor() which has no side effects.
    manager.register(
        Hook::new("System.Object..ctor")
            .match_name("System", "Object", ".ctor")
            .pre(object_ctor_pre),
    )?;

    // System.Object.ToString() — type-aware string conversion
    manager.register(
        Hook::new("System.Object.ToString")
            .match_name("System", "Object", "ToString")
            .pre(object_to_string_pre),
    )?;

    // System.Object.GetHashCode() — identity-based hash code
    manager.register(
        Hook::new("System.Object.GetHashCode")
            .match_name("System", "Object", "GetHashCode")
            .pre(object_get_hash_code_pre),
    )?;

    // System.Object.MemberwiseClone() — shallow clone
    manager.register(
        Hook::new("System.Object.MemberwiseClone")
            .match_name("System", "Object", "MemberwiseClone")
            .pre(object_memberwise_clone_pre),
    )?;

    // System.ValueType.Equals(object) — value type field-by-field equality
    manager.register(
        Hook::new("System.ValueType.Equals")
            .match_name("System", "ValueType", "Equals")
            .pre(valuetype_equals_pre),
    )?;

    // GC stubs — no-op in the emulator
    manager.register(
        Hook::new("System.GC.Collect")
            .match_name("System", "GC", "Collect")
            .pre(gc_noop_pre),
    )?;
    manager.register(
        Hook::new("System.GC.SuppressFinalize")
            .match_name("System", "GC", "SuppressFinalize")
            .pre(gc_noop_pre),
    )?;
    manager.register(
        Hook::new("System.GC.KeepAlive")
            .match_name("System", "GC", "KeepAlive")
            .pre(gc_noop_pre),
    )?;
    manager.register(
        Hook::new("System.GC.WaitForPendingFinalizers")
            .match_name("System", "GC", "WaitForPendingFinalizers")
            .pre(gc_noop_pre),
    )?;
    manager.register(
        Hook::new("System.GC.get_MaxGeneration")
            .match_name("System", "GC", "get_MaxGeneration")
            .pre(gc_get_max_generation_pre),
    )?;

    // System.Runtime.CompilerServices.Unsafe stubs
    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.As")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "As")
            .pre(unsafe_as_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.SizeOf")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "SizeOf")
            .pre(unsafe_sizeof_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.Add")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "Add")
            .pre(unsafe_passthrough_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.AddByteOffset")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "AddByteOffset")
            .pre(unsafe_passthrough_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.ReadUnaligned")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "ReadUnaligned")
            .pre(unsafe_read_unaligned_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.WriteUnaligned")
            .match_name(
                "System.Runtime.CompilerServices",
                "Unsafe",
                "WriteUnaligned",
            )
            .pre(unsafe_write_noop_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.AsRef")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "AsRef")
            .pre(unsafe_as_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.AsPointer")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "AsPointer")
            .pre(unsafe_passthrough_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.ByteOffset")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "ByteOffset")
            .pre(unsafe_byte_offset_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.AreSame")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "AreSame")
            .pre(unsafe_are_same_pre),
    )?;

    manager.register(
        Hook::new("System.Runtime.CompilerServices.Unsafe.IsNullRef")
            .match_name("System.Runtime.CompilerServices", "Unsafe", "IsNullRef")
            .pre(unsafe_is_null_ref_pre),
    )?;

    Ok(())
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray` method.
///
/// Provides a fast way to initialize an array from data stored in a module.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle) -> void`
///
/// # Parameters
///
/// - `array`: The array to be initialized
/// - `fldHandle`: A field handle that specifies the location of the data for the array
fn runtime_helpers_initialize_array_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    // RuntimeHelpers.InitializeArray(Array array, RuntimeFieldHandle fldHandle)
    // args[0] = array (ObjectRef)
    // args[1] = field handle (NativeInt/I32 containing token value)

    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    // Get the array reference
    let array_ref = match arg0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    // Get the field token from the RuntimeFieldHandle
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let field_token = match arg1 {
        EmValue::I32(v) => (*v).cast_unsigned(),
        EmValue::NativeInt(v) | EmValue::I64(v) => *v as u32,
        _ => return PreHookResult::Bypass(None),
    };

    // Need assembly access to read FieldRVA data
    let Some(assembly) = thread.assembly() else {
        return PreHookResult::Bypass(None);
    };

    // Look up the RVA for this field token in the FieldRVA table
    let Some(tables) = assembly.tables() else {
        return PreHookResult::Bypass(None);
    };

    let Some(fieldrva_table) = tables.table::<FieldRvaRaw>() else {
        return PreHookResult::Bypass(None);
    };

    // Find the RVA for this field token
    let mut rva: Option<u32> = None;
    for row in fieldrva_table {
        let row = match row {
            Ok(row) => row,
            Err(e) => {
                log::warn!("skipping unreadable metadata row: {e}");
                continue;
            }
        };
        // Convert field index to full token (table 0x04 = Field)
        let row_token = row.field | 0x0400_0000;
        if row_token == field_token && row.rva > 0 {
            rva = Some(row.rva);
            break;
        }
    }

    let Some(rva) = rva else {
        // Field not found in RVA table - may not have embedded data
        return PreHookResult::Bypass(None);
    };

    let file = assembly.file();

    // Get the array length and element type
    let array_len = thread.heap().get_array_length(array_ref).unwrap_or(0);
    if array_len == 0 {
        return PreHookResult::Bypass(None);
    }

    let element_type = thread
        .heap()
        .get_array_element_type(array_ref)
        .unwrap_or(CilFlavor::U1);

    // Calculate element size in bytes
    let Some(element_size) = element_type.element_size(ctx.pointer_size) else {
        return PreHookResult::Bypass(None);
    };

    // The array's bytes as the loaded image holds them at the field's RVA
    let Ok(data) = file.rva_slice(rva as usize, array_len.saturating_mul(element_size)) else {
        return PreHookResult::Bypass(None);
    };

    // Set each element in the array based on element type
    for i in 0..array_len {
        let Some(byte_offset) = i.checked_mul(element_size) else {
            break;
        };
        let Some(end_offset) = byte_offset.checked_add(element_size) else {
            break;
        };
        let Some(elem_bytes) = data.get(byte_offset..end_offset) else {
            break;
        };

        let value = match element_type {
            CilFlavor::Boolean | CilFlavor::I1 | CilFlavor::U1 => {
                let Some(b) = elem_bytes.first() else {
                    break;
                };
                EmValue::I32(i32::from(*b))
            }
            CilFlavor::Char | CilFlavor::I2 | CilFlavor::U2 => {
                let Ok(bytes) = <[u8; 2]>::try_from(elem_bytes) else {
                    break;
                };
                EmValue::I32(i32::from(i16::from_le_bytes(bytes)))
            }
            CilFlavor::I4 | CilFlavor::U4 => {
                let Ok(bytes) = <[u8; 4]>::try_from(elem_bytes) else {
                    break;
                };
                EmValue::I32(i32::from_le_bytes(bytes))
            }
            CilFlavor::R4 => {
                let Ok(bytes) = <[u8; 4]>::try_from(elem_bytes) else {
                    break;
                };
                EmValue::F32(f32::from_le_bytes(bytes))
            }
            CilFlavor::I8 | CilFlavor::U8 => {
                let Ok(bytes) = <[u8; 8]>::try_from(elem_bytes) else {
                    break;
                };
                EmValue::I64(i64::from_le_bytes(bytes))
            }
            CilFlavor::R8 => {
                let Ok(bytes) = <[u8; 8]>::try_from(elem_bytes) else {
                    break;
                };
                EmValue::F64(f64::from_le_bytes(bytes))
            }
            // For other types, treat as bytes
            _ => {
                let Some(b) = elem_bytes.first() else {
                    break;
                };
                EmValue::I32(i32::from(*b))
            }
        };

        try_hook!(thread.heap_mut().set_array_element(array_ref, i, value));
    }

    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode` method.
///
/// Returns a hash code for an object based on its identity.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.GetHashCode(Object) -> Int32`
///
/// # Parameters
///
/// - `o`: An object
fn runtime_helpers_get_hash_code_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // Return a hash based on the object reference ID
    let result = if let Some(EmValue::ObjectRef(r)) = ctx.args.first() {
        #[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
        let hash = r.id() as i32;
        EmValue::I32(hash)
    } else {
        EmValue::I32(0)
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.Equals` method.
///
/// Determines whether the specified object instances are the same instance.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.Equals(Object, Object) -> Boolean`
///
/// # Parameters
///
/// - `o1`: The first object to compare
/// - `o2`: The second object to compare
fn runtime_helpers_equals_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    let (Some(arg0), Some(arg1)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0))); // false
    };

    // Reference equality
    let equal = match (arg0, arg1) {
        (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => a.id() == b.id(),
        (EmValue::Null, EmValue::Null) => true,
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.GetObjectValue` method.
///
/// Boxes a value type. For reference types, returns the object unchanged.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.GetObjectValue(Object) -> Object`
///
/// # Parameters
///
/// - `obj`: The value type to be boxed (or reference type to return)
fn runtime_helpers_get_object_value_pre(
    ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // For reference types, return as-is
    // For value types, this would box them (we just return as-is)
    let result = if let Some(arg) = ctx.args.first() {
        arg.clone()
    } else {
        EmValue::Null
    };
    PreHookResult::Bypass(Some(result))
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor` method.
///
/// Runs a class constructor (static constructor).
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.RunClassConstructor(RuntimeTypeHandle) -> void`
///
/// # Parameters
///
/// - `type`: A type handle that specifies the class constructor to run
fn runtime_helpers_run_class_constructor_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    // We don't actually run the static constructor
    PreHookResult::Bypass(None)
}

/// Hook for `System.Runtime.CompilerServices.RuntimeHelpers.RunModuleConstructor` method.
///
/// Runs a module constructor.
///
/// # Handled Overloads
///
/// - `RuntimeHelpers.RunModuleConstructor(ModuleHandle) -> void`
///
/// # Parameters
///
/// - `module`: A handle that specifies the module constructor to run
fn runtime_helpers_run_module_constructor_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `RuntimeHelpers.PrepareDelegate` and `RuntimeHelpers.PrepareMethod`.
///
/// These are JIT compilation hints that request early compilation of delegates
/// and methods. In emulation we interpret IL directly, so pre-compilation is
/// unnecessary. Implemented as a void no-op.
fn runtime_helpers_prepare_noop_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `System.Object.Equals` method.
///
/// Handles both the instance and static overloads:
///
/// - `object.Equals(object) -> bool` (instance, virtual)
/// - `Object.Equals(object, object) -> bool` (static)
///
/// Uses reference equality for object references and value equality for
/// primitives. This is critical for ConfuserEx anti-tamper checks which call
/// `Assembly.GetExecutingAssembly().Equals(Assembly.GetCallingAssembly())`.
/// Without this hook, the call returns a Symbolic value, and depending on
/// how ControlFlow protection restructures branches, the anti-tamper check
/// may incorrectly fail, causing decryptors to return null.
fn object_equals_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    // Instance overload: this.Equals(other)
    if let Some(this) = ctx.this {
        let other = ctx.args.first().unwrap_or(&EmValue::Null);
        let equal = this.clr_equals(other);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))));
    }

    // Static overload: Object.Equals(a, b)
    if let (Some(a), Some(b)) = (ctx.args.first(), ctx.args.get(1)) {
        let equal = a.clr_equals(b);
        return PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))));
    }

    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `System.Object::.ctor()`.
///
/// The base `Object` constructor is a no-op in the CLR. Every type's constructor
/// chain ultimately calls this, but it performs no initialization.
fn object_ctor_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `Object.ToString()`.
///
/// Returns a string representation of the object. Type-aware:
/// - String objects → return self
/// - Boxed integers → numeric string
/// - ReflectionType → type's full name
/// - Other objects → type name or "System.Object"
#[allow(clippy::cast_sign_loss)]
fn object_to_string_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let text = match ctx.this {
        Some(EmValue::ObjectRef(href)) => {
            match thread.heap().get(*href) {
                Ok(HeapObject::String(_)) => {
                    // String.ToString() returns itself
                    return PreHookResult::Bypass(Some(EmValue::ObjectRef(*href)));
                }
                Ok(HeapObject::BoxedValue { value, .. }) => match &*value {
                    EmValue::I32(v) => v.to_string(),
                    EmValue::I64(v) => v.to_string(),
                    EmValue::F32(v) => v.to_string(),
                    EmValue::F64(v) => v.to_string(),
                    EmValue::Bool(b) => if *b { "True" } else { "False" }.to_string(),
                    EmValue::Char(c) => c.to_string(),
                    _ => "System.Object".to_string(),
                },
                Ok(HeapObject::ReflectionType { type_token, .. }) => {
                    // Return the type's full name if available
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().resolve(&type_token) {
                            if cil_type.namespace.is_empty() {
                                cil_type.name.clone()
                            } else {
                                format!("{}.{}", cil_type.namespace, cil_type.name)
                            }
                        } else {
                            format!("Type(0x{:08X})", type_token.value())
                        }
                    } else {
                        "System.Object".to_string()
                    }
                }
                Ok(HeapObject::Object { type_token, .. }) => {
                    // Try to get the type name from metadata
                    if let Some(asm) = thread.assembly().cloned() {
                        if let Some(cil_type) = asm.types().resolve(&type_token) {
                            if cil_type.namespace.is_empty() {
                                cil_type.name.clone()
                            } else {
                                format!("{}.{}", cil_type.namespace, cil_type.name)
                            }
                        } else {
                            "System.Object".to_string()
                        }
                    } else {
                        "System.Object".to_string()
                    }
                }
                _ => "System.Object".to_string(),
            }
        }
        Some(EmValue::I32(v)) => v.to_string(),
        Some(EmValue::I64(v)) => v.to_string(),
        Some(EmValue::Bool(b)) => if *b { "True" } else { "False" }.to_string(),
        Some(EmValue::Char(c)) => c.to_string(),
        _ => "System.Object".to_string(),
    };

    match thread.heap_mut().alloc_string(&text) {
        Ok(str_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(str_ref))),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `Object.GetHashCode()`.
///
/// Returns a deterministic hash code based on object identity (heap reference ID)
/// or the underlying value for value types.
fn object_get_hash_code_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    #[allow(clippy::cast_possible_truncation)]
    let hash = match ctx.this {
        Some(EmValue::ObjectRef(href)) => href.id() as i32,
        Some(EmValue::I32(v)) => *v,
        Some(EmValue::I64(v)) => *v as i32,
        Some(EmValue::Bool(b)) => i32::from(*b),
        Some(EmValue::Char(c)) => *c as i32,
        _ => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I32(hash)))
}

/// Hook for `System.Object.MemberwiseClone()`.
///
/// Creates a shallow copy of the current object. Allocates a new heap object
/// with the same type token and copies all field values.
///
/// # Handled Overloads
///
/// - `Object.MemberwiseClone() -> Object` (protected, instance)
fn object_memberwise_clone_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(EmValue::ObjectRef(src_ref)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let src_obj = match thread.heap().get(*src_ref) {
        Ok(obj) => obj,
        Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match src_obj {
        HeapObject::Object {
            type_token, fields, ..
        } => {
            // Allocate a new object with the same type
            let new_ref = match thread.heap_mut().alloc_object(type_token) {
                Ok(r) => r,
                Err(_) => return PreHookResult::Bypass(Some(EmValue::Null)),
            };
            // Copy all fields
            for (field_token, value) in &fields {
                try_hook!(thread
                    .heap_mut()
                    .set_field(new_ref, *field_token, value.clone()));
            }
            PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref)))
        }
        HeapObject::BoxedValue {
            type_token, value, ..
        } => {
            // Clone the boxed value
            match thread.heap_mut().alloc_boxed(type_token, (*value).clone()) {
                Ok(new_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
                Err(_) => PreHookResult::Bypass(Some(EmValue::Null)),
            }
        }
        _ => {
            // For other heap object types, return the original reference
            // (strings are immutable, arrays would need element-by-element copy)
            PreHookResult::Bypass(Some(EmValue::ObjectRef(*src_ref)))
        }
    }
}

/// Hook for `System.ValueType.Equals(object)`.
///
/// Compares two value types field-by-field. If both `this` and the argument are
/// boxed values with the same type token, compares their inner values. Otherwise
/// falls back to reference equality.
///
/// # Handled Overloads
///
/// - `ValueType.Equals(object) -> bool` (virtual, instance)
fn valuetype_equals_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(this_val) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let other = ctx.args.first().unwrap_or(&EmValue::Null);

    // Fast path: direct EmValue comparison (unboxed value types on the stack)
    if this_val.clr_equals(other) {
        return PreHookResult::Bypass(Some(EmValue::I32(1)));
    }

    // Boxed value comparison: compare inner values if same type
    let (this_ref, other_ref) = match (this_val, other) {
        (EmValue::ObjectRef(a), EmValue::ObjectRef(b)) => (*a, *b),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let this_obj = match thread.heap().get(this_ref) {
        Ok(obj) => obj,
        Err(_) => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let other_obj = match thread.heap().get(other_ref) {
        Ok(obj) => obj,
        Err(_) => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let equal = match (&this_obj, &other_obj) {
        (
            HeapObject::BoxedValue {
                type_token: t1,
                value: v1,
                ..
            },
            HeapObject::BoxedValue {
                type_token: t2,
                value: v2,
                ..
            },
        ) => {
            // Same type token and same inner value
            t1 == t2 && v1.clr_equals(v2)
        }
        (
            HeapObject::Object {
                type_token: t1,
                fields: f1,
                ..
            },
            HeapObject::Object {
                type_token: t2,
                fields: f2,
                ..
            },
        ) => {
            // Same type and all fields equal
            t1 == t2
                && f1.len() == f2.len()
                && f1
                    .iter()
                    .all(|(k, v)| f2.get(k).is_some_and(|v2| v.clr_equals(v2)))
        }
        _ => false,
    };

    PreHookResult::Bypass(Some(EmValue::I32(i32::from(equal))))
}

/// No-op hook for GC methods (`GC.Collect()`, `GC.SuppressFinalize()`, `GC.KeepAlive()`,
/// `GC.WaitForPendingFinalizers()`).
///
/// Garbage collection is not emulated — these are safe to skip entirely.
fn gc_noop_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `GC.get_MaxGeneration`.
///
/// .NET has 3 generations (0, 1, 2), so `MaxGeneration` returns 2.
fn gc_get_max_generation_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(2)))
}

/// Hook for `Unsafe.As<T>(object)` / `Unsafe.AsRef<T>(ref byte)`.
///
/// Reinterpret cast is a no-op in the emulator — just pass the value through.
fn unsafe_as_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = ctx.args.first().cloned().unwrap_or(EmValue::Null);
    PreHookResult::Bypass(Some(result))
}

/// Hook for `Unsafe.SizeOf<T>()`.
///
/// Returns a reasonable default size. Without generic instantiation info we
/// fall back to pointer size (8 on 64-bit, 4 on 32-bit). The return type
/// hint from the generic parameter is not available at hook level, so we
/// use a conservative default.
fn unsafe_sizeof_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let size = match ctx.pointer_size {
        PointerSize::Bit64 => 8,
        PointerSize::Bit32 => 4,
        PointerSize::Bit8 | PointerSize::Bit16 | PointerSize::Bit128 => 0,
    };
    PreHookResult::Bypass(Some(EmValue::I32(size)))
}

/// Hook for `Unsafe.Add<T>(ref T, int)` / `Unsafe.AddByteOffset` / `Unsafe.AsPointer`.
///
/// Stub: returns the first argument unchanged.
fn unsafe_passthrough_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let result = ctx.args.first().cloned().unwrap_or(EmValue::Null);
    PreHookResult::Bypass(Some(result))
}

/// Hook for `Unsafe.ReadUnaligned<T>(ref byte)`.
///
/// Stub: returns 0. Without actual memory layout we cannot read raw bytes.
fn unsafe_read_unaligned_pre(
    _ctx: &HookContext<'_>,
    _thread: &mut EmulationThread,
) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::I32(0)))
}

/// Hook for `Unsafe.WriteUnaligned<T>(ref byte, T)`.
///
/// No-op stub — raw memory writes are not supported in the emulator.
fn unsafe_write_noop_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(None)
}

/// Hook for `Unsafe.ByteOffset<T>(ref T, ref T)`.
///
/// Stub: returns 0 (cannot compute real pointer differences in emulation).
fn unsafe_byte_offset_pre(_ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    PreHookResult::Bypass(Some(EmValue::NativeInt(0)))
}

/// Hook for `Unsafe.AreSame<T>(ref T, ref T)`.
///
/// Compares the two arguments for reference equality.
fn unsafe_are_same_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    if let (Some(a), Some(b)) = (ctx.args.first(), ctx.args.get(1)) {
        let same = a.clr_equals(b);
        PreHookResult::Bypass(Some(EmValue::I32(i32::from(same))))
    } else {
        PreHookResult::Bypass(Some(EmValue::I32(0)))
    }
}

/// Hook for `Unsafe.IsNullRef<T>(ref T)`.
///
/// Returns true if the argument is Null.
fn unsafe_is_null_ref_pre(ctx: &HookContext<'_>, _thread: &mut EmulationThread) -> PreHookResult {
    let is_null = matches!(ctx.args.first(), Some(EmValue::Null) | None);
    PreHookResult::Bypass(Some(EmValue::I32(i32::from(is_null))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        emulation::{runtime::hook::HookManager, HeapRef},
        metadata::{token::Token, typesystem::PointerSize},
    };

    #[test]
    fn test_register_hooks() {
        let manager = HookManager::new();
        register(&manager).unwrap();
        assert_eq!(manager.len(), 30);
    }

    #[test]
    fn test_get_hash_code_hook() {
        let obj_ref = HeapRef::new(42);
        let args = [EmValue::ObjectRef(obj_ref)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "GetHashCode",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = runtime_helpers_get_hash_code_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }

    #[test]
    fn test_equals_hook_same_reference() {
        let obj1 = HeapRef::new(1);
        let obj2 = HeapRef::new(1);
        let args = [EmValue::ObjectRef(obj1), EmValue::ObjectRef(obj2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "Equals",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = runtime_helpers_equals_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 1), // true
            _ => panic!("Expected Bypass with I32(1)"),
        }
    }

    #[test]
    fn test_equals_hook_different_references() {
        let obj1 = HeapRef::new(1);
        let obj2 = HeapRef::new(2);
        let args = [EmValue::ObjectRef(obj1), EmValue::ObjectRef(obj2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "Equals",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = runtime_helpers_equals_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 0), // false
            _ => panic!("Expected Bypass with I32(0)"),
        }
    }

    #[test]
    fn test_get_object_value_hook() {
        let args = [EmValue::I32(42)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
            "GetObjectValue",
            PointerSize::Bit64,
        )
        .with_args(&args);

        let mut thread = crate::testkit::emulation::create_test_thread();
        let result = runtime_helpers_get_object_value_pre(&ctx, &mut thread);

        match result {
            PreHookResult::Bypass(Some(EmValue::I32(v))) => assert_eq!(v, 42),
            _ => panic!("Expected Bypass with I32(42)"),
        }
    }
}
