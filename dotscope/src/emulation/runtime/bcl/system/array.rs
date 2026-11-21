//! `System.Array` and `System.Buffer` method hooks.
//!
//! This module provides hook implementations for array manipulation methods from the
//! .NET Base Class Library. Arrays are fundamental to many obfuscation techniques,
//! particularly for byte-level manipulation of encrypted data.
//!
//! # Overview
//!
//! The hooks in this module support both single-dimensional and multi-dimensional arrays,
//! implementing the most commonly used `System.Array` and `System.Buffer` methods.
//!
//! # Emulated .NET Methods
//!
//! ## System.Array Instance Properties
//!
//! | Property | Return Type | Description |
//! |----------|-------------|-------------|
//! | `Length` | `int` | Total number of elements |
//! | `LongLength` | `long` | Total number of elements (64-bit) |
//! | `Rank` | `int` | Number of dimensions |
//!
//! ## System.Array Instance Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `GetValue(int)` | Gets element at index |
//! | `SetValue(object, int)` | Sets element at index |
//! | `GetLength(int)` | Gets length of specified dimension |
//! | `Clone()` | Creates a shallow copy |
//!
//! ## System.Array Static Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `Copy(Array, Array, int)` | Copies elements between arrays |
//! | `Copy(Array, int, Array, int, int)` | Copies with offsets |
//! | `Clear(Array, int, int)` | Sets elements to default values |
//! | `Reverse(Array)` | Reverses element order |
//! | `IndexOf(Array, object)` | Finds first occurrence |
//!
//! ## System.Buffer Static Methods
//!
//! | Method | Description |
//! |--------|-------------|
//! | `BlockCopy(Array, int, Array, int, int)` | Byte-level copy between arrays |
//! | `ByteLength(Array)` | Returns total byte size of array |
//!
//! # Deobfuscation Use Cases
//!
//! ## Byte Array Manipulation
//!
//! Obfuscators frequently use `Buffer.BlockCopy` and `Array.Copy` to reassemble
//! decrypted data from multiple sources.
//!
//! ## Array-Based Decryption
//!
//! Many string decryption routines work on character arrays using `Array.Reverse`.

use crate::{
    emulation::{
        engine::synthetic_exception,
        memory::HeapObject,
        runtime::hook::{Hook, HookContext, HookManager, PreHookResult},
        thread::EmulationThread,
        EmValue,
    },
    metadata::typesystem::CilFlavor,
    utils::to_i32_saturating,
    Result,
};

/// Registers all `System.Array` and `System.Buffer` method hooks.
///
/// # Arguments
///
/// * `manager` - The [`HookManager`] to register hooks with
///
/// # Registered Hooks
///
/// - Array properties: `get_Length`, `get_LongLength`, `get_Rank`
/// - Array methods: `GetValue`, `SetValue`, `GetLength`, `Clone`
/// - Static methods: `Copy`, `Clear`, `Reverse`, `IndexOf`
/// - Buffer methods: `BlockCopy`, `ByteLength`
pub fn register(manager: &HookManager) -> Result<()> {
    // Instance properties
    manager.register(
        Hook::new("System.Array.get_Length")
            .match_name("System", "Array", "get_Length")
            .pre(array_get_length_pre),
    )?;

    manager.register(
        Hook::new("System.Array.get_LongLength")
            .match_name("System", "Array", "get_LongLength")
            .pre(array_get_long_length_pre),
    )?;

    manager.register(
        Hook::new("System.Array.get_Rank")
            .match_name("System", "Array", "get_Rank")
            .pre(array_get_rank_pre),
    )?;

    // Instance methods
    manager.register(
        Hook::new("System.Array.GetValue")
            .match_name("System", "Array", "GetValue")
            .pre(array_get_value_pre),
    )?;

    manager.register(
        Hook::new("System.Array.SetValue")
            .match_name("System", "Array", "SetValue")
            .pre(array_set_value_pre),
    )?;

    manager.register(
        Hook::new("System.Array.GetLength")
            .match_name("System", "Array", "GetLength")
            .pre(array_get_dimension_length_pre),
    )?;

    manager.register(
        Hook::new("System.Array.Clone")
            .match_name("System", "Array", "Clone")
            .pre(array_clone_pre),
    )?;

    // Static methods
    manager.register(
        Hook::new("System.Array.Copy")
            .match_name("System", "Array", "Copy")
            .pre(array_copy_pre),
    )?;

    manager.register(
        Hook::new("System.Array.Clear")
            .match_name("System", "Array", "Clear")
            .pre(array_clear_pre),
    )?;

    manager.register(
        Hook::new("System.Array.Reverse")
            .match_name("System", "Array", "Reverse")
            .pre(array_reverse_pre),
    )?;

    manager.register(
        Hook::new("System.Array.IndexOf")
            .match_name("System", "Array", "IndexOf")
            .pre(array_index_of_pre),
    )?;

    // Static factory
    manager.register(
        Hook::new("System.Array.CreateInstance")
            .match_name("System", "Array", "CreateInstance")
            .pre(array_create_instance_pre),
    )?;

    // Buffer operations
    manager.register(
        Hook::new("System.Buffer.BlockCopy")
            .match_name("System", "Buffer", "BlockCopy")
            .pre(buffer_block_copy_pre),
    )?;

    manager.register(
        Hook::new("System.Buffer.ByteLength")
            .match_name("System", "Buffer", "ByteLength")
            .pre(buffer_byte_length_pre),
    )?;

    Ok(())
}

/// Hook for `System.Array.Length` property.
///
/// # Handled Overloads
///
/// - `Array.Length -> Int32` (property getter)
///
/// # Parameters
///
/// None (instance property, `this` is the array).
///
/// # Returns
///
/// The total number of elements in all dimensions of the array as `Int32`.
fn array_get_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Ok(obj) = thread.heap().get_shared(*href) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let len = match &*obj {
        HeapObject::Array { elements, .. } | HeapObject::MultiArray { elements, .. } => {
            elements.len()
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    PreHookResult::Bypass(Some(to_i32_saturating(len).into()))
}

/// Hook for `System.Array.LongLength` property.
///
/// # Handled Overloads
///
/// - `Array.LongLength -> Int64` (property getter)
///
/// # Parameters
///
/// None (instance property, `this` is the array).
///
/// # Returns
///
/// The total number of elements in all dimensions of the array as `Int64`.
fn array_get_long_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let Ok(obj) = thread.heap().get_shared(*href) else {
        return PreHookResult::Bypass(Some(EmValue::I64(0)));
    };

    let len = match &*obj {
        HeapObject::Array { elements, .. } | HeapObject::MultiArray { elements, .. } => {
            elements.len()
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I64(0))),
    };

    let len = i64::try_from(len).unwrap_or(i64::MAX);
    PreHookResult::Bypass(Some(len.into()))
}

/// Hook for `System.Array.Rank` property.
///
/// # Handled Overloads
///
/// - `Array.Rank -> Int32` (property getter)
///
/// # Parameters
///
/// None (instance property, `this` is the array).
///
/// # Returns
///
/// The number of dimensions of the array. Single-dimensional arrays return 1.
fn array_get_rank_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let Ok(obj) = thread.heap().get_shared(*href) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let rank: i32 = match &*obj {
        HeapObject::Array { .. } => 1,
        HeapObject::MultiArray { dimensions, .. } => {
            i32::try_from(dimensions.len()).unwrap_or(i32::MAX)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    PreHookResult::Bypass(Some(rank.into()))
}

/// Hook for `System.Array.GetValue` method.
///
/// # Handled Overloads
///
/// - `Array.GetValue(Int32) -> Object`
/// - `Array.GetValue(Int64) -> Object`
/// - `Array.GetValue(Int32[]) -> Object` (multi-dimensional)
/// - `Array.GetValue(Int64[]) -> Object` (multi-dimensional)
///
/// # Parameters
///
/// - `index`: The zero-based index of the element to get.
/// - `indices`: An array of indices for multi-dimensional arrays.
///
/// # Returns
///
/// The element at the specified index, or `null` if index is out of range.
fn array_get_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let index = match ctx.args.first() {
        Some(v) => usize::try_from(v).unwrap_or(0),
        None => return PreHookResult::Bypass(Some(EmValue::Null)),
    };

    match thread.heap().get_array_element(*href, index) {
        Ok(value) => PreHookResult::Bypass(Some(value)),
        Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
    }
}

/// Hook for `System.Array.SetValue` method.
///
/// # Handled Overloads
///
/// - `Array.SetValue(Object, Int32) -> void`
/// - `Array.SetValue(Object, Int64) -> void`
/// - `Array.SetValue(Object, Int32[]) -> void` (multi-dimensional)
/// - `Array.SetValue(Object, Int64[]) -> void` (multi-dimensional)
///
/// # Parameters
///
/// - `value`: The new value to set at the specified index.
/// - `index`: The zero-based index of the element to set.
/// - `indices`: An array of indices for multi-dimensional arrays.
///
/// # Returns
///
/// None. The array element is modified in-place.
fn array_set_value_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(None);
    };

    let (Some(value_arg), Some(index_arg)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(None);
    };

    let value = value_arg.clone();
    let index = usize::try_from(index_arg).unwrap_or(0);

    try_hook!(thread.heap_mut().set_array_element(*href, index, value));
    PreHookResult::Bypass(None)
}

/// Hook for `System.Array.GetLength` method.
///
/// # Handled Overloads
///
/// - `Array.GetLength(Int32) -> Int32`
///
/// # Parameters
///
/// - `dimension`: The zero-based dimension index.
///
/// # Returns
///
/// The number of elements in the specified dimension.
fn array_get_dimension_length_pre(
    ctx: &HookContext<'_>,
    thread: &mut EmulationThread,
) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let dimension = ctx
        .args
        .first()
        .map(usize::try_from)
        .and_then(|r| r.ok())
        .unwrap_or(0);

    let Ok(obj) = thread.heap().get_shared(*href) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let length = match &*obj {
        HeapObject::Array { elements, .. } if dimension == 0 => elements.len(),
        HeapObject::MultiArray { dimensions, .. } => match dimensions.get(dimension) {
            Some(d) => *d,
            None => return PreHookResult::Bypass(Some(EmValue::I32(0))),
        },
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    PreHookResult::Bypass(Some(to_i32_saturating(length).into()))
}

/// Hook for `System.Array.Clone` method.
///
/// # Handled Overloads
///
/// - `Array.Clone() -> Object`
///
/// # Parameters
///
/// None (instance method, `this` is the array to clone).
///
/// # Returns
///
/// A shallow copy of the array with the same element type and dimensions.
fn array_clone_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(EmValue::ObjectRef(href)) = ctx.this else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    let Ok(obj) = thread.heap().get_shared(*href) else {
        return PreHookResult::Bypass(Some(EmValue::Null));
    };

    match &*obj {
        HeapObject::Array {
            element_type,
            elements,
        } => match thread
            .heap_mut()
            .alloc_array_with_values(element_type.clone(), elements.to_vec())
        {
            Ok(new_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref))),
            Err(e) => PreHookResult::Error(format!("heap allocation failed: {e}")),
        },
        HeapObject::MultiArray {
            element_type,
            dimensions,
            elements,
        } => {
            let Ok(new_ref) = thread
                .heap_mut()
                .alloc_multi_array(element_type.clone(), dimensions.to_vec())
            else {
                return PreHookResult::Bypass(Some(EmValue::Null));
            };
            try_hook!(thread.heap_mut().with_object_mut(new_ref, |obj| {
                if let HeapObject::MultiArray {
                    elements: new_elements,
                    ..
                } = obj
                {
                    *new_elements = elements.to_vec();
                }
                Ok(())
            }));
            PreHookResult::Bypass(Some(EmValue::ObjectRef(new_ref)))
        }
        _ => PreHookResult::Bypass(Some(EmValue::Null)),
    }
}

/// Hook for `System.Array.Copy` static method.
///
/// # Handled Overloads
///
/// - `Array.Copy(Array, Array, Int32) -> void`
/// - `Array.Copy(Array, Array, Int64) -> void`
/// - `Array.Copy(Array, Int32, Array, Int32, Int32) -> void`
/// - `Array.Copy(Array, Int64, Array, Int64, Int64) -> void`
///
/// # Parameters
///
/// - `sourceArray`: The source array to copy from.
/// - `destinationArray`: The destination array to copy to.
/// - `length`: The number of elements to copy.
/// - `sourceIndex`: The starting index in the source array.
/// - `destinationIndex`: The starting index in the destination array.
///
/// # Returns
///
/// None. Elements are copied in-place to the destination array.
fn array_copy_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    if ctx.args.len() < 3 {
        return PreHookResult::Bypass(None);
    }

    let (src_ref, src_index, dst_ref, dst_index, length) = if ctx.args.len() >= 5 {
        let (Some(a0), Some(a1), Some(a2), Some(a3), Some(a4)) = (
            ctx.args.first(),
            ctx.args.get(1),
            ctx.args.get(2),
            ctx.args.get(3),
            ctx.args.get(4),
        ) else {
            return PreHookResult::Bypass(None);
        };
        let src_ref = match a0 {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        let src_index = usize::try_from(a1).unwrap_or(0);
        let dst_ref = match a2 {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        let dst_index = usize::try_from(a3).unwrap_or(0);
        let length = usize::try_from(a4).unwrap_or(0);
        (src_ref, src_index, dst_ref, dst_index, length)
    } else {
        let (Some(a0), Some(a1), Some(a2)) = (ctx.args.first(), ctx.args.get(1), ctx.args.get(2))
        else {
            return PreHookResult::Bypass(None);
        };
        let src_ref = match a0 {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        let dst_ref = match a1 {
            EmValue::ObjectRef(r) => *r,
            _ => return PreHookResult::Bypass(None),
        };
        let length = usize::try_from(a2).unwrap_or(0);
        (src_ref, 0, dst_ref, 0, length)
    };

    let src_elements: Vec<EmValue> = {
        let Ok(src_obj) = thread.heap().get_shared(src_ref) else {
            return PreHookResult::Bypass(None);
        };
        match &*src_obj {
            HeapObject::Array { elements, .. } => elements
                .iter()
                .skip(src_index)
                .take(length)
                .cloned()
                .collect(),
            _ => return PreHookResult::Bypass(None),
        }
    };

    try_hook!(thread.heap_mut().with_object_mut(dst_ref, |obj| match obj {
        HeapObject::Array { elements, .. } => {
            for (i, elem) in src_elements.into_iter().enumerate() {
                let Some(target_index) = dst_index.checked_add(i) else {
                    return Err(crate::malformed_error!(
                        "Array.Copy: destination index overflow"
                    ));
                };
                if let Some(slot) = elements.get_mut(target_index) {
                    *slot = elem;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Array.Clear` static method.
///
/// # Handled Overloads
///
/// - `Array.Clear(Array, Int32, Int32) -> void`
///
/// # Parameters
///
/// - `array`: The array whose elements are to be cleared.
/// - `index`: The starting index of the range to clear.
/// - `length`: The number of elements to clear.
///
/// # Returns
///
/// None. Elements are set to the default value for their element type.
fn array_clear_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(a0), Some(a1), Some(a2)) = (ctx.args.first(), ctx.args.get(1), ctx.args.get(2))
    else {
        return PreHookResult::Bypass(None);
    };

    let array_ref = match a0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let index = usize::try_from(a1).unwrap_or(0);
    let length = usize::try_from(a2).unwrap_or(0);

    try_hook!(thread
        .heap_mut()
        .with_object_mut(array_ref, |obj| match obj {
            HeapObject::Array {
                elements,
                element_type,
            } => {
                let default = EmValue::default_for_flavor(element_type);
                let end = index
                    .checked_add(length)
                    .ok_or_else(|| crate::malformed_error!("Array.Clear: index + length overflow"))?
                    .min(elements.len());
                for i in index..end {
                    if let Some(slot) = elements.get_mut(i) {
                        *slot = default.clone();
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Array.Reverse` static method.
///
/// # Handled Overloads
///
/// - `Array.Reverse(Array) -> void`
/// - `Array.Reverse(Array, Int32, Int32) -> void`
///
/// # Parameters
///
/// - `array`: The array to reverse.
/// - `index`: The starting index of the section to reverse.
/// - `length`: The number of elements in the section to reverse.
///
/// # Returns
///
/// None. The array (or section) is reversed in-place.
fn array_reverse_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(a0) = ctx.args.first() else {
        return PreHookResult::Bypass(None);
    };

    let array_ref = match a0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    try_hook!(thread
        .heap_mut()
        .with_object_mut(array_ref, |obj| match obj {
            HeapObject::Array { elements, .. } => {
                elements.reverse();
                Ok(())
            }
            _ => Ok(()),
        }));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Array.IndexOf` static method.
///
/// # Handled Overloads
///
/// - `Array.IndexOf(Array, Object) -> Int32`
/// - `Array.IndexOf(Array, Object, Int32) -> Int32`
/// - `Array.IndexOf(Array, Object, Int32, Int32) -> Int32`
/// - `Array.IndexOf<T>(T[], T) -> Int32`
/// - `Array.IndexOf<T>(T[], T, Int32) -> Int32`
/// - `Array.IndexOf<T>(T[], T, Int32, Int32) -> Int32`
///
/// # Parameters
///
/// - `array`: The array to search.
/// - `value`: The object to locate in the array.
/// - `startIndex`: The starting index for the search.
/// - `count`: The number of elements to search.
///
/// # Returns
///
/// The zero-based index of the first occurrence, or -1 if not found.
fn array_index_of_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(a0), Some(search_value)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    let array_ref = match a0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let Ok(obj) = thread.heap().get_shared(array_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(-1)));
    };

    let index = match &*obj {
        HeapObject::Array { elements, .. } => elements.iter().position(|e| e == search_value),
        _ => return PreHookResult::Bypass(Some(EmValue::I32(-1))),
    };

    let result = index.map_or(-1, |i| i32::try_from(i).unwrap_or(i32::MAX));
    PreHookResult::Bypass(Some(result.into()))
}

/// Hook for `System.Buffer.BlockCopy` static method.
///
/// # Handled Overloads
///
/// - `Buffer.BlockCopy(Array, Int32, Array, Int32, Int32) -> void`
///
/// # Parameters
///
/// - `src`: The source array.
/// - `srcOffset`: The byte offset into the source array.
/// - `dst`: The destination array.
/// - `dstOffset`: The byte offset into the destination array.
/// - `count`: The number of bytes to copy.
///
/// # Returns
///
/// None. Bytes are copied from source to destination at the byte level.
///
/// # Implementation Notes
///
/// This method operates at the byte level, not the element level. For example,
/// copying from an `int[]` with `srcOffset=2` means starting at byte 2 within
/// the first integer element, not at the third integer.
fn buffer_block_copy_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(a0), Some(a1), Some(a2), Some(a3), Some(a4)) = (
        ctx.args.first(),
        ctx.args.get(1),
        ctx.args.get(2),
        ctx.args.get(3),
        ctx.args.get(4),
    ) else {
        return PreHookResult::Bypass(None);
    };

    let src_ref = match a0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let src_offset = usize::try_from(a1).unwrap_or(0);

    let dst_ref = match a2 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(None),
    };

    let dst_offset = usize::try_from(a3).unwrap_or(0);
    let count = usize::try_from(a4).unwrap_or(0);

    if count == 0 {
        return PreHookResult::Bypass(None);
    }

    let ptr_size = ctx.pointer_size;

    // Extract source array bytes
    let (src_bytes, _src_elem_size): (Vec<u8>, usize) = {
        let Ok(src_obj) = thread.heap().get_shared(src_ref) else {
            return PreHookResult::Bypass(None);
        };
        match &*src_obj {
            HeapObject::Array {
                elements,
                element_type,
            } => {
                let Some(elem_size) = element_type.element_size(ptr_size) else {
                    return PreHookResult::Bypass(None);
                };
                let bytes: Vec<u8> = elements
                    .iter()
                    .flat_map(|e| e.to_le_bytes(element_type, ptr_size))
                    .collect();
                (bytes, elem_size)
            }
            _ => return PreHookResult::Bypass(None),
        }
    };

    // Extract the byte range we need to copy
    let Some(unbounded_end) = src_offset.checked_add(count) else {
        return PreHookResult::Error("Buffer.BlockCopy: src_offset + count overflow".to_string());
    };
    let end_offset = unbounded_end.min(src_bytes.len());
    if src_offset >= src_bytes.len() {
        return PreHookResult::Bypass(None);
    }
    let Some(bytes_to_copy) = src_bytes.get(src_offset..end_offset).map(<[u8]>::to_vec) else {
        return PreHookResult::Bypass(None);
    };

    // Apply bytes to destination array
    try_hook!(thread.heap_mut().with_object_mut(dst_ref, |obj| match obj {
        HeapObject::Array {
            elements,
            element_type,
        } => {
            let Some(dst_elem_size) = element_type.element_size(ptr_size) else {
                return Ok(());
            };
            let dst_byte_len = elements.len().checked_mul(dst_elem_size).ok_or_else(|| {
                crate::malformed_error!("Buffer.BlockCopy: destination byte length overflow")
            })?;

            if dst_offset >= dst_byte_len {
                return Ok(());
            }

            // Convert destination elements to bytes
            let mut dst_bytes: Vec<u8> = elements
                .iter()
                .flat_map(|e| e.to_le_bytes(element_type, ptr_size))
                .collect();

            // Copy the bytes
            let remaining = dst_byte_len.checked_sub(dst_offset).ok_or_else(|| {
                crate::malformed_error!("Buffer.BlockCopy: dst_offset exceeds buffer")
            })?;
            let copy_len = bytes_to_copy.len().min(remaining);
            let copy_end = dst_offset.checked_add(copy_len).ok_or_else(|| {
                crate::malformed_error!("Buffer.BlockCopy: dst_offset + copy_len overflow")
            })?;
            let dst_slice = dst_bytes
                .get_mut(dst_offset..copy_end)
                .ok_or(crate::out_of_bounds_error!())?;
            let src_slice = bytes_to_copy
                .get(..copy_len)
                .ok_or(crate::out_of_bounds_error!())?;
            dst_slice.copy_from_slice(src_slice);

            // Convert bytes back to elements
            for (i, chunk) in dst_bytes.chunks(dst_elem_size).enumerate() {
                if let Some(slot) = elements.get_mut(i) {
                    *slot = EmValue::from_le_bytes(chunk, element_type, ptr_size);
                }
            }

            Ok(())
        }
        _ => Ok(()),
    }));

    PreHookResult::Bypass(None)
}

/// Hook for `System.Buffer.ByteLength` static method.
///
/// # Handled Overloads
///
/// - `Buffer.ByteLength(Array) -> Int32`
///
/// # Parameters
///
/// - `array`: The array whose byte length is to be returned.
///
/// # Returns
///
/// The total size of the array in bytes (element count * element size).
fn buffer_byte_length_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let Some(a0) = ctx.args.first() else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let array_ref = match a0 {
        EmValue::ObjectRef(r) => *r,
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    let Ok(obj) = thread.heap().get_shared(array_ref) else {
        return PreHookResult::Bypass(Some(EmValue::I32(0)));
    };

    let length = match &*obj {
        HeapObject::Array {
            elements,
            element_type,
        } => {
            let element_size = match element_type {
                CilFlavor::I4 | CilFlavor::U4 | CilFlavor::R4 => 4,
                CilFlavor::I8 | CilFlavor::U8 | CilFlavor::R8 => 8,
                CilFlavor::I2 | CilFlavor::U2 | CilFlavor::Char => 2,
                CilFlavor::I1 | CilFlavor::U1 | CilFlavor::Boolean => 1,
                _ => std::mem::size_of::<usize>(),
            };
            elements.len().saturating_mul(element_size)
        }
        _ => return PreHookResult::Bypass(Some(EmValue::I32(0))),
    };

    PreHookResult::Bypass(Some(to_i32_saturating(length).into()))
}

/// Hook for `System.Array.CreateInstance` static method.
///
/// # Handled Overloads
///
/// - `Array.CreateInstance(Type, int) -> Array`
/// - `Array.CreateInstance(Type, int[]) -> Array` (only 1D)
///
/// Creates a new single-dimensional, zero-based array of the specified type and length.
/// The element type is resolved from the `Type` argument via the emulation thread's
/// type token resolution, which uses the assembly's metadata for accurate mapping.
fn array_create_instance_pre(ctx: &HookContext<'_>, thread: &mut EmulationThread) -> PreHookResult {
    let (Some(type_arg), Some(length_arg)) = (ctx.args.first(), ctx.args.get(1)) else {
        return PreHookResult::Continue;
    };

    // arg[1] = int length (or int[] for multi-dimensional, which we only handle for 1D)
    //
    // A bare `as usize` turns `Array.CreateInstance(typeof(int), -1)` into `usize::MAX`, which
    // the allocator then tries to honour. .NET throws ArgumentOutOfRangeException for a
    // negative length, so do the same and let emulated code catch it.
    let length = match length_arg {
        EmValue::I32(n) => usize::try_from(*n).ok(),
        EmValue::I64(n) | EmValue::NativeInt(n) => usize::try_from(*n).ok(),
        _ => return PreHookResult::Continue,
    };
    let Some(length) = length else {
        return PreHookResult::Throw {
            exception_type: synthetic_exception::ARGUMENT_OUT_OF_RANGE,
            message: "Array.CreateInstance: length must be non-negative".to_string(),
        };
    };

    // arg[0] = Type (ObjectRef to ReflectionType on the heap)
    // Resolve the element type through the proper metadata path
    let element_flavor = match type_arg {
        EmValue::ObjectRef(href) => {
            match thread.heap().get_reflection_type_token(*href) {
                Ok(Some(type_token)) => {
                    // Use the thread's type resolution which has full assembly context
                    thread
                        .type_token_to_cil_flavor(type_token)
                        .unwrap_or(CilFlavor::Object)
                }
                _ => return PreHookResult::Continue,
            }
        }
        other => {
            log::debug!(
                "Array.CreateInstance: Type argument is {:?}, not ObjectRef — falling through",
                other
            );
            return PreHookResult::Continue;
        }
    };

    match thread.heap_mut().alloc_array(element_flavor, length) {
        Ok(array_ref) => PreHookResult::Bypass(Some(EmValue::ObjectRef(array_ref))),
        // Falling through to `Continue` on a budget rejection would let the emulated program
        // proceed as though the allocation had succeeded. Surface it as the CLR exception the
        // real runtime raises so `catch` blocks in the sample still behave correctly.
        Err(e) => PreHookResult::Throw {
            exception_type: synthetic_exception::OUT_OF_MEMORY,
            message: format!("Array.CreateInstance: {e}"),
        },
    }
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
        assert_eq!(manager.len(), 14);
    }

    #[test]
    fn test_array_length_hook() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();

        let this = EmValue::ObjectRef(arr);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "get_Length",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));

        let result = array_get_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(5)))
        ));
    }

    #[test]
    fn test_array_get_set_value_hook() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();

        let this = EmValue::ObjectRef(arr);
        let set_args = [EmValue::I32(42), EmValue::I32(2)];
        let set_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "SetValue",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&set_args);
        array_set_value_pre(&set_ctx, &mut thread);

        let get_args = [EmValue::I32(2)];
        let get_ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "GetValue",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&get_args);
        let result = array_get_value_pre(&get_ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(42)))
        ));
    }

    #[test]
    fn test_array_reverse_hook() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();

        thread
            .heap_mut()
            .set_array_element(arr, 0, EmValue::I32(1))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 1, EmValue::I32(2))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 2, EmValue::I32(3))
            .unwrap();

        let args = [EmValue::ObjectRef(arr)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "Reverse",
            PointerSize::Bit64,
        )
        .with_args(&args);
        array_reverse_pre(&ctx, &mut thread);

        assert_eq!(
            thread.heap().get_array_element(arr, 0).unwrap(),
            EmValue::I32(3)
        );
        assert_eq!(
            thread.heap().get_array_element(arr, 1).unwrap(),
            EmValue::I32(2)
        );
        assert_eq!(
            thread.heap().get_array_element(arr, 2).unwrap(),
            EmValue::I32(1)
        );
    }

    #[test]
    fn test_array_clone_hook() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();

        thread
            .heap_mut()
            .set_array_element(arr, 0, EmValue::I32(10))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 1, EmValue::I32(20))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 2, EmValue::I32(30))
            .unwrap();

        let this = EmValue::ObjectRef(arr);
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "Clone",
            PointerSize::Bit64,
        )
        .with_this(Some(&this));
        let result = array_clone_pre(&ctx, &mut thread);

        if let PreHookResult::Bypass(Some(EmValue::ObjectRef(cloned))) = result {
            assert_ne!(arr, cloned);
            assert_eq!(
                thread.heap().get_array_element(cloned, 0).unwrap(),
                EmValue::I32(10)
            );
            assert_eq!(
                thread.heap().get_array_element(cloned, 1).unwrap(),
                EmValue::I32(20)
            );
            assert_eq!(
                thread.heap().get_array_element(cloned, 2).unwrap(),
                EmValue::I32(30)
            );
        } else {
            panic!("Expected Bypass with ObjectRef");
        }
    }

    #[test]
    fn test_array_copy_simple() {
        let mut thread = create_test_thread();
        let src = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 0, EmValue::I32(10))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 1, EmValue::I32(20))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 2, EmValue::I32(30))
            .unwrap();

        let dst = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();

        let args = [
            EmValue::ObjectRef(src),
            EmValue::ObjectRef(dst),
            EmValue::I32(3),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "Copy",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = array_copy_pre(&ctx, &mut thread);
        assert!(matches!(result, PreHookResult::Bypass(None)));

        assert_eq!(
            thread.heap().get_array_element(dst, 0).unwrap(),
            EmValue::I32(10)
        );
        assert_eq!(
            thread.heap().get_array_element(dst, 1).unwrap(),
            EmValue::I32(20)
        );
        assert_eq!(
            thread.heap().get_array_element(dst, 2).unwrap(),
            EmValue::I32(30)
        );
    }

    #[test]
    fn test_array_copy_with_offsets() {
        let mut thread = create_test_thread();
        let src = thread.heap_mut().alloc_array(CilFlavor::I4, 4).unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 0, EmValue::I32(1))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 1, EmValue::I32(2))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 2, EmValue::I32(3))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(src, 3, EmValue::I32(4))
            .unwrap();

        let dst = thread.heap_mut().alloc_array(CilFlavor::I4, 4).unwrap();

        // Copy 2 elements from src[1] to dst[2]
        let args = [
            EmValue::ObjectRef(src),
            EmValue::I32(1),
            EmValue::ObjectRef(dst),
            EmValue::I32(2),
            EmValue::I32(2),
        ];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "Copy",
            PointerSize::Bit64,
        )
        .with_args(&args);
        array_copy_pre(&ctx, &mut thread);

        assert_eq!(
            thread.heap().get_array_element(dst, 0).unwrap(),
            EmValue::I32(0)
        );
        assert_eq!(
            thread.heap().get_array_element(dst, 1).unwrap(),
            EmValue::I32(0)
        );
        assert_eq!(
            thread.heap().get_array_element(dst, 2).unwrap(),
            EmValue::I32(2)
        );
        assert_eq!(
            thread.heap().get_array_element(dst, 3).unwrap(),
            EmValue::I32(3)
        );
    }

    #[test]
    fn test_array_clear() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 4).unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 0, EmValue::I32(1))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 1, EmValue::I32(2))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 2, EmValue::I32(3))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 3, EmValue::I32(4))
            .unwrap();

        // Clear 2 elements starting at index 1
        let args = [EmValue::ObjectRef(arr), EmValue::I32(1), EmValue::I32(2)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "Clear",
            PointerSize::Bit64,
        )
        .with_args(&args);
        array_clear_pre(&ctx, &mut thread);

        assert_eq!(
            thread.heap().get_array_element(arr, 0).unwrap(),
            EmValue::I32(1)
        );
        assert_eq!(
            thread.heap().get_array_element(arr, 1).unwrap(),
            EmValue::I32(0)
        );
        assert_eq!(
            thread.heap().get_array_element(arr, 2).unwrap(),
            EmValue::I32(0)
        );
        assert_eq!(
            thread.heap().get_array_element(arr, 3).unwrap(),
            EmValue::I32(4)
        );
    }

    #[test]
    fn test_array_index_of_found() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 0, EmValue::I32(10))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 1, EmValue::I32(20))
            .unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 2, EmValue::I32(30))
            .unwrap();

        let args = [EmValue::ObjectRef(arr), EmValue::I32(20)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "IndexOf",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = array_index_of_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(1)))
        ));
    }

    #[test]
    fn test_array_index_of_not_found() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 3).unwrap();
        thread
            .heap_mut()
            .set_array_element(arr, 0, EmValue::I32(10))
            .unwrap();

        let args = [EmValue::ObjectRef(arr), EmValue::I32(99)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "IndexOf",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = array_index_of_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(-1)))
        ));
    }

    #[test]
    fn test_array_get_value_out_of_bounds() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 2).unwrap();

        let this = EmValue::ObjectRef(arr);
        let args = [EmValue::I32(5)]; // out of bounds
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Array",
            "GetValue",
            PointerSize::Bit64,
        )
        .with_this(Some(&this))
        .with_args(&args);
        let result = array_get_value_pre(&ctx, &mut thread);
        // Out-of-bounds returns Error (heap error), not Null
        assert!(matches!(result, PreHookResult::Error(_)));
    }

    #[test]
    fn test_buffer_byte_length_hook() {
        let mut thread = create_test_thread();
        let arr = thread.heap_mut().alloc_array(CilFlavor::I4, 5).unwrap();

        let args = [EmValue::ObjectRef(arr)];
        let ctx = HookContext::new(
            Token::new(0x0A000001),
            "System",
            "Buffer",
            "ByteLength",
            PointerSize::Bit64,
        )
        .with_args(&args);
        let result = buffer_byte_length_pre(&ctx, &mut thread);
        assert!(matches!(
            result,
            PreHookResult::Bypass(Some(EmValue::I32(20)))
        ));
    }
}
