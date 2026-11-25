//! Object construction and delegate detection for CIL emulation.
//!
//! Handles `newobj` instruction resolution: allocating objects, checking constructor
//! hooks, detecting delegate constructors, and returning resolution outcomes.

use log::debug;

use crate::{
    emulation::{
        engine::{context::EmulationContext, resolution::NewObjResolution, EmulationError},
        memory::{DelegateEntry, HeapObject},
        runtime::{HookContext, HookManager, HookOutcome},
        thread::EmulationThread,
        EmValue, HeapRef,
    },
    metadata::{
        streams::SharedStr,
        tables::{MemberRefSignature, TableId},
        token::Token,
        typesystem::{CilFlavor, CilType, PointerSize},
    },
    Result,
};

/// Resolves a `newobj` instruction — allocates an object and dispatches its constructor.
///
/// Handles MethodDef, MemberRef, and MethodSpec constructor tokens. Allocates the
/// object on the managed heap, tries constructor hooks, detects delegate constructors,
/// and determines whether to enter the constructor body or bypass it.
///
/// # Arguments
///
/// * `hooks` - The hook manager for constructor interception
/// * `context` - The emulation context for method/type metadata
/// * `constructor_token` - Token of the constructor method
/// * `thread` - The emulation thread for heap/stack access
/// * `pointer_size` - Target platform pointer size
///
/// # Returns
///
/// A [`NewObjResolution`] indicating how the caller should proceed (enter constructor,
/// bypass via hook, redirect to underlying token, etc.).
///
/// # Errors
///
/// Returns an error if method lookup, argument popping, or heap allocation fails.
pub fn resolve_newobj(
    hooks: &HookManager,
    context: &EmulationContext,
    constructor_token: Token,
    thread: &mut EmulationThread,
    pointer_size: PointerSize,
) -> Result<NewObjResolution> {
    // Handle MethodSpec tokens (generic constructor instantiations)
    if constructor_token.is_table(TableId::MethodSpec) {
        if let Some(method_spec) = context.get_method_spec(constructor_token) {
            if let Some(underlying_token) =
                EmulationContext::resolve_method_spec_to_token(&method_spec)
            {
                return Ok(NewObjResolution::Redirect { underlying_token });
            }
        }

        return Err(EmulationError::MethodNotFound {
            token: constructor_token,
        }
        .into());
    }

    // Handle MemberRef tokens (external constructors)
    if constructor_token.is_table(TableId::MemberRef) {
        return resolve_newobj_memberref(hooks, context, constructor_token, thread, pointer_size);
    }

    // Get constructor info for MethodDef tokens
    let method = context.get_method(constructor_token)?;
    let param_count = method.signature.params.len();

    let arg_values = thread.pop_args(param_count)?;

    let declaring_type = context
        .assembly()
        .resolver()
        .declaring_type(constructor_token);
    let type_token = declaring_type.as_ref().map_or_else(
        || Token::new(constructor_token.value() & 0x00FF_FFFF),
        |t| t.token,
    );

    let field_types: Vec<(Token, CilFlavor)> = declaring_type
        .as_ref()
        .map(|t| {
            t.fields
                .iter()
                .filter(|(_, f)| !f.flags.is_static())
                .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                .collect()
        })
        .unwrap_or_default();

    let obj_ref = thread
        .heap_mut()
        .alloc_object_with_fields(type_token, &field_types)?;

    // Try to find a constructor hook. What it constructs is what `newobj` pushes.
    let mut hooked: Option<EmValue> = None;
    if let Some(ref decl_type) = declaring_type {
        let this_value = EmValue::ObjectRef(obj_ref);
        let hook_context = HookContext::new(
            constructor_token,
            &decl_type.namespace,
            &decl_type.name,
            ".ctor",
            pointer_size,
        )
        .with_this(Some(&this_value))
        .with_args(&arg_values)
        .with_internal(constructor_token.is_table(TableId::MethodDef));

        match hooks.execute(&hook_context, thread, |_| None)? {
            HookOutcome::NoMatch => {}
            HookOutcome::Handled(value) => {
                hooked = Some(value.unwrap_or(EmValue::ObjectRef(obj_ref)));
            }
            HookOutcome::ReflectionInvoke { .. } => {
                hooked = Some(EmValue::ObjectRef(obj_ref));
            }
            HookOutcome::ThrewException {
                exception_type,
                message,
            } => {
                return Ok(NewObjResolution::ThrowException {
                    exception_type,
                    message,
                });
            }
        }
    }

    // Check that the method has a body AND has decoded instructions
    let has_instructions = method.instructions().next().is_some();
    if hooked.is_none() && method.has_body() && has_instructions {
        let mut full_args = vec![EmValue::ObjectRef(obj_ref)];
        full_args.extend(arg_values);

        return Ok(NewObjResolution::EnterConstructor {
            constructor_token,
            obj_ref,
            arguments: full_args,
        });
    }

    // Delegate constructor detection
    if hooked.is_none() && method.is_code_runtime() && arg_values.len() == 2 {
        if let Some(ref decl_type) = declaring_type {
            if is_delegate_type(decl_type) {
                let target = match arg_values.first() {
                    Some(EmValue::ObjectRef(href)) => Some(*href),
                    Some(EmValue::Null) => None,
                    _ => None,
                };

                let method_token_value = match arg_values.get(1) {
                    Some(EmValue::UnmanagedPtr(ptr)) => Some(Token::new(*ptr as u32)),
                    Some(EmValue::I32(v)) => Some(Token::new(*v as u32)),
                    Some(EmValue::I64(v)) => Some(Token::new(*v as u32)),
                    Some(EmValue::NativeInt(v)) => Some(Token::new(*v as u32)),
                    _ => None,
                };

                if let Some(delegate_method) = method_token_value {
                    debug!(
                        "Delegate .ctor: upgrading 0x{:08X} to HeapObject::Delegate \
                         (type=0x{:08X}, target={:?}, method=0x{:08X})",
                        obj_ref.id(),
                        type_token.value(),
                        target,
                        delegate_method.value(),
                    );

                    thread.heap().replace_object(
                        obj_ref,
                        HeapObject::Delegate {
                            type_token,
                            invocation_list: vec![DelegateEntry {
                                target,
                                method_token: delegate_method,
                            }],
                        },
                    )?;
                }
            }
        }
    }

    match hooked {
        Some(value) => Ok(NewObjResolution::HookedBypass { value }),
        None => Ok(NewObjResolution::DefaultObject { obj_ref }),
    }
}

/// Resolves a `newobj` instruction for MemberRef tokens (external constructors).
///
/// Handles constructor calls through MemberRef tokens, which reference constructors
/// in external assemblies. Allocates the object, checks for constructor hooks, and
/// detects delegate constructor patterns.
fn resolve_newobj_memberref(
    hooks: &HookManager,
    context: &EmulationContext,
    constructor_token: Token,
    thread: &mut EmulationThread,
    pointer_size: PointerSize,
) -> Result<NewObjResolution> {
    let member_ref =
        context
            .get_member_ref(constructor_token)
            .ok_or(EmulationError::MethodNotFound {
                token: constructor_token,
            })?;

    let param_count = if let MemberRefSignature::Method(method_sig) = &member_ref.signature {
        method_sig.param_count as usize
    } else {
        return Err(EmulationError::InvalidOperand {
            instruction: "newobj",
            expected: "method signature in MemberRef",
        }
        .into());
    };

    let args = thread.pop_args(param_count)?;

    let (namespace, type_name_only) = EmulationContext::get_member_ref_type_info(&member_ref)
        .unwrap_or_else(|| (SharedStr::default(), SharedStr::from("Unknown")));

    let type_token = EmulationContext::get_member_ref_type_token(&member_ref)
        .unwrap_or_else(|| Token::new(constructor_token.value() & 0x00FF_FFFF));

    let field_types: Vec<(Token, CilFlavor)> = context
        .get_type(type_token)
        .map(|t| {
            t.fields
                .iter()
                .filter(|(_, f)| !f.flags.is_static())
                .map(|(_, f)| (f.token, CilFlavor::from(&f.signature.base)))
                .collect()
        })
        .unwrap_or_default();

    let obj_ref = if type_name_only == "DynamicMethod" && namespace == "System.Reflection.Emit" {
        thread.heap_mut().alloc_dynamic_method()?
    } else if type_name_only == "String" && namespace == "System" {
        // System.String constructors: create a proper string object from args.
        // The CLR has several String constructors; the most common in obfuscated
        // code is String(char[]) which builds a string from a character array.
        create_string_from_ctor_args(thread, &args)?
    } else {
        thread
            .heap_mut()
            .alloc_object_with_fields(type_token, &field_types)?
    };

    let this_value = EmValue::ObjectRef(obj_ref);
    let hook_context = HookContext::new(
        constructor_token,
        &namespace,
        &type_name_only,
        ".ctor",
        pointer_size,
    )
    .with_this(Some(&this_value))
    .with_args(&args)
    .with_internal(false);

    match hooks.execute(&hook_context, thread, |_| None)? {
        HookOutcome::NoMatch => {}
        HookOutcome::Handled(value) => {
            // What the hook constructed, or the allocation it initialized
            return Ok(NewObjResolution::HookedBypass {
                value: value.unwrap_or(EmValue::ObjectRef(obj_ref)),
            });
        }
        HookOutcome::ReflectionInvoke { .. } => {
            return Ok(NewObjResolution::HookedBypass {
                value: EmValue::ObjectRef(obj_ref),
            });
        }
        HookOutcome::ThrewException {
            exception_type,
            message,
        } => {
            return Ok(NewObjResolution::ThrowException {
                exception_type,
                message,
            });
        }
    }

    // Delegate constructor detection for MemberRef path
    if args.len() == 2 {
        if let Some(cil_type) = context.get_type(type_token) {
            if is_delegate_type(&cil_type) {
                let target = match args.first() {
                    Some(EmValue::ObjectRef(href)) => Some(*href),
                    Some(EmValue::Null) => None,
                    _ => None,
                };

                let method_token_value = match args.get(1) {
                    Some(EmValue::UnmanagedPtr(ptr)) => Some(Token::new(*ptr as u32)),
                    Some(EmValue::I32(v)) => Some(Token::new(*v as u32)),
                    Some(EmValue::I64(v)) => Some(Token::new(*v as u32)),
                    Some(EmValue::NativeInt(v)) => Some(Token::new(*v as u32)),
                    _ => None,
                };

                if let Some(delegate_method) = method_token_value {
                    debug!(
                        "Delegate .ctor (MemberRef): upgrading 0x{:08X} to HeapObject::Delegate \
                         (type=0x{:08X}, target={:?}, method=0x{:08X})",
                        obj_ref.id(),
                        type_token.value(),
                        target,
                        delegate_method.value(),
                    );

                    thread.heap().replace_object(
                        obj_ref,
                        HeapObject::Delegate {
                            type_token,
                            invocation_list: vec![DelegateEntry {
                                target,
                                method_token: delegate_method,
                            }],
                        },
                    )?;
                }
            }
        }
    }

    Ok(NewObjResolution::DefaultObject { obj_ref })
}

/// Checks whether a type is a delegate type.
///
/// Walks the base type chain up to 3 levels looking for either `MulticastDelegate` or
/// `Delegate` in the `System` namespace. This detects both standard delegates and
/// custom delegate types generated by obfuscators.
///
/// # Arguments
///
/// * `cil_type` — The type to check.
///
/// # Returns
///
/// `true` if the type (or any of its bases within 3 levels) is `System.Delegate`
/// or `System.MulticastDelegate`.
pub fn is_delegate_type(cil_type: &CilType) -> bool {
    let mut current = cil_type.base();
    for _ in 0..3 {
        match current {
            Some(base) => {
                if base.namespace == "System"
                    && (base.name == "MulticastDelegate" || base.name == "Delegate")
                {
                    return true;
                }
                current = base.base();
            }
            None => break,
        }
    }
    false
}

/// The character `value` holds: a `char` as the stack or an array element holds it, either
/// as [`EmValue::Char`] or as the `int32` its UTF-16 code unit widens to.
fn char_of(value: &EmValue) -> Option<char> {
    match value {
        EmValue::Char(c) => Some(*c),
        #[allow(clippy::cast_sign_loss)]
        EmValue::I32(unit) => char::from_u32(*unit as u32),
        _ => None,
    }
}

/// Creates a `System.String` from constructor arguments.
///
/// Supports the string constructor overloads that take characters:
/// - `String(char[])` - the array's characters;
/// - `String(char[], int startIndex, int length)` - `length` of them from `startIndex`;
/// - `String(char c, int count)` - `c` repeated `count` times.
///
/// A character is accepted as [`EmValue::Char`] or as the `int32` a `char` widens to on the
/// stack. A negative count, start or length, or a slice past the array's end, is refused as
/// the runtime refuses it (`ArgumentOutOfRangeException`), and any other overload (from a
/// pointer, a span, an encoding) is refused rather than answered with a string it did not
/// build.
///
/// # Errors
///
/// [`EmulationError::InvalidStringOperation`] for the arguments the runtime refuses and the
/// overloads not emulated; a heap error reading the array or allocating the string.
fn create_string_from_ctor_args(thread: &mut EmulationThread, args: &[EmValue]) -> Result<HeapRef> {
    let refused = |description: String| -> crate::Error {
        EmulationError::InvalidStringOperation { description }.into()
    };
    match args {
        // String(char[])
        [EmValue::ObjectRef(array_ref)] => {
            let s = read_string_from_char_array(thread, *array_ref)?;
            thread.heap_mut().alloc_string(&s)
        }
        // String(char[], int startIndex, int length)
        [EmValue::ObjectRef(array_ref), EmValue::I32(start), EmValue::I32(len)] => {
            let (Ok(start), Ok(len)) = (usize::try_from(*start), usize::try_from(*len)) else {
                return Err(refused(format!(
                    "String(char[], int, int): start {start} and length {len} must be \
                     non-negative"
                )));
            };
            let chars: Vec<char> = read_string_from_char_array(thread, *array_ref)?
                .chars()
                .collect();
            let Some(slice) = start.checked_add(len).and_then(|end| chars.get(start..end)) else {
                return Err(refused(format!(
                    "String(char[], int, int): {len} characters from {start} pass the \
                     array's {} characters",
                    chars.len()
                )));
            };
            let s: String = slice.iter().collect();
            thread.heap_mut().alloc_string(&s)
        }
        // String(char c, int count) - repeats a character
        [ch, EmValue::I32(count)] if char_of(ch).is_some() => {
            let Ok(count) = usize::try_from(*count) else {
                return Err(refused(format!(
                    "String(char, int) constructor: count must be non-negative, got {count}"
                )));
            };
            let c = char_of(ch).unwrap_or('\0');
            let s: String = std::iter::repeat_n(c, count).collect();
            thread.heap_mut().alloc_string(&s)
        }
        _ => Err(refused(format!(
            "String constructor with arguments ({}) is not emulated",
            args.iter()
                .map(|arg| arg.cil_flavor().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// Reads a `char[]` array from the managed heap and converts it to a Rust `String`.
///
/// # Errors
///
/// [`EmulationError::InvalidStringOperation`] for an element that is no character; a heap
/// error reading the array.
fn read_string_from_char_array(thread: &EmulationThread, array_ref: HeapRef) -> Result<String> {
    let heap = thread.heap();
    let length = heap.get_array_length(array_ref)?;
    let mut chars = String::with_capacity(length);
    for i in 0..length {
        let element = heap.get_array_element(array_ref, i)?;
        let Some(ch) = char_of(&element) else {
            return Err(EmulationError::InvalidStringOperation {
                description: format!(
                    "char[] element {i} holds {}, which is no character",
                    element.cil_flavor()
                ),
            }
            .into());
        };
        chars.push(ch);
    }
    Ok(chars)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::emulation::create_test_thread;

    /// The string `args` construct, or the error they are refused with.
    fn construct(thread: &mut EmulationThread, args: &[EmValue]) -> Result<String> {
        let string = create_string_from_ctor_args(thread, args)?;
        Ok(thread.heap().get_string(string)?.to_string())
    }

    /// A `char[]` holding `text`, its elements as `kind` makes them.
    fn char_array(thread: &mut EmulationThread, text: &str, kind: fn(char) -> EmValue) -> EmValue {
        let elements = text.chars().map(kind).collect();
        EmValue::ObjectRef(
            thread
                .heap()
                .alloc_array_with_values(CilFlavor::Char, elements)
                .unwrap(),
        )
    }

    /// A character is accepted as `EmValue::Char` and as the `int32` a `char` widens to, in
    /// an array and as the repeated character alike.
    #[test]
    fn characters_are_read_as_chars_and_as_int32() {
        let mut thread = create_test_thread();
        for kind in [EmValue::Char as fn(char) -> EmValue, |c| {
            EmValue::I32(c as i32)
        }] {
            let array = char_array(&mut thread, "dotscope", kind);
            assert_eq!(
                construct(&mut thread, std::slice::from_ref(&array)).unwrap(),
                "dotscope"
            );
            assert_eq!(
                construct(&mut thread, &[array, EmValue::I32(3), EmValue::I32(5)]).unwrap(),
                "scope"
            );
            assert_eq!(
                construct(&mut thread, &[kind('x'), EmValue::I32(3)]).unwrap(),
                "xxx"
            );
        }
    }

    /// What the runtime refuses is refused, and an overload not emulated is refused rather
    /// than answered with an empty string.
    #[test]
    fn refused_arguments_and_unknown_overloads_are_errors() {
        let mut thread = create_test_thread();
        let array = char_array(&mut thread, "abc", EmValue::Char);
        for args in [
            vec![EmValue::Char('x'), EmValue::I32(-1)],
            vec![array.clone(), EmValue::I32(-1), EmValue::I32(1)],
            vec![array.clone(), EmValue::I32(1), EmValue::I32(-1)],
            vec![array.clone(), EmValue::I32(2), EmValue::I32(2)],
            vec![EmValue::I64(0)],
            vec![],
        ] {
            assert!(construct(&mut thread, &args).is_err(), "{args:?}");
        }
        let numbers = EmValue::ObjectRef(
            thread
                .heap()
                .alloc_array_with_values(CilFlavor::I8, vec![EmValue::I64(1)])
                .unwrap(),
        );
        assert!(construct(&mut thread, &[numbers]).is_err());
    }
}
