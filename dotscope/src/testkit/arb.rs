//! Generators of the values dotscope's encoders take, for property tests of the codecs, and
//! [`check`], which runs a property over them.
//!
//! The generators range over what the models can state, not only over what a compiler emits:
//! a codec property is that whatever an encoder accepts decodes back to itself, so a value the
//! encoder takes but writes as something else is a finding.

use std::fmt::Debug;

use proptest::{
    collection::vec,
    option,
    prelude::*,
    strategy::ValueTree,
    test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner},
};
use sha2::{Digest, Sha256};

use crate::metadata::{
    customattributes::{CustomAttributeArgument, CustomAttributeNamedArgument, FieldOrPropType},
    marshalling::NativeType,
    method::{ExceptionHandler, ExceptionHandlerFlags, ExceptionSectionFormat, MethodBody},
    security::Permission,
    signatures::{
        CustomModifier, SignatureArray, SignatureField, SignatureLocalVariable,
        SignatureLocalVariables, SignatureMethod, SignatureMethodSpec, SignatureParameter,
        SignaturePointer, SignatureProperty, SignatureSzArray, SignatureTypeSpec, TypeSignature,
    },
    tables::TableId,
    token::Token,
    typesystem::ArrayDimensions,
};

/// How many values a property is checked against.
const CASES: u32 = 1024;

/// Checks `property` against [`CASES`] values `strategy` generates, from a fixed seed so every
/// run checks the same values, and panics with the smallest failing value proptest shrinks a
/// failure to.
///
/// # Panics
///
/// When the property fails for a value.
pub fn check<S>(strategy: S, property: impl Fn(S::Value) -> Result<(), TestCaseError>)
where
    S: Strategy,
    S::Value: Debug,
{
    let config = Config {
        cases: CASES,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    if let Err(failure) = runner.run(&strategy, property) {
        panic!("{failure}");
    }
}

/// The value `strategy` generates with `data` as its seed: one value per input, the same
/// every run, so a fuzz target can drive the strategies the property tests use. `None` when
/// the strategy rejects the choices.
///
/// The choices are a ChaCha stream seeded with the input's hash rather than the input itself
/// (proptest's pass-through stream): past its input that stream gives zeros, and the uniform
/// sampling rejects a draw of zero for most ranges and draws again, for ever. Measured: an
/// empty input, and inputs that steer a strategy past a 64 KiB tail, hung the codec targets.
pub fn from_bytes<S: Strategy>(strategy: &S, data: &[u8]) -> Option<S::Value> {
    let seed: [u8; 32] = Sha256::digest(data).into();
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &seed),
    );
    strategy
        .new_tree(&mut runner)
        .ok()
        .map(|tree| tree.current())
}

/// The largest value a compressed unsigned integer (ECMA-335 II.23.2) holds.
const COMPRESSED_MAX: u32 = 0x1FFF_FFFF;

/// A compressed unsigned integer, biased towards each encoding width's edges.
fn compressed() -> impl Strategy<Value = u32> {
    prop_oneof![
        0u32..0x80,
        Just(0x7F),
        Just(0x80),
        0x80u32..0x4000,
        Just(0x3FFF),
        Just(0x4000),
        0x4000u32..=COMPRESSED_MAX,
        Just(COMPRESSED_MAX),
    ]
}

/// A token in a `TypeDefOrRef` coded index: a TypeDef, TypeRef or TypeSpec row.
pub fn type_def_or_ref() -> impl Strategy<Value = Token> {
    (
        prop_oneof![
            Just(TableId::TypeDef),
            Just(TableId::TypeRef),
            Just(TableId::TypeSpec)
        ],
        prop_oneof![1u32..0x100, 1u32..=0x00FF_FFFF],
    )
        .prop_map(|(table, row)| Token::from_parts(table, row))
}

/// A list of custom modifiers, `modreq` and `modopt` mixed.
pub fn custom_modifiers() -> impl Strategy<Value = Vec<CustomModifier>> {
    vec(
        (any::<bool>(), type_def_or_ref()).prop_map(|(is_required, modifier_type)| {
            CustomModifier {
                is_required,
                modifier_type,
            }
        }),
        0..3,
    )
}

/// A type with no type inside it.
fn leaf_type() -> impl Strategy<Value = TypeSignature> {
    prop_oneof![
        Just(TypeSignature::Void),
        Just(TypeSignature::Boolean),
        Just(TypeSignature::Char),
        Just(TypeSignature::I1),
        Just(TypeSignature::U1),
        Just(TypeSignature::I2),
        Just(TypeSignature::U2),
        Just(TypeSignature::I4),
        Just(TypeSignature::U4),
        Just(TypeSignature::I8),
        Just(TypeSignature::U8),
        Just(TypeSignature::R4),
        Just(TypeSignature::R8),
        Just(TypeSignature::String),
        Just(TypeSignature::TypedByRef),
        Just(TypeSignature::I),
        Just(TypeSignature::U),
        Just(TypeSignature::Object),
        type_def_or_ref().prop_map(TypeSignature::Class),
        type_def_or_ref().prop_map(TypeSignature::ValueType),
        compressed().prop_map(TypeSignature::GenericParamType),
        compressed().prop_map(TypeSignature::GenericParamMethod),
    ]
}

/// An array shape: a rank, and sizes and lower bounds for leading dimensions.
fn array_shape() -> impl Strategy<Value = (u32, Vec<ArrayDimensions>)> {
    (1u32..=32)
        .prop_flat_map(|rank| {
            (
                Just(rank),
                0..=rank,
                0..=rank,
                vec(compressed(), rank as usize),
                vec(-(1i32 << 28)..(1i32 << 28), rank as usize),
            )
        })
        .prop_map(|(rank, sizes, bounds, size_values, bound_values)| {
            let dimensions = (0..sizes.max(bounds) as usize)
                .map(|index| ArrayDimensions {
                    size: (index < sizes as usize).then(|| size_values[index]),
                    lower_bound: (index < bounds as usize).then(|| bound_values[index]),
                })
                .collect();
            (rank, dimensions)
        })
}

/// A type: leaves, and pointers, by-refs, arrays, generic instantiations and function
/// pointers nested around them.
pub fn type_signature() -> BoxedStrategy<TypeSignature> {
    leaf_type()
        .prop_recursive(6, 48, 6, |inner| {
            prop_oneof![
                (custom_modifiers(), inner.clone()).prop_map(|(modifiers, base)| {
                    TypeSignature::Ptr(SignaturePointer {
                        modifiers,
                        base: Box::new(base),
                    })
                }),
                inner
                    .clone()
                    .prop_map(|base| TypeSignature::ByRef(Box::new(base))),
                (custom_modifiers(), inner.clone()).prop_map(|(modifiers, base)| {
                    TypeSignature::SzArray(SignatureSzArray {
                        modifiers,
                        base: Box::new(base),
                    })
                }),
                (inner.clone(), array_shape()).prop_map(|(base, (rank, dimensions))| {
                    TypeSignature::Array(SignatureArray {
                        base: Box::new(base),
                        rank,
                        dimensions,
                    })
                }),
                (
                    prop_oneof![
                        type_def_or_ref().prop_map(TypeSignature::Class),
                        type_def_or_ref().prop_map(TypeSignature::ValueType)
                    ],
                    vec(inner.clone(), 1..5)
                )
                    .prop_map(|(base, arguments)| TypeSignature::GenericInst(
                        Box::new(base),
                        arguments
                    )),
                method_signature_over(inner)
                    .prop_map(|method| TypeSignature::FnPtr(Box::new(method))),
            ]
        })
        .boxed()
}

/// Whether `base` can be a parameter's or local's own type: a by-reference one states that
/// with its flag, which is what its encoding decodes to.
fn unflagged(base: &TypeSignature) -> bool {
    !matches!(base, TypeSignature::ByRef(_))
}

/// A parameter of type `base`: modifiers, by-reference or not, then the type.
fn parameter_over(
    base: impl Strategy<Value = TypeSignature>,
) -> impl Strategy<Value = SignatureParameter> {
    (
        custom_modifiers(),
        any::<bool>(),
        base.prop_filter("by-reference is the flag", unflagged),
    )
        .prop_map(|(modifiers, by_ref, base)| SignatureParameter {
            modifiers,
            by_ref,
            base,
        })
}

/// A method signature whose types `types` generates: every calling convention, `this`
/// flags, generic arity, and the varargs a `vararg` signature lists after its sentinel.
fn method_signature_over(
    types: impl Strategy<Value = TypeSignature> + Clone,
) -> impl Strategy<Value = SignatureMethod> {
    (
        prop_oneof![
            Just(0x00u8),
            Just(0x01),
            Just(0x02),
            Just(0x03),
            Just(0x04),
            Just(0x05),
            Just(0x09)
        ],
        prop_oneof![Just(0x00u8), Just(0x20), Just(0x60)],
        prop_oneof![Just(0u32), 1u32..4, compressed()],
        parameter_over(types.clone()),
        vec(parameter_over(types.clone()), 0..5),
        vec(parameter_over(types), 0..3),
    )
        .prop_map(|(kind, this, generic, return_type, params, varargs)| {
            let mut method = SignatureMethod::default();
            method
                .set_calling_convention(kind | this)
                .expect("a generated calling convention names a method signature kind");
            let varargs = if method.vararg { varargs } else { Vec::new() };
            method.param_count_generic = generic;
            method.param_count =
                u32::try_from(params.len() + varargs.len()).expect("a handful of parameters");
            method.return_type = return_type;
            method.params = params;
            method.varargs = varargs;
            method
        })
}

/// A method signature (MethodDefSig, MethodRefSig or StandAloneMethodSig).
pub fn method_signature() -> impl Strategy<Value = SignatureMethod> {
    method_signature_over(type_signature())
}

/// A field signature.
pub fn field_signature() -> impl Strategy<Value = SignatureField> {
    (custom_modifiers(), type_signature())
        .prop_map(|(modifiers, base)| SignatureField { modifiers, base })
}

/// A property signature.
pub fn property_signature() -> impl Strategy<Value = SignatureProperty> {
    (
        any::<bool>(),
        custom_modifiers(),
        type_signature(),
        vec(parameter_over(type_signature()), 0..4),
    )
        .prop_map(|(has_this, modifiers, base, params)| SignatureProperty {
            has_this,
            modifiers,
            base,
            params,
        })
}

/// A local variable signature.
pub fn local_var_signature() -> impl Strategy<Value = SignatureLocalVariables> {
    vec(
        (
            custom_modifiers(),
            any::<bool>(),
            any::<bool>(),
            type_signature().prop_filter("by-reference is the flag", unflagged),
        )
            .prop_map(
                |(modifiers, is_byref, is_pinned, base)| SignatureLocalVariable {
                    modifiers,
                    is_byref,
                    is_pinned,
                    base,
                },
            ),
        0..6,
    )
    .prop_map(|locals| SignatureLocalVariables { locals })
}

/// A type specification signature.
pub fn type_spec_signature() -> impl Strategy<Value = SignatureTypeSpec> {
    (custom_modifiers(), type_signature())
        .prop_map(|(modifiers, base)| SignatureTypeSpec { modifiers, base })
}

/// A generic method instantiation signature.
pub fn method_spec_signature() -> impl Strategy<Value = SignatureMethodSpec> {
    vec(type_signature(), 1..5).prop_map(|generic_args| SignatureMethodSpec { generic_args })
}

/// A string as custom attributes and marshalling descriptors write it: UTF-8, any length a
/// test can afford.
fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9_.]{0,12}",
        "[ a-z\t\n\r<>&\"'\u{0}-\u{1f}]{0,10}",
        any::<String>().prop_map(|s| s.chars().take(40).collect()),
    ]
}

/// A native type of a marshalling descriptor (ECMA-335 II.23.4), with every optional field
/// present or absent.
pub fn native_type() -> impl Strategy<Value = NativeType> {
    let leaf = prop_oneof![
        Just(NativeType::Void),
        Just(NativeType::Boolean),
        Just(NativeType::I1),
        Just(NativeType::U1),
        Just(NativeType::I2),
        Just(NativeType::U2),
        Just(NativeType::I4),
        Just(NativeType::U4),
        Just(NativeType::I8),
        Just(NativeType::U8),
        Just(NativeType::R4),
        Just(NativeType::R8),
        Just(NativeType::SysChar),
        Just(NativeType::Variant),
        Just(NativeType::Currency),
        Just(NativeType::Decimal),
        Just(NativeType::Date),
        Just(NativeType::Int),
        Just(NativeType::UInt),
        Just(NativeType::Error),
        Just(NativeType::BStr),
        option::of(compressed())
            .prop_map(|size_param_index| NativeType::LPStr { size_param_index }),
        option::of(compressed())
            .prop_map(|size_param_index| NativeType::LPWStr { size_param_index }),
        option::of(compressed())
            .prop_map(|size_param_index| NativeType::LPTStr { size_param_index }),
        option::of(compressed())
            .prop_map(|size_param_index| NativeType::LPUtf8Str { size_param_index }),
        compressed().prop_map(|size| NativeType::FixedSysString { size }),
        Just(NativeType::AnsiBStr),
        Just(NativeType::TBStr),
        compressed().prop_map(|size| NativeType::ByValStr { size }),
        Just(NativeType::VariantBool),
        (option::of(any::<u16>()), option::of(text())).prop_map(
            |(variant_type, user_defined_name)| NativeType::SafeArray {
                variant_type,
                user_defined_name,
            }
        ),
        Just(NativeType::IUnknown),
        Just(NativeType::IDispatch),
        Just(NativeType::IInspectable),
        option::of(compressed())
            .prop_map(|iid_param_index| NativeType::Interface { iid_param_index }),
        (option::of(any::<u8>()), option::of(compressed())).prop_map(
            |(packing_size, class_size)| NativeType::Struct {
                packing_size,
                class_size,
            }
        ),
        Just(NativeType::NestedStruct),
        Just(NativeType::LPStruct),
        (text(), text(), text(), text()).prop_map(
            |(guid, native_type_name, cookie, type_reference)| NativeType::CustomMarshaler {
                guid,
                native_type_name,
                cookie,
                type_reference,
            }
        ),
        Just(NativeType::ObjectRef),
        Just(NativeType::Func),
        Just(NativeType::AsAny),
        Just(NativeType::HString),
    ];
    // An element or a pointer's target is a tag alone: any byte, including ones no type has
    let tag = any::<u8>();
    prop_oneof![
        4 => leaf,
        1 => (compressed(), option::of(tag)).prop_map(|(size, element_type)| {
            NativeType::FixedArray { size, element_type }
        }),
        1 => (
            tag,
            option::of(compressed()),
            option::of(compressed()),
            option::of(compressed())
        )
            .prop_map(|(element_type, num_param, num_element, flags)| NativeType::Array {
                element_type,
                num_param,
                num_element,
                flags,
            }),
        1 => option::of(tag).prop_map(|ref_type| NativeType::Ptr { ref_type }),
    ]
}

/// The type a custom attribute names a field or property by (ECMA-335 II.23.3).
fn field_or_prop_type() -> impl Strategy<Value = FieldOrPropType> {
    let element = prop_oneof![
        Just(FieldOrPropType::Bool),
        Just(FieldOrPropType::Char),
        Just(FieldOrPropType::I1),
        Just(FieldOrPropType::U1),
        Just(FieldOrPropType::I2),
        Just(FieldOrPropType::U2),
        Just(FieldOrPropType::I4),
        Just(FieldOrPropType::U4),
        Just(FieldOrPropType::I8),
        Just(FieldOrPropType::U8),
        Just(FieldOrPropType::R4),
        Just(FieldOrPropType::R8),
        Just(FieldOrPropType::String),
        Just(FieldOrPropType::Type),
        Just(FieldOrPropType::Boxed),
        "[A-Z][a-zA-Z.]{0,20}".prop_map(FieldOrPropType::Enum),
    ];
    prop_oneof![
        3 => element.clone(),
        1 => element.prop_map(|element| FieldOrPropType::SzArray(Box::new(element))),
    ]
}

/// A value a custom attribute argument of `argument_type` holds. An enum holds an `int`.
fn argument_of(argument_type: &FieldOrPropType) -> BoxedStrategy<CustomAttributeArgument> {
    match argument_type {
        FieldOrPropType::Bool => any::<bool>()
            .prop_map(CustomAttributeArgument::Bool)
            .boxed(),
        FieldOrPropType::Char => any::<u16>().prop_map(CustomAttributeArgument::Char).boxed(),
        FieldOrPropType::I1 => any::<i8>().prop_map(CustomAttributeArgument::I1).boxed(),
        FieldOrPropType::U1 => any::<u8>().prop_map(CustomAttributeArgument::U1).boxed(),
        FieldOrPropType::I2 => any::<i16>().prop_map(CustomAttributeArgument::I2).boxed(),
        FieldOrPropType::U2 => any::<u16>().prop_map(CustomAttributeArgument::U2).boxed(),
        FieldOrPropType::I4 => any::<i32>().prop_map(CustomAttributeArgument::I4).boxed(),
        FieldOrPropType::U4 => any::<u32>().prop_map(CustomAttributeArgument::U4).boxed(),
        FieldOrPropType::I8 => any::<i64>().prop_map(CustomAttributeArgument::I8).boxed(),
        FieldOrPropType::U8 => any::<u64>().prop_map(CustomAttributeArgument::U8).boxed(),
        FieldOrPropType::R4 => any::<u32>()
            .prop_map(|bits| CustomAttributeArgument::R4(f32::from_bits(bits)))
            .boxed(),
        FieldOrPropType::R8 => any::<u64>()
            .prop_map(|bits| CustomAttributeArgument::R8(f64::from_bits(bits)))
            .boxed(),
        FieldOrPropType::String => option::of(text())
            .prop_map(CustomAttributeArgument::String)
            .boxed(),
        FieldOrPropType::Type => option::of("[A-Z][a-zA-Z.]{0,20}")
            .prop_map(CustomAttributeArgument::Type)
            .boxed(),
        FieldOrPropType::Boxed => field_or_prop_type()
            .prop_filter("a boxed value holds no boxed value", |held| {
                *held != FieldOrPropType::Boxed
            })
            .prop_flat_map(|held| argument_of(&held))
            .prop_map(|held| CustomAttributeArgument::Boxed(Box::new(held)))
            .boxed(),
        FieldOrPropType::Enum(name) => {
            let name = name.clone();
            any::<i32>()
                .prop_map(move |value| {
                    CustomAttributeArgument::Enum(
                        name.clone(),
                        Box::new(CustomAttributeArgument::I4(value)),
                    )
                })
                .boxed()
        }
        FieldOrPropType::SzArray(element) => {
            let element_type = (**element).clone();
            option::of(vec(argument_of(element), 0..4))
                .prop_map(move |elements| {
                    CustomAttributeArgument::Array(element_type.clone(), elements)
                })
                .boxed()
        }
    }
}

/// A custom attribute named argument: a field or property, its type and a value of it.
pub fn named_argument() -> impl Strategy<Value = CustomAttributeNamedArgument> {
    (
        any::<bool>(),
        "[A-Za-z_][A-Za-z0-9_]{0,15}",
        field_or_prop_type(),
    )
        .prop_flat_map(|(is_field, name, arg_type)| {
            argument_of(&arg_type).prop_map(move |value| CustomAttributeNamedArgument {
                is_field,
                name: name.clone(),
                arg_type: arg_type.clone(),
                value,
            })
        })
}

/// The permissions of a binary permission set: assembly-qualified attribute classes with
/// named arguments.
pub fn permissions() -> impl Strategy<Value = Vec<Permission>> {
    vec(
        (
            "System\\.Security\\.Permissions\\.[A-Z][a-zA-Z]{0,20}Attribute, mscorlib",
            vec(named_argument(), 0..4),
        )
            .prop_map(|(class_name, named_arguments)| Permission::new(class_name, named_arguments)),
        0..4,
    )
}

/// Exception handlers over `code_size` bytes of code: every clause kind, with offsets and
/// lengths that both the small and the fat format hold, and ones only the fat one does.
pub fn exception_handlers(code_size: u32) -> impl Strategy<Value = Vec<ExceptionHandler>> {
    let clause = (
        prop_oneof![
            Just(ExceptionHandlerFlags::EXCEPTION),
            Just(ExceptionHandlerFlags::FILTER),
            Just(ExceptionHandlerFlags::FINALLY),
            Just(ExceptionHandlerFlags::FAULT),
        ],
        0..code_size,
        0..code_size,
        0..code_size,
        0..code_size,
        any::<u32>(),
    )
        .prop_map(
            move |(flags, try_offset, try_length, handler_offset, handler_length, token)| {
                let try_length = try_length.min(code_size - try_offset);
                let handler_length = handler_length.min(code_size - handler_offset);
                ExceptionHandler {
                    flags,
                    try_offset,
                    try_length,
                    handler_offset,
                    handler_length,
                    // A filter's offset lies in the code; the field is a token otherwise
                    filter_offset: if flags == ExceptionHandlerFlags::FILTER {
                        token % code_size
                    } else {
                        token
                    },
                    handler: None,
                }
            },
        );
    prop_oneof![vec(clause.clone(), 1..4), vec(clause, 18..26)]
}

/// A method body and its code, as a body read from an assembly has them: a tiny one (at most
/// 63 bytes of code, a stack of 8, no locals or handlers) or a fat one with any header,
/// handlers, and the exception section format a reader records.
pub fn method_body() -> impl Strategy<Value = (MethodBody, Vec<u8>)> {
    let tiny = vec(any::<u8>(), 0..64).prop_map(|code| {
        (
            MethodBody {
                size_code: code.len(),
                size_header: 1,
                local_var_sig_token: 0,
                max_stack: 8,
                is_fat: false,
                is_init_local: false,
                is_exception_data: false,
                exception_handlers: Vec::new(),
                exception_format: None,
            },
            code,
        )
    });
    let fat = (
        prop_oneof![1u32..64, 64u32..400, Just(0x1_0000)],
        any::<u16>(),
        prop_oneof![
            Just(0u32),
            (1u32..0x00FF_FFFF).prop_map(|row| 0x1100_0000 | row)
        ],
        any::<bool>(),
    )
        .prop_flat_map(
            |(code_size, max_stack, local_var_sig_token, is_init_local)| {
                (
                    vec(any::<u8>(), code_size as usize),
                    Just(max_stack),
                    Just(local_var_sig_token),
                    Just(is_init_local),
                    prop_oneof![Just(Vec::new()), exception_handlers(code_size)],
                    any::<bool>(),
                    any::<bool>(),
                    any::<bool>(),
                )
            },
        )
        .prop_map(
            |(
                code,
                max_stack,
                local_var_sig_token,
                is_init_local,
                handlers,
                recorded,
                fat,
                with_header,
            )| {
                // A format a reader records: one that holds these clauses, its DataSize with
                // the header or, as AsmResolver writes it, without
                let small_fits = handlers.len() <= 20
                    && handlers.iter().all(|eh| {
                        eh.try_offset <= 0xFFFF
                            && eh.try_length <= 0xFF
                            && eh.handler_offset <= 0xFFFF
                            && eh.handler_length <= 0xFF
                    });
                let fat = fat || !small_fits;
                let clause = if fat { 24 } else { 12 };
                let data_size =
                    u32::try_from(handlers.len() * clause + if with_header { 4 } else { 0 })
                        .expect("a handful of clauses");
                let exception_format = (recorded && !handlers.is_empty())
                    .then_some(ExceptionSectionFormat { fat, data_size });
                (
                    MethodBody {
                        size_code: code.len(),
                        size_header: 12,
                        local_var_sig_token,
                        max_stack: usize::from(max_stack),
                        is_fat: true,
                        is_init_local,
                        is_exception_data: !handlers.is_empty(),
                        exception_handlers: handlers,
                        exception_format,
                    },
                    code,
                )
            },
        );
    prop_oneof![tiny, fat]
}
