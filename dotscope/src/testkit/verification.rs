//! What the packer suites hold a deobfuscated sample to besides loading: the TestApp's pure
//! methods computing what the original's do, run under the emulator
//! ([`verify_semantic_preservation`]), and the assembly keeping the original's structure
//! ([`assert_structural_match`]).

use std::{
    collections::{HashMap, HashSet},
    hash::Hash,
    path::Path,
    sync::Arc,
};

#[cfg(feature = "deobfuscation")]
use crate::deobfuscation::{DeobfuscationResult, INLINED_METHOD_REMOVED};
#[cfg(feature = "emulation")]
use crate::emulation::{EmValue, EmulationOutcome, EmulationProcess};
use crate::{
    metadata::{
        method::{Method, MethodModifiers},
        signatures::TypeSignature,
        token::Token,
    },
    CilObject,
};

/// What running the [`PURE_TEST_METHODS`] in a deobfuscated assembly showed.
#[derive(Debug, Default)]
pub struct SemanticVerificationResult {
    /// The methods run.
    pub methods_checked: usize,
    /// Those whose every run returned what the original's did.
    pub methods_preserved: usize,
    /// Those the output has no counterpart for because the run inlined every call to them
    /// and removed them: what they computed now lives in their callers, which the runtime
    /// differential runs.
    pub methods_inlined: usize,
    /// Each method that was not preserved, and why.
    pub failures: Vec<String>,
}

/// An argument of a [`PureMethod`] run.
#[derive(Debug, Clone, Copy)]
pub enum PureArg {
    /// An `int32`.
    I32(i32),
    /// A `uint8`.
    U8(u8),
    /// A string.
    Str(&'static str),
}

/// A TestApp method whose result depends only on its arguments, and the argument vectors it
/// runs on. Each is an instance method of a class with no state it reads; a run gets a
/// fresh instance.
#[derive(Debug, Clone, Copy)]
pub struct PureMethod {
    /// The method's name in the unprotected original.
    pub name: &'static str,
    /// The argument vectors.
    pub runs: &'static [&'static [PureArg]],
}

/// The TestApp's pure methods, run on ordinary and edge arguments: the integer arithmetic,
/// including a division by zero and an overflow, and the string methods, whose results the
/// string protections encrypt.
pub const PURE_TEST_METHODS: &[PureMethod] = {
    use PureArg::{Str, I32, U8};
    const PAIRS: &[&[PureArg]] = &[
        &[I32(10), I32(5)],
        &[I32(-7), I32(3)],
        &[I32(i32::MAX), I32(1)],
        &[I32(65_536), I32(65_536)],
    ];
    &[
        PureMethod {
            name: "Add",
            runs: PAIRS,
        },
        PureMethod {
            name: "Subtract",
            runs: PAIRS,
        },
        PureMethod {
            name: "Multiply",
            runs: PAIRS,
        },
        PureMethod {
            name: "Divide",
            runs: &[&[I32(10), I32(5)], &[I32(-7), I32(2)], &[I32(7), I32(0)]],
        },
        PureMethod {
            name: "Factorial",
            runs: &[&[I32(0)], &[I32(1)], &[I32(6)], &[I32(12)]],
        },
        PureMethod {
            name: "Fibonacci",
            runs: &[&[I32(0)], &[I32(1)], &[I32(10)], &[I32(30)]],
        },
        PureMethod {
            name: "GetApiKey",
            runs: &[&[]],
        },
        PureMethod {
            name: "GetConnectionString",
            runs: &[&[]],
        },
        PureMethod {
            name: "DecryptSecret",
            runs: &[&[Str("SGVsbG8gV29ybGQ=")], &[Str("not base64")]],
        },
        PureMethod {
            name: "XorEncrypt",
            runs: &[&[Str("Hello"), U8(42)]],
        },
    ]
};

/// Simplified type classification for fingerprinting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeKind {
    Void,
    Bool,
    Char,
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    String,
    Object,
    Array,
    IntPtr,
    UIntPtr,
    ValueType,
    Class,
    Generic,
    ByRef,
    Pointer,
    Other,
}

impl TypeKind {
    pub fn from_type_signature(sig: &TypeSignature) -> Self {
        match sig {
            TypeSignature::Void => TypeKind::Void,
            TypeSignature::Boolean => TypeKind::Bool,
            TypeSignature::Char => TypeKind::Char,
            TypeSignature::I1 => TypeKind::I8,
            TypeSignature::U1 => TypeKind::U8,
            TypeSignature::I2 => TypeKind::I16,
            TypeSignature::U2 => TypeKind::U16,
            TypeSignature::I4 => TypeKind::I32,
            TypeSignature::U4 => TypeKind::U32,
            TypeSignature::I8 => TypeKind::I64,
            TypeSignature::U8 => TypeKind::U64,
            TypeSignature::R4 => TypeKind::F32,
            TypeSignature::R8 => TypeKind::F64,
            TypeSignature::String => TypeKind::String,
            TypeSignature::Object => TypeKind::Object,
            TypeSignature::I => TypeKind::IntPtr,
            TypeSignature::U => TypeKind::UIntPtr,
            TypeSignature::SzArray(_) | TypeSignature::Array(_) => TypeKind::Array,
            TypeSignature::ValueType(_) => TypeKind::ValueType,
            TypeSignature::Class(_) => TypeKind::Class,
            TypeSignature::GenericInst { .. }
            | TypeSignature::GenericParamType(_)
            | TypeSignature::GenericParamMethod(_) => TypeKind::Generic,
            TypeSignature::ByRef(_) => TypeKind::ByRef,
            TypeSignature::Ptr(_) => TypeKind::Pointer,
            _ => TypeKind::Other,
        }
    }
}

/// Signature key for method matching (param count + types).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignatureKey {
    pub param_count: usize,
    pub return_type: TypeKind,
    pub param_types: Vec<TypeKind>,
    pub is_instance: bool,
}

/// An emulation process for running `assembly`'s pure methods.
#[cfg(feature = "emulation")]
fn pure_process(assembly: &Arc<CilObject>) -> std::result::Result<EmulationProcess, String> {
    crate::testkit::emulation::process_builder()
        .assembly_arc(Arc::clone(assembly))
        .build()
        .map_err(|error| error.to_string())
}

/// The results of running each of `methods` in `assembly`, a line per run, by method name.
///
/// A result is what the run returned (an integer, a string's contents), `threw`, or
/// `unfinished` with what stopped the emulator. Each run gets a fresh instance of the class
/// declaring its method.
#[cfg(feature = "emulation")]
#[must_use]
pub fn run_pure_methods(
    assembly: &Arc<CilObject>,
    methods: &[(&PureMethod, Arc<Method>)],
) -> HashMap<&'static str, Vec<String>> {
    let process = pure_process(assembly);
    methods
        .iter()
        .map(|(pure, method)| {
            let runs = match &process {
                Ok(process) => pure
                    .runs
                    .iter()
                    .map(|args| run_pure(process, method, args))
                    .collect(),
                Err(error) => vec![format!("unfinished: {error}")],
            };
            (pure.name, runs)
        })
        .collect()
}

/// One run of `method` on `args` in `process`, as [`run_pure_methods`] states it.
#[cfg(feature = "emulation")]
fn run_pure(process: &EmulationProcess, method: &Method, args: &[PureArg]) -> String {
    let space = process.address_space();
    let Some(declaring) = method.declaring_type_rc() else {
        return "unfinished: the method has no declaring type".to_string();
    };
    let this = match space.alloc_object(declaring.token) {
        Ok(this) => this,
        Err(error) => return format!("unfinished: {error}"),
    };
    let mut values = vec![EmValue::ObjectRef(this)];
    for arg in args {
        values.push(match arg {
            PureArg::I32(value) => EmValue::I32(*value),
            PureArg::U8(value) => EmValue::I32(i32::from(*value)),
            PureArg::Str(text) => match space.alloc_string(text) {
                Ok(string) => EmValue::ObjectRef(string),
                Err(error) => return format!("unfinished: {error}"),
            },
        });
    }
    match process.execute_method(method.token, values) {
        Ok(EmulationOutcome::Completed { return_value, .. }) => match return_value {
            Some(EmValue::ObjectRef(object)) => match space.get_string(object) {
                Ok(text) => format!("{text:?}"),
                Err(_) => "an object".to_string(),
            },
            Some(EmValue::I32(value)) => value.to_string(),
            Some(value) => format!("{value:?}"),
            None => "void".to_string(),
        },
        Ok(EmulationOutcome::UnhandledException { .. }) => "threw".to_string(),
        Ok(other) => format!("unfinished: {other}"),
        Err(error) => format!("unfinished: {error}"),
    }
}

/// The signatures of the methods of `input` that the run in `result` removed because it
/// inlined every call to them (see [`INLINED_METHOD_REMOVED`]).
#[cfg(feature = "deobfuscation")]
#[must_use]
pub fn inlined_away(input: &CilObject, result: &DeobfuscationResult) -> Vec<SignatureKey> {
    result
        .events
        .iter()
        .filter(|event| event.message == INLINED_METHOD_REMOVED)
        .filter_map(|event| event.method.as_ref())
        .filter_map(|method| input.method(&method.token()).ok())
        .map(|method| signature_of(&method))
        .collect()
}

/// How a method is called: its parameter and return types, and whether it has `this`.
fn signature_of(method: &Method) -> SignatureKey {
    SignatureKey {
        param_count: method.signature.params.len(),
        return_type: TypeKind::from_type_signature(&method.signature.return_type.base),
        param_types: method
            .signature
            .params
            .iter()
            .map(|p| TypeKind::from_type_signature(&p.base))
            .collect(),
        is_instance: !method.flags_modifiers.contains(MethodModifiers::STATIC),
    }
}

/// The methods of `original` that `methods` names, each with what it is.
#[cfg(feature = "emulation")]
#[must_use]
pub fn pure_methods_of<'m>(
    original: &CilObject,
    methods: &'m [PureMethod],
) -> Vec<(&'m PureMethod, Arc<Method>)> {
    methods
        .iter()
        .filter_map(|pure| {
            original
                .methods()
                .iter()
                .find(|entry| entry.value().name == pure.name)
                .map(|entry| (pure, entry.value().clone()))
        })
        .collect()
}

/// Whether `deobfuscated` computes what `original` computes: each of the original's pure
/// methods (`references`, with their results in `expected` from [`run_pure_methods`]) has a
/// counterpart in `deobfuscated` returning the same results on the same arguments.
///
/// The counterpart is the method of the same name, where the output has one. An output whose
/// names were changed is searched by execution instead: some method of the same signature has
/// to return exactly what the original's does on every run, so a method computing something
/// else never stands in for it. A method with no counterpart is inlined rather than lost
/// when one of `inlined_away` (the signatures of the methods the run removed after inlining
/// every call to them, from [`inlined_away`]) is its signature, each removal accounting for
/// one method. Otherwise it is not preserved, and neither is one the original itself does
/// not finish under emulation: the check cannot vouch for it.
#[cfg(feature = "emulation")]
#[must_use]
pub fn verify_semantic_preservation(
    references: &[(&PureMethod, Arc<Method>)],
    expected: &HashMap<&'static str, Vec<String>>,
    deobfuscated: &Arc<CilObject>,
    inlined_away: &[SignatureKey],
) -> SemanticVerificationResult {
    let mut result = SemanticVerificationResult::default();
    let mut unaccounted: Vec<&SignatureKey> = inlined_away.iter().collect();
    let process = match pure_process(deobfuscated) {
        Ok(process) => process,
        Err(error) => {
            result.methods_checked = references.len();
            result.failures.push(format!(
                "the output does not start under emulation: {error}"
            ));
            return result;
        }
    };
    for (pure, reference) in references {
        result.methods_checked += 1;
        let Some(expected) = expected.get(pure.name) else {
            result
                .failures
                .push(format!("{}: the original was not run", pure.name));
            continue;
        };
        if let Some(unfinished) = expected.iter().find(|run| run.starts_with("unfinished")) {
            result.failures.push(format!(
                "{}: the original does not finish under emulation ({unfinished})",
                pure.name
            ));
            continue;
        }
        let returns = |method: &Method| -> Vec<String> {
            pure.runs
                .iter()
                .map(|args| run_pure(&process, method, args))
                .collect()
        };
        let named = deobfuscated
            .methods()
            .iter()
            .find(|entry| entry.value().name == reference.name)
            .map(|entry| entry.value().clone());
        let verdict = if let Some(method) = named {
            let actual = returns(&method);
            (&actual != expected)
                .then(|| format!("returns {actual:?} where the original returns {expected:?}"))
        } else {
            let signature = signature_of(reference);
            let candidates: Vec<Arc<Method>> = deobfuscated
                .methods()
                .iter()
                .map(|entry| entry.value().clone())
                .filter(|method| !method.name.starts_with('.') && signature_of(method) == signature)
                .collect();
            if candidates.iter().any(|method| &returns(method) == expected) {
                None
            } else if let Some(index) = unaccounted
                .iter()
                .position(|removed| **removed == signature)
            {
                unaccounted.swap_remove(index);
                result.methods_inlined += 1;
                continue;
            } else {
                Some(format!(
                    "none of the output's {} methods of its signature returns what the \
                     original does ({expected:?})",
                    candidates.len()
                ))
            }
        };
        match verdict {
            None => result.methods_preserved += 1,
            Some(failure) => result.failures.push(format!("{}: {failure}", pure.name)),
        }
    }
    result
}

/// Structural statistics of a .NET assembly for comparing deobfuscated
/// output against the original baseline.
#[derive(Debug, Clone)]
pub struct AssemblyStats {
    /// File size in bytes.
    pub file_size: u64,
    /// User-defined type names (fully qualified, excluding compiler infrastructure).
    pub type_names: HashSet<String>,
    /// Number of user-defined methods (across all user types).
    pub method_count: usize,
    /// Number of user-defined fields (across all user types).
    pub field_count: usize,
    /// Embedded resource names.
    pub resource_names: HashSet<String>,
}

/// Names of types that are compiler/runtime infrastructure, not user code.
/// These are excluded from structural comparison.
const INFRASTRUCTURE_TYPE_PREFIXES: &[&str] = &["<Module>"];

const INFRASTRUCTURE_TYPE_NAMES: &[&str] = &[
    "System.Runtime.CompilerServices.RefSafetyRulesAttribute",
    "Microsoft.CodeAnalysis.EmbeddedAttribute",
    "System.Runtime.CompilerServices.NullableAttribute",
    "System.Runtime.CompilerServices.NullableContextAttribute",
];

/// Returns true if a type name is compiler/runtime infrastructure.
fn is_infrastructure_type(name: &str) -> bool {
    for prefix in INFRASTRUCTURE_TYPE_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }
    INFRASTRUCTURE_TYPE_NAMES.contains(&name)
}

impl AssemblyStats {
    /// Collects structural statistics from an assembly.
    pub fn from_assembly(assembly: &CilObject, file_size: u64) -> Self {
        let types = assembly.types();
        let mut type_names = HashSet::new();
        let mut method_count = 0usize;
        let mut field_count = 0usize;

        for entry in types.iter() {
            let token: Token = *entry.key();
            let cil_type = entry.value();

            // Only count TypeDef tokens (table 0x02), not TypeRef/TypeSpec
            if token.table() != 0x02 {
                continue;
            }

            let fullname = cil_type.fullname();

            // Skip infrastructure types
            if is_infrastructure_type(&fullname) {
                continue;
            }

            type_names.insert(fullname.to_string());

            // Count methods and fields on this type
            method_count += cil_type.methods().count();
            field_count += cil_type.fields().count();
        }

        // Collect resource names
        let mut resource_names = HashSet::new();
        for entry in assembly.resources().iter() {
            resource_names.insert(entry.value().name.clone());
        }

        Self {
            file_size,
            type_names,
            method_count,
            field_count,
            resource_names,
        }
    }

    /// Collects stats from a file path.
    pub fn from_file(path: &Path) -> Self {
        let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let assembly = CilObject::from_path(path).expect("failed to load assembly for stats");
        Self::from_assembly(&assembly, file_size)
    }
}

/// Configuration for structural assertions.
#[derive(Debug, Clone)]
pub struct StructuralConfig {
    /// Maximum allowed file size increase from original (0.10 = +10%).
    /// Smaller output is always accepted (obfuscator artifacts removed).
    pub size_tolerance: f64,
    /// Whether to check that type names match original.
    pub check_type_names: bool,
    /// Whether to check that resource names match original.
    pub check_resources: bool,
}

impl Default for StructuralConfig {
    fn default() -> Self {
        Self {
            size_tolerance: 0.10,
            check_type_names: true,
            check_resources: true,
        }
    }
}

/// Asserts that the deobfuscated assembly matches the original's structure.
///
/// Checks:
/// 1. File size within tolerance
/// 2. All original types present (no missing user types)
/// 3. No extra types (obfuscator artifacts should be cleaned)
/// 4. Resource names match
///
/// Prints a diagnostic summary to stderr before asserting, so failures
/// show exactly what's wrong.
pub fn assert_structural_match(
    original: &AssemblyStats,
    deobfuscated: &AssemblyStats,
    filename: &str,
    config: &StructuralConfig,
) {
    let mut failures: Vec<String> = Vec::new();

    // File size check — only flag if output is LARGER than tolerance.
    // Smaller output is expected (obfuscator artifacts removed).
    let size_ratio = deobfuscated.file_size as f64 / original.file_size as f64;
    let size_pct = (size_ratio - 1.0) * 100.0;
    if size_ratio > (1.0 + config.size_tolerance) {
        failures.push(format!(
            "file size: {} bytes ({:+.1}% vs original {}), tolerance +{:.0}%",
            deobfuscated.file_size,
            size_pct,
            original.file_size,
            config.size_tolerance * 100.0
        ));
    }

    if config.check_type_names {
        // Missing types (in original but not in deobfuscated)
        let missing: Vec<_> = original
            .type_names
            .difference(&deobfuscated.type_names)
            .cloned()
            .collect();
        if !missing.is_empty() {
            failures.push(format!("missing types: {:?}", missing));
        }

        // Extra types (in deobfuscated but not in original = obfuscator artifacts)
        let extra: Vec<_> = deobfuscated
            .type_names
            .difference(&original.type_names)
            .cloned()
            .collect();
        if !extra.is_empty() {
            failures.push(format!("extra types (artifacts not cleaned): {:?}", extra));
        }
    }

    if config.check_resources {
        let missing_res: Vec<_> = original
            .resource_names
            .difference(&deobfuscated.resource_names)
            .cloned()
            .collect();
        let extra_res: Vec<_> = deobfuscated
            .resource_names
            .difference(&original.resource_names)
            .cloned()
            .collect();
        if !missing_res.is_empty() {
            failures.push(format!("missing resources: {:?}", missing_res));
        }
        if !extra_res.is_empty() {
            failures.push(format!("extra resources: {:?}", extra_res));
        }
    }

    // Print diagnostic summary
    eprintln!(
        "  Structural: size={} ({:+.1}%), types={}/{}, methods={}/{}, fields={}/{}, resources={}/{}{}",
        deobfuscated.file_size,
        size_pct,
        deobfuscated.type_names.len(),
        original.type_names.len(),
        deobfuscated.method_count,
        original.method_count,
        deobfuscated.field_count,
        original.field_count,
        deobfuscated.resource_names.len(),
        original.resource_names.len(),
        if failures.is_empty() { " ✓" } else { " ✗" }
    );

    assert!(
        failures.is_empty(),
        "{filename}: structural mismatch:\n  {}",
        failures.join("\n  ")
    );
}
