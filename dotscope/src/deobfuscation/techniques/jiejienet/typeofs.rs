//! JIEJIE.NET typeof() encryption detection.
//!
//! Detects the typeof container class injected by JIEJIE.NET (typically named
//! `_RuntimeTypeHandleContainer`, but detection is purely structural and works
//! when renamed).
//!
//! # Structural Pattern
//!
//! The container class has:
//! - Exactly 1 static field: a `ValueType[]` array (`RuntimeTypeHandle[]`)
//! - A `.cctor` that populates the array with `ldtoken <type>` instructions
//! - An accessor method: `static Class(int32)` — indexes the array and calls
//!   `Type.GetTypeFromHandle()` to return a `System.Type`
//!
//! # Detection
//!
//! 1. Scan for classes with exactly 1 static `ValueType[]` field
//! 2. Look for an accessor method with signature `Class(int32)`
//! 3. Count `ldtoken` instructions in `.cctor` to determine handle count
//! 4. Populate [`TypeOfFindings`] with tokens and handle count

use std::{any::Any, sync::Arc};

use crate::{
    analysis::CilTarget,
    assembly::Operand,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::jiejienet::TypeOfRestorationPass,
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
    },
    metadata::{signatures::TypeSignature, token::Token, typesystem::wellknown},
    CilObject,
};

/// Findings from typeof container detection.
#[derive(Debug)]
pub struct TypeOfFindings {
    /// Token of the container class.
    pub container_type: Token,
    /// Token of the GetTypeInstance accessor method.
    pub accessor_token: Token,
    /// Token of the .cctor that populates the handle array.
    pub cctor_token: Option<Token>,
    /// Number of type handles stored (from .cctor ldtoken count).
    pub handle_count: usize,
    /// MemberRef token for `System.Type::GetTypeFromHandle(RuntimeTypeHandle)`,
    /// extracted from the accessor method body during detection.
    pub get_type_from_handle_token: Option<Token>,
}

/// Detects the JIEJIE.NET RuntimeTypeHandleContainer.
pub struct JiejieNetTypeOf;

impl Technique for JiejieNetTypeOf {
    fn id(&self) -> &'static str {
        "jiejienet.typeof"
    }

    fn name(&self) -> &'static str {
        "JIEJIE.NET typeof() Encryption"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Must have exactly 1 field (the RuntimeTypeHandle[] array)
            if cil_type.fields.count() != 1 {
                continue;
            }

            // Check if the field is a RuntimeTypeHandle array
            let Some((_, field)) = cil_type.fields.iter().next() else {
                continue;
            };
            let is_handle_array = match &field.signature.base {
                TypeSignature::SzArray(elem) => matches!(*elem.base, TypeSignature::ValueType(_)),
                _ => false,
            };

            if !is_handle_array || !field.flags.is_static() {
                continue;
            }

            // Look for accessor method: static, takes int32, returns a class type
            // (System.Type, but we check structurally for Class return + int32 param)
            let mut accessor_token: Option<Token> = None;
            let mut cctor_token: Option<Token> = None;

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };

                if method.name == wellknown::members::CCTOR {
                    cctor_token = Some(method.token);
                    continue;
                }

                if method.name == ".ctor" {
                    continue;
                }

                let sig = &method.signature;
                // Accessor: static, single int32 param, returns a class (Type)
                if method.is_static()
                    && sig.params.len() == 1
                    && sig
                        .params
                        .first()
                        .is_some_and(|p| matches!(p.base, TypeSignature::I4))
                    && matches!(sig.return_type.base, TypeSignature::Class(_))
                {
                    accessor_token = Some(method.token);
                }
            }

            let Some(accessor) = accessor_token else {
                continue;
            };

            // Extract the GetTypeFromHandle MemberRef token from the accessor body.
            // The accessor's IL: ldsfld handles → ldarg.0 → ldelem → call GetTypeFromHandle → ret
            let get_type_from_handle_token = assembly.method(&accessor).ok().and_then(|method| {
                method.instructions().find_map(|instr| {
                    if instr.mnemonic == "call" {
                        if let Operand::Token(token) = &instr.operand {
                            if let Some(member) = assembly.member_ref(token) {
                                if member.name == "GetTypeFromHandle" {
                                    return Some(*token);
                                }
                            }
                        }
                    }
                    None
                })
            });

            // Count ldtoken instructions in .cctor to determine handle count
            let handle_count = cctor_token
                .and_then(|t| assembly.method(&t).ok())
                .map(|m| m.instructions().filter(|i| i.mnemonic == "ldtoken").count())
                .unwrap_or(0);

            if handle_count == 0 {
                continue;
            }

            let evidence = vec![Evidence::Structural(format!(
                "RuntimeTypeHandle[] container with {} type handles and index accessor",
                handle_count,
            ))];

            let findings = TypeOfFindings {
                container_type: cil_type.token,
                accessor_token: accessor,
                cctor_token,
                handle_count,
                get_type_from_handle_token,
            };

            let mut detection = Detection::new_detected(
                evidence,
                Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
            );

            detection.cleanup_mut().add_type(cil_type.token);

            return detection;
        }

        Detection::new_empty()
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Value)
    }

    fn initialize(
        &self,
        _ctx: &AnalysisContext,
        _assembly: &CilObject,
        _detection: &Detection,
        _detections: &Detections,
    ) {
        // No warmup needed — we parse the .cctor statically in create_pass(),
        // so no emulation is required for typeof restoration.
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<TypeOfFindings>() else {
            return Vec::new();
        };
        let Some(cctor_token) = findings.cctor_token else {
            return Vec::new();
        };

        // Parse the .cctor to extract the ordered type tokens from ldtoken instructions
        let type_tokens = extract_cctor_type_tokens(assembly, cctor_token);
        if type_tokens.is_empty() {
            return Vec::new();
        }

        let Some(get_type_from_handle) = findings.get_type_from_handle_token else {
            log::warn!("JIEJIE.NET typeof: no GetTypeFromHandle token in findings");
            return Vec::new();
        };

        log::info!(
            "JIEJIE.NET typeof: extracted {} type tokens from .cctor, accessor=0x{:08X}",
            type_tokens.len(),
            findings.accessor_token.value(),
        );

        vec![Box::new(TypeOfRestorationPass::new(
            findings.accessor_token,
            type_tokens,
            get_type_from_handle,
        ))]
    }
}

/// Extracts the ordered list of type tokens from `ldtoken` instructions in the
/// container's `.cctor`.
///
/// The `.cctor` populates a `RuntimeTypeHandle[]` array with a sequence of
/// `ldtoken <type>` instructions. The order of `ldtoken` instructions corresponds
/// to array indices 0, 1, 2, ...
fn extract_cctor_type_tokens(assembly: &CilObject, cctor_token: Token) -> Vec<Token> {
    let Ok(method) = assembly.method(&cctor_token) else {
        return Vec::new();
    };

    method
        .instructions()
        .filter(|i| i.mnemonic == "ldtoken")
        .filter_map(|i| match &i.operand {
            Operand::Token(token) => Some(*token),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            jiejienet::typeofs::{JiejieNetTypeOf, TypeOfFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive_controlflow() {
        let asm = load_sample("packers/jiejie/source/jiejie_controlflow_no_rename.exe");
        let technique = JiejieNetTypeOf;
        let detection = technique.detect(&asm);

        assert!(detection.is_detected(), "Should detect typeof container");

        let findings = detection
            .findings::<TypeOfFindings>()
            .expect("Should have TypeOfFindings");

        assert_eq!(findings.handle_count, 6, "Should find 6 type handles");
    }

    #[test]
    fn test_detect_negative_strings_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_strings_only.exe");
        let technique = JiejieNetTypeOf;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "Should not detect in strings-only"
        );
    }

    #[test]
    fn test_detect_negative_original() {
        let asm = load_sample("packers/jiejie/source/original.exe");
        let technique = JiejieNetTypeOf;
        let detection = technique.detect(&asm);

        assert!(!detection.is_detected(), "Should not detect in original");
    }
}
