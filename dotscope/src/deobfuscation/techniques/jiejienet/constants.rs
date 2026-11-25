//! JIEJIE.NET Int32ValueContainer detection.
//!
//! Detects the integer constant container class injected by JIEJIE.NET (typically
//! named `_Int32ValueContainer`, but detection is purely structural and works when
//! renamed).
//!
//! # Structural Pattern
//!
//! The container class has:
//! - **All** fields are `static initonly int32` (no instance fields, no other types)
//! - A `.cctor` that initializes fields via an arithmetic delta chain:
//!
//! ```text
//! ldc.i8 <seed>       // Initial 64-bit accumulator
//! ldc.i8 <delta>      // First delta
//! add                 // seed + delta
//! dup                 // Keep accumulator on stack
//! conv.i4             // Truncate to int32
//! stsfld <field_1>    // Store first value
//! ldc.i8 <delta>      // Next delta
//! add                 // accumulate
//! dup
//! conv.i4
//! stsfld <field_2>    // Store second value
//! ...
//! ```
//!
//! - 10+ fields (typical range: 14-31 depending on protection configuration)
//!
//! # Detection
//!
//! 1. Scan for classes where every field is `static initonly int32`
//! 2. Verify the `.cctor` contains the `ldc.i8`/`add`/`dup`/`conv.i4`/`stsfld` chain
//! 3. Populate [`ConstantsFindings`] with field tokens and `.cctor` token

use std::{any::Any, sync::Arc};

use crate::{
    analysis::CilTarget,
    compiler::{CompilerContext, PassCapability, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{I32Extractor, StaticFieldResolutionPass},
        techniques::{Detection, Detections, Evidence, Technique, TechniqueCategory},
    },
    metadata::{signatures::TypeSignature, token::Token, typesystem::wellknown},
    CilObject,
};

/// Findings from Int32ValueContainer detection.
#[derive(Debug)]
pub struct ConstantsFindings {
    /// Token of the container class.
    pub container_type: Token,
    /// Tokens of all static int32 fields.
    pub field_tokens: Vec<Token>,
    /// Token of the .cctor method.
    pub cctor_token: Option<Token>,
}

/// Detects the JIEJIE.NET Int32ValueContainer by structural analysis.
pub struct JiejieNetConstants;

/// Minimum number of static int32 fields to consider a class as a container.
const MIN_FIELDS: usize = 10;

impl Technique for JiejieNetConstants {
    fn id(&self) -> &'static str {
        "jiejienet.constants"
    }

    fn name(&self) -> &'static str {
        "JIEJIE.NET Integer Constants"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Value
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        for type_entry in assembly.types().iter() {
            let cil_type = type_entry.value();

            // Must have fields
            if cil_type.fields.is_empty() {
                continue;
            }

            // Check if ALL fields are static initonly int32
            let mut all_static_int32 = true;
            let mut field_tokens: Vec<Token> = Vec::new();

            for (_, field) in cil_type.fields.iter() {
                let is_static = field.flags.is_static();
                let is_initonly = field.flags.is_init_only();
                let is_int32 = matches!(field.signature.base, TypeSignature::I4);

                if is_static && is_initonly && is_int32 {
                    field_tokens.push(field.token);
                } else {
                    all_static_int32 = false;
                    break;
                }
            }

            if !all_static_int32 || field_tokens.len() < MIN_FIELDS {
                continue;
            }

            // Verify .cctor has the ldc.i8 / add / conv.i4 / stsfld chain pattern
            let mut cctor_token = None;
            let mut has_delta_chain = false;

            for (_, method_ref) in cil_type.methods.iter() {
                let Some(method) = method_ref.upgrade() else {
                    continue;
                };
                if method.name == wellknown::members::CCTOR {
                    cctor_token = Some(method.token);

                    // Check for the delta chain pattern
                    let instructions: Vec<_> = method.instructions().collect();
                    let mut ldc_i8_count: usize = 0;
                    let mut has_conv_i4 = false;
                    let mut has_stsfld = false;
                    let mut has_dup = false;

                    for instr in &instructions {
                        match instr.mnemonic {
                            "ldc.i8" => ldc_i8_count = ldc_i8_count.saturating_add(1),
                            "conv.i4" => has_conv_i4 = true,
                            "stsfld" => has_stsfld = true,
                            "dup" => has_dup = true,
                            _ => {}
                        }
                    }

                    // The delta chain uses ldc.i8 for seed + deltas, conv.i4 to
                    // truncate, dup to keep the running accumulator, stsfld to store
                    has_delta_chain = ldc_i8_count >= 2 && has_conv_i4 && has_stsfld && has_dup;

                    break;
                }
            }

            if !has_delta_chain {
                continue;
            }

            let evidence = vec![Evidence::Structural(format!(
                "Class with {} static initonly int32 fields and ldc.i8 delta chain .cctor",
                field_tokens.len(),
            ))];

            let findings = ConstantsFindings {
                container_type: cil_type.token,
                field_tokens,
                cctor_token,
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
        ctx: &AnalysisContext,
        _assembly: &CilObject,
        detection: &Detection,
        _detections: &Detections,
    ) {
        let Some(findings) = detection.findings::<ConstantsFindings>() else {
            return;
        };

        // Register the container's .cctor as a warmup method so the emulation
        // template pool runs it before any forks. This populates all container
        // fields with their computed values.
        if let Some(cctor_token) = findings.cctor_token {
            log::info!(
                "JIEJIE.NET: registering Int32ValueContainer .cctor (0x{:08X}) as warmup, \
                 {} fields to resolve",
                cctor_token.value(),
                findings.field_tokens.len(),
            );
            ctx.register_warmup_method(cctor_token, vec![]);
        }
    }

    fn create_pass(
        &self,
        ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<ConstantsFindings>() else {
            return Vec::new();
        };
        let Some(pool) = ctx.template_pool.get().cloned() else {
            return Vec::new();
        };

        vec![Box::new(StaticFieldResolutionPass::new(
            "jiejie-int32-container",
            "Replaces JIEJIE.NET Int32ValueContainer field loads with resolved constant values",
            pool,
            findings.cctor_token,
            findings.field_tokens.clone(),
            Box::new(I32Extractor),
            vec![PassCapability::ResolvedStaticFields],
        ))]
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            jiejienet::constants::{ConstantsFindings, JiejieNetConstants},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive_controlflow_no_rename() {
        let asm = load_sample("packers/jiejie/source/jiejie_controlflow_no_rename.exe");
        let technique = JiejieNetConstants;
        let detection = technique.detect(&asm);

        assert!(detection.is_detected(), "Should detect Int32ValueContainer");

        let findings = detection
            .findings::<ConstantsFindings>()
            .expect("Should have ConstantsFindings");

        assert!(
            findings.field_tokens.len() >= 10,
            "Should find 10+ int32 fields, found {}",
            findings.field_tokens.len()
        );
        assert!(findings.cctor_token.is_some(), "Should have .cctor token");
    }

    #[test]
    fn test_detect_positive_renamed() {
        let asm = load_sample("packers/jiejie/source/jiejie_default.exe");
        let technique = JiejieNetConstants;
        let detection = technique.detect(&asm);

        assert!(
            detection.is_detected(),
            "Should detect container even when renamed"
        );
    }

    #[test]
    fn test_detect_negative_strings_only() {
        let asm = load_sample("packers/jiejie/source/jiejie_strings_only.exe");
        let technique = JiejieNetConstants;
        let detection = technique.detect(&asm);

        assert!(
            !detection.is_detected(),
            "Should not detect container in strings-only sample"
        );
    }

    #[test]
    fn test_detect_negative_original() {
        let asm = load_sample("packers/jiejie/source/original.exe");
        let technique = JiejieNetConstants;
        let detection = technique.detect(&asm);

        assert!(!detection.is_detected(), "Should not detect in original");
    }
}
