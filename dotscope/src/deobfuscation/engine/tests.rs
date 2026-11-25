use crate::{
    analysis::{
        AccessQualifiers, Budget, CallData, Callee, ConstValue, FieldRef, MethodPurity, MethodRef,
        ReturnInfo, SsaBlock, SsaFunction, SsaInstruction, SsaOp, SsaType, SsaVarId,
    },
    compiler::EventLog,
    deobfuscation::{
        config::{EngineConfig, PassConfig},
        engine::DeobfuscationEngine,
        result::DeobfuscationResult,
    },
    metadata::token::Token,
};

#[test]
fn test_engine_default() {
    let engine = DeobfuscationEngine::default();
    // Default config has all passes enabled
    assert!(engine.config.passes.constant_propagation);
    assert!(engine.config.passes.dead_code_elimination);
}

#[test]
fn test_engine_config() {
    let config = EngineConfig {
        budget: EngineConfig::BUDGET.with_limit(Budget::PipelineRounds, 10),
        passes: PassConfig {
            inline_threshold: 30,
            ..Default::default()
        },
        ..Default::default()
    };

    let engine = DeobfuscationEngine::new(config);
    assert_eq!(engine.config.budget.limit(Budget::PipelineRounds), 10);
    assert_eq!(engine.config.passes.inline_threshold, 30);
}

#[test]
fn test_pipeline_passes_default() {
    let engine = DeobfuscationEngine::default();
    let scheduler = engine.create_scheduler();

    // Deob passes (structure, value) are populated later by create_deob_passes().
    // create_scheduler only adds generic compiler passes.
    // Simplify (opaque predicates, VRP, CFG simplification, jump threading) + Inline
    assert!(scheduler.pass_count() > 0); // Opaque predicates + CFG + inlining
    assert!(scheduler.normalize_count() > 0); // DCE, constant prop, GVN, copy prop, strength reduction
}

#[test]
fn test_pipeline_passes_selective() {
    let config = EngineConfig {
        passes: PassConfig {
            constant_propagation: true,
            copy_propagation: false,
            opaque_predicate_removal: false,
            control_flow_simplification: false,
            dead_code_elimination: false,
            string_decryption: false,
            strength_reduction: false,
            memory_optimization: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let engine = DeobfuscationEngine::new(config);
    let scheduler = engine.create_scheduler();

    // ProxyDevirtualization + Reassociation + constant propagation + GVN should be in normalize
    assert_eq!(scheduler.normalize_count(), 4); // ProxyDevirtualizationPass + ReassociationPass + ConstantPropagationPass + GVN
                                                // No opaque pred, CFG simplification, or inlining
    assert_eq!(scheduler.pass_count(), 0);
}

/// `memory_optimization` is the only toggle that differs between these two
/// configs, so it must account for exactly one normalize pass.
#[test]
fn test_pipeline_memory_optimization_toggle() {
    let base = PassConfig {
        constant_propagation: false,
        copy_propagation: false,
        opaque_predicate_removal: false,
        control_flow_simplification: false,
        dead_code_elimination: false,
        string_decryption: false,
        strength_reduction: false,
        memory_optimization: false,
        ..Default::default()
    };

    let without = DeobfuscationEngine::new(EngineConfig {
        passes: base.clone(),
        ..Default::default()
    })
    .create_scheduler();

    let with = DeobfuscationEngine::new(EngineConfig {
        passes: PassConfig {
            memory_optimization: true,
            ..base
        },
        ..Default::default()
    })
    .create_scheduler();

    assert_eq!(
        with.normalize_count(),
        without.normalize_count() + 1,
        "enabling memory_optimization should register exactly one normalize pass"
    );
    assert_eq!(with.pass_count(), without.pass_count());
}

#[test]
fn test_analyze_return_void() {
    // Create SSA with void return
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
    ssa.add_block(block);

    let result = ssa.return_info();
    assert!(matches!(result, ReturnInfo::Void));
}

#[test]
fn test_analyze_return_constant() {
    // Create SSA that returns a constant
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    // Define a constant
    let var = SsaVarId::from_index(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
        dest: var,
        value: ConstValue::I32(42),
    }));

    // Return the constant
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(var))));
    ssa.add_block(block);

    let result = ssa.return_info();
    assert!(matches!(result, ReturnInfo::Constant(ConstValue::I32(42))));
}

#[test]
fn test_analyze_return_no_returns_is_void() {
    // Create SSA with no return statements (unusual but possible)
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let block = SsaBlock::new(0);
    ssa.add_block(block);

    let result = ssa.return_info();
    assert!(matches!(result, ReturnInfo::Void));
}

#[test]
fn test_analyze_purity_pure() {
    // Create SSA with only pure operations
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    // Pure arithmetic operation
    let dest = SsaVarId::from_index(0);
    let src1 = SsaVarId::from_index(1);
    let src2 = SsaVarId::from_index(2);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Add {
        dest,
        left: src1,
        right: src2,
        flags: None,
    }));
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(dest))));
    ssa.add_block(block);

    let result = ssa.purity(|_| None);
    assert!(matches!(result, MethodPurity::Pure));
}

#[test]
fn test_analyze_purity_impure_store_field() {
    // Create SSA with a field store
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let obj = SsaVarId::from_index(0);
    let val = SsaVarId::from_index(1);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::StoreField {
        object: obj,
        field: FieldRef::new(Token::new(0x04000001)),
        value: val,
        access: AccessQualifiers::FLAT,
    }));
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
    ssa.add_block(block);

    let result = ssa.purity(|_| None);
    assert!(matches!(result, MethodPurity::Impure));
}

#[test]
fn test_analyze_purity_impure_throw() {
    // Create SSA with a throw
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let exc = SsaVarId::from_index(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Throw { exception: exc }));
    ssa.add_block(block);

    let result = ssa.purity(|_| None);
    assert!(matches!(result, MethodPurity::Impure));
}

#[test]
fn test_analyze_purity_field_read_may_throw() {
    // A field read writes nothing, but faults on a null object: a call to it
    // may be inlined, not deleted.
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let dest = SsaVarId::from_index(0);
    let obj = SsaVarId::from_index(1);
    block.add_instruction(
        SsaInstruction::synthetic(SsaOp::LoadField {
            dest,
            object: obj,
            field: FieldRef::new(Token::new(0x04000001)),
            access: AccessQualifiers::FLAT,
        })
        .with_result_type(SsaType::I32),
    );
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(dest))));
    ssa.add_block(block);

    let result = ssa.purity(|_| None);
    assert!(matches!(result, MethodPurity::MayThrow));
    assert!(result.can_inline());
    assert!(!result.can_eliminate_if_unused());
}

#[test]
fn test_analyze_purity_unknown_calls() {
    // Create SSA with a call
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let dest = SsaVarId::from_index(0);
    block.add_instruction(
        SsaInstruction::synthetic(
            CallData::new(
                Some(dest),
                Callee::Direct(MethodRef::new(Token::new(0x06000001))),
                vec![],
            )
            .into(),
        )
        .with_result_type(SsaType::I32),
    );
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(dest))));
    ssa.add_block(block);

    let result = ssa.purity(|_| None);
    assert!(matches!(result, MethodPurity::Unknown));
}

#[test]
fn test_detect_string_decryptor_xor() {
    // Create small SSA with XOR operations (typical of string decryption)
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let dest = SsaVarId::from_index(0);
    let left = SsaVarId::from_index(1);
    let right = SsaVarId::from_index(2);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Xor {
        dest,
        left,
        right,
        flags: None,
    }));
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(dest))));
    ssa.add_block(block);

    let result = DeobfuscationEngine::detect_string_decryptor_pattern(&ssa);
    assert!(result);
}

#[test]
fn test_detect_string_decryptor_large_method() {
    // Create large SSA (over 200 instructions)
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    // Add 250 instructions
    for _ in 0..250_usize {
        let dest = SsaVarId::from_index(0);
        block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
            dest,
            value: ConstValue::I32(42),
        }));
    }
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
    ssa.add_block(block);

    // Large methods should not be detected as string decryptors
    let result = DeobfuscationEngine::detect_string_decryptor_pattern(&ssa);
    assert!(!result);
}

#[test]
fn test_detect_dispatcher_with_switch() {
    // Create SSA with a switch having 5+ targets
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let value = SsaVarId::from_index(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
        value,
        targets: vec![1, 2, 3, 4, 5], // 5 targets
        default: 6,
    }));
    ssa.add_block(block);

    let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
    assert!(result);
}

#[test]
fn test_detect_dispatcher_small_switch() {
    // Create SSA with a small switch (< 5 targets)
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let value = SsaVarId::from_index(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Switch {
        value,
        targets: vec![1, 2],
        default: 3,
    }));
    ssa.add_block(block);

    let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
    assert!(!result);
}

#[test]
fn test_detect_dispatcher_no_switch() {
    // Create SSA without switch
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(None)));
    ssa.add_block(block);

    let result = DeobfuscationEngine::detect_dispatcher_pattern(&ssa);
    assert!(!result);
}

#[test]
fn test_compute_method_summary() {
    let engine = DeobfuscationEngine::default();

    // Create a simple pure method with constant return
    let mut ssa: SsaFunction = SsaFunction::new(0, 0);
    let mut block = SsaBlock::new(0);

    let var = SsaVarId::from_index(0);
    block.add_instruction(SsaInstruction::synthetic(SsaOp::Const {
        dest: var,
        value: ConstValue::I32(42),
    }));
    block.add_instruction(SsaInstruction::synthetic(SsaOp::returns(Some(var))));
    ssa.add_block(block);

    let token = Token::new(0x06000001);
    let summary = engine.compute_method_summary(&ssa, token);

    assert_eq!(summary.token, token);
    assert!(matches!(summary.return_info, ReturnInfo::Constant(_)));
    assert!(matches!(summary.purity, MethodPurity::Pure));
    assert!(!summary.is_string_decryptor);
    assert!(!summary.is_dispatcher);
}

#[test]
fn test_deobfuscation_result_summary() {
    let result = DeobfuscationResult::new_with_techniques(EventLog::new(), Vec::new(), None);

    // summary() returns just the stats (no prefix)
    let summary = result.summary();
    assert!(!summary.is_empty() || summary == "No changes"); // Stats or "No changes"

    // detailed_summary() includes detection info
    let detailed = result.detailed_summary();
    assert!(detailed.contains("Deobfuscation complete"));
}
