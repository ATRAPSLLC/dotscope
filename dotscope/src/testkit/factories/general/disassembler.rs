//! Factory methods for disassembler-related test structures.
//!
//! Contains helper methods migrated from disassembler source files
//! for creating test data related to instruction disassembly and analysis.

use crate::assembly::{FlowType, Instruction, InstructionCategory, Operand, StackBehavior};

/// Helper function to create a sample instruction for testing
///
/// Originally from: `src/disassembler/block.rs`
pub fn create_sample_instruction(flow_type: FlowType) -> Instruction {
    Instruction {
        rva: 0x1000,
        offset: 0,
        size: 1,
        opcode: 0x00, // nop
        prefix: 0,
        mnemonic: "nop",
        category: InstructionCategory::Misc,
        flow_type,
        operand: Operand::None,
        stack_behavior: StackBehavior {
            pops: 0,
            pushes: 0,
            net_effect: 0,
        },
        branch_targets: Vec::new(),
    }
}
