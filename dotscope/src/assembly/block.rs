//! Basic block representation for CIL control flow analysis.
//!
//! This module defines the fundamental building blocks for control flow analysis in .NET assemblies.
//! Basic blocks represent maximal sequences of CIL instructions with single entry and exit points,
//! enabling sophisticated program analysis, optimization, and understanding capabilities.
//!
//! # Architecture
//!
//! The module is organized around the central [`crate::assembly::block::BasicBlock`] type, which
//! encapsulates instruction sequences and their control flow relationships. Basic blocks form the
//! foundation for constructing control flow graphs that enable dead code elimination, reachability
//! analysis, and other static analysis techniques.
//!
//! # Key Components
//!
//! - [`crate::assembly::block::BasicBlock`] - Core basic block representation with instruction sequences
//! - [`crate::assembly::block::BasicBlock::new`] - Factory method for creating new basic blocks
//! - [`crate::assembly::block::BasicBlock::is_entry`] - Identifies entry points in control flow
//! - [`crate::assembly::block::BasicBlock::is_exit`] - Identifies termination points in control flow
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::assembly::BasicBlock;
//!
//! // Create a basic block at method entry point
//! let entry_block = BasicBlock::new(0, 0x2000, 0x1000);
//!
//! // Verify it's an entry block (no predecessors)
//! assert!(entry_block.is_entry());
//! assert!(!entry_block.is_exit());
//!
//! // Basic blocks start with empty instruction sequences
//! assert_eq!(entry_block.instructions.len(), 0);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::assembly::decoder`] - Provides instructions for basic block construction
//! - [`crate::assembly::instruction`] - Defines the instruction types contained in blocks
//! - [`crate::assembly::decode_blocks`] - Function that constructs basic blocks from bytecode

use crate::{
    assembly::{FlowType, Instruction},
    metadata::method::ExceptionHandlerFlags,
};

/// Information about an exception handler entry point.
///
/// When a basic block is the entry point for an exception handler (catch, finally,
/// fault, or filter), this structure provides the necessary information for
/// proper stack simulation and control flow analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandlerEntryInfo {
    /// The index of the exception handler in the method's exception handler table.
    pub handler_index: usize,

    /// The type of exception handler (EXCEPTION, FINALLY, FAULT, or FILTER).
    pub handler_type: ExceptionHandlerFlags,
}

impl HandlerEntryInfo {
    /// Creates a new handler entry info.
    #[must_use]
    pub const fn new(handler_index: usize, handler_type: ExceptionHandlerFlags) -> Self {
        Self {
            handler_index,
            handler_type,
        }
    }

    /// Returns the expected stack depth at handler entry.
    ///
    /// - Catch handlers: 1 (exception object on stack)
    /// - Filter handlers: 1 (exception object on stack)
    /// - Finally handlers: 0 (empty stack)
    /// - Fault handlers: 0 (empty stack)
    #[must_use]
    pub const fn entry_stack_depth(&self) -> usize {
        if self.handler_type.bits() == ExceptionHandlerFlags::EXCEPTION.bits()
            || self.handler_type.bits() == ExceptionHandlerFlags::FILTER.bits()
        {
            1 // Exception object on stack
        } else {
            0 // Finally/Fault have empty stack
        }
    }
}

/// Represents a basic block in the control flow graph.
///
/// A basic block is a maximal sequence of instructions with the following properties:
/// - Single entry point (only the first instruction can be a branch target)
/// - Single exit point (only the last instruction can be a branch or fall-through)
/// - No internal control flow changes
///
/// Basic blocks are fundamental units for control flow analysis, optimization,
/// and program understanding. They are constructed by the [`crate::assembly::decode_blocks`] function
/// during disassembly and used by various analysis algorithms.
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::BasicBlock;
///
/// // Create a new basic block
/// let block = BasicBlock::new(0, 0x1000, 0x500);
///
/// // Check if it's an entry block (no predecessors)
/// assert!(block.is_entry());
///
/// // Basic blocks start empty
/// assert_eq!(block.instructions.len(), 0);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// [`BasicBlock`] is [`std::marker::Send`] and [`std::marker::Sync`] as all fields are thread-safe types.
/// Multiple threads can safely read from the same block concurrently, but mutation requires
/// external synchronization.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Unique identifier for this block within the method
    pub id: usize,
    /// Relative virtual address where this block starts
    pub rva: u64,
    /// File offset where this block starts
    pub offset: usize,
    /// Total size in bytes of all instructions in this block
    pub size: usize,
    /// All instructions contained in this block, in execution order
    pub instructions: Vec<Instruction>,
    /// IDs of blocks that can transfer control to this block
    pub predecessors: Vec<usize>,
    /// IDs of blocks that this block can transfer control to. Ordered by the last
    /// instruction's flow: a conditional branch lists its target, then the path not taken;
    /// a `switch` lists one entry per case in order (cases sharing a target repeat it),
    /// then its default (the next block, see
    /// [`crate::assembly::Instruction::fall_through`]); a block that falls through lists
    /// the next block
    pub successors: Vec<usize>,
    /// Indices of exception handlers that cover this block (this block is in their try region)
    pub exceptions: Vec<usize>,
    /// If this block is an exception handler entry point, contains the handler info.
    /// This is used by stack simulation to determine the entry stack state.
    pub handler_entry: Option<HandlerEntryInfo>,
    /// IDs of exception handler blocks that can be reached from this block.
    /// These are implicit edges - any instruction in a protected block can
    /// potentially transfer to its handler on exception.
    pub exception_successors: Vec<usize>,
}

impl BasicBlock {
    /// Creates a new basic block with the specified properties.
    ///
    /// The block is initialized with empty instruction, predecessor, successor,
    /// and exception handler vectors. The size is set to 0 and will be updated
    /// as instructions are added.
    ///
    /// # Arguments
    ///
    /// * `id` - Unique identifier for this block within the method
    /// * `rva` - Relative virtual address where this block starts
    /// * `offset` - File offset where this block starts in bytes
    ///
    /// # Returns
    ///
    /// A new [`BasicBlock`] instance ready for instruction insertion.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::BasicBlock;
    ///
    /// // Create a block at the beginning of a method
    /// let entry_block = BasicBlock::new(0, 0x2000, 0x1000);
    /// assert_eq!(entry_block.id, 0);
    /// assert_eq!(entry_block.rva, 0x2000);
    /// assert_eq!(entry_block.offset, 0x1000);
    /// assert_eq!(entry_block.size, 0);
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn new(id: usize, rva: u64, offset: usize) -> Self {
        Self {
            id,
            rva,
            offset,
            size: 0,
            instructions: Vec::new(),
            predecessors: Vec::new(),
            successors: Vec::new(),
            exceptions: Vec::new(),
            handler_entry: None,
            exception_successors: Vec::new(),
        }
    }

    /// Returns a reference to the first instruction in this block.
    ///
    /// This is useful for analyzing the entry point of a basic block,
    /// checking for branch targets, or examining block-level properties.
    ///
    /// # Returns
    ///
    /// `Some(&`[`crate::assembly::Instruction`]`)` if the block contains at least one instruction,
    /// `None` if the block is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty block returns None
    /// assert!(block.instruction_first().is_none());
    ///
    /// // After adding instructions, returns the first one
    /// // block.instructions.push(some_instruction);
    /// // assert!(block.instruction_first().is_some());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn instruction_first(&self) -> Option<&Instruction> {
        self.instructions.first()
    }

    /// Returns a reference to the last instruction in this block.
    ///
    /// This is particularly important for control flow analysis as the
    /// last instruction determines how control exits the block (branch,
    /// fall-through, return, etc.). The [`crate::assembly::FlowType`] of the last
    /// instruction determines the block's control flow behavior.
    ///
    /// # Returns
    ///
    /// `Some(&`[`crate::assembly::Instruction`]`)` if the block contains at least one instruction,
    /// `None` if the block is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty block returns None
    /// assert!(block.instruction_last().is_none());
    ///
    /// // The last instruction determines block exit behavior
    /// // if let Some(last) = block.instruction_last() {
    /// //     println!("Block exits with: {:?}", last.flow_type);
    /// // }
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn instruction_last(&self) -> Option<&Instruction> {
        self.instructions.last()
    }

    /// Checks if this block is an entry block (has no predecessors).
    ///
    /// Entry blocks are special because they represent the start of execution
    /// paths. In methods, there's typically one main entry block, plus additional
    /// entry blocks for exception handlers.
    ///
    /// # Returns
    ///
    /// `true` if this block has no predecessors (is an entry point),
    /// `false` if other blocks can transfer control to this block.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // New blocks start as entry blocks
    /// assert!(block.is_entry());
    ///
    /// // Adding a predecessor makes it non-entry
    /// block.predecessors.push(1);
    /// assert!(!block.is_entry());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_entry(&self) -> bool {
        self.predecessors.is_empty()
    }

    /// Checks if this block is an exit block (terminates execution).
    ///
    /// Exit blocks end with instructions that don't fall through to
    /// other blocks, such as return statements or throw instructions.
    /// These blocks represent the end of execution paths. The determination
    /// is based on the [`crate::assembly::FlowType`] of the last instruction.
    ///
    /// # Returns
    ///
    /// `true` if the block's last instruction has [`crate::assembly::FlowType::Return`],
    /// [`crate::assembly::FlowType::Throw`] or [`crate::assembly::FlowType::MethodJump`]
    /// (control leaves the method), `false` if the block can transfer control to other
    /// blocks or is empty.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::BasicBlock;
    ///
    /// let mut block = BasicBlock::new(0, 0x2000, 0x1000);
    ///
    /// // Empty blocks are not exit blocks
    /// assert!(!block.is_exit());
    ///
    /// // Blocks ending with return, throw or jmp are exit blocks
    /// // (This example assumes you have a return instruction)
    /// // block.instructions.push(return_instruction);
    /// // assert!(block.is_exit());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    #[must_use]
    pub fn is_exit(&self) -> bool {
        if let Some(last_instr) = self.instruction_last() {
            matches!(
                last_instr.flow_type,
                FlowType::Return | FlowType::Throw | FlowType::MethodJump
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::factories::general::disassembler::create_sample_instruction;

    #[test]
    fn test_basic_block_new() {
        let block = BasicBlock::new(42, 0x2000, 0x1500);

        assert_eq!(block.id, 42);
        assert_eq!(block.rva, 0x2000);
        assert_eq!(block.offset, 0x1500);
        assert_eq!(block.size, 0);
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());
        assert!(block.exceptions.is_empty());
    }

    #[test]
    fn test_basic_block_new_zero_values() {
        let block = BasicBlock::new(0, 0, 0);

        assert_eq!(block.id, 0);
        assert_eq!(block.rva, 0);
        assert_eq!(block.offset, 0);
        assert_eq!(block.size, 0);
    }

    #[test]
    fn test_basic_block_new_max_values() {
        let block = BasicBlock::new(usize::MAX, u64::MAX, usize::MAX);

        assert_eq!(block.id, usize::MAX);
        assert_eq!(block.rva, u64::MAX);
        assert_eq!(block.offset, usize::MAX);
    }

    #[test]
    fn test_instruction_first_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.instruction_first().is_none());
    }

    #[test]
    fn test_instruction_first_single_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let instr = create_sample_instruction(FlowType::Sequential);
        block.instructions.push(instr);

        let first = block.instruction_first().unwrap();
        assert_eq!(first.flow_type, FlowType::Sequential);
    }

    #[test]
    fn test_instruction_first_multiple_instructions() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let first_instr = create_sample_instruction(FlowType::Sequential);
        let second_instr = create_sample_instruction(FlowType::ConditionalBranch);

        block.instructions.push(first_instr);
        block.instructions.push(second_instr);

        let first = block.instruction_first().unwrap();
        assert_eq!(first.flow_type, FlowType::Sequential);
    }

    #[test]
    fn test_instruction_last_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.instruction_last().is_none());
    }

    #[test]
    fn test_instruction_last_single_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let instr = create_sample_instruction(FlowType::Return);
        block.instructions.push(instr);

        let last = block.instruction_last().unwrap();
        assert_eq!(last.flow_type, FlowType::Return);
    }

    #[test]
    fn test_instruction_last_multiple_instructions() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let first_instr = create_sample_instruction(FlowType::Sequential);
        let last_instr = create_sample_instruction(FlowType::ConditionalBranch);

        block.instructions.push(first_instr);
        block.instructions.push(last_instr);

        let last = block.instruction_last().unwrap();
        assert_eq!(last.flow_type, FlowType::ConditionalBranch);
    }

    #[test]
    fn test_is_entry_new_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(block.is_entry());
    }

    #[test]
    fn test_is_entry_with_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        assert!(!block.is_entry());
    }

    #[test]
    fn test_is_entry_multiple_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        block.predecessors.push(2);
        block.predecessors.push(3);
        assert!(!block.is_entry());
    }

    #[test]
    fn test_is_entry_after_removing_predecessors() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block.predecessors.push(1);
        assert!(!block.is_entry());

        block.predecessors.clear();
        assert!(block.is_entry());
    }

    #[test]
    fn test_is_exit_empty_block() {
        let block = BasicBlock::new(0, 0x1000, 0x500);
        assert!(!block.is_exit());
    }

    #[test]
    fn test_is_exit_return_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let return_instr = create_sample_instruction(FlowType::Return);
        block.instructions.push(return_instr);

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_throw_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        let throw_instr = create_sample_instruction(FlowType::Throw);
        block.instructions.push(throw_instr);

        assert!(block.is_exit());
    }

    /// `jmp` leaves the method (ECMA-335 III.3.37), as `ret` and `throw` do.
    #[test]
    fn test_is_exit_method_jump_instruction() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block
            .instructions
            .push(create_sample_instruction(FlowType::MethodJump));

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_non_terminating_instructions() {
        let flow_types = [
            FlowType::Sequential,
            FlowType::ConditionalBranch,
            FlowType::UnconditionalBranch,
            FlowType::Call,
            FlowType::CallIndirect,
        ];

        for flow_type in &flow_types {
            let mut block = BasicBlock::new(0, 0x1000, 0x500);
            let instr = create_sample_instruction(*flow_type);
            block.instructions.push(instr);

            assert!(
                !block.is_exit(),
                "Block with {flow_type:?} should not be exit"
            );
        }
    }

    #[test]
    fn test_is_exit_multiple_instructions_last_return() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Call));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Return));

        assert!(block.is_exit());
    }

    #[test]
    fn test_is_exit_multiple_instructions_last_non_terminating() {
        let mut block = BasicBlock::new(0, 0x1000, 0x500);
        block
            .instructions
            .push(create_sample_instruction(FlowType::Return));
        block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));

        assert!(!block.is_exit());
    }

    #[test]
    fn test_basic_block_debug_format() {
        let block = BasicBlock::new(5, 0x3000, 0x2000);
        let debug_str = format!("{block:?}");

        assert!(debug_str.contains("BasicBlock"));
        assert!(debug_str.contains("id: 5"));
        assert!(debug_str.contains("rva: 12288")); // 0x3000 in decimal
        assert!(debug_str.contains("offset: 8192")); // 0x2000 in decimal
    }

    #[test]
    fn test_basic_block_clone() {
        let mut original = BasicBlock::new(1, 0x1000, 0x500);
        original.size = 42;
        original
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        original.predecessors.push(2);
        original.successors.push(3);
        original.exceptions.push(4);

        let cloned = original.clone();

        assert_eq!(cloned.id, original.id);
        assert_eq!(cloned.rva, original.rva);
        assert_eq!(cloned.offset, original.offset);
        assert_eq!(cloned.size, original.size);
        assert_eq!(cloned.instructions.len(), original.instructions.len());
        assert_eq!(cloned.predecessors, original.predecessors);
        assert_eq!(cloned.successors, original.successors);
        assert_eq!(cloned.exceptions, original.exceptions);
    }

    #[test]
    fn test_complex_control_flow_scenario() {
        // Test a more complex scenario with multiple blocks
        let mut entry_block = BasicBlock::new(0, 0x1000, 0x500);
        let mut branch_block = BasicBlock::new(1, 0x1010, 0x510);
        let mut exit_block = BasicBlock::new(2, 0x1020, 0x520);

        // Set up control flow relationships
        entry_block.successors = vec![1, 2];
        branch_block.predecessors = vec![0];
        branch_block.successors = vec![2];
        exit_block.predecessors = vec![0, 1];

        // Add instructions
        entry_block
            .instructions
            .push(create_sample_instruction(FlowType::ConditionalBranch));
        branch_block
            .instructions
            .push(create_sample_instruction(FlowType::Sequential));
        exit_block
            .instructions
            .push(create_sample_instruction(FlowType::Return));

        // Verify properties
        assert!(entry_block.is_entry());
        assert!(!entry_block.is_exit());

        assert!(!branch_block.is_entry());
        assert!(!branch_block.is_exit());

        assert!(!exit_block.is_entry());
        assert!(exit_block.is_exit());
    }

    #[test]
    fn test_exception_handling_blocks() {
        let mut try_block = BasicBlock::new(0, 0x1000, 0x500);
        let mut catch_block = BasicBlock::new(1, 0x1010, 0x510);

        // Set up exception handling
        try_block.exceptions = vec![0, 1];
        catch_block.exceptions = vec![0];

        // Both blocks can still be entry blocks despite exception handling
        assert!(try_block.is_entry());
        assert!(catch_block.is_entry());

        // Exception information is preserved
        assert_eq!(try_block.exceptions.len(), 2);
        assert_eq!(catch_block.exceptions.len(), 1);
    }

    #[test]
    fn test_block_size_and_offset_boundaries() {
        let mut block = BasicBlock::new(0, u64::MAX, usize::MAX);
        block.size = usize::MAX;

        assert_eq!(block.rva, u64::MAX);
        assert_eq!(block.offset, usize::MAX);
        assert_eq!(block.size, usize::MAX);
    }

    #[test]
    fn test_empty_vectors_behavior() {
        let block = BasicBlock::new(0, 0x1000, 0x500);

        // Test that empty vectors behave correctly
        assert!(block.instructions.is_empty());
        assert!(block.predecessors.is_empty());
        assert!(block.successors.is_empty());
        assert!(block.exceptions.is_empty());

        // Test capacity (should be 0 for new empty vectors)
        assert_eq!(block.instructions.capacity(), 0);
        assert_eq!(block.predecessors.capacity(), 0);
        assert_eq!(block.successors.capacity(), 0);
        assert_eq!(block.exceptions.capacity(), 0);
    }
}
