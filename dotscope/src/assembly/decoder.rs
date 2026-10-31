//! CIL instruction decoding and disassembly utilities.
//!
//! This module provides the core decoding engine for transforming raw CIL bytecode into
//! structured instruction sequences and basic blocks. It implements the complete ECMA-335
//! disassembly pipeline, from individual instruction parsing to complex control flow analysis
//! with exception handler integration.
//!
//! # Architecture
//!
//! The module is organized around a stateful [`crate::assembly::decoder::Decoder`] that
//! maintains disassembly context while processing bytecode. Public functions provide different
//! levels of abstraction, from single instruction decoding to complete method disassembly
//! with basic block construction and control flow analysis.
//!
//! # Key Components
//!
//! - [`crate::assembly::decoder::decode_instruction`] - Core single instruction decoder
//! - [`crate::assembly::decoder::decode_stream`] - Linear instruction sequence decoder
//! - [`crate::assembly::decoder::decode_blocks`] - Complete control flow analysis with basic blocks
//! - [`crate::assembly::decoder::decode_method`] - Internal method-level disassembly integration
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::{Parser, assembly::{decode_instruction, decode_stream, decode_blocks}};
//!
//! // Decode a single instruction
//! let code = [0x2A]; // ret
//! let mut parser = Parser::new(&code);
//! let instr = decode_instruction(&mut parser, 0x1000)?;
//! assert_eq!(instr.mnemonic, "ret");
//!
//! // Decode a linear instruction stream  
//! let code = [0x00, 0x2A]; // nop, ret
//! let mut parser = Parser::new(&code);
//! let instrs = decode_stream(&mut parser, 0x1000)?;
//! assert_eq!(instrs.len(), 2);
//!
//! // Decode with control flow analysis
//! let code = [0x00, 0x2A]; // nop, ret
//! let blocks = decode_blocks(&code, 0, 0x1000, None)?;
//! assert_eq!(blocks.len(), 1);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::assembly::instruction`] - Defines instruction structure and metadata
//! - [`crate::assembly::block`] - Provides basic block representation for control flow
//! - [`crate::file::parser`] - Supplies low-level bytecode parsing capabilities
//! - [`crate::metadata::method`] - Supports method-level disassembly and caching

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{Arc, OnceLock},
};

use dashmap::DashMap;

use crate::{
    assembly::{
        BasicBlock, FlowType, HandlerEntryInfo, Immediate, Instruction, Operand, OperandType,
        StackBehavior, INSTRUCTIONS, INSTRUCTIONS_FE,
    },
    file::{parser::Parser, File},
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags, Method},
        token::Token,
    },
    utils::VisitedMap,
    Result,
};

/// A stateful decoder instance that exposes complex disassembly algorithms.
///
/// The [`Decoder`] maintains context during CIL bytecode disassembly, tracking visited
/// addresses and building control flow relationships between basic blocks. It provides
/// the core implementation for all higher-level disassembly functions.
///
/// # Thread Safety
///
/// [`Decoder`] is not [`std::marker::Send`] or [`std::marker::Sync`] due to mutable references
/// to parser state. Each thread should use its own decoder instance.
struct Decoder<'a> {
    /// Collection of decoded basic blocks
    blocks: Vec<BasicBlock>,
    /// Exception handlers that affect control flow (if any)
    exceptions: Option<&'a [ExceptionHandler]>,
    /// Which bytes of this method's code have been decoded, indexed from its
    /// first byte
    visited: VisitedMap,
    /// Parser for reading instruction bytes from the method body
    parser: &'a mut Parser<'a>,
    /// Current block identifier being processed
    block_id: usize,
    /// Starting offset within the method body
    offset_start: usize,
    /// Starting relative virtual address
    rva_start: usize,
    /// Index from each block's start RVA to its index in `blocks`.
    ///
    /// `find_block_containing_rva` is called once per branch target. A scan over every block
    /// would make block construction quadratic in a method whose branches are dense, and block
    /// count is bounded only by the size of the method body. This `BTreeMap` answers the
    /// containment query in O(log B) via `range(..=rva).next_back()`.
    ///
    /// Indices stay valid because blocks are only ever *appended*: `split_block_at` pushes the
    /// tail as a new block rather than inserting it, so no existing index shifts.
    block_starts: BTreeMap<u64, usize>,
    /// Exclusive upper bound on offsets this decoder may read.
    ///
    /// The parser spans the whole file image so that offsets stay file-absolute - the
    /// `VisitedMap` is shared across methods and keyed by those offsets, so a per-method
    /// window would make different methods collide at the same relative offset. Decoding is
    /// instead bounded here, at the end of *this* method's declared `size_code`.
    ///
    /// Without it every bound in this decoder was the file length, so a method whose last
    /// in-range instruction is not a terminator kept decoding into the next method, into the
    /// metadata streams and into resources.
    max_offset: usize,
}

impl<'a> Decoder<'a> {
    /// Whether the byte at file offset `offset` was already decoded. The map
    /// covers this method's code alone, indexed from its first byte.
    fn is_visited(&self, offset: usize) -> bool {
        offset
            .checked_sub(self.offset_start)
            .is_some_and(|index| self.visited.get(index))
    }

    /// Marks `len` bytes from file offset `offset` as decoded, as far as they
    /// lie within this method's code; an instruction running past the end is
    /// malformed, and its tail is nobody's to mark.
    fn mark_visited(&self, offset: usize, len: usize) {
        let Some(index) = offset.checked_sub(self.offset_start) else {
            return;
        };
        let window = self.max_offset.saturating_sub(self.offset_start);
        let len = len.min(window.saturating_sub(index));
        if len > 0 {
            self.visited.set_range(index, true, len);
        }
    }

    /// Create a new stateful decoder for CIL bytecode disassembly.
    ///
    /// Initializes a decoder instance for processing CIL bytecode into basic blocks.
    /// The decoder maintains state during disassembly, tracking visited addresses
    /// and building control flow relationships between basic blocks.
    ///
    /// # Arguments
    ///
    /// * `parser` - The [`crate::file::parser::Parser`] that wraps the byte stream to process
    /// * `offset` - The offset at which the first instruction starts (must be in range of parser)
    /// * `rva` - The relative virtual address of the first instruction
    /// * `exceptions` - Optional information about exception handlers from method metadata
    /// * `visited` - [`crate::utils::VisitedMap`] covering the bytes from `offset` to
    ///   `max_offset`, for tracking disassembly progress
    ///
    /// # Returns
    ///
    /// Returns a new [`crate::assembly::decoder::Decoder`] instance ready for block decoding,
    /// or an error if the offset is out of bounds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Parse`] carrying [`crate::ParseFailure::OutOfBounds`] if the offset exceeds the parser's data length.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn new(
        parser: &'a mut Parser<'a>,
        offset: usize,
        rva: usize,
        exceptions: Option<&'a [ExceptionHandler]>,
        visited: VisitedMap,
        max_offset: usize,
    ) -> Result<Self> {
        if offset > parser.len() {
            return Err(out_of_bounds_error!());
        }

        let max_offset = max_offset.min(parser.len());

        Ok(Decoder {
            blocks: Vec::new(),
            exceptions,
            visited,
            parser,
            block_id: 0,
            offset_start: offset,
            rva_start: rva,
            block_starts: BTreeMap::new(),
            max_offset,
        })
    }

    /// Returns a reference to the decoded basic blocks.
    ///
    /// This method provides read-only access to the basic blocks that have been
    /// decoded so far. The blocks are ordered by their position in the method body
    /// and contain complete instruction sequences with control flow relationships.
    ///
    /// # Returns
    ///
    /// A slice containing all decoded [`crate::assembly::BasicBlock`] instances.
    ///
    /// # Examples
    ///
    /// The `examples::blocks_example` test in this module runs this example.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn blocks(&self) -> &[BasicBlock] {
        &self.blocks
    }

    /// Consumes the decoder and returns ownership of the decoded blocks.
    ///
    /// This method transfers ownership of the decoded basic blocks from the decoder
    /// to the caller, consuming the decoder in the process. This is more efficient
    /// than cloning the blocks when transferring ownership is desired.
    ///
    /// # Usage in Method Integration
    ///
    /// This method is primarily used internally by [`crate::assembly::decode_method`] to efficiently
    /// transfer decoded blocks to the [`crate::metadata::method::Method`]'s `OnceLock<Vec<BasicBlock>>` field:
    ///
    /// ```no_run
    /// // Internal usage pattern
    /// let blocks = decoder.into_blocks();
    /// method.blocks.set(blocks);
    /// ```
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::assembly::decode_blocks;
    ///
    /// let bytecode = [0x00, 0x2A]; // nop, ret
    /// let blocks = decode_blocks(&bytecode, 0, 0x1000, None)?;
    ///
    /// // blocks now owns the decoded basic blocks
    /// println!("Decoded {} basic blocks", blocks.len());
    /// # Ok::<(), dotscope::Error>(())
    /// ```
    ///
    /// Note: [`crate::assembly::decode_blocks`] function internally uses this method to return ownership
    /// of the blocks to the caller.
    ///
    /// # Thread Safety
    ///
    /// This method is thread-safe and can be called concurrently from multiple threads.
    pub fn into_blocks(self) -> Vec<BasicBlock> {
        self.blocks
    }

    /// Decode all accessible blocks that are contained in this parser.
    ///
    /// This method implements a single-pass control flow analysis algorithm that
    /// discovers and decodes all reachable basic blocks in the method body. It uses
    /// a work-list approach where new blocks are discovered during decoding and
    /// added to the processing queue.
    ///
    /// # Algorithm
    ///
    /// 1. Initialize entry points from exception handlers (try blocks, catch handlers, filters)
    /// 2. Create the initial block at the method entry point
    /// 3. Process blocks in work-list fashion:
    ///    - Decode instructions sequentially until a control flow boundary
    ///    - When branch targets are discovered, create new blocks or split existing ones
    ///    - Track all entry points to detect block boundaries
    /// 4. Clean up empty blocks (unreachable code)
    /// 5. Sort blocks by RVA and reassign IDs for consistent ordering
    /// 6. Wire up control flow edges (successors/predecessors)
    ///
    /// # Block Splitting
    ///
    /// When a branch target falls in the middle of an already-decoded block, that
    /// block is split immediately at the target address. This ensures every branch
    /// target is the start of its own basic block, which is required for correct
    /// control flow graph construction.
    ///
    /// # Errors
    ///
    /// Returns an error if instruction decoding fails or if the parser encounters
    /// invalid bytecode.
    fn decode_blocks(&mut self) -> Result<()> {
        let mut entry_points: HashSet<u64> = HashSet::new();

        // Create the first block at method entry
        self.block_starts.insert(self.rva_start as u64, 0);
        self.blocks
            .push(BasicBlock::new(0, self.rva_start as u64, self.offset_start));
        entry_points.insert(self.rva_start as u64);

        // Create blocks for exception handler entry points
        // These must be created explicitly as they may not be reachable via normal control flow
        if let Some(exceptions) = self.exceptions {
            // Collect entry-point candidates first (handler/filter/try) to avoid
            // borrow conflicts between iterating `self.exceptions` and mutating self.
            let rva_base = self.rva_start as u64;
            let mut candidates: Vec<(u64, u32)> =
                Vec::with_capacity(exceptions.len().saturating_mul(3));
            for handler in exceptions {
                let handler_rva = rva_base
                    .checked_add(u64::from(handler.handler_offset))
                    .ok_or(out_of_bounds_error!())?;
                candidates.push((handler_rva, handler.handler_offset));
                if handler.filter_offset > 0 {
                    let filter_rva = rva_base
                        .checked_add(u64::from(handler.filter_offset))
                        .ok_or(out_of_bounds_error!())?;
                    candidates.push((filter_rva, handler.filter_offset));
                }
                let try_rva = rva_base
                    .checked_add(u64::from(handler.try_offset))
                    .ok_or(out_of_bounds_error!())?;
                candidates.push((try_rva, handler.try_offset));
            }

            for (entry_rva, entry_offset_u32) in candidates {
                if entry_points.contains(&entry_rva) {
                    continue;
                }
                let entry_offset = self
                    .offset_start
                    .checked_add(entry_offset_u32 as usize)
                    .ok_or(out_of_bounds_error!())?;
                if entry_offset < self.max_offset && !self.is_visited(entry_offset) {
                    self.block_starts.insert(entry_rva, self.blocks.len());
                    self.blocks
                        .push(BasicBlock::new(self.blocks.len(), entry_rva, entry_offset));
                    entry_points.insert(entry_rva);
                }
            }
        }

        while self.block_id < self.blocks.len() {
            self.decode_single_block(&mut entry_points)?;
            self.block_id = self.block_id.checked_add(1).ok_or(out_of_bounds_error!())?;
        }

        self.blocks.retain(|b| !b.instructions.is_empty());
        self.blocks.sort_by_key(|b| b.rva);

        for (idx, block) in self.blocks.iter_mut().enumerate() {
            block.id = idx;
        }

        self.process_exception_handlers()?;
        self.wire_control_flow_edges();
        self.wire_exception_edges()?;

        Ok(())
    }

    /// Decode a single basic block starting at the current block ID.
    ///
    /// This method decodes instructions sequentially from the block's starting offset
    /// until it encounters a control flow boundary (branch, return, throw, etc.) or
    /// reaches an existing block's entry point.
    ///
    /// # Control Flow Handling
    ///
    /// - **Conditional branches**: Both branch targets and fall-through paths become
    ///   new entry points. The block terminates after the branch instruction.
    /// - **Unconditional branches/switches**: All targets become entry points. No
    ///   fall-through path exists.
    /// - **Leave instructions**: Target becomes an entry point (used in exception handling).
    /// - **Return/Throw/EndFinally**: Terminal instructions that end the block with
    ///   no successors.
    /// - **Sequential/Call**: Continue decoding in the same block.
    ///
    /// # Block Boundary Detection
    ///
    /// If the decoder reaches an RVA that is already registered as an entry point
    /// (from a previous branch target), the current block ends and the remaining
    /// instructions belong to the other block.
    ///
    /// # Arguments
    ///
    /// * `entry_points` - Mutable set of known block entry points (RVAs). New entry
    ///   points discovered during decoding are added to this set.
    ///
    /// # Errors
    ///
    /// Returns an error if the block's offset is out of bounds or if instruction
    /// decoding fails.
    fn decode_single_block(&mut self, entry_points: &mut HashSet<u64>) -> Result<()> {
        let block_id = self.block_id;

        let (block_offset, block_rva) = {
            let block = self.blocks.get(block_id).ok_or(out_of_bounds_error!())?;
            (block.offset, block.rva)
        };

        // A branch can only land inside the method's own code.
        if block_offset > self.max_offset || block_offset < self.offset_start {
            return Err(out_of_bounds_error!());
        }

        if self.is_visited(block_offset) {
            return Ok(());
        }

        self.parser.seek(block_offset)?;

        let mut current_offset = block_offset;
        let mut current_rva = block_rva;

        loop {
            if current_offset >= self.max_offset {
                break;
            }

            if current_rva != block_rva && entry_points.contains(&current_rva) {
                // We've reached the start of another block - stop here
                break;
            }

            let instruction = decode_instruction(self.parser, current_rva)?;
            let instr_size = usize::try_from(instruction.size).map_err(|_| {
                malformed_error!(format!(
                    "instruction size {} exceeds platform limits at RVA 0x{:x}",
                    instruction.size, current_rva
                ))
            })?;

            self.mark_visited(current_offset, instr_size);

            {
                let block = self
                    .blocks
                    .get_mut(block_id)
                    .ok_or(out_of_bounds_error!())?;
                block.size = block
                    .size
                    .checked_add(instr_size)
                    .ok_or_else(|| malformed_error!("block size overflow"))?;
                block.instructions.push(instruction.clone());
            }

            match instruction.flow_type {
                FlowType::ConditionalBranch => {
                    for &target_rva in &instruction.branch_targets {
                        self.add_entry_point(target_rva, entry_points);
                    }

                    let fall_through_rva = current_rva
                        .checked_add(instruction.size)
                        .ok_or_else(|| malformed_error!("fall-through RVA overflow"))?;
                    self.add_entry_point(fall_through_rva, entry_points);

                    break;
                }
                FlowType::UnconditionalBranch | FlowType::Leave => {
                    for &target_rva in &instruction.branch_targets {
                        self.add_entry_point(target_rva, entry_points);
                    }
                    break;
                }
                FlowType::Switch => {
                    // Switch has branch targets AND a fall-through (default)
                    for &target_rva in &instruction.branch_targets {
                        self.add_entry_point(target_rva, entry_points);
                    }
                    // Add fall-through as entry point for the default case
                    let fall_through_rva = current_rva
                        .checked_add(instruction.size)
                        .ok_or_else(|| malformed_error!("fall-through RVA overflow"))?;
                    self.add_entry_point(fall_through_rva, entry_points);
                    break;
                }
                FlowType::Return | FlowType::Throw | FlowType::EndFinally => {
                    break;
                }
                _ => {
                    // Sequential instruction - continue
                }
            }

            current_offset = current_offset
                .checked_add(instr_size)
                .ok_or_else(|| malformed_error!("instruction offset overflow"))?;
            current_rva = current_rva
                .checked_add(instruction.size)
                .ok_or_else(|| malformed_error!("instruction RVA overflow"))?;
        }

        Ok(())
    }

    /// Register a new block entry point at the given RVA.
    ///
    /// This method handles the discovery of a new control flow target (branch destination,
    /// fall-through path, or exception handler). It ensures that a basic block exists
    /// starting at the given RVA.
    ///
    /// # Block Creation vs Splitting
    ///
    /// - If the RVA is not inside any existing block, a new empty block is created
    ///   and added to the work list for later decoding.
    /// - If the RVA falls in the middle of an already-decoded block, that block is
    ///   split at the RVA. The first part retains the original block's instructions
    ///   up to (but not including) the split point, and a new block is created with
    ///   the remaining instructions.
    ///
    /// # Bounds Checking
    ///
    /// Entry points outside the valid method body range are silently ignored. This
    /// handles edge cases like branches to addresses before the method start or
    /// beyond the method end.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address of the new entry point
    /// * `entry_points` - Mutable set tracking all known entry points to avoid
    ///   duplicate processing
    fn add_entry_point(&mut self, rva: u64, entry_points: &mut HashSet<u64>) {
        if rva < self.rva_start as u64 {
            return;
        }

        if entry_points.contains(&rva) {
            return;
        }

        let Some(delta) = rva.checked_sub(self.rva_start as u64) else {
            return;
        };
        let Ok(relative_offset) = usize::try_from(delta) else {
            return; // RVA delta too large for this platform
        };
        let Some(offset) = self.offset_start.checked_add(relative_offset) else {
            return;
        };
        if offset >= self.max_offset {
            return;
        }

        if let Some((block_idx, split_instr_idx)) = self.find_block_containing_rva(rva) {
            self.split_block_at(block_idx, split_instr_idx, rva, offset);
        } else {
            let new_block = BasicBlock::new(self.blocks.len(), rva, offset);
            self.block_starts.insert(rva, self.blocks.len());
            self.blocks.push(new_block);
        }

        entry_points.insert(rva);
    }

    /// Find a block that contains the given RVA in its interior (not at its start).
    ///
    /// This method searches through all decoded blocks to find one where the given
    /// RVA falls strictly inside the block's address range. This is used to detect
    /// when a branch target points to the middle of an already-decoded block,
    /// which requires splitting that block.
    ///
    /// # Returns
    ///
    /// - `Some((block_index, instruction_index))` if a block contains the RVA, where
    ///   `instruction_index` is the index of the instruction that starts at the RVA
    /// - `None` if no block contains the RVA (it's either at a block start, outside
    ///   all blocks, or doesn't align with an instruction boundary)
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to search for
    fn find_block_containing_rva(&self, rva: u64) -> Option<(usize, usize)> {
        // Already a block boundary - nothing to split.
        if self.block_starts.contains_key(&rva) {
            return None;
        }

        // The only block that can contain `rva` in its interior is the one with the greatest
        // start below it, since blocks do not overlap.
        let (_, &block_idx) = self.block_starts.range(..rva).next_back()?;
        let block = self.blocks.get(block_idx)?;

        let block_end_rva = block.rva.checked_add(block.size as u64)?;
        if rva > block.rva && rva < block_end_rva {
            for (instr_idx, instr) in block.instructions.iter().enumerate() {
                if instr.rva == rva {
                    return Some((block_idx, instr_idx));
                }
            }
        }

        None
    }

    /// Split a basic block at the specified instruction index.
    ///
    /// This method divides an existing block into two parts when a branch target
    /// is discovered that points to the middle of the block. The original block
    /// is truncated to contain only instructions before the split point, and a
    /// new block is created with the remaining instructions.
    ///
    /// # Block Modification
    ///
    /// - The original block (`block_idx`) keeps instructions `[0..split_instr_idx)`
    /// - A new block is created with instructions `[split_instr_idx..]`
    /// - The new block inherits exception handler associations from the original
    /// - Block sizes are recalculated for both blocks
    ///
    /// # Arguments
    ///
    /// * `block_idx` - Index of the block to split in `self.blocks`
    /// * `split_instr_idx` - Index of the first instruction for the new block
    /// * `rva` - RVA of the split point (for the new block's starting address)
    /// * `offset` - File offset of the split point (for the new block's offset)
    ///
    /// # Panics
    ///
    /// Does not panic, but silently returns if `split_instr_idx` is 0 (nothing to split).
    fn split_block_at(
        &mut self,
        block_idx: usize,
        split_instr_idx: usize,
        rva: u64,
        offset: usize,
    ) {
        if split_instr_idx == 0 {
            return;
        }

        // Create new block with instructions from split point onwards
        self.block_starts.insert(rva, self.blocks.len());
        let mut new_block = BasicBlock::new(self.blocks.len(), rva, offset);
        let Some(orig) = self.blocks.get(block_idx) else {
            return;
        };
        let Some(tail) = orig.instructions.get(split_instr_idx..) else {
            return;
        };
        new_block.instructions = tail.to_vec();
        new_block.size = Self::compute_instructions_size(&new_block.instructions);
        new_block.exceptions.clone_from(&orig.exceptions);

        // Truncate the original block
        let Some(orig_mut) = self.blocks.get_mut(block_idx) else {
            return;
        };
        orig_mut.instructions.truncate(split_instr_idx);
        orig_mut.size = Self::compute_instructions_size(&orig_mut.instructions);

        self.blocks.push(new_block);
    }

    /// Compute the total size of a slice of instructions with overflow protection.
    ///
    /// This method safely sums instruction sizes using saturating arithmetic to prevent
    /// overflow from malicious or corrupted input. Each instruction's `size` field is
    /// converted from `u64` to `usize`, clamping to `usize::MAX` if the value exceeds
    /// platform limits.
    ///
    /// # Arguments
    ///
    /// * `instructions` - Slice of instructions to sum sizes for
    ///
    /// # Returns
    ///
    /// Total size in bytes, saturating at `usize::MAX` if overflow would occur.
    fn compute_instructions_size(instructions: &[Instruction]) -> usize {
        instructions.iter().fold(0usize, |acc, instr| {
            let size = usize::try_from(instr.size).unwrap_or(usize::MAX);
            acc.saturating_add(size)
        })
    }

    /// Associate exception handlers with their corresponding basic blocks.
    ///
    /// This method iterates through all exception handlers defined for the method
    /// and performs two key tasks:
    ///
    /// 1. **Mark protected blocks**: Each block in a try region is marked with the
    ///    handler's index in `block.exceptions`.
    ///
    /// 2. **Mark handler entry blocks**: The first block of each handler is marked
    ///    with `HandlerEntryInfo` containing the handler type. This is crucial for
    ///    stack simulation - catch/filter handlers start with the exception object
    ///    on the stack, while finally/fault handlers start with an empty stack.
    ///
    /// # Handler Association
    ///
    /// A block is associated with an exception handler if the block's starting RVA
    /// falls within the try region's address range `[try_offset, try_offset + try_length)`.
    /// Multiple handlers can be associated with a single block (nested try blocks).
    ///
    /// # Note
    ///
    /// This method should be called after all blocks have been decoded and before
    /// control flow edges are wired, as the exception associations may affect
    /// control flow analysis.
    fn process_exception_handlers(&mut self) -> Result<()> {
        let Some(exceptions) = self.exceptions else {
            return Ok(());
        };

        // Build a map from RVA to block index for handler entry detection
        let rva_to_block: HashMap<u64, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.rva, idx))
            .collect();

        // Exception handler offsets are relative to IL code start.
        // Add base RVA to convert to absolute RVA for block lookup.
        let base_rva = self.rva_start as u64;

        for (handler_idx, handler) in exceptions.iter().enumerate() {
            let try_start = base_rva
                .checked_add(u64::from(handler.try_offset))
                .ok_or_else(|| malformed_error!("try_offset RVA overflow"))?;
            let try_end = try_start
                .checked_add(u64::from(handler.try_length))
                .ok_or_else(|| malformed_error!("try region end RVA overflow"))?;

            // Mark blocks in the try region.
            //
            // `self.blocks` is sorted by RVA, so binary-search the covered range instead of
            // scanning every block per handler: with H handlers whose try ranges span the
            // method, the scan was O(H·B), and B is bounded only by the method body's size.
            let lo = self.blocks.partition_point(|b| b.rva < try_start);
            let hi = self.blocks.partition_point(|b| b.rva < try_end);
            if let Some(covered) = self.blocks.get_mut(lo..hi) {
                for block in covered {
                    block.exceptions.push(handler_idx);
                }
            }

            // Mark handler entry block
            let handler_rva = base_rva
                .checked_add(u64::from(handler.handler_offset))
                .ok_or_else(|| malformed_error!("handler_offset RVA overflow"))?;
            if let Some(&handler_block_idx) = rva_to_block.get(&handler_rva) {
                if let Some(b) = self.blocks.get_mut(handler_block_idx) {
                    b.handler_entry = Some(HandlerEntryInfo::new(handler_idx, handler.flags));
                }
            }

            // Mark filter entry block (for filter handlers)
            if handler.flags == ExceptionHandlerFlags::FILTER && handler.filter_offset > 0 {
                let filter_rva = base_rva
                    .checked_add(u64::from(handler.filter_offset))
                    .ok_or_else(|| malformed_error!("filter_offset RVA overflow"))?;
                if let Some(&filter_block_idx) = rva_to_block.get(&filter_rva) {
                    if let Some(b) = self.blocks.get_mut(filter_block_idx) {
                        b.handler_entry = Some(HandlerEntryInfo::new(
                            handler_idx,
                            ExceptionHandlerFlags::FILTER,
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    /// Wire exception edges from protected blocks to their handler blocks.
    ///
    /// For each block in a protected (try) region, adds an exception successor
    /// edge to the handler block. This represents the implicit control flow
    /// that occurs when an instruction throws an exception.
    ///
    /// # Exception Control Flow
    ///
    /// Unlike normal control flow edges, exception edges are "implicit" - any
    /// instruction in a protected region can potentially transfer control to
    /// the handler. For analysis purposes, we model this as an edge from the
    /// block to the handler entry block.
    fn wire_exception_edges(&mut self) -> Result<()> {
        let Some(exceptions) = self.exceptions else {
            return Ok(());
        };

        // Build a map from RVA to block index
        let rva_to_block: HashMap<u64, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.rva, idx))
            .collect();

        // Exception handler offsets are relative to IL code start.
        // Add base RVA to convert to absolute RVA for block lookup.
        let base_rva = self.rva_start as u64;

        // For each handler, wire edges from protected blocks to handler blocks
        for handler in exceptions {
            let handler_rva = base_rva
                .checked_add(u64::from(handler.handler_offset))
                .ok_or_else(|| malformed_error!("handler_offset RVA overflow"))?;
            let Some(&handler_block_idx) = rva_to_block.get(&handler_rva) else {
                continue;
            };

            let try_start = base_rva
                .checked_add(u64::from(handler.try_offset))
                .ok_or_else(|| malformed_error!("try_offset RVA overflow"))?;
            let try_end = try_start
                .checked_add(u64::from(handler.try_length))
                .ok_or_else(|| malformed_error!("try region end RVA overflow"))?;

            // Same binary-searched range as `process_exception_handlers`. Duplicates are
            // removed in one pass afterwards rather than by a linear `contains` per push,
            // which made this O(B·H²) - each push scanned successors already accumulated.
            let lo = self.blocks.partition_point(|b| b.rva < try_start);
            let hi = self.blocks.partition_point(|b| b.rva < try_end);
            if let Some(covered) = self.blocks.get_mut(lo..hi) {
                for block in covered {
                    block.exception_successors.push(handler_block_idx);
                }
            }
        }

        // Deduplicate while preserving first-occurrence order, which encodes handler priority -
        // sorting would reorder the handler search.
        let mut seen: HashSet<usize> = HashSet::new();
        for block in &mut self.blocks {
            seen.clear();
            block.exception_successors.retain(|idx| seen.insert(*idx));
        }

        Ok(())
    }

    /// Wire up control flow edges (successors/predecessors) between blocks.
    ///
    /// This method is called after all blocks have been decoded and exception handlers
    /// have been processed. It analyzes the last instruction of each block to determine
    /// its control flow successors, building a complete control flow graph.
    ///
    /// # Edge Types
    ///
    /// The method handles various control flow patterns:
    /// - **Sequential/Call**: Fall through to the next block by address
    /// - **Conditional branches**: Both the branch target and fall-through become successors
    /// - **Unconditional branches**: Single successor at the branch target
    /// - **Switch statements**: Multiple successors for each case target
    /// - **Return/Throw**: No successors (terminal blocks)
    /// - **Leave**: Single successor outside the protected region
    ///
    /// # Bidirectional Edges
    ///
    /// For each successor relationship established, the corresponding predecessor
    /// relationship is also recorded. This enables both forward and backward
    /// traversal of the control flow graph.
    fn wire_control_flow_edges(&mut self) {
        let rva_to_block: HashMap<u64, usize> = self
            .blocks
            .iter()
            .enumerate()
            .map(|(idx, block)| (block.rva, idx))
            .collect();

        for block_idx in 0..self.blocks.len() {
            let successors = self.compute_block_successors(block_idx, &rva_to_block);

            if let Some(b) = self.blocks.get_mut(block_idx) {
                b.successors.clone_from(&successors);
            }

            for &succ_idx in &successors {
                if let Some(b) = self.blocks.get_mut(succ_idx) {
                    b.predecessors.push(block_idx);
                }
            }
        }
    }

    /// Compute the successor block indices for a given block.
    ///
    /// This method analyzes the last instruction of a block to determine which
    /// blocks can be reached via control flow from this block. The successors
    /// are determined based on the instruction's flow type and branch targets.
    ///
    /// # Flow Type Handling
    ///
    /// | Flow Type | Successors |
    /// |-----------|------------|
    /// | Return/Throw | None (terminal) |
    /// | UnconditionalBranch | Branch target only |
    /// | ConditionalBranch | Branch target + fall-through |
    /// | Switch | All case targets |
    /// | Leave | Leave target |
    /// | EndFinally | None (dynamic return) |
    /// | Sequential/Call | Fall-through to next block |
    ///
    /// # Arguments
    ///
    /// * `block_idx` - Index of the block in `self.blocks`
    /// * `rva_to_block` - Map from RVA to block index for target resolution
    ///
    /// # Returns
    ///
    /// A vector of block indices representing all possible control flow successors.
    /// The vector may be empty for terminal blocks (return, throw, endfinally).
    fn compute_block_successors(
        &self,
        block_idx: usize,
        rva_to_block: &HashMap<u64, usize>,
    ) -> Vec<usize> {
        let Some(block) = self.blocks.get(block_idx) else {
            return vec![];
        };
        let Some(last_instr) = block.instructions.last() else {
            return vec![];
        };
        let fall_through_rva = block.rva.checked_add(block.size as u64);

        match last_instr.flow_type {
            FlowType::Return | FlowType::Throw => {
                // No successors for terminal instructions
                vec![]
            }
            FlowType::UnconditionalBranch => {
                // Single successor: the branch target
                last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect()
            }
            FlowType::ConditionalBranch => {
                // Two successors: branch target (first) and fall-through (second)
                let mut successors = Vec::with_capacity(2);

                // Add branch target(s)
                for &target_rva in &last_instr.branch_targets {
                    if let Some(&target_idx) = rva_to_block.get(&target_rva) {
                        successors.push(target_idx);
                    }
                }

                // Add fall-through target (instruction immediately after this block)
                if let Some(rva) = fall_through_rva {
                    if let Some(&fall_through_idx) = rva_to_block.get(&rva) {
                        successors.push(fall_through_idx);
                    }
                }

                successors
            }
            FlowType::Switch => {
                // Multiple successors from switch targets + fall-through (default)
                let mut successors: Vec<usize> = last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect();

                // Add fall-through as the default (last successor)
                if let Some(rva) = fall_through_rva {
                    if let Some(&fall_through_idx) = rva_to_block.get(&rva) {
                        successors.push(fall_through_idx);
                    }
                }

                successors
            }
            FlowType::Leave => {
                // Leave instruction jumps to target outside protected region
                last_instr
                    .branch_targets
                    .iter()
                    .filter_map(|&target_rva| rva_to_block.get(&target_rva).copied())
                    .collect()
            }
            FlowType::EndFinally => {
                // EndFinally returns to caller of finally block - no static successors
                vec![]
            }
            FlowType::Sequential | FlowType::Call => {
                // Fall through to next block
                fall_through_rva
                    .and_then(|rva| rva_to_block.get(&rva).copied())
                    .map(|idx| vec![idx])
                    .unwrap_or_default()
            }
        }
    }
}

/// Method bodies decoded while loading one assembly, by RVA.
///
/// What a body decodes to depends only on the body: its IL and the exception
/// clauses stored with it. ECMA-335 lets several methods name the same body,
/// so each body is decoded once, by whichever method reaches it first, and
/// every other method naming it takes that result. Decoding it again per
/// method would only repeat the work.
#[derive(Default)]
pub struct DecodedBodies {
    by_rva: DashMap<u32, Arc<OnceLock<Result<Vec<BasicBlock>>>>>,
}

impl DecodedBodies {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Disassembles a method's body into basic blocks and stores them on the method.
///
/// The body is decoded once per RVA through `bodies`; a method sharing its
/// body with another one gets a copy of the same blocks.
///
/// # Arguments
///
/// * `method` - The [`crate::metadata::method::Method`] to populate with basic blocks
/// * `file` - The [`crate::file::File`] containing the method's bytecode
/// * `bodies` - The bodies decoded so far during this load
///
/// # Errors
///
/// Returns an error if the body cannot be decoded: an invalid offset, a
/// header larger than the file, malformed bytecode, or a branch leaving the
/// method. Every method sharing a body reports its failure.
///
/// # Thread Safety
///
/// Safe to call concurrently for different methods. Methods sharing a body wait
/// for the one decoding it rather than decoding it again.
pub(crate) fn decode_method(method: &Method, file: &File, bodies: &DecodedBodies) -> Result<()> {
    let Some(rva) = method.rva else {
        return Ok(());
    };

    // The map's guard is released before waiting on the cell, so a thread
    // waiting for one body never holds a shard another thread needs.
    let cell = Arc::clone(bodies.by_rva.entry(rva).or_default().value());
    let blocks = cell
        .get_or_init(|| decode_body(method, file, rva as usize))
        .clone()?;
    let _ = method.blocks.set(blocks);
    Ok(())
}

/// Decodes the body at `rva` into basic blocks.
fn decode_body(method: &Method, file: &File, rva: usize) -> Result<Vec<BasicBlock>> {
    let method_offset = file.rva_to_offset(rva)?;
    if method_offset >= file.data().len() {
        return Err(malformed_error!("Invalid method offset: {}", method_offset));
    }

    let Some(body) = method.body.get() else {
        return Err(malformed_error!("Method does not have a valid body"));
    };

    if body.size_header >= file.data().len() {
        return Err(malformed_error!(
            "MethodHeader size exceeds file size - {}",
            body.size_header
        ));
    }

    let Some(code_start) = method_offset.checked_add(body.size_header) else {
        return Err(malformed_error!(
            "Integer overflow size_header ({}) + method_offset ({})",
            body.size_header,
            method_offset
        ));
    };

    // Skip decoding if method has no code (e.g., abstract method or empty method body).
    // Without this check, the decoder would start reading bytes after the header,
    // which might be the next method's header or garbage data, causing invalid opcode errors.
    if body.size_code == 0 {
        return Ok(Vec::new());
    }

    // The runtimes refuse a body that runs past its section's data
    let in_section = file.section_bounded(rva)?.len();
    if body
        .size_header
        .checked_add(body.size_code)
        .is_none_or(|end| end > in_section)
    {
        return Err(malformed_error!(
            "Method body at RVA {:#x} runs past its section's data",
            rva
        ));
    }

    // Bound decoding to this method's declared code window, and track what has
    // been decoded within that window alone.
    let code_end = code_start
        .checked_add(body.size_code)
        .ok_or_else(|| malformed_error!("code_start + size_code overflow"))?;

    let mut parser = Parser::new(file.data());
    let rva_start = rva
        .checked_add(body.size_header)
        .ok_or_else(|| malformed_error!("rva + size_header overflow"))?;
    let mut decoder = Decoder::new(
        &mut parser,
        code_start,
        rva_start,
        Some(&body.exception_handlers),
        VisitedMap::new(body.size_code),
        code_end,
    )?;

    decoder.decode_blocks()?;
    Ok(decoder.into_blocks())
}

/// Decodes bytecode into a collection of basic blocks with control flow analysis.
///
/// This function performs comprehensive disassembly of raw bytecode into basic blocks,
/// automatically building the complete control flow graph. Unlike method-level disassembly,
/// this function works with standalone bytecode without requiring method metadata or
/// exception handler information, making it useful for analyzing code fragments.
///
/// The function automatically detects basic block boundaries based on control flow
/// instructions and builds predecessor/successor relationships between blocks.
///
/// # Arguments
///
/// * `data` - Raw bytecode buffer to disassemble
/// * `offset` - Starting offset within the bytecode buffer (0-based)
/// * `rva` - Relative Virtual Address of the first instruction for proper addressing
/// * `max_size` - Maximum number of bytes to process (None for entire buffer from offset)
///
/// # Returns
///
/// Returns a vector of [`crate::assembly::BasicBlock`] objects representing the control flow structure.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - The bytecode contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - The specified offset is beyond the buffer bounds
/// - Control flow analysis encounters invalid branch targets
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::assembly::decode_blocks;
///
/// // Simple bytecode sequence: nop, conditional branch, ret
/// let bytecode = [
///     0x00,             // nop
///     0x2C, 0x02,       // brfalse.s +2 (skip next instruction)
///     0x2A,             // ret
///     0x2A,             // ret (branch target)
/// ];
///
/// let blocks = decode_blocks(&bytecode, 0, 0x1000, None)?;
///
/// // Should produce multiple basic blocks due to control flow
/// assert!(blocks.len() >= 2);
/// # Ok::<(), dotscope::Error>(())
/// ```
pub fn decode_blocks(
    data: &[u8],
    offset: usize,
    rva: usize,
    max_size: Option<usize>,
) -> Result<Vec<BasicBlock>> {
    decode_blocks_with_handlers(data, offset, rva, max_size, &[])
}

/// Decodes bytecode into basic blocks, entering it at its exception handlers
/// as well as at its first instruction.
///
/// No instruction branches to a handler: the runtime enters it when something
/// throws. Decoding that follows control flow from the first instruction alone
/// therefore never reaches a `catch`, `filter`, `finally` or `fault` body, and
/// the blocks it returns describe a method with its handlers missing. This
/// seeds each clause's handler and filter start, the way method disassembly
/// does from the method body's clause table.
///
/// # Arguments
///
/// * `data` - Raw bytecode buffer to disassemble
/// * `offset` - Starting offset within the bytecode buffer (0-based)
/// * `rva` - Relative Virtual Address of the first instruction for proper addressing
/// * `max_size` - Maximum number of bytes to process (None for entire buffer from offset)
/// * `handlers` - The exception clauses, with offsets relative to `offset`
///
/// # Returns
///
/// The basic blocks, handler bodies included.
///
/// # Errors
///
/// Returns [`crate::Error`] under the same conditions as [`decode_blocks`].
pub fn decode_blocks_with_handlers(
    data: &[u8],
    offset: usize,
    rva: usize,
    max_size: Option<usize>,
    handlers: &[ExceptionHandler],
) -> Result<Vec<BasicBlock>> {
    if offset >= data.len() {
        return Err(malformed_error!(
            "Starting offset {} exceeds data length {}",
            offset,
            data.len()
        ));
    }

    let effective_data = if let Some(size) = max_size {
        let end_offset = offset.saturating_add(size).min(data.len());
        data.get(offset..end_offset).ok_or(out_of_bounds_error!())?
    } else {
        data.get(offset..).ok_or(out_of_bounds_error!())?
    };

    let mut parser = Parser::new(effective_data);
    let visited = VisitedMap::new(effective_data.len());
    // This entry point already slices `data` to the requested window and builds a private
    // `VisitedMap` over it, so the whole buffer is in bounds.
    let max_offset = effective_data.len();
    let handlers = (!handlers.is_empty()).then_some(handlers);
    let mut decoder = Decoder::new(&mut parser, 0, rva, handlers, visited, max_offset)?;

    decoder.decode_blocks()?;

    Ok(decoder.into_blocks())
}

/// Decodes a continuous stream of CIL instructions from a byte stream.
///
/// This function processes raw bytecode sequentially, decoding each instruction
/// until the parser reaches the end of available data. Unlike internal method disassembly,
/// this function does not perform control flow analysis or create basic blocks.
///
/// The function maintains proper RVA tracking as it processes instructions,
/// ensuring each decoded instruction has the correct virtual address information.
/// This is useful for linear disassembly scenarios or when working with
/// instruction streams outside of method contexts.
///
/// # Arguments
///
/// * `parser` - A mutable parser positioned at the start of the instruction stream
/// * `rva` - The relative virtual address of the first instruction in the stream
///
/// # Returns
///
/// Returns a `Vec<`[`crate::assembly::instruction::Instruction`]`>` containing all successfully decoded instructions.
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{assembly::decode_stream, Parser};
///
/// // Raw CIL bytecode: nop, ldloc.0, ret
/// let bytecode = [0x00, 0x06, 0x2A];
/// let mut parser = Parser::new(&bytecode);
///
/// let instructions = decode_stream(&mut parser, 0x2000)?;
///
/// assert_eq!(instructions.len(), 3);
/// assert_eq!(instructions[0].mnemonic, "nop");
/// assert_eq!(instructions[1].mnemonic, "ldloc.0");
/// assert_eq!(instructions[2].mnemonic, "ret");
///
/// // RVAs are properly tracked
/// assert_eq!(instructions[0].rva, 0x2000);
/// assert_eq!(instructions[1].rva, 0x2001);
/// assert_eq!(instructions[2].rva, 0x2002);
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - The bytecode stream contains invalid opcodes
/// - Instruction operands are malformed or truncated
/// - Parser encounters unexpected end of data during instruction decoding
///
/// # Notes
///
/// - Instructions are decoded in linear order without control flow analysis
/// - Each instruction's RVA is calculated based on the previous instruction's size
/// - The function stops when the parser has no more data available
/// - Use [`crate::assembly::decode_blocks`] for complete analysis with basic blocks
pub fn decode_stream(parser: &mut Parser, rva: u64) -> Result<Vec<Instruction>> {
    let mut current_rva = rva;
    let mut instructions = Vec::new();

    while parser.has_more_data() {
        let current_offset = parser.pos();
        let instruction = decode_instruction(parser, current_rva)?;

        instructions.push(instruction);

        let consumed = parser
            .pos()
            .checked_sub(current_offset)
            .ok_or_else(|| malformed_error!("parser position regressed during decode"))?
            as u64;
        current_rva = current_rva
            .checked_add(consumed)
            .ok_or_else(|| malformed_error!("instruction stream RVA overflow"))?;
    }

    Ok(instructions)
}

/// Decodes a single CIL instruction from the current parser position.
///
/// This is the core instruction decoding function that parses individual CIL
/// opcodes and their operands from raw bytecode. It handles both single-byte
/// and double-byte opcodes, correctly decoding all operand types including
/// immediate values, tokens, and branch targets.
///
/// The function advances the parser position as it reads the instruction data,
/// ensuring proper sequential decoding when called multiple times. Each decoded
/// instruction includes complete operand information and metadata for further
/// analysis.
///
/// # Arguments
///
/// * `parser` - A mutable parser positioned at the start of an instruction
/// * `rva` - The relative virtual address of the instruction being decoded
///
/// # Returns
///
/// Returns a fully populated [`crate::assembly::instruction::Instruction`] struct containing:
/// - The instruction mnemonic and opcode information
/// - Decoded operands with proper type information
/// - Stack behavior and flow control metadata
/// - Size and RVA information for the instruction
///
/// # Errors
///
/// Returns [`crate::Error`] if:
/// - An invalid or unrecognized opcode is encountered
/// - Operand data is truncated or corrupted
/// - Parser reaches end of data unexpectedly during operand decoding
///
/// # Examples
///
/// ```rust,no_run
/// use dotscope::{assembly::{decode_instruction, Operand}, Parser};
///
/// // Simple instruction: ldloc.0 (0x06)
/// let bytecode = [0x06];
/// let mut parser = Parser::new(&bytecode);
///
/// let instruction = decode_instruction(&mut parser, 0x2000)?;
///
/// assert_eq!(instruction.mnemonic, "ldloc.0");
/// assert_eq!(instruction.rva, 0x2000);
/// assert_eq!(instruction.size, 1);
/// assert!(matches!(instruction.operand, Operand::None)); // No operands for ldloc.0
///
/// // Instruction with operand: ldstr <token>
/// let bytecode = [0x72, 0x01, 0x00, 0x00, 0x70]; // ldstr followed by token
/// let mut parser = Parser::new(&bytecode);
///
/// let instruction = decode_instruction(&mut parser, 0x2010)?;
///
/// assert_eq!(instruction.mnemonic, "ldstr");
/// if let Operand::Token(token) = &instruction.operand {
///     // Token operand with value 0x70000001
///     assert_eq!(token.value(), 0x70000001);
/// }
/// # Ok::<(), dotscope::Error>(())
/// ```
///
/// # Thread Safety
///
/// This function is thread-safe and can be called concurrently from multiple threads
/// with different parser instances.
///
/// # Implementation Notes
///
/// - Handles both 0xFE-prefixed extended opcodes and standard single-byte opcodes
/// - Correctly decodes variable-length operands (int8, int16, int32, int64)
/// - Processes metadata tokens and resolves their table/row information
/// - Calculates branch target addresses for control flow instructions
/// - Maintains parser state for sequential instruction decoding
pub fn decode_instruction(parser: &mut Parser, rva: u64) -> Result<Instruction> {
    let offset = parser.pos() as u64;
    let first_byte = parser.read_le::<u8>()?;

    let (cil_instruction, prefix, opcode) = match first_byte {
        0xFE => {
            let second_byte = parser.read_le::<u8>()?;

            match INSTRUCTIONS_FE.get(second_byte as usize) {
                Some(instr) => (instr, 0xFE, second_byte),
                None => return Err(malformed_error!("Invalid opcode: FE {:02X}", second_byte)),
            }
        }
        _ => match INSTRUCTIONS.get(first_byte as usize) {
            Some(instr) => (instr, 0, first_byte),
            None => return Err(malformed_error!("Invalid opcode: {:X}", first_byte)),
        },
    };

    if cil_instruction.instr.is_empty() {
        return Err(malformed_error!("Reserved opcode: {:04X}", opcode));
    }

    let operand = match cil_instruction.op_type {
        OperandType::None => Operand::None,
        OperandType::Int8 => Operand::Immediate(Immediate::Int8(parser.read_le::<i8>()?)),
        OperandType::UInt8 => Operand::Immediate(Immediate::UInt8(parser.read_le::<u8>()?)),
        OperandType::Int16 => Operand::Immediate(Immediate::Int16(parser.read_le::<i16>()?)),
        OperandType::UInt16 => Operand::Immediate(Immediate::UInt16(parser.read_le::<u16>()?)),
        OperandType::Int32 => Operand::Immediate(Immediate::Int32(parser.read_le::<i32>()?)),
        OperandType::UInt32 => Operand::Immediate(Immediate::UInt32(parser.read_le::<u32>()?)),
        OperandType::Int64 => Operand::Immediate(Immediate::Int64(parser.read_le::<i64>()?)),
        OperandType::UInt64 => Operand::Immediate(Immediate::UInt64(parser.read_le::<u64>()?)),
        OperandType::Float32 => Operand::Immediate(Immediate::Float32(parser.read_le::<f32>()?)),
        OperandType::Float64 => Operand::Immediate(Immediate::Float64(parser.read_le::<f64>()?)),
        OperandType::Token => Operand::Token(Token::new(parser.read_le::<u32>()?)),
        OperandType::Switch => {
            let case_count = parser.read_le::<u32>()? as usize;

            // Each case is a 4-byte target that must actually be present, so the remaining
            // input is a hard upper bound on the count. Without this check the raw `u32` sizes
            // the reservation directly: five bytes (`0x45` plus `0xFFFFFFFF`) request ~16 GiB,
            // and a failed allocation *aborts* rather than unwinding, so it escapes the
            // crate's no-panic policy entirely.
            let available_targets = parser.len().saturating_sub(parser.pos()) / 4;
            if case_count > available_targets {
                return Err(malformed_error!(
                    "switch declares {} cases but only {} target slots remain in the method body",
                    case_count,
                    available_targets
                ));
            }

            let mut targets = Vec::with_capacity(case_count);
            for _ in 0..case_count {
                // Switch offsets are SIGNED 32-bit integers (can be negative for backward jumps)
                targets.push(parser.read_le::<i32>()?);
            }

            Operand::Switch(targets)
        }
    };
    let size = (parser.pos() as u64)
        .checked_sub(offset)
        .ok_or_else(|| malformed_error!("instruction size underflow"))?;

    let mut instruction = Instruction {
        rva,
        offset,
        size,
        opcode,
        prefix,
        mnemonic: cil_instruction.instr,
        category: cil_instruction.category,
        flow_type: cil_instruction.flow,
        stack_behavior: StackBehavior {
            pops: cil_instruction.stack_pops,
            pushes: cil_instruction.stack_pushes,
            // Stack effects are bounded: per ECMA-335 individual instructions push/pop
            // a small number of stack slots, so this fits in i8 with `wrapping_sub`.
            #[allow(clippy::cast_possible_wrap)]
            net_effect: (cil_instruction.stack_pushes as i8)
                .wrapping_sub(cil_instruction.stack_pops as i8),
        },
        branch_targets: Vec::new(),
        operand,
    };

    match instruction.flow_type {
        FlowType::ConditionalBranch | FlowType::UnconditionalBranch | FlowType::Leave => {
            // Every branch, `leave` included, encodes its target as a signed offset from the
            // next instruction. The operand states the resolved target, as `Operand::Target`
            // documents, so no consumer has to redo this arithmetic or know the encoding.
            if let Operand::Immediate(value) = instruction.operand {
                let next_instruction_rva = rva
                    .checked_add(instruction.size)
                    .ok_or_else(|| malformed_error!("branch instruction RVA overflow"))?;
                // Sign-extending: a signed immediate converts with its bit pattern widened.
                let branch_offset = <Immediate as Into<u64>>::into(value);
                let target = next_instruction_rva.wrapping_add(branch_offset);
                instruction.operand = Operand::Target(target);
                instruction.branch_targets.push(target);
            }
        }
        FlowType::Switch => {
            if let Operand::Switch(targets) = &instruction.operand {
                let next_instruction_rva = rva
                    .checked_add(instruction.size)
                    .ok_or_else(|| malformed_error!("switch instruction RVA overflow"))?;
                for &target in targets {
                    // Sign-extend i32 offset to i64 for proper signed arithmetic
                    let offset = i64::from(target);
                    #[allow(clippy::cast_sign_loss)]
                    let abs_target = next_instruction_rva.cast_signed().wrapping_add(offset) as u64;
                    instruction.branch_targets.push(abs_target);
                }
            }
        }
        _ => {}
    }

    Ok(instruction)
}

#[cfg(test)]
mod tests {
    use crate::{
        assembly::{
            decode_blocks, decode_instruction, decode_stream, FlowType, Immediate,
            InstructionCategory, Operand,
        },
        metadata::{
            tables::{MethodDefRaw, TableDataOwned, TableId},
            token::Token,
        },
        testkit::helpers::load_sample,
        Error, Parser,
    };

    /// Two methods whose rows name the same body both decode it. ECMA-335
    /// lets methods share a body; with a map of decoded bytes shared by every
    /// method, the first to decode claimed them and the other came out empty.
    #[test]
    fn methods_sharing_a_body_each_decode_it() {
        let assembly = load_sample("crafted_2.exe");
        let mut with_code: Vec<(Token, u32)> = assembly
            .methods()
            .iter()
            .filter_map(|entry| {
                let method = entry.value();
                let decoded = method.blocks.get().is_some_and(|blocks| !blocks.is_empty());
                method
                    .rva
                    .filter(|_| decoded)
                    .map(|rva| (method.token, rva))
            })
            .collect();
        with_code.sort();
        let [(first, first_rva), (second, _), ..] = with_code[..] else {
            panic!("the sample has two methods with code");
        };

        let mut row: MethodDefRaw = assembly
            .tables()
            .and_then(|tables| tables.table::<MethodDefRaw>())
            .and_then(|table| table.get(second.row()).ok().flatten())
            .expect("the second method's row");
        row.rva = first_rva;
        let mut rewritten = assembly.into_assembly();
        rewritten
            .table_row_update(
                TableId::MethodDef,
                second.row(),
                TableDataOwned::MethodDef(row),
            )
            .expect("the row updates");
        let reloaded = rewritten.into_cilobject().expect("the result loads");

        let rva_of = |token: Token| reloaded.method(&token).ok().and_then(|m| m.rva);
        assert_eq!(rva_of(first), rva_of(second), "the rows share a body");
        for token in [first, second] {
            let method = reloaded.method(&token).expect("the method survives");
            assert!(
                method.blocks.get().is_some_and(|blocks| !blocks.is_empty()),
                "{token:?} decoded nothing from the body it shares"
            );
        }
    }

    #[test]
    fn decode_instruction_basic() {
        // ldloc.s 10 (0x11, 0x10)
        let mut parser = Parser::new(&[0x11, 0x10]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.rva, rva);
        assert_eq!(result.offset, 0);
        assert_eq!(result.size, 2);
        assert_eq!(result.opcode, 0x11);
        assert_eq!(result.prefix, 0);
        assert_eq!(result.mnemonic, "ldloc.s");
        assert_eq!(result.category, InstructionCategory::LoadStore);
        assert_eq!(result.flow_type, FlowType::Sequential);
        // ldloc.s uses UInt8 for the local index (0-255 range, no sign needed)
        match &result.operand {
            Operand::Immediate(Immediate::UInt8(val)) => assert_eq!(*val, 0x10),
            _ => panic!("Expected Operand::Immediate(Immediate::UInt8)"),
        }
    }

    #[test]
    fn decode_instruction_two_byte() {
        // ceq (0xFE, 0x01)
        let mut parser = Parser::new(&[0xFE, 0x01]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.opcode, 0x01);
        assert_eq!(result.prefix, 0xFE);
        assert_eq!(result.mnemonic, "ceq");
        assert_eq!(result.category, InstructionCategory::Comparison);
        assert_eq!(result.flow_type, FlowType::Sequential);
    }

    #[test]
    fn decode_instruction_branch() {
        // br.s 10 (0x2B, 0x0A)
        let mut parser = Parser::new(&[0x2B, 0x0A]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "br.s");
        assert_eq!(result.flow_type, FlowType::UnconditionalBranch);
        assert_eq!(result.branch_targets.len(), 1);
        assert_eq!(result.branch_targets[0], 0x100C); // next_rva (0x1002) + offset (10)
        assert!(
            matches!(result.operand, Operand::Target(0x100C)),
            "the operand states the resolved target, got {:?}",
            result.operand
        );
    }

    /// A backward branch resolves below the branch: the offset is signed.
    #[test]
    fn decode_instruction_backward_branch_targets_below_itself() {
        // brtrue.s -4 (0x2D, 0xFC) at 0x1010: next is 0x1012, target 0x100E.
        let mut parser = Parser::new(&[0x2D, 0xFC]);
        let result = decode_instruction(&mut parser, 0x1010).unwrap();

        assert_eq!(result.flow_type, FlowType::ConditionalBranch);
        assert!(
            matches!(result.operand, Operand::Target(0x100E)),
            "{:?}",
            result.operand
        );
        assert_eq!(result.branch_targets, vec![0x100E]);
    }

    /// `leave` exits a protected region to a target like any other branch.
    #[test]
    fn decode_instruction_leave_states_its_target() {
        // leave 0x20 (0xDD, 0x20 0x00 0x00 0x00) at 0x2000: next 0x2005, target 0x2025.
        let mut parser = Parser::new(&[0xDD, 0x20, 0x00, 0x00, 0x00]);
        let result = decode_instruction(&mut parser, 0x2000).unwrap();

        assert_eq!(result.flow_type, FlowType::Leave);
        assert!(
            matches!(result.operand, Operand::Target(0x2025)),
            "{:?}",
            result.operand
        );
        assert_eq!(result.branch_targets, vec![0x2025]);
    }

    #[test]
    fn decode_instruction_switch() {
        let mut parser = Parser::new(&[
            0x45, 0x02, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00,
        ]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "switch");
        assert_eq!(result.flow_type, FlowType::Switch);
        assert_eq!(result.branch_targets.len(), 2);
        assert_eq!(result.branch_targets[0], 0x1017); // next_rva (0x100D) + offset (10)
        assert_eq!(result.branch_targets[1], 0x1021); // next_rva (0x100D) + offset (20)
    }

    #[test]
    fn decode_instruction_invalid_opcode() {
        let mut parser = Parser::new(&[0xFF, 0xFF]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva);
        assert!(result.is_err(), "Expected error for invalid opcode");
    }

    #[test]
    fn decode_instruction_token() {
        // ldtoken 0x02000001 (0xD0, 0x01, 0x00, 0x00, 0x02)
        let mut parser = Parser::new(&[0xD0, 0x01, 0x00, 0x00, 0x02]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldtoken");
        match &result.operand {
            Operand::Token(token) => assert_eq!(token.value(), 0x02000001),
            _ => panic!("Expected Operand::Token"),
        }
    }

    #[test]
    fn decode_stream_complex() {
        let code = vec![
            0x00, // nop
            0x2C, 0x05, // brfalse.s 5
            0x00, // nop
            0x2B, 0x03, // br.s 3
            0x00, // nop
            0x2A, // ret
            0x00, // nop
            0x2A, // ret
        ];

        let mut parser = Parser::new(&code);
        let result = decode_stream(&mut parser, 0x1000).unwrap();

        assert_eq!(result.len(), 8);
    }

    #[test]
    fn decode_blocks_simple() {
        // Simple linear code: nop, ret
        let code = [0x00, 0x2A]; // nop, ret
        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert_eq!(
            result.len(),
            1,
            "Expected single basic block for linear code"
        );
        assert_eq!(
            result[0].instructions.len(),
            2,
            "Expected 2 instructions in block"
        );
        assert_eq!(result[0].rva, 0x1000, "Expected correct starting RVA");
    }

    #[test]
    fn decode_blocks_with_conditional_branch() {
        let code = [
            0x00, // nop
            0x2C, 0x02, // brfalse.s +2 (skip next instruction)
            0x2A, // ret (false path)
            0x2A, // ret (true path - branch target)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to branching"
        );

        // Find the first block (should contain nop + brfalse.s)
        let first_block = &result[0];
        assert_eq!(
            first_block.instructions.len(),
            2,
            "First block should have nop + brfalse.s"
        );
        assert_eq!(first_block.instructions[0].mnemonic, "nop");
        assert_eq!(first_block.instructions[1].mnemonic, "brfalse.s");
    }

    #[test]
    fn decode_blocks_with_unconditional_branch() {
        let code = [
            0x00, // nop
            0x2B, 0x01, // br.s +1 (jump to last ret instruction)
            0x2A, // ret (unreachable)
            0x2A, // ret (branch target)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to branching, got {}",
            result.len()
        );

        // First block should end with unconditional branch
        let first_block = &result[0];
        assert_eq!(
            first_block.instructions.len(),
            2,
            "First block should have nop + br.s"
        );
        assert_eq!(first_block.instructions[1].mnemonic, "br.s");
    }

    #[test]
    fn decode_blocks_with_switch() {
        let code = [
            0x00, // nop                                          - offset 0, RVA 0x1000
            0x45, 0x02, 0x00, 0x00,
            0x00, // switch with 2 cases - offset 1-5, RVA 0x1001-0x1005
            0x00, 0x00, 0x00,
            0x00, // case 0: offset +0        - offset 6-9, RVA 0x1006-0x1009
            0x02, 0x00, 0x00,
            0x00, // case 1: offset +2        - offset 10-13, RVA 0x100A-0x100D
            0x2A, // ret (case 0 target at RVA 0x100E + 0)       - offset 14, RVA 0x100E
            0x2A, // ret (case 1 target at RVA 0x100E + 2)       - offset 15, RVA 0x100F
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, None).unwrap();

        assert!(
            result.len() >= 2,
            "Expected multiple basic blocks due to switch"
        );

        // First block should contain nop + switch
        let first_block = &result[0];
        assert_eq!(first_block.instructions.len(), 2);
        assert_eq!(first_block.instructions[0].mnemonic, "nop");
        assert_eq!(first_block.instructions[1].mnemonic, "switch");
    }

    #[test]
    fn decode_blocks_with_offset() {
        let code = [
            0xFF, 0xFF, 0xFF, // garbage bytes to skip
            0x00, // nop
            0x2A, // ret
        ];

        let result = super::decode_blocks(&code, 3, 0x1000, None).unwrap();

        assert_eq!(result.len(), 1, "Expected single basic block");
        assert_eq!(result[0].instructions.len(), 2, "Expected 2 instructions");
        assert_eq!(result[0].instructions[0].mnemonic, "nop");
        assert_eq!(result[0].instructions[1].mnemonic, "ret");
    }

    #[test]
    fn decode_blocks_with_max_size() {
        let code = [
            0x00, // nop
            0x2A, // ret
            0x00, // nop (should be ignored due to max_size)
            0x2A, // ret (should be ignored due to max_size)
        ];

        let result = super::decode_blocks(&code, 0, 0x1000, Some(2)).unwrap();

        assert_eq!(result.len(), 1, "Expected single basic block");
        assert_eq!(
            result[0].instructions.len(),
            2,
            "Expected only 2 instructions due to max_size"
        );
        assert_eq!(result[0].instructions[0].mnemonic, "nop");
        assert_eq!(result[0].instructions[1].mnemonic, "ret");
    }

    #[test]
    fn decode_blocks_invalid_offset() {
        let code = [0x00, 0x2A];
        let result = super::decode_blocks(&code, 10, 0x1000, None);

        assert!(result.is_err(), "Expected error for invalid offset");
    }

    #[test]
    fn decode_blocks_empty_data() {
        let code = [];
        let result = super::decode_blocks(&code, 0, 0x1000, None);

        assert!(
            result.is_err(),
            "Expected error for empty data with offset 0"
        );
    }

    #[test]
    fn decode_invalid_fe_instruction() {
        // Test invalid FE prefixed instruction
        let code = [0xFE, 0xFF]; // FE prefix with invalid second byte
        let mut parser = Parser::new(&code);
        let result = decode_instruction(&mut parser, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn decode_blocks_offset_out_of_bounds() {
        // Test decode_blocks with invalid offset
        let code = [0x00, 0x2A]; // nop, ret
        let result = decode_blocks(&code, 10, 0x1000, None); // offset 10 > code.len()
        assert!(result.is_err());
    }

    #[test]
    fn decode_empty_data() {
        // No code holds no instruction to start from: the decoder refuses it.
        let code = [];
        let result = decode_blocks(&code, 0, 0x1000, None);
        assert!(matches!(result, Err(Error::Parse(_))), "{result:?}");
    }

    #[test]
    fn decode_blocks_conditional_fall_through() {
        // This tests a pattern from ConfuserEx control-flow obfuscated code
        // where ble.s branches FORWARD, and the fall-through should also be decoded
        //
        // IL layout:
        // 0x00: 16       ldc.i4.0
        // 0x01: 31 05    ble.s +5 (target = 0x08)
        // 0x03: 06       ldloc.0  <- fall-through, MUST be decoded
        // 0x04: 16       ldc.i4.0
        // 0x05: 2B 01    br.s +1 (target = 0x08)
        // 0x07: 16       ldc.i4.0
        // 0x08: 0B       stloc.1  <- branch target
        // 0x09: 2A       ret
        let code = [
            0x16, // 0x00: ldc.i4.0
            0x31, 0x05, // 0x01: ble.s +5 (target = 0x08)
            0x06, // 0x03: ldloc.0 (fall-through)
            0x16, // 0x04: ldc.i4.0
            0x2B, 0x01, // 0x05: br.s +1 (target = 0x08)
            0x16, // 0x07: ldc.i4.0
            0x0B, // 0x08: stloc.1
            0x2A, // 0x09: ret
        ];

        let result = decode_blocks(&code, 0, 0x1000, None);
        assert!(result.is_ok(), "decode_blocks failed: {:?}", result.err());
        let blocks = result.unwrap();

        // Debug print for investigation
        eprintln!("=== Decoded blocks ===");
        for block in &blocks {
            eprintln!(
                "Block {}: RVA 0x{:04X}, {} instructions",
                block.id,
                block.rva,
                block.instructions.len()
            );
            for instr in &block.instructions {
                eprintln!("  0x{:04X}: {}", instr.offset, instr.mnemonic);
            }
        }

        // There should be blocks covering the fall-through path (0x03-0x06)
        // Not just the branch target (0x08)
        // Note: instruction.offset is the IL offset (from code start), not RVA
        let has_fall_through = blocks.iter().any(|b| {
            b.instructions.iter().any(|i| i.offset == 0x0003) // ldloc.0 at IL offset 3
        });
        assert!(
            has_fall_through,
            "Fall-through instruction at IL offset 0x03 was not decoded!"
        );

        // Check all expected instructions are present
        let all_offsets: Vec<u64> = blocks
            .iter()
            .flat_map(|b| b.instructions.iter().map(|i| i.offset))
            .collect();
        eprintln!("All instruction offsets: {:?}", all_offsets);

        // Verify key instructions are present (IL offsets, not RVAs)
        assert!(all_offsets.contains(&0x0001), "ble.s at IL 0x01 missing");
        assert!(
            all_offsets.contains(&0x0003),
            "fall-through ldloc.0 at IL 0x03 missing"
        );
        assert!(
            all_offsets.contains(&0x0008),
            "branch target at IL 0x08 missing"
        );
    }

    #[test]
    fn decode_instruction_uint8_operand() {
        let mut parser = Parser::new(&[0x11, 0xFF]); // ldloc.s with max u8 value (255)
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        // ldloc.s uses UInt8 for local index (0-255 range, no sign needed)
        // Verify the operand is properly decoded as unsigned
        match &result.operand {
            Operand::Immediate(Immediate::UInt8(val)) => assert_eq!(*val, 255), // 0xFF as unsigned
            _ => panic!("Expected Operand::Immediate(Immediate::UInt8)"),
        }
    }

    #[test]
    fn decode_instruction_uint16_operand() {
        // Test for UInt16 operand - need to find an instruction that actually uses UInt16
        // For now, removing this test since no instructions seem to use UInt16 operand type
        // This is likely because UInt16 operands are not used in the CIL instruction set
    }

    #[test]
    fn decode_instruction_int16_operand() {
        // Test for Int16 operand - ldarg uses Int16 operand type (FE 09)
        let mut parser = Parser::new(&[0xFE, 0x09, 0xFF, 0xFF]); // ldarg with -1
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldarg");
        // The operand should be decoded as Int16
        match &result.operand {
            Operand::Immediate(Immediate::Int16(val)) => assert_eq!(*val, -1),
            _ => panic!("Expected Operand::Immediate(Immediate::Int16)"),
        }
    }

    #[test]
    fn decode_instruction_uint32_operand() {
        // Test for UInt32 operand - switch instruction uses UInt32 for target count
        let mut parser = Parser::new(&[
            0x45, 0x01, 0x00, 0x00, 0x00, // switch with 1 target
            0x05, 0x00, 0x00, 0x00, // single target offset
        ]);
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "switch");
        assert_eq!(result.flow_type, FlowType::Switch);
        assert_eq!(result.branch_targets.len(), 1);
    }

    #[test]
    fn decode_instruction_uint64_operand() {
        // Test for Int64 operand - ldc.i8 uses Int64 operand type
        let mut parser = Parser::new(&[0x21, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]); // ldc.i8 with -1 as i64
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "ldc.i8");
        match &result.operand {
            Operand::Immediate(Immediate::Int64(val)) => assert_eq!(*val, -1),
            _ => panic!("Expected Operand::Immediate(Immediate::Int64)"),
        }
    }

    #[test]
    fn decode_bounds_error() {
        // Test the uncovered bounds error path in decode_blocks
        let data = [0x00]; // Single byte

        // Try to decode with offset beyond data length
        let result = decode_blocks(&data, 10, 0x1000, None);
        assert!(result.is_err());
    }

    #[test]
    fn decode_blocks_access() {
        // Test decode_blocks function
        let data = [0x00, 0x2A]; // nop, ret

        let blocks = decode_blocks(&data, 0, 0x1000, None).unwrap();
        assert!(!blocks.is_empty());
        assert_eq!(blocks.len(), 1); // Should create one basic block
    }

    #[test]
    fn decode_blocks_basic_coverage() {
        // Test basic decode_blocks functionality to cover more code paths
        let data = [
            0x00, // nop
            0x2A, // ret
        ];

        let blocks = decode_blocks(&data, 0, 0x1000, Some(2)).unwrap();
        assert!(!blocks.is_empty());
        assert_eq!(blocks.len(), 1);

        // Test the basic block structure
        let block = &blocks[0];
        assert_eq!(block.rva, 0x1000);
        assert_eq!(block.offset, 0);
        assert!(block.size > 0);
    }

    #[test]
    fn decode_blocks_max_size_limit() {
        // Test max_size parameter
        let data = [0x00, 0x00, 0x00, 0x2A]; // nop, nop, nop, ret

        // Limit to only 2 bytes
        let blocks = decode_blocks(&data, 0, 0x1000, Some(2)).unwrap();
        assert!(!blocks.is_empty());

        // Should only process the first 2 bytes
        let total_size: usize = blocks.iter().map(|b| b.size).sum();
        assert!(total_size <= 2);
    }

    #[test]
    fn decode_stream_empty() {
        // Test decode_stream with empty data
        let data = [];
        let mut parser = Parser::new(&data);

        let result = decode_stream(&mut parser, 0x1000).unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn decode_blocks_lone_nop_is_one_block() {
        // A single `nop` (0x00) is a whole instruction: one block holding it.
        let data = [0x00];
        let blocks = decode_blocks(&data, 0, 0x1000, None).unwrap();
        assert_eq!(blocks.len(), 1);
        let mnemonics: Vec<&str> = blocks[0].instructions.iter().map(|i| i.mnemonic).collect();
        assert_eq!(mnemonics, ["nop"]);
    }

    #[test]
    fn decode_instruction_leave_s() {
        // Test leave.s instruction (0xDE) - exits protected region with 1-byte offset
        let mut parser = Parser::new(&[0xDE, 0x05]); // leave.s +5
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "leave.s");
        assert_eq!(result.flow_type, FlowType::Leave);
        assert_eq!(result.size, 2);
        // Branch target should be computed: next_rva (0x1002) + offset (5) = 0x1007
        assert_eq!(result.branch_targets.len(), 1);
        assert_eq!(result.branch_targets[0], 0x1007);
    }

    #[test]
    fn decode_instruction_leave() {
        // Test leave instruction (0xDD) - exits protected region with 4-byte offset
        let mut parser = Parser::new(&[0xDD, 0x0A, 0x00, 0x00, 0x00]); // leave +10
        let rva = 0x1000;

        let result = decode_instruction(&mut parser, rva).unwrap();

        assert_eq!(result.mnemonic, "leave");
        assert_eq!(result.flow_type, FlowType::Leave);
        assert_eq!(result.size, 5);
        // Branch target should be computed: next_rva (0x1005) + offset (10) = 0x100F
        assert_eq!(result.branch_targets.len(), 1);
        assert_eq!(result.branch_targets[0], 0x100F);
    }

    #[test]
    fn decode_blocks_with_leave() {
        // Test that blocks ending with leave.s have proper successors
        let code = [
            0x00, // nop at RVA 0x1000
            0xDE, 0x01, // leave.s +1 at RVA 0x1001, target = 0x1004
            0x00, // nop at RVA 0x1003 (unreachable)
            0x2A, // ret at RVA 0x1004 (leave target)
        ];

        let blocks = decode_blocks(&code, 0, 0x1000, None).unwrap();

        // Should have at least 2 blocks: one with nop+leave.s, one with ret
        assert!(
            blocks.len() >= 2,
            "Expected at least 2 blocks, got {}",
            blocks.len()
        );

        // Find the block that ends with leave.s
        let leave_block = blocks.iter().find(|b| {
            b.instructions
                .last()
                .is_some_and(|i| i.mnemonic == "leave.s")
        });

        assert!(
            leave_block.is_some(),
            "Should have a block ending with leave.s"
        );
        let leave_block = leave_block.unwrap();

        // The leave.s block should have a successor (the block at RVA 0x1004)
        assert!(
            !leave_block.successors.is_empty(),
            "Block ending with leave.s should have successors"
        );
    }
}

#[cfg(test)]
mod examples {
    use super::*;
    use crate::{utils::VisitedMap, Parser, Result};

    /// `nop; ret` decodes to one block of two instructions.
    #[test]
    fn blocks_example() -> Result<()> {
        let code = [0x00, 0x2A];
        let mut parser = Parser::new(&code);
        let mut decoder = Decoder::new(&mut parser, 0, 0x1000, None, VisitedMap::new(2), 2)?;
        decoder.decode_blocks()?;

        let blocks = decoder.blocks();
        assert_eq!(blocks.len(), 1);
        let mnemonics: Vec<_> = blocks[0].instructions.iter().map(|i| i.mnemonic).collect();
        assert_eq!(mnemonics, ["nop", "ret"]);
        Ok(())
    }
}
