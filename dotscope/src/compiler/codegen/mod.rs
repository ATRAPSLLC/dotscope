//! SSA to CIL code generation.
//!
//! Converts SSA back to CIL bytecode, completing the roundtrip
//! CIL -> SSA -> (transformations) -> CIL.
//!
//! # How a body is generated
//!
//! 1. **Storage** ([`storage`]): which values are emitted at their use rather
//!    than given a row ([`FoldForest`](analyssa::analysis::folding::FoldForest)),
//!    which share a slot ([`Gathering`](analyssa::analysis::webs::Gathering)),
//!    and which argument or local slot each web is, with its type. Decided once,
//!    from one model of the order the body is emitted in.
//! 2. **Layout**: blocks ordered so fall-through paths need no jump, exception
//!    regions contiguous, and every phi-carrying edge out of a multi-way branch
//!    given a block of its own.
//! 3. **Emission**: each block's operations in SSA order. An operation's
//!    operands are loaded from their slots or produced in place as expression
//!    trees; its result is stored to its slot, or left for the consumer it was
//!    folded into. Phi copies are one parallel copy per predecessor.
//! 4. **Validation** ([`validate`]): the finished body is checked against the
//!    SSA by an independent abstract interpretation. A body that reads a value
//!    other than the one the SSA names, reorders an effect or truncates a value
//!    in a narrow slot is refused, and the method keeps its original IL.
//!
//! # Module Organization
//!
//! - [`emitter`]: Low-level CIL instruction emission helpers
//! - [`storage`]: Folding, slot sharing and slot typing
//! - [`validate`]: Translation validation of generated bodies

mod emitter;
mod storage;
mod validate;

pub use validate::validate_lift;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet, HashMap};

use analyssa::analysis::copies::ParallelCopy;

use crate::{
    analysis::{
        BlockRange, CmpKind, ConstValue, FloatFormat, HandlerKind, RuntimeValueKind, SsaBlock,
        SsaFunction, SsaOp, SsaType, SsaVarId, SsaVerifier, VerifierError, VerifyLevel,
    },
    assembly::{decode_stream, Immediate, InstructionEncoder, Operand},
    cilassembly::CilAssembly,
    compiler::codegen::{
        storage::{infer_type, is_slot_type, Materialise, Place, Storage},
        validate::{validate, EmitGroup, OpTag, Validation},
    },
    metadata::{
        method::{validate_protected_region_flow, ExceptionHandler},
        signatures::{
            encode_field_signature, encode_method_signature, encode_typespec_signature,
            CustomModifiers, SignatureField, SignatureLocalVariable, SignatureMethod,
            SignatureParameter, SignatureTypeSpec, TypeSignature,
        },
        tables::{
            skip_unreadable, ClassLayoutRaw, CodedIndex, CodedIndexType, FieldRaw, FieldRvaRaw,
            MemberRefBuilder, MemberRefRaw, NestedClassRaw, TableDataOwned, TableId, TypeDefRaw,
            TypeRefBuilder, TypeSpecRaw,
        },
        token::Token,
    },
    Error, Parser, Result,
};

/// Output of [`SsaCodeGenerator::compile`] - everything needed to assemble a method body.
///
/// Contains the CIL bytecode, stack depth, local variable signatures, and remapped
/// exception handlers. This is the bridge between code generation and
/// [`MethodBodyBuilder::from_compilation`](crate::cilassembly::MethodBodyBuilder::from_compilation).
pub struct CompilationResult {
    /// CIL bytecode.
    pub bytecode: Vec<u8>,
    /// Maximum evaluation stack depth.
    pub max_stack: u16,
    /// Local variable signatures (already built with correct types).
    pub locals: Vec<SignatureLocalVariable>,
    /// Exception handlers with bytecode offsets (already remapped from SSA block IDs).
    pub exception_handlers: Vec<ExceptionHandler>,
}

/// Pool of reusable temporary local slots.
///
/// Temporaries (a rotate's operands, a parallel copy's cycle breakers) are
/// allocated from this pool and released back for reuse by other temporaries of
/// the same type.
#[derive(Debug, Default)]
struct TempPool {
    /// Free slots indexed by type
    free_by_type: HashMap<SsaType, Vec<u16>>,
}

impl TempPool {
    /// Try to allocate a slot from the pool for the given type.
    fn try_allocate(&mut self, ty: &SsaType) -> Option<u16> {
        self.free_by_type.get_mut(ty).and_then(Vec::pop)
    }

    /// Release a slot back to the pool for the given type.
    fn release(&mut self, slot: u16, ty: SsaType) {
        self.free_by_type.entry(ty).or_default().push(slot);
    }

    /// Clear all pooled slots.
    fn clear(&mut self) {
        self.free_by_type.clear();
    }
}

/// One entry in the emission order.
///
/// Out-of-SSA needs somewhere to put a phi copy for the edge `from -> to`. When `from` has a
/// single successor the copy can simply precede its branch, but a multi-way terminator
/// (`Branch`, `BranchCmp`, `Switch`) has no such place: the copy belongs *on the edge*, and
/// each edge needs its own.
///
/// Edge blocks are therefore ordinary entries in the emission order rather than labelled runs
/// spliced into branch emission. That makes "does code sit between this block and its
/// successor" a structural property the layout answers - whatever lands between two blocks is
/// something the layout placed - rather than a condition each branch emitter has to maintain
/// by predicting what will be emitted after it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayoutEntry {
    /// A real SSA block, identified by its block id.
    Block(usize),
    /// A synthetic block carrying the phi copies for one CFG edge.
    SplitEdge {
        /// Block the edge leaves.
        from: usize,
        /// Block the edge enters.
        to: usize,
    },
}

/// What generating one block asks of the whole function, computed once per
/// method rather than rescanned per block.
#[derive(Default)]
struct MethodIndex {
    /// The blocks the runtime enters through exception dispatch: every handler
    /// and filter entry.
    dispatch_entries: BTreeSet<usize>,
    /// The entries entered with the exception object on the stack: catch and
    /// filter handlers, and filters.
    object_entries: BTreeSet<usize>,
    /// For each block, the blocks whose phis take an operand on an edge from
    /// it, in ascending order.
    phi_successors: BTreeMap<usize, Vec<usize>>,
}

impl MethodIndex {
    /// The index of `ssa`.
    fn of(ssa: &SsaFunction) -> Self {
        let mut index = Self::default();
        for handler in ssa.exception_handlers() {
            index.dispatch_entries.extend(handler.entry_blocks());
            if matches!(handler.kind(), HandlerKind::Catch | HandlerKind::Filter) {
                index
                    .object_entries
                    .extend(handler.handler_range.map(|range| range.start()));
            }
            index
                .object_entries
                .extend(handler.filter_range.map(|range| range.start()));
        }
        for block in ssa.blocks() {
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    let successors = index
                        .phi_successors
                        .entry(operand.predecessor())
                        .or_default();
                    if successors.last() != Some(&block.id()) {
                        successors.push(block.id());
                    }
                }
            }
        }
        index
    }
}

/// The state code generation keeps for one method.
///
/// Replaced whole at the start of every method, so nothing one method decided
/// can leak into the next; only the session's interning outlives a method.
#[derive(Default)]
struct MethodState {
    /// What generating one block asks of the whole function, computed once.
    index: MethodIndex,
    /// The current method's storage decisions.
    storage: Option<Storage>,
    /// The type of every local slot of the current method, temporaries
    /// included, by slot.
    slot_types: Vec<SsaType>,
    /// By slot: the method's own local the slot is, if it is one.
    declared: Vec<Option<u16>>,
    /// Map from block index to label name
    block_labels: BTreeMap<usize, String>,
    /// Label for each edge that was given its own block, keyed by `(from, to)`.
    ///
    /// Present only for edges leaving a multi-way terminator that carry phi copies. A
    /// branch whose target appears here jumps to the edge block instead of the target
    /// block; the edge block does the copies and then continues to the real target.
    split_edge_labels: BTreeMap<(usize, usize), String>,
    /// Types of the generated locals (local_idx -> SsaType), for the public
    /// [`Self::local_types`] view.
    local_types: BTreeMap<u16, SsaType>,
    /// Map from original local index to the slot it is generated in. Original
    /// locals keep their indices, so this is the identity over them.
    original_to_compacted: BTreeMap<u16, u16>,
    /// Map from block ID to its byte offset in the generated bytecode.
    /// Used for remapping exception handler offsets.
    block_offsets: BTreeMap<usize, u32>,
    /// Every entry of the emitted layout, in order, with its final offset.
    ///
    /// A region's extent is read from this rather than from the offset of the
    /// block numbered one past it: the layout does not emit blocks in index
    /// order, so that block can sit anywhere, and a region measured to it
    /// swallows whatever the layout put in between.
    layout_offsets: Vec<(LayoutEntry, u32)>,
    /// Pool of reusable temporary local slots.
    temp_pool: TempPool,
    /// The emitted runs implementing each SSA instruction, by instruction
    /// index, for the translation validator.
    emit_groups: Vec<EmitGroup>,
    /// Where each value an instruction defines is defined.
    def_sites: BTreeMap<SsaVarId, OpTag>,
    /// For each instruction, the prefix instructions (`constrained.`,
    /// `volatile.`, ...) directly before it, which are emitted directly
    /// before its own opcode.
    prefixes: BTreeMap<OpTag, Vec<OpTag>>,
    /// The place the last emitted instruction loaded, with the instruction
    /// count after it: a load of the same place right after it is a `dup`.
    last_load: Option<(Place, usize)>,
}

/// SSA to CIL code generator.
///
/// One generator compiles the methods of one assembly: a decrypted string or
/// array, or a TypeSpec, interned for one method is reused by the next, and the
/// array types they need are finalised once with
/// [`Self::finalize_array_types`]. A generator used with a second assembly would
/// name the first one's rows.
pub struct SsaCodeGenerator {
    /// Cache of interned decrypted strings (string content -> heap index)
    interned_strings: HashMap<String, u32>,
    /// The TypeSpec naming each type a load or store spells with a token it
    /// does not carry itself (`ldelem !0`), interned with the assembly.
    type_specs: HashMap<SsaType, Token>,
    /// The assembly's own TypeSpec rows, by signature blob, read on the first
    /// type that needs one so an existing row is reused.
    existing_type_specs: Option<HashMap<Vec<u8>, Token>>,
    /// Cache of interned decrypted arrays - maps array data bytes to the
    /// FieldDef token and InitializeArray MemberRef token needed for codegen.
    interned_arrays: HashMap<Vec<u8>, InternedArrayInfo>,
    /// Tokens created during code generation that must be protected from cleanup.
    /// Includes FieldDef tokens for array initializer data and the parent TypeDef.
    protected_tokens: BTreeSet<Token>,
    /// TypeDef token of the parent type for interned array fields.
    /// Created lazily during `finalize_array_types()` - must be the LAST
    /// TypeDef appended so it owns all trailing fields via field_list ranges.
    array_parent_type: Option<Token>,
    /// RID of the first array data field, used as field_list for the parent TypeDef.
    array_first_field_rid: Option<u32>,
    /// Cache of data size -> nested TypeDef token for `__StaticArrayInitTypeSize=N` types.
    /// Each unique array data size gets its own explicit-layout valuetype with
    /// ClassLayout.ClassSize = N, required by RuntimeHelpers.InitializeArray.
    array_size_types: BTreeMap<usize, Token>,
    /// What the method being compiled added to the session's interning, for
    /// [`Self::compile`] to take back if the method fails.
    interned_this_method: Vec<Interned>,
    /// The core library types this session added a reference to, by
    /// namespace and name.
    corelib_types: HashMap<(&'static str, &'static str), CodedIndex>,
    /// The `RuntimeHelpers.InitializeArray` the generated code calls, once
    /// found or added.
    initialize_array: Option<Token>,
    /// The state of the method being generated, replaced whole when the next
    /// one starts.
    method: MethodState,
}

/// An entry the current method added to one of the session's interning
/// tables.
enum Interned {
    /// A decrypted string, by content.
    String(String),
    /// The TypeSpec naming a type.
    TypeSpec(SsaType),
    /// A TypeSpec row added for a signature.
    TypeSpecRow(Vec<u8>),
    /// A decrypted array, by data.
    Array(Vec<u8>),
    /// The `__StaticArrayInitTypeSize` type for a size.
    SizeType(usize),
    /// A token protected from cleanup.
    Protected(Token),
    /// The first array data field, which the parent type's field list starts
    /// at.
    FirstArrayField,
    /// A reference added to a core library type.
    CorelibType(&'static str, &'static str),
    /// The `RuntimeHelpers.InitializeArray` reference.
    InitializeArray,
}

/// Information needed to emit a `RuntimeHelpers.InitializeArray` call for a decrypted array.
#[derive(Clone)]
struct InternedArrayInfo {
    /// Token of the FieldDef holding the FieldRVA data (for `ldtoken`).
    field_token: Token,
    /// Token of `RuntimeHelpers.InitializeArray` MemberRef (for `call`).
    initialize_array_token: Token,
}

/// The stack slots a call pops for `count` arguments.
///
/// A signature holds at most 65535 parameters, so a larger count is a call no
/// method can have.
fn call_arity(count: usize) -> Result<u16> {
    u16::try_from(count)
        .map_err(|_| Error::CodegenFailed(format!("a call with {count} arguments has no encoding")))
}

impl Default for SsaCodeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl SsaCodeGenerator {
    /// Creates a new code generator.
    #[must_use]
    pub fn new() -> Self {
        Self {
            interned_strings: HashMap::new(),
            type_specs: HashMap::new(),
            existing_type_specs: None,
            interned_arrays: HashMap::new(),
            protected_tokens: BTreeSet::new(),
            array_parent_type: None,
            array_first_field_rid: None,
            array_size_types: BTreeMap::new(),
            interned_this_method: Vec::new(),
            corelib_types: HashMap::new(),
            initialize_array: None,
            method: MethodState::default(),
        }
    }

    /// Returns tokens created during code generation that must be protected
    /// from cleanup (FieldDef + TypeDef entries for array initializer data).
    #[must_use]
    pub fn protected_tokens(&self) -> &BTreeSet<Token> {
        &self.protected_tokens
    }

    /// Creates the parent `<PrivateImplementationDetails>` TypeDef and NestedClass
    /// entries for all size types created during array interning.
    ///
    /// MUST be called after all `compile()` calls and before the assembly is
    /// finalized. The parent TypeDef is created LAST so that its `field_list`
    /// range covers all the array data fields (ECMA-335 §II.22.37: a TypeDef
    /// owns all Field rows from its `field_list` to the next TypeDef's).
    pub fn finalize_array_types(&mut self, assembly: &mut CilAssembly) -> Result<()> {
        let Some(first_field_rid) = self.array_first_field_rid else {
            return Ok(()); // No array fields created
        };
        if self.array_parent_type.is_some() {
            return Ok(()); // Already finalized
        }

        let parent_token = self.create_array_parent_type(assembly, first_field_rid)?;
        self.array_parent_type = Some(parent_token);
        self.protected_tokens.insert(parent_token);

        // Create NestedClass entries for each size type
        for &size_token in self.array_size_types.values() {
            assembly.table_row_add(
                TableId::NestedClass,
                TableDataOwned::NestedClass(NestedClassRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    nested_class: size_token.row(),
                    enclosing_class: parent_token.row(),
                }),
            )?;
        }

        Ok(())
    }

    /// Generates CIL bytecode from an SSA function.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to convert.
    ///
    /// # Returns
    ///
    /// A tuple of (bytecode, max_stack, num_locals).
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails due to invalid SSA or encoding issues.
    ///
    /// # Note
    ///
    /// This method does not support `DecryptedString` constants. If the SSA contains
    /// decrypted strings, use [`compile`](Self::compile) instead to properly intern
    /// strings into the assembly's #US heap.
    pub fn generate(&mut self, ssa: &SsaFunction) -> Result<(Vec<u8>, u16, u16)> {
        self.generate_internal(ssa, None)
    }

    /// Generates CIL bytecode and builds a complete [`CompilationResult`].
    ///
    /// Generates the body, interning what it needs with the assembly, and adds
    /// local variable signature building and exception handler remapping. The
    /// result contains everything needed for
    /// [`MethodBodyBuilder::from_compilation`](crate::cilassembly::MethodBodyBuilder::from_compilation)
    /// to assemble the final method body.
    ///
    /// All or nothing: a method that fails leaves the assembly, and what this
    /// generator has interned for the session, as they were before the call.
    ///
    /// # Arguments
    ///
    /// * `ssa` - The SSA function to convert.
    /// * `assembly` - An assembly mutator for adding metadata entries (strings, etc.).
    ///
    /// # Returns
    ///
    /// A [`CompilationResult`] with bytecode, max stack, local signatures, and exception handlers.
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails.
    pub fn compile(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<CompilationResult> {
        let savepoint = assembly.changes().savepoint();
        self.interned_this_method.clear();
        let compiled = self.compile_body(ssa, assembly);
        if compiled.is_err() {
            assembly.changes_mut().rollback_to(&savepoint)?;
            for interned in std::mem::take(&mut self.interned_this_method) {
                match interned {
                    Interned::String(value) => {
                        self.interned_strings.remove(&value);
                    }
                    Interned::TypeSpec(ty) => {
                        self.type_specs.remove(&ty);
                    }
                    Interned::TypeSpecRow(blob) => {
                        if let Some(existing) = self.existing_type_specs.as_mut() {
                            existing.remove(&blob);
                        }
                    }
                    Interned::Array(data) => {
                        self.interned_arrays.remove(&data);
                    }
                    Interned::SizeType(size) => {
                        self.array_size_types.remove(&size);
                    }
                    Interned::Protected(token) => {
                        self.protected_tokens.remove(&token);
                    }
                    Interned::FirstArrayField => self.array_first_field_rid = None,
                    Interned::CorelibType(namespace, name) => {
                        self.corelib_types.remove(&(namespace, name));
                    }
                    Interned::InitializeArray => self.initialize_array = None,
                }
            }
        }
        compiled
    }

    /// Generates one body and what [`Self::compile`] returns for it.
    fn compile_body(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<CompilationResult> {
        let (bytecode, max_stack, num_locals) = self.generate_internal(ssa, Some(assembly))?;

        // Build local variable signatures from codegen's compacted types.
        // Runtime-handle TypeRefs should have been pre-resolved via
        // [`set_handle_typerefs`] before this call; without it, locals
        // whose SSA type is a runtime handle fall back to `object` (the
        // analysis-crate default) and produce invalid CIL on `stloc`.
        let locals = self.build_local_signatures(ssa, num_locals)?;

        // Remap exception handlers using block offset mapping
        #[allow(clippy::cast_possible_truncation)]
        let exception_handlers = self.remap_exception_handlers(ssa, bytecode.len() as u32)?;

        // A body whose clauses let control into a handler, or out of a region
        // without `leave`, is one the runtime rejects the first time it is
        // called. Such a body is not emitted; the method keeps its original.
        if !exception_handlers.is_empty() {
            let instructions = decode_stream(&mut Parser::new(&bytecode), 0)?;
            validate_protected_region_flow(&instructions, &exception_handlers)?;
        }

        Ok(CompilationResult {
            bytecode,
            max_stack,
            locals,
            exception_handlers,
        })
    }

    /// Builds local variable signatures from codegen state and original SSA types.
    ///
    /// # Errors
    ///
    /// Returns an error if a generated local's type is unknown.
    fn build_local_signatures(
        &self,
        ssa: &SsaFunction,
        num_locals: u16,
    ) -> Result<Vec<SignatureLocalVariable>> {
        let mut locals = Vec::with_capacity(usize::from(num_locals));
        for idx in 0..num_locals {
            let slot = usize::from(idx);
            // The original declaration, when this slot has one, in preference
            // to anything inferred from SSA: `ldloca` needs the exact declared
            // type, not one widened by inference (`char` for `ldloca` followed
            // by `char::ToString()`).
            //
            // Taken whole rather than for its type alone, because `pinned` and
            // `byref` are part of what the slot is. A pinned local that loses
            // the marker lets the collector move the object while a pointer
            // into it is still live - a fault the generated code cannot see and
            // the verifier will not catch.
            if let Some(original) = self.original_declaration(ssa, slot) {
                locals.push(original.clone());
                continue;
            }
            let slot_type = self
                .method
                .slot_types
                .get(slot)
                .filter(|slot_type| is_slot_type(slot_type))
                .ok_or_else(|| {
                    Error::CodegenFailed(format!(
                        "local variable {idx} has type {:?}, which no local can be declared with",
                        self.method.slot_types.get(slot)
                    ))
                })?;
            locals.push(SignatureLocalVariable {
                modifiers: CustomModifiers::default(),
                is_pinned: false,
                is_byref: false,
                base: slot_type.to_type_signature(),
            });
        }
        Ok(locals)
    }

    /// The original declaration of the method's own local that `slot` is.
    fn original_declaration<'s>(
        &self,
        ssa: &'s SsaFunction,
        slot: usize,
    ) -> Option<&'s SignatureLocalVariable> {
        let original = self.method.declared.get(slot).copied().flatten()?;
        ssa.original_local_types()?.get(usize::from(original))
    }

    /// The slot the method's own local `local` is generated in.
    fn declared_slot(&self, local: u16) -> Result<u16> {
        self.method
            .original_to_compacted
            .get(&local)
            .copied()
            .ok_or_else(|| {
                Error::CodegenFailed(format!("local {local} is addressed but has no slot"))
            })
    }

    /// The declared type of every local slot, for the validator's store-width
    /// check; `None` for a byref slot.
    fn validation_slot_types(&self, ssa: &SsaFunction) -> Vec<Option<TypeSignature>> {
        (0..self.method.slot_types.len())
            .map(|slot| {
                if let Some(original) = self.original_declaration(ssa, slot) {
                    return (!original.is_byref).then(|| original.base.clone());
                }
                self.method
                    .slot_types
                    .get(slot)
                    .map(SsaType::to_type_signature)
            })
            .collect()
    }

    /// Remaps SSA exception handlers to bytecode offsets using block offset mapping.
    ///
    /// A clause none of whose blocks was emitted is dropped: it guarded code
    /// control no longer reaches.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EhRegionNotContiguous`] when the layout interleaves a
    /// region with code outside it, and [`Error::CodegenFailed`] when a clause
    /// is emitted only in part, has a region of no bytes, or lies outside the
    /// code.
    fn remap_exception_handlers(
        &self,
        ssa: &SsaFunction,
        bytecode_len: u32,
    ) -> Result<Vec<ExceptionHandler>> {
        if !ssa.has_exception_handlers() {
            return Ok(Vec::new());
        }

        let mut handlers = Vec::new();

        for eh in ssa.exception_handlers() {
            // A region is named by the blocks it covers, and those blocks are
            // where it is in *this* body. The offsets recorded when the method
            // was first read describe the layout it had then, which code
            // generation has just replaced, so falling back to them produces a
            // clause pointing outside the method - `handler=932..1078` in a
            // body 301 bytes long, which is how this was found.
            let span = |range: Option<BlockRange>| match range {
                Some(range) => self.region_span(range, bytecode_len),
                None => Ok(None),
            };
            let protected = span(eh.protected_range)?;
            let handler = span(eh.handler_range)?;
            let filter = span(eh.filter_range)?;

            // Only reachable blocks are emitted, and a handler is reachable
            // exactly when its protected code is. A clause none of whose
            // blocks was emitted guarded code that no longer runs, and goes
            // with it. Any other partial clause is code the runtime would run
            // without the clause that makes it valid - a handler entered by
            // nothing, or protected code with nothing to catch what it throws.
            if protected.is_none() && handler.is_none() && filter.is_none() {
                continue;
            }
            let (Some((try_offset, try_end)), Some((handler_offset, handler_end))) =
                (protected, handler)
            else {
                return Err(Error::CodegenFailed(format!(
                    "exception clause is only partly emitted: try={protected:?} \
                     handler={handler:?} filter={filter:?}"
                )));
            };

            // Without a filter range this field is the caught type's token
            // rather than an offset, so the recorded value is the right one. A
            // filter that *is* a region follows the same rule as the others.
            let filter_offset = match (eh.filter_range, filter) {
                (Some(_), Some((offset, _))) => offset,
                (Some(_), None) => {
                    return Err(Error::CodegenFailed(format!(
                        "filter clause is emitted without its filter: \
                         try={try_offset}..{try_end} handler={handler_offset}..{handler_end}"
                    )));
                }
                (None, _) => eh.class_token_or_filter,
            };

            // An emitted region that occupies no bytes cannot be stated: a
            // clause's lengths are positive.
            if try_offset >= try_end || handler_offset >= handler_end {
                return Err(Error::CodegenFailed(format!(
                    "exception clause has an empty region \
                     (try={try_offset}..{try_end}, handler={handler_offset}..{handler_end})"
                )));
            }

            // Validate offsets are within bytecode bounds. After the EH-aware
            // block linearizer, try blocks should always precede their handlers
            // and offsets should be in-bounds.
            if try_offset >= bytecode_len
                || handler_offset >= bytecode_len
                || try_end > bytecode_len
                || handler_end > bytecode_len
            {
                return Err(Error::CodegenFailed(format!(
                    "Exception handler offsets out of bounds \
                     (try={try_offset}..{try_end}, handler={handler_offset}..{handler_end}, \
                     bytecode_len={bytecode_len}); regions try={:?} handler={:?}, \
                     {} block offsets recorded, highest {:?}",
                    eh.protected_range.map(|r| (r.start(), r.end())),
                    eh.handler_range.map(|r| (r.start(), r.end())),
                    self.method.block_offsets.len(),
                    self.method.block_offsets.values().max(),
                )));
            }

            handlers.push(ExceptionHandler {
                flags: eh.flags,
                try_offset,
                try_length: try_end.saturating_sub(try_offset),
                handler_offset,
                handler_length: handler_end.saturating_sub(handler_offset),
                handler: None,
                filter_offset,
            });
        }

        Ok(handlers)
    }

    /// The byte extent of the blocks `range` covers, as emitted.
    ///
    /// The region is every layout entry that belongs to it: its blocks, and
    /// the edge blocks carrying phi copies out of them, which run as part of
    /// the region. They must be contiguous in the layout - an exception clause
    /// names one span of bytes - and the region ends where the next entry after
    /// them begins, or with the method.
    ///
    /// # Returns
    ///
    /// `(start, end)`, or `None` when none of the region's blocks was emitted.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EhRegionNotContiguous`] when the layout interleaves the
    /// region with code that is not in it, which no exception clause can
    /// describe.
    fn region_span(&self, range: BlockRange, code_len: u32) -> Result<Option<(u32, u32)>> {
        let belongs = |entry: &LayoutEntry| match *entry {
            LayoutEntry::Block(block) | LayoutEntry::SplitEdge { from: block, .. } => {
                block >= range.start() && block < range.end()
            }
        };
        let mut members = self
            .method
            .layout_offsets
            .iter()
            .enumerate()
            .filter(|(_, (entry, _))| belongs(entry))
            .map(|(index, _)| index);
        let Some(first) = members.next() else {
            return Ok(None);
        };
        let last = members.next_back().unwrap_or(first);
        if let Some((intruder, _)) = self
            .method
            .layout_offsets
            .get(first..=last)
            .into_iter()
            .flatten()
            .find(|(entry, _)| !belongs(entry))
        {
            return Err(Error::EhRegionNotContiguous {
                start: range.start(),
                end: range.end(),
                intruder: format!("{intruder:?}"),
            });
        }
        let start = self
            .method
            .layout_offsets
            .get(first)
            .map_or(code_len, |(_, offset)| *offset);
        let end = self
            .method
            .layout_offsets
            .get(last.saturating_add(1))
            .map_or(code_len, |(_, offset)| *offset);
        Ok(Some((start, end)))
    }

    /// Returns the types of any temporary locals allocated during code generation.
    ///
    /// These are locals that were created for PHI copy cycles or other codegen needs,
    /// beyond the original locals from the SSA function. The returned map contains
    /// (local_index -> type) pairs for these temporaries.
    ///
    /// This should be called after `generate_with_assembly` to get the types needed
    /// for generating a correct local variable signature.
    #[must_use]
    pub fn local_types(&self) -> &BTreeMap<u16, SsaType> {
        &self.method.local_types
    }

    /// Returns the mapping from original local indices to compacted indices.
    ///
    /// This should be called after `generate_with_assembly` to get the mapping needed
    /// for building local signatures with correct types from original SSA.
    #[must_use]
    pub fn original_local_mapping(&self) -> &BTreeMap<u16, u16> {
        &self.method.original_to_compacted
    }

    /// Returns the mapping from block IDs to their byte offsets in the generated code.
    ///
    /// This is used for remapping exception handler offsets. After code generation,
    /// the map contains each block's start offset in the new bytecode layout.
    ///
    /// This should be called after `generate_with_assembly` to get the offsets for
    /// exception handler remapping.
    #[must_use]
    pub fn block_offsets(&self) -> &BTreeMap<usize, u32> {
        &self.method.block_offsets
    }

    fn generate_internal(
        &mut self,
        ssa: &SsaFunction,
        assembly: Option<&mut CilAssembly>,
    ) -> Result<(Vec<u8>, u16, u16)> {
        // A handler phi and the values a throw hands it share one place, since
        // no copy runs on an exceptional edge. A value one of them shares with
        // other code - two locals a rewrite found both start as zero - gets a
        // copy of its own first, or the place would have to hold two values at
        // once (`SsaFunction::isolate_exceptional_operands`).
        let isolated;
        let ssa = if ssa.has_exception_handlers() {
            let mut copy = ssa.clone();
            if copy.isolate_exceptional_operands()? > 0 {
                isolated = copy;
                &isolated
            } else {
                ssa
            }
        } else {
            ssa
        };

        // A fresh method state. protected_tokens, array_parent_type, the
        // string, array and TypeSpec caches accumulate across the methods of
        // one session: all methods share the same parent TypeDef, a value
        // interned for one method is the same row for the next, and the field
        // tokens must survive until cleanup.
        self.method = MethodState {
            index: MethodIndex::of(ssa),
            ..MethodState::default()
        };
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            let mut pending: Vec<OpTag> = Vec::new();
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                let tag = OpTag {
                    block: block_idx,
                    instr: instr_idx,
                };
                for dest in instr.op().defs() {
                    self.method.def_sites.insert(dest, tag);
                }
                if Self::is_prefix(instr.op()) {
                    pending.push(tag);
                } else if !pending.is_empty() {
                    self.method
                        .prefixes
                        .insert(tag, std::mem::take(&mut pending));
                }
            }
            if !pending.is_empty() {
                return Err(Error::CodegenFailed(format!(
                    "block {block_idx} ends in a prefix with nothing to modify"
                )));
            }
        }

        // The validator below checks the generated code against this SSA, so
        // the SSA must be well-formed: a read of nothing, or a phi short an
        // operand, would make it check against nonsense. Checked before the
        // assembly is touched.
        // Two kinds of finding say nothing about the code: a cosmetic one (a
        // variable nothing defines and nothing reads, an id left behind by
        // pruning), and a stale use list, since emission builds its own
        // def-use index from the instructions and never reads the recorded one.
        let mut findings = SsaVerifier::new(ssa).verify(VerifyLevel::Standard);
        findings.retain(|finding| {
            !finding.is_cosmetic() && !matches!(finding, VerifierError::StaleUseList { .. })
        });
        if !findings.is_empty() {
            let shown: Vec<String> = findings.iter().take(5).map(ToString::to_string).collect();
            return Err(Error::CodegenFailed(format!(
                "the SSA handed to code generation is malformed ({} findings: {})",
                findings.len(),
                shown.join("; ")
            )));
        }

        // Phase 0: Pre-intern all decrypted strings (if assembly provided)
        if let Some(assembly) = assembly {
            self.preintern_decrypted_values(ssa, assembly)?;
        }

        // Phase 1: storage.
        let storage = Storage::build(ssa)?;
        self.method.slot_types = storage.local_types().to_vec();
        self.method.declared = storage.declared().to_vec();
        for (slot, original) in self.method.declared.iter().enumerate() {
            if let (Some(original), Ok(slot)) = (original, u16::try_from(slot)) {
                self.method.original_to_compacted.insert(*original, slot);
            }
        }
        self.method.storage = Some(storage);

        // Phase 2: Create block labels using actual block IDs (not sequential indices)
        for block in ssa.blocks() {
            let block_id = block.id();
            self.method
                .block_labels
                .insert(block_id, format!("block_{block_id}"));
        }
        // Also collect all branch targets and create labels for them
        self.collect_branch_targets(ssa);

        // Phase 3: Generate code
        let mut encoder = InstructionEncoder::new();

        // Set expected stack depth for exception handler entry blocks.
        // Catch and filter handlers start with the exception object already on the stack.
        for handler in ssa.exception_handlers() {
            // Catch handler entry: exception object is on the stack (depth 1)
            if let Some(handler_block) = handler.handler_range.map(|range| range.start()) {
                if matches!(handler.kind(), HandlerKind::Catch | HandlerKind::Filter) {
                    if let Some(label) = self.method.block_labels.get(&handler_block) {
                        encoder.set_label_stack_depth(label, 1);
                    }
                }
            }
            // Filter block entry: exception object is on the stack (depth 1).
            // A filter range only exists on a filter clause, so its presence is
            // the kind test.
            if let Some(filter_block) = handler.filter_range.map(|range| range.start()) {
                if let Some(label) = self.method.block_labels.get(&filter_block) {
                    encoder.set_label_stack_depth(label, 1);
                }
            }
        }

        // Collect branch targets - blocks that are referenced by some branch instruction
        let branch_targets: BTreeSet<usize> = self.method.block_labels.keys().copied().collect();

        // Include the blocks control can reach that have ops or are branch
        // targets (even if they only have undecomposed instructions). Blocks
        // that are branch targets must be included so their labels can be
        // defined. A block nothing reaches is left out: a handler whose
        // protected code is gone would otherwise be emitted with no clause to
        // enter it, and a clause with no handler would leave its protected
        // code unguarded.
        let reached = Self::reachable_blocks(ssa);
        let blocks_to_include: BTreeSet<usize> = ssa
            .blocks()
            .iter()
            .filter(|b| !b.instructions().is_empty() || branch_targets.contains(&b.id()))
            .map(SsaBlock::id)
            .filter(|block| reached.contains(block))
            .collect();

        // Compute optimal block layout to minimize unnecessary branches.
        // This reorders blocks so that fall-through paths don't need explicit jumps.
        let block_ids = Self::compute_block_layout(ssa, &blocks_to_include);

        // Give every phi-carrying edge out of a multi-way terminator its own block, and
        // register a label for it, so the copies are ordinary layout entries rather than
        // runs spliced into branch emission.
        let layout = self.expand_layout_with_edge_blocks(ssa, &block_ids);

        for idx in 0..layout.len() {
            let Some(&entry) = layout.get(idx) else {
                continue;
            };

            // Fall-through is available only to whatever the *next entry* is. Naming the
            // entry rather than a block id is what makes the elision safe by construction:
            // an edge block between two blocks is itself an entry, so it suppresses the
            // elision on its own instead of each branch helper having to predict that code
            // will be emitted after it.
            let next_entry = layout.get(idx.saturating_add(1)).copied();

            match entry {
                LayoutEntry::Block(block_id) => {
                    if ssa.block(block_id).is_none() {
                        continue;
                    }
                    // Record block start offset for exception handler remapping
                    let pos_before = encoder.current_position();
                    self.method.block_offsets.insert(block_id, pos_before);

                    self.generate_block(&mut encoder, ssa, block_id, next_entry)?;
                }
                LayoutEntry::SplitEdge { from, to } => {
                    self.generate_edge_block(&mut encoder, ssa, from, to, next_entry)?;
                }
            }
        }

        // Phase 4: Finalize and resolve labels
        let (bytecode, max_stack, final_label_positions) = encoder.finalize()?;

        // Phase 5: Update block_offsets with final positions (after branch optimization)
        // The branch optimizer in finalize() may shrink branches, changing positions.
        // We need to use the final label positions to get accurate block offsets.
        for (&block_id, label) in &self.method.block_labels {
            if let Some(&position) = final_label_positions.get(label) {
                self.method.block_offsets.insert(block_id, position);
            }
        }
        for &entry in &layout {
            let label = match entry {
                LayoutEntry::Block(block_id) => self.method.block_labels.get(&block_id),
                LayoutEntry::SplitEdge { from, to } => {
                    self.method.split_edge_labels.get(&(from, to))
                }
            };
            let position = label
                .and_then(|label| final_label_positions.get(label))
                .ok_or_else(|| {
                    Error::CodegenFailed(format!("layout entry {entry:?} has no emitted position"))
                })?;
            self.method.layout_offsets.push((entry, *position));
        }

        let num_locals = u16::try_from(self.method.slot_types.len()).map_err(|_| {
            Error::CodegenFailed("the method needs more than 65535 locals".to_string())
        })?;
        for (slot, slot_type) in self.method.slot_types.iter().enumerate() {
            if let Ok(slot) = u16::try_from(slot) {
                self.method.local_types.insert(slot, slot_type.clone());
            }
        }

        // A body that reads a value other than the one the SSA names, reorders
        // an effect or truncates a value is not emitted: the method keeps its
        // original body rather than computing something else.
        let locals = self.validation_slot_types(ssa);
        #[allow(clippy::cast_possible_truncation)]
        let handlers = self.remap_exception_handlers(ssa, bytecode.len() as u32)?;
        validate(&Validation {
            ssa,
            bytecode: &bytecode,
            handlers: &handlers,
            layout: &self.method.layout_offsets,
            groups: &self.method.emit_groups,
            locals: &locals,
        })?;

        Ok((bytecode, max_stack, num_locals))
    }

    /// Pre-interns all decrypted values in the SSA into the assembly's metadata.
    ///
    /// - `DecryptedString`: added to the #US heap for `ldstr` emission
    /// - `DecryptedArray`: creates FieldRVA + FieldDef entries for
    ///   `RuntimeHelpers.InitializeArray` emission (compact, O(1) instructions)
    fn preintern_decrypted_values(
        &mut self,
        ssa: &SsaFunction,
        assembly: &mut CilAssembly,
    ) -> Result<()> {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::Const {
                        value: ConstValue::DecryptedString(s),
                        ..
                    } if !self.interned_strings.contains_key(s.as_ref()) => {
                        let change_ref = assembly.userstring_add(s)?;
                        self.interned_strings
                            .insert(s.to_string(), change_ref.placeholder());
                        self.interned_this_method
                            .push(Interned::String(s.to_string()));
                    }
                    SsaOp::LoadElement { elem_type: ty, .. }
                    | SsaOp::StoreElement { elem_type: ty, .. }
                    | SsaOp::LoadIndirect { value_type: ty, .. }
                    | SsaOp::StoreIndirect { value_type: ty, .. }
                        if emitter::needs_type_spec(ty) && !self.type_specs.contains_key(ty) =>
                    {
                        let token = self.intern_type_spec(ty, assembly)?;
                        self.type_specs.insert(ty.clone(), token);
                        self.interned_this_method
                            .push(Interned::TypeSpec(ty.clone()));
                    }
                    SsaOp::Const {
                        value: ConstValue::DecryptedArray(arr),
                        ..
                    } if !self.interned_arrays.contains_key(&arr.data) => {
                        let info = self.intern_array_data(
                            &arr.data,
                            arr.element_type_ref.token(),
                            arr.element_size,
                            assembly,
                        )?;
                        self.interned_arrays.insert(arr.data.clone(), info);
                        self.interned_this_method
                            .push(Interned::Array(arr.data.clone()));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// The TypeSpec row whose signature is `ty`: the assembly's own when it
    /// has one, otherwise a new row.
    fn intern_type_spec(&mut self, ty: &SsaType, assembly: &mut CilAssembly) -> Result<Token> {
        let blob = encode_typespec_signature(&SignatureTypeSpec {
            modifiers: CustomModifiers::default(),
            base: ty.to_type_signature(),
        })?;
        let existing = self.existing_type_specs.get_or_insert_with(|| {
            let mut rows = HashMap::new();
            let view = assembly.view();
            if let (Some(table), Some(blobs)) = (
                view.tables()
                    .and_then(|tables| tables.table::<TypeSpecRaw>()),
                view.blobs(),
            ) {
                for row in table.iter().filter_map(skip_unreadable) {
                    if let Ok(signature) = blobs.get(row.signature as usize) {
                        rows.entry(signature.to_vec()).or_insert(row.token);
                    }
                }
            }
            rows
        });
        if let Some(&token) = existing.get(&blob) {
            return Ok(token);
        }
        let signature = assembly.blob_add(&blob)?;
        let row = assembly.table_row_add(
            TableId::TypeSpec,
            TableDataOwned::TypeSpec(TypeSpecRaw {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                signature: signature.placeholder(),
            }),
        )?;
        let token = row.token().ok_or_else(|| {
            Error::CodegenFailed("table_row_add should resolve the token immediately".into())
        })?;
        if self.protected_tokens.insert(token) {
            self.interned_this_method.push(Interned::Protected(token));
        }
        self.interned_this_method
            .push(Interned::TypeSpecRow(blob.clone()));
        existing.insert(blob, token);
        Ok(token)
    }

    /// Creates FieldRVA + FieldDef metadata entries for a decrypted array,
    /// enabling compact `RuntimeHelpers.InitializeArray` emission.
    ///
    /// On the first call, creates a parent TypeDef (`<PrivateImplementationDetails>`)
    /// appended at the end of the TypeDef table. All subsequent fields are also
    /// appended, maintaining the ECMA-335 sequential TypeDef→Field ownership
    /// invariant (since it's the last TypeDef, its field range extends to the
    /// end of the Field table).
    ///
    /// # Errors
    ///
    /// Returns an error when `RuntimeHelpers.InitializeArray` cannot be named.
    fn intern_array_data(
        &mut self,
        data: &[u8],
        _element_type_token: Token,
        _element_size: usize,
        assembly: &mut CilAssembly,
    ) -> Result<InternedArrayInfo> {
        let init_array_token = self.initialize_array_method(assembly)?;

        // Track first field RID — all array-related TypeDefs use this same value
        // for field_list to maintain the monotonic ordering invariant (ECMA-335).
        // Size types own [first..first) = nothing; the parent (created last)
        // owns [first..end] = all array data fields.
        if self.array_first_field_rid.is_none() {
            self.array_first_field_rid = Some(assembly.next_rid(TableId::Field)?);
            self.interned_this_method.push(Interned::FirstArrayField);
        }

        // Choose field type: get or create a __StaticArrayInitTypeSize=N
        // nested valuetype with ClassLayout.ClassSize = data.len().
        // RuntimeHelpers.InitializeArray requires the field's type to have
        // explicit size matching the array's byte length.
        // Note: parent TypeDef is NOT created here — it's deferred to
        // finalize_array_types() so it's the LAST TypeDef, owning all fields.
        let field_sig_blob = self.get_or_create_array_size_type(data.len(), assembly)?;

        // Store the raw data as FieldRVA
        let placeholder_rva = assembly.store_field_data(data.to_vec());

        // Named by the order the session interns arrays in, so the same
        // methods compiled in the same order name their arrays the same way.
        let field_name = assembly
            .string_get_or_add(&format!("__StaticArrayInit_{}", self.interned_arrays.len()))?;

        // Create FieldDef row: static, assembly-visible, HasFieldRVA
        let field_ref = assembly.table_row_add(
            TableId::Field,
            TableDataOwned::Field(FieldRaw {
                rid: 0, // assigned by table_row_add
                token: Token::new(0),
                offset: 0,
                flags: 0x0010 | 0x0003 | 0x0100, // Static | Assembly | HasFieldRVA
                name: field_name.placeholder(),
                signature: field_sig_blob,
            }),
        )?;

        // Use the resolved token from the ChangeRef — table_row_add resolves it
        // immediately with the correct RID (original_count + insertion_order).
        let field_token = field_ref.token().ok_or_else(|| {
            Error::CodegenFailed("table_row_add should resolve the token immediately".into())
        })?;

        // Protect this field from cleanup deletion
        if self.protected_tokens.insert(field_token) {
            self.interned_this_method
                .push(Interned::Protected(field_token));
        }

        // Create FieldRVA row
        assembly.table_row_add(
            TableId::FieldRVA,
            TableDataOwned::FieldRVA(FieldRvaRaw {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                rva: placeholder_rva,
                field: field_ref.placeholder(),
            }),
        )?;

        Ok(InternedArrayInfo {
            field_token,
            initialize_array_token: init_array_token,
        })
    }

    /// Creates a parent TypeDef for interned array fields.
    ///
    /// Appends a new `<PrivateImplementationDetails>` TypeDef at the end of the
    /// TypeDef table. Its `field_list` points to the next Field RID that will be
    /// assigned, and since it's the last TypeDef, its field range extends to the
    /// end of the Field table (covering all subsequently appended fields).
    fn create_array_parent_type(
        &mut self,
        assembly: &mut CilAssembly,
        first_field_rid: u32,
    ) -> Result<Token> {
        let type_name = assembly.string_get_or_add("<PrivateImplementationDetails>")?;

        // field_list points to the first array data field. Since this TypeDef
        // is the LAST one appended, its field range extends to the end of the
        // Field table — covering all subsequently created array data fields.
        let next_field_rid = first_field_rid;

        // method_list: point past all existing methods (no methods in this type).
        let next_method_rid = assembly.next_rid(TableId::MethodDef)?;

        // ECMA-335 §II.22.37: non-interface types MUST have a non-null extends.
        let extends = self.corelib_type(assembly, "System", "Object")?;

        // Sealed | BeforeFieldInit | AutoLayout | NotPublic
        let flags: u32 = 0x0010_0100;

        let type_ref = assembly.table_row_add(
            TableId::TypeDef,
            TableDataOwned::TypeDef(TypeDefRaw {
                rid: 0,
                token: Token::new(0),
                offset: 0,
                flags,
                type_name: type_name.placeholder(),
                type_namespace: 0,
                extends,
                field_list: next_field_rid,
                method_list: next_method_rid,
            }),
        )?;

        type_ref
            .token()
            .ok_or_else(|| Error::ModificationInvalid("Failed to resolve TypeDef token".into()))
    }

    /// The core library type `namespace.name`, as the module names it: its
    /// own reference into the core library, one this session added, or - in
    /// the core library itself - its own definition.
    ///
    /// # Errors
    ///
    /// Returns an error when the module references no core library and does
    /// not define the type either.
    fn corelib_type(
        &mut self,
        assembly: &mut CilAssembly,
        namespace: &'static str,
        name: &'static str,
    ) -> Result<CodedIndex> {
        if let Some(found) = assembly.find_corelib_type(namespace, name) {
            return Ok(found);
        }
        if let Some(added) = self.corelib_types.get(&(namespace, name)) {
            return Ok(added.clone());
        }
        let Some(scope) = assembly.find_core_library_ref() else {
            return Err(Error::CodegenFailed(format!(
                "{namespace}.{name} cannot be named: the module references no core library and \
                 does not define it"
            )));
        };
        let added = TypeRefBuilder::new()
            .name(name)
            .namespace(namespace)
            .resolution_scope(CodedIndex::new(
                TableId::AssemblyRef,
                scope.row,
                CodedIndexType::ResolutionScope,
            ))
            .build(assembly)?
            .token()
            .ok_or_else(|| {
                Error::CodegenFailed("table_row_add should resolve the token immediately".into())
            })?;
        let index = CodedIndex::new(TableId::TypeRef, added.row(), CodedIndexType::TypeDefOrRef);
        self.corelib_types.insert((namespace, name), index.clone());
        self.interned_this_method
            .push(Interned::CorelibType(namespace, name));
        if self.protected_tokens.insert(added) {
            self.interned_this_method.push(Interned::Protected(added));
        }
        Ok(index)
    }

    /// The core library's `RuntimeHelpers.InitializeArray(Array,
    /// RuntimeFieldHandle)`: the module's own reference when it has one with
    /// that signature, otherwise one added with the type references it needs.
    ///
    /// # Errors
    ///
    /// Returns an error when the core library's types cannot be named.
    fn initialize_array_method(&mut self, assembly: &mut CilAssembly) -> Result<Token> {
        if let Some(token) = self.initialize_array {
            return Ok(token);
        }
        let helpers = self.corelib_type(
            assembly,
            "System.Runtime.CompilerServices",
            "RuntimeHelpers",
        )?;
        let array = self.corelib_type(assembly, "System", "Array")?;
        let handle = self.corelib_type(assembly, "System", "RuntimeFieldHandle")?;
        let signature = SignatureMethod {
            has_this: false,
            explicit_this: false,
            default: true,
            vararg: false,
            cdecl: false,
            stdcall: false,
            thiscall: false,
            fastcall: false,
            unmanaged: false,
            param_count_generic: 0,
            param_count: 2,
            return_type: SignatureParameter {
                modifiers: Vec::new(),
                by_ref: false,
                base: TypeSignature::Void,
            },
            params: vec![
                SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::Class(array.token),
                },
                SignatureParameter {
                    modifiers: Vec::new(),
                    by_ref: false,
                    base: TypeSignature::ValueType(handle.token),
                },
            ],
            varargs: Vec::new(),
        };
        let wanted = encode_method_signature(&signature)?;

        let existing = {
            let view = assembly.view();
            match (view.tables(), view.strings(), view.blobs()) {
                (Some(tables), Some(strings), Some(blobs)) => tables
                    .table::<MemberRefRaw>()
                    .into_iter()
                    .flat_map(|table| table.iter().filter_map(skip_unreadable))
                    .find(|row| {
                        row.class.tag == helpers.tag
                            && row.class.row == helpers.row
                            && strings
                                .get(row.name as usize)
                                .is_ok_and(|name| name == "InitializeArray")
                            && blobs
                                .get(row.signature as usize)
                                .is_ok_and(|found| found == wanted.as_slice())
                    })
                    .map(|row| row.token),
                _ => None,
            }
        };
        let token = match existing {
            Some(token) => token,
            None => {
                let added = MemberRefBuilder::new()
                    .name("InitializeArray")
                    .class(CodedIndex::new(
                        helpers.tag,
                        helpers.row,
                        CodedIndexType::MemberRefParent,
                    ))
                    .signature(&wanted)
                    .build(assembly)?
                    .token()
                    .ok_or_else(|| {
                        Error::CodegenFailed(
                            "table_row_add should resolve the token immediately".into(),
                        )
                    })?;
                if self.protected_tokens.insert(added) {
                    self.interned_this_method.push(Interned::Protected(added));
                }
                added
            }
        };
        self.initialize_array = Some(token);
        self.interned_this_method.push(Interned::InitializeArray);
        Ok(token)
    }

    /// Gets or creates a `__StaticArrayInitTypeSize=N` nested valuetype with
    /// `ClassLayout.ClassSize = size`. Returns the blob placeholder for a field
    /// signature referencing that type.
    ///
    /// `RuntimeHelpers.InitializeArray` requires the FieldDef's type to have an
    /// explicit size (via ClassLayout) matching the array's total byte length.
    /// Using primitive types (int8, int32, etc.) causes "Field not large enough
    /// to fill array" at runtime.
    fn get_or_create_array_size_type(
        &mut self,
        size: usize,
        assembly: &mut CilAssembly,
    ) -> Result<u32> {
        // For sizes that match primitive types, use primitives directly.
        // The C# compiler does this: int64 for 8 bytes, int32 for 4, etc.
        // Mono handles primitive FieldRVA types correctly, but may have issues
        // with small ClassLayout value types.
        let primitive = match size {
            1 => Some(TypeSignature::I1),
            2 => Some(TypeSignature::I2),
            4 => Some(TypeSignature::I4),
            8 => Some(TypeSignature::I8),
            _ => None,
        };
        if let Some(prim_type) = primitive {
            let sig = SignatureField {
                modifiers: Vec::new(),
                base: prim_type,
            };
            let sig_bytes = encode_field_signature(&sig)?;
            let blob_ref = assembly.blob_add(&sig_bytes)?;
            return Ok(blob_ref.placeholder());
        }

        // Reuse existing type for this size
        let type_token = if let Some(&cached) = self.array_size_types.get(&size) {
            cached
        } else {
            // Create new __StaticArrayInitTypeSize=N nested valuetype.
            // Note: NestedClass entries linking to the parent are deferred to
            // finalize_array_types() — the parent TypeDef must be created LAST
            // to own all fields via field_list range.
            let type_name =
                assembly.string_get_or_add(&format!("__StaticArrayInitTypeSize={size}"))?;

            // A value type: the runtime reads a type as one by its base.
            let extends = self.corelib_type(assembly, "System", "ValueType")?;

            // field_list: use the SAME value as all other array types to maintain
            // the monotonic ordering invariant. Since size types own no fields,
            // their range [first..first) is empty. The parent type (created last)
            // will also use first_field_rid but own [first..end].
            let next_field_rid = self
                .array_first_field_rid
                .unwrap_or(assembly.next_rid(TableId::Field)?);
            let next_method_rid = assembly.next_rid(TableId::MethodDef)?;

            // ExplicitLayout (0x10) | Sealed (0x100) | NestedAssembly (0x05) | ANSI (0x00)
            let flags: u32 = 0x0000_0115;

            let type_ref = assembly.table_row_add(
                TableId::TypeDef,
                TableDataOwned::TypeDef(TypeDefRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    flags,
                    type_name: type_name.placeholder(),
                    type_namespace: 0,
                    extends,
                    field_list: next_field_rid,
                    method_list: next_method_rid,
                }),
            )?;

            let new_token = type_ref.token().ok_or_else(|| {
                Error::ModificationInvalid("Failed to resolve size type token".into())
            })?;

            // Add ClassLayout row: PackingSize=1, ClassSize=size
            assembly.table_row_add(
                TableId::ClassLayout,
                TableDataOwned::ClassLayout(ClassLayoutRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    packing_size: 1,
                    class_size: u32::try_from(size).unwrap_or(u32::MAX),
                    parent: type_ref.placeholder(),
                }),
            )?;

            if self.protected_tokens.insert(new_token) {
                self.interned_this_method
                    .push(Interned::Protected(new_token));
            }
            self.array_size_types.insert(size, new_token);
            self.interned_this_method.push(Interned::SizeType(size));
            new_token
        };

        // Build field signature: FIELD VALUETYPE <type_token>
        let sig = SignatureField {
            modifiers: Vec::new(),
            base: TypeSignature::ValueType(type_token),
        };
        let sig_bytes = encode_field_signature(&sig)?;
        let blob_ref = assembly.blob_add(&sig_bytes)?;
        Ok(blob_ref.placeholder())
    }

    /// Collects all branch targets and ensures they have labels.
    fn collect_branch_targets(&mut self, ssa: &SsaFunction) {
        for block in ssa.blocks() {
            for instr in block.instructions() {
                match instr.op() {
                    SsaOp::Jump { target } => {
                        self.method
                            .block_labels
                            .entry(*target)
                            .or_insert_with(|| format!("block_{target}"));
                    }
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    }
                    | SsaOp::BranchCmp {
                        true_target,
                        false_target,
                        ..
                    } => {
                        self.method
                            .block_labels
                            .entry(*true_target)
                            .or_insert_with(|| format!("block_{true_target}"));
                        self.method
                            .block_labels
                            .entry(*false_target)
                            .or_insert_with(|| format!("block_{false_target}"));
                    }
                    SsaOp::Switch {
                        targets, default, ..
                    } => {
                        for target in targets {
                            self.method
                                .block_labels
                                .entry(*target)
                                .or_insert_with(|| format!("block_{target}"));
                        }
                        self.method
                            .block_labels
                            .entry(*default)
                            .or_insert_with(|| format!("block_{default}"));
                    }
                    SsaOp::Leave { target } => {
                        self.method
                            .block_labels
                            .entry(*target)
                            .or_insert_with(|| format!("block_{target}"));
                    }
                    _ => {}
                }
            }
        }
    }

    /// The blocks control can reach: from the entry along terminator edges,
    /// and into a clause's filter and handler once its protected code is
    /// reached, since the runtime enters a handler only from its try.
    ///
    /// A clause whose protected region is not known is entered regardless,
    /// as nothing shows its handler cannot run.
    ///
    /// This is not analyssa's `FunctionRoots::live_blocks`. That follows a
    /// `leave` into the finallys it runs and on only from their `endfinally`,
    /// so behind a finally that never ends the leave's target is dead - but the
    /// `leave` still names it, and a block it names has to be emitted for its
    /// label to exist.
    fn reachable_blocks(ssa: &SsaFunction) -> BTreeSet<usize> {
        let handlers = ssa.exception_handlers();
        let mut entered = vec![false; handlers.len()];
        let mut reached = BTreeSet::new();
        let mut pending = vec![0usize];
        while !pending.is_empty() {
            while let Some(block) = pending.pop() {
                if !reached.insert(block) {
                    continue;
                }
                if let Some(block) = ssa.block(block) {
                    block.for_each_successor(|successor| pending.push(successor));
                }
            }
            for (handler, entered) in handlers.iter().zip(entered.iter_mut()) {
                let protects_reached = handler
                    .protected_range
                    .is_none_or(|range| reached.range(range.start()..range.end()).next().is_some());
                if !*entered && protects_reached {
                    *entered = true;
                    pending.extend(handler.entry_blocks());
                }
            }
        }
        reached
    }

    /// Orders the blocks for emission.
    ///
    /// # Regions are laid out whole
    ///
    /// Every protected, filter and handler range is a run of block indices, and
    /// [`Self::remap_exception_handlers`] needs each one to occupy one contiguous
    /// span of the emitted code, entered at its first block. The ranges nest (or
    /// are disjoint), so they form a tree, and the layout follows it: each level
    /// is laid out over *units* - a block of that level, or a whole child region -
    /// and a child region is laid out recursively, starting from its entry block,
    /// before anything outside it. Contiguity is then a property of the
    /// construction rather than of the heuristic below.
    ///
    /// A clause's protected region is placed before its filter, and its filter
    /// before its handler, so the offsets run in the order the clause states them.
    ///
    /// # Within a level
    ///
    /// Greedy fall-through: from the level's entry, follow each block's preferred
    /// successor (a `Jump`'s target, a two-way branch's false arm, a switch's
    /// default), so the common path needs no branch. When the chain ends, the
    /// eligible unit with the lowest block index goes next, which keeps the source
    /// order wherever the fall-through gives no reason to change it.
    fn compute_block_layout(ssa: &SsaFunction, blocks_to_include: &BTreeSet<usize>) -> Vec<usize> {
        /// A region of the layout tree: a block range and its nesting.
        struct RegionNode {
            start: usize,
            end: usize,
            parent: Option<usize>,
            children: Vec<usize>,
            loose_blocks: Vec<usize>,
        }

        /// What a level of the tree is laid out over.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Unit {
            Block(usize),
            Region(usize),
        }

        // The successor a block would like to fall through to.
        fn preferred_successor(
            ssa: &SsaFunction,
            block_id: usize,
            leave_targets: &BTreeSet<usize>,
        ) -> Option<usize> {
            match ssa.block(block_id)?.control_terminator()? {
                // A `leave` target is a merge point after the handlers; falling
                // into it from the try body would pull it inside.
                SsaOp::Jump { target } => (!leave_targets.contains(target)).then_some(*target),
                SsaOp::Branch { false_target, .. } | SsaOp::BranchCmp { false_target, .. } => {
                    Some(*false_target)
                }
                SsaOp::Switch { default, .. } => Some(*default),
                _ => None,
            }
        }

        if blocks_to_include.is_empty() {
            return Vec::new();
        }

        let leave_targets: BTreeSet<usize> = ssa
            .blocks()
            .iter()
            .filter_map(|b| match b.control_terminator() {
                Some(SsaOp::Leave { target }) => Some(*target),
                _ => None,
            })
            .collect();

        // The distinct ranges, outer before inner: by start, then widest first.
        let mut ranges: Vec<(usize, usize)> = ssa
            .exception_handlers()
            .iter()
            .flat_map(|eh| [eh.protected_range, eh.filter_range, eh.handler_range])
            .flatten()
            .map(|range| (range.start(), range.end()))
            .collect();
        ranges.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        ranges.dedup();

        // Node 0 is the whole function.
        let mut nodes = vec![RegionNode {
            start: 0,
            end: usize::MAX,
            parent: None,
            children: Vec::new(),
            loose_blocks: Vec::new(),
        }];
        let mut open: Vec<usize> = vec![0];
        for &(start, end) in &ranges {
            while let Some(&top) = open.last() {
                if nodes
                    .get(top)
                    .is_some_and(|node| node.start <= start && end <= node.end)
                {
                    break;
                }
                open.pop();
            }
            let parent = open.last().copied().unwrap_or(0);
            let id = nodes.len();
            nodes.push(RegionNode {
                start,
                end,
                parent: Some(parent),
                children: Vec::new(),
                loose_blocks: Vec::new(),
            });
            if let Some(node) = nodes.get_mut(parent) {
                node.children.push(id);
            }
            open.push(id);
        }

        // Each block's innermost region. Outer ranges come first, so an inner
        // one overwrites.
        let mut innermost: BTreeMap<usize, usize> = BTreeMap::new();
        for (id, node) in nodes.iter().enumerate().skip(1) {
            for &block in blocks_to_include.range(node.start..node.end) {
                innermost.insert(block, id);
            }
        }
        for &block in blocks_to_include {
            let id = innermost.get(&block).copied().unwrap_or(0);
            if let Some(node) = nodes.get_mut(id) {
                node.loose_blocks.push(block);
            }
        }
        // The first block of region `id` this layout includes.
        let region_entry = |id: usize| {
            nodes.get(id).and_then(|node| {
                blocks_to_include
                    .range(node.start..node.end)
                    .next()
                    .copied()
            })
        };

        // The unit `block` is at `level`: itself, or the child region of `level`
        // holding it. `None` when the block is outside `level`.
        let unit_at = |block: usize, level: usize| -> Option<Unit> {
            let mut region = innermost.get(&block).copied().unwrap_or(0);
            if region == level {
                return Some(Unit::Block(block));
            }
            while let Some(parent) = nodes.get(region).and_then(|node| node.parent) {
                if parent == level {
                    return Some(Unit::Region(region));
                }
                region = parent;
            }
            None
        };

        // A clause's protected region precedes its filter, and both its handler.
        let node_of = |start: usize, end: usize| {
            nodes
                .iter()
                .position(|node| node.start == start && node.end == end && node.parent.is_some())
        };
        let mut prerequisites: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for eh in ssa.exception_handlers() {
            let protected = eh
                .protected_range
                .and_then(|range| node_of(range.start(), range.end()));
            let filter = eh
                .filter_range
                .and_then(|range| node_of(range.start(), range.end()));
            let handler = eh
                .handler_range
                .and_then(|range| node_of(range.start(), range.end()));
            for (later, earlier) in [(filter, protected), (handler, protected), (handler, filter)] {
                if let (Some(later), Some(earlier)) = (later, earlier) {
                    if later != earlier {
                        prerequisites.entry(later).or_default().push(earlier);
                    }
                }
            }
        }

        let mut layout = Vec::with_capacity(blocks_to_include.len());
        let mut placed_blocks: BTreeSet<usize> = BTreeSet::new();
        let mut placed_regions: BTreeSet<usize> = BTreeSet::new();

        // Lay out one level, entered at `entry`. Iterative over an explicit
        // stack of levels so a deeply nested method cannot overflow the stack.
        struct Level {
            id: usize,
            worklist: Vec<Unit>,
        }
        let root_entry = if blocks_to_include.contains(&0) {
            0
        } else {
            blocks_to_include.iter().next().copied().unwrap_or(0)
        };
        let mut levels = vec![Level {
            id: 0,
            worklist: unit_at(root_entry, 0).into_iter().collect(),
        }];

        while let Some(level) = levels.last_mut() {
            let id = level.id;
            if let Some(unit) = level.worklist.pop() {
                match unit {
                    Unit::Block(block) => {
                        if !placed_blocks.insert(block) {
                            continue;
                        }
                        layout.push(block);
                        if let Some(next) = preferred_successor(ssa, block, &leave_targets)
                            .filter(|next| blocks_to_include.contains(next))
                            .and_then(|next| unit_at(next, id))
                        {
                            level.worklist.push(next);
                        }
                    }
                    Unit::Region(region) => {
                        if !placed_regions.insert(region) {
                            continue;
                        }
                        // Entered at its first block: control may only enter a
                        // protected region there.
                        let entry = region_entry(region);
                        levels.push(Level {
                            id: region,
                            worklist: entry.and_then(|b| unit_at(b, region)).into_iter().collect(),
                        });
                    }
                }
                continue;
            }

            // The chain ended: the eligible unit with the lowest block index.
            let Some(node) = nodes.get(id) else {
                levels.pop();
                continue;
            };
            let mut candidates: Vec<(usize, Unit)> = node
                .loose_blocks
                .iter()
                .filter(|b| !placed_blocks.contains(b))
                .map(|&b| (b, Unit::Block(b)))
                .chain(
                    node.children
                        .iter()
                        .filter(|&&r| !placed_regions.contains(&r))
                        .filter_map(|&r| region_entry(r).map(|first| (first, Unit::Region(r)))),
                )
                .collect();
            candidates.sort_by_key(|(first, _)| *first);
            let eligible = |unit: &Unit| match unit {
                Unit::Region(r) => prerequisites
                    .get(r)
                    .is_none_or(|before| before.iter().all(|p| placed_regions.contains(p))),
                Unit::Block(_) => true,
            };
            let next = candidates
                .iter()
                .find(|(_, unit)| eligible(unit))
                .or_else(|| candidates.first())
                .map(|(_, unit)| *unit);
            match next {
                Some(unit) => level.worklist.push(unit),
                None => {
                    levels.pop();
                }
            }
        }

        layout
    }

    /// Expands a block layout into the emission order, giving every phi-carrying edge out of
    /// a multi-way terminator its own [`LayoutEntry::SplitEdge`] block.
    ///
    /// # Which edges get a block
    ///
    /// Only edges leaving `Branch`, `BranchCmp` and `Switch`. A block with a single
    /// successor has a place for its copies already — immediately before its branch, where
    /// `generate_branch_op` still emits them — and an edge out of a single-successor block
    /// is never critical, so it cannot need one.
    ///
    /// # Where they go
    ///
    /// Directly after the block the edge leaves, preferred-successor edge first. That keeps
    /// each edge block inside whatever EH region its source block is in (a protected region
    /// can only be left by `leave`, so a two-way branch never crosses out of one), and lets
    /// the source block fall through into the edge it most likely takes.
    ///
    /// The edges are registered in `split_edge_labels` as they are placed, which is what
    /// makes [`Self::edge_label`] and [`Self::edge_destination`] agree with the layout: a
    /// branch names the edge block exactly when the layout created one.
    ///
    fn expand_layout_with_edge_blocks(
        &mut self,
        ssa: &SsaFunction,
        block_ids: &[usize],
    ) -> Vec<LayoutEntry> {
        let mut layout: Vec<LayoutEntry> = Vec::with_capacity(block_ids.len());

        for &block_id in block_ids {
            layout.push(LayoutEntry::Block(block_id));

            let Some(block) = ssa.block(block_id) else {
                continue;
            };

            // Preferred successor first, matching `compute_block_layout::preferred_successor`,
            // so the edge block that can be reached by fall-through is the adjacent one.
            let edge_targets: Vec<usize> = match block.control_terminator() {
                Some(
                    SsaOp::Branch {
                        true_target,
                        false_target,
                        ..
                    }
                    | SsaOp::BranchCmp {
                        true_target,
                        false_target,
                        ..
                    },
                ) => vec![*false_target, *true_target],
                Some(SsaOp::Switch {
                    targets, default, ..
                }) => {
                    let mut all = Vec::with_capacity(targets.len().saturating_add(1));
                    all.push(*default);
                    all.extend(targets.iter().copied());
                    all
                }
                _ => continue,
            };

            for to in edge_targets {
                // A switch may name the same target more than once, and a two-way branch
                // may name the same block on both edges. One edge, one block.
                if self.method.split_edge_labels.contains_key(&(block_id, to)) {
                    continue;
                }
                let carries_copies = self
                    .method
                    .storage
                    .as_ref()
                    .is_some_and(|storage| !storage.copies_on(ssa, block_id, to).is_empty());
                if !carries_copies {
                    continue;
                }

                self.method
                    .split_edge_labels
                    .insert((block_id, to), format!("edge_{block_id}_{to}"));
                layout.push(LayoutEntry::SplitEdge { from: block_id, to });
            }
        }

        layout
    }

    /// Emits the instruction `tag` names, assuming its operands are on the
    /// stack, preceded by any prefix instructions that modify it, and records
    /// the instructions as implementing it, for the translation validator.
    fn generate_op_core(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        tag: OpTag,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        for prefix in self.method.prefixes.get(&tag).cloned().unwrap_or_default() {
            let op = Self::op_at(ssa, prefix)?;
            let start = encoder.instruction_count();
            self.generate_op_core_untracked(encoder, ssa, prefix.block, op, None)?;
            self.record_group(start, encoder.instruction_count(), prefix);
        }
        let op = Self::op_at(ssa, tag)?;
        let start = encoder.instruction_count();
        self.generate_op_core_untracked(encoder, ssa, tag.block, op, next_entry)?;
        self.record_group(start, encoder.instruction_count(), tag);
        Ok(())
    }

    /// The operation at `tag`.
    fn op_at(ssa: &SsaFunction, tag: OpTag) -> Result<&SsaOp> {
        ssa.block(tag.block)
            .and_then(|block| block.instructions().get(tag.instr))
            .map(|instr| instr.op())
            .ok_or_else(|| {
                Error::CodegenFailed(format!("B{}:{} does not exist", tag.block, tag.instr))
            })
    }

    /// Records instructions `[start, end)` as implementing `tag`.
    fn record_group(&mut self, start: usize, end: usize, tag: OpTag) {
        if start < end {
            self.method.emit_groups.push(EmitGroup { start, end, tag });
        }
    }

    /// Materialises the constant `var` is defined as, recording it as that
    /// definition.
    fn emit_constant_of(
        &mut self,
        encoder: &mut InstructionEncoder,
        var: SsaVarId,
        value: &ConstValue,
    ) -> Result<()> {
        let start = encoder.instruction_count();
        self.generate_const(encoder, value)?;
        if let Some(&tag) = self.method.def_sites.get(&var) {
            self.record_group(start, encoder.instruction_count(), tag);
        }
        Ok(())
    }

    /// [`Self::generate_op_core`] without the record.
    fn generate_op_core_untracked(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        op: &SsaOp,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        match op {
            SsaOp::Const { dest, value } => {
                self.generate_const(encoder, value)?;
                // Don't store - the caller will handle the value
                // (it's left on the stack for the consumer)
                let _ = dest; // Silence unused warning
            }

            // Arithmetic and bitwise operations
            SsaOp::Add { .. }
            | SsaOp::Sub { .. }
            | SsaOp::Mul { .. }
            | SsaOp::Div { .. }
            | SsaOp::Rem { .. }
            | SsaOp::AddOvf { .. }
            | SsaOp::SubOvf { .. }
            | SsaOp::MulOvf { .. }
            | SsaOp::And { .. }
            | SsaOp::Or { .. }
            | SsaOp::Xor { .. }
            | SsaOp::Shl { .. }
            | SsaOp::Shr { .. }
            | SsaOp::Neg { .. }
            | SsaOp::Not { .. } => Self::generate_arithmetic_op(encoder, op)?,

            // Conversion operations
            SsaOp::IntConv { .. }
            | SsaOp::IntToPtr { .. }
            | SsaOp::PtrToInt { .. }
            | SsaOp::IntToFloat { .. }
            | SsaOp::FloatToInt { .. }
            | SsaOp::FloatConv { .. }
            | SsaOp::Ckfinite { .. } => {
                Self::generate_conversion_op(encoder, op)?;
            }

            // Comparison operations
            SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. } => {
                Self::generate_comparison_op(encoder, op)?;
            }

            // Call operations
            SsaOp::Call { .. }
            | SsaOp::CallVirt { .. }
            | SsaOp::CallIndirect { .. }
            | SsaOp::NewObj { .. } => Self::generate_call_op(encoder, op)?,

            // Load, store, and memory operations
            SsaOp::Copy { .. }
            | SsaOp::LoadField { .. }
            | SsaOp::StoreField { .. }
            | SsaOp::LoadStaticField { .. }
            | SsaOp::StoreStaticField { .. }
            | SsaOp::LoadElement { .. }
            | SsaOp::StoreElement { .. }
            | SsaOp::ArrayLength { .. }
            | SsaOp::NewArr { .. }
            | SsaOp::Box { .. }
            | SsaOp::Unbox { .. }
            | SsaOp::UnboxAny { .. }
            | SsaOp::CastClass { .. }
            | SsaOp::IsInst { .. }
            | SsaOp::SizeOf { .. }
            | SsaOp::LoadToken { .. }
            | SsaOp::LoadArg { .. }
            | SsaOp::LoadLocal { .. }
            | SsaOp::LoadArgAddr { .. }
            | SsaOp::LoadLocalAddr { .. }
            | SsaOp::LoadFieldAddr { .. }
            | SsaOp::LoadStaticFieldAddr { .. }
            | SsaOp::LoadFunctionPtr { .. }
            | SsaOp::LoadVirtFunctionPtr { .. }
            | SsaOp::LocalAlloc { .. }
            | SsaOp::InitObj { .. }
            | SsaOp::LoadObj { .. }
            | SsaOp::StoreObj { .. }
            | SsaOp::LoadIndirect { .. }
            | SsaOp::StoreIndirect { .. }
            | SsaOp::LoadElementAddr { .. }
            | SsaOp::InitBlk { .. }
            | SsaOp::CopyBlk { .. }
            | SsaOp::CopyObj { .. }
            | SsaOp::ArgList { .. }
            | SsaOp::MakeTypedRef { .. }
            | SsaOp::TypedRefValue { .. }
            | SsaOp::TypedRefType { .. } => self.generate_load_store_op(encoder, op)?,

            // Branch and control flow operations
            SsaOp::Return { .. }
            | SsaOp::Jump { .. }
            | SsaOp::Branch { .. }
            | SsaOp::Switch { .. }
            | SsaOp::Throw { .. }
            | SsaOp::Rethrow
            | SsaOp::Leave { .. }
            | SsaOp::EndFinally
            | SsaOp::EndFilter { .. }
            | SsaOp::BranchCmp { .. } => {
                self.generate_branch_op(encoder, ssa, current_block_idx, op, next_entry)?;
            }

            // Simple standalone operations
            SsaOp::Pop { .. } => {
                encoder.emit_instruction("pop", None)?;
            }

            SsaOp::Nop => {
                encoder.emit_instruction("nop", None)?;
            }

            SsaOp::Break(_) => {
                encoder.emit_instruction("break", None)?;
            }

            // Prefix instructions
            SsaOp::Constrained {
                constraint_type, ..
            } => {
                encoder.emit_instruction(
                    "constrained.",
                    Some(Operand::Token(constraint_type.token())),
                )?;
            }

            SsaOp::Volatile => {
                encoder.emit_instruction("volatile.", None)?;
            }

            SsaOp::Unaligned { alignment } => {
                encoder.emit_instruction(
                    "unaligned.",
                    Some(Operand::Immediate(Immediate::UInt8(*alignment))),
                )?;
            }

            SsaOp::TailPrefix => {
                encoder.emit_instruction("tail.", None)?;
            }

            SsaOp::Readonly => {
                encoder.emit_instruction("readonly.", None)?;
            }

            // CIL has no rotate or byte-swap instruction, but both are what the
            // algebraic pass folds a shift-and-or idiom into, and what the x86
            // lift produces for `rol`/`ror`/`bswap`. They are spelled back out
            // in shifts.
            SsaOp::Rol {
                dest,
                value,
                amount,
            } => self.generate_rotate(encoder, ssa, *dest, *value, *amount, true)?,
            SsaOp::Ror {
                dest,
                value,
                amount,
            } => self.generate_rotate(encoder, ssa, *dest, *value, *amount, false)?,
            SsaOp::BSwap { dest, src } => self.generate_byte_swap(encoder, ssa, *dest, *src)?,

            // Settled at the entry of the block it leads, before scheduling.
            SsaOp::RuntimeValue { dest, .. } => {
                return Err(Error::CodegenFailed(format!(
                    "runtime value {dest} was not settled at its block's entry"
                )));
            }

            SsaOp::Phi { .. }
            | SsaOp::Fence { .. }
            | SsaOp::InterruptReturn
            | SsaOp::Unreachable => {
                // Phi nodes are eliminated during code generation - no instruction emitted
            }

            // Anything else has no CIL spelling. Emitting nothing for it would
            // drop a computation - its result never pushed, its effect never
            // made - so the method fails to compile instead and keeps its
            // original body.
            _ => {
                return Err(Error::CodegenFailed(format!("no CIL lowering for {op:?}")));
            }
        }
        Ok(())
    }

    /// The integer width an operation on a value of `var` is taken at, and
    /// whether the value is signed.
    ///
    /// Reads the variable's own type, falling back to `fallback`'s when it has
    /// none. A native integer has no width known here, so it has none.
    fn integer_width(ssa: &SsaFunction, var: SsaVarId, fallback: SsaVarId) -> Option<(u32, bool)> {
        let width_of = |id: SsaVarId| {
            let var_type = ssa.variable(id)?.var_type();
            match var_type {
                SsaType::I8 => Some((8, true)),
                SsaType::U8 | SsaType::Bool => Some((8, false)),
                SsaType::I16 => Some((16, true)),
                SsaType::U16 | SsaType::Char => Some((16, false)),
                SsaType::I32 => Some((32, true)),
                SsaType::U32 => Some((32, false)),
                SsaType::I64 => Some((64, true)),
                SsaType::U64 => Some((64, false)),
                _ => None,
            }
        };
        width_of(var).or_else(|| width_of(fallback))
    }

    /// Emits a constant of the evaluation-stack type a `width`-bit integer
    /// occupies: `int64` for 64 bits, `int32` below.
    fn emit_width_const(encoder: &mut InstructionEncoder, width: u32, value: u64) -> Result<()> {
        if width == 64 {
            #[allow(clippy::cast_possible_wrap)] // The bit pattern is the constant.
            let value = value as i64;
            encoder
                .emit_instruction("ldc.i8", Some(Operand::Immediate(Immediate::Int64(value))))?;
        } else {
            #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
            // Below 64 bits the constant fits the low 32 bits of its pattern.
            let value = value as u32 as i32;
            emitter::emit_ldc_i4(encoder, value)?;
        }
        Ok(())
    }

    /// Re-establishes a sub-word result in the form its type is held on the
    /// evaluation stack: sign-extended for a signed type, zero-extended for an
    /// unsigned one. Full-width results need nothing.
    fn emit_subword_normalize(
        encoder: &mut InstructionEncoder,
        width: u32,
        signed: bool,
    ) -> Result<()> {
        let conv = match (width, signed) {
            (8, true) => "conv.i1",
            (8, false) => "conv.u1",
            (16, true) => "conv.i2",
            (16, false) => "conv.u2",
            _ => return Ok(()),
        };
        encoder.emit_instruction(conv, None)
    }

    /// Emits a rotate of the two operands on the stack (value, then amount).
    ///
    /// A rotate by `r` at width `w` is `(x << (r & (w-1))) | (x >>> (-r & (w-1)))`
    /// with the right shift logical. The count is reduced modulo the width as
    /// every ISA's rotate reduces it, and the masked negation makes a count of
    /// zero shift both halves by zero rather than one of them by the full width,
    /// which CIL leaves unspecified. A sub-word value is zero-extended first so
    /// the right shift brings in its own bits rather than the stack's sign
    /// extension, and the result is narrowed back to its type.
    ///
    /// # Errors
    ///
    /// Returns an error when the value's width is not known, as for a native
    /// integer, whose width depends on the platform the method runs on.
    fn generate_rotate(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        dest: SsaVarId,
        value: SsaVarId,
        amount: SsaVarId,
        left: bool,
    ) -> Result<()> {
        let (width, signed) = Self::integer_width(ssa, dest, value).ok_or_else(|| {
            Error::CodegenFailed(format!(
                "rotate of {value} has no fixed integer width to lower it at"
            ))
        })?;
        let mask = u64::from(width.saturating_sub(1));
        let value_type = if width == 64 {
            SsaType::I64
        } else {
            SsaType::I32
        };

        // A shift count is an `int32` on the CIL stack; a 64-bit amount is
        // narrowed, which keeps every bit the mask below reads.
        let amount_is_wide = ssa
            .variable(amount)
            .is_some_and(|var| matches!(var.var_type(), SsaType::I64 | SsaType::U64));
        if amount_is_wide {
            encoder.emit_instruction("conv.i4", None)?;
        }
        let amount_slot = self.allocate_temp_local(&SsaType::I32)?;
        emitter::emit_stloc(encoder, amount_slot)?;

        if width < 32 {
            Self::emit_width_const(encoder, 32, (1u64 << width).saturating_sub(1))?;
            encoder.emit_instruction("and", None)?;
        }
        let value_slot = self.allocate_temp_local(&value_type)?;
        emitter::emit_stloc(encoder, value_slot)?;

        let (first, second) = if left {
            ("shl", "shr.un")
        } else {
            ("shr.un", "shl")
        };

        emitter::emit_ldloc(encoder, value_slot)?;
        emitter::emit_ldloc(encoder, amount_slot)?;
        Self::emit_width_const(encoder, 32, mask)?;
        encoder.emit_instruction("and", None)?;
        encoder.emit_instruction(first, None)?;

        emitter::emit_ldloc(encoder, value_slot)?;
        emitter::emit_ldloc(encoder, amount_slot)?;
        encoder.emit_instruction("neg", None)?;
        Self::emit_width_const(encoder, 32, mask)?;
        encoder.emit_instruction("and", None)?;
        encoder.emit_instruction(second, None)?;

        encoder.emit_instruction("or", None)?;
        Self::emit_subword_normalize(encoder, width, signed)?;

        self.release_temp_local(value_slot, &value_type);
        self.release_temp_local(amount_slot, &SsaType::I32);
        Ok(())
    }

    /// Emits a byte swap of the operand on the stack.
    ///
    /// Each byte lane is shifted down to the bottom, masked, and shifted up to
    /// its mirrored position, and the lanes are or-ed together. The right shifts
    /// are logical so a lane never picks up the value's sign.
    ///
    /// # Errors
    ///
    /// Returns an error when the value's width is not a whole number of bytes of
    /// at least two, or is not known.
    fn generate_byte_swap(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        dest: SsaVarId,
        src: SsaVarId,
    ) -> Result<()> {
        let (width, signed) = Self::integer_width(ssa, dest, src)
            .filter(|&(width, _)| width >= 16)
            .ok_or_else(|| {
                Error::CodegenFailed(format!(
                    "byte swap of {src} has no fixed width of two bytes or more to lower it at"
                ))
            })?;
        let value_type = if width == 64 {
            SsaType::I64
        } else {
            SsaType::I32
        };
        let value_slot = self.allocate_temp_local(&value_type)?;
        emitter::emit_stloc(encoder, value_slot)?;

        let lanes = width / 8;
        for lane in 0..lanes {
            let from = lane.saturating_mul(8);
            let to = lanes
                .saturating_sub(1)
                .saturating_sub(lane)
                .saturating_mul(8);
            emitter::emit_ldloc(encoder, value_slot)?;
            if from > 0 {
                #[allow(clippy::cast_possible_wrap)] // At most 56.
                emitter::emit_ldc_i4(encoder, from as i32)?;
                encoder.emit_instruction("shr.un", None)?;
            }
            Self::emit_width_const(encoder, width, 0xff)?;
            encoder.emit_instruction("and", None)?;
            if to > 0 {
                #[allow(clippy::cast_possible_wrap)] // At most 56.
                emitter::emit_ldc_i4(encoder, to as i32)?;
                encoder.emit_instruction("shl", None)?;
            }
            if lane > 0 {
                encoder.emit_instruction("or", None)?;
            }
        }
        Self::emit_subword_normalize(encoder, width, signed)?;

        self.release_temp_local(value_slot, &value_type);
        Ok(())
    }

    /// Generates CIL for arithmetic and bitwise operations.
    ///
    /// Handles: `Add`, `Sub`, `Mul`, `Div`, `Rem`, overflow-checked variants,
    /// `And`, `Or`, `Xor`, `Shl`, `Shr`, `Neg`, `Not`.
    /// Operands are already on the evaluation stack.
    fn generate_arithmetic_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Add { dest, .. } => {
                encoder.emit_instruction("add", None)?;
                let _ = dest;
            }

            SsaOp::Sub { dest, .. } => {
                encoder.emit_instruction("sub", None)?;
                let _ = dest;
            }

            SsaOp::Mul { dest, .. } => {
                encoder.emit_instruction("mul", None)?;
                let _ = dest;
            }

            SsaOp::Div { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("div.un", None)?;
                } else {
                    encoder.emit_instruction("div", None)?;
                }
                let _ = dest;
            }

            SsaOp::Rem { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("rem.un", None)?;
                } else {
                    encoder.emit_instruction("rem", None)?;
                }
                let _ = dest;
            }

            SsaOp::AddOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("add.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("add.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::SubOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("sub.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("sub.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::MulOvf { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("mul.ovf.un", None)?;
                } else {
                    encoder.emit_instruction("mul.ovf", None)?;
                }
                let _ = dest;
            }

            SsaOp::And { dest, .. } => {
                encoder.emit_instruction("and", None)?;
                let _ = dest;
            }

            SsaOp::Or { dest, .. } => {
                encoder.emit_instruction("or", None)?;
                let _ = dest;
            }

            SsaOp::Xor { dest, .. } => {
                encoder.emit_instruction("xor", None)?;
                let _ = dest;
            }

            SsaOp::Shl { dest, .. } => {
                encoder.emit_instruction("shl", None)?;
                let _ = dest;
            }

            SsaOp::Shr { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("shr.un", None)?;
                } else {
                    encoder.emit_instruction("shr", None)?;
                }
                let _ = dest;
            }

            SsaOp::Neg { dest, .. } => {
                encoder.emit_instruction("neg", None)?;
                let _ = dest;
            }

            SsaOp::Not { dest, .. } => {
                encoder.emit_instruction("not", None)?;
                let _ = dest;
            }

            _ => unreachable!("generate_arithmetic_op called with non-arithmetic op"),
        }
        Ok(())
    }

    /// Generates CIL for comparison operations.
    ///
    /// Handles: `Ceq`, `Clt`, `Cgt` (and unsigned variants).
    /// Operands are already on the evaluation stack.
    fn generate_comparison_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Ceq { dest, .. } => {
                encoder.emit_instruction("ceq", None)?;
                let _ = dest;
            }

            SsaOp::Clt { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("clt.un", None)?;
                } else {
                    encoder.emit_instruction("clt", None)?;
                }
                let _ = dest;
            }

            SsaOp::Cgt { dest, unsigned, .. } => {
                if *unsigned {
                    encoder.emit_instruction("cgt.un", None)?;
                } else {
                    encoder.emit_instruction("cgt", None)?;
                }
                let _ = dest;
            }

            _ => unreachable!("generate_comparison_op called with non-comparison op"),
        }
        Ok(())
    }

    /// Generates CIL for conversion operations.
    ///
    /// Handles: `Conv` (with overflow check and unsigned variants), `Ckfinite`.
    /// Operand is already on the evaluation stack.
    fn generate_conversion_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            // An integer conversion carries an overflow check and whether its
            // source is read unsigned (`.un`); integer→float carries only the
            // latter; the pointer and float-width conversions carry neither.
            SsaOp::IntConv {
                dest,
                target,
                overflow_check,
                unsigned,
                ..
            } => {
                emitter::emit_conv(encoder, target, *overflow_check, *unsigned)?;
                let _ = dest;
            }
            // A float→integer conversion's flag is the destination's sign, which
            // the opcode already names (`conv.ovf.u4`); `.un` reads a source as
            // unsigned, which a float source cannot be.
            SsaOp::FloatToInt {
                dest,
                target,
                overflow_check,
                ..
            } => {
                emitter::emit_conv(encoder, target, *overflow_check, false)?;
                let _ = dest;
            }
            SsaOp::IntToFloat {
                dest,
                target,
                unsigned,
                ..
            } => {
                emitter::emit_conv(encoder, target, false, *unsigned)?;
                let _ = dest;
            }
            SsaOp::IntToPtr { dest, target, .. }
            | SsaOp::PtrToInt { dest, target, .. }
            | SsaOp::FloatConv { dest, target, .. } => {
                emitter::emit_conv(encoder, target, false, false)?;
                let _ = dest;
            }

            SsaOp::Ckfinite { dest, .. } => {
                encoder.emit_instruction("ckfinite", None)?;
                let _ = dest;
            }

            _ => unreachable!("generate_conversion_op called with non-conversion op"),
        }
        Ok(())
    }

    /// Generates CIL for call operations.
    ///
    /// Handles: `Call`, `CallVirt`, `CallIndirect`, `NewObj`.
    /// Arguments are already on the evaluation stack.
    fn generate_call_op(encoder: &mut InstructionEncoder, op: &SsaOp) -> Result<()> {
        match op {
            SsaOp::Call {
                dest, method, args, ..
            } => {
                // num_args: the method arguments that were pushed on stack
                let num_args = call_arity(args.len())?;
                let has_result = dest.is_some();
                encoder.emit_call(
                    "call",
                    Some(Operand::Token(method.token())),
                    num_args,
                    has_result,
                )?;
                // Result left on stack - handled by caller
                let _ = dest;
            }

            SsaOp::CallVirt {
                dest, method, args, ..
            } => {
                // num_args: the method arguments that were pushed on stack
                let num_args = call_arity(args.len())?;
                let has_result = dest.is_some();
                encoder.emit_call(
                    "callvirt",
                    Some(Operand::Token(method.token())),
                    num_args,
                    has_result,
                )?;
                let _ = dest;
            }

            SsaOp::CallIndirect {
                dest,
                signature,
                args,
                ..
            } => {
                // num_args: function pointer + the method arguments
                let num_args = call_arity(args.len().saturating_add(1))?;
                let has_result = dest.is_some();
                encoder.emit_call(
                    "calli",
                    Some(Operand::Token(signature.token())),
                    num_args,
                    has_result,
                )?;
                let _ = dest;
            }

            SsaOp::NewObj { dest, ctor, args } => {
                // num_args: constructor arguments (newobj always returns the new object)
                let num_args = call_arity(args.len())?;
                encoder.emit_call("newobj", Some(Operand::Token(ctor.token())), num_args, true)?;
                let _ = dest;
            }

            _ => unreachable!("generate_call_op called with non-call op"),
        }
        Ok(())
    }

    /// Generates CIL for load, store, and memory operations.
    ///
    /// Handles field access (`LoadField`, `StoreField`, `LoadStaticField`, etc.),
    /// element access (`LoadElement`, `StoreElement`, `LoadElementAddr`),
    /// local/arg access (`LoadArg`, `LoadLocal`, `LoadArgAddr`, `LoadLocalAddr`),
    /// object operations (`Box`, `Unbox`, `CastClass`, `IsInst`, `NewArr`, etc.),
    /// indirect access (`LoadIndirect`, `StoreIndirect`, `LoadObj`, `StoreObj`),
    /// block operations (`InitBlk`, `CopyBlk`, `CopyObj`), and `Copy`.
    fn generate_load_store_op(
        &mut self,
        encoder: &mut InstructionEncoder,
        op: &SsaOp,
    ) -> Result<()> {
        match op {
            SsaOp::Copy { .. } => {
                // A copy is a move between places, which block emission makes
                // itself; it has no instruction of its own.
                return Err(Error::CodegenFailed(format!(
                    "copy {op} reached operation lowering"
                )));
            }
            SsaOp::LoadField { dest, field, .. } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("ldfld", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }
            SsaOp::StoreField { field, .. } => {
                // object and value are loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("stfld", Some(Operand::Token(field.token())))?;
            }

            SsaOp::LoadStaticField { dest, field } => {
                encoder.emit_instruction("ldsfld", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::StoreStaticField { field, .. } => {
                // value is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("stsfld", Some(Operand::Token(field.token())))?;
            }
            SsaOp::LoadElement {
                dest, elem_type, ..
            } => {
                // array and index are loaded by scheduler via get_operands_in_stack_order
                emitter::emit_ldelem(encoder, elem_type, self.type_specs.get(elem_type).copied())?;
                let _ = dest;
            }
            SsaOp::StoreElement { elem_type, .. } => {
                // array, index, and value are loaded by scheduler via get_operands_in_stack_order
                emitter::emit_stelem(encoder, elem_type, self.type_specs.get(elem_type).copied())?;
            }
            SsaOp::ArrayLength { dest, .. } => {
                // array is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("ldlen", None)?;
                let _ = dest;
            }

            SsaOp::NewArr {
                dest, elem_type, ..
            } => {
                // length is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("newarr", Some(Operand::Token(elem_type.token())))?;
                let _ = dest;
            }
            SsaOp::Box {
                dest, value_type, ..
            } => {
                // value is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("box", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::Unbox {
                dest, value_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("unbox", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }
            SsaOp::UnboxAny {
                dest, value_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("unbox.any", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }
            SsaOp::CastClass {
                dest, target_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("castclass", Some(Operand::Token(target_type.token())))?;
                let _ = dest;
            }
            SsaOp::IsInst {
                dest, target_type, ..
            } => {
                // object is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("isinst", Some(Operand::Token(target_type.token())))?;
                let _ = dest;
            }

            SsaOp::SizeOf { dest, value_type } => {
                encoder.emit_instruction("sizeof", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::LoadToken { dest, token } => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(token.token())))?;
                let _ = dest;
            }

            SsaOp::ArgList { dest } => {
                encoder.emit_instruction("arglist", None)?;
                let _ = dest;
            }

            SsaOp::MakeTypedRef {
                dest, value_type, ..
            } => {
                // address is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("mkrefany", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::TypedRefValue {
                dest, value_type, ..
            } => {
                // typed_ref is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("refanyval", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::TypedRefType { dest, .. } => {
                // typed_ref is loaded by scheduler via get_operands_in_stack_order
                encoder.emit_instruction("refanytype", None)?;
                let _ = dest;
            }

            SsaOp::LoadArg { dest, arg_index } => {
                emitter::emit_ldarg(encoder, *arg_index)?;
                let _ = dest;
            }

            SsaOp::LoadLocal { dest, local_index } => {
                emitter::emit_ldloc(encoder, self.declared_slot(*local_index)?)?;
                let _ = dest;
            }

            SsaOp::LoadArgAddr { dest, arg_index } => {
                emitter::emit_ldarga(encoder, *arg_index)?;
                let _ = dest;
            }

            SsaOp::LoadLocalAddr { dest, local_index } => {
                emitter::emit_ldloca(encoder, self.declared_slot(*local_index)?)?;
                let _ = dest;
            }

            SsaOp::LoadFieldAddr { dest, field, .. } => {
                encoder.emit_instruction("ldflda", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::LoadStaticFieldAddr { dest, field } => {
                encoder.emit_instruction("ldsflda", Some(Operand::Token(field.token())))?;
                let _ = dest;
            }

            SsaOp::LoadFunctionPtr { dest, method } => {
                encoder.emit_instruction("ldftn", Some(Operand::Token(method.token())))?;
                let _ = dest;
            }

            SsaOp::LoadVirtFunctionPtr { dest, method, .. } => {
                encoder.emit_instruction("ldvirtftn", Some(Operand::Token(method.token())))?;
                let _ = dest;
            }

            SsaOp::LocalAlloc { dest, .. } => {
                encoder.emit_instruction("localloc", None)?;
                let _ = dest;
            }

            SsaOp::InitObj { value_type, .. } => {
                encoder.emit_instruction("initobj", Some(Operand::Token(value_type.token())))?;
            }

            SsaOp::LoadObj {
                dest, value_type, ..
            } => {
                encoder.emit_instruction("ldobj", Some(Operand::Token(value_type.token())))?;
                let _ = dest;
            }

            SsaOp::StoreObj { value_type, .. } => {
                encoder.emit_instruction("stobj", Some(Operand::Token(value_type.token())))?;
            }

            SsaOp::LoadIndirect { value_type, .. } => {
                emitter::emit_ldind(
                    encoder,
                    value_type,
                    self.type_specs.get(value_type).copied(),
                )?;
            }

            SsaOp::StoreIndirect { value_type, .. } => {
                emitter::emit_stind(
                    encoder,
                    value_type,
                    self.type_specs.get(value_type).copied(),
                )?;
            }

            SsaOp::LoadElementAddr {
                dest, elem_type, ..
            } => {
                encoder.emit_instruction("ldelema", Some(Operand::Token(elem_type.token())))?;
                let _ = dest;
            }

            SsaOp::InitBlk { .. } => {
                encoder.emit_instruction("initblk", None)?;
            }

            SsaOp::CopyBlk { .. } => {
                encoder.emit_instruction("cpblk", None)?;
            }

            SsaOp::CopyObj { value_type, .. } => {
                encoder.emit_instruction("cpobj", Some(Operand::Token(value_type.token())))?;
            }

            _ => unreachable!("generate_load_store_op called with non-load/store op"),
        }
        Ok(())
    }

    /// Generates CIL for branch and control flow operations.
    ///
    /// Handles: `Return`, `Jump`, `Branch`, `Switch`, `Throw`, `Rethrow`,
    /// `Leave`, `EndFinally`, `EndFilter`, `BranchCmp`.
    /// Spills remaining stack values before control flow transfer and emits
    /// phi stores for successor blocks as needed.
    fn generate_branch_op(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        current_block_idx: usize,
        op: &SsaOp,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        match op {
            SsaOp::Return { .. } => {
                encoder.emit_instruction("ret", None)?;
            }

            SsaOp::Jump { target } => {
                // A jump has one successor, so its copies have a place already: right here,
                // before the branch. No edge block is created for it.
                self.emit_copies_from(encoder, ssa, current_block_idx)?;

                if next_entry != Some(LayoutEntry::Block(*target)) {
                    let label = self.block_label(*target);
                    // emit_branch validates stack depth at target
                    encoder.emit_branch("br", &label)?;
                }
            }

            SsaOp::Branch {
                true_target,
                false_target,
                ..
            } => {
                self.emit_conditional_branch(
                    encoder,
                    current_block_idx,
                    *true_target,
                    *false_target,
                    next_entry,
                )?;
            }

            SsaOp::Switch {
                targets, default, ..
            } => {
                self.emit_switch_branch(encoder, current_block_idx, targets, *default, next_entry)?;
            }

            SsaOp::Throw { .. } => {
                encoder.emit_instruction("throw", None)?;
            }

            SsaOp::Rethrow => {
                encoder.emit_instruction("rethrow", None)?;
            }

            SsaOp::Leave { target } => {
                // A leave has one successor, so its copies go here, before the
                // transfer. Which block that is, the phis say: a leave that
                // exits a region with a finally reaches the finally first, and
                // the finally's phis take this block's value on that edge -
                // the target's take theirs from the finally's `endfinally`.
                self.emit_copies_from(encoder, ssa, current_block_idx)?;

                let label = self.block_label(*target);
                encoder.emit_branch("leave", &label)?;
            }

            SsaOp::EndFinally => {
                // `endfinally` resumes where the `leave` that ran the finally
                // was going, and the phis there take their operand on that edge
                // from this block - the `leave` itself names no phi operand of
                // them. Their copies go here, before the transfer, which is
                // where the slot allocator puts a predecessor's phi copies.
                //
                // Every such phi has a slot of its own (see
                // `finally_resume_phis`), so the copies are sound on every way
                // out of the finally: to any of the places it resumes, and while
                // an exception unwinds through it.
                self.emit_copies_from(encoder, ssa, current_block_idx)?;

                encoder.emit_instruction("endfinally", None)?;
            }

            SsaOp::EndFilter { .. } => {
                encoder.emit_instruction("endfilter", None)?;
            }

            SsaOp::BranchCmp {
                cmp,
                unsigned,
                true_target,
                false_target,
                ..
            } => {
                // Operands are already on the stack.
                self.emit_comparison_branch(
                    encoder,
                    current_block_idx,
                    *cmp,
                    *unsigned,
                    *true_target,
                    *false_target,
                    next_entry,
                )?;
            }

            _ => unreachable!("generate_branch_op called with non-branch op"),
        }
        Ok(())
    }

    /// Gets the operands of an operation in the order they should appear on the stack.
    ///
    /// For CIL stack-based operations, operands are consumed in a specific order.
    /// This method returns operands in that order so scheduling can ensure
    /// the correct stack layout.
    #[allow(clippy::match_same_arms)] // Arms intentionally separate for semantic clarity
    fn get_operands_in_stack_order(op: &SsaOp) -> Vec<SsaVarId> {
        match op {
            // Binary operations: left on stack bottom, right on top
            SsaOp::Add { left, right, .. }
            | SsaOp::AddOvf { left, right, .. }
            | SsaOp::Sub { left, right, .. }
            | SsaOp::SubOvf { left, right, .. }
            | SsaOp::Mul { left, right, .. }
            | SsaOp::MulOvf { left, right, .. }
            | SsaOp::Div { left, right, .. }
            | SsaOp::Rem { left, right, .. }
            | SsaOp::And { left, right, .. }
            | SsaOp::Or { left, right, .. }
            | SsaOp::Xor { left, right, .. }
            | SsaOp::Ceq { left, right, .. }
            | SsaOp::Clt { left, right, .. }
            | SsaOp::Cgt { left, right, .. } => vec![*left, *right],

            // Shift and rotate operations: value on bottom, amount on top
            SsaOp::Shl { value, amount, .. }
            | SsaOp::Shr { value, amount, .. }
            | SsaOp::Rol { value, amount, .. }
            | SsaOp::Ror { value, amount, .. } => {
                vec![*value, *amount]
            }

            SsaOp::BSwap { src, .. } => vec![*src],

            // Unary operations: single operand
            SsaOp::Neg { operand, .. }
            | SsaOp::Not { operand, .. }
            | SsaOp::IntConv { operand, .. }
            | SsaOp::IntToPtr { operand, .. }
            | SsaOp::PtrToInt { operand, .. }
            | SsaOp::IntToFloat { operand, .. }
            | SsaOp::FloatToInt { operand, .. }
            | SsaOp::FloatConv { operand, .. }
            | SsaOp::Ckfinite { operand, .. } => vec![*operand],

            // Return with value
            SsaOp::Return { value: Some(v) } => vec![*v],

            // Branch condition
            SsaOp::Branch { condition, .. } => vec![*condition],

            // BranchCmp: left and right operands
            SsaOp::BranchCmp { left, right, .. } => vec![*left, *right],

            // Throw exception
            SsaOp::Throw { exception } => vec![*exception],

            // Pop value
            SsaOp::Pop { value } => vec![*value],

            // Switch value
            SsaOp::Switch { value, .. } => vec![*value],

            // Store operations: object first (if present), then value
            SsaOp::StoreField { object, value, .. } => vec![*object, *value],

            SsaOp::StoreStaticField { value, .. } => vec![*value],

            // Store element: array, index, then value
            SsaOp::StoreElement {
                array,
                index,
                value,
                ..
            } => vec![*array, *index, *value],

            // Load element: array first, then index
            SsaOp::LoadElement { array, index, .. }
            | SsaOp::LoadElementAddr { array, index, .. } => vec![*array, *index],

            // Array length
            SsaOp::ArrayLength { array, .. } => vec![*array],

            // Load field: object reference
            SsaOp::LoadField { object, .. } | SsaOp::LoadFieldAddr { object, .. } => vec![*object],

            // New array: length
            SsaOp::NewArr { length, .. } => vec![*length],

            // Boxing/unboxing operations
            SsaOp::Box { value, .. } => vec![*value],
            SsaOp::Unbox { object, .. }
            | SsaOp::UnboxAny { object, .. }
            | SsaOp::CastClass { object, .. }
            | SsaOp::IsInst { object, .. } => vec![*object],

            // Typed references: the one value each takes
            SsaOp::MakeTypedRef { address, .. } => vec![*address],
            SsaOp::TypedRefValue { typed_ref, .. } | SsaOp::TypedRefType { typed_ref, .. } => {
                vec![*typed_ref]
            }

            // Copy operation
            SsaOp::Copy { src, .. } => vec![*src],

            // Local allocation
            SsaOp::LocalAlloc { size, .. } => vec![*size],

            // Virtual function pointer
            SsaOp::LoadVirtFunctionPtr { object, .. } => vec![*object],

            // Object operations
            SsaOp::InitObj { dest_addr, .. } => vec![*dest_addr],
            SsaOp::LoadObj { src_addr, .. } => vec![*src_addr],
            SsaOp::StoreObj {
                dest_addr, value, ..
            } => vec![*dest_addr, *value],
            SsaOp::CopyObj {
                dest_addr,
                src_addr,
                ..
            } => vec![*dest_addr, *src_addr],

            // Indirect memory operations
            SsaOp::LoadIndirect { addr, .. } => vec![*addr],
            SsaOp::StoreIndirect { addr, value, .. } => vec![*addr, *value],

            // Block memory operations
            SsaOp::InitBlk {
                dest_addr,
                value,
                size,
                reverse: _,
            } => vec![*dest_addr, *value, *size],
            SsaOp::CopyBlk {
                dest_addr,
                src_addr,
                size,
                reverse: _,
            } => vec![*dest_addr, *src_addr, *size],

            // Exception handling
            SsaOp::EndFilter { result } => vec![*result],

            // Call operations: use the op's uses() method
            SsaOp::Call { .. } | SsaOp::CallVirt { .. } | SsaOp::NewObj { .. } => op.uses(),

            // `calli` takes its arguments first and the function pointer on
            // top of them; `uses` names the pointer first.
            SsaOp::CallIndirect { fptr, args, .. } => {
                let mut operands = args.clone();
                operands.push(*fptr);
                operands
            }

            // Operations with no operands. An operation with operands that is
            // missing above has no lowering either, and `generate_op_core`
            // rejects it before its operands would matter.
            _ => Vec::new(),
        }
    }

    /// Checks if an operation is a terminator (control flow instruction).
    fn is_terminator(op: &SsaOp) -> bool {
        matches!(
            op,
            SsaOp::Jump { .. }
                | SsaOp::Branch { .. }
                | SsaOp::BranchCmp { .. }
                | SsaOp::Switch { .. }
                | SsaOp::Return { .. }
                | SsaOp::Throw { .. }
                | SsaOp::Rethrow
                | SsaOp::Leave { .. }
                | SsaOp::EndFinally
                | SsaOp::EndFilter { .. }
        )
    }

    /// Loads a constant value onto the stack.
    ///
    /// Uses optimized CIL instructions where possible (ldc.i4.0 through ldc.i4.8,
    /// ldc.i4.s for small values, etc.).
    fn generate_const(&self, encoder: &mut InstructionEncoder, value: &ConstValue) -> Result<()> {
        match value {
            // 8-bit signed integers use ldc.i4.s (sign-extends to i32)
            ConstValue::I8(v) => {
                encoder
                    .emit_instruction("ldc.i4.s", Some(Operand::Immediate(Immediate::Int8(*v))))?;
            }

            // 8-bit unsigned integers: use ldc.i4.s only if value fits in signed byte,
            // otherwise use ldc.i4 to avoid incorrect sign extension
            ConstValue::U8(v) => {
                if *v <= 127 {
                    encoder.emit_instruction(
                        "ldc.i4.s",
                        Some(Operand::Immediate(Immediate::Int8((*v).cast_signed()))),
                    )?;
                } else {
                    // Value > 127 would be sign-extended incorrectly by ldc.i4.s
                    encoder.emit_instruction(
                        "ldc.i4",
                        Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                    )?;
                }
            }

            // 16-bit integers widen to i32 for ldc.i4
            ConstValue::I16(v) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                )?;
            }

            ConstValue::U16(v) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::Int32(i32::from(*v)))),
                )?;
            }

            // 32-bit signed integers have optimized forms for common values
            ConstValue::I32(v) => {
                emitter::emit_ldc_i4(encoder, *v)?;
            }

            // 32-bit unsigned uses TryFrom (bit-preserving cast to Int32)
            ConstValue::U32(_) => {
                encoder.emit_instruction(
                    "ldc.i4",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // 64-bit integers (signed and unsigned) use ldc.i8
            ConstValue::I64(_) | ConstValue::U64(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // Native integers need conv.i/conv.u after loading
            ConstValue::NativeInt(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
                encoder.emit_instruction("conv.i", None)?;
            }

            ConstValue::NativeUInt(_) => {
                encoder.emit_instruction(
                    "ldc.i8",
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
                encoder.emit_instruction("conv.u", None)?;
            }

            // Floating point: CIL loads binary32 and binary64 constants
            ConstValue::Float(float) => {
                let opcode = match float.format() {
                    FloatFormat::Single => "ldc.r4",
                    FloatFormat::Double => "ldc.r8",
                    _ => {
                        return Err(Error::CodegenFailed(format!(
                            "{float:?} has a float format CIL cannot load"
                        )));
                    }
                };
                encoder.emit_instruction(
                    opcode,
                    Some(Operand::Immediate(Immediate::try_from(value)?)),
                )?;
            }

            // String constants reference the user string heap
            ConstValue::String(idx) => {
                let token = Token::new(0x7000_0000 | *idx);
                encoder.emit_instruction("ldstr", Some(Operand::Token(token)))?;
            }

            // Decrypted strings look up pre-interned index
            ConstValue::DecryptedString(s) => {
                if let Some(&idx) = self.interned_strings.get(s.as_ref()) {
                    let token = Token::new(0x7000_0000 | idx);
                    encoder.emit_instruction("ldstr", Some(Operand::Token(token)))?;
                } else {
                    return Err(Error::CodegenFailed(format!(
                        "decrypted string {s:?} was not interned before generation"
                    )));
                }
            }

            // Null reference
            ConstValue::Null => {
                encoder.emit_instruction("ldnull", None)?;
            }

            // Booleans use optimized ldc.i4.1/ldc.i4.0
            ConstValue::True => {
                encoder.emit_instruction("ldc.i4.1", None)?;
            }

            ConstValue::False => {
                encoder.emit_instruction("ldc.i4.0", None)?;
            }

            // Runtime handles use ldtoken
            ConstValue::Type(type_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(type_ref.token())))?;
            }

            ConstValue::MethodHandle(method_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(method_ref.token())))?;
            }

            ConstValue::FieldHandle(field_ref) => {
                encoder.emit_instruction("ldtoken", Some(Operand::Token(field_ref.token())))?;
            }
            // Uninhabited for this target: CIL has no symbol space.
            ConstValue::Symbol(symbol) => match *symbol {},
            // Decrypted arrays: emit newarr + InitializeArray using FieldRVA data.
            // Produces the same compact pattern as the C# compiler:
            //   ldc.i4 <num_elements>
            //   newarr <element_type>      ; push array (+1)
            //   dup                        ; push copy (+2)
            //   ldtoken <field_with_rva>   ; push handle (+3)
            //   call InitializeArray       ; pop 2 (+1) — net: 1 value on stack
            ConstValue::DecryptedArray(arr) => {
                let elem_size = arr.element_size.max(1);
                #[allow(clippy::cast_possible_truncation)]
                let num_elements = arr.data.len().checked_div(elem_size).unwrap_or(0);

                emitter::emit_ldc_i4(encoder, num_elements as i32)?;
                encoder.emit_instruction(
                    "newarr",
                    Some(Operand::Token(arr.element_type_ref.token())),
                )?;

                let Some(info) = self.interned_arrays.get(&arr.data) else {
                    return Err(Error::CodegenFailed(
                        "decrypted array was not interned before generation".to_string(),
                    ));
                };
                // Compact: dup + ldtoken + call InitializeArray
                // Stack: [array] → [array, array] → [array, array, handle] → [array]
                encoder.emit_instruction("dup", None)?;
                encoder.emit_instruction("ldtoken", Some(Operand::Token(info.field_token)))?;

                // InitializeArray(Array, RuntimeFieldHandle) → void: pops 2, pushes 0
                encoder.emit_call(
                    "call",
                    Some(Operand::Token(info.initialize_array_token)),
                    2,
                    false,
                )?;
            }

            // SIMD vector constants come from the native SSA substrate and have
            // no direct CIL `ldc`-style encoding.
            ConstValue::Vector(_) => {
                return Err(Error::CodegenFailed(
                    "Vector constants are not supported in CIL code generation".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Allocates a temporary local slot, reusing from the pool if available.
    ///
    /// When the temporary is no longer needed, call `release_temp_local` to
    /// return it to the pool for reuse.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CodegenFailed`] for a type no local can be declared
    /// with, or when the method already has 65536 locals.
    fn allocate_temp_local(&mut self, var_type: &SsaType) -> Result<u16> {
        if !is_slot_type(var_type) {
            return Err(Error::CodegenFailed(format!(
                "a temporary of type {var_type:?}, which no local can be declared with"
            )));
        }
        if let Some(slot) = self.method.temp_pool.try_allocate(var_type) {
            return Ok(slot);
        }
        let slot = u16::try_from(self.method.slot_types.len()).map_err(|_| {
            Error::CodegenFailed("the method needs more than 65535 locals".to_string())
        })?;
        self.method.slot_types.push(var_type.clone());
        Ok(slot)
    }

    /// Releases a temporary local slot back to the pool for reuse.
    fn release_temp_local(&mut self, slot: u16, var_type: &SsaType) {
        self.method.temp_pool.release(slot, var_type.clone());
    }

    /// Label of a real block.
    fn block_label(&self, block_id: usize) -> String {
        self.method
            .block_labels
            .get(&block_id)
            .cloned()
            .unwrap_or_else(|| format!("block_{block_id}"))
    }

    /// The layout entry the edge `from → to` actually lands on.
    ///
    /// This is the whole of the fall-through question. A branch may elide its `br` exactly
    /// when the entry it transfers to is the next one in the emission order — and because
    /// edge blocks are entries, "is there code in between" is answered by looking at the
    /// layout rather than by each emitter re-deriving what the others will emit after it.
    fn edge_destination(&self, from: usize, to: usize) -> LayoutEntry {
        if self.method.split_edge_labels.contains_key(&(from, to)) {
            LayoutEntry::SplitEdge { from, to }
        } else {
            LayoutEntry::Block(to)
        }
    }

    /// Label a branch along the edge `from → to` must name: the edge's own block when it has
    /// one, otherwise the target block directly.
    fn edge_label(&self, from: usize, to: usize) -> String {
        self.method
            .split_edge_labels
            .get(&(from, to))
            .cloned()
            .unwrap_or_else(|| self.block_label(to))
    }

    /// Generates the block holding the phi copies for one edge.
    ///
    /// The body is just the parallel copy for that edge followed by a transfer to the real
    /// target, which is elided when the target is the next entry.
    ///
    /// # Errors
    ///
    /// Returns an error if the edge has no registered label - which would mean the layout
    /// and [`Self::edge_destination`] disagree - or if emission fails.
    fn generate_edge_block(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        from: usize,
        to: usize,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        let label = self
            .method
            .split_edge_labels
            .get(&(from, to))
            .cloned()
            .ok_or_else(|| {
                Error::CodegenFailed(format!("Missing split-edge label for edge {from} -> {to}"))
            })?;

        encoder.define_label(&label)?;
        self.method.last_load = None;

        let copies = self
            .method
            .storage
            .as_ref()
            .map(|storage| storage.copies_on(ssa, from, to))
            .unwrap_or_default();
        self.emit_copies(encoder, ssa, from, &copies)?;

        if next_entry != Some(LayoutEntry::Block(to)) {
            let target_label = self.block_label(to);
            encoder.emit_branch("br", &target_label)?;
        }

        Ok(())
    }

    /// Emits a conditional branch (`brtrue`/`brfalse`).
    ///
    /// Phi copies are not this function's concern: any edge that carries them was given its
    /// own block by [`Self::expand_layout_with_edge_blocks`], so all that is emitted here is
    /// the branch, naming the edge block where there is one.
    fn emit_conditional_branch(
        &mut self,
        encoder: &mut InstructionEncoder,
        current_block_idx: usize,
        true_target: usize,
        false_target: usize,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        // Same-target: the condition cannot change where control goes, so discard it.
        if true_target == false_target {
            encoder.emit_instruction("pop", None)?;
            if next_entry != Some(self.edge_destination(current_block_idx, true_target)) {
                let label = self.edge_label(current_block_idx, true_target);
                encoder.emit_branch("br", &label)?;
            }
            return Ok(());
        }

        let true_label = self.edge_label(current_block_idx, true_target);
        let false_label = self.edge_label(current_block_idx, false_target);
        let true_dest = self.edge_destination(current_block_idx, true_target);
        let false_dest = self.edge_destination(current_block_idx, false_target);

        if next_entry == Some(false_dest) {
            encoder.emit_branch("brtrue", &true_label)?;
        } else if next_entry == Some(true_dest) {
            // `brfalse` is the exact complement of `brtrue`: both test one value against
            // zero/null, so there is no third outcome to mishandle. That is what makes the
            // inversion safe here and *not* safe for the comparison branches below.
            encoder.emit_branch("brfalse", &false_label)?;
        } else {
            encoder.emit_branch("brtrue", &true_label)?;
            encoder.emit_branch("br", &false_label)?;
        }

        Ok(())
    }

    /// Emits a comparison branch (`beq`, `blt`, …).
    ///
    /// As with [`Self::emit_conditional_branch`], phi copies live in their own blocks and are
    /// not emitted here.
    // The comparison kind and its signedness select the mnemonic, and both edges are needed to
    // decide which one can fall through; neither pair compresses into a type that would carry
    // its own meaning.
    #[allow(clippy::too_many_arguments)]
    fn emit_comparison_branch(
        &mut self,
        encoder: &mut InstructionEncoder,
        current_block_idx: usize,
        cmp: CmpKind,
        unsigned: bool,
        true_target: usize,
        false_target: usize,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        // Same-target: the comparison cannot change where control goes, so discard both
        // operands rather than evaluating it.
        if true_target == false_target {
            encoder.emit_instruction("pop", None)?;
            encoder.emit_instruction("pop", None)?;
            if next_entry != Some(self.edge_destination(current_block_idx, true_target)) {
                let label = self.edge_label(current_block_idx, true_target);
                encoder.emit_branch("br", &label)?;
            }
            return Ok(());
        }

        let true_label = self.edge_label(current_block_idx, true_target);
        let false_label = self.edge_label(current_block_idx, false_target);
        let false_dest = self.edge_destination(current_block_idx, false_target);

        // Only the comparison as written is needed; there is no inverse-mnemonic table
        // because the branch below never inverts. See the note there for why ordered
        // complements are wrong for floats.
        let mnemonic = match (cmp, unsigned) {
            (CmpKind::Eq, _) => "beq",
            (CmpKind::Ne, _) => "bne.un",
            (CmpKind::Lt, false) => "blt",
            (CmpKind::Lt, true) => "blt.un",
            (CmpKind::Le, false) => "ble",
            (CmpKind::Le, true) => "ble.un",
            (CmpKind::Gt, false) => "bgt",
            (CmpKind::Gt, true) => "bgt.un",
            (CmpKind::Ge, false) => "bge",
            (CmpKind::Ge, true) => "bge.un",
        };

        // Always branch on the comparison as written, never on its complement.
        //
        // A complement table built from *ordered* opposites (`blt`/`bge`, `ble`/`bgt`, …) is
        // wrong for floats: with a NaN operand every ordered comparison is false, so both
        // `blt` and `bge` are false and the inverted branch sends the NaN case down the true
        // edge — precisely the edge the comparison rejected. The complement can only be
        // stated correctly once the operand type is known, since `.un` means *unordered* for
        // floats but *unsigned* for integers. Emitting the original mnemonic sidesteps the
        // question entirely: no inversion, no type dependence.
        encoder.emit_branch(mnemonic, &true_label)?;
        if next_entry != Some(false_dest) {
            encoder.emit_branch("br", &false_label)?;
        }

        Ok(())
    }

    /// Emits a switch instruction and the transfer along its default edge.
    ///
    /// Each case edge names its own edge block where it has one, which keeps the switch a
    /// plain jump table: nothing is woven between the instruction and the default branch.
    fn emit_switch_branch(
        &mut self,
        encoder: &mut InstructionEncoder,
        current_block_idx: usize,
        targets: &[usize],
        default: usize,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        let switch_labels: Vec<String> = targets
            .iter()
            .map(|&target| self.edge_label(current_block_idx, target))
            .collect();

        let label_refs: Vec<&str> = switch_labels.iter().map(String::as_str).collect();
        encoder.emit_switch(&label_refs)?;

        // Falling out of a switch is the default edge.
        if next_entry != Some(self.edge_destination(current_block_idx, default)) {
            let default_label = self.edge_label(current_block_idx, default);
            encoder.emit_branch("br", &default_label)?;
        }

        Ok(())
    }

    /// Emits copies that take effect together: every source is read before any
    /// destination is written, with a temporary breaking each cycle.
    ///
    /// A source with no place (a constant, or a value folded into the copy) is
    /// produced in place and reads no slot the sequencing has to protect, apart
    /// from the slots its own operands are read from.
    ///
    /// # Arguments
    ///
    /// * `encoder` - The instruction encoder.
    /// * `ssa` - The function being generated.
    /// * `copies` - `(destination, source)` pairs; destinations must differ.
    ///
    /// # Errors
    ///
    /// Returns an error if two copies name one destination, or if a load or a
    /// temporary's type fails.
    fn emit_parallel_copies(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        copies: &[(Place, SsaVarId)],
    ) -> Result<()> {
        /// Where a sequenced copy writes.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum Dest {
            Place(Place),
            Temp(usize),
        }
        /// What a sequenced copy reads.
        #[derive(Debug, Clone, Copy)]
        enum Src {
            Var(SsaVarId),
            Temp(usize),
        }

        if copies.is_empty() {
            return Ok(());
        }
        for (i, (dest, _)) in copies.iter().enumerate() {
            if copies
                .iter()
                .skip(i.saturating_add(1))
                .any(|(other, _)| other == dest)
            {
                return Err(Error::CodegenFailed(format!(
                    "two copies taking effect together both write {dest:?}"
                )));
            }
        }

        let mut sequencer = Vec::with_capacity(copies.len());
        for &(dest, var) in copies {
            let reads: Vec<Dest> = self
                .places_read(ssa, var)
                .into_iter()
                .map(Dest::Place)
                .collect();
            sequencer.push((Dest::Place(dest), Src::Var(var), reads));
        }
        let mut temps_needed = 0usize;
        let ordered = ParallelCopy::new(sequencer).sequence(
            || {
                let temp = Dest::Temp(temps_needed);
                temps_needed = temps_needed.saturating_add(1);
                temp
            },
            |temp| match temp {
                Dest::Temp(index) => Src::Temp(index),
                // `fresh` only ever hands out temporaries.
                Dest::Place(_) => Src::Temp(usize::MAX),
            },
        );

        let mut temps: BTreeMap<usize, (u16, SsaType)> = BTreeMap::new();
        for (dest, src) in ordered {
            let temp_type = match src {
                Src::Var(var) => {
                    self.emit_value(encoder, ssa, var)?;
                    matches!(dest, Dest::Temp(_))
                        .then(|| infer_type(ssa, var))
                        .transpose()?
                }
                Src::Temp(index) => {
                    let (slot, var_type) = temps.remove(&index).ok_or_else(|| {
                        Error::CodegenFailed(format!("parallel copy read unwritten temp {index}"))
                    })?;
                    emitter::emit_ldloc(encoder, slot)?;
                    self.release_temp_local(slot, &var_type);
                    None
                }
            };
            match dest {
                Dest::Place(place) => Self::store_place(encoder, place)?,
                Dest::Temp(index) => {
                    let var_type = temp_type.ok_or_else(|| {
                        Error::CodegenFailed(format!("parallel copy temp {index} has no type"))
                    })?;
                    let slot = self.allocate_temp_local(&var_type)?;
                    emitter::emit_stloc(encoder, slot)?;
                    temps.insert(index, (slot, var_type));
                }
            }
        }
        Ok(())
    }

    /// The places producing `var` reads: its own place, or the places of the
    /// values a folded tree producing it loads.
    fn places_read(&self, ssa: &SsaFunction, var: SsaVarId) -> Vec<Place> {
        let Some(storage) = self.method.storage.as_ref() else {
            return Vec::new();
        };
        let mut found = Vec::new();
        let mut stack = vec![var];
        let mut seen = BTreeSet::new();
        while let Some(current) = stack.pop() {
            if !seen.insert(current) {
                continue;
            }
            match storage.materialise(current) {
                Some(Materialise::Folded) => {
                    if let Some(op) = self
                        .method
                        .def_sites
                        .get(&current)
                        .and_then(|tag| Self::op_at(ssa, *tag).ok())
                    {
                        stack.extend(op.uses());
                    }
                }
                Some(Materialise::Constant) => {}
                None => found.extend(storage.place(current)),
            }
        }
        found
    }

    /// Emits the phi copies owed on every edge leaving `from`, before its
    /// single-successor terminator or at the end of a block that falls
    /// through.
    fn emit_copies_from(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        from: usize,
    ) -> Result<()> {
        let Some(block) = ssa.block(from) else {
            return Ok(());
        };
        let mut successors: Vec<usize> = Vec::new();
        block.for_each_successor(|succ| successors.push(succ));
        // A leave's copies include those of the finally it runs, and an
        // `endfinally`'s those of every block it resumes: every block whose
        // phis take an operand on an edge from here.
        for &candidate in self
            .method
            .index
            .phi_successors
            .get(&from)
            .into_iter()
            .flatten()
        {
            if !successors.contains(&candidate) {
                successors.push(candidate);
            }
        }
        let mut copies = Vec::new();
        if let Some(storage) = self.method.storage.as_ref() {
            for successor in successors {
                for copy in storage.copies_on(ssa, from, successor) {
                    if !copies.contains(&copy) {
                        copies.push(copy);
                    }
                }
            }
        }
        self.emit_copies(encoder, ssa, from, &copies)
    }

    /// Emits `(phi result, operand)` copies for an edge leaving `from` as one
    /// parallel copy. A staged result is written to its temporary.
    fn emit_copies(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        from: usize,
        copies: &[(SsaVarId, SsaVarId)],
    ) -> Result<()> {
        let Some(storage) = self.method.storage.as_ref() else {
            return Ok(());
        };
        let mut moves: Vec<(Place, SsaVarId)> = Vec::with_capacity(copies.len());
        for &(result, operand) in copies {
            let dest = match storage.staged(result) {
                Some(temp) => Place::Local(temp),
                None => storage.place(result).ok_or_else(|| {
                    Error::CodegenFailed(format!(
                        "phi {result} copied on the edge from B{from} has no place"
                    ))
                })?,
            };
            // The address-taken slot a shadowed result is also written to.
            if let Some(slot) = storage.also_store(result) {
                if storage.staged(result).is_none()
                    && !moves.iter().any(|(existing, _)| *existing == slot)
                {
                    moves.push((slot, operand));
                }
            }
            // An operand already in the result's place needs no copy.
            if storage.materialise(operand).is_none() && storage.place(operand) == Some(dest) {
                continue;
            }
            if !moves.iter().any(|(existing, _)| *existing == dest) {
                moves.push((dest, operand));
            }
        }
        self.emit_parallel_copies(encoder, ssa, &moves)
    }

    /// Generates one block: its operations in SSA order.
    ///
    /// An operation's operands are loaded from their places or produced in
    /// place; its result is stored to its place, left for the consumer it is
    /// folded into, or dropped. A copy is a move between places, and nothing
    /// when both are one. Phi copies go before a single-successor terminator,
    /// at the end of a block that falls through, or in edge blocks.
    fn generate_block(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        block_idx: usize,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        let Some(block) = ssa.block(block_idx) else {
            return Ok(());
        };

        // Exception handler entry blocks are only entered via CLR exception
        // dispatch, never by falling through from the previous block in the
        // layout, so the label resets the stack depth to the handler's.
        if self.method.index.dispatch_entries.contains(&block_idx) {
            encoder.mark_unreachable();
        }
        let label = self.block_label(block_idx);
        encoder.define_label(&label)?;
        self.method.last_load = None;
        let emitted_before = encoder.instruction_count();

        let instructions = block.instructions();
        let mut settled: BTreeSet<usize> = BTreeSet::new();

        // A catch or filter is entered with the exception object on the stack.
        // It is settled before anything else, since the first instruction
        // emitted would bury it: stored to its variable's place, or dropped.
        if self.method.index.object_entries.contains(&block_idx) {
            self.settle_exception_object(encoder, ssa, block_idx, &mut settled)?;
        }

        // A staged phi result moves from its temporary into its place where
        // the phi stands.
        let staged = self
            .method
            .storage
            .as_ref()
            .map(|storage| storage.staged_in(ssa, block_idx))
            .unwrap_or_default();
        for (result, temp) in staged {
            emitter::emit_ldloc(encoder, temp)?;
            self.store_value(encoder, result)?;
        }

        let mut terminated = false;
        for (instr_idx, instr) in instructions.iter().enumerate() {
            if settled.contains(&instr_idx) {
                continue;
            }
            let op = instr.op();
            let tag = OpTag {
                block: block_idx,
                instr: instr_idx,
            };
            if matches!(op, SsaOp::Nop | SsaOp::Phi { .. }) || Self::is_prefix(op) {
                continue;
            }
            if let SsaOp::Copy { dest, src } = op {
                self.emit_copy_row(encoder, ssa, *dest, *src)?;
                continue;
            }
            let materialised = op
                .dest()
                .is_some_and(|dest| self.materialise_of(dest).is_some());
            if materialised {
                continue;
            }
            if Self::is_terminator(op) {
                terminated = true;
            }
            self.emit_row(encoder, ssa, tag, next_entry)?;
        }

        // A block with no terminator has exactly one successor, so its copies
        // go at its end.
        if !terminated {
            self.emit_copies_from(encoder, ssa, block_idx)?;
        }

        // A block that emitted nothing starts where the next one does. When
        // that one opens a region this block is not in, the block's offset
        // would be the region's first instruction, and a `leave` to it would
        // stay inside the region instead of leaving it, skipping the finally
        // it has to run. A `nop` gives the block an offset of its own.
        if encoder.instruction_count() == emitted_before {
            if let Some(LayoutEntry::Block(next)) = next_entry {
                let opens_other_region = ssa.exception_handlers().iter().any(|handler| {
                    [
                        handler.protected_range,
                        handler.handler_range,
                        handler.filter_range,
                    ]
                    .into_iter()
                    .flatten()
                    .any(|range| range.start() == next && !range.contains(block_idx))
                });
                if opens_other_region {
                    encoder.emit_instruction("nop", None)?;
                }
            }
        }
        Ok(())
    }

    /// Stores or drops the exception object a catch or filter is entered with.
    fn settle_exception_object(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        block_idx: usize,
        settled: &mut BTreeSet<usize>,
    ) -> Result<()> {
        let Some(block) = ssa.block(block_idx) else {
            return Ok(());
        };
        let instructions = block.instructions();
        if let Some((index, dest, kind)) =
            instructions
                .iter()
                .enumerate()
                .find_map(|(index, instr)| match instr.op() {
                    SsaOp::RuntimeValue { dest, kind } => Some((index, *dest, *kind)),
                    _ => None,
                })
        {
            if kind != RuntimeValueKind::ExceptionObject {
                return Err(Error::CodegenFailed(format!(
                    "{dest} = runtime {kind:?} in block {block_idx}, which the runtime does not \
                     enter holding an exception object"
                )));
            }
            settled.insert(index);
            if self
                .method
                .storage
                .as_ref()
                .is_some_and(|storage| storage.discarded(dest))
            {
                // Dropped on arrival; the `Pop`s that discard it are this.
                settled.extend(
                    instructions
                        .iter()
                        .enumerate()
                        .filter_map(|(index, instr)| {
                            matches!(instr.op(), SsaOp::Pop { value } if *value == dest)
                                .then_some(index)
                        }),
                );
                encoder.emit_instruction("pop", None)?;
                return Ok(());
            }
            match self
                .method
                .storage
                .as_ref()
                .and_then(|storage| storage.place(dest))
            {
                Some(_) => self.store_value(encoder, dest)?,
                None => encoder.emit_instruction("pop", None)?,
            }
            return Ok(());
        }
        // IR built without `RuntimeValue` names the object by a value nothing
        // defines, consumed by a `Pop`.
        let discarding_pop = instructions
            .iter()
            .enumerate()
            .find_map(|(index, instr)| match instr.op() {
                SsaOp::Pop { value }
                    if ssa.get_definition(*value).is_none()
                        && ssa.find_phi_defining(*value).is_none() =>
                {
                    Some(index)
                }
                _ => None,
            });
        let start = encoder.instruction_count();
        encoder.emit_instruction("pop", None)?;
        if let Some(index) = discarding_pop {
            settled.insert(index);
            self.record_group(
                start,
                encoder.instruction_count(),
                OpTag {
                    block: block_idx,
                    instr: index,
                },
            );
        }
        Ok(())
    }

    /// Emits the operation at `tag` as a row: operands, then the operation,
    /// then its result stored to its place or dropped.
    fn emit_row(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        tag: OpTag,
        next_entry: Option<LayoutEntry>,
    ) -> Result<()> {
        let op = Self::op_at(ssa, tag)?;
        let dest = op.dest();
        // A pure value nothing reads and nothing stores computes nothing -
        // unless an operand is produced in place, since a call or a load folded
        // into it still has to run.
        if op.is_pure() && !op.may_throw() && !Self::is_terminator(op) {
            if let Some(dest) = dest {
                let read =
                    self.method.storage.as_ref().is_some_and(|storage| {
                        storage.uses(dest) > 0 || storage.place(dest).is_some()
                    });
                let carries = Self::get_operands_in_stack_order(op)
                    .into_iter()
                    .any(|operand| self.materialise_of(operand) == Some(Materialise::Folded));
                if !read && !carries {
                    return Ok(());
                }
            }
        }
        for operand in Self::get_operands_in_stack_order(op) {
            self.emit_value(encoder, ssa, operand)?;
        }
        self.generate_op_core(encoder, ssa, tag, next_entry)?;
        if Self::is_terminator(op) {
            return Ok(());
        }
        if op.defs().count() > 1 {
            return Err(Error::CodegenFailed(format!(
                "{op} defines more than one value"
            )));
        }
        if let Some(dest) = dest {
            match self
                .method
                .storage
                .as_ref()
                .and_then(|storage| storage.place(dest))
            {
                Some(_) => self.store_value(encoder, dest)?,
                None => encoder.emit_instruction("pop", None)?,
            }
        }
        Ok(())
    }

    /// Emits a copy that keeps its row: the source into the destination's
    /// place, or nothing when the two share one or nothing reads the copy.
    fn emit_copy_row(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        dest: SsaVarId,
        src: SsaVarId,
    ) -> Result<()> {
        let Some(storage) = self.method.storage.as_ref() else {
            return Ok(());
        };
        if storage.materialise(dest).is_some() {
            return Ok(());
        }
        let Some(place) = storage.place(dest) else {
            // Nothing reads the copy; what its source computes in place still
            // has to run.
            if storage.materialise(src) == Some(Materialise::Folded) {
                self.emit_value(encoder, ssa, src)?;
                encoder.emit_instruction("pop", None)?;
            }
            return Ok(());
        };
        if storage.materialise(src).is_none()
            && storage.place(src) == Some(place)
            && storage.also_store(dest).is_none()
        {
            return Ok(());
        }
        self.emit_value(encoder, ssa, src)?;
        self.store_value(encoder, dest)
    }

    /// Stores the top of the stack as `var`: to its place, and to the
    /// address-taken slot its place shadows, when it has one.
    fn store_value(&mut self, encoder: &mut InstructionEncoder, var: SsaVarId) -> Result<()> {
        let place = self.place_of(var)?;
        if let Some(slot) = self
            .method
            .storage
            .as_ref()
            .and_then(|storage| storage.also_store(var))
        {
            encoder.emit_instruction("dup", None)?;
            Self::store_place(encoder, slot)?;
        }
        Self::store_place(encoder, place)
    }

    /// Pushes `var`'s value: loaded from its place, or produced in place when
    /// it has none.
    fn emit_value(
        &mut self,
        encoder: &mut InstructionEncoder,
        ssa: &SsaFunction,
        var: SsaVarId,
    ) -> Result<()> {
        match self.materialise_of(var) {
            Some(Materialise::Constant) => {
                let value = match ssa.get_definition(var) {
                    Some(SsaOp::Const { value, .. }) => value.clone(),
                    _ => {
                        return Err(Error::CodegenFailed(format!(
                            "{var} is materialised as a constant but defined otherwise"
                        )))
                    }
                };
                self.emit_constant_of(encoder, var, &value)
            }
            Some(Materialise::Folded) => {
                let tag = *self.method.def_sites.get(&var).ok_or_else(|| {
                    Error::CodegenFailed(format!("folded {var} has no definition"))
                })?;
                let op = Self::op_at(ssa, tag)?;
                if let SsaOp::Copy { src, .. } = op {
                    let src = *src;
                    return self.emit_value(encoder, ssa, src);
                }
                for operand in Self::get_operands_in_stack_order(op) {
                    self.emit_value(encoder, ssa, operand)?;
                }
                self.generate_op_core(encoder, ssa, tag, None)
            }
            None => {
                let place = self.place_of(var)?;
                self.load_place(encoder, place)
            }
        }
    }

    /// How `var` is produced when it has no place.
    fn materialise_of(&self, var: SsaVarId) -> Option<Materialise> {
        self.method
            .storage
            .as_ref()
            .and_then(|storage| storage.materialise(var))
    }

    /// The place `var` lives in.
    fn place_of(&self, var: SsaVarId) -> Result<Place> {
        self.method
            .storage
            .as_ref()
            .and_then(|storage| storage.place(var))
            .ok_or_else(|| {
                Error::CodegenFailed(format!(
                    "{var} is read but has no place and is not produced in place"
                ))
            })
    }

    /// Loads a place, as a `dup` when the instruction just emitted loaded it.
    ///
    /// Only within a run of straight-line code: every label resets the
    /// record, since control arriving at a label did not run the load before
    /// it.
    fn load_place(&mut self, encoder: &mut InstructionEncoder, place: Place) -> Result<()> {
        if self.method.last_load == Some((place, encoder.instruction_count())) {
            encoder.emit_instruction("dup", None)?;
        } else {
            match place {
                Place::Arg(idx) => emitter::emit_ldarg(encoder, idx)?,
                Place::Local(idx) => emitter::emit_ldloc(encoder, idx)?,
            }
        }
        self.method.last_load = Some((place, encoder.instruction_count()));
        Ok(())
    }

    /// Stores the top of the stack to a place.
    fn store_place(encoder: &mut InstructionEncoder, place: Place) -> Result<()> {
        match place {
            Place::Arg(idx) => emitter::emit_starg(encoder, idx),
            Place::Local(idx) => emitter::emit_stloc(encoder, idx),
        }
    }

    /// Whether `op` is a prefix that modifies the instruction after it.
    fn is_prefix(op: &SsaOp) -> bool {
        matches!(
            op,
            SsaOp::Constrained { .. }
                | SsaOp::Volatile
                | SsaOp::Unaligned { .. }
                | SsaOp::TailPrefix
                | SsaOp::Readonly
        )
    }
}
