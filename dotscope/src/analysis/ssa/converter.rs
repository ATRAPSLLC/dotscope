//! SSA construction algorithm (Cytron et al.).
//!
//! This module implements the classic SSA construction algorithm from:
//!
//! > Cytron et al., "Efficiently Computing Static Single Assignment Form and the
//! > Control Dependence Graph", ACM TOPLAS 1991
//!
//! # Algorithm Overview
//!
//! SSA construction proceeds in three phases:
//!
//! 1. **Stack Simulation**: Convert implicit CIL stack operations to explicit variables
//! 2. **Phi Placement**: Insert phi nodes at dominance frontiers for each variable
//! 3. **Variable Renaming**: Rename variables using dominator tree traversal
//!
//! # Usage
//!
//! ```no_run
//! use dotscope::analysis::{ControlFlowGraph, SsaConverter};
//! use dotscope::assembly::decode_blocks;
//!
//! // Build CFG from decoded blocks
//! let blocks = decode_blocks(data, offset, rva, Some(size))?;
//! let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
//!
//! // Construct SSA form
//! let ssa = SsaConverter::build(&cfg, 2, 3, &type_provider, Vec::new())?; // 2 args, 3 locals
//!
//! // Analyze the SSA form
//! for block in ssa.blocks() {
//!     for phi in block.phi_nodes() {
//!         println!("{}", phi);
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```

use std::collections::BTreeMap;

use analyssa::{
    graph::NodeId,
    ir::{
        function::{SsaConstructOptions, SsaEditOptions},
        ops::convert::ConversionIntent,
        FloatFormat,
    },
    BitSet,
};

use crate::{
    analysis::{
        cfg::ControlFlowGraph,
        ssa::{
            decompose::decompose_instruction, resolve_corelib_valuetype, ConstValue, DefSite,
            RuntimeValueKind, SimulationResult, SsaBlock, SsaExceptionHandler, SsaFunction,
            SsaInstruction, SsaOp, SsaType, SsaVarId, StackSimulator, TypeProvider, VariableOrigin,
        },
    },
    assembly::{opcodes, Immediate, Instruction, Operand},
    metadata::{
        signatures::TypeSignature,
        tables::{MemberRefSignature, StandAloneSigRaw, StandAloneSignature},
        token::Token,
        typesystem::CilTypeReference,
    },
    CilObject, Error, Result,
};

/// Builder for constructing SSA form from a control flow graph.
///
/// This implements the Cytron et al. algorithm with the following phases:
///
/// 1. Simulate the stack to identify variable definitions
/// 2. Compute dominance frontiers and place phi nodes
/// 3. Rename variables using dominator tree traversal
pub struct SsaConverter<'a, 'cfg> {
    /// The control flow graph being transformed.
    cfg: &'a ControlFlowGraph<'cfg>,

    /// Number of method arguments.
    num_args: usize,

    /// Number of local variables.
    num_locals: usize,

    /// The SSA function being built.
    function: SsaFunction,

    /// Variables (by group ID) that have had their address taken.
    address_taken: BitSet,

    /// Maps simulation variable IDs to their stack depth positions.
    ///
    /// Used during rename to assign correct stack-derived origins for temporary
    /// variables (those not covered by `infer_origin`, e.g. add, box, call results).
    var_stack_positions: BTreeMap<SsaVarId, usize>,

    /// The argument or local slot each simulation variable is a version of.
    ///
    /// Taken from the simulator, which records it for every `stloc`/`starg`
    /// result and for the value each slot starts with. A simulation variable
    /// absent here is a value of the evaluation stack, grouped by its depth.
    slot_versions: BTreeMap<SsaVarId, VariableOrigin>,

    /// Type provider for assigning types during SSA construction.
    ///
    /// Variables are assigned correct types at creation time based on method
    /// signature, local variable signature, and call return types.
    type_provider: &'a dyn TypeProvider,
}

impl<'a, 'cfg> SsaConverter<'a, 'cfg> {
    /// Converts a usize index to u16 with validation.
    ///
    /// Returns an error if the index exceeds `u16::MAX`.
    fn idx_to_u16(idx: usize) -> Result<u16> {
        u16::try_from(idx).map_err(|_| {
            Error::SsaError(format!(
                "Variable index {} exceeds maximum supported value of {}",
                idx,
                u16::MAX
            ))
        })
    }

    /// Returns the origin for a stack slot (always `Phi` — stack temps are synthetic).
    fn stack_slot_origin(&self, _slot: usize) -> VariableOrigin {
        VariableOrigin::Phi
    }

    /// Returns the rename group ID for a stack slot at the given depth.
    #[allow(clippy::cast_possible_truncation)]
    fn stack_group(&self, depth: usize) -> u32 {
        (self.num_args as u32)
            .saturating_add(self.num_locals as u32)
            .saturating_add(depth as u32)
    }

    /// Returns the rename group ID for an argument.
    fn arg_group(&self, idx: u16) -> u32 {
        idx as u32
    }

    /// Returns the rename group ID for a local.
    fn local_group(&self, idx: u16) -> u32 {
        (self.num_args as u32).saturating_add(idx as u32)
    }

    /// Returns the SSA type for a variable origin.
    ///
    /// Uses the type context to look up types from the method signature:
    /// - Arguments: type from method parameter signature
    /// - Locals: type from local variable signature
    /// - Stack temps: Unknown (must be inferred from producing instruction)
    fn type_for_origin(&self, origin: VariableOrigin) -> SsaType {
        match origin {
            VariableOrigin::Argument(idx) => self.type_provider.arg_type(idx),
            VariableOrigin::Local(idx) => self.type_provider.local_type(idx),
            VariableOrigin::Phi | VariableOrigin::EntryLiveIn => SsaType::Unknown,
        }
    }

    /// Infers the result type of an instruction that produces a stack value.
    ///
    /// Uses the type context to resolve:
    /// - Call/CallVirt: return type from method signature
    /// - NewObj: type of the constructed object
    /// - Const: type based on the constant value
    /// - Conv: target type of conversion
    fn infer_instruction_result_type(&self, block_idx: usize, instr_idx: usize) -> SsaType {
        let Some(block) = self.function.block(block_idx) else {
            return SsaType::Unknown;
        };
        let Some(instr) = block.instruction(instr_idx) else {
            return SsaType::Unknown;
        };

        // A type the instruction was built with is the one that holds: a
        // handler's exception object is typed by its catch clause, which the
        // operation itself does not name.
        if let Some(recorded) = instr.result_type().filter(|ty| !ty.is_unknown()) {
            return recorded.clone();
        }
        self.infer_op_result_type(instr.op())
    }

    /// The class `value` computes in as an operand of arithmetic, when its type
    /// is known ([`SsaType::arithmetic_class`]).
    fn operand_stack_type(&self, value: SsaVarId) -> Option<SsaType> {
        self.function.variable(value)?.var_type().arithmetic_class()
    }

    /// The result type of a binary numeric operation on `left` and `right`
    /// ([`SsaType::binary_numeric`]); `Unknown` while an operand's type is,
    /// which the phi typing fixpoint asks again once it is known
    /// ([`Self::resolve_phi_types`]).
    fn binary_numeric_type(&self, left: SsaVarId, right: SsaVarId, additive: bool) -> SsaType {
        let (Some(a), Some(b)) = (self.function.variable(left), self.function.variable(right))
        else {
            return SsaType::Unknown;
        };
        SsaType::binary_numeric(a.var_type(), b.var_type(), additive).unwrap_or(SsaType::Unknown)
    }

    /// Infers the result type of an SSA operation using the TypeContext.
    ///
    /// This is the core type inference routine that resolves types for all ops,
    /// including context-dependent ones (Call, LoadField, LoadArg, etc.) that
    /// require assembly metadata. The result is stored on `SsaInstruction.result_type`
    /// at construction time so it survives through deobfuscation transforms.
    fn infer_op_result_type(&self, op: &SsaOp) -> SsaType {
        match op {
            // Call instructions - look up return type from method signature
            SsaOp::Call { method, .. } | SsaOp::CallVirt { method, .. } => {
                self.type_provider.call_return_type(method.token())
            }

            // NewObj - look up constructed type from constructor
            SsaOp::NewObj { ctor, .. } => self.type_provider.newobj_type(ctor.token()),

            // Constants - infer type from the constant value
            SsaOp::Const { value, .. } => match value {
                ConstValue::I8(_) => SsaType::I8,
                ConstValue::I16(_) => SsaType::I16,
                ConstValue::I32(_) => SsaType::I32,
                ConstValue::I64(_) => SsaType::I64,
                ConstValue::U8(_) => SsaType::U8,
                ConstValue::U16(_) => SsaType::U16,
                ConstValue::U32(_) => SsaType::U32,
                ConstValue::U64(_) => SsaType::U64,
                ConstValue::NativeInt(_) => SsaType::NativeInt,
                ConstValue::NativeUInt(_) => SsaType::NativeUInt,
                ConstValue::String(_) | ConstValue::DecryptedString(_) => SsaType::String,
                ConstValue::DecryptedArray { .. } => SsaType::Object,
                // Uninhabited for this target: CIL has no symbol space.
                ConstValue::Symbol(symbol) => match *symbol {},
                // SIMD vector constant from the native substrate — no CIL type.
                ConstValue::Vector(_) => SsaType::Unknown,
                // binary32 and binary64 are CIL's floats; the other formats only native
                // code produces
                ConstValue::Float(bits) => match bits.format() {
                    FloatFormat::Single => SsaType::F32,
                    FloatFormat::Double => SsaType::F64,
                    _ => SsaType::Unknown,
                },
                ConstValue::Null => SsaType::Null,
                ConstValue::True | ConstValue::False => SsaType::Bool,
                // Runtime handle types (`ldtoken` results). Each handle
                // variant is a distinct corelib `valuetype`; resolve its
                // TypeRef so the SSA variable carries a real
                // `valuetype [mscorlib]System.Runtime*Handle` token from
                // construction — never a tokenless placeholder. The
                // operand's own token is the *subject* of the handle,
                // not its type, and is already preserved on the op.
                ConstValue::Type(_) => self
                    .type_provider
                    .assembly()
                    .map_or(SsaType::Unknown, |a| {
                        resolve_corelib_valuetype(a, "System.RuntimeTypeHandle")
                    }),
                ConstValue::MethodHandle(_) => self
                    .type_provider
                    .assembly()
                    .map_or(SsaType::Unknown, |a| {
                        resolve_corelib_valuetype(a, "System.RuntimeMethodHandle")
                    }),
                ConstValue::FieldHandle(_) => self
                    .type_provider
                    .assembly()
                    .map_or(SsaType::Unknown, |a| {
                        resolve_corelib_valuetype(a, "System.RuntimeFieldHandle")
                    }),
            },

            // Comparison results are always bool (represented as I32 on stack).
            // Native boolean ops from the analyssa substrate likewise yield bool.
            SsaOp::Ceq { .. }
            | SsaOp::Clt { .. }
            | SsaOp::Cgt { .. }
            | SsaOp::BoolAnd { .. }
            | SsaOp::BoolOr { .. }
            | SsaOp::BoolXor { .. }
            | SsaOp::BoolNot { .. } => SsaType::Bool,

            // Conversion - use the target type
            SsaOp::IntConv { target, .. } | SsaOp::IntToPtr { target, .. } | SsaOp::PtrToInt { target, .. } | SsaOp::IntToFloat { target, .. } | SsaOp::FloatToInt { target, .. } | SsaOp::FloatConv { target, .. } => target.clone(),

            // Arithmetic is typed by what it computes on (ECMA-335 III.1.5):
            // a `float32` sum is a `float32`, a `long` product a `long`.
            SsaOp::Add { left, right, .. }
            | SsaOp::AddOvf { left, right, .. }
            | SsaOp::Sub { left, right, .. }
            | SsaOp::SubOvf { left, right, .. } => {
                self.binary_numeric_type(*left, *right, true)
            }
            SsaOp::Mul { left, right, .. }
            | SsaOp::MulOvf { left, right, .. }
            | SsaOp::Div { left, right, .. }
            | SsaOp::Rem { left, right, .. }
            | SsaOp::And { left, right, .. }
            | SsaOp::Or { left, right, .. }
            | SsaOp::Xor { left, right, .. } => self.binary_numeric_type(*left, *right, false),
            // A shift's result is the value shifted; its count says nothing.
            SsaOp::Shl { value, .. } | SsaOp::Shr { value, .. } => {
                self.operand_stack_type(*value).unwrap_or(SsaType::Unknown)
            }
            SsaOp::Neg { operand, .. } | SsaOp::Not { operand, .. } => {
                self.operand_stack_type(*operand).unwrap_or(SsaType::Unknown)
            }

            // Rotate operations
            SsaOp::Rol { .. }
            | SsaOp::Ror { .. }
            // Bit manipulation operations
            | SsaOp::BSwap { .. }
            | SsaOp::BRev { .. }
            | SsaOp::BitScanForward { .. }
            | SsaOp::BitScanReverse { .. }
            | SsaOp::Popcount { .. }
            | SsaOp::Parity { .. }
            // Select produces values of varying types
            | SsaOp::Select { .. }
            // ReadFlags reads flag bits into an integer
            | SsaOp::ReadFlags { .. }
            // Sizeof produces int32
            | SsaOp::SizeOf { .. } => SsaType::I32,

            // Box produces object reference
            SsaOp::Box { .. } => SsaType::Object,

            // NewArr produces array
            SsaOp::NewArr { elem_type, .. } => {
                // Resolve the element type through the type provider so that
                // primitives like System.Char are represented as SsaType::Char
                // rather than SsaType::Class(TypeRef).
                let elem_ssa_type = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(elem_type.token(), asm)
                } else {
                    SsaType::Class(*elem_type)
                };
                SsaType::Array(Box::new(elem_ssa_type), 1)
            }

            // Cast and type check produce the target type
            SsaOp::CastClass { target_type, .. } | SsaOp::IsInst { target_type, .. } => {
                if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(target_type.token(), asm)
                } else {
                    SsaType::Class(*target_type)
                }
            }

            // The address a typed reference designates, like an unboxed value's.
            SsaOp::TypedRefValue { value_type, .. } => {
                let resolved = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(value_type.token(), asm)
                } else {
                    SsaType::ValueType(*value_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }
            SsaOp::MakeTypedRef { .. } => SsaType::TypedReference,
            // The two handles are corelib value types, as `ldtoken`'s are.
            SsaOp::ArgList { .. } => self.type_provider.assembly().map_or(SsaType::Unknown, |a| {
                resolve_corelib_valuetype(a, "System.RuntimeArgumentHandle")
            }),
            SsaOp::TypedRefType { .. } => self.type_provider.assembly().map_or(SsaType::Unknown, |a| {
                resolve_corelib_valuetype(a, "System.RuntimeTypeHandle")
            }),

            // Unbox operations - resolve value type through type provider for primitives
            SsaOp::Unbox { value_type, .. } => {
                let resolved = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(value_type.token(), asm)
                } else {
                    SsaType::ValueType(*value_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }
            SsaOp::UnboxAny { value_type, .. }
            // Load object (value type copy) — type from value_type token
            | SsaOp::LoadObj { value_type, .. } => {
                if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(value_type.token(), asm)
                } else {
                    SsaType::ValueType(*value_type)
                }
            }

            // Load field - look up field type from assembly
            SsaOp::LoadField { field, .. } | SsaOp::LoadStaticField { field, .. } => {
                self.type_provider.field_type(field.token())
            }

            // Load field address - byref to field type
            SsaOp::LoadFieldAddr { field, .. } | SsaOp::LoadStaticFieldAddr { field, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.field_type(field.token())))
            }

            // Load array element - use the element type from the op
            SsaOp::LoadElement { elem_type, .. } => elem_type.clone(),
            SsaOp::LoadElementAddr { elem_type, .. } => {
                let resolved = if let Some(asm) = self.type_provider.assembly() {
                    SsaType::from_type_token(elem_type.token(), asm)
                } else {
                    SsaType::Class(*elem_type)
                };
                SsaType::ByRef(Box::new(resolved))
            }

            // Indirect load - use the value_type from the op
            SsaOp::LoadIndirect { value_type, .. } => value_type.clone(),

            // Function pointer loads / Array length / LocalAlloc — all native int
            SsaOp::LoadFunctionPtr { .. }
            | SsaOp::LoadVirtFunctionPtr { .. }
            | SsaOp::ArrayLength { .. }
            | SsaOp::LocalAlloc { .. } => SsaType::NativeInt,

            // `ldtoken` yields one of three corelib `System.Runtime*Handle`
            // value-types, depending on which metadata table the operand
            // points into. Resolve the matching TypeRef so the SSA
            // variable carries a real `valuetype` token from construction.
            SsaOp::LoadToken { token, .. } => {
                let fullname = match token.token().table() {
                    0x06 | 0x0A | 0x2B => "System.RuntimeMethodHandle", // MethodDef, MemberRef, MethodSpec
                    0x04 => "System.RuntimeFieldHandle",                // Field
                    _ => "System.RuntimeTypeHandle", // TypeDef, TypeRef, TypeSpec, …
                };
                self.type_provider
                    .assembly()
                    .map_or(SsaType::Unknown, |a| resolve_corelib_valuetype(a, fullname))
            }

            // Load argument/local — type from type provider
            SsaOp::LoadArg { arg_index, .. } => self.type_provider.arg_type(*arg_index),
            SsaOp::LoadLocal { local_index, .. } => self.type_provider.local_type(*local_index),

            // Load argument/local address — byref to the argument/local type
            SsaOp::LoadArgAddr { arg_index, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.arg_type(*arg_index)))
            }
            SsaOp::LoadLocalAddr { local_index, .. } => {
                SsaType::ByRef(Box::new(self.type_provider.local_type(*local_index)))
            }

            // Ckfinite — operates on F64 stack type
            SsaOp::Ckfinite { .. } => SsaType::F64,

            // CallIndirect — resolve return type from standalone signature
            SsaOp::CallIndirect { signature, .. } => {
                self.type_provider.call_indirect_return_type(signature.token())
            }

            // Copy — inherit type from source operand
            SsaOp::Copy { src, .. } => self
                .function
                .variable(*src)
                .map(|v| v.var_type().clone())
                .unwrap_or(SsaType::Unknown),

            // Phi — types resolved during resolve_phi_types() after rename.
            // Non-value-producing operations — exhaustive list so new SsaOp
            // variants cause a compiler error instead of silently returning Unknown
            SsaOp::Phi { .. }
            | SsaOp::StoreField { .. }
            | SsaOp::StoreStaticField { .. }
            | SsaOp::StoreElement { .. }
            | SsaOp::StoreIndirect { .. }
            | SsaOp::StoreObj { .. }
            | SsaOp::Jump { .. }
            | SsaOp::Branch { .. }
            | SsaOp::BranchCmp { .. }
            | SsaOp::Switch { .. }
            | SsaOp::Return { .. }
            | SsaOp::Pop { .. }
            | SsaOp::Throw { .. }
            | SsaOp::Rethrow
            | SsaOp::EndFinally
            | SsaOp::EndFilter { .. }
            | SsaOp::Leave { .. }
            | SsaOp::InitBlk { .. }
            | SsaOp::CopyBlk { .. }
            | SsaOp::InitObj { .. }
            | SsaOp::CopyObj { .. }
            | SsaOp::Nop
            | SsaOp::Break(_)
            | SsaOp::Constrained { .. }
            | SsaOp::Volatile
            | SsaOp::Unaligned { .. }
            | SsaOp::TailPrefix
            | SsaOp::BranchFlags { .. }
            | SsaOp::Fence { .. }
            | SsaOp::InterruptReturn
            | SsaOp::Unreachable
            | SsaOp::Readonly => SsaType::Unknown,
            // Native architecture ops (x86/arm/riscv intrinsics, system, vector
            // crypto/SVE/SME, BCD, …) are never produced by dotscope's CIL
            // lifter, so their result type is left unresolved.
            _ => SsaType::Unknown,
        }
    }

    /// Returns the constant zero for a type, or `None` if it has no constant form.
    ///
    /// Mirrors CIL's `.locals init` semantics: integers and floats zero, references
    /// null. A value type has no constant form - a zeroed struct is not `ldnull` -
    /// so it has none here.
    fn zero_value_for(ty: &SsaType) -> Option<ConstValue> {
        Some(match ty {
            SsaType::Bool => ConstValue::False,
            SsaType::I8 => ConstValue::I8(0),
            SsaType::U8 => ConstValue::U8(0),
            SsaType::I16 => ConstValue::I16(0),
            SsaType::U16 => ConstValue::U16(0),
            SsaType::Char => ConstValue::U16(0),
            SsaType::I32 => ConstValue::I32(0),
            SsaType::U32 => ConstValue::U32(0),
            SsaType::I64 => ConstValue::I64(0),
            SsaType::U64 => ConstValue::U64(0),
            SsaType::NativeInt => ConstValue::NativeInt(0),
            SsaType::NativeUInt => ConstValue::NativeUInt(0),
            SsaType::F32 => ConstValue::from(0.0_f32),
            SsaType::F64 => ConstValue::from(0.0_f64),
            SsaType::Object
            | SsaType::String
            | SsaType::Null
            | SsaType::Class(_)
            | SsaType::Array(_, _)
            | SsaType::GenericInst(_, _)
            | SsaType::Pointer(_)
            | SsaType::ByRef(_)
            | SsaType::FnPtr(_) => ConstValue::Null,
            _ => return None,
        })
    }

    /// States what `.locals init` puts in each primitive local that is read
    /// before anything writes it.
    ///
    /// Construction resolves such a read to the local's entry value: a
    /// definition of the slot's group at entry, which says the local holds
    /// *something* before the body runs but not what. With `.locals init` that
    /// something is zero - or null, for a reference - and a pass that folds a
    /// comparison or a switch needs the value itself. So the entry value is
    /// given a definition: a `Const` at the top of the entry block, which
    /// construction has already made a block no edge enters, so the constant
    /// dominates every read.
    ///
    /// A value type has no constant form and keeps its entry value, which is
    /// what a zeroed slot is: code generation reads the slot, and the runtime
    /// zeroed it. Stating it with `ldloca; initobj` instead would take the
    /// slot's address, and a slot whose address is taken is memory rather than
    /// a value to every analysis after this one.
    ///
    /// Only entry values something reads are defined, so a local written before
    /// every read costs nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the insertion's repair fails.
    fn materialize_local_zero_init(&mut self) -> Result<()> {
        let mut read: BitSet = BitSet::new(self.function.var_id_capacity());
        for block in self.function.blocks() {
            for phi in block.phi_nodes() {
                for operand in phi.operands() {
                    read.insert(operand.value().index());
                }
            }
            for instr in block.instructions() {
                instr.for_each_use(|used| {
                    read.insert(used.index());
                });
            }
        }

        let zeros: Vec<(SsaVarId, ConstValue)> = self
            .function
            .variables()
            .iter()
            .filter(|var| {
                matches!(var.origin(), VariableOrigin::Local(_))
                    && var.version() == 0
                    && var.def_site() == DefSite::entry()
                    && read.contains(var.id().index())
            })
            .filter_map(|var| Some((var.id(), Self::zero_value_for(var.var_type())?)))
            .collect();
        if zeros.is_empty() {
            return Ok(());
        }

        // Block 0 is the entry, and construction left it without predecessors.
        let entry_block = 0;
        self.function
            .edit(SsaEditOptions::new(), |editor| {
                for (dest, value) in zeros {
                    editor.insert_instruction(
                        entry_block,
                        0,
                        SsaInstruction::synthetic(SsaOp::Const { dest, value }),
                    )?;
                }
                Ok(())
            })
            .map_err(|e| Error::SsaError(e.to_string()))?;
        Ok(())
    }

    /// Builds SSA form from a control flow graph.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The control flow graph to transform
    /// * `num_args` - Number of method arguments (including `this` for instance methods)
    /// * `num_locals` - Number of local variables
    /// * `type_provider` - Type provider for assigning types during construction.
    ///   Variables are assigned correct types based on method signature,
    ///   local variable signature, and call return types.
    /// * `handlers` - The method's exception clauses as block ranges, empty for
    ///   a method with none.
    ///
    /// # The exception table is an input
    ///
    /// Taken here rather than attached to the result, and the difference is not
    /// cosmetic. Construction reads it: which blocks control can enter without
    /// a terminator naming them decides where the dominator walk is rooted,
    /// which blocks are reachable at all, and - since a throw leaves a
    /// protected block from wherever it happened - what a phi at a handler
    /// entry merges. A table attached afterwards answers none of those
    /// questions in time, and the handler ends up with phis that name no
    /// predecessor and account for no throw.
    ///
    /// # Returns
    ///
    /// The complete SSA representation, or an error if construction fails.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The CFG is empty
    /// - Stack simulation encounters inconsistencies
    /// - Reconstruction cannot resolve a read
    pub fn build(
        cfg: &'a ControlFlowGraph<'cfg>,
        num_args: usize,
        num_locals: usize,
        type_provider: &'a dyn TypeProvider,
        handlers: Vec<SsaExceptionHandler>,
    ) -> Result<SsaFunction> {
        let block_count = cfg.block_count();
        if block_count == 0 {
            return Err(Error::SsaError(
                "Cannot build SSA from empty CFG".to_string(),
            ));
        }

        let mut builder = Self {
            cfg,
            num_args,
            num_locals,
            function: SsaFunction::with_capacity(num_args, num_locals, block_count, 0),
            address_taken: BitSet::new(num_args.saturating_add(num_locals)),
            var_stack_positions: BTreeMap::new(),
            slot_versions: BTreeMap::new(),
            type_provider,
        };

        // Get assembly reference from type provider for stack simulation
        let assembly = type_provider.assembly();

        // Phase 1: Simulate stack and collect definitions
        builder.simulate_all_blocks(assembly)?;

        // The exception table, before anything reads the flow graph. Everything
        // below - phi placement, the rename walk, and the reconstruction that
        // finishes the job - asks where control can enter, and a handler entry
        // is an answer only this table gives.
        if !handlers.is_empty() {
            builder.function.set_exception_handlers(handlers);
        }

        // Phase 2: give every value the simulation named a variable of the
        // function, carrying the storage location it is a version of.
        builder.materialize_simulation_variables()?;

        // Set original local type signatures from type provider for code generation
        if let Some(local_types) = type_provider.local_type_signatures() {
            builder.function.set_original_local_types(local_types);
        }

        // Phase 3: construction, from the crate that owns it. It places the
        // phis over the iterated dominance frontier and resolves every read to
        // the definition that reaches it, using the grouping phase 2 attached,
        // then finishes: instruction identities, address-taken slots, the prune
        // rooted at the entry and at every handler, definition sites, the use
        // index, and the dense renumbering.
        //
        // Not verified here: a finding is not this function's to act on, and a
        // caller that wants one asks for it. `Method::ssa` returns the IR
        // whatever its state, exactly as it did.
        builder
            .function
            .construct_ssa(&SsaConstructOptions::unverified())
            .map_err(|e| Error::SsaError(e.to_string()))?;

        if type_provider.locals_zero_initialized() {
            builder.materialize_local_zero_init()?;
        }

        // Phi types follow from the operands construction gave them.
        builder.resolve_phi_types();

        // Conversions are chosen once the values they convert have types. A CIL `conv.*` names
        // only its destination (`conv.i8` truncates a `float64` and widens an `int32`), so
        // decomposition chose from the destination alone; each conversion, of every kind, is
        // restated for the type its operand turned out to have.
        builder
            .function
            .settle_conversions(ConversionIntent::Values);

        // A store into a slot narrower than four bytes truncates; stated as the
        // conversion it is, once the stored values have types.
        builder.make_narrow_stores_explicit();

        // Validate no Unknown types remain on used variables
        builder.function.validate_types().map_err(Error::SsaError)?;

        Ok(builder.function)
    }

    /// Classifies a simulation variable: what it is a version of, and its type.
    ///
    /// A value the simulation named is a version of exactly one storage
    /// location: an argument or local slot when a store produced it, and the
    /// evaluation stack at the depth it was pushed to otherwise. The rename
    /// group is that location, and it is what tells SSA construction which
    /// definitions are the same variable.
    ///
    /// # Arguments
    ///
    /// * `var` - The simulation variable to classify.
    /// * `site` - Where it is defined, when it is defined by an instruction.
    ///   A value's type is the one its defining operation produces, so a value
    ///   with no definition in the block is left [`SsaType::Unknown`] for
    ///   construction to resolve from the definition that reaches it.
    fn classify_simulation_var(
        &self,
        var: SsaVarId,
        site: Option<(usize, usize)>,
    ) -> (VariableOrigin, Option<u32>, SsaType) {
        if let Some(&origin) = self.slot_versions.get(&var) {
            let group = match origin {
                VariableOrigin::Argument(idx) => Some(self.arg_group(idx)),
                VariableOrigin::Local(idx) => Some(self.local_group(idx)),
                VariableOrigin::Phi | VariableOrigin::EntryLiveIn => None,
            };
            return (origin, group, self.type_for_origin(origin));
        }

        let var_type = site.map_or(SsaType::Unknown, |(block_idx, instr_idx)| {
            self.infer_instruction_result_type(block_idx, instr_idx)
        });

        // A value the simulation put on the evaluation stack belongs to the
        // slot at that depth. One it never placed there belongs to no storage
        // location at all: a temporary some decomposition invented, live only
        // between the instruction that makes it and the one that reads it.
        //
        // Such a value must stay ungrouped. Folded into a slot's group - and
        // depth zero is what a missing entry would otherwise read as - it
        // becomes a version of that slot, aliasing every real value there and
        // answering reads that were never about it.
        let Some(&slot) = self.var_stack_positions.get(&var) else {
            return (VariableOrigin::Phi, None, var_type);
        };
        (
            self.stack_slot_origin(slot),
            Some(self.stack_group(slot)),
            var_type,
        )
    }

    /// Turns the simulation's placeholder values into variables of the function.
    ///
    /// Stack simulation names values with ids from a range of its own and
    /// records, for each, the storage location it is a version of. This gives
    /// every one of them a variable of the function carrying that grouping, and
    /// rewrites the instructions to name it.
    ///
    /// What it deliberately does not do is decide which definition each read
    /// names. That question is the same for every front end and
    /// [`SsaFunction::construct_ssa`] answers it from this grouping - placing
    /// the phis over the iterated dominance frontier and walking the dominator
    /// tree, rooted at the entry *and* at every handler, which is the part a
    /// hand-written renamer here used to get wrong for blocks only an exception
    /// reaches.
    fn materialize_simulation_variables(&mut self) -> Result<()> {
        // Every argument and local is defined on entry, before any instruction
        // runs: the caller supplies the arguments and `.locals init` zeroes the
        // locals. Stated as a definition of the slot's group, so a read that no
        // store dominates resolves to it rather than to nothing - which is what
        // "uses undefined variable" means when a front end leaves this out.
        let mut slot_entry: BTreeMap<u32, SsaVarId> = BTreeMap::new();
        for i in 0..self.num_args {
            let idx = Self::idx_to_u16(i)?;
            let origin = VariableOrigin::Argument(idx);
            let var_type = self.type_for_origin(origin);
            self.function.register_origin_type(origin, var_type.clone());
            let group = self.arg_group(idx);
            let entry = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            self.function.set_rename_group(entry, group);
            slot_entry.insert(group, entry);
        }
        for i in 0..self.num_locals {
            let idx = Self::idx_to_u16(i)?;
            let origin = VariableOrigin::Local(idx);
            let var_type = self.type_for_origin(origin);
            self.function.register_origin_type(origin, var_type.clone());
            let group = self.local_group(idx);
            let entry = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            self.function.set_rename_group(entry, group);
            slot_entry.insert(group, entry);
        }

        let mut map: BTreeMap<SsaVarId, SsaVarId> = BTreeMap::new();
        let block_count = self.function.blocks().len();

        // Definitions first, because a value's type is the one its defining
        // operation produces and that operation is only in hand here.
        for block_idx in 0..block_count {
            let instr_count = self
                .function
                .block(block_idx)
                .map_or(0, |block| block.instructions().len());
            for instr_idx in 0..instr_count {
                let Some(sim_def) = self
                    .function
                    .block(block_idx)
                    .and_then(|block| block.instruction(instr_idx))
                    .and_then(|instr| instr.op().dest())
                else {
                    continue;
                };
                if map.contains_key(&sim_def) {
                    continue;
                }
                let (origin, group, mut var_type) =
                    self.classify_simulation_var(sim_def, Some((block_idx, instr_idx)));
                // A copy is typed as what it copies, and the instruction still
                // names that as a simulation value here, which inference cannot
                // look up. Its variable is already made when it was defined
                // earlier in this walk; a copy left untyped would be given its
                // stack slot's type instead, which is whatever the slot held
                // first.
                if var_type.is_unknown() {
                    if let Some(SsaOp::Copy { src, .. }) = self
                        .function
                        .block(block_idx)
                        .and_then(|block| block.instruction(instr_idx))
                        .map(SsaInstruction::op)
                    {
                        if let Some(source) =
                            map.get(src).and_then(|real| self.function.variable(*real))
                        {
                            var_type = source.var_type().clone();
                        }
                    }
                }
                let def_site = DefSite::instruction(block_idx, instr_idx);
                let real = self.function.create_variable(origin, 0, def_site, var_type);
                if let Some(group) = group {
                    self.function.set_rename_group(real, group);
                }
                map.insert(sim_def, real);
            }
        }

        // Then the reads with no definition among them: a value the block was
        // entered with on the evaluation stack, or a slot read before anything
        // wrote it. Each is a version of its location like any other, and
        // construction resolves the read to whatever reaches it.
        let mut pending: Vec<SsaVarId> = Vec::new();
        for block_idx in 0..block_count {
            let Some(block) = self.function.block(block_idx) else {
                continue;
            };
            for instr in block.instructions() {
                for used in instr.op().uses() {
                    if !map.contains_key(&used) {
                        pending.push(used);
                    }
                }
            }
        }
        for sim_use in pending {
            if map.contains_key(&sim_use) {
                continue;
            }
            let (origin, group, var_type) = self.classify_simulation_var(sim_use, None);
            let real = self
                .function
                .create_variable(origin, 0, DefSite::entry(), var_type);
            if let Some(group) = group {
                self.function.set_rename_group(real, group);
            }
            map.insert(sim_use, real);
        }

        // Rewriting can be done one replacement at a time: simulation ids come
        // from a range disjoint from the function's, so no id being written can
        // collide with one still to be read, and the aliasing a simultaneous
        // substitution would have to handle cannot arise.
        let address_taken = self.address_taken.clone();
        // The group of a slot is a function of the counts alone, and those do
        // not change here; taken up front so the rewrite below borrows only the
        // blocks it is editing.
        let num_args_u32 = u32::try_from(self.num_args).unwrap_or(u32::MAX);
        for block_idx in 0..block_count {
            let Some(block) = self.function.block_mut(block_idx) else {
                continue;
            };
            for instr in block.instructions_mut() {
                let op = instr.op_mut();
                if let Some(sim_def) = op.dest() {
                    if let Some(&real) = map.get(&sim_def) {
                        op.replace_def(sim_def, real);
                    }
                }
                for sim_use in op.uses() {
                    if let Some(&real) = map.get(&sim_use) {
                        op.replace_uses(sim_use, real);
                    }
                }

                // A slot load, written as the transfer it is.
                //
                // `LoadArg`/`LoadLocal` name a slot, and construction reads them
                // as defining a value *of that slot's group*. In CIL they do not:
                // the value they produce lives on the evaluation stack, which is
                // a group of its own. Left as loads, construction resolves the
                // destination to the slot's reaching definition and drops the
                // instruction, and with it the only definition the stack slot had
                // in this block - so a later block reading that slot finds nothing
                // and the function fails to build.
                //
                // Written as a copy, both halves are stated: the use names the
                // slot, so construction redirects it to whatever definition
                // reaches here, and the definition names the stack slot, so the
                // value remains available to the blocks that go on to read it.
                //
                // A slot whose address is taken keeps its load. The value there
                // can change through the pointer, so the load is a read of memory
                // and not a transfer of a value construction could trace.
                let bridge = match op {
                    SsaOp::LoadArg { dest, arg_index } => {
                        let group = u32::from(*arg_index);
                        (!address_taken.contains(group as usize))
                            .then(|| slot_entry.get(&group).map(|&src| (*dest, src)))
                            .flatten()
                    }
                    SsaOp::LoadLocal { dest, local_index } => {
                        let group = num_args_u32.saturating_add(u32::from(*local_index));
                        (!address_taken.contains(group as usize))
                            .then(|| slot_entry.get(&group).map(|&src| (*dest, src)))
                            .flatten()
                    }
                    _ => None,
                };
                if let Some((dest, src)) = bridge {
                    instr.set_op(SsaOp::Copy { dest, src });
                }
            }
        }

        Ok(())
    }

    /// Phase 1: Simulates the stack for all blocks to identify variable definitions.
    fn simulate_all_blocks(&mut self, assembly: Option<&CilObject>) -> Result<()> {
        let rpo = self.cfg.reverse_postorder();

        // Collect exception handler entry blocks that may not be in normal RPO
        // (handler blocks are only reachable via exception flow, not normal control flow)
        let block_count = self.cfg.block_count();
        let mut rpo_set = BitSet::new(block_count);
        for n in &rpo {
            rpo_set.insert(n.index());
        }
        let mut handler_entry_blocks: Vec<usize> = Vec::new();
        for node_id in self.cfg.node_ids() {
            if let Some(block) = self.cfg.block(node_id) {
                if block.handler_entry.is_some() && !rpo_set.contains(node_id.index()) {
                    handler_entry_blocks.push(node_id.index());
                }
            }
        }

        // Compute ALL blocks reachable from handler entry blocks.
        // This is important because handlers may have internal control flow
        // (e.g., branches within the handler) that creates additional blocks
        // which are not handler entries but are only reachable via exception flow.
        let mut handler_reachable = BitSet::new(block_count);
        let mut worklist: Vec<usize> = handler_entry_blocks.clone();
        while let Some(block_idx) = worklist.pop() {
            if !handler_reachable.insert(block_idx) {
                continue; // Already visited
            }
            // Add all successors that aren't in normal RPO
            if let Some(block) = self.cfg.block(NodeId::new(block_idx)) {
                for &succ in &block.successors {
                    if !rpo_set.contains(succ) && !handler_reachable.contains(succ) {
                        worklist.push(succ);
                    }
                }
            }
        }

        // Convert handler reachable set to sorted vector for deterministic iteration
        let mut handler_blocks: Vec<usize> = handler_reachable.iter().collect();
        handler_blocks.sort_unstable();

        let block_count = self.cfg.block_count();
        for i in 0..block_count {
            self.function.add_block(SsaBlock::new(i));
        }

        // Every argument and local is named by a `u16` index.
        Self::idx_to_u16(self.num_args.saturating_sub(1))?;
        Self::idx_to_u16(self.num_locals.saturating_sub(1))?;

        // First pass: compute stack depths at block exits (including all handler-reachable blocks)
        let mut all_blocks = rpo.clone();
        for &handler_idx in &handler_blocks {
            all_blocks.push(NodeId::new(handler_idx));
        }
        let exit_depths = self.compute_stack_depths(&all_blocks, assembly)?;

        // Create a single simulator for the entire method to ensure unique variable IDs
        // across all blocks within this method. In well-formed CIL, the stack is always
        // balanced at block boundaries.
        let mut simulator = StackSimulator::new(self.num_args, self.num_locals);

        // Second pass: simulate with correct starting stack depths
        for &node_id in &rpo {
            let block_idx = node_id.index();
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            self.simulate_block(block_idx, entry_depth, &mut simulator, assembly)?;
        }

        // Also simulate all blocks reachable from exception handlers
        for &block_idx in &handler_blocks {
            let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
            self.simulate_block(block_idx, entry_depth, &mut simulator, assembly)?;
        }

        // Store stack positions for use during rename phase.
        // Maps simulation variable IDs to their stack depth at allocation time.
        self.var_stack_positions = simulator
            .var_stack_positions()
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();

        // The slot each simulation variable is a version of. With the stack
        // positions above, this is the whole of the grouping SSA construction
        // needs: together they say, for every value the simulation named, which
        // storage location it belongs to.
        self.slot_versions = simulator
            .slot_versions()
            .iter()
            .map(|(&k, &v)| (k, v))
            .collect();

        // num_locals stays at the original declared count — stack temps use
        // Phi origin and are grouped by rename_groups, not by Local index.
        self.function
            .set_num_locals(self.num_locals, self.num_locals);

        Ok(())
    }

    /// Computes the stack depth at the exit of each block.
    ///
    /// This uses a lightweight simulation that only tracks stack depth changes,
    /// not actual variable values. It iterates until fixed-point to correctly
    /// handle back edges in loops.
    ///
    /// When an assembly reference is provided, it's used to resolve correct
    /// argument counts for CALL/CALLVIRT/NEWOBJ instructions. Without it,
    /// falls back to static stack_behavior which may be incorrect.
    fn compute_stack_depths(
        &self,
        rpo: &[NodeId],
        assembly: Option<&CilObject>,
    ) -> Result<BTreeMap<usize, usize>> {
        // Limit iterations to prevent infinite loops in malformed CIL.
        const MAX_ITERATIONS: usize = 10;

        let mut exit_depths: BTreeMap<usize, usize> = BTreeMap::new();

        // Iterate until fixed-point to correctly handle back edges.
        // In the first iteration, back-edge predecessors won't be in exit_depths.
        // Subsequent iterations will see all predecessors and can compute correct depths.
        for _iteration in 0..MAX_ITERATIONS {
            let mut changed = false;

            for &node_id in rpo {
                let block_idx = node_id.index();
                let cfg_block = self.cfg.block(node_id).ok_or_else(|| {
                    Error::SsaError(format!("Block {block_idx} not found in CFG"))
                })?;

                // Compute entry depth from predecessors
                let entry_depth = self.compute_entry_depth(block_idx, &exit_depths);
                let mut depth = entry_depth;

                // Apply stack effects of each instruction
                for instr in &cfg_block.instructions {
                    // For CALL/CALLVIRT/NEWOBJ/CALLI, resolve actual argument counts from
                    // signatures since static stack_behavior metadata is often incorrect
                    // (CALLI has VarPop/VarPush so net_effect=0 without resolution)
                    let net_effect = match instr.opcode {
                        opcodes::CALL | opcodes::CALLVIRT | opcodes::NEWOBJ => assembly
                            .zip(Self::extract_token(&instr.operand))
                            .and_then(|(asm, token)| {
                                Self::resolve_call_info(asm, token).map(
                                    |(param_count, has_this, has_return)| {
                                        let is_newobj = instr.opcode == opcodes::NEWOBJ;
                                        let pops = if is_newobj {
                                            param_count
                                        } else {
                                            param_count.saturating_add(usize::from(has_this))
                                        };
                                        let pushes = if is_newobj {
                                            1
                                        } else {
                                            usize::from(has_return)
                                        };
                                        #[allow(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_possible_wrap
                                        )]
                                        ((pushes as i32)
                                            .saturating_sub(pops as i32)
                                            .clamp(i32::from(i8::MIN), i32::from(i8::MAX))
                                            as i8)
                                    },
                                )
                            })
                            .unwrap_or(instr.stack_behavior.net_effect),
                        opcodes::CALLI => assembly
                            .zip(Self::extract_token(&instr.operand))
                            .and_then(|(asm, token)| {
                                Self::resolve_calli_info(asm, token).map(
                                    |(param_count, has_this, has_return)| {
                                        // calli pops: param_count + has_this + 1 (function pointer)
                                        let pops = param_count
                                            .saturating_add(usize::from(has_this))
                                            .saturating_add(1);
                                        let pushes = usize::from(has_return);
                                        #[allow(
                                            clippy::cast_possible_truncation,
                                            clippy::cast_possible_wrap
                                        )]
                                        ((pushes as i32)
                                            .saturating_sub(pops as i32)
                                            .clamp(i32::from(i8::MIN), i32::from(i8::MAX))
                                            as i8)
                                    },
                                )
                            })
                            .unwrap_or(instr.stack_behavior.net_effect),
                        _ => instr.stack_behavior.net_effect,
                    };

                    // Apply effect, clamping to 0 if it would go negative (shouldn't happen in valid CIL)
                    #[allow(clippy::cast_sign_loss)] // Sign checked in condition
                    if net_effect < 0 {
                        depth = depth.saturating_sub(net_effect.unsigned_abs() as usize);
                    } else {
                        depth = depth.saturating_add(net_effect as usize);
                    }
                }

                // Special handling for leave instructions: they clear the stack
                // The target of a leave instruction has stack depth 0
                if let Some(last_instr) = cfg_block.instructions.last() {
                    if last_instr.opcode == opcodes::LEAVE || last_instr.opcode == opcodes::LEAVE_S
                    {
                        depth = 0;
                    }
                }

                // Check if this block's exit depth changed
                let prev_depth = exit_depths.get(&block_idx).copied();
                if prev_depth != Some(depth) {
                    exit_depths.insert(block_idx, depth);
                    changed = true;
                }
            }

            if !changed {
                break;
            }
        }

        Ok(exit_depths)
    }

    /// Computes the stack depth at block entry based on predecessor exit depths.
    ///
    /// Exception handler entry blocks have special handling:
    /// - Catch/filter handlers: stack depth = 1 (exception object on stack)
    /// - Finally/fault handlers: stack depth = 0 (empty stack)
    fn compute_entry_depth(&self, block_idx: usize, exit_depths: &BTreeMap<usize, usize>) -> usize {
        // Entry block always starts with empty stack
        if block_idx == self.cfg.entry().index() {
            return 0;
        }

        // Check if this is an exception handler entry block
        if let Some(cfg_block) = self.cfg.block(NodeId::new(block_idx)) {
            if let Some(handler_info) = &cfg_block.handler_entry {
                // Handler entry blocks have a fixed entry stack depth based on handler type
                return handler_info.entry_stack_depth();
            }
        }

        // Take the maximum of all predecessor exit depths
        // (In well-formed CIL, all predecessors should agree, but we use max for safety)
        let mut max_depth = 0;
        for pred_id in self.cfg.predecessors(NodeId::new(block_idx)) {
            if let Some(&pred_depth) = exit_depths.get(&pred_id.index()) {
                max_depth = max_depth.max(pred_depth);
            }
        }
        max_depth
    }

    /// Simulates a single block, converting CIL instructions to SSA.
    ///
    /// Uses a shared simulator to ensure unique variable IDs across all blocks within this method.
    /// In well-formed CIL, the stack is always balanced at block boundaries.
    ///
    /// # Arguments
    ///
    /// * `block_idx` - The index of the block to simulate.
    /// * `entry_stack_depth` - The stack depth at block entry.
    /// * `simulator` - The shared stack simulator for this method.
    /// * `assembly` - Optional assembly reference for resolving call signatures.
    fn simulate_block(
        &mut self,
        block_idx: usize,
        entry_stack_depth: usize,
        simulator: &mut StackSimulator,
        assembly: Option<&CilObject>,
    ) -> Result<()> {
        let node_id = NodeId::new(block_idx);
        let cfg_block = self
            .cfg
            .block(node_id)
            .ok_or_else(|| Error::SsaError(format!("Block {block_idx} not found in CFG")))?;

        // Reset the stack to the expected entry depth for this block
        // This handles cases where control flow merges with different stack states
        simulator.reset_stack_to_depth(entry_stack_depth);

        // Record the entry stack state (the placeholder variables created by reset_stack_to_depth)
        // This is needed to map placeholders to PHI results during rename
        let entry_stack = simulator.stack_snapshot();

        // A catch handler or a filter is entered with the exception on the
        // stack. Nothing computes it - the runtime put it there - so it is
        // stated as the definition it is, at the one position it can hold:
        // before anything in the block runs. Left implicit, the value has no
        // definition at all, and every reader of the IR has to know the
        // convention that a handler's first stack slot means something
        // different from every other value.
        if let Some(handler_info) = cfg_block.handler_entry.as_ref() {
            if handler_info.entry_stack_depth() > 0 {
                if let Some(&object) = entry_stack.first() {
                    let exception_type = self
                        .type_provider
                        .handler_catch_type(handler_info.handler_index);
                    if let Some(variable) = self.function.variable_mut(object) {
                        variable.set_type(exception_type.clone());
                    }
                    let mut instr = SsaInstruction::synthetic(SsaOp::RuntimeValue {
                        dest: object,
                        kind: RuntimeValueKind::ExceptionObject,
                    });
                    if !exception_type.is_unknown() {
                        instr = instr.with_result_type(exception_type);
                    }
                    if let Some(block) = self.function.block_mut(block_idx) {
                        block.add_instruction(instr);
                    }
                }
            }
        }

        // Get the block's successors for branch target resolution
        let successors = &cfg_block.successors;

        let instr_count = cfg_block.instructions.len();
        for (instr_idx, cil_instr) in cfg_block.instructions.iter().enumerate() {
            let result = Self::simulate_instruction(simulator, cil_instr, assembly)?;

            // Pass successors only for the last instruction (terminator)
            // Non-terminator instructions don't need successor information
            let instr_successors = if instr_idx.saturating_add(1) == instr_count {
                successors.as_slice()
            } else {
                &[]
            };

            // Decompose the CIL instruction into an SsaOp
            let op = decompose_instruction(
                cil_instr,
                &result.uses,
                result.def,
                instr_successors,
                assembly,
            )?;

            // Create SSA instruction with the decomposed operation and resolved type
            let result_type = self.infer_op_result_type(&op);
            let ssa_instr = if result_type.is_unknown() {
                SsaInstruction::new(cil_instr.clone(), op)
            } else {
                SsaInstruction::new(cil_instr.clone(), op).with_result_type(result_type)
            };

            if let Some(block) = self.function.block_mut(block_idx) {
                block.add_instruction(ssa_instr);
            }
        }

        // If the block doesn't end with a terminator and has a single successor (fallthrough),
        // add an explicit Jump instruction to make the control flow explicit in SSA.
        // This is essential for correct CFG analysis and dead code elimination.
        if let Some(block) = self.function.block_mut(block_idx) {
            let has_terminator = block
                .instructions()
                .last()
                .is_some_and(|instr| instr.op().is_terminator());

            if !has_terminator && successors.len() == 1 {
                if let Some(&fallthrough_target) = successors.first() {
                    let jump_instr = SsaInstruction::synthetic(SsaOp::Jump {
                        target: fallthrough_target,
                    });
                    block.add_instruction(jump_instr);
                }
            }
        }

        for i in 0..self.num_args {
            if simulator.is_arg_address_taken(i) {
                let idx = Self::idx_to_u16(i)?;
                self.address_taken.insert(self.arg_group(idx) as usize);
            }
        }
        for i in 0..self.num_locals {
            if simulator.is_local_address_taken(i) {
                let idx = Self::idx_to_u16(i)?;
                self.address_taken.insert(self.local_group(idx) as usize);
            }
        }

        Ok(())
    }

    /// Simulates a single CIL instruction, returning the stack effects.
    ///
    /// All 257 CIL instructions are covered: specific handling for load/store instructions
    /// that affect SSA variables, and generic stack effect simulation for all others.
    ///
    /// When an assembly reference is provided, call/callvirt/newobj instructions are handled
    /// with correct argument counts based on the method signature rather than using
    /// the static stack_behavior values.
    fn simulate_instruction(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
    ) -> Result<SimulationResult> {
        let result = if instr.prefix == opcodes::FE_PREFIX {
            match instr.opcode {
                opcodes::FE_LDARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::FE_LDARGA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::FE_STARG => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::FE_LDLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::FE_LDLOCA => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::FE_STLOC => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                opcodes::FE_INITOBJ => simulator.simulate_initobj(),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        } else {
            match instr.opcode {
                opcodes::LDARG_0 => simulator.simulate_ldarg(0),
                opcodes::LDARG_1 => simulator.simulate_ldarg(1),
                opcodes::LDARG_2 => simulator.simulate_ldarg(2),
                opcodes::LDARG_3 => simulator.simulate_ldarg(3),
                opcodes::LDLOC_0 => simulator.simulate_ldloc(0),
                opcodes::LDLOC_1 => simulator.simulate_ldloc(1),
                opcodes::LDLOC_2 => simulator.simulate_ldloc(2),
                opcodes::LDLOC_3 => simulator.simulate_ldloc(3),
                opcodes::STLOC_0 => simulator.simulate_stloc(0),
                opcodes::STLOC_1 => simulator.simulate_stloc(1),
                opcodes::STLOC_2 => simulator.simulate_stloc(2),
                opcodes::STLOC_3 => simulator.simulate_stloc(3),
                opcodes::LDARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarg(idx)),
                opcodes::LDARGA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldarga(idx)),
                opcodes::STARG_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_starg(idx)),
                opcodes::LDLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloc(idx)),
                opcodes::LDLOCA_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_ldloca(idx)),
                opcodes::STLOC_S => Self::extract_index(&instr.operand)
                    .and_then(|idx| simulator.simulate_stloc(idx)),
                opcodes::DUP => simulator.simulate_dup(),
                opcodes::RET => Some(simulator.simulate_ret()),
                // Leave instructions clear the stack and transfer out of protected region
                opcodes::LEAVE | opcodes::LEAVE_S => Some(simulator.simulate_leave()),
                // Call instructions require special handling with assembly for signature lookup
                opcodes::CALL | opcodes::CALLVIRT => {
                    return Self::simulate_call(simulator, instr, assembly, false);
                }
                opcodes::NEWOBJ => {
                    return Self::simulate_call(simulator, instr, assembly, true);
                }
                // calli requires StandAloneSig resolution for correct stack simulation
                opcodes::CALLI => {
                    return Self::simulate_calli(simulator, instr, assembly);
                }
                // stind.* instructions write through an address - track as indirect store
                opcodes::STIND_REF
                | opcodes::STIND_I1
                | opcodes::STIND_I2
                | opcodes::STIND_I4
                | opcodes::STIND_I8
                | opcodes::STIND_R4
                | opcodes::STIND_R8
                | opcodes::STIND_I => simulator.simulate_stind(),
                _ => simulator
                    .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes),
            }
        };

        result.ok_or_else(|| {
            Error::SsaError(format!(
                "Stack simulation failed for instruction: {}",
                instr.mnemonic
            ))
        })
    }

    /// Simulates a call instruction (call, callvirt, or newobj).
    ///
    /// If an assembly is provided, it's used to look up the method signature for
    /// correct argument counts. Returns an error if the signature cannot be resolved.
    ///
    /// # Errors
    ///
    /// Returns an error if the method signature cannot be resolved from the assembly.
    fn simulate_call(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
        is_newobj: bool,
    ) -> Result<SimulationResult> {
        let token = Self::extract_token(&instr.operand).ok_or_else(|| {
            Error::SsaError(format!(
                "Call instruction {} missing method token",
                instr.mnemonic
            ))
        })?;

        // Try to get call info from assembly
        if let Some(assembly) = assembly {
            if let Some((param_count, has_this, has_return)) =
                Self::resolve_call_info(assembly, token)
            {
                // For newobj: pop param_count args, push 1 (the new object)
                // For call/callvirt: pop (param_count + has_this) args, push has_return
                let pops = if is_newobj {
                    // newobj doesn't pop 'this' - it creates it
                    param_count
                } else {
                    param_count.saturating_add(usize::from(has_this))
                };

                let pushes = if is_newobj {
                    1 // newobj always pushes the new object
                } else {
                    usize::from(has_return)
                };

                #[allow(clippy::cast_possible_truncation)]
                return simulator
                    .simulate_stack_effect(pops.min(255) as u8, pushes.min(255) as u8)
                    .ok_or_else(|| {
                        Error::SsaError(format!(
                            "Stack underflow simulating {} with {} pops",
                            instr.mnemonic, pops
                        ))
                    });
            }
        }

        // Resolution failed - this is an error for call/callvirt/newobj since they have
        // "variable" stack behavior (pops=0, pushes=0 in metadata) that requires resolution.
        if instr.stack_behavior.pops == 0 && instr.stack_behavior.pushes == 0 {
            return Err(Error::SsaError(format!(
                "Failed to resolve method signature for {} token 0x{:08X}. \
                 Call instructions require signature resolution for correct stack simulation.",
                instr.mnemonic,
                token.value()
            )));
        }

        // Fall back to static stack behavior (for rare cases where metadata has correct values)
        simulator
            .simulate_stack_effect(instr.stack_behavior.pops, instr.stack_behavior.pushes)
            .ok_or_else(|| {
                Error::SsaError(format!("Stack underflow simulating {}", instr.mnemonic))
            })
    }

    /// Simulates a `calli` instruction by resolving its `StandAloneSig` token.
    ///
    /// The `calli` instruction pops: `arg0, arg1, ..., argN, function_pointer` and
    /// optionally pushes a return value. The number of arguments and return type are
    /// determined by the standalone method signature referenced by the instruction's
    /// operand token (table 0x11).
    fn simulate_calli(
        simulator: &mut StackSimulator,
        instr: &Instruction,
        assembly: Option<&CilObject>,
    ) -> Result<SimulationResult> {
        let token = Self::extract_token(&instr.operand).ok_or_else(|| {
            Error::SsaError(format!(
                "calli instruction missing StandAloneSig token: {}",
                instr.mnemonic
            ))
        })?;

        if let Some(assembly) = assembly {
            if let Some((param_count, has_this, has_return)) =
                Self::resolve_calli_info(assembly, token)
            {
                // calli pops: param_count + has_this args + 1 function pointer
                let pops = param_count
                    .saturating_add(usize::from(has_this))
                    .saturating_add(1);
                let pushes = usize::from(has_return);

                #[allow(clippy::cast_possible_truncation)]
                return simulator
                    .simulate_stack_effect(pops.min(255) as u8, pushes.min(255) as u8)
                    .ok_or_else(|| {
                        Error::SsaError(format!(
                            "Stack underflow simulating calli with {} pops",
                            pops
                        ))
                    });
            }
        }

        // Resolution failed — calli has VarPop/VarPush so static metadata is useless
        Err(Error::SsaError(format!(
            "Failed to resolve StandAloneSig for calli token 0x{:08X}. \
             calli requires signature resolution for correct stack simulation.",
            token.value()
        )))
    }

    /// Resolves a `StandAloneSig` token to (param_count, has_this, has_return).
    fn resolve_calli_info(assembly: &CilObject, token: Token) -> Option<(usize, bool, bool)> {
        if token.table() != 0x11 {
            return None;
        }
        let tables = assembly.tables()?;
        let table = tables.table::<StandAloneSigRaw>()?;
        let raw = table.get(token.row()).ok().flatten()?;
        let blob = assembly.blob()?;
        let owned = raw.to_owned(blob).ok()?;
        match &owned.parsed_signature {
            StandAloneSignature::Method(sig) => {
                let has_return = !matches!(sig.return_type.base, TypeSignature::Void);
                Some((sig.param_count as usize, sig.has_this, has_return))
            }
            _ => None,
        }
    }

    /// Resolves call information (param_count, has_this, has_return) from a method token.
    ///
    /// Handles MethodDef (0x06), MemberRef (0x0A), and MethodSpec (0x2B) tokens.
    fn resolve_call_info(assembly: &CilObject, token: Token) -> Option<(usize, bool, bool)> {
        match token.table() {
            // MethodDef (0x06) - method defined in this assembly
            0x06 => {
                let method = assembly.method(&token).ok()?;
                let param_count = method.signature.params.len();
                let has_this = !method.is_static();
                let has_return = !matches!(method.signature.return_type.base, TypeSignature::Void);
                Some((param_count, has_this, has_return))
            }

            // MemberRef (0x0A) - method or field in external assembly
            0x0A => {
                let member_ref = assembly.member_ref(&token)?;
                if let MemberRefSignature::Method(sig) = &member_ref.signature {
                    let has_return = !matches!(sig.return_type.base, TypeSignature::Void);
                    Some((sig.param_count as usize, sig.has_this, has_return))
                } else {
                    None // Field, not a method
                }
            }

            // MethodSpec (0x2B) - generic method instantiation
            0x2B => {
                let method_spec = assembly.method_spec(&token).ok()?;
                // Get the underlying method token from the CilTypeReference
                let underlying_token = match &method_spec.method {
                    CilTypeReference::MethodDef(method_ref) => {
                        method_ref.upgrade().map(|m| m.token)
                    }
                    CilTypeReference::MemberRef(member_ref) => Some(member_ref.token),
                    _ => None,
                };
                underlying_token.and_then(|t| Self::resolve_call_info(assembly, t))
            }

            _ => None,
        }
    }

    /// Extracts a method token from an instruction operand.
    fn extract_token(operand: &Operand) -> Option<Token> {
        match operand {
            Operand::Token(token) => Some(*token),
            _ => None,
        }
    }

    /// Extracts an index from an operand.
    ///
    /// Handles both the typed operand forms (Argument, Local) and immediate values
    /// that are produced by the instruction assembler/decoder.
    fn extract_index(operand: &Operand) -> Option<usize> {
        match operand {
            Operand::Argument(idx) | Operand::Local(idx) => Some(*idx as usize),
            Operand::Immediate(imm) => match imm {
                Immediate::Int8(v) => usize::try_from(*v).ok(),
                Immediate::UInt8(v) => Some(*v as usize),
                Immediate::Int16(v) => usize::try_from(*v).ok(),
                Immediate::UInt16(v) => Some(*v as usize),
                Immediate::Int32(v) => usize::try_from(*v).ok(),
                Immediate::UInt32(v) => Some(*v as usize),
                _ => None,
            },
            _ => None,
        }
    }

    /// Makes the truncation of a store into a narrow slot explicit.
    ///
    /// `stloc` and `starg` into a local or argument narrower than four bytes
    /// keep only the slot's width: a `uint` stored into a `ushort` local reads
    /// back as its low sixteen bits. Decomposed as a copy, the store claimed
    /// the slot held the whole value, and every pass reading the local later
    /// computed with a value the program never has. Each such copy becomes the
    /// conversion the store performs, unless the value is known to fit: a
    /// constant in range, a comparison, or a value whose own type fits the
    /// slot. A `bool` slot is left alone: compilers only store 0 or 1 into one,
    /// and a conversion to `bool` is not an integer conversion CIL has.
    fn make_narrow_stores_explicit(&mut self) {
        /// The values a narrow integer type holds.
        fn range(ty: &SsaType) -> Option<(i128, i128)> {
            match ty {
                SsaType::I8 => Some((-128, 127)),
                SsaType::U8 => Some((0, 255)),
                SsaType::I16 => Some((-32768, 32767)),
                SsaType::U16 | SsaType::Char => Some((0, 65535)),
                SsaType::Bool => Some((0, 1)),
                _ => None,
            }
        }
        for block_idx in 0..self.function.blocks().len() {
            let instr_count = self
                .function
                .block(block_idx)
                .map_or(0, |block| block.instructions().len());
            for instr_idx in 0..instr_count {
                let Some(SsaOp::Copy { dest, src }) = self
                    .function
                    .block(block_idx)
                    .and_then(|block| block.instruction(instr_idx))
                    .map(|instr| instr.op().clone())
                else {
                    continue;
                };
                let Some(origin) = self.function.variable(dest).map(|var| var.origin()) else {
                    continue;
                };
                if !matches!(
                    origin,
                    VariableOrigin::Local(_) | VariableOrigin::Argument(_)
                ) {
                    continue;
                }
                let slot_type = self.function.origin_type(origin);
                let Some((min, max)) = range(&slot_type) else {
                    continue;
                };
                if slot_type == SsaType::Bool {
                    continue;
                }
                let src_type = self
                    .function
                    .variable(src)
                    .map_or(SsaType::Unknown, |var| var.var_type().clone());
                let fits = match self.function.get_definition(src) {
                    Some(SsaOp::Const { value, .. }) => value
                        .as_i64()
                        .is_some_and(|v| (min..=max).contains(&i128::from(v))),
                    Some(SsaOp::Ceq { .. } | SsaOp::Clt { .. } | SsaOp::Cgt { .. }) => true,
                    _ => range(&src_type).is_some_and(|(lo, hi)| min <= lo && hi <= max),
                };
                if fits || !src_type.is_integer() {
                    continue;
                }
                let conversion = SsaOp::conversion_between(
                    dest,
                    src,
                    slot_type,
                    Some(&src_type),
                    matches!(
                        src_type,
                        SsaType::U8
                            | SsaType::U16
                            | SsaType::U32
                            | SsaType::U64
                            | SsaType::NativeUInt
                            | SsaType::Char
                            | SsaType::Bool
                    ),
                    false,
                );
                if let Some(instr) = self
                    .function
                    .block_mut(block_idx)
                    .and_then(|block| block.instructions_mut().get_mut(instr_idx))
                {
                    instr.set_op(conversion);
                }
            }
        }
    }

    /// Resolves Unknown-typed phi variables from their operands.
    ///
    /// After rename, phi nodes may have Unknown type because they were created
    /// before their operands were known. This pass iterates until fixpoint,
    /// propagating non-Unknown types bidirectionally:
    /// - Forward: from phi operands to phi results
    /// - Backward: from phi results to Unknown-typed operands
    ///
    /// After fixpoint, resolves any remaining Unknown-typed variables by
    /// examining their defining instruction's result type.
    fn resolve_phi_types(&mut self) {
        // Phases 1 and 2 feed each other: an arithmetic result is typed by
        // its operands, which a phi may type, and a phi by its operands, which
        // arithmetic may define. Both only turn `Unknown` into a type, so the
        // loop ends.
        loop {
            loop {
                self.resolve_phi_types_once();
                if !self.resolve_unknown_from_definitions() {
                    break;
                }
            }
            // An arithmetic result whose operands no evidence types is the
            // stack's default `int32`, as an untyped integer computation is;
            // what is computed from it is typed again from there.
            if !self.default_untyped_arithmetic() {
                break;
            }
        }
        self.propagate_group_types();
    }

    /// Types every `Unknown` arithmetic result `int32`. Returns whether any
    /// was typed.
    fn default_untyped_arithmetic(&mut self) -> bool {
        let mut typed = false;
        let var_count = self.function.variables().len();
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let Some(var) = self.function.variable(var_id) else {
                continue;
            };
            let (Some(instr), true) = (var.def_site().instruction, var.var_type().is_unknown())
            else {
                continue;
            };
            let arithmetic = self
                .function
                .block(var.def_site().block)
                .and_then(|block| block.instruction(instr))
                .is_some_and(|instruction| {
                    matches!(
                        instruction.op(),
                        SsaOp::Add { .. }
                            | SsaOp::AddOvf { .. }
                            | SsaOp::Sub { .. }
                            | SsaOp::SubOvf { .. }
                            | SsaOp::Mul { .. }
                            | SsaOp::MulOvf { .. }
                            | SsaOp::Div { .. }
                            | SsaOp::Rem { .. }
                            | SsaOp::And { .. }
                            | SsaOp::Or { .. }
                            | SsaOp::Xor { .. }
                            | SsaOp::Shl { .. }
                            | SsaOp::Shr { .. }
                            | SsaOp::Neg { .. }
                            | SsaOp::Not { .. }
                    )
                });
            if arithmetic {
                if let Some(var) = self.function.variable_mut(var_id) {
                    var.set_type(SsaType::I32);
                    typed = true;
                }
            }
        }
        typed
    }

    /// Phase 1: types phi results from their operands and operands from their
    /// phi, to a fixpoint.
    fn resolve_phi_types_once(&mut self) {
        let mut changed = true;
        while changed {
            changed = false;
            for block_idx in 0..self.function.blocks().len() {
                let phi_count = self.function.block(block_idx).map_or(0, |b| b.phi_count());
                for phi_idx in 0..phi_count {
                    let (result, operand_ids) = {
                        let Some(block) = self.function.block(block_idx) else {
                            continue;
                        };
                        let Some(phi) = block.phi(phi_idx) else {
                            continue;
                        };
                        let result = phi.result();
                        let ops: Vec<SsaVarId> = phi.operands().iter().map(|o| o.value()).collect();
                        (result, ops)
                    };

                    // Find first non-Unknown type among result and all operands
                    let known_type = {
                        let result_type = self
                            .function
                            .variable(result)
                            .map(|v| v.var_type().clone())
                            .filter(|t| !t.is_unknown());

                        // The join of every operand's type, not the first one
                        // seen: a merge of a `ushort` and a `uint` holds the
                        // `uint`, and typed `ushort` it gave the merge a slot
                        // that truncates the other arm.
                        result_type.or_else(|| {
                            operand_ids
                                .iter()
                                .filter_map(|&op_id| {
                                    self.function
                                        .variable(op_id)
                                        .map(|v| v.var_type().clone())
                                        .filter(|t| !t.is_unknown())
                                })
                                .reduce(|joined, ty| join_merge_types(&joined, &ty))
                        })
                    };

                    // A merge no type holds is as unknown as no operand at all:
                    // writing `Unknown` over `Unknown` changes nothing, and
                    // counting it as a change never lets the fixpoint end.
                    let Some(ty) = known_type.filter(|ty| !ty.is_unknown()) else {
                        continue;
                    };

                    // Forward: resolve phi result if Unknown
                    if let Some(var) = self.function.variable(result) {
                        if var.var_type().is_unknown() {
                            if let Some(var) = self.function.variable_mut(result) {
                                var.set_type(ty.clone());
                                changed = true;
                            }
                        }
                    }

                    // Backward: resolve Unknown-typed operands from the phi type
                    for &op_id in &operand_ids {
                        if let Some(var) = self.function.variable(op_id) {
                            if var.var_type().is_unknown() {
                                if let Some(var) = self.function.variable_mut(op_id) {
                                    var.set_type(ty.clone());
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Phase 2: types every `Unknown` variable an instruction defines from
    /// that instruction. Returns whether any was typed.
    fn resolve_unknown_from_definitions(&mut self) -> bool {
        let mut typed = false;
        let var_count = self.function.variables().len();
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let (is_unknown, block, instr_idx) = {
                let Some(var) = self.function.variable(var_id) else {
                    continue;
                };
                let ds = var.def_site();
                (var.var_type().is_unknown(), ds.block, ds.instruction)
            };
            if !is_unknown {
                continue;
            }
            if let Some(idx) = instr_idx {
                let resolved = self.infer_instruction_result_type(block, idx);
                if !resolved.is_unknown() {
                    if let Some(var) = self.function.variable_mut(var_id) {
                        var.set_type(resolved);
                        typed = true;
                    }
                }
            }
        }
        typed
    }

    /// Phase 3: types every `Unknown` version of an argument or local from the
    /// other versions of its slot.
    fn propagate_group_types(&mut self) {
        // Phase 3: Propagate types within the groups of arguments and locals.
        // Every version of a slot has the slot's type. A stack slot's group is
        // not one: the values pushed at a depth over a method are unrelated,
        // and typing one by another gave a copy of an object the `int32` a
        // slot held first.
        let var_count = self.function.variables().len();
        let mut group_types: BTreeMap<u32, SsaType> = BTreeMap::new();
        let slot_groups = self.stack_group(0);

        // Collect known types per group
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let group = self.function.rename_group(var_id);
            if group >= slot_groups {
                continue;
            }
            if let Some(var) = self.function.variable(var_id) {
                if !var.var_type().is_unknown() {
                    group_types
                        .entry(group)
                        .or_insert_with(|| var.var_type().clone());
                }
            }
        }

        // Apply group types to Unknown-typed variables
        for var_idx in 0..var_count {
            let var_id = SsaVarId::from_index(var_idx);
            let group = self.function.rename_group(var_id);
            if group >= slot_groups {
                continue;
            }
            if let Some(var) = self.function.variable(var_id) {
                if var.var_type().is_unknown() {
                    if let Some(ty) = group_types.get(&group) {
                        if let Some(var) = self.function.variable_mut(var_id) {
                            var.set_type(ty.clone());
                        }
                    }
                }
            }
        }
    }
}

/// The type a merge of values of types `a` and `b` holds.
///
/// Equal types are that type. Integers of one storage width join to the type
/// that holds both: the wider unsigned type when both are unsigned, else the
/// signed type of the width. The other merges are of what the evaluation stack
/// held, so they join to the stack's type: a 32-bit integer meeting a 64-bit
/// one is the 64-bit type; pointers and native integers are `native int`; a
/// value type meeting an integer is an enum, and the integer's stack width
/// holds it; two reference types meet at `object`. Anything else is `Unknown`:
/// no slot is chosen by guessing.
fn join_merge_types(a: &SsaType, b: &SsaType) -> SsaType {
    if a == b {
        return a.clone();
    }
    let unsigned = |ty: &SsaType| {
        matches!(
            ty,
            SsaType::Bool | SsaType::U8 | SsaType::U16 | SsaType::Char | SsaType::U32
        )
    };
    let native = |ty: &SsaType| {
        matches!(
            ty,
            SsaType::NativeInt | SsaType::NativeUInt | SsaType::Pointer(_) | SsaType::FnPtr(_)
        )
    };
    let width = |ty: &SsaType| match ty {
        SsaType::Bool | SsaType::I8 | SsaType::U8 => Some(1u8),
        SsaType::I16 | SsaType::U16 | SsaType::Char => Some(2),
        SsaType::I32 | SsaType::U32 => Some(4),
        _ => None,
    };
    match (width(a), width(b)) {
        (Some(wa), Some(wb)) => {
            if unsigned(a) && unsigned(b) {
                if wa >= wb && !matches!(a, SsaType::Bool | SsaType::Char) {
                    a.clone()
                } else if wb > wa && !matches!(b, SsaType::Bool | SsaType::Char) {
                    b.clone()
                } else if wa.max(wb) >= 4 {
                    SsaType::U32
                } else if wa.max(wb) == 2 {
                    SsaType::U16
                } else {
                    SsaType::U8
                }
            } else {
                SsaType::I32
            }
        }
        _ => match (a, b) {
            (SsaType::I64 | SsaType::U64, SsaType::I64 | SsaType::U64) => SsaType::I64,
            // A 32-bit integer meeting a 64-bit one: the wider type holds both.
            (SsaType::I64 | SsaType::U64, other) | (other, SsaType::I64 | SsaType::U64)
                if width(other).is_some() =>
            {
                SsaType::I64
            }
            // Pointers and native integers are one stack type, and a 32-bit
            // integer meeting one widens to it.
            _ if native(a) && (native(b) || width(b).is_some())
                || native(b) && width(a).is_some() =>
            {
                SsaType::NativeInt
            }
            (SsaType::ValueType(_), other) | (other, SsaType::ValueType(_))
                if width(other).is_some() =>
            {
                SsaType::I32
            }
            (SsaType::ValueType(_), SsaType::I64 | SsaType::U64)
            | (SsaType::I64 | SsaType::U64, SsaType::ValueType(_)) => SsaType::I64,
            (SsaType::Null, other) | (other, SsaType::Null) if other.is_reference() => {
                other.clone()
            }
            _ if a.is_reference() && b.is_reference() => SsaType::Object,
            _ => SsaType::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{
        analysis::{SsaVerifier, TypeRef, VerifyLevel},
        assembly::InstructionAssembler,
        testkit::{build_cfg, build_ssa, TestTypeProvider},
    };

    #[test]
    fn test_simple_function() {
        // Simple method: return arg0 + arg1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(2, 0)).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have at least 2 variables (args)
        assert!(ssa.variable_count() >= 2);
    }

    #[test]
    fn test_local_variable() {
        // Method: local0 = arg0; return local0
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        // Should have 1 block
        assert_eq!(ssa.block_count(), 1);

        // Should have variables for arg and local
        assert!(ssa.variable_count() >= 2);
    }

    /// arg ? null : 1.0 on the stack, then dropped: a phi of a reference and a double, which
    /// no type holds. Typing it must still finish; a stall hangs the test.
    #[test]
    fn a_merge_no_type_holds_does_not_stall_phi_typing() {
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brtrue_s("reference")
            .unwrap()
            .ldc_r8(1.0)
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("reference")
            .unwrap()
            .ldnull()
            .unwrap()
            .label("merge")
            .unwrap()
            .pop()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();
        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");

        build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction");
    }

    #[test]
    fn a_merge_joins_to_the_type_the_stack_held() {
        let enum_type = SsaType::ValueType(TypeRef::new(Token::new(0x0100_0002)));
        let class = SsaType::Class(TypeRef::new(Token::new(0x0100_0003)));
        let other_class = SsaType::Class(TypeRef::new(Token::new(0x0100_0004)));

        assert_eq!(join_merge_types(&SsaType::U8, &SsaType::U16), SsaType::U16);
        assert_eq!(join_merge_types(&SsaType::I16, &SsaType::U16), SsaType::I32);
        // An enum meeting a short: both were int32 on the stack.
        assert_eq!(join_merge_types(&SsaType::I16, &enum_type), SsaType::I32);
        assert_eq!(join_merge_types(&enum_type, &SsaType::I16), SsaType::I32);
        assert_eq!(join_merge_types(&enum_type, &SsaType::I64), SsaType::I64);
        assert_eq!(join_merge_types(&SsaType::Null, &class), class);
        assert_eq!(join_merge_types(&class, &other_class), SsaType::Object);
        assert_eq!(join_merge_types(&SsaType::I32, &SsaType::I64), SsaType::I64);
        assert_eq!(
            join_merge_types(
                &SsaType::Pointer(Box::new(SsaType::U8)),
                &SsaType::NativeUInt
            ),
            SsaType::NativeInt
        );
        assert_eq!(
            join_merge_types(&SsaType::I32, &SsaType::NativeInt),
            SsaType::NativeInt
        );
        // No stack type holds both: no guess.
        assert_eq!(join_merge_types(&SsaType::F64, &class), SsaType::Unknown);
    }

    /// The operation that defines `var`, if an instruction does.
    fn defining_op(ssa: &SsaFunction, var: SsaVarId) -> Option<&SsaOp> {
        ssa.blocks()
            .iter()
            .flat_map(|block| block.instructions())
            .map(SsaInstruction::op)
            .find(|op| op.dest() == Some(var))
    }

    /// The value the function's first `ret` returns, seen through copies.
    fn returned_value(ssa: &SsaFunction) -> SsaVarId {
        let mut value = ssa
            .blocks()
            .iter()
            .flat_map(|block| block.instructions())
            .find_map(|instr| match instr.op() {
                SsaOp::Return { value } => *value,
                _ => None,
            })
            .expect("a value-returning ret");
        while let Some(SsaOp::Copy { src, .. }) = defining_op(ssa, value) {
            value = *src;
        }
        value
    }

    #[test]
    fn a_local_read_before_any_write_holds_zero() {
        let mut asm = InstructionAssembler::new();
        asm.ldloc_0().unwrap().ret().unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction failed");

        assert!(
            matches!(
                defining_op(&ssa, returned_value(&ssa)),
                Some(SsaOp::Const {
                    value: ConstValue::I32(0),
                    ..
                })
            ),
            "`.locals init` zeroes the local, and the read sees that zero:\n{ssa}"
        );
        let findings = SsaVerifier::new(&ssa).verify(VerifyLevel::Full);
        assert!(
            findings.is_empty(),
            "the zero is a definition like any other: {findings:?}\n{ssa}"
        );
    }

    /// The conversion `ret`urned by a two-instruction body.
    fn conversion_of(asm: InstructionAssembler) -> SsaOp {
        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");
        defining_op(&ssa, returned_value(&ssa))
            .cloned()
            .expect("the returned value has a definition")
    }

    /// The type of the value a function built from `asm` returns.
    fn returned_type(asm: InstructionAssembler) -> SsaType {
        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");
        ssa.variable(returned_value(&ssa))
            .map(|variable| variable.var_type().clone())
            .expect("the returned value is a variable")
    }

    /// Arithmetic is typed by what it computes on (ECMA-335 III.1.5), not
    /// as `int32` whatever its operands: a `float32` product, an `int64`
    /// quotient, a shifted `int64`.
    ///
    /// Every arithmetic result used to be typed `int32`, so `conv.r8` of a
    /// `float32` division read as converting an integer, and a store forwarded
    /// to a `float32` field load was reconciled with a bitcast nothing could
    /// lower.
    #[test]
    fn arithmetic_is_typed_by_its_operands() {
        let mut asm = InstructionAssembler::new();
        asm.ldc_r4(1.5)
            .unwrap()
            .ldc_r4(2.0)
            .unwrap()
            .mul()
            .unwrap()
            .ret()
            .unwrap();
        assert_eq!(returned_type(asm), SsaType::F32);

        let mut asm = InstructionAssembler::new();
        asm.ldc_i8(10)
            .unwrap()
            .ldc_i8(3)
            .unwrap()
            .div()
            .unwrap()
            .ret()
            .unwrap();
        assert_eq!(returned_type(asm), SsaType::I64);

        let mut asm = InstructionAssembler::new();
        asm.ldc_i8(1)
            .unwrap()
            .ldc_i4(3)
            .unwrap()
            .shl()
            .unwrap()
            .ret()
            .unwrap();
        assert_eq!(returned_type(asm), SsaType::I64);

        let mut asm = InstructionAssembler::new();
        asm.ldc_r4(1.0)
            .unwrap()
            .ldc_r4(4.0)
            .unwrap()
            .div()
            .unwrap()
            .conv_r8()
            .unwrap()
            .ret()
            .unwrap();
        assert!(
            matches!(conversion_of(asm), SsaOp::FloatConv { .. }),
            "conv.r8 of a float32 quotient widens a float"
        );
    }

    /// `conv.i8` of a `float64` truncates it: a float-to-integer conversion,
    /// not an integer conversion of a float.
    ///
    /// Chosen from the destination alone, it came out as `IntConv`, which an
    /// analysis reading integer conversions as moving bits turned into a
    /// reinterpretation of the double's bits - a different number.
    #[test]
    fn conv_i8_of_a_double_truncates_it() {
        let mut asm = InstructionAssembler::new();
        asm.ldc_r8(2.5).unwrap().conv_i8().unwrap().ret().unwrap();
        assert!(
            matches!(conversion_of(asm), SsaOp::FloatToInt { .. }),
            "a float converted to an integer"
        );
    }

    /// `conv.r8` of a `float32` widens a float; of an `int32` it converts an
    /// integer.
    #[test]
    fn conv_r8_is_chosen_by_what_it_converts() {
        let mut asm = InstructionAssembler::new();
        asm.ldc_r4(1.5).unwrap().conv_r8().unwrap().ret().unwrap();
        assert!(matches!(conversion_of(asm), SsaOp::FloatConv { .. }));

        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(3).unwrap().conv_r8().unwrap().ret().unwrap();
        assert!(matches!(conversion_of(asm), SsaOp::IntToFloat { .. }));
    }

    /// The control: `conv.i8` of an `int32` stays an integer conversion.
    #[test]
    fn conv_i8_of_an_int_is_an_integer_conversion() {
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(3).unwrap().conv_i8().unwrap().ret().unwrap();
        assert!(matches!(conversion_of(asm), SsaOp::IntConv { .. }));
    }

    /// A `dup` copies the value on top of the stack, and is typed as that
    /// value - not as whatever the stack slot it lands in held first. Depth 1
    /// holds an `int64` before it holds the copy of a `float64` here.
    #[test]
    fn a_dup_is_typed_as_what_it_copies() {
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(1)
            .unwrap()
            .ldc_i8(7)
            .unwrap()
            .pop()
            .unwrap()
            .pop()
            .unwrap()
            .ldc_r8(2.5)
            .unwrap()
            .dup()
            .unwrap()
            .mul()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let provider = TestTypeProvider::all_i32(0, 0);
        let ssa = build_ssa(&cfg, &provider).expect("SSA construction failed");

        let copies: Vec<SsaType> = ssa
            .blocks()
            .iter()
            .flat_map(|block| block.instructions())
            .filter_map(|instr| match instr.op() {
                SsaOp::Copy { dest, .. } => ssa.variable(*dest).map(|v| v.var_type().clone()),
                _ => None,
            })
            .collect();
        assert_eq!(copies, vec![SsaType::F64], "{ssa}");
    }

    #[test]
    fn without_locals_init_an_unwritten_local_is_not_assumed_zero() {
        let mut asm = InstructionAssembler::new();
        asm.ldloc_0().unwrap().ret().unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let provider = TestTypeProvider::all_i32(0, 1).without_locals_init();
        let ssa = build_ssa(&cfg, &provider).expect("SSA construction failed");

        assert!(
            defining_op(&ssa, returned_value(&ssa)).is_none(),
            "the local's initial contents are unspecified:\n{ssa}"
        );
    }

    #[test]
    fn a_loop_at_the_first_instruction_starts_from_the_zeroed_local() {
        // loop: local0 = local0 + arg0; if (local0 < 10) goto loop; return local0
        let mut asm = InstructionAssembler::new();
        asm.label("loop")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(10)
            .unwrap()
            .blt("loop")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        let findings = SsaVerifier::new(&ssa).verify(VerifyLevel::Full);
        assert!(
            findings.is_empty(),
            "the zero must dominate the loop it enters: {findings:?}\n{ssa}"
        );
        let entry_operand_is_zero = ssa.blocks().iter().flat_map(|b| b.phi_nodes()).any(|phi| {
            phi.operands().iter().any(|operand| {
                matches!(
                    defining_op(&ssa, operand.value()),
                    Some(SsaOp::Const {
                        value: ConstValue::I32(0),
                        ..
                    })
                )
            })
        });
        assert!(
            entry_operand_is_zero,
            "the loop header merges the zeroed local on its entry edge:\n{ssa}"
        );
    }

    #[test]
    fn a_struct_local_read_before_any_write_does_not_take_its_address() {
        let mut asm = InstructionAssembler::new();
        asm.ldloc_0().unwrap().ret().unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let provider = TestTypeProvider::all_i32(0, 1)
            .local(0, SsaType::ValueType(TypeRef::new(Token::new(0x0200_0002))));
        let ssa = build_ssa(&cfg, &provider).expect("SSA construction failed");

        assert!(
            ssa.blocks()
                .iter()
                .flat_map(|b| b.instructions())
                .all(|i| !matches!(i.op(), SsaOp::LoadLocalAddr { .. } | SsaOp::InitObj { .. })),
            "a zeroed struct is the slot's entry value, not an `initobj` through its address:\n{ssa}"
        );
    }

    #[test]
    fn test_conditional_no_phi() {
        // if (arg0) { return 1; } return 0;
        // No phi needed because both paths return
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction failed");

        // Should have 3 blocks: entry, then, else
        assert_eq!(ssa.block_count(), 3);

        // No phi nodes should be needed (no merge point)
        assert_eq!(ssa.phi_count(), 0);
    }

    #[test]
    fn test_diamond_with_merge() {
        // if (arg0) { x = 1; } else { x = 0; } return x;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        // Should have 4 blocks: entry, then, else, merge
        assert_eq!(ssa.block_count(), 4);

        // Should have a phi node in the merge block
        // (local0 is defined in both then and else branches)
        assert!(ssa.phi_count() > 0);
    }

    #[test]
    fn test_loop_phi() {
        // i = 0; while (i < arg0) { i++; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .bge_s("loop_exit")
            .unwrap() // if (i >= arg0) exit
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap() // i++
            .br_s("loop_header")
            .unwrap()
            .label("loop_exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        // Should have multiple blocks
        assert!(ssa.block_count() >= 2);

        // Should have phi node(s) for the loop variable
        // (i is modified in the loop body and merged at the header)
    }

    #[test]
    fn test_empty_cfg_error() {
        // Create an empty CFG manually would require internal access
        // For now, test that construction succeeds with minimal valid input
        let mut asm = InstructionAssembler::new();
        asm.ret().unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let result = build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0));
        assert!(result.is_ok());
    }

    #[test]
    fn test_variable_versions_increment_correctly() {
        // Test that multiple definitions of the same local create different versions
        // local0 = 1; local0 = 2; local0 = 3; return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_0 = 1
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_1 = 2
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap() // local0_2 = 3
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction failed");

        // Collect all versions of local0
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();

        // Should have multiple versions: initial (version 0) plus 3 definitions
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0, got {}",
            local0_vars.len()
        );

        // Verify each version is unique
        let mut versions: Vec<u32> = local0_vars.iter().map(|v| v.version()).collect();
        versions.sort();
        versions.dedup();
        assert_eq!(
            versions.len(),
            local0_vars.len(),
            "Not all versions are unique"
        );
    }

    #[test]
    fn test_phi_node_operands_from_correct_predecessors() {
        // Diamond control flow: local0 defined differently in each branch
        // if (arg0) { local0 = 1; } else { local0 = 2; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            // then branch: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            // else branch: local0 = 2
            .label("else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            // merge point
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        // Find the merge block (block 3 in 0-indexed: entry=0, then=1, else=2, merge=3)
        // There should be a phi node for local0 in the merge block
        assert!(ssa.phi_count() > 0, "Expected phi nodes in merge block");

        // Get all phi nodes
        let phi_nodes: Vec<_> = ssa.all_phi_nodes().collect();
        assert!(!phi_nodes.is_empty(), "No phi nodes found");

        // Find phi node for local0
        let local0_phi = phi_nodes
            .iter()
            .find(|phi| phi.origin() == VariableOrigin::Local(0));
        assert!(
            local0_phi.is_some(),
            "No phi node found for local0 in merge block"
        );

        let phi = local0_phi.unwrap();

        // Phi should have 2 operands (one from each predecessor)
        assert_eq!(
            phi.operand_count(),
            2,
            "Phi node should have exactly 2 operands, got {}",
            phi.operand_count()
        );

        // Each operand should reference a different predecessor
        let predecessors: Vec<_> = phi.operands().iter().map(|op| op.predecessor()).collect();
        assert_ne!(
            predecessors[0], predecessors[1],
            "Phi operands should come from different predecessors"
        );
    }

    #[test]
    fn test_loop_variable_renaming() {
        // Loop with variable modified in body:
        // i = 0; while (i < 10) { i = i + 1; } return i;
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // i = 0
            .label("loop_header")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldc_i4_s(10)
            .unwrap()
            .bge_s("exit")
            .unwrap() // if i >= 10 exit
            // loop body: i = i + 1
            .ldloc_0()
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            .label("exit")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction failed");

        // Loop header should have a phi node for local0 (merges initial value and loop value)
        assert!(
            ssa.phi_count() > 0,
            "Expected phi node(s) for loop variable"
        );

        // Find phi node for local0
        let local0_phis: Vec<_> = ssa
            .all_phi_nodes()
            .filter(|phi| phi.origin() == VariableOrigin::Local(0))
            .collect();

        assert!(
            !local0_phis.is_empty(),
            "Expected phi node for loop variable local0"
        );

        // The phi in the loop header should have 2 operands:
        // one from entry block (initial value) and one from loop body (incremented value)
        for phi in &local0_phis {
            assert!(
                phi.operand_count() >= 2,
                "Loop phi should have at least 2 operands, got {}",
                phi.operand_count()
            );
        }

        // Verify we have multiple versions of local0
        let local0_versions: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_versions.len() >= 2,
            "Expected multiple versions of local0, got {}",
            local0_versions.len()
        );
    }

    #[test]
    fn test_unique_ssa_variable_ids() {
        // Test that all SSA variables have unique IDs
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .add()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ldarg_0()
            .unwrap()
            .mul()
            .unwrap()
            .stloc_0()
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(2, 1)).expect("SSA construction failed");

        // All variable IDs should be unique
        let mut ids: Vec<_> = ssa.variables().iter().map(|v| v.id().index()).collect();
        let original_len = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            original_len,
            "All SSA variable IDs should be unique"
        );
    }

    #[test]
    fn test_argument_variable_initial_version() {
        // Arguments should have version 0 at function entry
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .ldarg_1()
            .unwrap()
            .ldarg_2()
            .unwrap()
            .add()
            .unwrap()
            .add()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(3, 0)).expect("SSA construction failed");

        // Check that we have argument variables
        let arg_vars: Vec<_> = ssa.argument_variables().collect();
        assert_eq!(
            arg_vars.len(),
            3,
            "Expected 3 argument variables (version 0), got {}",
            arg_vars.len()
        );

        // All should have version 0
        for var in arg_vars {
            assert_eq!(
                var.version(),
                0,
                "Initial argument should have version 0, got {}",
                var.version()
            );
        }
    }

    #[test]
    fn test_stack_variable_across_branch() {
        // Test that stack values flowing across branches are handled correctly.
        // Valid CIL: both paths must have same stack depth at join point.
        // Pattern: if (arg0) return arg0; else return 0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap() // depth: 0→1, stack: [arg0]
            .dup()
            .unwrap() // depth: 1→2, stack: [arg0, arg0]
            .brtrue_s("has_value")
            .unwrap() // pops one, depth: 2→1, records 'has_value' expects 1
            .pop()
            .unwrap() // depth: 1→0
            .ldc_i4_0()
            .unwrap() // depth: 0→1, push replacement value
            .label("has_value")
            .unwrap() // depth: 1 (both paths)
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction failed");

        // Should succeed without error (this was failing before the stack depth fix)
        assert!(ssa.block_count() >= 2);
    }

    #[test]
    fn test_nested_conditionals_phi_placement() {
        // Nested conditionals to test phi node placement at correct join points
        // if (arg0) { if (arg1) { local0 = 1; } else { local0 = 2; } } else { local0 = 3; }
        // return local0;
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("outer_else")
            .unwrap()
            // outer then
            .ldarg_1()
            .unwrap()
            .brfalse_s("inner_else")
            .unwrap()
            // inner then: local0 = 1
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("inner_merge")
            .unwrap()
            // inner else: local0 = 2
            .label("inner_else")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("inner_merge")
            .unwrap()
            .br_s("outer_merge")
            .unwrap()
            // outer else: local0 = 3
            .label("outer_else")
            .unwrap()
            .ldc_i4_3()
            .unwrap()
            .stloc_0()
            .unwrap()
            // final merge
            .label("outer_merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(2, 1)).expect("SSA construction failed");

        // Should have phi nodes at merge points
        assert!(ssa.phi_count() >= 1, "Expected phi nodes at merge points");

        // Multiple versions of local0 should exist
        let local0_vars: Vec<_> = ssa.variables_from_local(0).collect();
        assert!(
            local0_vars.len() >= 3,
            "Expected at least 3 versions of local0 (one per definition path), got {}",
            local0_vars.len()
        );
    }

    #[test]
    fn test_argument_reassignment_creates_new_version() {
        // Test that storing to an argument creates a new version
        // starg.0 after using arg0 should create arg0_1
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap() // load arg0_0
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .starg_s(0)
            .unwrap() // arg0_1 = arg0_0 + 1
            .ldarg_0()
            .unwrap() // load arg0_1
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction failed");

        // Should have multiple versions of arg0
        let arg0_vars: Vec<_> = ssa.variables_from_argument(0).collect();
        assert!(
            arg0_vars.len() >= 2,
            "Expected at least 2 versions of arg0, got {}",
            arg0_vars.len()
        );

        // Should have version 0 and version 1
        let versions: Vec<u32> = arg0_vars.iter().map(|v| v.version()).collect();
        assert!(versions.contains(&0), "Expected version 0 of arg0 to exist");
    }

    #[test]
    fn test_phi_operands_reference_existing_variables() {
        // Verify that phi node operands reference variables that actually exist
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .stloc_0()
            .unwrap()
            .br_s("merge")
            .unwrap()
            .label("else")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap()
            .label("merge")
            .unwrap()
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 1)).expect("SSA construction failed");

        // For each phi node, verify all operand values reference valid variables
        let var_ids: BTreeSet<_> = ssa.variables().iter().map(|v| v.id()).collect();

        for phi in ssa.all_phi_nodes() {
            for operand in phi.operands() {
                assert!(
                    var_ids.contains(&operand.value()),
                    "Phi operand references non-existent variable {}",
                    operand.value()
                );
            }
        }
    }

    #[test]
    fn test_def_site_correctness() {
        // Verify that def_site accurately reflects where variables are defined
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .stloc_0()
            .unwrap() // local0 defined in block 0
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 1)).expect("SSA construction failed");

        // Find the non-initial version of local0 (the one from stloc)
        let local0_defs: Vec<_> = ssa
            .variables_from_local(0)
            .filter(|v| !v.def_site().is_phi()) // Skip phi/entry definitions
            .collect();

        // At least one should be defined by an instruction (not phi)
        for var in local0_defs {
            assert!(
                var.def_site().instruction.is_some(),
                "Non-phi variable should have instruction def site"
            );
            // def_site block should be valid
            assert!(
                var.def_site().block < ssa.block_count(),
                "Def site block out of range"
            );
        }
    }

    #[test]
    fn test_stack_value_at_merge_from_different_predecessors() {
        // Test: value pushed onto stack in different branches, used after merge
        //
        // Block 0: ldarg.0; brfalse block2
        // Block 1: ldc.i4.1; br block3  (pushes 1 onto stack)
        // Block 2: ldc.i4.2; br block3  (pushes 2 onto stack)
        // Block 3: ret                   (uses value from stack - should have phi)
        //
        // At block 3, the value on the stack should be a phi of:
        //   - 1 from block 1
        //   - 2 from block 2
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .brfalse_s("else_branch")
            .unwrap()
            // then branch: push 1
            .ldc_i4_1()
            .unwrap()
            .br_s("merge")
            .unwrap()
            // else branch: push 2
            .label("else_branch")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            // merge point
            .label("merge")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction failed");

        // Find the merge block (should be the last block)
        let merge_block_idx = ssa.block_count() - 1;
        let merge_block = ssa
            .block(merge_block_idx)
            .expect("Merge block should exist");

        // At a merge point with stack values from different predecessors,
        // there should be a PHI node for the stack position.
        // Without stack PHIs, the return would incorrectly use just one branch's value.
        assert!(
            merge_block.phi_count() > 0,
            "Merge block should have a PHI node for the stack value (different values from each predecessor)"
        );

        // The return should use the PHI result, not a value from just one predecessor
        let ret_instr = merge_block
            .instructions()
            .last()
            .expect("Merge block should have ret");

        if let SsaOp::Return {
            value: Some(ret_var),
        } = ret_instr.op()
        {
            // The return value should come from a PHI (def_site.instruction should be None)
            if let Some(var_info) = ssa.variable(*ret_var) {
                assert!(
                    var_info.def_site().instruction.is_none(),
                    "Return value {:?} should be from a PHI (stack merge), not a single predecessor",
                    ret_var
                );
            }
        }
    }

    #[test]
    fn test_stack_value_cff_pattern() {
        // Test: CFF-like pattern where constant is pushed and used via switch
        //
        // Block 0: ldc.i4 0x12345678; br block1 (push constant, jump to dispatcher)
        // Block 1: ldc.i4 5; rem.un; switch [block2, block3]
        // Block 2: ret
        // Block 3: ret
        //
        // At block 1, the value on stack (from block 0) should be traceable
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // dispatcher
            .label("dispatcher")
            .unwrap()
            .ldc_i4_5()
            .unwrap()
            .rem_un()
            .unwrap()
            .switch(&["case0", "case1"])
            .unwrap()
            // default case
            .ret()
            .unwrap()
            // case 0
            .label("case0")
            .unwrap()
            .ret()
            .unwrap()
            // case 1
            .label("case1")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");

        // The dispatcher block should use the constant from block 0 in rem.un
        // Find the rem.un instruction
        let mut rem_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Rem { left, .. } = instr.op() {
                    rem_found = true;
                    // The left operand should be traceable to the constant
                    let left_info = ssa.variable(*left);
                    assert!(
                        left_info.is_some(),
                        "rem.un operand {:?} should be in variable table (stack value from predecessor not tracked)",
                        left
                    );
                }
            }
        }
        assert!(rem_found, "rem.un instruction should exist in SSA");
    }

    #[test]
    fn test_stack_value_with_back_edge() {
        // Test: loop with value on stack at merge
        //
        // Block 0: ldc.i4.0; br block1
        // Block 1: dup; ldc.i4 10; blt block2  (loop back if < 10)
        //          br block3
        // Block 2: ldc.i4.1; add; br block1 (increment and loop back)
        // Block 3: ret
        //
        // At block 1, the stack value should be a phi of:
        //   - 0 from block 0 (initial)
        //   - incremented value from block 2
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4_0()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            // loop header
            .label("loop_header")
            .unwrap()
            .dup()
            .unwrap()
            .ldc_i4(10)
            .unwrap()
            .blt_s("loop_body")
            .unwrap()
            .br_s("exit")
            .unwrap()
            // loop body
            .label("loop_body")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .br_s("loop_header")
            .unwrap()
            // exit
            .label("exit")
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");

        // Find the add instruction and check its operands
        let mut add_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Add { left, .. } = instr.op() {
                    add_found = true;
                    // Both operands should be in the variable table
                    assert!(
                        ssa.variable(*left).is_some(),
                        "Add left operand {:?} should be trackable",
                        left
                    );
                }
            }
        }
        assert!(add_found, "Add instruction should exist in SSA");
    }

    #[test]
    fn test_switch_all_targets_reachable() {
        // Test that switch targets are properly represented in SSA
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()
            .unwrap()
            .switch(&["case0", "case1", "case2"])
            .unwrap()
            // default case
            .ldc_i4_m1()
            .unwrap()
            .ret()
            .unwrap()
            // case 0
            .label("case0")
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap()
            // case 1
            .label("case1")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .ret()
            .unwrap()
            // case 2
            .label("case2")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0)).expect("SSA construction failed");

        // Find the switch instruction
        let mut switch_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Switch {
                    targets, default, ..
                } = instr.op()
                {
                    switch_found = true;
                    assert_eq!(targets.len(), 3, "Switch should have 3 targets");
                    // All targets and default should be valid block indices
                    for &target in targets {
                        assert!(
                            target < ssa.block_count(),
                            "Switch target {} out of range",
                            target
                        );
                    }
                    assert!(
                        *default < ssa.block_count(),
                        "Switch default {} out of range",
                        default
                    );
                }
            }
        }
        assert!(switch_found, "Switch instruction should exist in SSA");
    }

    #[test]
    fn test_stack_phi_for_overestimated_entry_depth() {
        // Test: Entry depth computed by static analysis may exceed actual predecessor
        // exit_stack lengths. This can happen when:
        // 1. Fixed-point iteration includes back-edge contributions
        // 2. Static stack_behavior doesn't match actual simulation
        //
        // The fix ensures PHIs are created for all entry_stack slots, even if
        // no predecessor has values at those positions.
        //
        // Pattern: Loop with switch where case blocks have varying stack effects
        //
        // Block 0: push value onto stack, jump to dispatcher
        // Block 1 (dispatcher): use stack value, switch to cases
        // Block 2 (case): push new value and loop back
        // Block 3 (exit): pop and ret
        //
        // This tests that all stack operands are properly registered in variable table.
        let mut asm = InstructionAssembler::new();

        // Block 0: Push initial value
        asm.ldc_i4(0x1000)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Block 1 (dispatcher): Use stack value
            .label("dispatcher")
            .unwrap()
            .ldc_i4(0xFF)
            .unwrap()
            .xor()
            .unwrap()
            .dup()
            .unwrap()
            .ldc_i4(3)
            .unwrap()
            .rem_un()
            .unwrap()
            .switch(&["case0", "exit"])
            .unwrap()
            .br_s("exit")
            .unwrap()
            // Block 2 (case0): Modify and loop back
            .label("case0")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Block 3 (exit): Clean up and return
            .label("exit")
            .unwrap()
            .pop()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");

        // Verify ALL instruction operands are in the variable table
        // This catches any case where simulation variables aren't properly renamed
        for (block_idx, block) in ssa.blocks().iter().enumerate() {
            for (instr_idx, instr) in block.instructions().iter().enumerate() {
                for use_var in instr.uses().iter() {
                    assert!(
                        ssa.variable(*use_var).is_some(),
                        "Block {} instr {} ({:?}): use {:?} not in variable table",
                        block_idx,
                        instr_idx,
                        format!("{:?}", instr.op())
                            .chars()
                            .take(30)
                            .collect::<String>(),
                        use_var
                    );
                }
                if let Some(def_var) = instr.def() {
                    assert!(
                        ssa.variable(def_var).is_some(),
                        "Block {} instr {} ({:?}): def {:?} not in variable table",
                        block_idx,
                        instr_idx,
                        format!("{:?}", instr.op())
                            .chars()
                            .take(30)
                            .collect::<String>(),
                        def_var
                    );
                }
            }
            // Also check PHI operands
            for (phi_idx, phi) in block.phi_nodes().iter().enumerate() {
                for operand in phi.operands() {
                    assert!(
                        ssa.variable(operand.value()).is_some(),
                        "Block {} phi {}: operand {:?} not in variable table",
                        block_idx,
                        phi_idx,
                        operand.value()
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_ssa_variables_registered() {
        // Comprehensive test: verify that ALL variables used in the SSA are registered
        // in the variable table. This catches any edge case where simulation variables
        // escape into the final SSA without being properly renamed.
        //
        // Uses a complex control flow pattern similar to ConfuserEx CFF.
        let mut asm = InstructionAssembler::new();

        // Setup: push initial state onto stack and jump to dispatcher
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Dispatcher: compute next state and switch
            // Stack at entry: [state]
            .label("dispatcher")
            .unwrap()
            .ldc_i4(0xDEADBEEF_u32 as i32)
            .unwrap()
            .xor() // [new_state]
            .unwrap()
            .dup() // [new_state, new_state]
            .unwrap()
            .ldc_i4(4)
            .unwrap()
            .rem_un() // [new_state, index]
            .unwrap()
            .switch(&["case0", "case1", "case2"])
            .unwrap()
            // default: exit (stack: [new_state])
            .br_s("exit")
            .unwrap()
            // Case 0: stack at entry: [new_state]
            .label("case0")
            .unwrap()
            .ldc_i4_1()
            .unwrap()
            .add() // [new_state + 1]
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Case 1
            .label("case1")
            .unwrap()
            .ldc_i4_2()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Case 2
            .label("case2")
            .unwrap()
            .ldc_i4_3()
            .unwrap()
            .add()
            .unwrap()
            .br_s("dispatcher")
            .unwrap()
            // Exit: stack: [new_state]
            .label("exit")
            .unwrap()
            .pop()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");

        // Collect all variables used in the SSA
        let mut all_uses = BTreeSet::new();
        let mut all_defs = BTreeSet::new();

        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    all_uses.insert(*use_var);
                }
                if let Some(def_var) = instr.def() {
                    all_defs.insert(def_var);
                }
            }
            for phi in block.phi_nodes() {
                all_defs.insert(phi.result());
                for operand in phi.operands() {
                    all_uses.insert(operand.value());
                }
            }
        }

        // Verify all uses are in variable table
        for use_var in &all_uses {
            assert!(
                ssa.variable(*use_var).is_some(),
                "Use {:?} not in variable table - this indicates a simulation variable escaped renaming",
                use_var
            );
        }

        // Verify all defs are in variable table
        for def_var in &all_defs {
            assert!(
                ssa.variable(*def_var).is_some(),
                "Def {:?} not in variable table - this indicates incomplete variable registration",
                def_var
            );
        }
    }

    #[test]
    fn test_br_s_zero_offset_pattern() {
        // Test: Anti-disassembly pattern where br.s +0 creates an unnecessary block boundary
        //
        // This pattern is used by ConfuserEx's constants protection:
        //   ldc.i4 <encrypted_const>
        //   br.s   next_instruction  <-- Creates a new block
        //   call   Decryptor
        //
        // The value pushed by ldc.i4 must flow through the br.s to the call
        // in the next block, even though there's only one predecessor (no phi nodes).
        //
        // Block 0: ldc.i4 0x12345678; br.s next
        // Block 1: call (that takes 1 arg); ret
        //
        // At Block 1, the argument to call must be the constant from Block 0.
        let mut asm = InstructionAssembler::new();
        asm.ldc_i4(0x12345678)
            .unwrap()
            .br_s("after_br")
            .unwrap()
            // This label creates a new block, simulating the effect of br.s +0
            .label("after_br")
            .unwrap()
            // In real code this would be a call, but we simulate with pop + ldc + ret
            // to avoid needing assembly references
            .pop()
            .unwrap()
            .ldc_i4_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 0)).expect("SSA construction failed");

        // Find the pop instruction and verify its operand is registered
        let mut pop_found = false;
        for block in ssa.blocks() {
            for instr in block.instructions() {
                if let SsaOp::Pop { value } = instr.op() {
                    pop_found = true;
                    // The pop should use the constant from the previous block
                    let var_info = ssa.variable(*value);
                    assert!(
                        var_info.is_some(),
                        "Pop operand {:?} not in variable table - \
                         single-predecessor stack value not properly propagated",
                        value
                    );
                }
            }
        }
        assert!(pop_found, "Pop instruction should exist in SSA");

        // Also verify ALL uses are registered (comprehensive check)
        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    assert!(
                        ssa.variable(*use_var).is_some(),
                        "Use {:?} not in variable table - stack value not propagated across br.s",
                        use_var
                    );
                }
            }
        }
    }

    #[test]
    fn test_multiple_br_s_zero_offset_pattern() {
        // Test: Multiple anti-disassembly patterns in sequence
        //
        // This matches ConfuserEx's pattern more closely:
        //   ldc.i4 <encrypted1>; br.s next1; next1: pop; stloc.0
        //   ldc.i4 <encrypted2>; br.s next2; next2: pop; stloc.1
        //
        // Each br.s creates a new block, and the constant must flow through.
        let mut asm = InstructionAssembler::new();

        // First pattern: push constant, br.s, pop+store to local 0
        asm.ldc_i4(0x11111111)
            .unwrap()
            .br_s("next1")
            .unwrap()
            .label("next1")
            .unwrap()
            .stloc_0()
            .unwrap()
            // Second pattern: push constant, br.s, pop+store to local 1
            .ldc_i4(0x22222222)
            .unwrap()
            .br_s("next2")
            .unwrap()
            .label("next2")
            .unwrap()
            .stloc_1()
            .unwrap()
            // Third pattern: push constant, br.s, pop+store to local 2
            .ldc_i4(0x33333333)
            .unwrap()
            .br_s("next3")
            .unwrap()
            .label("next3")
            .unwrap()
            .stloc_2()
            .unwrap()
            // Return something
            .ldloc_0()
            .unwrap()
            .ret()
            .unwrap();

        let (_, cfg) = build_cfg(asm).expect("assembles and decodes");
        let ssa =
            build_ssa(&cfg, &TestTypeProvider::all_i32(0, 3)).expect("SSA construction failed");

        // Verify ALL uses are registered
        let mut unregistered = vec![];
        for block in ssa.blocks() {
            for instr in block.instructions() {
                for use_var in instr.uses().iter() {
                    if ssa.variable(*use_var).is_none() {
                        unregistered.push(*use_var);
                    }
                }
            }
        }
        assert!(
            unregistered.is_empty(),
            "Unregistered uses: {:?} - stack values not propagated across br.s",
            unregistered
        );
    }
}
