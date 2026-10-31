//! Static Single Assignment (SSA) form for CIL methods.
//!
//! This module provides SSA transformation for .NET CIL bytecode, converting
//! stack-based operations into an explicit variable form where each variable
//! is assigned exactly once. This representation enables powerful optimizations
//! and analyses like constant propagation, dead code elimination, and type inference.
//!
//! # Architecture
//!
//! The SSA primitives ([`SsaVarId`], [`PhiNode`], [`SsaBlock`],
//! [`SsaFunction`], [`SsaOp`]) and analyses ([`SsaCfg`], [`PhiAnalyzer`],
//! [`SsaEvaluator`], …) live in `analyssa::ir` / `analyssa::analysis`. The
//! files in this directory are CIL-side boundary code:
//!
//! - [`builder`] - SSA construction driver (Cytron et al.) for CIL
//! - [`converter`] - CIL → SSA conversion
//! - [`decompose`] - CIL instruction decomposition into SSA ops
//! - [`stack`] - CIL stack-typing simulator
//! - [`types`] - CIL type system (`SsaType`, `TypeRef`, `MethodRef`, …)
//! - [`target`] - `CilTarget` impl of `analyssa::Target`
//! - [`exception`] - CIL exception handler bridge
//! - [`value`], [`ops`] - CIL extension impls on `analyssa::ConstValue` / `analyssa::SsaOp`
//! - [`function`] - CIL-pinned `SsaFunctionCilExt`/`Semantics` extensions
//! - [`resolver`] - CIL-side value resolver for inline values
//!
//! # CIL to SSA Transformation
//!
//! CIL is a stack-based instruction set, while SSA uses explicit variables.
//! The transformation involves several phases:
//!
//! 1. **Stack Simulation**: Convert implicit stack operations to explicit variables
//! 2. **Phi Placement**: Insert phi nodes at dominance frontiers
//! 3. **Variable Renaming**: Assign unique versions using dominator tree traversal
//!
//! ## Variable Origins
//!
//! SSA variables can originate from several sources:
//!
//! - **Arguments**: Method parameters (`ldarg`, `starg`)
//! - **Locals**: Local variables (`ldloc`, `stloc`)
//! - **Stack slots**: Temporary values from stack operations
//! - **Phi nodes**: Merged values at control flow joins
//!
//! ## Address-Taking Considerations
//!
//! Variables whose address is taken (`ldarga`, `ldloca`) require special handling
//! as they may be modified through pointers. These are tracked separately and
//! may be excluded from full SSA optimization.
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
//! let ssa = SsaConverter::build(&cfg, num_args, num_locals, resolver, Vec::new())?;
//!
//! // Analyze phi nodes at merge points
//! for block in ssa.blocks() {
//!     for phi in block.phi_nodes() {
//!         println!("Phi: {:?} = phi({:?})", phi.result(), phi.operands());
//!     }
//! }
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # References
//!
//! - Cytron et al., "Efficiently Computing Static Single Assignment Form and the
//!   Control Dependence Graph", ACM TOPLAS 1991
//! - Cooper & Torczon, "Engineering a Compiler", Chapter 9

// CIL-bound boundary code stays in dotscope (CIL → SSA conversion, stack
// typing, codegen extensions on analyssa types).
mod builder;
mod converter;
mod decompose;
mod exception;
mod facts;
mod function;
mod ops;
mod resolver;
mod stack;
mod symbolic;
mod target;
mod types;
mod value;

// Generic SSA primitives + analyses live in analyssa. The thin re-export
// shims that used to mediate via `mod cfg/consts/phi/...` collapsed into
// the `pub use` block below.

// `SsaFunction`/`ReturnInfo`/`MethodPurity` live in `analyssa::ir::function`.
pub use analyssa::ir::{
    function::{AddressTakenSlots, MethodPurity},
    instruction::InstrId,
    FloatBits, FloatFormat,
};
pub use builder::SsaFunctionBuilder;
pub use converter::SsaConverter;
pub use exception::{
    BlockRange, ClauseLayout, ClausePart, ExceptionBlocks, ExceptionTableError, HandlerKind,
    LaidOutHandler, SsaExceptionHandler, SsaExceptionHandlerCilExt,
};
pub use facts::CilVariableFacts;
pub use function::{SsaFunctionCilExt, SsaFunctionSemanticsExt};
pub use ops::{
    BinaryOpKind, BreakpointOp, CmpKind, RuntimeValueKind, SsaOp, SsaOpCilExt, UnaryOpKind,
};
/// CIL-defaulted alias of [`analyssa::ir::function::SsaFunction`].
pub type SsaFunction<T = CilTarget> = analyssa::ir::function::SsaFunction<T>;
/// CIL-defaulted alias of [`analyssa::ir::function::ReturnInfo`].
pub type ReturnInfo<T = CilTarget> = analyssa::ir::function::ReturnInfo<T>;
pub use analyssa::{
    analysis::{
        address,
        consts::evaluate_const_op,
        evaluator::ControlFlow,
        memory::{AliasResult, ArrayIndex, IndirectLocation, MemoryDefSite, MemoryPhiOperand},
        phis::PhiAnalyzer,
        pointsto,
    },
    ir::{
        phi::{PhiNode, PhiOperand},
        variable::{DefSite, FunctionVarAllocator, SsaVarId, UseSite, VariableOrigin},
    },
    Target,
};
pub use resolver::ValueResolver;
pub use stack::{SimulationResult, StackSimulator};
#[cfg(feature = "z3")]
pub use symbolic::Z3Solver;
pub use symbolic::{SymbolicEvaluator, SymbolicExpr, SymbolicOp};
pub use target::CilTarget;
pub use types::{
    resolve_corelib_valuetype, FieldRef, MethodRef, SsaType, TypeClass, TypeContext, TypeProvider,
    TypeRef,
};
pub use value::{AbstractValue, ConstValue, ConstValueCilExt};

/// CIL-defaulted alias of [`analyssa::ir::block::SsaBlock`].
pub type SsaBlock<T = CilTarget> = analyssa::ir::block::SsaBlock<T>;
/// CIL-defaulted alias of [`analyssa::ir::instruction::SsaInstruction`].
pub type SsaInstruction<T = CilTarget> = analyssa::ir::instruction::SsaInstruction<T>;
/// CIL-defaulted alias of [`analyssa::ir::variable::SsaVariable`].
pub type SsaVariable<T = CilTarget> = analyssa::ir::variable::SsaVariable<T>;
/// CIL-defaulted alias of [`analyssa::analysis::SsaCfg`].
pub type SsaCfg<'a, T = CilTarget> = analyssa::analysis::cfg::SsaCfg<'a, T>;
/// CIL-defaulted alias of [`analyssa::analysis::consts::ConstEvaluator`].
pub type ConstEvaluator<'a, T = CilTarget> = analyssa::analysis::consts::ConstEvaluator<'a, T>;
/// CIL-defaulted alias of [`analyssa::analysis::evaluator::SsaEvaluator`].
pub type SsaEvaluator<'a, T = CilTarget> = analyssa::analysis::evaluator::SsaEvaluator<'a, T>;
/// CIL-defaulted alias of [`analyssa::analysis::evaluator::EvaluatorMark`].
pub type EvaluatorMark<T = CilTarget> = analyssa::analysis::evaluator::EvaluatorMark<T>;
/// CIL-defaulted alias of [`analyssa::analysis::evaluator::ExecutionTrace`].
pub type ExecutionTrace<T = CilTarget> = analyssa::analysis::evaluator::ExecutionTrace<T>;
/// CIL-defaulted alias of [`analyssa::analysis::patterns::PatternDetector`].
pub type PatternDetector<'a, T = CilTarget> = analyssa::analysis::patterns::PatternDetector<'a, T>;
/// CIL-defaulted alias of [`analyssa::analysis::patterns::DispatcherPattern`].
pub type DispatcherPattern<T = CilTarget> = analyssa::analysis::patterns::DispatcherPattern<T>;
/// CIL-defaulted alias of [`analyssa::analysis::patterns::SourceBlock`].
pub type SourceBlock<T = CilTarget> = analyssa::analysis::patterns::SourceBlock<T>;
/// CIL-defaulted alias of [`analyssa::analysis::patterns::OpaquePredicatePattern`].
pub type OpaquePredicatePattern<T = CilTarget> =
    analyssa::analysis::patterns::OpaquePredicatePattern<T>;
/// CIL-defaulted alias of [`analyssa::analysis::patterns::PredicateResolution`].
pub type PredicateResolution<T = CilTarget> = analyssa::analysis::patterns::PredicateResolution<T>;
/// CIL-defaulted alias of [`analyssa::analysis::constraints::Constraint`].
pub type Constraint<T = CilTarget> = analyssa::analysis::constraints::Constraint<T>;
/// CIL-defaulted alias of [`analyssa::analysis::constraints::PathConstraint`].
pub type PathConstraint<T = CilTarget> = analyssa::analysis::constraints::PathConstraint<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemoryLocation`].
pub type MemoryLocation<T = CilTarget> = analyssa::analysis::memory::MemoryLocation<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemoryOp`].
pub type MemoryOp<T = CilTarget> = analyssa::analysis::memory::MemoryOp<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemoryPhi`].
pub type MemoryPhi<T = CilTarget> = analyssa::analysis::memory::MemoryPhi<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemoryVersion`].
pub type MemoryVersion<T = CilTarget> = analyssa::analysis::memory::MemoryVersion<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemorySsa`].
pub type MemorySsa<T = CilTarget> = analyssa::analysis::memory::MemorySsa<T>;
/// CIL-defaulted alias of [`analyssa::analysis::memory::MemorySsaStats`].
pub type MemorySsaStats = analyssa::analysis::memory::MemorySsaStats;
/// CIL-defaulted alias of [`analyssa::analysis::verifier::SsaVerifier`].
pub type SsaVerifier<'a, T = CilTarget> = analyssa::analysis::verifier::SsaVerifier<'a, T>;
/// Re-export of [`analyssa::analysis::verifier::VerifierError`]: what the
/// verifier reports, and what a caller checking its own lift reads.
pub use analyssa::analysis::verifier::VerifierError;
/// Re-export of [`analyssa::analysis::verifier::VerifyLevel`], which the
/// verifier takes and which has nothing CIL-specific about it.
pub use analyssa::analysis::verifier::VerifyLevel;
