//! Symbolic execution and constraint solving using Z3.
//!
//! This module provides symbolic execution capabilities for SSA analysis,
//! powered by the Z3 SMT solver. It enables:
//!
//! - Building symbolic expressions from SSA operations
//! - Solving constraints to find values that satisfy conditions
//! - Enumerating all solutions within a range
//! - Control flow unflattening by inverting state encodings
//!
//! # Architecture
//!
//! The module uses [`SymbolicExpr`] as an intermediate representation that
//! maps directly to SSA operations. When solving is needed, expressions are
//! translated to Z3's AST and solved using Z3's powerful SMT solver.
//!
//! ```text
//! SSA Operations → SymbolicExpr (our IR) → Z3 AST → Z3 Solver → Solutions
//! ```
//!
//! # Module Structure
//!
//! The target-agnostic IR + evaluator now live in `analyssa::analysis::symbolic`:
//!
//! - [`NumericOp`] - Symbolic operation kinds (add, xor, comparison, etc.) — `analyssa::analysis::symbolic::ops`
//! - [`SymbolicExpr`] - Symbolic expression tree — `analyssa::analysis::symbolic::expr`
//! - [`SymbolicEvaluator`] - Builds expressions from SSA operations — `analyssa::analysis::symbolic::evaluator`
//!
//! The Z3 binding stays in dotscope under the `z3` Cargo feature (analyssa
//! intentionally avoids the Z3 dependency):
//!
//! - [`Z3Solver`] - Z3-based constraint solver (this crate, gated on `z3`)
//!
//! # Use Cases
//!
//! ## Control Flow Unflattening
//!
//! The primary use case is inverting state encodings used by control flow
//! flattening obfuscators like ConfuserEx. These obfuscators use a pattern:
//!
//! ```text
//! switch_idx = f(state)  // e.g., (state XOR C1) % N
//! switch (switch_idx) {
//!     case 0: ...; state = g0(state); break;
//!     case 1: ...; state = g1(state); break;
//!     ...
//! }
//! ```
//!
//! Given `f(state)` as a symbolic expression and a target case index, we use
//! Z3 to solve for all state values that reach that case:
//!
//! ```text
//! solve: f(state) == target_case
//! ```
//!
//! ## Constraint Satisfaction
//!
//! More generally, the module can solve arbitrary constraints involving
//! bitvector arithmetic (32-bit):
//!
//! - Arithmetic: add, sub, mul, div, rem
//! - Bitwise: and, or, xor, not, shl, shr
//! - Comparisons: eq, ne, lt, gt, le, ge (signed and unsigned)
//!
//! # Example
//!
//! ```
//! use dotscope::analysis::{SymbolicExpr, NumericOp, Z3Solver};
//!
//! // Build expression: (state XOR 0x12345678) % 13
//! let state = SymbolicExpr::named("state");
//! let xored = SymbolicExpr::binary(NumericOp::Xor, state, SymbolicExpr::constant_i32(0x12345678));
//! let result = SymbolicExpr::binary(NumericOp::RemU, xored, SymbolicExpr::constant_i32(13));
//!
//! // Use Z3 to find all states that produce case index 5
//! let solver = Z3Solver::new();
//! let solutions = solver.solve_for_value(&result, "state", 5, 100);
//!
//! // Build mapping: case_index -> [state values that reach it]
//! let mapping = solver.build_case_mapping(&result, "state", 13, 10);
//! ```
//!
//! # Performance Considerations
//!
//! Z3 context creation has some overhead. For repeated solving, create a single
//! [`Z3Solver`] and reuse it. The solver uses 32-bit bitvectors (`BV(32)`) for
//! all computations, matching CIL's `int32` semantics.

// `SymbolicEvaluator`, `SymbolicExpr`, `NumericOp` live in
// `analyssa::analysis::symbolic`. The Z3 binding stays here behind the `z3`
// feature flag — Z3 is a dotscope-side dependency that analyssa intentionally
// doesn't take.
pub use analyssa::{
    analysis::symbolic::{SymbolicEvaluator, SymbolicExpr},
    ir::evaluation::NumericOp,
};

#[cfg(feature = "z3")]
mod solver;
#[cfg(feature = "z3")]
pub use solver::Z3Solver;
