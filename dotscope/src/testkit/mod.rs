//! Test support shared by dotscope's unit and integration tests.
//!
//! Unit tests reach it as `crate::testkit`; integration tests as `dotscope::testkit`, through
//! the `testkit` feature the crate's own dev-dependency on itself turns on. Cargo unifies that
//! dev-dependency with the crate under test, so both see one crate instance and its types. It
//! is unstable and outside the semver surface.
//!
//! - [`builders`]: fluent builders for metadata objects (types, methods, references).
//! - [`factories`]: assemblies and rows crafted for validator and table tests.
//! - [`fixtures`]: the committed samples under `tests/samples`, resolved and checked against
//!   their manifest.
//! - [`helpers`]: sample loading and small utilities.
//! - [`framework`]: the obfuscator sample harness (deobfuscate, verify, summarize).
//! - [`verification`]: SSA-based semantic comparison of original and deobfuscated assemblies.
//! - [`compatibility`]: load and compare whole runtime corpora (Mono, .NET).
//! - [`corpus`]: checks swept over every assembly the fixture manifest lists.
//! - [`dump`]: an assembly's canonical dump, for comparing what two assemblies hold.
//! - [`equivalence`]: whether generated code computes what the SSA it came from computes.
//! - [`passes`]: running a pass in a test the way the scheduler does, verified.
//! - [`analysis`], [`mono`]: analysis and runtime harnesses.
//! - [`tools`]: which external tools a test may go without, and running them with a timeout.
//! - [`TestTypeProvider`] with [`build_cfg`], [`build_ssa`] and [`build_ssa_with_handlers`]:
//!   SSA from assembled CIL.

// Test support panics on what it cannot set up and indexes what it built itself.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]

pub mod analysis;
pub mod arb;
pub mod builders;
pub mod compatibility;
pub mod corpus;
mod crafted2;
pub mod dump;
#[cfg(feature = "emulation")]
pub mod emulation;
#[cfg(feature = "compiler")]
pub mod equivalence;
pub mod factories;
pub mod fixtures;
#[cfg(feature = "deobfuscation")]
pub mod framework;
#[cfg(feature = "deobfuscation")]
pub mod fuzz;
pub mod helpers;
pub mod mono;
pub mod oracle;
#[cfg(feature = "compiler")]
pub mod passes;
pub mod tools;
mod validator;
pub mod verification;
mod windowsbase;

pub use builders::*;
pub use crafted2::*;
pub use fixtures::{fixture, fixture_bytes};
#[cfg(feature = "deobfuscation")]
pub use framework::{deobfuscated, engine, engine_with, without_wall_clock, DeobOutcome};
pub use helpers::*;
pub use validator::*;
pub use windowsbase::*;

use crate::{
    analysis::{ControlFlowGraph, SsaConverter, SsaFunction, SsaType, TypeProvider},
    assembly::{decode_blocks, decode_blocks_with_handlers, InstructionAssembler},
    metadata::{
        method::{ExceptionHandler, Method},
        signatures::SignatureLocalVariable,
        token::Token,
    },
    CilObject, Result,
};

/// The types a test declares for the arguments and locals of synthetic CIL.
///
/// Converter tests build SSA from assembled CIL with no metadata behind it, so the test states
/// each slot's type: [`TestTypeProvider::all_i32`] when every slot holds a 32-bit integer, or
/// [`TestTypeProvider::typed`] slot by slot, with [`TestTypeProvider::arg`] and
/// [`TestTypeProvider::local`] to change one. A slot past the declared ones is `Unknown`.
/// Calls, indirect calls and fields are typed `I32` and `newobj` results `Object`: a test that
/// needs other types for them uses a real assembly.
pub struct TestTypeProvider {
    args: Vec<SsaType>,
    locals: Vec<SsaType>,
    /// Whether the body sets `.locals init`.
    locals_init: bool,
}

impl TestTypeProvider {
    /// Every argument and local an `I32`: for code that keeps only 32-bit integers in its
    /// slots.
    #[must_use]
    pub fn all_i32(num_args: usize, num_locals: usize) -> Self {
        Self::typed(vec![SsaType::I32; num_args], vec![SsaType::I32; num_locals])
    }

    /// Arguments and locals of these types, in slot order.
    #[must_use]
    pub fn typed(
        args: impl IntoIterator<Item = SsaType>,
        locals: impl IntoIterator<Item = SsaType>,
    ) -> Self {
        Self {
            args: args.into_iter().collect(),
            locals: locals.into_iter().collect(),
            locals_init: true,
        }
    }

    /// Declares argument `idx` with `ty`.
    ///
    /// # Panics
    ///
    /// When `idx` is not one of the declared arguments.
    #[must_use]
    pub fn arg(mut self, idx: u16, ty: SsaType) -> Self {
        let count = self.args.len();
        *self
            .args
            .get_mut(usize::from(idx))
            .unwrap_or_else(|| panic!("argument {idx} of {count}")) = ty;
        self
    }

    /// Declares local `idx` with `ty`.
    ///
    /// # Panics
    ///
    /// When `idx` is not one of the declared locals.
    #[must_use]
    pub fn local(mut self, idx: u16, ty: SsaType) -> Self {
        let count = self.locals.len();
        *self
            .locals
            .get_mut(usize::from(idx))
            .unwrap_or_else(|| panic!("local {idx} of {count}")) = ty;
        self
    }

    /// Declares a body without `.locals init`.
    #[must_use]
    pub fn without_locals_init(mut self) -> Self {
        self.locals_init = false;
        self
    }

    /// How many arguments are declared.
    #[must_use]
    pub fn num_args(&self) -> usize {
        self.args.len()
    }

    /// How many locals are declared.
    #[must_use]
    pub fn num_locals(&self) -> usize {
        self.locals.len()
    }
}

impl TypeProvider for TestTypeProvider {
    fn arg_type(&self, idx: u16) -> SsaType {
        self.args
            .get(usize::from(idx))
            .cloned()
            .unwrap_or(SsaType::Unknown)
    }

    fn local_type(&self, idx: u16) -> SsaType {
        self.locals
            .get(usize::from(idx))
            .cloned()
            .unwrap_or(SsaType::Unknown)
    }

    fn call_return_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn newobj_type(&self, _: Token) -> SsaType {
        SsaType::Object
    }

    fn field_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn call_indirect_return_type(&self, _: Token) -> SsaType {
        SsaType::I32
    }

    fn assembly(&self) -> Option<&CilObject> {
        None
    }

    fn local_type_signatures(&self) -> Option<Vec<SignatureLocalVariable>> {
        None
    }

    fn locals_zero_initialized(&self) -> bool {
        self.locals_init
    }
}

/// Build a control flow graph (and raw bytecode) from assembled CIL.
///
/// Returns both the bytecode vector and the CFG so callers that need
/// the original bytes for round-trip verification can keep them.
pub fn build_cfg(assembler: InstructionAssembler) -> Result<(Vec<u8>, ControlFlowGraph<'static>)> {
    let (bytecode, _max_stack, _) = assembler.finish()?;
    let blocks = decode_blocks(&bytecode, 0, 0x1000, Some(bytecode.len()))?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    Ok((bytecode, cfg))
}

/// Build SSA form from a control flow graph, its slots typed by `types`.
pub fn build_ssa(cfg: &ControlFlowGraph<'_>, types: &TestTypeProvider) -> Result<SsaFunction> {
    SsaConverter::build(cfg, types.num_args(), types.num_locals(), types, Vec::new())
}

/// Build SSA from assembled CIL with exception clauses, the way a method body
/// is: decoded from each handler entry as well as the first instruction, with
/// the clauses mapped onto the blocks and handed to construction.
pub fn build_ssa_with_handlers(
    bytecode: &[u8],
    clauses: &[ExceptionHandler],
    types: &TestTypeProvider,
) -> Result<SsaFunction> {
    let blocks = decode_blocks_with_handlers(bytecode, 0, 0x1000, Some(bytecode.len()), clauses)?;
    let handlers = Method::ssa_handlers_for_clauses(clauses, &blocks)?;
    let cfg = ControlFlowGraph::from_basic_blocks(blocks)?;
    SsaConverter::build(&cfg, types.num_args(), types.num_locals(), types, handlers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::VariableOrigin;

    #[test]
    fn a_declared_argument_type_reaches_ssa() -> Result<()> {
        let mut asm = InstructionAssembler::new();
        asm.ldarg_0()?.pop()?.ret()?;
        let (_, cfg) = build_cfg(asm)?;
        let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(1, 0).arg(0, SsaType::I64))?;

        let arg = ssa
            .variables()
            .iter()
            .find(|v| v.origin() == VariableOrigin::Argument(0))
            .expect("argument 0 has an SSA variable");
        assert_eq!(*arg.var_type(), SsaType::I64, "{ssa}");
        Ok(())
    }

    #[test]
    fn slots_are_typed_as_declared_and_unknown_past_them() {
        let types = TestTypeProvider::typed([SsaType::Object], [SsaType::I32, SsaType::F64])
            .local(0, SsaType::I64);

        assert_eq!((types.num_args(), types.num_locals()), (1, 2));
        assert_eq!(types.arg_type(0), SsaType::Object);
        assert_eq!(types.arg_type(1), SsaType::Unknown);
        assert_eq!(types.local_type(0), SsaType::I64);
        assert_eq!(types.local_type(1), SsaType::F64);
        assert_eq!(types.local_type(2), SsaType::Unknown);
        assert!(types.locals_zero_initialized());
        assert!(!types.without_locals_init().locals_zero_initialized());
    }

    #[test]
    #[should_panic(expected = "argument 2 of 2")]
    fn typing_an_undeclared_argument_panics() {
        let _ = TestTypeProvider::all_i32(2, 0).arg(2, SsaType::I64);
    }

    #[test]
    #[should_panic(expected = "local 1 of 1")]
    fn typing_an_undeclared_local_panics() {
        let _ = TestTypeProvider::all_i32(0, 1).local(1, SsaType::I64);
    }
}
