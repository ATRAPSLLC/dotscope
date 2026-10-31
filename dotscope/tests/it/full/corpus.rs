#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

//! Every assembly the fixture manifest lists loads as its entry says, its tables and heaps read
//! as what they hold, its signatures, custom attributes, marshalling descriptors, permission
//! sets, method bodies and every method's code (from the instructions it decodes to) encode
//! back to their bytes, it writes back unchanged to an assembly that holds the same, it loads
//! and writes the same on one thread as on several, and every method with a body lifts to SSA
//! the verifier accepts.
//!
//! The lift is the input to everything else: the passes, the interprocedural solve, the code
//! generator. IR that does not verify is not rejected anywhere downstream: a pass group that
//! touches such a method fails its boundary check, is rolled back, and reports that it changed
//! nothing. So the check belongs here, at the source, over the whole corpus rather than a
//! chosen method: the defects it catches are in the shapes a real compiler emits and a
//! hand-written fixture does not (deep protected regions, filters, `switch` dispatch, methods
//! with a thousand blocks, function pointers, `ref` returns).

use dotscope::{
    metadata::tables::MethodDefRaw,
    testkit::{
        corpus::{
            sweep, BodyCode, CodegenEquivalence, CustomAttributes, Deterministic,
            ExceptionStructure, Heaps, Lifts, Loads, Marshalling, MethodBodies, PermissionSets,
            Signatures, TableRows, WritesBackUnchanged,
        },
        dump::CanonicalDump,
        fixture_bytes,
    },
    CilAssembly, CilAssemblyView,
};

#[test]
fn every_corpus_assembly_loads_and_lifts() {
    let codegen_equivalence = CodegenEquivalence::default();
    sweep(&[
        &Loads,
        &TableRows,
        &Heaps,
        &Signatures,
        &CustomAttributes,
        &Marshalling,
        &PermissionSets,
        &MethodBodies,
        &BodyCode,
        &ExceptionStructure,
        &WritesBackUnchanged,
        &Deterministic,
        &Lifts,
        &codegen_equivalence,
    ])
    .assert_clean();
}

/// A method body at an RVA past 8 MB is written with the others: an RVA is not a placeholder
/// row (`0x800000` is where those start), so CoreLib's methods there lost their bodies.
#[test]
fn a_method_body_past_eight_megabytes_survives_a_write() {
    let bytes = fixture_bytes("dotnet_10.0/System.Private.CoreLib.dll").to_vec();
    let view = CilAssemblyView::from_mem(bytes).unwrap();
    let before = CanonicalDump::of(&view);
    let past = view
        .tables()
        .unwrap()
        .table::<MethodDefRaw>()
        .unwrap()
        .iter()
        .flatten()
        .find(|method| method.rva >= 0x0080_0000)
        .expect("CoreLib has code past 8 MB")
        .rid;
    let written = CilAssembly::new(view).to_memory().unwrap();
    let after = CanonicalDump::of(&CilAssemblyView::from_mem(written).unwrap());
    let path = format!("MethodDef[{past}].body");
    assert_eq!(before.entries().get(&path), after.entries().get(&path));
}
