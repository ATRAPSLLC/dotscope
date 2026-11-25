//! Mono 4.8 framework assemblies: every one loads, as a `CilAssemblyView` and through
//! `ProjectLoader` with its dependencies.

use dotscope::testkit::{compatibility::run_assembly_compatibility_test, fixture};

/// Every Mono 4.8 framework assembly loads, alone and as a project with its dependencies.
#[test]
fn every_mono_framework_assembly_loads() {
    run_assembly_compatibility_test(&fixture("mono_4.8"), "Mono");
}
