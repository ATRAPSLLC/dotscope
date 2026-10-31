//! dotscope's integration tests, built as one binary.
//!
//! A test inside a module named `full` belongs to the full tier: the packer suites, the
//! runtime corpora and the codegen validation sweep. `make test-quick` runs the rest
//! (`--skip full::`); `make test-full` and `make test-oracle` run everything. See
//! `docs/testkit.md`.

/// One `#[test]` per sample of a packer suite, each calling `$check` with the sample's file
/// name, plus `every_sample_has_a_test`, which fails when `$specs` (the suite's sample
/// descriptions) and the list here disagree. A failure then names its sample, and the samples
/// run in parallel; the deobfuscation itself is shared through `testkit::deobfuscated`.
macro_rules! sample_tests {
    ($specs:expr, $check:expr; $($name:ident => $file:literal),+ $(,)?) => {
        $(
            #[test]
            fn $name() {
                ($check)($file);
            }
        )+

        #[test]
        fn every_sample_has_a_test() {
            let described: Vec<&str> = $specs.iter().map(|spec| spec.filename).collect();
            assert_eq!(described, [$($file),+]);
        }
    };
}

mod builders;
mod cleanup;
mod deobfuscation;
mod docs;
mod dotnet10;
mod modify_add;
mod modify_basic;
mod modify_heaps;
mod modify_impexp;
mod modify_roundtrips_crafted2;
mod modify_roundtrips_method;
mod modify_roundtrips_wbdll;
mod pdb;
mod readytorun;
mod resources;
mod roundtrip_asm;
mod sections;
mod ssa;
mod stream_directory;

mod full {
    mod bitmono;
    mod codegen_validation;
    mod confuserex;
    mod corpus;
    mod jiejie;
    mod mono;
    mod netreactor;
    mod obfuscar;
    mod oracle;
    mod runtime;
}
