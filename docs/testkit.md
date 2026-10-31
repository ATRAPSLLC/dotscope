# dotscope testkit

The test support shared by dotscope's unit tests and integration tests lives in the crate itself,
as `dotscope::testkit` (`dotscope/src/testkit/`).

## Why in the crate, not a separate crate

A separate `dotscope-testkit` crate would depend on `dotscope`, and dotscope's own unit tests
would then need it as a dev-dependency. That makes a cycle Cargo resolves by linking a second
`dotscope` instance into the unit-test binary: the testkit's `dotscope::CilObject` and the unit
tests' `crate::CilObject` are different types, so nothing built by the testkit can be handed to
the code under test. The integration tests would work; the unit tests, the larger half, would not.

## How it is reached

```rust
// dotscope/src/lib.rs
#[cfg(any(test, feature = "testkit"))]
#[doc(hidden)]
pub mod testkit;
```

```toml
# dotscope/Cargo.toml
[features]
testkit = []

[dev-dependencies]
dotscope = { path = ".", features = ["testkit"] }
```

- **Unit tests** (`cargo test --lib`) compile the crate with `cfg(test)`, so `crate::testkit`
  exists and is the same crate.
- **Integration tests** (`tests/*.rs`) link the library as an ordinary dependency. The crate's
  dev-dependency on itself turns the `testkit` feature on, and Cargo unifies that dependency
  with the crate under test: `dotscope::testkit` and the tested types are one crate instance.

Compiled through the feature, the testkit is library code, not test code: it uses only the
crate's normal dependencies (`tempfile`, `rayon`, ...), never its dev-dependencies. The module
allows the panicking and indexing lints the library denies: test support panics on what it cannot
set up. It is `#[doc(hidden)]`, unstable, and outside the semver surface.

## Contents

| Module | What it holds |
|---|---|
| `fixtures` | `fixture(rel)`, `fixture_bytes(rel)` and `samples_dir()`: the committed fixtures under `tests/samples` |
| `builders` | Fluent builders for metadata objects: types, methods, fields, references |
| `factories` | Assemblies and rows crafted for validator and table tests |
| `helpers` | Sample loading (`load_sample`, `load_test_assembly`) and small utilities |
| `framework` | The obfuscator sample harness: deobfuscate, verify, summarize (`run_deobfuscation_test`, `assert_common_requirements`); `engine()`, `engine_with(config)`, and `deobfuscated(sample)`, each sample's run shared by every test (feature `deobfuscation`) |
| `verification` | Structural and semantic comparison of a deobfuscated assembly with its unprotected original: the original's methods run against their counterparts on fixed inputs |
| `compatibility` | Loading and comparing whole runtime corpora (Mono, .NET) |
| `analysis`, `mono` | Analysis and runtime harnesses |
| `tools` | `require_tool` and `run_with_timeout`: which external tools a test may go without, and running them |
| `emulation` | Emulator test setup: `emulation_config()`, `emulation_limits()`, `process_builder()` (feature `emulation`) |
| `passes` | `run_verified`: a pass run as the scheduler runs it, its result verified (feature `compiler`) |
| `equivalence` | `regenerate_and_compare`: generated code run against the SSA it came from (feature `compiler`) |
| crate root | `TestTypeProvider`, and `build_cfg` / `build_ssa` / `build_ssa_with_handlers` for SSA from assembled CIL |

There is one copy of each: `tests/common/` is gone, and so is the never-declared
`src/test/verification.rs` the integration tests had drifted away from.

## Fixtures

A fixture is named by its path relative to `tests/samples`: `fixture("crafted_2.exe")`,
`fixture(&format!("packers/bitmono/{version}/original.exe"))`. `fixture` resolves it through
`CARGO_MANIFEST_DIR`, so a test passes from any working directory, and panics when the file is
missing: a committed fixture is never skipped, and deleting one fails every test that uses it.
`fixture_bytes` reads one once per test binary; `load_sample(rel)` loads one as a `CilObject`.

`tests/samples/MANIFEST.toml` lists every file under `tests/samples` with its `sha256`,
`source`, `license` and `suites`, and `testkit::fixtures`' unit test fails on an unlisted file, a
listed file that is gone, or a changed hash. "Every file" is what git would commit (`git
ls-files --cached --others --exclude-standard`): files the repository ignores, like a
`.DS_Store`, are not fixtures. After adding, changing or removing fixtures,
refresh it with

```sh
DOTSCOPE_WRITE_MANIFEST=1 cargo test --profile ci-test -p dotscope --lib -- testkit::fixtures
```

The refresh updates paths and hashes and keeps what is edited by hand: `source` and `license`
(a new file takes them from where it lives), `suites`, the tags that select a fixture for a
tier or a sweep, and `reject`.

`reject` marks a fixture that is malformed by design, one that ECMA-335 or the CLR refuses, and
names the error loading it must fail with, as dotscope states it without the `(file.rs:line)`
locations an error carries. It is never written by a refresh: it says what the file is, and the
corpus sweep holds the file to exactly that error. A file that must load has no `reject`.

## Corpus sweep

`testkit::corpus` runs checks over every `.dll`, `.exe` and `.winmd` the manifest lists. Each assembly is
loaded once, as `CilObject::from_mem` loads it by default, and handed to every check in turn on
one thread; assemblies run on up to eight threads at once. A check states a property and
reports, a line per finding, what one assembly gets wrong; a check that panics reports the
panic. The sweep passes when nothing is reported: there is no list of failures to expect. What
a check counts without finding a defect in it (cases it cannot decide) are its tallies, which
every sweep prints with its findings.

`full::corpus` runs fourteen checks:

- `Loads`: every assembly loads, and a `reject` fixture fails with exactly the error it names.
- `TableRows`: every row of every table reads exactly its row size and writes back to its own
  bytes.
- `Heaps`: `#Strings`, `#US`, `#Blob` and `#GUID` read as a walk of their ECMA-335 layout
  finds them: every entry, at its offset, with its content.
- `Signatures`, `CustomAttributes`, `Marshalling`, `PermissionSets` and `MethodBodies`: every
  signature blob (read as the kind of the column naming it), custom attribute value,
  marshalling descriptor, binary permission set and method body decodes and encodes back to
  its own bytes.
- `BodyCode`: every method's instructions, encoded in place with their own branch forms, are
  the bytes of its code.
- `ExceptionStructure`: every method's exception clauses structure its code as ECMA-335
  requires: regions nest or are disjoint, every boundary and branch target is an instruction
  start, a region is entered only at its start and left only by `leave` (or `endfinally`,
  `endfilter`, `throw`, `rethrow`).
- `WritesBackUnchanged`: written back by `CilAssembly` without a change, the assembly has the
  canonical dump it was read with; one with field data the reader cannot read (past its
  section's VirtualSize, where the runtimes read different bytes) must refuse the write,
  naming that field.
- `Deterministic`: loading on one thread and on eight gives the same IL listing and the same
  written-back bytes.
- `Lifts`: every method with a body lifts to SSA that `SsaVerifier` accepts at the standard
  level.
- `CodegenEquivalence`: every method, lifted with no pass run on it, regenerates to code that,
  lifted again, returns what the SSA returns on the same arguments. Both run under
  `SsaEvaluator` on eight argument vectors drawn from ordinary and edge values of each
  argument's type. The evaluator computes pure values (arithmetic, logic, comparisons,
  conversions, slots, branches), so a method that calls, touches memory or objects, or has
  exception regions is tallied as unsupported by the first operation it cannot compute; so are
  the generator's refusals (which the codegen validation sweep judges) and runs the evaluator
  cannot finish. A difference is found only where the result depends on the arguments.

The row codecs are also held, in a unit test, to random rows under every column width: small
and large heaps and tables, and each coded-index family on both sides of the row count where
it widens. `DOTSCOPE_CORPUS_FILTER=part,part` narrows a sweep to the fixtures whose path
contains one of the parts, and `DOTSCOPE_CORPUS_REPORT=path` has a failing sweep write every
finding to `path`.

`testkit::dump::CanonicalDump` is what the writer check compares: every row by table and
RID, written again with every index four bytes wide and its heap columns resolved to the
strings, blobs and GUIDs they name; every method body decoded, branch targets and protected
regions as instruction positions; field data and embedded resources by content; debug
directory entries by content; and the CLI header. Heap offsets, RVAs, column widths, the
stream directory, relocations and signatures are left out: a writer may lay them out anew.

## The System.Reflection.Metadata oracle

The dump's format is written down in `testkit::dump` so that a second reader can write it.
`tests/oracle/srm-dump/SrmDump.cs` does: it writes an assembly's dump, as a JSON object of
path to value, from what Microsoft's System.Reflection.Metadata (SRM) reads in the file, using
SRM's object model for every column it exposes and the row SRM locates for the rest (column
widths checked against SRM's row sizes), and System.Reflection.Emit's opcode table for the
code. `testkit::oracle` builds it with Mono's `mcs` against the SRM 5.0 the fixtures hold
(`mono_4.5`, pinned by its manifest hash) and runs it under Mono. `full::oracle` has three
tests:

- `every_srm_fixture_reads_as_its_golden`: the fixtures the manifest tags `srm` have their
  SRM dumps committed under `tests/oracle/goldens/<fixture path>.json`, and dotscope's dump of
  each (read without validation, reasons after `unreadable` cut) must equal it. This needs no
  .NET tool.
- `the_srm_dumper_writes_the_goldens`: the dumper, built and run again, writes exactly the
  committed goldens. `make oracle-goldens` rewrites them.
- `every_corpus_assembly_reads_as_srm_reads_it`: a corpus check, `ReadsAsSrm`, compares the
  two dumps for every corpus assembly (about three minutes). Where SRM is not the authority,
  the fixture is declared in `disagreement` with its evidence: SRM refuses a file the runtime
  runs, or reads a stream directory by another rule than the runtime's
  (`stream_directory.rs` holds dotscope to what the CLR printed). A declaration is held both
  ways, so it fails once SRM and dotscope agree.

Both tool-running tests need `mcs` and `mono` (`ToolKind::MonoCompiler`), so they skip
without them, and fail in the oracle tier.

## Codec properties

The corpus holds the codecs to what compilers emit; `testkit::arb` holds them to everything
their models can state. It generates signatures, custom attribute named arguments,
marshalling descriptors, permission sets, method bodies with their exception sections, and
method headers, and `testkit::arb::check` runs a property over 1024 of them from a fixed seed,
so every run checks the same values and a failure is shrunk to the smallest value that shows
it. Each encoder's tests hold the property that whatever it accepts decodes back to itself: a
value it would write as something else must be refused.

## Validator tests

A validator's test runs `validator_test` (raw) or `owned_validator_test` (owned) over a factory
of `TestAssembly` cases: the clean assembly the validator accepts, and crafted ones that each
break one rule. A crafted case states what must happen to it:

```rust
create_test_assembly(get_testfile_mscorlib, Expect::fail("must also be virtual"), |assembly| {
    // build a method that is abstract but not virtual
    Ok(())
})
```

- `Expect::Pass`: the validator accepts it.
- `Expect::fail(text)`: the validator rejects it with a message containing `text`, which
  names the broken rule. An `ExpectedError` is never blank: matching any error let cases pass
  on failures that had nothing to do with their rule.
- `Expect::refused(text)`: the loader refuses it before any validator runs, with a message
  containing `text`: the rule is enforced at load. Such a case moves to `Expect::fail` when a
  lenient load lets it through.

The harness sets every case up first (load the bytes, scan references, load the project for an
owned validator). A case it cannot set up fails the test whichever way it was expected to go,
because the validator never ran. Every case runs, and the failure lists every mismatch by the
factory line that made the case (`TestAssembly` records it through `#[track_caller]`). The
validators share one thread pool.

A crafted case breaks one rule and keeps the rest of the metadata valid: list columns start
at the next row (the table builders' default), signatures are complete, mscorlib types extend
`System.Object` (`MSCORLIB_OBJECT_TYPEDEF`), and a method that needs a body points at a real
one (`MSCORLIB_OBJECT_CTOR_RVA`).

## SSA from assembled CIL

Converter and pass tests assemble CIL with `InstructionAssembler`, which has no metadata
behind it: no signature types the arguments, and no local signature types the locals. The test
states each slot's type with a `TestTypeProvider`:

```rust
let (_, cfg) = build_cfg(asm)?;
// two int32 slots of each kind
let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 2))?;
// an instance method: `this` is an object
let ssa = build_ssa(&cfg, &TestTypeProvider::all_i32(2, 4).arg(0, SsaType::Object))?;
// slot by slot
let types = TestTypeProvider::typed([SsaType::I64], [SsaType::F64, SsaType::I32]);
```

The provider declares how many arguments and locals the body has, so `build_ssa` and
`build_ssa_with_handlers` take only it. `arg(idx, ty)` and `local(idx, ty)` change a declared
slot and panic on one that is not declared; a slot past the declared ones is typed `Unknown`.
`without_locals_init()` declares a body without `.locals init`. Calls, indirect calls and fields
are typed `I32` and `newobj` results `Object`: a test that needs other types for them builds a
real assembly. There is no all-`I32` default: a test that keeps an `int64` or a float in a slot
declares it, so the converter sees the types the method's signatures would give it.

`SsaFunctionBuilder` builds SSA directly. It records each variable's uses and types what it
can: arithmetic by its operands (ECMA-335 III.1.5), and a placeholder from `var()` or `phi` by
its definition's stated type (`op_typed`), its operand's, the op's own result type or, for a
phi, its operands'. A variable left untyped and read fails the build.

## Pass tests

A pass test runs the pass with `testkit::passes::run_verified(&pass, &mut ssa, &method, &ctx)`,
not `run_on_method`: it runs analyssa's `PassScheduler::run_once`, the scheduler's own step,
with the edit-failure check and the repair or rebuild the pass's modification scope asks for,
and verifies the result at the standard level as a pipeline under `verify_hard` does. A pass
that fails, panics or leaves invalid SSA is an error, and the function is restored. The SSA it
is handed is verified first, so a test whose own fixture is invalid is told apart from a pass
that breaks valid SSA. A test asserts what the function holds after the repair: a nop the pass
leaves may be gone.

## Results independent of machine load

How busy the machine is must never decide whether a test passes. A test orders threads with
channels, joins or barriers, never with sleeps, and asserts on outcomes, never on elapsed time.

Emulation has wall-clock limits in the library's defaults (a deobfuscation run's per-method
`timeout` and `warmup_timeout`, `EmulationLimits::timeout_ms`): under load an emulation stops
earlier and a string it would have decrypted stays encrypted. Tests switch them off and rely
on the deterministic limits (instructions, call depth, memory):

- a deobfuscation engine comes from `engine()` or `engine_with(config)`, which apply
  `without_wall_clock`; the sample harness does the same for every sample;
- an emulation comes from `process_builder()`, `emulation_config()` or `emulation_limits()`
  in `testkit::emulation`.

The timeouts on external tools (`run_with_timeout`) are the exception: they stop a hung
`dotnet build` or `mono`, and are sized to pass in CI and locally.

## Fuzzing

Fuzzing runs on a developer's machine (`make fuzz`), never in CI. Each target in
`fuzz/fuzz_targets/` is a one-line wrapper over its entry point in `testkit::fuzz`, which states
the property the target checks: what a decoder reads its encoder writes back to the same value
(signatures, marshalling descriptors, permission sets, method bodies, and values generated from
the fuzzer's bytes through `testkit::arb::from_bytes`), an RVA the section map places in the file
reads that byte (`pe_file`), an assembly written back unchanged holds what it held
(`writer_roundtrip`), SSA that lifts verifies and regenerates to code that computes what it does
(`il_pipeline`), and the parsers, loaders, emulator and engine return on any input. Work is
bounded by counts (instructions, emulations, methods), never by time. The targets run on one
rayon thread (`RAYON_NUM_THREADS=1`): each thread adds AddressSanitizer allocator caches, and a
731 KB assembly that deobfuscates in 141 MB natively peaks at 2.6 GB under ASan on 56 threads,
1.3 GB on one, inside the 2 GB limit.

An input that crashes a target goes, once the defect is fixed, under
`tests/samples/fuzz-regressions/<target>/`. `tests/fuzz_regressions.rs` replays every one
through its own target's entry point, in the quick tier, with the counting allocator
(`benches/common/alloc.rs`) installed: each input may allocate at most 256 MiB all told, which
bounds its peak however its threads interleave. It does not check what a run still holds when
it returns, which moves by hundreds of kilobytes from run to run as other threads free memory
late; a leak is LeakSanitizer's to find, under the fuzzer.

`tests/allocations.rs` holds checks on what work allocates, under the same allocator: an
emulated loop over an array allocates in proportion to the array (doubling the input must not
quadruple the bytes).

## Test tiers

The tiers are cargo aliases in `.cargo/config.toml`, run by name from the Makefile, GitHub CI
and GitLab, all in the `ci-test` profile with the z3 feature:

| Tier | Command | What runs |
|---|---|---|
| quick | `cargo test-quick`, `make test-quick` | unit tests, the integration tests outside a `full` module, `fuzz_regressions` and `allocations` |
| full | `cargo test-full`, `make test-full` | every test: also the `full` modules (the corpus sweep among them) and `fuzzer` (the local fuzz corpus) |
| oracle | `make test-oracle` | full with `DOTSCOPE_REQUIRE_TOOLS=1` |

The integration tests are one binary, `tests/it/main.rs`, with a module per suite. A test
belongs to the full tier when it sits inside a module named `full`: a whole suite under `mod
full` in `main.rs` (the packer suites, the Mono corpus, the corpus sweep, the codegen validation sweep), or a
single slow test in a `mod full` of its own file (the .NET 10 corpus in `dotnet10.rs`). The
quick tier skips them by name (`--skip full::`), so they are not run, not reported as
passed. Linux CI runs the oracle tier; macOS and Windows run the quick tier, which shows the
platform works, while Linux carries the full coverage.

## Packer samples

Each packer suite describes its samples once (`all_samples()`, a `SampleSpec` per file with
the protections it carries) and has one test per sample, generated by `sample_tests!` in
`tests/it/main.rs`:

```rust
sample_tests! {
    all_samples(), check_sample;
    original => "original.exe",
    default => "obfuscar_default.exe",
}
```

`check_sample(filename)` runs the sample through `run_deobfuscation_test` and asserts what its
description promises. A failure names its sample (`full::obfuscar::default`), the samples run
in parallel, and the macro's `every_sample_has_a_test` fails when the list and `all_samples()`
disagree, so a sample added to one and not the other is never silently left out.

Deobfuscating a sample is the expensive part, and several tests check the same one: the sample
test, and the tests of one property (resource order, call targets, the trial check). They all
read `testkit::deobfuscated(path)`, the sample run once per test binary through `process_file`
with the default engine; a test asking while the run is in progress waits for it. A test with
another configuration builds its own engine with `engine_with(config)`.

`assert_common_requirements(result)` holds every sample to the same bar: the output loads and
passes validation, its structure matches the family's unprotected original (types, methods,
fields, resources, file size within a tolerance) where the spec asks for it, and it computes
what the original computes. For that last check the original's methods with fixed inputs
(`PURE_TEST_METHODS`: arithmetic, recursion, string and byte transforms) run under the
emulator in both assemblies. A method is matched with its counterpart by name, or, where
renaming lost the name, by running it among the methods of the same signature. A method of the
original with no counterpart passes only when every call to it was inlined, which cleanup
records as `deobfuscation::INLINED_METHOD_REMOVED`; an original that does not finish fails the
check rather than skipping it.

## External tools

Some tests compile C#, run it on Mono or .NET, disassemble it, or verify it with `peverify`.
Such a test asks for what it needs first:

```rust
let Some(caps) = require_tool(ToolKind::Toolchain) else {
    return Ok(());
};
```

`require_tool` returns the machine's capabilities (detected once per test binary) when it has
the tool. When it has not, the test skips, unless `DOTSCOPE_REQUIRE_TOOLS=1` is set: then the
test fails, naming what is missing. The Linux CI, coverage and release jobs install the .NET
SDK and Mono and set it, so no tool-dependent test passes there without running.
`TestRunner::new()` and `AnalysisTestRunner::new()` follow the same rule and return
`Result<Option<_>>`. A check that is one of several, like the disassembly step of
`run_complete_test` or the `peverify` comparison of the codegen roundtrip, is left out the same
way and reported as not run (`None`), never as passed.

The kinds are `Toolchain` (a C# compiler and a runtime that runs what it builds),
`Disassembler`, `Verifier` (`peverify`) and `Mono`, which the packer samples need: they are
.NET Framework executables, which `dotnet` does not run.

`full::runtime` deobfuscates every sample of each packer family and runs its output and the
family's unprotected original under Mono (`tests/it/full/runtime.rs`). The output must pass
production validation, `peverify` must accept it wherever it accepts the protected sample
(`tools::peverify_metadata_findings`), and it must print exactly what the original prints.
A sample is declared otherwise only in the test's `expectation`, each with its reason: its
lines in any order (a protection that reordered output the original order is lost from), a
protection dotscope does not reverse (still deobfuscated, validated and verified, not run), or
a file the engine refuses. A declaration naming a sample that does not exist fails the family.

Every tool runs through `run_with_timeout(command, timeout)`: stdout and stderr are drained on
their own threads while it runs, so a chatty tool cannot block on a full pipe, and one that
overstays is killed and reaped.

## Conventions

- Unit tests import `crate::testkit::...`; integration tests import `dotscope::testkit::...` in
  the same `use dotscope::{ ... }` block as the rest of the crate.
- Test support is added here, never copied into a test file.
- A test reaches a sample through `fixture`, never a `"tests/samples/..."` path, and never
  skips when one is missing.
- A test builds deobfuscation engines and emulations through the testkit, so none of them
  has a wall-clock limit.
- Every documentation example is real code. One that uses only public API is a doc test,
  `no_run` when it needs a file; one that needs crate-private API is a test in a
  `#[cfg(test)] mod examples` beside the item, which its documentation names.
  `docs::no_doc_example_is_ignored` fails on any `ignore` fence.
