#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    missing_docs
)]
#![cfg(feature = "deobfuscation")]

//! Every method this crate lifts regenerates to code that computes what the
//! lift says, and every sample recompiles to an assembly that loads.
//!
//! The code generator validates its own output against the SSA it was given
//! (value flow, effect order, store widths) and refuses a body that disagrees,
//! so the method keeps its original IL instead of computing something else. A
//! refusal is safe, but each one is a defect in scheduling or storage that the
//! generator should not have made. These sweeps lift every method of the
//! sample corpus and regenerate it with no passes in between, which isolates
//! the generator: whatever it refuses here, it refuses on code the front end
//! produced.
//!
//! The roundtrip sweep goes further: it writes each recompiled sample to a new
//! assembly, loads it back, and checks that every body on disk is the one the
//! generator validated, that it lifts again, and that the lift regenerates.
//!
//! # Reading a failure
//!
//! Refusals are counted by kind, because the kinds are the diagnosis: a read of
//! a value its slot no longer holds is storage sharing or a scheduling order the
//! allocation did not foresee; an effect out of order is the scheduler moving a
//! call, load or store; a narrow store is slot typing.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

use dotscope::{
    analysis::SsaFunction,
    assembly::{decode_stream, Instruction},
    compiler::{validate_lift, CompilationResult, EventKind, SsaCodeGenerator},
    metadata::{
        method::{ExceptionHandler, ExceptionHandlerFlags, Method},
        tables::{MethodDefRaw, TableDataOwned, TableId},
        token::Token,
        validation::ValidationConfig,
    },
    testkit::{
        engine,
        fixtures::samples_dir,
        tools::{peverify_metadata_findings, require_tool, ToolKind},
    },
    CilAssembly, CilObject, MethodBodyBuilder, Parser,
};

/// Every `.dll` and `.exe` under `root`, recursively, sorted.
fn sample_assemblies(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path
                .extension()
                .is_some_and(|ext| ext == "dll" || ext == "exe")
            {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// The kind a refusal or failure message names.
fn kind_of(message: &str) -> &'static str {
    if !message.contains("generated code") {
        return "codegen error (not a validator refusal)";
    }
    if message.contains("which follows it in the SSA") {
        "effect out of order"
    } else if message.contains("emitted more than once") {
        "effect duplicated"
    } else if message.contains("generated code drops") {
        "effect dropped"
    } else if message.contains("truncates") {
        "narrow store"
    } else if message.contains(" reads ") {
        "operand is not the value the SSA names"
    } else if message.contains("stack depth") || message.contains("depths") {
        "stack depth"
    } else if message.contains("implements no SSA instruction") {
        "untagged instruction"
    } else {
        "other refusal"
    }
}

/// How many examples a report lists per kind of finding: three, or
/// `CODEGEN_SWEEP_EXAMPLES` when set, for listing every finding of a run.
fn example_cap() -> usize {
    std::env::var("CODEGEN_SWEEP_EXAMPLES")
        .ok()
        .and_then(|cap| cap.parse().ok())
        .unwrap_or(3)
}

/// What a sweep of the corpus found.
#[derive(Default)]
struct Findings {
    assemblies: usize,
    unloadable: usize,
    methods: usize,
    generated: usize,
    lift_errors: usize,
    by_kind: BTreeMap<&'static str, usize>,
    examples: BTreeMap<&'static str, Vec<String>>,
    /// Code bytes and declared locals of the original bodies the generator
    /// replaced, and of what it replaced them with.
    size: [usize; 4],
}

impl Findings {
    fn record(&mut self, kind: &'static str, assembly: &str, method: &str, message: &str) {
        *self.by_kind.entry(kind).or_insert(0) += 1;
        let examples = self.examples.entry(kind).or_default();
        if examples.len() < example_cap() {
            examples.push(format!("{assembly}::{method}: {message}"));
        }
    }

    fn merge(&mut self, other: Self) {
        self.assemblies += other.assemblies;
        self.unloadable += other.unloadable;
        self.methods += other.methods;
        self.generated += other.generated;
        self.lift_errors += other.lift_errors;
        for (mine, theirs) in self.size.iter_mut().zip(other.size) {
            *mine += theirs;
        }
        for (kind, count) in other.by_kind {
            *self.by_kind.entry(kind).or_insert(0) += count;
        }
        for (kind, examples) in other.examples {
            let mine = self.examples.entry(kind).or_default();
            for example in examples {
                if mine.len() < example_cap() {
                    mine.push(example);
                }
            }
        }
    }

    /// Findings that are defects: everything but a generator error that is
    /// not a validator refusal (an operation with no CIL lowering, which keeps
    /// the method's original IL by design), and an assembly the writer cannot
    /// write even unmodified (its bodies are encrypted on disk), which says
    /// nothing about the code generator.
    fn defects(&self) -> usize {
        self.by_kind
            .iter()
            .filter(|(kind, _)| {
                !kind.starts_with("codegen error") && !kind.starts_with("unwritable original")
            })
            .map(|(_, count)| *count)
            .sum()
    }

    fn report(&self) -> String {
        let mut out = format!(
            "{} assemblies ({} unloadable), {} methods: {} generated, {} lift errors, {} defects\n",
            self.assemblies,
            self.unloadable,
            self.methods,
            self.generated,
            self.lift_errors,
            self.defects()
        );
        let [code, locals, regenerated_code, regenerated_locals] = self.size;
        if code > 0 {
            out.push_str(&format!(
                "  code {code} -> {regenerated_code} bytes, locals {locals} -> {regenerated_locals}\n"
            ));
        }
        for (kind, count) in &self.by_kind {
            out.push_str(&format!("  {count:>6}  {kind}\n"));
            for example in self.examples.get(kind).into_iter().flatten() {
                out.push_str(&format!("            {example}\n"));
            }
        }
        out
    }
}

/// Runs `check` on every loadable sample, several at a time, and merges what
/// each found.
///
/// `CODEGEN_SWEEP_FILTER`, when set, limits the sweep to samples whose path
/// contains it - or any of its comma-separated parts - for looking into a
/// finding. `CODEGEN_SWEEP_ROOT` sweeps
/// another directory of assemblies instead of the test samples.
fn sweep(check: impl Fn(&str, &Path, CilObject, &mut Findings) + Sync) -> Findings {
    let root = std::env::var_os("CODEGEN_SWEEP_ROOT").map_or_else(samples_dir, PathBuf::from);
    let mut assemblies = sample_assemblies(&root);
    assert!(
        !assemblies.is_empty(),
        "no samples under {}",
        root.display()
    );
    if let Ok(filter) = std::env::var("CODEGEN_SWEEP_FILTER") {
        assemblies.retain(|path| {
            let path = path.to_string_lossy();
            filter.split(',').any(|part| path.contains(part))
        });
    }

    // Capped: the largest samples lift to a few gigabytes of SSA at once.
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8);
    let next = AtomicUsize::new(0);
    let merged = Mutex::new(Findings::default());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                let mut findings = Findings::default();
                while let Some(path) = assemblies.get(next.fetch_add(1, Ordering::Relaxed)) {
                    let Ok(data) = std::fs::read(path) else {
                        continue;
                    };
                    // Loaded as the deobfuscation engine loads: obfuscated
                    // samples carry metadata the strict checks refuse.
                    let Ok(assembly) =
                        CilObject::from_mem_with_validation(data, ValidationConfig::analysis())
                    else {
                        findings.unloadable += 1;
                        continue;
                    };
                    findings.assemblies += 1;
                    let name = path
                        .strip_prefix(&root)
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                    check(&name, path, assembly, &mut findings);
                }
                merged.lock().unwrap().merge(findings);
            });
        }
    });
    merged.into_inner().unwrap()
}

/// Lifts and regenerates every method of every sample, counting what the
/// generator's validator refuses.
#[test]
fn every_lifted_method_regenerates_to_what_it_lifted() {
    let findings = sweep(|name, _, assembly, findings| {
        for entry in assembly.methods().iter() {
            let method = entry.value();
            let Ok(ssa) = method.ssa(&assembly) else {
                findings.lift_errors += 1;
                continue;
            };
            findings.methods += 1;
            match SsaCodeGenerator::new().generate(&ssa) {
                Ok(_) => findings.generated += 1,
                Err(error) => {
                    let message = error.to_string();
                    findings.record(kind_of(&message), name, &method.name, &message);
                }
            }
        }
    });

    eprintln!("{}", findings.report());
    assert_eq!(
        findings.defects(),
        0,
        "the generator's validator refused bodies:\n{}",
        findings.report()
    );
}

/// The control: every method's own IL checked against its lift.
///
/// The check the generator applies to its output, applied to the input it
/// was lifted from. The original IL is the reference implementation of the
/// lift, so every refusal here is either the check being wrong - and then the
/// generator's refusals above cannot be trusted - or the lift producing SSA
/// that does not compute what the IL does.
#[test]
fn every_method_validates_against_its_own_lift() {
    let findings = sweep(|name, _, assembly, findings| {
        for entry in assembly.methods().iter() {
            let method = entry.value();
            let Ok(ssa) = method.ssa(&assembly) else {
                findings.lift_errors += 1;
                continue;
            };
            findings.methods += 1;
            match validate_lift(&ssa, method) {
                Ok(()) => findings.generated += 1,
                Err(error) => {
                    let message = error.to_string();
                    findings.record(kind_of(&message), name, &method.name, &message);
                }
            }
        }
    });

    eprintln!("CONTROL {}", findings.report());
    assert_eq!(
        findings.defects(),
        0,
        "methods disagree with their own lift:\n{}",
        findings.report()
    );
}

/// The bytes of a method's code as they lie in the file it was loaded from.
fn code_on_disk(assembly: &CilObject, method: &Method) -> Option<Vec<u8>> {
    let body = method.body.get()?;
    let rva = method.rva?;
    let file = assembly.file();
    let offset = file.rva_to_offset(rva as usize).ok()?;
    file.data_slice(offset + body.size_header, body.size_code)
        .ok()
        .map(<[u8]>::to_vec)
}

/// The string a user string token names: one of `input`'s heap (`0x70`), or an appended one
/// by the placeholder the generator gave it (`0xF0`), as the written heap holds it.
fn string_named(input: &CilAssembly, written: &CilObject, token: u32) -> Option<String> {
    let offset = match token >> 24 {
        0x70 => {
            let text = input
                .view()
                .userstrings()?
                .get((token & 0x00FF_FFFF) as usize)
                .ok()?;
            return Some(text.to_string_lossy().to_string());
        }
        0xF0 => input
            .changes()
            .lookup_by_placeholder(0x8000_0000 | (token & 0x00FF_FFFF))?
            .offset()?,
        _ => return None,
    };
    let text = written.userstrings()?.get(offset as usize).ok()?;
    Some(text.to_string_lossy().to_string())
}

/// Whether the code on disk is the generated code: the same instructions, with each `ldstr`
/// loading the same string. The writer renumbers user string tokens when the heap moves, so
/// their bytes may differ while the string is the same.
fn same_code(input: &CilAssembly, written: &CilObject, on_disk: &[u8], generated: &[u8]) -> bool {
    let decode = |code: &[u8]| decode_stream(&mut Parser::new(code), 0).ok();
    let (Some(disk), Some(generated_code)) = (decode(on_disk), decode(generated)) else {
        return on_disk == generated;
    };
    disk.len() == generated_code.len()
        && disk.iter().zip(&generated_code).all(|(d, g)| {
            let bytes = |code: &[u8], instr: &Instruction| {
                code.get(instr.offset as usize..(instr.offset + instr.size) as usize)
                    .map(<[u8]>::to_vec)
            };
            if d.mnemonic != g.mnemonic || d.offset != g.offset || d.size != g.size {
                return false;
            }
            if d.mnemonic == "ldstr" {
                let (Some(dt), Some(gt)) = (d.get_token_operand(), g.get_token_operand()) else {
                    return false;
                };
                let on_disk_text = written
                    .userstrings()
                    .and_then(|heap| heap.get(dt.row() as usize).ok())
                    .map(|text| text.to_string_lossy().to_string());
                return on_disk_text.is_some()
                    && on_disk_text == string_named(input, written, gt.value());
            }
            bytes(on_disk, d) == bytes(generated, g)
        })
}

/// How a body on disk differs from the compilation it was written from, if it
/// does.
fn body_difference(
    input: &CilAssembly,
    assembly: &CilObject,
    method: &Method,
    compiled: &CompilationResult,
) -> Option<String> {
    let Some(body) = method.body.get() else {
        return Some("the method has no body".to_string());
    };
    let same = code_on_disk(assembly, method)
        .is_some_and(|code| same_code(input, assembly, &code, &compiled.bytecode));
    if !same {
        return Some("the code on disk is not the generated code".to_string());
    }
    // A tiny header implies a maximum stack of 8, enough for any body it
    // holds; a fat one records the generated maximum.
    let max_stack_ok = if body.is_fat {
        body.max_stack == usize::from(compiled.max_stack)
    } else {
        compiled.max_stack <= 8
    };
    if !max_stack_ok {
        return Some(format!(
            "max stack {} on disk, {} generated",
            body.max_stack, compiled.max_stack
        ));
    }
    if method.local_vars.count() != compiled.locals.len() {
        return Some(format!(
            "{} locals on disk, {} generated",
            method.local_vars.count(),
            compiled.locals.len()
        ));
    }
    // The last field of a clause is a filter's offset or a catch's type
    // token; the generator records either in `filter_offset`, while a loaded
    // catch carries its type in `handler`.
    let clause = |eh: &ExceptionHandler| {
        let flags = eh.flags.bits();
        let last = if flags == ExceptionHandlerFlags::FILTER.bits() {
            eh.filter_offset
        } else if flags == ExceptionHandlerFlags::EXCEPTION.bits() {
            eh.handler
                .as_ref()
                .map_or(eh.filter_offset, |class| class.token.value())
        } else {
            0
        };
        (
            flags,
            eh.try_offset,
            eh.try_length,
            eh.handler_offset,
            eh.handler_length,
            last,
        )
    };
    let on_disk: Vec<_> = body.exception_handlers.iter().map(clause).collect();
    let generated: Vec<_> = compiled.exception_handlers.iter().map(clause).collect();
    if on_disk != generated {
        return Some(format!(
            "exception clauses {on_disk:?} on disk, {generated:?} generated"
        ));
    }
    None
}

/// Recompiles every method of every sample with the code generator, writes
/// the result, and checks the assembly that comes back.
///
/// Each method is lifted with no pass run on it and regenerated; a method the
/// generator refuses keeps its original IL, as the deobfuscation engine
/// handles it. The written assembly must load, every regenerated body on disk
/// must be the code, stack size, locals and exception clauses the generator
/// produced and validated, and it must lift again and regenerate again: code
/// the generator emits is code it accepts. Where Mono's `peverify` is
/// installed, a sample whose metadata it accepts must still be accepted after
/// the rewrite.
///
/// The recompiled assemblies are written under the test target's temporary
/// directory and removed after the check; `CODEGEN_SWEEP_KEEP` keeps them.
#[test]
fn every_sample_recompiles_to_an_assembly_that_loads() {
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join("codegen_roundtrip");
    std::fs::create_dir_all(&scratch).unwrap();
    // Mono's metadata check is one check of several: without peverify the others still run.
    let mono_check = require_tool(ToolKind::Verifier).is_some();

    let findings = sweep(|name, path, assembly, findings| {
        // Lift everything while the original is loaded; the generator then
        // writes into the assembly the original becomes.
        let mut lifted: Vec<(Token, String, SsaFunction, [usize; 2])> = Vec::new();
        for entry in assembly.methods().iter() {
            let method = entry.value();
            if method.rva.is_none_or(|rva| rva == 0) {
                continue;
            }
            let original = [
                method.body.get().map_or(0, |body| body.size_code),
                method.local_vars.count(),
            ];
            match method.ssa(&assembly) {
                Ok(ssa) => lifted.push((method.token, method.name.clone(), ssa, original)),
                Err(_) => findings.lift_errors += 1,
            }
        }
        findings.methods += lifted.len();

        let mut cil = assembly.into_assembly();
        let mut generator = SsaCodeGenerator::new();
        let mut compiled: Vec<(Token, String, CompilationResult)> = Vec::new();
        for (token, method, ssa, [code, locals]) in &lifted {
            let result = match generator.compile(ssa, &mut cil) {
                Ok(result) => result,
                Err(error) => {
                    let message = error.to_string();
                    findings.record(kind_of(&message), name, method, &message);
                    continue;
                }
            };
            let existing = cil
                .view()
                .tables()
                .and_then(|tables| tables.table::<MethodDefRaw>())
                .and_then(|table| table.get(token.row()).ok().flatten());
            let Some(existing) = existing else {
                findings.record("method row missing", name, method, "no MethodDef row");
                continue;
            };
            let body = MethodBodyBuilder::from_compilation(
                result.bytecode.clone(),
                result.max_stack,
                result.locals.clone(),
                result.exception_handlers.clone(),
            )
            .build(&mut cil);
            let (body, _) = match body {
                Ok(body) => body,
                Err(error) => {
                    findings.record("body does not build", name, method, &error.to_string());
                    continue;
                }
            };
            let rva = cil.store_method_body(body);
            let row = MethodDefRaw { rva, ..existing };
            if let Err(error) = cil.table_row_update(
                TableId::MethodDef,
                token.row(),
                TableDataOwned::MethodDef(row),
            ) {
                findings.record("method row update", name, method, &error.to_string());
                continue;
            }
            findings.size[0] += code;
            findings.size[1] += locals;
            findings.size[2] += result.bytecode.len();
            findings.size[3] += result.locals.len();
            compiled.push((*token, method.clone(), result));
        }
        if let Err(error) = generator.finalize_array_types(&mut cil) {
            findings.record("array types", name, "", &error.to_string());
            return;
        }

        let bytes = match cil.to_memory() {
            Ok(bytes) => bytes,
            Err(error) => {
                // The control: an assembly whose original bodies the writer
                // cannot re-encode (anti-tamper ciphertext) fails unmodified
                // too, whatever the generator did.
                let unmodified = std::fs::read(path).ok().and_then(|data| {
                    CilObject::from_mem_with_validation(data, ValidationConfig::analysis()).ok()
                });
                let kind = if unmodified
                    .is_some_and(|original| original.into_assembly().to_memory().is_err())
                {
                    "unwritable original (not a codegen finding)"
                } else {
                    "assembly does not write"
                };
                findings.record(kind, name, "", &error.to_string());
                return;
            }
        };
        let written = scratch.join(name.replace(['/', '\\'], "__"));
        std::fs::write(&written, &bytes).unwrap();
        let reloaded =
            match CilObject::from_mem_with_validation(bytes, ValidationConfig::analysis()) {
                Ok(reloaded) => reloaded,
                Err(error) => {
                    findings.record(
                        "written assembly does not load",
                        name,
                        "",
                        &error.to_string(),
                    );
                    return;
                }
            };

        let mut relifted: Vec<(String, SsaFunction)> = Vec::new();
        for (token, method, result) in &compiled {
            let Some(entry) = reloaded.methods().get(token) else {
                findings.record("method missing after write", name, method, "");
                continue;
            };
            let on_disk = entry.value();
            if let Some(difference) = body_difference(&cil, &reloaded, on_disk, result) {
                findings.record("body differs on disk", name, method, &difference);
                continue;
            }
            let ssa = match on_disk.ssa(&reloaded) {
                Ok(ssa) => ssa,
                Err(error) => {
                    findings.record(
                        "regenerated body does not lift",
                        name,
                        method,
                        &error.to_string(),
                    );
                    continue;
                }
            };
            if let Err(error) = validate_lift(&ssa, on_disk) {
                findings.record(
                    "regenerated body disagrees with its lift",
                    name,
                    method,
                    &error.to_string(),
                );
                continue;
            }
            relifted.push((method.clone(), ssa));
        }

        // Code the generator emitted is code it accepts.
        let mut again = reloaded.into_assembly();
        let mut generator = SsaCodeGenerator::new();
        for (method, ssa) in &relifted {
            match generator.compile(ssa, &mut again) {
                Ok(_) => findings.generated += 1,
                Err(error) => {
                    let message = error.to_string();
                    let kind = if message.contains("generated code") {
                        "second generation refused"
                    } else {
                        "codegen error (second generation)"
                    };
                    findings.record(kind, name, method, &message);
                }
            }
        }

        let references = path.parent().unwrap_or(Path::new("."));
        if mono_check {
            let after = peverify_metadata_findings(&written, references).unwrap();
            if !after.is_empty()
                && peverify_metadata_findings(path, references)
                    .unwrap()
                    .is_empty()
            {
                findings.record("mono metadata check regressed", name, "", &after);
            }
        }
        if std::env::var_os("CODEGEN_SWEEP_KEEP").is_none() {
            let _ = std::fs::remove_file(&written);
        }
    });

    eprintln!("ROUNDTRIP {}", findings.report());
    assert_eq!(
        findings.defects(),
        0,
        "recompiled samples do not roundtrip:\n{}",
        findings.report()
    );
}

/// The deobfuscation engine's default pipeline over every sample: the passes,
/// then code generation, as a user runs it.
///
/// The sweeps above regenerate what was lifted; this one regenerates what the
/// passes made of it. A pass that hands the generator SSA computing something
/// other than the method's code is caught by the validator, and the method
/// keeps its original IL, so a refusal here is a pass defect or a generator
/// one. So is a pass that failed on a method and was rolled back, and a
/// sample the engine cannot process at all is reported apart.
///
/// Opt-in with `CODEGEN_SWEEP_PIPELINE`: it runs every technique on every
/// sample and takes far longer than the other sweeps.
#[test]
fn every_regenerated_method_survives_the_default_pipeline() {
    if std::env::var_os("CODEGEN_SWEEP_PIPELINE").is_none() {
        return;
    }
    let findings = sweep(|name, _, assembly, findings| {
        let engine = engine();
        match engine.process_assembly(assembly) {
            Ok((_, result)) => {
                findings.generated += result.events.count_kind(EventKind::CodeRegenerated);
                for refused in result.events.filter_kind(EventKind::CodegenRefused) {
                    findings.methods += 1;
                    findings.record(
                        "pipeline: codegen refused",
                        name,
                        &format!("{:?}", refused.method),
                        &refused.message,
                    );
                }
                for failed in result.events.filter_kind(EventKind::PassFailed) {
                    findings.record(
                        "pipeline: pass failed",
                        name,
                        &format!("{:?}", failed.method),
                        &failed.message,
                    );
                }
                findings.methods += result.events.count_kind(EventKind::CodeRegenerated);
            }
            Err(error) => {
                findings.record("pipeline: engine failed", name, "", &error.to_string());
            }
        }
    });

    eprintln!("PIPELINE {}", findings.report());
    assert_eq!(
        findings.defects(),
        0,
        "the default pipeline produced code the generator refused:\n{}",
        findings.report()
    );
}
