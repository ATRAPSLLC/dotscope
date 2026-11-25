use std::path::{Path, PathBuf};

use anyhow::Context;
use dotscope::{
    analysis::Budget,
    deobfuscation::{CleanupConfig, DeobfuscationEngine, DeobfuscationResult, EngineConfig},
};
use log::info;
use serde::Serialize;

use crate::{
    app::GlobalOptions,
    commands::common::{file_display_name, process_directory},
};

#[derive(Debug, Serialize)]
struct DeobfuscationReport {
    file: String,
    output: String,
    detected: bool,
    obfuscator: Option<String>,
    score: usize,
    input_size: u64,
    output_size: u64,
    iterations: usize,
    time_ms: u128,
    detection: DetectionReport,
    stats: StatsReport,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DetectionReport {
    techniques: Vec<TechniqueEntry>,
}

#[derive(Debug, Serialize)]
struct TechniqueEntry {
    id: String,
    detected: bool,
    transformed: bool,
}

#[derive(Debug, Serialize)]
struct StatsReport {
    methods_transformed: usize,
    strings_decrypted: usize,
    arrays_decrypted: usize,
    constants_folded: usize,
    constants_decrypted: usize,
    instructions_removed: usize,
    blocks_removed: usize,
    branches_simplified: usize,
    opaque_predicates_removed: usize,
    methods_inlined: usize,
    methods_regenerated: usize,
    artifacts_removed: usize,
}

pub struct DeobfuscateOptions<'a> {
    pub output: Option<&'a Path>,
    pub suffix: &'a str,
    pub recursive: bool,
    pub max_iterations: Option<usize>,
    pub max_instructions: Option<u64>,
    pub no_cleanup: bool,
    pub aggressive: bool,
    pub detailed: bool,
    pub report: Option<&'a Path>,
    pub global: &'a GlobalOptions,
}

pub fn run(path: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    if opts.recursive {
        run_recursive(path, opts)
    } else {
        run_single(path, opts)
    }
}

fn run_single(path: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    let config = build_config(opts);

    let engine = DeobfuscationEngine::new(config);
    let (deobfuscated, result) = engine
        .process_file(path)
        .with_context(|| format!("deobfuscation failed: {}", path.display()))?;

    let output_path = resolve_output_path(path, opts.output, opts.suffix);
    let output_data = deobfuscated.file().data();

    std::fs::write(&output_path, output_data)
        .with_context(|| format!("failed to write output: {}", output_path.display()))?;

    let input_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let output_size = output_data.len() as u64;
    let report = build_report(path, &output_path, &result, input_size, output_size);

    if let Some(report_file) = opts.report {
        let json = serde_json::to_string_pretty(&report)?;
        std::fs::write(report_file, json)
            .with_context(|| format!("failed to write report: {}", report_file.display()))?;
        info!("Report written to {}", report_file.display());
    }

    if opts.global.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        let input_name = file_display_name(path);
        let output_name = file_display_name(&output_path);

        eprintln!("deobfuscate: {input_name} -> {output_name}");
        eprintln!();

        if let Some(obf) = &report.obfuscator {
            eprintln!("  Obfuscator:  {} (score: {})", obf, report.score);
        } else {
            eprintln!("  Obfuscator:  none detected");
        }

        display_size(report.input_size, report.output_size);
        display_detection(&report.detection, opts.detailed);
        display_stats(&report);

        eprintln!();
        eprintln!("  Iterations:  {}", report.iterations);
        #[allow(clippy::cast_precision_loss)]
        let time_secs = report.time_ms as f64 / 1000.0;
        eprintln!("  Time:        {time_secs:.1}s");

        if !report.warnings.is_empty() {
            eprintln!();
            eprintln!("  Warnings:    {}", report.warnings.len());
            for w in &report.warnings {
                eprintln!("    - {w}");
            }
        }
    }

    Ok(())
}

fn run_recursive(dir: &Path, opts: &DeobfuscateOptions) -> anyhow::Result<()> {
    let config = build_config(opts);

    let (reports, fail_count) = process_directory(dir, |file| {
        let engine = DeobfuscationEngine::new(config.clone());
        let (deobfuscated, result) = engine
            .process_file(file)
            .with_context(|| format!("deobfuscation failed: {}", file.display()))?;

        let out_path = if let Some(out_dir) = opts.output {
            std::fs::create_dir_all(out_dir).with_context(|| {
                format!("failed to create output directory: {}", out_dir.display())
            })?;
            let name = suffixed_filename(file, opts.suffix);
            out_dir.join(name)
        } else {
            let name = suffixed_filename(file, opts.suffix);
            file.parent().unwrap_or(Path::new(".")).join(name)
        };

        let output_data = deobfuscated.file().data();

        std::fs::write(&out_path, output_data)
            .with_context(|| format!("failed to write output: {}", out_path.display()))?;

        let input_size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        let output_size = output_data.len() as u64;
        let report = build_report(file, &out_path, &result, input_size, output_size);

        if !opts.global.json {
            let fname = file_display_name(file);
            let obf = report.obfuscator.as_deref().unwrap_or("none");
            let in_kb = format_size_short(report.input_size);
            let out_kb = format_size_short(report.output_size);
            #[allow(clippy::cast_precision_loss)]
            let time_secs = report.time_ms as f64 / 1000.0;
            info!("{fname}: {obf}, {in_kb} -> {out_kb}, {time_secs:.1}s");
        }

        Ok(report)
    })?;

    let success_count = reports.len();

    if let Some(report_file) = opts.report {
        let json = serde_json::to_string_pretty(&reports)?;
        std::fs::write(report_file, json)
            .with_context(|| format!("failed to write report: {}", report_file.display()))?;
        info!("Report written to {}", report_file.display());
    }

    if opts.global.json {
        let json = serde_json::to_string_pretty(&reports)?;
        println!("{json}");
    } else {
        let total_input: u64 = reports.iter().map(|r| r.input_size).sum();
        let total_output: u64 = reports.iter().map(|r| r.output_size).sum();
        let total_strings: usize = reports.iter().map(|r| r.stats.strings_decrypted).sum();
        let total_methods: usize = reports.iter().map(|r| r.stats.methods_transformed).sum();

        eprintln!();
        eprintln!(
            "Processed {} files: {} succeeded, {} failed",
            success_count + fail_count,
            success_count,
            fail_count
        );
        eprintln!(
            "  Total size:               {} -> {}",
            format_size_short(total_input),
            format_size_short(total_output)
        );
        eprintln!("  Total strings decrypted:  {total_strings}");
        eprintln!("  Total methods transformed: {total_methods}");
    }

    Ok(())
}

fn build_config(opts: &DeobfuscateOptions) -> EngineConfig {
    let mut config = if opts.aggressive {
        EngineConfig::aggressive()
    } else {
        EngineConfig::default()
    };

    if let Some(iters) = opts.max_iterations {
        config.budget = config.budget.with_limit(Budget::PipelineRounds, iters);
    }
    if let Some(instrs) = opts.max_instructions {
        config.emulation.limits.max_instructions = instrs;
    }
    if opts.no_cleanup {
        config.cleanup = CleanupConfig::disabled();
    }

    config
}

fn resolve_output_path(input: &Path, output: Option<&Path>, suffix: &str) -> PathBuf {
    if let Some(out) = output {
        // If output is a directory, place the suffixed file inside it
        if out.is_dir() {
            let name = suffixed_filename(input, suffix);
            return out.join(name);
        }
        return out.to_path_buf();
    }

    let name = suffixed_filename(input, suffix);
    let parent = input.parent().unwrap_or(Path::new("."));
    parent.join(name)
}

fn suffixed_filename(input: &Path, suffix: &str) -> String {
    let stem = input
        .file_stem()
        .map_or("output", |s| s.to_str().unwrap_or("output"));
    let ext = input.extension().map_or("", |e| e.to_str().unwrap_or(""));

    if ext.is_empty() {
        format!("{stem}{suffix}")
    } else {
        format!("{stem}{suffix}.{ext}")
    }
}

fn build_report(
    input: &Path,
    output: &Path,
    result: &DeobfuscationResult,
    input_size: u64,
    output_size: u64,
) -> DeobfuscationReport {
    let obfuscator_name = result
        .attribution
        .as_ref()
        .map(|a| a.obfuscator_name.clone());
    let score = result
        .attribution
        .as_ref()
        .map_or(0, |a| a.supporting_matched);

    let derived = result.stats();
    let warnings: Vec<String> = Vec::new();

    let detection = build_detection_report(result);

    DeobfuscationReport {
        file: file_display_name(input),
        output: file_display_name(output),
        detected: result.attribution.is_some(),
        obfuscator: obfuscator_name,
        score,
        input_size,
        output_size,
        iterations: result.iterations,
        time_ms: result.total_time.as_millis(),
        detection,
        stats: StatsReport {
            methods_transformed: derived.methods_transformed,
            strings_decrypted: derived.strings_decrypted,
            arrays_decrypted: derived.arrays_decrypted,
            constants_folded: derived.constants_folded,
            constants_decrypted: derived.constants_decrypted,
            instructions_removed: derived.instructions_removed,
            blocks_removed: derived.blocks_removed,
            branches_simplified: derived.branches_simplified,
            opaque_predicates_removed: derived.opaque_predicates_removed,
            methods_inlined: derived.methods_inlined,
            methods_regenerated: derived.methods_regenerated,
            artifacts_removed: derived.artifacts_removed,
        },
        warnings,
    }
}

fn build_detection_report(result: &DeobfuscationResult) -> DetectionReport {
    let techniques: Vec<TechniqueEntry> = result
        .techniques
        .iter()
        .map(|t| TechniqueEntry {
            id: t.id.clone(),
            detected: t.detected,
            transformed: t.transformed,
        })
        .collect();

    DetectionReport { techniques }
}

fn display_size(input_size: u64, output_size: u64) {
    if input_size == 0 {
        return;
    }
    #[allow(clippy::cast_precision_loss)]
    let delta_pct = ((output_size as f64 - input_size as f64) / input_size as f64) * 100.0;
    let sign = if delta_pct >= 0.0 { "+" } else { "" };
    eprintln!(
        "  Size:        {} -> {} bytes ({sign}{delta_pct:.1}%)",
        input_size, output_size
    );
}

fn display_detection(det: &DetectionReport, detailed: bool) {
    if det.techniques.is_empty() {
        return;
    }

    let detected: Vec<&TechniqueEntry> = det.techniques.iter().filter(|t| t.detected).collect();
    if detected.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("  Detected techniques:");

    for entry in &detected {
        let status = if entry.transformed {
            "transformed"
        } else {
            "detected"
        };
        eprintln!("    {:<24} ({})", entry.id, status);

        if detailed {
            // In detailed mode the id and status are already shown above;
            // nothing extra to expand per technique at this time.
        }
    }
}

fn display_stats(report: &DeobfuscationReport) {
    let s = &report.stats;

    let has_any = s.strings_decrypted > 0
        || s.arrays_decrypted > 0
        || s.constants_folded > 0
        || s.constants_decrypted > 0
        || s.methods_transformed > 0
        || s.methods_regenerated > 0
        || s.instructions_removed > 0
        || s.blocks_removed > 0
        || s.branches_simplified > 0
        || s.opaque_predicates_removed > 0
        || s.methods_inlined > 0
        || s.artifacts_removed > 0;

    if !has_any {
        return;
    }

    eprintln!();
    eprintln!("  Transformations:");

    if s.strings_decrypted > 0 {
        eprintln!("    Strings:     {} decrypted", s.strings_decrypted);
    }
    if s.arrays_decrypted > 0 {
        eprintln!("    Arrays:      {} decrypted", s.arrays_decrypted);
    }
    if s.constants_folded > 0 || s.constants_decrypted > 0 {
        eprintln!(
            "    Constants:   {} folded, {} decrypted",
            s.constants_folded, s.constants_decrypted
        );
    }
    if s.methods_transformed > 0 || s.methods_regenerated > 0 {
        eprintln!(
            "    Methods:     {} transformed, {} regenerated",
            s.methods_transformed, s.methods_regenerated
        );
    }
    if s.instructions_removed > 0 || s.blocks_removed > 0 {
        eprintln!(
            "    Dead code:   {} instructions, {} blocks removed",
            s.instructions_removed, s.blocks_removed
        );
    }
    if s.branches_simplified > 0 {
        eprintln!("    Branches:    {} simplified", s.branches_simplified);
    }
    if s.opaque_predicates_removed > 0 {
        eprintln!("    Predicates:  {} removed", s.opaque_predicates_removed);
    }
    if s.methods_inlined > 0 {
        eprintln!("    Inlined:     {} methods", s.methods_inlined);
    }
    if s.artifacts_removed > 0 {
        eprintln!("    Artifacts:   {} removed", s.artifacts_removed);
    }
}

fn format_size_short(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{}K", bytes / 1024)
    } else {
        #[allow(clippy::cast_precision_loss)]
        let mb = bytes as f64 / (1024.0 * 1024.0);
        format!("{mb:.1}M")
    }
}
