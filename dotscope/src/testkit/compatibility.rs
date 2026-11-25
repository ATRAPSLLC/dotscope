//! Shared assembly compatibility testing infrastructure.
//!
//! Provides common loading, comparison, and analysis logic for testing
//! assembly compatibility across different runtime sample sets (e.g., Mono 4.8,
//! .NET 10). Each test file only needs to specify the sample directory and labels.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use rayon::prelude::*;

use crate::{project::ProjectLoader, CilAssemblyView};

/// Result of loading an assembly with a specific loader.
#[derive(Debug, Clone)]
pub struct LoadResult {
    pub success: bool,
    pub error_type: Option<String>,
}

/// Comprehensive comparison of loading results between ProjectLoader and CilAssemblyView.
#[derive(Debug)]
pub struct LoadComparison {
    pub file_name: String,
    pub file_size: u64,
    pub cilproject_result: LoadResult,
    pub cilassemblyview_result: LoadResult,
}

impl LoadComparison {
    pub fn both_successful(&self) -> bool {
        self.cilproject_result.success && self.cilassemblyview_result.success
    }

    pub fn both_failed(&self) -> bool {
        !self.cilproject_result.success && !self.cilassemblyview_result.success
    }

    pub fn only_cilproject_succeeded(&self) -> bool {
        self.cilproject_result.success && !self.cilassemblyview_result.success
    }

    pub fn only_cilassemblyview_succeeded(&self) -> bool {
        !self.cilproject_result.success && self.cilassemblyview_result.success
    }
}

/// Load an assembly using ProjectLoader (with dependencies) and return the result.
pub fn try_load_with_cilproject(path: &Path) -> LoadResult {
    let search_path = path.parent().unwrap_or_else(|| Path::new("."));

    match ProjectLoader::new()
        .primary_file(path)
        .and_then(|loader| loader.with_search_path(search_path))
        .map(|loader| loader.auto_discover(true))
        .and_then(|loader| loader.build())
    {
        Ok(result) => {
            if result.success_count() > 0 {
                LoadResult {
                    success: true,
                    error_type: None,
                }
            } else {
                LoadResult {
                    success: false,
                    error_type: Some("No assemblies loaded".to_string()),
                }
            }
        }
        Err(e) => LoadResult {
            success: false,
            error_type: Some(format!("{:?}", e)),
        },
    }
}

/// Load an assembly using CilAssemblyView and return the result.
pub fn try_load_with_cilassemblyview(path: &Path) -> LoadResult {
    match CilAssemblyView::from_path(path) {
        Ok(_) => LoadResult {
            success: true,
            error_type: None,
        },
        Err(e) => LoadResult {
            success: false,
            error_type: Some(format!("{:?}", e)),
        },
    }
}

/// Find all .dll and .exe files in a samples directory.
pub fn find_assemblies(samples_dir: &Path) -> Vec<PathBuf> {
    if !samples_dir.exists() {
        return Vec::new();
    }

    let mut assemblies = Vec::new();

    if let Ok(entries) = fs::read_dir(samples_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(extension) = path.extension() {
                    if extension == "dll" || extension == "exe" {
                        assemblies.push(path);
                    }
                }
            }
        }
    }

    assemblies.sort();
    assemblies
}

/// Categorize error types for analysis.
pub fn categorize_error(error: &str) -> &'static str {
    if error.contains("RecursionLimit") {
        "RecursionLimit"
    } else if error.contains("OutOfBounds") {
        "OutOfBounds"
    } else if error.contains("Unicode") || error.contains("Utf8") {
        "UnicodeError"
    } else if error.contains("NotSupported") {
        "NotSupported"
    } else if error.contains("Io(") {
        "Io"
    } else {
        "Other"
    }
}

/// Print detailed analysis of loading results.
pub fn print_analysis(comparisons: &[LoadComparison], label: &str) {
    println!("\n=== {} ASSEMBLY COMPATIBILITY ANALYSIS ===", label);
    println!("Total assemblies tested: {}", comparisons.len());

    let both_success = comparisons.iter().filter(|c| c.both_successful()).count();
    let both_failed = comparisons.iter().filter(|c| c.both_failed()).count();
    let only_cilproject = comparisons
        .iter()
        .filter(|c| c.only_cilproject_succeeded())
        .count();
    let only_cilassemblyview = comparisons
        .iter()
        .filter(|c| c.only_cilassemblyview_succeeded())
        .count();

    println!("\n--- OVERALL RESULTS ---");
    println!(
        "Both succeeded:              {} ({:.1}%)",
        both_success,
        both_success as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Both failed:                 {} ({:.1}%)",
        both_failed,
        both_failed as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Only CilProject succeeded:   {} ({:.1}%)",
        only_cilproject,
        only_cilproject as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "Only CilAssemblyView succeeded: {} ({:.1}%)",
        only_cilassemblyview,
        only_cilassemblyview as f64 / comparisons.len() as f64 * 100.0
    );

    let cilproject_success_rate = comparisons
        .iter()
        .filter(|c| c.cilproject_result.success)
        .count();
    let cilassemblyview_success_rate = comparisons
        .iter()
        .filter(|c| c.cilassemblyview_result.success)
        .count();

    println!("\n--- SUCCESS RATES ---");
    println!(
        "CilProject (with deps): {}/{} ({:.1}%)",
        cilproject_success_rate,
        comparisons.len(),
        cilproject_success_rate as f64 / comparisons.len() as f64 * 100.0
    );
    println!(
        "CilAssemblyView:        {}/{} ({:.1}%)",
        cilassemblyview_success_rate,
        comparisons.len(),
        cilassemblyview_success_rate as f64 / comparisons.len() as f64 * 100.0
    );

    // Error categorization for ProjectLoader and CilAssemblyView
    let mut cilproject_errors: HashMap<&str, usize> = HashMap::new();
    let mut cilassemblyview_errors: HashMap<&str, usize> = HashMap::new();

    for comparison in comparisons {
        if !comparison.cilproject_result.success {
            if let Some(error) = &comparison.cilproject_result.error_type {
                let category = categorize_error(error);
                *cilproject_errors.entry(category).or_insert(0) += 1;
            }
        }

        if !comparison.cilassemblyview_result.success {
            if let Some(error) = &comparison.cilassemblyview_result.error_type {
                let category = categorize_error(error);
                *cilassemblyview_errors.entry(category).or_insert(0) += 1;
            }
        }
    }

    println!("\n--- CILPROJECT ERROR CATEGORIES ---");
    for (category, count) in &cilproject_errors {
        println!("{}: {}", category, count);
    }

    println!("\n--- CILASSEMBLYVIEW ERROR CATEGORIES ---");
    for (category, count) in &cilassemblyview_errors {
        println!("{}: {}", category, count);
    }

    // Show successful assemblies
    println!("\n--- SUCCESSFUL ASSEMBLIES (Both) ---");
    for comparison in comparisons.iter().filter(|c| c.both_successful()) {
        println!(
            "  {} ({} bytes)",
            comparison.file_name, comparison.file_size
        );
    }

    // Show assemblies that only work with one approach
    if only_cilproject > 0 {
        println!("\n--- ONLY CILPROJECT SUCCEEDED ---");
        for comparison in comparisons.iter().filter(|c| c.only_cilproject_succeeded()) {
            println!(
                "  {} (CilAssemblyView error: {:?})",
                comparison.file_name, comparison.cilassemblyview_result.error_type
            );
        }
    }

    if only_cilassemblyview > 0 {
        println!("\n--- ONLY CILASSEMBLYVIEW SUCCEEDED ---");
        for comparison in comparisons
            .iter()
            .filter(|c| c.only_cilassemblyview_succeeded())
        {
            println!(
                "  {} (CilProject error: {:?})",
                comparison.file_name, comparison.cilproject_result.error_type
            );
        }
    }

    // Show failures for both
    if both_failed > 0 {
        println!("\n--- FAILED WITH BOTH APPROACHES ---");
        for comparison in comparisons.iter().filter(|c| c.both_failed()) {
            println!(
                "  {} ({} bytes)",
                comparison.file_name, comparison.file_size
            );
            println!(
                "   CilProject: {:?}",
                comparison.cilproject_result.error_type
            );
            println!(
                "   CilAssemblyView: {:?}",
                comparison.cilassemblyview_result.error_type
            );
        }
    }
}

/// Run a full assembly compatibility test for all assemblies in the given sample directory.
///
/// This is the main entry point shared by all runtime compatibility tests (mono, dotnet, etc.).
/// Every `.dll` and `.exe` in `samples_dir` must load alone, as a `CilAssemblyView`, and the
/// whole set must load as one project through `ProjectLoader`, each assembly once with its
/// references resolved within the set. These are runtime assemblies the CLR loads, so any
/// failure is a dotscope defect.
///
/// Loading each assembly as a project of its own would load its whole dependency closure
/// every time, most of the framework for most of them: memory then grows with the number of
/// loads running at once, about 10 GB each, and the same assemblies load hundreds of times.
///
/// # Panics
///
/// When `samples_dir` holds no assemblies, or any assembly fails either load; the message
/// names each failure.
pub fn run_assembly_compatibility_test(samples_dir: &Path, label: &str) {
    let mut assemblies = find_assemblies(samples_dir);
    assemblies.sort();
    assert!(
        !assemblies.is_empty(),
        "no assemblies in {}",
        samples_dir.display()
    );

    let mut failures: Vec<String> = assemblies
        .par_iter()
        .filter_map(|path| {
            let result = try_load_with_cilassemblyview(path);
            (!result.success).then(|| {
                format!(
                    "{} (CilAssemblyView): {}",
                    path.display(),
                    result.error_type.as_deref().unwrap_or("failed")
                )
            })
        })
        .collect();

    let (primary, dependencies) = assemblies.split_first().expect("not empty");
    let project = dependencies
        .iter()
        .fold(
            ProjectLoader::new().primary_file(primary),
            |loader, path| loader.and_then(|loader| loader.with_dependency(path)),
        )
        .and_then(|loader| loader.with_search_path(samples_dir))
        .and_then(|loader| loader.build());
    match project {
        Ok(result) => {
            failures.extend(
                result
                    .failed_loads
                    .iter()
                    .map(|(path, error)| format!("{path} (ProjectLoader): {error}")),
            );
            if result.success_count() != assemblies.len() {
                failures.push(format!(
                    "the project loaded {} of {} assemblies",
                    result.success_count(),
                    assemblies.len()
                ));
            }
        }
        Err(e) => failures.push(format!("the project failed to load: {e}")),
    }

    assert!(
        failures.is_empty(),
        "{label}: {} problems over {} assemblies:\n{}",
        failures.len(),
        assemblies.len(),
        failures.join("\n")
    );
}
