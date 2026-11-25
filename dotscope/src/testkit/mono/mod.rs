//! .NET assembly verification framework
//!
//! This module provides utilities for verifying that .NET assemblies generated or modified
//! by dotscope are valid and executable. It uses the available .NET tools (compilers, runtimes,
//! disassemblers) to validate that binary output is correct and interoperable with the .NET ecosystem.
//!
//! # Architecture
//!
//! The framework automatically detects available tools and adapts to the platform:
//!
//! - **Compilers**: `csc` (Roslyn), `mcs` (Mono), `dotnet` SDK
//! - **Runtimes**: `mono`, `dotnet`
//! - **Disassemblers**: `monodis`, `ildasm`, `dotnet-ildasm`
//!
//! # Modules
//!
//! - [`capabilities`] - Platform detection and tool availability
//! - [`runner`] - Test orchestration and temporary directory management
//! - [`compilation`] - C# compilation
//! - [`execution`] - Assembly execution
//! - [`disassembly`] - IL disassembly
//! - [`reflection`] - Reflection-based method invocation testing
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use dotscope::testkit::mono::{TestRunner, TestCapabilities};
//! use dotscope::testkit::mono::compilation::{compile, templates};
//! use dotscope::testkit::mono::execution::execute;
//!
//! # fn main() -> dotscope::Result<()> {
//! // Create test runner (auto-detects platform capabilities); `None` skips the test when
//! // the machine has no compiler and runtime.
//! let Some(runner) = TestRunner::new()? else {
//!     return Ok(());
//! };
//!
//! // Run tests for all supported architectures
//! let results = runner.for_each_architecture(|arch, dir, caps| {
//!     // Compile a test program
//!     let result = compile(caps, templates::HELLO_WORLD, dir, "test", arch)?;
//!
//!     // Execute it
//!     let exec = execute(caps, result.assembly_path())?;
//!
//!     Ok(exec.is_success())
//! });
//!
//! // Check results
//! assert!(TestRunner::all_passed(&results));
//! # Ok(())
//! # }
//! ```
//!
//! # Complete Test Example
//!
//! ```rust,no_run
//! use dotscope::prelude::*;
//! use dotscope::testkit::mono::{TestRunner, run_complete_test};
//!
//! # fn main() -> dotscope::Result<()> {
//! let Some(runner) = TestRunner::new()? else {
//!     return Ok(());
//! };
//!
//! // Source code to compile
//! let source = r#"
//! using System;
//! public class TestClass {
//!     public static void Main() { Console.WriteLine("Hello!"); }
//!     public static int Add(int a, int b) { return a + b; }
//! }
//! "#;
//!
//! // Run complete test (compile, modify, execute, verify)
//! let results = run_complete_test(
//!     &runner,
//!     source,
//!     |ctx| {
//!         // Modify the assembly using dotscope builders
//!         Ok(())
//!     },
//!     // No method tests: reflection only checks that the assembly loads.
//!     |_| Vec::new(),
//! )?;
//!
//! // Check results for each architecture
//! for result in &results {
//!     println!("{}: {}", result.architecture.name,
//!         if result.is_fully_successful() { "PASS" } else { "FAIL" });
//! }
//! # Ok(())
//! # }
//! ```

pub mod capabilities;
pub mod compilation;
pub mod disassembly;
pub mod execution;
pub mod reflection;
pub mod runner;

// Re-export main types
use std::path::Path;

pub use capabilities::{Architecture, TestCapabilities};
pub use reflection::MethodTest;
pub use runner::TestRunner;

use crate::{
    prelude::*,
    testkit::tools::{require_tool, ToolKind},
};

/// Result of a complete test run for one architecture
#[derive(Debug)]
pub struct CompleteTestResult {
    /// The architecture tested
    pub architecture: Architecture,
    /// Whether compilation succeeded
    pub compilation_success: bool,
    /// Whether assembly modification succeeded
    pub modification_success: bool,
    /// Whether execution succeeded
    pub execution_success: bool,
    /// Whether disassembly verification succeeded; `None` when no disassembler ran
    pub disassembly_success: Option<bool>,
    /// Whether reflection tests succeeded
    pub reflection_success: bool,
    /// Error messages
    pub errors: Vec<String>,
}

impl CompleteTestResult {
    /// Check if all test phases were successful
    pub fn is_fully_successful(&self) -> bool {
        self.compilation_success
            && self.modification_success
            && self.execution_success
            && self.disassembly_success != Some(false)
            && self.reflection_success
            && self.errors.is_empty()
    }

    /// Get a summary string
    pub fn summary(&self) -> String {
        if self.is_fully_successful() {
            format!("{}: All tests passed", self.architecture.name)
        } else {
            format!(
                "{}: compile={}, modify={}, exec={}, disasm={:?}, reflect={}, errors={}",
                self.architecture.name,
                self.compilation_success,
                self.modification_success,
                self.execution_success,
                self.disassembly_success,
                self.reflection_success,
                self.errors.len()
            )
        }
    }
}

/// Run a complete test workflow: compile, modify, execute, verify
///
/// For each supported architecture:
/// 1. Compile C# source code
/// 2. Modify the assembly using dotscope
/// 3. Execute the modified assembly
/// 4. Disassemble it, when the machine has a disassembler (see [`require_tool`])
/// 5. Run reflection tests
///
/// `create_tests_fn` receives the path to the modified assembly and returns the
/// [`reflection::MethodTest`]s that check the generated methods with specific inputs and
/// outputs; with none, step 5 only checks that the assembly loads.
pub fn run_complete_test<M, T>(
    runner: &TestRunner,
    source_code: &str,
    modify_fn: M,
    create_tests_fn: T,
) -> Result<Vec<CompleteTestResult>>
where
    M: Fn(&mut crate::CilAssembly) -> Result<()>,
    T: Fn(&Path) -> Vec<reflection::MethodTest>,
{
    let caps = runner.capabilities();
    let mut results = Vec::new();

    for arch in runner.architectures() {
        let mut result = CompleteTestResult {
            architecture: arch.clone(),
            compilation_success: false,
            modification_success: false,
            execution_success: false,
            disassembly_success: None,
            reflection_success: false,
            errors: Vec::new(),
        };

        // Create architecture-specific directory
        let arch_dir = match runner.arch_dir(arch) {
            Ok(d) => d,
            Err(e) => {
                result
                    .errors
                    .push(format!("Failed to create directory: {}", e));
                results.push(result);
                continue;
            }
        };

        // 1. Compile
        let compile_result = match compilation::compile(caps, source_code, &arch_dir, "test", arch)
        {
            Ok(r) => r,
            Err(e) => {
                result.errors.push(format!("Compilation error: {}", e));
                results.push(result);
                continue;
            }
        };

        if !compile_result.is_success() {
            result
                .errors
                .push(format!("Compilation failed: {:?}", compile_result.error));
            results.push(result);
            continue;
        }
        result.compilation_success = true;

        let original_path = compile_result.assembly_path();

        // 2. Modify assembly
        let modified_dir = arch_dir.join("modified");
        std::fs::create_dir_all(&modified_dir).ok();
        let modified_path = modified_dir.join(
            original_path
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("modified.dll")),
        );

        match modify_assembly(original_path, &modified_path, &modify_fn) {
            Ok(_) => {
                result.modification_success = true;

                // Copy runtimeconfig.json if it exists
                if let Some(stem) = original_path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(parent) = original_path.parent() {
                        let config_src = parent.join(format!("{}.runtimeconfig.json", stem));
                        if config_src.exists() {
                            let config_dst =
                                modified_dir.join(format!("{}.runtimeconfig.json", stem));
                            std::fs::copy(&config_src, &config_dst).ok();
                        }
                    }
                }
            }
            Err(e) => {
                result.errors.push(format!("Modification failed: {}", e));
                results.push(result);
                continue;
            }
        }

        // 3. Execute (basic execution test)
        match execution::execute(caps, &modified_path) {
            Ok(exec_result) => {
                if exec_result.is_success() {
                    result.execution_success = true;
                } else {
                    result
                        .errors
                        .push(format!("Execution failed: {}", exec_result.error_summary()));
                }
            }
            Err(e) => {
                result.errors.push(format!("Execution error: {}", e));
            }
        }

        // 4. Disassembly verification, when the machine has a disassembler
        if require_tool(ToolKind::Disassembler).is_some() {
            let disassembled = match disassembly::disassemble(caps, &modified_path) {
                Ok(disasm_result) if disasm_result.is_success() => true,
                Ok(disasm_result) => {
                    result
                        .errors
                        .push(format!("Disassembly failed: {:?}", disasm_result.error));
                    false
                }
                Err(e) => {
                    result.errors.push(format!("Disassembly error: {}", e));
                    false
                }
            };
            result.disassembly_success = Some(disassembled);
        }

        // 5. Reflection tests with custom method invocations
        let method_tests = create_tests_fn(&modified_path);
        if method_tests.is_empty() {
            // No custom tests, just verify assembly is loadable
            match reflection::verify_assembly_loadable(caps, &modified_path, &modified_dir, arch) {
                Ok(refl_result) => {
                    if refl_result.is_success() {
                        result.reflection_success = true;
                    } else {
                        result.errors.push(format!(
                            "Reflection failed: {}",
                            refl_result.error_summary()
                        ));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Reflection error: {}", e));
                }
            }
        } else {
            // Run custom method tests
            match reflection::run_reflection_test(
                caps,
                &modified_path,
                &method_tests,
                &modified_dir,
                arch,
            ) {
                Ok(refl_result) => {
                    if refl_result.is_success() {
                        result.reflection_success = true;
                    } else {
                        result.errors.push(format!(
                            "Reflection test failed: {}",
                            refl_result.error_summary()
                        ));
                    }
                }
                Err(e) => {
                    result.errors.push(format!("Reflection error: {}", e));
                }
            }
        }

        results.push(result);
    }

    Ok(results)
}

/// Modify an assembly using dotscope
fn modify_assembly<M>(original_path: &Path, modified_path: &Path, modify_fn: &M) -> Result<()>
where
    M: Fn(&mut crate::CilAssembly) -> Result<()>,
{
    use crate::prelude::*;

    let mut assembly = CilAssembly::from_path(original_path)?;

    modify_fn(&mut assembly)?;

    assembly.to_file(modified_path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_detection() {
        let caps = TestCapabilities::detect();
        println!("Detected: {}", caps.summary());
    }

    #[test]
    fn test_runner_creation() -> Result<()> {
        let Some(runner) = TestRunner::new()? else {
            return Ok(());
        };
        println!("Runner capabilities: {}", runner.capabilities().summary());
        println!(
            "Supported architectures: {:?}",
            runner
                .architectures()
                .iter()
                .map(|a| a.name)
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    #[test]
    fn test_complete_workflow() -> Result<()> {
        let Some(runner) = TestRunner::new()? else {
            return Ok(());
        };

        // No modifications and no method tests: just the workflow.
        let results = run_complete_test(
            &runner,
            compilation::templates::HELLO_WORLD,
            |_assembly| Ok(()),
            |_| Vec::new(),
        )?;

        for result in &results {
            println!("{}", result.summary());
        }

        // At least compilation should work
        assert!(
            results.iter().all(|r| r.compilation_success),
            "Compilation should succeed"
        );

        Ok(())
    }
}
