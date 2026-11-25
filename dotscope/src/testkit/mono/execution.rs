//! .NET assembly execution utilities
//!
//! This module handles execution of .NET assemblies using the detected runtime
//! from TestCapabilities.

use std::{
    path::{absolute, Path},
    process::{Command, Output},
    time::Duration,
};

use tempfile::TempDir;

use crate::{
    prelude::*,
    testkit::{
        mono::capabilities::{Runtime, TestCapabilities},
        tools::run_with_timeout,
    },
};

/// How long a test program may run.
const EXECUTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Result of executing an assembly
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Whether execution succeeded (exit code 0)
    pub success: bool,
    /// Exit code from the process
    pub exit_code: Option<i32>,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
}

impl ExecutionResult {
    /// Create a successful execution result
    pub fn success(stdout: String) -> Self {
        Self {
            success: true,
            exit_code: Some(0),
            stdout,
            stderr: String::new(),
        }
    }

    /// Create a failed execution result
    pub fn failure(exit_code: Option<i32>, stdout: String, stderr: String) -> Self {
        Self {
            success: false,
            exit_code,
            stdout,
            stderr,
        }
    }

    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get error summary for display
    pub fn error_summary(&self) -> String {
        if self.success {
            "Success".to_string()
        } else if !self.stderr.is_empty() {
            // Include all stderr for error diagnosis
            self.stderr.clone()
        } else if !self.stdout.is_empty() {
            // Look for ERROR lines first, otherwise show all output
            let error_lines: Vec<&str> = self
                .stdout
                .lines()
                .filter(|line| line.contains("ERROR"))
                .collect();
            if !error_lines.is_empty() {
                error_lines.join("\n")
            } else {
                self.stdout.clone()
            }
        } else {
            format!("Failed with exit code {:?}", self.exit_code)
        }
    }
}

/// Execute an assembly using the detected runtime
pub fn execute(capabilities: &TestCapabilities, assembly_path: &Path) -> Result<ExecutionResult> {
    let runtime = match capabilities.runtime {
        Some(r) => r,
        None => {
            return Ok(ExecutionResult::failure(
                None,
                String::new(),
                "No .NET runtime available".to_string(),
            ))
        }
    };

    execute_with_runtime(runtime, assembly_path)
}

/// Execute an assembly with a specific runtime
pub fn execute_with_runtime(runtime: Runtime, assembly_path: &Path) -> Result<ExecutionResult> {
    let output = match runtime {
        Runtime::Mono => execute_with_mono(assembly_path)?,
        Runtime::DotNet => execute_with_dotnet(assembly_path)?,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code();

    if output.status.success() {
        let mut result = ExecutionResult::success(stdout);
        result.stderr = stderr;
        result.exit_code = exit_code;
        Ok(result)
    } else {
        Ok(ExecutionResult::failure(exit_code, stdout, stderr))
    }
}

/// Execute using Mono runtime, in a working directory of its own: Mono writes its crash report
/// (`mono_crash.*.json`) there, and so may the program, so neither lands in the caller's tree.
fn execute_with_mono(assembly_path: &Path) -> Result<Output> {
    let assembly = absolute(assembly_path)?;
    let workdir = TempDir::new()?;
    run_with_timeout(
        Command::new("mono")
            .arg(assembly)
            .current_dir(workdir.path()),
        EXECUTION_TIMEOUT,
    )
}

/// Execute using dotnet runtime
fn execute_with_dotnet(assembly_path: &Path) -> Result<Output> {
    // For dotnet, we need to run from the assembly's directory
    // so it can find the runtimeconfig.json
    let mut cmd = Command::new("dotnet");

    if let Some(parent) = assembly_path.parent() {
        cmd.current_dir(parent);
        if let Some(filename) = assembly_path.file_name() {
            cmd.arg(filename);
        } else {
            cmd.arg(assembly_path);
        }
    } else {
        cmd.arg(assembly_path);
    }

    run_with_timeout(&mut cmd, EXECUTION_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::*;
    use crate::testkit::{
        mono::compilation::{compile, templates},
        tools::{require_tool, ToolKind},
    };

    #[test]
    fn test_execution_result() {
        let success = ExecutionResult::success("Hello".to_string());
        assert!(success.is_success());
        assert_eq!(success.stdout, "Hello");

        let failure = ExecutionResult::failure(Some(1), String::new(), "Error".to_string());
        assert!(!failure.is_success());
        assert_eq!(failure.exit_code, Some(1));
    }

    #[test]
    fn test_execute_hello_world() -> Result<()> {
        let Some(caps) = require_tool(ToolKind::Toolchain) else {
            return Ok(());
        };

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        // Compile
        let compile_result = compile(caps, templates::HELLO_WORLD, temp_dir.path(), "hello", arch)?;
        assert!(compile_result.is_success(), "Compilation failed");

        // Execute
        let exec_result = execute(caps, compile_result.assembly_path())?;
        assert!(
            exec_result.is_success(),
            "Execution failed: {}",
            exec_result.error_summary()
        );
        assert!(exec_result.stdout.contains("Hello from dotscope test!"));

        Ok(())
    }

    #[test]
    fn a_mono_program_writes_its_files_outside_the_callers_directory() -> Result<()> {
        let Some(caps) = require_tool(ToolKind::Toolchain) else {
            return Ok(());
        };
        if caps.runtime != Some(Runtime::Mono) {
            eprintln!(
                "skipped: the toolchain does not run on Mono ({})",
                caps.summary()
            );
            return Ok(());
        }
        let probe = "dotscope_mono_workdir_probe.txt";
        let source = format!(
            "class Program {{ static void Main() {{ \
             System.IO.File.WriteAllText(\"{probe}\", \"x\"); \
             System.Console.WriteLine(System.IO.File.Exists(\"{probe}\")); }} }}"
        );

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();
        let compiled = compile(caps, &source, temp_dir.path(), "probe", arch)?;
        assert!(compiled.is_success(), "Compilation failed");

        let run = execute_with_runtime(Runtime::Mono, compiled.assembly_path())?;
        assert!(
            run.is_success(),
            "Execution failed: {}",
            run.error_summary()
        );
        assert_eq!(
            run.stdout.trim(),
            "True",
            "the program could not write its file"
        );
        assert!(
            !env::current_dir()?.join(probe).exists(),
            "the program wrote into the caller's working directory"
        );
        assert!(
            !temp_dir.path().join(probe).exists(),
            "the program wrote next to its assembly"
        );
        Ok(())
    }
}
