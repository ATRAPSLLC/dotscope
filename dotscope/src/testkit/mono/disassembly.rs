//! IL disassembly utilities
//!
//! This module handles disassembly of .NET assemblies using the detected
//! disassembler from TestCapabilities.

use std::{path::Path, process::Command, time::Duration};

use crate::{
    prelude::*,
    testkit::{
        mono::capabilities::{Disassembler, TestCapabilities},
        tools::run_with_timeout,
    },
};

/// How long a disassembler may run over one test assembly.
const DISASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Result of a disassembly operation
#[derive(Debug, Clone)]
pub struct DisassemblyResult {
    /// Whether disassembly succeeded
    pub success: bool,
    /// The disassembled IL output
    pub il_output: String,
    /// Error message (if failed)
    pub error: Option<String>,
}

impl DisassemblyResult {
    /// Create a successful result
    pub fn success(il_output: String) -> Self {
        Self {
            success: true,
            il_output,
            error: None,
        }
    }

    /// Create a failed result
    pub fn failure(error: String) -> Self {
        Self {
            success: false,
            il_output: String::new(),
            error: Some(error),
        }
    }

    /// Check if disassembly was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Check if the IL output contains a specific method
    pub fn contains_method(&self, method_name: &str) -> bool {
        // Look for method definition pattern: .method ... methodname (
        self.il_output.contains(&format!(" {} ", method_name))
            || self.il_output.contains(&format!(" {}(", method_name))
            || self.il_output.contains(".method") && self.il_output.contains(method_name)
    }

    /// Check if the IL output contains a specific class
    pub fn contains_class(&self, class_name: &str) -> bool {
        self.il_output.contains(".class") && self.il_output.contains(class_name)
    }
}

/// Disassemble an assembly using the detected disassembler
pub fn disassemble(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
) -> Result<DisassemblyResult> {
    let disassembler = match capabilities.disassembler {
        Some(d) => d,
        None => {
            return Ok(DisassemblyResult::failure(
                "No IL disassembler available".to_string(),
            ))
        }
    };

    disassemble_with_caps(
        disassembler,
        assembly_path,
        capabilities.ildasm_path.as_deref(),
    )
}

/// Disassemble with a specific disassembler, using capabilities for path resolution
fn disassemble_with_caps(
    disassembler: Disassembler,
    assembly_path: &Path,
    ildasm_path: Option<&Path>,
) -> Result<DisassemblyResult> {
    let output = match disassembler {
        Disassembler::Monodis => disassemble_with_monodis(assembly_path)?,
        Disassembler::Ildasm => disassemble_with_ildasm(assembly_path, ildasm_path)?,
        Disassembler::DotNetIldasm => disassemble_with_dotnet_ildasm(assembly_path)?,
    };

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if output.status.success() {
        Ok(DisassemblyResult::success(stdout))
    } else {
        let error = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            "Disassembly failed with unknown error".to_string()
        };
        Ok(DisassemblyResult::failure(error))
    }
}

/// Disassemble using monodis
fn disassemble_with_monodis(assembly_path: &Path) -> Result<std::process::Output> {
    run_with_timeout(
        Command::new("monodis").arg(assembly_path),
        DISASSEMBLY_TIMEOUT,
    )
}

/// Disassemble using ildasm
fn disassemble_with_ildasm(
    assembly_path: &Path,
    ildasm_path: Option<&Path>,
) -> Result<std::process::Output> {
    let cmd = ildasm_path
        .map(|p| p.as_os_str().to_os_string())
        .unwrap_or_else(|| std::ffi::OsString::from("ildasm"));

    run_with_timeout(
        Command::new(cmd)
            .arg("/text")
            .arg("/nobar")
            .arg(assembly_path),
        DISASSEMBLY_TIMEOUT,
    )
}

/// Disassemble using dotnet-ildasm
fn disassemble_with_dotnet_ildasm(assembly_path: &Path) -> Result<std::process::Output> {
    run_with_timeout(
        Command::new("dotnet-ildasm").arg(assembly_path),
        DISASSEMBLY_TIMEOUT,
    )
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::testkit::{
        mono::compilation::{compile, templates},
        tools::{require_tool, ToolKind},
    };

    #[test]
    fn test_disassembly_result() {
        let success = DisassemblyResult::success(".method public static void Main()".to_string());
        assert!(success.is_success());
        assert!(success.contains_method("Main"));

        let failure = DisassemblyResult::failure("Error".to_string());
        assert!(!failure.is_success());
    }

    #[test]
    fn test_disassemble_assembly() -> Result<()> {
        let (Some(caps), Some(_)) = (
            require_tool(ToolKind::Toolchain),
            require_tool(ToolKind::Disassembler),
        ) else {
            return Ok(());
        };

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        // Compile
        let compile_result = compile(caps, templates::SIMPLE_CLASS, temp_dir.path(), "test", arch)?;
        assert!(compile_result.is_success(), "Compilation failed");

        // Disassemble
        let disasm_result = disassemble(caps, compile_result.assembly_path())?;
        assert!(
            disasm_result.is_success(),
            "Disassembly failed: {:?}",
            disasm_result.error
        );
        assert!(disasm_result.contains_method("Main"));
        assert!(disasm_result.contains_method("Add"));
        assert!(disasm_result.contains_class("TestClass"));

        Ok(())
    }
}
