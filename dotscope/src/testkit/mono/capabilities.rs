//! Platform capability detection for .NET assembly testing
//!
//! This module provides unified detection of available compilers, runtimes, and
//! supported architectures. It serves as the single source of truth for determining
//! what testing capabilities are available on the current system.
//!
//! # Design
//!
//! The [`TestCapabilities`] struct detects available tools at runtime and determines
//! which compiler/runtime combinations will actually work. This avoids the previous
//! issues where architecture selection was static and didn't account for runtime
//! limitations (e.g., .NET 8 SDK on 64-bit Windows cannot run x86 assemblies).

use std::{
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::testkit::tools::{run_with_timeout, ToolKind};

/// How long a probe of one tool may run: a first `dotnet` run sets up its caches.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

/// Available C# compiler types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compiler {
    /// Roslyn csc.exe compiler (from Visual Studio or Mono)
    Csc,
    /// Modern dotnet CLI (dotnet build)
    DotNet,
    /// Mono C# compiler (mcs)
    Mcs,
}

impl Compiler {
    /// Get the command name for this compiler
    pub fn command(&self) -> &'static str {
        match self {
            Compiler::Csc => "csc",
            Compiler::DotNet => "dotnet",
            Compiler::Mcs => "mcs",
        }
    }
}

/// Available .NET runtime types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Runtime {
    /// Mono runtime
    Mono,
    /// Modern .NET runtime (dotnet CLI)
    DotNet,
}

impl Runtime {
    /// Get the command name for this runtime
    pub fn command(&self) -> &'static str {
        match self {
            Runtime::Mono => "mono",
            Runtime::DotNet => "dotnet",
        }
    }
}

/// Architecture configuration for compilation and execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Architecture {
    /// Architecture name (x86, x64, anycpu, arm64)
    pub name: &'static str,
    /// Platform flags for csc/mcs compilers
    pub csc_flag: Option<&'static str>,
    /// Platform target for dotnet SDK csproj
    pub dotnet_platform: Option<&'static str>,
}

impl Architecture {
    /// x86 (32-bit) architecture
    pub const X86: Self = Self {
        name: "x86",
        csc_flag: Some("/platform:x86"),
        dotnet_platform: Some("x86"),
    };

    /// x64 (64-bit) architecture
    pub const X64: Self = Self {
        name: "x64",
        csc_flag: Some("/platform:x64"),
        dotnet_platform: Some("x64"),
    };

    /// AnyCPU (platform-agnostic) architecture
    pub const ANYCPU: Self = Self {
        name: "anycpu",
        csc_flag: None,
        dotnet_platform: None,
    };

    /// ARM64 architecture
    pub const ARM64: Self = Self {
        name: "arm64",
        csc_flag: Some("/platform:arm64"),
        dotnet_platform: Some("ARM64"),
    };

    /// Get a safe filename component for this architecture
    pub fn filename_suffix(&self) -> &str {
        self.name
    }
}

/// Available IL disassembler types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disassembler {
    /// Mono's monodis tool
    Monodis,
    /// Microsoft's ildasm (usually not in PATH)
    Ildasm,
    /// dotnet-ildasm global tool
    DotNetIldasm,
}

impl Disassembler {
    /// Get the command name for this disassembler
    pub fn command(&self) -> &'static str {
        match self {
            Disassembler::Monodis => "monodis",
            Disassembler::Ildasm => "ildasm",
            Disassembler::DotNetIldasm => "dotnet-ildasm",
        }
    }
}

/// Detected capabilities of the current system
#[derive(Debug)]
pub struct TestCapabilities {
    /// Available compiler (best one detected)
    pub compiler: Option<Compiler>,
    /// Available runtime (best one detected)
    pub runtime: Option<Runtime>,
    /// Available disassembler (best one detected)
    pub disassembler: Option<Disassembler>,
    /// Full path to ildasm.exe (Windows SDK) if detected
    pub ildasm_path: Option<std::path::PathBuf>,
    /// Whether Mono's metadata verifier, `peverify`, is installed
    pub peverify: bool,
    /// Whether Mono is installed: it runs .NET Framework executables, which `dotnet` does not
    pub mono: bool,
    /// Architectures that can be compiled AND executed
    pub supported_architectures: Vec<Architecture>,
}

impl TestCapabilities {
    /// Detect all available capabilities on the current system
    pub fn detect() -> Self {
        let available_compilers = Self::detect_compilers();
        let available_runtimes = Self::detect_runtimes();
        let (available_disassemblers, ildasm_path) = Self::detect_disassemblers();

        // Select compatible compiler/runtime pair
        // Key constraint: dotnet-compiled assemblies (.NET 8) require dotnet runtime
        // csc/mcs-compiled assemblies (.NET Framework) can run on mono or dotnet
        let (compiler, runtime) =
            Self::select_compatible_compiler_runtime(&available_compilers, &available_runtimes);

        // Select best disassembler
        let disassembler = if available_disassemblers.contains(&Disassembler::Monodis) {
            Some(Disassembler::Monodis)
        } else if available_disassemblers.contains(&Disassembler::Ildasm) {
            Some(Disassembler::Ildasm)
        } else if available_disassemblers.contains(&Disassembler::DotNetIldasm) {
            Some(Disassembler::DotNetIldasm)
        } else {
            None
        };

        // Determine supported architectures based on compiler/runtime combination
        let supported_architectures = Self::determine_supported_architectures(compiler, runtime);

        Self {
            compiler,
            runtime,
            disassembler,
            ildasm_path,
            peverify: Self::command_exists("peverify", &["--help"]),
            mono: available_runtimes.contains(&Runtime::Mono),
            supported_architectures,
        }
    }

    /// Whether this machine has the tools of `kind`.
    pub fn has(&self, kind: ToolKind) -> bool {
        match kind {
            ToolKind::Toolchain => self.can_test(),
            ToolKind::Disassembler => self.can_disassemble(),
            ToolKind::Verifier => self.peverify,
            ToolKind::Mono => self.mono,
            ToolKind::MonoCompiler => self.compiler == Some(Compiler::Mcs) && self.mono,
        }
    }

    /// Select a compatible compiler/runtime pair
    ///
    /// Compatibility rules:
    /// - dotnet (compiler) -> dotnet (runtime) ONLY (.NET 8 assemblies can't run on mono)
    /// - mcs (compiler) -> mono (preferred) or dotnet (runtime)
    /// - csc (compiler) -> mono (preferred on non-Windows) or dotnet (runtime)
    fn select_compatible_compiler_runtime(
        compilers: &[Compiler],
        runtimes: &[Runtime],
    ) -> (Option<Compiler>, Option<Runtime>) {
        // Preference order for .NET Framework compatibility:
        // 1. mcs + mono (pure Mono stack, most compatible)
        // 2. csc + mono (Windows tools with Mono runtime)
        // 3. csc + dotnet (Windows tools with modern runtime)
        // 4. dotnet + dotnet (.NET 8 only - no mono compatibility)

        let has_mono = runtimes.contains(&Runtime::Mono);
        let has_dotnet_runtime = runtimes.contains(&Runtime::DotNet);
        let has_mcs = compilers.contains(&Compiler::Mcs);
        let has_csc = compilers.contains(&Compiler::Csc);
        let has_dotnet_compiler = compilers.contains(&Compiler::DotNet);

        // Try mcs + mono first
        if has_mcs && has_mono {
            return (Some(Compiler::Mcs), Some(Runtime::Mono));
        }

        // Try csc + mono
        if has_csc && has_mono {
            return (Some(Compiler::Csc), Some(Runtime::Mono));
        }

        // Try mcs + dotnet (mcs can produce assemblies that dotnet can run)
        if has_mcs && has_dotnet_runtime {
            return (Some(Compiler::Mcs), Some(Runtime::DotNet));
        }

        // Try csc + dotnet
        if has_csc && has_dotnet_runtime {
            return (Some(Compiler::Csc), Some(Runtime::DotNet));
        }

        // Finally, dotnet + dotnet (must use dotnet runtime for .NET 8 assemblies)
        if has_dotnet_compiler && has_dotnet_runtime {
            return (Some(Compiler::DotNet), Some(Runtime::DotNet));
        }

        // No compatible pair found
        (None, None)
    }

    /// Check if testing is possible (compiler + runtime available)
    pub fn can_test(&self) -> bool {
        self.compiler.is_some()
            && self.runtime.is_some()
            && !self.supported_architectures.is_empty()
    }

    /// Check if disassembly verification is possible
    pub fn can_disassemble(&self) -> bool {
        self.disassembler.is_some()
    }

    /// Get a summary of detected capabilities
    pub fn summary(&self) -> String {
        let compiler_str = self.compiler.map(|c| c.command()).unwrap_or("none");
        let runtime_str = self.runtime.map(|r| r.command()).unwrap_or("none");
        let disasm_str = self.disassembler.map(|d| d.command()).unwrap_or("none");
        let archs: Vec<&str> = self
            .supported_architectures
            .iter()
            .map(|a| a.name)
            .collect();

        format!(
            "Compiler: {}, Runtime: {}, Disassembler: {}, peverify: {}, mono: {}, Architectures: [{}]",
            compiler_str,
            runtime_str,
            disasm_str,
            if self.peverify { "yes" } else { "no" },
            if self.mono { "yes" } else { "no" },
            archs.join(", ")
        )
    }

    /// Detect available compilers
    fn detect_compilers() -> Vec<Compiler> {
        let mut compilers = Vec::new();

        // Check csc
        if Self::command_exists("csc", &["/help"]) {
            compilers.push(Compiler::Csc);
        }

        // Check mcs
        if Self::command_exists("mcs", &["--version"]) {
            compilers.push(Compiler::Mcs);
        }

        // Check dotnet
        if Self::command_exists("dotnet", &["--version"]) {
            compilers.push(Compiler::DotNet);
        }

        compilers
    }

    /// Detect available runtimes
    fn detect_runtimes() -> Vec<Runtime> {
        let mut runtimes = Vec::new();

        // Check mono
        if Self::command_exists("mono", &["--version"]) {
            runtimes.push(Runtime::Mono);
        }

        // Check dotnet
        if Self::command_exists("dotnet", &["--version"]) {
            runtimes.push(Runtime::DotNet);
        }

        runtimes
    }

    /// Detect available disassemblers
    ///
    /// Returns a tuple of (disassemblers, ildasm_path) where ildasm_path is the
    /// full path to ildasm.exe if found in Windows SDK locations.
    fn detect_disassemblers() -> (Vec<Disassembler>, Option<std::path::PathBuf>) {
        let mut disassemblers = Vec::new();
        let mut ildasm_path = None;

        if Self::command_exists("monodis", &["--help"]) {
            disassemblers.push(Disassembler::Monodis);
        }

        // Check ildasm - first in PATH, then in Windows SDK locations
        if Self::command_exists("ildasm", &["/?"]) {
            disassemblers.push(Disassembler::Ildasm);
        } else if let Some(path) = Self::find_windows_sdk_ildasm() {
            disassemblers.push(Disassembler::Ildasm);
            ildasm_path = Some(path);
        }

        // Check dotnet-ildasm global tool (only if we don't have a better ildasm)
        // Note: dotnet-ildasm often fails on modern .NET due to framework version requirements
        if !disassemblers.contains(&Disassembler::Ildasm)
            && Self::command_exists("dotnet-ildasm", &["--help"])
        {
            disassemblers.push(Disassembler::DotNetIldasm);
        }

        (disassemblers, ildasm_path)
    }

    /// Find ildasm.exe in Windows SDK locations
    ///
    /// On Windows, ildasm.exe is typically installed with Visual Studio in the
    /// Windows SDK tools directory. This searches common locations.
    fn find_windows_sdk_ildasm() -> Option<PathBuf> {
        if !cfg!(target_os = "windows") {
            return None;
        }

        let sdk_paths = [
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8.1 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.7.2 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.7.1 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.7 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.2 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6.1 Tools",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.6 Tools",
        ];

        for sdk_path in &sdk_paths {
            let ildasm_exe = PathBuf::from(sdk_path).join("ildasm.exe");
            if ildasm_exe.exists() && Self::command_at_path_exists(&ildasm_exe, &["/?"]) {
                return Some(ildasm_exe);
            }
        }

        None
    }

    /// Check if a command at a specific path exists and runs successfully
    fn command_at_path_exists(path: &Path, args: &[&str]) -> bool {
        run_with_timeout(Command::new(path).args(args), PROBE_TIMEOUT)
            .is_ok_and(|output| output.status.success())
    }

    /// Check if a command exists and runs to completion
    fn command_exists(cmd: &str, args: &[&str]) -> bool {
        run_with_timeout(Command::new(cmd).args(args), PROBE_TIMEOUT).is_ok()
    }

    /// Determine which architectures can be compiled AND executed
    fn determine_supported_architectures(
        compiler: Option<Compiler>,
        runtime: Option<Runtime>,
    ) -> Vec<Architecture> {
        let (compiler, runtime) = match (compiler, runtime) {
            (Some(c), Some(r)) => (c, r),
            _ => return Vec::new(),
        };

        // Determine based on platform, compiler, and runtime combination
        match (compiler, runtime) {
            // mcs (Mono C# compiler) with mono runtime
            // mcs only supports: anycpu, anycpu32bitpreferred, arm, x86, x64, itanium
            // It does NOT support arm64 as a platform flag
            (Compiler::Mcs, Runtime::Mono) => {
                #[cfg(target_arch = "x86_64")]
                {
                    vec![Architecture::ANYCPU, Architecture::X64, Architecture::X86]
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // On ARM64 with mcs, only anycpu works (no arm64 platform flag)
                    vec![Architecture::ANYCPU]
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    vec![Architecture::ANYCPU]
                }
            }

            // csc compiler with mono runtime
            (Compiler::Csc, Runtime::Mono) => {
                #[cfg(target_arch = "x86_64")]
                {
                    vec![Architecture::ANYCPU, Architecture::X64, Architecture::X86]
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // csc supports arm64 on Windows, but on non-Windows ARM64 with mono
                    // we should still be conservative
                    vec![Architecture::ANYCPU, Architecture::ARM64]
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    vec![Architecture::ANYCPU]
                }
            }

            // DotNet runtime on Windows with dotnet compiler: x86 doesn't work!
            (Compiler::DotNet, Runtime::DotNet) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                {
                    // .NET 8 SDK on 64-bit Windows cannot run x86 assemblies
                    vec![Architecture::ANYCPU, Architecture::X64]
                }
                #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
                {
                    vec![Architecture::ANYCPU, Architecture::X64]
                }
                #[cfg(target_arch = "aarch64")]
                {
                    vec![Architecture::ANYCPU, Architecture::ARM64]
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    vec![Architecture::ANYCPU]
                }
            }

            // mcs compiler with dotnet runtime
            (Compiler::Mcs, Runtime::DotNet) => {
                #[cfg(target_arch = "x86_64")]
                {
                    vec![Architecture::ANYCPU, Architecture::X64]
                }
                #[cfg(target_arch = "aarch64")]
                {
                    // mcs doesn't support arm64 platform flag
                    vec![Architecture::ANYCPU]
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    vec![Architecture::ANYCPU]
                }
            }

            // csc compiler with dotnet runtime
            (Compiler::Csc, Runtime::DotNet) => {
                #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
                {
                    // On Windows, csc produces .NET Framework assemblies
                    // The dotnet runtime CAN run them, but x86 still doesn't work
                    vec![Architecture::ANYCPU, Architecture::X64]
                }
                #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
                {
                    vec![Architecture::ANYCPU, Architecture::X64]
                }
                #[cfg(target_arch = "aarch64")]
                {
                    vec![Architecture::ANYCPU, Architecture::ARM64]
                }
                #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
                {
                    vec![Architecture::ANYCPU]
                }
            }

            // dotnet compiler with mono runtime - NOT supported!
            // .NET 8 assemblies cannot run on mono
            (Compiler::DotNet, Runtime::Mono) => {
                // This combination should never be selected by select_compatible_compiler_runtime
                // but we need to handle it for exhaustiveness
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_capabilities() {
        let caps = TestCapabilities::detect();
        println!("Detected: {}", caps.summary());

        // We should have at least something available in a dev environment
        // (this test might fail in a bare container, which is fine)
    }

    #[test]
    fn test_architecture_constants() {
        assert_eq!(Architecture::X86.name, "x86");
        assert_eq!(Architecture::X64.name, "x64");
        assert_eq!(Architecture::ANYCPU.name, "anycpu");
        assert_eq!(Architecture::ARM64.name, "arm64");

        assert_eq!(Architecture::X86.csc_flag, Some("/platform:x86"));
        assert_eq!(Architecture::ANYCPU.csc_flag, None);
    }

    #[test]
    fn test_compiler_commands() {
        assert_eq!(Compiler::Csc.command(), "csc");
        assert_eq!(Compiler::DotNet.command(), "dotnet");
        assert_eq!(Compiler::Mcs.command(), "mcs");
    }

    #[test]
    fn test_runtime_commands() {
        assert_eq!(Runtime::Mono.command(), "mono");
        assert_eq!(Runtime::DotNet.command(), "dotnet");
    }
}
