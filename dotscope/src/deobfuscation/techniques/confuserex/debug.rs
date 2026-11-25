//! ConfuserEx anti-debug detection and neutralisation.
//!
//! ConfuserEx anti-debug protection injects runtime checks that detect
//! debuggers and profilers, then terminate the process via
//! `Environment.FailFast`. The protection supports three modes.
//!
//! # Source Code Analysis
//!
//! Based on analysis of the ConfuserEx source code at:
//! - `Confuser.Protections/AntiDebugProtection.cs` — Protection entry point
//! - `Confuser.Runtime/AntiDebug.Safe.cs` — Safe mode (managed-only)
//! - `Confuser.Runtime/AntiDebug.Win32.cs` — Win32 mode (P/Invoke)
//! - `Confuser.Runtime/AntiDebug.Antinet.cs` — Antinet mode (.NET-specific)
//!
//! Anti-debug is part of the **Minimum** preset.
//!
//! # Protection Modes
//!
//! ## Safe Mode (default, managed-only)
//!
//! Uses only managed APIs (cross-platform compatible):
//! - `Debugger.IsAttached` and `Debugger.IsLogging()` on a background thread
//! - `Environment.GetEnvironmentVariable("COR_ENABLE_PROFILING")` at init
//! - Calls `Environment.FailFast(null)` on detection
//! - Background thread runs checks every 1 second with `Thread.Sleep(1000)`
//!
//! ## Win32 Mode (P/Invoke-based)
//!
//! Uses native Windows APIs for stronger detection:
//! - P/Invoke: `IsDebuggerPresent`, `NtQueryInformationProcess`, `CloseHandle`,
//!   `OutputDebugString`
//! - Process handle validation: `Process.GetCurrentProcess().Handle == IntPtr.Zero`
//! - Anti-dnSpy: Parent process name check for "dnspy"
//! - Exception-based check: `CloseHandle(IntPtr.Zero)` throws under debugger
//! - Debug output check: `OutputDebugString("") > IntPtr.Size`
//!
//! ## Antinet Mode (.NET-specific)
//!
//! Uses CLR internals to detect managed debuggers and profilers:
//! - `InitializeAntiDebugger` and `InitializeAntiProfiler` methods
//! - `IsProfilerAttached` field
//! - `HandleProcessCorruptedStateExceptionsAttribute`
//!
//! # Injection Point
//!
//! Anti-debug initialization is injected at position 0 in `<Module>::.cctor`.
//!
//! # Detection
//!
//! Scans methods for anti-debug API calls and classifies the mode. Stores
//! method tokens and the detected mode in findings. Also detects P/Invoke
//! declarations for anti-debug APIs.
//!
//! # Neutralisation Strategy
//!
//! 1. **Debugger checks**: Replace with constant `false` (debugger appears not attached)
//! 2. **FailFast calls**: Replace with no-op to prevent termination
//! 3. Worker threads are marked for removal via dead method elimination
//!
//! # Passes
//!
//! Does not create its own pass — neutralisation is handled by the engine's
//! `NeutralizationPass` which processes all cleanup tokens. The cleanup
//! request marks anti-debug methods for neutralisation.
//!
//! # Test Samples
//!
//! | Sample | Has Anti-Debug | Mode | Notes |
//! |--------|----------------|------|-------|
//! | `mkaring_minimal.exe` | Yes | Safe | Minimum preset |
//! | `mkaring_normal.exe` | Yes | Safe | Normal preset |
//! | `mkaring_maximum.exe` | Yes | Safe | Maximum preset |

use std::{collections::HashSet, sync::Arc};

use crate::{
    analysis::CilTarget,
    cilassembly::CleanupRequest,
    compiler::{CompilerContext, PassPhase, SsaPass},
    deobfuscation::{
        context::AnalysisContext,
        passes::{SentinelCondition, SentinelTaintRemovalPass},
        techniques::{Detection, Evidence, Technique, TechniqueCategory},
    },
    metadata::token::Token,
    CilObject,
};

/// Detected anti-debug protection mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CxAntiDebugMode {
    /// Safe mode: managed-only APIs (Debugger.IsAttached, IsLogging, FailFast).
    Safe,
    /// Win32 mode: P/Invoke (IsDebuggerPresent, NtQueryInformationProcess).
    Win32,
    /// Antinet mode: .NET-specific anti-debug and anti-profiler.
    Antinet,
    /// Unknown mode: anti-debug detected but mode could not be determined.
    Unknown,
}

/// Findings from ConfuserEx anti-debug detection.
#[derive(Debug)]
pub struct AntiDebugFindings {
    /// Tokens of methods containing anti-debug checks.
    pub method_tokens: HashSet<Token>,
    /// Whether the module .cctor should also be processed.
    pub include_module_cctor: bool,
    /// Detected anti-debug mode.
    pub mode: CxAntiDebugMode,
}

/// Detects ConfuserEx anti-debug protection (Safe/Win32/Antinet modes).
///
/// Supersedes `generic.debug` with ConfuserEx-specific mode classification
/// and more precise detection of the injected protection patterns.
pub struct ConfuserExAntiDebug;

impl Technique for ConfuserExAntiDebug {
    fn id(&self) -> &'static str {
        "confuserex.debug"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Anti-Debug Neutralisation"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Neutralization
    }

    fn supersedes(&self) -> &[&'static str] {
        &["generic.debug"]
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let mut method_tokens = HashSet::new();
        let mut has_safe_mode = false;
        let mut has_win32_mode = false;

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            let mut calls_is_attached = false;
            let mut calls_is_logging = false;
            let mut calls_failfast = false;
            let mut calls_is_debugger_present = false;
            let mut calls_nt_query = false;
            let mut calls_set_is_background = false;
            let mut calls_thread_ctor = false;

            for instr in method.instructions() {
                if let Some(token) = instr.get_token_operand() {
                    if let Some(name) = assembly.resolve_method_name(token) {
                        match name.as_str() {
                            "get_IsAttached" => calls_is_attached = true,
                            "IsLogging" => calls_is_logging = true,
                            "FailFast" => calls_failfast = true,
                            "IsDebuggerPresent" => calls_is_debugger_present = true,
                            "NtQueryInformationProcess" => calls_nt_query = true,
                            "set_IsBackground" => calls_set_is_background = true,
                            ".ctor" => {
                                // Check for Thread constructor via MemberRef.
                                if let Some(member) = assembly.member_ref(&token) {
                                    if let Some(type_name) = member.declaredby.fullname() {
                                        if type_name.contains("Thread") {
                                            calls_thread_ctor = true;
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }

            let creates_background_thread = calls_thread_ctor && calls_set_is_background;

            // Classify the anti-debug pattern.
            let is_safe = (calls_is_attached || calls_is_logging) && calls_failfast;
            let is_win32 = calls_is_debugger_present || calls_nt_query;
            let has_indicator =
                is_safe || is_win32 || (calls_failfast && creates_background_thread);

            if has_indicator {
                method_tokens.insert(method.token);

                if is_win32 {
                    has_win32_mode = true;
                }
                if is_safe {
                    has_safe_mode = true;
                }
            }
        }

        if method_tokens.is_empty() {
            return Detection::new_empty();
        }

        // Determine the strongest mode detected.
        let mode = if has_win32_mode {
            CxAntiDebugMode::Win32
        } else if has_safe_mode {
            CxAntiDebugMode::Safe
        } else {
            CxAntiDebugMode::Unknown
        };

        let include_module_cctor = !method_tokens.is_empty();
        let count = method_tokens.len();

        let mode_name = match mode {
            CxAntiDebugMode::Safe => "Safe",
            CxAntiDebugMode::Win32 => "Win32",
            CxAntiDebugMode::Antinet => "Antinet",
            CxAntiDebugMode::Unknown => "Unknown",
        };

        let mut detection = Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} anti-debug methods ({mode_name} mode)",
            ))],
            None,
        );

        for token in &method_tokens {
            detection.cleanup_mut().add_method(*token);
        }

        detection.set_findings(Box::new(AntiDebugFindings {
            method_tokens,
            include_module_cctor,
            mode,
        }));

        detection
    }

    fn ssa_phase(&self) -> Option<PassPhase> {
        Some(PassPhase::Simplify)
    }

    fn create_pass(
        &self,
        _ctx: &AnalysisContext,
        detection: &Detection,
        _assembly: &Arc<CilObject>,
    ) -> Vec<Box<dyn SsaPass<CilTarget, CompilerContext>>> {
        let Some(findings) = detection.findings::<AntiDebugFindings>() else {
            return Vec::new();
        };
        if findings.method_tokens.is_empty() {
            return Vec::new();
        }

        // Select sentinel patterns based on the detected mode.
        // Safe mode: all three managed APIs must co-occur.
        // Win32 mode: native APIs — any single one is sufficient since
        // target_methods already filters to known anti-debug methods.
        let (sentinels, condition): (Vec<&'static str>, SentinelCondition) = match findings.mode {
            CxAntiDebugMode::Safe => (
                vec!["get_IsAttached", "IsLogging", "FailFast"],
                SentinelCondition::All,
            ),
            CxAntiDebugMode::Win32 => (
                vec![
                    "IsDebuggerPresent",
                    "NtQueryInformationProcess",
                    "GetCurrentProcess",
                    "FailFast",
                ],
                SentinelCondition::AtLeast(2),
            ),
            _ => (
                vec!["get_IsAttached", "IsLogging", "FailFast"],
                SentinelCondition::All,
            ),
        };

        vec![Box::new(SentinelTaintRemovalPass::new(
            "ConfuserExAntiDebug",
            "Removes ConfuserEx anti-debug checks via taint analysis",
            findings.method_tokens.clone(),
            sentinels,
            condition,
        ))]
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<AntiDebugFindings>()?;
        if findings.method_tokens.is_empty() {
            return None;
        }

        let mut request = CleanupRequest::new();
        for token in &findings.method_tokens {
            request.add_method(*token);
        }
        Some(request)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::debug::{AntiDebugFindings, ConfuserExAntiDebug},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_maximum.exe");

        let technique = ConfuserExAntiDebug;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExAntiDebug should detect anti-debug in mkaring_maximum.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<AntiDebugFindings>()
            .expect("Should have AntiDebugFindings");

        assert!(
            !findings.method_tokens.is_empty(),
            "Should have anti-debug method tokens"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExAntiDebug;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExAntiDebug should not detect anti-debug in original.exe"
        );
    }
}
