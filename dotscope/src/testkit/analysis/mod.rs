//! Analysis verification framework for .NET assemblies.
//!
//! This module provides infrastructure for testing dotscope's analysis capabilities
//! (CFG, SSA, Call Graph, Data Flow) against real compiled .NET assemblies.
//!
//! # Architecture
//!
//! The framework generates C# source code with known structure, compiles it using
//! the platform's .NET compiler, then verifies that dotscope's analysis produces
//! expected results.
//!
//! ```text
//! C# Source (templates.rs)
//!        │
//!        ▼ Compile (mcs/csc/dotnet)
//! Binary Assembly
//!        │
//!        ▼ Load with dotscope
//! For each test method:
//!   1. Find method by name
//!   2. Build CFG → verify against CfgExpectation
//!   3. Build SSA → verify against SsaExpectation
//!   4. Build CallGraph → verify against CallGraphExpectation
//!   5. Run DataFlow → verify results
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use dotscope::testkit::analysis::AnalysisTestRunner;
//!
//! # fn main() -> dotscope::Result<()> {
//! // `None` when this machine has no compiler and runtime: the test skips.
//! let Some(mut runner) = AnalysisTestRunner::new()? else {
//!     return Ok(());
//! };
//! let results = runner.run_all_tests()?;
//!
//! for result in &results {
//!     println!("{}: {}", result.test_name,
//!         if result.passed { "PASS" } else { "FAIL" });
//! }
//! # Ok(())
//! # }
//! ```

mod expectations;
mod runner;
mod templates;
mod verification;

// Re-export runner for test use
pub use expectations::{CallGraphExpectation, CfgExpectation, DataFlowExpectation, SsaExpectation};
pub use runner::{AnalysisTestResult, AnalysisTestRunner};
pub use templates::AnalysisTestCase;
pub use verification::VerificationError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analysis_verification_framework() {
        let Some(mut runner) = AnalysisTestRunner::new().expect("the runner's temp dir") else {
            return;
        };

        let results = match runner.run_all_tests() {
            Ok(r) => r,
            Err(e) => {
                panic!("Test execution failed: {}", e);
            }
        };

        let mut passed = 0;
        let mut failed = 0;

        for result in &results {
            if result.passed {
                passed += 1;
                println!("✓ {}", result.test_name);
            } else {
                failed += 1;
                println!("✗ {}: {}", result.test_name, result.error_message());
            }
        }

        println!("\nResults: {} passed, {} failed", passed, failed);

        assert!(
            failed == 0,
            "{} tests failed out of {}",
            failed,
            passed + failed
        );
    }
}
