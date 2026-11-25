//! Analysis test runner.
//!
//! This module provides the main test runner that compiles C# source,
//! loads the resulting assembly, and verifies analysis results.

use std::{path::PathBuf, sync::Arc};

use crate::{
    analysis::CallGraph,
    metadata::token::Token,
    project::ProjectLoader,
    testkit::{
        analysis::{
            templates::{AnalysisTestCase, ANALYSIS_TEST_CASES, ANALYSIS_TEST_SOURCE},
            verification::{
                build_analysis, verify_callgraph, verify_cfg, verify_dataflow, verify_ssa,
                VerificationError,
            },
        },
        fixture,
        mono::{compilation::compile_debug, Architecture, TestCapabilities},
        tools::{require_tool, ToolKind},
    },
    CilObject, Error, Result,
};

/// Result of running a single analysis test.
#[derive(Debug)]
pub struct AnalysisTestResult {
    /// Name of the test.
    pub test_name: String,
    /// Whether the test passed.
    pub passed: bool,
    /// Verification errors (empty if passed).
    pub errors: Vec<VerificationError>,
    /// Error message if the test failed to run.
    pub run_error: Option<String>,
}

impl AnalysisTestResult {
    /// Creates a successful test result.
    #[must_use]
    pub fn success(name: impl Into<String>) -> Self {
        Self {
            test_name: name.into(),
            passed: true,
            errors: Vec::new(),
            run_error: None,
        }
    }

    /// Creates a failed test result with verification errors.
    #[must_use]
    pub fn verification_failed(name: impl Into<String>, errors: Vec<VerificationError>) -> Self {
        Self {
            test_name: name.into(),
            passed: false,
            errors,
            run_error: None,
        }
    }

    /// Creates a failed test result with a run error.
    #[must_use]
    pub fn run_failed(name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            test_name: name.into(),
            passed: false,
            errors: Vec::new(),
            run_error: Some(error.into()),
        }
    }

    /// Gets a combined error message.
    #[must_use]
    pub fn error_message(&self) -> String {
        if let Some(ref run_error) = self.run_error {
            return run_error.clone();
        }

        if self.errors.is_empty() {
            return String::new();
        }

        self.errors
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Runner for analysis verification tests.
pub struct AnalysisTestRunner {
    /// Platform capabilities.
    capabilities: &'static TestCapabilities,
    /// Temporary directory for compiled assemblies.
    temp_dir: tempfile::TempDir,
    /// Path to compiled test assembly.
    assembly_path: Option<PathBuf>,
    /// Loaded assembly.
    assembly: Option<Arc<CilObject>>,
    /// Call graph (built once for all tests).
    callgraph: Option<CallGraph>,
}

impl AnalysisTestRunner {
    /// Creates a new analysis test runner.
    ///
    /// `None`, and the test skips, when this machine has no compiler and runtime (see
    /// [`require_tool`]).
    ///
    /// # Errors
    ///
    /// When the temporary directory cannot be created.
    ///
    /// # Panics
    ///
    /// When the toolchain is missing and `DOTSCOPE_REQUIRE_TOOLS=1` is set.
    pub fn new() -> Result<Option<Self>> {
        let Some(capabilities) = require_tool(ToolKind::Toolchain) else {
            return Ok(None);
        };
        let temp_dir = tempfile::TempDir::new()
            .map_err(|e| Error::Other(format!("Failed to create temp dir: {}", e)))?;

        Ok(Some(Self {
            capabilities,
            temp_dir,
            assembly_path: None,
            assembly: None,
            callgraph: None,
        }))
    }

    /// Compiles the test source code.
    ///
    /// # Returns
    ///
    /// The path to the compiled assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if compilation fails.
    pub fn compile(&mut self) -> Result<PathBuf> {
        if let Some(ref path) = self.assembly_path {
            return Ok(path.clone());
        }

        // Use the first available architecture
        let arch = self
            .capabilities
            .supported_architectures
            .first()
            .cloned()
            .unwrap_or(Architecture::ANYCPU);

        let result = compile_debug(
            self.capabilities,
            ANALYSIS_TEST_SOURCE,
            self.temp_dir.path(),
            "AnalysisTests",
            &arch,
        )?;

        if !result.is_success() {
            return Err(Error::Other(format!(
                "Compilation failed: {}",
                result.error.unwrap_or_else(|| "Unknown error".to_string())
            )));
        }

        let path = result.assembly_path().to_path_buf();
        self.assembly_path = Some(path.clone());
        Ok(path)
    }

    /// Loads the compiled assembly using CilProject for dependency resolution.
    ///
    /// Uses the Mono 4.8 framework assemblies as a search path to resolve
    /// dependencies like mscorlib that are needed for debug-compiled assemblies.
    ///
    /// # Returns
    ///
    /// A reference to the loaded assembly.
    ///
    /// # Errors
    ///
    /// Returns an error if loading fails.
    pub fn load(&mut self) -> Result<Arc<CilObject>> {
        if let Some(ref assembly) = self.assembly {
            return Ok(assembly.clone());
        }

        let path = self.compile()?;

        // Use ProjectLoader with Mono framework path for dependency resolution
        let project_result = ProjectLoader::new()
            .primary_file(&path)?
            .with_search_path(fixture("mono_4.8"))?
            .auto_discover(true)
            .build()?;

        let assembly = project_result
            .project
            .get_primary()
            .ok_or_else(|| Error::Other("Failed to get primary assembly".to_string()))?;

        self.assembly = Some(assembly.clone());
        Ok(assembly)
    }

    /// Builds the call graph for the loaded assembly.
    ///
    /// # Returns
    ///
    /// A reference to the call graph.
    ///
    /// # Errors
    ///
    /// Returns an error if call graph construction fails.
    pub fn build_callgraph(&mut self) -> Result<&CallGraph> {
        if let Some(ref cg) = self.callgraph {
            return Ok(cg);
        }

        let assembly = self.load()?;
        let callgraph = CallGraph::build(&assembly)?;
        self.callgraph = Some(callgraph);
        Ok(self.callgraph.as_ref().expect("just inserted"))
    }

    /// Finds a method by class and method name.
    ///
    /// # Arguments
    ///
    /// * `class_name` - The class containing the method
    /// * `method_name` - The method name
    ///
    /// # Returns
    ///
    /// The method token if found.
    pub fn find_method(&self, class_name: &str, method_name: &str) -> Option<Token> {
        let assembly = self.assembly.as_ref()?;

        // Search through types to find the class
        for type_info in assembly.types().all_types() {
            if type_info.name == class_name {
                // Search methods
                for (_, method_ref) in type_info.methods.iter() {
                    if let Some(method) = method_ref.upgrade() {
                        if method.name == method_name {
                            return Some(method.token);
                        }
                    }
                }
            }
        }

        None
    }

    /// Runs a single test case.
    ///
    /// # Arguments
    ///
    /// * `test_case` - The test case to run
    ///
    /// # Returns
    ///
    /// The test result.
    pub fn run_test(&mut self, test_case: &AnalysisTestCase) -> AnalysisTestResult {
        // Ensure assembly is loaded
        let assembly = match self.load() {
            Ok(a) => a,
            Err(e) => {
                return AnalysisTestResult::run_failed(
                    test_case.name,
                    format!("Failed to load assembly: {}", e),
                )
            }
        };

        // Find the method
        let token = match self.find_method(test_case.class_name, test_case.method_name) {
            Some(t) => t,
            None => {
                return AnalysisTestResult::run_failed(
                    test_case.name,
                    format!(
                        "Method not found: {}::{}",
                        test_case.class_name, test_case.method_name
                    ),
                )
            }
        };

        // Get the method
        let method = match assembly.method(&token) {
            Ok(method) => method,
            Err(_) => {
                return AnalysisTestResult::run_failed(
                    test_case.name,
                    format!("Method with token {:?} not in method table", token),
                )
            }
        };

        // Build CFG and SSA
        let (cfg, ssa) = match build_analysis(&method, &assembly) {
            Ok(result) => result,
            Err(e) => return AnalysisTestResult::run_failed(test_case.name, e),
        };

        let mut all_errors = Vec::new();

        // Verify CFG
        let cfg_errors = verify_cfg(&cfg, &test_case.cfg);
        all_errors.extend(cfg_errors);

        // Verify SSA
        let ssa_errors = verify_ssa(&ssa, &cfg, &test_case.ssa);
        all_errors.extend(ssa_errors);

        // Verify call graph if expectation is provided
        if let Some(ref cg_expectation) = test_case.callgraph {
            // Ensure call graph is built
            match self.build_callgraph() {
                Ok(callgraph) => {
                    let cg_errors = verify_callgraph(callgraph, &method, cg_expectation);
                    all_errors.extend(cg_errors);
                }
                Err(e) => {
                    all_errors.push(VerificationError::new(
                        "CallGraph",
                        "build",
                        "success",
                        format!("error: {}", e),
                    ));
                }
            }
        }

        // Verify data flow if expectation is provided
        if let Some(ref df_expectation) = test_case.dataflow {
            let df_errors = verify_dataflow(&ssa, &cfg, df_expectation);
            all_errors.extend(df_errors);
        }

        if all_errors.is_empty() {
            AnalysisTestResult::success(test_case.name)
        } else {
            AnalysisTestResult::verification_failed(test_case.name, all_errors)
        }
    }

    /// Runs all defined test cases.
    ///
    /// # Returns
    ///
    /// Results for all test cases.
    ///
    /// # Errors
    ///
    /// Returns an error if test setup fails (individual test failures are reported in results).
    pub fn run_all_tests(&mut self) -> Result<Vec<AnalysisTestResult>> {
        // Compile and load first
        self.load()?;

        let mut results = Vec::with_capacity(ANALYSIS_TEST_CASES.len());

        for test_case in ANALYSIS_TEST_CASES {
            let result = self.run_test(test_case);
            results.push(result);
        }

        Ok(results)
    }
}
