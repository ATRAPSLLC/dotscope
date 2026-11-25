//! Reflection-based method invocation testing
//!
//! This module generates and executes C# test programs that use .NET reflection
//! to invoke methods in dotscope-modified assemblies. This validates that methods
//! added or modified by dotscope are correctly callable at runtime.

use std::path::Path;

use crate::{
    prelude::*,
    testkit::mono::{
        capabilities::{Architecture, TestCapabilities},
        compilation::compile,
        execution::{execute, ExecutionResult},
    },
};

/// Result of a reflection test
#[derive(Debug)]
pub struct ReflectionTestResult {
    /// Whether the test passed
    pub success: bool,
    /// Execution result
    pub execution: Option<ExecutionResult>,
    /// Error message if failed
    pub error: Option<String>,
}

impl ReflectionTestResult {
    /// Create a successful result
    pub fn success(execution: ExecutionResult) -> Self {
        Self {
            success: true,
            execution: Some(execution),
            error: None,
        }
    }

    /// Check if test was successful
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Get error summary
    pub fn error_summary(&self) -> String {
        if let Some(ref err) = self.error {
            err.clone()
        } else if let Some(ref exec) = self.execution {
            if !exec.is_success() {
                exec.error_summary()
            } else {
                "Success".to_string()
            }
        } else {
            "Unknown error".to_string()
        }
    }
}

/// A single test case for method invocation
#[derive(Debug, Clone)]
pub struct MethodTest {
    /// Method name to invoke
    pub method_name: String,
    /// Type name containing the method
    pub type_name: Option<String>,
    /// Arguments to pass (as C# literal strings)
    pub arguments: Vec<String>,
    /// Expected return value (as C# literal)
    pub expected_result: Option<String>,
    /// Description of this test
    pub description: Option<String>,
}

impl MethodTest {
    /// Create a new method test
    pub fn new(method_name: &str) -> Self {
        Self {
            method_name: method_name.to_string(),
            type_name: None,
            arguments: Vec::new(),
            expected_result: None,
            description: None,
        }
    }

    /// Set the type containing the method
    pub fn in_type(mut self, type_name: &str) -> Self {
        self.type_name = Some(type_name.to_string());
        self
    }

    /// Add an integer argument
    pub fn arg_int(mut self, value: i32) -> Self {
        self.arguments.push(value.to_string());
        self
    }

    /// Add a boolean argument
    pub fn arg_bool(mut self, value: bool) -> Self {
        self.arguments
            .push(if value { "true" } else { "false" }.to_string());
        self
    }

    /// Expect an integer result
    pub fn expect_int(mut self, value: i32) -> Self {
        self.expected_result = Some(value.to_string());
        self
    }

    /// Expect a boolean result
    pub fn expect_bool(mut self, value: bool) -> Self {
        self.expected_result = Some(if value { "true" } else { "false" }.to_string());
        self
    }

    /// Set a description
    pub fn describe(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }
}

/// Generate a reflection test program
pub fn generate_test_program(assembly_path: &Path, tests: &[MethodTest]) -> String {
    let assembly_path_str = assembly_path.to_string_lossy().replace('\\', "\\\\");

    let mut test_code = String::new();

    for (i, test) in tests.iter().enumerate() {
        let type_search = if let Some(ref type_name) = test.type_name {
            format!(
                r#"
            Type type{i} = null;
            foreach (Type t in assembly.GetTypes())
            {{
                if (t.Name == "{type_name}" || t.FullName == "{type_name}")
                {{
                    type{i} = t;
                    break;
                }}
            }}
            if (type{i} == null)
            {{
                Console.WriteLine("ERROR: Type '{type_name}' not found");
                Environment.Exit(1);
            }}"#
            )
        } else {
            format!(
                r#"
            Type type{i} = assembly.GetTypes()[0];"#
            )
        };

        let method_name = &test.method_name;
        let args_array = if test.arguments.is_empty() {
            "new object[0]".to_string()
        } else {
            format!("new object[] {{ {} }}", test.arguments.join(", "))
        };

        let result_check = if let Some(ref expected) = test.expected_result {
            format!(
                r#"
            if (!result{i}.Equals({expected}))
            {{
                Console.WriteLine("ERROR: Expected {expected}, got " + result{i});
                Environment.Exit(1);
            }}
            Console.WriteLine("PASS: {method_name} returned " + result{i});"#
            )
        } else {
            format!(
                r#"
            Console.WriteLine("PASS: {method_name} executed successfully");"#
            )
        };

        let description = test.description.as_deref().unwrap_or(method_name);

        test_code.push_str(&format!(r#"
            // Test {i}: {description}
            {type_search}
            MethodInfo method{i} = type{i}.GetMethod("{method_name}", BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance);
            if (method{i} == null)
            {{
                Console.WriteLine("ERROR: Method '{method_name}' not found");
                Environment.Exit(1);
            }}
            object result{i} = method{i}.Invoke(null, {args_array});
            {result_check}
"#));
    }

    format!(
        r#"using System;
using System.Reflection;

class Program
{{
    static void Main()
    {{
        try
        {{
            Assembly assembly = Assembly.LoadFile(@"{assembly_path_str}");
            {test_code}
            Console.WriteLine("All tests passed!");
        }}
        catch (Exception ex)
        {{
            Console.WriteLine("ERROR: " + ex.Message);
            if (ex.InnerException != null)
            {{
                Console.WriteLine("Inner: " + ex.InnerException.Message);
            }}
            Environment.Exit(1);
        }}
    }}
}}
"#
    )
}

/// Run a reflection test
pub fn run_reflection_test(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
    tests: &[MethodTest],
    output_dir: &Path,
    arch: &Architecture,
) -> Result<ReflectionTestResult> {
    // Generate test program
    let test_source = generate_test_program(assembly_path, tests);

    // Compile test harness
    let compile_result = compile(
        capabilities,
        &test_source,
        output_dir,
        "reflection_test",
        arch,
    )?;

    if !compile_result.is_success() {
        return Ok(ReflectionTestResult {
            success: false,
            execution: None,
            error: Some("Failed to compile reflection test harness".to_string()),
        });
    }

    // Execute test harness
    let exec_result = execute(capabilities, compile_result.assembly_path())?;

    if exec_result.is_success() {
        Ok(ReflectionTestResult::success(exec_result))
    } else {
        Ok(ReflectionTestResult {
            success: false,
            execution: Some(exec_result.clone()),
            error: Some(exec_result.error_summary()),
        })
    }
}

/// Simple reflection test that just tries to load an assembly and list its types
pub fn verify_assembly_loadable(
    capabilities: &TestCapabilities,
    assembly_path: &Path,
    output_dir: &Path,
    arch: &Architecture,
) -> Result<ReflectionTestResult> {
    let assembly_path_str = assembly_path.to_string_lossy().replace('\\', "\\\\");

    let test_source = format!(
        r#"using System;
using System.Reflection;

class Program
{{
    static void Main()
    {{
        try
        {{
            Assembly assembly = Assembly.LoadFile(@"{assembly_path_str}");
            Console.WriteLine("Assembly loaded: " + assembly.FullName);
            foreach (Type t in assembly.GetTypes())
            {{
                Console.WriteLine("  Type: " + t.FullName);
                foreach (MethodInfo m in t.GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                {{
                    Console.WriteLine("    Method: " + m.Name);
                }}
            }}
            Console.WriteLine("SUCCESS: Assembly is valid and loadable");
        }}
        catch (Exception ex)
        {{
            Console.WriteLine("ERROR: " + ex.Message);
            if (ex.InnerException != null)
            {{
                Console.WriteLine("Inner: " + ex.InnerException.Message);
            }}
            Environment.Exit(1);
        }}
    }}
}}
"#
    );

    // Compile test harness
    let compile_result = compile(capabilities, &test_source, output_dir, "verify_test", arch)?;

    if !compile_result.is_success() {
        return Ok(ReflectionTestResult {
            success: false,
            execution: None,
            error: Some("Failed to compile verification test".to_string()),
        });
    }

    // Execute test harness
    let exec_result = execute(capabilities, compile_result.assembly_path())?;

    if exec_result.is_success() {
        Ok(ReflectionTestResult::success(exec_result))
    } else {
        Ok(ReflectionTestResult {
            success: false,
            execution: Some(exec_result.clone()),
            error: Some(exec_result.error_summary()),
        })
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::testkit::{
        mono::compilation::templates,
        tools::{require_tool, ToolKind},
    };

    #[test]
    fn test_method_test_builder() {
        let test = MethodTest::new("Add")
            .in_type("TestClass")
            .arg_int(5)
            .arg_int(7)
            .expect_int(12)
            .describe("Test addition");

        assert_eq!(test.method_name, "Add");
        assert_eq!(test.type_name, Some("TestClass".to_string()));
        assert_eq!(test.arguments, vec!["5", "7"]);
        assert_eq!(test.expected_result, Some("12".to_string()));
    }

    #[test]
    fn test_generate_test_program() {
        let tests = vec![MethodTest::new("Add")
            .in_type("TestClass")
            .arg_int(1)
            .arg_int(2)
            .expect_int(3)];

        let source = generate_test_program(Path::new("/test/assembly.dll"), &tests);
        assert!(source.contains("Assembly.LoadFile"));
        assert!(source.contains("GetMethod"));
        assert!(source.contains("Add"));
    }

    #[test]
    fn test_reflection_on_simple_class() -> Result<()> {
        let Some(caps) = require_tool(ToolKind::Toolchain) else {
            return Ok(());
        };

        let temp_dir = TempDir::new()?;
        let arch = caps.supported_architectures.first().unwrap();

        // Compile the test assembly
        let assembly_result = compile(
            caps,
            templates::SIMPLE_CLASS,
            temp_dir.path(),
            "testasm",
            arch,
        )?;
        assert!(
            assembly_result.is_success(),
            "Failed to compile test assembly"
        );

        // Create reflection tests
        let tests = vec![MethodTest::new("Add")
            .in_type("TestClass")
            .arg_int(5)
            .arg_int(7)
            .expect_int(12)
            .describe("5 + 7 = 12")];

        // Run reflection test
        let result = run_reflection_test(
            caps,
            assembly_result.assembly_path(),
            &tests,
            temp_dir.path(),
            arch,
        )?;

        assert!(
            result.is_success(),
            "Reflection test failed: {}",
            result.error_summary()
        );

        Ok(())
    }
}
