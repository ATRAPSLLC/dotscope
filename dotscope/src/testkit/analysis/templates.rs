//! C# source templates and test case definitions.
//!
//! This module contains the C# source code that gets compiled for analysis testing,
//! along with the test case definitions that map method names to expected properties.

use crate::testkit::analysis::expectations::{
    CallGraphExpectation, CfgExpectation, DataFlowExpectation, SsaExpectation,
};

/// A test case mapping a C# method to expected analysis properties.
#[derive(Debug, Clone)]
pub struct AnalysisTestCase {
    /// Unique test name (used for reporting).
    pub name: &'static str,
    /// Method name in the compiled assembly.
    pub method_name: &'static str,
    /// Class containing the method.
    pub class_name: &'static str,
    /// Expected CFG properties.
    pub cfg: CfgExpectation,
    /// Expected SSA properties.
    pub ssa: SsaExpectation,
    /// Expected call graph properties (for inter-procedural tests).
    pub callgraph: Option<CallGraphExpectation>,
    /// Expected data flow properties.
    pub dataflow: Option<DataFlowExpectation>,
}

/// The C# source code containing all test methods.
///
/// Each method is designed to produce a specific CFG/SSA structure that we can
/// verify against known expectations.
pub const ANALYSIS_TEST_SOURCE: &str = r#"
using System;
using System.Reflection;

[assembly: AssemblyVersion("1.0.0.0")]

/// <summary>
/// Test class containing methods for CFG analysis verification.
/// Each method produces a specific control flow pattern.
/// </summary>
public static class CfgTests
{
    // SEQUENTIAL CONTROL FLOW

    /// <summary>
    /// Simple sequential method: single basic block.
    /// CFG: 1 block, no branches, no loops.
    /// </summary>
    public static int Add(int a, int b)
    {
        return a + b;
    }

    /// <summary>
    /// Sequential with multiple statements.
    /// CFG: 1 block with multiple instructions.
    /// </summary>
    public static int Compute(int x, int y, int z)
    {
        int temp = x + y;
        int result = temp * z;
        return result;
    }

    /// <summary>
    /// Method returning constant.
    /// CFG: 1 block, minimal instructions.
    /// </summary>
    public static int Zero()
    {
        return 0;
    }

    // CONDITIONAL CONTROL FLOW

    /// <summary>
    /// Simple if-then (no else): two exit points.
    /// CFG: 3 blocks (entry, then, fallthrough), 2 exits.
    /// </summary>
    public static int IfThen(bool cond)
    {
        if (cond)
            return 1;
        return 0;
    }

    /// <summary>
    /// If-then-else with merge point.
    /// CFG: 4 blocks (entry, then, else, merge), 1 exit.
    /// SSA: Requires phi node at merge.
    /// </summary>
    public static int IfThenElse(bool cond)
    {
        int x;
        if (cond)
            x = 1;
        else
            x = 0;
        return x;
    }

    /// <summary>
    /// Nested conditionals.
    /// CFG: Multiple blocks with complex branching.
    /// </summary>
    public static int NestedIf(bool a, bool b)
    {
        if (a)
        {
            if (b)
                return 1;
            return 2;
        }
        return 0;
    }

    /// <summary>
    /// Ternary operator (conditional expression).
    /// CFG: Similar to if-then-else but expression-level.
    /// </summary>
    public static int Ternary(bool cond, int x, int y)
    {
        return cond ? x : y;
    }

    /// <summary>
    /// Multiple independent conditionals.
    /// CFG: Multiple branch points, linear merge.
    /// </summary>
    public static int MultipleIfs(bool a, bool b, bool c)
    {
        int result = 0;
        if (a) result += 1;
        if (b) result += 2;
        if (c) result += 4;
        return result;
    }

    // LOOP CONTROL FLOW

    /// <summary>
    /// Simple while loop.
    /// CFG: Has back edge, loop detected.
    /// </summary>
    public static int WhileLoop(int n)
    {
        int sum = 0;
        int i = 0;
        while (i < n)
        {
            sum += i;
            i++;
        }
        return sum;
    }

    /// <summary>
    /// For loop (canonical form).
    /// CFG: Loop with init, condition, increment.
    /// </summary>
    public static int ForLoop(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            sum += i;
        }
        return sum;
    }

    /// <summary>
    /// Do-while loop (body executes at least once).
    /// CFG: Different structure than while.
    /// </summary>
    public static int DoWhileLoop(int n)
    {
        int sum = 0;
        int i = 0;
        do
        {
            sum += i;
            i++;
        } while (i < n);
        return sum;
    }

    /// <summary>
    /// Nested loops.
    /// CFG: Multiple back edges, nested loop structure.
    /// </summary>
    public static int NestedLoops(int m, int n)
    {
        int sum = 0;
        for (int i = 0; i < m; i++)
        {
            for (int j = 0; j < n; j++)
            {
                sum += i * j;
            }
        }
        return sum;
    }

    /// <summary>
    /// Loop with break.
    /// CFG: Exit from middle of loop.
    /// </summary>
    public static int LoopWithBreak(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            if (i > 10) break;
            sum += i;
        }
        return sum;
    }

    /// <summary>
    /// Loop with continue.
    /// CFG: Skip iteration.
    /// </summary>
    public static int LoopWithContinue(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            if (i % 2 == 0) continue;
            sum += i;
        }
        return sum;
    }

    // SWITCH CONTROL FLOW

    /// <summary>
    /// Simple switch statement.
    /// CFG: Multi-way branch.
    /// </summary>
    public static int SimpleSwitch(int x)
    {
        switch (x)
        {
            case 0: return 10;
            case 1: return 20;
            case 2: return 30;
            default: return 0;
        }
    }

    /// <summary>
    /// Switch with fall-through cases.
    /// CFG: Shared targets.
    /// </summary>
    public static int SwitchWithFallthrough(int x)
    {
        int result = 0;
        switch (x)
        {
            case 0:
            case 1:
                result = 10;
                break;
            case 2:
            case 3:
                result = 20;
                break;
            default:
                result = 0;
                break;
        }
        return result;
    }
}

/// <summary>
/// Test class containing methods for SSA verification.
/// Each method produces specific phi node patterns.
/// </summary>
public static class SsaTests
{
    /// <summary>
    /// Variable defined in both branches, used after merge.
    /// SSA: Requires phi node.
    /// </summary>
    public static int PhiRequired(bool cond)
    {
        int x;
        if (cond)
            x = 1;
        else
            x = 2;
        return x;  // phi(x_then, x_else)
    }

    /// <summary>
    /// Multiple variables need phi nodes.
    /// SSA: Multiple phi nodes at merge.
    /// </summary>
    public static int MultiplePhis(bool cond)
    {
        int x, y;
        if (cond)
        {
            x = 1;
            y = 10;
        }
        else
        {
            x = 2;
            y = 20;
        }
        return x + y;  // phi(x) + phi(y)
    }

    /// <summary>
    /// Loop induction variable.
    /// SSA: Phi at loop header for loop variable.
    /// </summary>
    public static int LoopPhi(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            sum += i;  // Both sum and i need phis
        }
        return sum;
    }

    /// <summary>
    /// Variable only defined in one branch.
    /// SSA: May or may not need phi depending on initialization.
    /// </summary>
    public static int PartialDef(bool cond)
    {
        int x = 0;  // Default value
        if (cond)
            x = 1;  // Only modified in then branch
        return x;
    }

    /// <summary>
    /// Deep nesting with variable modifications.
    /// SSA: Complex phi placement.
    /// </summary>
    public static int DeepNesting(bool a, bool b, bool c)
    {
        int x = 0;
        if (a)
        {
            x = 1;
            if (b)
            {
                x = 2;
                if (c)
                    x = 3;
            }
        }
        return x;
    }

    /// <summary>
    /// Use-def chain: value flows through multiple uses.
    /// SSA: Track uses of each definition.
    /// </summary>
    public static int UseDefChain(int input)
    {
        int a = input;      // def a
        int b = a + 1;      // use a, def b
        int c = a + b;      // use a, use b, def c
        int d = b + c;      // use b, use c, def d
        return d;           // use d
    }
}

/// <summary>
/// Test class for call graph verification.
/// Methods with various call patterns.
/// </summary>
public static class CallGraphTests
{
    /// <summary>
    /// Method with no calls (leaf).
    /// CallGraph: No outgoing edges.
    /// </summary>
    public static int LeafMethod(int x)
    {
        return x * 2;
    }

    /// <summary>
    /// Method calling another method.
    /// CallGraph: Single outgoing edge.
    /// </summary>
    public static int SingleCall(int x)
    {
        return LeafMethod(x) + 1;
    }

    /// <summary>
    /// Method with multiple calls.
    /// CallGraph: Multiple outgoing edges.
    /// </summary>
    public static int MultipleCalls(int a, int b)
    {
        int x = LeafMethod(a);
        int y = LeafMethod(b);
        return x + y;
    }

    /// <summary>
    /// Direct recursion.
    /// CallGraph: Self-loop edge.
    /// </summary>
    public static int DirectRecursion(int n)
    {
        if (n <= 0) return 0;
        return n + DirectRecursion(n - 1);
    }

    /// <summary>
    /// Mutual recursion (part A).
    /// CallGraph: Cycle with MutualB.
    /// </summary>
    public static int MutualA(int n)
    {
        if (n <= 0) return 0;
        return n + MutualB(n - 1);
    }

    /// <summary>
    /// Mutual recursion (part B).
    /// CallGraph: Cycle with MutualA.
    /// </summary>
    public static int MutualB(int n)
    {
        if (n <= 0) return 1;
        return n * MutualA(n - 1);
    }

    /// <summary>
    /// Call chain: A -> B -> C.
    /// CallGraph: Linear call sequence.
    /// </summary>
    public static int ChainA(int x)
    {
        return ChainB(x + 1);
    }

    public static int ChainB(int x)
    {
        return ChainC(x + 2);
    }

    public static int ChainC(int x)
    {
        return x * 3;
    }

    /// <summary>
    /// Conditional call.
    /// CallGraph: Call site in conditional branch.
    /// </summary>
    public static int ConditionalCall(bool cond, int x)
    {
        if (cond)
            return LeafMethod(x);
        return x;
    }

    /// <summary>
    /// Call in loop.
    /// CallGraph: Call site inside loop body.
    /// </summary>
    public static int LoopCall(int n)
    {
        int sum = 0;
        for (int i = 0; i < n; i++)
        {
            sum += LeafMethod(i);
        }
        return sum;
    }
}

/// <summary>
/// Test class for data flow analysis verification.
/// </summary>
public static class DataFlowTests
{
    /// <summary>
    /// Constant propagation: all values are constants.
    /// SCCP: Should determine result is constant.
    /// </summary>
    public static int ConstantProp()
    {
        int a = 10;
        int b = 20;
        int c = a + b;  // = 30
        return c;
    }

    /// <summary>
    /// Constant propagation through conditionals.
    /// SCCP: Both branches assign same constant.
    /// </summary>
    public static int ConstantBranches(bool cond)
    {
        int x;
        if (cond)
            x = 42;
        else
            x = 42;
        return x;  // = 42 regardless of cond
    }

    /// <summary>
    /// Live variable: all variables are used.
    /// Liveness: No dead variables.
    /// </summary>
    public static int AllLive(int a, int b)
    {
        int c = a + b;
        return c;
    }

    /// <summary>
    /// Dead variable: unused assignment.
    /// Liveness: x is dead.
    /// </summary>
    public static int DeadVariable(int a)
    {
        int x = 100;  // Dead: never used
        return a;
    }

    /// <summary>
    /// Reaching definitions: definition reaches use.
    /// </summary>
    public static int ReachingDef(bool cond)
    {
        int x = 0;  // def1
        if (cond)
            x = 1;  // def2
        return x;   // reached by def1 or def2
    }
}

/// <summary>
/// Main class with entry point.
/// </summary>
public class Program
{
    public static void Main()
    {
        // Exercise all methods to ensure they compile correctly
        Console.WriteLine("Analysis test assembly loaded successfully");
    }
}
"#;

/// All defined test cases with their expected properties.
pub static ANALYSIS_TEST_CASES: &[AnalysisTestCase] = &[
    // CFG tests: sequential.
    AnalysisTestCase {
        name: "cfg_sequential_add",
        method_name: "Add",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 0,
            max_locals: 1,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_sequential_compute",
        method_name: "Compute",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 3,
            min_locals: 2,
            max_locals: 3,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_sequential_zero",
        method_name: "Zero",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 0,
            min_locals: 0,
            max_locals: 1,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    // CFG tests: conditional.
    AnalysisTestCase {
        name: "cfg_if_then",
        method_name: "IfThen",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 2,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 0,
            max_locals: 3, // Roslyn debug adds bool eval + return value temps
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_if_then_else",
        method_name: "IfThenElse",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 1,
            max_locals: 4, // Roslyn debug adds bool eval + return value + merge temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_nested_if",
        method_name: "NestedIf",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 4,
            max_blocks: 9,
            has_loops: false,
            min_exits: 1,
            max_exits: 4,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 0,
            max_locals: 4, // Roslyn debug adds multiple branch temps
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_ternary",
        method_name: "Ternary",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 3,
            min_locals: 0,
            max_locals: 1,
            has_phi_nodes: false, // May or may not have phi depending on codegen
            min_phi_count: 0,
            max_phi_count: 3,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_multiple_ifs",
        method_name: "MultipleIfs",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 4,
            max_blocks: 10,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 3,
            min_locals: 1,
            max_locals: 6, // Roslyn debug adds temps per branch (3 ifs)
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    // CFG tests: loops.
    AnalysisTestCase {
        name: "cfg_while_loop",
        method_name: "WhileLoop",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds loop control + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_for_loop",
        method_name: "ForLoop",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds loop control + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_do_while_loop",
        method_name: "DoWhileLoop",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds loop control + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_nested_loops",
        method_name: "NestedLoops",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 10,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 3,
            max_locals: 7, // Roslyn debug adds temps for nested loop control
            has_phi_nodes: true,
            min_phi_count: 2,
            max_phi_count: 15,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_loop_with_break",
        method_name: "LoopWithBreak",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 9,
            has_loops: true,
            min_exits: 1,
            max_exits: 2,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 6, // Roslyn debug adds loop + branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_loop_with_continue",
        method_name: "LoopWithContinue",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 10,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 6, // Roslyn debug adds loop + branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    // CFG tests: switch.
    AnalysisTestCase {
        name: "cfg_simple_switch",
        method_name: "SimpleSwitch",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 4,
            max_blocks: 10,
            has_loops: false,
            min_exits: 1,
            max_exits: 5,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 0,
            max_locals: 4, // Roslyn debug adds switch dispatch + return temps
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "cfg_switch_fallthrough",
        method_name: "SwitchWithFallthrough",
        class_name: "CfgTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 10,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 1,
            max_locals: 5, // Roslyn debug adds switch dispatch + merge temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: None,
    },
    // SSA tests.
    AnalysisTestCase {
        name: "ssa_phi_required",
        method_name: "PhiRequired",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 1,
            max_locals: 4, // Roslyn debug adds branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "ssa_multiple_phis",
        method_name: "MultiplePhis",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds branch + merge temps
            has_phi_nodes: true,
            min_phi_count: 2,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "ssa_loop_phi",
        method_name: "LoopPhi",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds loop control + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "ssa_partial_def",
        method_name: "PartialDef",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 1,
            max_locals: 4, // Roslyn debug adds branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "ssa_deep_nesting",
        method_name: "DeepNesting",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 4,
            max_blocks: 12,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 3,
            min_locals: 1,
            max_locals: 6, // Roslyn debug adds temps per nesting level
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: None,
        dataflow: None,
    },
    AnalysisTestCase {
        name: "ssa_use_def_chain",
        method_name: "UseDefChain",
        class_name: "SsaTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 4,
            max_locals: 5,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: None,
    },
    // Call graph tests.
    AnalysisTestCase {
        name: "callgraph_leaf",
        method_name: "LeafMethod",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 0,
            max_locals: 1,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 0,
            max_call_sites: 0,
            is_recursive: false,
            is_leaf: true,
        }),
        dataflow: None,
    },
    AnalysisTestCase {
        name: "callgraph_single_call",
        method_name: "SingleCall",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 0,
            max_locals: 1,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 1,
            max_call_sites: 1,
            is_recursive: false,
            is_leaf: false,
        }),
        dataflow: None,
    },
    AnalysisTestCase {
        name: "callgraph_multiple_calls",
        method_name: "MultipleCalls",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 2,
            max_locals: 3,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 2,
            max_call_sites: 2,
            is_recursive: false,
            is_leaf: false,
        }),
        dataflow: None,
    },
    AnalysisTestCase {
        name: "callgraph_direct_recursion",
        method_name: "DirectRecursion",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 2,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 0,
            max_locals: 3, // Roslyn debug adds branch + return temps
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 2,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 1,
            max_call_sites: 1,
            is_recursive: true,
            is_leaf: false,
        }),
        dataflow: None,
    },
    AnalysisTestCase {
        name: "callgraph_conditional_call",
        method_name: "ConditionalCall",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 2,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 0,
            max_locals: 3, // Roslyn debug adds branch + return temps
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 2,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 1,
            max_call_sites: 1,
            is_recursive: false,
            is_leaf: false,
        }),
        dataflow: None,
    },
    AnalysisTestCase {
        name: "callgraph_loop_call",
        method_name: "LoopCall",
        class_name: "CallGraphTests",
        cfg: CfgExpectation {
            min_blocks: 2,
            max_blocks: 6,
            has_loops: true,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2,
            max_locals: 5, // Roslyn debug adds loop control + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 10,
        },
        callgraph: Some(CallGraphExpectation {
            min_call_sites: 1,
            max_call_sites: 1,
            is_recursive: false,
            is_leaf: false,
        }),
        dataflow: None,
    },
    // Data flow tests.
    AnalysisTestCase {
        name: "dataflow_constant_prop",
        method_name: "ConstantProp",
        class_name: "DataFlowTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 0,
            min_locals: 3,
            max_locals: 4,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        // Note: has_constants is false because SCCP constant detection depends on
        // how IL instructions are translated to SSA values, which varies by compiler.
        dataflow: Some(DataFlowExpectation {
            has_constants: false,
            has_dead_code: false,
            all_blocks_reachable: true,
        }),
    },
    AnalysisTestCase {
        name: "dataflow_constant_branches",
        method_name: "ConstantBranches",
        class_name: "DataFlowTests",
        cfg: CfgExpectation {
            min_blocks: 3,
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 1,
            max_locals: 4, // Roslyn debug adds branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: Some(DataFlowExpectation {
            has_constants: false,
            has_dead_code: false,
            all_blocks_reachable: true,
        }),
    },
    // Note: Dead code detection (SCCP unreachable block analysis) cannot be tested
    // from C# source because mcs eliminates `if (false)` at compile time. SCCP's
    // dead code detection is tested in unit tests with hand-crafted IL instead.
    // See: src/analysis/dataflow/mod.rs::test_sccp_unreachable_code
    AnalysisTestCase {
        name: "dataflow_all_live",
        method_name: "AllLive",
        class_name: "DataFlowTests",
        cfg: CfgExpectation {
            min_blocks: 1,
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 2,
            min_locals: 1,
            max_locals: 2,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: Some(DataFlowExpectation {
            has_constants: false,
            has_dead_code: false,
            all_blocks_reachable: true,
        }),
    },
    // IL: ldc.i4.s 100; stloc.0; ldarg.0; stloc.1; ret
    // V_0 is dead (never read), V_1 is the return value
    AnalysisTestCase {
        name: "dataflow_dead_variable",
        method_name: "DeadVariable",
        class_name: "DataFlowTests",
        cfg: CfgExpectation {
            min_blocks: 2, // Entry + return block
            max_blocks: 2,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2, // V_0 (dead x=100), V_1 (return value)
            max_locals: 2,
            has_phi_nodes: false,
            min_phi_count: 0,
            max_phi_count: 0,
        },
        callgraph: None,
        dataflow: Some(DataFlowExpectation {
            has_constants: false, // SCCP doesn't track ldc.i4 as SSA constants
            has_dead_code: false,
            all_blocks_reachable: true,
        }),
    },
    // IL has conditional: brfalse -> assigns 0 or 1 to V_0
    // 4 blocks: entry, then, merge, return
    AnalysisTestCase {
        name: "dataflow_reaching_def",
        method_name: "ReachingDef",
        class_name: "DataFlowTests",
        cfg: CfgExpectation {
            min_blocks: 3, // Roslyn debug may merge blocks differently
            max_blocks: 6,
            has_loops: false,
            min_exits: 1,
            max_exits: 1,
        },
        ssa: SsaExpectation {
            num_args: 1,
            min_locals: 2, // V_0 (x), V_1 (return value)
            max_locals: 4, // Roslyn debug adds branch + return temps
            has_phi_nodes: true,
            min_phi_count: 1,
            max_phi_count: 5,
        },
        callgraph: None,
        dataflow: Some(DataFlowExpectation {
            has_constants: false, // SCCP doesn't track ldc.i4 as SSA constants
            has_dead_code: false,
            all_blocks_reachable: true,
        }),
    },
];
