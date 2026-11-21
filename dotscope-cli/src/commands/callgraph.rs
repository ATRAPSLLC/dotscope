use std::{collections::HashSet, path::Path};

use anyhow::{bail, Context};
use dotscope::{analysis::CallGraph, metadata::token::Token, CilObject};
use serde::Serialize;

use crate::{
    commands::{
        common::load_assembly,
        resolution::{parse_token_filter, resolve_single_method},
    },
    output::{Align, TabWriter},
};

#[derive(Debug, Serialize)]
struct CgNodeOutput {
    token: String,
    name: String,
    callees: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CallGraphOutput {
    method_count: usize,
    edge_count: usize,
    entry_points: Vec<String>,
    recursive_methods: Vec<String>,
    nodes: Vec<CgNodeOutput>,
}

pub fn run(
    path: &Path,
    format: &str,
    root: Option<&str>,
    depth: Option<usize>,
) -> anyhow::Result<()> {
    let assembly = load_assembly(path)?;

    let (cg, root_token) = if let Some(root_filter) = root {
        let token = resolve_root_token(&assembly, root_filter)?;
        let cg = CallGraph::build_from_roots(&assembly, &[token])
            .context("failed to build call graph from root")?;
        (cg, Some(token))
    } else {
        let cg = CallGraph::build(&assembly).context("failed to build call graph")?;
        (cg, None)
    };

    let assembly_name = assembly
        .assembly()
        .map_or_else(|| "unknown".to_string(), |a| a.name.to_string());

    match format {
        "json" => {
            let stats = cg.stats();
            let entry_points = cg.entry_points();
            let recursive = cg.recursive_methods();

            let show_tokens: Option<HashSet<Token>> =
                if let (Some(root_token), Some(max_depth)) = (root_token, depth) {
                    Some(bfs_reachable(&cg, root_token, max_depth))
                } else {
                    None
                };

            let mut nodes = Vec::new();
            for node in cg.nodes() {
                if let Some(ref allowed) = show_tokens {
                    if !allowed.contains(&node.token) {
                        continue;
                    }
                }

                let callees: Vec<String> = cg
                    .callees(node.token)
                    .iter()
                    .map(|t| node_label(&cg, *t))
                    .collect();

                nodes.push(CgNodeOutput {
                    token: format!("0x{:08X}", node.token.value()),
                    name: node.full_name.clone(),
                    callees,
                });
            }

            let output = CallGraphOutput {
                method_count: stats.method_count,
                edge_count: stats.edge_count,
                entry_points: entry_points.iter().map(|t| node_label(&cg, *t)).collect(),
                recursive_methods: recursive.iter().map(|t| node_label(&cg, *t)).collect(),
                nodes,
            };

            let json = serde_json::to_string_pretty(&output)?;
            println!("{json}");
        }
        "dot" => {
            if let (Some(root_token), Some(max_depth)) = (root_token, depth) {
                let reachable = bfs_reachable(&cg, root_token, max_depth);
                print_filtered_dot(&cg, &assembly_name, &reachable);
            } else {
                println!("{}", cg.to_dot(Some(&assembly_name)));
            }
        }
        "text" => {
            let stats = cg.stats();
            let entry_points = cg.entry_points();
            let recursive = cg.recursive_methods();

            let entry_names: Vec<String> =
                entry_points.iter().map(|t| node_label(&cg, *t)).collect();

            println!(
                "Call graph: {} methods, {} edges",
                stats.method_count, stats.edge_count
            );
            println!(
                "Entry points: {}",
                if entry_names.is_empty() {
                    "none".to_string()
                } else {
                    entry_names.join(", ")
                }
            );
            println!(
                "Recursive methods: {}",
                if recursive.is_empty() {
                    "none".to_string()
                } else {
                    recursive
                        .iter()
                        .map(|t| node_label(&cg, *t))
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            );
            println!();

            // Determine which methods to show
            let show_tokens: Option<HashSet<Token>> =
                if let (Some(root_token), Some(max_depth)) = (root_token, depth) {
                    Some(bfs_reachable(&cg, root_token, max_depth))
                } else {
                    None
                };

            let mut tw = TabWriter::new(&[("Method", Align::Left), ("Callees", Align::Left)]);

            for node in cg.nodes() {
                if let Some(ref allowed) = show_tokens {
                    if !allowed.contains(&node.token) {
                        continue;
                    }
                }

                let callees = cg.callees(node.token);
                let callee_names: Vec<String> =
                    callees.iter().map(|t| node_label(&cg, *t)).collect();

                let callee_str = if callee_names.is_empty() {
                    "(leaf)".to_string()
                } else {
                    callee_names.join(", ")
                };

                tw.row(vec![
                    format!("{} (0x{:08X})", node.full_name, node.token.value()),
                    callee_str,
                ]);
            }

            tw.print();
        }
        other => bail!("unsupported format '{other}'; expected 'text', 'dot', or 'json'"),
    }

    Ok(())
}

/// Resolve a root filter to a single token.
fn resolve_root_token(assembly: &CilObject, filter: &str) -> anyhow::Result<Token> {
    if let Some(token) = parse_token_filter(filter) {
        return Ok(token);
    }
    let method = resolve_single_method(assembly, filter)?;
    Ok(method.token)
}

/// BFS from `root` up to `max_depth` hops, returning the set of reachable tokens.
fn bfs_reachable(cg: &CallGraph, root: Token, max_depth: usize) -> HashSet<Token> {
    let mut visited = HashSet::new();
    let mut frontier = vec![root];
    visited.insert(root);

    for _ in 0..max_depth {
        let mut next_frontier = Vec::new();
        for token in &frontier {
            for callee in cg.callees(*token) {
                if visited.insert(callee) {
                    next_frontier.push(callee);
                }
            }
        }
        if next_frontier.is_empty() {
            break;
        }
        frontier = next_frontier;
    }

    visited
}

/// Short label for a call-graph node.
fn node_label(cg: &CallGraph, token: Token) -> String {
    cg.node(token).map_or_else(
        || format!("0x{:08X}", token.value()),
        |n| n.full_name.clone(),
    )
}

/// Emit a DOT graph limited to the given token set.
fn print_filtered_dot(cg: &CallGraph, title: &str, reachable: &HashSet<Token>) {
    println!("digraph \"{}\" {{", title.replace('"', "\\\""));
    println!("  rankdir=LR;");
    println!("  node [shape=box, style=filled, fillcolor=lightyellow];");

    for node in cg.nodes() {
        if !reachable.contains(&node.token) {
            continue;
        }
        let label = node.full_name.replace('"', "\\\"");
        println!("  \"0x{:08X}\" [label=\"{}\"];", node.token.value(), label);
    }

    for node in cg.nodes() {
        if !reachable.contains(&node.token) {
            continue;
        }
        for callee in cg.callees(node.token) {
            if reachable.contains(&callee) {
                println!(
                    "  \"0x{:08X}\" -> \"0x{:08X}\";",
                    node.token.value(),
                    callee.value()
                );
            }
        }
    }

    println!("}}");
}
