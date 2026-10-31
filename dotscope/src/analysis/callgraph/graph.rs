//! Call graph construction and representation.
//!
//! This module provides the main [`CallGraph`] structure which represents
//! the inter-procedural call relationships in a .NET assembly. The call graph
//! is constructed by scanning all method bodies for call instructions and
//! resolving their targets using assembly metadata and Class Hierarchy Analysis.
//!
//! The implementation leverages generic graph infrastructure, providing access
//! to standard graph algorithms.

use std::{
    collections::{HashMap, HashSet},
    fmt::Write,
    sync::OnceLock,
};

use analyssa::graph::{
    algorithms::{self, strongly_connected_components},
    DirectedGraph, NodeId,
};

use crate::{
    analysis::callgraph::{CallGraphNode, CallResolver, CallSite, CallTarget, CallType},
    assembly::{Instruction, Operand},
    metadata::{
        method::Method,
        tables::MemberRefSignature,
        token::Token,
        typesystem::{CilTypeReference, TypeRegistry},
    },
    utils::escape_dot,
    CilObject, Result,
};

/// Inter-procedural call graph for a .NET assembly.
///
/// The call graph captures method-to-method call relationships, enabling
/// inter-procedural analysis such as dead code detection, call chain analysis,
/// and optimization.
///
/// This implementation uses generic graph infrastructure, providing access
/// to standard graph algorithms like SCC computation, topological sorting,
/// and traversal.
///
/// # Example
///
/// ```no_run
/// let assembly = CilObject::open("sample.dll")?;
/// let call_graph = CallGraph::build(&assembly)?;
///
/// // Get statistics about the call graph
/// let stats = call_graph.stats();
/// println!("Methods: {}, Edges: {}", stats.method_count, stats.edge_count);
///
/// // Find methods called by a specific method
/// let callees = call_graph.callees(method_token);
/// # Ok::<(), dotscope::Error>(())
/// ```
#[derive(Debug)]
pub struct CallGraph {
    /// The underlying directed graph: nodes are method metadata, edges are call relationships.
    graph: DirectedGraph<'static, CallGraphNode, CallType>,
    /// Map from method token to node ID in the graph for O(1) lookup.
    token_to_node: HashMap<Token, NodeId>,
    /// Call resolver for virtual dispatch and type hierarchy queries.
    resolver: CallResolver,
    /// Strongly connected components (lazily computed on first access).
    sccs: OnceLock<Vec<Vec<NodeId>>>,
    /// Topological order of methods (lazily computed on first access).
    topo_order: OnceLock<Vec<Token>>,
    /// Entry points - methods with no callers (lazily computed on first access).
    entry_points: OnceLock<Vec<Token>>,
}

impl CallGraph {
    /// Creates an empty call graph.
    ///
    /// This is useful for testing or when a call graph is needed but no assembly
    /// analysis has been performed yet.
    ///
    /// # Returns
    ///
    /// An empty `CallGraph` with no methods or call edges.
    #[must_use]
    pub fn new() -> Self {
        Self {
            graph: DirectedGraph::new(),
            token_to_node: HashMap::new(),
            resolver: CallResolver::empty(),
            sccs: OnceLock::new(),
            topo_order: OnceLock::new(),
            entry_points: OnceLock::new(),
        }
    }

    /// Builds a call graph from an assembly.
    ///
    /// This method performs a two-pass construction:
    /// 1. First pass: Creates a node for each method in the assembly
    /// 2. Second pass: Scans method bodies for call instructions and creates edges
    ///
    /// Virtual calls are resolved using Class Hierarchy Analysis (CHA) to determine
    /// all possible runtime targets.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to build the call graph from
    ///
    /// # Returns
    ///
    /// A new [`CallGraph`] instance representing the inter-procedural call relationships.
    ///
    /// # Errors
    ///
    /// Returns an error if method body parsing fails during call site extraction.
    pub fn build(assembly: &CilObject) -> Result<Self> {
        let resolver = CallResolver::new(assembly);
        let methods = assembly.methods();
        let method_count = methods.len();
        let types = assembly.types();

        let mut graph: DirectedGraph<CallGraphNode, CallType> =
            DirectedGraph::with_capacity(method_count, method_count.saturating_mul(4));
        let mut token_to_node: HashMap<Token, NodeId> = HashMap::with_capacity(method_count);

        // First pass: add all internal methods as nodes
        for entry in methods {
            let method = entry.value();
            let full_name =
                Self::get_method_full_name(&types, &resolver, method.token, &method.name);
            let node = Self::create_node(method, full_name);
            let node_id = graph.add_node(node);
            token_to_node.insert(method.token, node_id);
        }

        // Second pass: extract call sites and build edges
        for entry in methods {
            let method = entry.value();
            let caller_token = method.token;

            let Some(&caller_node_id) = token_to_node.get(&caller_token) else {
                continue;
            };

            // Skip methods without bodies
            let Some(caller_node) = graph.node(caller_node_id) else {
                continue;
            };
            if caller_node.is_abstract || caller_node.is_external {
                continue;
            }

            // Extract call sites from the method body
            let call_sites = Self::extract_call_sites(assembly, method, &resolver);

            // Build edges for each call site
            for site in &call_sites {
                for callee_token in site.target.all_targets() {
                    // Check if target already exists
                    let callee_node_id = if let Some(&node_id) = token_to_node.get(&callee_token) {
                        node_id
                    } else {
                        // External reference - create node for it
                        if let Some(node) =
                            Self::create_external_node(assembly, &resolver, callee_token)
                        {
                            let node_id = graph.add_node(node);
                            token_to_node.insert(callee_token, node_id);
                            node_id
                        } else {
                            continue;
                        }
                    };

                    // Add edge from caller to callee
                    let _ = graph.add_edge(caller_node_id, callee_node_id, site.call_type);
                }
            }

            // Store call sites in the node
            if let Some(node) = graph.node_mut(caller_node_id) {
                node.call_sites = call_sites;
            }
        }

        Ok(Self {
            graph,
            token_to_node,
            resolver,
            sccs: OnceLock::new(),
            topo_order: OnceLock::new(),
            entry_points: OnceLock::new(),
        })
    }

    /// Builds a call graph starting from the assembly's entry point.
    ///
    /// Unlike [`Self::build`], this method only includes methods that are reachable
    /// from the assembly's entry point (typically `Main`). This produces a
    /// cleaner graph focused on the actual execution paths rather than
    /// including every method in the assembly.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to build the call graph from
    ///
    /// # Returns
    ///
    /// A new [`CallGraph`] instance containing only reachable methods,
    /// or `None` if the assembly has no entry point (e.g., a library).
    ///
    /// # Errors
    ///
    /// Returns an error if method body parsing fails during call site extraction.
    pub fn build_from_entrypoint(assembly: &CilObject) -> Result<Option<Self>> {
        let entry_point_token = assembly.cor20header().entry_point_token;
        if entry_point_token == 0 {
            return Ok(None);
        }

        let entry_token = Token::new(entry_point_token);
        Self::build_from_roots(assembly, &[entry_token]).map(Some)
    }

    /// Builds a call graph starting from specified root methods.
    ///
    /// This method performs a traversal starting from the given root tokens,
    /// only including methods that are reachable from those roots. This is
    /// useful for analyzing specific code paths or building focused call graphs.
    ///
    /// # Arguments
    ///
    /// * `assembly` - The assembly to build the call graph from
    /// * `roots` - The method tokens to start traversal from
    ///
    /// # Returns
    ///
    /// A new [`CallGraph`] instance containing only reachable methods.
    ///
    /// # Errors
    ///
    /// Returns an error if method body parsing fails during call site extraction.
    pub fn build_from_roots(assembly: &CilObject, roots: &[Token]) -> Result<Self> {
        let resolver = CallResolver::new(assembly);
        let methods = assembly.methods();
        let types = assembly.types();

        let mut graph: DirectedGraph<CallGraphNode, CallType> = DirectedGraph::new();
        let mut token_to_node: HashMap<Token, NodeId> = HashMap::new();

        // Worklist for BFS traversal
        let mut worklist: Vec<Token> = roots.to_vec();
        let mut visited: HashSet<Token> = HashSet::new();

        while let Some(current_token) = worklist.pop() {
            if !visited.insert(current_token) {
                continue;
            }

            // Try to get the method - could be internal (MethodDef) or external (MemberRef/MethodSpec)
            let table_id = current_token.table();

            if table_id == 0x06 {
                // MethodDef - internal method
                if let Some(method_entry) = methods.get(&current_token) {
                    let method = method_entry.value();
                    let full_name =
                        Self::get_method_full_name(&types, &resolver, method.token, &method.name);
                    let mut node = Self::create_node(method, full_name);

                    // Extract call sites if method has a body
                    if !node.is_abstract && !node.is_external {
                        let call_sites = Self::extract_call_sites(assembly, method, &resolver);

                        // Add callees to worklist
                        for site in &call_sites {
                            for callee_token in site.target.all_targets() {
                                if !visited.contains(&callee_token) {
                                    worklist.push(callee_token);
                                }
                            }
                        }

                        node.call_sites = call_sites;
                    }

                    let node_id = graph.add_node(node);
                    token_to_node.insert(current_token, node_id);
                }
            } else if table_id == 0x0A || table_id == 0x2B {
                // MemberRef or MethodSpec - external reference
                if let Some(node) = Self::create_external_node(assembly, &resolver, current_token) {
                    let node_id = graph.add_node(node);
                    token_to_node.insert(current_token, node_id);
                }
            }
        }

        // Second pass: collect edges first, then add them
        let edges_to_add: Vec<(NodeId, NodeId, CallType)> = token_to_node
            .values()
            .filter_map(|&node_id| {
                graph.node(node_id).map(|node| {
                    node.callees()
                        .into_iter()
                        .filter_map(|callee_token| {
                            token_to_node.get(&callee_token).map(|&callee_node_id| {
                                let call_type = node
                                    .call_sites
                                    .iter()
                                    .find(|s| s.target.all_targets().contains(&callee_token))
                                    .map_or(CallType::Call, |s| s.call_type);
                                (node_id, callee_node_id, call_type)
                            })
                        })
                        .collect::<Vec<_>>()
                })
            })
            .flatten()
            .collect();

        for (from, to, call_type) in edges_to_add {
            let _ = graph.add_edge(from, to, call_type);
        }

        Ok(Self {
            graph,
            token_to_node,
            resolver,
            sccs: OnceLock::new(),
            topo_order: OnceLock::new(),
            entry_points: OnceLock::new(),
        })
    }

    /// Creates a call graph node from a method.
    fn create_node(method: &Method, full_name: String) -> CallGraphNode {
        let mut node = CallGraphNode::new(
            method.token,
            method.name.clone(),
            full_name,
            method.signature.to_string(),
        );

        node.is_virtual = method.is_virtual();
        node.is_abstract = method.is_abstract();
        node.is_static = method.is_static();
        node.is_external = method.is_pinvoke() || method.is_internal_call();
        node.is_constructor = method.is_constructor();

        // Get override information if available (use first entry)
        if let Some((_, first_override)) = method.overrides.iter().next() {
            node.overrides = first_override.token();
        }

        node
    }

    /// Computes the full qualified name for a method.
    ///
    /// For internal methods (MethodDef), the full name includes the declaring type's
    /// namespace and name. For external methods, only the method name is returned.
    fn get_method_full_name(
        types: &TypeRegistry,
        resolver: &CallResolver,
        method_token: Token,
        method_name: &str,
    ) -> String {
        // Try to get declaring type from the resolver
        if let Some(type_token) = resolver.declaring_type(method_token) {
            if let Some(type_info) = types.get(&type_token) {
                return format!("{}::{method_name}", type_info.fullname());
            }
        }
        // Fallback to just the method name
        method_name.to_string()
    }

    /// Creates a call graph node for an external method reference (MemberRef or MethodSpec).
    fn create_external_node(
        assembly: &CilObject,
        resolver: &CallResolver,
        callee_token: Token,
    ) -> Option<CallGraphNode> {
        let table_id = callee_token.table();

        match table_id {
            // MemberRef table (0x0A)
            0x0A => {
                let refs = assembly.refs_members();
                if let Some(member_ref) = refs.get(&callee_token) {
                    let member_ref = member_ref.value();

                    // Get the declaring type name
                    let type_name = Self::get_external_type_name(&member_ref.declaredby);
                    let full_name = if type_name.is_empty() {
                        member_ref.name.clone()
                    } else {
                        format!("{}::{}", type_name, member_ref.name)
                    };

                    let signature = match &member_ref.signature {
                        MemberRefSignature::Method(sig) => sig.to_string(),
                        MemberRefSignature::Field(_) => String::new(),
                    };

                    let mut node = CallGraphNode::new(
                        callee_token,
                        member_ref.name.clone(),
                        full_name,
                        signature,
                    );
                    node.is_external_ref = true;
                    node.is_constructor = member_ref.is_constructor();
                    return Some(node);
                }
            }
            // MethodSpec table (0x2B)
            0x2B => {
                let specs = assembly.method_specs();
                if let Some(method_spec) = specs.get(&callee_token) {
                    let method_spec = method_spec.value();

                    // Get information from the underlying method
                    let (name, full_name, signature, is_constructor) =
                        Self::get_method_spec_info(assembly, resolver, &method_spec.method);

                    let mut node = CallGraphNode::new(callee_token, name, full_name, signature);
                    node.is_external_ref = true;
                    node.is_constructor = is_constructor;
                    return Some(node);
                }
            }
            _ => {}
        }

        None
    }

    /// Gets the type name from a CilTypeReference for external references.
    fn get_external_type_name(type_ref: &CilTypeReference) -> String {
        match type_ref {
            CilTypeReference::TypeRef(t)
            | CilTypeReference::TypeDef(t)
            | CilTypeReference::TypeSpec(t) => t.fullname().unwrap_or_default(),
            CilTypeReference::MemberRef(mr) => {
                // For MemberRef as parent, recurse to get its declaring type
                Self::get_external_type_name(&mr.declaredby)
            }
            CilTypeReference::ModuleRef(m) => m.name.clone(),
            _ => String::new(),
        }
    }

    /// Gets method information from a MethodSpec's underlying method reference.
    fn get_method_spec_info(
        assembly: &CilObject,
        resolver: &CallResolver,
        method_ref: &CilTypeReference,
    ) -> (String, String, String, bool) {
        match method_ref {
            CilTypeReference::MethodDef(mr) => {
                if let Some(method) = mr.upgrade() {
                    let types = assembly.types();
                    let full_name =
                        Self::get_method_full_name(&types, resolver, method.token, &method.name);
                    (
                        method.name.clone(),
                        full_name,
                        method.signature.to_string(),
                        method.is_constructor(),
                    )
                } else {
                    (
                        "unknown".to_string(),
                        "unknown".to_string(),
                        String::new(),
                        false,
                    )
                }
            }
            CilTypeReference::MemberRef(mr) => {
                let type_name = Self::get_external_type_name(&mr.declaredby);
                let full_name = if type_name.is_empty() {
                    mr.name.clone()
                } else {
                    format!("{}::{}", type_name, mr.name)
                };
                let signature = match &mr.signature {
                    MemberRefSignature::Method(sig) => sig.to_string(),
                    MemberRefSignature::Field(_) => String::new(),
                };
                (mr.name.clone(), full_name, signature, mr.is_constructor())
            }
            _ => (
                "unknown".to_string(),
                "unknown".to_string(),
                String::new(),
                false,
            ),
        }
    }

    /// Extracts call sites from a method body.
    fn extract_call_sites(
        assembly: &CilObject,
        method: &Method,
        resolver: &CallResolver,
    ) -> Vec<CallSite> {
        let mut call_sites = Vec::new();

        // Get method instructions - instructions() returns an iterator directly
        let instructions = method.instructions();

        for instr in instructions {
            if let Some((call_type, target)) = Self::analyze_instruction(assembly, resolver, instr)
            {
                // Safe cast: instruction offsets in CIL are at most 32 bits
                let offset = u32::try_from(instr.offset).unwrap_or(u32::MAX);
                let site = CallSite::new(offset, call_type, target);
                call_sites.push(site);
            }
        }

        call_sites
    }

    /// Analyzes an instruction to determine if it's a call and extract target.
    fn analyze_instruction(
        assembly: &CilObject,
        resolver: &CallResolver,
        instr: &Instruction,
    ) -> Option<(CallType, CallTarget)> {
        let (call_type, token) = match instr.mnemonic {
            "call" => (CallType::Call, Self::extract_method_token(instr)?),
            "callvirt" => (CallType::CallVirt, Self::extract_method_token(instr)?),
            "newobj" => (CallType::NewObj, Self::extract_method_token(instr)?),
            "ldftn" => (CallType::Ldftn, Self::extract_method_token(instr)?),
            "ldvirtftn" => (CallType::LdVirtFtn, Self::extract_method_token(instr)?),
            "calli" => return Some((CallType::Calli, CallTarget::Indirect)),
            // "tail." is a prefix handled with next instruction, fall through to default
            _ => return None,
        };

        // Resolve the target
        let target = Self::resolve_target(assembly, resolver, call_type, token);
        Some((call_type, target))
    }

    /// Extracts the method token from an instruction operand.
    fn extract_method_token(instr: &Instruction) -> Option<Token> {
        match &instr.operand {
            Operand::Token(token) => Some(*token),
            _ => None,
        }
    }

    /// Resolves a call target from a token.
    fn resolve_target(
        assembly: &CilObject,
        resolver: &CallResolver,
        call_type: CallType,
        token: Token,
    ) -> CallTarget {
        // A MemberRef or MethodSpec naming a method of this assembly calls that method: a
        // generic method's instantiation, or a method of a generic type, is called through one.
        let token = assembly.resolver().resolve_method(token).unwrap_or(token);
        if assembly.methods().contains_key(&token) {
            if call_type.is_virtual() {
                // Virtual call - use CHA
                let possible_targets = resolver.resolve_virtual(token);
                if possible_targets.len() > 1 {
                    CallTarget::Virtual {
                        declared: token,
                        possible_targets,
                    }
                } else {
                    CallTarget::Resolved(token)
                }
            } else {
                CallTarget::Resolved(token)
            }
        } else {
            // External reference
            CallTarget::Unresolved {
                token,
                reason: "External method reference".to_string(),
            }
        }
    }

    /// Returns the number of methods in the call graph.
    ///
    /// # Returns
    ///
    /// The total count of method nodes in the graph.
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.graph.node_count()
    }

    /// Returns the total number of call edges.
    ///
    /// Note that multiple calls from the same caller to the same callee
    /// are represented as a single edge.
    ///
    /// # Returns
    ///
    /// The total count of call edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.graph.edge_count()
    }

    /// Returns a node by its method token.
    ///
    /// # Arguments
    ///
    /// * `token` - The method token to look up
    ///
    /// # Returns
    ///
    /// A reference to the [`CallGraphNode`] if found, or `None` if the
    /// token does not correspond to a method in this call graph.
    #[must_use]
    pub fn node(&self, token: Token) -> Option<&CallGraphNode> {
        self.token_to_node
            .get(&token)
            .and_then(|&node_id| self.graph.node(node_id))
    }

    /// Returns an iterator over all nodes in the call graph.
    ///
    /// # Returns
    ///
    /// An iterator yielding references to all [`CallGraphNode`] instances.
    pub fn nodes(&self) -> impl Iterator<Item = &CallGraphNode> {
        self.graph.nodes().map(|(_, node)| node)
    }

    /// Returns all method tokens that are called by the given method.
    ///
    /// # Arguments
    ///
    /// * `caller` - The token of the calling method
    ///
    /// # Returns
    ///
    /// A vector of method tokens for all methods called by the specified method.
    /// Returns an empty vector if the caller is not found in the graph.
    #[must_use]
    pub fn callees(&self, caller: Token) -> Vec<Token> {
        let Some(&node_id) = self.token_to_node.get(&caller) else {
            return Vec::new();
        };

        self.graph
            .successors(node_id)
            .filter_map(|callee_id| self.graph.node(callee_id).map(|n| n.token))
            .collect()
    }

    /// Returns all method tokens that call the given method.
    ///
    /// # Arguments
    ///
    /// * `callee` - The token of the called method
    ///
    /// # Returns
    ///
    /// A vector of method tokens for all methods that call the specified method.
    /// Returns an empty vector if the callee is not found in the graph.
    #[must_use]
    pub fn callers(&self, callee: Token) -> Vec<Token> {
        let Some(&node_id) = self.token_to_node.get(&callee) else {
            return Vec::new();
        };

        self.graph
            .predecessors(node_id)
            .filter_map(|caller_id| self.graph.node(caller_id).map(|n| n.token))
            .collect()
    }

    /// Returns all call sites within a method.
    ///
    /// # Arguments
    ///
    /// * `method` - The token of the method to get call sites for
    ///
    /// # Returns
    ///
    /// A slice of [`CallSite`] instances representing all call instructions
    /// within the method body. Returns an empty slice if the method is not
    /// found or has no call sites.
    #[must_use]
    pub fn call_sites(&self, method: Token) -> &[CallSite] {
        self.node(method).map_or(&[], |n| n.call_sites.as_slice())
    }

    /// Returns entry points (methods with no callers within the assembly).
    ///
    /// Entry points are methods that are not called by any other method in
    /// the assembly. This typically includes `Main` methods, event handlers,
    /// and externally-invoked methods.
    ///
    /// # Returns
    ///
    /// A slice of method tokens for all entry point methods.
    #[must_use]
    pub fn entry_points(&self) -> &[Token] {
        self.entry_points.get_or_init(|| {
            self.graph
                .entry_nodes()
                .filter_map(|node_id| self.graph.node(node_id).map(|n| n.token))
                .collect()
        })
    }

    /// Returns leaf methods (methods with no callees).
    ///
    /// Leaf methods are terminal nodes in the call graph that do not call
    /// any other methods within the assembly.
    ///
    /// # Returns
    ///
    /// A vector of method tokens for all leaf methods.
    #[must_use]
    pub fn leaf_methods(&self) -> Vec<Token> {
        self.graph
            .exit_nodes()
            .filter_map(|node_id| self.graph.node(node_id).map(|n| n.token))
            .collect()
    }

    /// Returns the strongly connected components of the call graph.
    ///
    /// Each SCC is a set of methods that are mutually recursive - every method
    /// in the SCC can reach every other method in the same SCC through calls.
    /// SCCs are returned in reverse topological order (leaves first).
    ///
    /// The result is lazily computed and cached on first access.
    ///
    /// # Returns
    ///
    /// A slice of SCCs, where each SCC is a vector of node IDs.
    #[must_use]
    pub fn sccs(&self) -> &[Vec<NodeId>] {
        self.sccs
            .get_or_init(|| strongly_connected_components(&self.graph))
    }

    /// Returns method tokens in topological order (callees before callers).
    ///
    /// The order is the same with and without recursion: a method comes after every method
    /// it calls, except within a strongly connected component (mutual recursion), whose
    /// methods come in an arbitrary order. The result is lazily computed and cached on first
    /// access.
    ///
    /// # Returns
    ///
    /// A slice of method tokens in topological order.
    #[must_use]
    pub fn topological_order(&self) -> &[Token] {
        self.topo_order.get_or_init(|| {
            // Without cycles, a topological sort: it puts callers first (edges run from a
            // caller to its callees), so it is reversed
            if let Some(order) = algorithms::topological_sort(&self.graph) {
                order
                    .into_iter()
                    .rev()
                    .filter_map(|node_id| self.graph.node(node_id).map(|n| n.token))
                    .collect()
            } else {
                // With cycles, the strongly connected components, which come leaves first
                let sccs = self.sccs();
                sccs.iter()
                    .flatten()
                    .filter_map(|&node_id| self.graph.node(node_id).map(|n| n.token))
                    .collect()
            }
        })
    }

    /// Returns `true` if there are any recursive methods or mutual recursion.
    ///
    /// This detects both direct self-recursion (a method calling itself) and
    /// mutual recursion (cycles of methods calling each other).
    ///
    /// # Returns
    ///
    /// `true` if any recursion exists in the call graph, `false` otherwise.
    #[must_use]
    pub fn has_recursion(&self) -> bool {
        // Check for cycles using SCC - if any SCC has more than 1 node, there's mutual recursion
        self.sccs().iter().any(|scc| scc.len() > 1)
            // Also check for direct self-recursion
            || self.graph.node_ids().any(|node_id| {
                self.graph.successors(node_id).any(|succ| succ == node_id)
            })
    }

    /// Returns all methods involved in recursion.
    ///
    /// Includes both methods with direct self-recursion and methods involved
    /// in mutual recursion cycles.
    ///
    /// # Returns
    ///
    /// A sorted, deduplicated vector of method tokens for all recursive methods.
    #[must_use]
    pub fn recursive_methods(&self) -> Vec<Token> {
        let mut recursive = Vec::new();

        // Direct recursion (self-loops)
        for node_id in self.graph.node_ids() {
            if self.graph.successors(node_id).any(|succ| succ == node_id) {
                if let Some(node) = self.graph.node(node_id) {
                    recursive.push(node.token);
                }
            }
        }

        // Mutual recursion (SCCs with size > 1)
        for scc in self.sccs() {
            if scc.len() > 1 {
                for &node_id in scc {
                    if let Some(node) = self.graph.node(node_id) {
                        if !recursive.contains(&node.token) {
                            recursive.push(node.token);
                        }
                    }
                }
            }
        }

        recursive.sort();
        recursive.dedup();
        recursive
    }

    /// Returns the call resolver for virtual dispatch analysis.
    ///
    /// The resolver provides access to type hierarchy information and
    /// virtual method dispatch tables.
    ///
    /// # Returns
    ///
    /// A reference to the [`CallResolver`] used by this call graph.
    #[must_use]
    pub const fn resolver(&self) -> &CallResolver {
        &self.resolver
    }

    /// Returns a reference to the underlying directed graph.
    ///
    /// This provides access to the full graph API for advanced use cases
    /// such as custom traversals or algorithm applications.
    ///
    /// # Returns
    ///
    /// A reference to the underlying `DirectedGraph` structure.
    #[must_use]
    pub fn graph(&self) -> &DirectedGraph<'static, CallGraphNode, CallType> {
        &self.graph
    }

    /// Returns statistics about the call graph.
    ///
    /// Computes aggregate metrics about the call graph including method counts,
    /// edge counts, call site statistics, and recursion information.
    ///
    /// # Returns
    ///
    /// A [`CallGraphStats`] structure containing various metrics about the graph.
    #[must_use]
    pub fn stats(&self) -> CallGraphStats {
        let total_call_sites: usize = self.nodes().map(|n| n.call_sites.len()).sum();

        let virtual_calls = self
            .nodes()
            .flat_map(|n| &n.call_sites)
            .filter(|s| s.call_type.is_virtual())
            .count();

        let resolved_calls = self
            .nodes()
            .flat_map(|n| &n.call_sites)
            .filter(|s| s.is_resolved())
            .count();

        let polymorphic_calls = self
            .nodes()
            .flat_map(|n| &n.call_sites)
            .filter(|s| s.is_polymorphic())
            .count();

        let internal_methods = self.nodes().filter(|n| !n.is_external_ref).count();
        let external_refs = self.graph.node_count().saturating_sub(internal_methods);

        CallGraphStats {
            method_count: internal_methods,
            external_refs,
            edge_count: self.graph.edge_count(),
            total_call_sites,
            virtual_calls,
            resolved_calls,
            polymorphic_calls,
            entry_points: self.entry_points().len(),
            leaf_methods: self.leaf_methods().len(),
            scc_count: self.sccs().len(),
            recursive_methods: self.recursive_methods().len(),
        }
    }

    /// Generates a DOT format representation of this call graph.
    ///
    /// The generated DOT can be rendered using Graphviz tools like `dot` or
    /// online viewers. Entry points (methods with no callers) are highlighted
    /// in green, leaf methods (methods with no callees) are highlighted in blue.
    ///
    /// # Arguments
    ///
    /// * `title` - Optional title for the graph
    ///
    /// # Returns
    ///
    /// A string containing the DOT representation of the call graph.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use dotscope::analysis::CallGraph;
    /// use dotscope::CilObject;
    /// use std::path::Path;
    ///
    /// let assembly = CilObject::from_path(Path::new("test.dll"))?;
    /// let callgraph = CallGraph::build(&assembly)?;
    /// let dot = callgraph.to_dot(Some("MyAssembly"));
    /// std::fs::write("callgraph.dot", dot)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn to_dot(&self, title: Option<&str>) -> String {
        let mut dot = String::new();

        dot.push_str("digraph CallGraph {\n");
        if let Some(name) = title {
            let _ = writeln!(dot, "    label=\"{}\";", escape_dot(name));
        } else {
            dot.push_str("    label=\"Call Graph\";\n");
        }
        dot.push_str("    labelloc=t;\n");
        dot.push_str("    node [shape=box, fontname=\"Courier\", fontsize=10];\n");
        dot.push_str("    edge [fontname=\"Courier\", fontsize=9];\n");
        dot.push_str("    rankdir=TB;\n\n");

        let entry_points: HashSet<_> = self.entry_points().iter().copied().collect();

        // Generate nodes
        for node_id in self.graph.node_ids() {
            if let Some(node) = self.graph.node(node_id) {
                let style = if node.is_external_ref {
                    // External references (MemberRef/MethodSpec) in orange
                    ", style=filled, fillcolor=lightyellow"
                } else if entry_points.contains(&node.token) {
                    // Entry points in green
                    ", style=filled, fillcolor=lightgreen"
                } else if node.is_leaf() {
                    // Leaf methods in blue
                    ", style=filled, fillcolor=lightblue"
                } else {
                    ""
                };

                let _ = writeln!(
                    dot,
                    "    \"{}\" [label=\"{}\"{style}];",
                    node.token,
                    escape_dot(&node.full_name),
                );
            }
        }

        dot.push('\n');

        // Generate edges
        for node_id in self.graph.node_ids() {
            if let Some(node) = self.graph.node(node_id) {
                for callee_token in node.callees() {
                    if self.token_to_node.contains_key(&callee_token) {
                        let _ = writeln!(dot, "    \"{}\" -> \"{callee_token}\";", node.token);
                    }
                }
            }
        }

        dot.push_str("}\n");
        dot
    }
}

impl Default for CallGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about a call graph.
///
/// Provides aggregate metrics about the call graph structure, including
/// method counts, call site statistics, and recursion information.
#[derive(Debug, Clone, Default)]
pub struct CallGraphStats {
    /// Number of internal methods (MethodDef) in the graph.
    pub method_count: usize,
    /// Number of external references (MemberRef/MethodSpec) in the graph.
    pub external_refs: usize,
    /// Number of call edges between methods.
    pub edge_count: usize,
    /// Total number of call sites across all method bodies.
    pub total_call_sites: usize,
    /// Number of virtual call sites (`callvirt` instruction).
    pub virtual_calls: usize,
    /// Number of call sites with resolved targets.
    pub resolved_calls: usize,
    /// Number of polymorphic call sites (multiple possible targets).
    pub polymorphic_calls: usize,
    /// Number of entry points (methods with no callers).
    pub entry_points: usize,
    /// Number of leaf methods (methods with no callees).
    pub leaf_methods: usize,
    /// Number of strongly connected components.
    pub scc_count: usize,
    /// Number of methods involved in direct or mutual recursion.
    pub recursive_methods: usize,
}

impl CallGraphStats {
    /// Returns the call target resolution rate as a percentage.
    ///
    /// This metric indicates how many call sites were successfully resolved
    /// to concrete method targets within the assembly.
    ///
    /// # Returns
    ///
    /// The percentage of resolved call sites (0.0 to 100.0). Returns 100.0
    /// if there are no call sites.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn resolution_rate(&self) -> f64 {
        if self.total_call_sites == 0 {
            100.0
        } else {
            (self.resolved_calls as f64 / self.total_call_sites as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::{
        analysis::callgraph::CallGraphStats,
        metadata::tables::TableId,
        testkit::{
            helpers::load_sample,
            mono::compilation::compile,
            tools::{require_tool, ToolKind},
        },
    };

    /// A chain of calls, with or without a recursive method elsewhere: recursion makes the
    /// graph cyclic, which the order was computed differently for.
    fn chain(recursive: bool) -> String {
        let recursion = if recursive {
            "public static int Rec(int n) { return n == 0 ? 0 : Rec(n - 1); }"
        } else {
            ""
        };
        format!(
            "public static class Program {{
                public static int Leaf() {{ return 1; }}
                public static int Mid() {{ return Leaf() + 1; }}
                public static int Top() {{ return Mid() + 1; }}
                {recursion}
                public static void Main() {{ Top(); }}
            }}"
        )
    }

    #[test]
    fn the_topological_order_puts_callees_first_with_or_without_recursion() {
        let Some(caps) = require_tool(ToolKind::Toolchain) else {
            return;
        };
        let arch = caps.supported_architectures.first().unwrap();
        for recursive in [false, true] {
            let dir = TempDir::new().unwrap();
            let compiled = compile(caps, &chain(recursive), dir.path(), "chain", arch).unwrap();
            assert!(compiled.is_success(), "{:?}", compiled.error);
            let assembly = CilObject::from_path(compiled.assembly_path()).unwrap();
            let graph = CallGraph::build(&assembly).unwrap();
            assert_eq!(graph.has_recursion(), recursive);

            let order = graph.topological_order();
            let position = |name: &str| {
                let token = assembly
                    .methods()
                    .iter()
                    .find(|entry| entry.value().name == name)
                    .map(|entry| *entry.key())
                    .unwrap();
                order.iter().position(|&t| t == token).unwrap()
            };
            assert!(
                position("Leaf") < position("Mid") && position("Mid") < position("Top"),
                "recursive: {recursive}: {order:?}"
            );
            for _ in 0..10 {
                let again = CallGraph::build(&assembly).unwrap();
                assert_eq!(
                    again.topological_order(),
                    order,
                    "the order is deterministic"
                );
            }
        }
    }

    #[test]
    fn a_call_through_a_member_ref_or_method_spec_naming_a_local_method_is_an_edge_to_it() {
        // WindowsBase calls methods of its own generic types through MemberRefs; ConfuserEx's
        // type scrambler calls `BuildMessage<string>` through a MethodSpec.
        for (path, through) in [
            ("WindowsBase.dll", TableId::MemberRef),
            (
                "packers/confuserex/1.6.0/mkaring_typescramble.exe",
                TableId::MethodSpec,
            ),
        ] {
            let assembly = load_sample(path);
            let graph = CallGraph::build(&assembly).expect("built");
            let resolver = assembly.resolver();
            let mut calls = 0usize;
            for entry in assembly.methods().iter() {
                let caller = entry.value();
                for instr in caller.instructions() {
                    if !matches!(instr.mnemonic, "call" | "newobj" | "ldftn") {
                        continue;
                    }
                    let Some(token) = instr.get_token_operand() else {
                        continue;
                    };
                    let Some(local) = resolver.resolve_method(token) else {
                        continue;
                    };
                    if !token.is_table(through) {
                        continue;
                    }
                    calls = calls.saturating_add(1);
                    assert!(
                        graph.callees(caller.token).contains(&local),
                        "{path}: {} calls {local} through {token}",
                        caller.token
                    );
                }
            }
            assert!(calls > 0, "{path}: calls through {through:?}");
        }
    }

    #[test]
    fn test_call_graph_stats_resolution_rate() {
        let mut stats = CallGraphStats::default();

        // Empty graph - 100% resolved
        assert!((stats.resolution_rate() - 100.0).abs() < f64::EPSILON);

        // 8 out of 10 resolved
        stats.total_call_sites = 10;
        stats.resolved_calls = 8;
        assert!((stats.resolution_rate() - 80.0).abs() < f64::EPSILON);
    }
}
