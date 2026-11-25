//! Call graph node representation.
//!
//! This module defines the [`CallGraphNode`] structure which represents
//! a method in the call graph along with its metadata and call site information.

use crate::{
    analysis::callgraph::CallSite,
    metadata::{streams::SharedStr, token::Token},
};

/// A node in the call graph representing a method.
///
/// Each node contains metadata about the method (name, signature, modifiers)
/// as well as the call sites within the method body. The node also tracks
/// override relationships for virtual method dispatch analysis.
#[derive(Debug, Clone)]
pub struct CallGraphNode {
    /// The method token uniquely identifying this method in the assembly.
    pub token: Token,
    /// Method name, shared with the method's metadata.
    pub name: SharedStr,
    /// Full qualified name including type (e.g., "Namespace.Type::Method").
    pub full_name: String,
    /// Full method signature string for disambiguation of overloaded methods.
    pub signature: String,
    /// Whether this is a virtual method that can be overridden.
    pub is_virtual: bool,
    /// Whether this method is abstract (has no implementation body).
    pub is_abstract: bool,
    /// Whether this method is static (not associated with an instance).
    pub is_static: bool,
    /// Whether this is an external method (P/Invoke or internal call).
    pub is_external: bool,
    /// Whether this is a reference to an external assembly (MemberRef).
    pub is_external_ref: bool,
    /// Whether this is a constructor (`.ctor` or `.cctor`).
    pub is_constructor: bool,
    /// All call sites within this method's body.
    pub call_sites: Vec<CallSite>,
    /// Methods that override this method (populated for virtual methods).
    pub overriders: Vec<Token>,
    /// The base method this method overrides, if any.
    pub overrides: Option<Token>,
}

impl CallGraphNode {
    /// Creates a new call graph node with the specified method information.
    ///
    /// The node is initialized with default values for all boolean flags
    /// (all set to `false`) and empty collections for call sites and overriders.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token uniquely identifying the method
    /// * `name` - The method name for display purposes
    /// * `full_name` - The full qualified name including type (e.g., "Namespace.Type::Method")
    /// * `signature` - The full method signature string
    ///
    /// # Returns
    ///
    /// A new [`CallGraphNode`] instance with the specified properties and
    /// default values for flags and collections.
    #[must_use]
    pub fn new(
        token: Token,
        name: impl Into<SharedStr>,
        full_name: String,
        signature: String,
    ) -> Self {
        Self {
            token,
            name: name.into(),
            full_name,
            signature,
            is_virtual: false,
            is_abstract: false,
            is_static: false,
            is_external: false,
            is_external_ref: false,
            is_constructor: false,
            call_sites: Vec::new(),
            overriders: Vec::new(),
            overrides: None,
        }
    }

    /// Returns the number of call sites in this method.
    ///
    /// This counts all call instructions within the method body, including
    /// calls to the same target method at different offsets.
    ///
    /// # Returns
    ///
    /// The total number of call sites in the method body.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.call_sites.len()
    }

    /// Returns `true` if this method has no outgoing calls.
    ///
    /// A leaf method is one that does not call any other methods, making it
    /// a terminal node in the call graph traversal.
    ///
    /// # Returns
    ///
    /// `true` if the method contains no call sites, `false` otherwise.
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        self.call_sites.is_empty()
    }

    /// Returns `true` if this method can be overridden by derived classes.
    ///
    /// A method is overridable if it is virtual and not static. Static methods
    /// cannot be overridden regardless of the virtual flag.
    ///
    /// # Returns
    ///
    /// `true` if the method is virtual and non-static, `false` otherwise.
    #[must_use]
    pub const fn is_overridable(&self) -> bool {
        self.is_virtual && !self.is_static
    }

    /// Returns `true` if this method has a body that can be analyzed.
    ///
    /// Abstract methods and external methods (P/Invoke, internal calls) do not
    /// have IL bodies and cannot be analyzed for call sites.
    ///
    /// # Returns
    ///
    /// `true` if the method has an IL body, `false` for abstract or external methods.
    #[must_use]
    pub const fn has_body(&self) -> bool {
        !self.is_abstract && !self.is_external
    }

    /// Returns all unique callee tokens from this method.
    ///
    /// Collects all method tokens that are called from this method, with
    /// duplicates removed. For virtual calls with multiple possible targets,
    /// all possible targets are included.
    ///
    /// # Returns
    ///
    /// A vector of unique method tokens representing all callees. The order
    /// is based on the first occurrence of each callee in the call sites.
    #[must_use]
    pub fn callees(&self) -> Vec<Token> {
        let mut callees = Vec::new();
        for site in &self.call_sites {
            for target in site.target.all_targets() {
                if !callees.contains(&target) {
                    callees.push(target);
                }
            }
        }
        callees
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        analysis::callgraph::{CallGraphNode, CallSite, CallTarget, CallType},
        metadata::token::Token,
    };

    #[test]
    fn test_node_creation() {
        let token = Token::new(0x0600_0001);
        let node = CallGraphNode::new(
            token,
            "TestMethod".to_string(),
            "TestClass::TestMethod".to_string(),
            "void ()".to_string(),
        );

        assert_eq!(node.token, token);
        assert_eq!(node.name, "TestMethod");
        assert_eq!(node.full_name, "TestClass::TestMethod");
        assert!(!node.is_virtual);
        assert!(!node.is_abstract);
        assert!(node.is_leaf());
        assert_eq!(node.call_count(), 0);
    }

    #[test]
    fn test_node_with_calls() {
        let token = Token::new(0x0600_0001);
        let mut node = CallGraphNode::new(
            token,
            "Caller".to_string(),
            "TestClass::Caller".to_string(),
            "void ()".to_string(),
        );

        let callee1 = Token::new(0x0600_0002);
        let callee2 = Token::new(0x0600_0003);

        node.call_sites.push(CallSite::new(
            0x10,
            CallType::Call,
            CallTarget::Resolved(callee1),
        ));
        node.call_sites.push(CallSite::new(
            0x20,
            CallType::Call,
            CallTarget::Resolved(callee2),
        ));

        assert!(!node.is_leaf());
        assert_eq!(node.call_count(), 2);
        assert_eq!(node.callees(), vec![callee1, callee2]);
    }

    #[test]
    fn test_node_overridable() {
        let token = Token::new(0x0600_0001);
        let mut node = CallGraphNode::new(
            token,
            "Test".to_string(),
            "TestClass::Test".to_string(),
            "void ()".to_string(),
        );

        // Not virtual - not overridable
        assert!(!node.is_overridable());

        // Virtual - overridable
        node.is_virtual = true;
        assert!(node.is_overridable());

        // Virtual but static - not overridable
        node.is_static = true;
        assert!(!node.is_overridable());
    }

    #[test]
    fn test_node_has_body() {
        let token = Token::new(0x0600_0001);
        let mut node = CallGraphNode::new(
            token,
            "Test".to_string(),
            "TestClass::Test".to_string(),
            "void ()".to_string(),
        );

        // Normal method has body
        assert!(node.has_body());

        // Abstract has no body
        node.is_abstract = true;
        assert!(!node.has_body());

        // External has no body
        node.is_abstract = false;
        node.is_external = true;
        assert!(!node.has_body());
    }

    #[test]
    fn test_callees_deduplication() {
        let token = Token::new(0x0600_0001);
        let mut node = CallGraphNode::new(
            token,
            "Test".to_string(),
            "TestClass::Test".to_string(),
            "void ()".to_string(),
        );

        let callee = Token::new(0x0600_0002);

        // Add same callee twice
        node.call_sites.push(CallSite::new(
            0x10,
            CallType::Call,
            CallTarget::Resolved(callee),
        ));
        node.call_sites.push(CallSite::new(
            0x20,
            CallType::Call,
            CallTarget::Resolved(callee),
        ));

        // Should only appear once in callees
        assert_eq!(node.callees(), vec![callee]);
    }
}
