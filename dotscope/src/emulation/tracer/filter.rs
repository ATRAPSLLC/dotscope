//! Trace filtering for method-level and depth-level tracing control.
//!
//! Complex emulation runs (e.g., PureLogs string decryption) can execute
//! millions of instructions across thousands of methods, producing trace
//! files in the tens of gigabytes. The [`TraceFilter`] allows restricting
//! trace output to only the methods and call depths of interest, making
//! traces manageable for debugging.
//!
//! # Filtering Dimensions
//!
//! Three independent filtering dimensions can be combined:
//!
//! - **Method tokens** — a whitelist of specific method tokens to trace.
//!   When non-empty, only methods in the list produce events.
//! - **Name patterns** — glob-style patterns matching namespace, type, and
//!   method name (e.g., `"System.IO*"` matches all `System.IO` types).
//!   Patterns are applied in order; the last matching pattern wins.
//! - **Call depth** — minimum and/or maximum call depth limits. Useful for
//!   focusing on top-level dispatch without drilling into BCL internals.
//!
//! # Usage
//!
//! ```
//! use dotscope::emulation::{MethodPattern, TraceFilter};
//! use dotscope::metadata::token::Token;
//!
//! // Only trace a specific decryptor method
//! let filter = TraceFilter {
//!     method_tokens: vec![Token::new(0x0600_0D12)],
//!     ..TraceFilter::default()
//! };
//!
//! // Trace all System.IO methods at depth 1-5
//! let filter = TraceFilter {
//!     method_patterns: vec![MethodPattern {
//!         namespace: Some("System.IO*".into()),
//!         type_name: None,
//!         method_name: None,
//!         include: true,
//!     }],
//!     min_depth: Some(1),
//!     max_depth: Some(5),
//!     ..TraceFilter::default()
//! };
//! ```
//!
//! # Integration
//!
//! The filter is stored in [`TracingConfig`](crate::emulation::TracingConfig)
//! and checked by the controller at each trace point. When the filter
//! rejects a method, no trace event is emitted — the overhead is a single
//! `should_trace()` call per event.

use crate::metadata::token::Token;

/// Controls which trace events are emitted based on method tokens,
/// name patterns, and call depth.
#[derive(Clone, Debug, Default)]
pub struct TraceFilter {
    /// Only trace these specific method tokens (empty = all methods).
    pub method_tokens: Vec<Token>,
    /// Glob patterns for method matching (namespace/type/method).
    pub method_patterns: Vec<MethodPattern>,
    /// Minimum call depth to trace (None = no minimum).
    pub min_depth: Option<u32>,
    /// Maximum call depth to trace (None = no maximum).
    pub max_depth: Option<u32>,
    /// Whether to capture argument values as strings in call events.
    pub capture_arguments: bool,
    /// Whether to capture return values as strings in return events.
    pub capture_returns: bool,
    /// Instruction trace verbosity level.
    pub instructions: InstructionTraceLevel,
}

/// Glob-style method name pattern for trace filtering.
#[derive(Clone, Debug)]
pub struct MethodPattern {
    /// Namespace pattern (e.g., "System.Collections.*"). None matches any.
    pub namespace: Option<String>,
    /// Type name pattern. None matches any.
    pub type_name: Option<String>,
    /// Method name pattern. None matches any.
    pub method_name: Option<String>,
    /// Whether this is an include (true) or exclude (false) pattern.
    pub include: bool,
}

/// Instruction-level trace verbosity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum InstructionTraceLevel {
    /// No instruction tracing.
    Off,
    /// Only trace call/callvirt/ret instructions.
    CallsOnly,
    /// Trace calls and branch instructions.
    BranchesAndCalls,
    /// Trace all instructions.
    #[default]
    All,
}

impl TraceFilter {
    /// Returns a filter that allows everything (no filtering).
    #[must_use]
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Checks if a method at the given call depth should be traced.
    ///
    /// Evaluates the depth limits and token whitelist. Returns `true` if the
    /// method passes all active filters.
    ///
    /// # Arguments
    ///
    /// * `method_token` — Token of the method being called.
    /// * `call_depth` — Current call stack depth (0 = entry point).
    ///
    /// # Returns
    ///
    /// `true` if trace events should be emitted for this method, `false` to
    /// suppress them.
    #[must_use]
    pub fn should_trace(&self, method_token: Token, call_depth: u32) -> bool {
        // Check depth limits
        if let Some(min) = self.min_depth {
            if call_depth < min {
                return false;
            }
        }
        if let Some(max) = self.max_depth {
            if call_depth > max {
                return false;
            }
        }

        // Check token whitelist
        if !self.method_tokens.is_empty() && !self.method_tokens.contains(&method_token) {
            return false;
        }

        true
    }

    /// Checks if a method should be traced using name-based patterns.
    ///
    /// Unlike [`should_trace`](Self::should_trace), this method matches against
    /// the method's namespace, type name, and method name rather than its token.
    /// Patterns are evaluated in order; the last matching pattern determines
    /// inclusion (allowing exclude-then-include layering).
    ///
    /// # Arguments
    ///
    /// * `namespace` — Namespace of the method's declaring type (e.g., `"System.IO"`).
    /// * `type_name` — Name of the method's declaring type (e.g., `"Stream"`).
    /// * `method_name` — Name of the method (e.g., `"Read"`).
    /// * `call_depth` — Current call stack depth (0 = entry point).
    ///
    /// # Returns
    ///
    /// `true` if trace events should be emitted, `false` to suppress.
    /// Returns `true` when no patterns are configured (empty = trace everything).
    #[must_use]
    pub fn should_trace_by_name(
        &self,
        namespace: &str,
        type_name: &str,
        method_name: &str,
        call_depth: u32,
    ) -> bool {
        // Check depth limits
        if let Some(min) = self.min_depth {
            if call_depth < min {
                return false;
            }
        }
        if let Some(max) = self.max_depth {
            if call_depth > max {
                return false;
            }
        }

        // No patterns = trace everything
        if self.method_patterns.is_empty() {
            return true;
        }

        // Check patterns — start with default include, apply patterns in order
        let mut included = false;
        for pattern in &self.method_patterns {
            if pattern_matches(pattern, namespace, type_name, method_name) {
                included = pattern.include;
            }
        }

        included
    }
}

/// Simple glob matching (only supports trailing `*`).
fn glob_matches(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}

fn pattern_matches(
    pattern: &MethodPattern,
    namespace: &str,
    type_name: &str,
    method_name: &str,
) -> bool {
    if let Some(ref ns) = pattern.namespace {
        if !glob_matches(ns, namespace) {
            return false;
        }
    }
    if let Some(ref tn) = pattern.type_name {
        if !glob_matches(tn, type_name) {
            return false;
        }
    }
    if let Some(ref mn) = pattern.method_name {
        if !glob_matches(mn, method_name) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use crate::{
        emulation::tracer::filter::{InstructionTraceLevel, MethodPattern, TraceFilter},
        metadata::token::Token,
    };

    #[test]
    fn test_allow_all_traces_everything() {
        let filter = TraceFilter::allow_all();
        assert!(filter.should_trace(Token::new(0x0600_0001), 0));
        assert!(filter.should_trace(Token::new(0x0600_0001), 100));
    }

    #[test]
    fn test_depth_limits() {
        let filter = TraceFilter {
            min_depth: Some(2),
            max_depth: Some(5),
            ..TraceFilter::default()
        };
        assert!(!filter.should_trace(Token::new(0x0600_0001), 1));
        assert!(filter.should_trace(Token::new(0x0600_0001), 3));
        assert!(!filter.should_trace(Token::new(0x0600_0001), 6));
    }

    #[test]
    fn test_token_whitelist() {
        let target = Token::new(0x0600_0001);
        let other = Token::new(0x0600_0002);
        let filter = TraceFilter {
            method_tokens: vec![target],
            ..TraceFilter::default()
        };
        assert!(filter.should_trace(target, 0));
        assert!(!filter.should_trace(other, 0));
    }

    #[test]
    fn test_name_pattern_matching() {
        let filter = TraceFilter {
            method_patterns: vec![MethodPattern {
                namespace: Some("System.IO*".to_string()),
                type_name: None,
                method_name: None,
                include: true,
            }],
            ..TraceFilter::default()
        };

        assert!(filter.should_trace_by_name("System.IO", "Stream", "Read", 0));
        assert!(filter.should_trace_by_name("System.IO.Compression", "GZipStream", "Read", 0));
        assert!(!filter.should_trace_by_name("System.Text", "Encoding", "GetBytes", 0));
    }

    #[test]
    fn test_default_instruction_level() {
        let filter = TraceFilter::default();
        assert_eq!(filter.instructions, InstructionTraceLevel::All);
    }
}
