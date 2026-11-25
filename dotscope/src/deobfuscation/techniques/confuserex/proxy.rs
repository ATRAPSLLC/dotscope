//! ConfuserEx reference proxy detection and inlining.
//!
//! ConfuserEx's ReferenceProxy protection creates small forwarding stubs that
//! hide the real call targets. There are two proxy patterns:
//!
//! ## Mild Mode (direct call forwarding)
//!
//! ```text
//! ldarg.0
//! ldarg.1
//! call <RealTarget>
//! ret
//! ```
//!
//! A tiny method that loads all arguments in order, calls the real target
//! method, and returns the result. The forwarding is transparent.
//!
//! ## Strong Mode (delegate-based)
//!
//! ```text
//! ldsfld <DelegateType> <field>
//! ldarg.0
//! ldarg.1
//! callvirt <DelegateType>::Invoke(...)
//! ret
//! ```
//!
//! Loads a pre-initialised delegate from a static field, passes all arguments,
//! and invokes the delegate. The real target is hidden behind the delegate
//! initialisation code.
//!
//! # Detection
//!
//! Scans all methods for the mild and strong proxy patterns. Both produce
//! tiny methods (< 10 instructions) that forward all arguments.
//!
//! # Passes
//!
//! No SSA pass is needed -- the always-on [`ProxyDevirtualizationPass`](crate::compiler::ProxyDevirtualizationPass) in the
//! normalize phase handles proxy devirtualization for all detected proxies.
//! This technique only provides detection and cleanup (marking proxy methods
//! for dead method elimination).

use std::any::Any;

use crate::{
    assembly::Instruction,
    cilassembly::CleanupRequest,
    deobfuscation::techniques::{Detection, Evidence, Technique, TechniqueCategory},
    metadata::token::Token,
    prelude::FlowType,
    CilObject,
};

/// Maximum instruction count for a method to be considered a proxy candidate.
///
/// ReferenceProxy methods are tiny forwarding stubs. Even the strong mode
/// (delegate-based) pattern only needs ~5 instructions. We use 10 as a
/// generous upper bound.
const MAX_PROXY_INSTRUCTIONS: usize = 10;

/// Findings from reference proxy detection.
#[derive(Debug)]
pub struct ProxyFindings {
    /// Tokens of all detected proxy forwarding methods (mild + strong).
    pub proxy_methods: Vec<Token>,
    /// Tokens of strong (delegate-based) proxy methods only.
    /// These are safe to delete directly — the pattern is specific to ConfuserEx.
    pub strong_proxy_methods: Vec<Token>,
}

/// Detects ConfuserEx reference proxy forwarding stubs.
///
/// Scans all methods for mild (direct call forwarding) and strong
/// (delegate-based) proxy patterns, recording the proxy method tokens
/// for inlining.
pub struct ConfuserExReferenceProxy;

impl Technique for ConfuserExReferenceProxy {
    fn id(&self) -> &'static str {
        "confuserex.proxy"
    }

    fn name(&self) -> &'static str {
        "ConfuserEx Reference Proxy Inlining"
    }

    fn category(&self) -> TechniqueCategory {
        TechniqueCategory::Call
    }

    fn detect(&self, assembly: &CilObject) -> Detection {
        let entry_point_token = assembly.cor20header().entry_point_token;
        let entry_token = if entry_point_token != 0 {
            Some(Token::new(entry_point_token))
        } else {
            None
        };

        let mut proxy_methods = Vec::new();
        let mut strong_proxy_methods = Vec::new();

        for method_entry in assembly.methods() {
            let method = method_entry.value();

            // Skip constructors and static constructors.
            if method.is_ctor() || method.is_cctor() {
                continue;
            }

            // Skip the entry point method.
            if entry_token.is_some_and(|t| t == method.token) {
                continue;
            }

            let instructions: Vec<&Instruction> = method.instructions().collect();

            // Skip methods too large or too small to be proxies.
            if instructions.is_empty() || instructions.len() > MAX_PROXY_INSTRUCTIONS {
                continue;
            }

            if is_strong_proxy(&instructions, assembly) {
                proxy_methods.push(method.token);
                strong_proxy_methods.push(method.token);
            } else if is_mild_proxy(&instructions) {
                proxy_methods.push(method.token);
            }
        }

        if proxy_methods.is_empty() {
            return Detection::new_empty();
        }

        let count = proxy_methods.len();
        let findings = ProxyFindings {
            proxy_methods,
            strong_proxy_methods,
        };

        Detection::new_detected(
            vec![Evidence::BytecodePattern(format!(
                "{count} reference proxy forwarding stubs",
            ))],
            Some(Box::new(findings) as Box<dyn Any + Send + Sync>),
        )
    }

    fn cleanup(&self, detection: &Detection) -> Option<CleanupRequest> {
        let findings = detection.findings::<ProxyFindings>()?;
        if findings.strong_proxy_methods.is_empty() {
            return None;
        }

        // Only add strong (delegate-based) proxy methods to the cleanup request.
        // The strong pattern (ldsfld + callvirt Invoke) is specific to ConfuserEx
        // and safe to mark for deletion. Mild proxies are handled by the
        // devirtualization pass and dead method elimination.
        let mut request = CleanupRequest::new();
        for token in &findings.strong_proxy_methods {
            request.add_method(*token);
        }
        Some(request)
    }
}

/// Checks if a method matches the mild proxy pattern (direct call forwarding).
///
/// Pattern: zero or more `ldarg` instructions, one `call`, then `ret`.
fn is_mild_proxy(instructions: &[&Instruction]) -> bool {
    if instructions.len() < 2 {
        return false;
    }

    // Last instruction must be ret.
    let Some(last) = instructions.last() else {
        return false;
    };
    if last.mnemonic != "ret" {
        return false;
    }

    // Second-to-last must be a non-virtual call with a token operand.
    let Some(call_idx) = instructions.len().checked_sub(2) else {
        return false;
    };
    let Some(call_instr) = instructions.get(call_idx) else {
        return false;
    };
    if call_instr.mnemonic != "call" || call_instr.flow_type != FlowType::Call {
        return false;
    }
    if call_instr.get_token_operand().is_none() {
        return false;
    }

    // All preceding instructions must be ldarg variants.
    let Some(prefix) = instructions.get(..call_idx) else {
        return false;
    };
    for instr in prefix {
        if !instr.mnemonic.starts_with("ldarg") {
            return false;
        }
    }

    true
}

/// Checks if a method matches the strong proxy pattern (delegate-based).
///
/// Pattern: `ldsfld`, zero or more `ldarg`, `callvirt Invoke`, `ret`.
fn is_strong_proxy(instructions: &[&Instruction], _assembly: &CilObject) -> bool {
    if instructions.len() < 3 {
        return false;
    }

    // First instruction must be ldsfld.
    let Some(first) = instructions.first() else {
        return false;
    };
    if first.mnemonic != "ldsfld" {
        return false;
    }

    // Last instruction must be ret.
    let Some(last) = instructions.last() else {
        return false;
    };
    if last.mnemonic != "ret" {
        return false;
    }

    // Second-to-last must be callvirt (delegate dispatch).
    let Some(call_idx) = instructions.len().checked_sub(2) else {
        return false;
    };
    let Some(call_instr) = instructions.get(call_idx) else {
        return false;
    };
    if call_instr.mnemonic != "callvirt" || call_instr.flow_type != FlowType::Call {
        return false;
    }
    if call_instr.get_token_operand().is_none() {
        return false;
    }
    // Note: we don't check that the callvirt target is named "Invoke" because
    // ConfuserEx's renamer may rename the delegate's Invoke method. The pattern
    // (ldsfld + ldarg* + callvirt + ret) is specific enough to identify proxy stubs.

    // All instructions between ldsfld and callvirt must be ldarg variants.
    let Some(middle) = instructions.get(1..call_idx) else {
        return false;
    };
    for instr in middle {
        if !instr.mnemonic.starts_with("ldarg") {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use crate::{
        deobfuscation::techniques::{
            confuserex::proxy::{ConfuserExReferenceProxy, ProxyFindings},
            Technique,
        },
        testkit::helpers::load_sample,
    };

    #[test]
    fn test_detect_positive() {
        let assembly = load_sample("packers/confuserex/1.6.0/mkaring_normal.exe");

        let technique = ConfuserExReferenceProxy;
        let detection = technique.detect(&assembly);

        assert!(
            detection.is_detected(),
            "ConfuserExReferenceProxy should detect proxy stubs in mkaring_normal.exe"
        );
        assert!(
            !detection.evidence().is_empty(),
            "Detection should have evidence"
        );

        let findings = detection
            .findings::<ProxyFindings>()
            .expect("Should have ProxyFindings");

        assert!(
            !findings.proxy_methods.is_empty(),
            "Should have proxy method tokens"
        );
    }

    #[test]
    fn test_detect_negative() {
        let assembly = load_sample("packers/confuserex/1.6.0/original.exe");

        let technique = ConfuserExReferenceProxy;
        let detection = technique.detect(&assembly);

        assert!(
            !detection.is_detected(),
            "ConfuserExReferenceProxy should not detect proxy stubs in original.exe"
        );
    }
}
