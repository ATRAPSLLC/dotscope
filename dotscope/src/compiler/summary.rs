//! Method summaries for interprocedural analysis.
//!
//! This module provides types for summarizing method behavior, enabling
//! cross-method optimization like constant propagation, dead method detection,
//! and inlining decisions.

use crate::{
    analysis::{ConstValue, InstrId, MethodPurity, ReturnInfo},
    metadata::{signatures::TypeSignature, token::Token},
};

/// Summary of a method's behavior for interprocedural analysis.
#[derive(Debug, Clone)]
pub struct MethodSummary {
    /// The method token.
    pub token: Token,

    /// What this method returns.
    pub return_info: ReturnInfo,

    /// Side effect classification.
    pub purity: MethodPurity,

    /// Parameter analysis.
    pub parameters: Vec<ParameterSummary>,

    /// Is this method a string decryptor?
    pub is_string_decryptor: bool,

    /// Is this method part of control flow obfuscation (dispatcher)?
    pub is_dispatcher: bool,

    /// Should this method be considered for inlining?
    pub inline_candidate: bool,

    /// Approximate instruction count (for inlining heuristics).
    pub instruction_count: usize,

    /// Number of call sites (how many places call this method).
    pub call_site_count: usize,

    /// Is this method an entry point (Main, event handler, etc.)?
    pub is_entry_point: bool,

    /// Return type signature (from method metadata).
    pub return_type: Option<TypeSignature>,

    /// Parameter type signatures (from method metadata).
    pub parameter_types: Vec<TypeSignature>,

    /// Contains XOR operations (common in string decryption).
    pub has_xor_operations: bool,

    /// Contains array element access (common in string decryption).
    pub has_array_access: bool,

    /// Contains encoding/decoding method calls.
    pub has_encoding_calls: bool,

    /// Number of distinct constant values passed at call sites.
    pub distinct_arg_values: usize,
}

impl MethodSummary {
    /// Creates a new method summary with default values.
    ///
    /// All analysis properties start as `Unknown` or false until actual analysis is performed.
    ///
    /// # Arguments
    ///
    /// * `token` - The metadata token identifying the method.
    ///
    /// # Returns
    ///
    /// A new `MethodSummary` with default values.
    #[must_use]
    pub fn new(token: Token) -> Self {
        Self {
            token,
            return_info: ReturnInfo::Unknown,
            purity: MethodPurity::Unknown,
            parameters: Vec::new(),
            is_string_decryptor: false,
            is_dispatcher: false,
            inline_candidate: false,
            instruction_count: 0,
            call_site_count: 0,
            is_entry_point: false,
            return_type: None,
            parameter_types: Vec::new(),
            has_xor_operations: false,
            has_array_access: false,
            has_encoding_calls: false,
            distinct_arg_values: 0,
        }
    }

    /// Checks if this method is dead (no callers and not an entry point).
    ///
    /// # Returns
    ///
    /// `true` if the method has no call sites and is not marked as an entry point.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        self.call_site_count == 0 && !self.is_entry_point
    }

    /// Returns the constant return value if this method always returns the same value.
    ///
    /// # Returns
    ///
    /// A reference to the constant value if return is constant, `None` otherwise.
    #[must_use]
    pub fn returns_constant(&self) -> Option<&ConstValue> {
        match &self.return_info {
            ReturnInfo::Constant(v) => Some(v),
            _ => None,
        }
    }

    /// Checks if this method is pure (has no side effects).
    ///
    /// # Returns
    ///
    /// `true` if the method has been determined to be pure.
    #[must_use]
    pub fn is_pure(&self) -> bool {
        matches!(self.purity, MethodPurity::Pure)
    }

    /// Checks if this method only reads state (no mutations).
    ///
    /// # Returns
    ///
    /// `true` if the method is pure, read-only, or modifies nothing but may
    /// raise an exception.
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        matches!(
            self.purity,
            MethodPurity::Pure | MethodPurity::ReadOnly | MethodPurity::MayThrow
        )
    }

    /// Returns the constant value for a parameter if all call sites pass the same value.
    ///
    /// # Arguments
    ///
    /// * `index` - The zero-based parameter index.
    ///
    /// # Returns
    ///
    /// A reference to the constant value if all call sites agree, `None` otherwise.
    #[must_use]
    pub fn parameter_constant(&self, index: usize) -> Option<&ConstValue> {
        self.parameters
            .get(index)
            .and_then(|p| p.constant_value.as_ref())
    }

    /// Checks if this method returns a string type.
    ///
    /// # Returns
    ///
    /// `true` if the method returns `System.String`.
    #[must_use]
    pub fn returns_string(&self) -> bool {
        matches!(self.return_type, Some(TypeSignature::String))
    }

    /// Checks if any parameter accepts an integer type.
    ///
    /// Integer parameters are common in string decryptors where the
    /// integer is used as an index or decryption key.
    ///
    /// # Returns
    ///
    /// `true` if any parameter is an integer type (I1, U1, I2, U2, I4, U4, I8, U8).
    #[must_use]
    pub fn has_integer_parameter(&self) -> bool {
        self.parameter_types.iter().any(|t| {
            matches!(
                t,
                TypeSignature::I1
                    | TypeSignature::U1
                    | TypeSignature::I2
                    | TypeSignature::U2
                    | TypeSignature::I4
                    | TypeSignature::U4
                    | TypeSignature::I8
                    | TypeSignature::U8
                    | TypeSignature::I
                    | TypeSignature::U
            )
        })
    }

    /// Checks if any parameter is a byte array.
    ///
    /// Byte array parameters are common in string decryptors where
    /// the array contains encrypted string data.
    ///
    /// # Returns
    ///
    /// `true` if any parameter is `byte[]` or similar array type.
    #[must_use]
    pub fn has_byte_array_parameter(&self) -> bool {
        self.parameter_types.iter().any(|t| {
            if let TypeSignature::SzArray(arr) = t {
                matches!(*arr.base, TypeSignature::U1 | TypeSignature::I1)
            } else {
                false
            }
        })
    }

    /// Computes a heuristic score for how likely this method is a string decryptor.
    ///
    /// Higher scores indicate higher confidence. Considers:
    /// - Return type (string = +30)
    /// - Parameter types (int/byte[] = +20)
    /// - XOR operations (+15)
    /// - Array access (+10)
    /// - Encoding calls (+20)
    /// - Called with many distinct constants (+15)
    /// - Small method size (+5)
    ///
    /// # Returns
    ///
    /// A score from 0-100 indicating likelihood of being a string decryptor.
    #[must_use]
    pub fn string_decryptor_score(&self) -> u32 {
        let mut score = 0u32;

        // Return type is string
        if self.returns_string() {
            score = score.saturating_add(30);
        }

        // Has int or byte[] parameter
        if self.has_integer_parameter() {
            score = score.saturating_add(15);
        }
        if self.has_byte_array_parameter() {
            score = score.saturating_add(15);
        }

        // Contains XOR operations
        if self.has_xor_operations {
            score = score.saturating_add(15);
        }

        // Contains array access
        if self.has_array_access {
            score = score.saturating_add(10);
        }

        // Contains encoding calls
        if self.has_encoding_calls {
            score = score.saturating_add(20);
        }

        // Called with many distinct constant values
        if self.distinct_arg_values >= 5 {
            score = score.saturating_add(15);
        } else if self.distinct_arg_values >= 2 {
            score = score.saturating_add(5);
        }

        // Small method (decryptors tend to be compact)
        if self.instruction_count > 0 && self.instruction_count <= 100 {
            score = score.saturating_add(5);
        }

        score.min(100)
    }
}

/// Information about how a parameter is used.
#[derive(Debug, Clone)]
pub struct ParameterSummary {
    /// Parameter index.
    pub index: usize,

    /// Parameter name (if available from metadata).
    pub name: Option<String>,

    /// Whether this parameter is used in the method body.
    pub is_used: bool,

    /// Whether this parameter is only used in pure operations.
    pub pure_usage_only: bool,

    /// If ALL call sites pass the same constant, it's stored here.
    pub constant_value: Option<ConstValue>,

    /// Number of uses within the method.
    pub use_count: usize,
}

impl ParameterSummary {
    /// Creates a new parameter summary with default values.
    ///
    /// # Arguments
    ///
    /// * `index` - The zero-based parameter index.
    ///
    /// # Returns
    ///
    /// A new `ParameterSummary` with default values (unused, no constant).
    #[must_use]
    pub fn new(index: usize) -> Self {
        Self {
            index,
            name: None,
            is_used: false,
            pure_usage_only: true,
            constant_value: None,
            use_count: 0,
        }
    }

    /// Creates a parameter summary with a name.
    ///
    /// # Arguments
    ///
    /// * `index` - The zero-based parameter index.
    /// * `name` - The parameter name from metadata.
    ///
    /// # Returns
    ///
    /// A new `ParameterSummary` with the specified name.
    #[must_use]
    pub fn with_name(index: usize, name: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            ..Self::new(index)
        }
    }

    /// Checks if this parameter is dead (unused in the method body).
    ///
    /// # Returns
    ///
    /// `true` if the parameter is never used.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        !self.is_used
    }

    /// Checks if this parameter has a known constant value at all call sites.
    ///
    /// # Returns
    ///
    /// `true` if all call sites pass the same constant value for this parameter.
    #[must_use]
    pub fn has_constant(&self) -> bool {
        self.constant_value.is_some()
    }
}

/// Information about a call site for interprocedural analysis.
#[derive(Debug, Clone)]
pub struct CallSiteInfo {
    /// The calling method.
    pub caller: Token,

    /// The call instruction, by identity.
    ///
    /// `None` for a call whose instruction has not been stamped. An index
    /// would not do: a position means nothing once a pass has moved the
    /// instruction, and a block-local one means nothing even before that,
    /// since every block has an instruction 3.
    pub site: Option<InstrId>,

    /// Argument values at this call site (None if unknown).
    pub arguments: Vec<Option<ConstValue>>,

    /// Is this call site in live code?
    pub is_live: bool,
}

impl CallSiteInfo {
    /// Creates a new call site info with default values.
    ///
    /// # Arguments
    ///
    /// * `caller` - The metadata token of the calling method.
    /// * `site` - The call instruction's identity, when it has one.
    ///
    /// # Returns
    ///
    /// A new `CallSiteInfo` marked as live with no argument information.
    #[must_use]
    pub fn new(caller: Token, site: Option<InstrId>) -> Self {
        Self {
            caller,
            site,
            arguments: Vec::new(),
            is_live: true,
        }
    }

    /// Returns the constant value for an argument if known.
    ///
    /// # Arguments
    ///
    /// * `index` - The zero-based argument index.
    ///
    /// # Returns
    ///
    /// A reference to the constant value if known, `None` otherwise.
    #[must_use]
    pub fn argument_constant(&self, index: usize) -> Option<&ConstValue> {
        self.arguments.get(index).and_then(|v| v.as_ref())
    }

    /// Checks if all arguments have known constant values.
    ///
    /// # Returns
    ///
    /// `true` if every argument at this call site is a known constant.
    #[must_use]
    pub fn all_arguments_constant(&self) -> bool {
        self.arguments.iter().all(Option::is_some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::CilTarget;

    #[test]
    fn test_method_summary_default() {
        let summary = MethodSummary::new(Token::new(0x06000001));
        // Default summary: no callers (call_site_count=0), not an entry point
        // So is_dead() is true for a new summary
        assert!(summary.is_dead());
        assert!(!summary.is_pure());
        assert!(summary.returns_constant().is_none());
    }

    #[test]
    fn test_return_info() {
        assert!(ReturnInfo::<CilTarget>::Void.is_known());
        assert!(ReturnInfo::<CilTarget>::Constant(ConstValue::I32(42)).is_known());
        assert!(!ReturnInfo::<CilTarget>::Dynamic.is_known());

        assert!(ReturnInfo::<CilTarget>::PassThrough(0).is_potentially_foldable());
        assert!(ReturnInfo::<CilTarget>::PureComputation.is_potentially_foldable());
        assert!(!ReturnInfo::<CilTarget>::Dynamic.is_potentially_foldable());
    }

    #[test]
    fn test_method_purity() {
        assert!(MethodPurity::Pure.can_eliminate_if_unused());
        assert!(MethodPurity::ReadOnly.can_eliminate_if_unused());
        assert!(!MethodPurity::Impure.can_eliminate_if_unused());

        assert!(MethodPurity::Pure.can_inline());
        assert!(MethodPurity::LocalMutation.can_inline());
        assert!(!MethodPurity::Impure.can_inline());
    }

    #[test]
    fn test_parameter_summary() {
        let mut param = ParameterSummary::new(0);
        assert!(param.is_dead());
        assert!(!param.has_constant());

        param.is_used = true;
        param.constant_value = Some(ConstValue::I32(42));

        assert!(!param.is_dead());
        assert!(param.has_constant());
    }

    #[test]
    fn test_call_site_info() {
        let mut call_site = CallSiteInfo::new(Token::new(0x06000001), None);
        call_site.arguments = vec![Some(ConstValue::I32(1)), None, Some(ConstValue::I32(3))];

        assert_eq!(call_site.argument_constant(0), Some(&ConstValue::I32(1)));
        assert_eq!(call_site.argument_constant(1), None);
        assert!(!call_site.all_arguments_constant());
    }
}
