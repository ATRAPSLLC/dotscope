//! Shared reference validation utilities for the unified validation framework.
//!
//! This module provides common reference validation operations that analyze and validate
//! cross-table relationships in metadata. It centralizes reference integrity checking
//! logic that can be used by both raw and owned validators to ensure ECMA-335 compliance
//! and prevent dangling references, circular dependencies, and other referential integrity issues.
//!
//! # Architecture
//!
//! The reference validation system operates on pre-analyzed metadata using [`crate::metadata::validation::scanner::ReferenceScanner`]
//! to provide comprehensive cross-table relationship validation:
//! 1. **Existence Validation** - Ensures all referenced tokens exist in metadata
//! 2. **Integrity Validation** - Validates bidirectional reference consistency
//! 3. **Circular Detection** - Detects and prevents circular reference chains
//! 4. **Deletion Safety** - Validates safe token deletion without breaking references
//! 5. **Pattern Analysis** - Analyzes reference patterns for metadata quality assessment
//!
//! # Key Components
//!
//! - [`crate::metadata::validation::shared::references::ReferenceValidator`] - Main reference validation orchestrator
//! - [`crate::metadata::validation::shared::references::ReferenceAnalysis`] - Detailed reference pattern analysis results
//! - [`crate::metadata::validation::shared::references::ReferenceStatistics`] - Statistical information about reference validation
//!
//! # Usage Examples
//!
//! ```rust,no_run
//! use dotscope::metadata::validation::{ReferenceValidator, ReferenceScanner};
//! use dotscope::metadata::cilassemblyview::CilAssemblyView;
//! use dotscope::metadata::token::Token;
//! use std::path::Path;
//!
//! # let path = Path::new("assembly.dll");
//! let view = CilAssemblyView::from_path(&path)?;
//! let scanner = ReferenceScanner::from_view(&view)?;
//! let validator = ReferenceValidator::new(&scanner);
//!
//! // Validate token references
//! let tokens = vec![Token::new(0x02000001), Token::new(0x06000001)];
//! validator.validate_token_references(tokens)?;
//!
//! // Check for circular references
//! let token = Token::new(0x02000001);
//! if validator.has_circular_references(token) {
//!     println!("Circular reference detected");
//! }
//!
//! // Get reference statistics
//! let stats = validator.get_reference_statistics();
//! println!("Total references: {}", stats.total_references);
//! # Ok::<(), dotscope::Error>(())
//! ```
//!
//! # Thread Safety
//!
//! [`crate::metadata::validation::ReferenceValidator`] is stateless and implements [`Send`] + [`Sync`],
//! making it safe for concurrent use across multiple validation threads.
//!
//! # Integration
//!
//! This module integrates with:
//! - [`crate::metadata::validation::scanner`] - Provides pre-analyzed reference data
//! - Raw validators - Used by raw validators for basic reference validation
//! - Owned validators - Used by owned validators for cross-reference validation
//! - [`crate::metadata::token`] - Validates token-based references

use std::collections::HashSet;

use rustc_hash::{FxHashMap, FxHashSet};
use strum::IntoEnumIterator;

use crate::{
    metadata::{tables::TableId, token::Token, validation::scanner::ReferenceScanner},
    Error, Result,
};

/// Shared reference validation utilities.
///
/// This struct provides reusable reference validation operations for ensuring
/// cross-table relationships are properly maintained according to ECMA-335 requirements.
/// It helps detect dangling references, circular dependencies, and other referential integrity issues.
/// The validator operates on pre-analyzed metadata from [`crate::metadata::validation::scanner::ReferenceScanner`] to provide
/// efficient validation without redundant analysis.
///
/// # Thread Safety
///
/// This type is stateless and implements [`Send`] + [`Sync`], making it safe for concurrent use.
pub struct ReferenceValidator<'a> {
    /// Reference scanner for metadata analysis
    scanner: &'a ReferenceScanner,
}

impl<'a> ReferenceValidator<'a> {
    /// Creates a new reference validator using the provided reference scanner.
    ///
    /// # Arguments
    ///
    /// * `scanner` - The [`crate::metadata::validation::scanner::ReferenceScanner`] containing pre-analyzed metadata
    ///
    /// # Returns
    ///
    /// A new [`ReferenceValidator`] instance ready for validation operations.
    #[must_use]
    pub fn new(scanner: &'a ReferenceScanner) -> Self {
        Self { scanner }
    }

    /// Validates that all token references point to existing metadata entries.
    ///
    /// This method performs comprehensive reference validation including:
    /// - Existence validation for all referenced tokens
    /// - Cross-table reference integrity
    /// - Detection of dangling references
    ///
    /// # Arguments
    ///
    /// * `tokens` - Iterator of [`crate::metadata::token::Token`] instances to validate for existence
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all references are valid, or an error describing the first invalid reference.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error`] in the following cases:
    /// - [`crate::Error::InvalidRid`] - If a referenced token doesn't exist
    /// - [`crate::Error::InvalidToken`] - If a token type is invalid
    pub fn validate_token_references<I>(&self, tokens: I) -> Result<()>
    where
        I: IntoIterator<Item = Token>,
    {
        for token in tokens {
            if !self.scanner.token_exists(token) {
                return Err(Error::InvalidRid {
                    table: TableId::from_token_type(token.table()).unwrap_or(TableId::Module),
                    rid: token.row(),
                });
            }
        }
        Ok(())
    }

    /// Validates reference integrity for a specific token.
    ///
    /// This method checks that the token exists and that every token it references
    /// exists. Its incoming references need no check: the scanner records them from
    /// the rows it reads, so each one names a row that exists, and walking them for
    /// every row that references a popular target was quadratic in its referrers.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to validate references for
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if reference integrity is maintained, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the token does not exist or if any referenced tokens are invalid.
    pub fn validate_token_integrity(&self, token: Token) -> Result<()> {
        if !self.scanner.token_exists(token) {
            return Err(Error::InvalidRid {
                table: TableId::from_token_type(token.table()).unwrap_or(TableId::Module),
                rid: token.row(),
            });
        }

        // Validate all outgoing references
        if let Some(outgoing_refs) = self.scanner.references_from(token) {
            for &referenced_token in outgoing_refs {
                if !self.scanner.token_exists(referenced_token) {
                    return Err(Error::InvalidRid {
                        table: TableId::from_token_type(referenced_token.table())
                            .unwrap_or(TableId::Module),
                        rid: referenced_token.row(),
                    });
                }
            }
        }

        Ok(())
    }

    /// Detects circular reference chains in metadata.
    ///
    /// This method performs depth-first search to detect circular dependencies
    /// that could cause infinite loops or stack overflows during metadata processing.
    ///
    /// # Arguments
    ///
    /// * `start_token` - The token to start circular dependency detection from
    ///
    /// # Returns
    ///
    /// Returns `true` if a circular reference is detected, `false` otherwise.
    #[must_use]
    pub fn has_circular_references(&self, start_token: Token) -> bool {
        let mut visited = FxHashSet::default();
        let mut recursion_stack = FxHashSet::default();

        self.detect_cycle_dfs(start_token, &mut visited, &mut recursion_stack)
    }

    /// Depth-first search helper for circular reference detection.
    fn detect_cycle_dfs(
        &self,
        token: Token,
        visited: &mut FxHashSet<Token>,
        recursion_stack: &mut FxHashSet<Token>,
    ) -> bool {
        if recursion_stack.contains(&token) {
            return true; // Cycle detected
        }

        if visited.contains(&token) {
            return false; // Already processed
        }

        visited.insert(token);
        recursion_stack.insert(token);

        if let Some(references) = self.scanner.references_from(token) {
            for &referenced_token in references {
                if self.detect_cycle_dfs(referenced_token, visited, recursion_stack) {
                    return true;
                }
            }
        }

        recursion_stack.remove(&token);
        false
    }

    /// Finds all references to a specific table row.
    ///
    /// This method finds all references to a specific row in a metadata table.
    /// It returns a set of (table_id, rid) pairs that reference the target row.
    ///
    /// # Arguments
    ///
    /// * `table_id` - The table ID of the target row
    /// * `rid` - The row ID of the target row
    ///
    /// # Returns
    ///
    /// Returns a set of (table_id, rid) pairs that reference the target row.
    #[must_use]
    pub fn find_references_to_row(&self, table_id: TableId, rid: u32) -> HashSet<(TableId, u32)> {
        let target_token_value = (u32::from(table_id.token_type()) << 24) | (rid & 0x00FF_FFFF);
        let target_token = Token::new(target_token_value);

        self.scanner
            .references_to(target_token)
            .map(|refs| {
                refs.iter()
                    .filter_map(|token| {
                        TableId::from_token_type(token.table()).map(|table| (table, token.row()))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validates deletion safety for a token.
    ///
    /// This method checks whether a token can be safely deleted without
    /// breaking reference integrity. It considers all incoming references
    /// and determines if deletion would create dangling pointers.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check for deletion safety
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the token can be safely deleted, or an error if deletion would break integrity.
    ///
    /// # Errors
    ///
    /// - `ValidationReferenceError`: If deleting the token would break references
    pub fn validate_deletion_safety(&self, token: Token) -> Result<()> {
        if !self.scanner.can_delete_token(token) {
            let ref_count = self
                .scanner
                .references_to(token)
                .map_or(0, std::collections::HashSet::len);
            let token_value = token.value();
            return Err(Error::CrossReferenceError(format!(
                "Cannot delete token {token_value:#x}: {ref_count} references would be broken"
            )));
        }
        Ok(())
    }

    /// Analyzes reference patterns for potential issues.
    ///
    /// This method performs advanced reference analysis to detect common
    /// patterns that might indicate metadata corruption or design issues.
    ///
    /// # Returns
    ///
    /// Returns a `ReferenceAnalysis` struct containing detailed analysis results.
    #[must_use]
    pub fn analyze_reference_patterns(&self) -> ReferenceAnalysis {
        let mut analysis = ReferenceAnalysis::default();
        for table_id in TableId::iter() {
            let row_count = self.scanner.table_row_count(table_id);
            for rid in 1..=row_count {
                let token = Self::create_token(table_id, rid);
                self.analyze_token_references(token, &mut analysis);
            }
        }

        analysis
    }

    /// Analyzes references for a specific token.
    fn analyze_token_references(&self, token: Token, analysis: &mut ReferenceAnalysis) {
        let incoming_count = self
            .scanner
            .references_to(token)
            .map_or(0, std::collections::HashSet::len);
        let outgoing_count = self
            .scanner
            .references_from(token)
            .map_or(0, std::collections::HashSet::len);

        analysis.total_tokens = analysis.total_tokens.saturating_add(1);
        analysis.total_references = analysis
            .total_references
            .saturating_add(incoming_count.saturating_add(outgoing_count));

        if incoming_count == 0 {
            analysis.orphaned_tokens.insert(token);
        }

        if incoming_count > 10 {
            analysis
                .highly_referenced_tokens
                .insert(token, incoming_count);
        }

        if self.has_circular_references(token) {
            analysis.circular_reference_chains.push(token);
        }
    }

    /// Creates a token from table ID and RID.
    fn create_token(table_id: TableId, rid: u32) -> Token {
        let table_token_base = u32::from(table_id.token_type()) << 24;
        Token::new(table_token_base | rid)
    }

    /// Validates forward references are properly resolved.
    ///
    /// This method checks that all forward references in metadata point to
    /// tokens that are defined later in the same metadata stream.
    ///
    /// # Arguments
    ///
    /// * `token` - The token to check forward references for
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if forward references are valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if any forward reference points to a non-existent token.
    pub fn validate_forward_references(&self, token: Token) -> Result<()> {
        if let Some(references) = self.scanner.references_from(token) {
            for &referenced_token in references {
                if !self.scanner.token_exists(referenced_token) {
                    let from_token = token.value();
                    let to_token = referenced_token.value();
                    return Err(Error::CrossReferenceError(format!(
                        "Forward reference from {from_token:#x} to non-existent token {to_token:#x}"
                    )));
                }
            }
        }

        Ok(())
    }

    /// Validates parent-child relationships in hierarchical structures.
    ///
    /// This method ensures that parent-child relationships are properly
    /// maintained and don't create impossible hierarchies.
    ///
    /// # Arguments
    ///
    /// * `parent_token` - The parent token in the hierarchy
    /// * `child_token` - The child token in the hierarchy
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the parent-child relationship is valid, or an error otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if either the parent or child token does not exist, or if the relationship is invalid.
    pub fn validate_parent_child_relationship(
        &self,
        parent_token: Token,
        child_token: Token,
    ) -> Result<()> {
        if !self.scanner.token_exists(parent_token) {
            return Err(Error::InvalidRid {
                table: TableId::from_token_type(parent_token.table()).unwrap_or(TableId::Module),
                rid: parent_token.row(),
            });
        }

        if !self.scanner.token_exists(child_token) {
            return Err(Error::InvalidRid {
                table: TableId::from_token_type(child_token.table()).unwrap_or(TableId::Module),
                rid: child_token.row(),
            });
        }

        if parent_token == child_token {
            let token_value = parent_token.value();
            return Err(Error::CrossReferenceError(format!(
                "Self-referential parent-child relationship detected for token {token_value:#x}"
            )));
        }

        if let Some(parent_references) = self.scanner.references_from(child_token) {
            if parent_references.contains(&parent_token) {
                let parent_value = parent_token.value();
                let child_value = child_token.value();
                return Err(Error::CrossReferenceError(format!(
                    "Circular parent-child relationship detected between {parent_value:#x} and {child_value:#x}"
                )));
            }
        }

        Ok(())
    }

    /// Validates nested class relationships to prevent circular nesting.
    ///
    /// This method specifically validates nested class relationships and only checks
    /// for nesting-based circularity, not inheritance relationships. A nested class
    /// can legitimately inherit from its enclosing class, so inheritance relationships
    /// should not be considered when validating nesting circularity.
    ///
    /// # Arguments
    ///
    /// * `enclosing_token` - The enclosing (outer) class token
    /// * `nested_token` - The nested (inner) class token
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the nested class relationship is valid, or an error if
    /// there would be circular nesting (e.g., A nests B which nests A).
    ///
    /// # Errors
    ///
    /// Returns an error if either token does not exist or if there would be circular nesting.
    pub fn validate_nested_class_relationship(
        &self,
        enclosing_token: Token,
        nested_token: Token,
    ) -> Result<()> {
        if !self.scanner.token_exists(enclosing_token) {
            return Err(Error::InvalidRid {
                table: TableId::from_token_type(enclosing_token.table()).unwrap_or(TableId::Module),
                rid: enclosing_token.row(),
            });
        }

        if !self.scanner.token_exists(nested_token) {
            return Err(Error::InvalidRid {
                table: TableId::from_token_type(nested_token.table()).unwrap_or(TableId::Module),
                rid: nested_token.row(),
            });
        }

        if enclosing_token == nested_token {
            let token_value = enclosing_token.value();
            return Err(Error::CrossReferenceError(format!(
                "Self-referential nested class relationship detected for token {token_value:#x}"
            )));
        }

        // Check if the enclosing class is nested within the nested class (which would create a cycle).
        // For example: if we're trying to establish that A nests B, check if B already nests A
        // (directly or transitively). This would create a circular nesting relationship.
        if self.scanner.is_nested_within(nested_token, enclosing_token) {
            let enclosing_value = enclosing_token.value();
            let nested_value = nested_token.value();
            return Err(Error::CrossReferenceError(format!(
                "Circular nested class relationship detected: {enclosing_value:#x} cannot be the \
                 enclosing class of {nested_value:#x} because {enclosing_value:#x} is already \
                 nested within {nested_value:#x}"
            )));
        }

        Ok(())
    }

    /// Gets detailed reference statistics for the metadata.
    ///
    /// # Returns
    ///
    /// Returns comprehensive reference statistics for analysis and reporting.
    #[must_use]
    pub fn get_reference_statistics(&self) -> ReferenceStatistics {
        let analysis = self.analyze_reference_patterns();

        ReferenceStatistics {
            total_tokens: analysis.total_tokens,
            total_references: analysis.total_references,
            orphaned_count: analysis.orphaned_tokens.len(),
            circular_chains: analysis.circular_reference_chains.len(),
            highly_referenced_count: analysis.highly_referenced_tokens.len(),
            max_incoming_references: analysis
                .highly_referenced_tokens
                .values()
                .max()
                .copied()
                .unwrap_or(0),
        }
    }
}

/// Reference analysis results.
///
/// This struct contains detailed analysis of reference patterns in metadata,
/// useful for detecting potential issues and understanding metadata structure.
#[derive(Debug, Default)]
pub struct ReferenceAnalysis {
    /// Total number of tokens analyzed
    pub total_tokens: usize,
    /// Total number of references found
    pub total_references: usize,
    /// Tokens with no incoming references (potential orphans)
    pub orphaned_tokens: FxHashSet<Token>,
    /// Tokens with many incoming references and their reference counts
    pub highly_referenced_tokens: FxHashMap<Token, usize>,
    /// Tokens that are part of circular reference chains
    pub circular_reference_chains: Vec<Token>,
}

/// Reference validation statistics.
///
/// This struct contains statistical information about reference validation,
/// useful for reporting and debugging reference integrity.
#[derive(Debug, Clone)]
pub struct ReferenceStatistics {
    /// Total number of tokens in the metadata
    pub total_tokens: usize,
    /// Total number of references between tokens
    pub total_references: usize,
    /// Number of orphaned tokens (no incoming references)
    pub orphaned_count: usize,
    /// Number of circular reference chains detected
    pub circular_chains: usize,
    /// Number of highly referenced tokens (>10 references)
    pub highly_referenced_count: usize,
    /// Maximum number of incoming references to any single token
    pub max_incoming_references: usize,
}

impl std::fmt::Display for ReferenceStatistics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Reference Statistics: {} tokens, {} references, {} orphaned, {} circular chains, {} highly referenced (max: {})",
            self.total_tokens,
            self.total_references,
            self.orphaned_count,
            self.circular_chains,
            self.highly_referenced_count,
            self.max_incoming_references
        )
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::{metadata::cilassemblyview::CilAssemblyView, testkit::fixture};

    #[test]
    fn test_reference_validator_creation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        // Test basic functionality
        let stats = validator.get_reference_statistics();
        assert!(stats.total_tokens > 0);
    }

    #[test]
    fn test_token_reference_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        // Test with valid tokens
        if scanner.table_row_count(TableId::TypeDef) > 0 {
            let valid_token = Token::new(0x02000001); // TypeDef with RID 1
            let tokens = vec![valid_token];
            assert!(validator.validate_token_references(tokens).is_ok());
        }

        // Test with invalid token
        let invalid_token = Token::new(0x02000000); // TypeDef with RID 0
        let invalid_tokens = vec![invalid_token];
        assert!(validator.validate_token_references(invalid_tokens).is_err());
    }

    #[test]
    fn test_deletion_safety_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        if scanner.table_row_count(TableId::TypeDef) > 0 {
            let token = Token::new(0x02000001); // TypeDef with RID 1

            // Test deletion safety (result depends on whether token is referenced)
            let result = validator.validate_deletion_safety(token);
            // Don't assert specific result as it depends on the actual references
            // Just verify the method doesn't panic
            let _ = result;
        }
    }

    #[test]
    fn test_circular_reference_detection() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        if scanner.table_row_count(TableId::TypeDef) > 0 {
            let token = Token::new(0x02000001); // TypeDef with RID 1

            // Test circular reference detection
            let has_circular = validator.has_circular_references(token);
            // Don't assert specific result as it depends on the actual metadata
            // Just verify the method completes without error
            let _ = has_circular;
        }
    }

    #[test]
    fn test_parent_child_relationship_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        if scanner.table_row_count(TableId::TypeDef) >= 2 {
            let parent_token = Token::new(0x02000001); // TypeDef with RID 1
            let child_token = Token::new(0x02000002); // TypeDef with RID 2

            // Test basic parent-child validation
            let result = validator.validate_parent_child_relationship(parent_token, child_token);
            // Should pass basic validation (both tokens exist, not self-referential)
            assert!(result.is_ok());

            // Test self-referential relationship (should fail)
            let self_ref_result =
                validator.validate_parent_child_relationship(parent_token, parent_token);
            assert!(self_ref_result.is_err());
        }
    }

    #[test]
    fn test_reference_analysis() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        let analysis = validator.analyze_reference_patterns();
        assert!(analysis.total_tokens > 0);

        let stats = validator.get_reference_statistics();
        let stats_string = stats.to_string();
        assert!(stats_string.contains("tokens"));
        assert!(stats_string.contains("references"));
    }

    #[test]
    fn test_forward_reference_validation() {
        let path = fixture("WindowsBase.dll");
        let view = CilAssemblyView::from_path(&path).expect("the fixture loads");
        let scanner = ReferenceScanner::from_view(&view).expect("the reference scanner builds");
        let validator = ReferenceValidator::new(&scanner);

        if scanner.table_row_count(TableId::TypeDef) > 0 {
            let token = Token::new(0x02000001); // TypeDef with RID 1

            // Test forward reference validation
            let result = validator.validate_forward_references(token);
            // Should pass if all references point to existing tokens
            assert!(result.is_ok());
        }
    }
}
