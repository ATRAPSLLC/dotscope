//! Test factory modules for creating test data structures.
//!
//! This module contains factory functions that were migrated from `mod tests` blocks
//! within the main source code to improve code organization and ensure proper
//! codecov exclusion of test helper methods.
//!
//! ## Organization
//!
//! Factories are organized by their primary domain:
//! - [`table`] - Metadata table creation helpers
//! - [`validation`] - Test assemblies and validation scenario factories  
//! - [`metadata`] - General metadata structure factories
//! - [`general`] - Miscellaneous factories that don't fit other categories
//!
//! ## Usage
//!
//! Factory methods maintain the same signatures and behavior as their original
//! locations, but are now properly organized and excluded from coverage analysis.
//!
//! ```text
//! use crate::testkit::factories::table::cilassembly::create_test_typedef_row;
//! use crate::testkit::factories::validation::inheritance::create_assembly_with_circular_inheritance;
//!
//! // Use factories in tests as before
//! let test_row = create_test_typedef_row()?;
//! let test_assembly = create_assembly_with_circular_inheritance()?;
//! ```

pub mod general;
pub mod metadata;
pub mod table;
pub mod validation;
