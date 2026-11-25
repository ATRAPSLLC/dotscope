//! Factory methods for AssemblyRef table operations.
//!
//! Contains helper methods migrated from AssemblyRef table source files
//! for creating test data related to assembly reference operations.

use crate::{
    cilassembly::CilAssembly, metadata::cilassemblyview::CilAssemblyView, testkit::fixture, Result,
};

/// Helper function to get a test assembly for AssemblyRef operations
///
/// Originally from: `src/metadata/tables/assemblyref/builder.rs`
pub fn get_test_assembly() -> Result<CilAssembly> {
    let path = fixture("WindowsBase.dll");
    let view = CilAssemblyView::from_path(&path)?;
    Ok(CilAssembly::new(view))
}
