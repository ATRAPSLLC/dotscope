//! Table factory modules for creating test metadata table structures.
//!
//! Contains factory functions migrated from table-related source files
//! that create test data for metadata table manipulation and testing.

// Based on analysis, we need modules for:
// - cilassembly (from src/cilassembly/mod.rs, remapping/, resolver.rs)
// - assemblyref (from src/metadata/tables/assemblyref/)
// - assembly (from src/metadata/tables/assembly/)
// - constantmodule (from src/metadata/tables/constant/)
// - customattribute (from src/metadata/tables/customattribute/)
// - declsecurity (from src/metadata/tables/declsecurity/)
// - event (from src/metadata/tables/event/)
// - exportedtype (from src/metadata/tables/exportedtype/)
// - field (from src/metadata/tables/field/)
// - file (from src/metadata/tables/file/)
// - genericparam (from src/metadata/tables/genericparam/)
// - implmap (from src/metadata/tables/implmap/)
// - interfaceimpl (from src/metadata/tables/interfaceimpl/)
// - manifestresource (from src/metadata/tables/manifestresource/)
// - memberref (from src/metadata/tables/memberref/)
// - methoddef (from src/metadata/tables/methoddef/)
// - methodimpl (from src/metadata/tables/methodimpl/)
// - methodsemantics (from src/metadata/tables/methodsemantics/)
// - methodspec (from src/metadata/tables/methodspec/)
// - module (from src/metadata/tables/module/)
// - moduleref (from src/metadata/tables/moduleref/)
// - nestedclass (from src/metadata/tables/nestedclass/)
// - param (from src/metadata/tables/param/)
// - property (from src/metadata/tables/property/)
// - propertymap (from src/metadata/tables/propertymap/)
// - standalonesig (from src/metadata/tables/standalonesig/)
// - typedef (from src/metadata/tables/typedef/)
// - typeref (from src/metadata/tables/typeref/)
// - typespec (from src/metadata/tables/typespec/)

// Migrated factory modules:
pub mod assemblyref;
pub mod cilassembly;
pub mod constant;

// Additional modules will be added as we migrate each file
