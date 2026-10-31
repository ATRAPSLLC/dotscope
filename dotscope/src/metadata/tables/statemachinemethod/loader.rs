//! `StateMachineMethod` table loader for efficient metadata processing
//!
//! This module provides the [`StateMachineMethodLoader`] implementation that handles
//! loading and processing `StateMachineMethod` table entries from Portable PDB metadata.
//! The loader follows the established `MetadataLoader` pattern for consistent parallel
//! processing and efficient memory utilization.

use rayon::iter::IndexedParallelIterator;

use crate::{
    metadata::{
        diagnostics::DiagnosticCategory,
        loader::{LoaderContext, MetadataLoader},
        tables::{StateMachineMethodRaw, TableId},
    },
    utils::TryForEachInOrder,
    Result,
};

/// Metadata loader for `StateMachineMethod` table entries
///
/// This loader processes `StateMachineMethod` table data to build efficient lookup
/// structures for state machine debugging support. The loader handles:
///
/// - Parallel processing of table rows for optimal performance
/// - Building token-based lookup maps for fast method resolution
/// - Creating ordered lists for sequential access patterns
/// - Memory-efficient storage using reference counting
///
/// # State Machine Debugging Context
///
/// The `StateMachineMethod` table is crucial for modern .NET debugging because
/// async/await and iterator methods are implemented as state machines. Without
/// this mapping, debuggers would show confusing compiler-generated method names
/// and lose the connection to the original user code.
///
/// # Integration
///
/// This loader integrates with the broader metadata loading infrastructure:
/// - Uses the [`LoaderContext`] for coordinated loading across all tables
/// - Implements [`MetadataLoader`] trait for consistent processing patterns
/// - Provides thread-safe data structures for concurrent debugger access
///
/// # References
///
/// - [Portable PDB Format - StateMachineMethod Table](https://github.com/dotnet/corefx/blob/master/src/System.Reflection.Metadata/specs/PortablePdb-Metadata.md#statemachinemethod-table-0x36)
/// - [.NET State Machine Implementation](https://devblogs.microsoft.com/dotnet/how-async-await-really-works/)
pub struct StateMachineMethodLoader;

impl MetadataLoader for StateMachineMethodLoader {
    fn load(&self, context: &LoaderContext) -> Result<()> {
        let Some(pdb) = &context.pdb else {
            return Ok(());
        };
        let Some(header) = pdb.meta else {
            return Ok(());
        };
        let Some(table) = header.table::<StateMachineMethodRaw>() else {
            return Ok(());
        };

        table
            .par_iter()
            .enumerate()
            .try_for_each_in_order(|(index, row)| {
                let Some(row) = context.handle_row_in(pdb.lenient, row, index)? else {
                    return Ok(());
                };
                let token_msg = || format!("state machine method 0x{:08x}", row.token.value());

                let Some(state_machine_method) = context.handle_result_in(
                    pdb.lenient,
                    row.to_owned(context.method_def),
                    DiagnosticCategory::Method,
                    token_msg,
                )?
                else {
                    return Ok(());
                };

                pdb.target
                    .state_machine_methods
                    .insert(state_machine_method.token, state_machine_method);
                Ok(())
            })
    }

    fn table_id(&self) -> Option<TableId> {
        Some(TableId::StateMachineMethod)
    }

    fn dependencies(&self) -> &'static [TableId] {
        // Both columns name MethodDef rows, resolved through the loaded methods
        &[TableId::MethodDef]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        metadata::{tables::TableDataOwned, token::Token, validation::ValidationConfig},
        testkit::helpers::load_sample,
        CilObject,
    };

    /// A state machine's methods resolve once the methods are loaded: the loader ran before
    /// them and failed every row, which a strict load refuses.
    #[test]
    fn a_state_machine_method_resolves_its_methods() {
        let mut assembly = load_sample("packers/confuserex/1.6.0/original.exe").into_assembly();
        assembly
            .table_row_add(
                TableId::StateMachineMethod,
                TableDataOwned::StateMachineMethod(StateMachineMethodRaw {
                    rid: 0,
                    token: Token::new(0),
                    offset: 0,
                    move_next_method: 2,
                    kickoff_method: 1,
                }),
            )
            .unwrap();
        let written = assembly.to_memory().unwrap();
        CilObject::from_mem_with_validation(written, ValidationConfig::production()).unwrap();
    }
}
